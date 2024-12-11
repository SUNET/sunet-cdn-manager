package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	zlog "github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/argon2"
)

var (
	errForbidden     = errors.New("access to resource is not allowed")
	errNotFound      = errors.New("resource not found")
	errUnprocessable = errors.New("resource not processable")
	errAlreadyExists = errors.New("resource already exists")
)

type config struct {
	DB dbSettings
}

type dbSettings struct {
	User     string
	Password string
	DBName   string
	Host     string
	Port     int
	SSLMode  string
}

// Small struct that implements io.Writer so we can pass it to net/http server
// for error logging
type zerologErrorWriter struct {
	logger *zerolog.Logger
}

func (zew *zerologErrorWriter) Write(p []byte) (n int, err error) {
	zew.logger.Error().Msg(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

func rootHandler(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "Welcome to SUNET CDN Manager\n")
}

type argon2Settings struct {
	argonTime    uint32
	argonMemory  uint32
	argonThreads uint8
	argonTagSize uint32
}

func newArgon2DefaultSettings() argon2Settings {
	argon2Settings := argon2Settings{}
	// https://datatracker.ietf.org/doc/rfc9106/
	// ===
	// If much less memory is available, a uniformly safe option is
	// Argon2id with t=3 iterations, p=4 lanes, m=2^(16) (64 MiB of
	// RAM), 128-bit salt, and 256-bit tag size.  This is the SECOND
	// RECOMMENDED option.
	// [...]
	// The Argon2id variant with t=1 and 2 GiB memory is the FIRST
	// RECOMMENDED option and is suggested as a default setting for
	// all environments.  This setting is secure against
	// side-channel attacks and maximizes adversarial costs on
	// dedicated brute-force hardware. The Argon2id variant with t=3
	// and 64 MiB memory is the SECOND RECOMMENDED option and is
	// suggested as a default setting for memory- constrained
	// environments.
	// ===
	//
	// Use the "SECOND RECOMMENDED" settings because we are
	// probably running in a memory constrained container:
	// t=3 iterations
	argon2Settings.argonTime = uint32(3)

	// p=4 lanes
	// const ArgonThreads = uint8(4)
	argon2Settings.argonThreads = uint8(4)

	// m=2^(16) (64 MiB of RAM)
	argon2Settings.argonMemory = uint32(64 * 1024)

	// 256-bit tag size (== 32 bytes)
	argon2Settings.argonTagSize = uint32(32)
	return argon2Settings
}

type authDataKey struct{}

type authData struct {
	username  string
	userID    pgtype.UUID
	orgID     *pgtype.UUID
	orgName   *string
	superuser bool
	roleID    pgtype.UUID
	roleName  string
}

func authMiddleware(dbPool *pgxpool.Pool, logger zerolog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			realm := "SUNET CDN Manager"
			username, password, ok := r.BasicAuth()
			if !ok {
				w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			var userID, roleID pgtype.UUID
			var orgID *pgtype.UUID // can be nil if not belonging to a organization
			var orgName *string    // same as above
			var argon2Key, argon2Salt []byte
			var argon2Time, argon2Memory, argon2TagSize uint32
			var argon2Threads uint8
			var superuser bool
			var roleName string

			err := dbPool.QueryRow(
				context.Background(),
				`SELECT
				users.id,
				users.org_id,
				organizations.name,
				users.role_id,
				roles.name,
				roles.superuser,
				user_argon2keys.key,
				user_argon2keys.salt,
				user_argon2keys.time,
				user_argon2keys.memory,
				user_argon2keys.threads,
				user_argon2keys.tag_size
			FROM users
			JOIN user_argon2keys ON users.id = user_argon2keys.user_id
			JOIN roles ON users.role_id = roles.id
			LEFT JOIN organizations ON users.org_id = organizations.id
			WHERE users.name=$1`,
				username,
			).Scan(
				&userID,
				&orgID,
				&orgName,
				&roleID,
				&roleName,
				&superuser,
				&argon2Key,
				&argon2Salt,
				&argon2Time,
				&argon2Memory,
				&argon2Threads,
				&argon2TagSize,
			)
			if err != nil {
				logger.Err(err).Msg("failed looking up username for authentication")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			loginKey := argon2.IDKey([]byte(password), argon2Salt, argon2Time, argon2Memory, argon2Threads, argon2TagSize)
			// Use subtle.ConstantTimeCompare() in an attempt to
			// not leak password contents via timing attack
			passwordMatch := (subtle.ConstantTimeCompare(loginKey, argon2Key) == 1)

			if !passwordMatch {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			ad := authData{
				username:  username,
				userID:    userID,
				orgID:     orgID,
				orgName:   orgName,
				roleID:    roleID,
				roleName:  roleName,
				superuser: superuser,
			}

			ctx := context.WithValue(r.Context(), authDataKey{}, ad)

			// call the next handler in the chain, passing the response writer and
			// the updated request object with the new context value.
			//
			// note: context.Context values are nested, so any previously set
			// values will be accessible as well, and the new `"user"` key
			// will be accessible from this point forward.
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func selectUsers(dbPool *pgxpool.Pool, logger *zerolog.Logger, ad authData) ([]user, error) {
	var rows pgx.Rows
	var err error
	if ad.superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT users.id, users.name, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id ORDER BY users.ts")
		if err != nil {
			logger.Err(err).Msg("unable to query for users")
			return nil, fmt.Errorf("unable to query for users")
		}
	} else if ad.orgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT users.id, users.name, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id WHERE users.id=$1 ORDER BY users.ts", ad.userID)
		if err != nil {
			return nil, fmt.Errorf("unable to query for users for organization: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[user])
	if err != nil {
		logger.Err(err).Msg("unable to CollectRows for users")
		return nil, errors.New("unable to get rows for users")
	}

	return users, nil
}

func selectUserByID(dbPool *pgxpool.Pool, logger *zerolog.Logger, inputID string, ad authData) (user, error) {
	u := user{}
	userIdent, err := parseNameOrID(inputID)
	if err != nil {
		return user{}, fmt.Errorf("unable to parse name or id")
	}

	var roleName string
	var superuser bool
	if userIdent.isID() {
		if !ad.superuser && (ad.userID != *userIdent.id) {
			return user{}, errNotFound
		}

		var userName string
		err := dbPool.QueryRow(context.Background(), "SELECT users.name, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id WHERE users.id=$1", *userIdent.id).Scan(&userName, &roleName, &superuser)
		if err != nil {
			return user{}, fmt.Errorf("unable to SELECT user by id: %w", err)
		}
		u.ID = *userIdent.id
		u.Name = userName
	} else {
		if !ad.superuser && (ad.username != inputID) {
			return user{}, errNotFound
		}

		var userID pgtype.UUID
		err := dbPool.QueryRow(context.Background(), "SELECT users.id, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id WHERE users.name=$1", inputID).Scan(&userID, &roleName, &superuser)
		if err != nil {
			logger.Err(err).Str("id", inputID).Msg("unable to SELECT user by name")
			return user{}, fmt.Errorf("unable to SELECT user by name")
		}
		u.ID = userID
		u.Name = *userIdent.name
	}

	u.RoleName = roleName
	u.Superuser = superuser

	return u, nil
}

type argon2Data struct {
	key  []byte
	salt []byte
	argon2Settings
}

func passwordToArgon2(password string) (argon2Data, error) {
	argonSettings := newArgon2DefaultSettings()

	// Generate 16 byte (128 bit) salt as
	// recommended for argon2 in RFC 9106
	saltLen := 16

	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return argon2Data{}, fmt.Errorf("unable to create argon2 salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argonSettings.argonTime, argonSettings.argonMemory, argonSettings.argonThreads, argonSettings.argonTagSize)

	return argon2Data{
		key:            key,
		salt:           salt,
		argon2Settings: argonSettings,
	}, nil
}

func insertUserWithArgon2Tx(tx pgx.Tx, name string, orgID pgtype.UUID, roleID pgtype.UUID, a2Data argon2Data) (pgtype.UUID, error) {
	var userID pgtype.UUID

	err := tx.QueryRow(context.Background(), "INSERT INTO users (name, org_id, role_id) VALUES ($1, $2, $3) RETURNING id", name, orgID, roleID).Scan(&userID)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to INSERT user with IDs: %w", err)
	}

	err = tx.QueryRow(context.Background(), "INSERT INTO user_argon2keys (user_id, key, salt, time, memory, threads, tag_size) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id", userID, a2Data.key, a2Data.salt, a2Data.argonTime, a2Data.argonMemory, a2Data.argonThreads, a2Data.argonTagSize).Scan(&userID)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to INSERT user argon2 data with IDs: %w", err)
	}

	return userID, nil
}

func insertUser(dbPool *pgxpool.Pool, name string, password string, role string, organization string, ad authData) (pgtype.UUID, error) {
	if !ad.superuser {
		return pgtype.UUID{}, errForbidden
	}

	orgIdent, err := parseNameOrID(organization)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to parse organization for user INSERT: %w", err)
	}

	roleIdent, err := parseNameOrID(role)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to parse role for user INSERT: %w", err)
	}

	a2Data, err := passwordToArgon2(password)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to create password data for user INSERT: %w", err)
	}

	var userID pgtype.UUID
	// If we already have all the IDs needed just insert them via VALUES
	if orgIdent.isID() && roleIdent.isID() {
		err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			userID, err = insertUserWithArgon2Tx(tx, name, *orgIdent.id, *roleIdent.id, a2Data)
			if err != nil {
				return fmt.Errorf("unable to INSERT user with IDs: %w", err)
			}

			return nil
		})
		if err != nil {
			return pgtype.UUID{}, fmt.Errorf("user with IDs INSERT transaction failed: %w", err)
		}
	} else {
		var roleID pgtype.UUID
		var orgID pgtype.UUID
		// Fetch the missing IDs based on names instead where necessary
		// Use single transaction with FOR SHARE selects to make sure
		// the INSERT uses consistent data. To avoid deadlocks make
		// sure all code performans FOR SHARE selects in the same
		// order (alphabetical).
		err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			if !orgIdent.isID() {
				err := tx.QueryRow(
					context.Background(),
					`SELECT id FROM organizations WHERE name=$1 FOR SHARE`, *orgIdent.name,
				).Scan(
					&orgID,
				)
				if err != nil {
					return fmt.Errorf("unable to lookup organization ID from name for user INSERT: %w", err)
				}
			} else {
				orgID = *orgIdent.id
			}

			if !roleIdent.isID() {
				err := tx.QueryRow(
					context.Background(),
					`SELECT id FROM roles WHERE name=$1 FOR SHARE`, *roleIdent.name,
				).Scan(
					&roleID,
				)
				if err != nil {
					return fmt.Errorf("unable to lookup role ID from name for user INSERT: %w", err)
				}
			} else {
				roleID = *roleIdent.id
			}

			userID, err = insertUserWithArgon2Tx(tx, name, orgID, roleID, a2Data)
			if err != nil {
				return fmt.Errorf("unable to INSERT user after looking up IDs: %w", err)
			}

			return nil
		})
		if err != nil {
			return pgtype.UUID{}, fmt.Errorf("user INSERT transaction failed: %w", err)
		}
	}

	return userID, nil
}

func selectOrganizations(dbPool *pgxpool.Pool, ad authData) ([]organization, error) {
	var rows pgx.Rows
	var err error
	if ad.superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM organizations ORDER BY ts")
		if err != nil {
			return nil, fmt.Errorf("unable to query for organizations: %w", err)
		}
	} else if ad.orgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM organizations WHERE id=$1 ORDER BY ts", *ad.orgID)
		if err != nil {
			return nil, fmt.Errorf("unable to query for organizations: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	organizations, err := pgx.CollectRows(rows, pgx.RowToStructByName[organization])
	if err != nil {
		return nil, fmt.Errorf("unable to CollectRows for organizations: %w", err)
	}

	return organizations, nil
}

func selectOrganizationByID(dbPool *pgxpool.Pool, inputID string, ad authData) (organization, error) {
	o := organization{}
	orgIdent, err := parseNameOrID(inputID)
	if err != nil {
		return organization{}, fmt.Errorf("unable to parse name or id")
	}
	if orgIdent.isID() {
		if !ad.superuser && (ad.orgID == nil || *ad.orgID != *orgIdent.id) {
			return organization{}, errNotFound
		}

		var name string
		err := dbPool.QueryRow(context.Background(), "SELECT name FROM organizations WHERE id=$1", *orgIdent.id).Scan(&name)
		if err != nil {
			return organization{}, fmt.Errorf("unable to SELECT organization by id")
		}
		o.Name = name
		o.ID = *orgIdent.id
	} else {
		if !ad.superuser && (ad.orgName == nil || *ad.orgName != inputID) {
			return organization{}, errNotFound
		}
		var id pgtype.UUID
		err := dbPool.QueryRow(context.Background(), "SELECT id FROM organizations WHERE name=$1", inputID).Scan(&id)
		if err != nil {
			return organization{}, fmt.Errorf("unable to SELECT organization by name: %w", err)
		}
		o.Name = inputID
		o.ID = id
	}

	return o, nil
}

func insertOrganization(dbPool *pgxpool.Pool, name string, ad authData) (pgtype.UUID, error) {
	var id pgtype.UUID
	if !ad.superuser {
		return pgtype.UUID{}, errForbidden
	}
	err := dbPool.QueryRow(context.Background(), "INSERT INTO organizations (name) VALUES ($1) RETURNING id", name).Scan(&id)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to INSERT organization: %w", err)
	}

	return id, nil
}

func selectServices(dbPool *pgxpool.Pool, ad authData) ([]service, error) {
	var rows pgx.Rows
	var err error
	if ad.superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM services ORDER BY ts")
		if err != nil {
			return nil, fmt.Errorf("unable to Query for getServices as superuser: %w", err)
		}
	} else if ad.orgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM services WHERE org_id=$1 ORDER BY ts", *ad.orgID)
		if err != nil {
			return nil, fmt.Errorf("unable to Query for getServices as superuser: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	services := []service{}
	var serviceID pgtype.UUID
	var serviceName string
	_, err = pgx.ForEachRow(rows, []any{&serviceID, &serviceName}, func() error {
		services = append(
			services,
			service{
				ID:   serviceID,
				Name: serviceName,
			},
		)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("unable to ForEachRow over services in API GET: %w", err)
	}

	return services, nil
}

func selectServiceByID(dbPool *pgxpool.Pool, inputID string, ad authData) (service, error) {
	s := service{}
	var serviceName string
	var serviceID pgtype.UUID

	serviceIdent, err := parseNameOrID(inputID)
	if err != nil {
		return service{}, fmt.Errorf("unable to parse name or id")
	}
	if serviceIdent.isID() {
		if ad.superuser {
			err := dbPool.QueryRow(context.Background(), "SELECT name FROM services WHERE id=$1", *serviceIdent.id).Scan(&serviceName)
			if err != nil {
				return service{}, fmt.Errorf("unable to SELECT service by id for superuser")
			}
			s.Name = serviceName
			s.ID = *serviceIdent.id
		} else if ad.orgID != nil {
			err := dbPool.QueryRow(context.Background(), "SELECT services.name FROM services JOIN organizations ON services.org_id = organizations.id WHERE services.id=$1 AND organizations.id=$2", *serviceIdent.id, ad.orgID).Scan(&serviceName)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return service{}, errNotFound
				}
				return service{}, fmt.Errorf("unable to SELECT service by id for organization")
			}
			s.Name = serviceName
			s.ID = *serviceIdent.id
		} else {
			return service{}, errNotFound
		}
	} else {
		if ad.superuser {
			err := dbPool.QueryRow(context.Background(), "SELECT id FROM services WHERE name=$1", inputID).Scan(&serviceID)
			if err != nil {
				return service{}, fmt.Errorf("unable to SELECT service by name for superuser")
			}
			s.Name = inputID
			s.ID = serviceID
		} else if ad.orgID != nil {
			err := dbPool.QueryRow(context.Background(), "SELECT services.id FROM services JOIN organizations ON services.org_id = organizations.id WHERE services.name=$1 AND organizations.id=$2", inputID, ad.orgID).Scan(&serviceID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return service{}, errNotFound
				}
				return service{}, fmt.Errorf("unable to SELECT service by name for organization")
			}
			s.Name = inputID
			s.ID = serviceID
		} else {
			return service{}, errNotFound
		}
	}

	return s, nil
}

type identifier struct {
	name *string
	id   *pgtype.UUID
}

func parseNameOrID(inputID string) (identifier, error) {
	if inputID == "" {
		return identifier{}, errors.New("input id is empty")
	}

	id := new(pgtype.UUID)
	err := id.Scan(inputID)
	if err == nil {
		// This is a UUID, treat it as an ID
		return identifier{
			id: id,
		}, nil
	}

	// This is not a UUID, treat it as a name
	return identifier{
		name: &inputID,
	}, nil
}

func (i identifier) isID() bool {
	return i.id != nil
}

func (i identifier) isValid() bool {
	return i.id != nil || i.name != nil
}

func (i identifier) String() string {
	if i.name != nil {
		return *i.name
	}

	if i.id != nil {
		// We can drop the uuid module when
		// https://github.com/jackc/pgx/commit/8723855d957fc7a076a0e6998a016d8c4b138dca
		// is available in a release.
		u, err := uuid.FromBytes(i.id.Bytes[:])
		if err != nil {
			// Should not happen as parseNameOrID() would have errored out if it was unable to parse the UUID
			panic(err)
		}
		return u.String()
	}

	return ""
}

func insertService(dbPool *pgxpool.Pool, name string, orgNameOrID *string, ad authData) (pgtype.UUID, error) {
	var serviceID pgtype.UUID

	var orgIdent identifier
	var err error

	if orgNameOrID != nil {
		orgIdent, err = parseNameOrID(*orgNameOrID)
		if err != nil {
			return pgtype.UUID{}, errUnprocessable
		}
	}

	if ad.superuser {
		if !orgIdent.isValid() {
			return pgtype.UUID{}, errUnprocessable
		}
		if orgIdent.isID() {
			err := dbPool.QueryRow(context.Background(), "INSERT INTO services (name, org_id) VALUES ($1, $2) RETURNING id", name, *orgIdent.id).Scan(&serviceID)
			if err != nil {
				return pgtype.UUID{}, fmt.Errorf("unable to INSERT service for superuser with organizaiton id: %w", err)
			}
		} else {
			err := dbPool.QueryRow(context.Background(), "INSERT INTO services (name, org_id) SELECT $1, organizations.id FROM organizations WHERE organizations.name=$2 returning id", name, *orgIdent.name).Scan(&serviceID)
			if err != nil {
				return pgtype.UUID{}, fmt.Errorf("unable to INSERT service for superuser with organization name: %w", err)
			}
		}
	} else {
		if ad.orgID == nil {
			return pgtype.UUID{}, errForbidden
		}

		// If a user is trying to supply an org id for an org they are
		// not part of just error out to signal they are sending bad
		// data.
		if orgIdent.isValid() {
			if orgIdent.isID() {
				if *ad.orgID != *orgIdent.id {
					return pgtype.UUID{}, errForbidden
				}
			} else {
				if *ad.orgName != *orgIdent.name {
					return pgtype.UUID{}, errForbidden
				}
			}
		}

		err := dbPool.QueryRow(context.Background(), "INSERT INTO services (name, org_id) VALUES ($1, $2) RETURNING id", name, ad.orgID).Scan(&serviceID)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				// https://www.postgresql.org/docs/current/errcodes-appendix.html
				// unique_violation: 23505
				if pgErr.Code == "23505" {
					return pgtype.UUID{}, errAlreadyExists
				}
			}
			return pgtype.UUID{}, fmt.Errorf("unable to INSERT service for organization with id: %w", err)
		}
	}

	return serviceID, nil
}

func selectServiceVersions(dbPool *pgxpool.Pool, ad authData) ([]serviceVersion, error) {
	var rows pgx.Rows
	var err error
	if ad.superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT service_versions.id, service_versions.version, service_versions.active, services.name FROM service_versions JOIN services ON service_versions.service_id = services.id ORDER BY service_versions.version")
		if err != nil {
			return nil, fmt.Errorf("unable to Query for service versions as superuser: %w", err)
		}
	} else if ad.orgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT service_versions.id, service_versions.version, service_versions.active, services.name FROM service_versions JOIN services ON service_versions.service_id = services.id WHERE services.org_id=$1 ORDER BY service_versions.version", ad.orgID)
		if err != nil {
			return nil, fmt.Errorf("unable to Query for getServices as superuser: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	serviceVersions := []serviceVersion{}
	var id pgtype.UUID
	var version int64
	// active can be NULL in the database so that we can force uniqeness on
	// the TRUE value. Treat NULL as false in the API.
	var active *bool
	var serviceName string
	_, err = pgx.ForEachRow(rows, []any{&id, &version, &active, &serviceName}, func() error {
		if active == nil {
			b := false
			active = &b
		}
		serviceVersions = append(
			serviceVersions,
			serviceVersion{
				ID:          id,
				ServiceName: serviceName,
				Version:     version,
				Active:      *active,
			},
		)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("unable to ForEachRow over services in API GET: %w", err)
	}

	return serviceVersions, nil
}

type serviceVersionInsertResult struct {
	versionID     pgtype.UUID
	version       int64
	active        bool
	domainIDs     []pgtype.UUID
	originIDs     []pgtype.UUID
	deactivatedID pgtype.UUID
}

func insertServiceVersionTx(tx pgx.Tx, serviceID pgtype.UUID, orgID pgtype.UUID, domains []string, origins []origin, active *bool) (serviceVersionInsertResult, error) {
	var serviceVersionID pgtype.UUID
	var versionCounter int64
	var deactivatedServiceVersion pgtype.UUID

	err := tx.QueryRow(
		context.Background(),
		"UPDATE services SET version_counter=version_counter+1 WHERE id=$1 AND org_id=$2 RETURNING version_counter",
		serviceID,
		orgID,
	).Scan(&versionCounter)
	if err != nil {
		return serviceVersionInsertResult{}, fmt.Errorf("unable to UPDATE version_counter for service version: %w", err)
	}

	err = tx.QueryRow(
		context.Background(),
		"INSERT INTO service_versions (service_id, version, active) VALUES ($1, $2, $3) RETURNING id",
		serviceID,
		versionCounter,
		active,
	).Scan(&serviceVersionID)
	if err != nil {
		return serviceVersionInsertResult{}, fmt.Errorf("unable to INSERT service version: %w", err)
	}

	// If the new version is expected to be active we need to unset the currently active version
	if active != nil && *active {
		err := tx.QueryRow(
			context.Background(),
			"UPDATE service_versions SET active=NULL WHERE service_id=$1 AND active=true returning id",
			serviceID,
		).Scan(&deactivatedServiceVersion)
		if err != nil {
			return serviceVersionInsertResult{}, fmt.Errorf("unable to UPDATE active status for previous service version: %w", err)
		}
	}

	var serviceDomainIDs []pgtype.UUID
	for _, domain := range domains {
		var serviceDomainID pgtype.UUID
		err = tx.QueryRow(
			context.Background(),
			"INSERT INTO service_domains (service_version_id, domain) VALUES ($1, $2) RETURNING id",
			serviceVersionID,
			domain,
		).Scan(&serviceDomainID)
		if err != nil {
			return serviceVersionInsertResult{}, fmt.Errorf("unable to INSERT service version: %w", err)
		}
		serviceDomainIDs = append(serviceDomainIDs, serviceDomainID)
	}

	var serviceOriginIDs []pgtype.UUID
	for _, origin := range origins {
		var serviceOriginID pgtype.UUID
		err = tx.QueryRow(
			context.Background(),
			"INSERT INTO service_origins (service_version_id, host, port, tls) VALUES ($1, $2, $3, $4) RETURNING id",
			serviceVersionID,
			origin.Host,
			origin.Port,
			origin.TLS,
		).Scan(&serviceOriginID)
		if err != nil {
			return serviceVersionInsertResult{}, fmt.Errorf("unable to INSERT service version: %w", err)
		}
		serviceOriginIDs = append(serviceOriginIDs, serviceOriginID)
	}

	res := serviceVersionInsertResult{
		versionID:     serviceVersionID,
		version:       versionCounter,
		domainIDs:     serviceDomainIDs,
		originIDs:     serviceOriginIDs,
		deactivatedID: deactivatedServiceVersion,
	}

	if active != nil && *active {
		res.active = *active
	}

	return res, nil
}

func insertServiceVersion(dbPool *pgxpool.Pool, serviceID pgtype.UUID, orgNameOrID *string, domains []string, origins []origin, active *bool, ad authData) (serviceVersionInsertResult, error) {
	var serviceVersionResult serviceVersionInsertResult

	var orgIdent identifier
	var err error

	// The "active" column in the database uses NULL to represent "false"
	// so we can have a UNIQUE constraint for "true". For this reason,
	// translate boolean "false" to nil if necessary:
	if active != nil && !*active {
		active = nil
	}

	if orgNameOrID != nil {
		orgIdent, err = parseNameOrID(*orgNameOrID)
		if err != nil {
			return serviceVersionInsertResult{}, errUnprocessable
		}
	}

	if ad.superuser {
		if !orgIdent.isValid() {
			return serviceVersionInsertResult{}, errUnprocessable
		}
		if orgIdent.isID() {
			err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
				serviceVersionResult, err = insertServiceVersionTx(tx, serviceID, *orgIdent.id, domains, origins, active)
				if err != nil {
					return fmt.Errorf("unable to INSERT service version with org ID for superuser: %w", err)
				}

				return nil
			})
			if err != nil {
				return serviceVersionInsertResult{}, fmt.Errorf("service version with ID INSERT transaction failed: %w", err)
			}
		} else {
			err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
				var orgID pgtype.UUID
				err := tx.QueryRow(context.Background(), "SELECT id FROM organizations WHERE name=$1 FOR UPDATE", *orgIdent.name).Scan(&orgID)
				if err != nil {
					return fmt.Errorf("unable to SELECT org ID based on name for superuser: %w", err)
				}

				serviceVersionResult, err = insertServiceVersionTx(tx, serviceID, orgID, domains, origins, active)
				if err != nil {
					return fmt.Errorf("unable to INSERT service version with org name: %w", err)
				}

				return nil
			})
			if err != nil {
				return serviceVersionInsertResult{}, fmt.Errorf("service version with name INSERT transaction failed: %w", err)
			}
		}
	} else {
		if ad.orgID == nil {
			return serviceVersionInsertResult{}, errForbidden
		}

		// If a user is trying to supply an org id for an org they are
		// not part of just error out to signal they are sending bad
		// data.
		if orgIdent.isValid() {
			if orgIdent.isID() {
				if *ad.orgID != *orgIdent.id {
					return serviceVersionInsertResult{}, errForbidden
				}
			} else {
				if *ad.orgName != *orgIdent.name {
					return serviceVersionInsertResult{}, errForbidden
				}
			}
		}

		err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			serviceVersionResult, err = insertServiceVersionTx(tx, serviceID, *ad.orgID, domains, origins, active)
			if err != nil {
				return fmt.Errorf("unable to INSERT service version with org ID for user: %w", err)
			}

			return nil
		})
		if err != nil {
			return serviceVersionInsertResult{}, fmt.Errorf("service version with INSERT transaction for user failed: %w", err)
		}
	}

	return serviceVersionResult, nil
}

func generateCompleteVcl(sv selectVcl) (string, error) {
	var b strings.Builder

	b.WriteString("vcl 4.1;\n")
	b.WriteString("import std;\n")
	b.WriteString("import proxy;\n")
	b.WriteString("\n")
	b.WriteString("backend haproxy_https {\n")
	b.WriteString("  .path = \"/shared/haproxy_https\"\n")
	b.WriteString("}\n")
	b.WriteString("backend haproxy_http {\n")
	b.WriteString("  .path = \"/shared/haproxy_http\"\n")
	b.WriteString("}\n")
	b.WriteString("\n")

	for i, origin := range sv.Origins {
		b.WriteString(fmt.Sprintf("backend backend_%d {\n", i))
		b.WriteString(fmt.Sprintf("  .host = \"%s\";\n", origin.Host))
		b.WriteString(fmt.Sprintf("  .port = \"%d\";\n", origin.Port))
		if origin.TLS {
			b.WriteString("  .via = haproxy_https;\n")
		} else {
			b.WriteString("  .via = haproxy_http;\n")
		}
		b.WriteString("}\n")
	}
	if len(sv.Origins) > 0 {
		b.WriteString("\n")
	}

	b.WriteString("sub vcl_recv {\n")
	if len(sv.Domains) > 0 {
		b.WriteString("  if ")
		for i, domain := range sv.Domains {
			if i > 0 {
				b.WriteString(" && ")
			}
			b.WriteString(fmt.Sprintf("req.http.host != \"%s\"", domain))
		}
		b.WriteString(" {\n")
		b.WriteString("    return(synth(400,\"Unknown Host header.\"));\n")
		b.WriteString("  }\n")
	}

	if sv.VclRecvContent != "" {
		b.WriteString("  # vcl_recv content from database\n")
		scanner := bufio.NewScanner(strings.NewReader(sv.VclRecvContent))
		for scanner.Scan() {
			if scanner.Text() != "" {
				b.WriteString("  " + scanner.Text() + "\n")
			} else {
				b.WriteString("\n")
			}
		}
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("scanning VclRecvContent failed: %w", err)
		}
	}
	b.WriteString("}\n")

	return b.String(), nil
}

func selectVcls(dbPool *pgxpool.Pool, ad authData) ([]completeVcl, error) {
	var rows pgx.Rows
	var err error
	if ad.superuser {
		// Usage of JOIN with subqueries based on
		// https://stackoverflow.com/questions/27622398/multiple-array-agg-calls-in-a-single-query
		// (including separate version when having WHERE statement based on org).
		rows, err = dbPool.Query(
			context.Background(),
			`SELECT
				organizations.id AS org_id,
				services.id AS service_id,
				service_versions.version,
				service_versions.active,
				service_vcl_recv.content AS vcl_recv_content,
				agg_domains.domains,
				agg_origins.origins
			FROM
				organizations
				JOIN services ON organizations.id = services.org_id
				JOIN service_versions ON services.id = service_versions.service_id
				JOIN service_vcl_recv ON service_versions.id = service_vcl_recv.service_version_id
				JOIN (
					SELECT service_version_id, array_agg(domain ORDER BY domain) AS domains
					FROM service_domains
					GROUP BY service_version_id
				) AS agg_domains ON agg_domains.service_version_id = service_versions.id
				JOIN (
					SELECT service_version_id, array_agg((host, port, tls) ORDER BY host, port) AS origins
					FROM service_origins
					GROUP BY service_version_id
				) AS agg_origins ON agg_origins.service_version_id = service_versions.id
			ORDER BY organizations.name`,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to query for vcls as superuser: %w", err)
		}
	} else if ad.orgID != nil {
		rows, err = dbPool.Query(
			context.Background(),
			`SELECT
				organizations.id AS org_id,
				services.id AS service_id,
				service_versions.version,
				service_versions.active,
				service_vcl_recv.content AS vcl_recv_content,
				(SELECT
					array_agg(domain ORDER BY domain)
					FROM service_domains
					WHERE service_version_id = service_versions.id
				) AS domains,
				(SELECT
					array_agg((host, port, tls) ORDER BY host, port)
					FROM service_origins
					WHERE service_version_id = service_versions.id
				) AS origins
			FROM
				organizations
				JOIN services ON organizations.id = services.org_id
				JOIN service_versions ON services.id = service_versions.service_id
				JOIN service_vcl_recv ON service_versions.id = service_vcl_recv.service_version_id
			WHERE organizations.id=$1
			ORDER BY organizations.name`,
			*ad.orgID,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to query for vcls as normal user: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	selectedVcls, err := pgx.CollectRows(rows, pgx.RowToStructByName[selectVcl])
	if err != nil {
		return nil, fmt.Errorf("unable to get rows for vcls: %w", err)
	}

	var completeVcls []completeVcl
	for _, sv := range selectedVcls {
		vclContent, err := generateCompleteVcl(sv)
		if err != nil {
			return nil, fmt.Errorf("unable to generate complete vcl for selected vcl: %w", err)
		}
		completeVcls = append(completeVcls, completeVcl{
			OrgID:     sv.OrgID,
			ServiceID: sv.ServiceID,
			Active:    sv.Active,
			Version:   sv.Version,
			Content:   vclContent,
		})
	}

	return completeVcls, nil
}

func newChiRouter(logger zerolog.Logger, dbPool *pgxpool.Pool) *chi.Mux {
	router := chi.NewMux()

	hlogChain := chi.Chain(
		hlog.NewHandler(logger),
		hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
			hlog.FromRequest(r).Info().
				Str("method", r.Method).
				Stringer("url", r.URL).
				Int("status", status).
				Int("size", size).
				Dur("duration", duration).
				Msg("")
		}),
		hlog.RemoteAddrHandler("ip"),
		hlog.UserAgentHandler("user_agent"),
		hlog.RefererHandler("referer"),
		hlog.RequestIDHandler("req_id", "Request-Id"),
	)

	router.Use(hlogChain...)
	router.Use(authMiddleware(dbPool, logger))

	router.Get("/", rootHandler)

	return router
}

func setupHumaAPI(router *chi.Mux, dbPool *pgxpool.Pool) error {
	api := humachi.New(router, huma.DefaultConfig("SUNET CDN API", "0.0.1"))

	huma.Get(api, "/api/v1/users", func(ctx context.Context, _ *struct{},
	) (*usersOutput, error) {
		logger := zlog.Ctx(ctx)

		ad, ok := ctx.Value(authDataKey{}).(authData)
		if !ok {
			logger.Error().Msg("unable to read auth data from users handler")
			return nil, errors.New("unable to read auth data from users handler")
		}

		users, err := selectUsers(dbPool, logger, ad)
		if err != nil {
			if errors.Is(err, errForbidden) {
				return nil, huma.Error403Forbidden("not allowed to access resource")
			}
			logger.Err(err).Msg("unable to query users")
			return nil, err
		}

		resp := &usersOutput{
			Body: users,
		}
		return resp, nil
	})

	huma.Get(api, "/api/v1/users/{user}", func(ctx context.Context, input *struct {
		User string `path:"user" example:"1" doc:"User ID or name"`
	},
	) (*userOutput, error) {
		logger := zlog.Ctx(ctx)

		ad, ok := ctx.Value(authDataKey{}).(authData)
		if !ok {
			return nil, errors.New("unable to read auth data from user GET handler")
		}

		org, err := selectUserByID(dbPool, logger, input.User, ad)
		if err != nil {
			if errors.Is(err, errForbidden) {
				return nil, huma.Error403Forbidden("not allowed to access resource")
			} else if errors.Is(err, errNotFound) {
				return nil, huma.Error404NotFound("user not found")
			}
			logger.Err(err).Msg("unable to query users")
			return nil, err
		}
		resp := &userOutput{}
		resp.Body.ID = org.ID
		resp.Body.Name = org.Name
		return resp, nil
	})

	// We want to set a custom DefaultStatus, that is why we are not just using huma.Post().
	postUsersPath := "/api/v1/users"
	huma.Register(
		api,
		huma.Operation{
			OperationID:   huma.GenerateOperationID(http.MethodPost, postUsersPath, &userOutput{}),
			Summary:       huma.GenerateSummary(http.MethodPost, postUsersPath, &userOutput{}),
			Method:        http.MethodPost,
			Path:          postUsersPath,
			DefaultStatus: http.StatusCreated,
		},
		func(ctx context.Context, input *struct {
			Body struct {
				Name         string `json:"name" example:"you@example.com" doc:"The username"`
				Role         string `json:"role" example:"customer" doc:"Role ID or name"`
				Organization string `json:"organization" example:"Some name" doc:"Organization ID or name"`
				Password     string `json:"password" example:"verysecret" doc:"The user password"`
			}
		},
		) (*userOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from users POST handler")
			}

			id, err := insertUser(dbPool, input.Body.Name, input.Body.Password, input.Body.Role, input.Body.Organization, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to add resource")
				}
				logger.Err(err).Msg("unable to add user")
				return nil, err
			}
			resp := &userOutput{}
			resp.Body.ID = id
			resp.Body.Name = input.Body.Name
			return resp, nil
		},
	)

	huma.Get(api, "/api/v1/organizations", func(ctx context.Context, _ *struct{},
	) (*organizationsOutput, error) {
		logger := zlog.Ctx(ctx)

		ad, ok := ctx.Value(authDataKey{}).(authData)
		if !ok {
			return nil, errors.New("unable to read auth data from organizations GET handler")
		}

		orgs, err := selectOrganizations(dbPool, ad)
		if err != nil {
			if errors.Is(err, errForbidden) {
				return nil, huma.Error403Forbidden("not allowed to access resource")
			}
			logger.Err(err).Msg("unable to query organizations")
			return nil, err
		}

		resp := &organizationsOutput{
			Body: orgs,
		}
		return resp, nil
	})

	huma.Get(api, "/api/v1/organizations/{organization}", func(ctx context.Context, input *struct {
		Organization string `path:"organization" example:"1" doc:"Organization ID or name"`
	},
	) (*organizationOutput, error) {
		logger := zlog.Ctx(ctx)

		ad, ok := ctx.Value(authDataKey{}).(authData)
		if !ok {
			return nil, errors.New("unable to read auth data from organization GET handler")
		}

		org, err := selectOrganizationByID(dbPool, input.Organization, ad)
		if err != nil {
			if errors.Is(err, errForbidden) {
				return nil, huma.Error403Forbidden("not allowed to access resource")
			} else if errors.Is(err, errNotFound) {
				return nil, huma.Error404NotFound("organization not found")
			}
			logger.Err(err).Msg("unable to query organization")
			return nil, err
		}
		resp := &organizationOutput{}
		resp.Body.ID = org.ID
		resp.Body.Name = org.Name
		return resp, nil
	})

	// We want to set a custom DefaultStatus, that is why we are not just using huma.Post().
	postOrganizationsPath := "/api/v1/organizations"
	huma.Register(
		api,
		huma.Operation{
			OperationID:   huma.GenerateOperationID(http.MethodPost, postOrganizationsPath, &organizationOutput{}),
			Summary:       huma.GenerateSummary(http.MethodPost, postOrganizationsPath, &organizationOutput{}),
			Method:        http.MethodPost,
			Path:          postOrganizationsPath,
			DefaultStatus: http.StatusCreated,
		},
		func(ctx context.Context, input *struct {
			Body struct {
				Name string `json:"name" example:"Some name" doc:"Organization name"`
			}
		},
		) (*organizationOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from organization POST handler: %w")
			}

			id, err := insertOrganization(dbPool, input.Body.Name, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to add resource")
				}
				logger.Err(err).Msg("unable to add organization")
				return nil, err
			}
			resp := &organizationOutput{}
			resp.Body.ID = id
			resp.Body.Name = input.Body.Name
			return resp, nil
		},
	)

	huma.Get(api, "/api/v1/services", func(ctx context.Context, _ *struct{},
	) (*servicesOutput, error) {
		logger := zlog.Ctx(ctx)

		ad, ok := ctx.Value(authDataKey{}).(authData)
		if !ok {
			return nil, errors.New("unable to read auth data from services GET handler")
		}

		services, err := selectServices(dbPool, ad)
		if err != nil {
			if errors.Is(err, errForbidden) {
				return nil, huma.Error403Forbidden("not allowed to query for services")
			}
			logger.Err(err).Msg("unable to query services")
			return nil, err
		}

		resp := &servicesOutput{
			Body: services,
		}
		return resp, nil
	})

	huma.Get(api, "/api/v1/services/{service}", func(ctx context.Context, input *struct {
		Service string `path:"service" example:"1" doc:"Service ID or name"`
	},
	) (*serviceOutput, error) {
		logger := zlog.Ctx(ctx)

		ad, ok := ctx.Value(authDataKey{}).(authData)
		if !ok {
			return nil, errors.New("unable to read auth data from service GET handler")
		}

		services, err := selectServiceByID(dbPool, input.Service, ad)
		if err != nil {
			if errors.Is(err, errNotFound) {
				return nil, huma.Error404NotFound("service not found")
			} else if errors.Is(err, errForbidden) {
				return nil, huma.Error403Forbidden("access to this service is not allowed")
			}
			logger.Err(err).Msg("unable to query service by ID")
			return nil, err
		}

		resp := &serviceOutput{
			Body: services,
		}
		return resp, nil
	})

	postServicesPath := "/api/v1/services"
	huma.Register(
		api,
		huma.Operation{
			OperationID:   huma.GenerateOperationID(http.MethodPost, postServicesPath, &serviceOutput{}),
			Summary:       huma.GenerateSummary(http.MethodPost, postServicesPath, &serviceOutput{}),
			Method:        http.MethodPost,
			Path:          postServicesPath,
			DefaultStatus: http.StatusCreated,
		},
		func(ctx context.Context, input *struct {
			Body struct {
				Name         string  `json:"name" example:"Some name" doc:"Service name"`
				Organization *string `json:"organization,omitempty" example:"Name or ID of organization" doc:"org1"`
			}
		},
		) (*organizationOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from service GET handler")
			}

			id, err := insertService(dbPool, input.Body.Name, input.Body.Organization, ad)
			if err != nil {
				if errors.Is(err, errUnprocessable) {
					return nil, huma.Error422UnprocessableEntity("unable to parse request to add service")
				} else if errors.Is(err, errAlreadyExists) {
					return nil, huma.Error400BadRequest("service already exists")
				} else if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to create this service")
				}
				logger.Err(err).Msg("unable to add service")
				return nil, err
			}
			resp := &organizationOutput{}
			resp.Body.ID = id
			resp.Body.Name = input.Body.Name
			return resp, nil
		},
	)

	huma.Get(api, "/api/v1/service-versions", func(ctx context.Context, _ *struct{},
	) (*serviceVersionsOutput, error) {
		logger := zlog.Ctx(ctx)

		ad, ok := ctx.Value(authDataKey{}).(authData)
		if !ok {
			return nil, errors.New("unable to read auth data from service-versions GET handler")
		}

		serviceVersions, err := selectServiceVersions(dbPool, ad)
		if err != nil {
			if errors.Is(err, errForbidden) {
				return nil, huma.Error403Forbidden("not allowed to access resource")
			}
			logger.Err(err).Msg("unable to query service-versions")
			return nil, err
		}

		resp := &serviceVersionsOutput{
			Body: serviceVersions,
		}
		return resp, nil
	})

	postServiceVersionsPath := "/api/v1/service-versions"
	huma.Register(
		api,
		huma.Operation{
			OperationID:   huma.GenerateOperationID(http.MethodPost, postServiceVersionsPath, &serviceVersionOutput{}),
			Summary:       huma.GenerateSummary(http.MethodPost, postServiceVersionsPath, &serviceVersionOutput{}),
			Method:        http.MethodPost,
			Path:          postServiceVersionsPath,
			DefaultStatus: http.StatusCreated,
		},
		func(ctx context.Context, input *struct {
			Body struct {
				ServiceID    uuid.UUID `json:"service_id" doc:"Service ID"`
				Organization *string   `json:"organization,omitempty" example:"Name or ID of organization" doc:"Name or ID of the organization"`
				Domains      []string  `json:"domains" doc:"List of domains handled by the service"`
				Origins      []origin  `json:"origins" doc:"List of origin hosts for this service"`
				Active       *bool     `json:"active,omitempty" doc:"If the submitted config should be activated or not"`
			}
		},
		) (*serviceVersionOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from service GET handler")
			}

			// Seems we can not use pgtype.UUID as the type in the
			// input body directly, so go via google/uuid module
			// instead and convert here.
			//
			// Might be possible to make this work with pgtype.UUID
			// directly if it would implment
			// encoding.TextUnmarshaler as described here:
			// https://github.com/danielgtaylor/huma/issues/654
			var pgServiceID pgtype.UUID
			err := pgServiceID.Scan(input.Body.ServiceID.String())
			if err != nil {
				return nil, errors.New("unable to convert uuid to pgtype")
			}

			serviceVersionInsertRes, err := insertServiceVersion(dbPool, pgServiceID, input.Body.Organization, input.Body.Domains, input.Body.Origins, input.Body.Active, ad)
			if err != nil {
				if errors.Is(err, errUnprocessable) {
					return nil, huma.Error422UnprocessableEntity("unable to parse request to add service version")
				} else if errors.Is(err, errAlreadyExists) {
					return nil, huma.Error400BadRequest("service version already exists")
				} else if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to create this service version")
				}
				logger.Err(err).Msg("unable to add service")
				return nil, err
			}
			resp := &serviceVersionOutput{}
			resp.Body.ID = serviceVersionInsertRes.versionID
			resp.Body.Version = serviceVersionInsertRes.version
			resp.Body.Active = serviceVersionInsertRes.active
			return resp, nil
		},
	)

	huma.Get(api, "/api/v1/vcls", func(ctx context.Context, _ *struct{},
	) (*completeVclsOutput, error) {
		logger := zlog.Ctx(ctx)

		ad, ok := ctx.Value(authDataKey{}).(authData)
		if !ok {
			logger.Error().Msg("unable to read auth data from vcls handler")
			return nil, errors.New("unable to read auth data from vcls handler")
		}

		vcls, err := selectVcls(dbPool, ad)
		if err != nil {
			if errors.Is(err, errForbidden) {
				return nil, huma.Error403Forbidden("not allowed to access resource")
			}
			logger.Err(err).Msg("unable to query vcls")
			return nil, err
		}

		resp := &completeVclsOutput{
			Body: vcls,
		}
		return resp, nil
	})

	return nil
}

type user struct {
	ID        pgtype.UUID `json:"id" doc:"ID of user"`
	Name      string      `json:"name" example:"user1" doc:"name of user"`
	RoleName  string      `json:"role_name" example:"customer"`
	Superuser bool        `json:"superuser" example:"true" doc:"if user is a superuser"`
}

type userOutput struct {
	Body user
}

type usersOutput struct {
	Body []user
}

type organization struct {
	ID   pgtype.UUID `json:"id" doc:"ID of organization, UUIDv4"`
	Name string      `json:"name" example:"organization 1" doc:"name of organization"`
}

type organizationOutput struct {
	Body organization
}

type organizationsOutput struct {
	Body []organization
}

type service struct {
	ID   pgtype.UUID `json:"id" doc:"ID of service"`
	Name string      `json:"name" example:"service 1" doc:"name of service"`
}

type serviceOutput struct {
	Body service
}

type servicesOutput struct {
	Body []service
}

type serviceVersion struct {
	ID          pgtype.UUID `json:"id"`
	Version     int64       `json:"version"`
	Active      bool        `json:"active"`
	ServiceName string      `json:"service_name,omitempty"`
}

type serviceVersionOutput struct {
	Body serviceVersion
}

type serviceVersionsOutput struct {
	Body []serviceVersion
}

type origin struct {
	Host string `json:"host"`
	Port int    `json:"port" minimum:"1" maximum:"65535"`
	TLS  bool   `json:"tls"`
}

type selectVcl struct {
	OrgID          pgtype.UUID `json:"org_id" doc:"ID of organization"`
	ServiceID      pgtype.UUID `json:"service_id" doc:"ID of service"`
	Active         bool        `json:"active" example:"true" doc:"If the VCL is active"`
	Version        int64       `json:"version" example:"1" doc:"Version of the service"`
	Domains        []string    `json:"domains" doc:"The domains used by the VCL"`
	Origins        []origin    `json:"origins" doc:"The origins used by the VCL"`
	VclRecvContent string      `json:"vcl_recv_content" doc:"The vcl_recv content for the service"`
}

type completeVcl struct {
	OrgID     pgtype.UUID `json:"org_id" doc:"ID of organization"`
	ServiceID pgtype.UUID `json:"service_id" doc:"ID of service"`
	Active    bool        `json:"active" example:"true" doc:"If the VCL is active"`
	Version   int64       `json:"version" example:"1" doc:"Version of the service"`
	Content   string      `json:"content" doc:"The complete VCL loaded by varnish"`
}

type completeVclsOutput struct {
	Body []completeVcl
}

func Run(logger zerolog.Logger) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Exit gracefully on SIGINT or SIGTERM
	go func(logger zerolog.Logger, cancel context.CancelFunc) {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		s := <-sigCh
		logger.Info().Str("signal", s.String()).Msg("received signal")
		cancel()
	}(logger, cancel)

	var conf config
	err := viper.Unmarshal(&conf)
	if err != nil {
		logger.Fatal().Err(err).Msg("viper unable to decode into struct")
	}

	pgConfigString := fmt.Sprintf(
		"user=%s password=%s host=%s port=%d dbname=%s sslmode=%s",
		conf.DB.User,
		conf.DB.Password,
		conf.DB.Host,
		conf.DB.Port,
		conf.DB.DBName,
		conf.DB.SSLMode,
	)

	pgConfig, err := pgxpool.ParseConfig(pgConfigString)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to parse PostgreSQL config string")
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to create database pool")
	}
	defer dbPool.Close()

	err = dbPool.Ping(context.Background())
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to ping database connection")
	}

	router := newChiRouter(logger, dbPool)

	err = setupHumaAPI(router, dbPool)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to setup Huma API")
	}

	srv := &http.Server{
		Addr:         "127.0.0.1:8080",
		Handler:      router,
		ReadTimeout:  time.Second * 10,
		WriteTimeout: time.Second * 10,
		ErrorLog:     log.New(&zerologErrorWriter{&logger}, "", 0),
	}

	// Handle graceful shutdown of HTTP server when receiving signal
	idleConnsClosed := make(chan struct{})

	go func(ctx context.Context, logger zerolog.Logger) {
		<-ctx.Done()

		shutdownDelay := time.Second * 5
		logger.Info().Msgf("sleeping for %s then calling Shutdown()", shutdownDelay)
		time.Sleep(shutdownDelay)
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Err(err).Msg("HTTP server Shutdown failure")
		}
		close(idleConnsClosed)
	}(ctx, logger)

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatal().Err(err).Msg("HTTP server ListenAndServe failed")
	}

	<-idleConnsClosed
}
