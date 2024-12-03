package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	zlog "github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/argon2"
)

var (
	errForbidden            = errors.New("access to resource is not allowed")
	errNotFound             = errors.New("resource not found")
	errUnprocessable        = errors.New("resource not processable")
	errServiceAlreadyExists = errors.New("service already exists")
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
	username     string
	userID       int64
	customerID   *int64
	customerName *string
	superuser    bool
	roleID       int64
	roleName     string
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

			var userID, roleID int64
			var customerID *int64    // can be nil if not belonging to a customer
			var customerName *string // same as above
			var argon2Key, argon2Salt []byte
			var argon2Time, argon2Memory, argon2TagSize uint32
			var argon2Threads uint8
			var superuser bool
			var roleName string

			// Use RepeatableRead to make sure the databases does not change while we look up things spread over multiple SELECTs
			err := pgx.BeginTxFunc(context.Background(), dbPool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
				err := tx.QueryRow(
					context.Background(),
					`SELECT
						users.id,
						users.customer_id,
						customers.name,
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
					LEFT JOIN customers ON users.customer_id = customers.id
					WHERE users.name=$1`,
					username,
				).Scan(
					&userID,
					&customerID,
					&customerName,
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
					return err
				}

				return nil
			})
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
				username:     username,
				userID:       userID,
				customerID:   customerID,
				customerName: customerName,
				roleID:       roleID,
				roleName:     roleName,
				superuser:    superuser,
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
		rows, err = dbPool.Query(context.Background(), "SELECT users.id, users.name, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id ORDER BY id")
		if err != nil {
			logger.Err(err).Msg("unable to query for users")
			return nil, fmt.Errorf("unable to query for users")
		}
	} else if ad.customerID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT users.id, users.name, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id WHERE users.id=$1 ORDER BY users.id", ad.userID)
		if err != nil {
			logger.Err(err).Msg("unable to Query for users for customer")
			return nil, errors.New("unable to query for users")
		}
	} else {
		return nil, errForbidden
	}

	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[user])
	if err != nil {
		logger.Err(err).Msg("unable to CollectRows for users")
		return nil, errors.New("unable to get rows for for users")
	}

	return users, nil
}

func selectUserByID(dbPool *pgxpool.Pool, logger *zerolog.Logger, inputID string, ad authData) (user, error) {
	u := user{}
	ident, err := parseNameOrID(inputID)
	if err != nil {
		return user{}, fmt.Errorf("unable to parse name or id")
	}

	var roleName string
	var superuser bool
	if ident.isID() {
		if !ad.superuser && (ad.userID != *ident.id) {
			return user{}, errNotFound
		}

		var userName string
		err := dbPool.QueryRow(context.Background(), "SELECT users.name, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id WHERE users.id=$1", *ident.id).Scan(&userName, &roleName, &superuser)
		if err != nil {
			logger.Err(err).Int64("id", *ident.id).Msg("unable to SELECT user by id")
			return user{}, fmt.Errorf("unable to SELECT customer by id")
		}
		u.ID = *ident.id
		u.Name = userName
	} else {
		if !ad.superuser && (ad.username != inputID) {
			return user{}, errNotFound
		}

		var userID int64
		err := dbPool.QueryRow(context.Background(), "SELECT users.id, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id WHERE users.name=$1", inputID).Scan(&userID, &roleName, &superuser)
		if err != nil {
			logger.Err(err).Str("id", inputID).Msg("unable to SELECT user by name")
			return user{}, fmt.Errorf("unable to SELECT user by name")
		}
		u.ID = userID
		u.Name = *ident.name
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

func insertUserWithArgon2(tx pgx.Tx, name string, customerID int64, roleID int64, a2Data argon2Data) (int64, error) {
	var userID int64

	err := tx.QueryRow(context.Background(), "INSERT INTO users (name, customer_id, role_id) VALUES ($1, $2, $3) RETURNING id", name, customerID, roleID).Scan(&userID)
	if err != nil {
		return 0, fmt.Errorf("unable to INSERT user with IDs: %w", err)
	}

	err = tx.QueryRow(context.Background(), "INSERT INTO user_argon2keys (user_id, key, salt, time, memory, threads, tag_size) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id", userID, a2Data.key, a2Data.salt, a2Data.argonTime, a2Data.argonMemory, a2Data.argonThreads, a2Data.argonTagSize).Scan(&userID)
	if err != nil {
		return 0, fmt.Errorf("unable to INSERT user argon2 data with IDs: %w", err)
	}

	return userID, nil
}

func insertUser(dbPool *pgxpool.Pool, name string, password string, role string, customer string, ad authData) (int64, error) {
	if !ad.superuser {
		return 0, errForbidden
	}

	custIdent, err := parseNameOrID(customer)
	if err != nil {
		return 0, fmt.Errorf("unable to parse customer for user INSERT: %w", err)
	}

	roleIdent, err := parseNameOrID(role)
	if err != nil {
		return 0, fmt.Errorf("unable to parse role for user INSERT: %w", err)
	}

	a2Data, err := passwordToArgon2(password)
	if err != nil {
		return 0, fmt.Errorf("unable to create password data for user INSERT: %w", err)
	}

	var userID int64
	// If we already have all the IDs needed just insert them via VALUES
	if custIdent.isID() && roleIdent.isID() {
		err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			userID, err = insertUserWithArgon2(tx, name, *custIdent.id, *roleIdent.id, a2Data)
			if err != nil {
				return fmt.Errorf("unable to INSERT user with IDs: %w", err)
			}

			return nil
		})
		if err != nil {
			return 0, fmt.Errorf("user with IDs INSERT transaction failed: %w", err)
		}
	} else {
		var roleID int64
		var customerID int64
		// Fetch the missing IDs based on names instead where necessary
		// Use single transaction with FOR SHARE selects to make sure
		// the INSERT uses consistent data. To avoid deadlocks make
		// sure all code performans FOR SHARE selects in the same
		// order (alphabetical).
		err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			if !custIdent.isID() {
				err := tx.QueryRow(
					context.Background(),
					`SELECT id FROM customers WHERE name=$1 FOR SHARE`, *custIdent.name,
				).Scan(
					&customerID,
				)
				if err != nil {
					return fmt.Errorf("unable to lookup customer ID from name for user INSERT: %w", err)
				}
			} else {
				customerID = *custIdent.id
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

			userID, err = insertUserWithArgon2(tx, name, customerID, roleID, a2Data)
			if err != nil {
				return fmt.Errorf("unable to INSERT user after looking up IDs: %w", err)
			}

			return nil
		})
		if err != nil {
			return 0, fmt.Errorf("user INSERT transaction failed: %w", err)
		}
	}

	return userID, nil
}

func selectCustomers(dbPool *pgxpool.Pool, logger *zerolog.Logger, ad authData) ([]customer, error) {
	var rows pgx.Rows
	var err error
	if ad.superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM customers ORDER BY id")
		if err != nil {
			logger.Err(err).Msg("unable to Query for customers")
			return nil, fmt.Errorf("unable to query for customers: %w", err)
		}
	} else if ad.customerID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM customers WHERE id=$1 ORDER BY id", *ad.customerID)
		if err != nil {
			logger.Err(err).Msg("unable to Query for customers")
			return nil, fmt.Errorf("unable to query for customers: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	customers, err := pgx.CollectRows(rows, pgx.RowToStructByName[customer])
	if err != nil {
		logger.Err(err).Msg("unable to CollectRows for customers")
		return nil, fmt.Errorf("unable to CollectRows for customers: %w", err)
	}

	return customers, nil
}

func selectCustomerByID(dbPool *pgxpool.Pool, logger *zerolog.Logger, inputID string, ad authData) (customer, error) {
	c := customer{}
	ident, err := parseNameOrID(inputID)
	if err != nil {
		return customer{}, fmt.Errorf("unable to parse name or id")
	}
	if ident.isID() {
		if !ad.superuser && (ad.customerID == nil || *ad.customerID != *ident.id) {
			return customer{}, errNotFound
		}

		var name string
		err := dbPool.QueryRow(context.Background(), "SELECT name FROM customers WHERE id=$1", *ident.id).Scan(&name)
		if err != nil {
			logger.Err(err).Int64("id", *ident.id).Msg("unable to SELECT customer by id")
			return customer{}, fmt.Errorf("unable to SELECT customer by id")
		}
		c.Name = name
		c.ID = *ident.id
	} else {
		if !ad.superuser && (ad.customerName == nil || *ad.customerName != inputID) {
			return customer{}, errNotFound
		}
		var id int64
		err := dbPool.QueryRow(context.Background(), "SELECT id FROM customers WHERE name=$1", inputID).Scan(&id)
		if err != nil {
			logger.Err(err).Str("id", inputID).Msg("unable to SELECT customer by name")
			return customer{}, fmt.Errorf("unable to SELECT customer by name")
		}
		c.Name = inputID
		c.ID = id
	}

	return c, nil
}

func insertCustomer(dbPool *pgxpool.Pool, name string, ad authData) (int64, error) {
	var id int64
	if !ad.superuser {
		return 0, errForbidden
	}
	err := dbPool.QueryRow(context.Background(), "INSERT INTO customers (name) VALUES ($1) RETURNING id", name).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("unable to INSERT customer: %w", err)
	}

	return id, nil
}

func selectServices(dbPool *pgxpool.Pool, ad authData) ([]service, error) {
	var rows pgx.Rows
	var err error
	if ad.superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM services ORDER BY id")
		if err != nil {
			return nil, fmt.Errorf("unable to Query for getServices as superuser: %w", err)
		}
	} else if ad.customerID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM services WHERE customer_id=$1 ORDER BY id", *ad.customerID)
		if err != nil {
			return nil, fmt.Errorf("unable to Query for getServices as superuser: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	services := []service{}
	var serviceID int64
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
	var serviceID int64

	ident, err := parseNameOrID(inputID)
	if err != nil {
		return service{}, fmt.Errorf("unable to parse name or id")
	}
	if ident.isID() {
		if ad.superuser {
			err := dbPool.QueryRow(context.Background(), "SELECT name FROM services WHERE id=$1", *ident.id).Scan(&serviceName)
			if err != nil {
				return service{}, fmt.Errorf("unable to SELECT service by id for superuser")
			}
			s.Name = serviceName
			s.ID = *ident.id
		} else if ad.customerID != nil {
			err := dbPool.QueryRow(context.Background(), "SELECT services.name FROM services JOIN customers ON services.customer_id = customers.id WHERE services.id=$1 AND customers.id=$2", *ident.id, ad.customerID).Scan(&serviceName)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return service{}, errNotFound
				}
				return service{}, fmt.Errorf("unable to SELECT service by id for customer")
			}
			s.Name = serviceName
			s.ID = *ident.id
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
		} else if ad.customerID != nil {
			err := dbPool.QueryRow(context.Background(), "SELECT services.id FROM services JOIN customers ON services.customer_id = customers.id WHERE services.name=$1 AND customers.id=$2", inputID, ad.customerID).Scan(&serviceID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return service{}, errNotFound
				}
				return service{}, fmt.Errorf("unable to SELECT service by name for customer")
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
	id   *int64
}

func parseNameOrID(inputID string) (identifier, error) {
	id, err := strconv.ParseInt(inputID, 10, 64)
	if err == nil {
		// This is a numeric identifer, treat it as an ID as long as it is non-zero
		if id == 0 {
			return identifier{}, errors.New("input ID is 0")
		}
		return identifier{
			id: &id,
		}, nil
	}

	// This is not a numeric ID, treat it as a name if it is not empty
	if inputID == "" {
		return identifier{}, errors.New("input name is empty")
	}
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
		return strconv.FormatInt(*i.id, 10)
	}

	return ""
}

func insertService(dbPool *pgxpool.Pool, name string, customerNameOrID *string, ad authData) (int64, error) {
	var id int64

	var ident identifier
	var err error

	if customerNameOrID != nil {
		ident, err = parseNameOrID(*customerNameOrID)
		if err != nil {
			return 0, errUnprocessable
		}
	}

	if ad.superuser {
		if !ident.isValid() {
			return 0, errUnprocessable
		}
		if ident.isID() {
			err := dbPool.QueryRow(context.Background(), "INSERT INTO services (name, customer_id) VALUES ($1, $2) RETURNING id", name, *ident.id).Scan(&id)
			if err != nil {
				return 0, fmt.Errorf("unable to INSERT service for superuser with customer id: %w", err)
			}
		} else {
			err := dbPool.QueryRow(context.Background(), "INSERT INTO services (name, customer_id) SELECT $1, customers.id FROM customers where customers.name=$2 returning id", name, *ident.name).Scan(&id)
			if err != nil {
				return 0, fmt.Errorf("unable to INSERT service for superuser with customer name: %w", err)
			}
		}
	} else {
		if ad.customerID == nil {
			return 0, errForbidden
		}

		if ident.isValid() {
			if ident.isID() {
				if *ad.customerID != *ident.id {
					return 0, errForbidden
				}
			} else {
				if *ad.customerName != *ident.name {
					return 0, errForbidden
				}
			}
		}

		err := dbPool.QueryRow(context.Background(), "INSERT INTO services (name, customer_id) VALUES ($1, $2) RETURNING id", name, ad.customerID).Scan(&id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				// https://www.postgresql.org/docs/current/errcodes-appendix.html
				// unique_violation: 23505
				if pgErr.Code == "23505" {
					return 0, errServiceAlreadyExists
				}
			}
			return 0, fmt.Errorf("unable to INSERT service for customer with id: %w", err)
		}
	}

	return id, nil
}

func selectServiceVersions(dbPool *pgxpool.Pool, ad authData) ([]serviceVersion, error) {
	var rows pgx.Rows
	var err error
	if ad.superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT service_versions.id, service_versions.version, service_versions.active, services.name FROM service_versions JOIN services ON service_versions.service_id = services.id ORDER BY service_versions.version")
		if err != nil {
			return nil, fmt.Errorf("unable to Query for service versions as superuser: %w", err)
		}
	} else if ad.customerID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT service_versions.id, service_versions.version, service_versions.active, services.name FROM service_versions JOIN services ON service_versions.service_id = services.id WHERE services.customer_id=$1 ORDER BY service_versions.version", ad.customerID)
		if err != nil {
			return nil, fmt.Errorf("unable to Query for getServices as superuser: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	serviceVersions := []serviceVersion{}
	var id, version int64
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
			logger.Error().Msg("unable to read auth data from getCustomerHandler")
			return nil, errors.New("unable to read auth data from getCustomerHandler")
		}

		customer, err := selectUserByID(dbPool, logger, input.User, ad)
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
		resp.Body.ID = customer.ID
		resp.Body.Name = customer.Name
		return resp, nil
	})

	// We want to set a custom DefaultStatus, that is why we are not just using huma.Post().
	postUsersPath := "/api/v1/users"
	huma.Register(
		api,
		huma.Operation{
			OperationID:   huma.GenerateOperationID(http.MethodPost, postUsersPath, &customerOutput{}),
			Summary:       huma.GenerateSummary(http.MethodPost, postUsersPath, &customerOutput{}),
			Method:        http.MethodPost,
			Path:          postUsersPath,
			DefaultStatus: http.StatusCreated,
		},
		func(ctx context.Context, input *struct {
			Body struct {
				Name     string `json:"name" example:"you@example.com" doc:"The username"`
				Role     string `json:"role" example:"customer" doc:"Role ID or name"`
				Customer string `json:"customer" example:"Some name" doc:"Customer ID or name"`
				Password string `json:"password" example:"verysecret" doc:"The user password"`
			}
		},
		) (*userOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				logger.Error().Msg("unable to read auth data from getCustomerHandler")
				return nil, errors.New("unable to read auth data from getCustomerHandler")
			}

			id, err := insertUser(dbPool, input.Body.Name, input.Body.Password, input.Body.Role, input.Body.Customer, ad)
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

	huma.Get(api, "/api/v1/customers", func(ctx context.Context, _ *struct{},
	) (*customersOutput, error) {
		logger := zlog.Ctx(ctx)

		ad, ok := ctx.Value(authDataKey{}).(authData)
		if !ok {
			logger.Error().Msg("unable to read auth data from getCustomersHandler")
			return nil, errors.New("unable to read auth data from getCustomersHandler")
		}

		customers, err := selectCustomers(dbPool, logger, ad)
		if err != nil {
			if errors.Is(err, errForbidden) {
				return nil, huma.Error403Forbidden("not allowed to access resource")
			}
			logger.Err(err).Msg("unable to query customers")
			return nil, err
		}

		resp := &customersOutput{
			Body: customers,
		}
		return resp, nil
	})

	huma.Get(api, "/api/v1/customers/{customer}", func(ctx context.Context, input *struct {
		Customer string `path:"customer" example:"1" doc:"Customer ID or name"`
	},
	) (*customerOutput, error) {
		logger := zlog.Ctx(ctx)

		ad, ok := ctx.Value(authDataKey{}).(authData)
		if !ok {
			logger.Error().Msg("unable to read auth data from getCustomerHandler")
			return nil, errors.New("unable to read auth data from getCustomerHandler")
		}

		customer, err := selectCustomerByID(dbPool, logger, input.Customer, ad)
		if err != nil {
			if errors.Is(err, errForbidden) {
				return nil, huma.Error403Forbidden("not allowed to access resource")
			} else if errors.Is(err, errNotFound) {
				return nil, huma.Error404NotFound("customer not found")
			}
			logger.Err(err).Msg("unable to query customers")
			return nil, err
		}
		resp := &customerOutput{}
		resp.Body.ID = customer.ID
		resp.Body.Name = customer.Name
		return resp, nil
	})

	// We want to set a custom DefaultStatus, that is why we are not just using huma.Post().
	postCustomersPath := "/api/v1/customers"
	huma.Register(
		api,
		huma.Operation{
			OperationID:   huma.GenerateOperationID(http.MethodPost, postCustomersPath, &customerOutput{}),
			Summary:       huma.GenerateSummary(http.MethodPost, postCustomersPath, &customerOutput{}),
			Method:        http.MethodPost,
			Path:          postCustomersPath,
			DefaultStatus: http.StatusCreated,
		},
		func(ctx context.Context, input *struct {
			Body struct {
				Name string `json:"name" example:"Some name" doc:"Customer name"`
			}
		},
		) (*customerOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				logger.Error().Msg("unable to read auth data from getCustomerHandler")
				return nil, errors.New("unable to read auth data from getCustomerHandler")
			}

			id, err := insertCustomer(dbPool, input.Body.Name, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to add resource")
				}
				logger.Err(err).Msg("unable to add customer")
				return nil, err
			}
			resp := &customerOutput{}
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
			logger.Error().Msg("unable to read auth data from getCustomerHandler")
			return nil, errors.New("unable to read auth data from getCustomerHandler")
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
			logger.Error().Msg("unable to read auth data from getCustomerHandler")
			return nil, errors.New("unable to read auth data from getCustomerHandler")
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
				Name     string  `json:"name" example:"Some name" doc:"Service name"`
				Customer *string `json:"customer,omitempty" example:"Name or ID of customer" doc:"customer1"`
			}
		},
		) (*customerOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				logger.Error().Msg("unable to read auth data from getCustomerHandler")
				return nil, errors.New("unable to read auth data from getCustomerHandler")
			}

			id, err := insertService(dbPool, input.Body.Name, input.Body.Customer, ad)
			if err != nil {
				if errors.Is(err, errUnprocessable) {
					return nil, huma.Error422UnprocessableEntity("unable to parse request to add service")
				} else if errors.Is(err, errServiceAlreadyExists) {
					return nil, huma.Error400BadRequest("service already exists")
				} else if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to create this service")
				}
				logger.Err(err).Msg("unable to add service")
				return nil, err
			}
			resp := &customerOutput{}
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
			logger.Error().Msg("unable to read auth data from getServiceVersions")
			return nil, errors.New("unable to read auth data from getServiceVersions")
		}

		serviceVersions, err := selectServiceVersions(dbPool, ad)
		if err != nil {
			if errors.Is(err, errForbidden) {
				return nil, huma.Error403Forbidden("not allowed to access resource")
			}
			logger.Err(err).Msg("unable to query customers")
			return nil, err
		}

		resp := &serviceVersionsOutput{
			Body: serviceVersions,
		}
		return resp, nil
	})

	return nil
}

type user struct {
	ID        int64  `json:"id" example:"1" doc:"ID of user"`
	Name      string `json:"name" example:"user1" doc:"name of user"`
	RoleName  string `json:"role_name" example:"customer"`
	Superuser bool   `json:"superuser" example:"true" doc:"if user is a superuser"`
}

type userOutput struct {
	Body user
}

type usersOutput struct {
	Body []user
}

type customer struct {
	ID   int64  `json:"id" example:"1" doc:"ID of customer"`
	Name string `json:"name" example:"customer 1" doc:"name of customer"`
}

type customerOutput struct {
	Body customer
}

type customersOutput struct {
	Body []customer
}

type service struct {
	ID   int64  `json:"id" example:"1" doc:"ID of service"`
	Name string `json:"name" example:"service 1" doc:"name of service"`
}

type serviceOutput struct {
	Body service
}

type servicesOutput struct {
	Body []service
}

type serviceVersion struct {
	ID          int64  `json:"id"`
	Version     int64  `json:"version"`
	Active      bool   `json:"active"`
	ServiceName string `json:"service_name"`
}

type serviceVersionOutput struct {
	Body serviceVersion
}

type serviceVersionsOutput struct {
	Body []serviceVersion
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
