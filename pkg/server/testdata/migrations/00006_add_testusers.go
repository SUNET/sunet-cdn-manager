package migrations

import (
	"context"
	"crypto/rand"
	"database/sql"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/argon2"
)

type localUser struct {
	name      string
	password  string
	orgName   string
	role      string
	superuser bool
	id        string
}

func init() {
	goose.AddMigrationContext(upAddTestusers, downAddTestusers)
}

func strPtr(s string) *string {
	return &s
}

func upAddTestusers(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is applied.

	localUsers := []localUser{
		{
			name:     "admin",
			password: "adminpass1",
			role:     "admin",
			id:       "00000006-0000-0000-0000-000000000001",
		},
		{
			name:     "username1",
			password: "password1",
			role:     "customer",
			orgName:  "org1",
			id:       "00000006-0000-0000-0000-000000000002",
		},
		{
			name:     "username2",
			password: "password2",
			role:     "customer",
			orgName:  "org2",
			id:       "00000006-0000-0000-0000-000000000003",
		},
		{
			name:     "username3-no-org",
			password: "password3",
			role:     "customer",
			id:       "00000006-0000-0000-0000-000000000004",
		},
	}

	for _, localUser := range localUsers {
		var userID pgtype.UUID
		err := userID.Scan(localUser.id)
		if err != nil {
			return err
		}

		var orgID *pgtype.UUID // may be nil

		if localUser.orgName != "" {
			err := tx.QueryRow("SELECT id FROM organizations WHERE name=$1", localUser.orgName).Scan(&orgID)
			if err != nil {
				return err
			}
		}

		_, err = tx.Exec("INSERT INTO users (id, org_id, name, role_id) SELECT $1, $2, $3, id FROM roles WHERE name=$4", userID, orgID, localUser.name, localUser.role)
		if err != nil {
			return err
		}

		// Generate 16 byte (128 bit) salt as
		// recommended for argon2 in RFC 9106
		salt := make([]byte, 16)
		_, err = rand.Read(salt)
		if err != nil {
			return err
		}

		timeSize := uint32(1)
		memorySize := uint32(64 * 1024)
		threads := uint8(4)
		tagSize := uint32(32)

		key := argon2.IDKey([]byte(localUser.password), salt, timeSize, memorySize, threads, tagSize)
		_, err = tx.Exec("INSERT INTO user_argon2keys (user_id, key, salt, time, memory, threads, tag_size) VALUES ($1, $2, $3, $4, $5, $6, $7)", userID, key, salt, timeSize, memorySize, threads, tagSize)
		if err != nil {
			return err
		}
	}
	return nil
}

func downAddTestusers(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is rolled back.
	return nil
}
