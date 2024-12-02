package migrations

import (
	"context"
	"crypto/rand"
	"database/sql"

	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/argon2"
)

type localUser struct {
	name       string
	password   string
	customerID *int64
	role       string
	superuser  bool
}

func init() {
	goose.AddMigrationContext(upAddTestusers, downAddTestusers)
}

func int64Ptr(i int64) *int64 {
	return &i
}

func upAddTestusers(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is applied.

	localUsers := []localUser{
		{
			name:     "admin",
			password: "adminpass1",
			role:     "admin",
		},
		{
			name:       "username1",
			password:   "password1",
			role:       "customer",
			customerID: int64Ptr(1),
		},
		{
			name:       "username2",
			password:   "password2",
			role:       "customer",
			customerID: int64Ptr(2),
		},
		{
			name:     "username3-no-customer",
			password: "password3",
			role:     "customer",
		},
	}

	for _, localUser := range localUsers {
		var userID int64
		err := tx.QueryRow("INSERT INTO users (customer_id, name, role_id) SELECT $1, $2, id FROM roles WHERE name=$3 RETURNING id", localUser.customerID, localUser.name, localUser.role).Scan(&userID)
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
