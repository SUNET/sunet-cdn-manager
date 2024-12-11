package migrations

import (
	"context"
	"database/sql"
	"io/ioutil"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pressly/goose/v3"
)

type vclRcv struct {
	id               string
	file             string
	serviceVersionID string
}

func init() {
	goose.AddMigrationContext(upAddVclRcv, downAddVclRcv)
}

func upAddVclRcv(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is applied.

	vclRcvs := []vclRcv{
		{
			id:               "00000000-0000-0000-0000-000000000028",
			serviceVersionID: "00000000-0000-0000-0000-000000000015",
			file:             "testdata/vcl/vcl_recv/content1.vcl",
		},
	}

	for _, vclRcv := range vclRcvs {
		var vclID, serviceVersionID pgtype.UUID
		err := vclID.Scan(vclRcv.id)
		if err != nil {
			return err
		}

		err = serviceVersionID.Scan(vclRcv.serviceVersionID)
		if err != nil {
			return err
		}

		contentBytes, err := ioutil.ReadFile(vclRcv.file)
		if err != nil {
			return err
		}

		_, err = tx.Exec("INSERT INTO service_vcl_recv (id, service_version_id, content) VALUES($1, $2, $3)", vclID, serviceVersionID, contentBytes)
		if err != nil {
			return err
		}
	}
	return nil
}

func downAddVclRcv(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is rolled back.
	return nil
}
