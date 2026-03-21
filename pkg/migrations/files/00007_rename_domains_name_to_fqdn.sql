-- +goose up
ALTER TABLE domains RENAME COLUMN name TO fqdn;
ALTER TABLE domains RENAME CONSTRAINT non_empty_name TO non_empty_fqdn;
ALTER TABLE domains RENAME CONSTRAINT domains_name_not_null TO domains_fqdn_not_null;
ALTER INDEX domains_name_key RENAME TO domains_fqdn_key;
