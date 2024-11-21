-- +goose up
INSERT INTO customers (name) VALUES ('customer1');
INSERT INTO customers (name) VALUES ('customer2');
INSERT INTO customers (name) VALUES ('customer3');
-- +goose down
DELETE FROM customers;
