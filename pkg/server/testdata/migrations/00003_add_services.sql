-- +goose up
INSERT INTO services (customer_id, name) SELECT id, 'customer1-service1' FROM customers WHERE name='customer1';
INSERT INTO services (customer_id, name) SELECT id, 'customer1-service2' FROM customers WHERE name='customer1';
INSERT INTO services (customer_id, name) SELECT id, 'customer1-service3' FROM customers WHERE name='customer1';
INSERT INTO services (customer_id, name) SELECT id, 'customer2-service1' FROM customers WHERE name='customer2';
INSERT INTO services (customer_id, name) SELECT id, 'customer2-service2' FROM customers WHERE name='customer2';
INSERT INTO services (customer_id, name) SELECT id, 'customer2-service3' FROM customers WHERE name='customer2';
INSERT INTO services (customer_id, name) SELECT id, 'customer3-service1' FROM customers WHERE name='customer3';
INSERT INTO services (customer_id, name) SELECT id, 'customer3-service2' FROM customers WHERE name='customer3';
INSERT INTO services (customer_id, name) SELECT id, 'customer3-service3' FROM customers WHERE name='customer3';
-- +goose down
DELETE FROM services;
