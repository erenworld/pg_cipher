BEGIN;

-- Given a classic table
CREATE TABLE person (
    id SERIAL,
    firstname TEXT
);

INSERT INTO person VALUES (1, 'alice'), (2, 'bob');

CREATE EXTENSION IF NOT EXISTS pg_cipher;

-- Load the secret key
\! echo 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 > /tmp/chacha_key.txt

SELECT fetch_key_from_local_file('/tmp/chacha_key.txt');

-- Convert column into an encrypted column
ALTER TABLE person ALTER COLUMN firstname TYPE TCETEXT USING firstname::TCETEXT;

SELECT firstname, raw(firstname) FROM person;

-- Back to plain text
ALTER TABLE person ALTER COLUMN firstname TYPE VARCHAR(100);

SELECT firstname FROM person;

ROLLBACK;