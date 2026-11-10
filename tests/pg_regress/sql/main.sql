BEGIN;

CREATE EXTENSION IF NOT EXISTS pg_cipher;

\! echo 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 > /tmp/chacha_key.txt

SAVEPOINT START;

SELECT 'test'::TCETEXT;

ROLLBACK TO start;

SELECT fetch_key_from_local_file('/tmp/chacha_key.txt');

SELECT 'test'::TCETEXT;

SELECT raw('test'::TCETEXT);

CREATE TABLE person (
    id SERIAL,
    name TCETEXT
);

INSERT INTO person VALUES (1, 'alice');

INSERT INTO person SELECT n, 'bob' FROM generate_series(2,1000) n;

CREATE INDEX ON person(name);

SELECT * FROM person ORDER BY name ASC LIMIT 2;

SELECT * FROM person WHERE name='alice';

ROLLBACK;
