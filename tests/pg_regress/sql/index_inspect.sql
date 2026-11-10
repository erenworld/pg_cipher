BEGIN;

CREATE EXTENSION IF NOT EXISTS pg_cipher;

\! echo 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 > /tmp/chacha_key.txt

SELECT fetch_key_from_local_file('/tmp/chacha_key.txt');

-- Table with an encrypted column
CREATE TABLE person_tce (
    id SERIAL,
    name TCETEXT
);

INSERT INTO person_tce VALUES (1, 'alice');
INSERT INTO person_tce SELECT n, 'bob' FROM generate_series(2, 4) n;
CREATE INDEX ON person_tce(name);

-- Table without encryption
CREATE TABLE person_plain (
    id SERIAL,
    name TEXT
);
INSERT INTO person_plain VALUES (1, 'alice');
INSERT INTO person_plain SELECT n, 'bob' FROM generate_series(2, 1000) n;
CREATE INDEX ON person_plain(name);

CREATE EXTENSION IF NOT EXISTS pageinspect;
SAVEPOINT init;

-- Fails: the encrypted index does not contain readable text
SELECT convert_from(decode(replace(replace(data, ' 00', ''), ' ', ''), 'hex'), 'UTF8') FROM bt_page_items('person_tce_name_idx', 1);

ROLLBACK TO init;

-- The bytes stored in the index are the ciphertext returned by raw()
SELECT
    right(replace(replace(data, ' 18', ''), ' ', ''), length('alice') * 8) AS value_in_index,
        replace(raw('alice'::TCETEXT)::TEXT, '\x34', '') AS encrypted_value 
    FROM bt_page_items('person_tce_name_idx', 1)
    LIMIT 1;

-- The plain index contains the text as is
SELECT convert_from(decode(replace(replace(data, ' 00', ''), ' ', ''), 'hex'), 'UTF8') FROM bt_page_items('person_plain_name_idx', 1);

-- No plaintext in the encrypted index
SELECT bool_or(data LIKE '%61 6c 69 63 65%') AS plaintext_in_index
FROM bt_page_items('person_tce_name_idx', 1);

-- Plaintext in the plain index
SELECT bool_or(data LIKE '%61 6c 69 63 65%') AS plaintext_in_index
FROM bt_page_items('person_plain_name_idx', 1);

ROLLBACK;