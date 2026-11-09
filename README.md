<p align="center">
  <img src="public/banniere.png" alt="pg_cipher banner" width="100%" />
</p>

Transparent Column Encryption for PostgreSQL, written in Rust with [pgrx].

> [!WARNING]
> This is an educational reimplementation of [The Cryptic Elephant] by Dalibo.
> It is experimental. **DO NOT USE IN PRODUCTION.**
> If you need this extension, please refer to the original project.

## Usage

```sql
CREATE EXTENSION pg_cipher;

-- Load the secret key (32 bytes, hex encoded) from a remote file...
SELECT fetch_key_from_remote_file('https://secure.server.local/secret_key.txt');

-- ...or from a local file on the server
SELECT fetch_key_from_local_file('/path/to/secret_key.txt');

-- Use TCETEXT instead of TEXT
CREATE TABLE person (
    id   SERIAL,
    name TCETEXT
);

INSERT INTO person (name) VALUES ('alice');

-- Values are decrypted on output
SELECT name FROM person;

-- Inspect the ciphertext stored on disk
SELECT raw(name) FROM person;
```

## Build

1. Install pgrx: see the [pgrx README][pgrx].

2. Build and run (pick a PostgreSQL version, e.g. `pg17`):

   ```sh
   cargo pgrx run pg17
   ```

3. Run the tests:

   ```sh
   cargo pgrx test pg17
   cargo pgrx regress pg17
   ```

## To do

- Add more types
- Automatically fetch the key when a user connects
- Substitute `TCETEXT` for the regular `TEXT` type
- Implement AES encryption instead of ChaCha20

## License

See [LICENSE](LICENSE).

[pgrx]: https://github.com/pgcentralfoundation/pgrx
[The Cryptic Elephant]: https://gitlab.com/dalibo/the_cryptic_elephant
