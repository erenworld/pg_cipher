PGRX?=cargo pgrx
PGVER?=pg17
REGRESS_LOG?=/tmp/pg_cipher_regression.log

all: lint test regress

test:
		$(PGRX) test

regress:
		$(PGRX) regress $(PGVER) --resetdb 2>&1 | tee $(REGRESS_LOG)
		grep -q 'failed=0' $(REGRESS_LOG)

lint:
		cargo clippy --all-targets -- -D warnings

.PHONY: all test regress lint