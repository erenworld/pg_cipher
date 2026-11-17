PGRX?=cargo pgrx

all: test regress

test:
		$(PGRX) test

regress:
		$(PGRX) regress
