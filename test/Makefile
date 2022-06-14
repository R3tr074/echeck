all: echeck_test unit_tests clean

bins:
	git clone https://github.com/R3tr074/echeck-testbins bins

echeck_test: bins

clean:
	$(MAKE) -C unit clean

unit_tests: bins
	$(MAKE) -C unit
	$(MAKE) -C unit run
