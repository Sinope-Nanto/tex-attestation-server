# TDX attestation web service - convenience targets.
#
#   make            # build everything (Rust service + hardware test)
#   make kmod       # build and load the TDG.MR.VERIFYREPORT helper module
#   make test       # run every suite: hardware, unit, web (curl)
#   make test-hw    # TDX hardware test (/dev/tdx_guest + /dev/tdx_verify)
#   make test-unit  # cargo unit/integration tests
#   make test-web   # end-to-end curl test of the running service
#   make clean

CARGO ?= cargo
CC    ?= cc

WEB_BASE_URL ?= http://127.0.0.1:8080

.PHONY: all build test test-hw test-unit test-web test-tpm test-tpm-web kmod kmod-load clean

all: build

build:
	$(CC) -O2 -Wall -Wextra -o tests/test_tdx_hardware tests/test_tdx_hardware.c
	$(CARGO) build

# Hardware test: get_report + TDG.MR.VERIFYREPORT, incl. tamper detection.
test-hw:
	$(CC) -O2 -Wall -Wextra -o tests/test_tdx_hardware tests/test_tdx_hardware.c
	./tests/test_tdx_hardware

# Unit / integration tests (real TDX hardware required for the attestation ones).
test-unit:
	$(CARGO) test

# End-to-end HTTP test driven with curl(1).
test-web:
	WEB_BASE_URL=$(WEB_BASE_URL) bash tests/test_web_curl.sh

# Real TPM 2.0 simulator integration test (starts tpm-simu if needed).
test-tpm:
	bash tests/test_tpm_integration.sh

# curl(1) end-to-end test of the TPM and combined attestation endpoints.
test-tpm-web:
	WEB_BASE_URL=$(WEB_BASE_URL) bash tests/test_tpm_web.sh

test: test-hw test-unit test-web test-tpm test-tpm-web

# Helper kernel module: TDG.MR.VERIFYREPORT (TDX module leaf 22) for userspace.
kmod:
	$(MAKE) -C kmod

kmod-load: kmod
	$(MAKE) -C kmod load

clean:
	$(CARGO) clean
	rm -f tests/test_tdx_hardware
	-$(MAKE) -C kmod clean
