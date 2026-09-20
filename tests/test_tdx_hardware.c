// SPDX-License-Identifier: MIT
//
// Hardware test for the TDX attestation backends.
//
// Exercises the two real TDX hardware operations the service relies on:
//
//   * TDREPORT generation through /dev/tdx_guest (TDX_CMD_GET_REPORT0),
//     which the kernel forwards to TDCALL[TDG.MR.REPORT].
//   * TDREPORT verification through /dev/tdx_verify (TDX_VERIFY_REPORT),
//     which the helper module forwards to TDCALL[TDG.MR.VERIFYREPORT]
//     (TDX module leaf 22).
//
// The third and most important case proves that the verifier is really
// talking to the TDX module: a report whose REPORTMACSTRUCT has been altered
// by a single bit must be rejected.
//
// Exit code 0 only if every check passed.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define TDX_REPORTDATA_LEN 64
#define TDX_REPORT_LEN 1024

/* Offset of REPORTDATA inside TDREPORT_STRUCT.REPORTMACSTRUCT. */
#define TDREPORT_REPORTDATA_OFF 0x80

/* TDREPORT_STRUCT.REPORTMACSTRUCT.MAC, 32 bytes. Covered by the TDX MAC. */
#define TDREPORT_MAC_OFF 0xE0

struct tdx_report_req {
	uint8_t reportdata[TDX_REPORTDATA_LEN];
	uint8_t tdreport[TDX_REPORT_LEN];
};

#define TDX_CMD_GET_REPORT0 _IOWR('T', 1, struct tdx_report_req)

struct tdx_verify_request {
	uint8_t report[TDX_REPORT_LEN];
	uint64_t status;
};

#define TDX_VERIFY_REPORT _IOWR('T', 2, struct tdx_verify_request)

#define TDX_SUCCESS 0ULL

static int g_fails;

static void ok(const char *what)
{
	printf("  [PASS] %s\n", what);
}

static void fail(const char *what, const char *detail)
{
	printf("  [FAIL] %s%s%s\n", what, detail ? ": " : "",
	       detail ? detail : "");
	g_fails++;
}

/* Generate a TDREPORT bound to @rn (exactly 64 bytes). */
static int get_report(const uint8_t rn[TDX_REPORTDATA_LEN],
		      uint8_t out[TDX_REPORT_LEN], char *err, size_t errlen)
{
	struct tdx_report_req req;
	int fd;

	fd = open("/dev/tdx_guest", O_RDWR);
	if (fd < 0) {
		snprintf(err, errlen, "open /dev/tdx_guest: %s", strerror(errno));
		return -1;
	}

	memcpy(req.reportdata, rn, TDX_REPORTDATA_LEN);
	memset(req.tdreport, 0, TDX_REPORT_LEN);

	if (ioctl(fd, TDX_CMD_GET_REPORT0, &req) < 0) {
		snprintf(err, errlen, "ioctl TDX_CMD_GET_REPORT0: %s",
			 strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);
	memcpy(out, req.tdreport, TDX_REPORT_LEN);
	return 0;
}

/*
 * Verify a TDREPORT with TDCALL[TDG.MR.VERIFYREPORT] via /dev/tdx_verify.
 *
 * Returns 0 when the TDX module reports success (MAC valid), non-zero when
 * the report was rejected.  @err is filled in for transport failures.
 */
static int verify_report_hw(const uint8_t report[TDX_REPORT_LEN],
			    uint64_t *status_out, char *err, size_t errlen)
{
	struct tdx_verify_request req;
	int fd;

	fd = open("/dev/tdx_verify", O_RDWR);
	if (fd < 0) {
		snprintf(err, errlen, "open /dev/tdx_verify: %s", strerror(errno));
		return -1;
	}

	memcpy(req.report, report, TDX_REPORT_LEN);
	req.status = (uint64_t)-1;

	if (ioctl(fd, TDX_VERIFY_REPORT, &req) < 0) {
		snprintf(err, errlen, "ioctl TDX_VERIFY_REPORT: %s",
			 strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);
	if (status_out)
		*status_out = req.status;
	return req.status == TDX_SUCCESS ? 0 : 1;
}

int main(void)
{
	uint8_t rn[TDX_REPORTDATA_LEN];
	uint8_t report[TDX_REPORT_LEN];
	uint8_t report2[TDX_REPORT_LEN];
	uint8_t tampered[TDX_REPORT_LEN];
	uint64_t status = 0;
	char err[256] = {0};
	int i, rc;

	setvbuf(stdout, NULL, _IONBF, 0);

	printf("backend=TDG.MR.VERIFYREPORT\n");
	printf("leaf=22\n\n");

	/* --- test 1: get_report_success ------------------------------- */
	printf("get_report_success\n");

	for (i = 0; i < TDX_REPORTDATA_LEN; i++)
		rn[i] = (uint8_t)(i * 7 + 3);

	if (get_report(rn, report, err, sizeof(err)) != 0) {
		fail("get_report()", err);
		printf("\nhardware test: FAILED\n");
		return 1;
	}

	if (memcmp(report + TDREPORT_REPORTDATA_OFF, rn, TDX_REPORTDATA_LEN) == 0)
		ok("report[0x80..0xc0] == REPORTDATA");
	else
		fail("REPORTDATA not echoed at offset 0x80", NULL);

	printf("\nverify_fresh_report_success\n");
	rc = verify_report_hw(report, &status, err, sizeof(err));
	if (rc < 0) {
		fail("hardware verify unavailable", err);
		printf("\nhardware test: BLOCKED\n");
		return 2;
	}
	if (rc == 0) {
		printf("  TDX module status = 0x%llx\n",
		       (unsigned long long)status);
		ok("fresh report verification: PASS");
	} else {
		printf("  TDX module status = 0x%llx\n",
		       (unsigned long long)status);
		fail("fresh report verification", "rejected by TDX module");
	}

	/* --- test 3: verify_tampered_report_fails --------------------- */
	printf("\nverify_tampered_report_fails\n");

	memcpy(tampered, report, TDX_REPORT_LEN);
	tampered[TDREPORT_REPORTDATA_OFF] ^= 0x01;
	rc = verify_report_hw(tampered, &status, err, sizeof(err));
	if (rc < 0) {
		fail("hardware verify unavailable", err);
		printf("\nhardware test: BLOCKED\n");
		return 2;
	}
	if (rc != 0) {
		printf("  TDX module status = 0x%llx\n",
		       (unsigned long long)status);
		ok("REPORTDATA bit-flip rejected");
	} else {
		fail("tampered REPORTDATA was accepted", NULL);
	}

	/* A bit flip in the MAC itself must be rejected too. */
	memcpy(tampered, report, TDX_REPORT_LEN);
	tampered[TDREPORT_MAC_OFF] ^= 0x01;
	rc = verify_report_hw(tampered, &status, err, sizeof(err));
	if (rc < 0) {
		fail("hardware verify unavailable", err);
		printf("\nhardware test: BLOCKED\n");
		return 2;
	}
	if (rc != 0) {
		printf("  TDX module status = 0x%llx\n",
		       (unsigned long long)status);
		ok("MAC bit-flip rejected");
	} else {
		fail("tampered MAC was accepted", NULL);
	}

	/*
	 * Freshness: a second report for different REPORTDATA must also
	 * verify, and must differ from the first one in REPORTDATA.
	 */
	printf("\nfresh_report_is_not_replayed\n");
	rn[0] ^= 0xff;
	if (get_report(rn, report2, err, sizeof(err)) != 0) {
		fail("second get_report()", err);
	} else if (memcmp(report2 + TDREPORT_REPORTDATA_OFF, rn,
			 TDX_REPORTDATA_LEN) != 0) {
		fail("second REPORTDATA mismatch", NULL);
	} else {
		rc = verify_report_hw(report2, &status, err, sizeof(err));
		if (rc == 0)
			ok("second report verification: PASS");
		else
			fail("second report verification", "rejected");
	}

	if (g_fails) {
		printf("\nhardware test: FAILED (%d check(s))\n", g_fails);
		return 1;
	}

	printf("\nhardware test: PASSED\n");
	return 0;
}
