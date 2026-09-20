/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace ABI of the `tdx_verify` helper module.
 *
 * The module exposes exactly one operation: hardware verification of a TDX
 * TDREPORT via `TDCALL[TDG.MR.VERIFYREPORT]` (TDX module leaf 22).
 */

#ifndef _TDX_VERIFY_UAPI_H
#define _TDX_VERIFY_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

/* Length of a TDREPORT as returned by TDCALL[TDG.MR.REPORT]. */
#define TDX_VERIFY_REPORT_LEN	1024

/**
 * struct tdx_verify_request - request/response of TDX_VERIFY_REPORT.
 *
 * @report: Input. The 1024 byte TDREPORT whose REPORTMACSTRUCT.MAC has to be
 *          checked by the TDX module.
 * @status: Output. The raw return code of the TDCALL. 0 (TDX_SUCCESS) means
 *          the TDX module confirmed that the report was produced by it, i.e.
 *          that the MAC over REPORTMACSTRUCT is valid. Any other value is a
 *          TDX module error code and means the report was NOT verified.
 */
struct tdx_verify_request {
	__u8 report[TDX_VERIFY_REPORT_LEN];
	__u64 status;
};

/*
 * TDX_VERIFY_REPORT - verify a TDREPORT with TDG.MR.VERIFYREPORT.
 *
 * Return 0 when the request was processed (inspect @status for the outcome),
 * -EFAULT on a bad userspace pointer, -ENOTTY for an unknown command and
 * -ENOMEM when the kernel buffer could not be allocated.
 */
#define TDX_VERIFY_REPORT	_IOWR('T', 2, struct tdx_verify_request)

#endif /* _TDX_VERIFY_UAPI_H */
