// SPDX-License-Identifier: GPL-2.0
/*
 * tdx_verify - minimal TDX guest helper that exposes
 *              TDCALL[TDG.MR.VERIFYREPORT] to userspace.
 *
 * Why this module exists
 * ----------------------
 * The upstream `tdx_guest` driver only implements TDCALL[TDG.MR.REPORT]
 * (TDX_CMD_GET_REPORT0).  It deliberately does NOT expose a way to run
 * TDCALL[TDG.MR.VERIFYREPORT] (TDX module leaf 22), which is the only
 * *local* operation that can prove a TDREPORT really was produced by the
 * TDX module: it recomputes the MAC over REPORTMACSTRUCT with the
 * TDX-module/TD key and compares it with the MAC carried in the report.
 *
 * Two facts rule out the obvious alternatives:
 *
 *   1. TDCALL is a CPL0 instruction.  Executing it from ring 3 raises
 *      #GP (#UD is not used), so no userspace library can do this.
 *   2. Re-hashing the report (SHA384 over TEE_TCB_INFO / TDINFO) is only a
 *      *structural consistency* check.  It can never establish authenticity,
 *      because an attacker who fabricates a report can recompute those
 *      hashes too.  Only the TDX-module-held MAC key can do that.
 *
 * So this module runs the TDCALL in ring 0 - and nothing else.
 *
 * Interface
 * ---------
 *   /dev/tdx_verify  (0600, root only)
 *   ioctl(fd, TDX_VERIFY_REPORT, struct tdx_verify_request *)
 *
 * The struct carries the 1024-byte report in and the raw TDX module return
 * code out.  A return code of 0 (TDX_SUCCESS) means "the TDX module confirms
 * that this REPORTMACSTRUCT is authentic".  Every other value means it is
 * not.  The ioctl itself only fails for transport problems (bad pointer,
 * unknown command, ENOMEM); a *failed verification* is reported through
 * @status, not through errno, so callers cannot confuse the two.
 *
 * The report buffer is a single page obtained from the page allocator, so it
 * lives in the direct map: it is physically contiguous, page aligned and
 * never migrated, which makes virt_to_phys() a stable source for the GPA the
 * TDCALL needs.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <asm/cpufeature.h>
#include <asm/io.h>

#include "tdx_verify_uapi.h"

/* TDX module leaf for TDG.MR.VERIFYREPORT (TDX 1.5, GHCI "Module Call Leaves"). */
#define TDG_MR_VERIFYREPORT	22ULL

/* TDCALL success.  Any other value is a TDX module error code. */
#define TDX_SUCCESS		0ULL

/*
 * Issue TDCALL[TDG.MR.VERIFYREPORT] for the TDREPORT at @gpa.
 *
 * Input : RCX = guest physical address of the 1024-byte TDREPORT.
 * Output: RAX = TDX module return code (0 == MAC verified).
 *
 * Only the "common core" registers (RAX, RCX, RDX, R8-R11) are declared as
 * clobbered.  The TDX module is required to preserve the callee-saved
 * registers (RBX, RBP, RDI, RSI, R12-R15) for leaves that do not use them,
 * and leaf 22 uses none of them - this mirrors what the kernel's own
 * TDX_MODULE_CALL macro does for non-`saved` leaves.
 */
static noinline u64 tdx_mcall_verify_report(u64 gpa)
{
	register u64 rax asm("rax") = TDG_MR_VERIFYREPORT;
	register u64 rcx asm("rcx") = gpa;
	register u64 rdx asm("rdx");
	register u64 r8 asm("r8");
	register u64 r9 asm("r9");
	register u64 r10 asm("r10");
	register u64 r11 asm("r11");

	asm volatile("tdcall"
		     : "+r"(rax), "+r"(rcx), "+r"(rdx), "+r"(r8),
		       "+r"(r9), "+r"(r10), "+r"(r11)
		     :
		     : "memory");

	return rax;
}

static long tdx_verify_ioctl(struct file *filp, unsigned int cmd,
			     unsigned long arg)
{
	struct tdx_verify_request __user *ureq =
		(struct tdx_verify_request __user *)arg;
	unsigned long kbuf;
	u64 status;
	long ret = 0;

	if (cmd != TDX_VERIFY_REPORT)
		return -ENOTTY;

	if (!ureq)
		return -EFAULT;

	/*
	 * A whole page: page aligned, physically contiguous, direct mapped and
	 * not migratable.  virt_to_phys() below is therefore stable for the
	 * entire duration of the TDCALL.
	 */
	kbuf = __get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user((void *)kbuf, ureq->report, TDX_VERIFY_REPORT_LEN)) {
		ret = -EFAULT;
		goto out;
	}

	status = tdx_mcall_verify_report(virt_to_phys((void *)kbuf));

	/* Report the *verification outcome*, never fold it into errno. */
	if (put_user(status, &ureq->status))
		ret = -EFAULT;

out:
	free_page(kbuf);
	return ret;
}

static const struct file_operations tdx_verify_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= tdx_verify_ioctl,
	.llseek		= no_llseek,
};

static struct miscdevice tdx_verify_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "tdx_verify",
	.fops	= &tdx_verify_fops,
	.mode	= 0600,
};

static int __init tdx_verify_init(void)
{
	int ret;

	/*
	 * Refuse to load where TDCALL is unavailable.  On a non-TDX machine
	 * TDCALL raises #UD and would take the kernel down, so this check is
	 * not optional.
	 */
	if (!cpu_feature_enabled(X86_FEATURE_TDX_GUEST)) {
		pr_err("tdx_verify: not running as a TDX guest, refusing to load\n");
		return -ENODEV;
	}

	ret = misc_register(&tdx_verify_dev);
	if (ret) {
		pr_err("tdx_verify: misc_register failed: %d\n", ret);
		return ret;
	}

	pr_info("tdx_verify: ready, backend=TDCALL[TDG.MR.VERIFYREPORT] leaf=%llu\n",
		TDG_MR_VERIFYREPORT);
	return 0;
}

static void __exit tdx_verify_exit(void)
{
	misc_deregister(&tdx_verify_dev);
	pr_info("tdx_verify: unloaded\n");
}

module_init(tdx_verify_init);
module_exit(tdx_verify_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TDX attestation service");
MODULE_DESCRIPTION("Expose TDCALL[TDG.MR.VERIFYREPORT] to userspace");
MODULE_ALIAS_MISCDEV(MISC_DYNAMIC_MINOR);
