#include <errno.h>
#include <linux/audit.h>
#include <linux/elf.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>   /* struct user_pt_regs */
#include <sys/uio.h>
#include <sys/user.h>

#include "../arch.h"

#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif

/*
A 32-bit process on an arm64 kernel reports its registers as 18 32-bit words:
r0 through r15, then CPSR, then the original r0. A 64-bit process reports
struct user_pt_regs instead, and the two are told apart by the length the
kernel fills in.
*/
#define COMPAT_NGREG   18
#define COMPAT_R7      7
#define COMPAT_ORIG_R0 17

unsigned int arch_native_audit_arch(void)
{
    return AUDIT_ARCH_AARCH64;
}

bool arch_get_registers(pid_t pid, Registers *out)
{
    union {
        struct user_pt_regs regs64;
        uint32_t regs32[COMPAT_NGREG];
    } regs;
    struct iovec regs_vec = { &regs, sizeof regs };
    int syscall_nr = -1;
    struct iovec nr_vec = { &syscall_nr, sizeof syscall_nr };
    bool have_nr;

    memset(&regs, 0, sizeof regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &regs_vec) == -1) return false;
    memset(out, 0, sizeof *out);

    // x8 holds the syscall number only on the way in; the kernel keeps the
    // authoritative copy in a register set of its own, for 32-bit tasks too.
    have_nr = ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_ARM_SYSTEM_CALL, &nr_vec) == 0;

    if (regs_vec.iov_len == sizeof regs.regs32) {
        // 32-bit process: arm32 syscall numbers and argument registers.
        out->audit_arch = AUDIT_ARCH_ARM;
        out->nr = have_nr ? (unsigned long long)(unsigned int)syscall_nr : regs.regs32[COMPAT_R7];
        out->args[0] = regs.regs32[COMPAT_ORIG_R0];
        for (int i = 1; i < 6; i++) out->args[i] = regs.regs32[i];
        out->ret = (long long)(int32_t)regs.regs32[0];
        return true;
    }

    out->audit_arch = AUDIT_ARCH_AARCH64;
    out->nr = have_nr ? (unsigned long long)(unsigned int)syscall_nr : regs.regs64.regs[8];
    // x0 becomes the return value at syscall exit, which is why callers record
    // the arguments when the syscall is entered.
    for (int i = 0; i < 6; i++) out->args[i] = regs.regs64.regs[i];
    out->ret = (long long)regs.regs64.regs[0];
    return true;
}
