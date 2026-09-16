#include <errno.h>
#include <linux/audit.h>
#include <linux/elf.h>
#include <string.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>   /* struct user_pt_regs */
#include <sys/uio.h>
#include <sys/user.h>

#include "../arch.h"

#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif

unsigned int arch_native_audit_arch(void)
{
    return AUDIT_ARCH_AARCH64;
}

bool arch_get_registers(pid_t pid, Registers *out)
{
    struct user_pt_regs regs;
    struct iovec regs_vec = { &regs, sizeof regs };
    int syscall_nr = -1;
    struct iovec nr_vec = { &syscall_nr, sizeof syscall_nr };

    memset(&regs, 0, sizeof regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &regs_vec) == -1) return false;
    memset(out, 0, sizeof *out);

    out->audit_arch = AUDIT_ARCH_AARCH64;
    // x8 holds the syscall number only on the way in; the kernel keeps the
    // authoritative copy in its own register set.
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_ARM_SYSTEM_CALL, &nr_vec) == 0) {
        out->nr = (unsigned long long)(unsigned int)syscall_nr;
    } else {
        out->nr = regs.regs[8];
    }
    // x0 becomes the return value at syscall exit, which is why callers record
    // the arguments when the syscall is entered.
    for (int i = 0; i < 6; i++) out->args[i] = regs.regs[i];
    out->ret = (long long)regs.regs[0];
    return true;
}
