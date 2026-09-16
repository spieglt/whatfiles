#include <errno.h>
#include <linux/audit.h>
#include <string.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/user.h>

#include "../arch.h"

unsigned int arch_native_audit_arch(void)
{
    return AUDIT_ARCH_ARM;
}

bool arch_get_registers(pid_t pid, Registers *out)
{
    struct pt_regs regs;

    memset(&regs, 0, sizeof regs);
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) return false;
    memset(out, 0, sizeof *out);

    out->audit_arch = AUDIT_ARCH_ARM;
    out->nr = (unsigned long long)regs.ARM_r7;
    // ARM_r0 holds the return value once the syscall is done, so the first
    // argument is taken from the copy the kernel keeps of its original value.
    out->args[0] = (unsigned long long)regs.ARM_ORIG_r0;
    out->args[1] = (unsigned long long)regs.ARM_r1;
    out->args[2] = (unsigned long long)regs.ARM_r2;
    out->args[3] = (unsigned long long)regs.ARM_r3;
    out->args[4] = (unsigned long long)regs.ARM_r4;
    out->args[5] = (unsigned long long)regs.ARM_r5;
    out->ret = (long long)(long)regs.ARM_r0;
    return true;
}
