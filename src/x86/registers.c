#include <errno.h>
#include <linux/audit.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "../arch.h"

unsigned int arch_native_audit_arch(void)
{
    return AUDIT_ARCH_I386;
}

bool arch_get_registers(pid_t pid, Registers *out)
{
    struct user_regs_struct regs;

    memset(&regs, 0, sizeof regs);
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) return false;
    memset(out, 0, sizeof *out);

    out->audit_arch = AUDIT_ARCH_I386;
    out->nr = (unsigned long long)(unsigned int)regs.orig_eax;
    out->args[0] = (unsigned int)regs.ebx;
    out->args[1] = (unsigned int)regs.ecx;
    out->args[2] = (unsigned int)regs.edx;
    out->args[3] = (unsigned int)regs.esi;
    out->args[4] = (unsigned int)regs.edi;
    out->args[5] = (unsigned int)regs.ebp;
    out->ret = (int)regs.eax;
    return true;
}
