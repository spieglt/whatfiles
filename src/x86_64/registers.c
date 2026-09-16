#include <errno.h>
#include <linux/audit.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "../arch.h"

unsigned int arch_native_audit_arch(void)
{
    return AUDIT_ARCH_X86_64;
}

bool arch_get_registers(pid_t pid, Registers *out)
{
    struct user_regs_struct regs;

    memset(&regs, 0, sizeof regs);
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) return false;
    memset(out, 0, sizeof *out);

    if (regs.cs == 0x23) {
        // A 32-bit process: different syscall numbers, different argument
        // registers. (Kernels 5.3 and newer report this through
        // PTRACE_GET_SYSCALL_INFO, which is more reliable than the code segment.)
        out->audit_arch = AUDIT_ARCH_I386;
        out->nr = (unsigned int)regs.orig_rax;
        out->args[0] = (unsigned int)regs.rbx;
        out->args[1] = (unsigned int)regs.rcx;
        out->args[2] = (unsigned int)regs.rdx;
        out->args[3] = (unsigned int)regs.rsi;
        out->args[4] = (unsigned int)regs.rdi;
        out->args[5] = (unsigned int)regs.rbp;
        out->ret = (int)regs.rax;
    } else {
        out->audit_arch = AUDIT_ARCH_X86_64;
        out->nr = regs.orig_rax;
        out->args[0] = regs.rdi;
        out->args[1] = regs.rsi;
        out->args[2] = regs.rdx;
        out->args[3] = regs.r10;
        out->args[4] = regs.r8;
        out->args[5] = regs.r9;
        out->ret = (long long)regs.rax;
    }
    return true;
}
