#ifndef WF_ARCH_H
#define WF_ARCH_H

#include <stdbool.h>
#include <sys/types.h>

/*
Register state of a tracee at a syscall stop, normalized across architectures.
`args` are only meaningful at syscall entry: several architectures overwrite the
first argument register with the return value, which is why callers snapshot
them at entry instead of re-reading at exit.
*/
typedef struct {
    unsigned int audit_arch;   // AUDIT_ARCH_* of the syscall's ABI
    unsigned long long nr;     // syscall number in that ABI
    unsigned long long args[6];
    long long ret;             // return value (valid at syscall exit)
} Registers;

unsigned int arch_native_audit_arch(void);
bool arch_get_registers(pid_t pid, Registers *regs);

#endif /* !WF_ARCH_H */
