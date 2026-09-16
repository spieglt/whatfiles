#ifndef WF_SYSCALLS_H
#define WF_SYSCALLS_H

// The file-touching syscalls whatfiles reports, independent of architecture.
typedef enum {
    SC_NONE = 0,
    SC_OPEN, SC_OPENAT, SC_OPENAT2, SC_CREAT,
    SC_UNLINK, SC_UNLINKAT, SC_RMDIR,
    SC_MKDIR, SC_MKDIRAT,
    SC_RENAME, SC_RENAMEAT, SC_RENAMEAT2,
    SC_LINK, SC_LINKAT, SC_SYMLINK, SC_SYMLINKAT,
    SC_TRUNCATE, SC_CHMOD, SC_FCHMODAT,
    SC_CHOWN, SC_LCHOWN, SC_FCHOWNAT,
    SC_EXECVE, SC_EXECVEAT
} SyscallKind;

/*
Maps a syscall number to a kind. `audit_arch` is the ABI the tracee used, which
is not always the ABI whatfiles was built for: a 32-bit program, or any program
calling int $0x80, uses different syscall numbers on the same machine.
*/
SyscallKind syscall_classify(unsigned int audit_arch, unsigned long long nr);
const char *syscall_name(SyscallKind kind);

#endif /* !WF_SYSCALLS_H */
