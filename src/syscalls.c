#include <linux/audit.h>
#include <stddef.h>
#include <sys/syscall.h>

#include "arch.h"
#include "syscalls.h"

typedef struct {
    unsigned long long nr;
    SyscallKind kind;
} SyscallEntry;

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

// Syscall numbers of the ABI whatfiles was built for. Entries missing on an
// architecture (arm64 has no open(), for example) drop out with the #ifdefs.
static const SyscallEntry native_table[] = {
#ifdef SYS_open
    { SYS_open, SC_OPEN },
#endif
#ifdef SYS_openat
    { SYS_openat, SC_OPENAT },
#endif
#ifdef SYS_openat2
    { SYS_openat2, SC_OPENAT2 },
#else
    { 437, SC_OPENAT2 },
#endif
#ifdef SYS_creat
    { SYS_creat, SC_CREAT },
#endif
#ifdef SYS_unlink
    { SYS_unlink, SC_UNLINK },
#endif
#ifdef SYS_unlinkat
    { SYS_unlinkat, SC_UNLINKAT },
#endif
#ifdef SYS_rmdir
    { SYS_rmdir, SC_RMDIR },
#endif
#ifdef SYS_mkdir
    { SYS_mkdir, SC_MKDIR },
#endif
#ifdef SYS_mkdirat
    { SYS_mkdirat, SC_MKDIRAT },
#endif
#ifdef SYS_rename
    { SYS_rename, SC_RENAME },
#endif
#ifdef SYS_renameat
    { SYS_renameat, SC_RENAMEAT },
#endif
#ifdef SYS_renameat2
    { SYS_renameat2, SC_RENAMEAT2 },
#endif
#ifdef SYS_link
    { SYS_link, SC_LINK },
#endif
#ifdef SYS_linkat
    { SYS_linkat, SC_LINKAT },
#endif
#ifdef SYS_symlink
    { SYS_symlink, SC_SYMLINK },
#endif
#ifdef SYS_symlinkat
    { SYS_symlinkat, SC_SYMLINKAT },
#endif
#ifdef SYS_truncate
    { SYS_truncate, SC_TRUNCATE },
#endif
#ifdef SYS_truncate64
    { SYS_truncate64, SC_TRUNCATE },
#endif
#ifdef SYS_chmod
    { SYS_chmod, SC_CHMOD },
#endif
#ifdef SYS_fchmodat
    { SYS_fchmodat, SC_FCHMODAT },
#endif
#ifdef SYS_chown
    { SYS_chown, SC_CHOWN },
#endif
#ifdef SYS_chown32
    { SYS_chown32, SC_CHOWN },
#endif
#ifdef SYS_lchown
    { SYS_lchown, SC_LCHOWN },
#endif
#ifdef SYS_lchown32
    { SYS_lchown32, SC_LCHOWN },
#endif
#ifdef SYS_fchownat
    { SYS_fchownat, SC_FCHOWNAT },
#endif
#ifdef SYS_execve
    { SYS_execve, SC_EXECVE },
#endif
#ifdef SYS_execveat
    { SYS_execveat, SC_EXECVEAT },
#endif
};

#if defined(__x86_64__)
#define WF_HAVE_COMPAT_TABLE 1
#define WF_COMPAT_AUDIT_ARCH AUDIT_ARCH_I386
// i386 syscall numbers, used by 32-bit programs and by any program that enters
// the kernel through int $0x80 on an x86-64 machine.
static const SyscallEntry compat_table[] = {
    { 5, SC_OPEN },        { 295, SC_OPENAT },    { 437, SC_OPENAT2 },
    { 8, SC_CREAT },       { 10, SC_UNLINK },     { 301, SC_UNLINKAT },
    { 40, SC_RMDIR },      { 39, SC_MKDIR },      { 296, SC_MKDIRAT },
    { 38, SC_RENAME },     { 302, SC_RENAMEAT },  { 353, SC_RENAMEAT2 },
    { 9, SC_LINK },        { 303, SC_LINKAT },    { 83, SC_SYMLINK },
    { 304, SC_SYMLINKAT }, { 92, SC_TRUNCATE },   { 193, SC_TRUNCATE },
    { 15, SC_CHMOD },      { 306, SC_FCHMODAT },  { 182, SC_CHOWN },
    { 212, SC_CHOWN },     { 16, SC_LCHOWN },     { 198, SC_LCHOWN },
    { 298, SC_FCHOWNAT },  { 11, SC_EXECVE },     { 358, SC_EXECVEAT },
};
#elif defined(__aarch64__)
#define WF_HAVE_COMPAT_TABLE 1
#define WF_COMPAT_AUDIT_ARCH AUDIT_ARCH_ARM
// arm32 (EABI) syscall numbers, used by 32-bit programs on an arm64 machine.
static const SyscallEntry compat_table[] = {
    { 5, SC_OPEN },        { 322, SC_OPENAT },    { 437, SC_OPENAT2 },
    { 8, SC_CREAT },       { 10, SC_UNLINK },     { 328, SC_UNLINKAT },
    { 40, SC_RMDIR },      { 39, SC_MKDIR },      { 323, SC_MKDIRAT },
    { 38, SC_RENAME },     { 329, SC_RENAMEAT },  { 382, SC_RENAMEAT2 },
    { 9, SC_LINK },        { 330, SC_LINKAT },    { 83, SC_SYMLINK },
    { 331, SC_SYMLINKAT }, { 92, SC_TRUNCATE },   { 193, SC_TRUNCATE },
    { 15, SC_CHMOD },      { 333, SC_FCHMODAT },  { 182, SC_CHOWN },
    { 212, SC_CHOWN },     { 16, SC_LCHOWN },     { 198, SC_LCHOWN },
    { 325, SC_FCHOWNAT },  { 11, SC_EXECVE },     { 387, SC_EXECVEAT },
};
#endif

static SyscallKind lookup(const SyscallEntry *table, size_t len, unsigned long long nr)
{
    for (size_t i = 0; i < len; i++) {
        if (table[i].nr == nr) return table[i].kind;
    }
    return SC_NONE;
}

SyscallKind syscall_classify(unsigned int audit_arch, unsigned long long nr)
{
    if (audit_arch == 0 || audit_arch == arch_native_audit_arch()) {
        return lookup(native_table, ARRAY_LEN(native_table), nr);
    }
#ifdef WF_HAVE_COMPAT_TABLE
    if (audit_arch == WF_COMPAT_AUDIT_ARCH) {
        return lookup(compat_table, ARRAY_LEN(compat_table), nr);
    }
#endif
    return SC_NONE;
}

const char *syscall_name(SyscallKind kind)
{
    switch (kind) {
    case SC_OPEN:       return "open()";
    case SC_OPENAT:     return "openat()";
    case SC_OPENAT2:    return "openat2()";
    case SC_CREAT:      return "creat()";
    case SC_UNLINK:     return "unlink()";
    case SC_UNLINKAT:   return "unlinkat()";
    case SC_RMDIR:      return "rmdir()";
    case SC_MKDIR:      return "mkdir()";
    case SC_MKDIRAT:    return "mkdirat()";
    case SC_RENAME:     return "rename()";
    case SC_RENAMEAT:   return "renameat()";
    case SC_RENAMEAT2:  return "renameat2()";
    case SC_LINK:       return "link()";
    case SC_LINKAT:     return "linkat()";
    case SC_SYMLINK:    return "symlink()";
    case SC_SYMLINKAT:  return "symlinkat()";
    case SC_TRUNCATE:   return "truncate()";
    case SC_CHMOD:      return "chmod()";
    case SC_FCHMODAT:   return "fchmodat()";
    case SC_CHOWN:      return "chown()";
    case SC_LCHOWN:     return "lchown()";
    case SC_FCHOWNAT:   return "fchownat()";
    case SC_EXECVE:     return "execve()";
    case SC_EXECVEAT:   return "execveat()";
    case SC_NONE:       break;
    }
    return "?";
}
