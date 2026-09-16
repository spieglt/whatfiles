#define _GNU_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "whatfiles.h"

#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif
#ifndef PTRACE_LISTEN
#define PTRACE_LISTEN 0x4208
#endif

#define WF_SYSCALL_INFO_NONE    0
#define WF_SYSCALL_INFO_ENTRY   1
#define WF_SYSCALL_INFO_EXIT    2
#define WF_SYSCALL_INFO_SECCOMP 3

/*
Layout of struct ptrace_syscall_info (Linux 5.3+), declared here so that
whatfiles still builds against older headers and decides at runtime whether the
kernel supports the request. It reports directly whether a stop is a syscall
entry or exit, which register contents alone cannot tell us, and which ABI the
tracee used, which is how 32-bit syscalls are decoded correctly.
*/
struct wf_syscall_info {
    uint8_t op;
    uint8_t pad[3];
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
    union {
        struct { uint64_t nr; uint64_t args[6]; } entry;
        struct { int64_t rval; uint8_t is_error; } exit;
        struct { uint64_t nr; uint64_t args[6]; uint32_t ret_data; } seccomp;
    } u;
};

typedef struct {
    bool entry;
    unsigned int audit_arch;
    unsigned long long nr;
    unsigned long long args[6];
    long long ret;
} SyscallStop;

/*
Set to false the first time the kernel refuses PTRACE_GET_SYSCALL_INFO, which
switches over to reading registers. Build with -DWF_NO_SYSCALL_INFO to exercise
that path on a kernel that does support the request.
*/
#ifdef WF_NO_SYSCALL_INFO
static bool SyscallInfoWorks = false;
#else
static bool SyscallInfoWorks = true;
#endif

bool trace_uses_kernel_syscall_info(void)
{
    return SyscallInfoWorks;
}

void resume_task(pid_t pid, int sig)
{
    if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)(long)sig) == -1) {
        DEBUG("PID %d: could not resume: %s\n", (int)pid, strerror(errno));
    }
}

static bool read_syscall_stop(pid_t pid, Task *task, SyscallStop *out)
{
    memset(out, 0, sizeof *out);

    if (SyscallInfoWorks) {
        struct wf_syscall_info info;
        memset(&info, 0, sizeof info);
        errno = 0;
        long len = ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof info, &info);
        if (len > 0) {
            switch (info.op) {
            case WF_SYSCALL_INFO_ENTRY:
                out->entry = true;
                out->audit_arch = info.arch;
                out->nr = info.u.entry.nr;
                for (int i = 0; i < 6; i++) out->args[i] = info.u.entry.args[i];
                return true;
            case WF_SYSCALL_INFO_SECCOMP:
                out->entry = true;
                out->audit_arch = info.arch;
                out->nr = info.u.seccomp.nr;
                for (int i = 0; i < 6; i++) out->args[i] = info.u.seccomp.args[i];
                return true;
            case WF_SYSCALL_INFO_EXIT:
                out->entry = false;
                out->audit_arch = info.arch;
                out->ret = (long long)info.u.exit.rval;
                return true;
            default:
                return false;   // not a syscall stop after all
            }
        }
        if (errno == EIO || errno == EINVAL || errno == ENOSYS) {
            DEBUG("PTRACE_GET_SYSCALL_INFO unavailable, reading registers instead\n");
            SyscallInfoWorks = false;
        } else {
            DEBUG("PID %d: PTRACE_GET_SYSCALL_INFO failed: %s\n", (int)pid, strerror(errno));
            return false;
        }
    }

    // Fallback for kernels before 5.3: read registers and track entry/exit per
    // thread, since syscall stops alternate entry, exit, entry, exit.
    Registers regs;
    if (!arch_get_registers(pid, &regs)) {
        DEBUG("PID %d: could not read registers: %s\n", (int)pid, strerror(errno));
        return false;
    }
    out->entry = !task->in_syscall;
    out->audit_arch = regs.audit_arch;
    out->nr = regs.nr;
    memcpy(out->args, regs.args, sizeof out->args);
    out->ret = regs.ret;
    return true;
}

// Label for the second path of the syscalls that name two files.
static const char *second_path_label(SyscallKind kind)
{
    switch (kind) {
    case SC_SYMLINK:
    case SC_SYMLINKAT:
        return "target";
    default:
        return "to";
    }
}

static void clear_pending(Task *task)
{
    task->kind = SC_NONE;
    task->flags = 0;
    str_clear(&task->path);
    str_clear(&task->path2);
}

// openat2() passes its flags in a struct in the tracee's memory.
static unsigned long long read_open_how_flags(pid_t pid, unsigned long long addr)
{
    uint64_t how[3] = {0, 0, 0};   // flags, mode, resolve
    if (!addr || !read_tracee_data(pid, addr, how, sizeof how)) return 0;
    return (unsigned long long)how[0];
}

/*
Records the arguments of a syscall we report, so the log line can be written at
syscall exit with the result. Paths are read now because the tracee's memory may
have changed, or the pointer register may have been reused, by the time it exits.
*/
static void record_entry(pid_t pid, Task *task, const SyscallStop *stop)
{
    const unsigned long long *a = stop->args;

    clear_pending(task);
    task->kind = syscall_classify(stop->audit_arch, stop->nr);

    switch (task->kind) {
    case SC_NONE:
        return;
    case SC_OPEN:
        read_tracee_path(pid, AT_FDCWD, a[0], &task->path);
        task->flags = a[1];
        break;
    case SC_CREAT:
        read_tracee_path(pid, AT_FDCWD, a[0], &task->path);
        task->flags = O_WRONLY | O_CREAT | O_TRUNC;   // what creat() always means
        break;
    case SC_OPENAT:
        read_tracee_path(pid, (int)a[0], a[1], &task->path);
        task->flags = a[2];
        break;
    case SC_OPENAT2:
        read_tracee_path(pid, (int)a[0], a[1], &task->path);
        task->flags = read_open_how_flags(pid, a[2]);
        break;
    case SC_UNLINKAT:
        read_tracee_path(pid, (int)a[0], a[1], &task->path);
        task->flags = a[2];
        break;
    case SC_UNLINK:
    case SC_RMDIR:
    case SC_MKDIR:
    case SC_TRUNCATE:
    case SC_CHMOD:
    case SC_CHOWN:
    case SC_LCHOWN:
    case SC_EXECVE:
        read_tracee_path(pid, AT_FDCWD, a[0], &task->path);
        break;
    case SC_MKDIRAT:
    case SC_FCHMODAT:
    case SC_FCHOWNAT:
    case SC_EXECVEAT:
        read_tracee_path(pid, (int)a[0], a[1], &task->path);
        break;
    case SC_RENAME:
    case SC_LINK:
        read_tracee_path(pid, AT_FDCWD, a[0], &task->path);
        read_tracee_path(pid, AT_FDCWD, a[1], &task->path2);
        break;
    case SC_RENAMEAT:
    case SC_RENAMEAT2:
    case SC_LINKAT:
        read_tracee_path(pid, (int)a[0], a[1], &task->path);
        read_tracee_path(pid, (int)a[2], a[3], &task->path2);
        break;
    case SC_SYMLINK:
        // The first argument is the link's contents, not a path to resolve.
        read_tracee_string(pid, a[0], &task->path2);
        read_tracee_path(pid, AT_FDCWD, a[1], &task->path);
        break;
    case SC_SYMLINKAT:
        read_tracee_string(pid, a[0], &task->path2);
        read_tracee_path(pid, (int)a[1], a[2], &task->path);
        break;
    }
}

static void emit_record(pid_t pid, Task *task, long long ret)
{
    struct String line = {0};
    char mode[64];

    format_mode(task->kind, task->flags, mode, sizeof mode);
    str_init(&line, 256);
    str_appendf(&line, "mode: %6s, file: ", mode);
    str_append_escaped(&line, task->path.data ? task->path.data : "", task->path.len);
    if (task->path2.len) {
        str_appendf(&line, ", %s: ", second_path_label(task->kind));
        str_append_escaped(&line, task->path2.data, task->path2.len);
    }
    str_appendf(&line, ", syscall: %s, PID: %d, process: ",
                syscall_name(task->kind), (int)pid);
    if (task->name.len) str_append_escaped(&line, task->name.data, task->name.len);
    else str_append_cstr(&line, "[unknown]");
    if (ret < 0 && ret >= -4095) str_appendf(&line, ", result: -1 (%s)\n", strerror((int)-ret));
    else str_appendf(&line, ", result: %lld\n", ret);

    OUTPUT("%s", line.data);
    str_free(&line);
}

static void name_task(pid_t pid, Task *task, const struct String *exec_path)
{
    str_clear(&task->name);
    if (exec_path && exec_path->len) str_append(&task->name, exec_path->data, exec_path->len);
    else read_comm(pid, &task->name);
}

static void handle_event(pid_t pid, int sig, unsigned int event, HashMap map)
{
    unsigned long msg = 0;

    switch (event) {
    case PTRACE_EVENT_FORK:
    case PTRACE_EVENT_VFORK:
    case PTRACE_EVENT_CLONE:
        if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg) == 0) {
            pid_t child = (pid_t)msg;
            DEBUG("PID %d created PID %d\n", (int)pid, (int)child);
            Task *task = map_insert(map, child);
            if (task && !task->name.len) read_comm(child, &task->name);
        } else {
            DEBUG("PID %d: PTRACE_GETEVENTMSG failed: %s\n", (int)pid, strerror(errno));
        }
        break;

    case PTRACE_EVENT_EXEC: {
        /*
        A thread that calls execve() takes over the process ID, and its old
        thread ID disappears without ever reporting an exit. The old entry has
        to go, or whatfiles would wait forever for a thread that no longer exists.
        */
        struct String exec_path = {0};
        if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg) == 0 && (pid_t)msg != pid) {
            Task *old = map_find(map, (pid_t)msg);
            if (old) {
                DEBUG("PID %d exec'd, former thread ID %d\n", (int)pid, (int)msg);
                if (old->kind == SC_EXECVE || old->kind == SC_EXECVEAT) {
                    emit_record(pid, old, 0);
                }
                if (old->path.len) str_append(&exec_path, old->path.data, old->path.len);
                map_remove(map, (pid_t)msg);
            }
        }
        Task *task = map_insert(map, pid);
        if (task) {
            if (task->kind == SC_EXECVE || task->kind == SC_EXECVEAT) {
                if (!exec_path.len && task->path.len) {
                    str_append(&exec_path, task->path.data, task->path.len);
                }
                emit_record(pid, task, 0);
            }
            clear_pending(task);
            name_task(pid, task, &exec_path);
        }
        str_free(&exec_path);
        break; }

    case PTRACE_EVENT_STOP:
        /*
        Group-stop: the tracee was stopped by SIGSTOP or a terminal signal.
        PTRACE_LISTEN leaves it stopped, as job control intends, instead of
        secretly resuming it. It wakes up again when SIGCONT arrives.
        */
        if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
            if (ptrace(PTRACE_LISTEN, pid, 0, 0) == 0) return;
            DEBUG("PID %d: PTRACE_LISTEN failed: %s\n", (int)pid, strerror(errno));
        }
        break;

    default:
        break;
    }
    resume_task(pid, 0);
}

static void handle_syscall_stop(pid_t pid, HashMap map)
{
    Task *task = map_insert(map, pid);   // a thread whose creation we missed
    if (!task) {
        resume_task(pid, 0);
        return;
    }
    if (!task->name.len) read_comm(pid, &task->name);

    SyscallStop stop;
    if (!read_syscall_stop(pid, task, &stop)) {
        resume_task(pid, 0);
        return;
    }
    if (stop.entry) {
        record_entry(pid, task, &stop);
    } else if (task->kind != SC_NONE) {
        emit_record(pid, task, stop.ret);
        clear_pending(task);
    }
    task->in_syscall = stop.entry;
    resume_task(pid, 0);
}

void handle_stop(pid_t pid, int status, HashMap map)
{
    int sig = WSTOPSIG(status);
    unsigned int event = ((unsigned int)status >> 16) & 0xFFFF;

    if (event) {
        handle_event(pid, sig, event, map);
        return;
    }
    // PTRACE_O_TRACESYSGOOD sets bit 7 on the stop signal of a syscall stop,
    // which is the only reliable way to tell one from a real SIGTRAP.
    if (sig == (SIGTRAP | 0x80)) {
        handle_syscall_stop(pid, map);
        return;
    }
    /*
    Signal-delivery-stop. The signal only reaches the tracee if it is passed
    back here: dropping it breaks any program that relies on signal handlers,
    including sandboxes that broker syscalls through SIGSYS.
    */
    DEBUG("PID %d received signal %d (%s)\n", (int)pid, sig, strsignal(sig));
    resume_task(pid, sig);
}
