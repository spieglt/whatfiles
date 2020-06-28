
#include <sys/ptrace.h>
#include <linux/ptrace.h>

#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "../hashmap.h"
#include "../whatfiles.h"

void check_syscall(pid_t current_pid, void *registers, HashMap map)
{
    struct pt_regs *regs = (struct pt_regs*)registers;
    struct String filename = {0};
    struct String output = {0};
    init_string(&filename, 64);
    init_string(&output, 64);
    char mode[MODE_LEN] = {0};

    pid_t parent_tid, child_tid;
    unsigned long flags;
    unsigned long newsp;

    size_t index;
    HashError err = find_index(current_pid, map, &index);
    if (err) DEBUG("unknown pid %d, syscall %ld\n", current_pid, regs->ARM_r7);

    switch (regs->ARM_r7)
    {
    case SYS_execve:
        DEBUG("PID %d exec'd. orig_rax: %ld\n", current_pid, regs->ARM_r7);
        if (peek_filename(current_pid, regs->ARM_ORIG_r0, &filename)) {
            DEBUG("associated process %d with name \"%s\"\n", current_pid, filename.data);
            set_name(current_pid, filename.data, map);
        }
        break;
    case SYS_fork:
        DEBUG("PID %d forked. orig_rax: %ld\n", current_pid, regs->ARM_r7);
        break;
    case SYS_clone:
        flags = regs->ARM_ORIG_r0;
        newsp = regs->ARM_r1;
        parent_tid = ptrace(PTRACE_PEEKDATA, current_pid, (void*)regs->ARM_r2, 0);
        child_tid = ptrace(PTRACE_PEEKDATA, current_pid, (void*)regs->ARM_r4, 0);
        DEBUG("PID %d cloned. orig_rax: %ld, flags: 0x%ld, newsp: 0x%ld, parent pid: %d, child pid: %d\n", 
            current_pid, regs->ARM_r7, flags, newsp, parent_tid, child_tid);
        break;
    case SYS_creat:
        peek_filename(current_pid, regs->ARM_ORIG_r0, &filename);
        get_mode(regs->ARM_r1, mode);
        build_output(mode, "creat()", regs->ARM_r1, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_open:
        peek_filename(current_pid, regs->ARM_ORIG_r0, &filename);
        get_mode(regs->ARM_r2, mode);
        build_output(mode, "open()", regs->ARM_r2, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_openat:
        peek_filename(current_pid, regs->ARM_r1, &filename);
        get_mode(regs->ARM_r3, mode);
        build_output(mode, "openat()", regs->ARM_r3, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_unlink:
        peek_filename(current_pid, regs->ARM_ORIG_r0, &filename);
        build_output("delete", "unlink()", 0, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_unlinkat:
        peek_filename(current_pid, regs->ARM_r1, &filename);
        build_output("delete", "unlinkat()", 0, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    default:
        // DEBUG("syscall: %lld, pid: %d, %s\n", regs->orig_rax, current_pid, proc_name);
        break;
    }
    free(filename.data);
    free(output.data);
}


bool step_syscall(pid_t current_pid, int proc_status, HashMap map)
{
    long res;
    struct pt_regs regs;
    bool could_read = false;
    // get current register values
    // TODO: make this fault tolerant to a dead PID
    res = ptrace(PTRACE_GETREGS, current_pid, &regs, &regs);
    if (res == -1L) {
        DEBUG("CURRENT PID: %d, failed to get registers\n", current_pid);
    }

    // can't get some registers for some reason
    if (regs.ARM_ORIG_r0 != -1) {
        could_read = true;
        // If it's the same PID performing the same syscall (has same orig_rax) as last time, we don't care. Just means it's exiting the syscall.
        // Might want to keep for debug mode? This might result in missing some output, in the case where two threads of the same process enter the same syscall before either exits,
        // because they will both return the same PID to wait() when given SIGTRAP as part of the syscall-enter-exit loop. Might also result in double-printing,
        // because if two threads (that report the same PID) enter two different syscalls before either exits, the "last" syscall for the PID won't be the entry by that thread.
        if (!is_exiting(current_pid, regs.ARM_ORIG_r0) /*|| Debug*/) {
            check_syscall(current_pid, (void*)&regs, map);
        }
        LastSyscall.pid = current_pid;
        LastSyscall.syscall = regs.ARM_ORIG_r0;
        check_ptrace_event(current_pid, proc_status, map);
        // continue, catching next entry or exit from syscall
        res = ptrace(PTRACE_SYSCALL, current_pid, 0, 0);
        if (res == -1L) DEBUG("ptrace() failed to resume");
    } else {
        DEBUG("can't get registers, detaching from %d\n", current_pid);
        res = ptrace(PTRACE_DETACH, current_pid, 0, 0); // "Under Linux, a tracee can be detached in this way regardless of which method was used to initiate tracing."
        if (res == -1L) DEBUG("ptrace() failed to detach from %d\n", current_pid);
    }
    return could_read;
}
