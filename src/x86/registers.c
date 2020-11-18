
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "../hashmap.h"
#include "../whatfiles.h"

// looks at the current syscall and outputs its information if it's one we're interested in
void check_syscall(pid_t current_pid, void *registers, HashMap map)
{
    struct user_regs_struct *regs = (struct user_regs_struct*)registers;
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
    if (err) DEBUG("unknown pid %d, syscall %ld\n", current_pid, regs->orig_eax);

    switch (regs->orig_eax)
    {
    case SYS_execve:
        DEBUG("PID %d exec'd. orig_eax: %ld, eax: %ld\n", current_pid, regs->orig_eax, regs->eax);
        if (peek_filename(current_pid, regs->ebx, &filename)) {
            DEBUG("associated process %d with name \"%s\"\n", current_pid, filename.data);
            set_name(current_pid, filename.data, map);
        }
        break;
    case SYS_fork:
        DEBUG("PID %d forked. orig_eax: %ld, eax: %ld\n", current_pid, regs->orig_eax, regs->eax);
        break;
    case SYS_clone:
        flags = regs->ebx;
        newsp = regs->ecx;
        parent_tid = ptrace(PTRACE_PEEKDATA, current_pid, (void*)regs->edx, 0);
        child_tid = ptrace(PTRACE_PEEKDATA, current_pid, (void*)regs->esi, 0);
        DEBUG("PID %d cloned. orig_eax: %ld, eax: %ld, flags: 0x%ld, newsp: 0x%ld, parent pid: %d, child pid: %d\n", 
            current_pid, regs->orig_eax, regs->eax, flags, newsp, parent_tid, child_tid);
        break;
    case SYS_creat:
        peek_filename(current_pid, regs->ebx, &filename);
        get_mode(regs->ecx, mode);
        build_output(mode, "creat()", regs->ecx, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_open:
        peek_filename(current_pid, regs->ebx, &filename);
        get_mode(regs->edx, mode);
        build_output(mode, "open()", regs->edx, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_openat:
        peek_filename(current_pid, regs->ecx, &filename);
        get_mode(regs->esi, mode);
        build_output(mode, "openat()", regs->esi, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_unlink:
        peek_filename(current_pid, regs->ebx, &filename);
        build_output("delete", "unlink()", 0, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_unlinkat:
        peek_filename(current_pid, regs->ecx, &filename);
        build_output("delete", "unlinkat()", 0, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    default:
        // DEBUG("syscall: %lld, pid: %d, %s\n", regs->orig_eax, current_pid, proc_name);
        break;
    }
    free(filename.data);
    free(output.data);
}


bool step_syscall(pid_t current_pid, int proc_status, HashMap map)
{
    long res;
    struct user_regs_struct regs;
    bool could_read = false;
    // get current register values
    // TODO: make this fault tolerant to a dead PID
    res = ptrace(PTRACE_GETREGS, current_pid, &regs, &regs);
    if (res == -1L) {
        DEBUG("CURRENT PID: %d, failed to get registers\n", current_pid);
    }

    // can't get some registers for some reason
    if (regs.orig_eax != -1) {
        could_read = true;
        // If it's the same PID performing the same syscall (has same orig_eax) as last time, we don't care. Just means it's exiting the syscall.
        // Might want to keep for debug mode? This might result in missing some output, in the case where two threads of the same process enter the same syscall before either exits,
        // because they will both return the same PID to wait() when given SIGTRAP as part of the syscall-enter-exit loop. Might also result in double-printing,
        // because if two threads (that report the same PID) enter two different syscalls before either exits, the "last" syscall for the PID won't be the entry by that thread.
        if (!is_exiting(current_pid, regs.orig_eax) /*|| Debug*/) {
            check_syscall(current_pid, (void*)&regs, map);
        }
        LastSyscall.pid = current_pid;
        LastSyscall.syscall = regs.orig_eax;
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
