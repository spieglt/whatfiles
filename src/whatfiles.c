#include <dirent.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "whatfiles.h"
#include "hashmap.h"
#include "strings.h"

FILE *Handle = (FILE*)NULL;
int Debug = 0;
LastSyscall_t LastSyscall;
DebugStats_t DebugStats;

// looks at the current syscall and outputs its information if it's one we're interested in
void check_syscall(pid_t current_pid, struct user_regs_struct regs, HashMap map)
{
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
    if (err) DEBUG("unknown pid %d, syscall %lld\n", current_pid, regs.orig_rax);
    // struct String *proc_string = err ? NULL : &map->names[index];
    // char *proc_name = proc_string && proc_string->data && *proc_string->data
    //     ? proc_string->data
    //     : "[unknown]";

    switch (regs.orig_rax)
    {
    case SYS_execve:
        DEBUG("PID %d exec'd. orig_rax: %lld, rax: %lld\n", current_pid, regs.orig_rax, regs.rax);
        if (peek_filename(current_pid, regs.rdi, &filename)) {
            DEBUG("associated process %d with name \"%s\"\n", current_pid, filename.data);
            set_name(current_pid, filename.data, map);
        }
        break;
    case SYS_fork:
        DEBUG("PID %d forked. orig_rax: %lld, rax: %lld\n", current_pid, regs.orig_rax, regs.rax);
        break;
    case SYS_clone:
        flags = regs.rdi;
        newsp = regs.rsi;
        parent_tid = ptrace(PTRACE_PEEKDATA, current_pid, (void*)regs.rdx, 0);
        child_tid = ptrace(PTRACE_PEEKDATA, current_pid, (void*)regs.r10, 0);
        DEBUG("PID %d cloned. orig_rax: %lld, rax: %lld, flags: 0x%ld, newsp: 0x%ld, parent pid: %d, child pid: %d\n", 
            current_pid, regs.orig_rax, regs.rax, flags, newsp, parent_tid, child_tid);
        break;
    case SYS_creat:
        peek_filename(current_pid, regs.rdi, &filename);
        get_mode(regs.rsi, mode);
        build_output(mode, "creat()", regs.rsi, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_open:
        peek_filename(current_pid, regs.rdi, &filename);
        get_mode(regs.rdx, mode);
        build_output(mode, "open()", regs.rdx, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_openat:
        peek_filename(current_pid, regs.rsi, &filename);
        get_mode(regs.r10, mode);
        build_output(mode, "openat()", regs.r10, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_unlink:
        peek_filename(current_pid, regs.rdi, &filename);
        build_output("delete", "unlink()", 0, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    case SYS_unlinkat:
        peek_filename(current_pid, regs.rsi, &filename);
        build_output("delete", "unlinkat()", 0, current_pid, &filename, &output, map);
        OUTPUT("%s", output.data);
        break;
    default:
        // DEBUG("syscall: %lld, pid: %d, %s\n", regs.orig_rax, current_pid, proc_name);
        break;
    }
    free(filename.data);
    free(output.data);
}

// responsible for seeing new processes and threads created by forks, clones, or vforks, and inserting them into the hashmap
void check_ptrace_event(pid_t current_pid, int proc_status, HashMap map)
{
    struct String new_proc = {0};
    init_string(&new_proc, 128);

    unsigned long ptrace_event;
    long res = ptrace(PTRACE_GETEVENTMSG, current_pid, (char*)0, &ptrace_event);
    if (res == -1L) {
        DEBUG("ptrace() failed to get event msg");
        return;
    }
    switch (proc_status >> 8)
    {
    case SIGTRAP | (PTRACE_EVENT_FORK << 8):
        DEBUG("caught PTRACE_EVENT_FORK from pid %d. new pid: %ld\n", current_pid, ptrace_event);
        insert((pid_t)ptrace_event, ENTRY, map);
        if (read_task((pid_t)ptrace_event, &new_proc)) {
            set_name((pid_t)ptrace_event, new_proc.data, map);
        }
        break;
    case SIGTRAP | (PTRACE_EVENT_CLONE << 8):
        DEBUG("caught PTRACE_EVENT_CLONE from pid %d. new pid: %ld\n", current_pid, ptrace_event);
        insert((pid_t)ptrace_event, ENTRY, map);
        if (read_task((pid_t)ptrace_event, &new_proc)) {
            set_name((pid_t)ptrace_event, new_proc.data, map);
        }
        break;
    case SIGTRAP | (PTRACE_EVENT_VFORK << 8):
        DEBUG("caught PTRACE_EVENT_VFORK from pid %d. new pid: %ld\n", current_pid, ptrace_event);
        insert((pid_t)ptrace_event, ENTRY, map);
        if (read_task((pid_t)ptrace_event, &new_proc)) {
            set_name((pid_t)ptrace_event, new_proc.data, map);
        }
        break;
    case SIGTRAP | (PTRACE_EVENT_EXEC << 8):
        DEBUG("caught PTRACE_EVENT_EXEC from pid %d. former pid: %ld\n", current_pid, ptrace_event);
        /*
        from ptrace man page, "execve(2) under ptrace":
            When  one  thread  in  a multithreaded process calls execve(2), the kernel destroys all other threads in the
            process, and resets the thread ID of the execing thread to the thread group ID (process ID).   (Or,  to  put
            things another way, when a multithreaded process does an execve(2), at completion of the call, it appears as
            though the execve(2) occurred in the thread group leader, regardless of which  thread  did  the  execve(2).)
            This resetting of the thread ID looks very confusing to tracers: 
                [...]
                *   The  execing  tracee  changes  its  thread ID while it is in the execve(2).  (Remember, under ptrace, the
                    "pid" returned from waitpid(2), or fed into ptrace calls, is the  tracee's  thread  ID.)   That  is,  the
                    tracee's  thread  ID  is  reset  to  be the same as its process ID, which is the same as the thread group
                    leader's thread ID.
                *   Then a PTRACE_EVENT_EXEC stop happens, if the PTRACE_O_TRACEEXEC option was turned on.
        So, we should not insert the ptrace_event value, but the current_pid, as by the time we (the tracer)
        see this event, the PID has already been changed.
        */
        // insert((pid_t)ptrace_event, ENTRY, map);
        insert(current_pid, ENTRY, map);
        break;
    default:
        break;
    }

    free(new_proc.data);
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
    if (regs.orig_rax != -1) {
        could_read = true;
        // If it's the same PID performing the same syscall (has same orig_rax) as last time, we don't care. Just means it's exiting the syscall.
        // Might want to keep for debug mode? This might result in missing some output, in the case where two threads of the same process enter the same syscall before either exits,
        // because they will both return the same PID to wait() when given SIGTRAP as part of the syscall-enter-exit loop. Might also result in double-printing,
        // because if two threads (that report the same PID) enter two different syscalls before either exits, the "last" syscall for the PID won't be the entry by that thread.
        if (!is_exiting(current_pid, regs.orig_rax) /*|| Debug*/) {
            check_syscall(current_pid, regs, map);
        }
        LastSyscall.pid = current_pid;
        LastSyscall.syscall = regs.orig_rax;
        check_ptrace_event(current_pid, proc_status, map);
        // continue, catching next entry or exit from syscall
        res = ptrace(PTRACE_SYSCALL, current_pid, 0, 0);
        if (res == -1L) DEBUG("ptrace() failed to resume");
    } else {
        DEBUG("can't get registers\n");
    }
    return could_read;
}

int main(int argc, char* argv[])
{
    int pid, status;
    HashError err;
    int sys_err;
    bool stdout_override = false;
    bool attach = false;

    struct HashMap hm = {0};
    HashMap hashmap = &hm;
    init_hashmap(hashmap);

    int start_of_user_command = discover_flags(argc, argv);
    char *user_filename = parse_flags(start_of_user_command, argv, &pid, &stdout_override, &attach);
    if (start_of_user_command == argc && !attach) {
        fprintf(stderr, "Must specify a command to be run (after whatfiles arguments) or use the -p flag followed by a PID to attach to an existing process.\n");
        usage();
    }
    if (stdout_override) {
        Handle = stdout;
    } else {
        if (!user_filename) { // if filename is still empty string, make default
            char default_filename[64];
            sprintf(default_filename, "./whatfiles%lu.log", time(NULL));
            Handle = fopen(default_filename, "w");
            printf("whatfiles log location: %s\n", default_filename);
        } else {
            Handle = fopen(user_filename, "w");
            printf("whatfiles log location: %s\n", user_filename);
        }
        if (!Handle) SYS_ERR("could not open output file");
    }

    DEBUG("whatfiles pid: %d\n", getpid());

    if (attach) {
        OUTPUT("attaching to pid %d\n", pid);
        sys_err = attach_to_process(pid, hashmap);
        if (sys_err) SYS_ERR("error attaching to process");
    } else {
        // child process starts here
        if((pid = fork()) == 0) {
            DEBUG("whatfiles child pid: %d\n", getpid());
            sys_err = ptrace(PTRACE_TRACEME, 0, 0, 0);
            if (sys_err == -1) SYS_ERR("ptrace() failed to TRACEME");
            /*
                http://man7.org/linux/man-pages/man2/ptrace.2.html  
                "If the PTRACE_O_TRACEEXEC option is not in effect, all successful
                calls to execve(2) by the traced process will cause it to be sent a
                SIGTRAP signal, giving the parent a chance to gain control before the
                new program begins execution."
            */
            execvp(argv[start_of_user_command], &argv[start_of_user_command]);
            struct String err_msg = {0};
            init_string(&err_msg, 128);
            char *failed = "failed to execute ";
            append_str(failed, strlen(failed), &err_msg);
            append_str(argv[start_of_user_command], strlen(argv[start_of_user_command]), &err_msg);
            SYS_ERR(err_msg.data);
            free(err_msg.data); // not really necessary because SYS_ERR will exit() but meh
        }
        if (pid == -1) SYS_ERR("fork() failed");

        // tracing process continues here

        pid = wait(&status); // initial stop caused by exec in child process
        if (pid == -1) SYS_ERR("wait() failed");
        insert(pid, ENTRY, hashmap);

        if(WIFEXITED(status)) return 0;
        if(!WIFSTOPPED(status)) SYS_ERR("received non-SIGTRAP signal, ptrace() not working");
        err = set_name(pid, argv[start_of_user_command], &hm);
        HASH_ERR_CHECK(err, "could not set name for initial process");
        /*
            "When the tracee is in ptrace-stop, the tracer can read and write data
            to the tracee using informational commands.  These commands leave the
            tracee in ptrace-stopped state:"
            [PTRACE_SETOPTIONS among others]
        */
        // register for the ptrace events we want to catch
        sys_err = ptrace(PTRACE_SETOPTIONS, pid, (char*)0, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);
        if (sys_err == -1) SYS_ERR("ptrace() failed");

        // start PTRACE_SYSCALL/wait() loop. process/thread will receive SIGTRAP every time it makes a syscall
        sys_err = ptrace(PTRACE_SYSCALL, pid, 0, 0);
        if (sys_err == -1) SYS_ERR("ptrace() failed");
    }

    // by this point, whether attaching or spawning,
    // options should be in place and all processes/threads should be resumed with PTRACE_SYSCALL

    // if we're attaching to a process already in progress, block SIGINT and SIGTERM signals
    // so that we can detach from everything if whatfiles is closed while the process is still running
    sigset_t block_mask, pending_mask;
    if (attach) {
        sigemptyset(&block_mask);
        sigaddset(&block_mask, SIGINT);
        sigaddset(&block_mask, SIGTERM);
        sigprocmask(SIG_SETMASK, &block_mask, NULL);
    }

    // main loop
    for (;;) {
        if (attach) {
            sigpending(&pending_mask);
            if (sigismember(&pending_mask, SIGINT) || sigismember(&pending_mask, SIGTERM)) {
                DEBUG("pending signal caught\n");
                detach_from_process(hashmap);
                exit(errno);
            }
        }
        // catch any traced process' or thread's next state change
        pid = wait(&status);
        if (pid == -1) SYS_ERR("waiting for any child process failed");
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            DEBUG("exited %d at entry to syscall\n", pid);
            err = remove_pid(pid, hashmap);
            DEBUG("deletion of %d from hashmap failed\n", pid);
        }
        if (WIFSTOPPED(status)) {
            /*bool could_read = */ step_syscall(pid, status, hashmap);
        }
        if (hashmap->used == 0) {
            DEBUG("all children exited\n");
            break;
        }
    }

    err = destroy(hashmap);
    HASH_ERR_CHECK(err, "tried to free null pointers in hashmap.\n")
    fclose(Handle);
}

/*
TODO:
debug flag for use by hashdriver
more hashmap tests?
better allocator/destructor for String
have hashmap functions return index where appropriate. just insert()?
*/

/*
Because wait() will return the same PID for any of a process's threads, we need a way to get the thread ID so that we can keep track of entering/exiting.
Though the only reason we need to keep track of that is to not double-print. Can we just check whether the to-be-printed values are the same as the last ones?
Maybe yes, but it would be nice to be able to keep track of that, period. And what if two threads with the same PID enter the same syscall before either exits?
Then we'll only print once. Need linked list to keep track of syscalls that have entered but not exited? Would solve the problem of syscalls getting interrupted
before exiting, which happens. Context switching? But wouldn't solve the problem of two threads with the same PID that enter the same syscall before either exits.
But if that happens, there will just be "one on the stack twice" instead of "two on the stack once". Is that a problem?

What's happening with unseen PIDs: we are informed of a process entering a clone syscall, and before it exits, the new thread is scheduled and starts executing its own syscalls,
which we are informed of. Eventually followed by the original clone exiting, so does get inserted into map.

TODO: maybe still haven't accounted for this:
    If the thread group leader has reported its PTRACE_EVENT_EXIT stop by this time, it appears to the tracer
    that  the  dead  thread  leader "reappears from nowhere".  (Note: the thread group leader does not report
    death via WIFEXITED(status) until there is at least one other live thread.  This eliminates the possibil‐
    ity that the tracer will see it dying and then reappearing.)  If the thread group leader was still alive,
    for the tracer this may look as if thread group leader returns from  a  different  system  call  than  it
    entered,  or even "returned from a system call even though it was not in any system call".  If the thread
    group leader was not traced (or was traced by a different tracer), then during execve(2) it  will  appear
    as if it has become a tracee of the tracer of the execing tracee.
*/
