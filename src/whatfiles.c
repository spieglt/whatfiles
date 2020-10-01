#include <dirent.h>
#include <regex.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "whatfiles.h"
#include "hashmap.h"
#include "strings.h"

FILE *Handle = (FILE*)NULL;
int Debug = 0;
regex_t regex;
LastSyscall_t LastSyscall;
DebugStats_t DebugStats;

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

    if (regcomp(&regex, "State:\\W+([A-Za-z])", REG_EXTENDED) != 0) {
        SYS_ERR("regex compilation error");
    }

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
        if (pid == -1) SYS_ERR("whatfiles exiting");
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            DEBUG("PID %d exited", pid);
            // ok if this fails in case of process not in hashmap
            err = remove_pid(pid, hashmap);
            if (err) DEBUG(", was not in map");
            DEBUG("\n");
        } else if (WIFSTOPPED(status)) {
            /*bool could_read = */ step_syscall(pid, status, hashmap);
        }

        if (hashmap->used == 0) {
            DEBUG("all children exited\n");
            break;
        }
    }

    regfree(&regex);
    err = destroy(hashmap);
    HASH_ERR_CHECK(err, "tried to free null pointers in hashmap.\n")
    fclose(Handle);
}

/*
TODO:
confirm process exists for -p flag
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
