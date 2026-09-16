#define _GNU_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "whatfiles.h"

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL 0x00100000
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

FILE *Handle = NULL;
int Debug = 0;
volatile sig_atomic_t Interrupted = 0;

static void on_interrupt(int sig)
{
    Interrupted = sig;
}

static void install_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof action);
    action.sa_handler = on_interrupt;
    sigemptyset(&action.sa_mask);
    // No SA_RESTART on purpose: waitpid() must return EINTR so that the main
    // loop notices the interrupt even while every traced process sits idle.
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
}

static void open_log(const char *user_filename, bool stdout_override)
{
    char generated[64];
    const char *path = user_filename;
    int fd;

    if (stdout_override) {
        Handle = stdout;
        setvbuf(Handle, NULL, _IOLBF, 0);
        return;
    }
    if (path) {
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    } else {
        snprintf(generated, sizeof generated, "./whatfiles%lld-%d.log",
                 (long long)time(NULL), (int)getpid());
        path = generated;
        // The generated name is predictable and whatfiles is often run with
        // sudo, so refuse to follow a symlink or overwrite an existing file.
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    }
    if (fd == -1) {
        int saved = errno;
        fprintf(stderr, "whatfiles: could not create log file %s: %s\n", path, strerror(saved));
        // The working directory is often not writable, on Android especially.
        if (!user_filename) {
            fprintf(stderr, "use -o to put the log somewhere else, or -s to write to stdout\n");
        }
        exit(saved ? saved : EXIT_FAILURE);
    }
    // O_CLOEXEC above keeps this descriptor out of the traced program.
    Handle = fdopen(fd, "w");
    if (!Handle) SYS_ERR("could not open output file");
    // Line buffering, so an interrupted or killed run still leaves a full log.
    setvbuf(Handle, NULL, _IOLBF, 0);
    printf("whatfiles log location: %s\n", path);
    fflush(stdout);
}

static void launch_failed(pid_t child, const char *msg)
{
    int saved = errno;
    kill(child, SIGKILL);
    waitpid(child, NULL, __WALL);
    errno = saved;
    SYS_ERR(msg);
}

/*
Starts the program under tracing. The child waits on a pipe until the tracer has
seized it, which avoids PTRACE_TRACEME: a seized tracee reports group-stops
distinctly and can be interrupted and detached cleanly at any time.
*/
static pid_t launch(char **argv, HashMap map, int options)
{
    int sync_pipe[2];
    pid_t pid;
    int status;
    Task *task;

    if (pipe2(sync_pipe, O_CLOEXEC) == -1) SYS_ERR("pipe() failed");
    pid = fork();
    if (pid == -1) SYS_ERR("fork() failed");

    if (pid == 0) {
        char byte;
        close(sync_pipe[1]);
        while (read(sync_pipe[0], &byte, 1) == -1 && errno == EINTR) { }
        close(sync_pipe[0]);
        execvp(argv[0], argv);
        fprintf(stderr, "whatfiles: failed to execute %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    close(sync_pipe[0]);

    if (ptrace(PTRACE_SEIZE, pid, NULL, (void *)(long)options) == -1) {
        launch_failed(pid, "ptrace() failed to seize child");
    }
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
        launch_failed(pid, "ptrace() failed to stop child");
    }
    if (waitpid(pid, &status, __WALL) == -1) {
        launch_failed(pid, "waitpid() failed");
    }
    task = map_insert(map, pid);
    if (task) str_append_cstr(&task->name, argv[0]);
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        launch_failed(pid, "ptrace() failed to start syscall tracing");
    }
    close(sync_pipe[1]);   // lets the child proceed to execvp()
    return pid;
}

int main(int argc, char *argv[])
{
    struct HashMap hm = {0};
    HashMap map = &hm;
    bool stdout_override = false, attach = false, kill_on_exit = false;
    pid_t target = 0, first_child = 0;
    char *user_filename;
    int exit_status = 0;
    int options;

    user_filename = parse_flags(argc, argv, &target, &stdout_override, &attach, &kill_on_exit);
    if (attach && optind < argc) {
        FATAL("-p attaches to a running process, so it cannot also take a command to run\n");
    }
    if (!attach && optind >= argc) {
        fprintf(stderr, "Must specify a command to be run (after whatfiles arguments) "
                        "or use the -p flag followed by a PID to attach to an existing process.\n");
        usage();
    }

    map_init(map);
    open_log(user_filename, stdout_override);
    install_handlers();

    options = WF_PTRACE_OPTIONS;
    if (kill_on_exit) options |= PTRACE_O_EXITKILL;

    DEBUG("whatfiles pid: %d\n", (int)getpid());
    DEBUG("syscall decoding: %s\n",
          trace_uses_kernel_syscall_info() ? "kernel syscall info" : "registers");

    if (attach) {
        OUTPUT("attaching to pid %d\n", (int)target);
        if (seize_process(target, map, options) != 0) SYS_ERR("error attaching to process");
    } else {
        first_child = launch(&argv[optind], map, options);
    }

    for (;;) {
        int status;
        pid_t pid = waitpid(-1, &status, __WALL);

        if (pid == -1) {
            if (errno == EINTR) {
                if (Interrupted) break;
                continue;
            }
            if (errno == ECHILD) break;
            SYS_ERR("waitpid() failed");
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            DEBUG("PID %d exited\n", (int)pid);
            map_remove(map, pid);
            if (pid == first_child) {
                exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            }
            if (map_count(map) == 0) {
                DEBUG("all traced processes exited\n");
                break;
            }
            continue;
        }
        if (WIFSTOPPED(status)) handle_stop(pid, status, map);
    }

    if (Interrupted) {
        DEBUG("interrupted by signal %d, detaching\n", (int)Interrupted);
        detach_all(map);
        exit_status = 128 + (int)Interrupted;
    }
    map_destroy(map);
    if (Handle && Handle != stdout) fclose(Handle);
    return exit_status;
}
