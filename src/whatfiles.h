#ifndef WHATFILES_H
#define WHATFILES_H

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "arch.h"
#include "hashmap.h"
#include "syscalls.h"
#include "wfstring.h"

extern FILE *Handle;
extern int Debug;
extern volatile sig_atomic_t Interrupted;   // set by the SIGINT/SIGTERM handler

#define WHATFILES_VERSION "2.0"

#define OUTPUT(...) fprintf(Handle, __VA_ARGS__)
#define DEBUG(...) do { if (Debug) OUTPUT(__VA_ARGS__); } while (0)
// perror() can change errno, so the exit status is taken first.
#define SYS_ERR(msg) do {                       \
        int wf_errno = errno;                   \
        perror(msg);                            \
        exit(wf_errno ? wf_errno : EXIT_FAILURE); \
    } while (0)
#define FATAL(...) do {                         \
        fprintf(stderr, "whatfiles: " __VA_ARGS__); \
        exit(EXIT_FAILURE);                     \
    } while (0)

/*
TRACESYSGOOD marks syscall stops with bit 7 of the stop signal, which is what
lets whatfiles tell them apart from a signal the tracee should actually receive.
*/
#define WF_PTRACE_OPTIONS (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK \
                         | PTRACE_O_TRACEVFORK  | PTRACE_O_TRACECLONE \
                         | PTRACE_O_TRACEEXEC)

// trace.c
void handle_stop(pid_t pid, int status, HashMap map);
bool trace_uses_kernel_syscall_info(void);
void resume_task(pid_t pid, int sig);

// utilities.c
bool read_tracee_data(pid_t pid, unsigned long long addr, void *buf, size_t len);
bool read_tracee_string(pid_t pid, unsigned long long addr, struct String *out);
void read_tracee_path(pid_t pid, int dirfd, unsigned long long addr, struct String *out);
void format_mode(SyscallKind kind, unsigned long long flags, char *out, size_t len);
char *parse_flags(int argc, char *argv[], pid_t *pid, bool *stdout_override,
                  bool *attach, bool *kill_on_exit);
void usage(void);
void about(void);

// attach.c
int seize_process(pid_t pid, HashMap map, int options);
void detach_all(HashMap map);
bool read_comm(pid_t tid, struct String *out);

#endif /* !WHATFILES_H */
