/*
Mimics the Firefox content sandbox: a seccomp-bpf filter answers openat() with
SECCOMP_RET_TRAP, and a SIGSYS handler "brokers" the call by writing a result
into the saved registers. If the tracer drops SIGSYS, the handler never runs and
the program is handed the syscall number as if it were a file descriptor.
*/
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#if defined(__x86_64__)
#define SECCOMP_ARCH AUDIT_ARCH_X86_64
#define RESULT_REG REG_RAX
#elif defined(__i386__)
#define SECCOMP_ARCH AUDIT_ARCH_I386
#define RESULT_REG REG_EAX
#endif

static int brokered_fd = -1;
static volatile sig_atomic_t sigsys_count = 0;

#ifdef RESULT_REG
static void sigsys_handler(int sig, siginfo_t *info, void *context)
{
    ucontext_t *ctx = context;
    (void)sig;
    (void)info;
    sigsys_count++;
    ctx->uc_mcontext.gregs[RESULT_REG] = dup(brokered_fd);   // dup() is not trapped
}
#endif

int main(void)
{
#ifndef RESULT_REG
    fprintf(stderr, "SKIP: no SIGSYS emulation for this architecture\n");
    return 77;
#else
    struct sigaction action;
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { sizeof filter / sizeof filter[0], filter };
    char buf[256];
    ssize_t n;
    int fd;

    brokered_fd = open("/proc/self/status", O_RDONLY);
    if (brokered_fd < 0) {
        perror("open");
        return 2;
    }
    memset(&action, 0, sizeof action);
    action.sa_sigaction = sigsys_handler;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGSYS, &action, NULL);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        fprintf(stderr, "SKIP: seccomp unavailable: %s\n", strerror(errno));
        return 77;
    }
    fd = open("/proc/self/status", O_RDONLY);   // trapped, brokered by the handler
    n = read(fd, buf, sizeof buf);
    fprintf(stderr, "sandboxed open() returned %d, SIGSYS handler ran %d time(s), read() returned %zd\n",
            fd, (int)sigsys_count, n);
    return (sigsys_count == 1 && n > 0) ? 0 : 1;
#endif
}
