/*
Starts a target program, then becomes `whatfiles -p <target>`, so that whatfiles
is the target's ancestor. That satisfies Yama ptrace_scope=1 without root.
usage: t_attach_harness <whatfiles> <logfile> <target> [args...]
*/
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char pid[16];
    pid_t target;

    if (argc < 4) {
        fprintf(stderr, "usage: %s <whatfiles> <logfile> <target> [args...]\n", argv[0]);
        return 2;
    }
    target = fork();
    if (target == 0) {
        execv(argv[3], &argv[3]);
        _exit(127);
    }
    usleep(500000);   // let the target start its threads
    snprintf(pid, sizeof pid, "%d", target);
    execl(argv[1], argv[1], "-o", argv[2], "-p", pid, (char *)0);
    perror("exec whatfiles");
    return 1;
}
