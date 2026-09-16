/*
A signal that arrives while the program runs user code, rather than inside a
syscall, used to make whatfiles detach silently and drop the signal.
*/
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t fired = 0;
static void handler(int sig) { (void)sig; fired = 1; }

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);   // vDSO call: stays in user code
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(void)
{
    struct itimerval timer = { { 0, 0 }, { 0, 200000 } };
    double start;

    close(open("/nonexistent/before-signal", O_RDONLY));
    signal(SIGALRM, handler);
    setitimer(ITIMER_REAL, &timer, NULL);
    start = now();
    while (!fired && now() - start < 3.0) { }
    close(open("/nonexistent/after-signal", O_RDONLY));
    fprintf(stderr, "SIGALRM handler ran: %s (waited %.2fs)\n", fired ? "yes" : "NO", now() - start);
    return fired ? 0 : 1;
}
