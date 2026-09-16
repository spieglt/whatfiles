// Signals sent to a traced process must still reach its handlers.
#include <signal.h>
#include <stdio.h>

static volatile sig_atomic_t hits = 0;
static void handler(int sig) { (void)sig; hits++; }

int main(void)
{
    signal(SIGUSR1, handler);
    signal(SIGCHLD, handler);
    raise(SIGUSR1);
    raise(SIGCHLD);
    fprintf(stderr, "signals raised: 2, handler invocations: %d\n", (int)hits);
    return hits == 2 ? 0 : 1;
}
