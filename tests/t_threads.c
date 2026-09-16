// Interleaved threads must produce exactly one log line per open.
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#define THREADS 4
#define OPENS 250

static void *run(void *arg)
{
    char path[64];
    long id = (long)arg;
    for (int i = 0; i < OPENS; i++) {
        snprintf(path, sizeof path, "/nonexistent/thr%ld_%d", id, i);
        close(open(path, O_RDONLY));
        getppid();
    }
    return NULL;
}

int main(void)
{
    pthread_t threads[THREADS];
    for (long t = 0; t < THREADS; t++) pthread_create(&threads[t], NULL, run, (void *)t);
    for (int t = 0; t < THREADS; t++) pthread_join(threads[t], NULL);
    fprintf(stderr, "opens performed: %d\n", THREADS * OPENS);
    return 0;
}
