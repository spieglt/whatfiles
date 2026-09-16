// The main thread opens one marker; a worker thread forks children that open
// another, the way a browser launches its tab processes from a helper thread.
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define ROUNDS 20

static void *worker(void *arg)
{
    (void)arg;
    for (int i = 0; i < ROUNDS; i++) {
        pid_t child = fork();
        if (child == 0) {
            close(open("/nonexistent/opened-by-child-of-worker-thread", O_RDONLY));
            _exit(0);
        }
        waitpid(child, NULL, 0);
        usleep(150000);
    }
    return NULL;
}

int main(void)
{
    pthread_t thread;
    pthread_create(&thread, NULL, worker, NULL);
    for (int i = 0; i < ROUNDS; i++) {
        close(open("/nonexistent/opened-by-main-thread", O_RDONLY));
        usleep(150000);
    }
    pthread_join(thread, NULL);
    return 0;
}
