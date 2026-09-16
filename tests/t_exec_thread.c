// A non-leader thread calls execve() and takes over the process ID.
#include <pthread.h>
#include <unistd.h>

static void *run(void *arg)
{
    (void)arg;
    execl("/bin/true", "true", (char *)0);
    return NULL;
}

int main(void)
{
    pthread_t thread;
    pthread_create(&thread, NULL, run, NULL);
    sleep(5);
    return 0;
}
