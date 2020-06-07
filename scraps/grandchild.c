#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    printf("grandchild pid: %d\n", getpid());
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        printf("great-grandchild pid: %d\n", getpid());
        fflush(stdout);
        // printf("child ppid: %d\n", getppid());
        execl("/bin/ls", "/bin/ls", (char*)0);
    }
    int status;
    while (1) {
        waitpid(pid, &status, 0);
        if(WIFEXITED(status)) {
            printf("great-grandchild exited\n");
            return 0;
        }
    }
}