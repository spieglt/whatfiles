
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>
// #include <sys/types.h>
// #include <sys/stat.h>

int cloned_func(void *arg)
{
	printf("hello from clone\n");
	fflush(stdout);
	return 0;
}

int main()
{
	char *temp_filename = "./tempfile";
	char *message = "special message\n";
	char *clone_stack = malloc(1024);
	char *clone_stack_top = clone_stack + 1024;

	// SYS_fork
	printf("testing fork\n");
	fflush(stdout);
	pid_t child_pid = fork();
	if (child_pid == 0) { // if in child
		printf("testing exec\n");
		fflush(stdout);
		// SYS_execve
		execl("/bin/ls", "ls", (char*)0);
		return 0;
	}
	wait(NULL);

	// SYS_clone
	printf("testing clone\n");
	pid_t cloned_pid = clone(cloned_func, clone_stack_top, SIGCHLD, 0);
	wait(NULL);

	// SYS_creat
	printf("testing creat\n");
	int tfd = creat(temp_filename, S_IRWXU);
	close(tfd);

	// SYS_open
	printf("testing open\n");
	tfd = open(temp_filename, O_RDWR);
	write(tfd, message, strlen(message));
	close(tfd);

	// SYS_openat
	printf("testing openat\n");
	tfd = openat(AT_FDCWD, temp_filename, O_RDWR | O_APPEND);
	close(tfd);

	// SYS_unlink
	printf("testing unlink\n");
	unlink(temp_filename);

	// SYS_unlinkat
	printf("testing unlinkat\n");
	tfd = creat(temp_filename, S_IRWXU);
	close(tfd);
	unlinkat(AT_FDCWD, temp_filename, 0);

	return 0;
}
