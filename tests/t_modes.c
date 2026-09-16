// Opens one file every way that matters, so the reported mode can be checked.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void)
{
    const char *f = "modes_target.txt";

    close(openat(AT_FDCWD, f, O_WRONLY | O_CREAT | O_TRUNC, 0644));
    close(open(f, O_WRONLY | O_TRUNC));
    close(open(f, O_WRONLY | O_APPEND));
    close(open(f, O_RDWR));
    close(open(f, O_RDONLY | O_CLOEXEC));
#ifdef SYS_open
    close(syscall(SYS_open, f, O_WRONLY | O_TRUNC, 0));
#endif
#ifdef SYS_creat
    close(syscall(SYS_creat, f, 0600));
#endif
    unlink(f);
    return 0;
}
