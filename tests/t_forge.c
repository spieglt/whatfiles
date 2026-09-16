// A filename containing a newline must not be able to forge a log line.
#include <fcntl.h>
#include <unistd.h>

int main(void)
{
    getpid();
    close(open("/tmp/x\nmode:  read, file: /etc/FORGED-ENTRY, syscall: openat(), PID: 1, process: init",
               O_RDONLY));
    return 0;
}
