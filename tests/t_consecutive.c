// Three identical syscalls in a row: none of them may be dropped.
#include <fcntl.h>
#include <unistd.h>

int main(void)
{
    close(open("/nonexistent/first", O_RDONLY));
    close(open("/nonexistent/second", O_RDONLY));
    close(open("/nonexistent/third", O_RDONLY));
    return 0;
}
