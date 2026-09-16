// Relative paths, including one against a directory descriptor, should be
// logged as absolute paths.
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    int dirfd;

    mkdir("subdir", 0755);
    dirfd = open("subdir", O_RDONLY | O_DIRECTORY);
    close(open("relative-in-cwd", O_RDONLY));
    if (dirfd >= 0) {
        close(openat(dirfd, "relative-to-dirfd", O_RDONLY));
        close(dirfd);
    }
    rmdir("subdir");
    return 0;
}
