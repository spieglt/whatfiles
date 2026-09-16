// The other ways a program changes files, beyond open and unlink.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define IGNORE(call) do { if ((call) != 0) { /* the log entry is the point */ } } while (0)

int main(void)
{
    close(open("ops_a.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644));
    IGNORE(rename("ops_a.txt", "ops_b.txt"));
    IGNORE(link("ops_b.txt", "ops_link.txt"));
    IGNORE(symlink("ops_b.txt", "ops_symlink.txt"));
    IGNORE(truncate("ops_b.txt", 0));
    IGNORE(chmod("ops_b.txt", 0600));
    IGNORE(mkdir("ops_dir", 0755));
    IGNORE(rmdir("ops_dir"));
    IGNORE(unlink("ops_link.txt"));
    IGNORE(unlink("ops_symlink.txt"));
    IGNORE(unlink("ops_b.txt"));
    return 0;
}
