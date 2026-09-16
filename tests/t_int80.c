/*
An x86-64 program making 32-bit syscalls through int $0x80. Their numbers mean
different things than the 64-bit ones, so a tracer that assumes one table both
misses real file access and invents calls that never happened.
Build with -no-pie so the string addresses fit in 32 bits.
*/
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#if defined(__x86_64__)
long int80(long nr, long b, long c, long d, long S);
__asm__(".text\n.globl int80\nint80:\n"
        "  push %rbx\n"
        "  mov %rdi, %rax\n"
        "  mov %rsi, %rbx\n"
        "  mov %rcx, %r9\n"
        "  mov %rdx, %rcx\n"
        "  mov %r9, %rdx\n"
        "  mov %r8, %rsi\n"
        "  int $0x80\n"
        "  pop %rbx\n"
        "  ret\n");

static const char real_path[] = "/etc/hostname";
static const char phantom_path[] = "/phantom/never-opened";

int main(void)
{
    char buf[128];
    long fd = int80(5, (long)real_path, O_RDONLY, 0, 0);          // i386 open()
    long n = fd >= 0 ? read((int)fd, buf, sizeof buf) : -1;
    fprintf(stderr, "int 0x80 open(%s) -> fd %ld, read %ld bytes\n", real_path, fd, n);
    // i386 257 is remap_file_pages() and fails; on x86-64, 257 is openat(), and
    // rsi (its path argument) points at a path that is never opened.
    fprintf(stderr, "int 0x80 syscall 257 -> %ld\n", int80(257, 0, 0, 0, (long)phantom_path));
    return fd >= 0 ? 0 : 1;
}
#else
int main(void) { fprintf(stderr, "SKIP: not x86-64\n"); return 77; }
#endif
