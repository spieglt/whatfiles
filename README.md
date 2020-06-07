# whatfiles
Whatfiles is a Linux utility that logs what files other programs read/write/create/delete on your system. It traces any new processes and threads that are created as well.

## Rationale:
I've long been frustrated at the lack of a simple utility to see which files a process touches from `main()` to exit. Whether you don't trust a software vendor or are concerned about malware, it's important to be able to know what a program or installer does to your system. There's `lsof` for *nix, but it only observes a moment in time. There's `strace` for Linux and `dtruss` for Mac, but they're complicated and intimidating to many people and have a wide range of use cases. There's Process Explorer for Windows, but it only gives you slices in time also.

## Sample output:
```
mode:  read, file: /home/theron/.gimp-2.8/tool-options/gimp-clone-tool, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /home/theron/.gimp-2.8/tool-options/gimp-heal-tool, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /home/theron/.gimp-2.8/tool-options/gimp-perspective-clone-tool, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /home/theron/.gimp-2.8/tool-options/gimp-convolve-tool, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /home/theron/.gimp-2.8/tool-options/gimp-smudge-tool, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /home/theron/.gimp-2.8/tool-options/gimp-dodge-burn-tool, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /home/theron/.gimp-2.8/tool-options/gimp-desaturate-tool, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /home/theron/.gimp-2.8/plug-ins, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /usr/lib/gimp/2.0/plug-ins, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /home/theron/.gimp-2.8/pluginrc, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /usr/share/locale/en_US/LC_MESSAGES/gimp20-std-plug-ins.mo, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /usr/lib/gimp/2.0/plug-ins/script-fu, syscall: openat(), PID: 8566, process: gimp
mode:  read, file: /etc/ld.so.cache, syscall: openat(), PID: 8574, process: /usr/lib/gimp/2.0/plug-ins/script-fu
mode:  read, file: /etc/ld.so.cache, syscall: openat(), PID: 8574, process: /usr/lib/gimp/2.0/plug-ins/script-fu
mode:  read, file: /usr/lib/libgimpui-2.0.so.0, syscall: openat(), PID: 8574, process: /usr/lib/gimp/2.0/plug-ins/script-fu
mode:  read, file: /usr/lib/libgimpwidgets-2.0.so.0, syscall: openat(), PID: 8574, process: /usr/lib/gimp/2.0/plug-ins/script-fu
mode:  read, file: /usr/lib/libgimpwidgets-2.0.so.0, syscall: openat(), PID: 8574, process: /usr/lib/gimp/2.0/plug-ins/script-fu
mode:  read, file: /usr/lib/libgimp-2.0.so.0, syscall: openat(), PID: 8574, process: /usr/lib/gimp/2.0/plug-ins/script-fu
mode:  read, file: /usr/lib/libgimpcolor-2.0.so.0, syscall: openat(), PID: 8574, process: /usr/lib/gimp/2.0/plug-ins/script-fu
```

## Use:

- basic use, launches `ls` and writes output to a log file in the current directory:

    `$ whatfiles ls -lah ~/Documents`

- specify output file location with `-o`:

    `$ whatfiles -o MyLogFile cd ..`

- include debug output, print to stdout rather than log file:

    `$ whatfiles -d -s apt install zoom`

- attach to currently running process (requires root privileges):

    `$ sudo whatfiles -p 1234`

## Compilation (requires `gcc` and `make`):
```
$ cd whatfiles
$ make
$ sudo make install
```

## Questions that could be asked at some point:

- _Isn't this just a reimplementation of `strace -fe trace=creat,open,openat,unlink,unlinkat ./program`?_

  Yes. Though it aims to be simpler and more user friendly.

- _Are there Mac and Windows versions?_

  Not for the time being. Tracing syscalls on Mac requires `task_for_pid()`, which requires code signing, which I can't get to work, and anyway I have no interest in paying Apple $100/year to write free software. I would be interested in writing a version for Windows at some point but it would have to be a complete rewrite and a steep learning curve.

## Known issues:

- Seems to run slowly and occasionally freeze when used to launch Firefox and Chromium. (Attaching to both with `-p [PID]` once they're running works fine.)


Thank you for your interest, and please also check out [Cloaker](https://github.com/spieglt/cloaker), [Nestur](https://github.com/spieglt/nestur), and [Flying Carpet](https://github.com/spieglt/flyingcarpet)!
