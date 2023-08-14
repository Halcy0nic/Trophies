When executing my fuzz tests, I discovered that SSRC Version 1.33 suffers from a divide by zero bug [(CWE-369)](https://cwe.mitre.org/data/definitions/369.html) when supplied with malformed input in the form of a WAV file, effectively crashing the application. Any package or library that makes use of SSRC to convert or process WAV files will also crash, resulting in a denial of service.

## Reproduction

The files needed for reproduction have been attached to this repository.  The first file in the zip archive is named **crash_clang.wav** and can be used to reproduce the crash against programs compiled with Clang.  The second file is named **crash_gcc.wav**, which can be used to reproduce the crash against programs compiled with GCC.  For simplicity, you can compile the project using the default makefile and execute **ssrc** or **ssrc_hp** as seen below:

GCC
```
$ ./ssrc crash_gcc.wav output.wav

floating point exception  ./ssrc crash_gcc.wav output.wav
```
CLANG
```
$ ./ssrc crash_clang.wav output.wav

floating point exception  ./ssrc crash_clang.wav output.wav
```

This will result in a divide by zero bug, as seen in the GDB backtrace:

```
Program received signal SIGFPE, Arithmetic exception.
0x0000000000410022 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x61746164
 RBX  0x6926b0 ◂— 0xfbad2488
 RCX  0x61746164
 RDX  0x0
 RDI  0x140003
 RSI  0x0
 R8   0xc00
 R9   0x1
 R10  0x7ffff7cf79b8 ◂— 0x100022000076e7
 R11  0x7ffff7d62540 (fread) ◂— push   r15
 R12  0x1
 R13  0x1
 R14  0x7fffffffe1d2 ◂— 'output.wav'
 R15  0x7fffffffe1c8 ◂— 'crash.wav'
 RBP  0x48eae8 (__afl_area_ptr) —▸ 0x490f90 ◂— 0x0
 RSP  0x7fffffffd340 ◂— 0x0
 RIP  0x410022 ◂— idiv   esi
──────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x410022    idiv   esi
    ↓
   0x410022    idiv   esi

──────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffd340 ◂— 0x0
01:0008│     0x7fffffffd348 ◂— 0xffffd5e0
02:0010│     0x7fffffffd350 ◂— 0x1
03:0018│     0x7fffffffd358 ◂— 0xffffffff
04:0020│     0x7fffffffd360 ◂— 0x3ff0000000000000
05:0028│     0x7fffffffd368 ◂— 0xffffffff
06:0030│     0x7fffffffd370 ◂— 0xffffffff
07:0038│     0x7fffffffd378 ◂— 0x140003
────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0         0x410022
   f 1   0x7ffff7d1318a __libc_start_call_main+122
   f 2   0x7ffff7d13245 __libc_start_main+133
   f 3         0x4044b1

```

To verify, you can recompile the program using address sanitizer by adding *-fsanitize=address* to the *CFLAGS* variable in the makefile:

```
CFLAGS = -Wall -Wno-attributes -Wno-unused -O3 -ffp-contract=off -fsanitize=address
```


ASAN Output:

```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==1803467==ERROR: AddressSanitizer: FPE on unknown address 0x0000004dd700 (pc 0x0000004dd700 bp 0x7ffc22b743c0 sp 0x7ffc22b736c0 T0)
    #0 0x4dd700  (/home/kali/projects/fuzzing/SSRC/ssrc+0x4dd700)
    #1 0x7f43ab5ac189 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #2 0x7f43ab5ac244 in __libc_start_main csu/../csu/libc-start.c:381:3
    #3 0x4203c0  (/home/kali/projects/fuzzing/SSRC/ssrc+0x4203c0)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: FPE (/home/kali/projects/fuzzing/SSRC/ssrc+0x4dd700) 
==1803467==ABORTING
```


