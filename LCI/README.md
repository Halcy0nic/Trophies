Two unique security bugs were discovered in the LCI program when executing various fuzz tests against the interpreter.  The first vulnerability discovered was an out of bounds read and the second a null pointer dereference.  I have included brief descriptions of the bugs along with reproduction steps in the following sections and have attached the necessary LOLCODE files needed for replication.  Both issues were replicated on various 64 bit Linux and OSX systems (using gcc and clang to compile the program).  Given the nature and location of the out of bounds read and null pointer dereference, I would assume the vulnerability would affect 64 bit Windows systems as well.

## Out of Bounds Read

1. To reproduce the issue, execute LCI against the attached progam named **overflow.lol**.  Notice the interpreter segfaults immediatlely with an invalid READ of size 1

```
$ ./lci overflow.lol

segmentation fault  ./lci overflow.lo
```

2. Further debugging with ASAN gave better clarity regarding the exact location where the read was taking place. To compile with ASAN, you can add the following configuration options to the CMakeLists.txt file when building LCI from source:

```
add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)
```

3. Executing the program produces the following result from ASAN:
```                                                                                                                                            
=================================================================
==1078056==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x619000000480 at pc 0x7f35f2dadbac bp 0x7ffe77337270 sp 0x7ffe77336a20
READ of size 1 at 0x619000000480 thread T0
    #0 0x7f35f2dadbab in __interceptor_strncmp ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:497
    #1 0x5609c0da38f9 in scanBuffer (/home/kali/projects/fuzzing/lci/lci+0x21a8f9)
    #2 0x5609c0da4d57 in main (/home/kali/projects/fuzzing/lci/lci+0x21bd57)
    #3 0x7f35f2a67209 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7f35f2a672bb in __libc_start_main_impl ../csu/libc-start.c:389
    #5 0x5609c0d96350 in _start (/home/kali/projects/fuzzing/lci/lci+0x20d350)

0x619000000480 is located 0 bytes to the right of 1024-byte region [0x619000000080,0x619000000480)
allocated by thread T0 here:
    #0 0x7f35f2dceb48 in __interceptor_realloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:164
    #1 0x5609c0da48e7 in main (/home/kali/projects/fuzzing/lci/lci+0x21b8e7)
    #2 0x7f35f2a67209 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

SUMMARY: AddressSanitizer: heap-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:497 in __interceptor_strncmp
Shadow bytes around the buggy address:
  0x0c327fff8040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff8050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff8060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff8070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff8080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c327fff8090:[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff80a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff80b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff80c0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff80d0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff80e0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==1078056==ABORTING                    
```

4. Reviewing the backtrace with GDB shows the location of the out of bounds read when scanBuffer is called from main.c (I believe around line 232) with malformed input:


**GDB Backtrace**
```
 RAX  0x37600000
 RBX  0x0
 RCX  0x5555555e8376 ◂— 0x5754420052444c54 /* 'TLDR' */
 RDX  0x4
 RDI  0x5555556f8000
 RSI  0x5555555e8376 ◂— 0x5754420052444c54 /* 'TLDR' */
 R8   0x0
 R9   0x0
 R10  0x8a7732fc159aa867
 R11  0x7ffff7ebbc60 (main_arena) ◂— 0x0
 R12  0x7fffffffde98 —▸ 0x7fffffffe216 ◂— '/dev/shm/lci/lci'
 R13  0x5555555e100b (main) ◂— push   rbp
 R14  0x5555556aade0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555da2e0 (__do_global_dtors_aux) ◂— endbr64 
 R15  0x7ffff7ffd020 (_rtld_global) —▸ 0x7ffff7ffe2c0 —▸ 0x555555554000 ◂— 0x10102464c457f
 RBP  0x7fffffffdd10 —▸ 0x7fffffffdd80 ◂— 0x2
 RSP  0x7fffffffdc88 —▸ 0x5555555e0a44 (scanBuffer+1437) ◂— test   eax, eax
 RIP  0x7ffff7e2046d (__strncmp_avx2+29) ◂— vmovdqu ymm0, ymmword ptr [rdi]
──────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x7ffff7e2046d <__strncmp_avx2+29>    vmovdqu ymm0, ymmword ptr [rdi]
   0x7ffff7e20471 <__strncmp_avx2+33>    vpcmpeqb ymm1, ymm0, ymmword ptr [rsi]
   0x7ffff7e20475 <__strncmp_avx2+37>    vpcmpeqb ymm2, ymm15, ymm0
   0x7ffff7e20479 <__strncmp_avx2+41>    vpandn ymm1, ymm2, ymm1
   0x7ffff7e2047d <__strncmp_avx2+45>    vpmovmskb ecx, ymm1
   0x7ffff7e20481 <__strncmp_avx2+49>    cmp    rdx, 0x20
   0x7ffff7e20485 <__strncmp_avx2+53>    jbe    __strncmp_avx2+80                <__strncmp_avx2+80>
    ↓
   0x7ffff7e204a0 <__strncmp_avx2+80>    not    ecx
   0x7ffff7e204a2 <__strncmp_avx2+82>    bzhi   eax, ecx, edx
   0x7ffff7e204a7 <__strncmp_avx2+87>    jne    __strncmp_avx2+59                <__strncmp_avx2+59>
    ↓
   0x7ffff7e2048b <__strncmp_avx2+59>    tzcnt  ecx, ecx
──────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdc88 —▸ 0x5555555e0a44 (scanBuffer+1437) ◂— test   eax, eax
01:0008│     0x7fffffffdc90 —▸ 0x5555556d7480 ◂— 0x5555556d7
02:0010│     0x7fffffffdc98 —▸ 0x7fffffffe227 ◂— 'vuln/overflow.lo'
03:0018│     0x7fffffffdca0 ◂— 0x24400000000
04:0020│     0x7fffffffdca8 —▸ 0x5555556d86a0 ◂— 0xa322e3120494148 ('HAI 1.2\n')
05:0028│     0x7fffffffdcb0 —▸ 0x5555555e100b (main) ◂— push   rbp
06:0030│     0x7fffffffdcb8 —▸ 0x5555556aade0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555da2e0 (__do_global_dtors_aux) ◂— endbr64 
07:0038│     0x7fffffffdcc0 —▸ 0x5555556d7a90 —▸ 0x5555556d7ba0 —▸ 0x7ffff7eb0021 ◂— 0x38000b42080e4210
────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0   0x7ffff7e2046d __strncmp_avx2+29
   f 1   0x5555555e0a44 scanBuffer+1437
   f 2   0x5555555e1394 main+905
   f 3   0x7ffff7cf020a __libc_start_call_main+122
   f 4   0x7ffff7cf02bc __libc_start_main+124
   f 5   0x5555555da261 _start+33

```

## Null Pointer Dereference

1. To reproduce the issue, execute LCI against the attached progam named **nullderef.lol**.   Notice the interpreter segfaults immediatlely as the interpreter attempts to dereference the value stored in the RAX register, which is null (0). 

```
$ ./lci nullderef.lo

segmentation fault  ./lci nullderef.lol
```

2. Similar to the heap buffer overflow above, further debugging with ASAN gave better clarity regarding the exact location of the null pointer dereference, and helped confirm the existence of the vulnerability.  To compile with ASAN, you can add the following configuration options to the CMakeLists.txt file when building LCI from source:

```
add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)
```

3. Executing the program produces the following result from ASAN:
```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==1077686==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x5597acc7b2c2 bp 0x7fffd09715f0 sp 0x7fffd09715d0 T0)
==1077686==The signal is caused by a READ memory access.
==1077686==Hint: address points to the zero page.
    #0 0x5597acc7b2c2 in nextToken (/home/kali/projects/fuzzing/lci/lci+0x21f2c2)
    #1 0x5597acc80b11 in parseLoopStmtNode (/home/kali/projects/fuzzing/lci/lci+0x224b11)
    #2 0x5597acc8274b in parseStmtNode (/home/kali/projects/fuzzing/lci/lci+0x22674b)
    #3 0x5597acc82a38 in parseBlockNode (/home/kali/projects/fuzzing/lci/lci+0x226a38)
    #4 0x5597acc81c0c in parseFuncDefStmtNode (/home/kali/projects/fuzzing/lci/lci+0x225c0c)
    #5 0x5597acc82778 in parseStmtNode (/home/kali/projects/fuzzing/lci/lci+0x226778)
    #6 0x5597acc82a38 in parseBlockNode (/home/kali/projects/fuzzing/lci/lci+0x226a38)
    #7 0x5597acc81c0c in parseFuncDefStmtNode (/home/kali/projects/fuzzing/lci/lci+0x225c0c)
    #8 0x5597acc82778 in parseStmtNode (/home/kali/projects/fuzzing/lci/lci+0x226778)
    #9 0x5597acc82a38 in parseBlockNode (/home/kali/projects/fuzzing/lci/lci+0x226a38)
    #10 0x5597acc82d7f in parseMainNode (/home/kali/projects/fuzzing/lci/lci+0x226d7f)
    #11 0x5597acc77dc9 in main (/home/kali/projects/fuzzing/lci/lci+0x21bdc9)
    #12 0x7f8baecba209 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #13 0x7f8baecba2bb in __libc_start_main_impl ../csu/libc-start.c:389
    #14 0x5597acc69350 in _start (/home/kali/projects/fuzzing/lci/lci+0x20d350)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/home/kali/projects/fuzzing/lci/lci+0x21f2c2) in nextToken
==1077686==ABORTING   
```

4. Reviewing the backtrace with GDB shows the location of the following comparison in the function nextToken() that results in a null pointer dereference:


**GDB Backtrace**
```
Program received signal SIGSEGV, Segmentation fault.
0x00005555555e2c41 in nextToken ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x26
 RDX  0x5555556d9f48 —▸ 0x5555556d9e20 ◂— 0xd /* '\r' */
 RDI  0x7fffffffd938 —▸ 0x5555556d9f48 —▸ 0x5555556d9e20 ◂— 0xd /* '\r' */
 RSI  0x42
 R8   0x3
 R9   0x5555556d7e90 ◂— 'vuln/nullderef.lo'
 R10  0x0
 R11  0x7ffff7ebbc60 (main_arena) ◂— 0x0
 R12  0x7fffffffde98 —▸ 0x7fffffffe215 ◂— '/dev/shm/lci/lci'
 R13  0x5555555e100b (main) ◂— push   rbp
 R14  0x5555556aade0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555da2e0 (__do_global_dtors_aux) ◂— endbr64 
 R15  0x7ffff7ffd020 (_rtld_global) —▸ 0x7ffff7ffe2c0 —▸ 0x555555554000 ◂— 0x10102464c457f
 RBP  0x7fffffffd910 —▸ 0x7fffffffda10 —▸ 0x7fffffffda60 —▸ 0x7fffffffdab0 —▸ 0x7fffffffdb20 ◂— ...
 RSP  0x7fffffffd910 —▸ 0x7fffffffda10 —▸ 0x7fffffffda60 —▸ 0x7fffffffdab0 —▸ 0x7fffffffdb20 ◂— ...
 RIP  0x5555555e2c41 (nextToken+33) ◂— mov    eax, dword ptr [rax]
──────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x5555555e2c41 <nextToken+33>       mov    eax, dword ptr [rax]
   0x5555555e2c43 <nextToken+35>       cmp    dword ptr [rbp - 0x1c], eax
   0x5555555e2c46 <nextToken+38>       je     nextToken+47                <nextToken+47>
    ↓
   0x5555555e2c4f <nextToken+47>       mov    eax, 1
   0x5555555e2c54 <nextToken+52>       pop    rbp
   0x5555555e2c55 <nextToken+53>       ret    
 
   0x5555555e2c56 <parser_error>       push   rbp
   0x5555555e2c57 <parser_error+1>     mov    rbp, rsp
   0x5555555e2c5a <parser_error+4>     sub    rsp, 0x10
   0x5555555e2c5e <parser_error+8>     mov    dword ptr [rbp - 4], edi
   0x5555555e2c61 <parser_error+11>    mov    qword ptr [rbp - 0x10], rsi
──────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rbp rsp 0x7fffffffd910 —▸ 0x7fffffffda10 —▸ 0x7fffffffda60 —▸ 0x7fffffffdab0 —▸ 0x7fffffffdb20 ◂— ...
01:0008│         0x7fffffffd918 —▸ 0x5555555e58dd (parseLoopStmtNode+1023) ◂— test   eax, eax
02:0010│         0x7fffffffd920 —▸ 0x7ffff7ffd020 (_rtld_global) —▸ 0x7ffff7ffe2c0 —▸ 0x555555554000 ◂— 0x10102464c457f
03:0018│         0x7fffffffd928 —▸ 0x7fffffffda88 —▸ 0x5555556d9f38 —▸ 0x5555556d9ca0 ◂— 0x3a /* ':' */
04:0020│         0x7fffffffd930 ◂— 0x0
05:0028│ rdi     0x7fffffffd938 —▸ 0x5555556d9f48 —▸ 0x5555556d9e20 ◂— 0xd /* '\r' */
06:0030│         0x7fffffffd940 ◂— 0x0
07:0038│         0x7fffffffd948 ◂— 0x1ffffd9a0
────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0   0x5555555e2c41 nextToken+33
   f 1   0x5555555e58dd parseLoopStmtNode+1023
   f 2   0x5555555e6a3a parseStmtNode+825
   f 3   0x5555555e6b90 parseBlockNode+81
   f 4   0x5555555e6381 parseFuncDefStmtNode+443
   f 5   0x5555555e6a64 parseStmtNode+867
   f 6   0x5555555e6b90 parseBlockNode+81
   f 7   0x5555555e6381 parseFuncDefStmtNode+443


```

## References

* [CWE-125](https://cwe.mitre.org/data/definitions/125.html)
* [OWASP Null Pointer Dereference](https://owasp.org/www-community/vulnerabilities/Null_Dereference)
