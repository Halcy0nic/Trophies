While I was running my fuzz tests in the background I discovered multiple memory corruption security flaws in libforth Version 4.0 at various locations. I have attached a zip archive named crash.zip for replication.  The easiest way to reproduce is to compile the project and execute forth against the crash files that call specific library functions:

```
$ forth [name of reproduction file]
```

### Zip archive with reproduction files:

[crash.zip](https://github.com/Halcy0nic/Trophies/files/12330768/crash.zip)


### After triaging all of the crashes, I can verify that there are 17 separate and unique issues at the following locations:

## Out of bounds read (CWE-125) in *static int match(forth_cell_t \*m, forth_cell_t pwd, const char \*s)* at libforth.c, line 1306 when attempting to execute 'forth_cell_t len = WORD_LENGTH(m\[pwd + 1\]);':

### File for replication: match_line_1306.fth

### Source Code: 

https://github.com/howerj/libforth/blob/b851c6a25150e7d2114804fc8712664c6d825214/libforth.c#L1306

### GDB Backtrace:
```
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA                                                     
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x0                                                                                             
 RBX  0x7ffff7d87010 ◂— 0xf010408485434ff
 RCX  0x7ffff7f483c0 (_nl_C_LC_CTYPE_class+256) ◂— 0x2000200020002
 RDX  0x2000002da                                                                                     
 RDI  0x7ffff7d87010 ◂— 0xf010408485434ff
 RSI  0x7ffff7d87158 ◂— 0x2a /* '*' */             
 R8   0x8dc                                                                                                                                                                                                  
 R9   0x0                            
 R10  0x7ffff7f47ac0 (_nl_C_LC_CTYPE_toupper+512) ◂— 0x100000000            
 R11  0x7ffff7f483c0 (_nl_C_LC_CTYPE_class+256) ◂— 0x2000200020002
 R12  0x2000002db
 R13  0x7ffff7d87058 ◂— 0x0                                                                           
 R14  0x7ffff7d87058 ◂— 0x0
 R15  0x7fffffffdbd0 —▸ 0x7fffffffde98 ◂— 0x0                                                         
 RBP  0x7ffff7d87158 ◂— 0x2a /* '*' */                                                                
 RSP  0x7fffffffdb00 —▸ 0x7ffff7d87010 ◂— 0xf010408485434ff
 RIP  0x555555559e23 (forth_find+67) ◂— mov    rax, qword ptr [r13 + r12*8]
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x555555559e23 <forth_find+67>     mov    rax, qword ptr [r13 + r12*8]          
   0x555555559e28 <forth_find+72>     lea    r14, [r12*8]                                                                                                                                                    
   0x555555559e30 <forth_find+80>     mov    rbx, rax             
   0x555555559e33 <forth_find+83>     and    ebx, 0x80            
   0x555555559e39 <forth_find+89>     jne    forth_find+48                <forth_find+48>
    ↓                             
   0x555555559e10 <forth_find+48>     mov    rdx, qword ptr [r13 + r14 - 8]
   0x555555559e15 <forth_find+53>     cmp    rdx, 0x40
   0x555555559e19 <forth_find+57>     jbe    forth_find+208                <forth_find+208>
    ↓                                                                                                 
   0x555555559eb0 <forth_find+208>    xor    r12d, r12d                                                                                                                                                      
   0x555555559eb3 <forth_find+211>    jmp    forth_find+172                <forth_find+172>
    ↓                                
   0x555555559e8c <forth_find+172>    add    rsp, 8
```

### Address Sanitizer Output:
```
==1122143==ERROR: AddressSanitizer: SEGV on unknown address 0x7f89f7f6ff20 (pc 0x558480b1fd3b bp 0x7f79f7f6e808 sp 0x7ffe51895260 T0)
==1122143==The signal is caused by a READ memory access.
    #0 0x558480b1fd3b in match /dev/shm/libforth/libforth.c:1306
    #1 0x558480b1fd3b in forth_find /dev/shm/libforth/libforth.c:1343
    #2 0x558480b241ba in forth_run /dev/shm/libforth/libforth.c:2354
    #3 0x558480b1b92f in eval_file /dev/shm/libforth/main.c:248
    #4 0x558480b1af6e in main /dev/shm/libforth/main.c:449
    #5 0x7f79fac46189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0x7f79fac46244 in __libc_start_main_impl ../csu/libc-start.c:381
    #7 0x558480b1b530 in _start (/dev/shm/libforth/forth+0xc530)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /dev/shm/libforth/libforth.c:1306 in match
==1122143==ABORTING

```

---


## Invalid free (CWE-763) in *int forth_run(forth_t \*o)* at libforth.c, line 2745 when attempting to execute 'free((char*)f);':

### File for replication: forth_run_line_2745.fth

### Source Code: 

https://github.com/howerj/libforth/blob/b851c6a25150e7d2114804fc8712664c6d825214/libforth.c#L2745

### GDB Backtrace:
```
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffff7dc86c0 ◂— 0x0
 RBX  0xffffffffffffff80
 RCX  0x1
 RDX  0x55555555f0c0 ◂— 0xffffbf20ffffcc48
 RDI  0x2a
 RSI  0x1a
 R8   0x8dc
 R9   0x64
 R10  0x7ffff7dd69a0 ◂— 0x10001200004e24 /* '$N' */
 R11  0x7ffff7e63cc0 (free) ◂— test   rdi, rdi
 R12  0x0
 R13  0x40
 R14  0x7ffff7d87058 ◂— 0x0
 R15  0x7ffff7d87010 ◂— 0xf010408485434ff
 RBP  0x7ffff7dc5060 ◂— 0x0
 RSP  0x7fffffffdb00 —▸ 0x7ffff7d87010 ◂— 0xf010408485434ff
 RIP  0x7ffff7e63cda (free+26) ◂— mov    rax, qword ptr [rdi - 8]
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x7ffff7e63cda <free+26>     mov    rax, qword ptr [rdi - 8]
   0x7ffff7e63cde <free+30>     mov    ebp, dword ptr fs:[rbx]
   0x7ffff7e63ce1 <free+33>     test   al, 2
   0x7ffff7e63ce3 <free+35>     jne    free+128                <free+128>
    ↓
   0x7ffff7e63d40 <free+128>    mov    edx, dword ptr [rip + 0x139642] <mp_+72>
   0x7ffff7e63d46 <free+134>    test   edx, edx
   0x7ffff7e63d48 <free+136>    jne    free+176                <free+176>
    ↓
   0x7ffff7e63d70 <free+176>    mov    rdi, rsi
   0x7ffff7e63d73 <free+179>    call   munmap_chunk                <munmap_chunk>
 
   0x7ffff7e63d78 <free+184>    mov    dword ptr fs:[rbx], ebp
   0x7ffff7e63d7b <free+187>    add    rsp, 0x18

```

### Address Sanitizer Output:

```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==1147301==ERROR: AddressSanitizer: SEGV on unknown address 0x00000000001a (pc 0x7f24978289c6 bp 0x00000000002a sp 0x7ffe9396fb50 T0)
==1147301==The signal is caused by a WRITE memory access.
==1147301==Hint: address points to the zero page.
    #0 0x7f24978289c6 in bool __sanitizer::atomic_compare_exchange_strong<__sanitizer::atomic_uint8_t>(__sanitizer::atomic_uint8_t volatile*, __sanitizer::atomic_uint8_t::Type*, __sanitizer::atomic_uint8_t::Type, __sanitizer::memory_order) ../../../../src/libsanitizer/sanitizer_common/sanitizer_atomic_clang.h:80
    #1 0x7f24978289c6 in __asan::Allocator::AtomicallySetQuarantineFlagIfAllocated(__asan::AsanChunk*, void*, __sanitizer::BufferedStackTrace*) ../../../../src/libsanitizer/asan/asan_allocator.cpp:621
    #2 0x7f24978289c6 in __asan::Allocator::Deallocate(void*, unsigned long, unsigned long, __sanitizer::BufferedStackTrace*, __asan::AllocType) ../../../../src/libsanitizer/asan/asan_allocator.cpp:697
    #3 0x7f24978289c6 in __asan::asan_free(void*, __sanitizer::BufferedStackTrace*, __asan::AllocType) ../../../../src/libsanitizer/asan/asan_allocator.cpp:971
    #4 0x7f24978ae4a7 in __interceptor_free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:128
    #5 0x561df32b70bb in forth_run /dev/shm/libforth/libforth.c:2745
    #6 0x561df32b092f in eval_file /dev/shm/libforth/main.c:248
    #7 0x561df32aff6e in main /dev/shm/libforth/main.c:449
    #8 0x7f2497646189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #9 0x7f2497646244 in __libc_start_main_impl ../csu/libc-start.c:381
    #10 0x561df32b0530 in _start (/dev/shm/libforth/forth+0xc530)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV ../../../../src/libsanitizer/sanitizer_common/sanitizer_atomic_clang.h:80 in bool __sanitizer::atomic_compare_exchange_strong<__sanitizer::atomic_uint8_t>(__sanitizer::atomic_uint8_t volatile*, __sanitizer::atomic_uint8_t::Type*, __sanitizer::atomic_uint8_t::Type, __sanitizer::memory_order)
==1147301==ABORTING

```

---



## Out of bounds read (CWE-125) in *static void check_is_asciiz(jmp_buf \*on_error, char \*s, forth_cell_t end)* libforth/libforth.c, line 1436 when attempting to execute 'if (*(s + end) != '\0')':

### File for replication: check_is_asciiz_line_1436.fth

### Source Code: 

https://github.com/howerj/libforth/blob/b851c6a25150e7d2114804fc8712664c6d825214/libforth.c#L1436

### GDB Backtrace:
```
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA                                                     
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x55555557cf90 ◂— 0xfbad2480                                                                    
 RBX  0x7ffff7d87010 ◂— 0xf010408485434ff          
 RCX  0x4                                                                                                                                                                                                    
 RDX  0x55555555f0c0 ◂— 0xffffbf20ffffcc48
 RDI  0x7ffff7d87010 ◂— 0xf010408485434ff                                                             
 RSI  0x7fffffffdbc0 —▸ 0x7fffffffde88 ◂— 0x0
 R8   0x8dc                                 
 R9   0x5555555632a0 ◂— 0xfbad2488                 
 R10  0x180            
 R11  0x1e0                                                                                           
 R12  0x7ffff7d87058 ◂— 0x0   
 R13  0x55555555d11f ◂— 0x2065726f63006277 /* 'wb' */                                                 
 R14  0x7ffff7d87058 ◂— 0x0
 R15  0x7ffff7d87010 ◂— 0xf010408485434ff
 RBP  0x7ffff7dc5078 —▸ 0x55555557cdb0 ◂— 0xfbad2480                             
 RSP  0x7fffffffdb30 ◂— 0x2f9                                                                                                                                                                                
 RIP  0x55555555b6e7 (forth_run+2535) ◂— cmp    byte ptr [r12 + rax + 1], 0                           
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x55555555b6e7 <forth_run+2535>    cmp    byte ptr [r12 + rax + 1], 0                              
   0x55555555b6ed <forth_run+2541>    jne    forth_run+4648                <forth_run+4648>
    ↓                             
   0x55555555bf28 <forth_run+4648>    mov    r8, r12                                                  
   0x55555555bf2b <forth_run+4651>    lea    rcx, [rip + 0x294c]                                      
   0x55555555bf32 <forth_run+4658>    mov    edx, 0x59d                                                                                                                                                      
   0x55555555bf37 <forth_run+4663>    lea    rsi, [rip + 0x32b2]           <__func__.2>               
   0x55555555bf3e <forth_run+4670>    lea    rdi, [rip + 0x10e5]                                      
   0x55555555bf45 <forth_run+4677>    xor    eax, eax                                                 
   0x55555555bf47 <forth_run+4679>    call   forth_logger                <forth_logger>               
                                                  
   0x55555555bf4c <forth_run+4684>    lea    rdi, [rsp + 0x90]                                        
   0x55555555bf54 <forth_run+4692>    mov    esi, 3

```

### Address Sanitizer Output:
```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==1231948==ERROR: AddressSanitizer: SEGV on unknown address 0x1c16ea37e869 (pc 0x55be73cf37d3 bp 0x7f6351c27808 sp 0x7ffc17e47850 T0)
==1231948==The signal is caused by a READ memory access.
    #0 0x55be73cf37d3 in check_is_asciiz /dev/shm/libforth/libforth.c:1436
    #1 0x55be73cf37d3 in forth_get_string /dev/shm/libforth/libforth.c:1453
    #2 0x55be73cf37d3 in forth_run /dev/shm/libforth/libforth.c:2674
    #3 0x55be73cec92f in eval_file /dev/shm/libforth/main.c:248
    #4 0x55be73cebf6e in main /dev/shm/libforth/main.c:449
    #5 0x7f6351046189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0x7f6351046244 in __libc_start_main_impl ../csu/libc-start.c:381
    #7 0x55be73cec530 in _start (/dev/shm/libforth/forth+0xc530)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /dev/shm/libforth/libforth.c:1436 in check_is_asciiz
==1231948==ABORTING

```

---

## Stack-based buffer overflow (CWE-121) in *static int print_cell(forth_t \*o, FILE \*out, forth_cell_t u)* at libforth.c, line 1367 when attempting to execute 's\[i++\] = conv[u % base];':

### File for replication: print_cell_line_1367.fth

### Source Code: 

https://github.com/howerj/libforth/blob/b851c6a25150e7d2114804fc8712664c6d825214/libforth.c#L1367

### GDB Backtrace:

```
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA                                                     
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x40                                                                                                                                                                                                   
 RBX  0x8                                                                                             
 RCX  0x1580                                       
 RDX  0x30                                                                                            
 RDI  0x40                                                                                            
 RSI  0x1
 R8   0x40                                                                                            
 R9   0x55555555f700 (conv) ◂— '0123456789abcdefghijklmnopqrstuvwxzy'
 R10  0x1000                                                                                          
 R11  0x410                                                                                           
 R12  0x1580                                    
 R13  0x1                                                                                             
 R14  0x7ffff7f9e760 (_IO_2_1_stdout_) ◂— 0xfbad2a84
 R15  0x7ffff7d87010 ◂— 0xf010408485434ff                                                                                                                                                                    
 RBP  0x7fffffffda80 ◂— 0x3030303030303030 ('00000000')
 RSP  0x7fffffffda80 ◂— 0x3030303030303030 ('00000000')
 RIP  0x5555555593d6 (print_cell+150) ◂— mov    byte ptr [rbp + rcx], dl
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x5555555593d6 <print_cell+150>    mov    byte ptr [rbp + rcx], dl
   0x5555555593da <print_cell+154>    add    rcx, 1
   0x5555555593de <print_cell+158>    cmp    rdi, rsi
   0x5555555593e1 <print_cell+161>    jae    print_cell+128                <print_cell+128>
    ↓                                     
   0x5555555593c0 <print_cell+128>    mov    rax, r8 
   0x5555555593c3 <print_cell+131>    xor    edx, edx
   0x5555555593c5 <print_cell+133>    mov    rdi, r8
   0x5555555593c8 <print_cell+136>    mov    r12d, ecx                                                                                                                                                       
   0x5555555593cb <print_cell+139>    div    rsi                                                      
   0x5555555593ce <print_cell+142>    movzx  edx, byte ptr [r9 + rdx]
   0x5555555593d3 <print_cell+147>    mov    r8, rax        
```

### Address Sanitizer Output:
```
==1264804==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd6498d371 at pc 0x55e3edcf16f8 bp 0x7ffd6498d2e0 sp 0x7ffd6498d2d8
WRITE of size 1 at 0x7ffd6498d371 thread T0
    #0 0x55e3edcf16f7 in print_cell /dev/shm/libforth/libforth.c:1367
    #1 0x55e3edcf1849 in print_stack /dev/shm/libforth/libforth.c:1484
    #2 0x55e3edcf1849 in print_stack /dev/shm/libforth/libforth.c:1474
    #3 0x55e3edcf5f7a in forth_run /dev/shm/libforth/libforth.c:2554
    #4 0x55e3edcee92f in eval_file /dev/shm/libforth/main.c:248
    #5 0x55e3edcedf6e in main /dev/shm/libforth/main.c:449
    #6 0x7f7afea46189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #7 0x7f7afea46244 in __libc_start_main_impl ../csu/libc-start.c:381
    #8 0x55e3edcee530 in _start (/dev/shm/libforth/forth+0xc530)

Address 0x7ffd6498d371 is located in stack of thread T0 at offset 113 in frame
    #0 0x55e3edcf146f in print_cell /dev/shm/libforth/libforth.c:1357

  This frame has 1 object(s):
    [48, 113) 's' (line 1359) <== Memory access at offset 113 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /dev/shm/libforth/libforth.c:1367 in print_cell
Shadow bytes around the buggy address:
  0x10002c929a10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10002c929a20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10002c929a30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10002c929a40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10002c929a50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x10002c929a60: f1 f1 f1 f1 f1 f1 00 00 00 00 00 00 00 00[01]f3
  0x10002c929a70: f3 f3 f3 f3 00 00 00 00 00 00 00 00 00 00 00 00
  0x10002c929a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10002c929a90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10002c929aa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10002c929ab0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
==1264804==ABORTING

```


---

## Out of bounds write (CWE-787) in *static forth_cell_t compile(forth_t \*o, forth_cell_t code, const char \*str, forth_cell_t compiling, forth_cell_t hide)* at libforth.c, line 1241 when attempting to execute 'strcpy((char *)(o->m + head), str);':

### File for replication: compile_line_1241.fth

### Source Code: 

https://github.com/howerj/libforth/blob/b851c6a25150e7d2114804fc8712664c6d825214/libforth.c#L1241

### GDB Backtrace:

```
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x207ffff7d88750
 RBX  0x7ffff7d87010 ◂— 0xf010408485434ff
 RCX  0x18
 RDX  0x32
 RDI  0x207ffff7d88750
 RSI  0x7ffff7d87158 ◂— 0x32 /* '2' */
 R8   0x8dc
 R9   0x5555555632a0 ◂— 0xfbad2488
 R10  0x7ffff7fc5080
 R11  0x293
 R12  0x2
 R13  0x7ffff7d87158 ◂— 0x32 /* '2' */
 R14  0x7ffff7d87058 ◂— 0x0
 R15  0x7ffff7d87010 ◂— 0xf010408485434ff
 RBP  0x1
 RSP  0x7fffffffdaf8 —▸ 0x555555559667 (compile.constprop.0.isra+55) ◂— mov    rdi, r13
 RIP  0x7ffff7f20d23 (__strcpy_avx2+755) ◂— mov    word ptr [rdi], dx
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x7ffff7f20d23 <__strcpy_avx2+755>    mov    word ptr [rdi], dx
   0x7ffff7f20d26 <__strcpy_avx2+758>    vzeroupper 
   0x7ffff7f20d29 <__strcpy_avx2+761>    ret    
 
   0x7ffff7f20d2a <__strcpy_avx2+762>    nop    word ptr [rax + rax]
   0x7ffff7f20d30 <__strcpy_avx2+768>    movzx  ecx, word ptr [rsi]
   0x7ffff7f20d33 <__strcpy_avx2+771>    mov    word ptr [rdi], cx
   0x7ffff7f20d36 <__strcpy_avx2+774>    mov    byte ptr [rdi + 2], 0
   0x7ffff7f20d3a <__strcpy_avx2+778>    vzeroupper 
   0x7ffff7f20d3d <__strcpy_avx2+781>    ret    
 
   0x7ffff7f20d3e <__strcpy_avx2+782>    nop    
   0x7ffff7f20d40 <__strcpy_avx2+784>    mov    edx, dword ptr [rsi]

```

### Address Sanitizer Output:
```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==1333584==ERROR: AddressSanitizer: SEGV on unknown address (pc 0x7f7d8d838cab bp 0x7ffc98533a50 sp 0x7ffc985331e8 T0)
==1333584==The signal is caused by a READ memory access.
==1333584==Hint: this fault was caused by a dereference of a high value address (see register values below).  Dissassemble the provided pc to learn which register was used.
    #0 0x7f7d8d838cab in AddressIsPoisoned ../../../../src/libsanitizer/asan/asan_mapping.h:407
    #1 0x7f7d8d838cab in QuickCheckForUnpoisonedRegion ../../../../src/libsanitizer/asan/asan_interceptors_memintrinsics.h:31
    #2 0x7f7d8d85277f in __interceptor_strcpy ../../../../src/libsanitizer/asan/asan_interceptors.cpp:440
    #3 0x55aeea6fbb72 in compile /dev/shm/libforth/libforth.c:1241
    #4 0x55aeea70061c in forth_run /dev/shm/libforth/libforth.c:2304
    #5 0x55aeea6f892f in eval_file /dev/shm/libforth/main.c:248
    #6 0x55aeea6f7f6e in main /dev/shm/libforth/main.c:449
    #7 0x7f7d8e206189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #8 0x7f7d8e206244 in __libc_start_main_impl ../csu/libc-start.c:381
    #9 0x55aeea6f8530 in _start (/dev/shm/libforth/forth+0xc530)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV ../../../../src/libsanitizer/asan/asan_mapping.h:407 in AddressIsPoisoned
==1333584==ABORTING

```

---

## Out of bounds read (CWE-125) in *static int forth_get_char(forth_t \*o)* at libforth.c, line 1091 when attempting to execute 'r = fgetc((FILE*)(o->m\[FIN\]));':

### File for replication: forth_get_char_line_1091.fth

### Source Code: 

https://github.com/howerj/libforth/blob/b851c6a25150e7d2114804fc8712664c6d825214/libforth.c#L1091

### GDB Backtrace:

```
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x0
 RBX  0x5
 RCX  0x0
 RDX  0x55555555f0c0 ◂— 0xffffbf20ffffcc48
 RDI  0x5
 RSI  0x7ffff7d87158 ◂— 0x0
 R8   0x8dc
 R9   0x55555555edb0 ◂— 0x656764756d73203a (': smudge')
 R10  0x7ffff7fc5080
 R11  0x293
 R12  0x0
 R13  0x5
 R14  0x7ffff7d87158 ◂— 0x0
 R15  0x7fffffffda20 ◂— 0x7e02
 RBP  0x7ffff7dc5058 ◂— 0x0
 RSP  0x7fffffffd930 ◂— 0x0
 RIP  0x7ffff7e48b89 (getc+9) ◂— test   byte ptr [rdi + 0x74], 0x80
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x7ffff7e48b89 <getc+9>       test   byte ptr [rdi + 0x74], 0x80
   0x7ffff7e48b8d <getc+13>      je     getc+168                <getc+168>
    ↓
   0x7ffff7e48c28 <getc+168>     mov    rax, qword ptr [rdi + 8]
   0x7ffff7e48c2c <getc+172>     cmp    rax, qword ptr [rdi + 0x10]
   0x7ffff7e48c30 <getc+176>     jae    getc+240                <getc+240>
    ↓
   0x7ffff7e48c70 <getc+240>     add    rsp, 0x18
   0x7ffff7e48c74 <getc+244>     pop    rbx
   0x7ffff7e48c75 <getc+245>     pop    rbp
   0x7ffff7e48c76 <getc+246>     jmp    __uflow                <__uflow>
    ↓
   0x7ffff7e4dd50 <__uflow>      push   rbp
   0x7ffff7e4dd51 <__uflow+1>    push   rbx

```

### Address Sanitizer Output:
```
==1351430==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000079 (pc 0x7f670349cb89 bp 0x7f670401483c sp 0x7ffea3a50810 T0)
==1351430==The signal is caused by a READ memory access.
==1351430==Hint: address points to the zero page.
    #0 0x7f670349cb89 in _IO_getc libio/getc.c:37
    #1 0x55ad1ee56fa6 in forth_get_char /dev/shm/libforth/libforth.c:1091
    #2 0x55ad1ee56fa6 in forth_get_char /dev/shm/libforth/libforth.c:1081
    #3 0x55ad1ee56fa6 in forth_get_word /dev/shm/libforth/libforth.c:1140
    #4 0x55ad1ee5c185 in forth_run /dev/shm/libforth/libforth.c:2352
    #5 0x55ad1ee5c60e in forth_run /dev/shm/libforth/libforth.c:2535
    #6 0x55ad1ee5392f in eval_file /dev/shm/libforth/main.c:248
    #7 0x55ad1ee52f6e in main /dev/shm/libforth/main.c:449
    #8 0x7f6703446189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #9 0x7f6703446244 in __libc_start_main_impl ../csu/libc-start.c:381
    #10 0x55ad1ee53530 in _start (/dev/shm/libforth/forth+0xc530)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV libio/getc.c:37 in _IO_getc
==1351430==ABORTING

```

---

## Out of bounds read (CWE-125) in *static void print_stack(forth_t \*o, FILE \*out, forth_cell_t \*S, forth_cell_t f)* at libforth.c, line 1481 when attempting to execute 'print_cell(o, out, *(o->S + i + 1));':

### File for replication: print_stack_line_1481.fth


### Source Code: 

https://github.com/howerj/libforth/blob/b851c6a25150e7d2114804fc8712664c6d825214/libforth.c#L1481

### GDB Backtrace:

```
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffff7dc5058 ◂— 0x0                                                                           
 RBX  0x3cdf5                                                                                         
 RCX  0x7ffff7ec3190 (write+16) ◂— cmp    rax, -0x1000 /* 'H=' */                   
 RDX  0xffffffff                                                                                                                                                                                             
 RDI  0x7ffff7d87010 ◂— 0xf010408485434ff
 RSI  0x7ffff7f9e680 (_IO_2_1_stderr_) ◂— 0xfbad2887               
 R8   0x0                                                                                             
 R9   0x64                 
 R10  0x7fffffffb877 ◂— 0x7ffff7e4c55100
 R11  0x202                                                                                           
 R12  0x7ffff7d87010 ◂— 0xf010408485434ff                                                             
 R13  0xffffffffffff86e0                
 R14  0x0        
 R15  0x7fffffffdbc0 —▸ 0x7fffffffde88 ◂— 0x0
 RBP  0x7ffff7f9e680 (_IO_2_1_stderr_) ◂— 0xfbad2887
 RSP  0x7fffffffdb00 —▸ 0x7ffff7d87010 ◂— 0xf010408485434ff
 RIP  0x55555555949f (print_stack+95) ◂— mov    rdx, qword ptr [rax + rbx*8]                                                                                                                                 
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x55555555949f <print_stack+95>     mov    rdx, qword ptr [rax + rbx*8]
   0x5555555594a3 <print_stack+99>     call   print_cell                <print_cell>
                                  
   0x5555555594a8 <print_stack+104>    mov    rsi, rbp
   0x5555555594ab <print_stack+107>    mov    edi, 0x20                       
   0x5555555594b0 <print_stack+112>    call   fputc@plt                <fputc@plt>
                                  
   0x5555555594b5 <print_stack+117>    cmp    r13, rbx                                                                                                                                                       
   0x5555555594b8 <print_stack+120>    ja     print_stack+80                <print_stack+80>
                                      
   0x5555555594ba <print_stack+122>    mov    rsi, rbp
   0x5555555594bd <print_stack+125>    mov    rdi, r12
   0x5555555594c0 <print_stack+128>    mov    rdx, r14
   0x5555555594c3 <print_stack+131>    call   print_cell                <print_cell>

```

### Address Sanitizer Output:
```
==1381839==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7f1a49660848 at pc 0x55d3a318b87c bp 0x7ffd14815d80 sp 0x7ffd14815d78
READ of size 8 at 0x7f1a49660848 thread T0
    #0 0x55d3a318b87b in print_stack /dev/shm/libforth/libforth.c:1481
    #1 0x55d3a318b87b in print_stack /dev/shm/libforth/libforth.c:1474
    #2 0x55d3a318ef23 in trace /dev/shm/libforth/libforth.c:1500
    #3 0x55d3a318ef23 in forth_run /dev/shm/libforth/libforth.c:2269
    #4 0x55d3a318892f in eval_file /dev/shm/libforth/main.c:248
    #5 0x55d3a3187f6e in main /dev/shm/libforth/main.c:449
    #6 0x7f1a48a46189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #7 0x7f1a48a46244 in __libc_start_main_impl ../csu/libc-start.c:381
    #8 0x55d3a3188530 in _start (/dev/shm/libforth/forth+0xc530)

0x7f1a49660848 is located 0 bytes to the right of 262216-byte region [0x7f1a49620800,0x7f1a49660848)
allocated by thread T0 here:
    #0 0x7f1a48cae987 in __interceptor_calloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:154
    #1 0x55d3a319299f in forth_init /dev/shm/libforth/libforth.c:1721

SUMMARY: AddressSanitizer: heap-buffer-overflow /dev/shm/libforth/libforth.c:1481 in print_stack
Shadow bytes around the buggy address:
  0x0fe3c92c40b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe3c92c40c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe3c92c40d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe3c92c40e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe3c92c40f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0fe3c92c4100: 00 00 00 00 00 00 00 00 00[fa]fa fa fa fa fa fa
  0x0fe3c92c4110: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0fe3c92c4120: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0fe3c92c4130: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0fe3c92c4140: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0fe3c92c4150: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==1381839==ABORTING
```

---
