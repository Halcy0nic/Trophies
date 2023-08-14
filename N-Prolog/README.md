# CVE-2022-4334

N-Prolog v1.91 was discovered to contain a global buffer overflow vulnerability in the function gettoken() at Main.c. 

## Makefile
```
CC   = gcc
LIBS = -lm -ldl -fsanitize=address


LIBSRASPI = -lm -ldl -lwiringPi -fsanitize=address
INCS =  
CFLAGS = $(INCS) -Wall -O3 -fsanitize=address
DEST = /usr/local/bin
```

## Comiplation and Execution
```
$ make
$ ./npl -s CVE-2022-4334
```

# N-Prolog v 1.94 contains multiple memory corruption issues at various locations. 

### Note: Here is the Makefile I used to compile npl with address sanitizer for debugging
```
CC   = gcc
LIBS = -lm -ldl -fsanitize=address


LIBSRASPI = -lm -ldl -lwiringPi -fsanitize=address
INCS =  
CFLAGS = $(INCS) -Wall -O3 -fsanitize=address
DEST = /usr/local/bin
```

---

# Out-of-bounds read in add_data at data.c


#### Reproduction

```
$ ./npl -s add_data.pl
```

#### GDB Output
```

Program received signal SIGSEGV, Segmentation fault.   
0x000055555557eed1 in cdr (addr=-1000000001) at data.c:41
41                                                                                      
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA                          
─────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────
*RAX  0xfffffffe5ec479f9                                                                
*RBX  0x57e
*RCX  0x55555f5da420 (heap) ◂— 0x0                                                      
*RDX  0xffffffffc46535ff                                                                
*RDI  0xffffffff                                                                        
 RSI  0x0                                                                               
*R8   0x7ffff7ebfc60 (main_arena) ◂— 0x0                                                                                                                                        
 R9   0x0                                                                               
*R10  0x7ffff7cfc918 ◂— 0x10001200001017
*R11  0x20
*R12  0x5b1         
*R13  0xffffffffc46535ff
*R14  0x57e
*R15  0x5555a2cfa0a0 ◂— 'reproduction/add_data.pl'
*RBP  0x55555f5da420 (heap) ◂— 0x0
*RSP  0x7fffffffd960 ◂— 0x5a6
*RIP  0x55555557eed1 (add_data+193) ◂— mov eax, dword ptr [rbp + rax*8 + 8]
──────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────
   0x55555557eec0 <add_data+176>    movsxd rdx, eax
   0x55555557eec3 <add_data+179>    lea    rax, [rdx*8]                                                                                                                         
   0x55555557eecb <add_data+187>    mov    r13, rdx
   0x55555557eece <add_data+190>    sub    rax, rdx
 ► 0x55555557eed1 <add_data+193>    mov    eax, dword ptr [rbp + rax*8 + 8]
   0x55555557eed5 <add_data+197>    test   eax, eax        
   0x55555557eed7 <add_data+199>    jne    add_data+176                <add_data+176>
    ↓                                                                                   
   0x55555557eec0 <add_data+176>    movsxd rdx, eax
   0x55555557eec3 <add_data+179>    lea    rax, [rdx*8]
   0x55555557eecb <add_data+187>    mov    r13, rdx                                                                                                                             
   0x55555557eece <add_data+190>    sub    rax, rdx

                                   
```
#### GDB Backtrace

```
#0  0x000055555557eed1 in cdr (addr=-1000000001) at data.c:41
#1  add_data (pred=<optimized out>, data=data@entry=1457) at data.c:3478
#2  0x0000555555574035 in o_define (x=1446, y=<optimized out>) at builtin.c:4627
#3  0x000055555556918b in b_assert (arglist=1431, rest=rest@entry=0) at builtin.c:2544
#4  0x0000555555570068 in b_consult (rest=0, arglist=<optimized out>) at builtin.c:1581
#5  b_consult (arglist=<optimized out>, rest=rest@entry=0) at builtin.c:1521
#6  0x0000555555556870 in main (argc=argc@entry=3, argv=argv@entry=0x7fffffffdd78) at main.c:283
#7  0x00007ffff7d1418a in __libc_start_call_main (main=main@entry=0x555555556460 <main>, argc=argc@entry=3, argv=argv@entry=0x7fffffffdd78)
    at ../sysdeps/nptl/libc_start_call_main.h:58
#8  0x00007ffff7d14245 in __libc_start_main_impl (main=0x555555556460 <main>, argc=3, argv=0x7fffffffdd78, init=<optimized out>, fini=<optimized out>, 
    rtld_fini=<optimized out>, stack_end=0x7fffffffdd68) at ../csu/libc-start.c:381
#9  0x0000555555556a11 in _start ()

```


#### ASAN Output

```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==3596731==ERROR: AddressSanitizer: SEGV on unknown address 0x559b14b0b6f0 (pc 0x55a814841880 bp 0xffffffffc46535ff sp 0x7ffebacd4ab0 T0)
==3596731==The signal is caused by a READ memory access.
    #0 0x55a814841880 in add_data (/dev/shm/nprolog/npl+0x67880)
    #1 0x55a814823da5 in o_define (/dev/shm/nprolog/npl+0x49da5)
    #2 0x55a814811d75 in b_assert (/dev/shm/nprolog/npl+0x37d75)
    #3 0x55a814812217 in b_consult (/dev/shm/nprolog/npl+0x38217)
    #4 0x55a8147efd07 in main (/dev/shm/nprolog/npl+0x15d07)
    #5 0x7fbe73967189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0x7fbe73967244 in __libc_start_main_impl ../csu/libc-start.c:381
    #7 0x55a8147f0230 in _start (/dev/shm/nprolog/npl+0x16230)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/dev/shm/nprolog/npl+0x67880) in add_data
==3596731==ABORTING

```

---

# Out of bounds read in prove_all at main.c

#### Reproduction

```
$ ./npl -s prove_all_crash.pl
```

#### GDB Output

```
Program received signal SIGSEGV, Segmentation fault.              
0x0000555555576af5 in car (addr=addr@entry=1073741824) at data.c:11
11
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA    
─────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────
*RAX  0x1c0000000                                                                       
*RBX  0x40000000                                                                        
*RCX  0x57f                                                                             
*RDX  0x55555f5da420 (heap) ◂— 0x0                                                      
*RDI  0x40000000                                                                        
 RSI  0x0                                                                               
*R8   0x1999999999999999                                                                
 R9   0x0                                                                                                                                                                       
*R10  0x7ffff7e69ac0 (_nl_C_LC_CTYPE_toupper+512) ◂— 0x100000000
*R11  0x7ffff7e6a3c0 (_nl_C_LC_CTYPE_class+256) ◂— 0x2000200020002
*R12  0x55555f5da420 (heap) ◂— 0x0
*R13  0x573         
*R14  0x21
*R15  0x5555a2cfa0a0 ◂— './reproduction/prove_all_crash.pl'
 RBP  0x0                     
*RSP  0x7fffffffd9a8 —▸ 0x55555555b0c8 (prove_all+24) ◂— cmp eax, 0xc
*RIP  0x555555576af5 (car+21) ◂— mov eax, dword ptr [rdx + rax*8]
──────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────
 ► 0x555555576af5 <car+21>     mov    eax, dword ptr [rdx + rax*8]
   0x555555576af8 <car+24>     ret    
                                                                                                                                                                                
   0x555555576af9              nop    dword ptr [rax]                       
   0x555555576b00 <caar>       movsxd rdi, edi
   0x555555576b03 <caar+3>     lea    rdx, [rip + 0xa063916]        <heap>
   0x555555576b0a <caar+10>    lea    rax, [rdi*8]         
   0x555555576b12 <caar+18>    sub    rax, rdi                                     
   0x555555576b15 <caar+21>    movsxd rcx, dword ptr [rdx + rax*8]
   0x555555576b19 <caar+25>    lea    rax, [rcx*8]        
   0x555555576b21 <caar+33>    sub    rax, rcx    
   0x555555576b24 <caar+36>    mov    eax, dword ptr [rdx + rax*8]          

```

### GDB Backtrace

```
#0  0x0000555555576af5 in car (addr=addr@entry=1073741824) at data.c:11
#1  0x000055555555b0c8 in prove_all (goals=1073741824, bindings=0) at main.c:499
#2  0x00005555555700f4 in b_consult (rest=0, arglist=<optimized out>) at builtin.c:1570
#3  b_consult (arglist=<optimized out>, rest=rest@entry=0) at builtin.c:1521
#4  0x0000555555556870 in main (argc=argc@entry=3, argv=argv@entry=0x7fffffffdd78) at main.c:283
#5  0x00007ffff7d1418a in __libc_start_call_main (main=main@entry=0x555555556460 <main>, argc=argc@entry=3, argv=argv@entry=0x7fffffffdd78)
    at ../sysdeps/nptl/libc_start_call_main.h:58
#6  0x00007ffff7d14245 in __libc_start_main_impl (main=0x555555556460 <main>, argc=3, argv=0x7fffffffdd78, init=<optimized out>, fini=<optimized out>, 
    rtld_fini=<optimized out>, stack_end=0x7fffffffdd68) at ../csu/libc-start.c:381
#7  0x0000555555556a11 in _start ()

```

#### ASAN Output

```
==3618387==ERROR: AddressSanitizer: SEGV on unknown address 0x55b37689b720 (pc 0x55a56c7f6d5a bp 0x000000000000 sp 0x7ffe899bbac8 T0)
==3618387==The signal is caused by a READ memory access.
    #0 0x55a56c7f6d5a in car (/dev/shm/nprolog/npl+0x4fd5a)
    #1 0x55a56c7c3d67 in prove_all (/dev/shm/nprolog/npl+0x1cd67)
    #2 0x55a56c7df36d in b_consult (/dev/shm/nprolog/npl+0x3836d)
    #3 0x55a56c7bcd07 in main (/dev/shm/nprolog/npl+0x15d07)
    #4 0x7f9c96446189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #5 0x7f9c96446244 in __libc_start_main_impl ../csu/libc-start.c:381
    #6 0x55a56c7bd230 in _start (/dev/shm/nprolog/npl+0x16230)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/dev/shm/nprolog/npl+0x4fd5a) in car
==3618387==ABORTING
                     
```

---

# Stack overflow in deref at data.c


#### Reproduction
```
$ ./npl -s deref-crash.pl
```

#### GDB Output

```
Program received signal SIGSEGV, Segmentation fault.                                    
0x000055555557cb02 in deref (x=1534) at data.c:41                                                                                                                               
41                                                                                                                                                                              
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA                                       
─────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────
 RAX  0x29f2                                                                            
 RBX  0x5ff                                                                             
 RCX  0x55555f5ef490 (heap+86128) ◂— 0xc /* '\x0c' */                                   
 RDX  0x5fe                                                                             
 RDI  0x5fe                                                                             
 RSI  0x2                                                                                                                                                                       
 R8   0x7ffff7ebfc60 (main_arena) ◂— 0x0                                                                                                                                        
 R9   0x0                                                                               
 R10  0x7ffff7cfafc8 ◂— 0x100022000064f9
 R11  0x20                            
 R12  0x5ff                           
 R13  0x55555f5da420 (heap) ◂— 0x0    
 R14  0x0                             
 R15  0x5555a2cfa0a0 ◂— './reproduction/deref-crash.pl'
 RBP  0x5fe                                                                                                                                                                     
 RSP  0x7fffff7ff000 ◂— 0x0                                                                                                                                                     
 RIP  0x55555557cb02 (deref.part+2) ◂— push r13
──────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────
 ► 0x55555557cb02 <deref.part+2>     push   r13                           <heap>
   0x55555557cb04 <deref.part+4>     lea    r13, [rip + 0xa05d915]        <heap>                                                                                                
   0x55555557cb0b <deref.part+11>    push   r12
   0x55555557cb0d <deref.part+13>    push   rbp                               
   0x55555557cb0e <deref.part+14>    push   rbx
   0x55555557cb0f <deref.part+15>    movsxd rbx, edi
   0x55555557cb12 <deref.part+18>    lea    rax, [rbx*8]
   0x55555557cb1a <deref.part+26>    sub    rax, rbx       
   0x55555557cb1d <deref.part+29>    mov    ebp, dword ptr [r13 + rax*8 + 8]
   0x55555557cb22 <deref.part+34>    test   ebp, ebp                           
   0x55555557cb24 <deref.part+36>    je     deref.part+81                <deref.part+81>  
```

#### GDB Backtrace

```
#0  0x000055555557cb02 in deref (x=1534) at data.c:41
#1  0x000055555557cc1d in deref (x=1534) at data.c:154
#2  deref (x=<optimized out>) at data.c:2721
#3  0x000055555557cc0d in deref (x=1535) at data.c:154
#4  deref (x=<optimized out>) at data.c:2721
#5  0x000055555557cc1d in deref (x=1536) at data.c:154
#6  deref (x=<optimized out>) at data.c:2721
#7  0x000055555557cc1d in deref (x=1537) at data.c:154
#8  deref (x=<optimized out>) at data.c:2721
#9  0x000055555557cb91 in deref (x=1433) at data.c:2716
#10 deref (x=1534) at data.c:2721
#11 0x000055555557cc1d in deref (x=1534) at data.c:154
#12 deref (x=<optimized out>) at data.c:2721
Backtrace stopped: Cannot access memory at address 0x7fffff7ff128

```

#### ASAN Output

```
==3688642==ERROR: AddressSanitizer: stack-overflow on address 0x7fff36ba4ff8 (pc 0x55ee7c159402 bp 0x000000000601 sp 0x7fff36ba5000 T0)
    #0 0x55ee7c159402 in deref.part.0 (/dev/shm/nprolog/npl+0x62402)                                                                                                            
    #1 0x55ee7c1596e7 in deref.part.0 (/dev/shm/nprolog/npl+0x626e7)
    #2 0x55ee7c1596e7 in deref.part.0 (/dev/shm/nprolog/npl+0x626e7)
    #3 0x55ee7c159544 in deref.part.0 (/dev/shm/nprolog/npl+0x62544)
    #4 0x55ee7c1596e7 in deref.part.0 (/dev/shm/nprolog/npl+0x626e7)
    #5 0x55ee7c1596f7 in deref.part.0 (/dev/shm/nprolog/npl+0x626f7)
    #6 0x55ee7c1596e7 in deref.part.0 (/dev/shm/nprolog/npl+0x626e7)
    #7 0x55ee7c1596e7 in deref.part.0 (/dev/shm/nprolog/npl+0x626e7)
    #8 0x55ee7c159544 in deref.part.0 (/dev/shm/nprolog/npl+0x62544)
    #9 0x55ee7c1596e7 in deref.part.0 (/dev/shm/nprolog/npl+0x626e7)
    #10 0x55ee7c1596f7 in deref.part.0 (/dev/shm/nprolog/npl+0x626f7)
    #11 0x55ee7c1596e7 in deref.part.0 (/dev/shm/nprolog/npl+0x626e7)
...
...

SUMMARY: AddressSanitizer: stack-overflow (/dev/shm/nprolog/npl+0x62402) in deref.part.0
==3688642==ABORTING                                         
```

---

# Null pointer dereference in prove at main.c


#### Reproduction

```
$ ./npl -s ./null-pointer-deref.pl

```

#### GDB Output

```
Program received signal SIGSEGV, Segmentation fault.
0x0000000000000000 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────
 RAX  0x0
*RBX  0x1036646
*RCX  0x55555f5da420 (heap) ◂— 0x0
*RDX  0x55555f5da420 (heap) ◂— 0x0
 RDI  0x0
 RSI  0x0
*R8   0x7ffff7ebfc60 (main_arena) ◂— 0x0                                                                                                                                         R9   0x0                                                                               
*R10  0x7ffff7cf7470 ◂— 0x1000120000099a                                                
*R11  0x20                               
*R12  0x55555f5da420 (heap) ◂— 0x0
*R13  0x573                       
 R14  0x0                                                                               
*R15  0x5555a2cfa0a0 ◂— './reproduction/crash-unknown.pl'
*RBP  0x1c                        
*RSP  0x7fffffffd968 —▸ 0x55555555aec3 (prove+1187) ◂— cmp eax, 2                                                                                                               
*RIP  0x0              
──────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────
Invalid address 0x0                  
                                            
                                            
                                                                                        
                                                                                        
                                            
                                                                                                                                                                                
                                            
                                            
                                                                                        
                                                                                        
───────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffd968 —▸ 0x55555555aec3 (prove+1187) ◂— cmp eax, 2                                                                                                        
01:0008│     0x7fffffffd970 —▸ 0x5555a2cf9ec0 ◂— 0x5fbad2488                                                                                                                    
02:0010│     0x7fffffffd978 ◂— 0xa2cfa0a0                                               
03:0018│     0x7fffffffd980 ◂— 0x0                                                                                                                                              
04:0020│     0x7fffffffd988 ◂— 0x0                                                      
05:0028│     0x7fffffffd990 —▸ 0x55555558e1f2 ◂— '--script'
06:0030│     0x7fffffffd998 ◂— 0x58e
07:0038│     0x7fffffffd9a0 ◂— 0x0

```

#### GDB Backtrace

```
#0  0x0000000000000000 in ?? ()
#1  0x000055555555aec3 in prove (goal=17000006, bindings=0, rest=0) at main.c:682
#2  0x00005555555700f4 in b_consult (rest=0, arglist=<optimized out>) at builtin.c:1570
#3  b_consult (arglist=<optimized out>, rest=rest@entry=0) at builtin.c:1521
#4  0x0000555555556870 in main (argc=argc@entry=3, argv=argv@entry=0x7fffffffdd78) at main.c:283
#5  0x00007ffff7d1418a in __libc_start_call_main (main=main@entry=0x555555556460 <main>, argc=argc@entry=3, argv=argv@entry=0x7fffffffdd78)
    at ../sysdeps/nptl/libc_start_call_main.h:58
#6  0x00007ffff7d14245 in __libc_start_main_impl (main=0x555555556460 <main>, argc=3, argv=0x7fffffffdd78, init=<optimized out>, fini=<optimized out>, 
    rtld_fini=<optimized out>, stack_end=0x7fffffffdd68) at ../csu/libc-start.c:381
#7  0x0000555555556a11 in _start ()


```

#### ASAN Output

```
==3736178==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x000000000000 bp 0x00000000001c sp 0x7ffe8d907a68 T0)
==3736178==Hint: pc points to the zero page.
==3736178==The signal is caused by a READ memory access.
==3736178==Hint: address points to the zero page.
    #0 0x0  (<unknown module>)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (<unknown module>) 
==3736178==ABORTING

```

---

# Null pointer dereference in b_consult at builtin.c

#### Reproduction

```
$ ./npl -s ./reproduction/b_consult_null_deref.pl
```

#### GDB Output

```
Starting program: /home/kali/projects/fuzzing/nprolog/npl -s ./reproduction/b_consult_null_deref.pl
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
                                            
Program received signal SIGSEGV, Segmentation fault.
0x0000000000000000 in ?? ()             
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────
 RAX  0x0  
*RBX  0x586
*RCX  0x55555f5da420 (heap) ◂— 0x0                                                      
*RDX  0x55555f5da420 (heap) ◂— 0x0
*RDI  0x1036643                                                                         
 RSI  0x0
 R8   0x0                                                                                                                                                                       
 R9   0x0          
*R10  0x7ffff7cf7470 ◂— 0x1000120000099a
*R11  0x7ffff7d65000 (ungetc) ◂— cmp edi, -1
*R12  0x55555f5da420 (heap) ◂— 0x0
*R13  0x573
*R14  0x26
*R15  0x5555a2cfa0a0 ◂— './reproduction/b_consult_null_deref.pl'
 RBP  0x0
*RSP  0x7fffffffd9c8 —▸ 0x5555555700f4 (b_consult+548) ◂— jmp 0x555555570018
*RIP  0x0
──────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────
Invalid address 0x0                                                                                            
```

#### GDB Backtrace

```
#0  0x0000000000000000 in ?? ()
#1  0x00005555555700f4 in b_consult (rest=0, arglist=<optimized out>) at builtin.c:1570
#2  b_consult (arglist=<optimized out>, rest=rest@entry=0) at builtin.c:1521
#3  0x0000555555556870 in main (argc=argc@entry=3, argv=argv@entry=0x7fffffffdd78) at main.c:283
#4  0x00007ffff7d1418a in __libc_start_call_main (main=main@entry=0x555555556460 <main>, argc=argc@entry=3, argv=argv@entry=0x7fffffffdd78)
    at ../sysdeps/nptl/libc_start_call_main.h:58
#5  0x00007ffff7d14245 in __libc_start_main_impl (main=0x555555556460 <main>, argc=3, argv=0x7fffffffdd78, init=<optimized out>, fini=<optimized out>, 
    rtld_fini=<optimized out>, stack_end=0x7fffffffdd68) at ../csu/libc-start.c:381
#6  0x0000555555556a11 in _start ()

```

#### ASAN Output

```
==3758750==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x000000000000 bp 0x7ffea4030050 sp 0x7ffea4030028 T0)
==3758750==Hint: pc points to the zero page.
==3758750==The signal is caused by a READ memory access.
==3758750==Hint: address points to the zero page.
    #0 0x0  (<unknown module>)
    #1 0x5572435c7012  (/dev/shm/nprolog/npl+0x96012)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (<unknown module>) 
==3758750==ABORTING

```

---

# Out-of-bounds read in o_define at builtin.c

#### Reproduction

```
$ ./npl -s ./reproduction/o_define_crash.pl
```

#### GDB Output

```
Program received signal SIGSEGV, Segmentation fault.              
0x0000555555576af5 in car (addr=1073742624) at data.c:11
11                                                                                                                                                                              
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA                           
─────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────
*RAX  0x1c00015e0                                                                       
*RBX  0x40000320                                                                        
*RCX  0x596                                                                             
*RDX  0x55555f5da420 (heap) ◂— 0x0                                                      
*RDI  0x40000320                                                                        
 RSI  0x0                                                                               
*R8   0xfffffffffffffff                                                                                                                                                         
 R9   0x0                                                                                                                                                                       
*R10  0x7ffff7cf7470 ◂— 0x1000120000099a                                                
*R11  0x7ffff7d65000 (ungetc) ◂— cmp edi, -1
*R12  0x55555f5edd28 (heap+80136) ◂— 0x1a
*R13  0x55555558f5da ◂— 'assertz '   
*R14  0x20                       
*R15  0x5555a2cfa0a0 ◂— './reproduction/o_define_crash.pl'                              
*RBP  0x597                                                                             
*RSP  0x7fffffffd978 —▸ 0x55555557402c (o_define+284) ◂— mov esi, ebp                                                                                                           
*RIP  0x555555576af5 (car+21) ◂— mov eax, dword ptr [rdx + rax*8]
──────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────
 ► 0x555555576af5 <car+21>     mov    eax, dword ptr [rdx + rax*8]                      
   0x555555576af8 <car+24>     ret                                                      
                                                                                                                                                                                
   0x555555576af9              nop    dword ptr [rax]                       
   0x555555576b00 <caar>       movsxd rdi, edi                                                                                                                                  
   0x555555576b03 <caar+3>     lea    rdx, [rip + 0xa063916]        <heap>                                                                                                      
   0x555555576b0a <caar+10>    lea    rax, [rdi*8]                                      
   0x555555576b12 <caar+18>    sub    rax, rdi                                                                                                                                  
   0x555555576b15 <caar+21>    movsxd rcx, dword ptr [rdx + rax*8]                      
   0x555555576b19 <caar+25>    lea    rax, [rcx*8]
   0x555555576b21 <caar+33>    sub    rax, rcx
   0x555555576b24 <caar+36>    mov    eax, dword ptr [rdx + rax*8]

```

#### GDB Backtrace
```
#0  0x0000555555576af5 in car (addr=1073742624) at data.c:11
#1  0x000055555557402c in o_define (x=1073742624, y=<optimized out>) at builtin.c:4627
#2  0x000055555556918b in b_assert (arglist=1418, rest=rest@entry=0) at builtin.c:2544
#3  0x0000555555570068 in b_consult (rest=0, arglist=<optimized out>) at builtin.c:1581
#4  b_consult (arglist=<optimized out>, rest=rest@entry=0) at builtin.c:1521
#5  0x0000555555556870 in main (argc=argc@entry=3, argv=argv@entry=0x7fffffffdd78) at main.c:283
#6  0x00007ffff7d1418a in __libc_start_call_main (main=main@entry=0x555555556460 <main>, argc=argc@entry=3, argv=argv@entry=0x7fffffffdd78)
    at ../sysdeps/nptl/libc_start_call_main.h:58
#7  0x00007ffff7d14245 in __libc_start_main_impl (main=0x555555556460 <main>, argc=3, argv=0x7fffffffdd78, init=<optimized out>, fini=<optimized out>, 
    rtld_fini=<optimized out>, stack_end=0x7fffffffdd68) at ../csu/libc-start.c:381
#8  0x0000555555556a11 in _start ()

```

#### ASAN Output

```
=================================================================
==3773508==ERROR: AddressSanitizer: SEGV on unknown address 0x55f3b4b9c620 (pc 0x55e5aaaecd5a bp 0x000000013908 sp 0x7ffe09963658 T0)
==3773508==The signal is caused by a READ memory access.
    #0 0x55e5aaaecd5a in car (/dev/shm/nprolog/npl+0x4fd5a)
    #1 0x55e5aaae6d9b in o_define (/dev/shm/nprolog/npl+0x49d9b)
    #2 0x55e5aaad4d75 in b_assert (/dev/shm/nprolog/npl+0x37d75)
    #3 0x55e5aaad5217 in b_consult (/dev/shm/nprolog/npl+0x38217)
    #4 0x55e5aaab2d07 in main (/dev/shm/nprolog/npl+0x15d07)
    #5 0x7f1220246189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0x7f1220246244 in __libc_start_main_impl ../csu/libc-start.c:381
    #7 0x55e5aaab3230 in _start (/dev/shm/nprolog/npl+0x16230)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/dev/shm/nprolog/npl+0x4fd5a) in car
==3773508==ABORTING

```
# Crash in SET_CAR in version 1.90

## Reproduction

Files for reproduction:

[1.90-crashes.zip](https://github.com/Halcy0nic/Trophies/files/12330851/1.90-crashes.zip)


## Executing NPL
```
./npl -s ./crash1
 ```
