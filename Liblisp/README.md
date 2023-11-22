# Overview

Per usual, I ran my fuzz tests in the background against liblisp and found a couple of memory corruption bugs in the library through commit 4c65969.  I have included all of the files necessary for reproducing each bug.

* CVE-2023-48024:  Use-after-free in void hash_destroy(hash_table_t *h) at hash.c, lines 70-84.
* CVE-2023-48025: Out-of-bounds read in unsigned get_length(lisp_cell_t * x) at eval.c, line 272.

# CVE-2023-48024

There exist a use-after-free bug in void hash_destroy(hash_table_t *h) at hash.c, lines 70-84.    

#### Source Code 

```
 void hash_destroy(hash_table_t * h) { 
 	if (!h) 
 		return; 
 	for (size_t i = 0; i < h->len; i++) 
 		if (h->table[i]) { 
 			hash_entry_t *prev = NULL; 
 			for (hash_entry_t *cur = h->table[i]; cur; prev = cur, cur = cur->next) { 
 				h->free_key(cur->key); 
 				h->free_val(cur->val); 
 				free(prev); 
 			} 
 			free(prev); 
```

### Address Sanitizer Output
```
=================================================================
==134443==ERROR: AddressSanitizer: heap-use-after-free on address 0x6080000006a8 at pc 0x7f9da3ee019b bp 0x7ffce0e7abe0 sp 0x7ffce0e7abd8
READ of size 8 at 0x6080000006a8 thread T0
    #0 0x7f9da3ee019a in hash_destroy src/hash.c:73
    #1 0x7f9da3ee019a in hash_destroy src/hash.c:70
    #2 0x7f9da3edf78f in gc_free src/gc.c:50
    #3 0x7f9da3edf78f in lisp_gc_sweep_only src/gc.c:124
    #4 0x7f9da3ee4011 in lisp_destroy src/lisp.c:80
    #5 0x7f9da3ee871e in main_lisp_env src/repl.c:236
    #6 0x7f9da36456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #7 0x7f9da3645784 in __libc_start_main_impl ../csu/libc-start.c:360
    #8 0x5615bae755b0 in _start (/home/kali/projects/fuzzing/liblisp/lisp+0x25b0) (BuildId: 0827e7ee54f24ed60d4875e0b6fa13ce80a7782b)

0x6080000006a8 is located 8 bytes inside of 96-byte region [0x6080000006a0,0x608000000700)
freed by thread T0 here:
    #0 0x7f9da38d7298 in __interceptor_free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:52
    #1 0x7f9da3ee750e in read_hash src/read.c:211
    #2 0x7f9da3ee750e in reader src/read.c:279

previously allocated by thread T0 here:
    #0 0x7f9da38d7fa7 in __interceptor_calloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:77
    #1 0x7f9da3edfe97 in hash_create_custom src/hash.c:57

SUMMARY: AddressSanitizer: heap-use-after-free src/hash.c:73 in hash_destroy
Shadow bytes around the buggy address:
  0x608000000400: fa fa fa fa 00 00 00 00 00 00 00 00 00 00 07 fa
  0x608000000480: fa fa fa fa 00 00 00 00 00 00 00 00 00 00 00 00
  0x608000000500: fa fa fa fa 00 00 00 00 00 00 00 00 00 00 07 fa
  0x608000000580: fa fa fa fa 00 00 00 00 00 00 00 00 00 00 07 fa
  0x608000000600: fa fa fa fa 00 00 00 00 00 00 00 00 00 00 07 fa
=>0x608000000680: fa fa fa fa fd[fd]fd fd fd fd fd fd fd fd fd fd
  0x608000000700: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fa
  0x608000000780: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x608000000800: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x608000000880: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x608000000900: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==134443==ABORTING
```

### Mitigation

A potential fix for this would be to set the pointer 'hash_table_t *h' to null after passing it to 'free'.

# CVE-2023-48025

There exist an out-of-bounds read in unsigned get_length(lisp_cell_t * x) at eval.c, line 272.  The OOB read comes from the statement 'return (uintptr_t)(x->p[1].v);' when processing a malformed symbol.

#### Source Code

```
 case SYMBOL: 
 	return (uintptr_t)(x->p[1].v); 
```

### Address Sanitizer Output

```
=================================================================
==134237==ERROR: AddressSanitizer: global-buffer-overflow on address 0x7f76159f9430 at pc 0x7f76159c98d4 bp 0x7ffe27551db0 sp 0x7ffe27551da8
READ of size 8 at 0x7f76159f9430 thread T0
    #0 0x7f76159c98d3 in get_length src/eval.c:272
    #1 0x7f76159c98d3 in get_length src/eval.c:264
    #2 0x7f76159d6abf in subr_greater src/subr.c:325
    #3 0x7f76159cbecc in eval src/eval.c:707
    #4 0x7f76159d4c85 in lisp_repl src/repl.c:149
    #5 0x7f76159d4fb8 in main_lisp_env src/repl.c:212
    #6 0x7f76157f66c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #7 0x7f76157f6784 in __libc_start_main_impl ../csu/libc-start.c:360
    #8 0x563c29c2b5b0 in _start (/home/kali/projects/fuzzing/liblisp/lisp+0x25b0) (BuildId: 0827e7ee54f24ed60d4875e0b6fa13ce80a7782b)

0x7f76159f9430 is located 48 bytes before global variable '_nil' defined in 'src/subr.c:137:1' (0x7f76159f9460) of size 16
0x7f76159f9430 is located 0 bytes after global variable '_tee' defined in 'src/subr.c:137:1' (0x7f76159f9420) of size 16
SUMMARY: AddressSanitizer: global-buffer-overflow src/eval.c:272 in get_length
Shadow bytes around the buggy address:
  0x7f76159f9180: f9 f9 f9 f9 00 00 f9 f9 f9 f9 f9 f9 00 00 f9 f9
  0x7f76159f9200: f9 f9 f9 f9 00 00 f9 f9 f9 f9 f9 f9 00 00 f9 f9
  0x7f76159f9280: f9 f9 f9 f9 00 00 f9 f9 f9 f9 f9 f9 00 00 f9 f9
  0x7f76159f9300: f9 f9 f9 f9 00 00 f9 f9 f9 f9 f9 f9 00 00 f9 f9
  0x7f76159f9380: f9 f9 f9 f9 00 00 f9 f9 f9 f9 f9 f9 00 00 f9 f9
=>0x7f76159f9400: f9 f9 f9 f9 00 00[f9]f9 f9 f9 f9 f9 00 00 f9 f9
  0x7f76159f9480: f9 f9 f9 f9 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f76159f9500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f76159f9580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f76159f9600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f76159f9680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
==134237==ABORTING
=================================================================
```

### Mitigation
A potential fix for this would be to add check ensuring 'x->p[1].v' is within the bounds of the array.

# References

* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-48024
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-48025

@Halcy0nic

