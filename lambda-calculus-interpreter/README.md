# Lambda Calculus Interpreter

The [LCI](https://www.chatzi.org/lci/) platform is an interpreter for lambda calculus, featuring a suite of advanced functionalities such as recursion, the creation of user-defined operators, and the availability of various evaluation strategies, all grounded in the pure calculus framework.

Viewed as a compact yet robust functional programming language, LCI is founded on the principles of pure lambda-calculus. Its capabilities encompass:

- The establishment of lambda term aliases, effectively allowing for the naming of functions.
- The representation of integers through Church numerals, accompanied by standard arithmetic operations.
- The implementation of recursion, wherein self-referential aliases undergo expansion at runtime. Additionally, LCI is equipped to seamlessly transform recursive expressions into their non-recursive counterparts using a fixed point combinator.
- The facility for users to introduce new operators, specifying their precedence and associativity, and define them using lambda calculus. A variety of common operators, including those for integer, logic, and list operations, are pre-defined in the .lcirc file and are readily accessible.
- An intuitive list syntax, where sequences like [a,b,c] are interpreted as a:b:c:Nil (with : and Nil being constructs defined in .lcirc).
- Support for multiple evaluation strategies, enabling both call-by-name and call-by-value approaches within a single program.
- The presentation of terms in a format that is easily comprehensible to humans; for instance, Church numerals are shown as numbers, and lists are depicted using the [a,b,c] format.
- Execution tracing capabilities.
- The option to interpret files or engage in interactive sessions.
- Access to a library of pre-defined functions (.lcirc), enhancing the user experience and functionality.

# Vulnerabilities

While executing some fuzz tests against LCI, I discovered multiple memory corruption vulnerabilities through commit 2deb0d4 (Version 1.0)

* Stack Buffer Overflow in int execSystemCmd(TERM *t) at run.c, line 224 (CVE-2024-27543)
* Invalid Pointer Dereference in void termRemoveOper(TERM *t) at termproc.c, line 632 (CVE-2024-27542)
* Invalid Pointer Dereference in static TERM *fix_precedence(TERM\* op) at parser.c, line 95 (CVE-2024-27540)
* Invalid Pointer Dereference in TERM* create_bracket(TERM *t) at parser.c, line 162 (CVE-2024-27541)

Given the attack surface, these vulnerabilities could result in a denial of service, information disclosure, or potential remote code execution (depending on the implementation/environment/compiler for the stack buffer overflow). For more details check the impact section. I've included a zip file in this directory that contains all of the proof of concept files needed for reproducing each issue.

## Building LCI With Address Sanitizer and Debug Symbols

I compiled the project with address sanitizer (ASan) and debug symbols (on Linux) to help track down the location of each vulnerability.  This can be done with the following commands:

```
$ git clone https://github.com/chatziko/lci.git
$ cd lci
$ git submodule init
$ git submodule update
$ export ASAN_OPTIONS=detect_leaks=0   #This is to ignore memory leaks found when building the project
$ cmake -DCMAKE_C_FLAGS="-fsanitize=address -g" -DCMAKE_CXX_FLAGS="-fsanitize=address -g" -B build
$ cd build
$ make
```

After running these commands, the LCI binary should be built with ASan and debug symbols.  The compilation steps for Windows might differ slightly.  In the above commands, I ignored memory leaks that ASan detected while building the project.  If you are interested in finding/addressing those, don't execute the fifth command and you'll see the leaks detected once you run 'make'. 


## CVE-2024-27543 Stack Buffer Overflow in int execSystemCmd(TERM *t) at run.c, line 224

A stack buffer overflow vulnerability has been discovered in int execSystemCmd(TERM *t) at run.c, line 224. This vulnerability is triggered when processing certain input that leads to an unexpected code path, attempting to overwrite data on the stack.

```C
while(t->type == TM_APPL) {
  *sp++ = t->rterm;
  parno++;
  t = t->lterm;
}
```
 

#### Triggering the Vulnerability

To trigger the vulnerability, I've provided a proof of concept input that you can feed into LCI named bufferoverflow_execSystemCmd. We can send the contents of this text file into lci to view the crash:

```
$ cat bufferoverflow_execSystemCmd | lci
```

### Address Sanitizer Output

ASan catches the crash and provides some helpful information about where in the code this takes place:

```
=================================================================                                  
==520025==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fc0ab437780 at pc 0x55ff0ba73afb bp 0x7ffd39d78f60 sp 0x7ffd39d78f58                                                            
WRITE of size 8 at 0x7fc0ab437780 thread T0                                                        
    #0 0x55ff0ba73afa in execSystemCmd /dev/shm/lci/src/run.c:224
    #1 0x55ff0ba73cab in execTerm /dev/shm/lci/src/run.c:105     
    #2 0x55ff0ba7890b in d_final_reduction_code_5_8_gram /dev/shm/lci/src/grammar.g:34
    #3 0x55ff0ba90eb9 in commit_tree /dev/shm/lci/dparser/parse.c:1617
    #4 0x55ff0ba9081a in commit_tree /dev/shm/lci/dparser/parse.c:1602
    #5 0x55ff0ba9770d in dparse /dev/shm/lci/dparser/parse.c:2121
    #6 0x55ff0ba7164b in parse_string /dev/shm/lci/src/parser.c:35
    #7 0x55ff0ba6ac9a in main /dev/shm/lci/src/main.c:105        
    #8 0x7fc0ad2456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #9 0x7fc0ad245784 in __libc_start_main_impl ../csu/libc-start.c:360
    #10 0x55ff0ba6b260 in _start (/dev/shm/lci/build/lci+0x3b260) (BuildId: ff37cd476b852db6d5e5bad433ac32fa2ca6f5de)       


Address 0x7fc0ab437780 is located in stack of thread T0 at offset 128 in frame                                                                                                                         
    #0 0x55ff0ba7333f in execSystemCmd /dev/shm/lci/src/run.c:212                                  
                                                 
  This frame has 1 object(s):                                                                      
    [48, 128) 'stack' (line 219) <== Memory access at offset 128 overflows this variable           
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork                                                                                       
      (longjmp and C++ exceptions *are* supported)                                                 
SUMMARY: AddressSanitizer: stack-buffer-overflow /dev/shm/lci/src/run.c:224 in execSystemCmd       
Shadow bytes around the buggy address:                                                             
  0x7fc0ab437500: f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5                                                                                                                                      
  0x7fc0ab437580: f5 f5 f5 f5 00 00 00 00 00 00 00 00 00 00 00 00                                  
  0x7fc0ab437600: f1 f1 f1 f1 00 00 02 f2 f2 f2 f2 f2 00 00 02 f3
  0x7fc0ab437680: f3 f3 f3 f3 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fc0ab437700: f1 f1 f1 f1 f1 f1 00 00 00 00 00 00 00 00 00 00                     
=>0x7fc0ab437780:[f3]f3 f3 f3 00 00 00 00 00 00 00 00 00 00 00 00     
  0x7fc0ab437800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     
  0x7fc0ab437880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fc0ab437900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
  0x7fc0ab437980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fc0ab437a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00                        
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
==520025==ABORTING          
```

The AddressSanitizer output indicates a stack-buffer-overflow error. This type of error occurs when a program writes to a memory location on the stack outside of the allocated bounds for a stack variable. In this case, the overflow is happening with the stack array in the execSystemCmd function, which is defined with a fixed size of 10 elements.

The overflow occurs because the code does not check if the number of parameters (parno) exceeds the size of the stack array before incrementing the sp pointer and writing to the next element. This can lead to writing beyond the end of the stack array if more than 10 parameters are processed, causing memory corruption and potentially leading to a crash or other undefined behavior.


#### Mitigation 

I've provided an immediate workaround example to mitigate the vulnerability until a more comprehensive patch is released.  This will apply input validation and sanitization measures to reject potentially malicious or malformed inputs before processing them with LCI.  

To fix this vulnerability, we can add a check to ensure that the sp pointer does not exceed the bounds of the stack array. Here's an updated version of the execSystemCmd function with a bounds check:

```c
int execSystemCmd(TERM *t) {
    // interned constants, initialize on first execution
    static char* icon[sizeof(str_constants)/sizeof(char*)];
    if(icon[0] == NULL)
        for(int i = 0; i < sizeof(str_constants)/sizeof(char*); i++)
            icon[i] = str_intern(str_constants[i]);

    TERM *stack[10], **sp = stack, *par;
    int parno = 0;
    const int stackSize = sizeof(stack) / sizeof(stack[0]); // Calculate the size of the stack array

    // find the left-most term and keep params in the stack
    while(t->type == TM_APPL) {
        if (parno >= stackSize) {
            fprintf(stderr, "Error: Stack overflow in execSystemCmd - too many parameters.\n");
            // Handle the error, e.g., by safely exiting the function or taking corrective action
            return -1; // Return an error code or handle as appropriate for your application
        }
        *sp++ = t->rterm;
        parno++;
        t = t->lterm;
    }

    // The rest of the function...
}

```

* Calculate Stack Size: The stackSize variable is calculated to determine the number of elements in the stack array. This is done by dividing the total size of the array by the size of one element.
* Bounds Check: Before incrementing sp and writing a new parameter to the stack, the code checks if parno is equal to or greater than stackSize. If this condition is true, it means adding another parameter would overflow the stack, so an error is logged, and the function returns early to prevent the overflow.
* Error Handling: In the case of an overflow, an error message is printed, and the function returns a negative value to indicate an error. You should adjust this behavior based on how your application can best handle such errors.

## CVE-2024-27542 Invalid Pointer Dereference in void termRemoveOper(TERM *t) at termrpoc.c, line 632 

An invalid pointer dereference vulnerability has been discovered in void termRemoveOper(TERM *t) at termproc.c, line 632. This vulnerability is triggered when processing certain input that leads to an unexpected code path, attempting to dereference an invalid pointer, resulting in a segmentation fault and program crash.

```C
switch(t->type) {
```

#### Triggering the Vulnerability

To trigger the vulnerability, I've provided a proof of concept input that you can feed into LCI named invalid_deref_termRemoverOper.  We can send the contents of this text file into lci to view the crash:

```
$ cat nullderef_termRemoverOper | lci
```

### Address Sanitizer Output

ASan catches the crash and provides some helpful information about where in the code this takes place:

```
=================================================================
==460303==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000018 (pc 0x560e050aa5fa bp 0x7f67bb00bba0 sp 0x7ffdb726f830 T0)
==460303==The signal is caused by a READ memory access.
==460303==Hint: address points to the zero page.
    #0 0x560e050aa5fa in termRemoveOper /dev/shm/lci/src/termproc.c:632
    #1 0x560e050a5c9b in execTerm /dev/shm/lci/src/run.c:97
    #2 0x560e050aa90b in d_final_reduction_code_5_8_gram /dev/shm/lci/src/grammar.g:34
    #3 0x560e050c2eb9 in commit_tree /dev/shm/lci/dparser/parse.c:1617
    #4 0x560e050c281a in commit_tree /dev/shm/lci/dparser/parse.c:1602
    #5 0x560e050c970d in dparse /dev/shm/lci/dparser/parse.c:2121
    #6 0x560e050a364b in parse_string /dev/shm/lci/src/parser.c:35
    #7 0x560e0509cc9a in main /dev/shm/lci/src/main.c:105
    #8 0x7f67bce456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #9 0x7f67bce45784 in __libc_start_main_impl ../csu/libc-start.c:360
    #10 0x560e0509d260 in _start (/dev/shm/lci/build/lci+0x3b260) (BuildId: ff37cd476b852db6d5e5bad433ac32fa2ca6f5de)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /dev/shm/lci/src/termproc.c:632 in termRemoveOper
==460303==ABORTING
```

From the output we can verify that an invalid pointer with the value 0x000000000018 is being dereferenced at termproc.c, line 632.


#### Mitigation 

I've provided an immediate workaround example to mitigate the vulnerability until a more comprehensive patch is released.  This will apply input validation and sanitization measures to reject potentially malicious or malformed inputs before processing them with LCI.  Implementing additional checks for a pointer like 0x000000000018 is challenging, because what constitutes a "valid" pointer can vary. However, for critical software components, you might consider adding comprehensive checks where you suspect pointer corruption:

```c
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h> // For using 'bool' type

// Function to check pointer validity
bool isValidPointer(void* ptr) {
    const uintptr_t LOW_MEMORY_THRESHOLD = 0x1000; // Safe threshold for valid memory
    return (ptr != NULL) && ((uintptr_t)ptr >= LOW_MEMORY_THRESHOLD);
}

if (isValidPointer(t)) {
    switch(t->type) {
        case(TM_VAR):
        case(TM_ALIAS):
            // Handle TM_VAR and TM_ALIAS cases as before
            break;
        // Other cases as necessary
    }
} else {
    // Handle the case where 't' is not a valid pointer
    fprintf(stderr, "Error: 't' is an invalid pointer.\n");
    // Take appropriate action, which might involve returning from the function
    // if this code is part of a function that can handle this error scenario.
    return; // Or return a specific value/error code if required
}
```


## CVE-2024-27540 Invalid Pointer Dereference in static TERM *fix_precedence(TERM* op) at parser.c, line 95

An invalid pointer dereference vulnerability has been discovered in static TERM *fix_precedence(TERM* op) at parser.c, line 95. This vulnerability is triggered when processing certain input that leads to an unexpected code path, attempting to dereference an invalid pointer, resulting in a segmentation fault and program crash.

```C
static TERM *fix_precedence(TERM* op) {
	TERM *left = op->lterm;
	if(left->type != TM_APPL || left->closed)	// "closed" means it is protected by parenthesis
		return op;
```

#### Triggering the Vulnerability

To trigger the vulnerability, I've provided a proof of concept input that you can feed into LCI named invalid_deref_fix_precedence. We can send the contents of this text file into lci to view the crash:

```
$ cat invalid_deref_fix_precedence | lci
```

### Address Sanitizer Output

ASan catches the crash and provides some helpful information about where in the code this takes place:

```
=================================================================
==481033==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000018 (pc 0x55924056894f bp 0x000000000000 sp 0x7fff26e12790 T0)
==481033==The signal is caused by a READ memory access.
==481033==Hint: address points to the zero page.
    #0 0x55924056894f in fix_precedence /dev/shm/lci/src/parser.c:95
    #1 0x55924056894f in create_application /dev/shm/lci/src/parser.c:139
    #2 0x559240570024 in d_final_reduction_code_7_20_gram /dev/shm/lci/src/grammar.g:49
    #3 0x559240587eb9 in commit_tree /dev/shm/lci/dparser/parse.c:1617
    #4 0x55924058781a in commit_tree /dev/shm/lci/dparser/parse.c:1602
    #5 0x55924058781a in commit_tree /dev/shm/lci/dparser/parse.c:1602
    #6 0x55924058e70d in dparse /dev/shm/lci/dparser/parse.c:2121
    #7 0x55924056864b in parse_string /dev/shm/lci/src/parser.c:35
    #8 0x559240561c9a in main /dev/shm/lci/src/main.c:105
    #9 0x7f0db9e456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #10 0x7f0db9e45784 in __libc_start_main_impl ../csu/libc-start.c:360
    #11 0x559240562260 in _start (/dev/shm/lci/build/lci+0x3b260) (BuildId: ff37cd476b852db6d5e5bad433ac32fa2ca6f5de)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /dev/shm/lci/src/parser.c:95 in fix_precedence
==481033==ABORTING

```

From the output we can verify that an invalid pointer with the value 0x000000000018 is being dereferenced at parser.c, line 95.


#### Mitigation 

I've provided an immediate workaround example to mitigate the vulnerability until a more comprehensive patch is released.  This will apply input validation and sanitization measures to reject potentially malicious or malformed inputs before processing them with LCI.  Like before, implementing additional checks for a pointer like 0x000000000018 is challenging, because what constitutes a "valid" pointer can vary. However, for critical software components, you might consider adding comprehensive checks where you suspect pointer corruption:

```c


#include <stdio.h>
#include <stdint.h>
#include <stdbool.h> // For using 'bool' type

// Function to check pointer validity
bool isValidPointer(void* ptr) {
    const uintptr_t LOW_MEMORY_THRESHOLD = 0x1000;
    return (ptr != NULL) && ((uintptr_t)ptr >= LOW_MEMORY_THRESHOLD);
}

static TERM *fix_precedence(TERM* op) {
    // Ensure 'op' is not a null or invalid pointer
    if (!isValidPointer(op)) {
        fprintf(stderr, "Error: Invalid 'op' pointer in fix_precedence.\n");
        return NULL;
    }

    TERM *left = op->lterm;
    // Ensure 'left' is not a null or invalid pointer before dereferencing
    if (isValidPointer(left)) {
        if(left->type != TM_APPL || left->closed) {
            return op;
        }
        // Additional logic to handle 'left'...
    } else {
        fprintf(stderr, "Error: Invalid 'left' pointer in fix_precedence.\n");
        // Handle invalid 'left' pointer scenario
        // Depending on the context, you might return 'op', NULL, or take other actions
        return op; // Example action
    }

    // Rest of the function...
}

```


## CVE-2024-27541 Invalid Pointer Dereference in TERM* create_bracket(TERM *t) at parser.c, line 162

An invalid pointer dereference vulnerability has been discovered in TERM* create_bracket(TERM *t) at parser.c, line 162. This vulnerability is triggered when processing certain input that leads to an unexpected code path, attempting to dereference an invalid pointer, resulting in a segmentation fault and program crash.


```C
 TERM* create_bracket(TERM *t) { 
 	t->closed = 1;		// during parsing, 'closed' means enclosed in brackets 
 	return t; 
 } 
```

#### Triggering the Vulnerability

To trigger the vulnerability, I've provided a proof of concept input that you can feed into LCI named invalid_deref_create_bracket. We can send the contents of this text file into lci to view the crash:

```
$ cat invalid_deref_create_bracket | lci
```

### Address Sanitizer Output

ASan catches the crash and provides some helpful information about where in the code this takes place:

```
=================================================================
==502918==ERROR: AddressSanitizer: SEGV on unknown address 0x00000000001c (pc 0x556f680df0d3 bp 0x7ffee67786b0 sp 0x7ffee6778668 T0)
==502918==The signal is caused by a WRITE memory access.
==502918==Hint: address points to the zero page.
    #0 0x556f680df0d3 in create_bracket /dev/shm/lci/src/parser.c:162
    #1 0x556f680e5aaf in d_final_reduction_code_7_14_gram /dev/shm/lci/src/grammar.g:40
    #2 0x556f680fdeb9 in commit_tree /dev/shm/lci/dparser/parse.c:1617
    #3 0x556f680fd81a in commit_tree /dev/shm/lci/dparser/parse.c:1602
    #4 0x556f680fd81a in commit_tree /dev/shm/lci/dparser/parse.c:1602
    #5 0x556f680fd81a in commit_tree /dev/shm/lci/dparser/parse.c:1602
    #6 0x556f6810470d in dparse /dev/shm/lci/dparser/parse.c:2121
    #7 0x556f680de64b in parse_string /dev/shm/lci/src/parser.c:35
    #8 0x556f680d7c9a in main /dev/shm/lci/src/main.c:105
    #9 0x7fb7478456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #10 0x7fb747845784 in __libc_start_main_impl ../csu/libc-start.c:360
    #11 0x556f680d8260 in _start (/dev/shm/lci/build/lci+0x3b260) (BuildId: ff37cd476b852db6d5e5bad433ac32fa2ca6f5de)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /dev/shm/lci/src/parser.c:162 in create_bracket
==502918==ABORTING


```

The ASan output indicates a segmentation fault caused by a write memory access to an invalid address (0x00000000001c), occurring in the create_bracket function. This issue arises when attempting to set the closed field of a TERM structure through a pointer that may be invalid or uninitialized.


#### Mitigation 

I've provided an immediate workaround example to mitigate the vulnerability until a more comprehensive patch is released.  This will apply input validation and sanitization measures to reject potentially malicious or malformed inputs before processing them with LCI:

```c

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

bool isValidPointer(void* ptr) {
    const uintptr_t LOW_MEMORY_THRESHOLD = 0x1000;
    return (ptr != NULL) && ((uintptr_t)ptr >= LOW_MEMORY_THRESHOLD);
}
```

Updated create_bracket function:

```c
TERM* create_bracket(TERM *t) {
    // Check if 't' is a valid pointer before dereferencing
    if (!isValidPointer(t)) {
        fprintf(stderr, "Error: Invalid 't' pointer in create_bracket.\n");
        return NULL; // Or handle the error as appropriate for your application
    }

    t->closed = 1;  // during parsing, 'closed' means enclosed in brackets
    return t;
}
```


## Overview of Impact

The stack buffer overflow vulnerability in the execSystemCmd function poses the most critical risk, potentially leading to arbitrary code execution. In scenarios where LCI is used in a web environment or is accessible by untrusted users, an attacker could craft specific inputs to overflow the stack buffer, manipulate the execution flow, and execute malicious code. This could result in the compromise of the hosting system, allowing the attacker to gain unauthorized access, escalate privileges, or launch further attacks from the compromised system. For programs built on top of LCI, this vulnerability exposes them to a chain of threats where an exploit against LCI could lead to the compromise of the entire application stack, affecting not just the LCI runtime but also any application logic, data, or services relying on it.

The three instances of invalid pointer dereference in termRemoveOper, fix_precedence, and create_bracket functions primarily lead to denial of service (DoS) through program crashes. However, the impact could extend beyond a simple service disruption in specific environments or use cases:

* Information Disclosure: In certain configurations, the crash details (e.g., core dumps) might expose sensitive runtime information to attackers, aiding them in crafting further exploits. For applications built on LCI, such information disclosure could inadvertently reveal application logic, data structures, or even sensitive user data being processed at the time of the crash, leading to a broader security breach.

* Remote Code Execution (RCE): Although less likely than with the stack buffer overflow, there exists a theoretical possibility for remote code execution if the attacker can control the memory layout or exploit specific behaviors of the memory management in the hosting environment. Applications utilizing LCI as a foundation for processing or execution logic are particularly at risk, as any RCE vulnerability in LCI can be escalated to execute arbitrary code within the context of the host application, potentially allowing attackers to manipulate application behavior, access sensitive information, or exploit further vulnerabilities in the application stack.

* Extended Implications for Programs Built on LCI: The inherent risks of these vulnerabilities are magnified for programs built on LCI due to the cascading nature of security breaches. An exploit at the language interpreter level can provide an attacker with a foothold into higher levels of the application stack, from where they can mount attacks against other components of the system. This is especially critical for systems where LCI is used to process untrusted input or in environments where LCI's output directly influences other application components or user-facing features.

## References

* [CWE-822 Untrusted Pointer Dereference](https://cwe.mitre.org/data/definitions/822.html)
* [CWE-121 Stack Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
* [Address Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
