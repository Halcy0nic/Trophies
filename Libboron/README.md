While I was running boron in my environment, I happened to stumble upon 2 heap buffer overflows in libboron (libboron.so.2 version 2.0.8) when processing slightly malformed input.  This has been officially tested on both Mac (x86_64) and Linux (x86_64):

#### Files for reproduction
[reproduction.zip](./reproduction.zip)

## Compiling

```
git clone https://github.com/0branch/boron.git
cd boron
./configure && make
sudo make install && sudo ldconfig
```

## CVE-2023-40294- Heap buffer overflow in ur_parseBlockI at i_parse_blk.c:

https://github.com/0branch/boron/blob/e98ed6cbc7911cf31a6e4ac8a0b00fd7c224e807/urlan/i_parse_blk.c#L21


First, I executed boron against the file that produced the crash:

```
$ ./boron ur_parseBlockI_overflow.b 
malloc(): invalid size (unsorted)
zsh: IOT instruction  ./boron ur_parseBlockI_overflow.b
```

The output made be believe that there was a heap overflow corrupting a heap chunk in the unsorted bin, so I compiled the project with address sanitizer and debug symbols to verify:

#### Makefile
```
# Boron Makefile for UNIX systems.

VER=2.0.8

DESTDIR ?= /usr/local
BIN_DIR=$(DESTDIR)/bin
LIB_DIR=$(DESTDIR)/lib
INC_DIR=$(DESTDIR)/include/boron
MAN_DIR=$(DESTDIR)/share/man/man1
VIM_DIR=$(DESTDIR)/share/vim/vimfiles/syntax

OS := $(shell uname)

CFLAGS = -pipe -pedantic -Wall -W -Iinclude -Iurlan -Ieval -Isupport -g -fsanitize=address -DDEBUG
#CFLAGS += -O3 -DNDEBUG
#CFLAGS += -g -DDEBUG

ifeq ($(OS), Darwin)
CFLAGS += -std=c99
AR_LIB = libtool -static -o
else
CFLAGS += -std=gnu99 -fPIC
AR_LIB = ar rc
ifneq (,$(wildcard /usr/lib64/libc.so))
LIB_DIR=$(DESTDIR)/lib64
else ifneq (,$(wildcard /usr/lib/x86_64-linux-gnu/.))
LIB_DIR=$(DESTDIR)/lib/x86_64-linux-gnu
endif
endif

CONFIG := $(shell cat config.opt)
ifneq (,$(findstring _STATIC,$(CONFIG)))
	STATIC_LIB = true
endif

LIBS := -lm

ODIR = .obj
OBJ_FN = env.o array.o binary.o block.o coord.o date.o path.o \
	string.o context.o gc.o serialize.o tokenize.o \
	vector.o parse_block.o parse_string.o
OBJ_FN += str.o mem_util.o quickSortIndex.o fpconv.o
OBJ_FN += os.o boron.o port_file.o wait.o
ifneq (,$(findstring _HASHMAP,$(CONFIG)))
OBJ_FN += hashmap.o
endif
ifneq (,$(findstring _RANDOM,$(CONFIG)))
OBJ_FN += well512.o random.o
endif
ifneq (,$(findstring _SOCKET,$(CONFIG)))
OBJ_FN += port_socket.o
endif
ifneq (,$(findstring _THREAD,$(CONFIG)))
OBJ_FN += port_thread.o
ifeq ($(OS), Linux)
LIBS += -lpthread
endif
endif
LIB_OBJS = $(addprefix $(ODIR)/,$(OBJ_FN))


MAIN_FN = main.o 
ifneq (,$(findstring _LINENOISE,$(CONFIG)))
MAIN_FN += linenoise.o
else
EXE_LIBS += -lreadline -lhistory
endif
ifneq (,$(findstring _COMPRESS=1,$(CONFIG)))
LIBS += -lz
endif
ifneq (,$(findstring _COMPRESS=2,$(CONFIG)))
LIBS += -lbz2
endif
EXE_OBJS = $(addprefix $(ODIR)/,$(MAIN_FN))

ifdef STATIC_LIB
BORON_LIB = libboron.a
EXE_LIBS += $(LIBS)
else ifeq ($(OS), Darwin)
BORON_LIB = libboron.dylib
else
BORON_LIB = libboron.so.$(VER)
endif


$(ODIR)/%.o: urlan/%.c
	cc -c $(CFLAGS) $(CONFIG) $< -o $@
$(ODIR)/%.o: support/%.c
	cc -c $(CFLAGS) $(CONFIG) $< -o $@
$(ODIR)/%.o: eval/%.c
	cc -c $(CFLAGS) $(CONFIG) $< -o $@

boron: $(EXE_OBJS) $(BORON_LIB)
	cc $^ -o $@ $(EXE_LIBS) -g -fsanitize=address

$(ODIR)/os.o: unix/os.c
	cc -c $(CFLAGS) $(CONFIG) $< -o $@

$(EXE_OBJS): | $(ODIR)
$(LIB_OBJS): | $(ODIR)
$(ODIR):
	mkdir -p $@

$(BORON_LIB): $(LIB_OBJS)
ifdef STATIC_LIB
	$(AR_LIB) $@ $^
	ranlib $@
else ifeq ($(OS), Darwin)
	libtool -dynamiclib -o $@ $^ -install_name @rpath/$(BORON_LIB) $(LIBS)
else
	cc -o $@  -shared -g -fsanitize=address -Wl,-soname,libboron.so.2 $^ $(LIBS)
	ln -sf $(BORON_LIB) libboron.so.2
	ln -sf $(BORON_LIB) libboron.so
endif

.PHONY: clean install uninstall install-dev uninstall-dev

clean:
	rm -f boron $(BORON_LIB) $(LIB_OBJS) $(EXE_OBJS)
ifndef STATIC_LIB
	rm -f libboron.so*
endif
	rmdir $(ODIR)

install:
	mkdir -p $(BIN_DIR) $(LIB_DIR) $(MAN_DIR)
ifndef STATIC_LIB
ifeq ($(OS), Darwin)
	install_name_tool -id $(LIB_DIR)/libboron.dylib libboron.dylib
	install_name_tool -change libboron.dylib $(LIB_DIR)/libboron.dylib boron
	install -m 644 libboron.dylib $(LIB_DIR)
else
	install -m 755 -s $(BORON_LIB) $(LIB_DIR)
	ln -s $(BORON_LIB) $(LIB_DIR)/libboron.so.2
endif
endif
	install -s -m 755 boron $(BIN_DIR)
	gzip -c -n doc/boron.troff > doc/boron.1.gz
	install -m 644 doc/boron.1.gz $(MAN_DIR)

uninstall:
	rm -f $(BIN_DIR)/boron $(MAN_DIR)/boron.1
ifndef STATIC_LIB
	rm -f $(LIB_DIR)/$(BORON_LIB)
ifneq ($(OS), Darwin)
	rm -f $(LIB_DIR)/libboron.so.2
endif
endif

install-dev:
	mkdir -p $(INC_DIR) $(LIB_DIR)
	sed -e 's~"urlan.h"~<boron/urlan.h>~' include/boron.h >boron.tmp
	install -m 644 boron.tmp $(INC_DIR)/boron.h
	rm boron.tmp
	install -m 644 include/urlan.h        $(INC_DIR)
	install -m 644 include/urlan_atoms.h  $(INC_DIR)
#	install -m 755 scripts/copr.b $(BIN_DIR)/copr
ifdef STATIC_LIB
	install -m 644 $(BORON_LIB) $(LIB_DIR)
endif
ifneq ($(OS), Darwin)
	mkdir -p $(VIM_DIR)
	install -m 644 doc/boron.vim $(VIM_DIR)
ifndef STATIC_LIB
	ln -s $(BORON_LIB) $(LIB_DIR)/libboron.so
endif
endif

uninstall-dev:
ifdef STATIC_LIB
	rm -f $(LIB_DIR)/$(BORON_LIB)
endif
ifneq ($(OS), Darwin)
ifndef STATIC_LIB
	rm -f $(LIB_DIR)/libboron.so
endif
	rm -f $(VIM_DIR)/boron.vim
endif
#	rm -f $(BIN_DIR)/copr
	rm -f $(INC_DIR)/boron.h $(INC_DIR)/urlan.h $(INC_DIR)/urlan_atoms.h
	rmdir $(INC_DIR)
```

Executing boron against ur_parseBlockI_overflow.b a second time produces the following output from ASAN, confirming the heap buffer overflow:

#### Address Sanitizer Output

```
=================================================================
==104977==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000ce8 at pc 0x7ff8ed7c9b02 bp 0x7ffdcef68600 sp 0x7ffdcef685f8
WRITE of size 1 at 0x603000000ce8 thread T0
    #0 0x7ff8ed7c9b01  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa1b01) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #1 0x7ff8ed7c8426 in ur_parseBlockI (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa0426) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #2 0x7ff8ed7c8e63 in ur_parseBlockI (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa0e63) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #3 0x7ff8ed7cbf88 in boron_compileArgProgram (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa3f88) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #4 0x7ff8ed7b1364  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x89364) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #5 0x7ff8ed7cdefe  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa5efe) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #6 0x7ff8ed7cfac0 in boron_eval1 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa7ac0) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #7 0x7ff8ed7cfe44 in boron_eval1 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa7e44) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #8 0x7ff8ed7d090c in boron_doBlock (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa890c) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #9 0x7ff8ed7a119f in boron_doVoid (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x7919f) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #10 0x7ff8ed7b052d  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x8852d) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #11 0x7ff8ed7b071c  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x8871c) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #12 0x7ff8ed7cdefe  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa5efe) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #13 0x7ff8ed7cfac0 in boron_eval1 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa7ac0) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #14 0x7ff8ed7cf2f2  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa72f2) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #15 0x7ff8ed7cfb41 in boron_eval1 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa7b41) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #16 0x7ff8ed7cfe44 in boron_eval1 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa7e44) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #17 0x7ff8ed7d090c in boron_doBlock (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa890c) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #18 0x55a6bcb4873f in main eval/main.c:354
    #19 0x7ff8ed56d6c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #20 0x7ff8ed56d784 in __libc_start_main_impl ../csu/libc-start.c:360
    #21 0x55a6bcb474d0 in _start (/dev/shm/boron/boron+0x34d0) (BuildId: bdf03d04eb6f48f8cccbd806f9b1261d304239a6)

0x603000000ce8 is located 0 bytes after 24-byte region [0x603000000cd0,0x603000000ce8)
allocated by thread T0 here:
    #0 0x7ff8ed8d85cf in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x7ff8ed764cdf in ur_binReserve (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x3ccdf) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #2 0x7ff8ed7cbb5a in boron_compileArgProgram (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa3b5a) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #3 0x7ff8ed7b1364  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x89364) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #4 0x7ff8ed7cdefe  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa5efe) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #5 0x7ff8ed7cfac0 in boron_eval1 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa7ac0) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #6 0x7ff8ed7cfe44 in boron_eval1 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa7e44) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #7 0x7ff8ed7d090c in boron_doBlock (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa890c) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #8 0x7ff8ed7a119f in boron_doVoid (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x7919f) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #9 0x7ff8ed7b052d  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x8852d) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #10 0x7ff8ed7b071c  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x8871c) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #11 0x7ff8ed7cdefe  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa5efe) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #12 0x7ff8ed7cfac0 in boron_eval1 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa7ac0) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #13 0x7ff8ed7cf2f2  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa72f2) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #14 0x7ff8ed7cfb41 in boron_eval1 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa7b41) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #15 0x7ff8ed7cfe44 in boron_eval1 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa7e44) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #16 0x7ff8ed7d090c in boron_doBlock (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa890c) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #17 0x55a6bcb4873f in main eval/main.c:354
    #18 0x7ff8ed56d6c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

SUMMARY: AddressSanitizer: heap-buffer-overflow (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xa1b01) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a) 
Shadow bytes around the buggy address:
  0x603000000a00: 00 00 06 fa fa fa 00 00 04 fa fa fa 00 00 03 fa
  0x603000000a80: fa fa 00 00 01 fa fa fa 00 00 02 fa fa fa 00 00
  0x603000000b00: 00 03 fa fa 00 00 00 06 fa fa 00 00 00 fa fa fa
  0x603000000b80: 00 00 00 03 fa fa 00 00 00 fa fa fa 00 00 00 fa
  0x603000000c00: fa fa 00 00 00 fa fa fa 00 00 00 fa fa fa 00 00
=>0x603000000c80: 00 fa fa fa 00 00 00 fa fa fa 00 00 00[fa]fa fa
  0x603000000d00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x603000000d80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x603000000e00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x603000000e80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x603000000f00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==104977==ABORTING

```

## CVE-2023-40295- Heap buffer overflow in ur_strInitUtf8 at string.c 

https://github.com/0branch/boron/blob/e98ed6cbc7911cf31a6e4ac8a0b00fd7c224e807/urlan/string.c#L343

Next, I executed boron against the file that produced the crash in ur_strInitUtf8:

```
./boron ur_strInitUtf8_overflow.b 
corrupted size vs. prev_size
zsh: IOT instruction  ./boron ur_strInitUtf8_overflow.b

```

The output made be believe that there was a heap overflow corrupting the heap chunk size/prev_size, so I compiled the project with address sanitizer and debug symbols to verify:

```
# Boron Makefile for UNIX systems.

VER=2.0.8

DESTDIR ?= /usr/local
BIN_DIR=$(DESTDIR)/bin
LIB_DIR=$(DESTDIR)/lib
INC_DIR=$(DESTDIR)/include/boron
MAN_DIR=$(DESTDIR)/share/man/man1
VIM_DIR=$(DESTDIR)/share/vim/vimfiles/syntax

OS := $(shell uname)

CFLAGS = -pipe -pedantic -Wall -W -Iinclude -Iurlan -Ieval -Isupport -g -fsanitize=address -DDEBUG
#CFLAGS += -O3 -DNDEBUG
#CFLAGS += -g -DDEBUG

ifeq ($(OS), Darwin)
CFLAGS += -std=c99
AR_LIB = libtool -static -o
else
CFLAGS += -std=gnu99 -fPIC
AR_LIB = ar rc
ifneq (,$(wildcard /usr/lib64/libc.so))
LIB_DIR=$(DESTDIR)/lib64
else ifneq (,$(wildcard /usr/lib/x86_64-linux-gnu/.))
LIB_DIR=$(DESTDIR)/lib/x86_64-linux-gnu
endif
endif

CONFIG := $(shell cat config.opt)
ifneq (,$(findstring _STATIC,$(CONFIG)))
	STATIC_LIB = true
endif

LIBS := -lm

ODIR = .obj
OBJ_FN = env.o array.o binary.o block.o coord.o date.o path.o \
	string.o context.o gc.o serialize.o tokenize.o \
	vector.o parse_block.o parse_string.o
OBJ_FN += str.o mem_util.o quickSortIndex.o fpconv.o
OBJ_FN += os.o boron.o port_file.o wait.o
ifneq (,$(findstring _HASHMAP,$(CONFIG)))
OBJ_FN += hashmap.o
endif
ifneq (,$(findstring _RANDOM,$(CONFIG)))
OBJ_FN += well512.o random.o
endif
ifneq (,$(findstring _SOCKET,$(CONFIG)))
OBJ_FN += port_socket.o
endif
ifneq (,$(findstring _THREAD,$(CONFIG)))
OBJ_FN += port_thread.o
ifeq ($(OS), Linux)
LIBS += -lpthread
endif
endif
LIB_OBJS = $(addprefix $(ODIR)/,$(OBJ_FN))


MAIN_FN = main.o 
ifneq (,$(findstring _LINENOISE,$(CONFIG)))
MAIN_FN += linenoise.o
else
EXE_LIBS += -lreadline -lhistory
endif
ifneq (,$(findstring _COMPRESS=1,$(CONFIG)))
LIBS += -lz
endif
ifneq (,$(findstring _COMPRESS=2,$(CONFIG)))
LIBS += -lbz2
endif
EXE_OBJS = $(addprefix $(ODIR)/,$(MAIN_FN))

ifdef STATIC_LIB
BORON_LIB = libboron.a
EXE_LIBS += $(LIBS)
else ifeq ($(OS), Darwin)
BORON_LIB = libboron.dylib
else
BORON_LIB = libboron.so.$(VER)
endif


$(ODIR)/%.o: urlan/%.c
	cc -c $(CFLAGS) $(CONFIG) $< -o $@
$(ODIR)/%.o: support/%.c
	cc -c $(CFLAGS) $(CONFIG) $< -o $@
$(ODIR)/%.o: eval/%.c
	cc -c $(CFLAGS) $(CONFIG) $< -o $@

boron: $(EXE_OBJS) $(BORON_LIB)
	cc $^ -o $@ $(EXE_LIBS) -g -fsanitize=address

$(ODIR)/os.o: unix/os.c
	cc -c $(CFLAGS) $(CONFIG) $< -o $@

$(EXE_OBJS): | $(ODIR)
$(LIB_OBJS): | $(ODIR)
$(ODIR):
	mkdir -p $@

$(BORON_LIB): $(LIB_OBJS)
ifdef STATIC_LIB
	$(AR_LIB) $@ $^
	ranlib $@
else ifeq ($(OS), Darwin)
	libtool -dynamiclib -o $@ $^ -install_name @rpath/$(BORON_LIB) $(LIBS)
else
	cc -o $@  -shared -g -fsanitize=address -Wl,-soname,libboron.so.2 $^ $(LIBS)
	ln -sf $(BORON_LIB) libboron.so.2
	ln -sf $(BORON_LIB) libboron.so
endif

.PHONY: clean install uninstall install-dev uninstall-dev

clean:
	rm -f boron $(BORON_LIB) $(LIB_OBJS) $(EXE_OBJS)
ifndef STATIC_LIB
	rm -f libboron.so*
endif
	rmdir $(ODIR)

install:
	mkdir -p $(BIN_DIR) $(LIB_DIR) $(MAN_DIR)
ifndef STATIC_LIB
ifeq ($(OS), Darwin)
	install_name_tool -id $(LIB_DIR)/libboron.dylib libboron.dylib
	install_name_tool -change libboron.dylib $(LIB_DIR)/libboron.dylib boron
	install -m 644 libboron.dylib $(LIB_DIR)
else
	install -m 755 -s $(BORON_LIB) $(LIB_DIR)
	ln -s $(BORON_LIB) $(LIB_DIR)/libboron.so.2
endif
endif
	install -s -m 755 boron $(BIN_DIR)
	gzip -c -n doc/boron.troff > doc/boron.1.gz
	install -m 644 doc/boron.1.gz $(MAN_DIR)

uninstall:
	rm -f $(BIN_DIR)/boron $(MAN_DIR)/boron.1
ifndef STATIC_LIB
	rm -f $(LIB_DIR)/$(BORON_LIB)
ifneq ($(OS), Darwin)
	rm -f $(LIB_DIR)/libboron.so.2
endif
endif

install-dev:
	mkdir -p $(INC_DIR) $(LIB_DIR)
	sed -e 's~"urlan.h"~<boron/urlan.h>~' include/boron.h >boron.tmp
	install -m 644 boron.tmp $(INC_DIR)/boron.h
	rm boron.tmp
	install -m 644 include/urlan.h        $(INC_DIR)
	install -m 644 include/urlan_atoms.h  $(INC_DIR)
#	install -m 755 scripts/copr.b $(BIN_DIR)/copr
ifdef STATIC_LIB
	install -m 644 $(BORON_LIB) $(LIB_DIR)
endif
ifneq ($(OS), Darwin)
	mkdir -p $(VIM_DIR)
	install -m 644 doc/boron.vim $(VIM_DIR)
ifndef STATIC_LIB
	ln -s $(BORON_LIB) $(LIB_DIR)/libboron.so
endif
endif

uninstall-dev:
ifdef STATIC_LIB
	rm -f $(LIB_DIR)/$(BORON_LIB)
endif
ifneq ($(OS), Darwin)
ifndef STATIC_LIB
	rm -f $(LIB_DIR)/libboron.so
endif
	rm -f $(VIM_DIR)/boron.vim
endif
#	rm -f $(BIN_DIR)/copr
	rm -f $(INC_DIR)/boron.h $(INC_DIR)/urlan.h $(INC_DIR)/urlan_atoms.h
	rmdir $(INC_DIR)
```


Executing boron against ur_strInitUtf8_overflow.b a second time will produce the output from ASAN confirming the heap buffer overflow:

```
└─$ ./boron overflows/ur_strInitUtf8_overflow.b 
=================================================================
==122297==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x61a000001708 at pc 0x7f6b69141450 bp 0x7ffc47b562d0 sp 0x7ffc47b562c8
WRITE of size 1 at 0x61a000001708 thread T0
    #0 0x7f6b6914144f in ur_strInitUtf8 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x4644f) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #1 0x7f6b6914185c in ur_makeStringUtf8 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x4685c) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #2 0x7f6b69159959 in ur_tokenizeB (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x5e959) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #3 0x7f6b6915a3ac in ur_tokenize (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x5f3ac) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #4 0x7f6b69193e78  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x98e78) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #5 0x7f6b691a774b in boron_load (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xac74b) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #6 0x55e53db95707 in main eval/main.c:351
    #7 0x7f6b688456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #8 0x7f6b68845784 in __libc_start_main_impl ../csu/libc-start.c:360
    #9 0x55e53db944d0 in _start (/dev/shm/boron/boron+0x34d0) (BuildId: bdf03d04eb6f48f8cccbd806f9b1261d304239a6)

0x61a000001708 is located 0 bytes after 1160-byte region [0x61a000001280,0x61a000001708)
allocated by thread T0 here:
    #0 0x7f6b68ad85cf in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x7f6b69136c11 in ur_arrInit (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x3bc11) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #2 0x7f6b69141908 in ur_strInit (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x46908) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #3 0x7f6b691412bd in ur_strInitUtf8 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x462bd) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #4 0x7f6b6914185c in ur_makeStringUtf8 (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x4685c) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #5 0x7f6b69159959 in ur_tokenizeB (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x5e959) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #6 0x7f6b6915a3ac in ur_tokenize (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x5f3ac) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #7 0x7f6b69193e78  (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x98e78) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #8 0x7f6b691a774b in boron_load (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0xac74b) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a)
    #9 0x55e53db95707 in main eval/main.c:351
    #10 0x7f6b688456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

SUMMARY: AddressSanitizer: heap-buffer-overflow (/usr/local/lib/x86_64-linux-gnu/libboron.so.2+0x4644f) (BuildId: 8604ed3373a7d0fad1d0ab72cbd67e9bc93ce54a) in ur_strInitUtf8
Shadow bytes around the buggy address:
  0x61a000001480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x61a000001500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x61a000001580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x61a000001600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x61a000001680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x61a000001700: 00[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x61a000001780: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x61a000001800: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x61a000001880: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x61a000001900: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x61a000001980: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==122297==ABORTING

```

### Mitigation

For both of these heap overflows a check on the size of the data being copied over to the heap should do the trick.  

Thanks!
Halcy0nic
