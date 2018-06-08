CC           = gcc
CFLAGS       = -g -O2 -Wall -fPIC
LDFLAGS      = -shared -fPIC
SUBDIRS      = sha256 rlp jni
SOURCES      = $(wildcard *.c sha256/*.c rlp/*.c jni/*.c)
RMVDIRS      = $(notdir $(SOURCES))
OBJECTS      = $(patsubst %.c,%.o,$(RMVDIRS))

##Linux
# JNIHDRS      = -I /opt/jdk/include -I /opt/jdk/include/linux
## MacOS
JNIHDRS      = -I /Library/Java/JavaVirtualMachines/jdk1.7.0_80.jdk/Contents/Home/include -I /Library/Java/JavaVirtualMachines/jdk1.7.0_80.jdk/Contents/Home/include/darwin

LIBSECP256K1 = libsecp256k1.a
LIBCRYPTO    = libbrewchain-crypto.so


.PHONY:all

all:$(LIBSECP256K1) $(LIBCRYPTO)

$(LIBSECP256K1):
	cd secp256k1; ./autogen.sh; ./configure --enable-module-recovery --with-bignum=no; make libsecp256k1.la; cp .libs/libsecp256k1.a ..; cd ..

$(LIBCRYPTO):$(OBJECTS)
	$(CC) -o $(LIBCRYPTO) $^ $(LDFLAGS) -Wl,--whole-archive -L. -l:libsecp256k1.a -I secp256k1 -Wl,--no-whole-archive -Xlinker --unresolved-symbols=ignore-in-shared-libs

$(OBJECTS):$(SOURCES)
	$(CC) -c $^ $(CFLAGS) -I . -I secp256k1 $(JNIHDRS)


.PHONY:clean

clean:
	make clean -C secp256k1
	rm -f *.o *.so *.h.gch libsecp256k1.a
	for i in $(SUBDIRS); do rm -f $$i/*.o $$i/*.gch; done
