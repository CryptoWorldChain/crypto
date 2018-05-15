CC      = gcc
CFLAGS  = -g -O2 -Wall -fPIC
LDFLAGS = -shared -fPIC
SUBDIRS = sm4 jni
SOURCES = $(wildcard *.c sm4/*.c jni/*.c)
RMVDIRS = $(notdir $(SOURCES))
OBJECTS = $(patsubst %.c,%.o,$(RMVDIRS))
JNIHDRS = -I /usr/lib/jvm/java-7-openjdk-amd64/include -I /usr/lib/jvm/java-7-openjdk-amd64/include/linux
LIBSM4  = libsm-crypto.so


.PHONY:all

all:$(LIBSM4)

$(LIBSM4):$(OBJECTS)
	$(CC) -o $(LIBSM4) $^ $(LDFLAGS) -Xlinker --unresolved-symbols=ignore-in-shared-libs

$(OBJECTS):$(SOURCES)
	$(CC) -c $^ $(CFLAGS) -I sm4 $(JNIHDRS)


.PHONY:clean

clean:
	rm -f *.o *.so *.h.gch
	for i in $(SUBDIRS); do rm -f $$i/*.o $$i/*.gch; done
