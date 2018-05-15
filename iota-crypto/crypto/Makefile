CC        = gcc
CFLAGS    = -g -O2 -Wall -fPIC -std=c99 -D_GNU_SOURCE
LDFLAGS   = -shared -fPIC
SUBDIRS   = src jni
SOURCES   = $(wildcard *.c src/*.c jni/*.c)
RMVDIRS   = $(notdir $(SOURCES))
OBJECTS   = $(patsubst %.c,%.o,$(RMVDIRS))
JNIHDRS   = -I /usr/lib/jvm/java-7-openjdk-amd64/include -I /usr/lib/jvm/java-7-openjdk-amd64/include/linux
LIBCRYPTO = libiota-crypto.so


.PHONY:all

all:$(LIBCRYPTO)

$(LIBCRYPTO):$(OBJECTS)
	$(CC) -o $(LIBCRYPTO) $^ $(LDFLAGS) -Xlinker --unresolved-symbols=ignore-in-shared-libs

$(OBJECTS):$(SOURCES)
	$(CC) -c $^ $(CFLAGS) -I include $(JNIHDRS)


.PHONY:clean

clean:
	rm -f *.o *.so *.h.gch
	for i in $(SUBDIRS); do rm -f $$i/*.o $$i/*.gch; done
