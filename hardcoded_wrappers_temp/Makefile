CC = gcc
CFLAGS = -g -Wall -fPIC
LDFLAGS = -g -shared
LDLIBS = -ldl
INCLUDE = -I/opt/openssl/openssl/include

.PHONY: all
all: clean libuhh.so

.PHONY: clean
clean:
	rm -f *.o *.so

%.so:
	$(LINK.c) $(LDFLAGS) $^ -o $@ $(LDLIBS)

libuhh.so: uhh.o

uhh.o: uhh.c
	gcc -g -Wall -c uhh.c -o uhh.o $(CLFAGS) -I/opt/openssl/openssl/include $(LDLIBS)

# LD_PRELOAD="/root/apache/preloader/libuhh.so" /root/apache/bin/apachectl -D FOREGROUND
# LD_PRELOAD="/root/apache/preloader/libuhh.so" /root/apache/bin/apachectl
