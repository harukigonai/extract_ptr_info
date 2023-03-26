CC = gcc
CFLAGS = -g -Wall -fPIC
LDFLAGS = -g -shared
LDLIBS = -ldl
INCLUDE = -I/opt/openssl/openssl/include

.PHONY: all
all: clean libssl_wrapper.so

.PHONY: clean
clean:
	rm -f *.o *.so

%.so:
	$(LINK.c) $(LDFLAGS) $^ -o $@ $(LDLIBS)

libssl_wrapper.so: libssl_wrapper.o

libssl_wrapper.o: libssl_wrapper.c
	gcc -g -Wall -c libssl_wrapper.c -o libssl_wrapper.o $(CLFAGS) -I/opt/openssl/openssl/include $(LDLIBS)

# LD_PRELOAD="/root/apache/preloader/libssl_wrapper.so" /root/apache/bin/apachectl -D FOREGROUND
# LD_PRELOAD="/root/apache/preloader/libssl_wrapper.so" /root/apache/bin/apachectl
