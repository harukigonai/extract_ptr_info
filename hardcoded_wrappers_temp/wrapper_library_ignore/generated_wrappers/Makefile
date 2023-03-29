CC = gcc
CFLAGS = -g -Wall -fPIC
LDFLAGS = -g -shared
LDLIBS = -ldl
INCLUDE = -I/opt/openssl/openssl/include

SRC=$(wildcard *.c)

libssl_wrapper.so: $(SRC)
	$(CC) $(CFLAGS) $(INCLUDE) $(SRC) -o $@ $(LDFLAGS) $(LDLIBS)

.PHONY: all
all: clean libssl_wrapper.so

.PHONY: clean
clean:
	rm -f *.o *.so
