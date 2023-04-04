C = gcc
CFLAGS = -g -Wall -fPIC
LDFLAGS = -g -shared
LDLIBS = -ldl

.PHONY: all
all: clean libfree.so

.PHONY: clean
clean:
	rm -f *.o *.so *~

%.so:
	$(LINK.c) $(LDFLAGS) $^ -o $@ $(LDLIBS)

libfree.so: free.o

free.o: free.c
