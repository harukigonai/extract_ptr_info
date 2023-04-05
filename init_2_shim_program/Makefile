CC = gcc
CFLAGS = -g -Wall

.PHONY: all
all: clean lib_free init_2

.PHONY: clean
clean:
	rm -f *.o init_2 main && cd lib_free && $(MAKE) clean

init_2: init_2.o
	$(CC) -static $(CFLAGS) $^ -o $@ 

init_2.o: init_2.c

.PHONY: lib_free
lib_free:
	cd lib_free && $(MAKE)

