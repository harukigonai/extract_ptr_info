CC = gcc
CFLAGS = -g -Wall

.PHONY: all
all: clean init_2

.PHONY: clean
clean:
	rm -f *.o init_2 main

init_2: init_2.o
	$(CC) -static $(CFLAGS) $^ -o $@ 

init_2.o: init_2.c

