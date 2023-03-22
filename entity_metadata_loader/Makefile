CC = gcc
CFLAGS = -g -Wall
LDFLAGS = -g -Wall

main: main.o
	$(CC) $(LDFLAGS) main.cpp -o main

main.o: main.cpp struct_info.h
	$(CC) $(CFLAGS) main.cpp -o main.o

.PHONY: clean
clean:
	rm -f *.o main
