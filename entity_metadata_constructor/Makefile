CC = g++
CFLAGS = -g -Wall
LDFLAGS = -g -Wall
LDLIBS = -L/usr/lib/llvm-10/lib -lLLVM
INCLUDE = -I/usr/lib/llvm-10/include

main: main.o
	$(CC) $(LDFLAGS) main.cpp -o main $(INCLUDE) $(LDLIBS)

main.o: main.cpp struct_info.h
	$(CC) $(CFLAGS) main.cpp -o main.o $(INCLUDE) $(LDLIBS)

.PHONY: clean
clean:
	rm -f *.o main bin/*
