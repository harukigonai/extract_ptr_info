CC = g++
CFLAGS = -g -Wall
LDLIBS = -L/usr/lib/llvm-15/lib -lLLVM
# LDLIBS = -lLLVM
INCLUDE = -I/usr/lib/llvm-15/include

main: main.cpp
	$(CC) main.cpp -o main $(INCLUDE) $(LDLIBS)
