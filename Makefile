CC = g++
CFLAGS = -g -Wall -std=c++20
LDFLAGS = -g -Wall
LDLIBS = -L/usr/lib/llvm-11/lib -lLLVM
# LDLIBS = -lLLVM
INCLUDE = -I/usr/lib/llvm-11/include

main: main.o
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

main.o: main.cpp struct_info.h
	$(CC) -c $(CFLAGS) main.cpp -o $@ $(INCLUDE)

getFunctions: getFunctions.cpp
	$(CC) $(CFLAGS) getFunctions.cpp -o getFunctions $(INCLUDE) $(LDLIBS)
