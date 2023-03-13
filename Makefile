CC = g++
CFLAGS = -g -Wall
LDFLAGS = -g -Wall
LDLIBS = -L/usr/lib/llvm-15/lib -lLLVM
# LDLIBS = -lLLVM
INCLUDE = -I/usr/lib/llvm-15/include

main: main.o
	$(CC) $(LDFLAGS) main.cpp -o main $(INCLUDE) $(LDLIBS)

main.o: main.cpp struct_info.h
	$(CC) $(CFLAGS) main.cpp -o main.o $(INCLUDE) $(LDLIBS)

getFunctions: getFunctions.cpp
	$(CC) $(CFLAGS) getFunctions.cpp -o getFunctions $(INCLUDE) $(LDLIBS)
