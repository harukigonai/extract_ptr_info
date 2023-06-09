CC = g++
CFLAGS = -g -Wall -std=c++20
LDFLAGS = -g -Wall
LDLIBS = -L/usr/lib/llvm-11/lib -lLLVM
# LDLIBS = -lLLVM
INCLUDE = -I/usr/lib/llvm-11/include

.PHONY: clean
clean:
	rm -f *.o main getFunctions

getFunctions: getFunctions.cpp
	$(CC) $(CFLAGS) getFunctions.cpp -o getFunctions $(INCLUDE) $(LDLIBS)
