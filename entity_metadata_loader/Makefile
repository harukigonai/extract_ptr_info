CC = gcc
CFLAGS = -g -Wall
LDFLAGS = -g -Wall

test: test.o entity_metadata_loader.o lib_func_bst.o

test.o: test.c entity_metadata_loader.h lib_func_bst.h

entity_metadata_loader.o: entity_metadata_loader.c entity_metadata_loader.h

lib_func_bst.o: lib_func_bst.c lib_func_bst.h

.PHONY: clean
clean:
	rm -f *.o entity_metadata_loader test lib_func_bst
