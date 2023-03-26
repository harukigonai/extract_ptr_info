CC = gcc
CFLAGS = -g -Wall -fPIC
LDFLAGS = -g -shared
LDLIBS = -ldl
INCLUDE = -I/opt/openssl/openssl/include
WRAPPER_DIR = ./generated_wrappers

.PHONY: all
all: clean libssl_wrapper.so

.PHONY: clean
clean:
	rm -f *.o *.so

%.so:
	$(LINK.c) $(LDFLAGS) $^ -o $@ $(LDLIBS)

libssl_wrapper.so: *.o
	gcc -g -Wall \
		-c ${generated_wrappers}/libssl_wrapper.c \
		-o ${generated_wrappers}/libssl_wrapper.o $(CLFAGS) \
		${INCLUDE} $(LDLIBS)

${generated_wrappers}/%.o:
	gcc $(CFLAGS) -c $^ -o $@ ${INCLUDE}

# LD_PRELOAD="/root/apache/preloader/libssl_wrapper.so" /root/apache/bin/apachectl -D FOREGROUND
# LD_PRELOAD="/root/apache/preloader/libssl_wrapper.so" /root/apache/bin/apachectl
