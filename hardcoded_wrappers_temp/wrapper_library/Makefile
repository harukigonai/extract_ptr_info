CC = gcc
CFLAGS = -g -Wall -fPIC
LDFLAGS = -g -shared
LDLIBS = -ldl
INCLUDE = -I/opt/openssl/openssl/include
VPATH = generated_wrappers

# Figure out how to compile files in subdir generated_wrappers

# # CSOURCES :=  $(wildcard *.c)
# CSOURCES := $(generated_wrappers/*.c)
# # COBJECTS :=  $(wildcard *.o)
# COBJECTS :=  $(generated_wrappers/*.o)

.PHONY: all
all: clean libssl_wrapper.so

.PHONY: clean
clean:
	rm -f *.o *.so

.PHONY: libssl_wrapper.so
libssl_wrapper.so:
	cd generated_wrappers && \
	gcc -g -Wall *.c -o *.o $(INCLUDE)

# libssl_wrapper.so: $(COBJECTS)
# 	$(LINK.c) $(LDFLAGS) $(COBJECTS) -o libssl_wrapper.so $(LDLIBS)

generated_wrappers/%.o: generated_wrappers/%.c
	$(CC) $< -o $@

# ): $(CSOURCES)
# 	$(CC) $(CFLAGS) -c $^ -o $@ ${INCLUDE}

# LD_PRELOAD="/root/apache/preloader/libssl_wrapper.so" /root/apache/bin/apachectl -D FOREGROUND
# LD_PRELOAD="/root/apache/preloader/libssl_wrapper.so" /root/apache/bin/apachectl
