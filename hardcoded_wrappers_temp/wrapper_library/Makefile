.PHONY: libssl_wrapper.so
libssl_wrapper.so:
	$(MAKE) -C generated_wrappers && \
	cp generated_wrappers/libssl_wrapper.so ./

.PHONY: all
all: clean libssl_wrapper.so

.PHONY: clean
clean:
	rm -f *.o *.so

# LD_PRELOAD="/root/apache/preloader/libssl_wrapper.so" /root/apache/bin/apachectl -D FOREGROUND
# LD_PRELOAD="/root/apache/preloader/libssl_wrapper.so" /root/apache/bin/apachectl
