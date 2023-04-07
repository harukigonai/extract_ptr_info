#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/srp.h>

#include "../arg_struct.h"

void bb_EVP_cleanup(void);

void EVP_cleanup(void) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_cleanup called %lu\n", in_lib);
    if (!in_lib)
        bb_EVP_cleanup();
    else {
        void (*orig_EVP_cleanup)(void);
        orig_EVP_cleanup = dlsym(RTLD_NEXT, "EVP_cleanup");
        orig_EVP_cleanup();
    }
}

void bb_EVP_cleanup(void) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    args_addr->ret_entity_index = -1;

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    void (*orig_EVP_cleanup)(void);
    orig_EVP_cleanup = dlsym(RTLD_NEXT, "EVP_cleanup");
    (*orig_EVP_cleanup)();

    syscall(889);

    free(args_addr);

}

