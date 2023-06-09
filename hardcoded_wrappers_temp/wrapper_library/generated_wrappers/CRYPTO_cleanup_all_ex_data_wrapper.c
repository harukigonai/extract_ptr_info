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

void bb_CRYPTO_cleanup_all_ex_data(void);

void CRYPTO_cleanup_all_ex_data(void) 
{
    unsigned long in_lib = syscall(890);
    printf("CRYPTO_cleanup_all_ex_data called %lu\n", in_lib);
    if (!in_lib)
        bb_CRYPTO_cleanup_all_ex_data();
    else {
        void (*orig_CRYPTO_cleanup_all_ex_data)(void);
        orig_CRYPTO_cleanup_all_ex_data = dlsym(RTLD_NEXT, "CRYPTO_cleanup_all_ex_data");
        orig_CRYPTO_cleanup_all_ex_data();
    }
}

void bb_CRYPTO_cleanup_all_ex_data(void) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    args_addr->ret_entity_index = -1;

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    void (*orig_CRYPTO_cleanup_all_ex_data)(void);
    orig_CRYPTO_cleanup_all_ex_data = dlsym(RTLD_NEXT, "CRYPTO_cleanup_all_ex_data");
    (*orig_CRYPTO_cleanup_all_ex_data)();

    syscall(889);

    free(args_addr);

}

