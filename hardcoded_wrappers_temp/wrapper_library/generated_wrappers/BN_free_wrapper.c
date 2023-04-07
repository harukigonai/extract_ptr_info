#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
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

void bb_BN_free(BIGNUM * arg_a);

void BN_free(BIGNUM * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("BN_free called %lu\n", in_lib);
    if (!in_lib)
        bb_BN_free(arg_a);
    else {
        void (*orig_BN_free)(BIGNUM *);
        orig_BN_free = dlsym(RTLD_NEXT, "BN_free");
        orig_BN_free(arg_a);
    }
}

void bb_BN_free(BIGNUM * arg_a) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 4; em[2] = 0; /* 0: int */
    em[3] = 0; em[4] = 4; em[5] = 0; /* 3: unsigned int */
    em[6] = 8884099; em[7] = 8; em[8] = 2; /* 6: pointer_to_array_of_pointers_to_stack */
    	em[9] = 3; em[10] = 0; 
    	em[11] = 0; em[12] = 12; 
    em[13] = 0; em[14] = 24; em[15] = 1; /* 13: struct.bignum_st */
    	em[16] = 6; em[17] = 0; 
    em[18] = 1; em[19] = 8; em[20] = 1; /* 18: pointer.struct.bignum_st */
    	em[21] = 13; em[22] = 0; 
    args_addr->arg_entity_index[0] = 18;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIGNUM * new_arg_a = *((BIGNUM * *)new_args->args[0]);

    void (*orig_BN_free)(BIGNUM *);
    orig_BN_free = dlsym(RTLD_NEXT, "BN_free");
    (*orig_BN_free)(new_arg_a);

    syscall(889);

    free(args_addr);

}

