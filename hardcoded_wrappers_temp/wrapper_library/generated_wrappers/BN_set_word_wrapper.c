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

int bb_BN_set_word(BIGNUM * arg_a,BN_ULONG arg_b);

int BN_set_word(BIGNUM * arg_a,BN_ULONG arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("BN_set_word called %lu\n", in_lib);
    if (!in_lib)
        return bb_BN_set_word(arg_a,arg_b);
    else {
        int (*orig_BN_set_word)(BIGNUM *,BN_ULONG);
        orig_BN_set_word = dlsym(RTLD_NEXT, "BN_set_word");
        return orig_BN_set_word(arg_a,arg_b);
    }
}

int bb_BN_set_word(BIGNUM * arg_a,BN_ULONG arg_b) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884099; em[1] = 8; em[2] = 2; /* 0: pointer_to_array_of_pointers_to_stack */
    	em[3] = 7; em[4] = 0; 
    	em[5] = 10; em[6] = 12; 
    em[7] = 0; em[8] = 8; em[9] = 0; /* 7: long unsigned int */
    em[10] = 0; em[11] = 4; em[12] = 0; /* 10: int */
    em[13] = 0; em[14] = 24; em[15] = 1; /* 13: struct.bignum_st */
    	em[16] = 0; em[17] = 0; 
    em[18] = 1; em[19] = 8; em[20] = 1; /* 18: pointer.struct.bignum_st */
    	em[21] = 13; em[22] = 0; 
    em[23] = 0; em[24] = 4; em[25] = 0; /* 23: unsigned int */
    args_addr->arg_entity_index[0] = 18;
    args_addr->arg_entity_index[1] = 23;
    args_addr->ret_entity_index = 10;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIGNUM * new_arg_a = *((BIGNUM * *)new_args->args[0]);

    BN_ULONG new_arg_b = *((BN_ULONG *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_BN_set_word)(BIGNUM *,BN_ULONG);
    orig_BN_set_word = dlsym(RTLD_NEXT, "BN_set_word");
    *new_ret_ptr = (*orig_BN_set_word)(new_arg_a,new_arg_b);

    syscall(889);

    free(args_addr);

    return ret;
}

