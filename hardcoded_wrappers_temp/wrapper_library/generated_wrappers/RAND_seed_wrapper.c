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

void bb_RAND_seed(void * arg_a,int arg_b);

void RAND_seed(void * arg_a,int arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("RAND_seed called %lu\n", in_lib);
    if (!in_lib)
        bb_RAND_seed(arg_a,arg_b);
    else {
        void (*orig_RAND_seed)(void *,int);
        orig_RAND_seed = dlsym(RTLD_NEXT, "RAND_seed");
        orig_RAND_seed(arg_a,arg_b);
    }
}

void bb_RAND_seed(void * arg_a,int arg_b) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 8; em[2] = 0; /* 0: pointer.void */
    em[3] = 0; em[4] = 4; em[5] = 0; /* 3: int */
    args_addr->arg_entity_index[0] = 0;
    args_addr->arg_entity_index[1] = 3;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    void * new_arg_a = *((void * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    void (*orig_RAND_seed)(void *,int);
    orig_RAND_seed = dlsym(RTLD_NEXT, "RAND_seed");
    (*orig_RAND_seed)(new_arg_a,new_arg_b);

    syscall(889);

    free(args_addr);

}

