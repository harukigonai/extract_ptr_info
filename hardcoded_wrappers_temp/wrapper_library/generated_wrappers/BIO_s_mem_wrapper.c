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

BIO_METHOD * bb_BIO_s_mem(void);

BIO_METHOD * BIO_s_mem(void) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_s_mem called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_s_mem();
    else {
        BIO_METHOD * (*orig_BIO_s_mem)(void);
        orig_BIO_s_mem = dlsym(RTLD_NEXT, "BIO_s_mem");
        return orig_BIO_s_mem();
    }
}

BIO_METHOD * bb_BIO_s_mem(void) 
{
    BIO_METHOD * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 8884097; em[4] = 8; em[5] = 0; /* 3: pointer.func */
    em[6] = 8884097; em[7] = 8; em[8] = 0; /* 6: pointer.func */
    em[9] = 8884097; em[10] = 8; em[11] = 0; /* 9: pointer.func */
    em[12] = 8884097; em[13] = 8; em[14] = 0; /* 12: pointer.func */
    em[15] = 8884097; em[16] = 8; em[17] = 0; /* 15: pointer.func */
    em[18] = 0; em[19] = 1; em[20] = 0; /* 18: char */
    em[21] = 1; em[22] = 8; em[23] = 1; /* 21: pointer.char */
    	em[24] = 8884096; em[25] = 0; 
    em[26] = 0; em[27] = 80; em[28] = 9; /* 26: struct.bio_method_st */
    	em[29] = 21; em[30] = 8; 
    	em[31] = 15; em[32] = 16; 
    	em[33] = 12; em[34] = 24; 
    	em[35] = 9; em[36] = 32; 
    	em[37] = 12; em[38] = 40; 
    	em[39] = 3; em[40] = 48; 
    	em[41] = 0; em[42] = 56; 
    	em[43] = 0; em[44] = 64; 
    	em[45] = 6; em[46] = 72; 
    em[47] = 1; em[48] = 8; em[49] = 1; /* 47: pointer.struct.bio_method_st */
    	em[50] = 26; em[51] = 0; 
    args_addr->ret_entity_index = 47;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO_METHOD * *new_ret_ptr = (BIO_METHOD * *)new_args->ret;

    BIO_METHOD * (*orig_BIO_s_mem)(void);
    orig_BIO_s_mem = dlsym(RTLD_NEXT, "BIO_s_mem");
    *new_ret_ptr = (*orig_BIO_s_mem)();

    syscall(889);

    free(args_addr);

    return ret;
}

