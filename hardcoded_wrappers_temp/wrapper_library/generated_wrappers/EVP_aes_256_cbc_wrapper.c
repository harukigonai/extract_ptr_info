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

const EVP_CIPHER * bb_EVP_aes_256_cbc(void);

const EVP_CIPHER * EVP_aes_256_cbc(void) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_aes_256_cbc called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_aes_256_cbc();
    else {
        const EVP_CIPHER * (*orig_EVP_aes_256_cbc)(void);
        orig_EVP_aes_256_cbc = dlsym(RTLD_NEXT, "EVP_aes_256_cbc");
        return orig_EVP_aes_256_cbc();
    }
}

const EVP_CIPHER * bb_EVP_aes_256_cbc(void) 
{
    const EVP_CIPHER * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 8884097; em[4] = 8; em[5] = 0; /* 3: pointer.func */
    em[6] = 8884097; em[7] = 8; em[8] = 0; /* 6: pointer.func */
    em[9] = 8884097; em[10] = 8; em[11] = 0; /* 9: pointer.func */
    em[12] = 8884097; em[13] = 8; em[14] = 0; /* 12: pointer.func */
    em[15] = 0; em[16] = 88; em[17] = 7; /* 15: struct.evp_cipher_st */
    	em[18] = 12; em[19] = 24; 
    	em[20] = 6; em[21] = 32; 
    	em[22] = 9; em[23] = 40; 
    	em[24] = 3; em[25] = 56; 
    	em[26] = 3; em[27] = 64; 
    	em[28] = 0; em[29] = 72; 
    	em[30] = 32; em[31] = 80; 
    em[32] = 0; em[33] = 8; em[34] = 0; /* 32: pointer.void */
    em[35] = 1; em[36] = 8; em[37] = 1; /* 35: pointer.struct.evp_cipher_st */
    	em[38] = 15; em[39] = 0; 
    args_addr->ret_entity_index = 35;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EVP_CIPHER * *new_ret_ptr = (const EVP_CIPHER * *)new_args->ret;

    const EVP_CIPHER * (*orig_EVP_aes_256_cbc)(void);
    orig_EVP_aes_256_cbc = dlsym(RTLD_NEXT, "EVP_aes_256_cbc");
    *new_ret_ptr = (*orig_EVP_aes_256_cbc)();

    syscall(889);

    free(args_addr);

    return ret;
}

