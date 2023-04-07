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

const EVP_MD * bb_EVP_sha256(void);

const EVP_MD * EVP_sha256(void) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_sha256 called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_sha256();
    else {
        const EVP_MD * (*orig_EVP_sha256)(void);
        orig_EVP_sha256 = dlsym(RTLD_NEXT, "EVP_sha256");
        return orig_EVP_sha256();
    }
}

const EVP_MD * bb_EVP_sha256(void) 
{
    const EVP_MD * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 8884097; em[4] = 8; em[5] = 0; /* 3: pointer.func */
    em[6] = 8884097; em[7] = 8; em[8] = 0; /* 6: pointer.func */
    em[9] = 0; em[10] = 120; em[11] = 8; /* 9: struct.env_md_st */
    	em[12] = 28; em[13] = 24; 
    	em[14] = 31; em[15] = 32; 
    	em[16] = 34; em[17] = 40; 
    	em[18] = 6; em[19] = 48; 
    	em[20] = 28; em[21] = 56; 
    	em[22] = 3; em[23] = 64; 
    	em[24] = 0; em[25] = 72; 
    	em[26] = 37; em[27] = 112; 
    em[28] = 8884097; em[29] = 8; em[30] = 0; /* 28: pointer.func */
    em[31] = 8884097; em[32] = 8; em[33] = 0; /* 31: pointer.func */
    em[34] = 8884097; em[35] = 8; em[36] = 0; /* 34: pointer.func */
    em[37] = 8884097; em[38] = 8; em[39] = 0; /* 37: pointer.func */
    em[40] = 1; em[41] = 8; em[42] = 1; /* 40: pointer.struct.env_md_st */
    	em[43] = 9; em[44] = 0; 
    args_addr->ret_entity_index = 40;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EVP_MD * *new_ret_ptr = (const EVP_MD * *)new_args->ret;

    const EVP_MD * (*orig_EVP_sha256)(void);
    orig_EVP_sha256 = dlsym(RTLD_NEXT, "EVP_sha256");
    *new_ret_ptr = (*orig_EVP_sha256)();

    syscall(889);

    free(args_addr);

    return ret;
}

