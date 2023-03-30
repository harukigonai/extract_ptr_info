#define _GNU_SOURCE

#include <stdio.h>
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

const EVP_CIPHER * bb_EVP_aes_256_cbc(void);

const EVP_CIPHER * EVP_aes_256_cbc(void) 
{
    if (syscall(890))
        return bb_EVP_aes_256_cbc();
    else {
        const EVP_CIPHER * (*orig_EVP_aes_256_cbc)(void);
        orig_EVP_aes_256_cbc = dlsym(RTLD_NEXT, "EVP_aes_256_cbc");
        return orig_EVP_aes_256_cbc();
    }
}

const EVP_CIPHER * bb_EVP_aes_256_cbc(void) 
{
    printf("EVP_aes_256_cbc called\n");
    const EVP_CIPHER * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            1, 8, 1, /* 3: pointer.struct.evp_cipher_st.2256 */
            	8, 0,
            0, 88, 7, /* 8: struct.evp_cipher_st.2256 */
            	25, 24,
            	33, 32,
            	41, 40,
            	49, 56,
            	49, 64,
            	57, 72,
            	62, 80,
            1, 8, 1, /* 25: pointer.func */
            	30, 0,
            0, 0, 0, /* 30: func */
            1, 8, 1, /* 33: pointer.func */
            	38, 0,
            0, 0, 0, /* 38: func */
            1, 8, 1, /* 41: pointer.func */
            	46, 0,
            0, 0, 0, /* 46: func */
            1, 8, 1, /* 49: pointer.func */
            	54, 0,
            0, 0, 0, /* 54: func */
            1, 8, 1, /* 57: pointer.func */
            	0, 0,
            1, 8, 1, /* 62: pointer.char */
            	67, 0,
            0, 1, 0, /* 67: char */
            0, 8, 0, /* 70: long */
            0, 4, 0, /* 73: int */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 3,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EVP_CIPHER * *new_ret_ptr = (const EVP_CIPHER * *)new_args->ret;

    const EVP_CIPHER * (*orig_EVP_aes_256_cbc)(void);
    orig_EVP_aes_256_cbc = dlsym(RTLD_NEXT, "EVP_aes_256_cbc");
    *new_ret_ptr = (*orig_EVP_aes_256_cbc)();

    syscall(889);

    return ret;
}

