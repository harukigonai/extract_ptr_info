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

const EVP_CIPHER * EVP_aes_128_cbc(void) 
{
    const EVP_CIPHER * ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            1, 8, 1, /* 3: pointer.struct.evp_cipher_st.2256 */
            	8, 0,
            0, 88, 13, /* 8: struct.evp_cipher_st.2256 */
            	37, 0,
            	37, 4,
            	37, 8,
            	37, 12,
            	40, 16,
            	43, 24,
            	51, 32,
            	59, 40,
            	37, 48,
            	67, 56,
            	67, 64,
            	75, 72,
            	80, 80,
            0, 4, 0, /* 37: int */
            0, 8, 0, /* 40: long */
            1, 8, 1, /* 43: pointer.func */
            	48, 0,
            0, 0, 0, /* 48: func */
            1, 8, 1, /* 51: pointer.func */
            	56, 0,
            0, 0, 0, /* 56: func */
            1, 8, 1, /* 59: pointer.func */
            	64, 0,
            0, 0, 0, /* 64: func */
            1, 8, 1, /* 67: pointer.func */
            	72, 0,
            0, 0, 0, /* 72: func */
            1, 8, 1, /* 75: pointer.func */
            	0, 0,
            1, 8, 1, /* 80: pointer.char */
            	85, 0,
            0, 1, 0, /* 85: char */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 3,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EVP_CIPHER * *new_ret_ptr = (const EVP_CIPHER * *)new_args->ret;

    const EVP_CIPHER * (*orig_EVP_aes_128_cbc)(void);
    orig_EVP_aes_128_cbc = dlsym(RTLD_NEXT, "EVP_aes_128_cbc");
    *new_ret_ptr = (*orig_EVP_aes_128_cbc)();

    syscall(889);

    return ret;
}

