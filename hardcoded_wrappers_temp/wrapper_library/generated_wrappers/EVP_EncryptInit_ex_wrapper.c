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

int bb_EVP_EncryptInit_ex(EVP_CIPHER_CTX * arg_a,const EVP_CIPHER * arg_b,ENGINE * arg_c,const unsigned char * arg_d,const unsigned char * arg_e);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX * arg_a,const EVP_CIPHER * arg_b,ENGINE * arg_c,const unsigned char * arg_d,const unsigned char * arg_e) 
{
    printf("EVP_EncryptInit_ex called\n");
    if (!syscall(890))
        return bb_EVP_EncryptInit_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    else {
        int (*orig_EVP_EncryptInit_ex)(EVP_CIPHER_CTX *,const EVP_CIPHER *,ENGINE *,const unsigned char *,const unsigned char *);
        orig_EVP_EncryptInit_ex = dlsym(RTLD_NEXT, "EVP_EncryptInit_ex");
        return orig_EVP_EncryptInit_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    }
}

int bb_EVP_EncryptInit_ex(EVP_CIPHER_CTX * arg_a,const EVP_CIPHER * arg_b,ENGINE * arg_c,const unsigned char * arg_d,const unsigned char * arg_e) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 32, 1, /* 3: struct.stack_st_OPENSSL_STRING */
            	8, 0,
            0, 32, 1, /* 8: struct.stack_st */
            	13, 8,
            1, 8, 1, /* 13: pointer.pointer.char */
            	18, 0,
            1, 8, 1, /* 18: pointer.char */
            	23, 0,
            0, 1, 0, /* 23: char */
            1, 8, 1, /* 26: pointer.struct.ENGINE_CMD_DEFN_st */
            	31, 0,
            0, 32, 2, /* 31: struct.ENGINE_CMD_DEFN_st */
            	18, 8,
            	18, 16,
            0, 0, 0, /* 38: func */
            0, 0, 0, /* 41: func */
            0, 8, 0, /* 44: pointer.func */
            0, 0, 0, /* 47: struct.unnamed */
            0, 0, 0, /* 50: func */
            0, 8, 0, /* 53: pointer.func */
            0, 0, 0, /* 56: func */
            0, 8, 0, /* 59: pointer.func */
            0, 8, 0, /* 62: pointer.func */
            0, 0, 0, /* 65: func */
            0, 0, 0, /* 68: func */
            0, 8, 0, /* 71: pointer.func */
            0, 0, 0, /* 74: func */
            0, 8, 0, /* 77: pointer.func */
            0, 8, 0, /* 80: pointer.func */
            0, 0, 0, /* 83: func */
            0, 0, 0, /* 86: func */
            0, 8, 0, /* 89: pointer.func */
            1, 8, 1, /* 92: pointer.struct.rand_meth_st */
            	97, 0,
            0, 48, 0, /* 97: struct.rand_meth_st */
            0, 0, 0, /* 100: func */
            0, 0, 0, /* 103: func */
            0, 8, 0, /* 106: pointer.func */
            0, 48, 2, /* 109: struct.ecdsa_method */
            	18, 0,
            	18, 40,
            1, 8, 1, /* 116: pointer.struct.ecdsa_method */
            	109, 0,
            0, 32, 2, /* 121: struct.ecdh_method */
            	18, 0,
            	18, 24,
            1, 8, 1, /* 128: pointer.struct.ecdh_method */
            	121, 0,
            0, 8, 0, /* 133: pointer.func */
            0, 112, 2, /* 136: struct.rsa_meth_st.1132 */
            	18, 0,
            	18, 80,
            0, 0, 0, /* 143: func */
            0, 8, 0, /* 146: pointer.func */
            1, 8, 1, /* 149: pointer.struct.rsa_meth_st.1132 */
            	136, 0,
            0, 4, 0, /* 154: int */
            0, 8, 0, /* 157: pointer.func */
            0, 0, 0, /* 160: func */
            0, 216, 16, /* 163: struct.engine_st.1173 */
            	18, 0,
            	18, 8,
            	149, 16,
            	198, 24,
            	210, 32,
            	128, 40,
            	116, 48,
            	92, 56,
            	222, 64,
            	230, 104,
            	230, 112,
            	230, 120,
            	26, 160,
            	235, 184,
            	245, 200,
            	245, 208,
            1, 8, 1, /* 198: pointer.struct.dsa_method.1135 */
            	203, 0,
            0, 96, 2, /* 203: struct.dsa_method.1135 */
            	18, 0,
            	18, 72,
            1, 8, 1, /* 210: pointer.struct.dh_method.1137 */
            	215, 0,
            0, 72, 2, /* 215: struct.dh_method.1137 */
            	18, 0,
            	18, 56,
            1, 8, 1, /* 222: pointer.struct.store_method_st */
            	227, 0,
            0, 0, 0, /* 227: struct.store_method_st */
            1, 8, 1, /* 230: pointer.struct.unnamed */
            	47, 0,
            0, 16, 1, /* 235: struct.crypto_ex_data_st */
            	240, 0,
            1, 8, 1, /* 240: pointer.struct.stack_st_OPENSSL_STRING */
            	3, 0,
            1, 8, 1, /* 245: pointer.struct.engine_st.1173 */
            	163, 0,
            0, 0, 0, /* 250: func */
            0, 0, 0, /* 253: func */
            0, 8, 0, /* 256: pointer.func */
            0, 8, 0, /* 259: pointer.func */
            0, 0, 0, /* 262: func */
            0, 8, 0, /* 265: pointer.func */
            0, 0, 0, /* 268: func */
            0, 8, 0, /* 271: pointer.func */
            0, 0, 0, /* 274: func */
            0, 0, 0, /* 277: func */
            0, 8, 0, /* 280: pointer.func */
            1, 8, 1, /* 283: pointer.struct.evp_cipher_ctx_st.2258 */
            	288, 0,
            0, 168, 4, /* 288: struct.evp_cipher_ctx_st.2258 */
            	299, 0,
            	245, 8,
            	18, 96,
            	18, 120,
            1, 8, 1, /* 299: pointer.struct.evp_cipher_st.2256 */
            	304, 0,
            0, 88, 1, /* 304: struct.evp_cipher_st.2256 */
            	18, 80,
            0, 0, 0, /* 309: func */
            0, 8, 0, /* 312: pointer.func */
            0, 8, 0, /* 315: pointer.func */
            0, 0, 0, /* 318: func */
            0, 32, 0, /* 321: array[32].char */
            0, 8, 0, /* 324: pointer.func */
            0, 0, 0, /* 327: func */
            0, 8, 0, /* 330: pointer.func */
            0, 8, 0, /* 333: pointer.func */
            0, 0, 0, /* 336: func */
            0, 0, 0, /* 339: func */
            0, 8, 0, /* 342: long */
            0, 8, 0, /* 345: pointer.func */
            0, 8, 0, /* 348: pointer.func */
            0, 8, 0, /* 351: pointer.func */
            0, 8, 0, /* 354: pointer.func */
            0, 8, 0, /* 357: pointer.func */
            0, 8, 0, /* 360: pointer.func */
            0, 0, 0, /* 363: func */
            0, 0, 0, /* 366: func */
            0, 8, 0, /* 369: pointer.func */
            0, 0, 0, /* 372: func */
            0, 0, 0, /* 375: func */
            0, 0, 0, /* 378: func */
            0, 0, 0, /* 381: func */
            0, 8, 0, /* 384: pointer.func */
            0, 8, 0, /* 387: pointer.func */
            0, 8, 0, /* 390: pointer.func */
            0, 0, 0, /* 393: func */
            0, 8, 0, /* 396: pointer.func */
            0, 8, 0, /* 399: pointer.func */
            0, 8, 0, /* 402: pointer.func */
            0, 8, 0, /* 405: pointer.func */
            0, 0, 0, /* 408: func */
            0, 0, 0, /* 411: func */
            0, 8, 0, /* 414: pointer.func */
            0, 16, 0, /* 417: array[16].char */
            0, 0, 0, /* 420: func */
            0, 0, 0, /* 423: func */
            0, 8, 0, /* 426: pointer.func */
            0, 8, 0, /* 429: pointer.func */
            0, 0, 0, /* 432: func */
            0, 0, 0, /* 435: func */
            0, 0, 0, /* 438: func */
            0, 8, 0, /* 441: pointer.func */
            0, 0, 0, /* 444: func */
        },
        .arg_entity_index = { 283, 299, 245, 18, 18, },
        .ret_entity_index = 154,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_arg(args_addr, arg_e);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_CIPHER_CTX * new_arg_a = *((EVP_CIPHER_CTX * *)new_args->args[0]);

    const EVP_CIPHER * new_arg_b = *((const EVP_CIPHER * *)new_args->args[1]);

    ENGINE * new_arg_c = *((ENGINE * *)new_args->args[2]);

    const unsigned char * new_arg_d = *((const unsigned char * *)new_args->args[3]);

    const unsigned char * new_arg_e = *((const unsigned char * *)new_args->args[4]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_EncryptInit_ex)(EVP_CIPHER_CTX *,const EVP_CIPHER *,ENGINE *,const unsigned char *,const unsigned char *);
    orig_EVP_EncryptInit_ex = dlsym(RTLD_NEXT, "EVP_EncryptInit_ex");
    *new_ret_ptr = (*orig_EVP_EncryptInit_ex)(new_arg_a,new_arg_b,new_arg_c,new_arg_d,new_arg_e);

    syscall(889);

    return ret;
}

