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
    unsigned long in_lib = syscall(890);
    printf("EVP_EncryptInit_ex called %lu\n", in_lib);
    if (!in_lib)
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
            1, 8, 1, /* 0: pointer.struct.ENGINE_CMD_DEFN_st */
            	5, 0,
            0, 32, 2, /* 5: struct.ENGINE_CMD_DEFN_st */
            	12, 8,
            	12, 16,
            1, 8, 1, /* 12: pointer.char */
            	4096, 0,
            0, 0, 0, /* 17: func */
            0, 0, 0, /* 20: func */
            4097, 8, 0, /* 23: pointer.func */
            0, 0, 0, /* 26: func */
            4097, 8, 0, /* 29: pointer.func */
            0, 0, 0, /* 32: struct.unnamed */
            4097, 8, 0, /* 35: pointer.func */
            0, 0, 0, /* 38: struct.store_method_st */
            1, 8, 1, /* 41: pointer.struct.store_method_st */
            	38, 0,
            0, 0, 0, /* 46: func */
            4097, 8, 0, /* 49: pointer.func */
            0, 32, 0, /* 52: array[32].char */
            0, 0, 0, /* 55: func */
            1, 8, 1, /* 58: pointer.struct.rand_meth_st */
            	63, 0,
            0, 48, 0, /* 63: struct.rand_meth_st */
            0, 0, 0, /* 66: func */
            4097, 8, 0, /* 69: pointer.func */
            0, 0, 0, /* 72: func */
            4097, 8, 0, /* 75: pointer.func */
            0, 0, 0, /* 78: func */
            4097, 8, 0, /* 81: pointer.func */
            0, 48, 2, /* 84: struct.ecdsa_method */
            	12, 0,
            	12, 40,
            1, 8, 1, /* 91: pointer.struct.ecdsa_method */
            	84, 0,
            4097, 8, 0, /* 96: pointer.func */
            0, 0, 0, /* 99: func */
            1, 8, 1, /* 102: pointer.struct.ecdh_method */
            	107, 0,
            0, 32, 2, /* 107: struct.ecdh_method */
            	12, 0,
            	12, 24,
            4097, 8, 0, /* 114: pointer.func */
            0, 0, 0, /* 117: func */
            4097, 8, 0, /* 120: pointer.func */
            1, 8, 1, /* 123: pointer.struct.rsa_meth_st.1132 */
            	128, 0,
            0, 112, 2, /* 128: struct.rsa_meth_st.1132 */
            	12, 0,
            	12, 80,
            4097, 8, 0, /* 135: pointer.func */
            1, 8, 1, /* 138: pointer.struct.unnamed */
            	32, 0,
            0, 0, 0, /* 143: func */
            4097, 8, 0, /* 146: pointer.func */
            4097, 8, 0, /* 149: pointer.func */
            0, 0, 0, /* 152: func */
            0, 0, 0, /* 155: func */
            0, 32, 1, /* 158: struct.stack_st */
            	163, 8,
            1, 8, 1, /* 163: pointer.pointer.char */
            	12, 0,
            4097, 8, 0, /* 168: pointer.func */
            4097, 8, 0, /* 171: pointer.func */
            4097, 8, 0, /* 174: pointer.func */
            0, 16, 1, /* 177: struct.crypto_ex_data_st */
            	182, 0,
            1, 8, 1, /* 182: pointer.struct.stack_st_OPENSSL_STRING */
            	187, 0,
            0, 32, 1, /* 187: struct.stack_st_OPENSSL_STRING */
            	158, 0,
            0, 0, 0, /* 192: func */
            0, 0, 0, /* 195: func */
            4097, 8, 0, /* 198: pointer.func */
            0, 0, 0, /* 201: func */
            0, 4, 0, /* 204: int */
            0, 0, 0, /* 207: func */
            1, 8, 1, /* 210: pointer.struct.evp_cipher_ctx_st.2258 */
            	215, 0,
            0, 168, 4, /* 215: struct.evp_cipher_ctx_st.2258 */
            	226, 0,
            	236, 8,
            	12, 96,
            	12, 120,
            1, 8, 1, /* 226: pointer.struct.evp_cipher_st.2256 */
            	231, 0,
            0, 88, 1, /* 231: struct.evp_cipher_st.2256 */
            	12, 80,
            1, 8, 1, /* 236: pointer.struct.engine_st.1173 */
            	241, 0,
            0, 216, 16, /* 241: struct.engine_st.1173 */
            	12, 0,
            	12, 8,
            	123, 16,
            	276, 24,
            	288, 32,
            	102, 40,
            	91, 48,
            	58, 56,
            	41, 64,
            	138, 104,
            	138, 112,
            	138, 120,
            	0, 160,
            	177, 184,
            	236, 200,
            	236, 208,
            1, 8, 1, /* 276: pointer.struct.dsa_method.1135 */
            	281, 0,
            0, 96, 2, /* 281: struct.dsa_method.1135 */
            	12, 0,
            	12, 72,
            1, 8, 1, /* 288: pointer.struct.dh_method.1137 */
            	293, 0,
            0, 72, 2, /* 293: struct.dh_method.1137 */
            	12, 0,
            	12, 56,
            4097, 8, 0, /* 300: pointer.func */
            0, 0, 0, /* 303: func */
            4097, 8, 0, /* 306: pointer.func */
            0, 0, 0, /* 309: func */
            4097, 8, 0, /* 312: pointer.func */
            0, 0, 0, /* 315: func */
            0, 0, 0, /* 318: func */
            4097, 8, 0, /* 321: pointer.func */
            0, 0, 0, /* 324: func */
            4097, 8, 0, /* 327: pointer.func */
            4097, 8, 0, /* 330: pointer.func */
            4097, 8, 0, /* 333: pointer.func */
            4097, 8, 0, /* 336: pointer.func */
            0, 0, 0, /* 339: func */
            0, 0, 0, /* 342: func */
            0, 0, 0, /* 345: func */
            0, 0, 0, /* 348: func */
            4097, 8, 0, /* 351: pointer.func */
            0, 0, 0, /* 354: func */
            0, 1, 0, /* 357: char */
            0, 0, 0, /* 360: func */
            0, 8, 0, /* 363: long */
            0, 16, 0, /* 366: array[16].char */
            4097, 8, 0, /* 369: pointer.func */
            0, 0, 0, /* 372: func */
            4097, 8, 0, /* 375: pointer.func */
            4097, 8, 0, /* 378: pointer.func */
            4097, 8, 0, /* 381: pointer.func */
            4097, 8, 0, /* 384: pointer.func */
            0, 0, 0, /* 387: func */
            0, 0, 0, /* 390: func */
            0, 0, 0, /* 393: func */
            4097, 8, 0, /* 396: pointer.func */
            0, 0, 0, /* 399: func */
            4097, 8, 0, /* 402: pointer.func */
            4097, 8, 0, /* 405: pointer.func */
            0, 0, 0, /* 408: func */
            0, 0, 0, /* 411: func */
            4097, 8, 0, /* 414: pointer.func */
            0, 0, 0, /* 417: func */
            4097, 8, 0, /* 420: pointer.func */
            4097, 8, 0, /* 423: pointer.func */
            4097, 8, 0, /* 426: pointer.func */
            0, 0, 0, /* 429: func */
            0, 0, 0, /* 432: func */
            4097, 8, 0, /* 435: pointer.func */
            0, 0, 0, /* 438: func */
            4097, 8, 0, /* 441: pointer.func */
            0, 0, 0, /* 444: func */
        },
        .arg_entity_index = { 210, 226, 236, 12, 12, },
        .ret_entity_index = 204,
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

