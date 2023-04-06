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
            1, 8, 1, /* 0: pointer.struct.engine_st */
            	5, 0,
            0, 216, 24, /* 5: struct.engine_st */
            	56, 0,
            	56, 8,
            	61, 16,
            	121, 24,
            	172, 32,
            	208, 40,
            	225, 48,
            	252, 56,
            	287, 64,
            	295, 72,
            	298, 80,
            	301, 88,
            	304, 96,
            	307, 104,
            	307, 112,
            	307, 120,
            	310, 128,
            	313, 136,
            	313, 144,
            	316, 152,
            	319, 160,
            	331, 184,
            	0, 200,
            	0, 208,
            1, 8, 1, /* 56: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 61: pointer.struct.rsa_meth_st */
            	66, 0,
            0, 112, 13, /* 66: struct.rsa_meth_st */
            	56, 0,
            	95, 8,
            	95, 16,
            	95, 24,
            	95, 32,
            	98, 40,
            	101, 48,
            	104, 56,
            	104, 64,
            	107, 80,
            	112, 88,
            	115, 96,
            	118, 104,
            8884097, 8, 0, /* 95: pointer.func */
            8884097, 8, 0, /* 98: pointer.func */
            8884097, 8, 0, /* 101: pointer.func */
            8884097, 8, 0, /* 104: pointer.func */
            1, 8, 1, /* 107: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 112: pointer.func */
            8884097, 8, 0, /* 115: pointer.func */
            8884097, 8, 0, /* 118: pointer.func */
            1, 8, 1, /* 121: pointer.struct.dsa_method */
            	126, 0,
            0, 96, 11, /* 126: struct.dsa_method */
            	56, 0,
            	151, 8,
            	154, 16,
            	157, 24,
            	160, 32,
            	163, 40,
            	166, 48,
            	166, 56,
            	107, 72,
            	169, 80,
            	166, 88,
            8884097, 8, 0, /* 151: pointer.func */
            8884097, 8, 0, /* 154: pointer.func */
            8884097, 8, 0, /* 157: pointer.func */
            8884097, 8, 0, /* 160: pointer.func */
            8884097, 8, 0, /* 163: pointer.func */
            8884097, 8, 0, /* 166: pointer.func */
            8884097, 8, 0, /* 169: pointer.func */
            1, 8, 1, /* 172: pointer.struct.dh_method */
            	177, 0,
            0, 72, 8, /* 177: struct.dh_method */
            	56, 0,
            	196, 8,
            	199, 16,
            	202, 24,
            	196, 32,
            	196, 40,
            	107, 56,
            	205, 64,
            8884097, 8, 0, /* 196: pointer.func */
            8884097, 8, 0, /* 199: pointer.func */
            8884097, 8, 0, /* 202: pointer.func */
            8884097, 8, 0, /* 205: pointer.func */
            1, 8, 1, /* 208: pointer.struct.ecdh_method */
            	213, 0,
            0, 32, 3, /* 213: struct.ecdh_method */
            	56, 0,
            	222, 8,
            	107, 24,
            8884097, 8, 0, /* 222: pointer.func */
            1, 8, 1, /* 225: pointer.struct.ecdsa_method */
            	230, 0,
            0, 48, 5, /* 230: struct.ecdsa_method */
            	56, 0,
            	243, 8,
            	246, 16,
            	249, 24,
            	107, 40,
            8884097, 8, 0, /* 243: pointer.func */
            8884097, 8, 0, /* 246: pointer.func */
            8884097, 8, 0, /* 249: pointer.func */
            1, 8, 1, /* 252: pointer.struct.rand_meth_st */
            	257, 0,
            0, 48, 6, /* 257: struct.rand_meth_st */
            	272, 0,
            	275, 8,
            	278, 16,
            	281, 24,
            	275, 32,
            	284, 40,
            8884097, 8, 0, /* 272: pointer.func */
            8884097, 8, 0, /* 275: pointer.func */
            8884097, 8, 0, /* 278: pointer.func */
            8884097, 8, 0, /* 281: pointer.func */
            8884097, 8, 0, /* 284: pointer.func */
            1, 8, 1, /* 287: pointer.struct.store_method_st */
            	292, 0,
            0, 0, 0, /* 292: struct.store_method_st */
            8884097, 8, 0, /* 295: pointer.func */
            8884097, 8, 0, /* 298: pointer.func */
            8884097, 8, 0, /* 301: pointer.func */
            8884097, 8, 0, /* 304: pointer.func */
            8884097, 8, 0, /* 307: pointer.func */
            8884097, 8, 0, /* 310: pointer.func */
            8884097, 8, 0, /* 313: pointer.func */
            8884097, 8, 0, /* 316: pointer.func */
            1, 8, 1, /* 319: pointer.struct.ENGINE_CMD_DEFN_st */
            	324, 0,
            0, 32, 2, /* 324: struct.ENGINE_CMD_DEFN_st */
            	56, 8,
            	56, 16,
            0, 16, 1, /* 331: struct.crypto_ex_data_st */
            	336, 0,
            1, 8, 1, /* 336: pointer.struct.stack_st_void */
            	341, 0,
            0, 32, 1, /* 341: struct.stack_st_void */
            	346, 0,
            0, 32, 2, /* 346: struct.stack_st */
            	353, 8,
            	358, 24,
            1, 8, 1, /* 353: pointer.pointer.char */
            	107, 0,
            8884097, 8, 0, /* 358: pointer.func */
            1, 8, 1, /* 361: pointer.struct.engine_st */
            	5, 0,
            0, 1, 0, /* 366: unsigned char */
            1, 8, 1, /* 369: pointer.struct.evp_cipher_st */
            	374, 0,
            0, 88, 7, /* 374: struct.evp_cipher_st */
            	391, 24,
            	394, 32,
            	397, 40,
            	400, 56,
            	400, 64,
            	403, 72,
            	406, 80,
            8884097, 8, 0, /* 391: pointer.func */
            8884097, 8, 0, /* 394: pointer.func */
            8884097, 8, 0, /* 397: pointer.func */
            8884097, 8, 0, /* 400: pointer.func */
            8884097, 8, 0, /* 403: pointer.func */
            0, 8, 0, /* 406: pointer.void */
            0, 1, 0, /* 409: char */
            0, 4, 0, /* 412: int */
            1, 8, 1, /* 415: pointer.unsigned char */
            	366, 0,
            1, 8, 1, /* 420: pointer.struct.evp_cipher_ctx_st */
            	425, 0,
            0, 168, 4, /* 425: struct.evp_cipher_ctx_st */
            	369, 0,
            	361, 8,
            	406, 96,
            	406, 120,
        },
        .arg_entity_index = { 420, 369, 361, 415, 415, },
        .ret_entity_index = 412,
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

