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
            4097, 8, 0, /* 0: pointer.func */
            0, 32, 1, /* 3: struct.stack_st_OPENSSL_STRING */
            	8, 0,
            0, 32, 2, /* 8: struct.stack_st */
            	15, 8,
            	0, 24,
            1, 8, 1, /* 15: pointer.pointer.char */
            	20, 0,
            1, 8, 1, /* 20: pointer.char */
            	4096, 0,
            0, 16, 1, /* 25: struct.crypto_ex_data_st */
            	30, 0,
            1, 8, 1, /* 30: pointer.struct.stack_st_OPENSSL_STRING */
            	3, 0,
            0, 32, 2, /* 35: struct.ENGINE_CMD_DEFN_st */
            	20, 8,
            	20, 16,
            4097, 8, 0, /* 42: pointer.func */
            0, 0, 0, /* 45: struct.unnamed */
            1, 8, 1, /* 48: pointer.struct.unnamed */
            	45, 0,
            4097, 8, 0, /* 53: pointer.func */
            4097, 8, 0, /* 56: pointer.func */
            4097, 8, 0, /* 59: pointer.func */
            1, 8, 1, /* 62: pointer.struct.dsa_method */
            	67, 0,
            0, 96, 11, /* 67: struct.dsa_method */
            	20, 0,
            	92, 8,
            	95, 16,
            	98, 24,
            	101, 32,
            	104, 40,
            	107, 48,
            	107, 56,
            	20, 72,
            	110, 80,
            	107, 88,
            4097, 8, 0, /* 92: pointer.func */
            4097, 8, 0, /* 95: pointer.func */
            4097, 8, 0, /* 98: pointer.func */
            4097, 8, 0, /* 101: pointer.func */
            4097, 8, 0, /* 104: pointer.func */
            4097, 8, 0, /* 107: pointer.func */
            4097, 8, 0, /* 110: pointer.func */
            4097, 8, 0, /* 113: pointer.func */
            4097, 8, 0, /* 116: pointer.func */
            0, 112, 13, /* 119: struct.rsa_meth_st */
            	20, 0,
            	148, 8,
            	148, 16,
            	148, 24,
            	148, 32,
            	151, 40,
            	154, 48,
            	157, 56,
            	157, 64,
            	20, 80,
            	160, 88,
            	163, 96,
            	116, 104,
            4097, 8, 0, /* 148: pointer.func */
            4097, 8, 0, /* 151: pointer.func */
            4097, 8, 0, /* 154: pointer.func */
            4097, 8, 0, /* 157: pointer.func */
            4097, 8, 0, /* 160: pointer.func */
            4097, 8, 0, /* 163: pointer.func */
            0, 4, 0, /* 166: int */
            4097, 8, 0, /* 169: pointer.func */
            1, 8, 1, /* 172: pointer.struct.ENGINE_CMD_DEFN_st */
            	35, 0,
            4097, 8, 0, /* 177: pointer.func */
            1, 8, 1, /* 180: pointer.struct.rsa_meth_st */
            	119, 0,
            0, 88, 7, /* 185: struct.evp_cipher_st */
            	202, 24,
            	205, 32,
            	208, 40,
            	211, 56,
            	211, 64,
            	214, 72,
            	20, 80,
            4097, 8, 0, /* 202: pointer.func */
            4097, 8, 0, /* 205: pointer.func */
            4097, 8, 0, /* 208: pointer.func */
            4097, 8, 0, /* 211: pointer.func */
            4097, 8, 0, /* 214: pointer.func */
            1, 8, 1, /* 217: pointer.struct.dh_method */
            	222, 0,
            0, 72, 8, /* 222: struct.dh_method */
            	20, 0,
            	241, 8,
            	244, 16,
            	177, 24,
            	241, 32,
            	241, 40,
            	20, 56,
            	247, 64,
            4097, 8, 0, /* 241: pointer.func */
            4097, 8, 0, /* 244: pointer.func */
            4097, 8, 0, /* 247: pointer.func */
            4097, 8, 0, /* 250: pointer.func */
            4097, 8, 0, /* 253: pointer.func */
            0, 8, 0, /* 256: pointer.void */
            0, 216, 24, /* 259: struct.engine_st */
            	20, 0,
            	20, 8,
            	180, 16,
            	62, 24,
            	217, 32,
            	310, 40,
            	327, 48,
            	348, 56,
            	377, 64,
            	385, 72,
            	388, 80,
            	391, 88,
            	53, 96,
            	48, 104,
            	48, 112,
            	48, 120,
            	42, 128,
            	59, 136,
            	59, 144,
            	253, 152,
            	172, 160,
            	25, 184,
            	394, 200,
            	394, 208,
            1, 8, 1, /* 310: pointer.struct.ecdh_method */
            	315, 0,
            0, 32, 3, /* 315: struct.ecdh_method */
            	20, 0,
            	324, 8,
            	20, 24,
            4097, 8, 0, /* 324: pointer.func */
            1, 8, 1, /* 327: pointer.struct.ecdsa_method */
            	332, 0,
            0, 48, 5, /* 332: struct.ecdsa_method */
            	20, 0,
            	345, 8,
            	113, 16,
            	56, 24,
            	20, 40,
            4097, 8, 0, /* 345: pointer.func */
            1, 8, 1, /* 348: pointer.struct.rand_meth_st */
            	353, 0,
            0, 48, 6, /* 353: struct.rand_meth_st */
            	250, 0,
            	368, 8,
            	371, 16,
            	169, 24,
            	368, 32,
            	374, 40,
            4097, 8, 0, /* 368: pointer.func */
            4097, 8, 0, /* 371: pointer.func */
            4097, 8, 0, /* 374: pointer.func */
            1, 8, 1, /* 377: pointer.struct.store_method_st */
            	382, 0,
            0, 0, 0, /* 382: struct.store_method_st */
            4097, 8, 0, /* 385: pointer.func */
            4097, 8, 0, /* 388: pointer.func */
            4097, 8, 0, /* 391: pointer.func */
            1, 8, 1, /* 394: pointer.struct.engine_st */
            	259, 0,
            1, 8, 1, /* 399: pointer.struct.evp_cipher_st */
            	185, 0,
            0, 1, 0, /* 404: char */
            1, 8, 1, /* 407: pointer.struct.evp_cipher_ctx_st */
            	412, 0,
            0, 168, 4, /* 412: struct.evp_cipher_ctx_st */
            	399, 0,
            	394, 8,
            	20, 96,
            	20, 120,
        },
        .arg_entity_index = { 407, 399, 394, 20, 20, },
        .ret_entity_index = 166,
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

