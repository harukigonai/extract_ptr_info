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
            0, 0, 0, /* 35: func */
            0, 0, 0, /* 38: func */
            4097, 8, 0, /* 41: pointer.func */
            0, 0, 0, /* 44: struct.unnamed */
            1, 8, 1, /* 47: pointer.struct.unnamed */
            	44, 0,
            0, 0, 0, /* 52: func */
            4097, 8, 0, /* 55: pointer.func */
            4097, 8, 0, /* 58: pointer.func */
            0, 0, 0, /* 61: func */
            4097, 8, 0, /* 64: pointer.func */
            1, 8, 1, /* 67: pointer.struct.store_method_st */
            	72, 0,
            0, 0, 0, /* 72: struct.store_method_st */
            0, 0, 0, /* 75: func */
            4097, 8, 0, /* 78: pointer.func */
            4097, 8, 0, /* 81: pointer.func */
            0, 0, 0, /* 84: func */
            4097, 8, 0, /* 87: pointer.func */
            4097, 8, 0, /* 90: pointer.func */
            0, 48, 6, /* 93: struct.rand_meth_st */
            	90, 0,
            	87, 8,
            	81, 16,
            	78, 24,
            	87, 32,
            	108, 40,
            4097, 8, 0, /* 108: pointer.func */
            0, 0, 0, /* 111: func */
            4097, 8, 0, /* 114: pointer.func */
            0, 32, 0, /* 117: array[32].char */
            4097, 8, 0, /* 120: pointer.func */
            4097, 8, 0, /* 123: pointer.func */
            0, 48, 5, /* 126: struct.ecdsa_method */
            	20, 0,
            	123, 8,
            	120, 16,
            	114, 24,
            	20, 40,
            0, 0, 0, /* 139: func */
            1, 8, 1, /* 142: pointer.struct.ecdsa_method */
            	126, 0,
            4097, 8, 0, /* 147: pointer.func */
            1, 8, 1, /* 150: pointer.struct.ecdh_method */
            	155, 0,
            0, 32, 3, /* 155: struct.ecdh_method */
            	20, 0,
            	147, 8,
            	20, 24,
            0, 0, 0, /* 164: func */
            0, 0, 0, /* 167: func */
            0, 0, 0, /* 170: func */
            0, 0, 0, /* 173: func */
            0, 0, 0, /* 176: func */
            1, 8, 1, /* 179: pointer.struct.rsa_meth_st */
            	184, 0,
            0, 112, 13, /* 184: struct.rsa_meth_st */
            	20, 0,
            	213, 8,
            	213, 16,
            	213, 24,
            	213, 32,
            	216, 40,
            	219, 48,
            	222, 56,
            	222, 64,
            	20, 80,
            	225, 88,
            	228, 96,
            	231, 104,
            4097, 8, 0, /* 213: pointer.func */
            4097, 8, 0, /* 216: pointer.func */
            4097, 8, 0, /* 219: pointer.func */
            4097, 8, 0, /* 222: pointer.func */
            4097, 8, 0, /* 225: pointer.func */
            4097, 8, 0, /* 228: pointer.func */
            4097, 8, 0, /* 231: pointer.func */
            0, 0, 0, /* 234: func */
            1, 8, 1, /* 237: pointer.struct.dh_method */
            	242, 0,
            0, 72, 8, /* 242: struct.dh_method */
            	20, 0,
            	261, 8,
            	264, 16,
            	267, 24,
            	261, 32,
            	261, 40,
            	20, 56,
            	270, 64,
            4097, 8, 0, /* 261: pointer.func */
            4097, 8, 0, /* 264: pointer.func */
            4097, 8, 0, /* 267: pointer.func */
            4097, 8, 0, /* 270: pointer.func */
            0, 0, 0, /* 273: func */
            0, 0, 0, /* 276: func */
            4097, 8, 0, /* 279: pointer.func */
            4097, 8, 0, /* 282: pointer.func */
            4097, 8, 0, /* 285: pointer.func */
            1, 8, 1, /* 288: pointer.struct.evp_cipher_ctx_st */
            	293, 0,
            0, 168, 4, /* 293: struct.evp_cipher_ctx_st */
            	304, 0,
            	338, 8,
            	335, 96,
            	335, 120,
            1, 8, 1, /* 304: pointer.struct.evp_cipher_st */
            	309, 0,
            0, 88, 7, /* 309: struct.evp_cipher_st */
            	326, 24,
            	279, 32,
            	329, 40,
            	332, 56,
            	332, 64,
            	282, 72,
            	335, 80,
            4097, 8, 0, /* 326: pointer.func */
            4097, 8, 0, /* 329: pointer.func */
            4097, 8, 0, /* 332: pointer.func */
            0, 8, 0, /* 335: pointer.void */
            1, 8, 1, /* 338: pointer.struct.engine_st */
            	343, 0,
            0, 216, 24, /* 343: struct.engine_st */
            	20, 0,
            	20, 8,
            	179, 16,
            	394, 24,
            	237, 32,
            	150, 40,
            	142, 48,
            	442, 56,
            	67, 64,
            	447, 72,
            	64, 80,
            	58, 88,
            	55, 96,
            	47, 104,
            	47, 112,
            	47, 120,
            	41, 128,
            	450, 136,
            	450, 144,
            	453, 152,
            	456, 160,
            	25, 184,
            	338, 200,
            	338, 208,
            1, 8, 1, /* 394: pointer.struct.dsa_method */
            	399, 0,
            0, 96, 11, /* 399: struct.dsa_method */
            	20, 0,
            	424, 8,
            	427, 16,
            	430, 24,
            	285, 32,
            	433, 40,
            	436, 48,
            	436, 56,
            	20, 72,
            	439, 80,
            	436, 88,
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            4097, 8, 0, /* 430: pointer.func */
            4097, 8, 0, /* 433: pointer.func */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            1, 8, 1, /* 442: pointer.struct.rand_meth_st */
            	93, 0,
            4097, 8, 0, /* 447: pointer.func */
            4097, 8, 0, /* 450: pointer.func */
            4097, 8, 0, /* 453: pointer.func */
            1, 8, 1, /* 456: pointer.struct.ENGINE_CMD_DEFN_st */
            	461, 0,
            0, 32, 2, /* 461: struct.ENGINE_CMD_DEFN_st */
            	20, 8,
            	20, 16,
            0, 0, 0, /* 468: func */
            0, 0, 0, /* 471: func */
            0, 0, 0, /* 474: func */
            0, 0, 0, /* 477: func */
            0, 0, 0, /* 480: func */
            0, 8, 0, /* 483: long */
            0, 0, 0, /* 486: func */
            0, 0, 0, /* 489: func */
            0, 0, 0, /* 492: func */
            0, 0, 0, /* 495: func */
            0, 0, 0, /* 498: func */
            0, 1, 0, /* 501: char */
            0, 0, 0, /* 504: func */
            0, 0, 0, /* 507: func */
            0, 0, 0, /* 510: func */
            0, 0, 0, /* 513: func */
            0, 16, 0, /* 516: array[16].char */
            0, 0, 0, /* 519: func */
            0, 4, 0, /* 522: int */
            0, 0, 0, /* 525: func */
            0, 0, 0, /* 528: func */
            0, 0, 0, /* 531: func */
            0, 0, 0, /* 534: func */
            0, 0, 0, /* 537: func */
            0, 0, 0, /* 540: func */
            0, 0, 0, /* 543: func */
            0, 0, 0, /* 546: func */
            0, 0, 0, /* 549: func */
        },
        .arg_entity_index = { 288, 304, 338, 20, 20, },
        .ret_entity_index = 522,
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

