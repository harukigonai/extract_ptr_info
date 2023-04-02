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
            0, 8, 0, /* 0: pointer.void */
            4097, 8, 0, /* 3: pointer.func */
            0, 32, 1, /* 6: struct.stack_st_OPENSSL_STRING */
            	11, 0,
            0, 32, 2, /* 11: struct.stack_st */
            	18, 8,
            	3, 24,
            0, 8, 1, /* 18: pointer.pointer.char */
            	23, 0,
            0, 8, 1, /* 23: pointer.char */
            	4096, 0,
            0, 16, 1, /* 28: struct.crypto_ex_data_st */
            	33, 0,
            0, 8, 1, /* 33: pointer.struct.stack_st_OPENSSL_STRING */
            	6, 0,
            0, 0, 0, /* 38: func */
            0, 0, 0, /* 41: func */
            4097, 8, 0, /* 44: pointer.func */
            0, 0, 0, /* 47: struct.unnamed */
            0, 8, 1, /* 50: pointer.struct.unnamed */
            	47, 0,
            0, 0, 0, /* 55: func */
            4097, 8, 0, /* 58: pointer.func */
            4097, 8, 0, /* 61: pointer.func */
            0, 0, 0, /* 64: func */
            4097, 8, 0, /* 67: pointer.func */
            0, 8, 1, /* 70: pointer.struct.store_method_st */
            	75, 0,
            0, 0, 0, /* 75: struct.store_method_st */
            0, 0, 0, /* 78: func */
            4097, 8, 0, /* 81: pointer.func */
            4097, 8, 0, /* 84: pointer.func */
            0, 0, 0, /* 87: func */
            4097, 8, 0, /* 90: pointer.func */
            4097, 8, 0, /* 93: pointer.func */
            0, 48, 6, /* 96: struct.rand_meth_st */
            	93, 0,
            	90, 8,
            	84, 16,
            	81, 24,
            	90, 32,
            	111, 40,
            4097, 8, 0, /* 111: pointer.func */
            0, 0, 0, /* 114: func */
            4097, 8, 0, /* 117: pointer.func */
            0, 32, 0, /* 120: array[32].char */
            4097, 8, 0, /* 123: pointer.func */
            4097, 8, 0, /* 126: pointer.func */
            0, 48, 5, /* 129: struct.ecdsa_method */
            	23, 0,
            	126, 8,
            	123, 16,
            	117, 24,
            	23, 40,
            0, 0, 0, /* 142: func */
            0, 8, 1, /* 145: pointer.struct.ecdsa_method */
            	129, 0,
            4097, 8, 0, /* 150: pointer.func */
            0, 8, 1, /* 153: pointer.struct.ecdh_method */
            	158, 0,
            0, 32, 3, /* 158: struct.ecdh_method */
            	23, 0,
            	150, 8,
            	23, 24,
            0, 0, 0, /* 167: func */
            0, 0, 0, /* 170: func */
            0, 0, 0, /* 173: func */
            0, 0, 0, /* 176: func */
            0, 0, 0, /* 179: func */
            0, 8, 1, /* 182: pointer.struct.rsa_meth_st */
            	187, 0,
            0, 112, 13, /* 187: struct.rsa_meth_st */
            	23, 0,
            	216, 8,
            	216, 16,
            	216, 24,
            	216, 32,
            	219, 40,
            	222, 48,
            	225, 56,
            	225, 64,
            	23, 80,
            	228, 88,
            	231, 96,
            	234, 104,
            4097, 8, 0, /* 216: pointer.func */
            4097, 8, 0, /* 219: pointer.func */
            4097, 8, 0, /* 222: pointer.func */
            4097, 8, 0, /* 225: pointer.func */
            4097, 8, 0, /* 228: pointer.func */
            4097, 8, 0, /* 231: pointer.func */
            4097, 8, 0, /* 234: pointer.func */
            0, 0, 0, /* 237: func */
            0, 8, 1, /* 240: pointer.struct.dh_method */
            	245, 0,
            0, 72, 8, /* 245: struct.dh_method */
            	23, 0,
            	264, 8,
            	267, 16,
            	270, 24,
            	264, 32,
            	264, 40,
            	23, 56,
            	273, 64,
            4097, 8, 0, /* 264: pointer.func */
            4097, 8, 0, /* 267: pointer.func */
            4097, 8, 0, /* 270: pointer.func */
            4097, 8, 0, /* 273: pointer.func */
            0, 0, 0, /* 276: func */
            0, 0, 0, /* 279: func */
            4097, 8, 0, /* 282: pointer.func */
            4097, 8, 0, /* 285: pointer.func */
            4097, 8, 0, /* 288: pointer.func */
            0, 8, 1, /* 291: pointer.struct.evp_cipher_ctx_st */
            	296, 0,
            0, 168, 4, /* 296: struct.evp_cipher_ctx_st */
            	307, 0,
            	338, 8,
            	0, 96,
            	0, 120,
            0, 8, 1, /* 307: pointer.struct.evp_cipher_st */
            	312, 0,
            0, 88, 7, /* 312: struct.evp_cipher_st */
            	329, 24,
            	282, 32,
            	332, 40,
            	335, 56,
            	335, 64,
            	285, 72,
            	0, 80,
            4097, 8, 0, /* 329: pointer.func */
            4097, 8, 0, /* 332: pointer.func */
            4097, 8, 0, /* 335: pointer.func */
            0, 8, 1, /* 338: pointer.struct.engine_st */
            	343, 0,
            0, 216, 24, /* 343: struct.engine_st */
            	23, 0,
            	23, 8,
            	182, 16,
            	394, 24,
            	240, 32,
            	153, 40,
            	145, 48,
            	442, 56,
            	70, 64,
            	447, 72,
            	67, 80,
            	61, 88,
            	58, 96,
            	50, 104,
            	50, 112,
            	50, 120,
            	44, 128,
            	450, 136,
            	450, 144,
            	453, 152,
            	456, 160,
            	28, 184,
            	338, 200,
            	338, 208,
            0, 8, 1, /* 394: pointer.struct.dsa_method */
            	399, 0,
            0, 96, 11, /* 399: struct.dsa_method */
            	23, 0,
            	424, 8,
            	427, 16,
            	430, 24,
            	288, 32,
            	433, 40,
            	436, 48,
            	436, 56,
            	23, 72,
            	439, 80,
            	436, 88,
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            4097, 8, 0, /* 430: pointer.func */
            4097, 8, 0, /* 433: pointer.func */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            0, 8, 1, /* 442: pointer.struct.rand_meth_st */
            	96, 0,
            4097, 8, 0, /* 447: pointer.func */
            4097, 8, 0, /* 450: pointer.func */
            4097, 8, 0, /* 453: pointer.func */
            0, 8, 1, /* 456: pointer.struct.ENGINE_CMD_DEFN_st */
            	461, 0,
            0, 32, 2, /* 461: struct.ENGINE_CMD_DEFN_st */
            	23, 8,
            	23, 16,
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
        .arg_entity_index = { 291, 307, 338, 23, 23, },
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

