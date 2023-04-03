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

int bb_EVP_PKEY_size(EVP_PKEY * arg_a);

int EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_size called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_PKEY_size(arg_a);
    else {
        int (*orig_EVP_PKEY_size)(EVP_PKEY *);
        orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
        return orig_EVP_PKEY_size(arg_a);
    }
}

int bb_EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 0, /* 0: pointer.void */
            0, 8, 1, /* 3: struct.fnames */
            	8, 0,
            1, 8, 1, /* 8: pointer.char */
            	4096, 0,
            0, 32, 2, /* 13: struct.stack_st */
            	20, 8,
            	25, 24,
            1, 8, 1, /* 20: pointer.pointer.char */
            	8, 0,
            4097, 8, 0, /* 25: pointer.func */
            0, 0, 0, /* 28: func */
            1, 8, 1, /* 31: pointer.struct.ENGINE_CMD_DEFN_st */
            	36, 0,
            0, 32, 2, /* 36: struct.ENGINE_CMD_DEFN_st */
            	8, 8,
            	8, 16,
            1, 8, 1, /* 43: pointer.struct.evp_pkey_st */
            	48, 0,
            0, 56, 4, /* 48: struct.evp_pkey_st */
            	59, 16,
            	157, 24,
            	3, 32,
            	471, 48,
            1, 8, 1, /* 59: pointer.struct.evp_pkey_asn1_method_st */
            	64, 0,
            0, 208, 24, /* 64: struct.evp_pkey_asn1_method_st */
            	8, 16,
            	8, 24,
            	115, 32,
            	118, 40,
            	121, 48,
            	124, 56,
            	127, 64,
            	130, 72,
            	124, 80,
            	133, 88,
            	133, 96,
            	136, 104,
            	139, 112,
            	133, 120,
            	121, 128,
            	121, 136,
            	124, 144,
            	142, 152,
            	145, 160,
            	148, 168,
            	136, 176,
            	139, 184,
            	151, 192,
            	154, 200,
            4097, 8, 0, /* 115: pointer.func */
            4097, 8, 0, /* 118: pointer.func */
            4097, 8, 0, /* 121: pointer.func */
            4097, 8, 0, /* 124: pointer.func */
            4097, 8, 0, /* 127: pointer.func */
            4097, 8, 0, /* 130: pointer.func */
            4097, 8, 0, /* 133: pointer.func */
            4097, 8, 0, /* 136: pointer.func */
            4097, 8, 0, /* 139: pointer.func */
            4097, 8, 0, /* 142: pointer.func */
            4097, 8, 0, /* 145: pointer.func */
            4097, 8, 0, /* 148: pointer.func */
            4097, 8, 0, /* 151: pointer.func */
            4097, 8, 0, /* 154: pointer.func */
            1, 8, 1, /* 157: pointer.struct.engine_st */
            	162, 0,
            0, 216, 24, /* 162: struct.engine_st */
            	8, 0,
            	8, 8,
            	213, 16,
            	268, 24,
            	319, 32,
            	355, 40,
            	372, 48,
            	399, 56,
            	434, 64,
            	442, 72,
            	445, 80,
            	448, 88,
            	451, 96,
            	454, 104,
            	454, 112,
            	454, 120,
            	457, 128,
            	460, 136,
            	460, 144,
            	463, 152,
            	31, 160,
            	466, 184,
            	157, 200,
            	157, 208,
            1, 8, 1, /* 213: pointer.struct.rsa_meth_st */
            	218, 0,
            0, 112, 13, /* 218: struct.rsa_meth_st */
            	8, 0,
            	247, 8,
            	247, 16,
            	247, 24,
            	247, 32,
            	250, 40,
            	253, 48,
            	256, 56,
            	256, 64,
            	8, 80,
            	259, 88,
            	262, 96,
            	265, 104,
            4097, 8, 0, /* 247: pointer.func */
            4097, 8, 0, /* 250: pointer.func */
            4097, 8, 0, /* 253: pointer.func */
            4097, 8, 0, /* 256: pointer.func */
            4097, 8, 0, /* 259: pointer.func */
            4097, 8, 0, /* 262: pointer.func */
            4097, 8, 0, /* 265: pointer.func */
            1, 8, 1, /* 268: pointer.struct.dsa_method */
            	273, 0,
            0, 96, 11, /* 273: struct.dsa_method */
            	8, 0,
            	298, 8,
            	301, 16,
            	304, 24,
            	307, 32,
            	310, 40,
            	313, 48,
            	313, 56,
            	8, 72,
            	316, 80,
            	313, 88,
            4097, 8, 0, /* 298: pointer.func */
            4097, 8, 0, /* 301: pointer.func */
            4097, 8, 0, /* 304: pointer.func */
            4097, 8, 0, /* 307: pointer.func */
            4097, 8, 0, /* 310: pointer.func */
            4097, 8, 0, /* 313: pointer.func */
            4097, 8, 0, /* 316: pointer.func */
            1, 8, 1, /* 319: pointer.struct.dh_method */
            	324, 0,
            0, 72, 8, /* 324: struct.dh_method */
            	8, 0,
            	343, 8,
            	346, 16,
            	349, 24,
            	343, 32,
            	343, 40,
            	8, 56,
            	352, 64,
            4097, 8, 0, /* 343: pointer.func */
            4097, 8, 0, /* 346: pointer.func */
            4097, 8, 0, /* 349: pointer.func */
            4097, 8, 0, /* 352: pointer.func */
            1, 8, 1, /* 355: pointer.struct.ecdh_method */
            	360, 0,
            0, 32, 3, /* 360: struct.ecdh_method */
            	8, 0,
            	369, 8,
            	8, 24,
            4097, 8, 0, /* 369: pointer.func */
            1, 8, 1, /* 372: pointer.struct.ecdsa_method */
            	377, 0,
            0, 48, 5, /* 377: struct.ecdsa_method */
            	8, 0,
            	390, 8,
            	393, 16,
            	396, 24,
            	8, 40,
            4097, 8, 0, /* 390: pointer.func */
            4097, 8, 0, /* 393: pointer.func */
            4097, 8, 0, /* 396: pointer.func */
            1, 8, 1, /* 399: pointer.struct.rand_meth_st */
            	404, 0,
            0, 48, 6, /* 404: struct.rand_meth_st */
            	419, 0,
            	422, 8,
            	425, 16,
            	428, 24,
            	422, 32,
            	431, 40,
            4097, 8, 0, /* 419: pointer.func */
            4097, 8, 0, /* 422: pointer.func */
            4097, 8, 0, /* 425: pointer.func */
            4097, 8, 0, /* 428: pointer.func */
            4097, 8, 0, /* 431: pointer.func */
            1, 8, 1, /* 434: pointer.struct.store_method_st */
            	439, 0,
            0, 0, 0, /* 439: struct.store_method_st */
            4097, 8, 0, /* 442: pointer.func */
            4097, 8, 0, /* 445: pointer.func */
            4097, 8, 0, /* 448: pointer.func */
            4097, 8, 0, /* 451: pointer.func */
            4097, 8, 0, /* 454: pointer.func */
            4097, 8, 0, /* 457: pointer.func */
            4097, 8, 0, /* 460: pointer.func */
            4097, 8, 0, /* 463: pointer.func */
            0, 16, 1, /* 466: struct.crypto_ex_data_st */
            	471, 0,
            1, 8, 1, /* 471: pointer.struct.stack_st_OPENSSL_STRING */
            	476, 0,
            0, 32, 1, /* 476: struct.stack_st_OPENSSL_STRING */
            	13, 0,
            0, 0, 0, /* 481: func */
            0, 0, 0, /* 484: func */
            0, 0, 0, /* 487: func */
            0, 0, 0, /* 490: func */
            0, 0, 0, /* 493: func */
            0, 0, 0, /* 496: func */
            0, 0, 0, /* 499: func */
            0, 0, 0, /* 502: func */
            0, 0, 0, /* 505: func */
            0, 0, 0, /* 508: func */
            0, 0, 0, /* 511: func */
            0, 0, 0, /* 514: func */
            0, 0, 0, /* 517: func */
            0, 8, 0, /* 520: long */
            0, 0, 0, /* 523: func */
            0, 0, 0, /* 526: func */
            0, 0, 0, /* 529: func */
            0, 0, 0, /* 532: func */
            0, 0, 0, /* 535: func */
            0, 0, 0, /* 538: func */
            0, 4, 0, /* 541: int */
            0, 0, 0, /* 544: func */
            0, 0, 0, /* 547: func */
            0, 0, 0, /* 550: func */
            0, 0, 0, /* 553: func */
            0, 0, 0, /* 556: func */
            0, 0, 0, /* 559: func */
            0, 1, 0, /* 562: char */
            0, 0, 0, /* 565: func */
            0, 0, 0, /* 568: func */
            0, 0, 0, /* 571: func */
            0, 0, 0, /* 574: func */
            0, 0, 0, /* 577: func */
            0, 0, 0, /* 580: func */
            0, 0, 0, /* 583: func */
            0, 0, 0, /* 586: func */
            0, 0, 0, /* 589: func */
            0, 0, 0, /* 592: func */
            0, 0, 0, /* 595: func */
            0, 0, 0, /* 598: func */
            0, 0, 0, /* 601: func */
            0, 0, 0, /* 604: func */
            0, 0, 0, /* 607: func */
            0, 0, 0, /* 610: func */
            0, 0, 0, /* 613: func */
            0, 0, 0, /* 616: func */
            0, 0, 0, /* 619: func */
            0, 0, 0, /* 622: func */
            0, 0, 0, /* 625: func */
            0, 0, 0, /* 628: func */
            0, 0, 0, /* 631: func */
            0, 0, 0, /* 634: func */
        },
        .arg_entity_index = { 43, },
        .ret_entity_index = 541,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_PKEY_size)(EVP_PKEY *);
    orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
    *new_ret_ptr = (*orig_EVP_PKEY_size)(new_arg_a);

    syscall(889);

    return ret;
}

