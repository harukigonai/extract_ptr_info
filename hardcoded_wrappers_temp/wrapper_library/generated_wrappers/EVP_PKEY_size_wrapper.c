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
            0, 8, 1, /* 0: struct.fnames */
            	5, 0,
            0, 8, 1, /* 5: pointer.char */
            	4096, 0,
            0, 32, 2, /* 10: struct.stack_st */
            	17, 8,
            	22, 24,
            0, 8, 1, /* 17: pointer.pointer.char */
            	5, 0,
            4097, 8, 0, /* 22: pointer.func */
            0, 0, 0, /* 25: func */
            0, 8, 1, /* 28: pointer.struct.ENGINE_CMD_DEFN_st */
            	33, 0,
            0, 32, 2, /* 33: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 8, 1, /* 40: pointer.struct.evp_pkey_st */
            	45, 0,
            0, 56, 4, /* 45: struct.evp_pkey_st */
            	56, 16,
            	154, 24,
            	0, 32,
            	468, 48,
            0, 8, 1, /* 56: pointer.struct.evp_pkey_asn1_method_st */
            	61, 0,
            0, 208, 24, /* 61: struct.evp_pkey_asn1_method_st */
            	5, 16,
            	5, 24,
            	112, 32,
            	115, 40,
            	118, 48,
            	121, 56,
            	124, 64,
            	127, 72,
            	121, 80,
            	130, 88,
            	130, 96,
            	133, 104,
            	136, 112,
            	130, 120,
            	118, 128,
            	118, 136,
            	121, 144,
            	139, 152,
            	142, 160,
            	145, 168,
            	133, 176,
            	136, 184,
            	148, 192,
            	151, 200,
            4097, 8, 0, /* 112: pointer.func */
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
            0, 8, 1, /* 154: pointer.struct.engine_st */
            	159, 0,
            0, 216, 24, /* 159: struct.engine_st */
            	5, 0,
            	5, 8,
            	210, 16,
            	265, 24,
            	316, 32,
            	352, 40,
            	369, 48,
            	396, 56,
            	431, 64,
            	439, 72,
            	442, 80,
            	445, 88,
            	448, 96,
            	451, 104,
            	451, 112,
            	451, 120,
            	454, 128,
            	457, 136,
            	457, 144,
            	460, 152,
            	28, 160,
            	463, 184,
            	154, 200,
            	154, 208,
            0, 8, 1, /* 210: pointer.struct.rsa_meth_st */
            	215, 0,
            0, 112, 13, /* 215: struct.rsa_meth_st */
            	5, 0,
            	244, 8,
            	244, 16,
            	244, 24,
            	244, 32,
            	247, 40,
            	250, 48,
            	253, 56,
            	253, 64,
            	5, 80,
            	256, 88,
            	259, 96,
            	262, 104,
            4097, 8, 0, /* 244: pointer.func */
            4097, 8, 0, /* 247: pointer.func */
            4097, 8, 0, /* 250: pointer.func */
            4097, 8, 0, /* 253: pointer.func */
            4097, 8, 0, /* 256: pointer.func */
            4097, 8, 0, /* 259: pointer.func */
            4097, 8, 0, /* 262: pointer.func */
            0, 8, 1, /* 265: pointer.struct.dsa_method */
            	270, 0,
            0, 96, 11, /* 270: struct.dsa_method */
            	5, 0,
            	295, 8,
            	298, 16,
            	301, 24,
            	304, 32,
            	307, 40,
            	310, 48,
            	310, 56,
            	5, 72,
            	313, 80,
            	310, 88,
            4097, 8, 0, /* 295: pointer.func */
            4097, 8, 0, /* 298: pointer.func */
            4097, 8, 0, /* 301: pointer.func */
            4097, 8, 0, /* 304: pointer.func */
            4097, 8, 0, /* 307: pointer.func */
            4097, 8, 0, /* 310: pointer.func */
            4097, 8, 0, /* 313: pointer.func */
            0, 8, 1, /* 316: pointer.struct.dh_method */
            	321, 0,
            0, 72, 8, /* 321: struct.dh_method */
            	5, 0,
            	340, 8,
            	343, 16,
            	346, 24,
            	340, 32,
            	340, 40,
            	5, 56,
            	349, 64,
            4097, 8, 0, /* 340: pointer.func */
            4097, 8, 0, /* 343: pointer.func */
            4097, 8, 0, /* 346: pointer.func */
            4097, 8, 0, /* 349: pointer.func */
            0, 8, 1, /* 352: pointer.struct.ecdh_method */
            	357, 0,
            0, 32, 3, /* 357: struct.ecdh_method */
            	5, 0,
            	366, 8,
            	5, 24,
            4097, 8, 0, /* 366: pointer.func */
            0, 8, 1, /* 369: pointer.struct.ecdsa_method */
            	374, 0,
            0, 48, 5, /* 374: struct.ecdsa_method */
            	5, 0,
            	387, 8,
            	390, 16,
            	393, 24,
            	5, 40,
            4097, 8, 0, /* 387: pointer.func */
            4097, 8, 0, /* 390: pointer.func */
            4097, 8, 0, /* 393: pointer.func */
            0, 8, 1, /* 396: pointer.struct.rand_meth_st */
            	401, 0,
            0, 48, 6, /* 401: struct.rand_meth_st */
            	416, 0,
            	419, 8,
            	422, 16,
            	425, 24,
            	419, 32,
            	428, 40,
            4097, 8, 0, /* 416: pointer.func */
            4097, 8, 0, /* 419: pointer.func */
            4097, 8, 0, /* 422: pointer.func */
            4097, 8, 0, /* 425: pointer.func */
            4097, 8, 0, /* 428: pointer.func */
            0, 8, 1, /* 431: pointer.struct.store_method_st */
            	436, 0,
            0, 0, 0, /* 436: struct.store_method_st */
            4097, 8, 0, /* 439: pointer.func */
            4097, 8, 0, /* 442: pointer.func */
            4097, 8, 0, /* 445: pointer.func */
            4097, 8, 0, /* 448: pointer.func */
            4097, 8, 0, /* 451: pointer.func */
            4097, 8, 0, /* 454: pointer.func */
            4097, 8, 0, /* 457: pointer.func */
            4097, 8, 0, /* 460: pointer.func */
            0, 16, 1, /* 463: struct.crypto_ex_data_st */
            	468, 0,
            0, 8, 1, /* 468: pointer.struct.stack_st_OPENSSL_STRING */
            	473, 0,
            0, 32, 1, /* 473: struct.stack_st_OPENSSL_STRING */
            	10, 0,
            0, 0, 0, /* 478: func */
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
            0, 8, 0, /* 517: long */
            0, 0, 0, /* 520: func */
            0, 0, 0, /* 523: func */
            0, 0, 0, /* 526: func */
            0, 0, 0, /* 529: func */
            0, 0, 0, /* 532: func */
            0, 0, 0, /* 535: func */
            0, 4, 0, /* 538: int */
            0, 0, 0, /* 541: func */
            0, 0, 0, /* 544: func */
            0, 0, 0, /* 547: func */
            0, 0, 0, /* 550: func */
            0, 0, 0, /* 553: func */
            0, 0, 0, /* 556: func */
            0, 1, 0, /* 559: char */
            0, 0, 0, /* 562: func */
            0, 0, 0, /* 565: func */
            0, 0, 0, /* 568: func */
            0, 0, 0, /* 571: func */
            0, 0, 0, /* 574: func */
            0, 0, 0, /* 577: func */
            0, 0, 0, /* 580: func */
            0, 0, 0, /* 583: func */
            0, 0, 0, /* 586: func */
            0, 8, 0, /* 589: pointer.void */
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
        .arg_entity_index = { 40, },
        .ret_entity_index = 538,
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

