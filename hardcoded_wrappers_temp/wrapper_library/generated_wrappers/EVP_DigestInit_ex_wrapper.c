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

int bb_EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c);

int EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestInit_ex called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestInit_ex(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
        orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
        return orig_EVP_DigestInit_ex(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 1, /* 0: struct.fnames */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	4096, 0,
            0, 0, 0, /* 10: func */
            4097, 8, 0, /* 13: pointer.func */
            0, 0, 0, /* 16: func */
            0, 0, 0, /* 19: func */
            4097, 8, 0, /* 22: pointer.func */
            0, 0, 0, /* 25: func */
            4097, 8, 0, /* 28: pointer.func */
            0, 0, 0, /* 31: func */
            4097, 8, 0, /* 34: pointer.func */
            0, 0, 0, /* 37: func */
            4097, 8, 0, /* 40: pointer.func */
            0, 0, 0, /* 43: func */
            0, 56, 4, /* 46: struct.evp_pkey_st */
            	57, 16,
            	145, 24,
            	0, 32,
            	471, 48,
            1, 8, 1, /* 57: pointer.struct.evp_pkey_asn1_method_st */
            	62, 0,
            0, 208, 24, /* 62: struct.evp_pkey_asn1_method_st */
            	5, 16,
            	5, 24,
            	113, 32,
            	121, 40,
            	40, 48,
            	124, 56,
            	34, 64,
            	28, 72,
            	124, 80,
            	22, 88,
            	22, 96,
            	127, 104,
            	130, 112,
            	22, 120,
            	40, 128,
            	40, 136,
            	124, 144,
            	13, 152,
            	133, 160,
            	136, 168,
            	127, 176,
            	130, 184,
            	139, 192,
            	142, 200,
            1, 8, 1, /* 113: pointer.struct.unnamed */
            	118, 0,
            0, 0, 0, /* 118: struct.unnamed */
            4097, 8, 0, /* 121: pointer.func */
            4097, 8, 0, /* 124: pointer.func */
            4097, 8, 0, /* 127: pointer.func */
            4097, 8, 0, /* 130: pointer.func */
            4097, 8, 0, /* 133: pointer.func */
            4097, 8, 0, /* 136: pointer.func */
            4097, 8, 0, /* 139: pointer.func */
            4097, 8, 0, /* 142: pointer.func */
            1, 8, 1, /* 145: pointer.struct.engine_st */
            	150, 0,
            0, 216, 24, /* 150: struct.engine_st */
            	5, 0,
            	5, 8,
            	201, 16,
            	256, 24,
            	307, 32,
            	343, 40,
            	360, 48,
            	387, 56,
            	422, 64,
            	430, 72,
            	433, 80,
            	436, 88,
            	439, 96,
            	442, 104,
            	442, 112,
            	442, 120,
            	445, 128,
            	448, 136,
            	448, 144,
            	451, 152,
            	454, 160,
            	466, 184,
            	145, 200,
            	145, 208,
            1, 8, 1, /* 201: pointer.struct.rsa_meth_st */
            	206, 0,
            0, 112, 13, /* 206: struct.rsa_meth_st */
            	5, 0,
            	235, 8,
            	235, 16,
            	235, 24,
            	235, 32,
            	238, 40,
            	241, 48,
            	244, 56,
            	244, 64,
            	5, 80,
            	247, 88,
            	250, 96,
            	253, 104,
            4097, 8, 0, /* 235: pointer.func */
            4097, 8, 0, /* 238: pointer.func */
            4097, 8, 0, /* 241: pointer.func */
            4097, 8, 0, /* 244: pointer.func */
            4097, 8, 0, /* 247: pointer.func */
            4097, 8, 0, /* 250: pointer.func */
            4097, 8, 0, /* 253: pointer.func */
            1, 8, 1, /* 256: pointer.struct.dsa_method */
            	261, 0,
            0, 96, 11, /* 261: struct.dsa_method */
            	5, 0,
            	286, 8,
            	289, 16,
            	292, 24,
            	295, 32,
            	298, 40,
            	301, 48,
            	301, 56,
            	5, 72,
            	304, 80,
            	301, 88,
            4097, 8, 0, /* 286: pointer.func */
            4097, 8, 0, /* 289: pointer.func */
            4097, 8, 0, /* 292: pointer.func */
            4097, 8, 0, /* 295: pointer.func */
            4097, 8, 0, /* 298: pointer.func */
            4097, 8, 0, /* 301: pointer.func */
            4097, 8, 0, /* 304: pointer.func */
            1, 8, 1, /* 307: pointer.struct.dh_method */
            	312, 0,
            0, 72, 8, /* 312: struct.dh_method */
            	5, 0,
            	331, 8,
            	334, 16,
            	337, 24,
            	331, 32,
            	331, 40,
            	5, 56,
            	340, 64,
            4097, 8, 0, /* 331: pointer.func */
            4097, 8, 0, /* 334: pointer.func */
            4097, 8, 0, /* 337: pointer.func */
            4097, 8, 0, /* 340: pointer.func */
            1, 8, 1, /* 343: pointer.struct.ecdh_method */
            	348, 0,
            0, 32, 3, /* 348: struct.ecdh_method */
            	5, 0,
            	357, 8,
            	5, 24,
            4097, 8, 0, /* 357: pointer.func */
            1, 8, 1, /* 360: pointer.struct.ecdsa_method */
            	365, 0,
            0, 48, 5, /* 365: struct.ecdsa_method */
            	5, 0,
            	378, 8,
            	381, 16,
            	384, 24,
            	5, 40,
            4097, 8, 0, /* 378: pointer.func */
            4097, 8, 0, /* 381: pointer.func */
            4097, 8, 0, /* 384: pointer.func */
            1, 8, 1, /* 387: pointer.struct.rand_meth_st */
            	392, 0,
            0, 48, 6, /* 392: struct.rand_meth_st */
            	407, 0,
            	410, 8,
            	413, 16,
            	416, 24,
            	410, 32,
            	419, 40,
            4097, 8, 0, /* 407: pointer.func */
            4097, 8, 0, /* 410: pointer.func */
            4097, 8, 0, /* 413: pointer.func */
            4097, 8, 0, /* 416: pointer.func */
            4097, 8, 0, /* 419: pointer.func */
            1, 8, 1, /* 422: pointer.struct.store_method_st */
            	427, 0,
            0, 0, 0, /* 427: struct.store_method_st */
            4097, 8, 0, /* 430: pointer.func */
            4097, 8, 0, /* 433: pointer.func */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            4097, 8, 0, /* 442: pointer.func */
            4097, 8, 0, /* 445: pointer.func */
            4097, 8, 0, /* 448: pointer.func */
            4097, 8, 0, /* 451: pointer.func */
            1, 8, 1, /* 454: pointer.struct.ENGINE_CMD_DEFN_st */
            	459, 0,
            0, 32, 2, /* 459: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 466: struct.crypto_ex_data_st */
            	471, 0,
            1, 8, 1, /* 471: pointer.struct.stack_st_OPENSSL_STRING */
            	476, 0,
            0, 32, 1, /* 476: struct.stack_st_OPENSSL_STRING */
            	481, 0,
            0, 32, 2, /* 481: struct.stack_st */
            	488, 8,
            	493, 24,
            1, 8, 1, /* 488: pointer.pointer.char */
            	5, 0,
            4097, 8, 0, /* 493: pointer.func */
            1, 8, 1, /* 496: pointer.struct.evp_pkey_st */
            	46, 0,
            4097, 8, 0, /* 501: pointer.func */
            0, 0, 0, /* 504: func */
            0, 0, 0, /* 507: func */
            4097, 8, 0, /* 510: pointer.func */
            0, 0, 0, /* 513: func */
            4097, 8, 0, /* 516: pointer.func */
            0, 0, 0, /* 519: func */
            4097, 8, 0, /* 522: pointer.func */
            0, 0, 0, /* 525: func */
            4097, 8, 0, /* 528: pointer.func */
            0, 0, 0, /* 531: func */
            4097, 8, 0, /* 534: pointer.func */
            0, 0, 0, /* 537: func */
            1, 8, 1, /* 540: pointer.int */
            	545, 0,
            0, 4, 0, /* 545: int */
            4097, 8, 0, /* 548: pointer.func */
            0, 0, 0, /* 551: func */
            4097, 8, 0, /* 554: pointer.func */
            0, 0, 0, /* 557: func */
            4097, 8, 0, /* 560: pointer.func */
            0, 0, 0, /* 563: func */
            0, 0, 0, /* 566: func */
            0, 0, 0, /* 569: func */
            0, 0, 0, /* 572: func */
            0, 0, 0, /* 575: func */
            0, 0, 0, /* 578: func */
            0, 0, 0, /* 581: func */
            0, 0, 0, /* 584: func */
            0, 0, 0, /* 587: func */
            4097, 8, 0, /* 590: pointer.func */
            0, 0, 0, /* 593: func */
            4097, 8, 0, /* 596: pointer.func */
            0, 0, 0, /* 599: func */
            0, 0, 0, /* 602: func */
            0, 0, 0, /* 605: func */
            0, 0, 0, /* 608: func */
            0, 0, 0, /* 611: func */
            0, 0, 0, /* 614: func */
            0, 120, 8, /* 617: struct.env_md_st */
            	636, 24,
            	639, 32,
            	642, 40,
            	645, 48,
            	636, 56,
            	596, 64,
            	590, 72,
            	648, 112,
            4097, 8, 0, /* 636: pointer.func */
            4097, 8, 0, /* 639: pointer.func */
            4097, 8, 0, /* 642: pointer.func */
            4097, 8, 0, /* 645: pointer.func */
            4097, 8, 0, /* 648: pointer.func */
            0, 0, 0, /* 651: func */
            0, 0, 0, /* 654: func */
            0, 48, 5, /* 657: struct.env_md_ctx_st */
            	670, 0,
            	145, 8,
            	675, 24,
            	678, 32,
            	639, 40,
            1, 8, 1, /* 670: pointer.struct.env_md_st */
            	617, 0,
            0, 8, 0, /* 675: pointer.void */
            1, 8, 1, /* 678: pointer.struct.evp_pkey_ctx_st */
            	683, 0,
            0, 80, 8, /* 683: struct.evp_pkey_ctx_st */
            	702, 0,
            	145, 8,
            	496, 16,
            	496, 24,
            	5, 40,
            	5, 48,
            	113, 56,
            	540, 64,
            1, 8, 1, /* 702: pointer.struct.evp_pkey_method_st */
            	707, 0,
            0, 208, 25, /* 707: struct.evp_pkey_method_st */
            	113, 8,
            	760, 16,
            	763, 24,
            	113, 32,
            	560, 40,
            	113, 48,
            	560, 56,
            	113, 64,
            	554, 72,
            	113, 80,
            	548, 88,
            	113, 96,
            	554, 104,
            	534, 112,
            	528, 120,
            	534, 128,
            	522, 136,
            	113, 144,
            	554, 152,
            	113, 160,
            	554, 168,
            	113, 176,
            	516, 184,
            	510, 192,
            	501, 200,
            4097, 8, 0, /* 760: pointer.func */
            4097, 8, 0, /* 763: pointer.func */
            0, 0, 0, /* 766: func */
            0, 0, 0, /* 769: func */
            0, 0, 0, /* 772: func */
            0, 0, 0, /* 775: func */
            1, 8, 1, /* 778: pointer.struct.env_md_ctx_st */
            	657, 0,
            0, 0, 0, /* 783: func */
            0, 0, 0, /* 786: func */
            0, 0, 0, /* 789: func */
            0, 8, 0, /* 792: long */
            0, 0, 0, /* 795: func */
            0, 20, 0, /* 798: array[5].int */
            0, 0, 0, /* 801: func */
            0, 0, 0, /* 804: func */
            0, 0, 0, /* 807: func */
            0, 1, 0, /* 810: char */
            0, 0, 0, /* 813: func */
            0, 0, 0, /* 816: func */
            0, 0, 0, /* 819: func */
            0, 0, 0, /* 822: func */
            0, 0, 0, /* 825: func */
            0, 0, 0, /* 828: func */
            0, 0, 0, /* 831: func */
            0, 0, 0, /* 834: func */
            0, 0, 0, /* 837: func */
            0, 0, 0, /* 840: func */
            0, 0, 0, /* 843: func */
            0, 0, 0, /* 846: func */
            0, 0, 0, /* 849: func */
            0, 0, 0, /* 852: func */
            0, 0, 0, /* 855: func */
            0, 0, 0, /* 858: func */
            0, 0, 0, /* 861: func */
            0, 0, 0, /* 864: func */
            0, 0, 0, /* 867: func */
            0, 0, 0, /* 870: func */
            0, 0, 0, /* 873: func */
            0, 0, 0, /* 876: func */
        },
        .arg_entity_index = { 778, 670, 145, },
        .ret_entity_index = 545,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    const EVP_MD * new_arg_b = *((const EVP_MD * *)new_args->args[1]);

    ENGINE * new_arg_c = *((ENGINE * *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
    orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
    *new_ret_ptr = (*orig_EVP_DigestInit_ex)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

