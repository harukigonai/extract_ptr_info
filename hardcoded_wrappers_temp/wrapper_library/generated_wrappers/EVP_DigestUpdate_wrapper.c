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

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c);

int EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestUpdate called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
        orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
        return orig_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
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
            0, 0, 0, /* 13: func */
            4097, 8, 0, /* 16: pointer.func */
            0, 0, 0, /* 19: func */
            0, 0, 0, /* 22: func */
            4097, 8, 0, /* 25: pointer.func */
            0, 0, 0, /* 28: func */
            4097, 8, 0, /* 31: pointer.func */
            0, 0, 0, /* 34: func */
            4097, 8, 0, /* 37: pointer.func */
            0, 0, 0, /* 40: func */
            4097, 8, 0, /* 43: pointer.func */
            0, 0, 0, /* 46: func */
            0, 56, 4, /* 49: struct.evp_pkey_st */
            	60, 16,
            	148, 24,
            	3, 32,
            	474, 48,
            1, 8, 1, /* 60: pointer.struct.evp_pkey_asn1_method_st */
            	65, 0,
            0, 208, 24, /* 65: struct.evp_pkey_asn1_method_st */
            	8, 16,
            	8, 24,
            	116, 32,
            	124, 40,
            	43, 48,
            	127, 56,
            	37, 64,
            	31, 72,
            	127, 80,
            	25, 88,
            	25, 96,
            	130, 104,
            	133, 112,
            	25, 120,
            	43, 128,
            	43, 136,
            	127, 144,
            	16, 152,
            	136, 160,
            	139, 168,
            	130, 176,
            	133, 184,
            	142, 192,
            	145, 200,
            1, 8, 1, /* 116: pointer.struct.unnamed */
            	121, 0,
            0, 0, 0, /* 121: struct.unnamed */
            4097, 8, 0, /* 124: pointer.func */
            4097, 8, 0, /* 127: pointer.func */
            4097, 8, 0, /* 130: pointer.func */
            4097, 8, 0, /* 133: pointer.func */
            4097, 8, 0, /* 136: pointer.func */
            4097, 8, 0, /* 139: pointer.func */
            4097, 8, 0, /* 142: pointer.func */
            4097, 8, 0, /* 145: pointer.func */
            1, 8, 1, /* 148: pointer.struct.engine_st */
            	153, 0,
            0, 216, 24, /* 153: struct.engine_st */
            	8, 0,
            	8, 8,
            	204, 16,
            	259, 24,
            	310, 32,
            	346, 40,
            	363, 48,
            	390, 56,
            	425, 64,
            	433, 72,
            	436, 80,
            	439, 88,
            	442, 96,
            	445, 104,
            	445, 112,
            	445, 120,
            	448, 128,
            	451, 136,
            	451, 144,
            	454, 152,
            	457, 160,
            	469, 184,
            	148, 200,
            	148, 208,
            1, 8, 1, /* 204: pointer.struct.rsa_meth_st */
            	209, 0,
            0, 112, 13, /* 209: struct.rsa_meth_st */
            	8, 0,
            	238, 8,
            	238, 16,
            	238, 24,
            	238, 32,
            	241, 40,
            	244, 48,
            	247, 56,
            	247, 64,
            	8, 80,
            	250, 88,
            	253, 96,
            	256, 104,
            4097, 8, 0, /* 238: pointer.func */
            4097, 8, 0, /* 241: pointer.func */
            4097, 8, 0, /* 244: pointer.func */
            4097, 8, 0, /* 247: pointer.func */
            4097, 8, 0, /* 250: pointer.func */
            4097, 8, 0, /* 253: pointer.func */
            4097, 8, 0, /* 256: pointer.func */
            1, 8, 1, /* 259: pointer.struct.dsa_method */
            	264, 0,
            0, 96, 11, /* 264: struct.dsa_method */
            	8, 0,
            	289, 8,
            	292, 16,
            	295, 24,
            	298, 32,
            	301, 40,
            	304, 48,
            	304, 56,
            	8, 72,
            	307, 80,
            	304, 88,
            4097, 8, 0, /* 289: pointer.func */
            4097, 8, 0, /* 292: pointer.func */
            4097, 8, 0, /* 295: pointer.func */
            4097, 8, 0, /* 298: pointer.func */
            4097, 8, 0, /* 301: pointer.func */
            4097, 8, 0, /* 304: pointer.func */
            4097, 8, 0, /* 307: pointer.func */
            1, 8, 1, /* 310: pointer.struct.dh_method */
            	315, 0,
            0, 72, 8, /* 315: struct.dh_method */
            	8, 0,
            	334, 8,
            	337, 16,
            	340, 24,
            	334, 32,
            	334, 40,
            	8, 56,
            	343, 64,
            4097, 8, 0, /* 334: pointer.func */
            4097, 8, 0, /* 337: pointer.func */
            4097, 8, 0, /* 340: pointer.func */
            4097, 8, 0, /* 343: pointer.func */
            1, 8, 1, /* 346: pointer.struct.ecdh_method */
            	351, 0,
            0, 32, 3, /* 351: struct.ecdh_method */
            	8, 0,
            	360, 8,
            	8, 24,
            4097, 8, 0, /* 360: pointer.func */
            1, 8, 1, /* 363: pointer.struct.ecdsa_method */
            	368, 0,
            0, 48, 5, /* 368: struct.ecdsa_method */
            	8, 0,
            	381, 8,
            	384, 16,
            	387, 24,
            	8, 40,
            4097, 8, 0, /* 381: pointer.func */
            4097, 8, 0, /* 384: pointer.func */
            4097, 8, 0, /* 387: pointer.func */
            1, 8, 1, /* 390: pointer.struct.rand_meth_st */
            	395, 0,
            0, 48, 6, /* 395: struct.rand_meth_st */
            	410, 0,
            	413, 8,
            	416, 16,
            	419, 24,
            	413, 32,
            	422, 40,
            4097, 8, 0, /* 410: pointer.func */
            4097, 8, 0, /* 413: pointer.func */
            4097, 8, 0, /* 416: pointer.func */
            4097, 8, 0, /* 419: pointer.func */
            4097, 8, 0, /* 422: pointer.func */
            1, 8, 1, /* 425: pointer.struct.store_method_st */
            	430, 0,
            0, 0, 0, /* 430: struct.store_method_st */
            4097, 8, 0, /* 433: pointer.func */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            4097, 8, 0, /* 442: pointer.func */
            4097, 8, 0, /* 445: pointer.func */
            4097, 8, 0, /* 448: pointer.func */
            4097, 8, 0, /* 451: pointer.func */
            4097, 8, 0, /* 454: pointer.func */
            1, 8, 1, /* 457: pointer.struct.ENGINE_CMD_DEFN_st */
            	462, 0,
            0, 32, 2, /* 462: struct.ENGINE_CMD_DEFN_st */
            	8, 8,
            	8, 16,
            0, 16, 1, /* 469: struct.crypto_ex_data_st */
            	474, 0,
            1, 8, 1, /* 474: pointer.struct.stack_st_OPENSSL_STRING */
            	479, 0,
            0, 32, 1, /* 479: struct.stack_st_OPENSSL_STRING */
            	484, 0,
            0, 32, 2, /* 484: struct.stack_st */
            	491, 8,
            	496, 24,
            1, 8, 1, /* 491: pointer.pointer.char */
            	8, 0,
            4097, 8, 0, /* 496: pointer.func */
            1, 8, 1, /* 499: pointer.struct.evp_pkey_st */
            	49, 0,
            4097, 8, 0, /* 504: pointer.func */
            0, 0, 0, /* 507: func */
            0, 0, 0, /* 510: func */
            4097, 8, 0, /* 513: pointer.func */
            0, 0, 0, /* 516: func */
            4097, 8, 0, /* 519: pointer.func */
            0, 0, 0, /* 522: func */
            4097, 8, 0, /* 525: pointer.func */
            0, 0, 0, /* 528: func */
            4097, 8, 0, /* 531: pointer.func */
            0, 0, 0, /* 534: func */
            4097, 8, 0, /* 537: pointer.func */
            0, 0, 0, /* 540: func */
            1, 8, 1, /* 543: pointer.int */
            	548, 0,
            0, 4, 0, /* 548: int */
            4097, 8, 0, /* 551: pointer.func */
            0, 0, 0, /* 554: func */
            4097, 8, 0, /* 557: pointer.func */
            0, 0, 0, /* 560: func */
            4097, 8, 0, /* 563: pointer.func */
            0, 0, 0, /* 566: func */
            0, 0, 0, /* 569: func */
            0, 0, 0, /* 572: func */
            0, 0, 0, /* 575: func */
            0, 0, 0, /* 578: func */
            0, 0, 0, /* 581: func */
            0, 0, 0, /* 584: func */
            0, 0, 0, /* 587: func */
            0, 0, 0, /* 590: func */
            4097, 8, 0, /* 593: pointer.func */
            0, 0, 0, /* 596: func */
            4097, 8, 0, /* 599: pointer.func */
            0, 0, 0, /* 602: func */
            0, 0, 0, /* 605: func */
            0, 0, 0, /* 608: func */
            0, 0, 0, /* 611: func */
            0, 0, 0, /* 614: func */
            0, 0, 0, /* 617: func */
            0, 120, 8, /* 620: struct.env_md_st */
            	639, 24,
            	642, 32,
            	645, 40,
            	648, 48,
            	639, 56,
            	599, 64,
            	593, 72,
            	651, 112,
            4097, 8, 0, /* 639: pointer.func */
            4097, 8, 0, /* 642: pointer.func */
            4097, 8, 0, /* 645: pointer.func */
            4097, 8, 0, /* 648: pointer.func */
            4097, 8, 0, /* 651: pointer.func */
            0, 0, 0, /* 654: func */
            0, 0, 0, /* 657: func */
            0, 48, 5, /* 660: struct.env_md_ctx_st */
            	673, 0,
            	148, 8,
            	0, 24,
            	678, 32,
            	642, 40,
            1, 8, 1, /* 673: pointer.struct.env_md_st */
            	620, 0,
            1, 8, 1, /* 678: pointer.struct.evp_pkey_ctx_st */
            	683, 0,
            0, 80, 8, /* 683: struct.evp_pkey_ctx_st */
            	702, 0,
            	148, 8,
            	499, 16,
            	499, 24,
            	8, 40,
            	8, 48,
            	116, 56,
            	543, 64,
            1, 8, 1, /* 702: pointer.struct.evp_pkey_method_st */
            	707, 0,
            0, 208, 25, /* 707: struct.evp_pkey_method_st */
            	116, 8,
            	760, 16,
            	763, 24,
            	116, 32,
            	563, 40,
            	116, 48,
            	563, 56,
            	116, 64,
            	557, 72,
            	116, 80,
            	551, 88,
            	116, 96,
            	557, 104,
            	537, 112,
            	531, 120,
            	537, 128,
            	525, 136,
            	116, 144,
            	557, 152,
            	116, 160,
            	557, 168,
            	116, 176,
            	519, 184,
            	513, 192,
            	504, 200,
            4097, 8, 0, /* 760: pointer.func */
            4097, 8, 0, /* 763: pointer.func */
            0, 0, 0, /* 766: func */
            0, 0, 0, /* 769: func */
            0, 0, 0, /* 772: func */
            0, 0, 0, /* 775: func */
            1, 8, 1, /* 778: pointer.struct.env_md_ctx_st */
            	660, 0,
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
        .arg_entity_index = { 778, 0, 792, },
        .ret_entity_index = 548,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

     const void * new_arg_b = *(( const void * *)new_args->args[1]);

    size_t new_arg_c = *((size_t *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
    orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
    *new_ret_ptr = (*orig_EVP_DigestUpdate)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

