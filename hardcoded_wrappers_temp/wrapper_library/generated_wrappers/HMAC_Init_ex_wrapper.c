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

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e);

int HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
{
    unsigned long in_lib = syscall(890);
    printf("HMAC_Init_ex called %lu\n", in_lib);
    if (!in_lib)
        return bb_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    else {
        int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
        orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
        return orig_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    }
}

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 0, /* 0: pointer.void */
            0, 128, 0, /* 3: array[128].char */
            0, 8, 1, /* 6: struct.fnames */
            	11, 0,
            1, 8, 1, /* 11: pointer.char */
            	4096, 0,
            0, 0, 0, /* 16: func */
            4097, 8, 0, /* 19: pointer.func */
            0, 0, 0, /* 22: func */
            0, 0, 0, /* 25: func */
            4097, 8, 0, /* 28: pointer.func */
            0, 0, 0, /* 31: func */
            4097, 8, 0, /* 34: pointer.func */
            0, 0, 0, /* 37: func */
            4097, 8, 0, /* 40: pointer.func */
            0, 0, 0, /* 43: func */
            4097, 8, 0, /* 46: pointer.func */
            0, 0, 0, /* 49: func */
            0, 56, 4, /* 52: struct.evp_pkey_st */
            	63, 16,
            	151, 24,
            	6, 32,
            	477, 48,
            1, 8, 1, /* 63: pointer.struct.evp_pkey_asn1_method_st */
            	68, 0,
            0, 208, 24, /* 68: struct.evp_pkey_asn1_method_st */
            	11, 16,
            	11, 24,
            	119, 32,
            	127, 40,
            	46, 48,
            	130, 56,
            	40, 64,
            	34, 72,
            	130, 80,
            	28, 88,
            	28, 96,
            	133, 104,
            	136, 112,
            	28, 120,
            	46, 128,
            	46, 136,
            	130, 144,
            	19, 152,
            	139, 160,
            	142, 168,
            	133, 176,
            	136, 184,
            	145, 192,
            	148, 200,
            1, 8, 1, /* 119: pointer.struct.unnamed */
            	124, 0,
            0, 0, 0, /* 124: struct.unnamed */
            4097, 8, 0, /* 127: pointer.func */
            4097, 8, 0, /* 130: pointer.func */
            4097, 8, 0, /* 133: pointer.func */
            4097, 8, 0, /* 136: pointer.func */
            4097, 8, 0, /* 139: pointer.func */
            4097, 8, 0, /* 142: pointer.func */
            4097, 8, 0, /* 145: pointer.func */
            4097, 8, 0, /* 148: pointer.func */
            1, 8, 1, /* 151: pointer.struct.engine_st */
            	156, 0,
            0, 216, 24, /* 156: struct.engine_st */
            	11, 0,
            	11, 8,
            	207, 16,
            	262, 24,
            	313, 32,
            	349, 40,
            	366, 48,
            	393, 56,
            	428, 64,
            	436, 72,
            	439, 80,
            	442, 88,
            	445, 96,
            	448, 104,
            	448, 112,
            	448, 120,
            	451, 128,
            	454, 136,
            	454, 144,
            	457, 152,
            	460, 160,
            	472, 184,
            	151, 200,
            	151, 208,
            1, 8, 1, /* 207: pointer.struct.rsa_meth_st */
            	212, 0,
            0, 112, 13, /* 212: struct.rsa_meth_st */
            	11, 0,
            	241, 8,
            	241, 16,
            	241, 24,
            	241, 32,
            	244, 40,
            	247, 48,
            	250, 56,
            	250, 64,
            	11, 80,
            	253, 88,
            	256, 96,
            	259, 104,
            4097, 8, 0, /* 241: pointer.func */
            4097, 8, 0, /* 244: pointer.func */
            4097, 8, 0, /* 247: pointer.func */
            4097, 8, 0, /* 250: pointer.func */
            4097, 8, 0, /* 253: pointer.func */
            4097, 8, 0, /* 256: pointer.func */
            4097, 8, 0, /* 259: pointer.func */
            1, 8, 1, /* 262: pointer.struct.dsa_method */
            	267, 0,
            0, 96, 11, /* 267: struct.dsa_method */
            	11, 0,
            	292, 8,
            	295, 16,
            	298, 24,
            	301, 32,
            	304, 40,
            	307, 48,
            	307, 56,
            	11, 72,
            	310, 80,
            	307, 88,
            4097, 8, 0, /* 292: pointer.func */
            4097, 8, 0, /* 295: pointer.func */
            4097, 8, 0, /* 298: pointer.func */
            4097, 8, 0, /* 301: pointer.func */
            4097, 8, 0, /* 304: pointer.func */
            4097, 8, 0, /* 307: pointer.func */
            4097, 8, 0, /* 310: pointer.func */
            1, 8, 1, /* 313: pointer.struct.dh_method */
            	318, 0,
            0, 72, 8, /* 318: struct.dh_method */
            	11, 0,
            	337, 8,
            	340, 16,
            	343, 24,
            	337, 32,
            	337, 40,
            	11, 56,
            	346, 64,
            4097, 8, 0, /* 337: pointer.func */
            4097, 8, 0, /* 340: pointer.func */
            4097, 8, 0, /* 343: pointer.func */
            4097, 8, 0, /* 346: pointer.func */
            1, 8, 1, /* 349: pointer.struct.ecdh_method */
            	354, 0,
            0, 32, 3, /* 354: struct.ecdh_method */
            	11, 0,
            	363, 8,
            	11, 24,
            4097, 8, 0, /* 363: pointer.func */
            1, 8, 1, /* 366: pointer.struct.ecdsa_method */
            	371, 0,
            0, 48, 5, /* 371: struct.ecdsa_method */
            	11, 0,
            	384, 8,
            	387, 16,
            	390, 24,
            	11, 40,
            4097, 8, 0, /* 384: pointer.func */
            4097, 8, 0, /* 387: pointer.func */
            4097, 8, 0, /* 390: pointer.func */
            1, 8, 1, /* 393: pointer.struct.rand_meth_st */
            	398, 0,
            0, 48, 6, /* 398: struct.rand_meth_st */
            	413, 0,
            	416, 8,
            	419, 16,
            	422, 24,
            	416, 32,
            	425, 40,
            4097, 8, 0, /* 413: pointer.func */
            4097, 8, 0, /* 416: pointer.func */
            4097, 8, 0, /* 419: pointer.func */
            4097, 8, 0, /* 422: pointer.func */
            4097, 8, 0, /* 425: pointer.func */
            1, 8, 1, /* 428: pointer.struct.store_method_st */
            	433, 0,
            0, 0, 0, /* 433: struct.store_method_st */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            4097, 8, 0, /* 442: pointer.func */
            4097, 8, 0, /* 445: pointer.func */
            4097, 8, 0, /* 448: pointer.func */
            4097, 8, 0, /* 451: pointer.func */
            4097, 8, 0, /* 454: pointer.func */
            4097, 8, 0, /* 457: pointer.func */
            1, 8, 1, /* 460: pointer.struct.ENGINE_CMD_DEFN_st */
            	465, 0,
            0, 32, 2, /* 465: struct.ENGINE_CMD_DEFN_st */
            	11, 8,
            	11, 16,
            0, 16, 1, /* 472: struct.crypto_ex_data_st */
            	477, 0,
            1, 8, 1, /* 477: pointer.struct.stack_st_OPENSSL_STRING */
            	482, 0,
            0, 32, 1, /* 482: struct.stack_st_OPENSSL_STRING */
            	487, 0,
            0, 32, 2, /* 487: struct.stack_st */
            	494, 8,
            	499, 24,
            1, 8, 1, /* 494: pointer.pointer.char */
            	11, 0,
            4097, 8, 0, /* 499: pointer.func */
            1, 8, 1, /* 502: pointer.struct.evp_pkey_st */
            	52, 0,
            4097, 8, 0, /* 507: pointer.func */
            0, 0, 0, /* 510: func */
            0, 0, 0, /* 513: func */
            4097, 8, 0, /* 516: pointer.func */
            0, 0, 0, /* 519: func */
            4097, 8, 0, /* 522: pointer.func */
            0, 0, 0, /* 525: func */
            4097, 8, 0, /* 528: pointer.func */
            0, 0, 0, /* 531: func */
            4097, 8, 0, /* 534: pointer.func */
            0, 0, 0, /* 537: func */
            4097, 8, 0, /* 540: pointer.func */
            0, 0, 0, /* 543: func */
            1, 8, 1, /* 546: pointer.int */
            	551, 0,
            0, 4, 0, /* 551: int */
            4097, 8, 0, /* 554: pointer.func */
            0, 0, 0, /* 557: func */
            4097, 8, 0, /* 560: pointer.func */
            0, 0, 0, /* 563: func */
            4097, 8, 0, /* 566: pointer.func */
            0, 0, 0, /* 569: func */
            4097, 8, 0, /* 572: pointer.func */
            0, 0, 0, /* 575: func */
            0, 0, 0, /* 578: func */
            0, 0, 0, /* 581: func */
            0, 0, 0, /* 584: func */
            0, 0, 0, /* 587: func */
            0, 0, 0, /* 590: func */
            0, 0, 0, /* 593: func */
            0, 0, 0, /* 596: func */
            0, 0, 0, /* 599: func */
            0, 0, 0, /* 602: func */
            0, 0, 0, /* 605: func */
            4097, 8, 0, /* 608: pointer.func */
            0, 0, 0, /* 611: func */
            0, 0, 0, /* 614: func */
            0, 0, 0, /* 617: func */
            0, 0, 0, /* 620: func */
            0, 0, 0, /* 623: func */
            4097, 8, 0, /* 626: pointer.func */
            0, 0, 0, /* 629: func */
            4097, 8, 0, /* 632: pointer.func */
            0, 0, 0, /* 635: func */
            0, 120, 8, /* 638: struct.env_md_st */
            	657, 24,
            	626, 32,
            	632, 40,
            	660, 48,
            	657, 56,
            	608, 64,
            	663, 72,
            	666, 112,
            4097, 8, 0, /* 657: pointer.func */
            4097, 8, 0, /* 660: pointer.func */
            4097, 8, 0, /* 663: pointer.func */
            4097, 8, 0, /* 666: pointer.func */
            0, 0, 0, /* 669: func */
            0, 0, 0, /* 672: func */
            0, 48, 5, /* 675: struct.env_md_ctx_st */
            	688, 0,
            	151, 8,
            	0, 24,
            	693, 32,
            	626, 40,
            1, 8, 1, /* 688: pointer.struct.env_md_st */
            	638, 0,
            1, 8, 1, /* 693: pointer.struct.evp_pkey_ctx_st */
            	698, 0,
            0, 80, 8, /* 698: struct.evp_pkey_ctx_st */
            	717, 0,
            	151, 8,
            	502, 16,
            	502, 24,
            	11, 40,
            	11, 48,
            	119, 56,
            	546, 64,
            1, 8, 1, /* 717: pointer.struct.evp_pkey_method_st */
            	722, 0,
            0, 208, 25, /* 722: struct.evp_pkey_method_st */
            	119, 8,
            	775, 16,
            	572, 24,
            	119, 32,
            	566, 40,
            	119, 48,
            	566, 56,
            	119, 64,
            	560, 72,
            	119, 80,
            	554, 88,
            	119, 96,
            	560, 104,
            	540, 112,
            	534, 120,
            	540, 128,
            	528, 136,
            	119, 144,
            	560, 152,
            	119, 160,
            	560, 168,
            	119, 176,
            	522, 184,
            	516, 192,
            	507, 200,
            4097, 8, 0, /* 775: pointer.func */
            0, 288, 4, /* 778: struct.hmac_ctx_st */
            	688, 0,
            	675, 8,
            	675, 56,
            	675, 104,
            0, 0, 0, /* 789: func */
            0, 0, 0, /* 792: func */
            0, 0, 0, /* 795: func */
            0, 0, 0, /* 798: func */
            0, 8, 0, /* 801: long */
            0, 0, 0, /* 804: func */
            0, 20, 0, /* 807: array[5].int */
            0, 0, 0, /* 810: func */
            0, 0, 0, /* 813: func */
            0, 0, 0, /* 816: func */
            0, 1, 0, /* 819: char */
            0, 0, 0, /* 822: func */
            0, 0, 0, /* 825: func */
            0, 0, 0, /* 828: func */
            0, 0, 0, /* 831: func */
            0, 0, 0, /* 834: func */
            0, 0, 0, /* 837: func */
            0, 0, 0, /* 840: func */
            0, 0, 0, /* 843: func */
            1, 8, 1, /* 846: pointer.struct.hmac_ctx_st */
            	778, 0,
            0, 0, 0, /* 851: func */
            0, 0, 0, /* 854: func */
            0, 0, 0, /* 857: func */
            0, 0, 0, /* 860: func */
            0, 0, 0, /* 863: func */
            0, 0, 0, /* 866: func */
            0, 0, 0, /* 869: func */
            0, 0, 0, /* 872: func */
            0, 0, 0, /* 875: func */
            0, 0, 0, /* 878: func */
            0, 0, 0, /* 881: func */
            0, 0, 0, /* 884: func */
            0, 0, 0, /* 887: func */
            0, 0, 0, /* 890: func */
        },
        .arg_entity_index = { 846, 0, 551, 688, 151, },
        .ret_entity_index = 551,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_arg(args_addr, arg_e);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    HMAC_CTX * new_arg_a = *((HMAC_CTX * *)new_args->args[0]);

    const void * new_arg_b = *((const void * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    const EVP_MD * new_arg_d = *((const EVP_MD * *)new_args->args[3]);

    ENGINE * new_arg_e = *((ENGINE * *)new_args->args[4]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
    orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
    *new_ret_ptr = (*orig_HMAC_Init_ex)(new_arg_a,new_arg_b,new_arg_c,new_arg_d,new_arg_e);

    syscall(889);

    return ret;
}

