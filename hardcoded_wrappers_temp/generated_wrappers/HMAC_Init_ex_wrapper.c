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

int HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
{
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 8, 1, /* 0: struct.fnames */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	10, 0,
            0, 1, 0, /* 10: char */
            0, 0, 0, /* 13: func */
            1, 8, 1, /* 16: pointer.func */
            	21, 0,
            0, 0, 0, /* 21: func */
            0, 0, 0, /* 24: func */
            1, 8, 1, /* 27: pointer.func */
            	24, 0,
            1, 8, 1, /* 32: pointer.func */
            	37, 0,
            0, 0, 0, /* 37: func */
            0, 0, 0, /* 40: func */
            0, 128, 128, /* 43: array[128].char */
            	10, 0,
            	10, 1,
            	10, 2,
            	10, 3,
            	10, 4,
            	10, 5,
            	10, 6,
            	10, 7,
            	10, 8,
            	10, 9,
            	10, 10,
            	10, 11,
            	10, 12,
            	10, 13,
            	10, 14,
            	10, 15,
            	10, 16,
            	10, 17,
            	10, 18,
            	10, 19,
            	10, 20,
            	10, 21,
            	10, 22,
            	10, 23,
            	10, 24,
            	10, 25,
            	10, 26,
            	10, 27,
            	10, 28,
            	10, 29,
            	10, 30,
            	10, 31,
            	10, 32,
            	10, 33,
            	10, 34,
            	10, 35,
            	10, 36,
            	10, 37,
            	10, 38,
            	10, 39,
            	10, 40,
            	10, 41,
            	10, 42,
            	10, 43,
            	10, 44,
            	10, 45,
            	10, 46,
            	10, 47,
            	10, 48,
            	10, 49,
            	10, 50,
            	10, 51,
            	10, 52,
            	10, 53,
            	10, 54,
            	10, 55,
            	10, 56,
            	10, 57,
            	10, 58,
            	10, 59,
            	10, 60,
            	10, 61,
            	10, 62,
            	10, 63,
            	10, 64,
            	10, 65,
            	10, 66,
            	10, 67,
            	10, 68,
            	10, 69,
            	10, 70,
            	10, 71,
            	10, 72,
            	10, 73,
            	10, 74,
            	10, 75,
            	10, 76,
            	10, 77,
            	10, 78,
            	10, 79,
            	10, 80,
            	10, 81,
            	10, 82,
            	10, 83,
            	10, 84,
            	10, 85,
            	10, 86,
            	10, 87,
            	10, 88,
            	10, 89,
            	10, 90,
            	10, 91,
            	10, 92,
            	10, 93,
            	10, 94,
            	10, 95,
            	10, 96,
            	10, 97,
            	10, 98,
            	10, 99,
            	10, 100,
            	10, 101,
            	10, 102,
            	10, 103,
            	10, 104,
            	10, 105,
            	10, 106,
            	10, 107,
            	10, 108,
            	10, 109,
            	10, 110,
            	10, 111,
            	10, 112,
            	10, 113,
            	10, 114,
            	10, 115,
            	10, 116,
            	10, 117,
            	10, 118,
            	10, 119,
            	10, 120,
            	10, 121,
            	10, 122,
            	10, 123,
            	10, 124,
            	10, 125,
            	10, 126,
            	10, 127,
            1, 8, 1, /* 302: pointer.func */
            	40, 0,
            0, 0, 0, /* 307: func */
            1, 8, 1, /* 310: pointer.func */
            	307, 0,
            0, 0, 0, /* 315: func */
            1, 8, 1, /* 318: pointer.func */
            	315, 0,
            0, 0, 0, /* 323: func */
            1, 8, 1, /* 326: pointer.func */
            	323, 0,
            1, 8, 1, /* 331: pointer.func */
            	336, 0,
            0, 0, 0, /* 336: func */
            1, 8, 1, /* 339: pointer.func */
            	344, 0,
            0, 0, 0, /* 344: func */
            0, 0, 0, /* 347: func */
            1, 8, 1, /* 350: pointer.func */
            	347, 0,
            0, 0, 0, /* 355: func */
            1, 8, 1, /* 358: pointer.func */
            	355, 0,
            0, 0, 0, /* 363: func */
            0, 208, 27, /* 366: struct.evp_pkey_asn1_method_st */
            	423, 0,
            	423, 4,
            	426, 8,
            	5, 16,
            	5, 24,
            	429, 32,
            	437, 40,
            	358, 48,
            	350, 56,
            	339, 64,
            	331, 72,
            	350, 80,
            	326, 88,
            	326, 96,
            	318, 104,
            	310, 112,
            	326, 120,
            	358, 128,
            	358, 136,
            	350, 144,
            	302, 152,
            	32, 160,
            	27, 168,
            	318, 176,
            	310, 184,
            	16, 192,
            	442, 200,
            0, 4, 0, /* 423: int */
            0, 8, 0, /* 426: long */
            1, 8, 1, /* 429: pointer.struct.unnamed */
            	434, 0,
            0, 0, 0, /* 434: struct.unnamed */
            1, 8, 1, /* 437: pointer.func */
            	363, 0,
            1, 8, 1, /* 442: pointer.func */
            	13, 0,
            1, 8, 1, /* 447: pointer.struct.evp_pkey_asn1_method_st */
            	366, 0,
            0, 56, 8, /* 452: struct.evp_pkey_st */
            	423, 0,
            	423, 4,
            	423, 8,
            	447, 16,
            	471, 24,
            	0, 32,
            	423, 40,
            	994, 48,
            1, 8, 1, /* 471: pointer.struct.engine_st */
            	476, 0,
            0, 216, 27, /* 476: struct.engine_st */
            	5, 0,
            	5, 8,
            	533, 16,
            	625, 24,
            	713, 32,
            	771, 40,
            	795, 48,
            	839, 56,
            	899, 64,
            	907, 72,
            	915, 80,
            	923, 88,
            	931, 96,
            	939, 104,
            	939, 112,
            	939, 120,
            	947, 128,
            	955, 136,
            	955, 144,
            	963, 152,
            	971, 160,
            	423, 168,
            	423, 172,
            	423, 176,
            	987, 184,
            	471, 200,
            	471, 208,
            1, 8, 1, /* 533: pointer.struct.rsa_meth_st */
            	538, 0,
            0, 112, 14, /* 538: struct.rsa_meth_st */
            	5, 0,
            	569, 8,
            	569, 16,
            	569, 24,
            	569, 32,
            	577, 40,
            	585, 48,
            	593, 56,
            	593, 64,
            	423, 72,
            	5, 80,
            	601, 88,
            	609, 96,
            	617, 104,
            1, 8, 1, /* 569: pointer.func */
            	574, 0,
            0, 0, 0, /* 574: func */
            1, 8, 1, /* 577: pointer.func */
            	582, 0,
            0, 0, 0, /* 582: func */
            1, 8, 1, /* 585: pointer.func */
            	590, 0,
            0, 0, 0, /* 590: func */
            1, 8, 1, /* 593: pointer.func */
            	598, 0,
            0, 0, 0, /* 598: func */
            1, 8, 1, /* 601: pointer.func */
            	606, 0,
            0, 0, 0, /* 606: func */
            1, 8, 1, /* 609: pointer.func */
            	614, 0,
            0, 0, 0, /* 614: func */
            1, 8, 1, /* 617: pointer.func */
            	622, 0,
            0, 0, 0, /* 622: func */
            1, 8, 1, /* 625: pointer.struct.dsa_method.1040 */
            	630, 0,
            0, 96, 12, /* 630: struct.dsa_method.1040 */
            	5, 0,
            	657, 8,
            	665, 16,
            	673, 24,
            	681, 32,
            	689, 40,
            	697, 48,
            	697, 56,
            	423, 64,
            	5, 72,
            	705, 80,
            	697, 88,
            1, 8, 1, /* 657: pointer.func */
            	662, 0,
            0, 0, 0, /* 662: func */
            1, 8, 1, /* 665: pointer.func */
            	670, 0,
            0, 0, 0, /* 670: func */
            1, 8, 1, /* 673: pointer.func */
            	678, 0,
            0, 0, 0, /* 678: func */
            1, 8, 1, /* 681: pointer.func */
            	686, 0,
            0, 0, 0, /* 686: func */
            1, 8, 1, /* 689: pointer.func */
            	694, 0,
            0, 0, 0, /* 694: func */
            1, 8, 1, /* 697: pointer.func */
            	702, 0,
            0, 0, 0, /* 702: func */
            1, 8, 1, /* 705: pointer.func */
            	710, 0,
            0, 0, 0, /* 710: func */
            1, 8, 1, /* 713: pointer.struct.dh_method */
            	718, 0,
            0, 72, 9, /* 718: struct.dh_method */
            	5, 0,
            	739, 8,
            	747, 16,
            	755, 24,
            	739, 32,
            	739, 40,
            	423, 48,
            	5, 56,
            	763, 64,
            1, 8, 1, /* 739: pointer.func */
            	744, 0,
            0, 0, 0, /* 744: func */
            1, 8, 1, /* 747: pointer.func */
            	752, 0,
            0, 0, 0, /* 752: func */
            1, 8, 1, /* 755: pointer.func */
            	760, 0,
            0, 0, 0, /* 760: func */
            1, 8, 1, /* 763: pointer.func */
            	768, 0,
            0, 0, 0, /* 768: func */
            1, 8, 1, /* 771: pointer.struct.ecdh_method */
            	776, 0,
            0, 32, 4, /* 776: struct.ecdh_method */
            	5, 0,
            	787, 8,
            	423, 16,
            	5, 24,
            1, 8, 1, /* 787: pointer.func */
            	792, 0,
            0, 0, 0, /* 792: func */
            1, 8, 1, /* 795: pointer.struct.ecdsa_method */
            	800, 0,
            0, 48, 6, /* 800: struct.ecdsa_method */
            	5, 0,
            	815, 8,
            	823, 16,
            	831, 24,
            	423, 32,
            	5, 40,
            1, 8, 1, /* 815: pointer.func */
            	820, 0,
            0, 0, 0, /* 820: func */
            1, 8, 1, /* 823: pointer.func */
            	828, 0,
            0, 0, 0, /* 828: func */
            1, 8, 1, /* 831: pointer.func */
            	836, 0,
            0, 0, 0, /* 836: func */
            1, 8, 1, /* 839: pointer.struct.rand_meth_st */
            	844, 0,
            0, 48, 6, /* 844: struct.rand_meth_st */
            	859, 0,
            	867, 8,
            	875, 16,
            	883, 24,
            	867, 32,
            	891, 40,
            1, 8, 1, /* 859: pointer.func */
            	864, 0,
            0, 0, 0, /* 864: func */
            1, 8, 1, /* 867: pointer.func */
            	872, 0,
            0, 0, 0, /* 872: func */
            1, 8, 1, /* 875: pointer.func */
            	880, 0,
            0, 0, 0, /* 880: func */
            1, 8, 1, /* 883: pointer.func */
            	888, 0,
            0, 0, 0, /* 888: func */
            1, 8, 1, /* 891: pointer.func */
            	896, 0,
            0, 0, 0, /* 896: func */
            1, 8, 1, /* 899: pointer.struct.store_method_st */
            	904, 0,
            0, 0, 0, /* 904: struct.store_method_st */
            1, 8, 1, /* 907: pointer.func */
            	912, 0,
            0, 0, 0, /* 912: func */
            1, 8, 1, /* 915: pointer.func */
            	920, 0,
            0, 0, 0, /* 920: func */
            1, 8, 1, /* 923: pointer.func */
            	928, 0,
            0, 0, 0, /* 928: func */
            1, 8, 1, /* 931: pointer.func */
            	936, 0,
            0, 0, 0, /* 936: func */
            1, 8, 1, /* 939: pointer.func */
            	944, 0,
            0, 0, 0, /* 944: func */
            1, 8, 1, /* 947: pointer.func */
            	952, 0,
            0, 0, 0, /* 952: func */
            1, 8, 1, /* 955: pointer.func */
            	960, 0,
            0, 0, 0, /* 960: func */
            1, 8, 1, /* 963: pointer.func */
            	968, 0,
            0, 0, 0, /* 968: func */
            1, 8, 1, /* 971: pointer.struct.ENGINE_CMD_DEFN_st */
            	976, 0,
            0, 32, 4, /* 976: struct.ENGINE_CMD_DEFN_st */
            	423, 0,
            	5, 8,
            	5, 16,
            	423, 24,
            0, 16, 2, /* 987: struct.crypto_ex_data_st */
            	994, 0,
            	423, 8,
            1, 8, 1, /* 994: pointer.struct.stack_st_OPENSSL_STRING */
            	999, 0,
            0, 32, 1, /* 999: struct.stack_st_OPENSSL_STRING */
            	1004, 0,
            0, 32, 5, /* 1004: struct.stack_st */
            	423, 0,
            	1017, 8,
            	423, 16,
            	423, 20,
            	1022, 24,
            1, 8, 1, /* 1017: pointer.pointer.char */
            	5, 0,
            1, 8, 1, /* 1022: pointer.func */
            	1027, 0,
            0, 0, 0, /* 1027: func */
            0, 0, 0, /* 1030: func */
            1, 8, 1, /* 1033: pointer.func */
            	1030, 0,
            1, 8, 1, /* 1038: pointer.func */
            	1043, 0,
            0, 0, 0, /* 1043: func */
            0, 0, 0, /* 1046: func */
            1, 8, 1, /* 1049: pointer.func */
            	1046, 0,
            0, 0, 0, /* 1054: func */
            1, 8, 1, /* 1057: pointer.func */
            	1062, 0,
            0, 0, 0, /* 1062: func */
            1, 8, 1, /* 1065: pointer.func */
            	1070, 0,
            0, 0, 0, /* 1070: func */
            1, 8, 1, /* 1073: pointer.func */
            	1078, 0,
            0, 0, 0, /* 1078: func */
            0, 0, 0, /* 1081: func */
            1, 8, 1, /* 1084: pointer.func */
            	1089, 0,
            0, 0, 0, /* 1089: func */
            1, 8, 1, /* 1092: pointer.func */
            	1081, 0,
            1, 8, 1, /* 1097: pointer.func */
            	1102, 0,
            0, 0, 0, /* 1102: func */
            1, 8, 1, /* 1105: pointer.func */
            	1110, 0,
            0, 0, 0, /* 1110: func */
            1, 8, 1, /* 1113: pointer.struct.evp_pkey_st */
            	452, 0,
            0, 0, 0, /* 1118: func */
            0, 0, 0, /* 1121: func */
            1, 8, 1, /* 1124: pointer.func */
            	1054, 0,
            0, 120, 15, /* 1129: struct.env_md_st */
            	423, 0,
            	423, 4,
            	423, 8,
            	426, 16,
            	1162, 24,
            	1170, 32,
            	1105, 40,
            	1175, 48,
            	1162, 56,
            	1183, 64,
            	1188, 72,
            	1196, 80,
            	423, 100,
            	423, 104,
            	1209, 112,
            1, 8, 1, /* 1162: pointer.func */
            	1167, 0,
            0, 0, 0, /* 1167: func */
            1, 8, 1, /* 1170: pointer.func */
            	1121, 0,
            1, 8, 1, /* 1175: pointer.func */
            	1180, 0,
            0, 0, 0, /* 1180: func */
            1, 8, 1, /* 1183: pointer.func */
            	1118, 0,
            1, 8, 1, /* 1188: pointer.func */
            	1193, 0,
            0, 0, 0, /* 1193: func */
            0, 20, 5, /* 1196: array[5].int */
            	423, 0,
            	423, 4,
            	423, 8,
            	423, 12,
            	423, 16,
            1, 8, 1, /* 1209: pointer.func */
            	1214, 0,
            0, 0, 0, /* 1214: func */
            1, 8, 1, /* 1217: pointer.struct.env_md_st */
            	1129, 0,
            0, 48, 6, /* 1222: struct.env_md_ctx_st */
            	1217, 0,
            	471, 8,
            	426, 16,
            	5, 24,
            	1237, 32,
            	1170, 40,
            1, 8, 1, /* 1237: pointer.struct.evp_pkey_ctx_st */
            	1242, 0,
            0, 80, 10, /* 1242: struct.evp_pkey_ctx_st */
            	1265, 0,
            	471, 8,
            	1113, 16,
            	1113, 24,
            	423, 32,
            	5, 40,
            	5, 48,
            	429, 56,
            	1335, 64,
            	423, 72,
            1, 8, 1, /* 1265: pointer.struct.evp_pkey_method_st */
            	1270, 0,
            0, 208, 27, /* 1270: struct.evp_pkey_method_st */
            	423, 0,
            	423, 4,
            	429, 8,
            	1327, 16,
            	1092, 24,
            	429, 32,
            	1073, 40,
            	429, 48,
            	1073, 56,
            	429, 64,
            	1065, 72,
            	429, 80,
            	1057, 88,
            	429, 96,
            	1065, 104,
            	1124, 112,
            	1049, 120,
            	1124, 128,
            	1097, 136,
            	429, 144,
            	1065, 152,
            	429, 160,
            	1065, 168,
            	429, 176,
            	1084, 184,
            	1038, 192,
            	1033, 200,
            1, 8, 1, /* 1327: pointer.func */
            	1332, 0,
            0, 0, 0, /* 1332: func */
            1, 8, 1, /* 1335: pointer.int */
            	423, 0,
            0, 288, 6, /* 1340: struct.hmac_ctx_st */
            	1217, 0,
            	1222, 8,
            	1222, 56,
            	1222, 104,
            	423, 152,
            	43, 156,
            1, 8, 1, /* 1355: pointer.struct.hmac_ctx_st */
            	1340, 0,
        },
        .arg_entity_index = { 1355, 5, 423, 1217, 471, },
        .ret_entity_index = 423,
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

