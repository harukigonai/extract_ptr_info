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

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d);

int EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_SignFinal called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    else {
        int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
        orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
        return orig_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    }
}

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.dsa_st */
            	5, 0,
            0, 136, 11, /* 5: struct.dsa_st */
            	30, 24,
            	30, 32,
            	30, 40,
            	30, 48,
            	30, 56,
            	30, 64,
            	30, 72,
            	53, 88,
            	67, 104,
            	102, 120,
            	158, 128,
            1, 8, 1, /* 30: pointer.struct.bignum_st */
            	35, 0,
            0, 24, 1, /* 35: struct.bignum_st */
            	40, 0,
            8884099, 8, 2, /* 40: pointer_to_array_of_pointers_to_stack */
            	47, 0,
            	50, 12,
            0, 4, 0, /* 47: unsigned int */
            0, 4, 0, /* 50: int */
            1, 8, 1, /* 53: pointer.struct.bn_mont_ctx_st */
            	58, 0,
            0, 96, 3, /* 58: struct.bn_mont_ctx_st */
            	35, 8,
            	35, 32,
            	35, 56,
            0, 16, 1, /* 67: struct.crypto_ex_data_st */
            	72, 0,
            1, 8, 1, /* 72: pointer.struct.stack_st_void */
            	77, 0,
            0, 32, 1, /* 77: struct.stack_st_void */
            	82, 0,
            0, 32, 2, /* 82: struct.stack_st */
            	89, 8,
            	99, 24,
            1, 8, 1, /* 89: pointer.pointer.char */
            	94, 0,
            1, 8, 1, /* 94: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 99: pointer.func */
            1, 8, 1, /* 102: pointer.struct.dsa_method */
            	107, 0,
            0, 96, 11, /* 107: struct.dsa_method */
            	132, 0,
            	137, 8,
            	140, 16,
            	143, 24,
            	146, 32,
            	149, 40,
            	152, 48,
            	152, 56,
            	94, 72,
            	155, 80,
            	152, 88,
            1, 8, 1, /* 132: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 137: pointer.func */
            8884097, 8, 0, /* 140: pointer.func */
            8884097, 8, 0, /* 143: pointer.func */
            8884097, 8, 0, /* 146: pointer.func */
            8884097, 8, 0, /* 149: pointer.func */
            8884097, 8, 0, /* 152: pointer.func */
            8884097, 8, 0, /* 155: pointer.func */
            1, 8, 1, /* 158: pointer.struct.engine_st */
            	163, 0,
            0, 216, 24, /* 163: struct.engine_st */
            	132, 0,
            	132, 8,
            	214, 16,
            	269, 24,
            	320, 32,
            	356, 40,
            	373, 48,
            	400, 56,
            	435, 64,
            	443, 72,
            	446, 80,
            	449, 88,
            	452, 96,
            	455, 104,
            	455, 112,
            	455, 120,
            	458, 128,
            	461, 136,
            	461, 144,
            	464, 152,
            	467, 160,
            	479, 184,
            	501, 200,
            	501, 208,
            1, 8, 1, /* 214: pointer.struct.rsa_meth_st */
            	219, 0,
            0, 112, 13, /* 219: struct.rsa_meth_st */
            	132, 0,
            	248, 8,
            	248, 16,
            	248, 24,
            	248, 32,
            	251, 40,
            	254, 48,
            	257, 56,
            	257, 64,
            	94, 80,
            	260, 88,
            	263, 96,
            	266, 104,
            8884097, 8, 0, /* 248: pointer.func */
            8884097, 8, 0, /* 251: pointer.func */
            8884097, 8, 0, /* 254: pointer.func */
            8884097, 8, 0, /* 257: pointer.func */
            8884097, 8, 0, /* 260: pointer.func */
            8884097, 8, 0, /* 263: pointer.func */
            8884097, 8, 0, /* 266: pointer.func */
            1, 8, 1, /* 269: pointer.struct.dsa_method */
            	274, 0,
            0, 96, 11, /* 274: struct.dsa_method */
            	132, 0,
            	299, 8,
            	302, 16,
            	305, 24,
            	308, 32,
            	311, 40,
            	314, 48,
            	314, 56,
            	94, 72,
            	317, 80,
            	314, 88,
            8884097, 8, 0, /* 299: pointer.func */
            8884097, 8, 0, /* 302: pointer.func */
            8884097, 8, 0, /* 305: pointer.func */
            8884097, 8, 0, /* 308: pointer.func */
            8884097, 8, 0, /* 311: pointer.func */
            8884097, 8, 0, /* 314: pointer.func */
            8884097, 8, 0, /* 317: pointer.func */
            1, 8, 1, /* 320: pointer.struct.dh_method */
            	325, 0,
            0, 72, 8, /* 325: struct.dh_method */
            	132, 0,
            	344, 8,
            	347, 16,
            	350, 24,
            	344, 32,
            	344, 40,
            	94, 56,
            	353, 64,
            8884097, 8, 0, /* 344: pointer.func */
            8884097, 8, 0, /* 347: pointer.func */
            8884097, 8, 0, /* 350: pointer.func */
            8884097, 8, 0, /* 353: pointer.func */
            1, 8, 1, /* 356: pointer.struct.ecdh_method */
            	361, 0,
            0, 32, 3, /* 361: struct.ecdh_method */
            	132, 0,
            	370, 8,
            	94, 24,
            8884097, 8, 0, /* 370: pointer.func */
            1, 8, 1, /* 373: pointer.struct.ecdsa_method */
            	378, 0,
            0, 48, 5, /* 378: struct.ecdsa_method */
            	132, 0,
            	391, 8,
            	394, 16,
            	397, 24,
            	94, 40,
            8884097, 8, 0, /* 391: pointer.func */
            8884097, 8, 0, /* 394: pointer.func */
            8884097, 8, 0, /* 397: pointer.func */
            1, 8, 1, /* 400: pointer.struct.rand_meth_st */
            	405, 0,
            0, 48, 6, /* 405: struct.rand_meth_st */
            	420, 0,
            	423, 8,
            	426, 16,
            	429, 24,
            	423, 32,
            	432, 40,
            8884097, 8, 0, /* 420: pointer.func */
            8884097, 8, 0, /* 423: pointer.func */
            8884097, 8, 0, /* 426: pointer.func */
            8884097, 8, 0, /* 429: pointer.func */
            8884097, 8, 0, /* 432: pointer.func */
            1, 8, 1, /* 435: pointer.struct.store_method_st */
            	440, 0,
            0, 0, 0, /* 440: struct.store_method_st */
            8884097, 8, 0, /* 443: pointer.func */
            8884097, 8, 0, /* 446: pointer.func */
            8884097, 8, 0, /* 449: pointer.func */
            8884097, 8, 0, /* 452: pointer.func */
            8884097, 8, 0, /* 455: pointer.func */
            8884097, 8, 0, /* 458: pointer.func */
            8884097, 8, 0, /* 461: pointer.func */
            8884097, 8, 0, /* 464: pointer.func */
            1, 8, 1, /* 467: pointer.struct.ENGINE_CMD_DEFN_st */
            	472, 0,
            0, 32, 2, /* 472: struct.ENGINE_CMD_DEFN_st */
            	132, 8,
            	132, 16,
            0, 16, 1, /* 479: struct.crypto_ex_data_st */
            	484, 0,
            1, 8, 1, /* 484: pointer.struct.stack_st_void */
            	489, 0,
            0, 32, 1, /* 489: struct.stack_st_void */
            	494, 0,
            0, 32, 2, /* 494: struct.stack_st */
            	89, 8,
            	99, 24,
            1, 8, 1, /* 501: pointer.struct.engine_st */
            	163, 0,
            1, 8, 1, /* 506: pointer.struct.rsa_st */
            	511, 0,
            0, 168, 17, /* 511: struct.rsa_st */
            	548, 16,
            	603, 24,
            	608, 32,
            	608, 40,
            	608, 48,
            	608, 56,
            	608, 64,
            	608, 72,
            	608, 80,
            	608, 88,
            	625, 96,
            	647, 120,
            	647, 128,
            	647, 136,
            	94, 144,
            	661, 152,
            	661, 160,
            1, 8, 1, /* 548: pointer.struct.rsa_meth_st */
            	553, 0,
            0, 112, 13, /* 553: struct.rsa_meth_st */
            	132, 0,
            	582, 8,
            	582, 16,
            	582, 24,
            	582, 32,
            	585, 40,
            	588, 48,
            	591, 56,
            	591, 64,
            	94, 80,
            	594, 88,
            	597, 96,
            	600, 104,
            8884097, 8, 0, /* 582: pointer.func */
            8884097, 8, 0, /* 585: pointer.func */
            8884097, 8, 0, /* 588: pointer.func */
            8884097, 8, 0, /* 591: pointer.func */
            8884097, 8, 0, /* 594: pointer.func */
            8884097, 8, 0, /* 597: pointer.func */
            8884097, 8, 0, /* 600: pointer.func */
            1, 8, 1, /* 603: pointer.struct.engine_st */
            	163, 0,
            1, 8, 1, /* 608: pointer.struct.bignum_st */
            	613, 0,
            0, 24, 1, /* 613: struct.bignum_st */
            	618, 0,
            8884099, 8, 2, /* 618: pointer_to_array_of_pointers_to_stack */
            	47, 0,
            	50, 12,
            0, 16, 1, /* 625: struct.crypto_ex_data_st */
            	630, 0,
            1, 8, 1, /* 630: pointer.struct.stack_st_void */
            	635, 0,
            0, 32, 1, /* 635: struct.stack_st_void */
            	640, 0,
            0, 32, 2, /* 640: struct.stack_st */
            	89, 8,
            	99, 24,
            1, 8, 1, /* 647: pointer.struct.bn_mont_ctx_st */
            	652, 0,
            0, 96, 3, /* 652: struct.bn_mont_ctx_st */
            	613, 8,
            	613, 32,
            	613, 56,
            1, 8, 1, /* 661: pointer.struct.bn_blinding_st */
            	666, 0,
            0, 88, 7, /* 666: struct.bn_blinding_st */
            	683, 0,
            	683, 8,
            	683, 16,
            	683, 24,
            	700, 40,
            	708, 72,
            	722, 80,
            1, 8, 1, /* 683: pointer.struct.bignum_st */
            	688, 0,
            0, 24, 1, /* 688: struct.bignum_st */
            	693, 0,
            8884099, 8, 2, /* 693: pointer_to_array_of_pointers_to_stack */
            	47, 0,
            	50, 12,
            0, 16, 1, /* 700: struct.crypto_threadid_st */
            	705, 0,
            0, 8, 0, /* 705: pointer.void */
            1, 8, 1, /* 708: pointer.struct.bn_mont_ctx_st */
            	713, 0,
            0, 96, 3, /* 713: struct.bn_mont_ctx_st */
            	688, 8,
            	688, 32,
            	688, 56,
            8884097, 8, 0, /* 722: pointer.func */
            0, 8, 5, /* 725: union.unknown */
            	94, 0,
            	506, 0,
            	0, 0,
            	738, 0,
            	872, 0,
            1, 8, 1, /* 738: pointer.struct.dh_st */
            	743, 0,
            0, 144, 12, /* 743: struct.dh_st */
            	770, 8,
            	770, 16,
            	770, 32,
            	770, 40,
            	787, 56,
            	770, 64,
            	770, 72,
            	801, 80,
            	770, 96,
            	809, 112,
            	831, 128,
            	867, 136,
            1, 8, 1, /* 770: pointer.struct.bignum_st */
            	775, 0,
            0, 24, 1, /* 775: struct.bignum_st */
            	780, 0,
            8884099, 8, 2, /* 780: pointer_to_array_of_pointers_to_stack */
            	47, 0,
            	50, 12,
            1, 8, 1, /* 787: pointer.struct.bn_mont_ctx_st */
            	792, 0,
            0, 96, 3, /* 792: struct.bn_mont_ctx_st */
            	775, 8,
            	775, 32,
            	775, 56,
            1, 8, 1, /* 801: pointer.unsigned char */
            	806, 0,
            0, 1, 0, /* 806: unsigned char */
            0, 16, 1, /* 809: struct.crypto_ex_data_st */
            	814, 0,
            1, 8, 1, /* 814: pointer.struct.stack_st_void */
            	819, 0,
            0, 32, 1, /* 819: struct.stack_st_void */
            	824, 0,
            0, 32, 2, /* 824: struct.stack_st */
            	89, 8,
            	99, 24,
            1, 8, 1, /* 831: pointer.struct.dh_method */
            	836, 0,
            0, 72, 8, /* 836: struct.dh_method */
            	132, 0,
            	855, 8,
            	858, 16,
            	861, 24,
            	855, 32,
            	855, 40,
            	94, 56,
            	864, 64,
            8884097, 8, 0, /* 855: pointer.func */
            8884097, 8, 0, /* 858: pointer.func */
            8884097, 8, 0, /* 861: pointer.func */
            8884097, 8, 0, /* 864: pointer.func */
            1, 8, 1, /* 867: pointer.struct.engine_st */
            	163, 0,
            1, 8, 1, /* 872: pointer.struct.ec_key_st */
            	877, 0,
            0, 56, 4, /* 877: struct.ec_key_st */
            	888, 8,
            	1336, 16,
            	1341, 24,
            	1358, 48,
            1, 8, 1, /* 888: pointer.struct.ec_group_st */
            	893, 0,
            0, 232, 12, /* 893: struct.ec_group_st */
            	920, 0,
            	1092, 8,
            	1292, 16,
            	1292, 40,
            	801, 80,
            	1304, 96,
            	1292, 104,
            	1292, 152,
            	1292, 176,
            	705, 208,
            	705, 216,
            	1333, 224,
            1, 8, 1, /* 920: pointer.struct.ec_method_st */
            	925, 0,
            0, 304, 37, /* 925: struct.ec_method_st */
            	1002, 8,
            	1005, 16,
            	1005, 24,
            	1008, 32,
            	1011, 40,
            	1014, 48,
            	1017, 56,
            	1020, 64,
            	1023, 72,
            	1026, 80,
            	1026, 88,
            	1029, 96,
            	1032, 104,
            	1035, 112,
            	1038, 120,
            	1041, 128,
            	1044, 136,
            	1047, 144,
            	1050, 152,
            	1053, 160,
            	1056, 168,
            	1059, 176,
            	1062, 184,
            	1065, 192,
            	1068, 200,
            	1071, 208,
            	1062, 216,
            	1074, 224,
            	1077, 232,
            	1080, 240,
            	1017, 248,
            	1083, 256,
            	1086, 264,
            	1083, 272,
            	1086, 280,
            	1086, 288,
            	1089, 296,
            8884097, 8, 0, /* 1002: pointer.func */
            8884097, 8, 0, /* 1005: pointer.func */
            8884097, 8, 0, /* 1008: pointer.func */
            8884097, 8, 0, /* 1011: pointer.func */
            8884097, 8, 0, /* 1014: pointer.func */
            8884097, 8, 0, /* 1017: pointer.func */
            8884097, 8, 0, /* 1020: pointer.func */
            8884097, 8, 0, /* 1023: pointer.func */
            8884097, 8, 0, /* 1026: pointer.func */
            8884097, 8, 0, /* 1029: pointer.func */
            8884097, 8, 0, /* 1032: pointer.func */
            8884097, 8, 0, /* 1035: pointer.func */
            8884097, 8, 0, /* 1038: pointer.func */
            8884097, 8, 0, /* 1041: pointer.func */
            8884097, 8, 0, /* 1044: pointer.func */
            8884097, 8, 0, /* 1047: pointer.func */
            8884097, 8, 0, /* 1050: pointer.func */
            8884097, 8, 0, /* 1053: pointer.func */
            8884097, 8, 0, /* 1056: pointer.func */
            8884097, 8, 0, /* 1059: pointer.func */
            8884097, 8, 0, /* 1062: pointer.func */
            8884097, 8, 0, /* 1065: pointer.func */
            8884097, 8, 0, /* 1068: pointer.func */
            8884097, 8, 0, /* 1071: pointer.func */
            8884097, 8, 0, /* 1074: pointer.func */
            8884097, 8, 0, /* 1077: pointer.func */
            8884097, 8, 0, /* 1080: pointer.func */
            8884097, 8, 0, /* 1083: pointer.func */
            8884097, 8, 0, /* 1086: pointer.func */
            8884097, 8, 0, /* 1089: pointer.func */
            1, 8, 1, /* 1092: pointer.struct.ec_point_st */
            	1097, 0,
            0, 88, 4, /* 1097: struct.ec_point_st */
            	1108, 0,
            	1280, 8,
            	1280, 32,
            	1280, 56,
            1, 8, 1, /* 1108: pointer.struct.ec_method_st */
            	1113, 0,
            0, 304, 37, /* 1113: struct.ec_method_st */
            	1190, 8,
            	1193, 16,
            	1193, 24,
            	1196, 32,
            	1199, 40,
            	1202, 48,
            	1205, 56,
            	1208, 64,
            	1211, 72,
            	1214, 80,
            	1214, 88,
            	1217, 96,
            	1220, 104,
            	1223, 112,
            	1226, 120,
            	1229, 128,
            	1232, 136,
            	1235, 144,
            	1238, 152,
            	1241, 160,
            	1244, 168,
            	1247, 176,
            	1250, 184,
            	1253, 192,
            	1256, 200,
            	1259, 208,
            	1250, 216,
            	1262, 224,
            	1265, 232,
            	1268, 240,
            	1205, 248,
            	1271, 256,
            	1274, 264,
            	1271, 272,
            	1274, 280,
            	1274, 288,
            	1277, 296,
            8884097, 8, 0, /* 1190: pointer.func */
            8884097, 8, 0, /* 1193: pointer.func */
            8884097, 8, 0, /* 1196: pointer.func */
            8884097, 8, 0, /* 1199: pointer.func */
            8884097, 8, 0, /* 1202: pointer.func */
            8884097, 8, 0, /* 1205: pointer.func */
            8884097, 8, 0, /* 1208: pointer.func */
            8884097, 8, 0, /* 1211: pointer.func */
            8884097, 8, 0, /* 1214: pointer.func */
            8884097, 8, 0, /* 1217: pointer.func */
            8884097, 8, 0, /* 1220: pointer.func */
            8884097, 8, 0, /* 1223: pointer.func */
            8884097, 8, 0, /* 1226: pointer.func */
            8884097, 8, 0, /* 1229: pointer.func */
            8884097, 8, 0, /* 1232: pointer.func */
            8884097, 8, 0, /* 1235: pointer.func */
            8884097, 8, 0, /* 1238: pointer.func */
            8884097, 8, 0, /* 1241: pointer.func */
            8884097, 8, 0, /* 1244: pointer.func */
            8884097, 8, 0, /* 1247: pointer.func */
            8884097, 8, 0, /* 1250: pointer.func */
            8884097, 8, 0, /* 1253: pointer.func */
            8884097, 8, 0, /* 1256: pointer.func */
            8884097, 8, 0, /* 1259: pointer.func */
            8884097, 8, 0, /* 1262: pointer.func */
            8884097, 8, 0, /* 1265: pointer.func */
            8884097, 8, 0, /* 1268: pointer.func */
            8884097, 8, 0, /* 1271: pointer.func */
            8884097, 8, 0, /* 1274: pointer.func */
            8884097, 8, 0, /* 1277: pointer.func */
            0, 24, 1, /* 1280: struct.bignum_st */
            	1285, 0,
            8884099, 8, 2, /* 1285: pointer_to_array_of_pointers_to_stack */
            	47, 0,
            	50, 12,
            0, 24, 1, /* 1292: struct.bignum_st */
            	1297, 0,
            8884099, 8, 2, /* 1297: pointer_to_array_of_pointers_to_stack */
            	47, 0,
            	50, 12,
            1, 8, 1, /* 1304: pointer.struct.ec_extra_data_st */
            	1309, 0,
            0, 40, 5, /* 1309: struct.ec_extra_data_st */
            	1322, 0,
            	705, 8,
            	1327, 16,
            	1330, 24,
            	1330, 32,
            1, 8, 1, /* 1322: pointer.struct.ec_extra_data_st */
            	1309, 0,
            8884097, 8, 0, /* 1327: pointer.func */
            8884097, 8, 0, /* 1330: pointer.func */
            8884097, 8, 0, /* 1333: pointer.func */
            1, 8, 1, /* 1336: pointer.struct.ec_point_st */
            	1097, 0,
            1, 8, 1, /* 1341: pointer.struct.bignum_st */
            	1346, 0,
            0, 24, 1, /* 1346: struct.bignum_st */
            	1351, 0,
            8884099, 8, 2, /* 1351: pointer_to_array_of_pointers_to_stack */
            	47, 0,
            	50, 12,
            1, 8, 1, /* 1358: pointer.struct.ec_extra_data_st */
            	1363, 0,
            0, 40, 5, /* 1363: struct.ec_extra_data_st */
            	1376, 0,
            	705, 8,
            	1327, 16,
            	1330, 24,
            	1330, 32,
            1, 8, 1, /* 1376: pointer.struct.ec_extra_data_st */
            	1363, 0,
            1, 8, 1, /* 1381: pointer.int */
            	50, 0,
            8884097, 8, 0, /* 1386: pointer.func */
            0, 0, 0, /* 1389: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1392: pointer.struct.ASN1_VALUE_st */
            	1389, 0,
            1, 8, 1, /* 1397: pointer.struct.asn1_string_st */
            	1402, 0,
            0, 24, 1, /* 1402: struct.asn1_string_st */
            	801, 8,
            1, 8, 1, /* 1407: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1412: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1417: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1422: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1427: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1432: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1437: pointer.struct.asn1_string_st */
            	1402, 0,
            0, 16, 1, /* 1442: struct.asn1_type_st */
            	1447, 8,
            0, 8, 20, /* 1447: union.unknown */
            	94, 0,
            	1437, 0,
            	1490, 0,
            	1509, 0,
            	1432, 0,
            	1514, 0,
            	1427, 0,
            	1519, 0,
            	1422, 0,
            	1417, 0,
            	1412, 0,
            	1407, 0,
            	1524, 0,
            	1529, 0,
            	1534, 0,
            	1539, 0,
            	1397, 0,
            	1437, 0,
            	1437, 0,
            	1392, 0,
            1, 8, 1, /* 1490: pointer.struct.asn1_object_st */
            	1495, 0,
            0, 40, 3, /* 1495: struct.asn1_object_st */
            	132, 0,
            	132, 8,
            	1504, 24,
            1, 8, 1, /* 1504: pointer.unsigned char */
            	806, 0,
            1, 8, 1, /* 1509: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1514: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1519: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1524: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1529: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1534: pointer.struct.asn1_string_st */
            	1402, 0,
            1, 8, 1, /* 1539: pointer.struct.asn1_string_st */
            	1402, 0,
            0, 0, 0, /* 1544: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1547: pointer.struct.asn1_string_st */
            	1552, 0,
            0, 24, 1, /* 1552: struct.asn1_string_st */
            	801, 8,
            1, 8, 1, /* 1557: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1562: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1567: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1572: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1577: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1582: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1587: pointer.struct.asn1_string_st */
            	1552, 0,
            0, 0, 1, /* 1592: ASN1_TYPE */
            	1597, 0,
            0, 16, 1, /* 1597: struct.asn1_type_st */
            	1602, 8,
            0, 8, 20, /* 1602: union.unknown */
            	94, 0,
            	1587, 0,
            	1645, 0,
            	1582, 0,
            	1659, 0,
            	1577, 0,
            	1664, 0,
            	1572, 0,
            	1669, 0,
            	1567, 0,
            	1674, 0,
            	1679, 0,
            	1684, 0,
            	1689, 0,
            	1562, 0,
            	1557, 0,
            	1547, 0,
            	1587, 0,
            	1587, 0,
            	1694, 0,
            1, 8, 1, /* 1645: pointer.struct.asn1_object_st */
            	1650, 0,
            0, 40, 3, /* 1650: struct.asn1_object_st */
            	132, 0,
            	132, 8,
            	1504, 24,
            1, 8, 1, /* 1659: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1664: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1669: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1674: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1679: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1684: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1689: pointer.struct.asn1_string_st */
            	1552, 0,
            1, 8, 1, /* 1694: pointer.struct.ASN1_VALUE_st */
            	1544, 0,
            1, 8, 1, /* 1699: pointer.struct.stack_st_ASN1_TYPE */
            	1704, 0,
            0, 32, 2, /* 1704: struct.stack_st_fake_ASN1_TYPE */
            	1711, 8,
            	99, 24,
            8884099, 8, 2, /* 1711: pointer_to_array_of_pointers_to_stack */
            	1718, 0,
            	50, 20,
            0, 8, 1, /* 1718: pointer.ASN1_TYPE */
            	1592, 0,
            0, 24, 2, /* 1723: struct.x509_attributes_st */
            	1490, 0,
            	1730, 16,
            0, 8, 3, /* 1730: union.unknown */
            	94, 0,
            	1699, 0,
            	1739, 0,
            1, 8, 1, /* 1739: pointer.struct.asn1_type_st */
            	1442, 0,
            0, 32, 2, /* 1744: struct.stack_st_fake_X509_ATTRIBUTE */
            	1751, 8,
            	99, 24,
            8884099, 8, 2, /* 1751: pointer_to_array_of_pointers_to_stack */
            	1758, 0,
            	50, 20,
            0, 8, 1, /* 1758: pointer.X509_ATTRIBUTE */
            	1763, 0,
            0, 0, 1, /* 1763: X509_ATTRIBUTE */
            	1723, 0,
            0, 48, 5, /* 1768: struct.env_md_ctx_st */
            	1781, 0,
            	867, 8,
            	705, 24,
            	1826, 32,
            	1808, 40,
            1, 8, 1, /* 1781: pointer.struct.env_md_st */
            	1786, 0,
            0, 120, 8, /* 1786: struct.env_md_st */
            	1805, 24,
            	1808, 32,
            	1811, 40,
            	1814, 48,
            	1805, 56,
            	1817, 64,
            	1820, 72,
            	1823, 112,
            8884097, 8, 0, /* 1805: pointer.func */
            8884097, 8, 0, /* 1808: pointer.func */
            8884097, 8, 0, /* 1811: pointer.func */
            8884097, 8, 0, /* 1814: pointer.func */
            8884097, 8, 0, /* 1817: pointer.func */
            8884097, 8, 0, /* 1820: pointer.func */
            8884097, 8, 0, /* 1823: pointer.func */
            1, 8, 1, /* 1826: pointer.struct.evp_pkey_ctx_st */
            	1831, 0,
            0, 80, 8, /* 1831: struct.evp_pkey_ctx_st */
            	1850, 0,
            	867, 8,
            	1944, 16,
            	1944, 24,
            	705, 40,
            	705, 48,
            	1386, 56,
            	1381, 64,
            1, 8, 1, /* 1850: pointer.struct.evp_pkey_method_st */
            	1855, 0,
            0, 208, 25, /* 1855: struct.evp_pkey_method_st */
            	1908, 8,
            	1911, 16,
            	1914, 24,
            	1908, 32,
            	1917, 40,
            	1908, 48,
            	1917, 56,
            	1908, 64,
            	1920, 72,
            	1908, 80,
            	1923, 88,
            	1908, 96,
            	1920, 104,
            	1926, 112,
            	1929, 120,
            	1926, 128,
            	1932, 136,
            	1908, 144,
            	1920, 152,
            	1908, 160,
            	1920, 168,
            	1908, 176,
            	1935, 184,
            	1938, 192,
            	1941, 200,
            8884097, 8, 0, /* 1908: pointer.func */
            8884097, 8, 0, /* 1911: pointer.func */
            8884097, 8, 0, /* 1914: pointer.func */
            8884097, 8, 0, /* 1917: pointer.func */
            8884097, 8, 0, /* 1920: pointer.func */
            8884097, 8, 0, /* 1923: pointer.func */
            8884097, 8, 0, /* 1926: pointer.func */
            8884097, 8, 0, /* 1929: pointer.func */
            8884097, 8, 0, /* 1932: pointer.func */
            8884097, 8, 0, /* 1935: pointer.func */
            8884097, 8, 0, /* 1938: pointer.func */
            8884097, 8, 0, /* 1941: pointer.func */
            1, 8, 1, /* 1944: pointer.struct.evp_pkey_st */
            	1949, 0,
            0, 56, 4, /* 1949: struct.evp_pkey_st */
            	1960, 16,
            	867, 24,
            	2061, 32,
            	2089, 48,
            1, 8, 1, /* 1960: pointer.struct.evp_pkey_asn1_method_st */
            	1965, 0,
            0, 208, 24, /* 1965: struct.evp_pkey_asn1_method_st */
            	94, 16,
            	94, 24,
            	2016, 32,
            	2019, 40,
            	2022, 48,
            	2025, 56,
            	2028, 64,
            	2031, 72,
            	2025, 80,
            	2034, 88,
            	2034, 96,
            	2037, 104,
            	2040, 112,
            	2034, 120,
            	2043, 128,
            	2022, 136,
            	2025, 144,
            	2046, 152,
            	2049, 160,
            	2052, 168,
            	2037, 176,
            	2040, 184,
            	2055, 192,
            	2058, 200,
            8884097, 8, 0, /* 2016: pointer.func */
            8884097, 8, 0, /* 2019: pointer.func */
            8884097, 8, 0, /* 2022: pointer.func */
            8884097, 8, 0, /* 2025: pointer.func */
            8884097, 8, 0, /* 2028: pointer.func */
            8884097, 8, 0, /* 2031: pointer.func */
            8884097, 8, 0, /* 2034: pointer.func */
            8884097, 8, 0, /* 2037: pointer.func */
            8884097, 8, 0, /* 2040: pointer.func */
            8884097, 8, 0, /* 2043: pointer.func */
            8884097, 8, 0, /* 2046: pointer.func */
            8884097, 8, 0, /* 2049: pointer.func */
            8884097, 8, 0, /* 2052: pointer.func */
            8884097, 8, 0, /* 2055: pointer.func */
            8884097, 8, 0, /* 2058: pointer.func */
            0, 8, 5, /* 2061: union.unknown */
            	94, 0,
            	2074, 0,
            	2079, 0,
            	2084, 0,
            	872, 0,
            1, 8, 1, /* 2074: pointer.struct.rsa_st */
            	511, 0,
            1, 8, 1, /* 2079: pointer.struct.dsa_st */
            	5, 0,
            1, 8, 1, /* 2084: pointer.struct.dh_st */
            	743, 0,
            1, 8, 1, /* 2089: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2094, 0,
            0, 32, 2, /* 2094: struct.stack_st_fake_X509_ATTRIBUTE */
            	2101, 8,
            	99, 24,
            8884099, 8, 2, /* 2101: pointer_to_array_of_pointers_to_stack */
            	2108, 0,
            	50, 20,
            0, 8, 1, /* 2108: pointer.X509_ATTRIBUTE */
            	1763, 0,
            0, 1, 0, /* 2113: char */
            1, 8, 1, /* 2116: pointer.struct.evp_pkey_st */
            	2121, 0,
            0, 56, 4, /* 2121: struct.evp_pkey_st */
            	1960, 16,
            	867, 24,
            	725, 32,
            	2132, 48,
            1, 8, 1, /* 2132: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1744, 0,
            1, 8, 1, /* 2137: pointer.struct.env_md_ctx_st */
            	1768, 0,
            1, 8, 1, /* 2142: pointer.unsigned int */
            	47, 0,
        },
        .arg_entity_index = { 2137, 801, 2142, 2116, },
        .ret_entity_index = 50,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    unsigned char * new_arg_b = *((unsigned char * *)new_args->args[1]);

    unsigned int * new_arg_c = *((unsigned int * *)new_args->args[2]);

    EVP_PKEY * new_arg_d = *((EVP_PKEY * *)new_args->args[3]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
    orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
    *new_ret_ptr = (*orig_EVP_SignFinal)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

