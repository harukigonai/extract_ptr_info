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

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d);

EVP_PKEY * PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("PEM_read_bio_PrivateKey called %lu\n", in_lib);
    if (!in_lib)
        return bb_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    else {
        EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
        orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
        return orig_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    }
}

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    EVP_PKEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            8884097, 8, 0, /* 0: pointer.func */
            0, 32, 2, /* 3: struct.stack_st */
            	10, 8,
            	20, 24,
            1, 8, 1, /* 10: pointer.pointer.char */
            	15, 0,
            1, 8, 1, /* 15: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 20: pointer.func */
            0, 32, 1, /* 23: struct.stack_st_void */
            	3, 0,
            1, 8, 1, /* 28: pointer.struct.stack_st_void */
            	23, 0,
            8884097, 8, 0, /* 33: pointer.func */
            0, 80, 9, /* 36: struct.bio_method_st */
            	57, 8,
            	62, 16,
            	65, 24,
            	68, 32,
            	65, 40,
            	71, 48,
            	74, 56,
            	74, 64,
            	77, 72,
            1, 8, 1, /* 57: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 62: pointer.func */
            8884097, 8, 0, /* 65: pointer.func */
            8884097, 8, 0, /* 68: pointer.func */
            8884097, 8, 0, /* 71: pointer.func */
            8884097, 8, 0, /* 74: pointer.func */
            8884097, 8, 0, /* 77: pointer.func */
            1, 8, 1, /* 80: pointer.struct.bio_method_st */
            	36, 0,
            1, 8, 1, /* 85: pointer.struct.bio_st */
            	90, 0,
            0, 112, 7, /* 90: struct.bio_st */
            	80, 0,
            	33, 8,
            	15, 16,
            	107, 48,
            	110, 56,
            	110, 64,
            	115, 96,
            0, 8, 0, /* 107: pointer.void */
            1, 8, 1, /* 110: pointer.struct.bio_st */
            	90, 0,
            0, 16, 1, /* 115: struct.crypto_ex_data_st */
            	28, 0,
            0, 0, 0, /* 120: struct.ASN1_VALUE_st */
            1, 8, 1, /* 123: pointer.struct.ASN1_VALUE_st */
            	120, 0,
            1, 8, 1, /* 128: pointer.struct.asn1_string_st */
            	133, 0,
            0, 24, 1, /* 133: struct.asn1_string_st */
            	138, 8,
            1, 8, 1, /* 138: pointer.unsigned char */
            	143, 0,
            0, 1, 0, /* 143: unsigned char */
            1, 8, 1, /* 146: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 151: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 156: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 161: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 166: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 171: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 176: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 181: pointer.struct.asn1_string_st */
            	133, 0,
            0, 16, 1, /* 186: struct.asn1_type_st */
            	191, 8,
            0, 8, 20, /* 191: union.unknown */
            	15, 0,
            	181, 0,
            	234, 0,
            	253, 0,
            	176, 0,
            	171, 0,
            	166, 0,
            	258, 0,
            	161, 0,
            	156, 0,
            	151, 0,
            	146, 0,
            	263, 0,
            	268, 0,
            	273, 0,
            	278, 0,
            	128, 0,
            	181, 0,
            	181, 0,
            	123, 0,
            1, 8, 1, /* 234: pointer.struct.asn1_object_st */
            	239, 0,
            0, 40, 3, /* 239: struct.asn1_object_st */
            	57, 0,
            	57, 8,
            	248, 24,
            1, 8, 1, /* 248: pointer.unsigned char */
            	143, 0,
            1, 8, 1, /* 253: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 258: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 263: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 268: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 273: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 278: pointer.struct.asn1_string_st */
            	133, 0,
            0, 0, 0, /* 283: struct.ASN1_VALUE_st */
            1, 8, 1, /* 286: pointer.struct.asn1_string_st */
            	291, 0,
            0, 24, 1, /* 291: struct.asn1_string_st */
            	138, 8,
            1, 8, 1, /* 296: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 301: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 306: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 311: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 316: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 321: pointer.struct.dsa_method */
            	326, 0,
            0, 96, 11, /* 326: struct.dsa_method */
            	57, 0,
            	351, 8,
            	354, 16,
            	357, 24,
            	360, 32,
            	363, 40,
            	366, 48,
            	366, 56,
            	15, 72,
            	369, 80,
            	366, 88,
            8884097, 8, 0, /* 351: pointer.func */
            8884097, 8, 0, /* 354: pointer.func */
            8884097, 8, 0, /* 357: pointer.func */
            8884097, 8, 0, /* 360: pointer.func */
            8884097, 8, 0, /* 363: pointer.func */
            8884097, 8, 0, /* 366: pointer.func */
            8884097, 8, 0, /* 369: pointer.func */
            8884097, 8, 0, /* 372: pointer.func */
            0, 88, 7, /* 375: struct.bn_blinding_st */
            	392, 0,
            	392, 8,
            	392, 16,
            	392, 24,
            	415, 40,
            	420, 72,
            	434, 80,
            1, 8, 1, /* 392: pointer.struct.bignum_st */
            	397, 0,
            0, 24, 1, /* 397: struct.bignum_st */
            	402, 0,
            8884099, 8, 2, /* 402: pointer_to_array_of_pointers_to_stack */
            	409, 0,
            	412, 12,
            0, 4, 0, /* 409: unsigned int */
            0, 4, 0, /* 412: int */
            0, 16, 1, /* 415: struct.crypto_threadid_st */
            	107, 0,
            1, 8, 1, /* 420: pointer.struct.bn_mont_ctx_st */
            	425, 0,
            0, 96, 3, /* 425: struct.bn_mont_ctx_st */
            	397, 8,
            	397, 32,
            	397, 56,
            8884097, 8, 0, /* 434: pointer.func */
            0, 96, 3, /* 437: struct.bn_mont_ctx_st */
            	446, 8,
            	446, 32,
            	446, 56,
            0, 24, 1, /* 446: struct.bignum_st */
            	451, 0,
            8884099, 8, 2, /* 451: pointer_to_array_of_pointers_to_stack */
            	409, 0,
            	412, 12,
            1, 8, 1, /* 458: pointer.struct.stack_st_void */
            	463, 0,
            0, 32, 1, /* 463: struct.stack_st_void */
            	468, 0,
            0, 32, 2, /* 468: struct.stack_st */
            	10, 8,
            	20, 24,
            8884097, 8, 0, /* 475: pointer.func */
            8884097, 8, 0, /* 478: pointer.func */
            1, 8, 1, /* 481: pointer.struct.asn1_string_st */
            	291, 0,
            8884097, 8, 0, /* 486: pointer.func */
            0, 88, 4, /* 489: struct.ec_point_st */
            	500, 0,
            	669, 8,
            	669, 32,
            	669, 56,
            1, 8, 1, /* 500: pointer.struct.ec_method_st */
            	505, 0,
            0, 304, 37, /* 505: struct.ec_method_st */
            	582, 8,
            	585, 16,
            	585, 24,
            	588, 32,
            	591, 40,
            	594, 48,
            	597, 56,
            	600, 64,
            	603, 72,
            	606, 80,
            	606, 88,
            	609, 96,
            	612, 104,
            	615, 112,
            	618, 120,
            	621, 128,
            	624, 136,
            	627, 144,
            	630, 152,
            	633, 160,
            	636, 168,
            	475, 176,
            	639, 184,
            	642, 192,
            	645, 200,
            	648, 208,
            	639, 216,
            	651, 224,
            	654, 232,
            	657, 240,
            	597, 248,
            	660, 256,
            	663, 264,
            	660, 272,
            	663, 280,
            	663, 288,
            	666, 296,
            8884097, 8, 0, /* 582: pointer.func */
            8884097, 8, 0, /* 585: pointer.func */
            8884097, 8, 0, /* 588: pointer.func */
            8884097, 8, 0, /* 591: pointer.func */
            8884097, 8, 0, /* 594: pointer.func */
            8884097, 8, 0, /* 597: pointer.func */
            8884097, 8, 0, /* 600: pointer.func */
            8884097, 8, 0, /* 603: pointer.func */
            8884097, 8, 0, /* 606: pointer.func */
            8884097, 8, 0, /* 609: pointer.func */
            8884097, 8, 0, /* 612: pointer.func */
            8884097, 8, 0, /* 615: pointer.func */
            8884097, 8, 0, /* 618: pointer.func */
            8884097, 8, 0, /* 621: pointer.func */
            8884097, 8, 0, /* 624: pointer.func */
            8884097, 8, 0, /* 627: pointer.func */
            8884097, 8, 0, /* 630: pointer.func */
            8884097, 8, 0, /* 633: pointer.func */
            8884097, 8, 0, /* 636: pointer.func */
            8884097, 8, 0, /* 639: pointer.func */
            8884097, 8, 0, /* 642: pointer.func */
            8884097, 8, 0, /* 645: pointer.func */
            8884097, 8, 0, /* 648: pointer.func */
            8884097, 8, 0, /* 651: pointer.func */
            8884097, 8, 0, /* 654: pointer.func */
            8884097, 8, 0, /* 657: pointer.func */
            8884097, 8, 0, /* 660: pointer.func */
            8884097, 8, 0, /* 663: pointer.func */
            8884097, 8, 0, /* 666: pointer.func */
            0, 24, 1, /* 669: struct.bignum_st */
            	674, 0,
            8884099, 8, 2, /* 674: pointer_to_array_of_pointers_to_stack */
            	409, 0,
            	412, 12,
            0, 16, 1, /* 681: struct.crypto_ex_data_st */
            	458, 0,
            8884097, 8, 0, /* 686: pointer.func */
            8884097, 8, 0, /* 689: pointer.func */
            1, 8, 1, /* 692: pointer.struct.bignum_st */
            	446, 0,
            0, 16, 1, /* 697: struct.crypto_ex_data_st */
            	702, 0,
            1, 8, 1, /* 702: pointer.struct.stack_st_void */
            	707, 0,
            0, 32, 1, /* 707: struct.stack_st_void */
            	712, 0,
            0, 32, 2, /* 712: struct.stack_st */
            	10, 8,
            	20, 24,
            8884097, 8, 0, /* 719: pointer.func */
            0, 1, 0, /* 722: char */
            1, 8, 1, /* 725: pointer.struct.asn1_object_st */
            	730, 0,
            0, 40, 3, /* 730: struct.asn1_object_st */
            	57, 0,
            	57, 8,
            	248, 24,
            0, 8, 1, /* 739: pointer.ASN1_TYPE */
            	744, 0,
            0, 0, 1, /* 744: ASN1_TYPE */
            	749, 0,
            0, 16, 1, /* 749: struct.asn1_type_st */
            	754, 8,
            0, 8, 20, /* 754: union.unknown */
            	15, 0,
            	797, 0,
            	725, 0,
            	802, 0,
            	807, 0,
            	316, 0,
            	481, 0,
            	311, 0,
            	812, 0,
            	306, 0,
            	817, 0,
            	822, 0,
            	827, 0,
            	832, 0,
            	301, 0,
            	296, 0,
            	286, 0,
            	797, 0,
            	797, 0,
            	837, 0,
            1, 8, 1, /* 797: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 802: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 807: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 812: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 817: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 822: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 827: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 832: pointer.struct.asn1_string_st */
            	291, 0,
            1, 8, 1, /* 837: pointer.struct.ASN1_VALUE_st */
            	283, 0,
            8884097, 8, 0, /* 842: pointer.func */
            8884097, 8, 0, /* 845: pointer.func */
            8884097, 8, 0, /* 848: pointer.func */
            8884097, 8, 0, /* 851: pointer.func */
            1, 8, 1, /* 854: pointer.struct.rsa_meth_st */
            	859, 0,
            0, 112, 13, /* 859: struct.rsa_meth_st */
            	57, 0,
            	888, 8,
            	888, 16,
            	888, 24,
            	888, 32,
            	891, 40,
            	894, 48,
            	845, 56,
            	845, 64,
            	15, 80,
            	719, 88,
            	897, 96,
            	900, 104,
            8884097, 8, 0, /* 888: pointer.func */
            8884097, 8, 0, /* 891: pointer.func */
            8884097, 8, 0, /* 894: pointer.func */
            8884097, 8, 0, /* 897: pointer.func */
            8884097, 8, 0, /* 900: pointer.func */
            8884097, 8, 0, /* 903: pointer.func */
            0, 168, 17, /* 906: struct.rsa_st */
            	854, 16,
            	943, 24,
            	692, 32,
            	692, 40,
            	692, 48,
            	692, 56,
            	692, 64,
            	692, 72,
            	692, 80,
            	692, 88,
            	681, 96,
            	1279, 120,
            	1279, 128,
            	1279, 136,
            	15, 144,
            	1284, 152,
            	1284, 160,
            1, 8, 1, /* 943: pointer.struct.engine_st */
            	948, 0,
            0, 216, 24, /* 948: struct.engine_st */
            	57, 0,
            	57, 8,
            	999, 16,
            	1051, 24,
            	1099, 32,
            	1132, 40,
            	1149, 48,
            	1176, 56,
            	1211, 64,
            	1219, 72,
            	1222, 80,
            	1225, 88,
            	1228, 96,
            	1231, 104,
            	1231, 112,
            	1231, 120,
            	1234, 128,
            	903, 136,
            	903, 144,
            	1237, 152,
            	1240, 160,
            	1252, 184,
            	1274, 200,
            	1274, 208,
            1, 8, 1, /* 999: pointer.struct.rsa_meth_st */
            	1004, 0,
            0, 112, 13, /* 1004: struct.rsa_meth_st */
            	57, 0,
            	848, 8,
            	848, 16,
            	848, 24,
            	848, 32,
            	1033, 40,
            	1036, 48,
            	1039, 56,
            	1039, 64,
            	15, 80,
            	1042, 88,
            	1045, 96,
            	1048, 104,
            8884097, 8, 0, /* 1033: pointer.func */
            8884097, 8, 0, /* 1036: pointer.func */
            8884097, 8, 0, /* 1039: pointer.func */
            8884097, 8, 0, /* 1042: pointer.func */
            8884097, 8, 0, /* 1045: pointer.func */
            8884097, 8, 0, /* 1048: pointer.func */
            1, 8, 1, /* 1051: pointer.struct.dsa_method */
            	1056, 0,
            0, 96, 11, /* 1056: struct.dsa_method */
            	57, 0,
            	851, 8,
            	1081, 16,
            	1084, 24,
            	1087, 32,
            	1090, 40,
            	1093, 48,
            	1093, 56,
            	15, 72,
            	1096, 80,
            	1093, 88,
            8884097, 8, 0, /* 1081: pointer.func */
            8884097, 8, 0, /* 1084: pointer.func */
            8884097, 8, 0, /* 1087: pointer.func */
            8884097, 8, 0, /* 1090: pointer.func */
            8884097, 8, 0, /* 1093: pointer.func */
            8884097, 8, 0, /* 1096: pointer.func */
            1, 8, 1, /* 1099: pointer.struct.dh_method */
            	1104, 0,
            0, 72, 8, /* 1104: struct.dh_method */
            	57, 0,
            	842, 8,
            	1123, 16,
            	1126, 24,
            	842, 32,
            	842, 40,
            	15, 56,
            	1129, 64,
            8884097, 8, 0, /* 1123: pointer.func */
            8884097, 8, 0, /* 1126: pointer.func */
            8884097, 8, 0, /* 1129: pointer.func */
            1, 8, 1, /* 1132: pointer.struct.ecdh_method */
            	1137, 0,
            0, 32, 3, /* 1137: struct.ecdh_method */
            	57, 0,
            	1146, 8,
            	15, 24,
            8884097, 8, 0, /* 1146: pointer.func */
            1, 8, 1, /* 1149: pointer.struct.ecdsa_method */
            	1154, 0,
            0, 48, 5, /* 1154: struct.ecdsa_method */
            	57, 0,
            	1167, 8,
            	1170, 16,
            	1173, 24,
            	15, 40,
            8884097, 8, 0, /* 1167: pointer.func */
            8884097, 8, 0, /* 1170: pointer.func */
            8884097, 8, 0, /* 1173: pointer.func */
            1, 8, 1, /* 1176: pointer.struct.rand_meth_st */
            	1181, 0,
            0, 48, 6, /* 1181: struct.rand_meth_st */
            	1196, 0,
            	1199, 8,
            	1202, 16,
            	1205, 24,
            	1199, 32,
            	1208, 40,
            8884097, 8, 0, /* 1196: pointer.func */
            8884097, 8, 0, /* 1199: pointer.func */
            8884097, 8, 0, /* 1202: pointer.func */
            8884097, 8, 0, /* 1205: pointer.func */
            8884097, 8, 0, /* 1208: pointer.func */
            1, 8, 1, /* 1211: pointer.struct.store_method_st */
            	1216, 0,
            0, 0, 0, /* 1216: struct.store_method_st */
            8884097, 8, 0, /* 1219: pointer.func */
            8884097, 8, 0, /* 1222: pointer.func */
            8884097, 8, 0, /* 1225: pointer.func */
            8884097, 8, 0, /* 1228: pointer.func */
            8884097, 8, 0, /* 1231: pointer.func */
            8884097, 8, 0, /* 1234: pointer.func */
            8884097, 8, 0, /* 1237: pointer.func */
            1, 8, 1, /* 1240: pointer.struct.ENGINE_CMD_DEFN_st */
            	1245, 0,
            0, 32, 2, /* 1245: struct.ENGINE_CMD_DEFN_st */
            	57, 8,
            	57, 16,
            0, 16, 1, /* 1252: struct.crypto_ex_data_st */
            	1257, 0,
            1, 8, 1, /* 1257: pointer.struct.stack_st_void */
            	1262, 0,
            0, 32, 1, /* 1262: struct.stack_st_void */
            	1267, 0,
            0, 32, 2, /* 1267: struct.stack_st */
            	10, 8,
            	20, 24,
            1, 8, 1, /* 1274: pointer.struct.engine_st */
            	948, 0,
            1, 8, 1, /* 1279: pointer.struct.bn_mont_ctx_st */
            	437, 0,
            1, 8, 1, /* 1284: pointer.struct.bn_blinding_st */
            	375, 0,
            0, 8, 5, /* 1289: union.unknown */
            	15, 0,
            	1302, 0,
            	1307, 0,
            	1373, 0,
            	1499, 0,
            1, 8, 1, /* 1302: pointer.struct.rsa_st */
            	906, 0,
            1, 8, 1, /* 1307: pointer.struct.dsa_st */
            	1312, 0,
            0, 136, 11, /* 1312: struct.dsa_st */
            	1337, 24,
            	1337, 32,
            	1337, 40,
            	1337, 48,
            	1337, 56,
            	1337, 64,
            	1337, 72,
            	1354, 88,
            	697, 104,
            	321, 120,
            	1368, 128,
            1, 8, 1, /* 1337: pointer.struct.bignum_st */
            	1342, 0,
            0, 24, 1, /* 1342: struct.bignum_st */
            	1347, 0,
            8884099, 8, 2, /* 1347: pointer_to_array_of_pointers_to_stack */
            	409, 0,
            	412, 12,
            1, 8, 1, /* 1354: pointer.struct.bn_mont_ctx_st */
            	1359, 0,
            0, 96, 3, /* 1359: struct.bn_mont_ctx_st */
            	1342, 8,
            	1342, 32,
            	1342, 56,
            1, 8, 1, /* 1368: pointer.struct.engine_st */
            	948, 0,
            1, 8, 1, /* 1373: pointer.struct.dh_st */
            	1378, 0,
            0, 144, 12, /* 1378: struct.dh_st */
            	1405, 8,
            	1405, 16,
            	1405, 32,
            	1405, 40,
            	1422, 56,
            	1405, 64,
            	1405, 72,
            	138, 80,
            	1405, 96,
            	1436, 112,
            	1458, 128,
            	1494, 136,
            1, 8, 1, /* 1405: pointer.struct.bignum_st */
            	1410, 0,
            0, 24, 1, /* 1410: struct.bignum_st */
            	1415, 0,
            8884099, 8, 2, /* 1415: pointer_to_array_of_pointers_to_stack */
            	409, 0,
            	412, 12,
            1, 8, 1, /* 1422: pointer.struct.bn_mont_ctx_st */
            	1427, 0,
            0, 96, 3, /* 1427: struct.bn_mont_ctx_st */
            	1410, 8,
            	1410, 32,
            	1410, 56,
            0, 16, 1, /* 1436: struct.crypto_ex_data_st */
            	1441, 0,
            1, 8, 1, /* 1441: pointer.struct.stack_st_void */
            	1446, 0,
            0, 32, 1, /* 1446: struct.stack_st_void */
            	1451, 0,
            0, 32, 2, /* 1451: struct.stack_st */
            	10, 8,
            	20, 24,
            1, 8, 1, /* 1458: pointer.struct.dh_method */
            	1463, 0,
            0, 72, 8, /* 1463: struct.dh_method */
            	57, 0,
            	1482, 8,
            	1485, 16,
            	1488, 24,
            	1482, 32,
            	1482, 40,
            	15, 56,
            	1491, 64,
            8884097, 8, 0, /* 1482: pointer.func */
            8884097, 8, 0, /* 1485: pointer.func */
            8884097, 8, 0, /* 1488: pointer.func */
            8884097, 8, 0, /* 1491: pointer.func */
            1, 8, 1, /* 1494: pointer.struct.engine_st */
            	948, 0,
            1, 8, 1, /* 1499: pointer.struct.ec_key_st */
            	1504, 0,
            0, 56, 4, /* 1504: struct.ec_key_st */
            	1515, 8,
            	1756, 16,
            	1761, 24,
            	1778, 48,
            1, 8, 1, /* 1515: pointer.struct.ec_group_st */
            	1520, 0,
            0, 232, 12, /* 1520: struct.ec_group_st */
            	1547, 0,
            	1707, 8,
            	1712, 16,
            	1712, 40,
            	138, 80,
            	1724, 96,
            	1712, 104,
            	1712, 152,
            	1712, 176,
            	107, 208,
            	107, 216,
            	1753, 224,
            1, 8, 1, /* 1547: pointer.struct.ec_method_st */
            	1552, 0,
            0, 304, 37, /* 1552: struct.ec_method_st */
            	1629, 8,
            	1632, 16,
            	1632, 24,
            	1635, 32,
            	689, 40,
            	1638, 48,
            	1641, 56,
            	1644, 64,
            	1647, 72,
            	1650, 80,
            	1650, 88,
            	1653, 96,
            	1656, 104,
            	1659, 112,
            	1662, 120,
            	1665, 128,
            	1668, 136,
            	478, 144,
            	1671, 152,
            	1674, 160,
            	1677, 168,
            	1680, 176,
            	1683, 184,
            	1686, 192,
            	1689, 200,
            	1692, 208,
            	1683, 216,
            	486, 224,
            	1695, 232,
            	1698, 240,
            	1641, 248,
            	1701, 256,
            	1704, 264,
            	1701, 272,
            	1704, 280,
            	1704, 288,
            	372, 296,
            8884097, 8, 0, /* 1629: pointer.func */
            8884097, 8, 0, /* 1632: pointer.func */
            8884097, 8, 0, /* 1635: pointer.func */
            8884097, 8, 0, /* 1638: pointer.func */
            8884097, 8, 0, /* 1641: pointer.func */
            8884097, 8, 0, /* 1644: pointer.func */
            8884097, 8, 0, /* 1647: pointer.func */
            8884097, 8, 0, /* 1650: pointer.func */
            8884097, 8, 0, /* 1653: pointer.func */
            8884097, 8, 0, /* 1656: pointer.func */
            8884097, 8, 0, /* 1659: pointer.func */
            8884097, 8, 0, /* 1662: pointer.func */
            8884097, 8, 0, /* 1665: pointer.func */
            8884097, 8, 0, /* 1668: pointer.func */
            8884097, 8, 0, /* 1671: pointer.func */
            8884097, 8, 0, /* 1674: pointer.func */
            8884097, 8, 0, /* 1677: pointer.func */
            8884097, 8, 0, /* 1680: pointer.func */
            8884097, 8, 0, /* 1683: pointer.func */
            8884097, 8, 0, /* 1686: pointer.func */
            8884097, 8, 0, /* 1689: pointer.func */
            8884097, 8, 0, /* 1692: pointer.func */
            8884097, 8, 0, /* 1695: pointer.func */
            8884097, 8, 0, /* 1698: pointer.func */
            8884097, 8, 0, /* 1701: pointer.func */
            8884097, 8, 0, /* 1704: pointer.func */
            1, 8, 1, /* 1707: pointer.struct.ec_point_st */
            	489, 0,
            0, 24, 1, /* 1712: struct.bignum_st */
            	1717, 0,
            8884099, 8, 2, /* 1717: pointer_to_array_of_pointers_to_stack */
            	409, 0,
            	412, 12,
            1, 8, 1, /* 1724: pointer.struct.ec_extra_data_st */
            	1729, 0,
            0, 40, 5, /* 1729: struct.ec_extra_data_st */
            	1742, 0,
            	107, 8,
            	1747, 16,
            	1750, 24,
            	1750, 32,
            1, 8, 1, /* 1742: pointer.struct.ec_extra_data_st */
            	1729, 0,
            8884097, 8, 0, /* 1747: pointer.func */
            8884097, 8, 0, /* 1750: pointer.func */
            8884097, 8, 0, /* 1753: pointer.func */
            1, 8, 1, /* 1756: pointer.struct.ec_point_st */
            	489, 0,
            1, 8, 1, /* 1761: pointer.struct.bignum_st */
            	1766, 0,
            0, 24, 1, /* 1766: struct.bignum_st */
            	1771, 0,
            8884099, 8, 2, /* 1771: pointer_to_array_of_pointers_to_stack */
            	409, 0,
            	412, 12,
            1, 8, 1, /* 1778: pointer.struct.ec_extra_data_st */
            	1783, 0,
            0, 40, 5, /* 1783: struct.ec_extra_data_st */
            	1796, 0,
            	107, 8,
            	1747, 16,
            	1750, 24,
            	1750, 32,
            1, 8, 1, /* 1796: pointer.struct.ec_extra_data_st */
            	1783, 0,
            8884097, 8, 0, /* 1801: pointer.func */
            1, 8, 1, /* 1804: pointer.pointer.struct.evp_pkey_st */
            	1809, 0,
            1, 8, 1, /* 1809: pointer.struct.evp_pkey_st */
            	1814, 0,
            0, 56, 4, /* 1814: struct.evp_pkey_st */
            	1825, 16,
            	1920, 24,
            	1289, 32,
            	1925, 48,
            1, 8, 1, /* 1825: pointer.struct.evp_pkey_asn1_method_st */
            	1830, 0,
            0, 208, 24, /* 1830: struct.evp_pkey_asn1_method_st */
            	15, 16,
            	15, 24,
            	1881, 32,
            	1884, 40,
            	1887, 48,
            	1890, 56,
            	1893, 64,
            	1896, 72,
            	1890, 80,
            	1899, 88,
            	1899, 96,
            	1902, 104,
            	1905, 112,
            	1899, 120,
            	1908, 128,
            	1887, 136,
            	1890, 144,
            	686, 152,
            	1911, 160,
            	1914, 168,
            	1902, 176,
            	1905, 184,
            	1801, 192,
            	1917, 200,
            8884097, 8, 0, /* 1881: pointer.func */
            8884097, 8, 0, /* 1884: pointer.func */
            8884097, 8, 0, /* 1887: pointer.func */
            8884097, 8, 0, /* 1890: pointer.func */
            8884097, 8, 0, /* 1893: pointer.func */
            8884097, 8, 0, /* 1896: pointer.func */
            8884097, 8, 0, /* 1899: pointer.func */
            8884097, 8, 0, /* 1902: pointer.func */
            8884097, 8, 0, /* 1905: pointer.func */
            8884097, 8, 0, /* 1908: pointer.func */
            8884097, 8, 0, /* 1911: pointer.func */
            8884097, 8, 0, /* 1914: pointer.func */
            8884097, 8, 0, /* 1917: pointer.func */
            1, 8, 1, /* 1920: pointer.struct.engine_st */
            	948, 0,
            1, 8, 1, /* 1925: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1930, 0,
            0, 32, 2, /* 1930: struct.stack_st_fake_X509_ATTRIBUTE */
            	1937, 8,
            	20, 24,
            8884099, 8, 2, /* 1937: pointer_to_array_of_pointers_to_stack */
            	1944, 0,
            	412, 20,
            0, 8, 1, /* 1944: pointer.X509_ATTRIBUTE */
            	1949, 0,
            0, 0, 1, /* 1949: X509_ATTRIBUTE */
            	1954, 0,
            0, 24, 2, /* 1954: struct.x509_attributes_st */
            	234, 0,
            	1961, 16,
            0, 8, 3, /* 1961: union.unknown */
            	15, 0,
            	1970, 0,
            	1989, 0,
            1, 8, 1, /* 1970: pointer.struct.stack_st_ASN1_TYPE */
            	1975, 0,
            0, 32, 2, /* 1975: struct.stack_st_fake_ASN1_TYPE */
            	1982, 8,
            	20, 24,
            8884099, 8, 2, /* 1982: pointer_to_array_of_pointers_to_stack */
            	739, 0,
            	412, 20,
            1, 8, 1, /* 1989: pointer.struct.asn1_type_st */
            	186, 0,
        },
        .arg_entity_index = { 85, 1804, 0, 107, },
        .ret_entity_index = 1809,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    EVP_PKEY ** new_arg_b = *((EVP_PKEY ** *)new_args->args[1]);

    pem_password_cb * new_arg_c = *((pem_password_cb * *)new_args->args[2]);

    void * new_arg_d = *((void * *)new_args->args[3]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
    orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
    *new_ret_ptr = (*orig_PEM_read_bio_PrivateKey)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

