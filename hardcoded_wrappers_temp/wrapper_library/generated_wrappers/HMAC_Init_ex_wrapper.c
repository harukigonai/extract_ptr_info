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
            1, 8, 1, /* 0: pointer.int */
            	5, 0,
            0, 4, 0, /* 5: int */
            8884097, 8, 0, /* 8: pointer.func */
            0, 0, 0, /* 11: struct.ASN1_VALUE_st */
            1, 8, 1, /* 14: pointer.struct.ASN1_VALUE_st */
            	11, 0,
            1, 8, 1, /* 19: pointer.struct.asn1_string_st */
            	24, 0,
            0, 24, 1, /* 24: struct.asn1_string_st */
            	29, 8,
            1, 8, 1, /* 29: pointer.unsigned char */
            	34, 0,
            0, 1, 0, /* 34: unsigned char */
            1, 8, 1, /* 37: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 42: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 47: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 52: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 57: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 62: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 67: pointer.struct.asn1_string_st */
            	24, 0,
            0, 16, 1, /* 72: struct.asn1_type_st */
            	77, 8,
            0, 8, 20, /* 77: union.unknown */
            	120, 0,
            	67, 0,
            	125, 0,
            	149, 0,
            	62, 0,
            	154, 0,
            	57, 0,
            	159, 0,
            	52, 0,
            	47, 0,
            	42, 0,
            	37, 0,
            	164, 0,
            	169, 0,
            	174, 0,
            	179, 0,
            	19, 0,
            	67, 0,
            	67, 0,
            	14, 0,
            1, 8, 1, /* 120: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 125: pointer.struct.asn1_object_st */
            	130, 0,
            0, 40, 3, /* 130: struct.asn1_object_st */
            	139, 0,
            	139, 8,
            	144, 24,
            1, 8, 1, /* 139: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 144: pointer.unsigned char */
            	34, 0,
            1, 8, 1, /* 149: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 154: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 159: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 164: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 169: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 174: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 179: pointer.struct.asn1_string_st */
            	24, 0,
            0, 0, 0, /* 184: struct.ASN1_VALUE_st */
            1, 8, 1, /* 187: pointer.struct.asn1_string_st */
            	192, 0,
            0, 24, 1, /* 192: struct.asn1_string_st */
            	29, 8,
            1, 8, 1, /* 197: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 202: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 207: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 212: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 217: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 222: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 227: pointer.struct.asn1_string_st */
            	192, 0,
            0, 0, 1, /* 232: ASN1_TYPE */
            	237, 0,
            0, 16, 1, /* 237: struct.asn1_type_st */
            	242, 8,
            0, 8, 20, /* 242: union.unknown */
            	120, 0,
            	227, 0,
            	285, 0,
            	222, 0,
            	299, 0,
            	217, 0,
            	304, 0,
            	212, 0,
            	309, 0,
            	207, 0,
            	314, 0,
            	319, 0,
            	324, 0,
            	329, 0,
            	202, 0,
            	197, 0,
            	187, 0,
            	227, 0,
            	227, 0,
            	334, 0,
            1, 8, 1, /* 285: pointer.struct.asn1_object_st */
            	290, 0,
            0, 40, 3, /* 290: struct.asn1_object_st */
            	139, 0,
            	139, 8,
            	144, 24,
            1, 8, 1, /* 299: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 304: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 309: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 314: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 319: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 324: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 329: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 334: pointer.struct.ASN1_VALUE_st */
            	184, 0,
            1, 8, 1, /* 339: pointer.struct.stack_st_ASN1_TYPE */
            	344, 0,
            0, 32, 2, /* 344: struct.stack_st_fake_ASN1_TYPE */
            	351, 8,
            	363, 24,
            8884099, 8, 2, /* 351: pointer_to_array_of_pointers_to_stack */
            	358, 0,
            	5, 20,
            0, 8, 1, /* 358: pointer.ASN1_TYPE */
            	232, 0,
            8884097, 8, 0, /* 363: pointer.func */
            0, 24, 2, /* 366: struct.x509_attributes_st */
            	125, 0,
            	373, 16,
            0, 8, 3, /* 373: union.unknown */
            	120, 0,
            	339, 0,
            	382, 0,
            1, 8, 1, /* 382: pointer.struct.asn1_type_st */
            	72, 0,
            1, 8, 1, /* 387: pointer.struct.ec_extra_data_st */
            	392, 0,
            0, 40, 5, /* 392: struct.ec_extra_data_st */
            	387, 0,
            	405, 8,
            	408, 16,
            	411, 24,
            	411, 32,
            0, 8, 0, /* 405: pointer.void */
            8884097, 8, 0, /* 408: pointer.func */
            8884097, 8, 0, /* 411: pointer.func */
            1, 8, 1, /* 414: pointer.struct.ec_extra_data_st */
            	392, 0,
            0, 24, 1, /* 419: struct.bignum_st */
            	424, 0,
            8884099, 8, 2, /* 424: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            0, 4, 0, /* 431: unsigned int */
            1, 8, 1, /* 434: pointer.struct.bignum_st */
            	419, 0,
            1, 8, 1, /* 439: pointer.struct.ec_point_st */
            	444, 0,
            0, 88, 4, /* 444: struct.ec_point_st */
            	455, 0,
            	627, 8,
            	627, 32,
            	627, 56,
            1, 8, 1, /* 455: pointer.struct.ec_method_st */
            	460, 0,
            0, 304, 37, /* 460: struct.ec_method_st */
            	537, 8,
            	540, 16,
            	540, 24,
            	543, 32,
            	546, 40,
            	549, 48,
            	552, 56,
            	555, 64,
            	558, 72,
            	561, 80,
            	561, 88,
            	564, 96,
            	567, 104,
            	570, 112,
            	573, 120,
            	576, 128,
            	579, 136,
            	582, 144,
            	585, 152,
            	588, 160,
            	591, 168,
            	594, 176,
            	597, 184,
            	600, 192,
            	603, 200,
            	606, 208,
            	597, 216,
            	609, 224,
            	612, 232,
            	615, 240,
            	552, 248,
            	618, 256,
            	621, 264,
            	618, 272,
            	621, 280,
            	621, 288,
            	624, 296,
            8884097, 8, 0, /* 537: pointer.func */
            8884097, 8, 0, /* 540: pointer.func */
            8884097, 8, 0, /* 543: pointer.func */
            8884097, 8, 0, /* 546: pointer.func */
            8884097, 8, 0, /* 549: pointer.func */
            8884097, 8, 0, /* 552: pointer.func */
            8884097, 8, 0, /* 555: pointer.func */
            8884097, 8, 0, /* 558: pointer.func */
            8884097, 8, 0, /* 561: pointer.func */
            8884097, 8, 0, /* 564: pointer.func */
            8884097, 8, 0, /* 567: pointer.func */
            8884097, 8, 0, /* 570: pointer.func */
            8884097, 8, 0, /* 573: pointer.func */
            8884097, 8, 0, /* 576: pointer.func */
            8884097, 8, 0, /* 579: pointer.func */
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
            0, 24, 1, /* 627: struct.bignum_st */
            	632, 0,
            8884099, 8, 2, /* 632: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            8884097, 8, 0, /* 639: pointer.func */
            8884097, 8, 0, /* 642: pointer.func */
            8884097, 8, 0, /* 645: pointer.func */
            8884097, 8, 0, /* 648: pointer.func */
            0, 32, 2, /* 651: struct.stack_st */
            	658, 8,
            	363, 24,
            1, 8, 1, /* 658: pointer.pointer.char */
            	120, 0,
            8884097, 8, 0, /* 663: pointer.func */
            8884097, 8, 0, /* 666: pointer.func */
            0, 112, 13, /* 669: struct.rsa_meth_st */
            	139, 0,
            	698, 8,
            	698, 16,
            	698, 24,
            	698, 32,
            	701, 40,
            	704, 48,
            	645, 56,
            	645, 64,
            	120, 80,
            	707, 88,
            	710, 96,
            	642, 104,
            8884097, 8, 0, /* 698: pointer.func */
            8884097, 8, 0, /* 701: pointer.func */
            8884097, 8, 0, /* 704: pointer.func */
            8884097, 8, 0, /* 707: pointer.func */
            8884097, 8, 0, /* 710: pointer.func */
            0, 168, 17, /* 713: struct.rsa_st */
            	750, 16,
            	755, 24,
            	1100, 32,
            	1100, 40,
            	1100, 48,
            	1100, 56,
            	1100, 64,
            	1100, 72,
            	1100, 80,
            	1100, 88,
            	1117, 96,
            	1132, 120,
            	1132, 128,
            	1132, 136,
            	120, 144,
            	1146, 152,
            	1146, 160,
            1, 8, 1, /* 750: pointer.struct.rsa_meth_st */
            	669, 0,
            1, 8, 1, /* 755: pointer.struct.engine_st */
            	760, 0,
            0, 216, 24, /* 760: struct.engine_st */
            	139, 0,
            	139, 8,
            	811, 16,
            	863, 24,
            	914, 32,
            	950, 40,
            	967, 48,
            	994, 56,
            	1029, 64,
            	1037, 72,
            	1040, 80,
            	1043, 88,
            	1046, 96,
            	1049, 104,
            	1049, 112,
            	1049, 120,
            	1052, 128,
            	1055, 136,
            	1055, 144,
            	1058, 152,
            	1061, 160,
            	1073, 184,
            	1095, 200,
            	1095, 208,
            1, 8, 1, /* 811: pointer.struct.rsa_meth_st */
            	816, 0,
            0, 112, 13, /* 816: struct.rsa_meth_st */
            	139, 0,
            	648, 8,
            	648, 16,
            	648, 24,
            	648, 32,
            	845, 40,
            	848, 48,
            	851, 56,
            	851, 64,
            	120, 80,
            	854, 88,
            	857, 96,
            	860, 104,
            8884097, 8, 0, /* 845: pointer.func */
            8884097, 8, 0, /* 848: pointer.func */
            8884097, 8, 0, /* 851: pointer.func */
            8884097, 8, 0, /* 854: pointer.func */
            8884097, 8, 0, /* 857: pointer.func */
            8884097, 8, 0, /* 860: pointer.func */
            1, 8, 1, /* 863: pointer.struct.dsa_method */
            	868, 0,
            0, 96, 11, /* 868: struct.dsa_method */
            	139, 0,
            	893, 8,
            	896, 16,
            	899, 24,
            	902, 32,
            	905, 40,
            	908, 48,
            	908, 56,
            	120, 72,
            	911, 80,
            	908, 88,
            8884097, 8, 0, /* 893: pointer.func */
            8884097, 8, 0, /* 896: pointer.func */
            8884097, 8, 0, /* 899: pointer.func */
            8884097, 8, 0, /* 902: pointer.func */
            8884097, 8, 0, /* 905: pointer.func */
            8884097, 8, 0, /* 908: pointer.func */
            8884097, 8, 0, /* 911: pointer.func */
            1, 8, 1, /* 914: pointer.struct.dh_method */
            	919, 0,
            0, 72, 8, /* 919: struct.dh_method */
            	139, 0,
            	938, 8,
            	941, 16,
            	944, 24,
            	938, 32,
            	938, 40,
            	120, 56,
            	947, 64,
            8884097, 8, 0, /* 938: pointer.func */
            8884097, 8, 0, /* 941: pointer.func */
            8884097, 8, 0, /* 944: pointer.func */
            8884097, 8, 0, /* 947: pointer.func */
            1, 8, 1, /* 950: pointer.struct.ecdh_method */
            	955, 0,
            0, 32, 3, /* 955: struct.ecdh_method */
            	139, 0,
            	964, 8,
            	120, 24,
            8884097, 8, 0, /* 964: pointer.func */
            1, 8, 1, /* 967: pointer.struct.ecdsa_method */
            	972, 0,
            0, 48, 5, /* 972: struct.ecdsa_method */
            	139, 0,
            	985, 8,
            	988, 16,
            	991, 24,
            	120, 40,
            8884097, 8, 0, /* 985: pointer.func */
            8884097, 8, 0, /* 988: pointer.func */
            8884097, 8, 0, /* 991: pointer.func */
            1, 8, 1, /* 994: pointer.struct.rand_meth_st */
            	999, 0,
            0, 48, 6, /* 999: struct.rand_meth_st */
            	1014, 0,
            	1017, 8,
            	1020, 16,
            	1023, 24,
            	1017, 32,
            	1026, 40,
            8884097, 8, 0, /* 1014: pointer.func */
            8884097, 8, 0, /* 1017: pointer.func */
            8884097, 8, 0, /* 1020: pointer.func */
            8884097, 8, 0, /* 1023: pointer.func */
            8884097, 8, 0, /* 1026: pointer.func */
            1, 8, 1, /* 1029: pointer.struct.store_method_st */
            	1034, 0,
            0, 0, 0, /* 1034: struct.store_method_st */
            8884097, 8, 0, /* 1037: pointer.func */
            8884097, 8, 0, /* 1040: pointer.func */
            8884097, 8, 0, /* 1043: pointer.func */
            8884097, 8, 0, /* 1046: pointer.func */
            8884097, 8, 0, /* 1049: pointer.func */
            8884097, 8, 0, /* 1052: pointer.func */
            8884097, 8, 0, /* 1055: pointer.func */
            8884097, 8, 0, /* 1058: pointer.func */
            1, 8, 1, /* 1061: pointer.struct.ENGINE_CMD_DEFN_st */
            	1066, 0,
            0, 32, 2, /* 1066: struct.ENGINE_CMD_DEFN_st */
            	139, 8,
            	139, 16,
            0, 16, 1, /* 1073: struct.crypto_ex_data_st */
            	1078, 0,
            1, 8, 1, /* 1078: pointer.struct.stack_st_void */
            	1083, 0,
            0, 32, 1, /* 1083: struct.stack_st_void */
            	1088, 0,
            0, 32, 2, /* 1088: struct.stack_st */
            	658, 8,
            	363, 24,
            1, 8, 1, /* 1095: pointer.struct.engine_st */
            	760, 0,
            1, 8, 1, /* 1100: pointer.struct.bignum_st */
            	1105, 0,
            0, 24, 1, /* 1105: struct.bignum_st */
            	1110, 0,
            8884099, 8, 2, /* 1110: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            0, 16, 1, /* 1117: struct.crypto_ex_data_st */
            	1122, 0,
            1, 8, 1, /* 1122: pointer.struct.stack_st_void */
            	1127, 0,
            0, 32, 1, /* 1127: struct.stack_st_void */
            	651, 0,
            1, 8, 1, /* 1132: pointer.struct.bn_mont_ctx_st */
            	1137, 0,
            0, 96, 3, /* 1137: struct.bn_mont_ctx_st */
            	1105, 8,
            	1105, 32,
            	1105, 56,
            1, 8, 1, /* 1146: pointer.struct.bn_blinding_st */
            	1151, 0,
            0, 88, 7, /* 1151: struct.bn_blinding_st */
            	1168, 0,
            	1168, 8,
            	1168, 16,
            	1168, 24,
            	1185, 40,
            	1190, 72,
            	1204, 80,
            1, 8, 1, /* 1168: pointer.struct.bignum_st */
            	1173, 0,
            0, 24, 1, /* 1173: struct.bignum_st */
            	1178, 0,
            8884099, 8, 2, /* 1178: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            0, 16, 1, /* 1185: struct.crypto_threadid_st */
            	405, 0,
            1, 8, 1, /* 1190: pointer.struct.bn_mont_ctx_st */
            	1195, 0,
            0, 96, 3, /* 1195: struct.bn_mont_ctx_st */
            	1173, 8,
            	1173, 32,
            	1173, 56,
            8884097, 8, 0, /* 1204: pointer.func */
            8884097, 8, 0, /* 1207: pointer.func */
            0, 208, 24, /* 1210: struct.evp_pkey_asn1_method_st */
            	120, 16,
            	120, 24,
            	1261, 32,
            	1264, 40,
            	1267, 48,
            	1270, 56,
            	1273, 64,
            	1276, 72,
            	1270, 80,
            	1207, 88,
            	1207, 96,
            	1279, 104,
            	1282, 112,
            	1207, 120,
            	1285, 128,
            	1267, 136,
            	1270, 144,
            	1288, 152,
            	1291, 160,
            	1294, 168,
            	1279, 176,
            	1282, 184,
            	1297, 192,
            	1300, 200,
            8884097, 8, 0, /* 1261: pointer.func */
            8884097, 8, 0, /* 1264: pointer.func */
            8884097, 8, 0, /* 1267: pointer.func */
            8884097, 8, 0, /* 1270: pointer.func */
            8884097, 8, 0, /* 1273: pointer.func */
            8884097, 8, 0, /* 1276: pointer.func */
            8884097, 8, 0, /* 1279: pointer.func */
            8884097, 8, 0, /* 1282: pointer.func */
            8884097, 8, 0, /* 1285: pointer.func */
            8884097, 8, 0, /* 1288: pointer.func */
            8884097, 8, 0, /* 1291: pointer.func */
            8884097, 8, 0, /* 1294: pointer.func */
            8884097, 8, 0, /* 1297: pointer.func */
            8884097, 8, 0, /* 1300: pointer.func */
            8884097, 8, 0, /* 1303: pointer.func */
            1, 8, 1, /* 1306: pointer.struct.evp_pkey_asn1_method_st */
            	1210, 0,
            0, 56, 4, /* 1311: struct.evp_pkey_st */
            	1306, 16,
            	1322, 24,
            	1327, 32,
            	1859, 48,
            1, 8, 1, /* 1322: pointer.struct.engine_st */
            	760, 0,
            0, 8, 5, /* 1327: union.unknown */
            	120, 0,
            	1340, 0,
            	1345, 0,
            	1484, 0,
            	1605, 0,
            1, 8, 1, /* 1340: pointer.struct.rsa_st */
            	713, 0,
            1, 8, 1, /* 1345: pointer.struct.dsa_st */
            	1350, 0,
            0, 136, 11, /* 1350: struct.dsa_st */
            	1375, 24,
            	1375, 32,
            	1375, 40,
            	1375, 48,
            	1375, 56,
            	1375, 64,
            	1375, 72,
            	1392, 88,
            	1406, 104,
            	1428, 120,
            	1479, 128,
            1, 8, 1, /* 1375: pointer.struct.bignum_st */
            	1380, 0,
            0, 24, 1, /* 1380: struct.bignum_st */
            	1385, 0,
            8884099, 8, 2, /* 1385: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            1, 8, 1, /* 1392: pointer.struct.bn_mont_ctx_st */
            	1397, 0,
            0, 96, 3, /* 1397: struct.bn_mont_ctx_st */
            	1380, 8,
            	1380, 32,
            	1380, 56,
            0, 16, 1, /* 1406: struct.crypto_ex_data_st */
            	1411, 0,
            1, 8, 1, /* 1411: pointer.struct.stack_st_void */
            	1416, 0,
            0, 32, 1, /* 1416: struct.stack_st_void */
            	1421, 0,
            0, 32, 2, /* 1421: struct.stack_st */
            	658, 8,
            	363, 24,
            1, 8, 1, /* 1428: pointer.struct.dsa_method */
            	1433, 0,
            0, 96, 11, /* 1433: struct.dsa_method */
            	139, 0,
            	1458, 8,
            	1461, 16,
            	1464, 24,
            	1467, 32,
            	1470, 40,
            	1473, 48,
            	1473, 56,
            	120, 72,
            	1476, 80,
            	1473, 88,
            8884097, 8, 0, /* 1458: pointer.func */
            8884097, 8, 0, /* 1461: pointer.func */
            8884097, 8, 0, /* 1464: pointer.func */
            8884097, 8, 0, /* 1467: pointer.func */
            8884097, 8, 0, /* 1470: pointer.func */
            8884097, 8, 0, /* 1473: pointer.func */
            8884097, 8, 0, /* 1476: pointer.func */
            1, 8, 1, /* 1479: pointer.struct.engine_st */
            	760, 0,
            1, 8, 1, /* 1484: pointer.struct.dh_st */
            	1489, 0,
            0, 144, 12, /* 1489: struct.dh_st */
            	1516, 8,
            	1516, 16,
            	1516, 32,
            	1516, 40,
            	1533, 56,
            	1516, 64,
            	1516, 72,
            	29, 80,
            	1516, 96,
            	1547, 112,
            	1569, 128,
            	1322, 136,
            1, 8, 1, /* 1516: pointer.struct.bignum_st */
            	1521, 0,
            0, 24, 1, /* 1521: struct.bignum_st */
            	1526, 0,
            8884099, 8, 2, /* 1526: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            1, 8, 1, /* 1533: pointer.struct.bn_mont_ctx_st */
            	1538, 0,
            0, 96, 3, /* 1538: struct.bn_mont_ctx_st */
            	1521, 8,
            	1521, 32,
            	1521, 56,
            0, 16, 1, /* 1547: struct.crypto_ex_data_st */
            	1552, 0,
            1, 8, 1, /* 1552: pointer.struct.stack_st_void */
            	1557, 0,
            0, 32, 1, /* 1557: struct.stack_st_void */
            	1562, 0,
            0, 32, 2, /* 1562: struct.stack_st */
            	658, 8,
            	363, 24,
            1, 8, 1, /* 1569: pointer.struct.dh_method */
            	1574, 0,
            0, 72, 8, /* 1574: struct.dh_method */
            	139, 0,
            	1593, 8,
            	1596, 16,
            	1599, 24,
            	1593, 32,
            	1593, 40,
            	120, 56,
            	1602, 64,
            8884097, 8, 0, /* 1593: pointer.func */
            8884097, 8, 0, /* 1596: pointer.func */
            8884097, 8, 0, /* 1599: pointer.func */
            8884097, 8, 0, /* 1602: pointer.func */
            1, 8, 1, /* 1605: pointer.struct.ec_key_st */
            	1610, 0,
            0, 56, 4, /* 1610: struct.ec_key_st */
            	1621, 8,
            	439, 16,
            	434, 24,
            	414, 48,
            1, 8, 1, /* 1621: pointer.struct.ec_group_st */
            	1626, 0,
            0, 232, 12, /* 1626: struct.ec_group_st */
            	1653, 0,
            	1819, 8,
            	1824, 16,
            	1824, 40,
            	29, 80,
            	1836, 96,
            	1824, 104,
            	1824, 152,
            	1824, 176,
            	405, 208,
            	405, 216,
            	639, 224,
            1, 8, 1, /* 1653: pointer.struct.ec_method_st */
            	1658, 0,
            0, 304, 37, /* 1658: struct.ec_method_st */
            	1735, 8,
            	1738, 16,
            	1738, 24,
            	1741, 32,
            	1744, 40,
            	1747, 48,
            	1750, 56,
            	1753, 64,
            	1756, 72,
            	1759, 80,
            	1759, 88,
            	1762, 96,
            	1765, 104,
            	1768, 112,
            	1771, 120,
            	1774, 128,
            	1777, 136,
            	663, 144,
            	1780, 152,
            	1783, 160,
            	1786, 168,
            	1789, 176,
            	1792, 184,
            	1795, 192,
            	1798, 200,
            	1801, 208,
            	1792, 216,
            	666, 224,
            	1804, 232,
            	1807, 240,
            	1750, 248,
            	1810, 256,
            	1813, 264,
            	1810, 272,
            	1813, 280,
            	1813, 288,
            	1816, 296,
            8884097, 8, 0, /* 1735: pointer.func */
            8884097, 8, 0, /* 1738: pointer.func */
            8884097, 8, 0, /* 1741: pointer.func */
            8884097, 8, 0, /* 1744: pointer.func */
            8884097, 8, 0, /* 1747: pointer.func */
            8884097, 8, 0, /* 1750: pointer.func */
            8884097, 8, 0, /* 1753: pointer.func */
            8884097, 8, 0, /* 1756: pointer.func */
            8884097, 8, 0, /* 1759: pointer.func */
            8884097, 8, 0, /* 1762: pointer.func */
            8884097, 8, 0, /* 1765: pointer.func */
            8884097, 8, 0, /* 1768: pointer.func */
            8884097, 8, 0, /* 1771: pointer.func */
            8884097, 8, 0, /* 1774: pointer.func */
            8884097, 8, 0, /* 1777: pointer.func */
            8884097, 8, 0, /* 1780: pointer.func */
            8884097, 8, 0, /* 1783: pointer.func */
            8884097, 8, 0, /* 1786: pointer.func */
            8884097, 8, 0, /* 1789: pointer.func */
            8884097, 8, 0, /* 1792: pointer.func */
            8884097, 8, 0, /* 1795: pointer.func */
            8884097, 8, 0, /* 1798: pointer.func */
            8884097, 8, 0, /* 1801: pointer.func */
            8884097, 8, 0, /* 1804: pointer.func */
            8884097, 8, 0, /* 1807: pointer.func */
            8884097, 8, 0, /* 1810: pointer.func */
            8884097, 8, 0, /* 1813: pointer.func */
            8884097, 8, 0, /* 1816: pointer.func */
            1, 8, 1, /* 1819: pointer.struct.ec_point_st */
            	444, 0,
            0, 24, 1, /* 1824: struct.bignum_st */
            	1829, 0,
            8884099, 8, 2, /* 1829: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            1, 8, 1, /* 1836: pointer.struct.ec_extra_data_st */
            	1841, 0,
            0, 40, 5, /* 1841: struct.ec_extra_data_st */
            	1854, 0,
            	405, 8,
            	408, 16,
            	411, 24,
            	411, 32,
            1, 8, 1, /* 1854: pointer.struct.ec_extra_data_st */
            	1841, 0,
            1, 8, 1, /* 1859: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1864, 0,
            0, 32, 2, /* 1864: struct.stack_st_fake_X509_ATTRIBUTE */
            	1871, 8,
            	363, 24,
            8884099, 8, 2, /* 1871: pointer_to_array_of_pointers_to_stack */
            	1878, 0,
            	5, 20,
            0, 8, 1, /* 1878: pointer.X509_ATTRIBUTE */
            	1883, 0,
            0, 0, 1, /* 1883: X509_ATTRIBUTE */
            	366, 0,
            1, 8, 1, /* 1888: pointer.struct.evp_pkey_st */
            	1311, 0,
            8884097, 8, 0, /* 1893: pointer.func */
            0, 1, 0, /* 1896: char */
            8884097, 8, 0, /* 1899: pointer.func */
            8884097, 8, 0, /* 1902: pointer.func */
            8884097, 8, 0, /* 1905: pointer.func */
            0, 288, 4, /* 1908: struct.hmac_ctx_st */
            	1919, 0,
            	1961, 8,
            	1961, 56,
            	1961, 104,
            1, 8, 1, /* 1919: pointer.struct.env_md_st */
            	1924, 0,
            0, 120, 8, /* 1924: struct.env_md_st */
            	1943, 24,
            	1946, 32,
            	1949, 40,
            	1952, 48,
            	1943, 56,
            	1955, 64,
            	1303, 72,
            	1958, 112,
            8884097, 8, 0, /* 1943: pointer.func */
            8884097, 8, 0, /* 1946: pointer.func */
            8884097, 8, 0, /* 1949: pointer.func */
            8884097, 8, 0, /* 1952: pointer.func */
            8884097, 8, 0, /* 1955: pointer.func */
            8884097, 8, 0, /* 1958: pointer.func */
            0, 48, 5, /* 1961: struct.env_md_ctx_st */
            	1919, 0,
            	1974, 8,
            	405, 24,
            	1979, 32,
            	1946, 40,
            1, 8, 1, /* 1974: pointer.struct.engine_st */
            	760, 0,
            1, 8, 1, /* 1979: pointer.struct.evp_pkey_ctx_st */
            	1984, 0,
            0, 80, 8, /* 1984: struct.evp_pkey_ctx_st */
            	2003, 0,
            	1322, 8,
            	1888, 16,
            	1888, 24,
            	405, 40,
            	405, 48,
            	8, 56,
            	0, 64,
            1, 8, 1, /* 2003: pointer.struct.evp_pkey_method_st */
            	2008, 0,
            0, 208, 25, /* 2008: struct.evp_pkey_method_st */
            	1905, 8,
            	2061, 16,
            	2064, 24,
            	1905, 32,
            	2067, 40,
            	1905, 48,
            	2067, 56,
            	1905, 64,
            	2070, 72,
            	1905, 80,
            	2073, 88,
            	1905, 96,
            	2070, 104,
            	2076, 112,
            	1902, 120,
            	2076, 128,
            	2079, 136,
            	1905, 144,
            	2070, 152,
            	1905, 160,
            	2070, 168,
            	1905, 176,
            	1899, 184,
            	2082, 192,
            	1893, 200,
            8884097, 8, 0, /* 2061: pointer.func */
            8884097, 8, 0, /* 2064: pointer.func */
            8884097, 8, 0, /* 2067: pointer.func */
            8884097, 8, 0, /* 2070: pointer.func */
            8884097, 8, 0, /* 2073: pointer.func */
            8884097, 8, 0, /* 2076: pointer.func */
            8884097, 8, 0, /* 2079: pointer.func */
            8884097, 8, 0, /* 2082: pointer.func */
            1, 8, 1, /* 2085: pointer.struct.hmac_ctx_st */
            	1908, 0,
        },
        .arg_entity_index = { 2085, 405, 5, 1919, 1974, },
        .ret_entity_index = 5,
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

