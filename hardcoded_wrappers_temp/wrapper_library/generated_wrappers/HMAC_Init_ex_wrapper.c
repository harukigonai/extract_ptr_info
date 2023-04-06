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
            1, 8, 1, /* 8: pointer.struct.ASN1_VALUE_st */
            	13, 0,
            0, 0, 0, /* 13: struct.ASN1_VALUE_st */
            1, 8, 1, /* 16: pointer.struct.asn1_string_st */
            	21, 0,
            0, 24, 1, /* 21: struct.asn1_string_st */
            	26, 8,
            1, 8, 1, /* 26: pointer.unsigned char */
            	31, 0,
            0, 1, 0, /* 31: unsigned char */
            1, 8, 1, /* 34: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 39: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 44: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 49: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 54: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 59: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 64: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 69: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 74: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 79: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 84: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 89: pointer.struct.asn1_string_st */
            	21, 0,
            0, 16, 1, /* 94: struct.asn1_type_st */
            	99, 8,
            0, 8, 20, /* 99: union.unknown */
            	142, 0,
            	89, 0,
            	147, 0,
            	171, 0,
            	84, 0,
            	79, 0,
            	74, 0,
            	69, 0,
            	64, 0,
            	59, 0,
            	54, 0,
            	49, 0,
            	44, 0,
            	39, 0,
            	34, 0,
            	176, 0,
            	16, 0,
            	89, 0,
            	89, 0,
            	8, 0,
            1, 8, 1, /* 142: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 147: pointer.struct.asn1_object_st */
            	152, 0,
            0, 40, 3, /* 152: struct.asn1_object_st */
            	161, 0,
            	161, 8,
            	166, 24,
            1, 8, 1, /* 161: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 166: pointer.unsigned char */
            	31, 0,
            1, 8, 1, /* 171: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 176: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 181: pointer.struct.asn1_string_st */
            	186, 0,
            0, 24, 1, /* 186: struct.asn1_string_st */
            	26, 8,
            1, 8, 1, /* 191: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 196: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 201: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 206: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 211: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 216: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 221: pointer.struct.asn1_string_st */
            	186, 0,
            0, 40, 3, /* 226: struct.asn1_object_st */
            	161, 0,
            	161, 8,
            	166, 24,
            1, 8, 1, /* 235: pointer.struct.asn1_object_st */
            	226, 0,
            1, 8, 1, /* 240: pointer.struct.asn1_string_st */
            	186, 0,
            0, 8, 20, /* 245: union.unknown */
            	142, 0,
            	240, 0,
            	235, 0,
            	221, 0,
            	216, 0,
            	288, 0,
            	211, 0,
            	293, 0,
            	298, 0,
            	206, 0,
            	201, 0,
            	303, 0,
            	196, 0,
            	191, 0,
            	308, 0,
            	313, 0,
            	181, 0,
            	240, 0,
            	240, 0,
            	318, 0,
            1, 8, 1, /* 288: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 293: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 298: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 303: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 308: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 313: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 318: pointer.struct.ASN1_VALUE_st */
            	323, 0,
            0, 0, 0, /* 323: struct.ASN1_VALUE_st */
            0, 16, 1, /* 326: struct.asn1_type_st */
            	245, 8,
            0, 0, 1, /* 331: ASN1_TYPE */
            	326, 0,
            1, 8, 1, /* 336: pointer.struct.stack_st_ASN1_TYPE */
            	341, 0,
            0, 32, 2, /* 341: struct.stack_st_fake_ASN1_TYPE */
            	348, 8,
            	360, 24,
            8884099, 8, 2, /* 348: pointer_to_array_of_pointers_to_stack */
            	355, 0,
            	5, 20,
            0, 8, 1, /* 355: pointer.ASN1_TYPE */
            	331, 0,
            8884097, 8, 0, /* 360: pointer.func */
            0, 8, 3, /* 363: union.unknown */
            	142, 0,
            	336, 0,
            	372, 0,
            1, 8, 1, /* 372: pointer.struct.asn1_type_st */
            	94, 0,
            1, 8, 1, /* 377: pointer.struct.stack_st_X509_ATTRIBUTE */
            	382, 0,
            0, 32, 2, /* 382: struct.stack_st_fake_X509_ATTRIBUTE */
            	389, 8,
            	360, 24,
            8884099, 8, 2, /* 389: pointer_to_array_of_pointers_to_stack */
            	396, 0,
            	5, 20,
            0, 8, 1, /* 396: pointer.X509_ATTRIBUTE */
            	401, 0,
            0, 0, 1, /* 401: X509_ATTRIBUTE */
            	406, 0,
            0, 24, 2, /* 406: struct.x509_attributes_st */
            	147, 0,
            	363, 16,
            0, 24, 1, /* 413: struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 418: pointer.unsigned int */
            	423, 0,
            0, 4, 0, /* 423: unsigned int */
            1, 8, 1, /* 426: pointer.struct.ec_point_st */
            	431, 0,
            0, 88, 4, /* 431: struct.ec_point_st */
            	442, 0,
            	614, 8,
            	614, 32,
            	614, 56,
            1, 8, 1, /* 442: pointer.struct.ec_method_st */
            	447, 0,
            0, 304, 37, /* 447: struct.ec_method_st */
            	524, 8,
            	527, 16,
            	527, 24,
            	530, 32,
            	533, 40,
            	536, 48,
            	539, 56,
            	542, 64,
            	545, 72,
            	548, 80,
            	548, 88,
            	551, 96,
            	554, 104,
            	557, 112,
            	560, 120,
            	563, 128,
            	566, 136,
            	569, 144,
            	572, 152,
            	575, 160,
            	578, 168,
            	581, 176,
            	584, 184,
            	587, 192,
            	590, 200,
            	593, 208,
            	584, 216,
            	596, 224,
            	599, 232,
            	602, 240,
            	539, 248,
            	605, 256,
            	608, 264,
            	605, 272,
            	608, 280,
            	608, 288,
            	611, 296,
            8884097, 8, 0, /* 524: pointer.func */
            8884097, 8, 0, /* 527: pointer.func */
            8884097, 8, 0, /* 530: pointer.func */
            8884097, 8, 0, /* 533: pointer.func */
            8884097, 8, 0, /* 536: pointer.func */
            8884097, 8, 0, /* 539: pointer.func */
            8884097, 8, 0, /* 542: pointer.func */
            8884097, 8, 0, /* 545: pointer.func */
            8884097, 8, 0, /* 548: pointer.func */
            8884097, 8, 0, /* 551: pointer.func */
            8884097, 8, 0, /* 554: pointer.func */
            8884097, 8, 0, /* 557: pointer.func */
            8884097, 8, 0, /* 560: pointer.func */
            8884097, 8, 0, /* 563: pointer.func */
            8884097, 8, 0, /* 566: pointer.func */
            8884097, 8, 0, /* 569: pointer.func */
            8884097, 8, 0, /* 572: pointer.func */
            8884097, 8, 0, /* 575: pointer.func */
            8884097, 8, 0, /* 578: pointer.func */
            8884097, 8, 0, /* 581: pointer.func */
            8884097, 8, 0, /* 584: pointer.func */
            8884097, 8, 0, /* 587: pointer.func */
            8884097, 8, 0, /* 590: pointer.func */
            8884097, 8, 0, /* 593: pointer.func */
            8884097, 8, 0, /* 596: pointer.func */
            8884097, 8, 0, /* 599: pointer.func */
            8884097, 8, 0, /* 602: pointer.func */
            8884097, 8, 0, /* 605: pointer.func */
            8884097, 8, 0, /* 608: pointer.func */
            8884097, 8, 0, /* 611: pointer.func */
            0, 24, 1, /* 614: struct.bignum_st */
            	418, 0,
            8884097, 8, 0, /* 619: pointer.func */
            8884097, 8, 0, /* 622: pointer.func */
            0, 112, 13, /* 625: struct.rsa_meth_st */
            	161, 0,
            	654, 8,
            	654, 16,
            	654, 24,
            	654, 32,
            	657, 40,
            	660, 48,
            	663, 56,
            	663, 64,
            	142, 80,
            	666, 88,
            	669, 96,
            	672, 104,
            8884097, 8, 0, /* 654: pointer.func */
            8884097, 8, 0, /* 657: pointer.func */
            8884097, 8, 0, /* 660: pointer.func */
            8884097, 8, 0, /* 663: pointer.func */
            8884097, 8, 0, /* 666: pointer.func */
            8884097, 8, 0, /* 669: pointer.func */
            8884097, 8, 0, /* 672: pointer.func */
            0, 32, 2, /* 675: struct.stack_st */
            	682, 8,
            	360, 24,
            1, 8, 1, /* 682: pointer.pointer.char */
            	142, 0,
            0, 168, 17, /* 687: struct.rsa_st */
            	724, 16,
            	729, 24,
            	1077, 32,
            	1077, 40,
            	1077, 48,
            	1077, 56,
            	1077, 64,
            	1077, 72,
            	1077, 80,
            	1077, 88,
            	1087, 96,
            	1109, 120,
            	1109, 128,
            	1109, 136,
            	142, 144,
            	1123, 152,
            	1123, 160,
            1, 8, 1, /* 724: pointer.struct.rsa_meth_st */
            	625, 0,
            1, 8, 1, /* 729: pointer.struct.engine_st */
            	734, 0,
            0, 216, 24, /* 734: struct.engine_st */
            	161, 0,
            	161, 8,
            	785, 16,
            	840, 24,
            	891, 32,
            	927, 40,
            	944, 48,
            	971, 56,
            	1006, 64,
            	1014, 72,
            	1017, 80,
            	1020, 88,
            	1023, 96,
            	1026, 104,
            	1026, 112,
            	1026, 120,
            	1029, 128,
            	1032, 136,
            	1032, 144,
            	1035, 152,
            	1038, 160,
            	1050, 184,
            	1072, 200,
            	1072, 208,
            1, 8, 1, /* 785: pointer.struct.rsa_meth_st */
            	790, 0,
            0, 112, 13, /* 790: struct.rsa_meth_st */
            	161, 0,
            	819, 8,
            	819, 16,
            	819, 24,
            	819, 32,
            	822, 40,
            	825, 48,
            	828, 56,
            	828, 64,
            	142, 80,
            	831, 88,
            	834, 96,
            	837, 104,
            8884097, 8, 0, /* 819: pointer.func */
            8884097, 8, 0, /* 822: pointer.func */
            8884097, 8, 0, /* 825: pointer.func */
            8884097, 8, 0, /* 828: pointer.func */
            8884097, 8, 0, /* 831: pointer.func */
            8884097, 8, 0, /* 834: pointer.func */
            8884097, 8, 0, /* 837: pointer.func */
            1, 8, 1, /* 840: pointer.struct.dsa_method */
            	845, 0,
            0, 96, 11, /* 845: struct.dsa_method */
            	161, 0,
            	870, 8,
            	873, 16,
            	876, 24,
            	879, 32,
            	882, 40,
            	885, 48,
            	885, 56,
            	142, 72,
            	888, 80,
            	885, 88,
            8884097, 8, 0, /* 870: pointer.func */
            8884097, 8, 0, /* 873: pointer.func */
            8884097, 8, 0, /* 876: pointer.func */
            8884097, 8, 0, /* 879: pointer.func */
            8884097, 8, 0, /* 882: pointer.func */
            8884097, 8, 0, /* 885: pointer.func */
            8884097, 8, 0, /* 888: pointer.func */
            1, 8, 1, /* 891: pointer.struct.dh_method */
            	896, 0,
            0, 72, 8, /* 896: struct.dh_method */
            	161, 0,
            	915, 8,
            	918, 16,
            	921, 24,
            	915, 32,
            	915, 40,
            	142, 56,
            	924, 64,
            8884097, 8, 0, /* 915: pointer.func */
            8884097, 8, 0, /* 918: pointer.func */
            8884097, 8, 0, /* 921: pointer.func */
            8884097, 8, 0, /* 924: pointer.func */
            1, 8, 1, /* 927: pointer.struct.ecdh_method */
            	932, 0,
            0, 32, 3, /* 932: struct.ecdh_method */
            	161, 0,
            	941, 8,
            	142, 24,
            8884097, 8, 0, /* 941: pointer.func */
            1, 8, 1, /* 944: pointer.struct.ecdsa_method */
            	949, 0,
            0, 48, 5, /* 949: struct.ecdsa_method */
            	161, 0,
            	962, 8,
            	965, 16,
            	968, 24,
            	142, 40,
            8884097, 8, 0, /* 962: pointer.func */
            8884097, 8, 0, /* 965: pointer.func */
            8884097, 8, 0, /* 968: pointer.func */
            1, 8, 1, /* 971: pointer.struct.rand_meth_st */
            	976, 0,
            0, 48, 6, /* 976: struct.rand_meth_st */
            	991, 0,
            	994, 8,
            	997, 16,
            	1000, 24,
            	994, 32,
            	1003, 40,
            8884097, 8, 0, /* 991: pointer.func */
            8884097, 8, 0, /* 994: pointer.func */
            8884097, 8, 0, /* 997: pointer.func */
            8884097, 8, 0, /* 1000: pointer.func */
            8884097, 8, 0, /* 1003: pointer.func */
            1, 8, 1, /* 1006: pointer.struct.store_method_st */
            	1011, 0,
            0, 0, 0, /* 1011: struct.store_method_st */
            8884097, 8, 0, /* 1014: pointer.func */
            8884097, 8, 0, /* 1017: pointer.func */
            8884097, 8, 0, /* 1020: pointer.func */
            8884097, 8, 0, /* 1023: pointer.func */
            8884097, 8, 0, /* 1026: pointer.func */
            8884097, 8, 0, /* 1029: pointer.func */
            8884097, 8, 0, /* 1032: pointer.func */
            8884097, 8, 0, /* 1035: pointer.func */
            1, 8, 1, /* 1038: pointer.struct.ENGINE_CMD_DEFN_st */
            	1043, 0,
            0, 32, 2, /* 1043: struct.ENGINE_CMD_DEFN_st */
            	161, 8,
            	161, 16,
            0, 16, 1, /* 1050: struct.crypto_ex_data_st */
            	1055, 0,
            1, 8, 1, /* 1055: pointer.struct.stack_st_void */
            	1060, 0,
            0, 32, 1, /* 1060: struct.stack_st_void */
            	1065, 0,
            0, 32, 2, /* 1065: struct.stack_st */
            	682, 8,
            	360, 24,
            1, 8, 1, /* 1072: pointer.struct.engine_st */
            	734, 0,
            1, 8, 1, /* 1077: pointer.struct.bignum_st */
            	1082, 0,
            0, 24, 1, /* 1082: struct.bignum_st */
            	418, 0,
            0, 16, 1, /* 1087: struct.crypto_ex_data_st */
            	1092, 0,
            1, 8, 1, /* 1092: pointer.struct.stack_st_void */
            	1097, 0,
            0, 32, 1, /* 1097: struct.stack_st_void */
            	1102, 0,
            0, 32, 2, /* 1102: struct.stack_st */
            	682, 8,
            	360, 24,
            1, 8, 1, /* 1109: pointer.struct.bn_mont_ctx_st */
            	1114, 0,
            0, 96, 3, /* 1114: struct.bn_mont_ctx_st */
            	1082, 8,
            	1082, 32,
            	1082, 56,
            1, 8, 1, /* 1123: pointer.struct.bn_blinding_st */
            	1128, 0,
            0, 88, 7, /* 1128: struct.bn_blinding_st */
            	1145, 0,
            	1145, 8,
            	1145, 16,
            	1145, 24,
            	1155, 40,
            	1163, 72,
            	1177, 80,
            1, 8, 1, /* 1145: pointer.struct.bignum_st */
            	1150, 0,
            0, 24, 1, /* 1150: struct.bignum_st */
            	418, 0,
            0, 16, 1, /* 1155: struct.crypto_threadid_st */
            	1160, 0,
            0, 8, 0, /* 1160: pointer.void */
            1, 8, 1, /* 1163: pointer.struct.bn_mont_ctx_st */
            	1168, 0,
            0, 96, 3, /* 1168: struct.bn_mont_ctx_st */
            	1150, 8,
            	1150, 32,
            	1150, 56,
            8884097, 8, 0, /* 1177: pointer.func */
            0, 8, 5, /* 1180: union.unknown */
            	142, 0,
            	1193, 0,
            	1198, 0,
            	1330, 0,
            	1437, 0,
            1, 8, 1, /* 1193: pointer.struct.rsa_st */
            	687, 0,
            1, 8, 1, /* 1198: pointer.struct.dsa_st */
            	1203, 0,
            0, 136, 11, /* 1203: struct.dsa_st */
            	1228, 24,
            	1228, 32,
            	1228, 40,
            	1228, 48,
            	1228, 56,
            	1228, 64,
            	1228, 72,
            	1238, 88,
            	1252, 104,
            	1274, 120,
            	1325, 128,
            1, 8, 1, /* 1228: pointer.struct.bignum_st */
            	1233, 0,
            0, 24, 1, /* 1233: struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 1238: pointer.struct.bn_mont_ctx_st */
            	1243, 0,
            0, 96, 3, /* 1243: struct.bn_mont_ctx_st */
            	1233, 8,
            	1233, 32,
            	1233, 56,
            0, 16, 1, /* 1252: struct.crypto_ex_data_st */
            	1257, 0,
            1, 8, 1, /* 1257: pointer.struct.stack_st_void */
            	1262, 0,
            0, 32, 1, /* 1262: struct.stack_st_void */
            	1267, 0,
            0, 32, 2, /* 1267: struct.stack_st */
            	682, 8,
            	360, 24,
            1, 8, 1, /* 1274: pointer.struct.dsa_method */
            	1279, 0,
            0, 96, 11, /* 1279: struct.dsa_method */
            	161, 0,
            	1304, 8,
            	1307, 16,
            	1310, 24,
            	1313, 32,
            	1316, 40,
            	1319, 48,
            	1319, 56,
            	142, 72,
            	1322, 80,
            	1319, 88,
            8884097, 8, 0, /* 1304: pointer.func */
            8884097, 8, 0, /* 1307: pointer.func */
            8884097, 8, 0, /* 1310: pointer.func */
            8884097, 8, 0, /* 1313: pointer.func */
            8884097, 8, 0, /* 1316: pointer.func */
            8884097, 8, 0, /* 1319: pointer.func */
            8884097, 8, 0, /* 1322: pointer.func */
            1, 8, 1, /* 1325: pointer.struct.engine_st */
            	734, 0,
            1, 8, 1, /* 1330: pointer.struct.dh_st */
            	1335, 0,
            0, 144, 12, /* 1335: struct.dh_st */
            	1362, 8,
            	1362, 16,
            	1362, 32,
            	1362, 40,
            	1372, 56,
            	1362, 64,
            	1362, 72,
            	26, 80,
            	1362, 96,
            	1386, 112,
            	1401, 128,
            	729, 136,
            1, 8, 1, /* 1362: pointer.struct.bignum_st */
            	1367, 0,
            0, 24, 1, /* 1367: struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 1372: pointer.struct.bn_mont_ctx_st */
            	1377, 0,
            0, 96, 3, /* 1377: struct.bn_mont_ctx_st */
            	1367, 8,
            	1367, 32,
            	1367, 56,
            0, 16, 1, /* 1386: struct.crypto_ex_data_st */
            	1391, 0,
            1, 8, 1, /* 1391: pointer.struct.stack_st_void */
            	1396, 0,
            0, 32, 1, /* 1396: struct.stack_st_void */
            	675, 0,
            1, 8, 1, /* 1401: pointer.struct.dh_method */
            	1406, 0,
            0, 72, 8, /* 1406: struct.dh_method */
            	161, 0,
            	1425, 8,
            	1428, 16,
            	1431, 24,
            	1425, 32,
            	1425, 40,
            	142, 56,
            	1434, 64,
            8884097, 8, 0, /* 1425: pointer.func */
            8884097, 8, 0, /* 1428: pointer.func */
            8884097, 8, 0, /* 1431: pointer.func */
            8884097, 8, 0, /* 1434: pointer.func */
            1, 8, 1, /* 1437: pointer.struct.ec_key_st */
            	1442, 0,
            0, 56, 4, /* 1442: struct.ec_key_st */
            	1453, 8,
            	426, 16,
            	1693, 24,
            	1698, 48,
            1, 8, 1, /* 1453: pointer.struct.ec_group_st */
            	1458, 0,
            0, 232, 12, /* 1458: struct.ec_group_st */
            	1485, 0,
            	1657, 8,
            	1662, 16,
            	1662, 40,
            	26, 80,
            	1667, 96,
            	1662, 104,
            	1662, 152,
            	1662, 176,
            	1160, 208,
            	1160, 216,
            	619, 224,
            1, 8, 1, /* 1485: pointer.struct.ec_method_st */
            	1490, 0,
            0, 304, 37, /* 1490: struct.ec_method_st */
            	1567, 8,
            	1570, 16,
            	1570, 24,
            	1573, 32,
            	1576, 40,
            	1579, 48,
            	1582, 56,
            	1585, 64,
            	1588, 72,
            	1591, 80,
            	1591, 88,
            	1594, 96,
            	1597, 104,
            	1600, 112,
            	1603, 120,
            	1606, 128,
            	1609, 136,
            	1612, 144,
            	1615, 152,
            	1618, 160,
            	1621, 168,
            	1624, 176,
            	1627, 184,
            	1630, 192,
            	1633, 200,
            	1636, 208,
            	1627, 216,
            	1639, 224,
            	1642, 232,
            	1645, 240,
            	1582, 248,
            	1648, 256,
            	1651, 264,
            	1648, 272,
            	1651, 280,
            	1651, 288,
            	1654, 296,
            8884097, 8, 0, /* 1567: pointer.func */
            8884097, 8, 0, /* 1570: pointer.func */
            8884097, 8, 0, /* 1573: pointer.func */
            8884097, 8, 0, /* 1576: pointer.func */
            8884097, 8, 0, /* 1579: pointer.func */
            8884097, 8, 0, /* 1582: pointer.func */
            8884097, 8, 0, /* 1585: pointer.func */
            8884097, 8, 0, /* 1588: pointer.func */
            8884097, 8, 0, /* 1591: pointer.func */
            8884097, 8, 0, /* 1594: pointer.func */
            8884097, 8, 0, /* 1597: pointer.func */
            8884097, 8, 0, /* 1600: pointer.func */
            8884097, 8, 0, /* 1603: pointer.func */
            8884097, 8, 0, /* 1606: pointer.func */
            8884097, 8, 0, /* 1609: pointer.func */
            8884097, 8, 0, /* 1612: pointer.func */
            8884097, 8, 0, /* 1615: pointer.func */
            8884097, 8, 0, /* 1618: pointer.func */
            8884097, 8, 0, /* 1621: pointer.func */
            8884097, 8, 0, /* 1624: pointer.func */
            8884097, 8, 0, /* 1627: pointer.func */
            8884097, 8, 0, /* 1630: pointer.func */
            8884097, 8, 0, /* 1633: pointer.func */
            8884097, 8, 0, /* 1636: pointer.func */
            8884097, 8, 0, /* 1639: pointer.func */
            8884097, 8, 0, /* 1642: pointer.func */
            8884097, 8, 0, /* 1645: pointer.func */
            8884097, 8, 0, /* 1648: pointer.func */
            8884097, 8, 0, /* 1651: pointer.func */
            8884097, 8, 0, /* 1654: pointer.func */
            1, 8, 1, /* 1657: pointer.struct.ec_point_st */
            	431, 0,
            0, 24, 1, /* 1662: struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 1667: pointer.struct.ec_extra_data_st */
            	1672, 0,
            0, 40, 5, /* 1672: struct.ec_extra_data_st */
            	1685, 0,
            	1160, 8,
            	622, 16,
            	1690, 24,
            	1690, 32,
            1, 8, 1, /* 1685: pointer.struct.ec_extra_data_st */
            	1672, 0,
            8884097, 8, 0, /* 1690: pointer.func */
            1, 8, 1, /* 1693: pointer.struct.bignum_st */
            	413, 0,
            1, 8, 1, /* 1698: pointer.struct.ec_extra_data_st */
            	1703, 0,
            0, 40, 5, /* 1703: struct.ec_extra_data_st */
            	1716, 0,
            	1160, 8,
            	622, 16,
            	1690, 24,
            	1690, 32,
            1, 8, 1, /* 1716: pointer.struct.ec_extra_data_st */
            	1703, 0,
            8884097, 8, 0, /* 1721: pointer.func */
            8884097, 8, 0, /* 1724: pointer.func */
            8884097, 8, 0, /* 1727: pointer.func */
            8884097, 8, 0, /* 1730: pointer.func */
            8884097, 8, 0, /* 1733: pointer.func */
            8884097, 8, 0, /* 1736: pointer.func */
            0, 208, 24, /* 1739: struct.evp_pkey_asn1_method_st */
            	142, 16,
            	142, 24,
            	1790, 32,
            	1793, 40,
            	1796, 48,
            	1799, 56,
            	1802, 64,
            	1805, 72,
            	1799, 80,
            	1733, 88,
            	1733, 96,
            	1808, 104,
            	1811, 112,
            	1733, 120,
            	1736, 128,
            	1796, 136,
            	1799, 144,
            	1814, 152,
            	1730, 160,
            	1727, 168,
            	1808, 176,
            	1811, 184,
            	1817, 192,
            	1721, 200,
            8884097, 8, 0, /* 1790: pointer.func */
            8884097, 8, 0, /* 1793: pointer.func */
            8884097, 8, 0, /* 1796: pointer.func */
            8884097, 8, 0, /* 1799: pointer.func */
            8884097, 8, 0, /* 1802: pointer.func */
            8884097, 8, 0, /* 1805: pointer.func */
            8884097, 8, 0, /* 1808: pointer.func */
            8884097, 8, 0, /* 1811: pointer.func */
            8884097, 8, 0, /* 1814: pointer.func */
            8884097, 8, 0, /* 1817: pointer.func */
            8884097, 8, 0, /* 1820: pointer.func */
            0, 56, 4, /* 1823: struct.evp_pkey_st */
            	1834, 16,
            	1839, 24,
            	1180, 32,
            	377, 48,
            1, 8, 1, /* 1834: pointer.struct.evp_pkey_asn1_method_st */
            	1739, 0,
            1, 8, 1, /* 1839: pointer.struct.engine_st */
            	734, 0,
            1, 8, 1, /* 1844: pointer.struct.evp_pkey_st */
            	1823, 0,
            1, 8, 1, /* 1849: pointer.struct.engine_st */
            	734, 0,
            8884097, 8, 0, /* 1854: pointer.func */
            8884097, 8, 0, /* 1857: pointer.func */
            8884097, 8, 0, /* 1860: pointer.func */
            8884097, 8, 0, /* 1863: pointer.func */
            8884097, 8, 0, /* 1866: pointer.func */
            8884097, 8, 0, /* 1869: pointer.func */
            0, 208, 25, /* 1872: struct.evp_pkey_method_st */
            	1925, 8,
            	1928, 16,
            	1869, 24,
            	1925, 32,
            	1931, 40,
            	1925, 48,
            	1931, 56,
            	1925, 64,
            	1866, 72,
            	1925, 80,
            	1863, 88,
            	1925, 96,
            	1866, 104,
            	1860, 112,
            	1857, 120,
            	1860, 128,
            	1854, 136,
            	1925, 144,
            	1866, 152,
            	1925, 160,
            	1866, 168,
            	1925, 176,
            	1934, 184,
            	1937, 192,
            	1940, 200,
            8884097, 8, 0, /* 1925: pointer.func */
            8884097, 8, 0, /* 1928: pointer.func */
            8884097, 8, 0, /* 1931: pointer.func */
            8884097, 8, 0, /* 1934: pointer.func */
            8884097, 8, 0, /* 1937: pointer.func */
            8884097, 8, 0, /* 1940: pointer.func */
            0, 288, 4, /* 1943: struct.hmac_ctx_st */
            	1954, 0,
            	1993, 8,
            	1993, 56,
            	1993, 104,
            1, 8, 1, /* 1954: pointer.struct.env_md_st */
            	1959, 0,
            0, 120, 8, /* 1959: struct.env_md_st */
            	1978, 24,
            	1981, 32,
            	1984, 40,
            	1987, 48,
            	1978, 56,
            	1990, 64,
            	1820, 72,
            	1724, 112,
            8884097, 8, 0, /* 1978: pointer.func */
            8884097, 8, 0, /* 1981: pointer.func */
            8884097, 8, 0, /* 1984: pointer.func */
            8884097, 8, 0, /* 1987: pointer.func */
            8884097, 8, 0, /* 1990: pointer.func */
            0, 48, 5, /* 1993: struct.env_md_ctx_st */
            	1954, 0,
            	1849, 8,
            	1160, 24,
            	2006, 32,
            	1981, 40,
            1, 8, 1, /* 2006: pointer.struct.evp_pkey_ctx_st */
            	2011, 0,
            0, 80, 8, /* 2011: struct.evp_pkey_ctx_st */
            	2030, 0,
            	1839, 8,
            	1844, 16,
            	1844, 24,
            	1160, 40,
            	1160, 48,
            	2035, 56,
            	0, 64,
            1, 8, 1, /* 2030: pointer.struct.evp_pkey_method_st */
            	1872, 0,
            8884097, 8, 0, /* 2035: pointer.func */
            0, 1, 0, /* 2038: char */
            1, 8, 1, /* 2041: pointer.struct.hmac_ctx_st */
            	1943, 0,
        },
        .arg_entity_index = { 2041, 1160, 5, 1954, 1849, },
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

