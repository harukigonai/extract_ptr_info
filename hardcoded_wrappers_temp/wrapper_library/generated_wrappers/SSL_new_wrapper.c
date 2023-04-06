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

SSL * bb_SSL_new(SSL_CTX * arg_a);

SSL * SSL_new(SSL_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_new called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_new(arg_a);
    else {
        SSL * (*orig_SSL_new)(SSL_CTX *);
        orig_SSL_new = dlsym(RTLD_NEXT, "SSL_new");
        return orig_SSL_new(arg_a);
    }
}

SSL * bb_SSL_new(SSL_CTX * arg_a) 
{
    SSL * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 128, 14, /* 0: struct.srp_ctx_st */
            	31, 0,
            	34, 8,
            	37, 16,
            	40, 24,
            	43, 32,
            	48, 40,
            	48, 48,
            	48, 56,
            	48, 64,
            	48, 72,
            	48, 80,
            	48, 88,
            	48, 96,
            	43, 104,
            0, 8, 0, /* 31: pointer.void */
            8884097, 8, 0, /* 34: pointer.func */
            8884097, 8, 0, /* 37: pointer.func */
            8884097, 8, 0, /* 40: pointer.func */
            1, 8, 1, /* 43: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 48: pointer.struct.bignum_st */
            	53, 0,
            0, 24, 1, /* 53: struct.bignum_st */
            	58, 0,
            1, 8, 1, /* 58: pointer.unsigned int */
            	63, 0,
            0, 4, 0, /* 63: unsigned int */
            8884097, 8, 0, /* 66: pointer.func */
            1, 8, 1, /* 69: pointer.struct.cert_st */
            	74, 0,
            0, 296, 7, /* 74: struct.cert_st */
            	91, 0,
            	3826, 48,
            	3831, 56,
            	3834, 64,
            	3839, 72,
            	3842, 80,
            	3847, 88,
            1, 8, 1, /* 91: pointer.struct.cert_pkey_st */
            	96, 0,
            0, 24, 3, /* 96: struct.cert_pkey_st */
            	105, 0,
            	3698, 8,
            	3781, 16,
            1, 8, 1, /* 105: pointer.struct.x509_st */
            	110, 0,
            0, 184, 12, /* 110: struct.x509_st */
            	137, 0,
            	185, 8,
            	2291, 16,
            	43, 32,
            	2361, 40,
            	2383, 104,
            	2388, 112,
            	2711, 120,
            	3147, 128,
            	3286, 136,
            	3310, 144,
            	3622, 176,
            1, 8, 1, /* 137: pointer.struct.x509_cinf_st */
            	142, 0,
            0, 104, 11, /* 142: struct.x509_cinf_st */
            	167, 0,
            	167, 8,
            	185, 16,
            	362, 24,
            	452, 32,
            	362, 40,
            	469, 48,
            	2291, 56,
            	2291, 64,
            	2296, 72,
            	2356, 80,
            1, 8, 1, /* 167: pointer.struct.asn1_string_st */
            	172, 0,
            0, 24, 1, /* 172: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 177: pointer.unsigned char */
            	182, 0,
            0, 1, 0, /* 182: unsigned char */
            1, 8, 1, /* 185: pointer.struct.X509_algor_st */
            	190, 0,
            0, 16, 2, /* 190: struct.X509_algor_st */
            	197, 0,
            	221, 8,
            1, 8, 1, /* 197: pointer.struct.asn1_object_st */
            	202, 0,
            0, 40, 3, /* 202: struct.asn1_object_st */
            	211, 0,
            	211, 8,
            	216, 24,
            1, 8, 1, /* 211: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 216: pointer.unsigned char */
            	182, 0,
            1, 8, 1, /* 221: pointer.struct.asn1_type_st */
            	226, 0,
            0, 16, 1, /* 226: struct.asn1_type_st */
            	231, 8,
            0, 8, 20, /* 231: union.unknown */
            	43, 0,
            	274, 0,
            	197, 0,
            	284, 0,
            	289, 0,
            	294, 0,
            	299, 0,
            	304, 0,
            	309, 0,
            	314, 0,
            	319, 0,
            	324, 0,
            	329, 0,
            	334, 0,
            	339, 0,
            	344, 0,
            	349, 0,
            	274, 0,
            	274, 0,
            	354, 0,
            1, 8, 1, /* 274: pointer.struct.asn1_string_st */
            	279, 0,
            0, 24, 1, /* 279: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 284: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 289: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 294: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 299: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 304: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 309: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 314: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 319: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 324: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 329: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 334: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 339: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 344: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 349: pointer.struct.asn1_string_st */
            	279, 0,
            1, 8, 1, /* 354: pointer.struct.ASN1_VALUE_st */
            	359, 0,
            0, 0, 0, /* 359: struct.ASN1_VALUE_st */
            1, 8, 1, /* 362: pointer.struct.X509_name_st */
            	367, 0,
            0, 40, 3, /* 367: struct.X509_name_st */
            	376, 0,
            	442, 16,
            	177, 24,
            1, 8, 1, /* 376: pointer.struct.stack_st_X509_NAME_ENTRY */
            	381, 0,
            0, 32, 2, /* 381: struct.stack_st_fake_X509_NAME_ENTRY */
            	388, 8,
            	439, 24,
            8884099, 8, 2, /* 388: pointer_to_array_of_pointers_to_stack */
            	395, 0,
            	436, 20,
            0, 8, 1, /* 395: pointer.X509_NAME_ENTRY */
            	400, 0,
            0, 0, 1, /* 400: X509_NAME_ENTRY */
            	405, 0,
            0, 24, 2, /* 405: struct.X509_name_entry_st */
            	412, 0,
            	426, 8,
            1, 8, 1, /* 412: pointer.struct.asn1_object_st */
            	417, 0,
            0, 40, 3, /* 417: struct.asn1_object_st */
            	211, 0,
            	211, 8,
            	216, 24,
            1, 8, 1, /* 426: pointer.struct.asn1_string_st */
            	431, 0,
            0, 24, 1, /* 431: struct.asn1_string_st */
            	177, 8,
            0, 4, 0, /* 436: int */
            8884097, 8, 0, /* 439: pointer.func */
            1, 8, 1, /* 442: pointer.struct.buf_mem_st */
            	447, 0,
            0, 24, 1, /* 447: struct.buf_mem_st */
            	43, 8,
            1, 8, 1, /* 452: pointer.struct.X509_val_st */
            	457, 0,
            0, 16, 2, /* 457: struct.X509_val_st */
            	464, 0,
            	464, 8,
            1, 8, 1, /* 464: pointer.struct.asn1_string_st */
            	172, 0,
            1, 8, 1, /* 469: pointer.struct.X509_pubkey_st */
            	474, 0,
            0, 24, 3, /* 474: struct.X509_pubkey_st */
            	483, 0,
            	488, 8,
            	498, 16,
            1, 8, 1, /* 483: pointer.struct.X509_algor_st */
            	190, 0,
            1, 8, 1, /* 488: pointer.struct.asn1_string_st */
            	493, 0,
            0, 24, 1, /* 493: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 498: pointer.struct.evp_pkey_st */
            	503, 0,
            0, 56, 4, /* 503: struct.evp_pkey_st */
            	514, 16,
            	615, 24,
            	968, 32,
            	1912, 48,
            1, 8, 1, /* 514: pointer.struct.evp_pkey_asn1_method_st */
            	519, 0,
            0, 208, 24, /* 519: struct.evp_pkey_asn1_method_st */
            	43, 16,
            	43, 24,
            	570, 32,
            	573, 40,
            	576, 48,
            	579, 56,
            	582, 64,
            	585, 72,
            	579, 80,
            	588, 88,
            	588, 96,
            	591, 104,
            	594, 112,
            	588, 120,
            	597, 128,
            	576, 136,
            	579, 144,
            	600, 152,
            	603, 160,
            	606, 168,
            	591, 176,
            	594, 184,
            	609, 192,
            	612, 200,
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
            1, 8, 1, /* 615: pointer.struct.engine_st */
            	620, 0,
            0, 216, 24, /* 620: struct.engine_st */
            	211, 0,
            	211, 8,
            	671, 16,
            	726, 24,
            	777, 32,
            	813, 40,
            	830, 48,
            	857, 56,
            	892, 64,
            	900, 72,
            	903, 80,
            	906, 88,
            	909, 96,
            	912, 104,
            	912, 112,
            	912, 120,
            	915, 128,
            	918, 136,
            	918, 144,
            	921, 152,
            	924, 160,
            	936, 184,
            	963, 200,
            	963, 208,
            1, 8, 1, /* 671: pointer.struct.rsa_meth_st */
            	676, 0,
            0, 112, 13, /* 676: struct.rsa_meth_st */
            	211, 0,
            	705, 8,
            	705, 16,
            	705, 24,
            	705, 32,
            	708, 40,
            	711, 48,
            	714, 56,
            	714, 64,
            	43, 80,
            	717, 88,
            	720, 96,
            	723, 104,
            8884097, 8, 0, /* 705: pointer.func */
            8884097, 8, 0, /* 708: pointer.func */
            8884097, 8, 0, /* 711: pointer.func */
            8884097, 8, 0, /* 714: pointer.func */
            8884097, 8, 0, /* 717: pointer.func */
            8884097, 8, 0, /* 720: pointer.func */
            8884097, 8, 0, /* 723: pointer.func */
            1, 8, 1, /* 726: pointer.struct.dsa_method */
            	731, 0,
            0, 96, 11, /* 731: struct.dsa_method */
            	211, 0,
            	756, 8,
            	759, 16,
            	762, 24,
            	765, 32,
            	768, 40,
            	771, 48,
            	771, 56,
            	43, 72,
            	774, 80,
            	771, 88,
            8884097, 8, 0, /* 756: pointer.func */
            8884097, 8, 0, /* 759: pointer.func */
            8884097, 8, 0, /* 762: pointer.func */
            8884097, 8, 0, /* 765: pointer.func */
            8884097, 8, 0, /* 768: pointer.func */
            8884097, 8, 0, /* 771: pointer.func */
            8884097, 8, 0, /* 774: pointer.func */
            1, 8, 1, /* 777: pointer.struct.dh_method */
            	782, 0,
            0, 72, 8, /* 782: struct.dh_method */
            	211, 0,
            	801, 8,
            	804, 16,
            	807, 24,
            	801, 32,
            	801, 40,
            	43, 56,
            	810, 64,
            8884097, 8, 0, /* 801: pointer.func */
            8884097, 8, 0, /* 804: pointer.func */
            8884097, 8, 0, /* 807: pointer.func */
            8884097, 8, 0, /* 810: pointer.func */
            1, 8, 1, /* 813: pointer.struct.ecdh_method */
            	818, 0,
            0, 32, 3, /* 818: struct.ecdh_method */
            	211, 0,
            	827, 8,
            	43, 24,
            8884097, 8, 0, /* 827: pointer.func */
            1, 8, 1, /* 830: pointer.struct.ecdsa_method */
            	835, 0,
            0, 48, 5, /* 835: struct.ecdsa_method */
            	211, 0,
            	848, 8,
            	851, 16,
            	854, 24,
            	43, 40,
            8884097, 8, 0, /* 848: pointer.func */
            8884097, 8, 0, /* 851: pointer.func */
            8884097, 8, 0, /* 854: pointer.func */
            1, 8, 1, /* 857: pointer.struct.rand_meth_st */
            	862, 0,
            0, 48, 6, /* 862: struct.rand_meth_st */
            	877, 0,
            	880, 8,
            	883, 16,
            	886, 24,
            	880, 32,
            	889, 40,
            8884097, 8, 0, /* 877: pointer.func */
            8884097, 8, 0, /* 880: pointer.func */
            8884097, 8, 0, /* 883: pointer.func */
            8884097, 8, 0, /* 886: pointer.func */
            8884097, 8, 0, /* 889: pointer.func */
            1, 8, 1, /* 892: pointer.struct.store_method_st */
            	897, 0,
            0, 0, 0, /* 897: struct.store_method_st */
            8884097, 8, 0, /* 900: pointer.func */
            8884097, 8, 0, /* 903: pointer.func */
            8884097, 8, 0, /* 906: pointer.func */
            8884097, 8, 0, /* 909: pointer.func */
            8884097, 8, 0, /* 912: pointer.func */
            8884097, 8, 0, /* 915: pointer.func */
            8884097, 8, 0, /* 918: pointer.func */
            8884097, 8, 0, /* 921: pointer.func */
            1, 8, 1, /* 924: pointer.struct.ENGINE_CMD_DEFN_st */
            	929, 0,
            0, 32, 2, /* 929: struct.ENGINE_CMD_DEFN_st */
            	211, 8,
            	211, 16,
            0, 16, 1, /* 936: struct.crypto_ex_data_st */
            	941, 0,
            1, 8, 1, /* 941: pointer.struct.stack_st_void */
            	946, 0,
            0, 32, 1, /* 946: struct.stack_st_void */
            	951, 0,
            0, 32, 2, /* 951: struct.stack_st */
            	958, 8,
            	439, 24,
            1, 8, 1, /* 958: pointer.pointer.char */
            	43, 0,
            1, 8, 1, /* 963: pointer.struct.engine_st */
            	620, 0,
            0, 8, 5, /* 968: union.unknown */
            	43, 0,
            	981, 0,
            	1183, 0,
            	1310, 0,
            	1424, 0,
            1, 8, 1, /* 981: pointer.struct.rsa_st */
            	986, 0,
            0, 168, 17, /* 986: struct.rsa_st */
            	1023, 16,
            	1078, 24,
            	1083, 32,
            	1083, 40,
            	1083, 48,
            	1083, 56,
            	1083, 64,
            	1083, 72,
            	1083, 80,
            	1083, 88,
            	1093, 96,
            	1115, 120,
            	1115, 128,
            	1115, 136,
            	43, 144,
            	1129, 152,
            	1129, 160,
            1, 8, 1, /* 1023: pointer.struct.rsa_meth_st */
            	1028, 0,
            0, 112, 13, /* 1028: struct.rsa_meth_st */
            	211, 0,
            	1057, 8,
            	1057, 16,
            	1057, 24,
            	1057, 32,
            	1060, 40,
            	1063, 48,
            	1066, 56,
            	1066, 64,
            	43, 80,
            	1069, 88,
            	1072, 96,
            	1075, 104,
            8884097, 8, 0, /* 1057: pointer.func */
            8884097, 8, 0, /* 1060: pointer.func */
            8884097, 8, 0, /* 1063: pointer.func */
            8884097, 8, 0, /* 1066: pointer.func */
            8884097, 8, 0, /* 1069: pointer.func */
            8884097, 8, 0, /* 1072: pointer.func */
            8884097, 8, 0, /* 1075: pointer.func */
            1, 8, 1, /* 1078: pointer.struct.engine_st */
            	620, 0,
            1, 8, 1, /* 1083: pointer.struct.bignum_st */
            	1088, 0,
            0, 24, 1, /* 1088: struct.bignum_st */
            	58, 0,
            0, 16, 1, /* 1093: struct.crypto_ex_data_st */
            	1098, 0,
            1, 8, 1, /* 1098: pointer.struct.stack_st_void */
            	1103, 0,
            0, 32, 1, /* 1103: struct.stack_st_void */
            	1108, 0,
            0, 32, 2, /* 1108: struct.stack_st */
            	958, 8,
            	439, 24,
            1, 8, 1, /* 1115: pointer.struct.bn_mont_ctx_st */
            	1120, 0,
            0, 96, 3, /* 1120: struct.bn_mont_ctx_st */
            	1088, 8,
            	1088, 32,
            	1088, 56,
            1, 8, 1, /* 1129: pointer.struct.bn_blinding_st */
            	1134, 0,
            0, 88, 7, /* 1134: struct.bn_blinding_st */
            	1151, 0,
            	1151, 8,
            	1151, 16,
            	1151, 24,
            	1161, 40,
            	1166, 72,
            	1180, 80,
            1, 8, 1, /* 1151: pointer.struct.bignum_st */
            	1156, 0,
            0, 24, 1, /* 1156: struct.bignum_st */
            	58, 0,
            0, 16, 1, /* 1161: struct.crypto_threadid_st */
            	31, 0,
            1, 8, 1, /* 1166: pointer.struct.bn_mont_ctx_st */
            	1171, 0,
            0, 96, 3, /* 1171: struct.bn_mont_ctx_st */
            	1156, 8,
            	1156, 32,
            	1156, 56,
            8884097, 8, 0, /* 1180: pointer.func */
            1, 8, 1, /* 1183: pointer.struct.dsa_st */
            	1188, 0,
            0, 136, 11, /* 1188: struct.dsa_st */
            	1213, 24,
            	1213, 32,
            	1213, 40,
            	1213, 48,
            	1213, 56,
            	1213, 64,
            	1213, 72,
            	1223, 88,
            	1237, 104,
            	1259, 120,
            	615, 128,
            1, 8, 1, /* 1213: pointer.struct.bignum_st */
            	1218, 0,
            0, 24, 1, /* 1218: struct.bignum_st */
            	58, 0,
            1, 8, 1, /* 1223: pointer.struct.bn_mont_ctx_st */
            	1228, 0,
            0, 96, 3, /* 1228: struct.bn_mont_ctx_st */
            	1218, 8,
            	1218, 32,
            	1218, 56,
            0, 16, 1, /* 1237: struct.crypto_ex_data_st */
            	1242, 0,
            1, 8, 1, /* 1242: pointer.struct.stack_st_void */
            	1247, 0,
            0, 32, 1, /* 1247: struct.stack_st_void */
            	1252, 0,
            0, 32, 2, /* 1252: struct.stack_st */
            	958, 8,
            	439, 24,
            1, 8, 1, /* 1259: pointer.struct.dsa_method */
            	1264, 0,
            0, 96, 11, /* 1264: struct.dsa_method */
            	211, 0,
            	1289, 8,
            	1292, 16,
            	1295, 24,
            	1298, 32,
            	1301, 40,
            	1304, 48,
            	1304, 56,
            	43, 72,
            	1307, 80,
            	1304, 88,
            8884097, 8, 0, /* 1289: pointer.func */
            8884097, 8, 0, /* 1292: pointer.func */
            8884097, 8, 0, /* 1295: pointer.func */
            8884097, 8, 0, /* 1298: pointer.func */
            8884097, 8, 0, /* 1301: pointer.func */
            8884097, 8, 0, /* 1304: pointer.func */
            8884097, 8, 0, /* 1307: pointer.func */
            1, 8, 1, /* 1310: pointer.struct.dh_st */
            	1315, 0,
            0, 144, 12, /* 1315: struct.dh_st */
            	1342, 8,
            	1342, 16,
            	1342, 32,
            	1342, 40,
            	1352, 56,
            	1342, 64,
            	1342, 72,
            	177, 80,
            	1342, 96,
            	1366, 112,
            	1388, 128,
            	1078, 136,
            1, 8, 1, /* 1342: pointer.struct.bignum_st */
            	1347, 0,
            0, 24, 1, /* 1347: struct.bignum_st */
            	58, 0,
            1, 8, 1, /* 1352: pointer.struct.bn_mont_ctx_st */
            	1357, 0,
            0, 96, 3, /* 1357: struct.bn_mont_ctx_st */
            	1347, 8,
            	1347, 32,
            	1347, 56,
            0, 16, 1, /* 1366: struct.crypto_ex_data_st */
            	1371, 0,
            1, 8, 1, /* 1371: pointer.struct.stack_st_void */
            	1376, 0,
            0, 32, 1, /* 1376: struct.stack_st_void */
            	1381, 0,
            0, 32, 2, /* 1381: struct.stack_st */
            	958, 8,
            	439, 24,
            1, 8, 1, /* 1388: pointer.struct.dh_method */
            	1393, 0,
            0, 72, 8, /* 1393: struct.dh_method */
            	211, 0,
            	1412, 8,
            	1415, 16,
            	1418, 24,
            	1412, 32,
            	1412, 40,
            	43, 56,
            	1421, 64,
            8884097, 8, 0, /* 1412: pointer.func */
            8884097, 8, 0, /* 1415: pointer.func */
            8884097, 8, 0, /* 1418: pointer.func */
            8884097, 8, 0, /* 1421: pointer.func */
            1, 8, 1, /* 1424: pointer.struct.ec_key_st */
            	1429, 0,
            0, 56, 4, /* 1429: struct.ec_key_st */
            	1440, 8,
            	1874, 16,
            	1879, 24,
            	1889, 48,
            1, 8, 1, /* 1440: pointer.struct.ec_group_st */
            	1445, 0,
            0, 232, 12, /* 1445: struct.ec_group_st */
            	1472, 0,
            	1644, 8,
            	1837, 16,
            	1837, 40,
            	177, 80,
            	1842, 96,
            	1837, 104,
            	1837, 152,
            	1837, 176,
            	31, 208,
            	31, 216,
            	1871, 224,
            1, 8, 1, /* 1472: pointer.struct.ec_method_st */
            	1477, 0,
            0, 304, 37, /* 1477: struct.ec_method_st */
            	1554, 8,
            	1557, 16,
            	1557, 24,
            	1560, 32,
            	1563, 40,
            	1566, 48,
            	1569, 56,
            	1572, 64,
            	1575, 72,
            	1578, 80,
            	1578, 88,
            	1581, 96,
            	1584, 104,
            	1587, 112,
            	1590, 120,
            	1593, 128,
            	1596, 136,
            	1599, 144,
            	1602, 152,
            	1605, 160,
            	1608, 168,
            	1611, 176,
            	1614, 184,
            	1617, 192,
            	1620, 200,
            	1623, 208,
            	1614, 216,
            	1626, 224,
            	1629, 232,
            	1632, 240,
            	1569, 248,
            	1635, 256,
            	1638, 264,
            	1635, 272,
            	1638, 280,
            	1638, 288,
            	1641, 296,
            8884097, 8, 0, /* 1554: pointer.func */
            8884097, 8, 0, /* 1557: pointer.func */
            8884097, 8, 0, /* 1560: pointer.func */
            8884097, 8, 0, /* 1563: pointer.func */
            8884097, 8, 0, /* 1566: pointer.func */
            8884097, 8, 0, /* 1569: pointer.func */
            8884097, 8, 0, /* 1572: pointer.func */
            8884097, 8, 0, /* 1575: pointer.func */
            8884097, 8, 0, /* 1578: pointer.func */
            8884097, 8, 0, /* 1581: pointer.func */
            8884097, 8, 0, /* 1584: pointer.func */
            8884097, 8, 0, /* 1587: pointer.func */
            8884097, 8, 0, /* 1590: pointer.func */
            8884097, 8, 0, /* 1593: pointer.func */
            8884097, 8, 0, /* 1596: pointer.func */
            8884097, 8, 0, /* 1599: pointer.func */
            8884097, 8, 0, /* 1602: pointer.func */
            8884097, 8, 0, /* 1605: pointer.func */
            8884097, 8, 0, /* 1608: pointer.func */
            8884097, 8, 0, /* 1611: pointer.func */
            8884097, 8, 0, /* 1614: pointer.func */
            8884097, 8, 0, /* 1617: pointer.func */
            8884097, 8, 0, /* 1620: pointer.func */
            8884097, 8, 0, /* 1623: pointer.func */
            8884097, 8, 0, /* 1626: pointer.func */
            8884097, 8, 0, /* 1629: pointer.func */
            8884097, 8, 0, /* 1632: pointer.func */
            8884097, 8, 0, /* 1635: pointer.func */
            8884097, 8, 0, /* 1638: pointer.func */
            8884097, 8, 0, /* 1641: pointer.func */
            1, 8, 1, /* 1644: pointer.struct.ec_point_st */
            	1649, 0,
            0, 88, 4, /* 1649: struct.ec_point_st */
            	1660, 0,
            	1832, 8,
            	1832, 32,
            	1832, 56,
            1, 8, 1, /* 1660: pointer.struct.ec_method_st */
            	1665, 0,
            0, 304, 37, /* 1665: struct.ec_method_st */
            	1742, 8,
            	1745, 16,
            	1745, 24,
            	1748, 32,
            	1751, 40,
            	1754, 48,
            	1757, 56,
            	1760, 64,
            	1763, 72,
            	1766, 80,
            	1766, 88,
            	1769, 96,
            	1772, 104,
            	1775, 112,
            	1778, 120,
            	1781, 128,
            	1784, 136,
            	1787, 144,
            	1790, 152,
            	1793, 160,
            	1796, 168,
            	1799, 176,
            	1802, 184,
            	1805, 192,
            	1808, 200,
            	1811, 208,
            	1802, 216,
            	1814, 224,
            	1817, 232,
            	1820, 240,
            	1757, 248,
            	1823, 256,
            	1826, 264,
            	1823, 272,
            	1826, 280,
            	1826, 288,
            	1829, 296,
            8884097, 8, 0, /* 1742: pointer.func */
            8884097, 8, 0, /* 1745: pointer.func */
            8884097, 8, 0, /* 1748: pointer.func */
            8884097, 8, 0, /* 1751: pointer.func */
            8884097, 8, 0, /* 1754: pointer.func */
            8884097, 8, 0, /* 1757: pointer.func */
            8884097, 8, 0, /* 1760: pointer.func */
            8884097, 8, 0, /* 1763: pointer.func */
            8884097, 8, 0, /* 1766: pointer.func */
            8884097, 8, 0, /* 1769: pointer.func */
            8884097, 8, 0, /* 1772: pointer.func */
            8884097, 8, 0, /* 1775: pointer.func */
            8884097, 8, 0, /* 1778: pointer.func */
            8884097, 8, 0, /* 1781: pointer.func */
            8884097, 8, 0, /* 1784: pointer.func */
            8884097, 8, 0, /* 1787: pointer.func */
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
            8884097, 8, 0, /* 1823: pointer.func */
            8884097, 8, 0, /* 1826: pointer.func */
            8884097, 8, 0, /* 1829: pointer.func */
            0, 24, 1, /* 1832: struct.bignum_st */
            	58, 0,
            0, 24, 1, /* 1837: struct.bignum_st */
            	58, 0,
            1, 8, 1, /* 1842: pointer.struct.ec_extra_data_st */
            	1847, 0,
            0, 40, 5, /* 1847: struct.ec_extra_data_st */
            	1860, 0,
            	31, 8,
            	1865, 16,
            	1868, 24,
            	1868, 32,
            1, 8, 1, /* 1860: pointer.struct.ec_extra_data_st */
            	1847, 0,
            8884097, 8, 0, /* 1865: pointer.func */
            8884097, 8, 0, /* 1868: pointer.func */
            8884097, 8, 0, /* 1871: pointer.func */
            1, 8, 1, /* 1874: pointer.struct.ec_point_st */
            	1649, 0,
            1, 8, 1, /* 1879: pointer.struct.bignum_st */
            	1884, 0,
            0, 24, 1, /* 1884: struct.bignum_st */
            	58, 0,
            1, 8, 1, /* 1889: pointer.struct.ec_extra_data_st */
            	1894, 0,
            0, 40, 5, /* 1894: struct.ec_extra_data_st */
            	1907, 0,
            	31, 8,
            	1865, 16,
            	1868, 24,
            	1868, 32,
            1, 8, 1, /* 1907: pointer.struct.ec_extra_data_st */
            	1894, 0,
            1, 8, 1, /* 1912: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1917, 0,
            0, 32, 2, /* 1917: struct.stack_st_fake_X509_ATTRIBUTE */
            	1924, 8,
            	439, 24,
            8884099, 8, 2, /* 1924: pointer_to_array_of_pointers_to_stack */
            	1931, 0,
            	436, 20,
            0, 8, 1, /* 1931: pointer.X509_ATTRIBUTE */
            	1936, 0,
            0, 0, 1, /* 1936: X509_ATTRIBUTE */
            	1941, 0,
            0, 24, 2, /* 1941: struct.x509_attributes_st */
            	1948, 0,
            	1962, 16,
            1, 8, 1, /* 1948: pointer.struct.asn1_object_st */
            	1953, 0,
            0, 40, 3, /* 1953: struct.asn1_object_st */
            	211, 0,
            	211, 8,
            	216, 24,
            0, 8, 3, /* 1962: union.unknown */
            	43, 0,
            	1971, 0,
            	2150, 0,
            1, 8, 1, /* 1971: pointer.struct.stack_st_ASN1_TYPE */
            	1976, 0,
            0, 32, 2, /* 1976: struct.stack_st_fake_ASN1_TYPE */
            	1983, 8,
            	439, 24,
            8884099, 8, 2, /* 1983: pointer_to_array_of_pointers_to_stack */
            	1990, 0,
            	436, 20,
            0, 8, 1, /* 1990: pointer.ASN1_TYPE */
            	1995, 0,
            0, 0, 1, /* 1995: ASN1_TYPE */
            	2000, 0,
            0, 16, 1, /* 2000: struct.asn1_type_st */
            	2005, 8,
            0, 8, 20, /* 2005: union.unknown */
            	43, 0,
            	2048, 0,
            	2058, 0,
            	2072, 0,
            	2077, 0,
            	2082, 0,
            	2087, 0,
            	2092, 0,
            	2097, 0,
            	2102, 0,
            	2107, 0,
            	2112, 0,
            	2117, 0,
            	2122, 0,
            	2127, 0,
            	2132, 0,
            	2137, 0,
            	2048, 0,
            	2048, 0,
            	2142, 0,
            1, 8, 1, /* 2048: pointer.struct.asn1_string_st */
            	2053, 0,
            0, 24, 1, /* 2053: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 2058: pointer.struct.asn1_object_st */
            	2063, 0,
            0, 40, 3, /* 2063: struct.asn1_object_st */
            	211, 0,
            	211, 8,
            	216, 24,
            1, 8, 1, /* 2072: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2077: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2082: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2087: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2092: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2097: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2102: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2107: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2112: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2117: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2122: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2127: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2132: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2137: pointer.struct.asn1_string_st */
            	2053, 0,
            1, 8, 1, /* 2142: pointer.struct.ASN1_VALUE_st */
            	2147, 0,
            0, 0, 0, /* 2147: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2150: pointer.struct.asn1_type_st */
            	2155, 0,
            0, 16, 1, /* 2155: struct.asn1_type_st */
            	2160, 8,
            0, 8, 20, /* 2160: union.unknown */
            	43, 0,
            	2203, 0,
            	1948, 0,
            	2213, 0,
            	2218, 0,
            	2223, 0,
            	2228, 0,
            	2233, 0,
            	2238, 0,
            	2243, 0,
            	2248, 0,
            	2253, 0,
            	2258, 0,
            	2263, 0,
            	2268, 0,
            	2273, 0,
            	2278, 0,
            	2203, 0,
            	2203, 0,
            	2283, 0,
            1, 8, 1, /* 2203: pointer.struct.asn1_string_st */
            	2208, 0,
            0, 24, 1, /* 2208: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 2213: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2218: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2223: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2228: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2233: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2238: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2243: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2248: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2253: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2258: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2263: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2268: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2273: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2278: pointer.struct.asn1_string_st */
            	2208, 0,
            1, 8, 1, /* 2283: pointer.struct.ASN1_VALUE_st */
            	2288, 0,
            0, 0, 0, /* 2288: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2291: pointer.struct.asn1_string_st */
            	172, 0,
            1, 8, 1, /* 2296: pointer.struct.stack_st_X509_EXTENSION */
            	2301, 0,
            0, 32, 2, /* 2301: struct.stack_st_fake_X509_EXTENSION */
            	2308, 8,
            	439, 24,
            8884099, 8, 2, /* 2308: pointer_to_array_of_pointers_to_stack */
            	2315, 0,
            	436, 20,
            0, 8, 1, /* 2315: pointer.X509_EXTENSION */
            	2320, 0,
            0, 0, 1, /* 2320: X509_EXTENSION */
            	2325, 0,
            0, 24, 2, /* 2325: struct.X509_extension_st */
            	2332, 0,
            	2346, 16,
            1, 8, 1, /* 2332: pointer.struct.asn1_object_st */
            	2337, 0,
            0, 40, 3, /* 2337: struct.asn1_object_st */
            	211, 0,
            	211, 8,
            	216, 24,
            1, 8, 1, /* 2346: pointer.struct.asn1_string_st */
            	2351, 0,
            0, 24, 1, /* 2351: struct.asn1_string_st */
            	177, 8,
            0, 24, 1, /* 2356: struct.ASN1_ENCODING_st */
            	177, 0,
            0, 16, 1, /* 2361: struct.crypto_ex_data_st */
            	2366, 0,
            1, 8, 1, /* 2366: pointer.struct.stack_st_void */
            	2371, 0,
            0, 32, 1, /* 2371: struct.stack_st_void */
            	2376, 0,
            0, 32, 2, /* 2376: struct.stack_st */
            	958, 8,
            	439, 24,
            1, 8, 1, /* 2383: pointer.struct.asn1_string_st */
            	172, 0,
            1, 8, 1, /* 2388: pointer.struct.AUTHORITY_KEYID_st */
            	2393, 0,
            0, 24, 3, /* 2393: struct.AUTHORITY_KEYID_st */
            	2402, 0,
            	2412, 8,
            	2706, 16,
            1, 8, 1, /* 2402: pointer.struct.asn1_string_st */
            	2407, 0,
            0, 24, 1, /* 2407: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 2412: pointer.struct.stack_st_GENERAL_NAME */
            	2417, 0,
            0, 32, 2, /* 2417: struct.stack_st_fake_GENERAL_NAME */
            	2424, 8,
            	439, 24,
            8884099, 8, 2, /* 2424: pointer_to_array_of_pointers_to_stack */
            	2431, 0,
            	436, 20,
            0, 8, 1, /* 2431: pointer.GENERAL_NAME */
            	2436, 0,
            0, 0, 1, /* 2436: GENERAL_NAME */
            	2441, 0,
            0, 16, 1, /* 2441: struct.GENERAL_NAME_st */
            	2446, 8,
            0, 8, 15, /* 2446: union.unknown */
            	43, 0,
            	2479, 0,
            	2598, 0,
            	2598, 0,
            	2505, 0,
            	2646, 0,
            	2694, 0,
            	2598, 0,
            	2583, 0,
            	2491, 0,
            	2583, 0,
            	2646, 0,
            	2598, 0,
            	2491, 0,
            	2505, 0,
            1, 8, 1, /* 2479: pointer.struct.otherName_st */
            	2484, 0,
            0, 16, 2, /* 2484: struct.otherName_st */
            	2491, 0,
            	2505, 8,
            1, 8, 1, /* 2491: pointer.struct.asn1_object_st */
            	2496, 0,
            0, 40, 3, /* 2496: struct.asn1_object_st */
            	211, 0,
            	211, 8,
            	216, 24,
            1, 8, 1, /* 2505: pointer.struct.asn1_type_st */
            	2510, 0,
            0, 16, 1, /* 2510: struct.asn1_type_st */
            	2515, 8,
            0, 8, 20, /* 2515: union.unknown */
            	43, 0,
            	2558, 0,
            	2491, 0,
            	2568, 0,
            	2573, 0,
            	2578, 0,
            	2583, 0,
            	2588, 0,
            	2593, 0,
            	2598, 0,
            	2603, 0,
            	2608, 0,
            	2613, 0,
            	2618, 0,
            	2623, 0,
            	2628, 0,
            	2633, 0,
            	2558, 0,
            	2558, 0,
            	2638, 0,
            1, 8, 1, /* 2558: pointer.struct.asn1_string_st */
            	2563, 0,
            0, 24, 1, /* 2563: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 2568: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2573: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2578: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2583: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2588: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2593: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2598: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2603: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2608: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2613: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2618: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2623: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2628: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2633: pointer.struct.asn1_string_st */
            	2563, 0,
            1, 8, 1, /* 2638: pointer.struct.ASN1_VALUE_st */
            	2643, 0,
            0, 0, 0, /* 2643: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2646: pointer.struct.X509_name_st */
            	2651, 0,
            0, 40, 3, /* 2651: struct.X509_name_st */
            	2660, 0,
            	2684, 16,
            	177, 24,
            1, 8, 1, /* 2660: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2665, 0,
            0, 32, 2, /* 2665: struct.stack_st_fake_X509_NAME_ENTRY */
            	2672, 8,
            	439, 24,
            8884099, 8, 2, /* 2672: pointer_to_array_of_pointers_to_stack */
            	2679, 0,
            	436, 20,
            0, 8, 1, /* 2679: pointer.X509_NAME_ENTRY */
            	400, 0,
            1, 8, 1, /* 2684: pointer.struct.buf_mem_st */
            	2689, 0,
            0, 24, 1, /* 2689: struct.buf_mem_st */
            	43, 8,
            1, 8, 1, /* 2694: pointer.struct.EDIPartyName_st */
            	2699, 0,
            0, 16, 2, /* 2699: struct.EDIPartyName_st */
            	2558, 0,
            	2558, 8,
            1, 8, 1, /* 2706: pointer.struct.asn1_string_st */
            	2407, 0,
            1, 8, 1, /* 2711: pointer.struct.X509_POLICY_CACHE_st */
            	2716, 0,
            0, 40, 2, /* 2716: struct.X509_POLICY_CACHE_st */
            	2723, 0,
            	3047, 8,
            1, 8, 1, /* 2723: pointer.struct.X509_POLICY_DATA_st */
            	2728, 0,
            0, 32, 3, /* 2728: struct.X509_POLICY_DATA_st */
            	2737, 8,
            	2751, 16,
            	3009, 24,
            1, 8, 1, /* 2737: pointer.struct.asn1_object_st */
            	2742, 0,
            0, 40, 3, /* 2742: struct.asn1_object_st */
            	211, 0,
            	211, 8,
            	216, 24,
            1, 8, 1, /* 2751: pointer.struct.stack_st_POLICYQUALINFO */
            	2756, 0,
            0, 32, 2, /* 2756: struct.stack_st_fake_POLICYQUALINFO */
            	2763, 8,
            	439, 24,
            8884099, 8, 2, /* 2763: pointer_to_array_of_pointers_to_stack */
            	2770, 0,
            	436, 20,
            0, 8, 1, /* 2770: pointer.POLICYQUALINFO */
            	2775, 0,
            0, 0, 1, /* 2775: POLICYQUALINFO */
            	2780, 0,
            0, 16, 2, /* 2780: struct.POLICYQUALINFO_st */
            	2787, 0,
            	2801, 8,
            1, 8, 1, /* 2787: pointer.struct.asn1_object_st */
            	2792, 0,
            0, 40, 3, /* 2792: struct.asn1_object_st */
            	211, 0,
            	211, 8,
            	216, 24,
            0, 8, 3, /* 2801: union.unknown */
            	2810, 0,
            	2820, 0,
            	2883, 0,
            1, 8, 1, /* 2810: pointer.struct.asn1_string_st */
            	2815, 0,
            0, 24, 1, /* 2815: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 2820: pointer.struct.USERNOTICE_st */
            	2825, 0,
            0, 16, 2, /* 2825: struct.USERNOTICE_st */
            	2832, 0,
            	2844, 8,
            1, 8, 1, /* 2832: pointer.struct.NOTICEREF_st */
            	2837, 0,
            0, 16, 2, /* 2837: struct.NOTICEREF_st */
            	2844, 0,
            	2849, 8,
            1, 8, 1, /* 2844: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2849: pointer.struct.stack_st_ASN1_INTEGER */
            	2854, 0,
            0, 32, 2, /* 2854: struct.stack_st_fake_ASN1_INTEGER */
            	2861, 8,
            	439, 24,
            8884099, 8, 2, /* 2861: pointer_to_array_of_pointers_to_stack */
            	2868, 0,
            	436, 20,
            0, 8, 1, /* 2868: pointer.ASN1_INTEGER */
            	2873, 0,
            0, 0, 1, /* 2873: ASN1_INTEGER */
            	2878, 0,
            0, 24, 1, /* 2878: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 2883: pointer.struct.asn1_type_st */
            	2888, 0,
            0, 16, 1, /* 2888: struct.asn1_type_st */
            	2893, 8,
            0, 8, 20, /* 2893: union.unknown */
            	43, 0,
            	2844, 0,
            	2787, 0,
            	2936, 0,
            	2941, 0,
            	2946, 0,
            	2951, 0,
            	2956, 0,
            	2961, 0,
            	2810, 0,
            	2966, 0,
            	2971, 0,
            	2976, 0,
            	2981, 0,
            	2986, 0,
            	2991, 0,
            	2996, 0,
            	2844, 0,
            	2844, 0,
            	3001, 0,
            1, 8, 1, /* 2936: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2941: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2946: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2951: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2956: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2961: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2966: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2971: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2976: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2981: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2986: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2991: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 2996: pointer.struct.asn1_string_st */
            	2815, 0,
            1, 8, 1, /* 3001: pointer.struct.ASN1_VALUE_st */
            	3006, 0,
            0, 0, 0, /* 3006: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3009: pointer.struct.stack_st_ASN1_OBJECT */
            	3014, 0,
            0, 32, 2, /* 3014: struct.stack_st_fake_ASN1_OBJECT */
            	3021, 8,
            	439, 24,
            8884099, 8, 2, /* 3021: pointer_to_array_of_pointers_to_stack */
            	3028, 0,
            	436, 20,
            0, 8, 1, /* 3028: pointer.ASN1_OBJECT */
            	3033, 0,
            0, 0, 1, /* 3033: ASN1_OBJECT */
            	3038, 0,
            0, 40, 3, /* 3038: struct.asn1_object_st */
            	211, 0,
            	211, 8,
            	216, 24,
            1, 8, 1, /* 3047: pointer.struct.stack_st_X509_POLICY_DATA */
            	3052, 0,
            0, 32, 2, /* 3052: struct.stack_st_fake_X509_POLICY_DATA */
            	3059, 8,
            	439, 24,
            8884099, 8, 2, /* 3059: pointer_to_array_of_pointers_to_stack */
            	3066, 0,
            	436, 20,
            0, 8, 1, /* 3066: pointer.X509_POLICY_DATA */
            	3071, 0,
            0, 0, 1, /* 3071: X509_POLICY_DATA */
            	3076, 0,
            0, 32, 3, /* 3076: struct.X509_POLICY_DATA_st */
            	3085, 8,
            	3099, 16,
            	3123, 24,
            1, 8, 1, /* 3085: pointer.struct.asn1_object_st */
            	3090, 0,
            0, 40, 3, /* 3090: struct.asn1_object_st */
            	211, 0,
            	211, 8,
            	216, 24,
            1, 8, 1, /* 3099: pointer.struct.stack_st_POLICYQUALINFO */
            	3104, 0,
            0, 32, 2, /* 3104: struct.stack_st_fake_POLICYQUALINFO */
            	3111, 8,
            	439, 24,
            8884099, 8, 2, /* 3111: pointer_to_array_of_pointers_to_stack */
            	3118, 0,
            	436, 20,
            0, 8, 1, /* 3118: pointer.POLICYQUALINFO */
            	2775, 0,
            1, 8, 1, /* 3123: pointer.struct.stack_st_ASN1_OBJECT */
            	3128, 0,
            0, 32, 2, /* 3128: struct.stack_st_fake_ASN1_OBJECT */
            	3135, 8,
            	439, 24,
            8884099, 8, 2, /* 3135: pointer_to_array_of_pointers_to_stack */
            	3142, 0,
            	436, 20,
            0, 8, 1, /* 3142: pointer.ASN1_OBJECT */
            	3033, 0,
            1, 8, 1, /* 3147: pointer.struct.stack_st_DIST_POINT */
            	3152, 0,
            0, 32, 2, /* 3152: struct.stack_st_fake_DIST_POINT */
            	3159, 8,
            	439, 24,
            8884099, 8, 2, /* 3159: pointer_to_array_of_pointers_to_stack */
            	3166, 0,
            	436, 20,
            0, 8, 1, /* 3166: pointer.DIST_POINT */
            	3171, 0,
            0, 0, 1, /* 3171: DIST_POINT */
            	3176, 0,
            0, 32, 3, /* 3176: struct.DIST_POINT_st */
            	3185, 0,
            	3276, 8,
            	3204, 16,
            1, 8, 1, /* 3185: pointer.struct.DIST_POINT_NAME_st */
            	3190, 0,
            0, 24, 2, /* 3190: struct.DIST_POINT_NAME_st */
            	3197, 8,
            	3252, 16,
            0, 8, 2, /* 3197: union.unknown */
            	3204, 0,
            	3228, 0,
            1, 8, 1, /* 3204: pointer.struct.stack_st_GENERAL_NAME */
            	3209, 0,
            0, 32, 2, /* 3209: struct.stack_st_fake_GENERAL_NAME */
            	3216, 8,
            	439, 24,
            8884099, 8, 2, /* 3216: pointer_to_array_of_pointers_to_stack */
            	3223, 0,
            	436, 20,
            0, 8, 1, /* 3223: pointer.GENERAL_NAME */
            	2436, 0,
            1, 8, 1, /* 3228: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3233, 0,
            0, 32, 2, /* 3233: struct.stack_st_fake_X509_NAME_ENTRY */
            	3240, 8,
            	439, 24,
            8884099, 8, 2, /* 3240: pointer_to_array_of_pointers_to_stack */
            	3247, 0,
            	436, 20,
            0, 8, 1, /* 3247: pointer.X509_NAME_ENTRY */
            	400, 0,
            1, 8, 1, /* 3252: pointer.struct.X509_name_st */
            	3257, 0,
            0, 40, 3, /* 3257: struct.X509_name_st */
            	3228, 0,
            	3266, 16,
            	177, 24,
            1, 8, 1, /* 3266: pointer.struct.buf_mem_st */
            	3271, 0,
            0, 24, 1, /* 3271: struct.buf_mem_st */
            	43, 8,
            1, 8, 1, /* 3276: pointer.struct.asn1_string_st */
            	3281, 0,
            0, 24, 1, /* 3281: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 3286: pointer.struct.stack_st_GENERAL_NAME */
            	3291, 0,
            0, 32, 2, /* 3291: struct.stack_st_fake_GENERAL_NAME */
            	3298, 8,
            	439, 24,
            8884099, 8, 2, /* 3298: pointer_to_array_of_pointers_to_stack */
            	3305, 0,
            	436, 20,
            0, 8, 1, /* 3305: pointer.GENERAL_NAME */
            	2436, 0,
            1, 8, 1, /* 3310: pointer.struct.NAME_CONSTRAINTS_st */
            	3315, 0,
            0, 16, 2, /* 3315: struct.NAME_CONSTRAINTS_st */
            	3322, 0,
            	3322, 8,
            1, 8, 1, /* 3322: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3327, 0,
            0, 32, 2, /* 3327: struct.stack_st_fake_GENERAL_SUBTREE */
            	3334, 8,
            	439, 24,
            8884099, 8, 2, /* 3334: pointer_to_array_of_pointers_to_stack */
            	3341, 0,
            	436, 20,
            0, 8, 1, /* 3341: pointer.GENERAL_SUBTREE */
            	3346, 0,
            0, 0, 1, /* 3346: GENERAL_SUBTREE */
            	3351, 0,
            0, 24, 3, /* 3351: struct.GENERAL_SUBTREE_st */
            	3360, 0,
            	3492, 8,
            	3492, 16,
            1, 8, 1, /* 3360: pointer.struct.GENERAL_NAME_st */
            	3365, 0,
            0, 16, 1, /* 3365: struct.GENERAL_NAME_st */
            	3370, 8,
            0, 8, 15, /* 3370: union.unknown */
            	43, 0,
            	3403, 0,
            	3522, 0,
            	3522, 0,
            	3429, 0,
            	3562, 0,
            	3610, 0,
            	3522, 0,
            	3507, 0,
            	3415, 0,
            	3507, 0,
            	3562, 0,
            	3522, 0,
            	3415, 0,
            	3429, 0,
            1, 8, 1, /* 3403: pointer.struct.otherName_st */
            	3408, 0,
            0, 16, 2, /* 3408: struct.otherName_st */
            	3415, 0,
            	3429, 8,
            1, 8, 1, /* 3415: pointer.struct.asn1_object_st */
            	3420, 0,
            0, 40, 3, /* 3420: struct.asn1_object_st */
            	211, 0,
            	211, 8,
            	216, 24,
            1, 8, 1, /* 3429: pointer.struct.asn1_type_st */
            	3434, 0,
            0, 16, 1, /* 3434: struct.asn1_type_st */
            	3439, 8,
            0, 8, 20, /* 3439: union.unknown */
            	43, 0,
            	3482, 0,
            	3415, 0,
            	3492, 0,
            	3497, 0,
            	3502, 0,
            	3507, 0,
            	3512, 0,
            	3517, 0,
            	3522, 0,
            	3527, 0,
            	3532, 0,
            	3537, 0,
            	3542, 0,
            	3547, 0,
            	3552, 0,
            	3557, 0,
            	3482, 0,
            	3482, 0,
            	3001, 0,
            1, 8, 1, /* 3482: pointer.struct.asn1_string_st */
            	3487, 0,
            0, 24, 1, /* 3487: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 3492: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3497: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3502: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3507: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3512: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3517: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3522: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3527: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3532: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3537: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3542: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3547: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3552: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3557: pointer.struct.asn1_string_st */
            	3487, 0,
            1, 8, 1, /* 3562: pointer.struct.X509_name_st */
            	3567, 0,
            0, 40, 3, /* 3567: struct.X509_name_st */
            	3576, 0,
            	3600, 16,
            	177, 24,
            1, 8, 1, /* 3576: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3581, 0,
            0, 32, 2, /* 3581: struct.stack_st_fake_X509_NAME_ENTRY */
            	3588, 8,
            	439, 24,
            8884099, 8, 2, /* 3588: pointer_to_array_of_pointers_to_stack */
            	3595, 0,
            	436, 20,
            0, 8, 1, /* 3595: pointer.X509_NAME_ENTRY */
            	400, 0,
            1, 8, 1, /* 3600: pointer.struct.buf_mem_st */
            	3605, 0,
            0, 24, 1, /* 3605: struct.buf_mem_st */
            	43, 8,
            1, 8, 1, /* 3610: pointer.struct.EDIPartyName_st */
            	3615, 0,
            0, 16, 2, /* 3615: struct.EDIPartyName_st */
            	3482, 0,
            	3482, 8,
            1, 8, 1, /* 3622: pointer.struct.x509_cert_aux_st */
            	3627, 0,
            0, 40, 5, /* 3627: struct.x509_cert_aux_st */
            	3640, 0,
            	3640, 8,
            	3664, 16,
            	2383, 24,
            	3669, 32,
            1, 8, 1, /* 3640: pointer.struct.stack_st_ASN1_OBJECT */
            	3645, 0,
            0, 32, 2, /* 3645: struct.stack_st_fake_ASN1_OBJECT */
            	3652, 8,
            	439, 24,
            8884099, 8, 2, /* 3652: pointer_to_array_of_pointers_to_stack */
            	3659, 0,
            	436, 20,
            0, 8, 1, /* 3659: pointer.ASN1_OBJECT */
            	3033, 0,
            1, 8, 1, /* 3664: pointer.struct.asn1_string_st */
            	172, 0,
            1, 8, 1, /* 3669: pointer.struct.stack_st_X509_ALGOR */
            	3674, 0,
            0, 32, 2, /* 3674: struct.stack_st_fake_X509_ALGOR */
            	3681, 8,
            	439, 24,
            8884099, 8, 2, /* 3681: pointer_to_array_of_pointers_to_stack */
            	3688, 0,
            	436, 20,
            0, 8, 1, /* 3688: pointer.X509_ALGOR */
            	3693, 0,
            0, 0, 1, /* 3693: X509_ALGOR */
            	190, 0,
            1, 8, 1, /* 3698: pointer.struct.evp_pkey_st */
            	3703, 0,
            0, 56, 4, /* 3703: struct.evp_pkey_st */
            	3714, 16,
            	3719, 24,
            	3724, 32,
            	3757, 48,
            1, 8, 1, /* 3714: pointer.struct.evp_pkey_asn1_method_st */
            	519, 0,
            1, 8, 1, /* 3719: pointer.struct.engine_st */
            	620, 0,
            0, 8, 5, /* 3724: union.unknown */
            	43, 0,
            	3737, 0,
            	3742, 0,
            	3747, 0,
            	3752, 0,
            1, 8, 1, /* 3737: pointer.struct.rsa_st */
            	986, 0,
            1, 8, 1, /* 3742: pointer.struct.dsa_st */
            	1188, 0,
            1, 8, 1, /* 3747: pointer.struct.dh_st */
            	1315, 0,
            1, 8, 1, /* 3752: pointer.struct.ec_key_st */
            	1429, 0,
            1, 8, 1, /* 3757: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3762, 0,
            0, 32, 2, /* 3762: struct.stack_st_fake_X509_ATTRIBUTE */
            	3769, 8,
            	439, 24,
            8884099, 8, 2, /* 3769: pointer_to_array_of_pointers_to_stack */
            	3776, 0,
            	436, 20,
            0, 8, 1, /* 3776: pointer.X509_ATTRIBUTE */
            	1936, 0,
            1, 8, 1, /* 3781: pointer.struct.env_md_st */
            	3786, 0,
            0, 120, 8, /* 3786: struct.env_md_st */
            	3805, 24,
            	3808, 32,
            	3811, 40,
            	3814, 48,
            	3805, 56,
            	3817, 64,
            	3820, 72,
            	3823, 112,
            8884097, 8, 0, /* 3805: pointer.func */
            8884097, 8, 0, /* 3808: pointer.func */
            8884097, 8, 0, /* 3811: pointer.func */
            8884097, 8, 0, /* 3814: pointer.func */
            8884097, 8, 0, /* 3817: pointer.func */
            8884097, 8, 0, /* 3820: pointer.func */
            8884097, 8, 0, /* 3823: pointer.func */
            1, 8, 1, /* 3826: pointer.struct.rsa_st */
            	986, 0,
            8884097, 8, 0, /* 3831: pointer.func */
            1, 8, 1, /* 3834: pointer.struct.dh_st */
            	1315, 0,
            8884097, 8, 0, /* 3839: pointer.func */
            1, 8, 1, /* 3842: pointer.struct.ec_key_st */
            	1429, 0,
            8884097, 8, 0, /* 3847: pointer.func */
            1, 8, 1, /* 3850: pointer.struct.stack_st_X509_NAME */
            	3855, 0,
            0, 32, 2, /* 3855: struct.stack_st_fake_X509_NAME */
            	3862, 8,
            	439, 24,
            8884099, 8, 2, /* 3862: pointer_to_array_of_pointers_to_stack */
            	3869, 0,
            	436, 20,
            0, 8, 1, /* 3869: pointer.X509_NAME */
            	3874, 0,
            0, 0, 1, /* 3874: X509_NAME */
            	3879, 0,
            0, 40, 3, /* 3879: struct.X509_name_st */
            	3888, 0,
            	3912, 16,
            	177, 24,
            1, 8, 1, /* 3888: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3893, 0,
            0, 32, 2, /* 3893: struct.stack_st_fake_X509_NAME_ENTRY */
            	3900, 8,
            	439, 24,
            8884099, 8, 2, /* 3900: pointer_to_array_of_pointers_to_stack */
            	3907, 0,
            	436, 20,
            0, 8, 1, /* 3907: pointer.X509_NAME_ENTRY */
            	400, 0,
            1, 8, 1, /* 3912: pointer.struct.buf_mem_st */
            	3917, 0,
            0, 24, 1, /* 3917: struct.buf_mem_st */
            	43, 8,
            8884097, 8, 0, /* 3922: pointer.func */
            1, 8, 1, /* 3925: pointer.struct.stack_st_SSL_COMP */
            	3930, 0,
            0, 32, 2, /* 3930: struct.stack_st_fake_SSL_COMP */
            	3937, 8,
            	439, 24,
            8884099, 8, 2, /* 3937: pointer_to_array_of_pointers_to_stack */
            	3944, 0,
            	436, 20,
            0, 8, 1, /* 3944: pointer.SSL_COMP */
            	3949, 0,
            0, 0, 1, /* 3949: SSL_COMP */
            	3954, 0,
            0, 24, 2, /* 3954: struct.ssl_comp_st */
            	211, 8,
            	3961, 16,
            1, 8, 1, /* 3961: pointer.struct.comp_method_st */
            	3966, 0,
            0, 64, 7, /* 3966: struct.comp_method_st */
            	211, 8,
            	3983, 16,
            	3986, 24,
            	3989, 32,
            	3989, 40,
            	3992, 48,
            	3992, 56,
            8884097, 8, 0, /* 3983: pointer.func */
            8884097, 8, 0, /* 3986: pointer.func */
            8884097, 8, 0, /* 3989: pointer.func */
            8884097, 8, 0, /* 3992: pointer.func */
            1, 8, 1, /* 3995: pointer.struct.stack_st_X509 */
            	4000, 0,
            0, 32, 2, /* 4000: struct.stack_st_fake_X509 */
            	4007, 8,
            	439, 24,
            8884099, 8, 2, /* 4007: pointer_to_array_of_pointers_to_stack */
            	4014, 0,
            	436, 20,
            0, 8, 1, /* 4014: pointer.X509 */
            	4019, 0,
            0, 0, 1, /* 4019: X509 */
            	4024, 0,
            0, 184, 12, /* 4024: struct.x509_st */
            	4051, 0,
            	4091, 8,
            	4123, 16,
            	43, 32,
            	1237, 40,
            	4157, 104,
            	4162, 112,
            	4167, 120,
            	4172, 128,
            	4196, 136,
            	4220, 144,
            	4225, 176,
            1, 8, 1, /* 4051: pointer.struct.x509_cinf_st */
            	4056, 0,
            0, 104, 11, /* 4056: struct.x509_cinf_st */
            	4081, 0,
            	4081, 8,
            	4091, 16,
            	4096, 24,
            	4101, 32,
            	4096, 40,
            	4118, 48,
            	4123, 56,
            	4123, 64,
            	4128, 72,
            	4152, 80,
            1, 8, 1, /* 4081: pointer.struct.asn1_string_st */
            	4086, 0,
            0, 24, 1, /* 4086: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 4091: pointer.struct.X509_algor_st */
            	190, 0,
            1, 8, 1, /* 4096: pointer.struct.X509_name_st */
            	3879, 0,
            1, 8, 1, /* 4101: pointer.struct.X509_val_st */
            	4106, 0,
            0, 16, 2, /* 4106: struct.X509_val_st */
            	4113, 0,
            	4113, 8,
            1, 8, 1, /* 4113: pointer.struct.asn1_string_st */
            	4086, 0,
            1, 8, 1, /* 4118: pointer.struct.X509_pubkey_st */
            	474, 0,
            1, 8, 1, /* 4123: pointer.struct.asn1_string_st */
            	4086, 0,
            1, 8, 1, /* 4128: pointer.struct.stack_st_X509_EXTENSION */
            	4133, 0,
            0, 32, 2, /* 4133: struct.stack_st_fake_X509_EXTENSION */
            	4140, 8,
            	439, 24,
            8884099, 8, 2, /* 4140: pointer_to_array_of_pointers_to_stack */
            	4147, 0,
            	436, 20,
            0, 8, 1, /* 4147: pointer.X509_EXTENSION */
            	2320, 0,
            0, 24, 1, /* 4152: struct.ASN1_ENCODING_st */
            	177, 0,
            1, 8, 1, /* 4157: pointer.struct.asn1_string_st */
            	4086, 0,
            1, 8, 1, /* 4162: pointer.struct.AUTHORITY_KEYID_st */
            	2393, 0,
            1, 8, 1, /* 4167: pointer.struct.X509_POLICY_CACHE_st */
            	2716, 0,
            1, 8, 1, /* 4172: pointer.struct.stack_st_DIST_POINT */
            	4177, 0,
            0, 32, 2, /* 4177: struct.stack_st_fake_DIST_POINT */
            	4184, 8,
            	439, 24,
            8884099, 8, 2, /* 4184: pointer_to_array_of_pointers_to_stack */
            	4191, 0,
            	436, 20,
            0, 8, 1, /* 4191: pointer.DIST_POINT */
            	3171, 0,
            1, 8, 1, /* 4196: pointer.struct.stack_st_GENERAL_NAME */
            	4201, 0,
            0, 32, 2, /* 4201: struct.stack_st_fake_GENERAL_NAME */
            	4208, 8,
            	439, 24,
            8884099, 8, 2, /* 4208: pointer_to_array_of_pointers_to_stack */
            	4215, 0,
            	436, 20,
            0, 8, 1, /* 4215: pointer.GENERAL_NAME */
            	2436, 0,
            1, 8, 1, /* 4220: pointer.struct.NAME_CONSTRAINTS_st */
            	3315, 0,
            1, 8, 1, /* 4225: pointer.struct.x509_cert_aux_st */
            	4230, 0,
            0, 40, 5, /* 4230: struct.x509_cert_aux_st */
            	4243, 0,
            	4243, 8,
            	4267, 16,
            	4157, 24,
            	4272, 32,
            1, 8, 1, /* 4243: pointer.struct.stack_st_ASN1_OBJECT */
            	4248, 0,
            0, 32, 2, /* 4248: struct.stack_st_fake_ASN1_OBJECT */
            	4255, 8,
            	439, 24,
            8884099, 8, 2, /* 4255: pointer_to_array_of_pointers_to_stack */
            	4262, 0,
            	436, 20,
            0, 8, 1, /* 4262: pointer.ASN1_OBJECT */
            	3033, 0,
            1, 8, 1, /* 4267: pointer.struct.asn1_string_st */
            	4086, 0,
            1, 8, 1, /* 4272: pointer.struct.stack_st_X509_ALGOR */
            	4277, 0,
            0, 32, 2, /* 4277: struct.stack_st_fake_X509_ALGOR */
            	4284, 8,
            	439, 24,
            8884099, 8, 2, /* 4284: pointer_to_array_of_pointers_to_stack */
            	4291, 0,
            	436, 20,
            0, 8, 1, /* 4291: pointer.X509_ALGOR */
            	3693, 0,
            8884097, 8, 0, /* 4296: pointer.func */
            8884097, 8, 0, /* 4299: pointer.func */
            8884097, 8, 0, /* 4302: pointer.func */
            8884097, 8, 0, /* 4305: pointer.func */
            8884097, 8, 0, /* 4308: pointer.func */
            0, 88, 1, /* 4311: struct.ssl_cipher_st */
            	211, 8,
            0, 40, 5, /* 4316: struct.x509_cert_aux_st */
            	4329, 0,
            	4329, 8,
            	4353, 16,
            	4363, 24,
            	4368, 32,
            1, 8, 1, /* 4329: pointer.struct.stack_st_ASN1_OBJECT */
            	4334, 0,
            0, 32, 2, /* 4334: struct.stack_st_fake_ASN1_OBJECT */
            	4341, 8,
            	439, 24,
            8884099, 8, 2, /* 4341: pointer_to_array_of_pointers_to_stack */
            	4348, 0,
            	436, 20,
            0, 8, 1, /* 4348: pointer.ASN1_OBJECT */
            	3033, 0,
            1, 8, 1, /* 4353: pointer.struct.asn1_string_st */
            	4358, 0,
            0, 24, 1, /* 4358: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 4363: pointer.struct.asn1_string_st */
            	4358, 0,
            1, 8, 1, /* 4368: pointer.struct.stack_st_X509_ALGOR */
            	4373, 0,
            0, 32, 2, /* 4373: struct.stack_st_fake_X509_ALGOR */
            	4380, 8,
            	439, 24,
            8884099, 8, 2, /* 4380: pointer_to_array_of_pointers_to_stack */
            	4387, 0,
            	436, 20,
            0, 8, 1, /* 4387: pointer.X509_ALGOR */
            	3693, 0,
            1, 8, 1, /* 4392: pointer.struct.stack_st_GENERAL_NAME */
            	4397, 0,
            0, 32, 2, /* 4397: struct.stack_st_fake_GENERAL_NAME */
            	4404, 8,
            	439, 24,
            8884099, 8, 2, /* 4404: pointer_to_array_of_pointers_to_stack */
            	4411, 0,
            	436, 20,
            0, 8, 1, /* 4411: pointer.GENERAL_NAME */
            	2436, 0,
            0, 24, 1, /* 4416: struct.ASN1_ENCODING_st */
            	177, 0,
            1, 8, 1, /* 4421: pointer.struct.stack_st_X509_EXTENSION */
            	4426, 0,
            0, 32, 2, /* 4426: struct.stack_st_fake_X509_EXTENSION */
            	4433, 8,
            	439, 24,
            8884099, 8, 2, /* 4433: pointer_to_array_of_pointers_to_stack */
            	4440, 0,
            	436, 20,
            0, 8, 1, /* 4440: pointer.X509_EXTENSION */
            	2320, 0,
            1, 8, 1, /* 4445: pointer.struct.X509_pubkey_st */
            	474, 0,
            0, 16, 2, /* 4450: struct.X509_val_st */
            	4457, 0,
            	4457, 8,
            1, 8, 1, /* 4457: pointer.struct.asn1_string_st */
            	4358, 0,
            1, 8, 1, /* 4462: pointer.struct.buf_mem_st */
            	4467, 0,
            0, 24, 1, /* 4467: struct.buf_mem_st */
            	43, 8,
            1, 8, 1, /* 4472: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4477, 0,
            0, 32, 2, /* 4477: struct.stack_st_fake_X509_NAME_ENTRY */
            	4484, 8,
            	439, 24,
            8884099, 8, 2, /* 4484: pointer_to_array_of_pointers_to_stack */
            	4491, 0,
            	436, 20,
            0, 8, 1, /* 4491: pointer.X509_NAME_ENTRY */
            	400, 0,
            1, 8, 1, /* 4496: pointer.struct.X509_name_st */
            	4501, 0,
            0, 40, 3, /* 4501: struct.X509_name_st */
            	4472, 0,
            	4462, 16,
            	177, 24,
            1, 8, 1, /* 4510: pointer.struct.X509_algor_st */
            	190, 0,
            0, 352, 14, /* 4515: struct.ssl_session_st */
            	43, 144,
            	43, 152,
            	4546, 168,
            	4998, 176,
            	5136, 224,
            	5141, 240,
            	5075, 248,
            	5175, 264,
            	5175, 272,
            	43, 280,
            	177, 296,
            	177, 312,
            	177, 320,
            	43, 344,
            1, 8, 1, /* 4546: pointer.struct.sess_cert_st */
            	4551, 0,
            0, 248, 5, /* 4551: struct.sess_cert_st */
            	4564, 0,
            	4588, 16,
            	4988, 216,
            	4993, 224,
            	3842, 232,
            1, 8, 1, /* 4564: pointer.struct.stack_st_X509 */
            	4569, 0,
            0, 32, 2, /* 4569: struct.stack_st_fake_X509 */
            	4576, 8,
            	439, 24,
            8884099, 8, 2, /* 4576: pointer_to_array_of_pointers_to_stack */
            	4583, 0,
            	436, 20,
            0, 8, 1, /* 4583: pointer.X509 */
            	4019, 0,
            1, 8, 1, /* 4588: pointer.struct.cert_pkey_st */
            	4593, 0,
            0, 24, 3, /* 4593: struct.cert_pkey_st */
            	4602, 0,
            	4881, 8,
            	4949, 16,
            1, 8, 1, /* 4602: pointer.struct.x509_st */
            	4607, 0,
            0, 184, 12, /* 4607: struct.x509_st */
            	4634, 0,
            	4674, 8,
            	4749, 16,
            	43, 32,
            	4783, 40,
            	4805, 104,
            	2388, 112,
            	2711, 120,
            	3147, 128,
            	3286, 136,
            	3310, 144,
            	4810, 176,
            1, 8, 1, /* 4634: pointer.struct.x509_cinf_st */
            	4639, 0,
            0, 104, 11, /* 4639: struct.x509_cinf_st */
            	4664, 0,
            	4664, 8,
            	4674, 16,
            	4679, 24,
            	4727, 32,
            	4679, 40,
            	4744, 48,
            	4749, 56,
            	4749, 64,
            	4754, 72,
            	4778, 80,
            1, 8, 1, /* 4664: pointer.struct.asn1_string_st */
            	4669, 0,
            0, 24, 1, /* 4669: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 4674: pointer.struct.X509_algor_st */
            	190, 0,
            1, 8, 1, /* 4679: pointer.struct.X509_name_st */
            	4684, 0,
            0, 40, 3, /* 4684: struct.X509_name_st */
            	4693, 0,
            	4717, 16,
            	177, 24,
            1, 8, 1, /* 4693: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4698, 0,
            0, 32, 2, /* 4698: struct.stack_st_fake_X509_NAME_ENTRY */
            	4705, 8,
            	439, 24,
            8884099, 8, 2, /* 4705: pointer_to_array_of_pointers_to_stack */
            	4712, 0,
            	436, 20,
            0, 8, 1, /* 4712: pointer.X509_NAME_ENTRY */
            	400, 0,
            1, 8, 1, /* 4717: pointer.struct.buf_mem_st */
            	4722, 0,
            0, 24, 1, /* 4722: struct.buf_mem_st */
            	43, 8,
            1, 8, 1, /* 4727: pointer.struct.X509_val_st */
            	4732, 0,
            0, 16, 2, /* 4732: struct.X509_val_st */
            	4739, 0,
            	4739, 8,
            1, 8, 1, /* 4739: pointer.struct.asn1_string_st */
            	4669, 0,
            1, 8, 1, /* 4744: pointer.struct.X509_pubkey_st */
            	474, 0,
            1, 8, 1, /* 4749: pointer.struct.asn1_string_st */
            	4669, 0,
            1, 8, 1, /* 4754: pointer.struct.stack_st_X509_EXTENSION */
            	4759, 0,
            0, 32, 2, /* 4759: struct.stack_st_fake_X509_EXTENSION */
            	4766, 8,
            	439, 24,
            8884099, 8, 2, /* 4766: pointer_to_array_of_pointers_to_stack */
            	4773, 0,
            	436, 20,
            0, 8, 1, /* 4773: pointer.X509_EXTENSION */
            	2320, 0,
            0, 24, 1, /* 4778: struct.ASN1_ENCODING_st */
            	177, 0,
            0, 16, 1, /* 4783: struct.crypto_ex_data_st */
            	4788, 0,
            1, 8, 1, /* 4788: pointer.struct.stack_st_void */
            	4793, 0,
            0, 32, 1, /* 4793: struct.stack_st_void */
            	4798, 0,
            0, 32, 2, /* 4798: struct.stack_st */
            	958, 8,
            	439, 24,
            1, 8, 1, /* 4805: pointer.struct.asn1_string_st */
            	4669, 0,
            1, 8, 1, /* 4810: pointer.struct.x509_cert_aux_st */
            	4815, 0,
            0, 40, 5, /* 4815: struct.x509_cert_aux_st */
            	4828, 0,
            	4828, 8,
            	4852, 16,
            	4805, 24,
            	4857, 32,
            1, 8, 1, /* 4828: pointer.struct.stack_st_ASN1_OBJECT */
            	4833, 0,
            0, 32, 2, /* 4833: struct.stack_st_fake_ASN1_OBJECT */
            	4840, 8,
            	439, 24,
            8884099, 8, 2, /* 4840: pointer_to_array_of_pointers_to_stack */
            	4847, 0,
            	436, 20,
            0, 8, 1, /* 4847: pointer.ASN1_OBJECT */
            	3033, 0,
            1, 8, 1, /* 4852: pointer.struct.asn1_string_st */
            	4669, 0,
            1, 8, 1, /* 4857: pointer.struct.stack_st_X509_ALGOR */
            	4862, 0,
            0, 32, 2, /* 4862: struct.stack_st_fake_X509_ALGOR */
            	4869, 8,
            	439, 24,
            8884099, 8, 2, /* 4869: pointer_to_array_of_pointers_to_stack */
            	4876, 0,
            	436, 20,
            0, 8, 1, /* 4876: pointer.X509_ALGOR */
            	3693, 0,
            1, 8, 1, /* 4881: pointer.struct.evp_pkey_st */
            	4886, 0,
            0, 56, 4, /* 4886: struct.evp_pkey_st */
            	3714, 16,
            	3719, 24,
            	4897, 32,
            	4925, 48,
            0, 8, 5, /* 4897: union.unknown */
            	43, 0,
            	4910, 0,
            	4915, 0,
            	4920, 0,
            	3752, 0,
            1, 8, 1, /* 4910: pointer.struct.rsa_st */
            	986, 0,
            1, 8, 1, /* 4915: pointer.struct.dsa_st */
            	1188, 0,
            1, 8, 1, /* 4920: pointer.struct.dh_st */
            	1315, 0,
            1, 8, 1, /* 4925: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4930, 0,
            0, 32, 2, /* 4930: struct.stack_st_fake_X509_ATTRIBUTE */
            	4937, 8,
            	439, 24,
            8884099, 8, 2, /* 4937: pointer_to_array_of_pointers_to_stack */
            	4944, 0,
            	436, 20,
            0, 8, 1, /* 4944: pointer.X509_ATTRIBUTE */
            	1936, 0,
            1, 8, 1, /* 4949: pointer.struct.env_md_st */
            	4954, 0,
            0, 120, 8, /* 4954: struct.env_md_st */
            	4973, 24,
            	4976, 32,
            	4979, 40,
            	4982, 48,
            	4973, 56,
            	3817, 64,
            	3820, 72,
            	4985, 112,
            8884097, 8, 0, /* 4973: pointer.func */
            8884097, 8, 0, /* 4976: pointer.func */
            8884097, 8, 0, /* 4979: pointer.func */
            8884097, 8, 0, /* 4982: pointer.func */
            8884097, 8, 0, /* 4985: pointer.func */
            1, 8, 1, /* 4988: pointer.struct.rsa_st */
            	986, 0,
            1, 8, 1, /* 4993: pointer.struct.dh_st */
            	1315, 0,
            1, 8, 1, /* 4998: pointer.struct.x509_st */
            	5003, 0,
            0, 184, 12, /* 5003: struct.x509_st */
            	5030, 0,
            	4510, 8,
            	5070, 16,
            	43, 32,
            	5075, 40,
            	4363, 104,
            	5097, 112,
            	2711, 120,
            	5102, 128,
            	4392, 136,
            	5126, 144,
            	5131, 176,
            1, 8, 1, /* 5030: pointer.struct.x509_cinf_st */
            	5035, 0,
            0, 104, 11, /* 5035: struct.x509_cinf_st */
            	5060, 0,
            	5060, 8,
            	4510, 16,
            	4496, 24,
            	5065, 32,
            	4496, 40,
            	4445, 48,
            	5070, 56,
            	5070, 64,
            	4421, 72,
            	4416, 80,
            1, 8, 1, /* 5060: pointer.struct.asn1_string_st */
            	4358, 0,
            1, 8, 1, /* 5065: pointer.struct.X509_val_st */
            	4450, 0,
            1, 8, 1, /* 5070: pointer.struct.asn1_string_st */
            	4358, 0,
            0, 16, 1, /* 5075: struct.crypto_ex_data_st */
            	5080, 0,
            1, 8, 1, /* 5080: pointer.struct.stack_st_void */
            	5085, 0,
            0, 32, 1, /* 5085: struct.stack_st_void */
            	5090, 0,
            0, 32, 2, /* 5090: struct.stack_st */
            	958, 8,
            	439, 24,
            1, 8, 1, /* 5097: pointer.struct.AUTHORITY_KEYID_st */
            	2393, 0,
            1, 8, 1, /* 5102: pointer.struct.stack_st_DIST_POINT */
            	5107, 0,
            0, 32, 2, /* 5107: struct.stack_st_fake_DIST_POINT */
            	5114, 8,
            	439, 24,
            8884099, 8, 2, /* 5114: pointer_to_array_of_pointers_to_stack */
            	5121, 0,
            	436, 20,
            0, 8, 1, /* 5121: pointer.DIST_POINT */
            	3171, 0,
            1, 8, 1, /* 5126: pointer.struct.NAME_CONSTRAINTS_st */
            	3315, 0,
            1, 8, 1, /* 5131: pointer.struct.x509_cert_aux_st */
            	4316, 0,
            1, 8, 1, /* 5136: pointer.struct.ssl_cipher_st */
            	4311, 0,
            1, 8, 1, /* 5141: pointer.struct.stack_st_SSL_CIPHER */
            	5146, 0,
            0, 32, 2, /* 5146: struct.stack_st_fake_SSL_CIPHER */
            	5153, 8,
            	439, 24,
            8884099, 8, 2, /* 5153: pointer_to_array_of_pointers_to_stack */
            	5160, 0,
            	436, 20,
            0, 8, 1, /* 5160: pointer.SSL_CIPHER */
            	5165, 0,
            0, 0, 1, /* 5165: SSL_CIPHER */
            	5170, 0,
            0, 88, 1, /* 5170: struct.ssl_cipher_st */
            	211, 8,
            1, 8, 1, /* 5175: pointer.struct.ssl_session_st */
            	4515, 0,
            8884097, 8, 0, /* 5180: pointer.func */
            1, 8, 1, /* 5183: pointer.struct.stack_st_X509_LOOKUP */
            	5188, 0,
            0, 32, 2, /* 5188: struct.stack_st_fake_X509_LOOKUP */
            	5195, 8,
            	439, 24,
            8884099, 8, 2, /* 5195: pointer_to_array_of_pointers_to_stack */
            	5202, 0,
            	436, 20,
            0, 8, 1, /* 5202: pointer.X509_LOOKUP */
            	5207, 0,
            0, 0, 1, /* 5207: X509_LOOKUP */
            	5212, 0,
            0, 32, 3, /* 5212: struct.x509_lookup_st */
            	5221, 8,
            	43, 16,
            	5270, 24,
            1, 8, 1, /* 5221: pointer.struct.x509_lookup_method_st */
            	5226, 0,
            0, 80, 10, /* 5226: struct.x509_lookup_method_st */
            	211, 0,
            	5249, 8,
            	5252, 16,
            	5249, 24,
            	5249, 32,
            	5255, 40,
            	5258, 48,
            	5261, 56,
            	5264, 64,
            	5267, 72,
            8884097, 8, 0, /* 5249: pointer.func */
            8884097, 8, 0, /* 5252: pointer.func */
            8884097, 8, 0, /* 5255: pointer.func */
            8884097, 8, 0, /* 5258: pointer.func */
            8884097, 8, 0, /* 5261: pointer.func */
            8884097, 8, 0, /* 5264: pointer.func */
            8884097, 8, 0, /* 5267: pointer.func */
            1, 8, 1, /* 5270: pointer.struct.x509_store_st */
            	5275, 0,
            0, 144, 15, /* 5275: struct.x509_store_st */
            	5308, 8,
            	5982, 16,
            	6006, 24,
            	6018, 32,
            	6021, 40,
            	6024, 48,
            	6027, 56,
            	6018, 64,
            	6030, 72,
            	6033, 80,
            	6036, 88,
            	6039, 96,
            	6042, 104,
            	6018, 112,
            	5534, 120,
            1, 8, 1, /* 5308: pointer.struct.stack_st_X509_OBJECT */
            	5313, 0,
            0, 32, 2, /* 5313: struct.stack_st_fake_X509_OBJECT */
            	5320, 8,
            	439, 24,
            8884099, 8, 2, /* 5320: pointer_to_array_of_pointers_to_stack */
            	5327, 0,
            	436, 20,
            0, 8, 1, /* 5327: pointer.X509_OBJECT */
            	5332, 0,
            0, 0, 1, /* 5332: X509_OBJECT */
            	5337, 0,
            0, 16, 1, /* 5337: struct.x509_object_st */
            	5342, 8,
            0, 8, 4, /* 5342: union.unknown */
            	43, 0,
            	5353, 0,
            	5695, 0,
            	5904, 0,
            1, 8, 1, /* 5353: pointer.struct.x509_st */
            	5358, 0,
            0, 184, 12, /* 5358: struct.x509_st */
            	5385, 0,
            	5425, 8,
            	5500, 16,
            	43, 32,
            	5534, 40,
            	5556, 104,
            	5561, 112,
            	5566, 120,
            	5571, 128,
            	5595, 136,
            	5619, 144,
            	5624, 176,
            1, 8, 1, /* 5385: pointer.struct.x509_cinf_st */
            	5390, 0,
            0, 104, 11, /* 5390: struct.x509_cinf_st */
            	5415, 0,
            	5415, 8,
            	5425, 16,
            	5430, 24,
            	5478, 32,
            	5430, 40,
            	5495, 48,
            	5500, 56,
            	5500, 64,
            	5505, 72,
            	5529, 80,
            1, 8, 1, /* 5415: pointer.struct.asn1_string_st */
            	5420, 0,
            0, 24, 1, /* 5420: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 5425: pointer.struct.X509_algor_st */
            	190, 0,
            1, 8, 1, /* 5430: pointer.struct.X509_name_st */
            	5435, 0,
            0, 40, 3, /* 5435: struct.X509_name_st */
            	5444, 0,
            	5468, 16,
            	177, 24,
            1, 8, 1, /* 5444: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5449, 0,
            0, 32, 2, /* 5449: struct.stack_st_fake_X509_NAME_ENTRY */
            	5456, 8,
            	439, 24,
            8884099, 8, 2, /* 5456: pointer_to_array_of_pointers_to_stack */
            	5463, 0,
            	436, 20,
            0, 8, 1, /* 5463: pointer.X509_NAME_ENTRY */
            	400, 0,
            1, 8, 1, /* 5468: pointer.struct.buf_mem_st */
            	5473, 0,
            0, 24, 1, /* 5473: struct.buf_mem_st */
            	43, 8,
            1, 8, 1, /* 5478: pointer.struct.X509_val_st */
            	5483, 0,
            0, 16, 2, /* 5483: struct.X509_val_st */
            	5490, 0,
            	5490, 8,
            1, 8, 1, /* 5490: pointer.struct.asn1_string_st */
            	5420, 0,
            1, 8, 1, /* 5495: pointer.struct.X509_pubkey_st */
            	474, 0,
            1, 8, 1, /* 5500: pointer.struct.asn1_string_st */
            	5420, 0,
            1, 8, 1, /* 5505: pointer.struct.stack_st_X509_EXTENSION */
            	5510, 0,
            0, 32, 2, /* 5510: struct.stack_st_fake_X509_EXTENSION */
            	5517, 8,
            	439, 24,
            8884099, 8, 2, /* 5517: pointer_to_array_of_pointers_to_stack */
            	5524, 0,
            	436, 20,
            0, 8, 1, /* 5524: pointer.X509_EXTENSION */
            	2320, 0,
            0, 24, 1, /* 5529: struct.ASN1_ENCODING_st */
            	177, 0,
            0, 16, 1, /* 5534: struct.crypto_ex_data_st */
            	5539, 0,
            1, 8, 1, /* 5539: pointer.struct.stack_st_void */
            	5544, 0,
            0, 32, 1, /* 5544: struct.stack_st_void */
            	5549, 0,
            0, 32, 2, /* 5549: struct.stack_st */
            	958, 8,
            	439, 24,
            1, 8, 1, /* 5556: pointer.struct.asn1_string_st */
            	5420, 0,
            1, 8, 1, /* 5561: pointer.struct.AUTHORITY_KEYID_st */
            	2393, 0,
            1, 8, 1, /* 5566: pointer.struct.X509_POLICY_CACHE_st */
            	2716, 0,
            1, 8, 1, /* 5571: pointer.struct.stack_st_DIST_POINT */
            	5576, 0,
            0, 32, 2, /* 5576: struct.stack_st_fake_DIST_POINT */
            	5583, 8,
            	439, 24,
            8884099, 8, 2, /* 5583: pointer_to_array_of_pointers_to_stack */
            	5590, 0,
            	436, 20,
            0, 8, 1, /* 5590: pointer.DIST_POINT */
            	3171, 0,
            1, 8, 1, /* 5595: pointer.struct.stack_st_GENERAL_NAME */
            	5600, 0,
            0, 32, 2, /* 5600: struct.stack_st_fake_GENERAL_NAME */
            	5607, 8,
            	439, 24,
            8884099, 8, 2, /* 5607: pointer_to_array_of_pointers_to_stack */
            	5614, 0,
            	436, 20,
            0, 8, 1, /* 5614: pointer.GENERAL_NAME */
            	2436, 0,
            1, 8, 1, /* 5619: pointer.struct.NAME_CONSTRAINTS_st */
            	3315, 0,
            1, 8, 1, /* 5624: pointer.struct.x509_cert_aux_st */
            	5629, 0,
            0, 40, 5, /* 5629: struct.x509_cert_aux_st */
            	5642, 0,
            	5642, 8,
            	5666, 16,
            	5556, 24,
            	5671, 32,
            1, 8, 1, /* 5642: pointer.struct.stack_st_ASN1_OBJECT */
            	5647, 0,
            0, 32, 2, /* 5647: struct.stack_st_fake_ASN1_OBJECT */
            	5654, 8,
            	439, 24,
            8884099, 8, 2, /* 5654: pointer_to_array_of_pointers_to_stack */
            	5661, 0,
            	436, 20,
            0, 8, 1, /* 5661: pointer.ASN1_OBJECT */
            	3033, 0,
            1, 8, 1, /* 5666: pointer.struct.asn1_string_st */
            	5420, 0,
            1, 8, 1, /* 5671: pointer.struct.stack_st_X509_ALGOR */
            	5676, 0,
            0, 32, 2, /* 5676: struct.stack_st_fake_X509_ALGOR */
            	5683, 8,
            	439, 24,
            8884099, 8, 2, /* 5683: pointer_to_array_of_pointers_to_stack */
            	5690, 0,
            	436, 20,
            0, 8, 1, /* 5690: pointer.X509_ALGOR */
            	3693, 0,
            1, 8, 1, /* 5695: pointer.struct.X509_crl_st */
            	5700, 0,
            0, 120, 10, /* 5700: struct.X509_crl_st */
            	5723, 0,
            	5425, 8,
            	5500, 16,
            	5561, 32,
            	5826, 40,
            	5415, 56,
            	5415, 64,
            	5838, 96,
            	5879, 104,
            	31, 112,
            1, 8, 1, /* 5723: pointer.struct.X509_crl_info_st */
            	5728, 0,
            0, 80, 8, /* 5728: struct.X509_crl_info_st */
            	5415, 0,
            	5425, 8,
            	5430, 16,
            	5490, 24,
            	5490, 32,
            	5747, 40,
            	5505, 48,
            	5529, 56,
            1, 8, 1, /* 5747: pointer.struct.stack_st_X509_REVOKED */
            	5752, 0,
            0, 32, 2, /* 5752: struct.stack_st_fake_X509_REVOKED */
            	5759, 8,
            	439, 24,
            8884099, 8, 2, /* 5759: pointer_to_array_of_pointers_to_stack */
            	5766, 0,
            	436, 20,
            0, 8, 1, /* 5766: pointer.X509_REVOKED */
            	5771, 0,
            0, 0, 1, /* 5771: X509_REVOKED */
            	5776, 0,
            0, 40, 4, /* 5776: struct.x509_revoked_st */
            	5787, 0,
            	5797, 8,
            	5802, 16,
            	4196, 24,
            1, 8, 1, /* 5787: pointer.struct.asn1_string_st */
            	5792, 0,
            0, 24, 1, /* 5792: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 5797: pointer.struct.asn1_string_st */
            	5792, 0,
            1, 8, 1, /* 5802: pointer.struct.stack_st_X509_EXTENSION */
            	5807, 0,
            0, 32, 2, /* 5807: struct.stack_st_fake_X509_EXTENSION */
            	5814, 8,
            	439, 24,
            8884099, 8, 2, /* 5814: pointer_to_array_of_pointers_to_stack */
            	5821, 0,
            	436, 20,
            0, 8, 1, /* 5821: pointer.X509_EXTENSION */
            	2320, 0,
            1, 8, 1, /* 5826: pointer.struct.ISSUING_DIST_POINT_st */
            	5831, 0,
            0, 32, 2, /* 5831: struct.ISSUING_DIST_POINT_st */
            	3185, 0,
            	3276, 16,
            1, 8, 1, /* 5838: pointer.struct.stack_st_GENERAL_NAMES */
            	5843, 0,
            0, 32, 2, /* 5843: struct.stack_st_fake_GENERAL_NAMES */
            	5850, 8,
            	439, 24,
            8884099, 8, 2, /* 5850: pointer_to_array_of_pointers_to_stack */
            	5857, 0,
            	436, 20,
            0, 8, 1, /* 5857: pointer.GENERAL_NAMES */
            	5862, 0,
            0, 0, 1, /* 5862: GENERAL_NAMES */
            	5867, 0,
            0, 32, 1, /* 5867: struct.stack_st_GENERAL_NAME */
            	5872, 0,
            0, 32, 2, /* 5872: struct.stack_st */
            	958, 8,
            	439, 24,
            1, 8, 1, /* 5879: pointer.struct.x509_crl_method_st */
            	5884, 0,
            0, 40, 4, /* 5884: struct.x509_crl_method_st */
            	5895, 8,
            	5895, 16,
            	5898, 24,
            	5901, 32,
            8884097, 8, 0, /* 5895: pointer.func */
            8884097, 8, 0, /* 5898: pointer.func */
            8884097, 8, 0, /* 5901: pointer.func */
            1, 8, 1, /* 5904: pointer.struct.evp_pkey_st */
            	5909, 0,
            0, 56, 4, /* 5909: struct.evp_pkey_st */
            	5920, 16,
            	1078, 24,
            	5925, 32,
            	5958, 48,
            1, 8, 1, /* 5920: pointer.struct.evp_pkey_asn1_method_st */
            	519, 0,
            0, 8, 5, /* 5925: union.unknown */
            	43, 0,
            	5938, 0,
            	5943, 0,
            	5948, 0,
            	5953, 0,
            1, 8, 1, /* 5938: pointer.struct.rsa_st */
            	986, 0,
            1, 8, 1, /* 5943: pointer.struct.dsa_st */
            	1188, 0,
            1, 8, 1, /* 5948: pointer.struct.dh_st */
            	1315, 0,
            1, 8, 1, /* 5953: pointer.struct.ec_key_st */
            	1429, 0,
            1, 8, 1, /* 5958: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5963, 0,
            0, 32, 2, /* 5963: struct.stack_st_fake_X509_ATTRIBUTE */
            	5970, 8,
            	439, 24,
            8884099, 8, 2, /* 5970: pointer_to_array_of_pointers_to_stack */
            	5977, 0,
            	436, 20,
            0, 8, 1, /* 5977: pointer.X509_ATTRIBUTE */
            	1936, 0,
            1, 8, 1, /* 5982: pointer.struct.stack_st_X509_LOOKUP */
            	5987, 0,
            0, 32, 2, /* 5987: struct.stack_st_fake_X509_LOOKUP */
            	5994, 8,
            	439, 24,
            8884099, 8, 2, /* 5994: pointer_to_array_of_pointers_to_stack */
            	6001, 0,
            	436, 20,
            0, 8, 1, /* 6001: pointer.X509_LOOKUP */
            	5207, 0,
            1, 8, 1, /* 6006: pointer.struct.X509_VERIFY_PARAM_st */
            	6011, 0,
            0, 56, 2, /* 6011: struct.X509_VERIFY_PARAM_st */
            	43, 0,
            	5642, 48,
            8884097, 8, 0, /* 6018: pointer.func */
            8884097, 8, 0, /* 6021: pointer.func */
            8884097, 8, 0, /* 6024: pointer.func */
            8884097, 8, 0, /* 6027: pointer.func */
            8884097, 8, 0, /* 6030: pointer.func */
            8884097, 8, 0, /* 6033: pointer.func */
            8884097, 8, 0, /* 6036: pointer.func */
            8884097, 8, 0, /* 6039: pointer.func */
            8884097, 8, 0, /* 6042: pointer.func */
            8884097, 8, 0, /* 6045: pointer.func */
            1, 8, 1, /* 6048: pointer.struct.ssl3_enc_method */
            	6053, 0,
            0, 112, 11, /* 6053: struct.ssl3_enc_method */
            	6078, 0,
            	6081, 8,
            	6084, 16,
            	6087, 24,
            	6078, 32,
            	6090, 40,
            	6093, 56,
            	211, 64,
            	211, 80,
            	6096, 96,
            	6099, 104,
            8884097, 8, 0, /* 6078: pointer.func */
            8884097, 8, 0, /* 6081: pointer.func */
            8884097, 8, 0, /* 6084: pointer.func */
            8884097, 8, 0, /* 6087: pointer.func */
            8884097, 8, 0, /* 6090: pointer.func */
            8884097, 8, 0, /* 6093: pointer.func */
            8884097, 8, 0, /* 6096: pointer.func */
            8884097, 8, 0, /* 6099: pointer.func */
            8884097, 8, 0, /* 6102: pointer.func */
            8884097, 8, 0, /* 6105: pointer.func */
            8884097, 8, 0, /* 6108: pointer.func */
            8884097, 8, 0, /* 6111: pointer.func */
            8884097, 8, 0, /* 6114: pointer.func */
            8884097, 8, 0, /* 6117: pointer.func */
            0, 16, 1, /* 6120: struct.tls_session_ticket_ext_st */
            	31, 8,
            0, 24, 1, /* 6125: struct.asn1_string_st */
            	177, 8,
            0, 24, 1, /* 6130: struct.buf_mem_st */
            	43, 8,
            0, 8, 2, /* 6135: union.unknown */
            	6142, 0,
            	6185, 0,
            1, 8, 1, /* 6142: pointer.struct.X509_name_st */
            	6147, 0,
            0, 40, 3, /* 6147: struct.X509_name_st */
            	6156, 0,
            	6180, 16,
            	177, 24,
            1, 8, 1, /* 6156: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6161, 0,
            0, 32, 2, /* 6161: struct.stack_st_fake_X509_NAME_ENTRY */
            	6168, 8,
            	439, 24,
            8884099, 8, 2, /* 6168: pointer_to_array_of_pointers_to_stack */
            	6175, 0,
            	436, 20,
            0, 8, 1, /* 6175: pointer.X509_NAME_ENTRY */
            	400, 0,
            1, 8, 1, /* 6180: pointer.struct.buf_mem_st */
            	6130, 0,
            1, 8, 1, /* 6185: pointer.struct.asn1_string_st */
            	6125, 0,
            0, 0, 1, /* 6190: OCSP_RESPID */
            	6195, 0,
            0, 16, 1, /* 6195: struct.ocsp_responder_id_st */
            	6135, 8,
            0, 16, 1, /* 6200: struct.srtp_protection_profile_st */
            	211, 0,
            8884097, 8, 0, /* 6205: pointer.func */
            8884097, 8, 0, /* 6208: pointer.func */
            1, 8, 1, /* 6211: pointer.struct.bignum_st */
            	6216, 0,
            0, 24, 1, /* 6216: struct.bignum_st */
            	58, 0,
            0, 8, 1, /* 6221: struct.ssl3_buf_freelist_entry_st */
            	6226, 0,
            1, 8, 1, /* 6226: pointer.struct.ssl3_buf_freelist_entry_st */
            	6221, 0,
            0, 24, 1, /* 6231: struct.ssl3_buf_freelist_st */
            	6226, 16,
            1, 8, 1, /* 6236: pointer.struct.ssl3_buf_freelist_st */
            	6231, 0,
            8884097, 8, 0, /* 6241: pointer.func */
            1, 8, 1, /* 6244: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6249, 0,
            0, 32, 2, /* 6249: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6256, 8,
            	439, 24,
            8884099, 8, 2, /* 6256: pointer_to_array_of_pointers_to_stack */
            	6263, 0,
            	436, 20,
            0, 8, 1, /* 6263: pointer.SRTP_PROTECTION_PROFILE */
            	6268, 0,
            0, 0, 1, /* 6268: SRTP_PROTECTION_PROFILE */
            	6200, 0,
            1, 8, 1, /* 6273: pointer.struct.stack_st_SSL_COMP */
            	6278, 0,
            0, 32, 2, /* 6278: struct.stack_st_fake_SSL_COMP */
            	6285, 8,
            	439, 24,
            8884099, 8, 2, /* 6285: pointer_to_array_of_pointers_to_stack */
            	6292, 0,
            	436, 20,
            0, 8, 1, /* 6292: pointer.SSL_COMP */
            	3949, 0,
            8884097, 8, 0, /* 6297: pointer.func */
            8884097, 8, 0, /* 6300: pointer.func */
            8884097, 8, 0, /* 6303: pointer.func */
            8884097, 8, 0, /* 6306: pointer.func */
            8884097, 8, 0, /* 6309: pointer.func */
            1, 8, 1, /* 6312: pointer.struct.lhash_node_st */
            	6317, 0,
            0, 24, 2, /* 6317: struct.lhash_node_st */
            	31, 0,
            	6312, 8,
            1, 8, 1, /* 6324: pointer.struct.lhash_st */
            	6329, 0,
            0, 176, 3, /* 6329: struct.lhash_st */
            	6338, 0,
            	439, 8,
            	6345, 16,
            8884099, 8, 2, /* 6338: pointer_to_array_of_pointers_to_stack */
            	6312, 0,
            	63, 28,
            8884097, 8, 0, /* 6345: pointer.func */
            8884097, 8, 0, /* 6348: pointer.func */
            8884097, 8, 0, /* 6351: pointer.func */
            8884097, 8, 0, /* 6354: pointer.func */
            8884097, 8, 0, /* 6357: pointer.func */
            1, 8, 1, /* 6360: pointer.struct.stack_st_X509_LOOKUP */
            	6365, 0,
            0, 32, 2, /* 6365: struct.stack_st_fake_X509_LOOKUP */
            	6372, 8,
            	439, 24,
            8884099, 8, 2, /* 6372: pointer_to_array_of_pointers_to_stack */
            	6379, 0,
            	436, 20,
            0, 8, 1, /* 6379: pointer.X509_LOOKUP */
            	5207, 0,
            8884097, 8, 0, /* 6384: pointer.func */
            8884097, 8, 0, /* 6387: pointer.func */
            8884097, 8, 0, /* 6390: pointer.func */
            1, 8, 1, /* 6393: pointer.struct.ssl3_buf_freelist_st */
            	6231, 0,
            0, 16, 1, /* 6398: struct.srtp_protection_profile_st */
            	211, 0,
            1, 8, 1, /* 6403: pointer.struct.stack_st_X509 */
            	6408, 0,
            0, 32, 2, /* 6408: struct.stack_st_fake_X509 */
            	6415, 8,
            	439, 24,
            8884099, 8, 2, /* 6415: pointer_to_array_of_pointers_to_stack */
            	6422, 0,
            	436, 20,
            0, 8, 1, /* 6422: pointer.X509 */
            	4019, 0,
            8884097, 8, 0, /* 6427: pointer.func */
            8884097, 8, 0, /* 6430: pointer.func */
            1, 8, 1, /* 6433: pointer.struct.x509_store_st */
            	6438, 0,
            0, 144, 15, /* 6438: struct.x509_store_st */
            	6471, 8,
            	6360, 16,
            	6495, 24,
            	6354, 32,
            	6531, 40,
            	6534, 48,
            	6357, 56,
            	6354, 64,
            	6537, 72,
            	6430, 80,
            	6540, 88,
            	6351, 96,
            	6348, 104,
            	6354, 112,
            	6543, 120,
            1, 8, 1, /* 6471: pointer.struct.stack_st_X509_OBJECT */
            	6476, 0,
            0, 32, 2, /* 6476: struct.stack_st_fake_X509_OBJECT */
            	6483, 8,
            	439, 24,
            8884099, 8, 2, /* 6483: pointer_to_array_of_pointers_to_stack */
            	6490, 0,
            	436, 20,
            0, 8, 1, /* 6490: pointer.X509_OBJECT */
            	5332, 0,
            1, 8, 1, /* 6495: pointer.struct.X509_VERIFY_PARAM_st */
            	6500, 0,
            0, 56, 2, /* 6500: struct.X509_VERIFY_PARAM_st */
            	43, 0,
            	6507, 48,
            1, 8, 1, /* 6507: pointer.struct.stack_st_ASN1_OBJECT */
            	6512, 0,
            0, 32, 2, /* 6512: struct.stack_st_fake_ASN1_OBJECT */
            	6519, 8,
            	439, 24,
            8884099, 8, 2, /* 6519: pointer_to_array_of_pointers_to_stack */
            	6526, 0,
            	436, 20,
            0, 8, 1, /* 6526: pointer.ASN1_OBJECT */
            	3033, 0,
            8884097, 8, 0, /* 6531: pointer.func */
            8884097, 8, 0, /* 6534: pointer.func */
            8884097, 8, 0, /* 6537: pointer.func */
            8884097, 8, 0, /* 6540: pointer.func */
            0, 16, 1, /* 6543: struct.crypto_ex_data_st */
            	6548, 0,
            1, 8, 1, /* 6548: pointer.struct.stack_st_void */
            	6553, 0,
            0, 32, 1, /* 6553: struct.stack_st_void */
            	6558, 0,
            0, 32, 2, /* 6558: struct.stack_st */
            	958, 8,
            	439, 24,
            0, 736, 50, /* 6565: struct.ssl_ctx_st */
            	6668, 0,
            	6785, 8,
            	6785, 16,
            	6433, 24,
            	6324, 32,
            	6809, 48,
            	6809, 56,
            	7093, 80,
            	6309, 88,
            	7096, 96,
            	6306, 152,
            	31, 160,
            	6303, 168,
            	31, 176,
            	7099, 184,
            	6300, 192,
            	6297, 200,
            	6543, 208,
            	7102, 224,
            	7102, 232,
            	7102, 240,
            	6403, 248,
            	6273, 256,
            	7141, 264,
            	7144, 272,
            	7168, 304,
            	7173, 320,
            	31, 328,
            	6531, 376,
            	7176, 384,
            	6495, 392,
            	3719, 408,
            	6241, 416,
            	31, 424,
            	6390, 480,
            	6387, 488,
            	31, 496,
            	7179, 504,
            	31, 512,
            	43, 520,
            	7182, 528,
            	7185, 536,
            	6236, 552,
            	6236, 560,
            	7188, 568,
            	6208, 696,
            	31, 704,
            	6205, 712,
            	31, 720,
            	6244, 728,
            1, 8, 1, /* 6668: pointer.struct.ssl_method_st */
            	6673, 0,
            0, 232, 28, /* 6673: struct.ssl_method_st */
            	6732, 8,
            	6735, 16,
            	6735, 24,
            	6732, 32,
            	6732, 40,
            	6738, 48,
            	6738, 56,
            	6741, 64,
            	6732, 72,
            	6732, 80,
            	6732, 88,
            	6744, 96,
            	6747, 104,
            	6750, 112,
            	6732, 120,
            	6753, 128,
            	6756, 136,
            	6759, 144,
            	6762, 152,
            	6765, 160,
            	889, 168,
            	6768, 176,
            	6771, 184,
            	3992, 192,
            	6774, 200,
            	889, 208,
            	6779, 216,
            	6782, 224,
            8884097, 8, 0, /* 6732: pointer.func */
            8884097, 8, 0, /* 6735: pointer.func */
            8884097, 8, 0, /* 6738: pointer.func */
            8884097, 8, 0, /* 6741: pointer.func */
            8884097, 8, 0, /* 6744: pointer.func */
            8884097, 8, 0, /* 6747: pointer.func */
            8884097, 8, 0, /* 6750: pointer.func */
            8884097, 8, 0, /* 6753: pointer.func */
            8884097, 8, 0, /* 6756: pointer.func */
            8884097, 8, 0, /* 6759: pointer.func */
            8884097, 8, 0, /* 6762: pointer.func */
            8884097, 8, 0, /* 6765: pointer.func */
            8884097, 8, 0, /* 6768: pointer.func */
            8884097, 8, 0, /* 6771: pointer.func */
            1, 8, 1, /* 6774: pointer.struct.ssl3_enc_method */
            	6053, 0,
            8884097, 8, 0, /* 6779: pointer.func */
            8884097, 8, 0, /* 6782: pointer.func */
            1, 8, 1, /* 6785: pointer.struct.stack_st_SSL_CIPHER */
            	6790, 0,
            0, 32, 2, /* 6790: struct.stack_st_fake_SSL_CIPHER */
            	6797, 8,
            	439, 24,
            8884099, 8, 2, /* 6797: pointer_to_array_of_pointers_to_stack */
            	6804, 0,
            	436, 20,
            0, 8, 1, /* 6804: pointer.SSL_CIPHER */
            	5165, 0,
            1, 8, 1, /* 6809: pointer.struct.ssl_session_st */
            	6814, 0,
            0, 352, 14, /* 6814: struct.ssl_session_st */
            	43, 144,
            	43, 152,
            	6845, 168,
            	6850, 176,
            	7083, 224,
            	6785, 240,
            	6543, 248,
            	6809, 264,
            	6809, 272,
            	43, 280,
            	177, 296,
            	177, 312,
            	177, 320,
            	43, 344,
            1, 8, 1, /* 6845: pointer.struct.sess_cert_st */
            	4551, 0,
            1, 8, 1, /* 6850: pointer.struct.x509_st */
            	6855, 0,
            0, 184, 12, /* 6855: struct.x509_st */
            	6882, 0,
            	6922, 8,
            	6997, 16,
            	43, 32,
            	6543, 40,
            	7031, 104,
            	2388, 112,
            	2711, 120,
            	3147, 128,
            	3286, 136,
            	3310, 144,
            	7036, 176,
            1, 8, 1, /* 6882: pointer.struct.x509_cinf_st */
            	6887, 0,
            0, 104, 11, /* 6887: struct.x509_cinf_st */
            	6912, 0,
            	6912, 8,
            	6922, 16,
            	6927, 24,
            	6975, 32,
            	6927, 40,
            	6992, 48,
            	6997, 56,
            	6997, 64,
            	7002, 72,
            	7026, 80,
            1, 8, 1, /* 6912: pointer.struct.asn1_string_st */
            	6917, 0,
            0, 24, 1, /* 6917: struct.asn1_string_st */
            	177, 8,
            1, 8, 1, /* 6922: pointer.struct.X509_algor_st */
            	190, 0,
            1, 8, 1, /* 6927: pointer.struct.X509_name_st */
            	6932, 0,
            0, 40, 3, /* 6932: struct.X509_name_st */
            	6941, 0,
            	6965, 16,
            	177, 24,
            1, 8, 1, /* 6941: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6946, 0,
            0, 32, 2, /* 6946: struct.stack_st_fake_X509_NAME_ENTRY */
            	6953, 8,
            	439, 24,
            8884099, 8, 2, /* 6953: pointer_to_array_of_pointers_to_stack */
            	6960, 0,
            	436, 20,
            0, 8, 1, /* 6960: pointer.X509_NAME_ENTRY */
            	400, 0,
            1, 8, 1, /* 6965: pointer.struct.buf_mem_st */
            	6970, 0,
            0, 24, 1, /* 6970: struct.buf_mem_st */
            	43, 8,
            1, 8, 1, /* 6975: pointer.struct.X509_val_st */
            	6980, 0,
            0, 16, 2, /* 6980: struct.X509_val_st */
            	6987, 0,
            	6987, 8,
            1, 8, 1, /* 6987: pointer.struct.asn1_string_st */
            	6917, 0,
            1, 8, 1, /* 6992: pointer.struct.X509_pubkey_st */
            	474, 0,
            1, 8, 1, /* 6997: pointer.struct.asn1_string_st */
            	6917, 0,
            1, 8, 1, /* 7002: pointer.struct.stack_st_X509_EXTENSION */
            	7007, 0,
            0, 32, 2, /* 7007: struct.stack_st_fake_X509_EXTENSION */
            	7014, 8,
            	439, 24,
            8884099, 8, 2, /* 7014: pointer_to_array_of_pointers_to_stack */
            	7021, 0,
            	436, 20,
            0, 8, 1, /* 7021: pointer.X509_EXTENSION */
            	2320, 0,
            0, 24, 1, /* 7026: struct.ASN1_ENCODING_st */
            	177, 0,
            1, 8, 1, /* 7031: pointer.struct.asn1_string_st */
            	6917, 0,
            1, 8, 1, /* 7036: pointer.struct.x509_cert_aux_st */
            	7041, 0,
            0, 40, 5, /* 7041: struct.x509_cert_aux_st */
            	6507, 0,
            	6507, 8,
            	7054, 16,
            	7031, 24,
            	7059, 32,
            1, 8, 1, /* 7054: pointer.struct.asn1_string_st */
            	6917, 0,
            1, 8, 1, /* 7059: pointer.struct.stack_st_X509_ALGOR */
            	7064, 0,
            0, 32, 2, /* 7064: struct.stack_st_fake_X509_ALGOR */
            	7071, 8,
            	439, 24,
            8884099, 8, 2, /* 7071: pointer_to_array_of_pointers_to_stack */
            	7078, 0,
            	436, 20,
            0, 8, 1, /* 7078: pointer.X509_ALGOR */
            	3693, 0,
            1, 8, 1, /* 7083: pointer.struct.ssl_cipher_st */
            	7088, 0,
            0, 88, 1, /* 7088: struct.ssl_cipher_st */
            	211, 8,
            8884097, 8, 0, /* 7093: pointer.func */
            8884097, 8, 0, /* 7096: pointer.func */
            8884097, 8, 0, /* 7099: pointer.func */
            1, 8, 1, /* 7102: pointer.struct.env_md_st */
            	7107, 0,
            0, 120, 8, /* 7107: struct.env_md_st */
            	7126, 24,
            	7129, 32,
            	7132, 40,
            	7135, 48,
            	7126, 56,
            	3817, 64,
            	3820, 72,
            	7138, 112,
            8884097, 8, 0, /* 7126: pointer.func */
            8884097, 8, 0, /* 7129: pointer.func */
            8884097, 8, 0, /* 7132: pointer.func */
            8884097, 8, 0, /* 7135: pointer.func */
            8884097, 8, 0, /* 7138: pointer.func */
            8884097, 8, 0, /* 7141: pointer.func */
            1, 8, 1, /* 7144: pointer.struct.stack_st_X509_NAME */
            	7149, 0,
            0, 32, 2, /* 7149: struct.stack_st_fake_X509_NAME */
            	7156, 8,
            	439, 24,
            8884099, 8, 2, /* 7156: pointer_to_array_of_pointers_to_stack */
            	7163, 0,
            	436, 20,
            0, 8, 1, /* 7163: pointer.X509_NAME */
            	3874, 0,
            1, 8, 1, /* 7168: pointer.struct.cert_st */
            	74, 0,
            8884097, 8, 0, /* 7173: pointer.func */
            8884097, 8, 0, /* 7176: pointer.func */
            8884097, 8, 0, /* 7179: pointer.func */
            8884097, 8, 0, /* 7182: pointer.func */
            8884097, 8, 0, /* 7185: pointer.func */
            0, 128, 14, /* 7188: struct.srp_ctx_st */
            	31, 0,
            	6241, 8,
            	6387, 16,
            	7219, 24,
            	43, 32,
            	6211, 40,
            	6211, 48,
            	6211, 56,
            	6211, 64,
            	6211, 72,
            	6211, 80,
            	6211, 88,
            	6211, 96,
            	43, 104,
            8884097, 8, 0, /* 7219: pointer.func */
            1, 8, 1, /* 7222: pointer.struct.ssl_ctx_st */
            	6565, 0,
            8884097, 8, 0, /* 7227: pointer.func */
            8884097, 8, 0, /* 7230: pointer.func */
            8884097, 8, 0, /* 7233: pointer.func */
            1, 8, 1, /* 7236: pointer.struct.stack_st_X509_OBJECT */
            	7241, 0,
            0, 32, 2, /* 7241: struct.stack_st_fake_X509_OBJECT */
            	7248, 8,
            	439, 24,
            8884099, 8, 2, /* 7248: pointer_to_array_of_pointers_to_stack */
            	7255, 0,
            	436, 20,
            0, 8, 1, /* 7255: pointer.X509_OBJECT */
            	5332, 0,
            1, 8, 1, /* 7260: pointer.struct.stack_st_X509_EXTENSION */
            	7265, 0,
            0, 32, 2, /* 7265: struct.stack_st_fake_X509_EXTENSION */
            	7272, 8,
            	439, 24,
            8884099, 8, 2, /* 7272: pointer_to_array_of_pointers_to_stack */
            	7279, 0,
            	436, 20,
            0, 8, 1, /* 7279: pointer.X509_EXTENSION */
            	2320, 0,
            8884097, 8, 0, /* 7284: pointer.func */
            8884097, 8, 0, /* 7287: pointer.func */
            1, 8, 1, /* 7290: pointer.struct.X509_VERIFY_PARAM_st */
            	7295, 0,
            0, 56, 2, /* 7295: struct.X509_VERIFY_PARAM_st */
            	43, 0,
            	4329, 48,
            8884097, 8, 0, /* 7302: pointer.func */
            8884097, 8, 0, /* 7305: pointer.func */
            1, 8, 1, /* 7308: pointer.struct.dsa_st */
            	1188, 0,
            1, 8, 1, /* 7313: pointer.struct.engine_st */
            	620, 0,
            0, 736, 50, /* 7318: struct.ssl_ctx_st */
            	7421, 0,
            	5141, 8,
            	5141, 16,
            	7506, 24,
            	6324, 32,
            	5175, 48,
            	5175, 56,
            	7565, 80,
            	7568, 88,
            	4308, 96,
            	6384, 152,
            	31, 160,
            	6303, 168,
            	31, 176,
            	7571, 184,
            	4305, 192,
            	4302, 200,
            	5075, 208,
            	7574, 224,
            	7574, 232,
            	7574, 240,
            	3995, 248,
            	3925, 256,
            	3922, 264,
            	3850, 272,
            	69, 304,
            	7287, 320,
            	31, 328,
            	7233, 376,
            	7305, 384,
            	7290, 392,
            	3719, 408,
            	34, 416,
            	31, 424,
            	66, 480,
            	37, 488,
            	31, 496,
            	7227, 504,
            	31, 512,
            	43, 520,
            	7230, 528,
            	7604, 536,
            	6393, 552,
            	6393, 560,
            	0, 568,
            	7607, 696,
            	31, 704,
            	7610, 712,
            	31, 720,
            	7613, 728,
            1, 8, 1, /* 7421: pointer.struct.ssl_method_st */
            	7426, 0,
            0, 232, 28, /* 7426: struct.ssl_method_st */
            	6117, 8,
            	7485, 16,
            	7485, 24,
            	6117, 32,
            	6117, 40,
            	6427, 48,
            	6427, 56,
            	6114, 64,
            	6117, 72,
            	6117, 80,
            	6117, 88,
            	6111, 96,
            	6108, 104,
            	7488, 112,
            	6117, 120,
            	7491, 128,
            	7284, 136,
            	7494, 144,
            	7497, 152,
            	7500, 160,
            	889, 168,
            	6105, 176,
            	6102, 184,
            	3992, 192,
            	6048, 200,
            	889, 208,
            	6045, 216,
            	7503, 224,
            8884097, 8, 0, /* 7485: pointer.func */
            8884097, 8, 0, /* 7488: pointer.func */
            8884097, 8, 0, /* 7491: pointer.func */
            8884097, 8, 0, /* 7494: pointer.func */
            8884097, 8, 0, /* 7497: pointer.func */
            8884097, 8, 0, /* 7500: pointer.func */
            8884097, 8, 0, /* 7503: pointer.func */
            1, 8, 1, /* 7506: pointer.struct.x509_store_st */
            	7511, 0,
            0, 144, 15, /* 7511: struct.x509_store_st */
            	7236, 8,
            	5183, 16,
            	7290, 24,
            	5180, 32,
            	7233, 40,
            	7544, 48,
            	7547, 56,
            	5180, 64,
            	7550, 72,
            	7553, 80,
            	7556, 88,
            	7559, 96,
            	7562, 104,
            	5180, 112,
            	5075, 120,
            8884097, 8, 0, /* 7544: pointer.func */
            8884097, 8, 0, /* 7547: pointer.func */
            8884097, 8, 0, /* 7550: pointer.func */
            8884097, 8, 0, /* 7553: pointer.func */
            8884097, 8, 0, /* 7556: pointer.func */
            8884097, 8, 0, /* 7559: pointer.func */
            8884097, 8, 0, /* 7562: pointer.func */
            8884097, 8, 0, /* 7565: pointer.func */
            8884097, 8, 0, /* 7568: pointer.func */
            8884097, 8, 0, /* 7571: pointer.func */
            1, 8, 1, /* 7574: pointer.struct.env_md_st */
            	7579, 0,
            0, 120, 8, /* 7579: struct.env_md_st */
            	7598, 24,
            	7302, 32,
            	4299, 40,
            	4296, 48,
            	7598, 56,
            	3817, 64,
            	3820, 72,
            	7601, 112,
            8884097, 8, 0, /* 7598: pointer.func */
            8884097, 8, 0, /* 7601: pointer.func */
            8884097, 8, 0, /* 7604: pointer.func */
            8884097, 8, 0, /* 7607: pointer.func */
            8884097, 8, 0, /* 7610: pointer.func */
            1, 8, 1, /* 7613: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	7618, 0,
            0, 32, 2, /* 7618: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	7625, 8,
            	439, 24,
            8884099, 8, 2, /* 7625: pointer_to_array_of_pointers_to_stack */
            	7632, 0,
            	436, 20,
            0, 8, 1, /* 7632: pointer.SRTP_PROTECTION_PROFILE */
            	6268, 0,
            0, 24, 1, /* 7637: struct.ssl3_buffer_st */
            	177, 0,
            8884097, 8, 0, /* 7642: pointer.func */
            0, 8, 5, /* 7645: union.unknown */
            	43, 0,
            	7658, 0,
            	7308, 0,
            	7663, 0,
            	7668, 0,
            1, 8, 1, /* 7658: pointer.struct.rsa_st */
            	986, 0,
            1, 8, 1, /* 7663: pointer.struct.dh_st */
            	1315, 0,
            1, 8, 1, /* 7668: pointer.struct.ec_key_st */
            	1429, 0,
            8884097, 8, 0, /* 7673: pointer.func */
            8884097, 8, 0, /* 7676: pointer.func */
            8884097, 8, 0, /* 7679: pointer.func */
            0, 56, 3, /* 7682: struct.ssl3_record_st */
            	177, 16,
            	177, 24,
            	177, 32,
            8884097, 8, 0, /* 7691: pointer.func */
            0, 208, 25, /* 7694: struct.evp_pkey_method_st */
            	7747, 8,
            	7691, 16,
            	7750, 24,
            	7747, 32,
            	7753, 40,
            	7747, 48,
            	7753, 56,
            	7747, 64,
            	7756, 72,
            	7747, 80,
            	7759, 88,
            	7747, 96,
            	7756, 104,
            	7676, 112,
            	7673, 120,
            	7676, 128,
            	7762, 136,
            	7747, 144,
            	7756, 152,
            	7747, 160,
            	7756, 168,
            	7747, 176,
            	7765, 184,
            	7768, 192,
            	7771, 200,
            8884097, 8, 0, /* 7747: pointer.func */
            8884097, 8, 0, /* 7750: pointer.func */
            8884097, 8, 0, /* 7753: pointer.func */
            8884097, 8, 0, /* 7756: pointer.func */
            8884097, 8, 0, /* 7759: pointer.func */
            8884097, 8, 0, /* 7762: pointer.func */
            8884097, 8, 0, /* 7765: pointer.func */
            8884097, 8, 0, /* 7768: pointer.func */
            8884097, 8, 0, /* 7771: pointer.func */
            0, 344, 9, /* 7774: struct.ssl2_state_st */
            	216, 24,
            	177, 56,
            	177, 64,
            	177, 72,
            	177, 104,
            	177, 112,
            	177, 120,
            	177, 128,
            	177, 136,
            8884097, 8, 0, /* 7795: pointer.func */
            1, 8, 1, /* 7798: pointer.struct.stack_st_OCSP_RESPID */
            	7803, 0,
            0, 32, 2, /* 7803: struct.stack_st_fake_OCSP_RESPID */
            	7810, 8,
            	439, 24,
            8884099, 8, 2, /* 7810: pointer_to_array_of_pointers_to_stack */
            	7817, 0,
            	436, 20,
            0, 8, 1, /* 7817: pointer.OCSP_RESPID */
            	6190, 0,
            8884097, 8, 0, /* 7822: pointer.func */
            1, 8, 1, /* 7825: pointer.struct.bio_method_st */
            	7830, 0,
            0, 80, 9, /* 7830: struct.bio_method_st */
            	211, 8,
            	7795, 16,
            	7822, 24,
            	7679, 32,
            	7822, 40,
            	7851, 48,
            	7854, 56,
            	7854, 64,
            	7857, 72,
            8884097, 8, 0, /* 7851: pointer.func */
            8884097, 8, 0, /* 7854: pointer.func */
            8884097, 8, 0, /* 7857: pointer.func */
            8884097, 8, 0, /* 7860: pointer.func */
            1, 8, 1, /* 7863: pointer.struct.evp_cipher_ctx_st */
            	7868, 0,
            0, 168, 4, /* 7868: struct.evp_cipher_ctx_st */
            	7879, 0,
            	3719, 8,
            	31, 96,
            	31, 120,
            1, 8, 1, /* 7879: pointer.struct.evp_cipher_st */
            	7884, 0,
            0, 88, 7, /* 7884: struct.evp_cipher_st */
            	7901, 24,
            	7904, 32,
            	7907, 40,
            	7910, 56,
            	7910, 64,
            	7913, 72,
            	31, 80,
            8884097, 8, 0, /* 7901: pointer.func */
            8884097, 8, 0, /* 7904: pointer.func */
            8884097, 8, 0, /* 7907: pointer.func */
            8884097, 8, 0, /* 7910: pointer.func */
            8884097, 8, 0, /* 7913: pointer.func */
            0, 112, 7, /* 7916: struct.bio_st */
            	7825, 0,
            	7933, 8,
            	43, 16,
            	31, 48,
            	7936, 56,
            	7936, 64,
            	6543, 96,
            8884097, 8, 0, /* 7933: pointer.func */
            1, 8, 1, /* 7936: pointer.struct.bio_st */
            	7916, 0,
            1, 8, 1, /* 7941: pointer.struct.bio_st */
            	7916, 0,
            0, 808, 51, /* 7946: struct.ssl_st */
            	6668, 8,
            	7941, 16,
            	7941, 24,
            	7941, 32,
            	6732, 48,
            	6965, 80,
            	31, 88,
            	177, 104,
            	8051, 120,
            	8056, 128,
            	8250, 136,
            	7173, 152,
            	31, 160,
            	6495, 176,
            	6785, 184,
            	6785, 192,
            	7863, 208,
            	8089, 216,
            	8320, 224,
            	7863, 232,
            	8089, 240,
            	8320, 248,
            	7168, 256,
            	8332, 304,
            	7176, 312,
            	6531, 328,
            	7141, 336,
            	7182, 352,
            	7185, 360,
            	7222, 368,
            	6543, 392,
            	7144, 408,
            	8337, 464,
            	31, 472,
            	43, 480,
            	7798, 504,
            	7260, 512,
            	177, 520,
            	177, 544,
            	177, 560,
            	31, 568,
            	8340, 584,
            	8345, 592,
            	31, 600,
            	8348, 608,
            	31, 616,
            	7222, 624,
            	177, 632,
            	6244, 648,
            	8351, 656,
            	7188, 680,
            1, 8, 1, /* 8051: pointer.struct.ssl2_state_st */
            	7774, 0,
            1, 8, 1, /* 8056: pointer.struct.ssl3_state_st */
            	8061, 0,
            0, 1200, 10, /* 8061: struct.ssl3_state_st */
            	7637, 240,
            	7637, 264,
            	7682, 288,
            	7682, 344,
            	216, 432,
            	7941, 440,
            	8084, 448,
            	31, 496,
            	31, 512,
            	8186, 528,
            1, 8, 1, /* 8084: pointer.pointer.struct.env_md_ctx_st */
            	8089, 0,
            1, 8, 1, /* 8089: pointer.struct.env_md_ctx_st */
            	8094, 0,
            0, 48, 5, /* 8094: struct.env_md_ctx_st */
            	7102, 0,
            	3719, 8,
            	31, 24,
            	8107, 32,
            	7129, 40,
            1, 8, 1, /* 8107: pointer.struct.evp_pkey_ctx_st */
            	8112, 0,
            0, 80, 8, /* 8112: struct.evp_pkey_ctx_st */
            	8131, 0,
            	7313, 8,
            	8136, 16,
            	8136, 24,
            	31, 40,
            	31, 48,
            	7860, 56,
            	8181, 64,
            1, 8, 1, /* 8131: pointer.struct.evp_pkey_method_st */
            	7694, 0,
            1, 8, 1, /* 8136: pointer.struct.evp_pkey_st */
            	8141, 0,
            0, 56, 4, /* 8141: struct.evp_pkey_st */
            	8152, 16,
            	7313, 24,
            	7645, 32,
            	8157, 48,
            1, 8, 1, /* 8152: pointer.struct.evp_pkey_asn1_method_st */
            	519, 0,
            1, 8, 1, /* 8157: pointer.struct.stack_st_X509_ATTRIBUTE */
            	8162, 0,
            0, 32, 2, /* 8162: struct.stack_st_fake_X509_ATTRIBUTE */
            	8169, 8,
            	439, 24,
            8884099, 8, 2, /* 8169: pointer_to_array_of_pointers_to_stack */
            	8176, 0,
            	436, 20,
            0, 8, 1, /* 8176: pointer.X509_ATTRIBUTE */
            	1936, 0,
            1, 8, 1, /* 8181: pointer.int */
            	436, 0,
            0, 528, 8, /* 8186: struct.unknown */
            	7083, 408,
            	8205, 416,
            	3842, 424,
            	7144, 464,
            	177, 480,
            	7879, 488,
            	7102, 496,
            	8210, 512,
            1, 8, 1, /* 8205: pointer.struct.dh_st */
            	1315, 0,
            1, 8, 1, /* 8210: pointer.struct.ssl_comp_st */
            	8215, 0,
            0, 24, 2, /* 8215: struct.ssl_comp_st */
            	211, 8,
            	8222, 16,
            1, 8, 1, /* 8222: pointer.struct.comp_method_st */
            	8227, 0,
            0, 64, 7, /* 8227: struct.comp_method_st */
            	211, 8,
            	8244, 16,
            	8247, 24,
            	7642, 32,
            	7642, 40,
            	3992, 48,
            	3992, 56,
            8884097, 8, 0, /* 8244: pointer.func */
            8884097, 8, 0, /* 8247: pointer.func */
            1, 8, 1, /* 8250: pointer.struct.dtls1_state_st */
            	8255, 0,
            0, 888, 7, /* 8255: struct.dtls1_state_st */
            	8272, 576,
            	8272, 592,
            	8277, 608,
            	8277, 616,
            	8272, 624,
            	8304, 648,
            	8304, 736,
            0, 16, 1, /* 8272: struct.record_pqueue_st */
            	8277, 8,
            1, 8, 1, /* 8277: pointer.struct._pqueue */
            	8282, 0,
            0, 16, 1, /* 8282: struct._pqueue */
            	8287, 0,
            1, 8, 1, /* 8287: pointer.struct._pitem */
            	8292, 0,
            0, 24, 2, /* 8292: struct._pitem */
            	31, 8,
            	8299, 16,
            1, 8, 1, /* 8299: pointer.struct._pitem */
            	8292, 0,
            0, 88, 1, /* 8304: struct.hm_header_st */
            	8309, 48,
            0, 40, 4, /* 8309: struct.dtls1_retransmit_state */
            	7863, 0,
            	8089, 8,
            	8320, 16,
            	8332, 24,
            1, 8, 1, /* 8320: pointer.struct.comp_ctx_st */
            	8325, 0,
            0, 56, 2, /* 8325: struct.comp_ctx_st */
            	8222, 0,
            	6543, 40,
            1, 8, 1, /* 8332: pointer.struct.ssl_session_st */
            	6814, 0,
            8884097, 8, 0, /* 8337: pointer.func */
            1, 8, 1, /* 8340: pointer.struct.tls_session_ticket_ext_st */
            	6120, 0,
            8884097, 8, 0, /* 8345: pointer.func */
            8884097, 8, 0, /* 8348: pointer.func */
            1, 8, 1, /* 8351: pointer.struct.srtp_protection_profile_st */
            	6398, 0,
            0, 1, 0, /* 8356: char */
            1, 8, 1, /* 8359: pointer.struct.ssl_ctx_st */
            	7318, 0,
            1, 8, 1, /* 8364: pointer.struct.ssl_st */
            	7946, 0,
        },
        .arg_entity_index = { 8359, },
        .ret_entity_index = 8364,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    SSL * *new_ret_ptr = (SSL * *)new_args->ret;

    SSL * (*orig_SSL_new)(SSL_CTX *);
    orig_SSL_new = dlsym(RTLD_NEXT, "SSL_new");
    *new_ret_ptr = (*orig_SSL_new)(new_arg_a);

    syscall(889);

    return ret;
}

