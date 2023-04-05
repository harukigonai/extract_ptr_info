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

void bb_SSL_CTX_free(SSL_CTX * arg_a);

void SSL_CTX_free(SSL_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_free called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_free(arg_a);
    else {
        void (*orig_SSL_CTX_free)(SSL_CTX *);
        orig_SSL_CTX_free = dlsym(RTLD_NEXT, "SSL_CTX_free");
        orig_SSL_CTX_free(arg_a);
    }
}

void bb_SSL_CTX_free(SSL_CTX * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 1, /* 0: SRTP_PROTECTION_PROFILE */
            	5, 0,
            0, 16, 1, /* 5: struct.srtp_protection_profile_st */
            	10, 0,
            1, 8, 1, /* 10: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 15: pointer.func */
            0, 128, 14, /* 18: struct.srp_ctx_st */
            	49, 0,
            	52, 8,
            	55, 16,
            	58, 24,
            	61, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	66, 80,
            	66, 88,
            	66, 96,
            	61, 104,
            0, 8, 0, /* 49: pointer.void */
            8884097, 8, 0, /* 52: pointer.func */
            8884097, 8, 0, /* 55: pointer.func */
            8884097, 8, 0, /* 58: pointer.func */
            1, 8, 1, /* 61: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 66: pointer.struct.bignum_st */
            	71, 0,
            0, 24, 1, /* 71: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 76: pointer.unsigned int */
            	81, 0,
            0, 4, 0, /* 81: unsigned int */
            1, 8, 1, /* 84: pointer.struct.ssl3_buf_freelist_entry_st */
            	89, 0,
            0, 8, 1, /* 89: struct.ssl3_buf_freelist_entry_st */
            	84, 0,
            8884097, 8, 0, /* 94: pointer.func */
            8884097, 8, 0, /* 97: pointer.func */
            8884097, 8, 0, /* 100: pointer.func */
            0, 296, 7, /* 103: struct.cert_st */
            	120, 0,
            	2230, 48,
            	2235, 56,
            	2238, 64,
            	2243, 72,
            	2246, 80,
            	100, 88,
            1, 8, 1, /* 120: pointer.struct.cert_pkey_st */
            	125, 0,
            0, 24, 3, /* 125: struct.cert_pkey_st */
            	134, 0,
            	497, 8,
            	2185, 16,
            1, 8, 1, /* 134: pointer.struct.x509_st */
            	139, 0,
            0, 184, 12, /* 139: struct.x509_st */
            	166, 0,
            	214, 8,
            	308, 16,
            	61, 32,
            	639, 40,
            	313, 104,
            	1289, 112,
            	1597, 120,
            	1605, 128,
            	1744, 136,
            	1768, 144,
            	2088, 176,
            1, 8, 1, /* 166: pointer.struct.x509_cinf_st */
            	171, 0,
            0, 104, 11, /* 171: struct.x509_cinf_st */
            	196, 0,
            	196, 8,
            	214, 16,
            	376, 24,
            	466, 32,
            	376, 40,
            	483, 48,
            	308, 56,
            	308, 64,
            	1224, 72,
            	1284, 80,
            1, 8, 1, /* 196: pointer.struct.asn1_string_st */
            	201, 0,
            0, 24, 1, /* 201: struct.asn1_string_st */
            	206, 8,
            1, 8, 1, /* 206: pointer.unsigned char */
            	211, 0,
            0, 1, 0, /* 211: unsigned char */
            1, 8, 1, /* 214: pointer.struct.X509_algor_st */
            	219, 0,
            0, 16, 2, /* 219: struct.X509_algor_st */
            	226, 0,
            	245, 8,
            1, 8, 1, /* 226: pointer.struct.asn1_object_st */
            	231, 0,
            0, 40, 3, /* 231: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 240: pointer.unsigned char */
            	211, 0,
            1, 8, 1, /* 245: pointer.struct.asn1_type_st */
            	250, 0,
            0, 16, 1, /* 250: struct.asn1_type_st */
            	255, 8,
            0, 8, 20, /* 255: union.unknown */
            	61, 0,
            	298, 0,
            	226, 0,
            	196, 0,
            	303, 0,
            	308, 0,
            	313, 0,
            	318, 0,
            	323, 0,
            	328, 0,
            	333, 0,
            	338, 0,
            	343, 0,
            	348, 0,
            	353, 0,
            	358, 0,
            	363, 0,
            	298, 0,
            	298, 0,
            	368, 0,
            1, 8, 1, /* 298: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 303: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 308: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 313: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 318: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 323: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 328: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 333: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 338: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 343: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 348: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 353: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 358: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 363: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 368: pointer.struct.ASN1_VALUE_st */
            	373, 0,
            0, 0, 0, /* 373: struct.ASN1_VALUE_st */
            1, 8, 1, /* 376: pointer.struct.X509_name_st */
            	381, 0,
            0, 40, 3, /* 381: struct.X509_name_st */
            	390, 0,
            	456, 16,
            	206, 24,
            1, 8, 1, /* 390: pointer.struct.stack_st_X509_NAME_ENTRY */
            	395, 0,
            0, 32, 2, /* 395: struct.stack_st_fake_X509_NAME_ENTRY */
            	402, 8,
            	453, 24,
            8884099, 8, 2, /* 402: pointer_to_array_of_pointers_to_stack */
            	409, 0,
            	450, 20,
            0, 8, 1, /* 409: pointer.X509_NAME_ENTRY */
            	414, 0,
            0, 0, 1, /* 414: X509_NAME_ENTRY */
            	419, 0,
            0, 24, 2, /* 419: struct.X509_name_entry_st */
            	426, 0,
            	440, 8,
            1, 8, 1, /* 426: pointer.struct.asn1_object_st */
            	431, 0,
            0, 40, 3, /* 431: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 440: pointer.struct.asn1_string_st */
            	445, 0,
            0, 24, 1, /* 445: struct.asn1_string_st */
            	206, 8,
            0, 4, 0, /* 450: int */
            8884097, 8, 0, /* 453: pointer.func */
            1, 8, 1, /* 456: pointer.struct.buf_mem_st */
            	461, 0,
            0, 24, 1, /* 461: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 466: pointer.struct.X509_val_st */
            	471, 0,
            0, 16, 2, /* 471: struct.X509_val_st */
            	478, 0,
            	478, 8,
            1, 8, 1, /* 478: pointer.struct.asn1_string_st */
            	201, 0,
            1, 8, 1, /* 483: pointer.struct.X509_pubkey_st */
            	488, 0,
            0, 24, 3, /* 488: struct.X509_pubkey_st */
            	214, 0,
            	308, 8,
            	497, 16,
            1, 8, 1, /* 497: pointer.struct.evp_pkey_st */
            	502, 0,
            0, 56, 4, /* 502: struct.evp_pkey_st */
            	513, 16,
            	521, 24,
            	529, 32,
            	845, 48,
            1, 8, 1, /* 513: pointer.struct.evp_pkey_asn1_method_st */
            	518, 0,
            0, 0, 0, /* 518: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 521: pointer.struct.engine_st */
            	526, 0,
            0, 0, 0, /* 526: struct.engine_st */
            0, 8, 5, /* 529: union.unknown */
            	61, 0,
            	542, 0,
            	688, 0,
            	769, 0,
            	837, 0,
            1, 8, 1, /* 542: pointer.struct.rsa_st */
            	547, 0,
            0, 168, 17, /* 547: struct.rsa_st */
            	584, 16,
            	521, 24,
            	66, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	66, 80,
            	66, 88,
            	639, 96,
            	666, 120,
            	666, 128,
            	666, 136,
            	61, 144,
            	680, 152,
            	680, 160,
            1, 8, 1, /* 584: pointer.struct.rsa_meth_st */
            	589, 0,
            0, 112, 13, /* 589: struct.rsa_meth_st */
            	10, 0,
            	618, 8,
            	618, 16,
            	618, 24,
            	618, 32,
            	621, 40,
            	624, 48,
            	627, 56,
            	627, 64,
            	61, 80,
            	630, 88,
            	633, 96,
            	636, 104,
            8884097, 8, 0, /* 618: pointer.func */
            8884097, 8, 0, /* 621: pointer.func */
            8884097, 8, 0, /* 624: pointer.func */
            8884097, 8, 0, /* 627: pointer.func */
            8884097, 8, 0, /* 630: pointer.func */
            8884097, 8, 0, /* 633: pointer.func */
            8884097, 8, 0, /* 636: pointer.func */
            0, 16, 1, /* 639: struct.crypto_ex_data_st */
            	644, 0,
            1, 8, 1, /* 644: pointer.struct.stack_st_void */
            	649, 0,
            0, 32, 1, /* 649: struct.stack_st_void */
            	654, 0,
            0, 32, 2, /* 654: struct.stack_st */
            	661, 8,
            	453, 24,
            1, 8, 1, /* 661: pointer.pointer.char */
            	61, 0,
            1, 8, 1, /* 666: pointer.struct.bn_mont_ctx_st */
            	671, 0,
            0, 96, 3, /* 671: struct.bn_mont_ctx_st */
            	71, 8,
            	71, 32,
            	71, 56,
            1, 8, 1, /* 680: pointer.struct.bn_blinding_st */
            	685, 0,
            0, 0, 0, /* 685: struct.bn_blinding_st */
            1, 8, 1, /* 688: pointer.struct.dsa_st */
            	693, 0,
            0, 136, 11, /* 693: struct.dsa_st */
            	66, 24,
            	66, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	666, 88,
            	639, 104,
            	718, 120,
            	521, 128,
            1, 8, 1, /* 718: pointer.struct.dsa_method */
            	723, 0,
            0, 96, 11, /* 723: struct.dsa_method */
            	10, 0,
            	748, 8,
            	751, 16,
            	754, 24,
            	757, 32,
            	760, 40,
            	763, 48,
            	763, 56,
            	61, 72,
            	766, 80,
            	763, 88,
            8884097, 8, 0, /* 748: pointer.func */
            8884097, 8, 0, /* 751: pointer.func */
            8884097, 8, 0, /* 754: pointer.func */
            8884097, 8, 0, /* 757: pointer.func */
            8884097, 8, 0, /* 760: pointer.func */
            8884097, 8, 0, /* 763: pointer.func */
            8884097, 8, 0, /* 766: pointer.func */
            1, 8, 1, /* 769: pointer.struct.dh_st */
            	774, 0,
            0, 144, 12, /* 774: struct.dh_st */
            	66, 8,
            	66, 16,
            	66, 32,
            	66, 40,
            	666, 56,
            	66, 64,
            	66, 72,
            	206, 80,
            	66, 96,
            	639, 112,
            	801, 128,
            	521, 136,
            1, 8, 1, /* 801: pointer.struct.dh_method */
            	806, 0,
            0, 72, 8, /* 806: struct.dh_method */
            	10, 0,
            	825, 8,
            	828, 16,
            	831, 24,
            	825, 32,
            	825, 40,
            	61, 56,
            	834, 64,
            8884097, 8, 0, /* 825: pointer.func */
            8884097, 8, 0, /* 828: pointer.func */
            8884097, 8, 0, /* 831: pointer.func */
            8884097, 8, 0, /* 834: pointer.func */
            1, 8, 1, /* 837: pointer.struct.ec_key_st */
            	842, 0,
            0, 0, 0, /* 842: struct.ec_key_st */
            1, 8, 1, /* 845: pointer.struct.stack_st_X509_ATTRIBUTE */
            	850, 0,
            0, 32, 2, /* 850: struct.stack_st_fake_X509_ATTRIBUTE */
            	857, 8,
            	453, 24,
            8884099, 8, 2, /* 857: pointer_to_array_of_pointers_to_stack */
            	864, 0,
            	450, 20,
            0, 8, 1, /* 864: pointer.X509_ATTRIBUTE */
            	869, 0,
            0, 0, 1, /* 869: X509_ATTRIBUTE */
            	874, 0,
            0, 24, 2, /* 874: struct.x509_attributes_st */
            	881, 0,
            	895, 16,
            1, 8, 1, /* 881: pointer.struct.asn1_object_st */
            	886, 0,
            0, 40, 3, /* 886: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            0, 8, 3, /* 895: union.unknown */
            	61, 0,
            	904, 0,
            	1083, 0,
            1, 8, 1, /* 904: pointer.struct.stack_st_ASN1_TYPE */
            	909, 0,
            0, 32, 2, /* 909: struct.stack_st_fake_ASN1_TYPE */
            	916, 8,
            	453, 24,
            8884099, 8, 2, /* 916: pointer_to_array_of_pointers_to_stack */
            	923, 0,
            	450, 20,
            0, 8, 1, /* 923: pointer.ASN1_TYPE */
            	928, 0,
            0, 0, 1, /* 928: ASN1_TYPE */
            	933, 0,
            0, 16, 1, /* 933: struct.asn1_type_st */
            	938, 8,
            0, 8, 20, /* 938: union.unknown */
            	61, 0,
            	981, 0,
            	991, 0,
            	1005, 0,
            	1010, 0,
            	1015, 0,
            	1020, 0,
            	1025, 0,
            	1030, 0,
            	1035, 0,
            	1040, 0,
            	1045, 0,
            	1050, 0,
            	1055, 0,
            	1060, 0,
            	1065, 0,
            	1070, 0,
            	981, 0,
            	981, 0,
            	1075, 0,
            1, 8, 1, /* 981: pointer.struct.asn1_string_st */
            	986, 0,
            0, 24, 1, /* 986: struct.asn1_string_st */
            	206, 8,
            1, 8, 1, /* 991: pointer.struct.asn1_object_st */
            	996, 0,
            0, 40, 3, /* 996: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 1005: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1010: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1015: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1020: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1025: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1030: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1035: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1040: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1045: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1050: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1055: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1060: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1065: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1070: pointer.struct.asn1_string_st */
            	986, 0,
            1, 8, 1, /* 1075: pointer.struct.ASN1_VALUE_st */
            	1080, 0,
            0, 0, 0, /* 1080: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1083: pointer.struct.asn1_type_st */
            	1088, 0,
            0, 16, 1, /* 1088: struct.asn1_type_st */
            	1093, 8,
            0, 8, 20, /* 1093: union.unknown */
            	61, 0,
            	1136, 0,
            	881, 0,
            	1146, 0,
            	1151, 0,
            	1156, 0,
            	1161, 0,
            	1166, 0,
            	1171, 0,
            	1176, 0,
            	1181, 0,
            	1186, 0,
            	1191, 0,
            	1196, 0,
            	1201, 0,
            	1206, 0,
            	1211, 0,
            	1136, 0,
            	1136, 0,
            	1216, 0,
            1, 8, 1, /* 1136: pointer.struct.asn1_string_st */
            	1141, 0,
            0, 24, 1, /* 1141: struct.asn1_string_st */
            	206, 8,
            1, 8, 1, /* 1146: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1151: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1156: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1161: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1166: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1171: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1176: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1181: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1186: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1191: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1196: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1201: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1206: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1211: pointer.struct.asn1_string_st */
            	1141, 0,
            1, 8, 1, /* 1216: pointer.struct.ASN1_VALUE_st */
            	1221, 0,
            0, 0, 0, /* 1221: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1224: pointer.struct.stack_st_X509_EXTENSION */
            	1229, 0,
            0, 32, 2, /* 1229: struct.stack_st_fake_X509_EXTENSION */
            	1236, 8,
            	453, 24,
            8884099, 8, 2, /* 1236: pointer_to_array_of_pointers_to_stack */
            	1243, 0,
            	450, 20,
            0, 8, 1, /* 1243: pointer.X509_EXTENSION */
            	1248, 0,
            0, 0, 1, /* 1248: X509_EXTENSION */
            	1253, 0,
            0, 24, 2, /* 1253: struct.X509_extension_st */
            	1260, 0,
            	1274, 16,
            1, 8, 1, /* 1260: pointer.struct.asn1_object_st */
            	1265, 0,
            0, 40, 3, /* 1265: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 1274: pointer.struct.asn1_string_st */
            	1279, 0,
            0, 24, 1, /* 1279: struct.asn1_string_st */
            	206, 8,
            0, 24, 1, /* 1284: struct.ASN1_ENCODING_st */
            	206, 0,
            1, 8, 1, /* 1289: pointer.struct.AUTHORITY_KEYID_st */
            	1294, 0,
            0, 24, 3, /* 1294: struct.AUTHORITY_KEYID_st */
            	313, 0,
            	1303, 8,
            	196, 16,
            1, 8, 1, /* 1303: pointer.struct.stack_st_GENERAL_NAME */
            	1308, 0,
            0, 32, 2, /* 1308: struct.stack_st_fake_GENERAL_NAME */
            	1315, 8,
            	453, 24,
            8884099, 8, 2, /* 1315: pointer_to_array_of_pointers_to_stack */
            	1322, 0,
            	450, 20,
            0, 8, 1, /* 1322: pointer.GENERAL_NAME */
            	1327, 0,
            0, 0, 1, /* 1327: GENERAL_NAME */
            	1332, 0,
            0, 16, 1, /* 1332: struct.GENERAL_NAME_st */
            	1337, 8,
            0, 8, 15, /* 1337: union.unknown */
            	61, 0,
            	1370, 0,
            	1489, 0,
            	1489, 0,
            	1396, 0,
            	1537, 0,
            	1585, 0,
            	1489, 0,
            	1474, 0,
            	1382, 0,
            	1474, 0,
            	1537, 0,
            	1489, 0,
            	1382, 0,
            	1396, 0,
            1, 8, 1, /* 1370: pointer.struct.otherName_st */
            	1375, 0,
            0, 16, 2, /* 1375: struct.otherName_st */
            	1382, 0,
            	1396, 8,
            1, 8, 1, /* 1382: pointer.struct.asn1_object_st */
            	1387, 0,
            0, 40, 3, /* 1387: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 1396: pointer.struct.asn1_type_st */
            	1401, 0,
            0, 16, 1, /* 1401: struct.asn1_type_st */
            	1406, 8,
            0, 8, 20, /* 1406: union.unknown */
            	61, 0,
            	1449, 0,
            	1382, 0,
            	1459, 0,
            	1464, 0,
            	1469, 0,
            	1474, 0,
            	1479, 0,
            	1484, 0,
            	1489, 0,
            	1494, 0,
            	1499, 0,
            	1504, 0,
            	1509, 0,
            	1514, 0,
            	1519, 0,
            	1524, 0,
            	1449, 0,
            	1449, 0,
            	1529, 0,
            1, 8, 1, /* 1449: pointer.struct.asn1_string_st */
            	1454, 0,
            0, 24, 1, /* 1454: struct.asn1_string_st */
            	206, 8,
            1, 8, 1, /* 1459: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1464: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1469: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1474: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1479: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1484: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1489: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1494: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1499: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1504: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1509: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1514: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1519: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1524: pointer.struct.asn1_string_st */
            	1454, 0,
            1, 8, 1, /* 1529: pointer.struct.ASN1_VALUE_st */
            	1534, 0,
            0, 0, 0, /* 1534: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1537: pointer.struct.X509_name_st */
            	1542, 0,
            0, 40, 3, /* 1542: struct.X509_name_st */
            	1551, 0,
            	1575, 16,
            	206, 24,
            1, 8, 1, /* 1551: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1556, 0,
            0, 32, 2, /* 1556: struct.stack_st_fake_X509_NAME_ENTRY */
            	1563, 8,
            	453, 24,
            8884099, 8, 2, /* 1563: pointer_to_array_of_pointers_to_stack */
            	1570, 0,
            	450, 20,
            0, 8, 1, /* 1570: pointer.X509_NAME_ENTRY */
            	414, 0,
            1, 8, 1, /* 1575: pointer.struct.buf_mem_st */
            	1580, 0,
            0, 24, 1, /* 1580: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 1585: pointer.struct.EDIPartyName_st */
            	1590, 0,
            0, 16, 2, /* 1590: struct.EDIPartyName_st */
            	1449, 0,
            	1449, 8,
            1, 8, 1, /* 1597: pointer.struct.X509_POLICY_CACHE_st */
            	1602, 0,
            0, 0, 0, /* 1602: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1605: pointer.struct.stack_st_DIST_POINT */
            	1610, 0,
            0, 32, 2, /* 1610: struct.stack_st_fake_DIST_POINT */
            	1617, 8,
            	453, 24,
            8884099, 8, 2, /* 1617: pointer_to_array_of_pointers_to_stack */
            	1624, 0,
            	450, 20,
            0, 8, 1, /* 1624: pointer.DIST_POINT */
            	1629, 0,
            0, 0, 1, /* 1629: DIST_POINT */
            	1634, 0,
            0, 32, 3, /* 1634: struct.DIST_POINT_st */
            	1643, 0,
            	1734, 8,
            	1662, 16,
            1, 8, 1, /* 1643: pointer.struct.DIST_POINT_NAME_st */
            	1648, 0,
            0, 24, 2, /* 1648: struct.DIST_POINT_NAME_st */
            	1655, 8,
            	1710, 16,
            0, 8, 2, /* 1655: union.unknown */
            	1662, 0,
            	1686, 0,
            1, 8, 1, /* 1662: pointer.struct.stack_st_GENERAL_NAME */
            	1667, 0,
            0, 32, 2, /* 1667: struct.stack_st_fake_GENERAL_NAME */
            	1674, 8,
            	453, 24,
            8884099, 8, 2, /* 1674: pointer_to_array_of_pointers_to_stack */
            	1681, 0,
            	450, 20,
            0, 8, 1, /* 1681: pointer.GENERAL_NAME */
            	1327, 0,
            1, 8, 1, /* 1686: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1691, 0,
            0, 32, 2, /* 1691: struct.stack_st_fake_X509_NAME_ENTRY */
            	1698, 8,
            	453, 24,
            8884099, 8, 2, /* 1698: pointer_to_array_of_pointers_to_stack */
            	1705, 0,
            	450, 20,
            0, 8, 1, /* 1705: pointer.X509_NAME_ENTRY */
            	414, 0,
            1, 8, 1, /* 1710: pointer.struct.X509_name_st */
            	1715, 0,
            0, 40, 3, /* 1715: struct.X509_name_st */
            	1686, 0,
            	1724, 16,
            	206, 24,
            1, 8, 1, /* 1724: pointer.struct.buf_mem_st */
            	1729, 0,
            0, 24, 1, /* 1729: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 1734: pointer.struct.asn1_string_st */
            	1739, 0,
            0, 24, 1, /* 1739: struct.asn1_string_st */
            	206, 8,
            1, 8, 1, /* 1744: pointer.struct.stack_st_GENERAL_NAME */
            	1749, 0,
            0, 32, 2, /* 1749: struct.stack_st_fake_GENERAL_NAME */
            	1756, 8,
            	453, 24,
            8884099, 8, 2, /* 1756: pointer_to_array_of_pointers_to_stack */
            	1763, 0,
            	450, 20,
            0, 8, 1, /* 1763: pointer.GENERAL_NAME */
            	1327, 0,
            1, 8, 1, /* 1768: pointer.struct.NAME_CONSTRAINTS_st */
            	1773, 0,
            0, 16, 2, /* 1773: struct.NAME_CONSTRAINTS_st */
            	1780, 0,
            	1780, 8,
            1, 8, 1, /* 1780: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1785, 0,
            0, 32, 2, /* 1785: struct.stack_st_fake_GENERAL_SUBTREE */
            	1792, 8,
            	453, 24,
            8884099, 8, 2, /* 1792: pointer_to_array_of_pointers_to_stack */
            	1799, 0,
            	450, 20,
            0, 8, 1, /* 1799: pointer.GENERAL_SUBTREE */
            	1804, 0,
            0, 0, 1, /* 1804: GENERAL_SUBTREE */
            	1809, 0,
            0, 24, 3, /* 1809: struct.GENERAL_SUBTREE_st */
            	1818, 0,
            	1950, 8,
            	1950, 16,
            1, 8, 1, /* 1818: pointer.struct.GENERAL_NAME_st */
            	1823, 0,
            0, 16, 1, /* 1823: struct.GENERAL_NAME_st */
            	1828, 8,
            0, 8, 15, /* 1828: union.unknown */
            	61, 0,
            	1861, 0,
            	1980, 0,
            	1980, 0,
            	1887, 0,
            	2028, 0,
            	2076, 0,
            	1980, 0,
            	1965, 0,
            	1873, 0,
            	1965, 0,
            	2028, 0,
            	1980, 0,
            	1873, 0,
            	1887, 0,
            1, 8, 1, /* 1861: pointer.struct.otherName_st */
            	1866, 0,
            0, 16, 2, /* 1866: struct.otherName_st */
            	1873, 0,
            	1887, 8,
            1, 8, 1, /* 1873: pointer.struct.asn1_object_st */
            	1878, 0,
            0, 40, 3, /* 1878: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 1887: pointer.struct.asn1_type_st */
            	1892, 0,
            0, 16, 1, /* 1892: struct.asn1_type_st */
            	1897, 8,
            0, 8, 20, /* 1897: union.unknown */
            	61, 0,
            	1940, 0,
            	1873, 0,
            	1950, 0,
            	1955, 0,
            	1960, 0,
            	1965, 0,
            	1970, 0,
            	1975, 0,
            	1980, 0,
            	1985, 0,
            	1990, 0,
            	1995, 0,
            	2000, 0,
            	2005, 0,
            	2010, 0,
            	2015, 0,
            	1940, 0,
            	1940, 0,
            	2020, 0,
            1, 8, 1, /* 1940: pointer.struct.asn1_string_st */
            	1945, 0,
            0, 24, 1, /* 1945: struct.asn1_string_st */
            	206, 8,
            1, 8, 1, /* 1950: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 1955: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 1960: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 1965: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 1970: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 1975: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 1980: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 1985: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 1990: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 1995: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 2000: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 2005: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 2010: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 2015: pointer.struct.asn1_string_st */
            	1945, 0,
            1, 8, 1, /* 2020: pointer.struct.ASN1_VALUE_st */
            	2025, 0,
            0, 0, 0, /* 2025: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2028: pointer.struct.X509_name_st */
            	2033, 0,
            0, 40, 3, /* 2033: struct.X509_name_st */
            	2042, 0,
            	2066, 16,
            	206, 24,
            1, 8, 1, /* 2042: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2047, 0,
            0, 32, 2, /* 2047: struct.stack_st_fake_X509_NAME_ENTRY */
            	2054, 8,
            	453, 24,
            8884099, 8, 2, /* 2054: pointer_to_array_of_pointers_to_stack */
            	2061, 0,
            	450, 20,
            0, 8, 1, /* 2061: pointer.X509_NAME_ENTRY */
            	414, 0,
            1, 8, 1, /* 2066: pointer.struct.buf_mem_st */
            	2071, 0,
            0, 24, 1, /* 2071: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 2076: pointer.struct.EDIPartyName_st */
            	2081, 0,
            0, 16, 2, /* 2081: struct.EDIPartyName_st */
            	1940, 0,
            	1940, 8,
            1, 8, 1, /* 2088: pointer.struct.x509_cert_aux_st */
            	2093, 0,
            0, 40, 5, /* 2093: struct.x509_cert_aux_st */
            	2106, 0,
            	2106, 8,
            	363, 16,
            	313, 24,
            	2144, 32,
            1, 8, 1, /* 2106: pointer.struct.stack_st_ASN1_OBJECT */
            	2111, 0,
            0, 32, 2, /* 2111: struct.stack_st_fake_ASN1_OBJECT */
            	2118, 8,
            	453, 24,
            8884099, 8, 2, /* 2118: pointer_to_array_of_pointers_to_stack */
            	2125, 0,
            	450, 20,
            0, 8, 1, /* 2125: pointer.ASN1_OBJECT */
            	2130, 0,
            0, 0, 1, /* 2130: ASN1_OBJECT */
            	2135, 0,
            0, 40, 3, /* 2135: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 2144: pointer.struct.stack_st_X509_ALGOR */
            	2149, 0,
            0, 32, 2, /* 2149: struct.stack_st_fake_X509_ALGOR */
            	2156, 8,
            	453, 24,
            8884099, 8, 2, /* 2156: pointer_to_array_of_pointers_to_stack */
            	2163, 0,
            	450, 20,
            0, 8, 1, /* 2163: pointer.X509_ALGOR */
            	2168, 0,
            0, 0, 1, /* 2168: X509_ALGOR */
            	2173, 0,
            0, 16, 2, /* 2173: struct.X509_algor_st */
            	991, 0,
            	2180, 8,
            1, 8, 1, /* 2180: pointer.struct.asn1_type_st */
            	933, 0,
            1, 8, 1, /* 2185: pointer.struct.env_md_st */
            	2190, 0,
            0, 120, 8, /* 2190: struct.env_md_st */
            	2209, 24,
            	2212, 32,
            	2215, 40,
            	2218, 48,
            	2209, 56,
            	2221, 64,
            	2224, 72,
            	2227, 112,
            8884097, 8, 0, /* 2209: pointer.func */
            8884097, 8, 0, /* 2212: pointer.func */
            8884097, 8, 0, /* 2215: pointer.func */
            8884097, 8, 0, /* 2218: pointer.func */
            8884097, 8, 0, /* 2221: pointer.func */
            8884097, 8, 0, /* 2224: pointer.func */
            8884097, 8, 0, /* 2227: pointer.func */
            1, 8, 1, /* 2230: pointer.struct.rsa_st */
            	547, 0,
            8884097, 8, 0, /* 2235: pointer.func */
            1, 8, 1, /* 2238: pointer.struct.dh_st */
            	774, 0,
            8884097, 8, 0, /* 2243: pointer.func */
            1, 8, 1, /* 2246: pointer.struct.ec_key_st */
            	842, 0,
            1, 8, 1, /* 2251: pointer.struct.cert_st */
            	103, 0,
            8884097, 8, 0, /* 2256: pointer.func */
            0, 0, 1, /* 2259: X509_NAME */
            	2264, 0,
            0, 40, 3, /* 2264: struct.X509_name_st */
            	2273, 0,
            	2297, 16,
            	206, 24,
            1, 8, 1, /* 2273: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2278, 0,
            0, 32, 2, /* 2278: struct.stack_st_fake_X509_NAME_ENTRY */
            	2285, 8,
            	453, 24,
            8884099, 8, 2, /* 2285: pointer_to_array_of_pointers_to_stack */
            	2292, 0,
            	450, 20,
            0, 8, 1, /* 2292: pointer.X509_NAME_ENTRY */
            	414, 0,
            1, 8, 1, /* 2297: pointer.struct.buf_mem_st */
            	2302, 0,
            0, 24, 1, /* 2302: struct.buf_mem_st */
            	61, 8,
            8884097, 8, 0, /* 2307: pointer.func */
            8884097, 8, 0, /* 2310: pointer.func */
            0, 64, 7, /* 2313: struct.comp_method_st */
            	10, 8,
            	2330, 16,
            	2310, 24,
            	2307, 32,
            	2307, 40,
            	2333, 48,
            	2333, 56,
            8884097, 8, 0, /* 2330: pointer.func */
            8884097, 8, 0, /* 2333: pointer.func */
            1, 8, 1, /* 2336: pointer.struct.comp_method_st */
            	2313, 0,
            0, 0, 1, /* 2341: SSL_COMP */
            	2346, 0,
            0, 24, 2, /* 2346: struct.ssl_comp_st */
            	10, 8,
            	2336, 16,
            1, 8, 1, /* 2353: pointer.struct.stack_st_SSL_COMP */
            	2358, 0,
            0, 32, 2, /* 2358: struct.stack_st_fake_SSL_COMP */
            	2365, 8,
            	453, 24,
            8884099, 8, 2, /* 2365: pointer_to_array_of_pointers_to_stack */
            	2372, 0,
            	450, 20,
            0, 8, 1, /* 2372: pointer.SSL_COMP */
            	2341, 0,
            8884097, 8, 0, /* 2377: pointer.func */
            8884097, 8, 0, /* 2380: pointer.func */
            0, 88, 1, /* 2383: struct.ssl_cipher_st */
            	10, 8,
            0, 16, 1, /* 2388: struct.crypto_ex_data_st */
            	2393, 0,
            1, 8, 1, /* 2393: pointer.struct.stack_st_void */
            	2398, 0,
            0, 32, 1, /* 2398: struct.stack_st_void */
            	2403, 0,
            0, 32, 2, /* 2403: struct.stack_st */
            	661, 8,
            	453, 24,
            8884097, 8, 0, /* 2410: pointer.func */
            8884097, 8, 0, /* 2413: pointer.func */
            8884097, 8, 0, /* 2416: pointer.func */
            0, 168, 17, /* 2419: struct.rsa_st */
            	2456, 16,
            	2508, 24,
            	2516, 32,
            	2516, 40,
            	2516, 48,
            	2516, 56,
            	2516, 64,
            	2516, 72,
            	2516, 80,
            	2516, 88,
            	2526, 96,
            	2548, 120,
            	2548, 128,
            	2548, 136,
            	61, 144,
            	2562, 152,
            	2562, 160,
            1, 8, 1, /* 2456: pointer.struct.rsa_meth_st */
            	2461, 0,
            0, 112, 13, /* 2461: struct.rsa_meth_st */
            	10, 0,
            	2490, 8,
            	2490, 16,
            	2490, 24,
            	2490, 32,
            	2413, 40,
            	2493, 48,
            	2496, 56,
            	2496, 64,
            	61, 80,
            	2499, 88,
            	2502, 96,
            	2505, 104,
            8884097, 8, 0, /* 2490: pointer.func */
            8884097, 8, 0, /* 2493: pointer.func */
            8884097, 8, 0, /* 2496: pointer.func */
            8884097, 8, 0, /* 2499: pointer.func */
            8884097, 8, 0, /* 2502: pointer.func */
            8884097, 8, 0, /* 2505: pointer.func */
            1, 8, 1, /* 2508: pointer.struct.engine_st */
            	2513, 0,
            0, 0, 0, /* 2513: struct.engine_st */
            1, 8, 1, /* 2516: pointer.struct.bignum_st */
            	2521, 0,
            0, 24, 1, /* 2521: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 2526: struct.crypto_ex_data_st */
            	2531, 0,
            1, 8, 1, /* 2531: pointer.struct.stack_st_void */
            	2536, 0,
            0, 32, 1, /* 2536: struct.stack_st_void */
            	2541, 0,
            0, 32, 2, /* 2541: struct.stack_st */
            	661, 8,
            	453, 24,
            1, 8, 1, /* 2548: pointer.struct.bn_mont_ctx_st */
            	2553, 0,
            0, 96, 3, /* 2553: struct.bn_mont_ctx_st */
            	2521, 8,
            	2521, 32,
            	2521, 56,
            1, 8, 1, /* 2562: pointer.struct.bn_blinding_st */
            	2567, 0,
            0, 0, 0, /* 2567: struct.bn_blinding_st */
            0, 1, 0, /* 2570: char */
            8884097, 8, 0, /* 2573: pointer.func */
            0, 72, 8, /* 2576: struct.dh_method */
            	10, 0,
            	2595, 8,
            	2598, 16,
            	2601, 24,
            	2595, 32,
            	2595, 40,
            	61, 56,
            	2604, 64,
            8884097, 8, 0, /* 2595: pointer.func */
            8884097, 8, 0, /* 2598: pointer.func */
            8884097, 8, 0, /* 2601: pointer.func */
            8884097, 8, 0, /* 2604: pointer.func */
            8884097, 8, 0, /* 2607: pointer.func */
            1, 8, 1, /* 2610: pointer.struct.asn1_string_st */
            	2615, 0,
            0, 24, 1, /* 2615: struct.asn1_string_st */
            	206, 8,
            8884097, 8, 0, /* 2620: pointer.func */
            1, 8, 1, /* 2623: pointer.struct.X509_algor_st */
            	2628, 0,
            0, 16, 2, /* 2628: struct.X509_algor_st */
            	2635, 0,
            	2649, 8,
            1, 8, 1, /* 2635: pointer.struct.asn1_object_st */
            	2640, 0,
            0, 40, 3, /* 2640: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 2649: pointer.struct.asn1_type_st */
            	2654, 0,
            0, 16, 1, /* 2654: struct.asn1_type_st */
            	2659, 8,
            0, 8, 20, /* 2659: union.unknown */
            	61, 0,
            	2702, 0,
            	2635, 0,
            	2707, 0,
            	2712, 0,
            	2717, 0,
            	2722, 0,
            	2727, 0,
            	2732, 0,
            	2737, 0,
            	2742, 0,
            	2747, 0,
            	2752, 0,
            	2610, 0,
            	2757, 0,
            	2762, 0,
            	2767, 0,
            	2702, 0,
            	2702, 0,
            	1216, 0,
            1, 8, 1, /* 2702: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2707: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2712: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2717: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2722: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2727: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2732: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2737: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2742: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2747: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2752: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2757: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2762: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2767: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2772: pointer.struct.X509_POLICY_CACHE_st */
            	2777, 0,
            0, 0, 0, /* 2777: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2780: struct.AUTHORITY_KEYID_st */
            0, 0, 0, /* 2783: struct.ec_key_st */
            1, 8, 1, /* 2786: pointer.struct.AUTHORITY_KEYID_st */
            	2780, 0,
            8884097, 8, 0, /* 2791: pointer.func */
            8884097, 8, 0, /* 2794: pointer.func */
            0, 112, 11, /* 2797: struct.ssl3_enc_method */
            	2822, 0,
            	2825, 8,
            	2828, 16,
            	2831, 24,
            	2822, 32,
            	2834, 40,
            	2573, 56,
            	10, 64,
            	10, 80,
            	2837, 96,
            	2840, 104,
            8884097, 8, 0, /* 2822: pointer.func */
            8884097, 8, 0, /* 2825: pointer.func */
            8884097, 8, 0, /* 2828: pointer.func */
            8884097, 8, 0, /* 2831: pointer.func */
            8884097, 8, 0, /* 2834: pointer.func */
            8884097, 8, 0, /* 2837: pointer.func */
            8884097, 8, 0, /* 2840: pointer.func */
            8884097, 8, 0, /* 2843: pointer.func */
            8884097, 8, 0, /* 2846: pointer.func */
            0, 0, 0, /* 2849: struct.X509_POLICY_CACHE_st */
            0, 32, 1, /* 2852: struct.stack_st_GENERAL_NAME */
            	2857, 0,
            0, 32, 2, /* 2857: struct.stack_st */
            	661, 8,
            	453, 24,
            1, 8, 1, /* 2864: pointer.struct.ssl_session_st */
            	2869, 0,
            0, 352, 14, /* 2869: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	2900, 168,
            	134, 176,
            	3588, 224,
            	3593, 240,
            	639, 248,
            	2864, 264,
            	2864, 272,
            	61, 280,
            	206, 296,
            	206, 312,
            	206, 320,
            	61, 344,
            1, 8, 1, /* 2900: pointer.struct.sess_cert_st */
            	2905, 0,
            0, 248, 5, /* 2905: struct.sess_cert_st */
            	2918, 0,
            	120, 16,
            	2230, 216,
            	2238, 224,
            	2246, 232,
            1, 8, 1, /* 2918: pointer.struct.stack_st_X509 */
            	2923, 0,
            0, 32, 2, /* 2923: struct.stack_st_fake_X509 */
            	2930, 8,
            	453, 24,
            8884099, 8, 2, /* 2930: pointer_to_array_of_pointers_to_stack */
            	2937, 0,
            	450, 20,
            0, 8, 1, /* 2937: pointer.X509 */
            	2942, 0,
            0, 0, 1, /* 2942: X509 */
            	2947, 0,
            0, 184, 12, /* 2947: struct.x509_st */
            	2974, 0,
            	3014, 8,
            	3103, 16,
            	61, 32,
            	2526, 40,
            	3108, 104,
            	3453, 112,
            	3461, 120,
            	3466, 128,
            	3490, 136,
            	3514, 144,
            	3522, 176,
            1, 8, 1, /* 2974: pointer.struct.x509_cinf_st */
            	2979, 0,
            0, 104, 11, /* 2979: struct.x509_cinf_st */
            	3004, 0,
            	3004, 8,
            	3014, 16,
            	3171, 24,
            	3176, 32,
            	3171, 40,
            	3193, 48,
            	3103, 56,
            	3103, 64,
            	3424, 72,
            	3448, 80,
            1, 8, 1, /* 3004: pointer.struct.asn1_string_st */
            	3009, 0,
            0, 24, 1, /* 3009: struct.asn1_string_st */
            	206, 8,
            1, 8, 1, /* 3014: pointer.struct.X509_algor_st */
            	3019, 0,
            0, 16, 2, /* 3019: struct.X509_algor_st */
            	3026, 0,
            	3040, 8,
            1, 8, 1, /* 3026: pointer.struct.asn1_object_st */
            	3031, 0,
            0, 40, 3, /* 3031: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 3040: pointer.struct.asn1_type_st */
            	3045, 0,
            0, 16, 1, /* 3045: struct.asn1_type_st */
            	3050, 8,
            0, 8, 20, /* 3050: union.unknown */
            	61, 0,
            	3093, 0,
            	3026, 0,
            	3004, 0,
            	3098, 0,
            	3103, 0,
            	3108, 0,
            	3113, 0,
            	3118, 0,
            	3123, 0,
            	3128, 0,
            	3133, 0,
            	3138, 0,
            	3143, 0,
            	3148, 0,
            	3153, 0,
            	3158, 0,
            	3093, 0,
            	3093, 0,
            	3163, 0,
            1, 8, 1, /* 3093: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3098: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3103: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3108: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3113: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3118: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3123: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3128: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3133: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3138: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3143: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3148: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3153: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3158: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3163: pointer.struct.ASN1_VALUE_st */
            	3168, 0,
            0, 0, 0, /* 3168: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3171: pointer.struct.X509_name_st */
            	2264, 0,
            1, 8, 1, /* 3176: pointer.struct.X509_val_st */
            	3181, 0,
            0, 16, 2, /* 3181: struct.X509_val_st */
            	3188, 0,
            	3188, 8,
            1, 8, 1, /* 3188: pointer.struct.asn1_string_st */
            	3009, 0,
            1, 8, 1, /* 3193: pointer.struct.X509_pubkey_st */
            	3198, 0,
            0, 24, 3, /* 3198: struct.X509_pubkey_st */
            	3014, 0,
            	3103, 8,
            	3207, 16,
            1, 8, 1, /* 3207: pointer.struct.evp_pkey_st */
            	3212, 0,
            0, 56, 4, /* 3212: struct.evp_pkey_st */
            	3223, 16,
            	2508, 24,
            	3231, 32,
            	3400, 48,
            1, 8, 1, /* 3223: pointer.struct.evp_pkey_asn1_method_st */
            	3228, 0,
            0, 0, 0, /* 3228: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3231: union.unknown */
            	61, 0,
            	3244, 0,
            	3249, 0,
            	3327, 0,
            	3392, 0,
            1, 8, 1, /* 3244: pointer.struct.rsa_st */
            	2419, 0,
            1, 8, 1, /* 3249: pointer.struct.dsa_st */
            	3254, 0,
            0, 136, 11, /* 3254: struct.dsa_st */
            	2516, 24,
            	2516, 32,
            	2516, 40,
            	2516, 48,
            	2516, 56,
            	2516, 64,
            	2516, 72,
            	2548, 88,
            	2526, 104,
            	3279, 120,
            	2508, 128,
            1, 8, 1, /* 3279: pointer.struct.dsa_method */
            	3284, 0,
            0, 96, 11, /* 3284: struct.dsa_method */
            	10, 0,
            	3309, 8,
            	3312, 16,
            	3315, 24,
            	2843, 32,
            	3318, 40,
            	3321, 48,
            	3321, 56,
            	61, 72,
            	3324, 80,
            	3321, 88,
            8884097, 8, 0, /* 3309: pointer.func */
            8884097, 8, 0, /* 3312: pointer.func */
            8884097, 8, 0, /* 3315: pointer.func */
            8884097, 8, 0, /* 3318: pointer.func */
            8884097, 8, 0, /* 3321: pointer.func */
            8884097, 8, 0, /* 3324: pointer.func */
            1, 8, 1, /* 3327: pointer.struct.dh_st */
            	3332, 0,
            0, 144, 12, /* 3332: struct.dh_st */
            	2516, 8,
            	2516, 16,
            	2516, 32,
            	2516, 40,
            	2548, 56,
            	2516, 64,
            	2516, 72,
            	206, 80,
            	2516, 96,
            	2526, 112,
            	3359, 128,
            	2508, 136,
            1, 8, 1, /* 3359: pointer.struct.dh_method */
            	3364, 0,
            0, 72, 8, /* 3364: struct.dh_method */
            	10, 0,
            	3383, 8,
            	2607, 16,
            	3386, 24,
            	3383, 32,
            	3383, 40,
            	61, 56,
            	3389, 64,
            8884097, 8, 0, /* 3383: pointer.func */
            8884097, 8, 0, /* 3386: pointer.func */
            8884097, 8, 0, /* 3389: pointer.func */
            1, 8, 1, /* 3392: pointer.struct.ec_key_st */
            	3397, 0,
            0, 0, 0, /* 3397: struct.ec_key_st */
            1, 8, 1, /* 3400: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3405, 0,
            0, 32, 2, /* 3405: struct.stack_st_fake_X509_ATTRIBUTE */
            	3412, 8,
            	453, 24,
            8884099, 8, 2, /* 3412: pointer_to_array_of_pointers_to_stack */
            	3419, 0,
            	450, 20,
            0, 8, 1, /* 3419: pointer.X509_ATTRIBUTE */
            	869, 0,
            1, 8, 1, /* 3424: pointer.struct.stack_st_X509_EXTENSION */
            	3429, 0,
            0, 32, 2, /* 3429: struct.stack_st_fake_X509_EXTENSION */
            	3436, 8,
            	453, 24,
            8884099, 8, 2, /* 3436: pointer_to_array_of_pointers_to_stack */
            	3443, 0,
            	450, 20,
            0, 8, 1, /* 3443: pointer.X509_EXTENSION */
            	1248, 0,
            0, 24, 1, /* 3448: struct.ASN1_ENCODING_st */
            	206, 0,
            1, 8, 1, /* 3453: pointer.struct.AUTHORITY_KEYID_st */
            	3458, 0,
            0, 0, 0, /* 3458: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3461: pointer.struct.X509_POLICY_CACHE_st */
            	2849, 0,
            1, 8, 1, /* 3466: pointer.struct.stack_st_DIST_POINT */
            	3471, 0,
            0, 32, 2, /* 3471: struct.stack_st_fake_DIST_POINT */
            	3478, 8,
            	453, 24,
            8884099, 8, 2, /* 3478: pointer_to_array_of_pointers_to_stack */
            	3485, 0,
            	450, 20,
            0, 8, 1, /* 3485: pointer.DIST_POINT */
            	1629, 0,
            1, 8, 1, /* 3490: pointer.struct.stack_st_GENERAL_NAME */
            	3495, 0,
            0, 32, 2, /* 3495: struct.stack_st_fake_GENERAL_NAME */
            	3502, 8,
            	453, 24,
            8884099, 8, 2, /* 3502: pointer_to_array_of_pointers_to_stack */
            	3509, 0,
            	450, 20,
            0, 8, 1, /* 3509: pointer.GENERAL_NAME */
            	1327, 0,
            1, 8, 1, /* 3514: pointer.struct.NAME_CONSTRAINTS_st */
            	3519, 0,
            0, 0, 0, /* 3519: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3522: pointer.struct.x509_cert_aux_st */
            	3527, 0,
            0, 40, 5, /* 3527: struct.x509_cert_aux_st */
            	3540, 0,
            	3540, 8,
            	3158, 16,
            	3108, 24,
            	3564, 32,
            1, 8, 1, /* 3540: pointer.struct.stack_st_ASN1_OBJECT */
            	3545, 0,
            0, 32, 2, /* 3545: struct.stack_st_fake_ASN1_OBJECT */
            	3552, 8,
            	453, 24,
            8884099, 8, 2, /* 3552: pointer_to_array_of_pointers_to_stack */
            	3559, 0,
            	450, 20,
            0, 8, 1, /* 3559: pointer.ASN1_OBJECT */
            	2130, 0,
            1, 8, 1, /* 3564: pointer.struct.stack_st_X509_ALGOR */
            	3569, 0,
            0, 32, 2, /* 3569: struct.stack_st_fake_X509_ALGOR */
            	3576, 8,
            	453, 24,
            8884099, 8, 2, /* 3576: pointer_to_array_of_pointers_to_stack */
            	3583, 0,
            	450, 20,
            0, 8, 1, /* 3583: pointer.X509_ALGOR */
            	2168, 0,
            1, 8, 1, /* 3588: pointer.struct.ssl_cipher_st */
            	2383, 0,
            1, 8, 1, /* 3593: pointer.struct.stack_st_SSL_CIPHER */
            	3598, 0,
            0, 32, 2, /* 3598: struct.stack_st_fake_SSL_CIPHER */
            	3605, 8,
            	453, 24,
            8884099, 8, 2, /* 3605: pointer_to_array_of_pointers_to_stack */
            	3612, 0,
            	450, 20,
            0, 8, 1, /* 3612: pointer.SSL_CIPHER */
            	3617, 0,
            0, 0, 1, /* 3617: SSL_CIPHER */
            	3622, 0,
            0, 88, 1, /* 3622: struct.ssl_cipher_st */
            	10, 8,
            8884097, 8, 0, /* 3627: pointer.func */
            1, 8, 1, /* 3630: pointer.struct.stack_st_X509_LOOKUP */
            	3635, 0,
            0, 32, 2, /* 3635: struct.stack_st_fake_X509_LOOKUP */
            	3642, 8,
            	453, 24,
            8884099, 8, 2, /* 3642: pointer_to_array_of_pointers_to_stack */
            	3649, 0,
            	450, 20,
            0, 8, 1, /* 3649: pointer.X509_LOOKUP */
            	3654, 0,
            0, 0, 1, /* 3654: X509_LOOKUP */
            	3659, 0,
            0, 32, 3, /* 3659: struct.x509_lookup_st */
            	3668, 8,
            	61, 16,
            	3714, 24,
            1, 8, 1, /* 3668: pointer.struct.x509_lookup_method_st */
            	3673, 0,
            0, 80, 10, /* 3673: struct.x509_lookup_method_st */
            	10, 0,
            	3696, 8,
            	2791, 16,
            	3696, 24,
            	3696, 32,
            	3699, 40,
            	3702, 48,
            	3705, 56,
            	3708, 64,
            	3711, 72,
            8884097, 8, 0, /* 3696: pointer.func */
            8884097, 8, 0, /* 3699: pointer.func */
            8884097, 8, 0, /* 3702: pointer.func */
            8884097, 8, 0, /* 3705: pointer.func */
            8884097, 8, 0, /* 3708: pointer.func */
            8884097, 8, 0, /* 3711: pointer.func */
            1, 8, 1, /* 3714: pointer.struct.x509_store_st */
            	3719, 0,
            0, 144, 15, /* 3719: struct.x509_store_st */
            	3752, 8,
            	4607, 16,
            	4631, 24,
            	4643, 32,
            	4646, 40,
            	3627, 48,
            	4649, 56,
            	4643, 64,
            	4652, 72,
            	4655, 80,
            	4658, 88,
            	2410, 96,
            	4661, 104,
            	4643, 112,
            	2388, 120,
            1, 8, 1, /* 3752: pointer.struct.stack_st_X509_OBJECT */
            	3757, 0,
            0, 32, 2, /* 3757: struct.stack_st_fake_X509_OBJECT */
            	3764, 8,
            	453, 24,
            8884099, 8, 2, /* 3764: pointer_to_array_of_pointers_to_stack */
            	3771, 0,
            	450, 20,
            0, 8, 1, /* 3771: pointer.X509_OBJECT */
            	3776, 0,
            0, 0, 1, /* 3776: X509_OBJECT */
            	3781, 0,
            0, 16, 1, /* 3781: struct.x509_object_st */
            	3786, 8,
            0, 8, 4, /* 3786: union.unknown */
            	61, 0,
            	3797, 0,
            	4407, 0,
            	3938, 0,
            1, 8, 1, /* 3797: pointer.struct.x509_st */
            	3802, 0,
            0, 184, 12, /* 3802: struct.x509_st */
            	3829, 0,
            	2623, 8,
            	2717, 16,
            	61, 32,
            	2388, 40,
            	2722, 104,
            	2786, 112,
            	2772, 120,
            	4285, 128,
            	4309, 136,
            	4333, 144,
            	4341, 176,
            1, 8, 1, /* 3829: pointer.struct.x509_cinf_st */
            	3834, 0,
            0, 104, 11, /* 3834: struct.x509_cinf_st */
            	2707, 0,
            	2707, 8,
            	2623, 16,
            	3859, 24,
            	3907, 32,
            	3859, 40,
            	3924, 48,
            	2717, 56,
            	2717, 64,
            	4256, 72,
            	4280, 80,
            1, 8, 1, /* 3859: pointer.struct.X509_name_st */
            	3864, 0,
            0, 40, 3, /* 3864: struct.X509_name_st */
            	3873, 0,
            	3897, 16,
            	206, 24,
            1, 8, 1, /* 3873: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3878, 0,
            0, 32, 2, /* 3878: struct.stack_st_fake_X509_NAME_ENTRY */
            	3885, 8,
            	453, 24,
            8884099, 8, 2, /* 3885: pointer_to_array_of_pointers_to_stack */
            	3892, 0,
            	450, 20,
            0, 8, 1, /* 3892: pointer.X509_NAME_ENTRY */
            	414, 0,
            1, 8, 1, /* 3897: pointer.struct.buf_mem_st */
            	3902, 0,
            0, 24, 1, /* 3902: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 3907: pointer.struct.X509_val_st */
            	3912, 0,
            0, 16, 2, /* 3912: struct.X509_val_st */
            	3919, 0,
            	3919, 8,
            1, 8, 1, /* 3919: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 3924: pointer.struct.X509_pubkey_st */
            	3929, 0,
            0, 24, 3, /* 3929: struct.X509_pubkey_st */
            	2623, 0,
            	2717, 8,
            	3938, 16,
            1, 8, 1, /* 3938: pointer.struct.evp_pkey_st */
            	3943, 0,
            0, 56, 4, /* 3943: struct.evp_pkey_st */
            	3954, 16,
            	3962, 24,
            	3970, 32,
            	4232, 48,
            1, 8, 1, /* 3954: pointer.struct.evp_pkey_asn1_method_st */
            	3959, 0,
            0, 0, 0, /* 3959: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3962: pointer.struct.engine_st */
            	3967, 0,
            0, 0, 0, /* 3967: struct.engine_st */
            0, 8, 5, /* 3970: union.unknown */
            	61, 0,
            	3983, 0,
            	4109, 0,
            	4190, 0,
            	4227, 0,
            1, 8, 1, /* 3983: pointer.struct.rsa_st */
            	3988, 0,
            0, 168, 17, /* 3988: struct.rsa_st */
            	4025, 16,
            	3962, 24,
            	4077, 32,
            	4077, 40,
            	4077, 48,
            	4077, 56,
            	4077, 64,
            	4077, 72,
            	4077, 80,
            	4077, 88,
            	2388, 96,
            	4087, 120,
            	4087, 128,
            	4087, 136,
            	61, 144,
            	4101, 152,
            	4101, 160,
            1, 8, 1, /* 4025: pointer.struct.rsa_meth_st */
            	4030, 0,
            0, 112, 13, /* 4030: struct.rsa_meth_st */
            	10, 0,
            	4059, 8,
            	4059, 16,
            	4059, 24,
            	4059, 32,
            	4062, 40,
            	4065, 48,
            	2620, 56,
            	2620, 64,
            	61, 80,
            	4068, 88,
            	4071, 96,
            	4074, 104,
            8884097, 8, 0, /* 4059: pointer.func */
            8884097, 8, 0, /* 4062: pointer.func */
            8884097, 8, 0, /* 4065: pointer.func */
            8884097, 8, 0, /* 4068: pointer.func */
            8884097, 8, 0, /* 4071: pointer.func */
            8884097, 8, 0, /* 4074: pointer.func */
            1, 8, 1, /* 4077: pointer.struct.bignum_st */
            	4082, 0,
            0, 24, 1, /* 4082: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 4087: pointer.struct.bn_mont_ctx_st */
            	4092, 0,
            0, 96, 3, /* 4092: struct.bn_mont_ctx_st */
            	4082, 8,
            	4082, 32,
            	4082, 56,
            1, 8, 1, /* 4101: pointer.struct.bn_blinding_st */
            	4106, 0,
            0, 0, 0, /* 4106: struct.bn_blinding_st */
            1, 8, 1, /* 4109: pointer.struct.dsa_st */
            	4114, 0,
            0, 136, 11, /* 4114: struct.dsa_st */
            	4077, 24,
            	4077, 32,
            	4077, 40,
            	4077, 48,
            	4077, 56,
            	4077, 64,
            	4077, 72,
            	4087, 88,
            	2388, 104,
            	4139, 120,
            	3962, 128,
            1, 8, 1, /* 4139: pointer.struct.dsa_method */
            	4144, 0,
            0, 96, 11, /* 4144: struct.dsa_method */
            	10, 0,
            	4169, 8,
            	4172, 16,
            	4175, 24,
            	4178, 32,
            	4181, 40,
            	4184, 48,
            	4184, 56,
            	61, 72,
            	4187, 80,
            	4184, 88,
            8884097, 8, 0, /* 4169: pointer.func */
            8884097, 8, 0, /* 4172: pointer.func */
            8884097, 8, 0, /* 4175: pointer.func */
            8884097, 8, 0, /* 4178: pointer.func */
            8884097, 8, 0, /* 4181: pointer.func */
            8884097, 8, 0, /* 4184: pointer.func */
            8884097, 8, 0, /* 4187: pointer.func */
            1, 8, 1, /* 4190: pointer.struct.dh_st */
            	4195, 0,
            0, 144, 12, /* 4195: struct.dh_st */
            	4077, 8,
            	4077, 16,
            	4077, 32,
            	4077, 40,
            	4087, 56,
            	4077, 64,
            	4077, 72,
            	206, 80,
            	4077, 96,
            	2388, 112,
            	4222, 128,
            	3962, 136,
            1, 8, 1, /* 4222: pointer.struct.dh_method */
            	2576, 0,
            1, 8, 1, /* 4227: pointer.struct.ec_key_st */
            	2783, 0,
            1, 8, 1, /* 4232: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4237, 0,
            0, 32, 2, /* 4237: struct.stack_st_fake_X509_ATTRIBUTE */
            	4244, 8,
            	453, 24,
            8884099, 8, 2, /* 4244: pointer_to_array_of_pointers_to_stack */
            	4251, 0,
            	450, 20,
            0, 8, 1, /* 4251: pointer.X509_ATTRIBUTE */
            	869, 0,
            1, 8, 1, /* 4256: pointer.struct.stack_st_X509_EXTENSION */
            	4261, 0,
            0, 32, 2, /* 4261: struct.stack_st_fake_X509_EXTENSION */
            	4268, 8,
            	453, 24,
            8884099, 8, 2, /* 4268: pointer_to_array_of_pointers_to_stack */
            	4275, 0,
            	450, 20,
            0, 8, 1, /* 4275: pointer.X509_EXTENSION */
            	1248, 0,
            0, 24, 1, /* 4280: struct.ASN1_ENCODING_st */
            	206, 0,
            1, 8, 1, /* 4285: pointer.struct.stack_st_DIST_POINT */
            	4290, 0,
            0, 32, 2, /* 4290: struct.stack_st_fake_DIST_POINT */
            	4297, 8,
            	453, 24,
            8884099, 8, 2, /* 4297: pointer_to_array_of_pointers_to_stack */
            	4304, 0,
            	450, 20,
            0, 8, 1, /* 4304: pointer.DIST_POINT */
            	1629, 0,
            1, 8, 1, /* 4309: pointer.struct.stack_st_GENERAL_NAME */
            	4314, 0,
            0, 32, 2, /* 4314: struct.stack_st_fake_GENERAL_NAME */
            	4321, 8,
            	453, 24,
            8884099, 8, 2, /* 4321: pointer_to_array_of_pointers_to_stack */
            	4328, 0,
            	450, 20,
            0, 8, 1, /* 4328: pointer.GENERAL_NAME */
            	1327, 0,
            1, 8, 1, /* 4333: pointer.struct.NAME_CONSTRAINTS_st */
            	4338, 0,
            0, 0, 0, /* 4338: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4341: pointer.struct.x509_cert_aux_st */
            	4346, 0,
            0, 40, 5, /* 4346: struct.x509_cert_aux_st */
            	4359, 0,
            	4359, 8,
            	2767, 16,
            	2722, 24,
            	4383, 32,
            1, 8, 1, /* 4359: pointer.struct.stack_st_ASN1_OBJECT */
            	4364, 0,
            0, 32, 2, /* 4364: struct.stack_st_fake_ASN1_OBJECT */
            	4371, 8,
            	453, 24,
            8884099, 8, 2, /* 4371: pointer_to_array_of_pointers_to_stack */
            	4378, 0,
            	450, 20,
            0, 8, 1, /* 4378: pointer.ASN1_OBJECT */
            	2130, 0,
            1, 8, 1, /* 4383: pointer.struct.stack_st_X509_ALGOR */
            	4388, 0,
            0, 32, 2, /* 4388: struct.stack_st_fake_X509_ALGOR */
            	4395, 8,
            	453, 24,
            8884099, 8, 2, /* 4395: pointer_to_array_of_pointers_to_stack */
            	4402, 0,
            	450, 20,
            0, 8, 1, /* 4402: pointer.X509_ALGOR */
            	2168, 0,
            1, 8, 1, /* 4407: pointer.struct.X509_crl_st */
            	4412, 0,
            0, 120, 10, /* 4412: struct.X509_crl_st */
            	4435, 0,
            	2623, 8,
            	2717, 16,
            	2786, 32,
            	4562, 40,
            	2707, 56,
            	2707, 64,
            	4570, 96,
            	4599, 104,
            	49, 112,
            1, 8, 1, /* 4435: pointer.struct.X509_crl_info_st */
            	4440, 0,
            0, 80, 8, /* 4440: struct.X509_crl_info_st */
            	2707, 0,
            	2623, 8,
            	3859, 16,
            	3919, 24,
            	3919, 32,
            	4459, 40,
            	4256, 48,
            	4280, 56,
            1, 8, 1, /* 4459: pointer.struct.stack_st_X509_REVOKED */
            	4464, 0,
            0, 32, 2, /* 4464: struct.stack_st_fake_X509_REVOKED */
            	4471, 8,
            	453, 24,
            8884099, 8, 2, /* 4471: pointer_to_array_of_pointers_to_stack */
            	4478, 0,
            	450, 20,
            0, 8, 1, /* 4478: pointer.X509_REVOKED */
            	4483, 0,
            0, 0, 1, /* 4483: X509_REVOKED */
            	4488, 0,
            0, 40, 4, /* 4488: struct.x509_revoked_st */
            	4499, 0,
            	4509, 8,
            	4514, 16,
            	4538, 24,
            1, 8, 1, /* 4499: pointer.struct.asn1_string_st */
            	4504, 0,
            0, 24, 1, /* 4504: struct.asn1_string_st */
            	206, 8,
            1, 8, 1, /* 4509: pointer.struct.asn1_string_st */
            	4504, 0,
            1, 8, 1, /* 4514: pointer.struct.stack_st_X509_EXTENSION */
            	4519, 0,
            0, 32, 2, /* 4519: struct.stack_st_fake_X509_EXTENSION */
            	4526, 8,
            	453, 24,
            8884099, 8, 2, /* 4526: pointer_to_array_of_pointers_to_stack */
            	4533, 0,
            	450, 20,
            0, 8, 1, /* 4533: pointer.X509_EXTENSION */
            	1248, 0,
            1, 8, 1, /* 4538: pointer.struct.stack_st_GENERAL_NAME */
            	4543, 0,
            0, 32, 2, /* 4543: struct.stack_st_fake_GENERAL_NAME */
            	4550, 8,
            	453, 24,
            8884099, 8, 2, /* 4550: pointer_to_array_of_pointers_to_stack */
            	4557, 0,
            	450, 20,
            0, 8, 1, /* 4557: pointer.GENERAL_NAME */
            	1327, 0,
            1, 8, 1, /* 4562: pointer.struct.ISSUING_DIST_POINT_st */
            	4567, 0,
            0, 0, 0, /* 4567: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 4570: pointer.struct.stack_st_GENERAL_NAMES */
            	4575, 0,
            0, 32, 2, /* 4575: struct.stack_st_fake_GENERAL_NAMES */
            	4582, 8,
            	453, 24,
            8884099, 8, 2, /* 4582: pointer_to_array_of_pointers_to_stack */
            	4589, 0,
            	450, 20,
            0, 8, 1, /* 4589: pointer.GENERAL_NAMES */
            	4594, 0,
            0, 0, 1, /* 4594: GENERAL_NAMES */
            	2852, 0,
            1, 8, 1, /* 4599: pointer.struct.x509_crl_method_st */
            	4604, 0,
            0, 0, 0, /* 4604: struct.x509_crl_method_st */
            1, 8, 1, /* 4607: pointer.struct.stack_st_X509_LOOKUP */
            	4612, 0,
            0, 32, 2, /* 4612: struct.stack_st_fake_X509_LOOKUP */
            	4619, 8,
            	453, 24,
            8884099, 8, 2, /* 4619: pointer_to_array_of_pointers_to_stack */
            	4626, 0,
            	450, 20,
            0, 8, 1, /* 4626: pointer.X509_LOOKUP */
            	3654, 0,
            1, 8, 1, /* 4631: pointer.struct.X509_VERIFY_PARAM_st */
            	4636, 0,
            0, 56, 2, /* 4636: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	4359, 48,
            8884097, 8, 0, /* 4643: pointer.func */
            8884097, 8, 0, /* 4646: pointer.func */
            8884097, 8, 0, /* 4649: pointer.func */
            8884097, 8, 0, /* 4652: pointer.func */
            8884097, 8, 0, /* 4655: pointer.func */
            8884097, 8, 0, /* 4658: pointer.func */
            8884097, 8, 0, /* 4661: pointer.func */
            8884097, 8, 0, /* 4664: pointer.func */
            8884097, 8, 0, /* 4667: pointer.func */
            8884097, 8, 0, /* 4670: pointer.func */
            8884097, 8, 0, /* 4673: pointer.func */
            1, 8, 1, /* 4676: pointer.struct.stack_st_X509_OBJECT */
            	4681, 0,
            0, 32, 2, /* 4681: struct.stack_st_fake_X509_OBJECT */
            	4688, 8,
            	453, 24,
            8884099, 8, 2, /* 4688: pointer_to_array_of_pointers_to_stack */
            	4695, 0,
            	450, 20,
            0, 8, 1, /* 4695: pointer.X509_OBJECT */
            	3776, 0,
            1, 8, 1, /* 4700: pointer.struct.ssl_method_st */
            	4705, 0,
            0, 232, 28, /* 4705: struct.ssl_method_st */
            	2828, 8,
            	4764, 16,
            	4764, 24,
            	2828, 32,
            	2828, 40,
            	4670, 48,
            	4670, 56,
            	4767, 64,
            	2828, 72,
            	2828, 80,
            	2828, 88,
            	4770, 96,
            	4673, 104,
            	4773, 112,
            	2828, 120,
            	4776, 128,
            	4779, 136,
            	4782, 144,
            	4785, 152,
            	4788, 160,
            	4791, 168,
            	4794, 176,
            	4797, 184,
            	2333, 192,
            	4800, 200,
            	4791, 208,
            	4805, 216,
            	4808, 224,
            8884097, 8, 0, /* 4764: pointer.func */
            8884097, 8, 0, /* 4767: pointer.func */
            8884097, 8, 0, /* 4770: pointer.func */
            8884097, 8, 0, /* 4773: pointer.func */
            8884097, 8, 0, /* 4776: pointer.func */
            8884097, 8, 0, /* 4779: pointer.func */
            8884097, 8, 0, /* 4782: pointer.func */
            8884097, 8, 0, /* 4785: pointer.func */
            8884097, 8, 0, /* 4788: pointer.func */
            8884097, 8, 0, /* 4791: pointer.func */
            8884097, 8, 0, /* 4794: pointer.func */
            8884097, 8, 0, /* 4797: pointer.func */
            1, 8, 1, /* 4800: pointer.struct.ssl3_enc_method */
            	2797, 0,
            8884097, 8, 0, /* 4805: pointer.func */
            8884097, 8, 0, /* 4808: pointer.func */
            8884097, 8, 0, /* 4811: pointer.func */
            0, 144, 15, /* 4814: struct.x509_store_st */
            	4676, 8,
            	3630, 16,
            	4847, 24,
            	4859, 32,
            	4862, 40,
            	4865, 48,
            	4868, 56,
            	4859, 64,
            	4871, 72,
            	4874, 80,
            	4877, 88,
            	2794, 96,
            	4880, 104,
            	4859, 112,
            	639, 120,
            1, 8, 1, /* 4847: pointer.struct.X509_VERIFY_PARAM_st */
            	4852, 0,
            0, 56, 2, /* 4852: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	2106, 48,
            8884097, 8, 0, /* 4859: pointer.func */
            8884097, 8, 0, /* 4862: pointer.func */
            8884097, 8, 0, /* 4865: pointer.func */
            8884097, 8, 0, /* 4868: pointer.func */
            8884097, 8, 0, /* 4871: pointer.func */
            8884097, 8, 0, /* 4874: pointer.func */
            8884097, 8, 0, /* 4877: pointer.func */
            8884097, 8, 0, /* 4880: pointer.func */
            0, 8, 1, /* 4883: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            1, 8, 1, /* 4888: pointer.struct.x509_store_st */
            	4814, 0,
            8884097, 8, 0, /* 4893: pointer.func */
            1, 8, 1, /* 4896: pointer.struct.lhash_node_st */
            	4901, 0,
            0, 24, 2, /* 4901: struct.lhash_node_st */
            	49, 0,
            	4908, 8,
            1, 8, 1, /* 4908: pointer.struct.lhash_node_st */
            	4901, 0,
            0, 32, 2, /* 4913: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4920, 8,
            	453, 24,
            8884099, 8, 2, /* 4920: pointer_to_array_of_pointers_to_stack */
            	4883, 0,
            	450, 20,
            1, 8, 1, /* 4927: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4913, 0,
            0, 736, 50, /* 4932: struct.ssl_ctx_st */
            	4700, 0,
            	3593, 8,
            	3593, 16,
            	4888, 24,
            	5035, 32,
            	2864, 48,
            	2864, 56,
            	5054, 80,
            	5057, 88,
            	2380, 96,
            	4664, 152,
            	49, 160,
            	5060, 168,
            	49, 176,
            	5063, 184,
            	5066, 192,
            	2377, 200,
            	639, 208,
            	2185, 224,
            	2185, 232,
            	2185, 240,
            	2918, 248,
            	2353, 256,
            	2256, 264,
            	5069, 272,
            	2251, 304,
            	2416, 320,
            	49, 328,
            	4862, 376,
            	5093, 384,
            	4847, 392,
            	521, 408,
            	52, 416,
            	49, 424,
            	4667, 480,
            	55, 488,
            	49, 496,
            	97, 504,
            	49, 512,
            	61, 520,
            	94, 528,
            	4893, 536,
            	5096, 552,
            	5096, 560,
            	18, 568,
            	15, 696,
            	49, 704,
            	2846, 712,
            	49, 720,
            	4927, 728,
            1, 8, 1, /* 5035: pointer.struct.lhash_st */
            	5040, 0,
            0, 176, 3, /* 5040: struct.lhash_st */
            	5049, 0,
            	453, 8,
            	4811, 16,
            1, 8, 1, /* 5049: pointer.pointer.struct.lhash_node_st */
            	4896, 0,
            8884097, 8, 0, /* 5054: pointer.func */
            8884097, 8, 0, /* 5057: pointer.func */
            8884097, 8, 0, /* 5060: pointer.func */
            8884097, 8, 0, /* 5063: pointer.func */
            8884097, 8, 0, /* 5066: pointer.func */
            1, 8, 1, /* 5069: pointer.struct.stack_st_X509_NAME */
            	5074, 0,
            0, 32, 2, /* 5074: struct.stack_st_fake_X509_NAME */
            	5081, 8,
            	453, 24,
            8884099, 8, 2, /* 5081: pointer_to_array_of_pointers_to_stack */
            	5088, 0,
            	450, 20,
            0, 8, 1, /* 5088: pointer.X509_NAME */
            	2259, 0,
            8884097, 8, 0, /* 5093: pointer.func */
            1, 8, 1, /* 5096: pointer.struct.ssl3_buf_freelist_st */
            	5101, 0,
            0, 24, 1, /* 5101: struct.ssl3_buf_freelist_st */
            	84, 16,
            1, 8, 1, /* 5106: pointer.struct.ssl_ctx_st */
            	4932, 0,
        },
        .arg_entity_index = { 5106, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    void (*orig_SSL_CTX_free)(SSL_CTX *);
    orig_SSL_CTX_free = dlsym(RTLD_NEXT, "SSL_CTX_free");
    (*orig_SSL_CTX_free)(new_arg_a);

    syscall(889);

}

