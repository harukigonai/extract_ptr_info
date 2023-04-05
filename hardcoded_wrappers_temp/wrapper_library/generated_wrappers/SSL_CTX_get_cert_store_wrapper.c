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

X509_STORE * bb_SSL_CTX_get_cert_store(const SSL_CTX * arg_a);

X509_STORE * SSL_CTX_get_cert_store(const SSL_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_get_cert_store called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_get_cert_store(arg_a);
    else {
        X509_STORE * (*orig_SSL_CTX_get_cert_store)(const SSL_CTX *);
        orig_SSL_CTX_get_cert_store = dlsym(RTLD_NEXT, "SSL_CTX_get_cert_store");
        return orig_SSL_CTX_get_cert_store(arg_a);
    }
}

X509_STORE * bb_SSL_CTX_get_cert_store(const SSL_CTX * arg_a) 
{
    X509_STORE * ret;

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
            1, 8, 1, /* 2388: pointer.struct.stack_st_X509_OBJECT */
            	2393, 0,
            0, 32, 2, /* 2393: struct.stack_st_fake_X509_OBJECT */
            	2400, 8,
            	453, 24,
            8884099, 8, 2, /* 2400: pointer_to_array_of_pointers_to_stack */
            	2407, 0,
            	450, 20,
            0, 8, 1, /* 2407: pointer.X509_OBJECT */
            	2412, 0,
            0, 0, 1, /* 2412: X509_OBJECT */
            	2417, 0,
            0, 16, 1, /* 2417: struct.x509_object_st */
            	2422, 8,
            0, 8, 4, /* 2422: union.unknown */
            	61, 0,
            	2433, 0,
            	3277, 0,
            	2733, 0,
            1, 8, 1, /* 2433: pointer.struct.x509_st */
            	2438, 0,
            0, 184, 12, /* 2438: struct.x509_st */
            	2465, 0,
            	2505, 8,
            	2594, 16,
            	61, 32,
            	2885, 40,
            	2599, 104,
            	3139, 112,
            	3147, 120,
            	3155, 128,
            	3179, 136,
            	3203, 144,
            	3211, 176,
            1, 8, 1, /* 2465: pointer.struct.x509_cinf_st */
            	2470, 0,
            0, 104, 11, /* 2470: struct.x509_cinf_st */
            	2495, 0,
            	2495, 8,
            	2505, 16,
            	2654, 24,
            	2702, 32,
            	2654, 40,
            	2719, 48,
            	2594, 56,
            	2594, 64,
            	3110, 72,
            	3134, 80,
            1, 8, 1, /* 2495: pointer.struct.asn1_string_st */
            	2500, 0,
            0, 24, 1, /* 2500: struct.asn1_string_st */
            	206, 8,
            1, 8, 1, /* 2505: pointer.struct.X509_algor_st */
            	2510, 0,
            0, 16, 2, /* 2510: struct.X509_algor_st */
            	2517, 0,
            	2531, 8,
            1, 8, 1, /* 2517: pointer.struct.asn1_object_st */
            	2522, 0,
            0, 40, 3, /* 2522: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 2531: pointer.struct.asn1_type_st */
            	2536, 0,
            0, 16, 1, /* 2536: struct.asn1_type_st */
            	2541, 8,
            0, 8, 20, /* 2541: union.unknown */
            	61, 0,
            	2584, 0,
            	2517, 0,
            	2495, 0,
            	2589, 0,
            	2594, 0,
            	2599, 0,
            	2604, 0,
            	2609, 0,
            	2614, 0,
            	2619, 0,
            	2624, 0,
            	2629, 0,
            	2634, 0,
            	2639, 0,
            	2644, 0,
            	2649, 0,
            	2584, 0,
            	2584, 0,
            	1216, 0,
            1, 8, 1, /* 2584: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2589: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2594: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2599: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2604: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2609: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2614: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2619: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2624: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2629: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2634: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2639: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2644: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2649: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2654: pointer.struct.X509_name_st */
            	2659, 0,
            0, 40, 3, /* 2659: struct.X509_name_st */
            	2668, 0,
            	2692, 16,
            	206, 24,
            1, 8, 1, /* 2668: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2673, 0,
            0, 32, 2, /* 2673: struct.stack_st_fake_X509_NAME_ENTRY */
            	2680, 8,
            	453, 24,
            8884099, 8, 2, /* 2680: pointer_to_array_of_pointers_to_stack */
            	2687, 0,
            	450, 20,
            0, 8, 1, /* 2687: pointer.X509_NAME_ENTRY */
            	414, 0,
            1, 8, 1, /* 2692: pointer.struct.buf_mem_st */
            	2697, 0,
            0, 24, 1, /* 2697: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 2702: pointer.struct.X509_val_st */
            	2707, 0,
            0, 16, 2, /* 2707: struct.X509_val_st */
            	2714, 0,
            	2714, 8,
            1, 8, 1, /* 2714: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2719: pointer.struct.X509_pubkey_st */
            	2724, 0,
            0, 24, 3, /* 2724: struct.X509_pubkey_st */
            	2505, 0,
            	2594, 8,
            	2733, 16,
            1, 8, 1, /* 2733: pointer.struct.evp_pkey_st */
            	2738, 0,
            0, 56, 4, /* 2738: struct.evp_pkey_st */
            	2749, 16,
            	2757, 24,
            	2765, 32,
            	3086, 48,
            1, 8, 1, /* 2749: pointer.struct.evp_pkey_asn1_method_st */
            	2754, 0,
            0, 0, 0, /* 2754: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2757: pointer.struct.engine_st */
            	2762, 0,
            0, 0, 0, /* 2762: struct.engine_st */
            0, 8, 5, /* 2765: union.unknown */
            	61, 0,
            	2778, 0,
            	2929, 0,
            	3010, 0,
            	3078, 0,
            1, 8, 1, /* 2778: pointer.struct.rsa_st */
            	2783, 0,
            0, 168, 17, /* 2783: struct.rsa_st */
            	2820, 16,
            	2757, 24,
            	2875, 32,
            	2875, 40,
            	2875, 48,
            	2875, 56,
            	2875, 64,
            	2875, 72,
            	2875, 80,
            	2875, 88,
            	2885, 96,
            	2907, 120,
            	2907, 128,
            	2907, 136,
            	61, 144,
            	2921, 152,
            	2921, 160,
            1, 8, 1, /* 2820: pointer.struct.rsa_meth_st */
            	2825, 0,
            0, 112, 13, /* 2825: struct.rsa_meth_st */
            	10, 0,
            	2854, 8,
            	2854, 16,
            	2854, 24,
            	2854, 32,
            	2857, 40,
            	2860, 48,
            	2863, 56,
            	2863, 64,
            	61, 80,
            	2866, 88,
            	2869, 96,
            	2872, 104,
            8884097, 8, 0, /* 2854: pointer.func */
            8884097, 8, 0, /* 2857: pointer.func */
            8884097, 8, 0, /* 2860: pointer.func */
            8884097, 8, 0, /* 2863: pointer.func */
            8884097, 8, 0, /* 2866: pointer.func */
            8884097, 8, 0, /* 2869: pointer.func */
            8884097, 8, 0, /* 2872: pointer.func */
            1, 8, 1, /* 2875: pointer.struct.bignum_st */
            	2880, 0,
            0, 24, 1, /* 2880: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 2885: struct.crypto_ex_data_st */
            	2890, 0,
            1, 8, 1, /* 2890: pointer.struct.stack_st_void */
            	2895, 0,
            0, 32, 1, /* 2895: struct.stack_st_void */
            	2900, 0,
            0, 32, 2, /* 2900: struct.stack_st */
            	661, 8,
            	453, 24,
            1, 8, 1, /* 2907: pointer.struct.bn_mont_ctx_st */
            	2912, 0,
            0, 96, 3, /* 2912: struct.bn_mont_ctx_st */
            	2880, 8,
            	2880, 32,
            	2880, 56,
            1, 8, 1, /* 2921: pointer.struct.bn_blinding_st */
            	2926, 0,
            0, 0, 0, /* 2926: struct.bn_blinding_st */
            1, 8, 1, /* 2929: pointer.struct.dsa_st */
            	2934, 0,
            0, 136, 11, /* 2934: struct.dsa_st */
            	2875, 24,
            	2875, 32,
            	2875, 40,
            	2875, 48,
            	2875, 56,
            	2875, 64,
            	2875, 72,
            	2907, 88,
            	2885, 104,
            	2959, 120,
            	2757, 128,
            1, 8, 1, /* 2959: pointer.struct.dsa_method */
            	2964, 0,
            0, 96, 11, /* 2964: struct.dsa_method */
            	10, 0,
            	2989, 8,
            	2992, 16,
            	2995, 24,
            	2998, 32,
            	3001, 40,
            	3004, 48,
            	3004, 56,
            	61, 72,
            	3007, 80,
            	3004, 88,
            8884097, 8, 0, /* 2989: pointer.func */
            8884097, 8, 0, /* 2992: pointer.func */
            8884097, 8, 0, /* 2995: pointer.func */
            8884097, 8, 0, /* 2998: pointer.func */
            8884097, 8, 0, /* 3001: pointer.func */
            8884097, 8, 0, /* 3004: pointer.func */
            8884097, 8, 0, /* 3007: pointer.func */
            1, 8, 1, /* 3010: pointer.struct.dh_st */
            	3015, 0,
            0, 144, 12, /* 3015: struct.dh_st */
            	2875, 8,
            	2875, 16,
            	2875, 32,
            	2875, 40,
            	2907, 56,
            	2875, 64,
            	2875, 72,
            	206, 80,
            	2875, 96,
            	2885, 112,
            	3042, 128,
            	2757, 136,
            1, 8, 1, /* 3042: pointer.struct.dh_method */
            	3047, 0,
            0, 72, 8, /* 3047: struct.dh_method */
            	10, 0,
            	3066, 8,
            	3069, 16,
            	3072, 24,
            	3066, 32,
            	3066, 40,
            	61, 56,
            	3075, 64,
            8884097, 8, 0, /* 3066: pointer.func */
            8884097, 8, 0, /* 3069: pointer.func */
            8884097, 8, 0, /* 3072: pointer.func */
            8884097, 8, 0, /* 3075: pointer.func */
            1, 8, 1, /* 3078: pointer.struct.ec_key_st */
            	3083, 0,
            0, 0, 0, /* 3083: struct.ec_key_st */
            1, 8, 1, /* 3086: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3091, 0,
            0, 32, 2, /* 3091: struct.stack_st_fake_X509_ATTRIBUTE */
            	3098, 8,
            	453, 24,
            8884099, 8, 2, /* 3098: pointer_to_array_of_pointers_to_stack */
            	3105, 0,
            	450, 20,
            0, 8, 1, /* 3105: pointer.X509_ATTRIBUTE */
            	869, 0,
            1, 8, 1, /* 3110: pointer.struct.stack_st_X509_EXTENSION */
            	3115, 0,
            0, 32, 2, /* 3115: struct.stack_st_fake_X509_EXTENSION */
            	3122, 8,
            	453, 24,
            8884099, 8, 2, /* 3122: pointer_to_array_of_pointers_to_stack */
            	3129, 0,
            	450, 20,
            0, 8, 1, /* 3129: pointer.X509_EXTENSION */
            	1248, 0,
            0, 24, 1, /* 3134: struct.ASN1_ENCODING_st */
            	206, 0,
            1, 8, 1, /* 3139: pointer.struct.AUTHORITY_KEYID_st */
            	3144, 0,
            0, 0, 0, /* 3144: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3147: pointer.struct.X509_POLICY_CACHE_st */
            	3152, 0,
            0, 0, 0, /* 3152: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3155: pointer.struct.stack_st_DIST_POINT */
            	3160, 0,
            0, 32, 2, /* 3160: struct.stack_st_fake_DIST_POINT */
            	3167, 8,
            	453, 24,
            8884099, 8, 2, /* 3167: pointer_to_array_of_pointers_to_stack */
            	3174, 0,
            	450, 20,
            0, 8, 1, /* 3174: pointer.DIST_POINT */
            	1629, 0,
            1, 8, 1, /* 3179: pointer.struct.stack_st_GENERAL_NAME */
            	3184, 0,
            0, 32, 2, /* 3184: struct.stack_st_fake_GENERAL_NAME */
            	3191, 8,
            	453, 24,
            8884099, 8, 2, /* 3191: pointer_to_array_of_pointers_to_stack */
            	3198, 0,
            	450, 20,
            0, 8, 1, /* 3198: pointer.GENERAL_NAME */
            	1327, 0,
            1, 8, 1, /* 3203: pointer.struct.NAME_CONSTRAINTS_st */
            	3208, 0,
            0, 0, 0, /* 3208: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3211: pointer.struct.x509_cert_aux_st */
            	3216, 0,
            0, 40, 5, /* 3216: struct.x509_cert_aux_st */
            	3229, 0,
            	3229, 8,
            	2649, 16,
            	2599, 24,
            	3253, 32,
            1, 8, 1, /* 3229: pointer.struct.stack_st_ASN1_OBJECT */
            	3234, 0,
            0, 32, 2, /* 3234: struct.stack_st_fake_ASN1_OBJECT */
            	3241, 8,
            	453, 24,
            8884099, 8, 2, /* 3241: pointer_to_array_of_pointers_to_stack */
            	3248, 0,
            	450, 20,
            0, 8, 1, /* 3248: pointer.ASN1_OBJECT */
            	2130, 0,
            1, 8, 1, /* 3253: pointer.struct.stack_st_X509_ALGOR */
            	3258, 0,
            0, 32, 2, /* 3258: struct.stack_st_fake_X509_ALGOR */
            	3265, 8,
            	453, 24,
            8884099, 8, 2, /* 3265: pointer_to_array_of_pointers_to_stack */
            	3272, 0,
            	450, 20,
            0, 8, 1, /* 3272: pointer.X509_ALGOR */
            	2168, 0,
            1, 8, 1, /* 3277: pointer.struct.X509_crl_st */
            	3282, 0,
            0, 120, 10, /* 3282: struct.X509_crl_st */
            	3305, 0,
            	2505, 8,
            	2594, 16,
            	3139, 32,
            	3432, 40,
            	2495, 56,
            	2495, 64,
            	3440, 96,
            	3481, 104,
            	49, 112,
            1, 8, 1, /* 3305: pointer.struct.X509_crl_info_st */
            	3310, 0,
            0, 80, 8, /* 3310: struct.X509_crl_info_st */
            	2495, 0,
            	2505, 8,
            	2654, 16,
            	2714, 24,
            	2714, 32,
            	3329, 40,
            	3110, 48,
            	3134, 56,
            1, 8, 1, /* 3329: pointer.struct.stack_st_X509_REVOKED */
            	3334, 0,
            0, 32, 2, /* 3334: struct.stack_st_fake_X509_REVOKED */
            	3341, 8,
            	453, 24,
            8884099, 8, 2, /* 3341: pointer_to_array_of_pointers_to_stack */
            	3348, 0,
            	450, 20,
            0, 8, 1, /* 3348: pointer.X509_REVOKED */
            	3353, 0,
            0, 0, 1, /* 3353: X509_REVOKED */
            	3358, 0,
            0, 40, 4, /* 3358: struct.x509_revoked_st */
            	3369, 0,
            	3379, 8,
            	3384, 16,
            	3408, 24,
            1, 8, 1, /* 3369: pointer.struct.asn1_string_st */
            	3374, 0,
            0, 24, 1, /* 3374: struct.asn1_string_st */
            	206, 8,
            1, 8, 1, /* 3379: pointer.struct.asn1_string_st */
            	3374, 0,
            1, 8, 1, /* 3384: pointer.struct.stack_st_X509_EXTENSION */
            	3389, 0,
            0, 32, 2, /* 3389: struct.stack_st_fake_X509_EXTENSION */
            	3396, 8,
            	453, 24,
            8884099, 8, 2, /* 3396: pointer_to_array_of_pointers_to_stack */
            	3403, 0,
            	450, 20,
            0, 8, 1, /* 3403: pointer.X509_EXTENSION */
            	1248, 0,
            1, 8, 1, /* 3408: pointer.struct.stack_st_GENERAL_NAME */
            	3413, 0,
            0, 32, 2, /* 3413: struct.stack_st_fake_GENERAL_NAME */
            	3420, 8,
            	453, 24,
            8884099, 8, 2, /* 3420: pointer_to_array_of_pointers_to_stack */
            	3427, 0,
            	450, 20,
            0, 8, 1, /* 3427: pointer.GENERAL_NAME */
            	1327, 0,
            1, 8, 1, /* 3432: pointer.struct.ISSUING_DIST_POINT_st */
            	3437, 0,
            0, 0, 0, /* 3437: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3440: pointer.struct.stack_st_GENERAL_NAMES */
            	3445, 0,
            0, 32, 2, /* 3445: struct.stack_st_fake_GENERAL_NAMES */
            	3452, 8,
            	453, 24,
            8884099, 8, 2, /* 3452: pointer_to_array_of_pointers_to_stack */
            	3459, 0,
            	450, 20,
            0, 8, 1, /* 3459: pointer.GENERAL_NAMES */
            	3464, 0,
            0, 0, 1, /* 3464: GENERAL_NAMES */
            	3469, 0,
            0, 32, 1, /* 3469: struct.stack_st_GENERAL_NAME */
            	3474, 0,
            0, 32, 2, /* 3474: struct.stack_st */
            	661, 8,
            	453, 24,
            1, 8, 1, /* 3481: pointer.struct.x509_crl_method_st */
            	3486, 0,
            0, 0, 0, /* 3486: struct.x509_crl_method_st */
            8884097, 8, 0, /* 3489: pointer.func */
            8884097, 8, 0, /* 3492: pointer.func */
            1, 8, 1, /* 3495: pointer.struct.asn1_string_st */
            	3500, 0,
            0, 24, 1, /* 3500: struct.asn1_string_st */
            	206, 8,
            8884097, 8, 0, /* 3505: pointer.func */
            1, 8, 1, /* 3508: pointer.struct.ASN1_VALUE_st */
            	3513, 0,
            0, 0, 0, /* 3513: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 3516: pointer.func */
            8884097, 8, 0, /* 3519: pointer.func */
            0, 168, 17, /* 3522: struct.rsa_st */
            	3559, 16,
            	3611, 24,
            	3619, 32,
            	3619, 40,
            	3619, 48,
            	3619, 56,
            	3619, 64,
            	3619, 72,
            	3619, 80,
            	3619, 88,
            	3629, 96,
            	3651, 120,
            	3651, 128,
            	3651, 136,
            	61, 144,
            	3665, 152,
            	3665, 160,
            1, 8, 1, /* 3559: pointer.struct.rsa_meth_st */
            	3564, 0,
            0, 112, 13, /* 3564: struct.rsa_meth_st */
            	10, 0,
            	3593, 8,
            	3593, 16,
            	3593, 24,
            	3593, 32,
            	3516, 40,
            	3596, 48,
            	3599, 56,
            	3599, 64,
            	61, 80,
            	3602, 88,
            	3605, 96,
            	3608, 104,
            8884097, 8, 0, /* 3593: pointer.func */
            8884097, 8, 0, /* 3596: pointer.func */
            8884097, 8, 0, /* 3599: pointer.func */
            8884097, 8, 0, /* 3602: pointer.func */
            8884097, 8, 0, /* 3605: pointer.func */
            8884097, 8, 0, /* 3608: pointer.func */
            1, 8, 1, /* 3611: pointer.struct.engine_st */
            	3616, 0,
            0, 0, 0, /* 3616: struct.engine_st */
            1, 8, 1, /* 3619: pointer.struct.bignum_st */
            	3624, 0,
            0, 24, 1, /* 3624: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 3629: struct.crypto_ex_data_st */
            	3634, 0,
            1, 8, 1, /* 3634: pointer.struct.stack_st_void */
            	3639, 0,
            0, 32, 1, /* 3639: struct.stack_st_void */
            	3644, 0,
            0, 32, 2, /* 3644: struct.stack_st */
            	661, 8,
            	453, 24,
            1, 8, 1, /* 3651: pointer.struct.bn_mont_ctx_st */
            	3656, 0,
            0, 96, 3, /* 3656: struct.bn_mont_ctx_st */
            	3624, 8,
            	3624, 32,
            	3624, 56,
            1, 8, 1, /* 3665: pointer.struct.bn_blinding_st */
            	3670, 0,
            0, 0, 0, /* 3670: struct.bn_blinding_st */
            0, 1, 0, /* 3673: char */
            8884097, 8, 0, /* 3676: pointer.func */
            8884097, 8, 0, /* 3679: pointer.func */
            8884097, 8, 0, /* 3682: pointer.func */
            8884097, 8, 0, /* 3685: pointer.func */
            8884097, 8, 0, /* 3688: pointer.func */
            0, 112, 11, /* 3691: struct.ssl3_enc_method */
            	3716, 0,
            	3719, 8,
            	3722, 16,
            	3725, 24,
            	3716, 32,
            	3728, 40,
            	3676, 56,
            	10, 64,
            	10, 80,
            	3731, 96,
            	3734, 104,
            8884097, 8, 0, /* 3716: pointer.func */
            8884097, 8, 0, /* 3719: pointer.func */
            8884097, 8, 0, /* 3722: pointer.func */
            8884097, 8, 0, /* 3725: pointer.func */
            8884097, 8, 0, /* 3728: pointer.func */
            8884097, 8, 0, /* 3731: pointer.func */
            8884097, 8, 0, /* 3734: pointer.func */
            8884097, 8, 0, /* 3737: pointer.func */
            8884097, 8, 0, /* 3740: pointer.func */
            1, 8, 1, /* 3743: pointer.struct.X509_pubkey_st */
            	3748, 0,
            0, 24, 3, /* 3748: struct.X509_pubkey_st */
            	3757, 0,
            	3851, 8,
            	3906, 16,
            1, 8, 1, /* 3757: pointer.struct.X509_algor_st */
            	3762, 0,
            0, 16, 2, /* 3762: struct.X509_algor_st */
            	3769, 0,
            	3783, 8,
            1, 8, 1, /* 3769: pointer.struct.asn1_object_st */
            	3774, 0,
            0, 40, 3, /* 3774: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 3783: pointer.struct.asn1_type_st */
            	3788, 0,
            0, 16, 1, /* 3788: struct.asn1_type_st */
            	3793, 8,
            0, 8, 20, /* 3793: union.unknown */
            	61, 0,
            	3836, 0,
            	3769, 0,
            	3841, 0,
            	3846, 0,
            	3851, 0,
            	3856, 0,
            	3861, 0,
            	3866, 0,
            	3495, 0,
            	3871, 0,
            	3876, 0,
            	3881, 0,
            	3886, 0,
            	3891, 0,
            	3896, 0,
            	3901, 0,
            	3836, 0,
            	3836, 0,
            	3508, 0,
            1, 8, 1, /* 3836: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3841: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3846: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3851: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3856: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3861: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3866: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3871: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3876: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3881: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3886: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3891: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3896: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3901: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 3906: pointer.struct.evp_pkey_st */
            	3911, 0,
            0, 56, 4, /* 3911: struct.evp_pkey_st */
            	3922, 16,
            	3611, 24,
            	3930, 32,
            	4096, 48,
            1, 8, 1, /* 3922: pointer.struct.evp_pkey_asn1_method_st */
            	3927, 0,
            0, 0, 0, /* 3927: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3930: union.unknown */
            	61, 0,
            	3943, 0,
            	3948, 0,
            	4023, 0,
            	4088, 0,
            1, 8, 1, /* 3943: pointer.struct.rsa_st */
            	3522, 0,
            1, 8, 1, /* 3948: pointer.struct.dsa_st */
            	3953, 0,
            0, 136, 11, /* 3953: struct.dsa_st */
            	3619, 24,
            	3619, 32,
            	3619, 40,
            	3619, 48,
            	3619, 56,
            	3619, 64,
            	3619, 72,
            	3651, 88,
            	3629, 104,
            	3978, 120,
            	3611, 128,
            1, 8, 1, /* 3978: pointer.struct.dsa_method */
            	3983, 0,
            0, 96, 11, /* 3983: struct.dsa_method */
            	10, 0,
            	4008, 8,
            	4011, 16,
            	3489, 24,
            	3737, 32,
            	4014, 40,
            	4017, 48,
            	4017, 56,
            	61, 72,
            	4020, 80,
            	4017, 88,
            8884097, 8, 0, /* 4008: pointer.func */
            8884097, 8, 0, /* 4011: pointer.func */
            8884097, 8, 0, /* 4014: pointer.func */
            8884097, 8, 0, /* 4017: pointer.func */
            8884097, 8, 0, /* 4020: pointer.func */
            1, 8, 1, /* 4023: pointer.struct.dh_st */
            	4028, 0,
            0, 144, 12, /* 4028: struct.dh_st */
            	3619, 8,
            	3619, 16,
            	3619, 32,
            	3619, 40,
            	3651, 56,
            	3619, 64,
            	3619, 72,
            	206, 80,
            	3619, 96,
            	3629, 112,
            	4055, 128,
            	3611, 136,
            1, 8, 1, /* 4055: pointer.struct.dh_method */
            	4060, 0,
            0, 72, 8, /* 4060: struct.dh_method */
            	10, 0,
            	4079, 8,
            	3679, 16,
            	4082, 24,
            	4079, 32,
            	4079, 40,
            	61, 56,
            	4085, 64,
            8884097, 8, 0, /* 4079: pointer.func */
            8884097, 8, 0, /* 4082: pointer.func */
            8884097, 8, 0, /* 4085: pointer.func */
            1, 8, 1, /* 4088: pointer.struct.ec_key_st */
            	4093, 0,
            0, 0, 0, /* 4093: struct.ec_key_st */
            1, 8, 1, /* 4096: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4101, 0,
            0, 32, 2, /* 4101: struct.stack_st_fake_X509_ATTRIBUTE */
            	4108, 8,
            	453, 24,
            8884099, 8, 2, /* 4108: pointer_to_array_of_pointers_to_stack */
            	4115, 0,
            	450, 20,
            0, 8, 1, /* 4115: pointer.X509_ATTRIBUTE */
            	869, 0,
            0, 0, 0, /* 4120: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4123: pointer.struct.ssl_session_st */
            	4128, 0,
            0, 352, 14, /* 4128: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	4159, 168,
            	134, 176,
            	4449, 224,
            	4454, 240,
            	639, 248,
            	4123, 264,
            	4123, 272,
            	61, 280,
            	206, 296,
            	206, 312,
            	206, 320,
            	61, 344,
            1, 8, 1, /* 4159: pointer.struct.sess_cert_st */
            	4164, 0,
            0, 248, 5, /* 4164: struct.sess_cert_st */
            	4177, 0,
            	120, 16,
            	2230, 216,
            	2238, 224,
            	2246, 232,
            1, 8, 1, /* 4177: pointer.struct.stack_st_X509 */
            	4182, 0,
            0, 32, 2, /* 4182: struct.stack_st_fake_X509 */
            	4189, 8,
            	453, 24,
            8884099, 8, 2, /* 4189: pointer_to_array_of_pointers_to_stack */
            	4196, 0,
            	450, 20,
            0, 8, 1, /* 4196: pointer.X509 */
            	4201, 0,
            0, 0, 1, /* 4201: X509 */
            	4206, 0,
            0, 184, 12, /* 4206: struct.x509_st */
            	4233, 0,
            	3757, 8,
            	3851, 16,
            	61, 32,
            	3629, 40,
            	3856, 104,
            	4314, 112,
            	4322, 120,
            	4327, 128,
            	4351, 136,
            	4375, 144,
            	4383, 176,
            1, 8, 1, /* 4233: pointer.struct.x509_cinf_st */
            	4238, 0,
            0, 104, 11, /* 4238: struct.x509_cinf_st */
            	3841, 0,
            	3841, 8,
            	3757, 16,
            	4263, 24,
            	4268, 32,
            	4263, 40,
            	3743, 48,
            	3851, 56,
            	3851, 64,
            	4285, 72,
            	4309, 80,
            1, 8, 1, /* 4263: pointer.struct.X509_name_st */
            	2264, 0,
            1, 8, 1, /* 4268: pointer.struct.X509_val_st */
            	4273, 0,
            0, 16, 2, /* 4273: struct.X509_val_st */
            	4280, 0,
            	4280, 8,
            1, 8, 1, /* 4280: pointer.struct.asn1_string_st */
            	3500, 0,
            1, 8, 1, /* 4285: pointer.struct.stack_st_X509_EXTENSION */
            	4290, 0,
            0, 32, 2, /* 4290: struct.stack_st_fake_X509_EXTENSION */
            	4297, 8,
            	453, 24,
            8884099, 8, 2, /* 4297: pointer_to_array_of_pointers_to_stack */
            	4304, 0,
            	450, 20,
            0, 8, 1, /* 4304: pointer.X509_EXTENSION */
            	1248, 0,
            0, 24, 1, /* 4309: struct.ASN1_ENCODING_st */
            	206, 0,
            1, 8, 1, /* 4314: pointer.struct.AUTHORITY_KEYID_st */
            	4319, 0,
            0, 0, 0, /* 4319: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4322: pointer.struct.X509_POLICY_CACHE_st */
            	4120, 0,
            1, 8, 1, /* 4327: pointer.struct.stack_st_DIST_POINT */
            	4332, 0,
            0, 32, 2, /* 4332: struct.stack_st_fake_DIST_POINT */
            	4339, 8,
            	453, 24,
            8884099, 8, 2, /* 4339: pointer_to_array_of_pointers_to_stack */
            	4346, 0,
            	450, 20,
            0, 8, 1, /* 4346: pointer.DIST_POINT */
            	1629, 0,
            1, 8, 1, /* 4351: pointer.struct.stack_st_GENERAL_NAME */
            	4356, 0,
            0, 32, 2, /* 4356: struct.stack_st_fake_GENERAL_NAME */
            	4363, 8,
            	453, 24,
            8884099, 8, 2, /* 4363: pointer_to_array_of_pointers_to_stack */
            	4370, 0,
            	450, 20,
            0, 8, 1, /* 4370: pointer.GENERAL_NAME */
            	1327, 0,
            1, 8, 1, /* 4375: pointer.struct.NAME_CONSTRAINTS_st */
            	4380, 0,
            0, 0, 0, /* 4380: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4383: pointer.struct.x509_cert_aux_st */
            	4388, 0,
            0, 40, 5, /* 4388: struct.x509_cert_aux_st */
            	4401, 0,
            	4401, 8,
            	3901, 16,
            	3856, 24,
            	4425, 32,
            1, 8, 1, /* 4401: pointer.struct.stack_st_ASN1_OBJECT */
            	4406, 0,
            0, 32, 2, /* 4406: struct.stack_st_fake_ASN1_OBJECT */
            	4413, 8,
            	453, 24,
            8884099, 8, 2, /* 4413: pointer_to_array_of_pointers_to_stack */
            	4420, 0,
            	450, 20,
            0, 8, 1, /* 4420: pointer.ASN1_OBJECT */
            	2130, 0,
            1, 8, 1, /* 4425: pointer.struct.stack_st_X509_ALGOR */
            	4430, 0,
            0, 32, 2, /* 4430: struct.stack_st_fake_X509_ALGOR */
            	4437, 8,
            	453, 24,
            8884099, 8, 2, /* 4437: pointer_to_array_of_pointers_to_stack */
            	4444, 0,
            	450, 20,
            0, 8, 1, /* 4444: pointer.X509_ALGOR */
            	2168, 0,
            1, 8, 1, /* 4449: pointer.struct.ssl_cipher_st */
            	2383, 0,
            1, 8, 1, /* 4454: pointer.struct.stack_st_SSL_CIPHER */
            	4459, 0,
            0, 32, 2, /* 4459: struct.stack_st_fake_SSL_CIPHER */
            	4466, 8,
            	453, 24,
            8884099, 8, 2, /* 4466: pointer_to_array_of_pointers_to_stack */
            	4473, 0,
            	450, 20,
            0, 8, 1, /* 4473: pointer.SSL_CIPHER */
            	4478, 0,
            0, 0, 1, /* 4478: SSL_CIPHER */
            	4483, 0,
            0, 88, 1, /* 4483: struct.ssl_cipher_st */
            	10, 8,
            8884097, 8, 0, /* 4488: pointer.func */
            1, 8, 1, /* 4491: pointer.struct.stack_st_X509_LOOKUP */
            	4496, 0,
            0, 32, 2, /* 4496: struct.stack_st_fake_X509_LOOKUP */
            	4503, 8,
            	453, 24,
            8884099, 8, 2, /* 4503: pointer_to_array_of_pointers_to_stack */
            	4510, 0,
            	450, 20,
            0, 8, 1, /* 4510: pointer.X509_LOOKUP */
            	4515, 0,
            0, 0, 1, /* 4515: X509_LOOKUP */
            	4520, 0,
            0, 32, 3, /* 4520: struct.x509_lookup_st */
            	4529, 8,
            	61, 16,
            	4575, 24,
            1, 8, 1, /* 4529: pointer.struct.x509_lookup_method_st */
            	4534, 0,
            0, 80, 10, /* 4534: struct.x509_lookup_method_st */
            	10, 0,
            	4557, 8,
            	3685, 16,
            	4557, 24,
            	4557, 32,
            	4560, 40,
            	4563, 48,
            	4566, 56,
            	4569, 64,
            	4572, 72,
            8884097, 8, 0, /* 4557: pointer.func */
            8884097, 8, 0, /* 4560: pointer.func */
            8884097, 8, 0, /* 4563: pointer.func */
            8884097, 8, 0, /* 4566: pointer.func */
            8884097, 8, 0, /* 4569: pointer.func */
            8884097, 8, 0, /* 4572: pointer.func */
            1, 8, 1, /* 4575: pointer.struct.x509_store_st */
            	4580, 0,
            0, 144, 15, /* 4580: struct.x509_store_st */
            	2388, 8,
            	4613, 16,
            	4637, 24,
            	4649, 32,
            	4652, 40,
            	4488, 48,
            	3682, 56,
            	4649, 64,
            	4655, 72,
            	4658, 80,
            	4661, 88,
            	3492, 96,
            	4664, 104,
            	4649, 112,
            	2885, 120,
            1, 8, 1, /* 4613: pointer.struct.stack_st_X509_LOOKUP */
            	4618, 0,
            0, 32, 2, /* 4618: struct.stack_st_fake_X509_LOOKUP */
            	4625, 8,
            	453, 24,
            8884099, 8, 2, /* 4625: pointer_to_array_of_pointers_to_stack */
            	4632, 0,
            	450, 20,
            0, 8, 1, /* 4632: pointer.X509_LOOKUP */
            	4515, 0,
            1, 8, 1, /* 4637: pointer.struct.X509_VERIFY_PARAM_st */
            	4642, 0,
            0, 56, 2, /* 4642: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	3229, 48,
            8884097, 8, 0, /* 4649: pointer.func */
            8884097, 8, 0, /* 4652: pointer.func */
            8884097, 8, 0, /* 4655: pointer.func */
            8884097, 8, 0, /* 4658: pointer.func */
            8884097, 8, 0, /* 4661: pointer.func */
            8884097, 8, 0, /* 4664: pointer.func */
            8884097, 8, 0, /* 4667: pointer.func */
            8884097, 8, 0, /* 4670: pointer.func */
            1, 8, 1, /* 4673: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4678, 0,
            0, 32, 2, /* 4678: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4685, 8,
            	453, 24,
            8884099, 8, 2, /* 4685: pointer_to_array_of_pointers_to_stack */
            	4692, 0,
            	450, 20,
            0, 8, 1, /* 4692: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 4697: pointer.func */
            8884097, 8, 0, /* 4700: pointer.func */
            8884097, 8, 0, /* 4703: pointer.func */
            0, 144, 15, /* 4706: struct.x509_store_st */
            	4739, 8,
            	4491, 16,
            	4763, 24,
            	4775, 32,
            	4778, 40,
            	4781, 48,
            	4784, 56,
            	4775, 64,
            	4787, 72,
            	4790, 80,
            	3505, 88,
            	3688, 96,
            	4793, 104,
            	4775, 112,
            	639, 120,
            1, 8, 1, /* 4739: pointer.struct.stack_st_X509_OBJECT */
            	4744, 0,
            0, 32, 2, /* 4744: struct.stack_st_fake_X509_OBJECT */
            	4751, 8,
            	453, 24,
            8884099, 8, 2, /* 4751: pointer_to_array_of_pointers_to_stack */
            	4758, 0,
            	450, 20,
            0, 8, 1, /* 4758: pointer.X509_OBJECT */
            	2412, 0,
            1, 8, 1, /* 4763: pointer.struct.X509_VERIFY_PARAM_st */
            	4768, 0,
            0, 56, 2, /* 4768: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	2106, 48,
            8884097, 8, 0, /* 4775: pointer.func */
            8884097, 8, 0, /* 4778: pointer.func */
            8884097, 8, 0, /* 4781: pointer.func */
            8884097, 8, 0, /* 4784: pointer.func */
            8884097, 8, 0, /* 4787: pointer.func */
            8884097, 8, 0, /* 4790: pointer.func */
            8884097, 8, 0, /* 4793: pointer.func */
            1, 8, 1, /* 4796: pointer.struct.x509_store_st */
            	4706, 0,
            8884097, 8, 0, /* 4801: pointer.func */
            1, 8, 1, /* 4804: pointer.struct.ssl_method_st */
            	4809, 0,
            0, 232, 28, /* 4809: struct.ssl_method_st */
            	3722, 8,
            	4868, 16,
            	4868, 24,
            	3722, 32,
            	3722, 40,
            	4700, 48,
            	4700, 56,
            	4871, 64,
            	3722, 72,
            	3722, 80,
            	3722, 88,
            	4874, 96,
            	4877, 104,
            	4880, 112,
            	3722, 120,
            	4883, 128,
            	4886, 136,
            	4889, 144,
            	4892, 152,
            	4895, 160,
            	4898, 168,
            	4697, 176,
            	4901, 184,
            	2333, 192,
            	4904, 200,
            	4898, 208,
            	4909, 216,
            	4667, 224,
            8884097, 8, 0, /* 4868: pointer.func */
            8884097, 8, 0, /* 4871: pointer.func */
            8884097, 8, 0, /* 4874: pointer.func */
            8884097, 8, 0, /* 4877: pointer.func */
            8884097, 8, 0, /* 4880: pointer.func */
            8884097, 8, 0, /* 4883: pointer.func */
            8884097, 8, 0, /* 4886: pointer.func */
            8884097, 8, 0, /* 4889: pointer.func */
            8884097, 8, 0, /* 4892: pointer.func */
            8884097, 8, 0, /* 4895: pointer.func */
            8884097, 8, 0, /* 4898: pointer.func */
            8884097, 8, 0, /* 4901: pointer.func */
            1, 8, 1, /* 4904: pointer.struct.ssl3_enc_method */
            	3691, 0,
            8884097, 8, 0, /* 4909: pointer.func */
            8884097, 8, 0, /* 4912: pointer.func */
            8884097, 8, 0, /* 4915: pointer.func */
            1, 8, 1, /* 4918: pointer.struct.x509_store_st */
            	4706, 0,
            8884097, 8, 0, /* 4923: pointer.func */
            1, 8, 1, /* 4926: pointer.pointer.struct.lhash_node_st */
            	4931, 0,
            1, 8, 1, /* 4931: pointer.struct.lhash_node_st */
            	4936, 0,
            0, 24, 2, /* 4936: struct.lhash_node_st */
            	49, 0,
            	4943, 8,
            1, 8, 1, /* 4943: pointer.struct.lhash_node_st */
            	4936, 0,
            8884097, 8, 0, /* 4948: pointer.func */
            1, 8, 1, /* 4951: pointer.struct.ssl_ctx_st */
            	4956, 0,
            0, 736, 50, /* 4956: struct.ssl_ctx_st */
            	4804, 0,
            	4454, 8,
            	4454, 16,
            	4796, 24,
            	5059, 32,
            	4123, 48,
            	4123, 56,
            	4948, 80,
            	5073, 88,
            	2380, 96,
            	4923, 152,
            	49, 160,
            	5076, 168,
            	49, 176,
            	4801, 184,
            	5079, 192,
            	2377, 200,
            	639, 208,
            	2185, 224,
            	2185, 232,
            	2185, 240,
            	4177, 248,
            	2353, 256,
            	2256, 264,
            	5082, 272,
            	2251, 304,
            	3519, 320,
            	49, 328,
            	4778, 376,
            	4912, 384,
            	4763, 392,
            	521, 408,
            	52, 416,
            	49, 424,
            	4670, 480,
            	55, 488,
            	49, 496,
            	97, 504,
            	49, 512,
            	61, 520,
            	94, 528,
            	4915, 536,
            	5106, 552,
            	5106, 560,
            	18, 568,
            	15, 696,
            	49, 704,
            	3740, 712,
            	49, 720,
            	4673, 728,
            1, 8, 1, /* 5059: pointer.struct.lhash_st */
            	5064, 0,
            0, 176, 3, /* 5064: struct.lhash_st */
            	4926, 0,
            	453, 8,
            	4703, 16,
            8884097, 8, 0, /* 5073: pointer.func */
            8884097, 8, 0, /* 5076: pointer.func */
            8884097, 8, 0, /* 5079: pointer.func */
            1, 8, 1, /* 5082: pointer.struct.stack_st_X509_NAME */
            	5087, 0,
            0, 32, 2, /* 5087: struct.stack_st_fake_X509_NAME */
            	5094, 8,
            	453, 24,
            8884099, 8, 2, /* 5094: pointer_to_array_of_pointers_to_stack */
            	5101, 0,
            	450, 20,
            0, 8, 1, /* 5101: pointer.X509_NAME */
            	2259, 0,
            1, 8, 1, /* 5106: pointer.struct.ssl3_buf_freelist_st */
            	5111, 0,
            0, 24, 1, /* 5111: struct.ssl3_buf_freelist_st */
            	84, 16,
        },
        .arg_entity_index = { 4951, },
        .ret_entity_index = 4918,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL_CTX * new_arg_a = *((const SSL_CTX * *)new_args->args[0]);

    X509_STORE * *new_ret_ptr = (X509_STORE * *)new_args->ret;

    X509_STORE * (*orig_SSL_CTX_get_cert_store)(const SSL_CTX *);
    orig_SSL_CTX_get_cert_store = dlsym(RTLD_NEXT, "SSL_CTX_get_cert_store");
    *new_ret_ptr = (*orig_SSL_CTX_get_cert_store)(new_arg_a);

    syscall(889);

    return ret;
}

