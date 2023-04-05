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

long bb_SSL_CTX_ctrl(SSL_CTX * arg_a,int arg_b,long arg_c,void * arg_d);

long SSL_CTX_ctrl(SSL_CTX * arg_a,int arg_b,long arg_c,void * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_ctrl called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_ctrl(arg_a,arg_b,arg_c,arg_d);
    else {
        long (*orig_SSL_CTX_ctrl)(SSL_CTX *,int,long,void *);
        orig_SSL_CTX_ctrl = dlsym(RTLD_NEXT, "SSL_CTX_ctrl");
        return orig_SSL_CTX_ctrl(arg_a,arg_b,arg_c,arg_d);
    }
}

long bb_SSL_CTX_ctrl(SSL_CTX * arg_a,int arg_b,long arg_c,void * arg_d) 
{
    long ret;

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
            0, 0, 0, /* 2772: struct.AUTHORITY_KEYID_st */
            0, 0, 0, /* 2775: struct.ec_key_st */
            1, 8, 1, /* 2778: pointer.struct.AUTHORITY_KEYID_st */
            	2772, 0,
            8884097, 8, 0, /* 2783: pointer.func */
            8884097, 8, 0, /* 2786: pointer.func */
            0, 112, 11, /* 2789: struct.ssl3_enc_method */
            	2814, 0,
            	2817, 8,
            	2820, 16,
            	2823, 24,
            	2814, 32,
            	2826, 40,
            	2573, 56,
            	10, 64,
            	10, 80,
            	2829, 96,
            	2832, 104,
            8884097, 8, 0, /* 2814: pointer.func */
            8884097, 8, 0, /* 2817: pointer.func */
            8884097, 8, 0, /* 2820: pointer.func */
            8884097, 8, 0, /* 2823: pointer.func */
            8884097, 8, 0, /* 2826: pointer.func */
            8884097, 8, 0, /* 2829: pointer.func */
            8884097, 8, 0, /* 2832: pointer.func */
            8884097, 8, 0, /* 2835: pointer.func */
            8884097, 8, 0, /* 2838: pointer.func */
            0, 0, 0, /* 2841: struct.X509_POLICY_CACHE_st */
            0, 32, 1, /* 2844: struct.stack_st_GENERAL_NAME */
            	2849, 0,
            0, 32, 2, /* 2849: struct.stack_st */
            	661, 8,
            	453, 24,
            1, 8, 1, /* 2856: pointer.struct.ssl_session_st */
            	2861, 0,
            0, 352, 14, /* 2861: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	2892, 168,
            	134, 176,
            	3580, 224,
            	3585, 240,
            	639, 248,
            	2856, 264,
            	2856, 272,
            	61, 280,
            	206, 296,
            	206, 312,
            	206, 320,
            	61, 344,
            1, 8, 1, /* 2892: pointer.struct.sess_cert_st */
            	2897, 0,
            0, 248, 5, /* 2897: struct.sess_cert_st */
            	2910, 0,
            	120, 16,
            	2230, 216,
            	2238, 224,
            	2246, 232,
            1, 8, 1, /* 2910: pointer.struct.stack_st_X509 */
            	2915, 0,
            0, 32, 2, /* 2915: struct.stack_st_fake_X509 */
            	2922, 8,
            	453, 24,
            8884099, 8, 2, /* 2922: pointer_to_array_of_pointers_to_stack */
            	2929, 0,
            	450, 20,
            0, 8, 1, /* 2929: pointer.X509 */
            	2934, 0,
            0, 0, 1, /* 2934: X509 */
            	2939, 0,
            0, 184, 12, /* 2939: struct.x509_st */
            	2966, 0,
            	3006, 8,
            	3095, 16,
            	61, 32,
            	2526, 40,
            	3100, 104,
            	3445, 112,
            	3453, 120,
            	3458, 128,
            	3482, 136,
            	3506, 144,
            	3514, 176,
            1, 8, 1, /* 2966: pointer.struct.x509_cinf_st */
            	2971, 0,
            0, 104, 11, /* 2971: struct.x509_cinf_st */
            	2996, 0,
            	2996, 8,
            	3006, 16,
            	3163, 24,
            	3168, 32,
            	3163, 40,
            	3185, 48,
            	3095, 56,
            	3095, 64,
            	3416, 72,
            	3440, 80,
            1, 8, 1, /* 2996: pointer.struct.asn1_string_st */
            	3001, 0,
            0, 24, 1, /* 3001: struct.asn1_string_st */
            	206, 8,
            1, 8, 1, /* 3006: pointer.struct.X509_algor_st */
            	3011, 0,
            0, 16, 2, /* 3011: struct.X509_algor_st */
            	3018, 0,
            	3032, 8,
            1, 8, 1, /* 3018: pointer.struct.asn1_object_st */
            	3023, 0,
            0, 40, 3, /* 3023: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	240, 24,
            1, 8, 1, /* 3032: pointer.struct.asn1_type_st */
            	3037, 0,
            0, 16, 1, /* 3037: struct.asn1_type_st */
            	3042, 8,
            0, 8, 20, /* 3042: union.unknown */
            	61, 0,
            	3085, 0,
            	3018, 0,
            	2996, 0,
            	3090, 0,
            	3095, 0,
            	3100, 0,
            	3105, 0,
            	3110, 0,
            	3115, 0,
            	3120, 0,
            	3125, 0,
            	3130, 0,
            	3135, 0,
            	3140, 0,
            	3145, 0,
            	3150, 0,
            	3085, 0,
            	3085, 0,
            	3155, 0,
            1, 8, 1, /* 3085: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3090: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3095: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3100: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3105: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3110: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3115: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3120: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3125: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3130: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3135: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3140: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3145: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3150: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3155: pointer.struct.ASN1_VALUE_st */
            	3160, 0,
            0, 0, 0, /* 3160: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3163: pointer.struct.X509_name_st */
            	2264, 0,
            1, 8, 1, /* 3168: pointer.struct.X509_val_st */
            	3173, 0,
            0, 16, 2, /* 3173: struct.X509_val_st */
            	3180, 0,
            	3180, 8,
            1, 8, 1, /* 3180: pointer.struct.asn1_string_st */
            	3001, 0,
            1, 8, 1, /* 3185: pointer.struct.X509_pubkey_st */
            	3190, 0,
            0, 24, 3, /* 3190: struct.X509_pubkey_st */
            	3006, 0,
            	3095, 8,
            	3199, 16,
            1, 8, 1, /* 3199: pointer.struct.evp_pkey_st */
            	3204, 0,
            0, 56, 4, /* 3204: struct.evp_pkey_st */
            	3215, 16,
            	2508, 24,
            	3223, 32,
            	3392, 48,
            1, 8, 1, /* 3215: pointer.struct.evp_pkey_asn1_method_st */
            	3220, 0,
            0, 0, 0, /* 3220: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3223: union.unknown */
            	61, 0,
            	3236, 0,
            	3241, 0,
            	3319, 0,
            	3384, 0,
            1, 8, 1, /* 3236: pointer.struct.rsa_st */
            	2419, 0,
            1, 8, 1, /* 3241: pointer.struct.dsa_st */
            	3246, 0,
            0, 136, 11, /* 3246: struct.dsa_st */
            	2516, 24,
            	2516, 32,
            	2516, 40,
            	2516, 48,
            	2516, 56,
            	2516, 64,
            	2516, 72,
            	2548, 88,
            	2526, 104,
            	3271, 120,
            	2508, 128,
            1, 8, 1, /* 3271: pointer.struct.dsa_method */
            	3276, 0,
            0, 96, 11, /* 3276: struct.dsa_method */
            	10, 0,
            	3301, 8,
            	3304, 16,
            	3307, 24,
            	2835, 32,
            	3310, 40,
            	3313, 48,
            	3313, 56,
            	61, 72,
            	3316, 80,
            	3313, 88,
            8884097, 8, 0, /* 3301: pointer.func */
            8884097, 8, 0, /* 3304: pointer.func */
            8884097, 8, 0, /* 3307: pointer.func */
            8884097, 8, 0, /* 3310: pointer.func */
            8884097, 8, 0, /* 3313: pointer.func */
            8884097, 8, 0, /* 3316: pointer.func */
            1, 8, 1, /* 3319: pointer.struct.dh_st */
            	3324, 0,
            0, 144, 12, /* 3324: struct.dh_st */
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
            	3351, 128,
            	2508, 136,
            1, 8, 1, /* 3351: pointer.struct.dh_method */
            	3356, 0,
            0, 72, 8, /* 3356: struct.dh_method */
            	10, 0,
            	3375, 8,
            	2607, 16,
            	3378, 24,
            	3375, 32,
            	3375, 40,
            	61, 56,
            	3381, 64,
            8884097, 8, 0, /* 3375: pointer.func */
            8884097, 8, 0, /* 3378: pointer.func */
            8884097, 8, 0, /* 3381: pointer.func */
            1, 8, 1, /* 3384: pointer.struct.ec_key_st */
            	3389, 0,
            0, 0, 0, /* 3389: struct.ec_key_st */
            1, 8, 1, /* 3392: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3397, 0,
            0, 32, 2, /* 3397: struct.stack_st_fake_X509_ATTRIBUTE */
            	3404, 8,
            	453, 24,
            8884099, 8, 2, /* 3404: pointer_to_array_of_pointers_to_stack */
            	3411, 0,
            	450, 20,
            0, 8, 1, /* 3411: pointer.X509_ATTRIBUTE */
            	869, 0,
            1, 8, 1, /* 3416: pointer.struct.stack_st_X509_EXTENSION */
            	3421, 0,
            0, 32, 2, /* 3421: struct.stack_st_fake_X509_EXTENSION */
            	3428, 8,
            	453, 24,
            8884099, 8, 2, /* 3428: pointer_to_array_of_pointers_to_stack */
            	3435, 0,
            	450, 20,
            0, 8, 1, /* 3435: pointer.X509_EXTENSION */
            	1248, 0,
            0, 24, 1, /* 3440: struct.ASN1_ENCODING_st */
            	206, 0,
            1, 8, 1, /* 3445: pointer.struct.AUTHORITY_KEYID_st */
            	3450, 0,
            0, 0, 0, /* 3450: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3453: pointer.struct.X509_POLICY_CACHE_st */
            	2841, 0,
            1, 8, 1, /* 3458: pointer.struct.stack_st_DIST_POINT */
            	3463, 0,
            0, 32, 2, /* 3463: struct.stack_st_fake_DIST_POINT */
            	3470, 8,
            	453, 24,
            8884099, 8, 2, /* 3470: pointer_to_array_of_pointers_to_stack */
            	3477, 0,
            	450, 20,
            0, 8, 1, /* 3477: pointer.DIST_POINT */
            	1629, 0,
            1, 8, 1, /* 3482: pointer.struct.stack_st_GENERAL_NAME */
            	3487, 0,
            0, 32, 2, /* 3487: struct.stack_st_fake_GENERAL_NAME */
            	3494, 8,
            	453, 24,
            8884099, 8, 2, /* 3494: pointer_to_array_of_pointers_to_stack */
            	3501, 0,
            	450, 20,
            0, 8, 1, /* 3501: pointer.GENERAL_NAME */
            	1327, 0,
            1, 8, 1, /* 3506: pointer.struct.NAME_CONSTRAINTS_st */
            	3511, 0,
            0, 0, 0, /* 3511: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3514: pointer.struct.x509_cert_aux_st */
            	3519, 0,
            0, 40, 5, /* 3519: struct.x509_cert_aux_st */
            	3532, 0,
            	3532, 8,
            	3150, 16,
            	3100, 24,
            	3556, 32,
            1, 8, 1, /* 3532: pointer.struct.stack_st_ASN1_OBJECT */
            	3537, 0,
            0, 32, 2, /* 3537: struct.stack_st_fake_ASN1_OBJECT */
            	3544, 8,
            	453, 24,
            8884099, 8, 2, /* 3544: pointer_to_array_of_pointers_to_stack */
            	3551, 0,
            	450, 20,
            0, 8, 1, /* 3551: pointer.ASN1_OBJECT */
            	2130, 0,
            1, 8, 1, /* 3556: pointer.struct.stack_st_X509_ALGOR */
            	3561, 0,
            0, 32, 2, /* 3561: struct.stack_st_fake_X509_ALGOR */
            	3568, 8,
            	453, 24,
            8884099, 8, 2, /* 3568: pointer_to_array_of_pointers_to_stack */
            	3575, 0,
            	450, 20,
            0, 8, 1, /* 3575: pointer.X509_ALGOR */
            	2168, 0,
            1, 8, 1, /* 3580: pointer.struct.ssl_cipher_st */
            	2383, 0,
            1, 8, 1, /* 3585: pointer.struct.stack_st_SSL_CIPHER */
            	3590, 0,
            0, 32, 2, /* 3590: struct.stack_st_fake_SSL_CIPHER */
            	3597, 8,
            	453, 24,
            8884099, 8, 2, /* 3597: pointer_to_array_of_pointers_to_stack */
            	3604, 0,
            	450, 20,
            0, 8, 1, /* 3604: pointer.SSL_CIPHER */
            	3609, 0,
            0, 0, 1, /* 3609: SSL_CIPHER */
            	3614, 0,
            0, 88, 1, /* 3614: struct.ssl_cipher_st */
            	10, 8,
            8884097, 8, 0, /* 3619: pointer.func */
            1, 8, 1, /* 3622: pointer.struct.stack_st_X509_LOOKUP */
            	3627, 0,
            0, 32, 2, /* 3627: struct.stack_st_fake_X509_LOOKUP */
            	3634, 8,
            	453, 24,
            8884099, 8, 2, /* 3634: pointer_to_array_of_pointers_to_stack */
            	3641, 0,
            	450, 20,
            0, 8, 1, /* 3641: pointer.X509_LOOKUP */
            	3646, 0,
            0, 0, 1, /* 3646: X509_LOOKUP */
            	3651, 0,
            0, 32, 3, /* 3651: struct.x509_lookup_st */
            	3660, 8,
            	61, 16,
            	3706, 24,
            1, 8, 1, /* 3660: pointer.struct.x509_lookup_method_st */
            	3665, 0,
            0, 80, 10, /* 3665: struct.x509_lookup_method_st */
            	10, 0,
            	3688, 8,
            	2783, 16,
            	3688, 24,
            	3688, 32,
            	3691, 40,
            	3694, 48,
            	3697, 56,
            	3700, 64,
            	3703, 72,
            8884097, 8, 0, /* 3688: pointer.func */
            8884097, 8, 0, /* 3691: pointer.func */
            8884097, 8, 0, /* 3694: pointer.func */
            8884097, 8, 0, /* 3697: pointer.func */
            8884097, 8, 0, /* 3700: pointer.func */
            8884097, 8, 0, /* 3703: pointer.func */
            1, 8, 1, /* 3706: pointer.struct.x509_store_st */
            	3711, 0,
            0, 144, 15, /* 3711: struct.x509_store_st */
            	3744, 8,
            	4607, 16,
            	4631, 24,
            	4643, 32,
            	4646, 40,
            	3619, 48,
            	4649, 56,
            	4643, 64,
            	4652, 72,
            	4655, 80,
            	4658, 88,
            	2410, 96,
            	4661, 104,
            	4643, 112,
            	2388, 120,
            1, 8, 1, /* 3744: pointer.struct.stack_st_X509_OBJECT */
            	3749, 0,
            0, 32, 2, /* 3749: struct.stack_st_fake_X509_OBJECT */
            	3756, 8,
            	453, 24,
            8884099, 8, 2, /* 3756: pointer_to_array_of_pointers_to_stack */
            	3763, 0,
            	450, 20,
            0, 8, 1, /* 3763: pointer.X509_OBJECT */
            	3768, 0,
            0, 0, 1, /* 3768: X509_OBJECT */
            	3773, 0,
            0, 16, 1, /* 3773: struct.x509_object_st */
            	3778, 8,
            0, 8, 4, /* 3778: union.unknown */
            	61, 0,
            	3789, 0,
            	4407, 0,
            	3930, 0,
            1, 8, 1, /* 3789: pointer.struct.x509_st */
            	3794, 0,
            0, 184, 12, /* 3794: struct.x509_st */
            	3821, 0,
            	2623, 8,
            	2717, 16,
            	61, 32,
            	2388, 40,
            	2722, 104,
            	2778, 112,
            	4277, 120,
            	4285, 128,
            	4309, 136,
            	4333, 144,
            	4341, 176,
            1, 8, 1, /* 3821: pointer.struct.x509_cinf_st */
            	3826, 0,
            0, 104, 11, /* 3826: struct.x509_cinf_st */
            	2707, 0,
            	2707, 8,
            	2623, 16,
            	3851, 24,
            	3899, 32,
            	3851, 40,
            	3916, 48,
            	2717, 56,
            	2717, 64,
            	4248, 72,
            	4272, 80,
            1, 8, 1, /* 3851: pointer.struct.X509_name_st */
            	3856, 0,
            0, 40, 3, /* 3856: struct.X509_name_st */
            	3865, 0,
            	3889, 16,
            	206, 24,
            1, 8, 1, /* 3865: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3870, 0,
            0, 32, 2, /* 3870: struct.stack_st_fake_X509_NAME_ENTRY */
            	3877, 8,
            	453, 24,
            8884099, 8, 2, /* 3877: pointer_to_array_of_pointers_to_stack */
            	3884, 0,
            	450, 20,
            0, 8, 1, /* 3884: pointer.X509_NAME_ENTRY */
            	414, 0,
            1, 8, 1, /* 3889: pointer.struct.buf_mem_st */
            	3894, 0,
            0, 24, 1, /* 3894: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 3899: pointer.struct.X509_val_st */
            	3904, 0,
            0, 16, 2, /* 3904: struct.X509_val_st */
            	3911, 0,
            	3911, 8,
            1, 8, 1, /* 3911: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 3916: pointer.struct.X509_pubkey_st */
            	3921, 0,
            0, 24, 3, /* 3921: struct.X509_pubkey_st */
            	2623, 0,
            	2717, 8,
            	3930, 16,
            1, 8, 1, /* 3930: pointer.struct.evp_pkey_st */
            	3935, 0,
            0, 56, 4, /* 3935: struct.evp_pkey_st */
            	3946, 16,
            	3954, 24,
            	3962, 32,
            	4224, 48,
            1, 8, 1, /* 3946: pointer.struct.evp_pkey_asn1_method_st */
            	3951, 0,
            0, 0, 0, /* 3951: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3954: pointer.struct.engine_st */
            	3959, 0,
            0, 0, 0, /* 3959: struct.engine_st */
            0, 8, 5, /* 3962: union.unknown */
            	61, 0,
            	3975, 0,
            	4101, 0,
            	4182, 0,
            	4219, 0,
            1, 8, 1, /* 3975: pointer.struct.rsa_st */
            	3980, 0,
            0, 168, 17, /* 3980: struct.rsa_st */
            	4017, 16,
            	3954, 24,
            	4069, 32,
            	4069, 40,
            	4069, 48,
            	4069, 56,
            	4069, 64,
            	4069, 72,
            	4069, 80,
            	4069, 88,
            	2388, 96,
            	4079, 120,
            	4079, 128,
            	4079, 136,
            	61, 144,
            	4093, 152,
            	4093, 160,
            1, 8, 1, /* 4017: pointer.struct.rsa_meth_st */
            	4022, 0,
            0, 112, 13, /* 4022: struct.rsa_meth_st */
            	10, 0,
            	4051, 8,
            	4051, 16,
            	4051, 24,
            	4051, 32,
            	4054, 40,
            	4057, 48,
            	2620, 56,
            	2620, 64,
            	61, 80,
            	4060, 88,
            	4063, 96,
            	4066, 104,
            8884097, 8, 0, /* 4051: pointer.func */
            8884097, 8, 0, /* 4054: pointer.func */
            8884097, 8, 0, /* 4057: pointer.func */
            8884097, 8, 0, /* 4060: pointer.func */
            8884097, 8, 0, /* 4063: pointer.func */
            8884097, 8, 0, /* 4066: pointer.func */
            1, 8, 1, /* 4069: pointer.struct.bignum_st */
            	4074, 0,
            0, 24, 1, /* 4074: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 4079: pointer.struct.bn_mont_ctx_st */
            	4084, 0,
            0, 96, 3, /* 4084: struct.bn_mont_ctx_st */
            	4074, 8,
            	4074, 32,
            	4074, 56,
            1, 8, 1, /* 4093: pointer.struct.bn_blinding_st */
            	4098, 0,
            0, 0, 0, /* 4098: struct.bn_blinding_st */
            1, 8, 1, /* 4101: pointer.struct.dsa_st */
            	4106, 0,
            0, 136, 11, /* 4106: struct.dsa_st */
            	4069, 24,
            	4069, 32,
            	4069, 40,
            	4069, 48,
            	4069, 56,
            	4069, 64,
            	4069, 72,
            	4079, 88,
            	2388, 104,
            	4131, 120,
            	3954, 128,
            1, 8, 1, /* 4131: pointer.struct.dsa_method */
            	4136, 0,
            0, 96, 11, /* 4136: struct.dsa_method */
            	10, 0,
            	4161, 8,
            	4164, 16,
            	4167, 24,
            	4170, 32,
            	4173, 40,
            	4176, 48,
            	4176, 56,
            	61, 72,
            	4179, 80,
            	4176, 88,
            8884097, 8, 0, /* 4161: pointer.func */
            8884097, 8, 0, /* 4164: pointer.func */
            8884097, 8, 0, /* 4167: pointer.func */
            8884097, 8, 0, /* 4170: pointer.func */
            8884097, 8, 0, /* 4173: pointer.func */
            8884097, 8, 0, /* 4176: pointer.func */
            8884097, 8, 0, /* 4179: pointer.func */
            1, 8, 1, /* 4182: pointer.struct.dh_st */
            	4187, 0,
            0, 144, 12, /* 4187: struct.dh_st */
            	4069, 8,
            	4069, 16,
            	4069, 32,
            	4069, 40,
            	4079, 56,
            	4069, 64,
            	4069, 72,
            	206, 80,
            	4069, 96,
            	2388, 112,
            	4214, 128,
            	3954, 136,
            1, 8, 1, /* 4214: pointer.struct.dh_method */
            	2576, 0,
            1, 8, 1, /* 4219: pointer.struct.ec_key_st */
            	2775, 0,
            1, 8, 1, /* 4224: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4229, 0,
            0, 32, 2, /* 4229: struct.stack_st_fake_X509_ATTRIBUTE */
            	4236, 8,
            	453, 24,
            8884099, 8, 2, /* 4236: pointer_to_array_of_pointers_to_stack */
            	4243, 0,
            	450, 20,
            0, 8, 1, /* 4243: pointer.X509_ATTRIBUTE */
            	869, 0,
            1, 8, 1, /* 4248: pointer.struct.stack_st_X509_EXTENSION */
            	4253, 0,
            0, 32, 2, /* 4253: struct.stack_st_fake_X509_EXTENSION */
            	4260, 8,
            	453, 24,
            8884099, 8, 2, /* 4260: pointer_to_array_of_pointers_to_stack */
            	4267, 0,
            	450, 20,
            0, 8, 1, /* 4267: pointer.X509_EXTENSION */
            	1248, 0,
            0, 24, 1, /* 4272: struct.ASN1_ENCODING_st */
            	206, 0,
            1, 8, 1, /* 4277: pointer.struct.X509_POLICY_CACHE_st */
            	4282, 0,
            0, 0, 0, /* 4282: struct.X509_POLICY_CACHE_st */
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
            	2778, 32,
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
            	3851, 16,
            	3911, 24,
            	3911, 32,
            	4459, 40,
            	4248, 48,
            	4272, 56,
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
            	2844, 0,
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
            	3646, 0,
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
            	3768, 0,
            1, 8, 1, /* 4700: pointer.struct.ssl_method_st */
            	4705, 0,
            0, 232, 28, /* 4705: struct.ssl_method_st */
            	2820, 8,
            	4764, 16,
            	4764, 24,
            	2820, 32,
            	2820, 40,
            	4670, 48,
            	4670, 56,
            	4767, 64,
            	2820, 72,
            	2820, 80,
            	2820, 88,
            	4770, 96,
            	4673, 104,
            	4773, 112,
            	2820, 120,
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
            	2789, 0,
            8884097, 8, 0, /* 4805: pointer.func */
            8884097, 8, 0, /* 4808: pointer.func */
            8884097, 8, 0, /* 4811: pointer.func */
            0, 144, 15, /* 4814: struct.x509_store_st */
            	4676, 8,
            	3622, 16,
            	4847, 24,
            	4859, 32,
            	4862, 40,
            	4865, 48,
            	4868, 56,
            	4859, 64,
            	4871, 72,
            	4874, 80,
            	4877, 88,
            	2786, 96,
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
            0, 32, 2, /* 4896: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4903, 8,
            	453, 24,
            8884099, 8, 2, /* 4903: pointer_to_array_of_pointers_to_stack */
            	4883, 0,
            	450, 20,
            1, 8, 1, /* 4910: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4896, 0,
            0, 8, 0, /* 4915: long int */
            1, 8, 1, /* 4918: pointer.struct.lhash_node_st */
            	4923, 0,
            0, 24, 2, /* 4923: struct.lhash_node_st */
            	49, 0,
            	4930, 8,
            1, 8, 1, /* 4930: pointer.struct.lhash_node_st */
            	4923, 0,
            0, 736, 50, /* 4935: struct.ssl_ctx_st */
            	4700, 0,
            	3585, 8,
            	3585, 16,
            	4888, 24,
            	5038, 32,
            	2856, 48,
            	2856, 56,
            	5057, 80,
            	5060, 88,
            	2380, 96,
            	4664, 152,
            	49, 160,
            	5063, 168,
            	49, 176,
            	5066, 184,
            	5069, 192,
            	2377, 200,
            	639, 208,
            	2185, 224,
            	2185, 232,
            	2185, 240,
            	2910, 248,
            	2353, 256,
            	2256, 264,
            	5072, 272,
            	2251, 304,
            	2416, 320,
            	49, 328,
            	4862, 376,
            	5096, 384,
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
            	5099, 552,
            	5099, 560,
            	18, 568,
            	15, 696,
            	49, 704,
            	2838, 712,
            	49, 720,
            	4910, 728,
            1, 8, 1, /* 5038: pointer.struct.lhash_st */
            	5043, 0,
            0, 176, 3, /* 5043: struct.lhash_st */
            	5052, 0,
            	453, 8,
            	4811, 16,
            1, 8, 1, /* 5052: pointer.pointer.struct.lhash_node_st */
            	4918, 0,
            8884097, 8, 0, /* 5057: pointer.func */
            8884097, 8, 0, /* 5060: pointer.func */
            8884097, 8, 0, /* 5063: pointer.func */
            8884097, 8, 0, /* 5066: pointer.func */
            8884097, 8, 0, /* 5069: pointer.func */
            1, 8, 1, /* 5072: pointer.struct.stack_st_X509_NAME */
            	5077, 0,
            0, 32, 2, /* 5077: struct.stack_st_fake_X509_NAME */
            	5084, 8,
            	453, 24,
            8884099, 8, 2, /* 5084: pointer_to_array_of_pointers_to_stack */
            	5091, 0,
            	450, 20,
            0, 8, 1, /* 5091: pointer.X509_NAME */
            	2259, 0,
            8884097, 8, 0, /* 5096: pointer.func */
            1, 8, 1, /* 5099: pointer.struct.ssl3_buf_freelist_st */
            	5104, 0,
            0, 24, 1, /* 5104: struct.ssl3_buf_freelist_st */
            	84, 16,
            1, 8, 1, /* 5109: pointer.struct.ssl_ctx_st */
            	4935, 0,
        },
        .arg_entity_index = { 5109, 450, 4915, 49, },
        .ret_entity_index = 4915,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    long new_arg_c = *((long *)new_args->args[2]);

    void * new_arg_d = *((void * *)new_args->args[3]);

    long *new_ret_ptr = (long *)new_args->ret;

    long (*orig_SSL_CTX_ctrl)(SSL_CTX *,int,long,void *);
    orig_SSL_CTX_ctrl = dlsym(RTLD_NEXT, "SSL_CTX_ctrl");
    *new_ret_ptr = (*orig_SSL_CTX_ctrl)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

