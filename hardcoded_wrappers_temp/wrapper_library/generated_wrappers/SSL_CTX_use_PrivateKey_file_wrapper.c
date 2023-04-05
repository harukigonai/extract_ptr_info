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

int bb_SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c);

int SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_use_PrivateKey_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_use_PrivateKey_file(arg_a,arg_b,arg_c);
    else {
        int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *,const char *,int);
        orig_SSL_CTX_use_PrivateKey_file = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey_file");
        return orig_SSL_CTX_use_PrivateKey_file(arg_a,arg_b,arg_c);
    }
}

int bb_SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	64096, 0,
            0, 0, 1, /* 10: SRTP_PROTECTION_PROFILE */
            	0, 0,
            0, 8, 1, /* 15: struct.ssl3_buf_freelist_entry_st */
            	20, 0,
            1, 8, 1, /* 20: pointer.struct.ssl3_buf_freelist_entry_st */
            	15, 0,
            0, 24, 1, /* 25: struct.ssl3_buf_freelist_st */
            	20, 16,
            1, 8, 1, /* 30: pointer.struct.ssl3_buf_freelist_st */
            	25, 0,
            64097, 8, 0, /* 35: pointer.func */
            64097, 8, 0, /* 38: pointer.func */
            64097, 8, 0, /* 41: pointer.func */
            64097, 8, 0, /* 44: pointer.func */
            64097, 8, 0, /* 47: pointer.func */
            64097, 8, 0, /* 50: pointer.func */
            64097, 8, 0, /* 53: pointer.func */
            0, 296, 7, /* 56: struct.cert_st */
            	73, 0,
            	2006, 48,
            	53, 56,
            	2011, 64,
            	50, 72,
            	2016, 80,
            	47, 88,
            1, 8, 1, /* 73: pointer.struct.cert_pkey_st */
            	78, 0,
            0, 24, 3, /* 78: struct.cert_pkey_st */
            	87, 0,
            	455, 8,
            	1961, 16,
            1, 8, 1, /* 87: pointer.struct.x509_st */
            	92, 0,
            0, 184, 12, /* 92: struct.x509_st */
            	119, 0,
            	167, 8,
            	266, 16,
            	251, 32,
            	615, 40,
            	271, 104,
            	1265, 112,
            	1273, 120,
            	1281, 128,
            	1690, 136,
            	1714, 144,
            	1722, 176,
            1, 8, 1, /* 119: pointer.struct.x509_cinf_st */
            	124, 0,
            0, 104, 11, /* 124: struct.x509_cinf_st */
            	149, 0,
            	149, 8,
            	167, 16,
            	334, 24,
            	424, 32,
            	334, 40,
            	441, 48,
            	266, 56,
            	266, 64,
            	1200, 72,
            	1260, 80,
            1, 8, 1, /* 149: pointer.struct.asn1_string_st */
            	154, 0,
            0, 24, 1, /* 154: struct.asn1_string_st */
            	159, 8,
            1, 8, 1, /* 159: pointer.unsigned char */
            	164, 0,
            0, 1, 0, /* 164: unsigned char */
            1, 8, 1, /* 167: pointer.struct.X509_algor_st */
            	172, 0,
            0, 16, 2, /* 172: struct.X509_algor_st */
            	179, 0,
            	198, 8,
            1, 8, 1, /* 179: pointer.struct.asn1_object_st */
            	184, 0,
            0, 40, 3, /* 184: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	193, 24,
            1, 8, 1, /* 193: pointer.unsigned char */
            	164, 0,
            1, 8, 1, /* 198: pointer.struct.asn1_type_st */
            	203, 0,
            0, 16, 1, /* 203: struct.asn1_type_st */
            	208, 8,
            0, 8, 20, /* 208: union.unknown */
            	251, 0,
            	256, 0,
            	179, 0,
            	149, 0,
            	261, 0,
            	266, 0,
            	271, 0,
            	276, 0,
            	281, 0,
            	286, 0,
            	291, 0,
            	296, 0,
            	301, 0,
            	306, 0,
            	311, 0,
            	316, 0,
            	321, 0,
            	256, 0,
            	256, 0,
            	326, 0,
            1, 8, 1, /* 251: pointer.char */
            	64096, 0,
            1, 8, 1, /* 256: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 261: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 266: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 271: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 276: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 281: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 286: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 291: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 296: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 301: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 306: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 311: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 316: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 321: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 326: pointer.struct.ASN1_VALUE_st */
            	331, 0,
            0, 0, 0, /* 331: struct.ASN1_VALUE_st */
            1, 8, 1, /* 334: pointer.struct.X509_name_st */
            	339, 0,
            0, 40, 3, /* 339: struct.X509_name_st */
            	348, 0,
            	414, 16,
            	159, 24,
            1, 8, 1, /* 348: pointer.struct.stack_st_X509_NAME_ENTRY */
            	353, 0,
            0, 32, 2, /* 353: struct.stack_st_fake_X509_NAME_ENTRY */
            	360, 8,
            	411, 24,
            64099, 8, 2, /* 360: pointer_to_array_of_pointers_to_stack */
            	367, 0,
            	408, 20,
            0, 8, 1, /* 367: pointer.X509_NAME_ENTRY */
            	372, 0,
            0, 0, 1, /* 372: X509_NAME_ENTRY */
            	377, 0,
            0, 24, 2, /* 377: struct.X509_name_entry_st */
            	384, 0,
            	398, 8,
            1, 8, 1, /* 384: pointer.struct.asn1_object_st */
            	389, 0,
            0, 40, 3, /* 389: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	193, 24,
            1, 8, 1, /* 398: pointer.struct.asn1_string_st */
            	403, 0,
            0, 24, 1, /* 403: struct.asn1_string_st */
            	159, 8,
            0, 4, 0, /* 408: int */
            64097, 8, 0, /* 411: pointer.func */
            1, 8, 1, /* 414: pointer.struct.buf_mem_st */
            	419, 0,
            0, 24, 1, /* 419: struct.buf_mem_st */
            	251, 8,
            1, 8, 1, /* 424: pointer.struct.X509_val_st */
            	429, 0,
            0, 16, 2, /* 429: struct.X509_val_st */
            	436, 0,
            	436, 8,
            1, 8, 1, /* 436: pointer.struct.asn1_string_st */
            	154, 0,
            1, 8, 1, /* 441: pointer.struct.X509_pubkey_st */
            	446, 0,
            0, 24, 3, /* 446: struct.X509_pubkey_st */
            	167, 0,
            	266, 8,
            	455, 16,
            1, 8, 1, /* 455: pointer.struct.evp_pkey_st */
            	460, 0,
            0, 56, 4, /* 460: struct.evp_pkey_st */
            	471, 16,
            	479, 24,
            	487, 32,
            	821, 48,
            1, 8, 1, /* 471: pointer.struct.evp_pkey_asn1_method_st */
            	476, 0,
            0, 0, 0, /* 476: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 479: pointer.struct.engine_st */
            	484, 0,
            0, 0, 0, /* 484: struct.engine_st */
            0, 8, 5, /* 487: union.unknown */
            	251, 0,
            	500, 0,
            	664, 0,
            	745, 0,
            	813, 0,
            1, 8, 1, /* 500: pointer.struct.rsa_st */
            	505, 0,
            0, 168, 17, /* 505: struct.rsa_st */
            	542, 16,
            	479, 24,
            	597, 32,
            	597, 40,
            	597, 48,
            	597, 56,
            	597, 64,
            	597, 72,
            	597, 80,
            	597, 88,
            	615, 96,
            	642, 120,
            	642, 128,
            	642, 136,
            	251, 144,
            	656, 152,
            	656, 160,
            1, 8, 1, /* 542: pointer.struct.rsa_meth_st */
            	547, 0,
            0, 112, 13, /* 547: struct.rsa_meth_st */
            	5, 0,
            	576, 8,
            	576, 16,
            	576, 24,
            	576, 32,
            	579, 40,
            	582, 48,
            	585, 56,
            	585, 64,
            	251, 80,
            	588, 88,
            	591, 96,
            	594, 104,
            64097, 8, 0, /* 576: pointer.func */
            64097, 8, 0, /* 579: pointer.func */
            64097, 8, 0, /* 582: pointer.func */
            64097, 8, 0, /* 585: pointer.func */
            64097, 8, 0, /* 588: pointer.func */
            64097, 8, 0, /* 591: pointer.func */
            64097, 8, 0, /* 594: pointer.func */
            1, 8, 1, /* 597: pointer.struct.bignum_st */
            	602, 0,
            0, 24, 1, /* 602: struct.bignum_st */
            	607, 0,
            1, 8, 1, /* 607: pointer.unsigned int */
            	612, 0,
            0, 4, 0, /* 612: unsigned int */
            0, 16, 1, /* 615: struct.crypto_ex_data_st */
            	620, 0,
            1, 8, 1, /* 620: pointer.struct.stack_st_void */
            	625, 0,
            0, 32, 1, /* 625: struct.stack_st_void */
            	630, 0,
            0, 32, 2, /* 630: struct.stack_st */
            	637, 8,
            	411, 24,
            1, 8, 1, /* 637: pointer.pointer.char */
            	251, 0,
            1, 8, 1, /* 642: pointer.struct.bn_mont_ctx_st */
            	647, 0,
            0, 96, 3, /* 647: struct.bn_mont_ctx_st */
            	602, 8,
            	602, 32,
            	602, 56,
            1, 8, 1, /* 656: pointer.struct.bn_blinding_st */
            	661, 0,
            0, 0, 0, /* 661: struct.bn_blinding_st */
            1, 8, 1, /* 664: pointer.struct.dsa_st */
            	669, 0,
            0, 136, 11, /* 669: struct.dsa_st */
            	597, 24,
            	597, 32,
            	597, 40,
            	597, 48,
            	597, 56,
            	597, 64,
            	597, 72,
            	642, 88,
            	615, 104,
            	694, 120,
            	479, 128,
            1, 8, 1, /* 694: pointer.struct.dsa_method */
            	699, 0,
            0, 96, 11, /* 699: struct.dsa_method */
            	5, 0,
            	724, 8,
            	727, 16,
            	730, 24,
            	733, 32,
            	736, 40,
            	739, 48,
            	739, 56,
            	251, 72,
            	742, 80,
            	739, 88,
            64097, 8, 0, /* 724: pointer.func */
            64097, 8, 0, /* 727: pointer.func */
            64097, 8, 0, /* 730: pointer.func */
            64097, 8, 0, /* 733: pointer.func */
            64097, 8, 0, /* 736: pointer.func */
            64097, 8, 0, /* 739: pointer.func */
            64097, 8, 0, /* 742: pointer.func */
            1, 8, 1, /* 745: pointer.struct.dh_st */
            	750, 0,
            0, 144, 12, /* 750: struct.dh_st */
            	597, 8,
            	597, 16,
            	597, 32,
            	597, 40,
            	642, 56,
            	597, 64,
            	597, 72,
            	159, 80,
            	597, 96,
            	615, 112,
            	777, 128,
            	479, 136,
            1, 8, 1, /* 777: pointer.struct.dh_method */
            	782, 0,
            0, 72, 8, /* 782: struct.dh_method */
            	5, 0,
            	801, 8,
            	804, 16,
            	807, 24,
            	801, 32,
            	801, 40,
            	251, 56,
            	810, 64,
            64097, 8, 0, /* 801: pointer.func */
            64097, 8, 0, /* 804: pointer.func */
            64097, 8, 0, /* 807: pointer.func */
            64097, 8, 0, /* 810: pointer.func */
            1, 8, 1, /* 813: pointer.struct.ec_key_st */
            	818, 0,
            0, 0, 0, /* 818: struct.ec_key_st */
            1, 8, 1, /* 821: pointer.struct.stack_st_X509_ATTRIBUTE */
            	826, 0,
            0, 32, 2, /* 826: struct.stack_st_fake_X509_ATTRIBUTE */
            	833, 8,
            	411, 24,
            64099, 8, 2, /* 833: pointer_to_array_of_pointers_to_stack */
            	840, 0,
            	408, 20,
            0, 8, 1, /* 840: pointer.X509_ATTRIBUTE */
            	845, 0,
            0, 0, 1, /* 845: X509_ATTRIBUTE */
            	850, 0,
            0, 24, 2, /* 850: struct.x509_attributes_st */
            	857, 0,
            	871, 16,
            1, 8, 1, /* 857: pointer.struct.asn1_object_st */
            	862, 0,
            0, 40, 3, /* 862: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	193, 24,
            0, 8, 3, /* 871: union.unknown */
            	251, 0,
            	880, 0,
            	1059, 0,
            1, 8, 1, /* 880: pointer.struct.stack_st_ASN1_TYPE */
            	885, 0,
            0, 32, 2, /* 885: struct.stack_st_fake_ASN1_TYPE */
            	892, 8,
            	411, 24,
            64099, 8, 2, /* 892: pointer_to_array_of_pointers_to_stack */
            	899, 0,
            	408, 20,
            0, 8, 1, /* 899: pointer.ASN1_TYPE */
            	904, 0,
            0, 0, 1, /* 904: ASN1_TYPE */
            	909, 0,
            0, 16, 1, /* 909: struct.asn1_type_st */
            	914, 8,
            0, 8, 20, /* 914: union.unknown */
            	251, 0,
            	957, 0,
            	967, 0,
            	981, 0,
            	986, 0,
            	991, 0,
            	996, 0,
            	1001, 0,
            	1006, 0,
            	1011, 0,
            	1016, 0,
            	1021, 0,
            	1026, 0,
            	1031, 0,
            	1036, 0,
            	1041, 0,
            	1046, 0,
            	957, 0,
            	957, 0,
            	1051, 0,
            1, 8, 1, /* 957: pointer.struct.asn1_string_st */
            	962, 0,
            0, 24, 1, /* 962: struct.asn1_string_st */
            	159, 8,
            1, 8, 1, /* 967: pointer.struct.asn1_object_st */
            	972, 0,
            0, 40, 3, /* 972: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	193, 24,
            1, 8, 1, /* 981: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 986: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 991: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 996: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1001: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1006: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1011: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1016: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1021: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1026: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1031: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1036: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1041: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1046: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1051: pointer.struct.ASN1_VALUE_st */
            	1056, 0,
            0, 0, 0, /* 1056: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1059: pointer.struct.asn1_type_st */
            	1064, 0,
            0, 16, 1, /* 1064: struct.asn1_type_st */
            	1069, 8,
            0, 8, 20, /* 1069: union.unknown */
            	251, 0,
            	1112, 0,
            	857, 0,
            	1122, 0,
            	1127, 0,
            	1132, 0,
            	1137, 0,
            	1142, 0,
            	1147, 0,
            	1152, 0,
            	1157, 0,
            	1162, 0,
            	1167, 0,
            	1172, 0,
            	1177, 0,
            	1182, 0,
            	1187, 0,
            	1112, 0,
            	1112, 0,
            	1192, 0,
            1, 8, 1, /* 1112: pointer.struct.asn1_string_st */
            	1117, 0,
            0, 24, 1, /* 1117: struct.asn1_string_st */
            	159, 8,
            1, 8, 1, /* 1122: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1127: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1132: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1137: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1142: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1147: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1152: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1157: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1162: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1167: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1172: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1177: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1182: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1187: pointer.struct.asn1_string_st */
            	1117, 0,
            1, 8, 1, /* 1192: pointer.struct.ASN1_VALUE_st */
            	1197, 0,
            0, 0, 0, /* 1197: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1200: pointer.struct.stack_st_X509_EXTENSION */
            	1205, 0,
            0, 32, 2, /* 1205: struct.stack_st_fake_X509_EXTENSION */
            	1212, 8,
            	411, 24,
            64099, 8, 2, /* 1212: pointer_to_array_of_pointers_to_stack */
            	1219, 0,
            	408, 20,
            0, 8, 1, /* 1219: pointer.X509_EXTENSION */
            	1224, 0,
            0, 0, 1, /* 1224: X509_EXTENSION */
            	1229, 0,
            0, 24, 2, /* 1229: struct.X509_extension_st */
            	1236, 0,
            	1250, 16,
            1, 8, 1, /* 1236: pointer.struct.asn1_object_st */
            	1241, 0,
            0, 40, 3, /* 1241: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	193, 24,
            1, 8, 1, /* 1250: pointer.struct.asn1_string_st */
            	1255, 0,
            0, 24, 1, /* 1255: struct.asn1_string_st */
            	159, 8,
            0, 24, 1, /* 1260: struct.ASN1_ENCODING_st */
            	159, 0,
            1, 8, 1, /* 1265: pointer.struct.AUTHORITY_KEYID_st */
            	1270, 0,
            0, 0, 0, /* 1270: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1273: pointer.struct.X509_POLICY_CACHE_st */
            	1278, 0,
            0, 0, 0, /* 1278: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1281: pointer.struct.stack_st_DIST_POINT */
            	1286, 0,
            0, 32, 2, /* 1286: struct.stack_st_fake_DIST_POINT */
            	1293, 8,
            	411, 24,
            64099, 8, 2, /* 1293: pointer_to_array_of_pointers_to_stack */
            	1300, 0,
            	408, 20,
            0, 8, 1, /* 1300: pointer.DIST_POINT */
            	1305, 0,
            0, 0, 1, /* 1305: DIST_POINT */
            	1310, 0,
            0, 32, 3, /* 1310: struct.DIST_POINT_st */
            	1319, 0,
            	1680, 8,
            	1338, 16,
            1, 8, 1, /* 1319: pointer.struct.DIST_POINT_NAME_st */
            	1324, 0,
            0, 24, 2, /* 1324: struct.DIST_POINT_NAME_st */
            	1331, 8,
            	1656, 16,
            0, 8, 2, /* 1331: union.unknown */
            	1338, 0,
            	1632, 0,
            1, 8, 1, /* 1338: pointer.struct.stack_st_GENERAL_NAME */
            	1343, 0,
            0, 32, 2, /* 1343: struct.stack_st_fake_GENERAL_NAME */
            	1350, 8,
            	411, 24,
            64099, 8, 2, /* 1350: pointer_to_array_of_pointers_to_stack */
            	1357, 0,
            	408, 20,
            0, 8, 1, /* 1357: pointer.GENERAL_NAME */
            	1362, 0,
            0, 0, 1, /* 1362: GENERAL_NAME */
            	1367, 0,
            0, 16, 1, /* 1367: struct.GENERAL_NAME_st */
            	1372, 8,
            0, 8, 15, /* 1372: union.unknown */
            	251, 0,
            	1405, 0,
            	1524, 0,
            	1524, 0,
            	1431, 0,
            	1572, 0,
            	1620, 0,
            	1524, 0,
            	1509, 0,
            	1417, 0,
            	1509, 0,
            	1572, 0,
            	1524, 0,
            	1417, 0,
            	1431, 0,
            1, 8, 1, /* 1405: pointer.struct.otherName_st */
            	1410, 0,
            0, 16, 2, /* 1410: struct.otherName_st */
            	1417, 0,
            	1431, 8,
            1, 8, 1, /* 1417: pointer.struct.asn1_object_st */
            	1422, 0,
            0, 40, 3, /* 1422: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	193, 24,
            1, 8, 1, /* 1431: pointer.struct.asn1_type_st */
            	1436, 0,
            0, 16, 1, /* 1436: struct.asn1_type_st */
            	1441, 8,
            0, 8, 20, /* 1441: union.unknown */
            	251, 0,
            	1484, 0,
            	1417, 0,
            	1494, 0,
            	1499, 0,
            	1504, 0,
            	1509, 0,
            	1514, 0,
            	1519, 0,
            	1524, 0,
            	1529, 0,
            	1534, 0,
            	1539, 0,
            	1544, 0,
            	1549, 0,
            	1554, 0,
            	1559, 0,
            	1484, 0,
            	1484, 0,
            	1564, 0,
            1, 8, 1, /* 1484: pointer.struct.asn1_string_st */
            	1489, 0,
            0, 24, 1, /* 1489: struct.asn1_string_st */
            	159, 8,
            1, 8, 1, /* 1494: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1499: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1504: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1509: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1514: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1519: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1524: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1529: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1534: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1539: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1544: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1549: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1554: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1559: pointer.struct.asn1_string_st */
            	1489, 0,
            1, 8, 1, /* 1564: pointer.struct.ASN1_VALUE_st */
            	1569, 0,
            0, 0, 0, /* 1569: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1572: pointer.struct.X509_name_st */
            	1577, 0,
            0, 40, 3, /* 1577: struct.X509_name_st */
            	1586, 0,
            	1610, 16,
            	159, 24,
            1, 8, 1, /* 1586: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1591, 0,
            0, 32, 2, /* 1591: struct.stack_st_fake_X509_NAME_ENTRY */
            	1598, 8,
            	411, 24,
            64099, 8, 2, /* 1598: pointer_to_array_of_pointers_to_stack */
            	1605, 0,
            	408, 20,
            0, 8, 1, /* 1605: pointer.X509_NAME_ENTRY */
            	372, 0,
            1, 8, 1, /* 1610: pointer.struct.buf_mem_st */
            	1615, 0,
            0, 24, 1, /* 1615: struct.buf_mem_st */
            	251, 8,
            1, 8, 1, /* 1620: pointer.struct.EDIPartyName_st */
            	1625, 0,
            0, 16, 2, /* 1625: struct.EDIPartyName_st */
            	1484, 0,
            	1484, 8,
            1, 8, 1, /* 1632: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1637, 0,
            0, 32, 2, /* 1637: struct.stack_st_fake_X509_NAME_ENTRY */
            	1644, 8,
            	411, 24,
            64099, 8, 2, /* 1644: pointer_to_array_of_pointers_to_stack */
            	1651, 0,
            	408, 20,
            0, 8, 1, /* 1651: pointer.X509_NAME_ENTRY */
            	372, 0,
            1, 8, 1, /* 1656: pointer.struct.X509_name_st */
            	1661, 0,
            0, 40, 3, /* 1661: struct.X509_name_st */
            	1632, 0,
            	1670, 16,
            	159, 24,
            1, 8, 1, /* 1670: pointer.struct.buf_mem_st */
            	1675, 0,
            0, 24, 1, /* 1675: struct.buf_mem_st */
            	251, 8,
            1, 8, 1, /* 1680: pointer.struct.asn1_string_st */
            	1685, 0,
            0, 24, 1, /* 1685: struct.asn1_string_st */
            	159, 8,
            1, 8, 1, /* 1690: pointer.struct.stack_st_GENERAL_NAME */
            	1695, 0,
            0, 32, 2, /* 1695: struct.stack_st_fake_GENERAL_NAME */
            	1702, 8,
            	411, 24,
            64099, 8, 2, /* 1702: pointer_to_array_of_pointers_to_stack */
            	1709, 0,
            	408, 20,
            0, 8, 1, /* 1709: pointer.GENERAL_NAME */
            	1362, 0,
            1, 8, 1, /* 1714: pointer.struct.NAME_CONSTRAINTS_st */
            	1719, 0,
            0, 0, 0, /* 1719: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 1722: pointer.struct.x509_cert_aux_st */
            	1727, 0,
            0, 40, 5, /* 1727: struct.x509_cert_aux_st */
            	1740, 0,
            	1740, 8,
            	321, 16,
            	271, 24,
            	1778, 32,
            1, 8, 1, /* 1740: pointer.struct.stack_st_ASN1_OBJECT */
            	1745, 0,
            0, 32, 2, /* 1745: struct.stack_st_fake_ASN1_OBJECT */
            	1752, 8,
            	411, 24,
            64099, 8, 2, /* 1752: pointer_to_array_of_pointers_to_stack */
            	1759, 0,
            	408, 20,
            0, 8, 1, /* 1759: pointer.ASN1_OBJECT */
            	1764, 0,
            0, 0, 1, /* 1764: ASN1_OBJECT */
            	1769, 0,
            0, 40, 3, /* 1769: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	193, 24,
            1, 8, 1, /* 1778: pointer.struct.stack_st_X509_ALGOR */
            	1783, 0,
            0, 32, 2, /* 1783: struct.stack_st_fake_X509_ALGOR */
            	1790, 8,
            	411, 24,
            64099, 8, 2, /* 1790: pointer_to_array_of_pointers_to_stack */
            	1797, 0,
            	408, 20,
            0, 8, 1, /* 1797: pointer.X509_ALGOR */
            	1802, 0,
            0, 0, 1, /* 1802: X509_ALGOR */
            	1807, 0,
            0, 16, 2, /* 1807: struct.X509_algor_st */
            	1814, 0,
            	1828, 8,
            1, 8, 1, /* 1814: pointer.struct.asn1_object_st */
            	1819, 0,
            0, 40, 3, /* 1819: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	193, 24,
            1, 8, 1, /* 1828: pointer.struct.asn1_type_st */
            	1833, 0,
            0, 16, 1, /* 1833: struct.asn1_type_st */
            	1838, 8,
            0, 8, 20, /* 1838: union.unknown */
            	251, 0,
            	1881, 0,
            	1814, 0,
            	1891, 0,
            	1896, 0,
            	1901, 0,
            	1906, 0,
            	1911, 0,
            	1916, 0,
            	1921, 0,
            	1926, 0,
            	1931, 0,
            	1936, 0,
            	1941, 0,
            	1946, 0,
            	1951, 0,
            	1956, 0,
            	1881, 0,
            	1881, 0,
            	1192, 0,
            1, 8, 1, /* 1881: pointer.struct.asn1_string_st */
            	1886, 0,
            0, 24, 1, /* 1886: struct.asn1_string_st */
            	159, 8,
            1, 8, 1, /* 1891: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1896: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1901: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1906: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1911: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1916: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1921: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1926: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1931: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1936: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1941: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1946: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1951: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1956: pointer.struct.asn1_string_st */
            	1886, 0,
            1, 8, 1, /* 1961: pointer.struct.env_md_st */
            	1966, 0,
            0, 120, 8, /* 1966: struct.env_md_st */
            	1985, 24,
            	1988, 32,
            	1991, 40,
            	1994, 48,
            	1985, 56,
            	1997, 64,
            	2000, 72,
            	2003, 112,
            64097, 8, 0, /* 1985: pointer.func */
            64097, 8, 0, /* 1988: pointer.func */
            64097, 8, 0, /* 1991: pointer.func */
            64097, 8, 0, /* 1994: pointer.func */
            64097, 8, 0, /* 1997: pointer.func */
            64097, 8, 0, /* 2000: pointer.func */
            64097, 8, 0, /* 2003: pointer.func */
            1, 8, 1, /* 2006: pointer.struct.rsa_st */
            	505, 0,
            1, 8, 1, /* 2011: pointer.struct.dh_st */
            	750, 0,
            1, 8, 1, /* 2016: pointer.struct.ec_key_st */
            	818, 0,
            0, 24, 1, /* 2021: struct.buf_mem_st */
            	251, 8,
            0, 40, 3, /* 2026: struct.X509_name_st */
            	2035, 0,
            	2059, 16,
            	159, 24,
            1, 8, 1, /* 2035: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2040, 0,
            0, 32, 2, /* 2040: struct.stack_st_fake_X509_NAME_ENTRY */
            	2047, 8,
            	411, 24,
            64099, 8, 2, /* 2047: pointer_to_array_of_pointers_to_stack */
            	2054, 0,
            	408, 20,
            0, 8, 1, /* 2054: pointer.X509_NAME_ENTRY */
            	372, 0,
            1, 8, 1, /* 2059: pointer.struct.buf_mem_st */
            	2021, 0,
            64097, 8, 0, /* 2064: pointer.func */
            64097, 8, 0, /* 2067: pointer.func */
            64097, 8, 0, /* 2070: pointer.func */
            0, 24, 2, /* 2073: struct.ssl_comp_st */
            	5, 8,
            	2080, 16,
            1, 8, 1, /* 2080: pointer.struct.comp_method_st */
            	2085, 0,
            0, 64, 7, /* 2085: struct.comp_method_st */
            	5, 8,
            	2070, 16,
            	2102, 24,
            	2067, 32,
            	2067, 40,
            	2105, 48,
            	2105, 56,
            64097, 8, 0, /* 2102: pointer.func */
            64097, 8, 0, /* 2105: pointer.func */
            1, 8, 1, /* 2108: pointer.struct.stack_st_SSL_COMP */
            	2113, 0,
            0, 32, 2, /* 2113: struct.stack_st_fake_SSL_COMP */
            	2120, 8,
            	411, 24,
            64099, 8, 2, /* 2120: pointer_to_array_of_pointers_to_stack */
            	2127, 0,
            	408, 20,
            0, 8, 1, /* 2127: pointer.SSL_COMP */
            	2132, 0,
            0, 0, 1, /* 2132: SSL_COMP */
            	2073, 0,
            64097, 8, 0, /* 2137: pointer.func */
            64097, 8, 0, /* 2140: pointer.func */
            64097, 8, 0, /* 2143: pointer.func */
            64097, 8, 0, /* 2146: pointer.func */
            64097, 8, 0, /* 2149: pointer.func */
            64097, 8, 0, /* 2152: pointer.func */
            64097, 8, 0, /* 2155: pointer.func */
            1, 8, 1, /* 2158: pointer.struct.ssl_cipher_st */
            	2163, 0,
            0, 88, 1, /* 2163: struct.ssl_cipher_st */
            	5, 8,
            0, 16, 1, /* 2168: struct.crypto_ex_data_st */
            	2173, 0,
            1, 8, 1, /* 2173: pointer.struct.stack_st_void */
            	2178, 0,
            0, 32, 1, /* 2178: struct.stack_st_void */
            	2183, 0,
            0, 32, 2, /* 2183: struct.stack_st */
            	637, 8,
            	411, 24,
            64097, 8, 0, /* 2190: pointer.func */
            0, 136, 11, /* 2193: struct.dsa_st */
            	2218, 24,
            	2218, 32,
            	2218, 40,
            	2218, 48,
            	2218, 56,
            	2218, 64,
            	2218, 72,
            	2228, 88,
            	2168, 104,
            	2242, 120,
            	2293, 128,
            1, 8, 1, /* 2218: pointer.struct.bignum_st */
            	2223, 0,
            0, 24, 1, /* 2223: struct.bignum_st */
            	607, 0,
            1, 8, 1, /* 2228: pointer.struct.bn_mont_ctx_st */
            	2233, 0,
            0, 96, 3, /* 2233: struct.bn_mont_ctx_st */
            	2223, 8,
            	2223, 32,
            	2223, 56,
            1, 8, 1, /* 2242: pointer.struct.dsa_method */
            	2247, 0,
            0, 96, 11, /* 2247: struct.dsa_method */
            	5, 0,
            	2272, 8,
            	2275, 16,
            	2278, 24,
            	2281, 32,
            	2284, 40,
            	2287, 48,
            	2287, 56,
            	251, 72,
            	2290, 80,
            	2287, 88,
            64097, 8, 0, /* 2272: pointer.func */
            64097, 8, 0, /* 2275: pointer.func */
            64097, 8, 0, /* 2278: pointer.func */
            64097, 8, 0, /* 2281: pointer.func */
            64097, 8, 0, /* 2284: pointer.func */
            64097, 8, 0, /* 2287: pointer.func */
            64097, 8, 0, /* 2290: pointer.func */
            1, 8, 1, /* 2293: pointer.struct.engine_st */
            	2298, 0,
            0, 0, 0, /* 2298: struct.engine_st */
            64097, 8, 0, /* 2301: pointer.func */
            64097, 8, 0, /* 2304: pointer.func */
            1, 8, 1, /* 2307: pointer.struct.X509_algor_st */
            	2312, 0,
            0, 16, 2, /* 2312: struct.X509_algor_st */
            	2319, 0,
            	2333, 8,
            1, 8, 1, /* 2319: pointer.struct.asn1_object_st */
            	2324, 0,
            0, 40, 3, /* 2324: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	193, 24,
            1, 8, 1, /* 2333: pointer.struct.asn1_type_st */
            	2338, 0,
            0, 16, 1, /* 2338: struct.asn1_type_st */
            	2343, 8,
            0, 8, 20, /* 2343: union.unknown */
            	251, 0,
            	2386, 0,
            	2319, 0,
            	2396, 0,
            	2401, 0,
            	2406, 0,
            	2411, 0,
            	2416, 0,
            	2421, 0,
            	2426, 0,
            	2431, 0,
            	2436, 0,
            	2441, 0,
            	2446, 0,
            	2451, 0,
            	2456, 0,
            	2461, 0,
            	2386, 0,
            	2386, 0,
            	1192, 0,
            1, 8, 1, /* 2386: pointer.struct.asn1_string_st */
            	2391, 0,
            0, 24, 1, /* 2391: struct.asn1_string_st */
            	159, 8,
            1, 8, 1, /* 2396: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2401: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2406: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2411: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2416: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2421: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2426: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2431: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2436: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2441: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2446: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2451: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2456: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2461: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 2466: pointer.struct.stack_st_DIST_POINT */
            	2471, 0,
            0, 32, 2, /* 2471: struct.stack_st_fake_DIST_POINT */
            	2478, 8,
            	411, 24,
            64099, 8, 2, /* 2478: pointer_to_array_of_pointers_to_stack */
            	2485, 0,
            	408, 20,
            0, 8, 1, /* 2485: pointer.DIST_POINT */
            	1305, 0,
            1, 8, 1, /* 2490: pointer.struct.X509_POLICY_CACHE_st */
            	2495, 0,
            0, 0, 0, /* 2495: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2498: struct.ec_key_st */
            1, 8, 1, /* 2501: pointer.struct.AUTHORITY_KEYID_st */
            	2506, 0,
            0, 0, 0, /* 2506: struct.AUTHORITY_KEYID_st */
            64097, 8, 0, /* 2509: pointer.func */
            64097, 8, 0, /* 2512: pointer.func */
            1, 8, 1, /* 2515: pointer.struct.X509_pubkey_st */
            	2520, 0,
            0, 24, 3, /* 2520: struct.X509_pubkey_st */
            	2529, 0,
            	2628, 8,
            	2696, 16,
            1, 8, 1, /* 2529: pointer.struct.X509_algor_st */
            	2534, 0,
            0, 16, 2, /* 2534: struct.X509_algor_st */
            	2541, 0,
            	2555, 8,
            1, 8, 1, /* 2541: pointer.struct.asn1_object_st */
            	2546, 0,
            0, 40, 3, /* 2546: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	193, 24,
            1, 8, 1, /* 2555: pointer.struct.asn1_type_st */
            	2560, 0,
            0, 16, 1, /* 2560: struct.asn1_type_st */
            	2565, 8,
            0, 8, 20, /* 2565: union.unknown */
            	251, 0,
            	2608, 0,
            	2541, 0,
            	2618, 0,
            	2623, 0,
            	2628, 0,
            	2633, 0,
            	2638, 0,
            	2643, 0,
            	2648, 0,
            	2653, 0,
            	2658, 0,
            	2663, 0,
            	2668, 0,
            	2673, 0,
            	2678, 0,
            	2683, 0,
            	2608, 0,
            	2608, 0,
            	2688, 0,
            1, 8, 1, /* 2608: pointer.struct.asn1_string_st */
            	2613, 0,
            0, 24, 1, /* 2613: struct.asn1_string_st */
            	159, 8,
            1, 8, 1, /* 2618: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2623: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2628: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2633: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2638: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2643: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2648: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2653: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2658: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2663: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2668: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2673: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2678: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2683: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 2688: pointer.struct.ASN1_VALUE_st */
            	2693, 0,
            0, 0, 0, /* 2693: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2696: pointer.struct.evp_pkey_st */
            	2701, 0,
            0, 56, 4, /* 2701: struct.evp_pkey_st */
            	2712, 16,
            	2720, 24,
            	2728, 32,
            	3046, 48,
            1, 8, 1, /* 2712: pointer.struct.evp_pkey_asn1_method_st */
            	2717, 0,
            0, 0, 0, /* 2717: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2720: pointer.struct.engine_st */
            	2725, 0,
            0, 0, 0, /* 2725: struct.engine_st */
            0, 8, 5, /* 2728: union.unknown */
            	251, 0,
            	2741, 0,
            	2892, 0,
            	2970, 0,
            	3038, 0,
            1, 8, 1, /* 2741: pointer.struct.rsa_st */
            	2746, 0,
            0, 168, 17, /* 2746: struct.rsa_st */
            	2783, 16,
            	2720, 24,
            	2838, 32,
            	2838, 40,
            	2838, 48,
            	2838, 56,
            	2838, 64,
            	2838, 72,
            	2838, 80,
            	2838, 88,
            	2848, 96,
            	2870, 120,
            	2870, 128,
            	2870, 136,
            	251, 144,
            	2884, 152,
            	2884, 160,
            1, 8, 1, /* 2783: pointer.struct.rsa_meth_st */
            	2788, 0,
            0, 112, 13, /* 2788: struct.rsa_meth_st */
            	5, 0,
            	2817, 8,
            	2817, 16,
            	2817, 24,
            	2817, 32,
            	2820, 40,
            	2823, 48,
            	2826, 56,
            	2826, 64,
            	251, 80,
            	2829, 88,
            	2832, 96,
            	2835, 104,
            64097, 8, 0, /* 2817: pointer.func */
            64097, 8, 0, /* 2820: pointer.func */
            64097, 8, 0, /* 2823: pointer.func */
            64097, 8, 0, /* 2826: pointer.func */
            64097, 8, 0, /* 2829: pointer.func */
            64097, 8, 0, /* 2832: pointer.func */
            64097, 8, 0, /* 2835: pointer.func */
            1, 8, 1, /* 2838: pointer.struct.bignum_st */
            	2843, 0,
            0, 24, 1, /* 2843: struct.bignum_st */
            	607, 0,
            0, 16, 1, /* 2848: struct.crypto_ex_data_st */
            	2853, 0,
            1, 8, 1, /* 2853: pointer.struct.stack_st_void */
            	2858, 0,
            0, 32, 1, /* 2858: struct.stack_st_void */
            	2863, 0,
            0, 32, 2, /* 2863: struct.stack_st */
            	637, 8,
            	411, 24,
            1, 8, 1, /* 2870: pointer.struct.bn_mont_ctx_st */
            	2875, 0,
            0, 96, 3, /* 2875: struct.bn_mont_ctx_st */
            	2843, 8,
            	2843, 32,
            	2843, 56,
            1, 8, 1, /* 2884: pointer.struct.bn_blinding_st */
            	2889, 0,
            0, 0, 0, /* 2889: struct.bn_blinding_st */
            1, 8, 1, /* 2892: pointer.struct.dsa_st */
            	2897, 0,
            0, 136, 11, /* 2897: struct.dsa_st */
            	2838, 24,
            	2838, 32,
            	2838, 40,
            	2838, 48,
            	2838, 56,
            	2838, 64,
            	2838, 72,
            	2870, 88,
            	2848, 104,
            	2922, 120,
            	2720, 128,
            1, 8, 1, /* 2922: pointer.struct.dsa_method */
            	2927, 0,
            0, 96, 11, /* 2927: struct.dsa_method */
            	5, 0,
            	2952, 8,
            	2955, 16,
            	2958, 24,
            	2512, 32,
            	2961, 40,
            	2964, 48,
            	2964, 56,
            	251, 72,
            	2967, 80,
            	2964, 88,
            64097, 8, 0, /* 2952: pointer.func */
            64097, 8, 0, /* 2955: pointer.func */
            64097, 8, 0, /* 2958: pointer.func */
            64097, 8, 0, /* 2961: pointer.func */
            64097, 8, 0, /* 2964: pointer.func */
            64097, 8, 0, /* 2967: pointer.func */
            1, 8, 1, /* 2970: pointer.struct.dh_st */
            	2975, 0,
            0, 144, 12, /* 2975: struct.dh_st */
            	2838, 8,
            	2838, 16,
            	2838, 32,
            	2838, 40,
            	2870, 56,
            	2838, 64,
            	2838, 72,
            	159, 80,
            	2838, 96,
            	2848, 112,
            	3002, 128,
            	2720, 136,
            1, 8, 1, /* 3002: pointer.struct.dh_method */
            	3007, 0,
            0, 72, 8, /* 3007: struct.dh_method */
            	5, 0,
            	3026, 8,
            	3029, 16,
            	3032, 24,
            	3026, 32,
            	3026, 40,
            	251, 56,
            	3035, 64,
            64097, 8, 0, /* 3026: pointer.func */
            64097, 8, 0, /* 3029: pointer.func */
            64097, 8, 0, /* 3032: pointer.func */
            64097, 8, 0, /* 3035: pointer.func */
            1, 8, 1, /* 3038: pointer.struct.ec_key_st */
            	3043, 0,
            0, 0, 0, /* 3043: struct.ec_key_st */
            1, 8, 1, /* 3046: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3051, 0,
            0, 32, 2, /* 3051: struct.stack_st_fake_X509_ATTRIBUTE */
            	3058, 8,
            	411, 24,
            64099, 8, 2, /* 3058: pointer_to_array_of_pointers_to_stack */
            	3065, 0,
            	408, 20,
            0, 8, 1, /* 3065: pointer.X509_ATTRIBUTE */
            	845, 0,
            64097, 8, 0, /* 3070: pointer.func */
            0, 0, 1, /* 3073: X509_OBJECT */
            	3078, 0,
            0, 16, 1, /* 3078: struct.x509_object_st */
            	3083, 8,
            0, 8, 4, /* 3083: union.unknown */
            	251, 0,
            	3094, 0,
            	3606, 0,
            	3235, 0,
            1, 8, 1, /* 3094: pointer.struct.x509_st */
            	3099, 0,
            0, 184, 12, /* 3099: struct.x509_st */
            	3126, 0,
            	2307, 8,
            	2406, 16,
            	251, 32,
            	2168, 40,
            	2411, 104,
            	2501, 112,
            	2490, 120,
            	2466, 128,
            	3508, 136,
            	3532, 144,
            	3540, 176,
            1, 8, 1, /* 3126: pointer.struct.x509_cinf_st */
            	3131, 0,
            0, 104, 11, /* 3131: struct.x509_cinf_st */
            	2396, 0,
            	2396, 8,
            	2307, 16,
            	3156, 24,
            	3204, 32,
            	3156, 40,
            	3221, 48,
            	2406, 56,
            	2406, 64,
            	3479, 72,
            	3503, 80,
            1, 8, 1, /* 3156: pointer.struct.X509_name_st */
            	3161, 0,
            0, 40, 3, /* 3161: struct.X509_name_st */
            	3170, 0,
            	3194, 16,
            	159, 24,
            1, 8, 1, /* 3170: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3175, 0,
            0, 32, 2, /* 3175: struct.stack_st_fake_X509_NAME_ENTRY */
            	3182, 8,
            	411, 24,
            64099, 8, 2, /* 3182: pointer_to_array_of_pointers_to_stack */
            	3189, 0,
            	408, 20,
            0, 8, 1, /* 3189: pointer.X509_NAME_ENTRY */
            	372, 0,
            1, 8, 1, /* 3194: pointer.struct.buf_mem_st */
            	3199, 0,
            0, 24, 1, /* 3199: struct.buf_mem_st */
            	251, 8,
            1, 8, 1, /* 3204: pointer.struct.X509_val_st */
            	3209, 0,
            0, 16, 2, /* 3209: struct.X509_val_st */
            	3216, 0,
            	3216, 8,
            1, 8, 1, /* 3216: pointer.struct.asn1_string_st */
            	2391, 0,
            1, 8, 1, /* 3221: pointer.struct.X509_pubkey_st */
            	3226, 0,
            0, 24, 3, /* 3226: struct.X509_pubkey_st */
            	2307, 0,
            	2406, 8,
            	3235, 16,
            1, 8, 1, /* 3235: pointer.struct.evp_pkey_st */
            	3240, 0,
            0, 56, 4, /* 3240: struct.evp_pkey_st */
            	3251, 16,
            	2293, 24,
            	3259, 32,
            	3455, 48,
            1, 8, 1, /* 3251: pointer.struct.evp_pkey_asn1_method_st */
            	3256, 0,
            0, 0, 0, /* 3256: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3259: union.unknown */
            	251, 0,
            	3272, 0,
            	3377, 0,
            	3382, 0,
            	3450, 0,
            1, 8, 1, /* 3272: pointer.struct.rsa_st */
            	3277, 0,
            0, 168, 17, /* 3277: struct.rsa_st */
            	3314, 16,
            	2293, 24,
            	2218, 32,
            	2218, 40,
            	2218, 48,
            	2218, 56,
            	2218, 64,
            	2218, 72,
            	2218, 80,
            	2218, 88,
            	2168, 96,
            	2228, 120,
            	2228, 128,
            	2228, 136,
            	251, 144,
            	3369, 152,
            	3369, 160,
            1, 8, 1, /* 3314: pointer.struct.rsa_meth_st */
            	3319, 0,
            0, 112, 13, /* 3319: struct.rsa_meth_st */
            	5, 0,
            	3348, 8,
            	3348, 16,
            	3348, 24,
            	3348, 32,
            	3351, 40,
            	3354, 48,
            	3357, 56,
            	3357, 64,
            	251, 80,
            	3360, 88,
            	3363, 96,
            	3366, 104,
            64097, 8, 0, /* 3348: pointer.func */
            64097, 8, 0, /* 3351: pointer.func */
            64097, 8, 0, /* 3354: pointer.func */
            64097, 8, 0, /* 3357: pointer.func */
            64097, 8, 0, /* 3360: pointer.func */
            64097, 8, 0, /* 3363: pointer.func */
            64097, 8, 0, /* 3366: pointer.func */
            1, 8, 1, /* 3369: pointer.struct.bn_blinding_st */
            	3374, 0,
            0, 0, 0, /* 3374: struct.bn_blinding_st */
            1, 8, 1, /* 3377: pointer.struct.dsa_st */
            	2193, 0,
            1, 8, 1, /* 3382: pointer.struct.dh_st */
            	3387, 0,
            0, 144, 12, /* 3387: struct.dh_st */
            	2218, 8,
            	2218, 16,
            	2218, 32,
            	2218, 40,
            	2228, 56,
            	2218, 64,
            	2218, 72,
            	159, 80,
            	2218, 96,
            	2168, 112,
            	3414, 128,
            	2293, 136,
            1, 8, 1, /* 3414: pointer.struct.dh_method */
            	3419, 0,
            0, 72, 8, /* 3419: struct.dh_method */
            	5, 0,
            	3438, 8,
            	3441, 16,
            	3444, 24,
            	3438, 32,
            	3438, 40,
            	251, 56,
            	3447, 64,
            64097, 8, 0, /* 3438: pointer.func */
            64097, 8, 0, /* 3441: pointer.func */
            64097, 8, 0, /* 3444: pointer.func */
            64097, 8, 0, /* 3447: pointer.func */
            1, 8, 1, /* 3450: pointer.struct.ec_key_st */
            	2498, 0,
            1, 8, 1, /* 3455: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3460, 0,
            0, 32, 2, /* 3460: struct.stack_st_fake_X509_ATTRIBUTE */
            	3467, 8,
            	411, 24,
            64099, 8, 2, /* 3467: pointer_to_array_of_pointers_to_stack */
            	3474, 0,
            	408, 20,
            0, 8, 1, /* 3474: pointer.X509_ATTRIBUTE */
            	845, 0,
            1, 8, 1, /* 3479: pointer.struct.stack_st_X509_EXTENSION */
            	3484, 0,
            0, 32, 2, /* 3484: struct.stack_st_fake_X509_EXTENSION */
            	3491, 8,
            	411, 24,
            64099, 8, 2, /* 3491: pointer_to_array_of_pointers_to_stack */
            	3498, 0,
            	408, 20,
            0, 8, 1, /* 3498: pointer.X509_EXTENSION */
            	1224, 0,
            0, 24, 1, /* 3503: struct.ASN1_ENCODING_st */
            	159, 0,
            1, 8, 1, /* 3508: pointer.struct.stack_st_GENERAL_NAME */
            	3513, 0,
            0, 32, 2, /* 3513: struct.stack_st_fake_GENERAL_NAME */
            	3520, 8,
            	411, 24,
            64099, 8, 2, /* 3520: pointer_to_array_of_pointers_to_stack */
            	3527, 0,
            	408, 20,
            0, 8, 1, /* 3527: pointer.GENERAL_NAME */
            	1362, 0,
            1, 8, 1, /* 3532: pointer.struct.NAME_CONSTRAINTS_st */
            	3537, 0,
            0, 0, 0, /* 3537: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3540: pointer.struct.x509_cert_aux_st */
            	3545, 0,
            0, 40, 5, /* 3545: struct.x509_cert_aux_st */
            	3558, 0,
            	3558, 8,
            	2461, 16,
            	2411, 24,
            	3582, 32,
            1, 8, 1, /* 3558: pointer.struct.stack_st_ASN1_OBJECT */
            	3563, 0,
            0, 32, 2, /* 3563: struct.stack_st_fake_ASN1_OBJECT */
            	3570, 8,
            	411, 24,
            64099, 8, 2, /* 3570: pointer_to_array_of_pointers_to_stack */
            	3577, 0,
            	408, 20,
            0, 8, 1, /* 3577: pointer.ASN1_OBJECT */
            	1764, 0,
            1, 8, 1, /* 3582: pointer.struct.stack_st_X509_ALGOR */
            	3587, 0,
            0, 32, 2, /* 3587: struct.stack_st_fake_X509_ALGOR */
            	3594, 8,
            	411, 24,
            64099, 8, 2, /* 3594: pointer_to_array_of_pointers_to_stack */
            	3601, 0,
            	408, 20,
            0, 8, 1, /* 3601: pointer.X509_ALGOR */
            	1802, 0,
            1, 8, 1, /* 3606: pointer.struct.X509_crl_st */
            	3611, 0,
            0, 120, 10, /* 3611: struct.X509_crl_st */
            	3634, 0,
            	2307, 8,
            	2406, 16,
            	2501, 32,
            	3761, 40,
            	2396, 56,
            	2396, 64,
            	3769, 96,
            	3810, 104,
            	3818, 112,
            1, 8, 1, /* 3634: pointer.struct.X509_crl_info_st */
            	3639, 0,
            0, 80, 8, /* 3639: struct.X509_crl_info_st */
            	2396, 0,
            	2307, 8,
            	3156, 16,
            	3216, 24,
            	3216, 32,
            	3658, 40,
            	3479, 48,
            	3503, 56,
            1, 8, 1, /* 3658: pointer.struct.stack_st_X509_REVOKED */
            	3663, 0,
            0, 32, 2, /* 3663: struct.stack_st_fake_X509_REVOKED */
            	3670, 8,
            	411, 24,
            64099, 8, 2, /* 3670: pointer_to_array_of_pointers_to_stack */
            	3677, 0,
            	408, 20,
            0, 8, 1, /* 3677: pointer.X509_REVOKED */
            	3682, 0,
            0, 0, 1, /* 3682: X509_REVOKED */
            	3687, 0,
            0, 40, 4, /* 3687: struct.x509_revoked_st */
            	3698, 0,
            	3708, 8,
            	3713, 16,
            	3737, 24,
            1, 8, 1, /* 3698: pointer.struct.asn1_string_st */
            	3703, 0,
            0, 24, 1, /* 3703: struct.asn1_string_st */
            	159, 8,
            1, 8, 1, /* 3708: pointer.struct.asn1_string_st */
            	3703, 0,
            1, 8, 1, /* 3713: pointer.struct.stack_st_X509_EXTENSION */
            	3718, 0,
            0, 32, 2, /* 3718: struct.stack_st_fake_X509_EXTENSION */
            	3725, 8,
            	411, 24,
            64099, 8, 2, /* 3725: pointer_to_array_of_pointers_to_stack */
            	3732, 0,
            	408, 20,
            0, 8, 1, /* 3732: pointer.X509_EXTENSION */
            	1224, 0,
            1, 8, 1, /* 3737: pointer.struct.stack_st_GENERAL_NAME */
            	3742, 0,
            0, 32, 2, /* 3742: struct.stack_st_fake_GENERAL_NAME */
            	3749, 8,
            	411, 24,
            64099, 8, 2, /* 3749: pointer_to_array_of_pointers_to_stack */
            	3756, 0,
            	408, 20,
            0, 8, 1, /* 3756: pointer.GENERAL_NAME */
            	1362, 0,
            1, 8, 1, /* 3761: pointer.struct.ISSUING_DIST_POINT_st */
            	3766, 0,
            0, 0, 0, /* 3766: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3769: pointer.struct.stack_st_GENERAL_NAMES */
            	3774, 0,
            0, 32, 2, /* 3774: struct.stack_st_fake_GENERAL_NAMES */
            	3781, 8,
            	411, 24,
            64099, 8, 2, /* 3781: pointer_to_array_of_pointers_to_stack */
            	3788, 0,
            	408, 20,
            0, 8, 1, /* 3788: pointer.GENERAL_NAMES */
            	3793, 0,
            0, 0, 1, /* 3793: GENERAL_NAMES */
            	3798, 0,
            0, 32, 1, /* 3798: struct.stack_st_GENERAL_NAME */
            	3803, 0,
            0, 32, 2, /* 3803: struct.stack_st */
            	637, 8,
            	411, 24,
            1, 8, 1, /* 3810: pointer.struct.x509_crl_method_st */
            	3815, 0,
            0, 0, 0, /* 3815: struct.x509_crl_method_st */
            0, 8, 0, /* 3818: pointer.void */
            1, 8, 1, /* 3821: pointer.struct.cert_st */
            	56, 0,
            0, 104, 11, /* 3826: struct.x509_cinf_st */
            	2618, 0,
            	2618, 8,
            	2529, 16,
            	3851, 24,
            	3899, 32,
            	3851, 40,
            	2515, 48,
            	2628, 56,
            	2628, 64,
            	3916, 72,
            	3940, 80,
            1, 8, 1, /* 3851: pointer.struct.X509_name_st */
            	3856, 0,
            0, 40, 3, /* 3856: struct.X509_name_st */
            	3865, 0,
            	3889, 16,
            	159, 24,
            1, 8, 1, /* 3865: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3870, 0,
            0, 32, 2, /* 3870: struct.stack_st_fake_X509_NAME_ENTRY */
            	3877, 8,
            	411, 24,
            64099, 8, 2, /* 3877: pointer_to_array_of_pointers_to_stack */
            	3884, 0,
            	408, 20,
            0, 8, 1, /* 3884: pointer.X509_NAME_ENTRY */
            	372, 0,
            1, 8, 1, /* 3889: pointer.struct.buf_mem_st */
            	3894, 0,
            0, 24, 1, /* 3894: struct.buf_mem_st */
            	251, 8,
            1, 8, 1, /* 3899: pointer.struct.X509_val_st */
            	3904, 0,
            0, 16, 2, /* 3904: struct.X509_val_st */
            	3911, 0,
            	3911, 8,
            1, 8, 1, /* 3911: pointer.struct.asn1_string_st */
            	2613, 0,
            1, 8, 1, /* 3916: pointer.struct.stack_st_X509_EXTENSION */
            	3921, 0,
            0, 32, 2, /* 3921: struct.stack_st_fake_X509_EXTENSION */
            	3928, 8,
            	411, 24,
            64099, 8, 2, /* 3928: pointer_to_array_of_pointers_to_stack */
            	3935, 0,
            	408, 20,
            0, 8, 1, /* 3935: pointer.X509_EXTENSION */
            	1224, 0,
            0, 24, 1, /* 3940: struct.ASN1_ENCODING_st */
            	159, 0,
            0, 0, 0, /* 3945: struct.X509_POLICY_CACHE_st */
            0, 8, 1, /* 3948: pointer.SRTP_PROTECTION_PROFILE */
            	10, 0,
            1, 8, 1, /* 3953: pointer.struct.sess_cert_st */
            	3958, 0,
            0, 248, 5, /* 3958: struct.sess_cert_st */
            	3971, 0,
            	73, 16,
            	2006, 216,
            	2011, 224,
            	2016, 232,
            1, 8, 1, /* 3971: pointer.struct.stack_st_X509 */
            	3976, 0,
            0, 32, 2, /* 3976: struct.stack_st_fake_X509 */
            	3983, 8,
            	411, 24,
            64099, 8, 2, /* 3983: pointer_to_array_of_pointers_to_stack */
            	3990, 0,
            	408, 20,
            0, 8, 1, /* 3990: pointer.X509 */
            	3995, 0,
            0, 0, 1, /* 3995: X509 */
            	4000, 0,
            0, 184, 12, /* 4000: struct.x509_st */
            	4027, 0,
            	2529, 8,
            	2628, 16,
            	251, 32,
            	2848, 40,
            	2633, 104,
            	4032, 112,
            	4040, 120,
            	4045, 128,
            	4069, 136,
            	4093, 144,
            	4101, 176,
            1, 8, 1, /* 4027: pointer.struct.x509_cinf_st */
            	3826, 0,
            1, 8, 1, /* 4032: pointer.struct.AUTHORITY_KEYID_st */
            	4037, 0,
            0, 0, 0, /* 4037: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4040: pointer.struct.X509_POLICY_CACHE_st */
            	3945, 0,
            1, 8, 1, /* 4045: pointer.struct.stack_st_DIST_POINT */
            	4050, 0,
            0, 32, 2, /* 4050: struct.stack_st_fake_DIST_POINT */
            	4057, 8,
            	411, 24,
            64099, 8, 2, /* 4057: pointer_to_array_of_pointers_to_stack */
            	4064, 0,
            	408, 20,
            0, 8, 1, /* 4064: pointer.DIST_POINT */
            	1305, 0,
            1, 8, 1, /* 4069: pointer.struct.stack_st_GENERAL_NAME */
            	4074, 0,
            0, 32, 2, /* 4074: struct.stack_st_fake_GENERAL_NAME */
            	4081, 8,
            	411, 24,
            64099, 8, 2, /* 4081: pointer_to_array_of_pointers_to_stack */
            	4088, 0,
            	408, 20,
            0, 8, 1, /* 4088: pointer.GENERAL_NAME */
            	1362, 0,
            1, 8, 1, /* 4093: pointer.struct.NAME_CONSTRAINTS_st */
            	4098, 0,
            0, 0, 0, /* 4098: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4101: pointer.struct.x509_cert_aux_st */
            	4106, 0,
            0, 40, 5, /* 4106: struct.x509_cert_aux_st */
            	4119, 0,
            	4119, 8,
            	2683, 16,
            	2633, 24,
            	4143, 32,
            1, 8, 1, /* 4119: pointer.struct.stack_st_ASN1_OBJECT */
            	4124, 0,
            0, 32, 2, /* 4124: struct.stack_st_fake_ASN1_OBJECT */
            	4131, 8,
            	411, 24,
            64099, 8, 2, /* 4131: pointer_to_array_of_pointers_to_stack */
            	4138, 0,
            	408, 20,
            0, 8, 1, /* 4138: pointer.ASN1_OBJECT */
            	1764, 0,
            1, 8, 1, /* 4143: pointer.struct.stack_st_X509_ALGOR */
            	4148, 0,
            0, 32, 2, /* 4148: struct.stack_st_fake_X509_ALGOR */
            	4155, 8,
            	411, 24,
            64099, 8, 2, /* 4155: pointer_to_array_of_pointers_to_stack */
            	4162, 0,
            	408, 20,
            0, 8, 1, /* 4162: pointer.X509_ALGOR */
            	1802, 0,
            64097, 8, 0, /* 4167: pointer.func */
            0, 0, 1, /* 4170: SSL_CIPHER */
            	4175, 0,
            0, 88, 1, /* 4175: struct.ssl_cipher_st */
            	5, 8,
            64097, 8, 0, /* 4180: pointer.func */
            64097, 8, 0, /* 4183: pointer.func */
            64099, 8, 2, /* 4186: pointer_to_array_of_pointers_to_stack */
            	3948, 0,
            	408, 20,
            64097, 8, 0, /* 4193: pointer.func */
            0, 32, 2, /* 4196: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4186, 8,
            	411, 24,
            64097, 8, 0, /* 4203: pointer.func */
            64097, 8, 0, /* 4206: pointer.func */
            1, 8, 1, /* 4209: pointer.struct.ssl_method_st */
            	4214, 0,
            0, 232, 28, /* 4214: struct.ssl_method_st */
            	4206, 8,
            	4273, 16,
            	4273, 24,
            	4206, 32,
            	4206, 40,
            	4276, 48,
            	4276, 56,
            	4279, 64,
            	4206, 72,
            	4206, 80,
            	4206, 88,
            	4282, 96,
            	2301, 104,
            	4193, 112,
            	4206, 120,
            	4285, 128,
            	4288, 136,
            	4291, 144,
            	4294, 152,
            	4297, 160,
            	4300, 168,
            	4303, 176,
            	4306, 184,
            	2105, 192,
            	4309, 200,
            	4300, 208,
            	4357, 216,
            	4360, 224,
            64097, 8, 0, /* 4273: pointer.func */
            64097, 8, 0, /* 4276: pointer.func */
            64097, 8, 0, /* 4279: pointer.func */
            64097, 8, 0, /* 4282: pointer.func */
            64097, 8, 0, /* 4285: pointer.func */
            64097, 8, 0, /* 4288: pointer.func */
            64097, 8, 0, /* 4291: pointer.func */
            64097, 8, 0, /* 4294: pointer.func */
            64097, 8, 0, /* 4297: pointer.func */
            64097, 8, 0, /* 4300: pointer.func */
            64097, 8, 0, /* 4303: pointer.func */
            64097, 8, 0, /* 4306: pointer.func */
            1, 8, 1, /* 4309: pointer.struct.ssl3_enc_method */
            	4314, 0,
            0, 112, 11, /* 4314: struct.ssl3_enc_method */
            	4339, 0,
            	4342, 8,
            	4206, 16,
            	4345, 24,
            	4339, 32,
            	4180, 40,
            	4348, 56,
            	5, 64,
            	5, 80,
            	4351, 96,
            	4354, 104,
            64097, 8, 0, /* 4339: pointer.func */
            64097, 8, 0, /* 4342: pointer.func */
            64097, 8, 0, /* 4345: pointer.func */
            64097, 8, 0, /* 4348: pointer.func */
            64097, 8, 0, /* 4351: pointer.func */
            64097, 8, 0, /* 4354: pointer.func */
            64097, 8, 0, /* 4357: pointer.func */
            64097, 8, 0, /* 4360: pointer.func */
            0, 1, 0, /* 4363: char */
            1, 8, 1, /* 4366: pointer.struct.stack_st_SSL_CIPHER */
            	4371, 0,
            0, 32, 2, /* 4371: struct.stack_st_fake_SSL_CIPHER */
            	4378, 8,
            	411, 24,
            64099, 8, 2, /* 4378: pointer_to_array_of_pointers_to_stack */
            	4385, 0,
            	408, 20,
            0, 8, 1, /* 4385: pointer.SSL_CIPHER */
            	4170, 0,
            64097, 8, 0, /* 4390: pointer.func */
            1, 8, 1, /* 4393: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4196, 0,
            64097, 8, 0, /* 4398: pointer.func */
            0, 736, 50, /* 4401: struct.ssl_ctx_st */
            	4209, 0,
            	4366, 8,
            	4366, 16,
            	4504, 24,
            	4802, 32,
            	4838, 48,
            	4838, 56,
            	2155, 80,
            	2149, 88,
            	2146, 96,
            	2143, 152,
            	3818, 160,
            	4874, 168,
            	3818, 176,
            	2140, 184,
            	4390, 192,
            	2137, 200,
            	615, 208,
            	1961, 224,
            	1961, 232,
            	1961, 240,
            	3971, 248,
            	2108, 256,
            	2064, 264,
            	4877, 272,
            	3821, 304,
            	44, 320,
            	3818, 328,
            	4778, 376,
            	38, 384,
            	4763, 392,
            	479, 408,
            	4906, 416,
            	3818, 424,
            	35, 480,
            	2304, 488,
            	3818, 496,
            	4909, 504,
            	3818, 512,
            	251, 520,
            	2152, 528,
            	4912, 536,
            	30, 552,
            	30, 560,
            	4915, 568,
            	4946, 696,
            	3818, 704,
            	41, 712,
            	3818, 720,
            	4393, 728,
            1, 8, 1, /* 4504: pointer.struct.x509_store_st */
            	4509, 0,
            0, 144, 15, /* 4509: struct.x509_store_st */
            	4542, 8,
            	4566, 16,
            	4763, 24,
            	4775, 32,
            	4778, 40,
            	4781, 48,
            	4784, 56,
            	4775, 64,
            	4787, 72,
            	4790, 80,
            	4793, 88,
            	4796, 96,
            	4799, 104,
            	4775, 112,
            	615, 120,
            1, 8, 1, /* 4542: pointer.struct.stack_st_X509_OBJECT */
            	4547, 0,
            0, 32, 2, /* 4547: struct.stack_st_fake_X509_OBJECT */
            	4554, 8,
            	411, 24,
            64099, 8, 2, /* 4554: pointer_to_array_of_pointers_to_stack */
            	4561, 0,
            	408, 20,
            0, 8, 1, /* 4561: pointer.X509_OBJECT */
            	3073, 0,
            1, 8, 1, /* 4566: pointer.struct.stack_st_X509_LOOKUP */
            	4571, 0,
            0, 32, 2, /* 4571: struct.stack_st_fake_X509_LOOKUP */
            	4578, 8,
            	411, 24,
            64099, 8, 2, /* 4578: pointer_to_array_of_pointers_to_stack */
            	4585, 0,
            	408, 20,
            0, 8, 1, /* 4585: pointer.X509_LOOKUP */
            	4590, 0,
            0, 0, 1, /* 4590: X509_LOOKUP */
            	4595, 0,
            0, 32, 3, /* 4595: struct.x509_lookup_st */
            	4604, 8,
            	251, 16,
            	4647, 24,
            1, 8, 1, /* 4604: pointer.struct.x509_lookup_method_st */
            	4609, 0,
            0, 80, 10, /* 4609: struct.x509_lookup_method_st */
            	5, 0,
            	4632, 8,
            	2509, 16,
            	4632, 24,
            	4632, 32,
            	4635, 40,
            	4638, 48,
            	4183, 56,
            	4641, 64,
            	4644, 72,
            64097, 8, 0, /* 4632: pointer.func */
            64097, 8, 0, /* 4635: pointer.func */
            64097, 8, 0, /* 4638: pointer.func */
            64097, 8, 0, /* 4641: pointer.func */
            64097, 8, 0, /* 4644: pointer.func */
            1, 8, 1, /* 4647: pointer.struct.x509_store_st */
            	4652, 0,
            0, 144, 15, /* 4652: struct.x509_store_st */
            	4685, 8,
            	4709, 16,
            	4733, 24,
            	4745, 32,
            	4748, 40,
            	4751, 48,
            	4203, 56,
            	4745, 64,
            	4754, 72,
            	4757, 80,
            	4760, 88,
            	4398, 96,
            	3070, 104,
            	4745, 112,
            	2168, 120,
            1, 8, 1, /* 4685: pointer.struct.stack_st_X509_OBJECT */
            	4690, 0,
            0, 32, 2, /* 4690: struct.stack_st_fake_X509_OBJECT */
            	4697, 8,
            	411, 24,
            64099, 8, 2, /* 4697: pointer_to_array_of_pointers_to_stack */
            	4704, 0,
            	408, 20,
            0, 8, 1, /* 4704: pointer.X509_OBJECT */
            	3073, 0,
            1, 8, 1, /* 4709: pointer.struct.stack_st_X509_LOOKUP */
            	4714, 0,
            0, 32, 2, /* 4714: struct.stack_st_fake_X509_LOOKUP */
            	4721, 8,
            	411, 24,
            64099, 8, 2, /* 4721: pointer_to_array_of_pointers_to_stack */
            	4728, 0,
            	408, 20,
            0, 8, 1, /* 4728: pointer.X509_LOOKUP */
            	4590, 0,
            1, 8, 1, /* 4733: pointer.struct.X509_VERIFY_PARAM_st */
            	4738, 0,
            0, 56, 2, /* 4738: struct.X509_VERIFY_PARAM_st */
            	251, 0,
            	3558, 48,
            64097, 8, 0, /* 4745: pointer.func */
            64097, 8, 0, /* 4748: pointer.func */
            64097, 8, 0, /* 4751: pointer.func */
            64097, 8, 0, /* 4754: pointer.func */
            64097, 8, 0, /* 4757: pointer.func */
            64097, 8, 0, /* 4760: pointer.func */
            1, 8, 1, /* 4763: pointer.struct.X509_VERIFY_PARAM_st */
            	4768, 0,
            0, 56, 2, /* 4768: struct.X509_VERIFY_PARAM_st */
            	251, 0,
            	1740, 48,
            64097, 8, 0, /* 4775: pointer.func */
            64097, 8, 0, /* 4778: pointer.func */
            64097, 8, 0, /* 4781: pointer.func */
            64097, 8, 0, /* 4784: pointer.func */
            64097, 8, 0, /* 4787: pointer.func */
            64097, 8, 0, /* 4790: pointer.func */
            64097, 8, 0, /* 4793: pointer.func */
            64097, 8, 0, /* 4796: pointer.func */
            64097, 8, 0, /* 4799: pointer.func */
            1, 8, 1, /* 4802: pointer.struct.lhash_st */
            	4807, 0,
            0, 176, 3, /* 4807: struct.lhash_st */
            	4816, 0,
            	411, 8,
            	4167, 16,
            1, 8, 1, /* 4816: pointer.pointer.struct.lhash_node_st */
            	4821, 0,
            1, 8, 1, /* 4821: pointer.struct.lhash_node_st */
            	4826, 0,
            0, 24, 2, /* 4826: struct.lhash_node_st */
            	3818, 0,
            	4833, 8,
            1, 8, 1, /* 4833: pointer.struct.lhash_node_st */
            	4826, 0,
            1, 8, 1, /* 4838: pointer.struct.ssl_session_st */
            	4843, 0,
            0, 352, 14, /* 4843: struct.ssl_session_st */
            	251, 144,
            	251, 152,
            	3953, 168,
            	87, 176,
            	2158, 224,
            	4366, 240,
            	615, 248,
            	4838, 264,
            	4838, 272,
            	251, 280,
            	159, 296,
            	159, 312,
            	159, 320,
            	251, 344,
            64097, 8, 0, /* 4874: pointer.func */
            1, 8, 1, /* 4877: pointer.struct.stack_st_X509_NAME */
            	4882, 0,
            0, 32, 2, /* 4882: struct.stack_st_fake_X509_NAME */
            	4889, 8,
            	411, 24,
            64099, 8, 2, /* 4889: pointer_to_array_of_pointers_to_stack */
            	4896, 0,
            	408, 20,
            0, 8, 1, /* 4896: pointer.X509_NAME */
            	4901, 0,
            0, 0, 1, /* 4901: X509_NAME */
            	2026, 0,
            64097, 8, 0, /* 4906: pointer.func */
            64097, 8, 0, /* 4909: pointer.func */
            64097, 8, 0, /* 4912: pointer.func */
            0, 128, 14, /* 4915: struct.srp_ctx_st */
            	3818, 0,
            	4906, 8,
            	2304, 16,
            	2190, 24,
            	251, 32,
            	597, 40,
            	597, 48,
            	597, 56,
            	597, 64,
            	597, 72,
            	597, 80,
            	597, 88,
            	597, 96,
            	251, 104,
            64097, 8, 0, /* 4946: pointer.func */
            1, 8, 1, /* 4949: pointer.struct.ssl_ctx_st */
            	4401, 0,
        },
        .arg_entity_index = { 4949, 5, 408, },
        .ret_entity_index = 408,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *,const char *,int);
    orig_SSL_CTX_use_PrivateKey_file = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey_file");
    *new_ret_ptr = (*orig_SSL_CTX_use_PrivateKey_file)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

