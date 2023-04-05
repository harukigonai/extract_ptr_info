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
            	8884096, 0,
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
            8884097, 8, 0, /* 35: pointer.func */
            8884097, 8, 0, /* 38: pointer.func */
            8884097, 8, 0, /* 41: pointer.func */
            8884097, 8, 0, /* 44: pointer.func */
            8884097, 8, 0, /* 47: pointer.func */
            8884097, 8, 0, /* 50: pointer.func */
            8884097, 8, 0, /* 53: pointer.func */
            8884097, 8, 0, /* 56: pointer.func */
            0, 296, 7, /* 59: struct.cert_st */
            	76, 0,
            	2009, 48,
            	56, 56,
            	2014, 64,
            	53, 72,
            	2019, 80,
            	50, 88,
            1, 8, 1, /* 76: pointer.struct.cert_pkey_st */
            	81, 0,
            0, 24, 3, /* 81: struct.cert_pkey_st */
            	90, 0,
            	458, 8,
            	1964, 16,
            1, 8, 1, /* 90: pointer.struct.x509_st */
            	95, 0,
            0, 184, 12, /* 95: struct.x509_st */
            	122, 0,
            	170, 8,
            	269, 16,
            	254, 32,
            	618, 40,
            	274, 104,
            	1268, 112,
            	1276, 120,
            	1284, 128,
            	1693, 136,
            	1717, 144,
            	1725, 176,
            1, 8, 1, /* 122: pointer.struct.x509_cinf_st */
            	127, 0,
            0, 104, 11, /* 127: struct.x509_cinf_st */
            	152, 0,
            	152, 8,
            	170, 16,
            	337, 24,
            	427, 32,
            	337, 40,
            	444, 48,
            	269, 56,
            	269, 64,
            	1203, 72,
            	1263, 80,
            1, 8, 1, /* 152: pointer.struct.asn1_string_st */
            	157, 0,
            0, 24, 1, /* 157: struct.asn1_string_st */
            	162, 8,
            1, 8, 1, /* 162: pointer.unsigned char */
            	167, 0,
            0, 1, 0, /* 167: unsigned char */
            1, 8, 1, /* 170: pointer.struct.X509_algor_st */
            	175, 0,
            0, 16, 2, /* 175: struct.X509_algor_st */
            	182, 0,
            	201, 8,
            1, 8, 1, /* 182: pointer.struct.asn1_object_st */
            	187, 0,
            0, 40, 3, /* 187: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	196, 24,
            1, 8, 1, /* 196: pointer.unsigned char */
            	167, 0,
            1, 8, 1, /* 201: pointer.struct.asn1_type_st */
            	206, 0,
            0, 16, 1, /* 206: struct.asn1_type_st */
            	211, 8,
            0, 8, 20, /* 211: union.unknown */
            	254, 0,
            	259, 0,
            	182, 0,
            	152, 0,
            	264, 0,
            	269, 0,
            	274, 0,
            	279, 0,
            	284, 0,
            	289, 0,
            	294, 0,
            	299, 0,
            	304, 0,
            	309, 0,
            	314, 0,
            	319, 0,
            	324, 0,
            	259, 0,
            	259, 0,
            	329, 0,
            1, 8, 1, /* 254: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 259: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 264: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 269: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 274: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 279: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 284: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 289: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 294: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 299: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 304: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 309: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 314: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 319: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 324: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 329: pointer.struct.ASN1_VALUE_st */
            	334, 0,
            0, 0, 0, /* 334: struct.ASN1_VALUE_st */
            1, 8, 1, /* 337: pointer.struct.X509_name_st */
            	342, 0,
            0, 40, 3, /* 342: struct.X509_name_st */
            	351, 0,
            	417, 16,
            	162, 24,
            1, 8, 1, /* 351: pointer.struct.stack_st_X509_NAME_ENTRY */
            	356, 0,
            0, 32, 2, /* 356: struct.stack_st_fake_X509_NAME_ENTRY */
            	363, 8,
            	414, 24,
            8884099, 8, 2, /* 363: pointer_to_array_of_pointers_to_stack */
            	370, 0,
            	411, 20,
            0, 8, 1, /* 370: pointer.X509_NAME_ENTRY */
            	375, 0,
            0, 0, 1, /* 375: X509_NAME_ENTRY */
            	380, 0,
            0, 24, 2, /* 380: struct.X509_name_entry_st */
            	387, 0,
            	401, 8,
            1, 8, 1, /* 387: pointer.struct.asn1_object_st */
            	392, 0,
            0, 40, 3, /* 392: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	196, 24,
            1, 8, 1, /* 401: pointer.struct.asn1_string_st */
            	406, 0,
            0, 24, 1, /* 406: struct.asn1_string_st */
            	162, 8,
            0, 4, 0, /* 411: int */
            8884097, 8, 0, /* 414: pointer.func */
            1, 8, 1, /* 417: pointer.struct.buf_mem_st */
            	422, 0,
            0, 24, 1, /* 422: struct.buf_mem_st */
            	254, 8,
            1, 8, 1, /* 427: pointer.struct.X509_val_st */
            	432, 0,
            0, 16, 2, /* 432: struct.X509_val_st */
            	439, 0,
            	439, 8,
            1, 8, 1, /* 439: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 444: pointer.struct.X509_pubkey_st */
            	449, 0,
            0, 24, 3, /* 449: struct.X509_pubkey_st */
            	170, 0,
            	269, 8,
            	458, 16,
            1, 8, 1, /* 458: pointer.struct.evp_pkey_st */
            	463, 0,
            0, 56, 4, /* 463: struct.evp_pkey_st */
            	474, 16,
            	482, 24,
            	490, 32,
            	824, 48,
            1, 8, 1, /* 474: pointer.struct.evp_pkey_asn1_method_st */
            	479, 0,
            0, 0, 0, /* 479: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 482: pointer.struct.engine_st */
            	487, 0,
            0, 0, 0, /* 487: struct.engine_st */
            0, 8, 5, /* 490: union.unknown */
            	254, 0,
            	503, 0,
            	667, 0,
            	748, 0,
            	816, 0,
            1, 8, 1, /* 503: pointer.struct.rsa_st */
            	508, 0,
            0, 168, 17, /* 508: struct.rsa_st */
            	545, 16,
            	482, 24,
            	600, 32,
            	600, 40,
            	600, 48,
            	600, 56,
            	600, 64,
            	600, 72,
            	600, 80,
            	600, 88,
            	618, 96,
            	645, 120,
            	645, 128,
            	645, 136,
            	254, 144,
            	659, 152,
            	659, 160,
            1, 8, 1, /* 545: pointer.struct.rsa_meth_st */
            	550, 0,
            0, 112, 13, /* 550: struct.rsa_meth_st */
            	5, 0,
            	579, 8,
            	579, 16,
            	579, 24,
            	579, 32,
            	582, 40,
            	585, 48,
            	588, 56,
            	588, 64,
            	254, 80,
            	591, 88,
            	594, 96,
            	597, 104,
            8884097, 8, 0, /* 579: pointer.func */
            8884097, 8, 0, /* 582: pointer.func */
            8884097, 8, 0, /* 585: pointer.func */
            8884097, 8, 0, /* 588: pointer.func */
            8884097, 8, 0, /* 591: pointer.func */
            8884097, 8, 0, /* 594: pointer.func */
            8884097, 8, 0, /* 597: pointer.func */
            1, 8, 1, /* 600: pointer.struct.bignum_st */
            	605, 0,
            0, 24, 1, /* 605: struct.bignum_st */
            	610, 0,
            1, 8, 1, /* 610: pointer.unsigned int */
            	615, 0,
            0, 4, 0, /* 615: unsigned int */
            0, 16, 1, /* 618: struct.crypto_ex_data_st */
            	623, 0,
            1, 8, 1, /* 623: pointer.struct.stack_st_void */
            	628, 0,
            0, 32, 1, /* 628: struct.stack_st_void */
            	633, 0,
            0, 32, 2, /* 633: struct.stack_st */
            	640, 8,
            	414, 24,
            1, 8, 1, /* 640: pointer.pointer.char */
            	254, 0,
            1, 8, 1, /* 645: pointer.struct.bn_mont_ctx_st */
            	650, 0,
            0, 96, 3, /* 650: struct.bn_mont_ctx_st */
            	605, 8,
            	605, 32,
            	605, 56,
            1, 8, 1, /* 659: pointer.struct.bn_blinding_st */
            	664, 0,
            0, 0, 0, /* 664: struct.bn_blinding_st */
            1, 8, 1, /* 667: pointer.struct.dsa_st */
            	672, 0,
            0, 136, 11, /* 672: struct.dsa_st */
            	600, 24,
            	600, 32,
            	600, 40,
            	600, 48,
            	600, 56,
            	600, 64,
            	600, 72,
            	645, 88,
            	618, 104,
            	697, 120,
            	482, 128,
            1, 8, 1, /* 697: pointer.struct.dsa_method */
            	702, 0,
            0, 96, 11, /* 702: struct.dsa_method */
            	5, 0,
            	727, 8,
            	730, 16,
            	733, 24,
            	736, 32,
            	739, 40,
            	742, 48,
            	742, 56,
            	254, 72,
            	745, 80,
            	742, 88,
            8884097, 8, 0, /* 727: pointer.func */
            8884097, 8, 0, /* 730: pointer.func */
            8884097, 8, 0, /* 733: pointer.func */
            8884097, 8, 0, /* 736: pointer.func */
            8884097, 8, 0, /* 739: pointer.func */
            8884097, 8, 0, /* 742: pointer.func */
            8884097, 8, 0, /* 745: pointer.func */
            1, 8, 1, /* 748: pointer.struct.dh_st */
            	753, 0,
            0, 144, 12, /* 753: struct.dh_st */
            	600, 8,
            	600, 16,
            	600, 32,
            	600, 40,
            	645, 56,
            	600, 64,
            	600, 72,
            	162, 80,
            	600, 96,
            	618, 112,
            	780, 128,
            	482, 136,
            1, 8, 1, /* 780: pointer.struct.dh_method */
            	785, 0,
            0, 72, 8, /* 785: struct.dh_method */
            	5, 0,
            	804, 8,
            	807, 16,
            	810, 24,
            	804, 32,
            	804, 40,
            	254, 56,
            	813, 64,
            8884097, 8, 0, /* 804: pointer.func */
            8884097, 8, 0, /* 807: pointer.func */
            8884097, 8, 0, /* 810: pointer.func */
            8884097, 8, 0, /* 813: pointer.func */
            1, 8, 1, /* 816: pointer.struct.ec_key_st */
            	821, 0,
            0, 0, 0, /* 821: struct.ec_key_st */
            1, 8, 1, /* 824: pointer.struct.stack_st_X509_ATTRIBUTE */
            	829, 0,
            0, 32, 2, /* 829: struct.stack_st_fake_X509_ATTRIBUTE */
            	836, 8,
            	414, 24,
            8884099, 8, 2, /* 836: pointer_to_array_of_pointers_to_stack */
            	843, 0,
            	411, 20,
            0, 8, 1, /* 843: pointer.X509_ATTRIBUTE */
            	848, 0,
            0, 0, 1, /* 848: X509_ATTRIBUTE */
            	853, 0,
            0, 24, 2, /* 853: struct.x509_attributes_st */
            	860, 0,
            	874, 16,
            1, 8, 1, /* 860: pointer.struct.asn1_object_st */
            	865, 0,
            0, 40, 3, /* 865: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	196, 24,
            0, 8, 3, /* 874: union.unknown */
            	254, 0,
            	883, 0,
            	1062, 0,
            1, 8, 1, /* 883: pointer.struct.stack_st_ASN1_TYPE */
            	888, 0,
            0, 32, 2, /* 888: struct.stack_st_fake_ASN1_TYPE */
            	895, 8,
            	414, 24,
            8884099, 8, 2, /* 895: pointer_to_array_of_pointers_to_stack */
            	902, 0,
            	411, 20,
            0, 8, 1, /* 902: pointer.ASN1_TYPE */
            	907, 0,
            0, 0, 1, /* 907: ASN1_TYPE */
            	912, 0,
            0, 16, 1, /* 912: struct.asn1_type_st */
            	917, 8,
            0, 8, 20, /* 917: union.unknown */
            	254, 0,
            	960, 0,
            	970, 0,
            	984, 0,
            	989, 0,
            	994, 0,
            	999, 0,
            	1004, 0,
            	1009, 0,
            	1014, 0,
            	1019, 0,
            	1024, 0,
            	1029, 0,
            	1034, 0,
            	1039, 0,
            	1044, 0,
            	1049, 0,
            	960, 0,
            	960, 0,
            	1054, 0,
            1, 8, 1, /* 960: pointer.struct.asn1_string_st */
            	965, 0,
            0, 24, 1, /* 965: struct.asn1_string_st */
            	162, 8,
            1, 8, 1, /* 970: pointer.struct.asn1_object_st */
            	975, 0,
            0, 40, 3, /* 975: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	196, 24,
            1, 8, 1, /* 984: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 989: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 994: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 999: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 1004: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 1009: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 1014: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 1019: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 1024: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 1029: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 1034: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 1039: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 1044: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 1049: pointer.struct.asn1_string_st */
            	965, 0,
            1, 8, 1, /* 1054: pointer.struct.ASN1_VALUE_st */
            	1059, 0,
            0, 0, 0, /* 1059: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1062: pointer.struct.asn1_type_st */
            	1067, 0,
            0, 16, 1, /* 1067: struct.asn1_type_st */
            	1072, 8,
            0, 8, 20, /* 1072: union.unknown */
            	254, 0,
            	1115, 0,
            	860, 0,
            	1125, 0,
            	1130, 0,
            	1135, 0,
            	1140, 0,
            	1145, 0,
            	1150, 0,
            	1155, 0,
            	1160, 0,
            	1165, 0,
            	1170, 0,
            	1175, 0,
            	1180, 0,
            	1185, 0,
            	1190, 0,
            	1115, 0,
            	1115, 0,
            	1195, 0,
            1, 8, 1, /* 1115: pointer.struct.asn1_string_st */
            	1120, 0,
            0, 24, 1, /* 1120: struct.asn1_string_st */
            	162, 8,
            1, 8, 1, /* 1125: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1130: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1135: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1140: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1145: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1150: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1155: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1160: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1165: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1170: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1175: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1180: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1185: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1190: pointer.struct.asn1_string_st */
            	1120, 0,
            1, 8, 1, /* 1195: pointer.struct.ASN1_VALUE_st */
            	1200, 0,
            0, 0, 0, /* 1200: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1203: pointer.struct.stack_st_X509_EXTENSION */
            	1208, 0,
            0, 32, 2, /* 1208: struct.stack_st_fake_X509_EXTENSION */
            	1215, 8,
            	414, 24,
            8884099, 8, 2, /* 1215: pointer_to_array_of_pointers_to_stack */
            	1222, 0,
            	411, 20,
            0, 8, 1, /* 1222: pointer.X509_EXTENSION */
            	1227, 0,
            0, 0, 1, /* 1227: X509_EXTENSION */
            	1232, 0,
            0, 24, 2, /* 1232: struct.X509_extension_st */
            	1239, 0,
            	1253, 16,
            1, 8, 1, /* 1239: pointer.struct.asn1_object_st */
            	1244, 0,
            0, 40, 3, /* 1244: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	196, 24,
            1, 8, 1, /* 1253: pointer.struct.asn1_string_st */
            	1258, 0,
            0, 24, 1, /* 1258: struct.asn1_string_st */
            	162, 8,
            0, 24, 1, /* 1263: struct.ASN1_ENCODING_st */
            	162, 0,
            1, 8, 1, /* 1268: pointer.struct.AUTHORITY_KEYID_st */
            	1273, 0,
            0, 0, 0, /* 1273: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1276: pointer.struct.X509_POLICY_CACHE_st */
            	1281, 0,
            0, 0, 0, /* 1281: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1284: pointer.struct.stack_st_DIST_POINT */
            	1289, 0,
            0, 32, 2, /* 1289: struct.stack_st_fake_DIST_POINT */
            	1296, 8,
            	414, 24,
            8884099, 8, 2, /* 1296: pointer_to_array_of_pointers_to_stack */
            	1303, 0,
            	411, 20,
            0, 8, 1, /* 1303: pointer.DIST_POINT */
            	1308, 0,
            0, 0, 1, /* 1308: DIST_POINT */
            	1313, 0,
            0, 32, 3, /* 1313: struct.DIST_POINT_st */
            	1322, 0,
            	1683, 8,
            	1341, 16,
            1, 8, 1, /* 1322: pointer.struct.DIST_POINT_NAME_st */
            	1327, 0,
            0, 24, 2, /* 1327: struct.DIST_POINT_NAME_st */
            	1334, 8,
            	1659, 16,
            0, 8, 2, /* 1334: union.unknown */
            	1341, 0,
            	1635, 0,
            1, 8, 1, /* 1341: pointer.struct.stack_st_GENERAL_NAME */
            	1346, 0,
            0, 32, 2, /* 1346: struct.stack_st_fake_GENERAL_NAME */
            	1353, 8,
            	414, 24,
            8884099, 8, 2, /* 1353: pointer_to_array_of_pointers_to_stack */
            	1360, 0,
            	411, 20,
            0, 8, 1, /* 1360: pointer.GENERAL_NAME */
            	1365, 0,
            0, 0, 1, /* 1365: GENERAL_NAME */
            	1370, 0,
            0, 16, 1, /* 1370: struct.GENERAL_NAME_st */
            	1375, 8,
            0, 8, 15, /* 1375: union.unknown */
            	254, 0,
            	1408, 0,
            	1527, 0,
            	1527, 0,
            	1434, 0,
            	1575, 0,
            	1623, 0,
            	1527, 0,
            	1512, 0,
            	1420, 0,
            	1512, 0,
            	1575, 0,
            	1527, 0,
            	1420, 0,
            	1434, 0,
            1, 8, 1, /* 1408: pointer.struct.otherName_st */
            	1413, 0,
            0, 16, 2, /* 1413: struct.otherName_st */
            	1420, 0,
            	1434, 8,
            1, 8, 1, /* 1420: pointer.struct.asn1_object_st */
            	1425, 0,
            0, 40, 3, /* 1425: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	196, 24,
            1, 8, 1, /* 1434: pointer.struct.asn1_type_st */
            	1439, 0,
            0, 16, 1, /* 1439: struct.asn1_type_st */
            	1444, 8,
            0, 8, 20, /* 1444: union.unknown */
            	254, 0,
            	1487, 0,
            	1420, 0,
            	1497, 0,
            	1502, 0,
            	1507, 0,
            	1512, 0,
            	1517, 0,
            	1522, 0,
            	1527, 0,
            	1532, 0,
            	1537, 0,
            	1542, 0,
            	1547, 0,
            	1552, 0,
            	1557, 0,
            	1562, 0,
            	1487, 0,
            	1487, 0,
            	1567, 0,
            1, 8, 1, /* 1487: pointer.struct.asn1_string_st */
            	1492, 0,
            0, 24, 1, /* 1492: struct.asn1_string_st */
            	162, 8,
            1, 8, 1, /* 1497: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1502: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1507: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1512: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1517: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1522: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1527: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1532: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1537: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1542: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1547: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1552: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1557: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1562: pointer.struct.asn1_string_st */
            	1492, 0,
            1, 8, 1, /* 1567: pointer.struct.ASN1_VALUE_st */
            	1572, 0,
            0, 0, 0, /* 1572: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1575: pointer.struct.X509_name_st */
            	1580, 0,
            0, 40, 3, /* 1580: struct.X509_name_st */
            	1589, 0,
            	1613, 16,
            	162, 24,
            1, 8, 1, /* 1589: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1594, 0,
            0, 32, 2, /* 1594: struct.stack_st_fake_X509_NAME_ENTRY */
            	1601, 8,
            	414, 24,
            8884099, 8, 2, /* 1601: pointer_to_array_of_pointers_to_stack */
            	1608, 0,
            	411, 20,
            0, 8, 1, /* 1608: pointer.X509_NAME_ENTRY */
            	375, 0,
            1, 8, 1, /* 1613: pointer.struct.buf_mem_st */
            	1618, 0,
            0, 24, 1, /* 1618: struct.buf_mem_st */
            	254, 8,
            1, 8, 1, /* 1623: pointer.struct.EDIPartyName_st */
            	1628, 0,
            0, 16, 2, /* 1628: struct.EDIPartyName_st */
            	1487, 0,
            	1487, 8,
            1, 8, 1, /* 1635: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1640, 0,
            0, 32, 2, /* 1640: struct.stack_st_fake_X509_NAME_ENTRY */
            	1647, 8,
            	414, 24,
            8884099, 8, 2, /* 1647: pointer_to_array_of_pointers_to_stack */
            	1654, 0,
            	411, 20,
            0, 8, 1, /* 1654: pointer.X509_NAME_ENTRY */
            	375, 0,
            1, 8, 1, /* 1659: pointer.struct.X509_name_st */
            	1664, 0,
            0, 40, 3, /* 1664: struct.X509_name_st */
            	1635, 0,
            	1673, 16,
            	162, 24,
            1, 8, 1, /* 1673: pointer.struct.buf_mem_st */
            	1678, 0,
            0, 24, 1, /* 1678: struct.buf_mem_st */
            	254, 8,
            1, 8, 1, /* 1683: pointer.struct.asn1_string_st */
            	1688, 0,
            0, 24, 1, /* 1688: struct.asn1_string_st */
            	162, 8,
            1, 8, 1, /* 1693: pointer.struct.stack_st_GENERAL_NAME */
            	1698, 0,
            0, 32, 2, /* 1698: struct.stack_st_fake_GENERAL_NAME */
            	1705, 8,
            	414, 24,
            8884099, 8, 2, /* 1705: pointer_to_array_of_pointers_to_stack */
            	1712, 0,
            	411, 20,
            0, 8, 1, /* 1712: pointer.GENERAL_NAME */
            	1365, 0,
            1, 8, 1, /* 1717: pointer.struct.NAME_CONSTRAINTS_st */
            	1722, 0,
            0, 0, 0, /* 1722: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 1725: pointer.struct.x509_cert_aux_st */
            	1730, 0,
            0, 40, 5, /* 1730: struct.x509_cert_aux_st */
            	1743, 0,
            	1743, 8,
            	324, 16,
            	274, 24,
            	1781, 32,
            1, 8, 1, /* 1743: pointer.struct.stack_st_ASN1_OBJECT */
            	1748, 0,
            0, 32, 2, /* 1748: struct.stack_st_fake_ASN1_OBJECT */
            	1755, 8,
            	414, 24,
            8884099, 8, 2, /* 1755: pointer_to_array_of_pointers_to_stack */
            	1762, 0,
            	411, 20,
            0, 8, 1, /* 1762: pointer.ASN1_OBJECT */
            	1767, 0,
            0, 0, 1, /* 1767: ASN1_OBJECT */
            	1772, 0,
            0, 40, 3, /* 1772: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	196, 24,
            1, 8, 1, /* 1781: pointer.struct.stack_st_X509_ALGOR */
            	1786, 0,
            0, 32, 2, /* 1786: struct.stack_st_fake_X509_ALGOR */
            	1793, 8,
            	414, 24,
            8884099, 8, 2, /* 1793: pointer_to_array_of_pointers_to_stack */
            	1800, 0,
            	411, 20,
            0, 8, 1, /* 1800: pointer.X509_ALGOR */
            	1805, 0,
            0, 0, 1, /* 1805: X509_ALGOR */
            	1810, 0,
            0, 16, 2, /* 1810: struct.X509_algor_st */
            	1817, 0,
            	1831, 8,
            1, 8, 1, /* 1817: pointer.struct.asn1_object_st */
            	1822, 0,
            0, 40, 3, /* 1822: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	196, 24,
            1, 8, 1, /* 1831: pointer.struct.asn1_type_st */
            	1836, 0,
            0, 16, 1, /* 1836: struct.asn1_type_st */
            	1841, 8,
            0, 8, 20, /* 1841: union.unknown */
            	254, 0,
            	1884, 0,
            	1817, 0,
            	1894, 0,
            	1899, 0,
            	1904, 0,
            	1909, 0,
            	1914, 0,
            	1919, 0,
            	1924, 0,
            	1929, 0,
            	1934, 0,
            	1939, 0,
            	1944, 0,
            	1949, 0,
            	1954, 0,
            	1959, 0,
            	1884, 0,
            	1884, 0,
            	1195, 0,
            1, 8, 1, /* 1884: pointer.struct.asn1_string_st */
            	1889, 0,
            0, 24, 1, /* 1889: struct.asn1_string_st */
            	162, 8,
            1, 8, 1, /* 1894: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1899: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1904: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1909: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1914: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1919: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1924: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1929: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1934: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1939: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1944: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1949: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1954: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1959: pointer.struct.asn1_string_st */
            	1889, 0,
            1, 8, 1, /* 1964: pointer.struct.env_md_st */
            	1969, 0,
            0, 120, 8, /* 1969: struct.env_md_st */
            	1988, 24,
            	1991, 32,
            	1994, 40,
            	1997, 48,
            	1988, 56,
            	2000, 64,
            	2003, 72,
            	2006, 112,
            8884097, 8, 0, /* 1988: pointer.func */
            8884097, 8, 0, /* 1991: pointer.func */
            8884097, 8, 0, /* 1994: pointer.func */
            8884097, 8, 0, /* 1997: pointer.func */
            8884097, 8, 0, /* 2000: pointer.func */
            8884097, 8, 0, /* 2003: pointer.func */
            8884097, 8, 0, /* 2006: pointer.func */
            1, 8, 1, /* 2009: pointer.struct.rsa_st */
            	508, 0,
            1, 8, 1, /* 2014: pointer.struct.dh_st */
            	753, 0,
            1, 8, 1, /* 2019: pointer.struct.ec_key_st */
            	821, 0,
            1, 8, 1, /* 2024: pointer.struct.cert_st */
            	59, 0,
            1, 8, 1, /* 2029: pointer.struct.buf_mem_st */
            	2034, 0,
            0, 24, 1, /* 2034: struct.buf_mem_st */
            	254, 8,
            1, 8, 1, /* 2039: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2044, 0,
            0, 32, 2, /* 2044: struct.stack_st_fake_X509_NAME_ENTRY */
            	2051, 8,
            	414, 24,
            8884099, 8, 2, /* 2051: pointer_to_array_of_pointers_to_stack */
            	2058, 0,
            	411, 20,
            0, 8, 1, /* 2058: pointer.X509_NAME_ENTRY */
            	375, 0,
            0, 40, 3, /* 2063: struct.X509_name_st */
            	2039, 0,
            	2029, 16,
            	162, 24,
            8884097, 8, 0, /* 2072: pointer.func */
            8884097, 8, 0, /* 2075: pointer.func */
            8884097, 8, 0, /* 2078: pointer.func */
            0, 64, 7, /* 2081: struct.comp_method_st */
            	5, 8,
            	2078, 16,
            	2075, 24,
            	2098, 32,
            	2098, 40,
            	2101, 48,
            	2101, 56,
            8884097, 8, 0, /* 2098: pointer.func */
            8884097, 8, 0, /* 2101: pointer.func */
            1, 8, 1, /* 2104: pointer.struct.comp_method_st */
            	2081, 0,
            0, 0, 1, /* 2109: SSL_COMP */
            	2114, 0,
            0, 24, 2, /* 2114: struct.ssl_comp_st */
            	5, 8,
            	2104, 16,
            1, 8, 1, /* 2121: pointer.struct.stack_st_SSL_COMP */
            	2126, 0,
            0, 32, 2, /* 2126: struct.stack_st_fake_SSL_COMP */
            	2133, 8,
            	414, 24,
            8884099, 8, 2, /* 2133: pointer_to_array_of_pointers_to_stack */
            	2140, 0,
            	411, 20,
            0, 8, 1, /* 2140: pointer.SSL_COMP */
            	2109, 0,
            8884097, 8, 0, /* 2145: pointer.func */
            8884097, 8, 0, /* 2148: pointer.func */
            8884097, 8, 0, /* 2151: pointer.func */
            8884097, 8, 0, /* 2154: pointer.func */
            8884097, 8, 0, /* 2157: pointer.func */
            0, 0, 1, /* 2160: X509_NAME */
            	2063, 0,
            0, 16, 1, /* 2165: struct.crypto_ex_data_st */
            	2170, 0,
            1, 8, 1, /* 2170: pointer.struct.stack_st_void */
            	2175, 0,
            0, 32, 1, /* 2175: struct.stack_st_void */
            	2180, 0,
            0, 32, 2, /* 2180: struct.stack_st */
            	640, 8,
            	414, 24,
            8884097, 8, 0, /* 2187: pointer.func */
            0, 136, 11, /* 2190: struct.dsa_st */
            	2215, 24,
            	2215, 32,
            	2215, 40,
            	2215, 48,
            	2215, 56,
            	2215, 64,
            	2215, 72,
            	2225, 88,
            	2165, 104,
            	2239, 120,
            	2290, 128,
            1, 8, 1, /* 2215: pointer.struct.bignum_st */
            	2220, 0,
            0, 24, 1, /* 2220: struct.bignum_st */
            	610, 0,
            1, 8, 1, /* 2225: pointer.struct.bn_mont_ctx_st */
            	2230, 0,
            0, 96, 3, /* 2230: struct.bn_mont_ctx_st */
            	2220, 8,
            	2220, 32,
            	2220, 56,
            1, 8, 1, /* 2239: pointer.struct.dsa_method */
            	2244, 0,
            0, 96, 11, /* 2244: struct.dsa_method */
            	5, 0,
            	2269, 8,
            	2272, 16,
            	2275, 24,
            	2278, 32,
            	2281, 40,
            	2284, 48,
            	2284, 56,
            	254, 72,
            	2287, 80,
            	2284, 88,
            8884097, 8, 0, /* 2269: pointer.func */
            8884097, 8, 0, /* 2272: pointer.func */
            8884097, 8, 0, /* 2275: pointer.func */
            8884097, 8, 0, /* 2278: pointer.func */
            8884097, 8, 0, /* 2281: pointer.func */
            8884097, 8, 0, /* 2284: pointer.func */
            8884097, 8, 0, /* 2287: pointer.func */
            1, 8, 1, /* 2290: pointer.struct.engine_st */
            	2295, 0,
            0, 0, 0, /* 2295: struct.engine_st */
            8884097, 8, 0, /* 2298: pointer.func */
            1, 8, 1, /* 2301: pointer.struct.X509_crl_info_st */
            	2306, 0,
            0, 80, 8, /* 2306: struct.X509_crl_info_st */
            	2325, 0,
            	2335, 8,
            	2484, 16,
            	2532, 24,
            	2532, 32,
            	2537, 40,
            	2640, 48,
            	2664, 56,
            1, 8, 1, /* 2325: pointer.struct.asn1_string_st */
            	2330, 0,
            0, 24, 1, /* 2330: struct.asn1_string_st */
            	162, 8,
            1, 8, 1, /* 2335: pointer.struct.X509_algor_st */
            	2340, 0,
            0, 16, 2, /* 2340: struct.X509_algor_st */
            	2347, 0,
            	2361, 8,
            1, 8, 1, /* 2347: pointer.struct.asn1_object_st */
            	2352, 0,
            0, 40, 3, /* 2352: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	196, 24,
            1, 8, 1, /* 2361: pointer.struct.asn1_type_st */
            	2366, 0,
            0, 16, 1, /* 2366: struct.asn1_type_st */
            	2371, 8,
            0, 8, 20, /* 2371: union.unknown */
            	254, 0,
            	2414, 0,
            	2347, 0,
            	2325, 0,
            	2419, 0,
            	2424, 0,
            	2429, 0,
            	2434, 0,
            	2439, 0,
            	2444, 0,
            	2449, 0,
            	2454, 0,
            	2459, 0,
            	2464, 0,
            	2469, 0,
            	2474, 0,
            	2479, 0,
            	2414, 0,
            	2414, 0,
            	1195, 0,
            1, 8, 1, /* 2414: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2419: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2424: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2429: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2434: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2439: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2444: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2449: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2454: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2459: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2464: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2469: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2474: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2479: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2484: pointer.struct.X509_name_st */
            	2489, 0,
            0, 40, 3, /* 2489: struct.X509_name_st */
            	2498, 0,
            	2522, 16,
            	162, 24,
            1, 8, 1, /* 2498: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2503, 0,
            0, 32, 2, /* 2503: struct.stack_st_fake_X509_NAME_ENTRY */
            	2510, 8,
            	414, 24,
            8884099, 8, 2, /* 2510: pointer_to_array_of_pointers_to_stack */
            	2517, 0,
            	411, 20,
            0, 8, 1, /* 2517: pointer.X509_NAME_ENTRY */
            	375, 0,
            1, 8, 1, /* 2522: pointer.struct.buf_mem_st */
            	2527, 0,
            0, 24, 1, /* 2527: struct.buf_mem_st */
            	254, 8,
            1, 8, 1, /* 2532: pointer.struct.asn1_string_st */
            	2330, 0,
            1, 8, 1, /* 2537: pointer.struct.stack_st_X509_REVOKED */
            	2542, 0,
            0, 32, 2, /* 2542: struct.stack_st_fake_X509_REVOKED */
            	2549, 8,
            	414, 24,
            8884099, 8, 2, /* 2549: pointer_to_array_of_pointers_to_stack */
            	2556, 0,
            	411, 20,
            0, 8, 1, /* 2556: pointer.X509_REVOKED */
            	2561, 0,
            0, 0, 1, /* 2561: X509_REVOKED */
            	2566, 0,
            0, 40, 4, /* 2566: struct.x509_revoked_st */
            	2577, 0,
            	2587, 8,
            	2592, 16,
            	2616, 24,
            1, 8, 1, /* 2577: pointer.struct.asn1_string_st */
            	2582, 0,
            0, 24, 1, /* 2582: struct.asn1_string_st */
            	162, 8,
            1, 8, 1, /* 2587: pointer.struct.asn1_string_st */
            	2582, 0,
            1, 8, 1, /* 2592: pointer.struct.stack_st_X509_EXTENSION */
            	2597, 0,
            0, 32, 2, /* 2597: struct.stack_st_fake_X509_EXTENSION */
            	2604, 8,
            	414, 24,
            8884099, 8, 2, /* 2604: pointer_to_array_of_pointers_to_stack */
            	2611, 0,
            	411, 20,
            0, 8, 1, /* 2611: pointer.X509_EXTENSION */
            	1227, 0,
            1, 8, 1, /* 2616: pointer.struct.stack_st_GENERAL_NAME */
            	2621, 0,
            0, 32, 2, /* 2621: struct.stack_st_fake_GENERAL_NAME */
            	2628, 8,
            	414, 24,
            8884099, 8, 2, /* 2628: pointer_to_array_of_pointers_to_stack */
            	2635, 0,
            	411, 20,
            0, 8, 1, /* 2635: pointer.GENERAL_NAME */
            	1365, 0,
            1, 8, 1, /* 2640: pointer.struct.stack_st_X509_EXTENSION */
            	2645, 0,
            0, 32, 2, /* 2645: struct.stack_st_fake_X509_EXTENSION */
            	2652, 8,
            	414, 24,
            8884099, 8, 2, /* 2652: pointer_to_array_of_pointers_to_stack */
            	2659, 0,
            	411, 20,
            0, 8, 1, /* 2659: pointer.X509_EXTENSION */
            	1227, 0,
            0, 24, 1, /* 2664: struct.ASN1_ENCODING_st */
            	162, 0,
            8884097, 8, 0, /* 2669: pointer.func */
            1, 8, 1, /* 2672: pointer.struct.stack_st_DIST_POINT */
            	2677, 0,
            0, 32, 2, /* 2677: struct.stack_st_fake_DIST_POINT */
            	2684, 8,
            	414, 24,
            8884099, 8, 2, /* 2684: pointer_to_array_of_pointers_to_stack */
            	2691, 0,
            	411, 20,
            0, 8, 1, /* 2691: pointer.DIST_POINT */
            	1308, 0,
            1, 8, 1, /* 2696: pointer.struct.X509_POLICY_CACHE_st */
            	2701, 0,
            0, 0, 0, /* 2701: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2704: struct.AUTHORITY_KEYID_st */
            0, 0, 0, /* 2707: struct.ec_key_st */
            1, 8, 1, /* 2710: pointer.struct.AUTHORITY_KEYID_st */
            	2704, 0,
            8884097, 8, 0, /* 2715: pointer.func */
            8884097, 8, 0, /* 2718: pointer.func */
            0, 104, 11, /* 2721: struct.x509_cinf_st */
            	2746, 0,
            	2746, 8,
            	2756, 16,
            	2913, 24,
            	2961, 32,
            	2913, 40,
            	2978, 48,
            	2845, 56,
            	2845, 64,
            	3366, 72,
            	3390, 80,
            1, 8, 1, /* 2746: pointer.struct.asn1_string_st */
            	2751, 0,
            0, 24, 1, /* 2751: struct.asn1_string_st */
            	162, 8,
            1, 8, 1, /* 2756: pointer.struct.X509_algor_st */
            	2761, 0,
            0, 16, 2, /* 2761: struct.X509_algor_st */
            	2768, 0,
            	2782, 8,
            1, 8, 1, /* 2768: pointer.struct.asn1_object_st */
            	2773, 0,
            0, 40, 3, /* 2773: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	196, 24,
            1, 8, 1, /* 2782: pointer.struct.asn1_type_st */
            	2787, 0,
            0, 16, 1, /* 2787: struct.asn1_type_st */
            	2792, 8,
            0, 8, 20, /* 2792: union.unknown */
            	254, 0,
            	2835, 0,
            	2768, 0,
            	2746, 0,
            	2840, 0,
            	2845, 0,
            	2850, 0,
            	2855, 0,
            	2860, 0,
            	2865, 0,
            	2870, 0,
            	2875, 0,
            	2880, 0,
            	2885, 0,
            	2890, 0,
            	2895, 0,
            	2900, 0,
            	2835, 0,
            	2835, 0,
            	2905, 0,
            1, 8, 1, /* 2835: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2840: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2845: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2850: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2855: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2860: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2865: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2870: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2875: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2880: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2885: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2890: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2895: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2900: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2905: pointer.struct.ASN1_VALUE_st */
            	2910, 0,
            0, 0, 0, /* 2910: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2913: pointer.struct.X509_name_st */
            	2918, 0,
            0, 40, 3, /* 2918: struct.X509_name_st */
            	2927, 0,
            	2951, 16,
            	162, 24,
            1, 8, 1, /* 2927: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2932, 0,
            0, 32, 2, /* 2932: struct.stack_st_fake_X509_NAME_ENTRY */
            	2939, 8,
            	414, 24,
            8884099, 8, 2, /* 2939: pointer_to_array_of_pointers_to_stack */
            	2946, 0,
            	411, 20,
            0, 8, 1, /* 2946: pointer.X509_NAME_ENTRY */
            	375, 0,
            1, 8, 1, /* 2951: pointer.struct.buf_mem_st */
            	2956, 0,
            0, 24, 1, /* 2956: struct.buf_mem_st */
            	254, 8,
            1, 8, 1, /* 2961: pointer.struct.X509_val_st */
            	2966, 0,
            0, 16, 2, /* 2966: struct.X509_val_st */
            	2973, 0,
            	2973, 8,
            1, 8, 1, /* 2973: pointer.struct.asn1_string_st */
            	2751, 0,
            1, 8, 1, /* 2978: pointer.struct.X509_pubkey_st */
            	2983, 0,
            0, 24, 3, /* 2983: struct.X509_pubkey_st */
            	2756, 0,
            	2845, 8,
            	2992, 16,
            1, 8, 1, /* 2992: pointer.struct.evp_pkey_st */
            	2997, 0,
            0, 56, 4, /* 2997: struct.evp_pkey_st */
            	3008, 16,
            	3016, 24,
            	3024, 32,
            	3342, 48,
            1, 8, 1, /* 3008: pointer.struct.evp_pkey_asn1_method_st */
            	3013, 0,
            0, 0, 0, /* 3013: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3016: pointer.struct.engine_st */
            	3021, 0,
            0, 0, 0, /* 3021: struct.engine_st */
            0, 8, 5, /* 3024: union.unknown */
            	254, 0,
            	3037, 0,
            	3188, 0,
            	3266, 0,
            	3334, 0,
            1, 8, 1, /* 3037: pointer.struct.rsa_st */
            	3042, 0,
            0, 168, 17, /* 3042: struct.rsa_st */
            	3079, 16,
            	3016, 24,
            	3134, 32,
            	3134, 40,
            	3134, 48,
            	3134, 56,
            	3134, 64,
            	3134, 72,
            	3134, 80,
            	3134, 88,
            	3144, 96,
            	3166, 120,
            	3166, 128,
            	3166, 136,
            	254, 144,
            	3180, 152,
            	3180, 160,
            1, 8, 1, /* 3079: pointer.struct.rsa_meth_st */
            	3084, 0,
            0, 112, 13, /* 3084: struct.rsa_meth_st */
            	5, 0,
            	3113, 8,
            	3113, 16,
            	3113, 24,
            	3113, 32,
            	3116, 40,
            	3119, 48,
            	3122, 56,
            	3122, 64,
            	254, 80,
            	3125, 88,
            	3128, 96,
            	3131, 104,
            8884097, 8, 0, /* 3113: pointer.func */
            8884097, 8, 0, /* 3116: pointer.func */
            8884097, 8, 0, /* 3119: pointer.func */
            8884097, 8, 0, /* 3122: pointer.func */
            8884097, 8, 0, /* 3125: pointer.func */
            8884097, 8, 0, /* 3128: pointer.func */
            8884097, 8, 0, /* 3131: pointer.func */
            1, 8, 1, /* 3134: pointer.struct.bignum_st */
            	3139, 0,
            0, 24, 1, /* 3139: struct.bignum_st */
            	610, 0,
            0, 16, 1, /* 3144: struct.crypto_ex_data_st */
            	3149, 0,
            1, 8, 1, /* 3149: pointer.struct.stack_st_void */
            	3154, 0,
            0, 32, 1, /* 3154: struct.stack_st_void */
            	3159, 0,
            0, 32, 2, /* 3159: struct.stack_st */
            	640, 8,
            	414, 24,
            1, 8, 1, /* 3166: pointer.struct.bn_mont_ctx_st */
            	3171, 0,
            0, 96, 3, /* 3171: struct.bn_mont_ctx_st */
            	3139, 8,
            	3139, 32,
            	3139, 56,
            1, 8, 1, /* 3180: pointer.struct.bn_blinding_st */
            	3185, 0,
            0, 0, 0, /* 3185: struct.bn_blinding_st */
            1, 8, 1, /* 3188: pointer.struct.dsa_st */
            	3193, 0,
            0, 136, 11, /* 3193: struct.dsa_st */
            	3134, 24,
            	3134, 32,
            	3134, 40,
            	3134, 48,
            	3134, 56,
            	3134, 64,
            	3134, 72,
            	3166, 88,
            	3144, 104,
            	3218, 120,
            	3016, 128,
            1, 8, 1, /* 3218: pointer.struct.dsa_method */
            	3223, 0,
            0, 96, 11, /* 3223: struct.dsa_method */
            	5, 0,
            	3248, 8,
            	3251, 16,
            	3254, 24,
            	2718, 32,
            	3257, 40,
            	3260, 48,
            	3260, 56,
            	254, 72,
            	3263, 80,
            	3260, 88,
            8884097, 8, 0, /* 3248: pointer.func */
            8884097, 8, 0, /* 3251: pointer.func */
            8884097, 8, 0, /* 3254: pointer.func */
            8884097, 8, 0, /* 3257: pointer.func */
            8884097, 8, 0, /* 3260: pointer.func */
            8884097, 8, 0, /* 3263: pointer.func */
            1, 8, 1, /* 3266: pointer.struct.dh_st */
            	3271, 0,
            0, 144, 12, /* 3271: struct.dh_st */
            	3134, 8,
            	3134, 16,
            	3134, 32,
            	3134, 40,
            	3166, 56,
            	3134, 64,
            	3134, 72,
            	162, 80,
            	3134, 96,
            	3144, 112,
            	3298, 128,
            	3016, 136,
            1, 8, 1, /* 3298: pointer.struct.dh_method */
            	3303, 0,
            0, 72, 8, /* 3303: struct.dh_method */
            	5, 0,
            	3322, 8,
            	3325, 16,
            	3328, 24,
            	3322, 32,
            	3322, 40,
            	254, 56,
            	3331, 64,
            8884097, 8, 0, /* 3322: pointer.func */
            8884097, 8, 0, /* 3325: pointer.func */
            8884097, 8, 0, /* 3328: pointer.func */
            8884097, 8, 0, /* 3331: pointer.func */
            1, 8, 1, /* 3334: pointer.struct.ec_key_st */
            	3339, 0,
            0, 0, 0, /* 3339: struct.ec_key_st */
            1, 8, 1, /* 3342: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3347, 0,
            0, 32, 2, /* 3347: struct.stack_st_fake_X509_ATTRIBUTE */
            	3354, 8,
            	414, 24,
            8884099, 8, 2, /* 3354: pointer_to_array_of_pointers_to_stack */
            	3361, 0,
            	411, 20,
            0, 8, 1, /* 3361: pointer.X509_ATTRIBUTE */
            	848, 0,
            1, 8, 1, /* 3366: pointer.struct.stack_st_X509_EXTENSION */
            	3371, 0,
            0, 32, 2, /* 3371: struct.stack_st_fake_X509_EXTENSION */
            	3378, 8,
            	414, 24,
            8884099, 8, 2, /* 3378: pointer_to_array_of_pointers_to_stack */
            	3385, 0,
            	411, 20,
            0, 8, 1, /* 3385: pointer.X509_EXTENSION */
            	1227, 0,
            0, 24, 1, /* 3390: struct.ASN1_ENCODING_st */
            	162, 0,
            0, 0, 0, /* 3395: struct.X509_POLICY_CACHE_st */
            8884097, 8, 0, /* 3398: pointer.func */
            1, 8, 1, /* 3401: pointer.struct.ssl_cipher_st */
            	3406, 0,
            0, 88, 1, /* 3406: struct.ssl_cipher_st */
            	5, 8,
            8884097, 8, 0, /* 3411: pointer.func */
            0, 184, 12, /* 3414: struct.x509_st */
            	3441, 0,
            	2335, 8,
            	2424, 16,
            	254, 32,
            	2165, 40,
            	2429, 104,
            	2710, 112,
            	2696, 120,
            	2672, 128,
            	3738, 136,
            	3762, 144,
            	3770, 176,
            1, 8, 1, /* 3441: pointer.struct.x509_cinf_st */
            	3446, 0,
            0, 104, 11, /* 3446: struct.x509_cinf_st */
            	2325, 0,
            	2325, 8,
            	2335, 16,
            	2484, 24,
            	3471, 32,
            	2484, 40,
            	3483, 48,
            	2424, 56,
            	2424, 64,
            	2640, 72,
            	2664, 80,
            1, 8, 1, /* 3471: pointer.struct.X509_val_st */
            	3476, 0,
            0, 16, 2, /* 3476: struct.X509_val_st */
            	2532, 0,
            	2532, 8,
            1, 8, 1, /* 3483: pointer.struct.X509_pubkey_st */
            	3488, 0,
            0, 24, 3, /* 3488: struct.X509_pubkey_st */
            	2335, 0,
            	2424, 8,
            	3497, 16,
            1, 8, 1, /* 3497: pointer.struct.evp_pkey_st */
            	3502, 0,
            0, 56, 4, /* 3502: struct.evp_pkey_st */
            	3513, 16,
            	2290, 24,
            	3521, 32,
            	3714, 48,
            1, 8, 1, /* 3513: pointer.struct.evp_pkey_asn1_method_st */
            	3518, 0,
            0, 0, 0, /* 3518: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3521: union.unknown */
            	254, 0,
            	3534, 0,
            	3636, 0,
            	3641, 0,
            	3709, 0,
            1, 8, 1, /* 3534: pointer.struct.rsa_st */
            	3539, 0,
            0, 168, 17, /* 3539: struct.rsa_st */
            	3576, 16,
            	2290, 24,
            	2215, 32,
            	2215, 40,
            	2215, 48,
            	2215, 56,
            	2215, 64,
            	2215, 72,
            	2215, 80,
            	2215, 88,
            	2165, 96,
            	2225, 120,
            	2225, 128,
            	2225, 136,
            	254, 144,
            	3628, 152,
            	3628, 160,
            1, 8, 1, /* 3576: pointer.struct.rsa_meth_st */
            	3581, 0,
            0, 112, 13, /* 3581: struct.rsa_meth_st */
            	5, 0,
            	3610, 8,
            	3610, 16,
            	3610, 24,
            	3610, 32,
            	3613, 40,
            	3616, 48,
            	3411, 56,
            	3411, 64,
            	254, 80,
            	3619, 88,
            	3622, 96,
            	3625, 104,
            8884097, 8, 0, /* 3610: pointer.func */
            8884097, 8, 0, /* 3613: pointer.func */
            8884097, 8, 0, /* 3616: pointer.func */
            8884097, 8, 0, /* 3619: pointer.func */
            8884097, 8, 0, /* 3622: pointer.func */
            8884097, 8, 0, /* 3625: pointer.func */
            1, 8, 1, /* 3628: pointer.struct.bn_blinding_st */
            	3633, 0,
            0, 0, 0, /* 3633: struct.bn_blinding_st */
            1, 8, 1, /* 3636: pointer.struct.dsa_st */
            	2190, 0,
            1, 8, 1, /* 3641: pointer.struct.dh_st */
            	3646, 0,
            0, 144, 12, /* 3646: struct.dh_st */
            	2215, 8,
            	2215, 16,
            	2215, 32,
            	2215, 40,
            	2225, 56,
            	2215, 64,
            	2215, 72,
            	162, 80,
            	2215, 96,
            	2165, 112,
            	3673, 128,
            	2290, 136,
            1, 8, 1, /* 3673: pointer.struct.dh_method */
            	3678, 0,
            0, 72, 8, /* 3678: struct.dh_method */
            	5, 0,
            	3697, 8,
            	3700, 16,
            	3703, 24,
            	3697, 32,
            	3697, 40,
            	254, 56,
            	3706, 64,
            8884097, 8, 0, /* 3697: pointer.func */
            8884097, 8, 0, /* 3700: pointer.func */
            8884097, 8, 0, /* 3703: pointer.func */
            8884097, 8, 0, /* 3706: pointer.func */
            1, 8, 1, /* 3709: pointer.struct.ec_key_st */
            	2707, 0,
            1, 8, 1, /* 3714: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3719, 0,
            0, 32, 2, /* 3719: struct.stack_st_fake_X509_ATTRIBUTE */
            	3726, 8,
            	414, 24,
            8884099, 8, 2, /* 3726: pointer_to_array_of_pointers_to_stack */
            	3733, 0,
            	411, 20,
            0, 8, 1, /* 3733: pointer.X509_ATTRIBUTE */
            	848, 0,
            1, 8, 1, /* 3738: pointer.struct.stack_st_GENERAL_NAME */
            	3743, 0,
            0, 32, 2, /* 3743: struct.stack_st_fake_GENERAL_NAME */
            	3750, 8,
            	414, 24,
            8884099, 8, 2, /* 3750: pointer_to_array_of_pointers_to_stack */
            	3757, 0,
            	411, 20,
            0, 8, 1, /* 3757: pointer.GENERAL_NAME */
            	1365, 0,
            1, 8, 1, /* 3762: pointer.struct.NAME_CONSTRAINTS_st */
            	3767, 0,
            0, 0, 0, /* 3767: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3770: pointer.struct.x509_cert_aux_st */
            	3775, 0,
            0, 40, 5, /* 3775: struct.x509_cert_aux_st */
            	3788, 0,
            	3788, 8,
            	2479, 16,
            	2429, 24,
            	3812, 32,
            1, 8, 1, /* 3788: pointer.struct.stack_st_ASN1_OBJECT */
            	3793, 0,
            0, 32, 2, /* 3793: struct.stack_st_fake_ASN1_OBJECT */
            	3800, 8,
            	414, 24,
            8884099, 8, 2, /* 3800: pointer_to_array_of_pointers_to_stack */
            	3807, 0,
            	411, 20,
            0, 8, 1, /* 3807: pointer.ASN1_OBJECT */
            	1767, 0,
            1, 8, 1, /* 3812: pointer.struct.stack_st_X509_ALGOR */
            	3817, 0,
            0, 32, 2, /* 3817: struct.stack_st_fake_X509_ALGOR */
            	3824, 8,
            	414, 24,
            8884099, 8, 2, /* 3824: pointer_to_array_of_pointers_to_stack */
            	3831, 0,
            	411, 20,
            0, 8, 1, /* 3831: pointer.X509_ALGOR */
            	1805, 0,
            8884097, 8, 0, /* 3836: pointer.func */
            1, 8, 1, /* 3839: pointer.struct.sess_cert_st */
            	3844, 0,
            0, 248, 5, /* 3844: struct.sess_cert_st */
            	3857, 0,
            	76, 16,
            	2009, 216,
            	2014, 224,
            	2019, 232,
            1, 8, 1, /* 3857: pointer.struct.stack_st_X509 */
            	3862, 0,
            0, 32, 2, /* 3862: struct.stack_st_fake_X509 */
            	3869, 8,
            	414, 24,
            8884099, 8, 2, /* 3869: pointer_to_array_of_pointers_to_stack */
            	3876, 0,
            	411, 20,
            0, 8, 1, /* 3876: pointer.X509 */
            	3881, 0,
            0, 0, 1, /* 3881: X509 */
            	3886, 0,
            0, 184, 12, /* 3886: struct.x509_st */
            	3913, 0,
            	2756, 8,
            	2845, 16,
            	254, 32,
            	3144, 40,
            	2850, 104,
            	3918, 112,
            	3926, 120,
            	3931, 128,
            	3955, 136,
            	3979, 144,
            	3987, 176,
            1, 8, 1, /* 3913: pointer.struct.x509_cinf_st */
            	2721, 0,
            1, 8, 1, /* 3918: pointer.struct.AUTHORITY_KEYID_st */
            	3923, 0,
            0, 0, 0, /* 3923: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3926: pointer.struct.X509_POLICY_CACHE_st */
            	3395, 0,
            1, 8, 1, /* 3931: pointer.struct.stack_st_DIST_POINT */
            	3936, 0,
            0, 32, 2, /* 3936: struct.stack_st_fake_DIST_POINT */
            	3943, 8,
            	414, 24,
            8884099, 8, 2, /* 3943: pointer_to_array_of_pointers_to_stack */
            	3950, 0,
            	411, 20,
            0, 8, 1, /* 3950: pointer.DIST_POINT */
            	1308, 0,
            1, 8, 1, /* 3955: pointer.struct.stack_st_GENERAL_NAME */
            	3960, 0,
            0, 32, 2, /* 3960: struct.stack_st_fake_GENERAL_NAME */
            	3967, 8,
            	414, 24,
            8884099, 8, 2, /* 3967: pointer_to_array_of_pointers_to_stack */
            	3974, 0,
            	411, 20,
            0, 8, 1, /* 3974: pointer.GENERAL_NAME */
            	1365, 0,
            1, 8, 1, /* 3979: pointer.struct.NAME_CONSTRAINTS_st */
            	3984, 0,
            0, 0, 0, /* 3984: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3987: pointer.struct.x509_cert_aux_st */
            	3992, 0,
            0, 40, 5, /* 3992: struct.x509_cert_aux_st */
            	4005, 0,
            	4005, 8,
            	2900, 16,
            	2850, 24,
            	4029, 32,
            1, 8, 1, /* 4005: pointer.struct.stack_st_ASN1_OBJECT */
            	4010, 0,
            0, 32, 2, /* 4010: struct.stack_st_fake_ASN1_OBJECT */
            	4017, 8,
            	414, 24,
            8884099, 8, 2, /* 4017: pointer_to_array_of_pointers_to_stack */
            	4024, 0,
            	411, 20,
            0, 8, 1, /* 4024: pointer.ASN1_OBJECT */
            	1767, 0,
            1, 8, 1, /* 4029: pointer.struct.stack_st_X509_ALGOR */
            	4034, 0,
            0, 32, 2, /* 4034: struct.stack_st_fake_X509_ALGOR */
            	4041, 8,
            	414, 24,
            8884099, 8, 2, /* 4041: pointer_to_array_of_pointers_to_stack */
            	4048, 0,
            	411, 20,
            0, 8, 1, /* 4048: pointer.X509_ALGOR */
            	1805, 0,
            8884097, 8, 0, /* 4053: pointer.func */
            8884097, 8, 0, /* 4056: pointer.func */
            0, 32, 1, /* 4059: struct.stack_st_GENERAL_NAME */
            	4064, 0,
            0, 32, 2, /* 4064: struct.stack_st */
            	640, 8,
            	414, 24,
            1, 8, 1, /* 4071: pointer.struct.x509_st */
            	3414, 0,
            0, 0, 1, /* 4076: SSL_CIPHER */
            	4081, 0,
            0, 88, 1, /* 4081: struct.ssl_cipher_st */
            	5, 8,
            8884097, 8, 0, /* 4086: pointer.func */
            8884097, 8, 0, /* 4089: pointer.func */
            8884097, 8, 0, /* 4092: pointer.func */
            8884097, 8, 0, /* 4095: pointer.func */
            8884097, 8, 0, /* 4098: pointer.func */
            8884097, 8, 0, /* 4101: pointer.func */
            1, 8, 1, /* 4104: pointer.struct.ssl_method_st */
            	4109, 0,
            0, 232, 28, /* 4109: struct.ssl_method_st */
            	4101, 8,
            	4168, 16,
            	4168, 24,
            	4101, 32,
            	4101, 40,
            	4171, 48,
            	4171, 56,
            	4174, 64,
            	4101, 72,
            	4101, 80,
            	4101, 88,
            	4177, 96,
            	2298, 104,
            	4095, 112,
            	4101, 120,
            	4180, 128,
            	4183, 136,
            	4186, 144,
            	4189, 152,
            	4192, 160,
            	4195, 168,
            	4198, 176,
            	4201, 184,
            	2101, 192,
            	4204, 200,
            	4195, 208,
            	4252, 216,
            	4255, 224,
            8884097, 8, 0, /* 4168: pointer.func */
            8884097, 8, 0, /* 4171: pointer.func */
            8884097, 8, 0, /* 4174: pointer.func */
            8884097, 8, 0, /* 4177: pointer.func */
            8884097, 8, 0, /* 4180: pointer.func */
            8884097, 8, 0, /* 4183: pointer.func */
            8884097, 8, 0, /* 4186: pointer.func */
            8884097, 8, 0, /* 4189: pointer.func */
            8884097, 8, 0, /* 4192: pointer.func */
            8884097, 8, 0, /* 4195: pointer.func */
            8884097, 8, 0, /* 4198: pointer.func */
            8884097, 8, 0, /* 4201: pointer.func */
            1, 8, 1, /* 4204: pointer.struct.ssl3_enc_method */
            	4209, 0,
            0, 112, 11, /* 4209: struct.ssl3_enc_method */
            	4234, 0,
            	4237, 8,
            	4101, 16,
            	4240, 24,
            	4234, 32,
            	4086, 40,
            	4243, 56,
            	5, 64,
            	5, 80,
            	4246, 96,
            	4249, 104,
            8884097, 8, 0, /* 4234: pointer.func */
            8884097, 8, 0, /* 4237: pointer.func */
            8884097, 8, 0, /* 4240: pointer.func */
            8884097, 8, 0, /* 4243: pointer.func */
            8884097, 8, 0, /* 4246: pointer.func */
            8884097, 8, 0, /* 4249: pointer.func */
            8884097, 8, 0, /* 4252: pointer.func */
            8884097, 8, 0, /* 4255: pointer.func */
            0, 1, 0, /* 4258: char */
            1, 8, 1, /* 4261: pointer.struct.stack_st_SSL_CIPHER */
            	4266, 0,
            0, 32, 2, /* 4266: struct.stack_st_fake_SSL_CIPHER */
            	4273, 8,
            	414, 24,
            8884099, 8, 2, /* 4273: pointer_to_array_of_pointers_to_stack */
            	4280, 0,
            	411, 20,
            0, 8, 1, /* 4280: pointer.SSL_CIPHER */
            	4076, 0,
            8884097, 8, 0, /* 4285: pointer.func */
            0, 32, 2, /* 4288: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4295, 8,
            	414, 24,
            8884099, 8, 2, /* 4295: pointer_to_array_of_pointers_to_stack */
            	4302, 0,
            	411, 20,
            0, 8, 1, /* 4302: pointer.SRTP_PROTECTION_PROFILE */
            	10, 0,
            0, 352, 14, /* 4307: struct.ssl_session_st */
            	254, 144,
            	254, 152,
            	3839, 168,
            	90, 176,
            	3401, 224,
            	4261, 240,
            	618, 248,
            	4338, 264,
            	4338, 272,
            	254, 280,
            	162, 296,
            	162, 312,
            	162, 320,
            	254, 344,
            1, 8, 1, /* 4338: pointer.struct.ssl_session_st */
            	4307, 0,
            1, 8, 1, /* 4343: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4288, 0,
            0, 736, 50, /* 4348: struct.ssl_ctx_st */
            	4104, 0,
            	4261, 8,
            	4261, 16,
            	4451, 24,
            	4843, 32,
            	4338, 48,
            	4338, 56,
            	4056, 80,
            	3836, 88,
            	2157, 96,
            	2154, 152,
            	4607, 160,
            	4882, 168,
            	4607, 176,
            	2151, 184,
            	2148, 192,
            	2145, 200,
            	618, 208,
            	1964, 224,
            	1964, 232,
            	1964, 240,
            	3857, 248,
            	2121, 256,
            	2072, 264,
            	4885, 272,
            	2024, 304,
            	47, 320,
            	4607, 328,
            	4822, 376,
            	41, 384,
            	4807, 392,
            	482, 408,
            	4909, 416,
            	4607, 424,
            	38, 480,
            	2669, 488,
            	4607, 496,
            	35, 504,
            	4607, 512,
            	254, 520,
            	4053, 528,
            	4912, 536,
            	30, 552,
            	30, 560,
            	4915, 568,
            	4946, 696,
            	4607, 704,
            	44, 712,
            	4607, 720,
            	4343, 728,
            1, 8, 1, /* 4451: pointer.struct.x509_store_st */
            	4456, 0,
            0, 144, 15, /* 4456: struct.x509_store_st */
            	4489, 8,
            	4610, 16,
            	4807, 24,
            	4819, 32,
            	4822, 40,
            	4825, 48,
            	4092, 56,
            	4819, 64,
            	4828, 72,
            	4831, 80,
            	4834, 88,
            	4837, 96,
            	4840, 104,
            	4819, 112,
            	618, 120,
            1, 8, 1, /* 4489: pointer.struct.stack_st_X509_OBJECT */
            	4494, 0,
            0, 32, 2, /* 4494: struct.stack_st_fake_X509_OBJECT */
            	4501, 8,
            	414, 24,
            8884099, 8, 2, /* 4501: pointer_to_array_of_pointers_to_stack */
            	4508, 0,
            	411, 20,
            0, 8, 1, /* 4508: pointer.X509_OBJECT */
            	4513, 0,
            0, 0, 1, /* 4513: X509_OBJECT */
            	4518, 0,
            0, 16, 1, /* 4518: struct.x509_object_st */
            	4523, 8,
            0, 8, 4, /* 4523: union.unknown */
            	254, 0,
            	4071, 0,
            	4534, 0,
            	3497, 0,
            1, 8, 1, /* 4534: pointer.struct.X509_crl_st */
            	4539, 0,
            0, 120, 10, /* 4539: struct.X509_crl_st */
            	2301, 0,
            	2335, 8,
            	2424, 16,
            	2710, 32,
            	4562, 40,
            	2325, 56,
            	2325, 64,
            	4570, 96,
            	4599, 104,
            	4607, 112,
            1, 8, 1, /* 4562: pointer.struct.ISSUING_DIST_POINT_st */
            	4567, 0,
            0, 0, 0, /* 4567: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 4570: pointer.struct.stack_st_GENERAL_NAMES */
            	4575, 0,
            0, 32, 2, /* 4575: struct.stack_st_fake_GENERAL_NAMES */
            	4582, 8,
            	414, 24,
            8884099, 8, 2, /* 4582: pointer_to_array_of_pointers_to_stack */
            	4589, 0,
            	411, 20,
            0, 8, 1, /* 4589: pointer.GENERAL_NAMES */
            	4594, 0,
            0, 0, 1, /* 4594: GENERAL_NAMES */
            	4059, 0,
            1, 8, 1, /* 4599: pointer.struct.x509_crl_method_st */
            	4604, 0,
            0, 0, 0, /* 4604: struct.x509_crl_method_st */
            0, 8, 0, /* 4607: pointer.void */
            1, 8, 1, /* 4610: pointer.struct.stack_st_X509_LOOKUP */
            	4615, 0,
            0, 32, 2, /* 4615: struct.stack_st_fake_X509_LOOKUP */
            	4622, 8,
            	414, 24,
            8884099, 8, 2, /* 4622: pointer_to_array_of_pointers_to_stack */
            	4629, 0,
            	411, 20,
            0, 8, 1, /* 4629: pointer.X509_LOOKUP */
            	4634, 0,
            0, 0, 1, /* 4634: X509_LOOKUP */
            	4639, 0,
            0, 32, 3, /* 4639: struct.x509_lookup_st */
            	4648, 8,
            	254, 16,
            	4691, 24,
            1, 8, 1, /* 4648: pointer.struct.x509_lookup_method_st */
            	4653, 0,
            0, 80, 10, /* 4653: struct.x509_lookup_method_st */
            	5, 0,
            	4676, 8,
            	2715, 16,
            	4676, 24,
            	4676, 32,
            	4679, 40,
            	4682, 48,
            	4089, 56,
            	4685, 64,
            	4688, 72,
            8884097, 8, 0, /* 4676: pointer.func */
            8884097, 8, 0, /* 4679: pointer.func */
            8884097, 8, 0, /* 4682: pointer.func */
            8884097, 8, 0, /* 4685: pointer.func */
            8884097, 8, 0, /* 4688: pointer.func */
            1, 8, 1, /* 4691: pointer.struct.x509_store_st */
            	4696, 0,
            0, 144, 15, /* 4696: struct.x509_store_st */
            	4729, 8,
            	4753, 16,
            	4777, 24,
            	4789, 32,
            	4792, 40,
            	4285, 48,
            	4098, 56,
            	4789, 64,
            	4795, 72,
            	4798, 80,
            	4801, 88,
            	4804, 96,
            	3398, 104,
            	4789, 112,
            	2165, 120,
            1, 8, 1, /* 4729: pointer.struct.stack_st_X509_OBJECT */
            	4734, 0,
            0, 32, 2, /* 4734: struct.stack_st_fake_X509_OBJECT */
            	4741, 8,
            	414, 24,
            8884099, 8, 2, /* 4741: pointer_to_array_of_pointers_to_stack */
            	4748, 0,
            	411, 20,
            0, 8, 1, /* 4748: pointer.X509_OBJECT */
            	4513, 0,
            1, 8, 1, /* 4753: pointer.struct.stack_st_X509_LOOKUP */
            	4758, 0,
            0, 32, 2, /* 4758: struct.stack_st_fake_X509_LOOKUP */
            	4765, 8,
            	414, 24,
            8884099, 8, 2, /* 4765: pointer_to_array_of_pointers_to_stack */
            	4772, 0,
            	411, 20,
            0, 8, 1, /* 4772: pointer.X509_LOOKUP */
            	4634, 0,
            1, 8, 1, /* 4777: pointer.struct.X509_VERIFY_PARAM_st */
            	4782, 0,
            0, 56, 2, /* 4782: struct.X509_VERIFY_PARAM_st */
            	254, 0,
            	3788, 48,
            8884097, 8, 0, /* 4789: pointer.func */
            8884097, 8, 0, /* 4792: pointer.func */
            8884097, 8, 0, /* 4795: pointer.func */
            8884097, 8, 0, /* 4798: pointer.func */
            8884097, 8, 0, /* 4801: pointer.func */
            8884097, 8, 0, /* 4804: pointer.func */
            1, 8, 1, /* 4807: pointer.struct.X509_VERIFY_PARAM_st */
            	4812, 0,
            0, 56, 2, /* 4812: struct.X509_VERIFY_PARAM_st */
            	254, 0,
            	1743, 48,
            8884097, 8, 0, /* 4819: pointer.func */
            8884097, 8, 0, /* 4822: pointer.func */
            8884097, 8, 0, /* 4825: pointer.func */
            8884097, 8, 0, /* 4828: pointer.func */
            8884097, 8, 0, /* 4831: pointer.func */
            8884097, 8, 0, /* 4834: pointer.func */
            8884097, 8, 0, /* 4837: pointer.func */
            8884097, 8, 0, /* 4840: pointer.func */
            1, 8, 1, /* 4843: pointer.struct.lhash_st */
            	4848, 0,
            0, 176, 3, /* 4848: struct.lhash_st */
            	4857, 0,
            	414, 8,
            	4879, 16,
            1, 8, 1, /* 4857: pointer.pointer.struct.lhash_node_st */
            	4862, 0,
            1, 8, 1, /* 4862: pointer.struct.lhash_node_st */
            	4867, 0,
            0, 24, 2, /* 4867: struct.lhash_node_st */
            	4607, 0,
            	4874, 8,
            1, 8, 1, /* 4874: pointer.struct.lhash_node_st */
            	4867, 0,
            8884097, 8, 0, /* 4879: pointer.func */
            8884097, 8, 0, /* 4882: pointer.func */
            1, 8, 1, /* 4885: pointer.struct.stack_st_X509_NAME */
            	4890, 0,
            0, 32, 2, /* 4890: struct.stack_st_fake_X509_NAME */
            	4897, 8,
            	414, 24,
            8884099, 8, 2, /* 4897: pointer_to_array_of_pointers_to_stack */
            	4904, 0,
            	411, 20,
            0, 8, 1, /* 4904: pointer.X509_NAME */
            	2160, 0,
            8884097, 8, 0, /* 4909: pointer.func */
            8884097, 8, 0, /* 4912: pointer.func */
            0, 128, 14, /* 4915: struct.srp_ctx_st */
            	4607, 0,
            	4909, 8,
            	2669, 16,
            	2187, 24,
            	254, 32,
            	600, 40,
            	600, 48,
            	600, 56,
            	600, 64,
            	600, 72,
            	600, 80,
            	600, 88,
            	600, 96,
            	254, 104,
            8884097, 8, 0, /* 4946: pointer.func */
            1, 8, 1, /* 4949: pointer.struct.ssl_ctx_st */
            	4348, 0,
        },
        .arg_entity_index = { 4949, 5, 411, },
        .ret_entity_index = 411,
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

