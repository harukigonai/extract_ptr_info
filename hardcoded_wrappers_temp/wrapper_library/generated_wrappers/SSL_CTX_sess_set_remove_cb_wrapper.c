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

void bb_SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *));

void SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_sess_set_remove_cb called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_sess_set_remove_cb(arg_a,arg_b);
    else {
        void (*orig_SSL_CTX_sess_set_remove_cb)(SSL_CTX *,void (*)(struct ssl_ctx_st *,SSL_SESSION *));
        orig_SSL_CTX_sess_set_remove_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_remove_cb");
        orig_SSL_CTX_sess_set_remove_cb(arg_a,arg_b);
    }
}

void bb_SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            8884097, 8, 0, /* 0: pointer.func */
            0, 0, 1, /* 3: SRTP_PROTECTION_PROFILE */
            	8, 0,
            0, 16, 1, /* 8: struct.srtp_protection_profile_st */
            	13, 0,
            1, 8, 1, /* 13: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 18: pointer.func */
            0, 128, 14, /* 21: struct.srp_ctx_st */
            	52, 0,
            	55, 8,
            	58, 16,
            	61, 24,
            	64, 32,
            	69, 40,
            	69, 48,
            	69, 56,
            	69, 64,
            	69, 72,
            	69, 80,
            	69, 88,
            	69, 96,
            	64, 104,
            0, 8, 0, /* 52: pointer.void */
            8884097, 8, 0, /* 55: pointer.func */
            8884097, 8, 0, /* 58: pointer.func */
            8884097, 8, 0, /* 61: pointer.func */
            1, 8, 1, /* 64: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 69: pointer.struct.bignum_st */
            	74, 0,
            0, 24, 1, /* 74: struct.bignum_st */
            	79, 0,
            1, 8, 1, /* 79: pointer.unsigned int */
            	84, 0,
            0, 4, 0, /* 84: unsigned int */
            8884097, 8, 0, /* 87: pointer.func */
            0, 8, 1, /* 90: struct.ssl3_buf_freelist_entry_st */
            	95, 0,
            1, 8, 1, /* 95: pointer.struct.ssl3_buf_freelist_entry_st */
            	90, 0,
            1, 8, 1, /* 100: pointer.struct.ssl3_buf_freelist_st */
            	105, 0,
            0, 24, 1, /* 105: struct.ssl3_buf_freelist_st */
            	95, 16,
            8884097, 8, 0, /* 110: pointer.func */
            8884097, 8, 0, /* 113: pointer.func */
            8884097, 8, 0, /* 116: pointer.func */
            8884097, 8, 0, /* 119: pointer.func */
            0, 24, 1, /* 122: struct.buf_mem_st */
            	64, 8,
            1, 8, 1, /* 127: pointer.struct.buf_mem_st */
            	122, 0,
            1, 8, 1, /* 132: pointer.struct.stack_st_X509_NAME_ENTRY */
            	137, 0,
            0, 32, 2, /* 137: struct.stack_st_fake_X509_NAME_ENTRY */
            	144, 8,
            	208, 24,
            8884099, 8, 2, /* 144: pointer_to_array_of_pointers_to_stack */
            	151, 0,
            	205, 20,
            0, 8, 1, /* 151: pointer.X509_NAME_ENTRY */
            	156, 0,
            0, 0, 1, /* 156: X509_NAME_ENTRY */
            	161, 0,
            0, 24, 2, /* 161: struct.X509_name_entry_st */
            	168, 0,
            	190, 8,
            1, 8, 1, /* 168: pointer.struct.asn1_object_st */
            	173, 0,
            0, 40, 3, /* 173: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	182, 24,
            1, 8, 1, /* 182: pointer.unsigned char */
            	187, 0,
            0, 1, 0, /* 187: unsigned char */
            1, 8, 1, /* 190: pointer.struct.asn1_string_st */
            	195, 0,
            0, 24, 1, /* 195: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 200: pointer.unsigned char */
            	187, 0,
            0, 4, 0, /* 205: int */
            8884097, 8, 0, /* 208: pointer.func */
            0, 40, 3, /* 211: struct.X509_name_st */
            	132, 0,
            	127, 16,
            	200, 24,
            1, 8, 1, /* 220: pointer.struct.stack_st_X509_NAME */
            	225, 0,
            0, 32, 2, /* 225: struct.stack_st_fake_X509_NAME */
            	232, 8,
            	208, 24,
            8884099, 8, 2, /* 232: pointer_to_array_of_pointers_to_stack */
            	239, 0,
            	205, 20,
            0, 8, 1, /* 239: pointer.X509_NAME */
            	244, 0,
            0, 0, 1, /* 244: X509_NAME */
            	211, 0,
            8884097, 8, 0, /* 249: pointer.func */
            8884097, 8, 0, /* 252: pointer.func */
            8884097, 8, 0, /* 255: pointer.func */
            0, 64, 7, /* 258: struct.comp_method_st */
            	13, 8,
            	275, 16,
            	255, 24,
            	252, 32,
            	252, 40,
            	278, 48,
            	278, 56,
            8884097, 8, 0, /* 275: pointer.func */
            8884097, 8, 0, /* 278: pointer.func */
            1, 8, 1, /* 281: pointer.struct.comp_method_st */
            	258, 0,
            0, 0, 1, /* 286: SSL_COMP */
            	291, 0,
            0, 24, 2, /* 291: struct.ssl_comp_st */
            	13, 8,
            	281, 16,
            1, 8, 1, /* 298: pointer.struct.stack_st_SSL_COMP */
            	303, 0,
            0, 32, 2, /* 303: struct.stack_st_fake_SSL_COMP */
            	310, 8,
            	208, 24,
            8884099, 8, 2, /* 310: pointer_to_array_of_pointers_to_stack */
            	317, 0,
            	205, 20,
            0, 8, 1, /* 317: pointer.SSL_COMP */
            	286, 0,
            8884097, 8, 0, /* 322: pointer.func */
            8884097, 8, 0, /* 325: pointer.func */
            8884097, 8, 0, /* 328: pointer.func */
            8884097, 8, 0, /* 331: pointer.func */
            0, 88, 1, /* 334: struct.ssl_cipher_st */
            	13, 8,
            1, 8, 1, /* 339: pointer.struct.ssl_cipher_st */
            	334, 0,
            1, 8, 1, /* 344: pointer.struct.ec_key_st */
            	349, 0,
            0, 0, 0, /* 349: struct.ec_key_st */
            8884097, 8, 0, /* 352: pointer.func */
            8884097, 8, 0, /* 355: pointer.func */
            8884097, 8, 0, /* 358: pointer.func */
            8884097, 8, 0, /* 361: pointer.func */
            0, 120, 8, /* 364: struct.env_md_st */
            	383, 24,
            	361, 32,
            	358, 40,
            	355, 48,
            	383, 56,
            	352, 64,
            	386, 72,
            	389, 112,
            8884097, 8, 0, /* 383: pointer.func */
            8884097, 8, 0, /* 386: pointer.func */
            8884097, 8, 0, /* 389: pointer.func */
            1, 8, 1, /* 392: pointer.struct.x509_cert_aux_st */
            	397, 0,
            0, 40, 5, /* 397: struct.x509_cert_aux_st */
            	410, 0,
            	410, 8,
            	448, 16,
            	458, 24,
            	463, 32,
            1, 8, 1, /* 410: pointer.struct.stack_st_ASN1_OBJECT */
            	415, 0,
            0, 32, 2, /* 415: struct.stack_st_fake_ASN1_OBJECT */
            	422, 8,
            	208, 24,
            8884099, 8, 2, /* 422: pointer_to_array_of_pointers_to_stack */
            	429, 0,
            	205, 20,
            0, 8, 1, /* 429: pointer.ASN1_OBJECT */
            	434, 0,
            0, 0, 1, /* 434: ASN1_OBJECT */
            	439, 0,
            0, 40, 3, /* 439: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	182, 24,
            1, 8, 1, /* 448: pointer.struct.asn1_string_st */
            	453, 0,
            0, 24, 1, /* 453: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 458: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 463: pointer.struct.stack_st_X509_ALGOR */
            	468, 0,
            0, 32, 2, /* 468: struct.stack_st_fake_X509_ALGOR */
            	475, 8,
            	208, 24,
            8884099, 8, 2, /* 475: pointer_to_array_of_pointers_to_stack */
            	482, 0,
            	205, 20,
            0, 8, 1, /* 482: pointer.X509_ALGOR */
            	487, 0,
            0, 0, 1, /* 487: X509_ALGOR */
            	492, 0,
            0, 16, 2, /* 492: struct.X509_algor_st */
            	499, 0,
            	513, 8,
            1, 8, 1, /* 499: pointer.struct.asn1_object_st */
            	504, 0,
            0, 40, 3, /* 504: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	182, 24,
            1, 8, 1, /* 513: pointer.struct.asn1_type_st */
            	518, 0,
            0, 16, 1, /* 518: struct.asn1_type_st */
            	523, 8,
            0, 8, 20, /* 523: union.unknown */
            	64, 0,
            	566, 0,
            	499, 0,
            	576, 0,
            	581, 0,
            	586, 0,
            	591, 0,
            	596, 0,
            	601, 0,
            	606, 0,
            	611, 0,
            	616, 0,
            	621, 0,
            	626, 0,
            	631, 0,
            	636, 0,
            	641, 0,
            	566, 0,
            	566, 0,
            	646, 0,
            1, 8, 1, /* 566: pointer.struct.asn1_string_st */
            	571, 0,
            0, 24, 1, /* 571: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 576: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 581: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 586: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 591: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 596: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 601: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 606: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 611: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 616: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 621: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 626: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 631: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 636: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 641: pointer.struct.asn1_string_st */
            	571, 0,
            1, 8, 1, /* 646: pointer.struct.ASN1_VALUE_st */
            	651, 0,
            0, 0, 0, /* 651: struct.ASN1_VALUE_st */
            1, 8, 1, /* 654: pointer.struct.stack_st_GENERAL_NAME */
            	659, 0,
            0, 32, 2, /* 659: struct.stack_st_fake_GENERAL_NAME */
            	666, 8,
            	208, 24,
            8884099, 8, 2, /* 666: pointer_to_array_of_pointers_to_stack */
            	673, 0,
            	205, 20,
            0, 8, 1, /* 673: pointer.GENERAL_NAME */
            	678, 0,
            0, 0, 1, /* 678: GENERAL_NAME */
            	683, 0,
            0, 16, 1, /* 683: struct.GENERAL_NAME_st */
            	688, 8,
            0, 8, 15, /* 688: union.unknown */
            	64, 0,
            	721, 0,
            	840, 0,
            	840, 0,
            	747, 0,
            	888, 0,
            	936, 0,
            	840, 0,
            	825, 0,
            	733, 0,
            	825, 0,
            	888, 0,
            	840, 0,
            	733, 0,
            	747, 0,
            1, 8, 1, /* 721: pointer.struct.otherName_st */
            	726, 0,
            0, 16, 2, /* 726: struct.otherName_st */
            	733, 0,
            	747, 8,
            1, 8, 1, /* 733: pointer.struct.asn1_object_st */
            	738, 0,
            0, 40, 3, /* 738: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	182, 24,
            1, 8, 1, /* 747: pointer.struct.asn1_type_st */
            	752, 0,
            0, 16, 1, /* 752: struct.asn1_type_st */
            	757, 8,
            0, 8, 20, /* 757: union.unknown */
            	64, 0,
            	800, 0,
            	733, 0,
            	810, 0,
            	815, 0,
            	820, 0,
            	825, 0,
            	830, 0,
            	835, 0,
            	840, 0,
            	845, 0,
            	850, 0,
            	855, 0,
            	860, 0,
            	865, 0,
            	870, 0,
            	875, 0,
            	800, 0,
            	800, 0,
            	880, 0,
            1, 8, 1, /* 800: pointer.struct.asn1_string_st */
            	805, 0,
            0, 24, 1, /* 805: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 810: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 815: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 820: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 825: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 830: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 835: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 840: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 845: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 850: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 855: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 860: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 865: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 870: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 875: pointer.struct.asn1_string_st */
            	805, 0,
            1, 8, 1, /* 880: pointer.struct.ASN1_VALUE_st */
            	885, 0,
            0, 0, 0, /* 885: struct.ASN1_VALUE_st */
            1, 8, 1, /* 888: pointer.struct.X509_name_st */
            	893, 0,
            0, 40, 3, /* 893: struct.X509_name_st */
            	902, 0,
            	926, 16,
            	200, 24,
            1, 8, 1, /* 902: pointer.struct.stack_st_X509_NAME_ENTRY */
            	907, 0,
            0, 32, 2, /* 907: struct.stack_st_fake_X509_NAME_ENTRY */
            	914, 8,
            	208, 24,
            8884099, 8, 2, /* 914: pointer_to_array_of_pointers_to_stack */
            	921, 0,
            	205, 20,
            0, 8, 1, /* 921: pointer.X509_NAME_ENTRY */
            	156, 0,
            1, 8, 1, /* 926: pointer.struct.buf_mem_st */
            	931, 0,
            0, 24, 1, /* 931: struct.buf_mem_st */
            	64, 8,
            1, 8, 1, /* 936: pointer.struct.EDIPartyName_st */
            	941, 0,
            0, 16, 2, /* 941: struct.EDIPartyName_st */
            	800, 0,
            	800, 8,
            1, 8, 1, /* 948: pointer.struct.stack_st_DIST_POINT */
            	953, 0,
            0, 32, 2, /* 953: struct.stack_st_fake_DIST_POINT */
            	960, 8,
            	208, 24,
            8884099, 8, 2, /* 960: pointer_to_array_of_pointers_to_stack */
            	967, 0,
            	205, 20,
            0, 8, 1, /* 967: pointer.DIST_POINT */
            	972, 0,
            0, 0, 1, /* 972: DIST_POINT */
            	977, 0,
            0, 32, 3, /* 977: struct.DIST_POINT_st */
            	986, 0,
            	1077, 8,
            	1005, 16,
            1, 8, 1, /* 986: pointer.struct.DIST_POINT_NAME_st */
            	991, 0,
            0, 24, 2, /* 991: struct.DIST_POINT_NAME_st */
            	998, 8,
            	1053, 16,
            0, 8, 2, /* 998: union.unknown */
            	1005, 0,
            	1029, 0,
            1, 8, 1, /* 1005: pointer.struct.stack_st_GENERAL_NAME */
            	1010, 0,
            0, 32, 2, /* 1010: struct.stack_st_fake_GENERAL_NAME */
            	1017, 8,
            	208, 24,
            8884099, 8, 2, /* 1017: pointer_to_array_of_pointers_to_stack */
            	1024, 0,
            	205, 20,
            0, 8, 1, /* 1024: pointer.GENERAL_NAME */
            	678, 0,
            1, 8, 1, /* 1029: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1034, 0,
            0, 32, 2, /* 1034: struct.stack_st_fake_X509_NAME_ENTRY */
            	1041, 8,
            	208, 24,
            8884099, 8, 2, /* 1041: pointer_to_array_of_pointers_to_stack */
            	1048, 0,
            	205, 20,
            0, 8, 1, /* 1048: pointer.X509_NAME_ENTRY */
            	156, 0,
            1, 8, 1, /* 1053: pointer.struct.X509_name_st */
            	1058, 0,
            0, 40, 3, /* 1058: struct.X509_name_st */
            	1029, 0,
            	1067, 16,
            	200, 24,
            1, 8, 1, /* 1067: pointer.struct.buf_mem_st */
            	1072, 0,
            0, 24, 1, /* 1072: struct.buf_mem_st */
            	64, 8,
            1, 8, 1, /* 1077: pointer.struct.asn1_string_st */
            	1082, 0,
            0, 24, 1, /* 1082: struct.asn1_string_st */
            	200, 8,
            0, 0, 0, /* 1087: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1090: pointer.struct.X509_POLICY_CACHE_st */
            	1087, 0,
            0, 0, 0, /* 1095: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1098: pointer.struct.AUTHORITY_KEYID_st */
            	1095, 0,
            0, 24, 1, /* 1103: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 1108: pointer.struct.stack_st_X509_EXTENSION */
            	1113, 0,
            0, 32, 2, /* 1113: struct.stack_st_fake_X509_EXTENSION */
            	1120, 8,
            	208, 24,
            8884099, 8, 2, /* 1120: pointer_to_array_of_pointers_to_stack */
            	1127, 0,
            	205, 20,
            0, 8, 1, /* 1127: pointer.X509_EXTENSION */
            	1132, 0,
            0, 0, 1, /* 1132: X509_EXTENSION */
            	1137, 0,
            0, 24, 2, /* 1137: struct.X509_extension_st */
            	1144, 0,
            	1158, 16,
            1, 8, 1, /* 1144: pointer.struct.asn1_object_st */
            	1149, 0,
            0, 40, 3, /* 1149: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	182, 24,
            1, 8, 1, /* 1158: pointer.struct.asn1_string_st */
            	1163, 0,
            0, 24, 1, /* 1163: struct.asn1_string_st */
            	200, 8,
            8884097, 8, 0, /* 1168: pointer.func */
            0, 72, 8, /* 1171: struct.dh_method */
            	13, 0,
            	1190, 8,
            	1193, 16,
            	1168, 24,
            	1190, 32,
            	1190, 40,
            	64, 56,
            	1196, 64,
            8884097, 8, 0, /* 1190: pointer.func */
            8884097, 8, 0, /* 1193: pointer.func */
            8884097, 8, 0, /* 1196: pointer.func */
            0, 144, 12, /* 1199: struct.dh_st */
            	69, 8,
            	69, 16,
            	69, 32,
            	69, 40,
            	1226, 56,
            	69, 64,
            	69, 72,
            	200, 80,
            	69, 96,
            	1240, 112,
            	1267, 128,
            	1272, 136,
            1, 8, 1, /* 1226: pointer.struct.bn_mont_ctx_st */
            	1231, 0,
            0, 96, 3, /* 1231: struct.bn_mont_ctx_st */
            	74, 8,
            	74, 32,
            	74, 56,
            0, 16, 1, /* 1240: struct.crypto_ex_data_st */
            	1245, 0,
            1, 8, 1, /* 1245: pointer.struct.stack_st_void */
            	1250, 0,
            0, 32, 1, /* 1250: struct.stack_st_void */
            	1255, 0,
            0, 32, 2, /* 1255: struct.stack_st */
            	1262, 8,
            	208, 24,
            1, 8, 1, /* 1262: pointer.pointer.char */
            	64, 0,
            1, 8, 1, /* 1267: pointer.struct.dh_method */
            	1171, 0,
            1, 8, 1, /* 1272: pointer.struct.engine_st */
            	1277, 0,
            0, 0, 0, /* 1277: struct.engine_st */
            1, 8, 1, /* 1280: pointer.struct.dh_st */
            	1199, 0,
            0, 16, 1, /* 1285: struct.crypto_ex_data_st */
            	1290, 0,
            1, 8, 1, /* 1290: pointer.struct.stack_st_void */
            	1295, 0,
            0, 32, 1, /* 1295: struct.stack_st_void */
            	1300, 0,
            0, 32, 2, /* 1300: struct.stack_st */
            	1262, 8,
            	208, 24,
            1, 8, 1, /* 1307: pointer.struct.asn1_string_st */
            	1312, 0,
            0, 24, 1, /* 1312: struct.asn1_string_st */
            	200, 8,
            0, 24, 1, /* 1317: struct.buf_mem_st */
            	64, 8,
            8884097, 8, 0, /* 1322: pointer.func */
            0, 24, 1, /* 1325: struct.ASN1_ENCODING_st */
            	200, 0,
            8884097, 8, 0, /* 1330: pointer.func */
            8884097, 8, 0, /* 1333: pointer.func */
            1, 8, 1, /* 1336: pointer.struct.asn1_string_st */
            	1341, 0,
            0, 24, 1, /* 1341: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1346: pointer.struct.dh_st */
            	1199, 0,
            0, 16, 2, /* 1351: struct.X509_algor_st */
            	1358, 0,
            	1372, 8,
            1, 8, 1, /* 1358: pointer.struct.asn1_object_st */
            	1363, 0,
            0, 40, 3, /* 1363: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	182, 24,
            1, 8, 1, /* 1372: pointer.struct.asn1_type_st */
            	1377, 0,
            0, 16, 1, /* 1377: struct.asn1_type_st */
            	1382, 8,
            0, 8, 20, /* 1382: union.unknown */
            	64, 0,
            	1425, 0,
            	1358, 0,
            	1430, 0,
            	1435, 0,
            	1440, 0,
            	1307, 0,
            	1445, 0,
            	1450, 0,
            	1455, 0,
            	1460, 0,
            	1465, 0,
            	1470, 0,
            	1475, 0,
            	1480, 0,
            	1485, 0,
            	1490, 0,
            	1425, 0,
            	1425, 0,
            	646, 0,
            1, 8, 1, /* 1425: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1430: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1435: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1440: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1445: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1450: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1455: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1460: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1465: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1470: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1475: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1480: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1485: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1490: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1495: pointer.struct.rsa_st */
            	1500, 0,
            0, 168, 17, /* 1500: struct.rsa_st */
            	1537, 16,
            	1592, 24,
            	1600, 32,
            	1600, 40,
            	1600, 48,
            	1600, 56,
            	1600, 64,
            	1600, 72,
            	1600, 80,
            	1600, 88,
            	1285, 96,
            	1610, 120,
            	1610, 128,
            	1610, 136,
            	64, 144,
            	1624, 152,
            	1624, 160,
            1, 8, 1, /* 1537: pointer.struct.rsa_meth_st */
            	1542, 0,
            0, 112, 13, /* 1542: struct.rsa_meth_st */
            	13, 0,
            	1571, 8,
            	1571, 16,
            	1571, 24,
            	1571, 32,
            	1574, 40,
            	1577, 48,
            	1580, 56,
            	1580, 64,
            	64, 80,
            	1583, 88,
            	1586, 96,
            	1589, 104,
            8884097, 8, 0, /* 1571: pointer.func */
            8884097, 8, 0, /* 1574: pointer.func */
            8884097, 8, 0, /* 1577: pointer.func */
            8884097, 8, 0, /* 1580: pointer.func */
            8884097, 8, 0, /* 1583: pointer.func */
            8884097, 8, 0, /* 1586: pointer.func */
            8884097, 8, 0, /* 1589: pointer.func */
            1, 8, 1, /* 1592: pointer.struct.engine_st */
            	1597, 0,
            0, 0, 0, /* 1597: struct.engine_st */
            1, 8, 1, /* 1600: pointer.struct.bignum_st */
            	1605, 0,
            0, 24, 1, /* 1605: struct.bignum_st */
            	79, 0,
            1, 8, 1, /* 1610: pointer.struct.bn_mont_ctx_st */
            	1615, 0,
            0, 96, 3, /* 1615: struct.bn_mont_ctx_st */
            	1605, 8,
            	1605, 32,
            	1605, 56,
            1, 8, 1, /* 1624: pointer.struct.bn_blinding_st */
            	1629, 0,
            0, 0, 0, /* 1629: struct.bn_blinding_st */
            1, 8, 1, /* 1632: pointer.struct.X509_crl_info_st */
            	1637, 0,
            0, 80, 8, /* 1637: struct.X509_crl_info_st */
            	1430, 0,
            	1656, 8,
            	1661, 16,
            	1704, 24,
            	1704, 32,
            	1709, 40,
            	1812, 48,
            	1325, 56,
            1, 8, 1, /* 1656: pointer.struct.X509_algor_st */
            	1351, 0,
            1, 8, 1, /* 1661: pointer.struct.X509_name_st */
            	1666, 0,
            0, 40, 3, /* 1666: struct.X509_name_st */
            	1675, 0,
            	1699, 16,
            	200, 24,
            1, 8, 1, /* 1675: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1680, 0,
            0, 32, 2, /* 1680: struct.stack_st_fake_X509_NAME_ENTRY */
            	1687, 8,
            	208, 24,
            8884099, 8, 2, /* 1687: pointer_to_array_of_pointers_to_stack */
            	1694, 0,
            	205, 20,
            0, 8, 1, /* 1694: pointer.X509_NAME_ENTRY */
            	156, 0,
            1, 8, 1, /* 1699: pointer.struct.buf_mem_st */
            	1317, 0,
            1, 8, 1, /* 1704: pointer.struct.asn1_string_st */
            	1312, 0,
            1, 8, 1, /* 1709: pointer.struct.stack_st_X509_REVOKED */
            	1714, 0,
            0, 32, 2, /* 1714: struct.stack_st_fake_X509_REVOKED */
            	1721, 8,
            	208, 24,
            8884099, 8, 2, /* 1721: pointer_to_array_of_pointers_to_stack */
            	1728, 0,
            	205, 20,
            0, 8, 1, /* 1728: pointer.X509_REVOKED */
            	1733, 0,
            0, 0, 1, /* 1733: X509_REVOKED */
            	1738, 0,
            0, 40, 4, /* 1738: struct.x509_revoked_st */
            	1749, 0,
            	1759, 8,
            	1764, 16,
            	1788, 24,
            1, 8, 1, /* 1749: pointer.struct.asn1_string_st */
            	1754, 0,
            0, 24, 1, /* 1754: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1759: pointer.struct.asn1_string_st */
            	1754, 0,
            1, 8, 1, /* 1764: pointer.struct.stack_st_X509_EXTENSION */
            	1769, 0,
            0, 32, 2, /* 1769: struct.stack_st_fake_X509_EXTENSION */
            	1776, 8,
            	208, 24,
            8884099, 8, 2, /* 1776: pointer_to_array_of_pointers_to_stack */
            	1783, 0,
            	205, 20,
            0, 8, 1, /* 1783: pointer.X509_EXTENSION */
            	1132, 0,
            1, 8, 1, /* 1788: pointer.struct.stack_st_GENERAL_NAME */
            	1793, 0,
            0, 32, 2, /* 1793: struct.stack_st_fake_GENERAL_NAME */
            	1800, 8,
            	208, 24,
            8884099, 8, 2, /* 1800: pointer_to_array_of_pointers_to_stack */
            	1807, 0,
            	205, 20,
            0, 8, 1, /* 1807: pointer.GENERAL_NAME */
            	678, 0,
            1, 8, 1, /* 1812: pointer.struct.stack_st_X509_EXTENSION */
            	1817, 0,
            0, 32, 2, /* 1817: struct.stack_st_fake_X509_EXTENSION */
            	1824, 8,
            	208, 24,
            8884099, 8, 2, /* 1824: pointer_to_array_of_pointers_to_stack */
            	1831, 0,
            	205, 20,
            0, 8, 1, /* 1831: pointer.X509_EXTENSION */
            	1132, 0,
            1, 8, 1, /* 1836: pointer.struct.cert_st */
            	1841, 0,
            0, 296, 7, /* 1841: struct.cert_st */
            	1858, 0,
            	2755, 48,
            	119, 56,
            	1346, 64,
            	2760, 72,
            	344, 80,
            	116, 88,
            1, 8, 1, /* 1858: pointer.struct.cert_pkey_st */
            	1863, 0,
            0, 24, 3, /* 1863: struct.cert_pkey_st */
            	1872, 0,
            	2165, 8,
            	2750, 16,
            1, 8, 1, /* 1872: pointer.struct.x509_st */
            	1877, 0,
            0, 184, 12, /* 1877: struct.x509_st */
            	1904, 0,
            	1939, 8,
            	2028, 16,
            	64, 32,
            	1240, 40,
            	458, 104,
            	1098, 112,
            	1090, 120,
            	948, 128,
            	654, 136,
            	2742, 144,
            	392, 176,
            1, 8, 1, /* 1904: pointer.struct.x509_cinf_st */
            	1909, 0,
            0, 104, 11, /* 1909: struct.x509_cinf_st */
            	1934, 0,
            	1934, 8,
            	1939, 16,
            	2086, 24,
            	2134, 32,
            	2086, 40,
            	2151, 48,
            	2028, 56,
            	2028, 64,
            	1108, 72,
            	1103, 80,
            1, 8, 1, /* 1934: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 1939: pointer.struct.X509_algor_st */
            	1944, 0,
            0, 16, 2, /* 1944: struct.X509_algor_st */
            	1951, 0,
            	1965, 8,
            1, 8, 1, /* 1951: pointer.struct.asn1_object_st */
            	1956, 0,
            0, 40, 3, /* 1956: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	182, 24,
            1, 8, 1, /* 1965: pointer.struct.asn1_type_st */
            	1970, 0,
            0, 16, 1, /* 1970: struct.asn1_type_st */
            	1975, 8,
            0, 8, 20, /* 1975: union.unknown */
            	64, 0,
            	2018, 0,
            	1951, 0,
            	1934, 0,
            	2023, 0,
            	2028, 0,
            	458, 0,
            	2033, 0,
            	2038, 0,
            	2043, 0,
            	2048, 0,
            	2053, 0,
            	2058, 0,
            	2063, 0,
            	2068, 0,
            	2073, 0,
            	448, 0,
            	2018, 0,
            	2018, 0,
            	2078, 0,
            1, 8, 1, /* 2018: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2023: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2028: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2033: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2038: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2043: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2048: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2053: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2058: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2063: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2068: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2073: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2078: pointer.struct.ASN1_VALUE_st */
            	2083, 0,
            0, 0, 0, /* 2083: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2086: pointer.struct.X509_name_st */
            	2091, 0,
            0, 40, 3, /* 2091: struct.X509_name_st */
            	2100, 0,
            	2124, 16,
            	200, 24,
            1, 8, 1, /* 2100: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2105, 0,
            0, 32, 2, /* 2105: struct.stack_st_fake_X509_NAME_ENTRY */
            	2112, 8,
            	208, 24,
            8884099, 8, 2, /* 2112: pointer_to_array_of_pointers_to_stack */
            	2119, 0,
            	205, 20,
            0, 8, 1, /* 2119: pointer.X509_NAME_ENTRY */
            	156, 0,
            1, 8, 1, /* 2124: pointer.struct.buf_mem_st */
            	2129, 0,
            0, 24, 1, /* 2129: struct.buf_mem_st */
            	64, 8,
            1, 8, 1, /* 2134: pointer.struct.X509_val_st */
            	2139, 0,
            0, 16, 2, /* 2139: struct.X509_val_st */
            	2146, 0,
            	2146, 8,
            1, 8, 1, /* 2146: pointer.struct.asn1_string_st */
            	453, 0,
            1, 8, 1, /* 2151: pointer.struct.X509_pubkey_st */
            	2156, 0,
            0, 24, 3, /* 2156: struct.X509_pubkey_st */
            	1939, 0,
            	2028, 8,
            	2165, 16,
            1, 8, 1, /* 2165: pointer.struct.evp_pkey_st */
            	2170, 0,
            0, 56, 4, /* 2170: struct.evp_pkey_st */
            	2181, 16,
            	1272, 24,
            	2189, 32,
            	2390, 48,
            1, 8, 1, /* 2181: pointer.struct.evp_pkey_asn1_method_st */
            	2186, 0,
            0, 0, 0, /* 2186: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 2189: union.unknown */
            	64, 0,
            	2202, 0,
            	2307, 0,
            	1280, 0,
            	2385, 0,
            1, 8, 1, /* 2202: pointer.struct.rsa_st */
            	2207, 0,
            0, 168, 17, /* 2207: struct.rsa_st */
            	2244, 16,
            	1272, 24,
            	69, 32,
            	69, 40,
            	69, 48,
            	69, 56,
            	69, 64,
            	69, 72,
            	69, 80,
            	69, 88,
            	1240, 96,
            	1226, 120,
            	1226, 128,
            	1226, 136,
            	64, 144,
            	2299, 152,
            	2299, 160,
            1, 8, 1, /* 2244: pointer.struct.rsa_meth_st */
            	2249, 0,
            0, 112, 13, /* 2249: struct.rsa_meth_st */
            	13, 0,
            	2278, 8,
            	2278, 16,
            	2278, 24,
            	2278, 32,
            	2281, 40,
            	2284, 48,
            	2287, 56,
            	2287, 64,
            	64, 80,
            	2290, 88,
            	2293, 96,
            	2296, 104,
            8884097, 8, 0, /* 2278: pointer.func */
            8884097, 8, 0, /* 2281: pointer.func */
            8884097, 8, 0, /* 2284: pointer.func */
            8884097, 8, 0, /* 2287: pointer.func */
            8884097, 8, 0, /* 2290: pointer.func */
            8884097, 8, 0, /* 2293: pointer.func */
            8884097, 8, 0, /* 2296: pointer.func */
            1, 8, 1, /* 2299: pointer.struct.bn_blinding_st */
            	2304, 0,
            0, 0, 0, /* 2304: struct.bn_blinding_st */
            1, 8, 1, /* 2307: pointer.struct.dsa_st */
            	2312, 0,
            0, 136, 11, /* 2312: struct.dsa_st */
            	69, 24,
            	69, 32,
            	69, 40,
            	69, 48,
            	69, 56,
            	69, 64,
            	69, 72,
            	1226, 88,
            	1240, 104,
            	2337, 120,
            	1272, 128,
            1, 8, 1, /* 2337: pointer.struct.dsa_method */
            	2342, 0,
            0, 96, 11, /* 2342: struct.dsa_method */
            	13, 0,
            	2367, 8,
            	2370, 16,
            	2373, 24,
            	1322, 32,
            	2376, 40,
            	2379, 48,
            	2379, 56,
            	64, 72,
            	2382, 80,
            	2379, 88,
            8884097, 8, 0, /* 2367: pointer.func */
            8884097, 8, 0, /* 2370: pointer.func */
            8884097, 8, 0, /* 2373: pointer.func */
            8884097, 8, 0, /* 2376: pointer.func */
            8884097, 8, 0, /* 2379: pointer.func */
            8884097, 8, 0, /* 2382: pointer.func */
            1, 8, 1, /* 2385: pointer.struct.ec_key_st */
            	349, 0,
            1, 8, 1, /* 2390: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2395, 0,
            0, 32, 2, /* 2395: struct.stack_st_fake_X509_ATTRIBUTE */
            	2402, 8,
            	208, 24,
            8884099, 8, 2, /* 2402: pointer_to_array_of_pointers_to_stack */
            	2409, 0,
            	205, 20,
            0, 8, 1, /* 2409: pointer.X509_ATTRIBUTE */
            	2414, 0,
            0, 0, 1, /* 2414: X509_ATTRIBUTE */
            	2419, 0,
            0, 24, 2, /* 2419: struct.x509_attributes_st */
            	2426, 0,
            	2440, 16,
            1, 8, 1, /* 2426: pointer.struct.asn1_object_st */
            	2431, 0,
            0, 40, 3, /* 2431: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	182, 24,
            0, 8, 3, /* 2440: union.unknown */
            	64, 0,
            	2449, 0,
            	2619, 0,
            1, 8, 1, /* 2449: pointer.struct.stack_st_ASN1_TYPE */
            	2454, 0,
            0, 32, 2, /* 2454: struct.stack_st_fake_ASN1_TYPE */
            	2461, 8,
            	208, 24,
            8884099, 8, 2, /* 2461: pointer_to_array_of_pointers_to_stack */
            	2468, 0,
            	205, 20,
            0, 8, 1, /* 2468: pointer.ASN1_TYPE */
            	2473, 0,
            0, 0, 1, /* 2473: ASN1_TYPE */
            	2478, 0,
            0, 16, 1, /* 2478: struct.asn1_type_st */
            	2483, 8,
            0, 8, 20, /* 2483: union.unknown */
            	64, 0,
            	2526, 0,
            	2536, 0,
            	2541, 0,
            	2546, 0,
            	2551, 0,
            	2556, 0,
            	2561, 0,
            	2566, 0,
            	2571, 0,
            	2576, 0,
            	2581, 0,
            	2586, 0,
            	2591, 0,
            	2596, 0,
            	2601, 0,
            	2606, 0,
            	2526, 0,
            	2526, 0,
            	2611, 0,
            1, 8, 1, /* 2526: pointer.struct.asn1_string_st */
            	2531, 0,
            0, 24, 1, /* 2531: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2536: pointer.struct.asn1_object_st */
            	439, 0,
            1, 8, 1, /* 2541: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2546: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2551: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2556: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2561: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2566: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2571: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2576: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2581: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2586: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2591: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2596: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2601: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2606: pointer.struct.asn1_string_st */
            	2531, 0,
            1, 8, 1, /* 2611: pointer.struct.ASN1_VALUE_st */
            	2616, 0,
            0, 0, 0, /* 2616: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2619: pointer.struct.asn1_type_st */
            	2624, 0,
            0, 16, 1, /* 2624: struct.asn1_type_st */
            	2629, 8,
            0, 8, 20, /* 2629: union.unknown */
            	64, 0,
            	1336, 0,
            	2426, 0,
            	2672, 0,
            	2677, 0,
            	2682, 0,
            	2687, 0,
            	2692, 0,
            	2697, 0,
            	2702, 0,
            	2707, 0,
            	2712, 0,
            	2717, 0,
            	2722, 0,
            	2727, 0,
            	2732, 0,
            	2737, 0,
            	1336, 0,
            	1336, 0,
            	646, 0,
            1, 8, 1, /* 2672: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2677: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2682: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2687: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2692: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2697: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2702: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2707: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2712: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2717: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2722: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2727: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2732: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2737: pointer.struct.asn1_string_st */
            	1341, 0,
            1, 8, 1, /* 2742: pointer.struct.NAME_CONSTRAINTS_st */
            	2747, 0,
            0, 0, 0, /* 2747: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2750: pointer.struct.env_md_st */
            	364, 0,
            1, 8, 1, /* 2755: pointer.struct.rsa_st */
            	2207, 0,
            8884097, 8, 0, /* 2760: pointer.func */
            1, 8, 1, /* 2763: pointer.struct.stack_st_DIST_POINT */
            	2768, 0,
            0, 32, 2, /* 2768: struct.stack_st_fake_DIST_POINT */
            	2775, 8,
            	208, 24,
            8884099, 8, 2, /* 2775: pointer_to_array_of_pointers_to_stack */
            	2782, 0,
            	205, 20,
            0, 8, 1, /* 2782: pointer.DIST_POINT */
            	972, 0,
            1, 8, 1, /* 2787: pointer.struct.X509_POLICY_CACHE_st */
            	2792, 0,
            0, 0, 0, /* 2792: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2795: struct.AUTHORITY_KEYID_st */
            0, 0, 0, /* 2798: struct.ec_key_st */
            1, 8, 1, /* 2801: pointer.struct.AUTHORITY_KEYID_st */
            	2795, 0,
            1, 8, 1, /* 2806: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	2811, 0,
            0, 32, 2, /* 2811: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	2818, 8,
            	208, 24,
            8884099, 8, 2, /* 2818: pointer_to_array_of_pointers_to_stack */
            	2825, 0,
            	205, 20,
            0, 8, 1, /* 2825: pointer.SRTP_PROTECTION_PROFILE */
            	3, 0,
            8884097, 8, 0, /* 2830: pointer.func */
            8884097, 8, 0, /* 2833: pointer.func */
            8884097, 8, 0, /* 2836: pointer.func */
            1, 8, 1, /* 2839: pointer.struct.stack_st_X509_OBJECT */
            	2844, 0,
            0, 32, 2, /* 2844: struct.stack_st_fake_X509_OBJECT */
            	2851, 8,
            	208, 24,
            8884099, 8, 2, /* 2851: pointer_to_array_of_pointers_to_stack */
            	2858, 0,
            	205, 20,
            0, 8, 1, /* 2858: pointer.X509_OBJECT */
            	2863, 0,
            0, 0, 1, /* 2863: X509_OBJECT */
            	2868, 0,
            0, 16, 1, /* 2868: struct.x509_object_st */
            	2873, 8,
            0, 8, 4, /* 2873: union.unknown */
            	64, 0,
            	2884, 0,
            	3285, 0,
            	2972, 0,
            1, 8, 1, /* 2884: pointer.struct.x509_st */
            	2889, 0,
            0, 184, 12, /* 2889: struct.x509_st */
            	2916, 0,
            	1656, 8,
            	1440, 16,
            	64, 32,
            	1285, 40,
            	1307, 104,
            	2801, 112,
            	2787, 120,
            	2763, 128,
            	3187, 136,
            	3211, 144,
            	3219, 176,
            1, 8, 1, /* 2916: pointer.struct.x509_cinf_st */
            	2921, 0,
            0, 104, 11, /* 2921: struct.x509_cinf_st */
            	1430, 0,
            	1430, 8,
            	1656, 16,
            	1661, 24,
            	2946, 32,
            	1661, 40,
            	2958, 48,
            	1440, 56,
            	1440, 64,
            	1812, 72,
            	1325, 80,
            1, 8, 1, /* 2946: pointer.struct.X509_val_st */
            	2951, 0,
            0, 16, 2, /* 2951: struct.X509_val_st */
            	1704, 0,
            	1704, 8,
            1, 8, 1, /* 2958: pointer.struct.X509_pubkey_st */
            	2963, 0,
            0, 24, 3, /* 2963: struct.X509_pubkey_st */
            	1656, 0,
            	1440, 8,
            	2972, 16,
            1, 8, 1, /* 2972: pointer.struct.evp_pkey_st */
            	2977, 0,
            0, 56, 4, /* 2977: struct.evp_pkey_st */
            	2988, 16,
            	1592, 24,
            	2996, 32,
            	3163, 48,
            1, 8, 1, /* 2988: pointer.struct.evp_pkey_asn1_method_st */
            	2993, 0,
            0, 0, 0, /* 2993: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 2996: union.unknown */
            	64, 0,
            	1495, 0,
            	3009, 0,
            	3090, 0,
            	3158, 0,
            1, 8, 1, /* 3009: pointer.struct.dsa_st */
            	3014, 0,
            0, 136, 11, /* 3014: struct.dsa_st */
            	1600, 24,
            	1600, 32,
            	1600, 40,
            	1600, 48,
            	1600, 56,
            	1600, 64,
            	1600, 72,
            	1610, 88,
            	1285, 104,
            	3039, 120,
            	1592, 128,
            1, 8, 1, /* 3039: pointer.struct.dsa_method */
            	3044, 0,
            0, 96, 11, /* 3044: struct.dsa_method */
            	13, 0,
            	3069, 8,
            	3072, 16,
            	3075, 24,
            	3078, 32,
            	3081, 40,
            	3084, 48,
            	3084, 56,
            	64, 72,
            	3087, 80,
            	3084, 88,
            8884097, 8, 0, /* 3069: pointer.func */
            8884097, 8, 0, /* 3072: pointer.func */
            8884097, 8, 0, /* 3075: pointer.func */
            8884097, 8, 0, /* 3078: pointer.func */
            8884097, 8, 0, /* 3081: pointer.func */
            8884097, 8, 0, /* 3084: pointer.func */
            8884097, 8, 0, /* 3087: pointer.func */
            1, 8, 1, /* 3090: pointer.struct.dh_st */
            	3095, 0,
            0, 144, 12, /* 3095: struct.dh_st */
            	1600, 8,
            	1600, 16,
            	1600, 32,
            	1600, 40,
            	1610, 56,
            	1600, 64,
            	1600, 72,
            	200, 80,
            	1600, 96,
            	1285, 112,
            	3122, 128,
            	1592, 136,
            1, 8, 1, /* 3122: pointer.struct.dh_method */
            	3127, 0,
            0, 72, 8, /* 3127: struct.dh_method */
            	13, 0,
            	3146, 8,
            	3149, 16,
            	3152, 24,
            	3146, 32,
            	3146, 40,
            	64, 56,
            	3155, 64,
            8884097, 8, 0, /* 3146: pointer.func */
            8884097, 8, 0, /* 3149: pointer.func */
            8884097, 8, 0, /* 3152: pointer.func */
            8884097, 8, 0, /* 3155: pointer.func */
            1, 8, 1, /* 3158: pointer.struct.ec_key_st */
            	2798, 0,
            1, 8, 1, /* 3163: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3168, 0,
            0, 32, 2, /* 3168: struct.stack_st_fake_X509_ATTRIBUTE */
            	3175, 8,
            	208, 24,
            8884099, 8, 2, /* 3175: pointer_to_array_of_pointers_to_stack */
            	3182, 0,
            	205, 20,
            0, 8, 1, /* 3182: pointer.X509_ATTRIBUTE */
            	2414, 0,
            1, 8, 1, /* 3187: pointer.struct.stack_st_GENERAL_NAME */
            	3192, 0,
            0, 32, 2, /* 3192: struct.stack_st_fake_GENERAL_NAME */
            	3199, 8,
            	208, 24,
            8884099, 8, 2, /* 3199: pointer_to_array_of_pointers_to_stack */
            	3206, 0,
            	205, 20,
            0, 8, 1, /* 3206: pointer.GENERAL_NAME */
            	678, 0,
            1, 8, 1, /* 3211: pointer.struct.NAME_CONSTRAINTS_st */
            	3216, 0,
            0, 0, 0, /* 3216: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3219: pointer.struct.x509_cert_aux_st */
            	3224, 0,
            0, 40, 5, /* 3224: struct.x509_cert_aux_st */
            	3237, 0,
            	3237, 8,
            	1490, 16,
            	1307, 24,
            	3261, 32,
            1, 8, 1, /* 3237: pointer.struct.stack_st_ASN1_OBJECT */
            	3242, 0,
            0, 32, 2, /* 3242: struct.stack_st_fake_ASN1_OBJECT */
            	3249, 8,
            	208, 24,
            8884099, 8, 2, /* 3249: pointer_to_array_of_pointers_to_stack */
            	3256, 0,
            	205, 20,
            0, 8, 1, /* 3256: pointer.ASN1_OBJECT */
            	434, 0,
            1, 8, 1, /* 3261: pointer.struct.stack_st_X509_ALGOR */
            	3266, 0,
            0, 32, 2, /* 3266: struct.stack_st_fake_X509_ALGOR */
            	3273, 8,
            	208, 24,
            8884099, 8, 2, /* 3273: pointer_to_array_of_pointers_to_stack */
            	3280, 0,
            	205, 20,
            0, 8, 1, /* 3280: pointer.X509_ALGOR */
            	487, 0,
            1, 8, 1, /* 3285: pointer.struct.X509_crl_st */
            	3290, 0,
            0, 120, 10, /* 3290: struct.X509_crl_st */
            	1632, 0,
            	1656, 8,
            	1440, 16,
            	2801, 32,
            	3313, 40,
            	1430, 56,
            	1430, 64,
            	3321, 96,
            	3362, 104,
            	52, 112,
            1, 8, 1, /* 3313: pointer.struct.ISSUING_DIST_POINT_st */
            	3318, 0,
            0, 0, 0, /* 3318: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3321: pointer.struct.stack_st_GENERAL_NAMES */
            	3326, 0,
            0, 32, 2, /* 3326: struct.stack_st_fake_GENERAL_NAMES */
            	3333, 8,
            	208, 24,
            8884099, 8, 2, /* 3333: pointer_to_array_of_pointers_to_stack */
            	3340, 0,
            	205, 20,
            0, 8, 1, /* 3340: pointer.GENERAL_NAMES */
            	3345, 0,
            0, 0, 1, /* 3345: GENERAL_NAMES */
            	3350, 0,
            0, 32, 1, /* 3350: struct.stack_st_GENERAL_NAME */
            	3355, 0,
            0, 32, 2, /* 3355: struct.stack_st */
            	1262, 8,
            	208, 24,
            1, 8, 1, /* 3362: pointer.struct.x509_crl_method_st */
            	3367, 0,
            0, 0, 0, /* 3367: struct.x509_crl_method_st */
            8884097, 8, 0, /* 3370: pointer.func */
            8884097, 8, 0, /* 3373: pointer.func */
            0, 104, 11, /* 3376: struct.x509_cinf_st */
            	3401, 0,
            	3401, 8,
            	3411, 16,
            	3568, 24,
            	3616, 32,
            	3568, 40,
            	3633, 48,
            	3500, 56,
            	3500, 64,
            	4021, 72,
            	4045, 80,
            1, 8, 1, /* 3401: pointer.struct.asn1_string_st */
            	3406, 0,
            0, 24, 1, /* 3406: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 3411: pointer.struct.X509_algor_st */
            	3416, 0,
            0, 16, 2, /* 3416: struct.X509_algor_st */
            	3423, 0,
            	3437, 8,
            1, 8, 1, /* 3423: pointer.struct.asn1_object_st */
            	3428, 0,
            0, 40, 3, /* 3428: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	182, 24,
            1, 8, 1, /* 3437: pointer.struct.asn1_type_st */
            	3442, 0,
            0, 16, 1, /* 3442: struct.asn1_type_st */
            	3447, 8,
            0, 8, 20, /* 3447: union.unknown */
            	64, 0,
            	3490, 0,
            	3423, 0,
            	3401, 0,
            	3495, 0,
            	3500, 0,
            	3505, 0,
            	3510, 0,
            	3515, 0,
            	3520, 0,
            	3525, 0,
            	3530, 0,
            	3535, 0,
            	3540, 0,
            	3545, 0,
            	3550, 0,
            	3555, 0,
            	3490, 0,
            	3490, 0,
            	3560, 0,
            1, 8, 1, /* 3490: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3495: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3500: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3505: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3510: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3515: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3520: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3525: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3530: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3535: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3540: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3545: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3550: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3555: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3560: pointer.struct.ASN1_VALUE_st */
            	3565, 0,
            0, 0, 0, /* 3565: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3568: pointer.struct.X509_name_st */
            	3573, 0,
            0, 40, 3, /* 3573: struct.X509_name_st */
            	3582, 0,
            	3606, 16,
            	200, 24,
            1, 8, 1, /* 3582: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3587, 0,
            0, 32, 2, /* 3587: struct.stack_st_fake_X509_NAME_ENTRY */
            	3594, 8,
            	208, 24,
            8884099, 8, 2, /* 3594: pointer_to_array_of_pointers_to_stack */
            	3601, 0,
            	205, 20,
            0, 8, 1, /* 3601: pointer.X509_NAME_ENTRY */
            	156, 0,
            1, 8, 1, /* 3606: pointer.struct.buf_mem_st */
            	3611, 0,
            0, 24, 1, /* 3611: struct.buf_mem_st */
            	64, 8,
            1, 8, 1, /* 3616: pointer.struct.X509_val_st */
            	3621, 0,
            0, 16, 2, /* 3621: struct.X509_val_st */
            	3628, 0,
            	3628, 8,
            1, 8, 1, /* 3628: pointer.struct.asn1_string_st */
            	3406, 0,
            1, 8, 1, /* 3633: pointer.struct.X509_pubkey_st */
            	3638, 0,
            0, 24, 3, /* 3638: struct.X509_pubkey_st */
            	3411, 0,
            	3500, 8,
            	3647, 16,
            1, 8, 1, /* 3647: pointer.struct.evp_pkey_st */
            	3652, 0,
            0, 56, 4, /* 3652: struct.evp_pkey_st */
            	3663, 16,
            	3671, 24,
            	3679, 32,
            	3997, 48,
            1, 8, 1, /* 3663: pointer.struct.evp_pkey_asn1_method_st */
            	3668, 0,
            0, 0, 0, /* 3668: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3671: pointer.struct.engine_st */
            	3676, 0,
            0, 0, 0, /* 3676: struct.engine_st */
            0, 8, 5, /* 3679: union.unknown */
            	64, 0,
            	3692, 0,
            	3843, 0,
            	3921, 0,
            	3989, 0,
            1, 8, 1, /* 3692: pointer.struct.rsa_st */
            	3697, 0,
            0, 168, 17, /* 3697: struct.rsa_st */
            	3734, 16,
            	3671, 24,
            	3789, 32,
            	3789, 40,
            	3789, 48,
            	3789, 56,
            	3789, 64,
            	3789, 72,
            	3789, 80,
            	3789, 88,
            	3799, 96,
            	3821, 120,
            	3821, 128,
            	3821, 136,
            	64, 144,
            	3835, 152,
            	3835, 160,
            1, 8, 1, /* 3734: pointer.struct.rsa_meth_st */
            	3739, 0,
            0, 112, 13, /* 3739: struct.rsa_meth_st */
            	13, 0,
            	3768, 8,
            	3768, 16,
            	3768, 24,
            	3768, 32,
            	3771, 40,
            	3774, 48,
            	3777, 56,
            	3777, 64,
            	64, 80,
            	3780, 88,
            	3783, 96,
            	3786, 104,
            8884097, 8, 0, /* 3768: pointer.func */
            8884097, 8, 0, /* 3771: pointer.func */
            8884097, 8, 0, /* 3774: pointer.func */
            8884097, 8, 0, /* 3777: pointer.func */
            8884097, 8, 0, /* 3780: pointer.func */
            8884097, 8, 0, /* 3783: pointer.func */
            8884097, 8, 0, /* 3786: pointer.func */
            1, 8, 1, /* 3789: pointer.struct.bignum_st */
            	3794, 0,
            0, 24, 1, /* 3794: struct.bignum_st */
            	79, 0,
            0, 16, 1, /* 3799: struct.crypto_ex_data_st */
            	3804, 0,
            1, 8, 1, /* 3804: pointer.struct.stack_st_void */
            	3809, 0,
            0, 32, 1, /* 3809: struct.stack_st_void */
            	3814, 0,
            0, 32, 2, /* 3814: struct.stack_st */
            	1262, 8,
            	208, 24,
            1, 8, 1, /* 3821: pointer.struct.bn_mont_ctx_st */
            	3826, 0,
            0, 96, 3, /* 3826: struct.bn_mont_ctx_st */
            	3794, 8,
            	3794, 32,
            	3794, 56,
            1, 8, 1, /* 3835: pointer.struct.bn_blinding_st */
            	3840, 0,
            0, 0, 0, /* 3840: struct.bn_blinding_st */
            1, 8, 1, /* 3843: pointer.struct.dsa_st */
            	3848, 0,
            0, 136, 11, /* 3848: struct.dsa_st */
            	3789, 24,
            	3789, 32,
            	3789, 40,
            	3789, 48,
            	3789, 56,
            	3789, 64,
            	3789, 72,
            	3821, 88,
            	3799, 104,
            	3873, 120,
            	3671, 128,
            1, 8, 1, /* 3873: pointer.struct.dsa_method */
            	3878, 0,
            0, 96, 11, /* 3878: struct.dsa_method */
            	13, 0,
            	3903, 8,
            	3906, 16,
            	3909, 24,
            	3370, 32,
            	3912, 40,
            	3915, 48,
            	3915, 56,
            	64, 72,
            	3918, 80,
            	3915, 88,
            8884097, 8, 0, /* 3903: pointer.func */
            8884097, 8, 0, /* 3906: pointer.func */
            8884097, 8, 0, /* 3909: pointer.func */
            8884097, 8, 0, /* 3912: pointer.func */
            8884097, 8, 0, /* 3915: pointer.func */
            8884097, 8, 0, /* 3918: pointer.func */
            1, 8, 1, /* 3921: pointer.struct.dh_st */
            	3926, 0,
            0, 144, 12, /* 3926: struct.dh_st */
            	3789, 8,
            	3789, 16,
            	3789, 32,
            	3789, 40,
            	3821, 56,
            	3789, 64,
            	3789, 72,
            	200, 80,
            	3789, 96,
            	3799, 112,
            	3953, 128,
            	3671, 136,
            1, 8, 1, /* 3953: pointer.struct.dh_method */
            	3958, 0,
            0, 72, 8, /* 3958: struct.dh_method */
            	13, 0,
            	3977, 8,
            	3980, 16,
            	3983, 24,
            	3977, 32,
            	3977, 40,
            	64, 56,
            	3986, 64,
            8884097, 8, 0, /* 3977: pointer.func */
            8884097, 8, 0, /* 3980: pointer.func */
            8884097, 8, 0, /* 3983: pointer.func */
            8884097, 8, 0, /* 3986: pointer.func */
            1, 8, 1, /* 3989: pointer.struct.ec_key_st */
            	3994, 0,
            0, 0, 0, /* 3994: struct.ec_key_st */
            1, 8, 1, /* 3997: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4002, 0,
            0, 32, 2, /* 4002: struct.stack_st_fake_X509_ATTRIBUTE */
            	4009, 8,
            	208, 24,
            8884099, 8, 2, /* 4009: pointer_to_array_of_pointers_to_stack */
            	4016, 0,
            	205, 20,
            0, 8, 1, /* 4016: pointer.X509_ATTRIBUTE */
            	2414, 0,
            1, 8, 1, /* 4021: pointer.struct.stack_st_X509_EXTENSION */
            	4026, 0,
            0, 32, 2, /* 4026: struct.stack_st_fake_X509_EXTENSION */
            	4033, 8,
            	208, 24,
            8884099, 8, 2, /* 4033: pointer_to_array_of_pointers_to_stack */
            	4040, 0,
            	205, 20,
            0, 8, 1, /* 4040: pointer.X509_EXTENSION */
            	1132, 0,
            0, 24, 1, /* 4045: struct.ASN1_ENCODING_st */
            	200, 0,
            0, 0, 0, /* 4050: struct.X509_POLICY_CACHE_st */
            0, 184, 12, /* 4053: struct.x509_st */
            	4080, 0,
            	3411, 8,
            	3500, 16,
            	64, 32,
            	3799, 40,
            	3505, 104,
            	4085, 112,
            	4093, 120,
            	4098, 128,
            	4122, 136,
            	4146, 144,
            	4154, 176,
            1, 8, 1, /* 4080: pointer.struct.x509_cinf_st */
            	3376, 0,
            1, 8, 1, /* 4085: pointer.struct.AUTHORITY_KEYID_st */
            	4090, 0,
            0, 0, 0, /* 4090: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4093: pointer.struct.X509_POLICY_CACHE_st */
            	4050, 0,
            1, 8, 1, /* 4098: pointer.struct.stack_st_DIST_POINT */
            	4103, 0,
            0, 32, 2, /* 4103: struct.stack_st_fake_DIST_POINT */
            	4110, 8,
            	208, 24,
            8884099, 8, 2, /* 4110: pointer_to_array_of_pointers_to_stack */
            	4117, 0,
            	205, 20,
            0, 8, 1, /* 4117: pointer.DIST_POINT */
            	972, 0,
            1, 8, 1, /* 4122: pointer.struct.stack_st_GENERAL_NAME */
            	4127, 0,
            0, 32, 2, /* 4127: struct.stack_st_fake_GENERAL_NAME */
            	4134, 8,
            	208, 24,
            8884099, 8, 2, /* 4134: pointer_to_array_of_pointers_to_stack */
            	4141, 0,
            	205, 20,
            0, 8, 1, /* 4141: pointer.GENERAL_NAME */
            	678, 0,
            1, 8, 1, /* 4146: pointer.struct.NAME_CONSTRAINTS_st */
            	4151, 0,
            0, 0, 0, /* 4151: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4154: pointer.struct.x509_cert_aux_st */
            	4159, 0,
            0, 40, 5, /* 4159: struct.x509_cert_aux_st */
            	4172, 0,
            	4172, 8,
            	3555, 16,
            	3505, 24,
            	4196, 32,
            1, 8, 1, /* 4172: pointer.struct.stack_st_ASN1_OBJECT */
            	4177, 0,
            0, 32, 2, /* 4177: struct.stack_st_fake_ASN1_OBJECT */
            	4184, 8,
            	208, 24,
            8884099, 8, 2, /* 4184: pointer_to_array_of_pointers_to_stack */
            	4191, 0,
            	205, 20,
            0, 8, 1, /* 4191: pointer.ASN1_OBJECT */
            	434, 0,
            1, 8, 1, /* 4196: pointer.struct.stack_st_X509_ALGOR */
            	4201, 0,
            0, 32, 2, /* 4201: struct.stack_st_fake_X509_ALGOR */
            	4208, 8,
            	208, 24,
            8884099, 8, 2, /* 4208: pointer_to_array_of_pointers_to_stack */
            	4215, 0,
            	205, 20,
            0, 8, 1, /* 4215: pointer.X509_ALGOR */
            	487, 0,
            8884097, 8, 0, /* 4220: pointer.func */
            8884097, 8, 0, /* 4223: pointer.func */
            8884097, 8, 0, /* 4226: pointer.func */
            0, 144, 15, /* 4229: struct.x509_store_st */
            	2839, 8,
            	4262, 16,
            	4465, 24,
            	4477, 32,
            	4480, 40,
            	4483, 48,
            	4486, 56,
            	4477, 64,
            	4489, 72,
            	4492, 80,
            	4495, 88,
            	3373, 96,
            	4498, 104,
            	4477, 112,
            	1240, 120,
            1, 8, 1, /* 4262: pointer.struct.stack_st_X509_LOOKUP */
            	4267, 0,
            0, 32, 2, /* 4267: struct.stack_st_fake_X509_LOOKUP */
            	4274, 8,
            	208, 24,
            8884099, 8, 2, /* 4274: pointer_to_array_of_pointers_to_stack */
            	4281, 0,
            	205, 20,
            0, 8, 1, /* 4281: pointer.X509_LOOKUP */
            	4286, 0,
            0, 0, 1, /* 4286: X509_LOOKUP */
            	4291, 0,
            0, 32, 3, /* 4291: struct.x509_lookup_st */
            	4300, 8,
            	64, 16,
            	4343, 24,
            1, 8, 1, /* 4300: pointer.struct.x509_lookup_method_st */
            	4305, 0,
            0, 80, 10, /* 4305: struct.x509_lookup_method_st */
            	13, 0,
            	4328, 8,
            	2830, 16,
            	4328, 24,
            	4328, 32,
            	4331, 40,
            	4334, 48,
            	4223, 56,
            	4337, 64,
            	4340, 72,
            8884097, 8, 0, /* 4328: pointer.func */
            8884097, 8, 0, /* 4331: pointer.func */
            8884097, 8, 0, /* 4334: pointer.func */
            8884097, 8, 0, /* 4337: pointer.func */
            8884097, 8, 0, /* 4340: pointer.func */
            1, 8, 1, /* 4343: pointer.struct.x509_store_st */
            	4348, 0,
            0, 144, 15, /* 4348: struct.x509_store_st */
            	4381, 8,
            	4405, 16,
            	4429, 24,
            	4441, 32,
            	4444, 40,
            	4447, 48,
            	4450, 56,
            	4441, 64,
            	4453, 72,
            	4456, 80,
            	4459, 88,
            	4462, 96,
            	4226, 104,
            	4441, 112,
            	1285, 120,
            1, 8, 1, /* 4381: pointer.struct.stack_st_X509_OBJECT */
            	4386, 0,
            0, 32, 2, /* 4386: struct.stack_st_fake_X509_OBJECT */
            	4393, 8,
            	208, 24,
            8884099, 8, 2, /* 4393: pointer_to_array_of_pointers_to_stack */
            	4400, 0,
            	205, 20,
            0, 8, 1, /* 4400: pointer.X509_OBJECT */
            	2863, 0,
            1, 8, 1, /* 4405: pointer.struct.stack_st_X509_LOOKUP */
            	4410, 0,
            0, 32, 2, /* 4410: struct.stack_st_fake_X509_LOOKUP */
            	4417, 8,
            	208, 24,
            8884099, 8, 2, /* 4417: pointer_to_array_of_pointers_to_stack */
            	4424, 0,
            	205, 20,
            0, 8, 1, /* 4424: pointer.X509_LOOKUP */
            	4286, 0,
            1, 8, 1, /* 4429: pointer.struct.X509_VERIFY_PARAM_st */
            	4434, 0,
            0, 56, 2, /* 4434: struct.X509_VERIFY_PARAM_st */
            	64, 0,
            	3237, 48,
            8884097, 8, 0, /* 4441: pointer.func */
            8884097, 8, 0, /* 4444: pointer.func */
            8884097, 8, 0, /* 4447: pointer.func */
            8884097, 8, 0, /* 4450: pointer.func */
            8884097, 8, 0, /* 4453: pointer.func */
            8884097, 8, 0, /* 4456: pointer.func */
            8884097, 8, 0, /* 4459: pointer.func */
            8884097, 8, 0, /* 4462: pointer.func */
            1, 8, 1, /* 4465: pointer.struct.X509_VERIFY_PARAM_st */
            	4470, 0,
            0, 56, 2, /* 4470: struct.X509_VERIFY_PARAM_st */
            	64, 0,
            	410, 48,
            8884097, 8, 0, /* 4477: pointer.func */
            8884097, 8, 0, /* 4480: pointer.func */
            8884097, 8, 0, /* 4483: pointer.func */
            8884097, 8, 0, /* 4486: pointer.func */
            8884097, 8, 0, /* 4489: pointer.func */
            8884097, 8, 0, /* 4492: pointer.func */
            8884097, 8, 0, /* 4495: pointer.func */
            8884097, 8, 0, /* 4498: pointer.func */
            8884097, 8, 0, /* 4501: pointer.func */
            0, 0, 1, /* 4504: SSL_CIPHER */
            	4509, 0,
            0, 88, 1, /* 4509: struct.ssl_cipher_st */
            	13, 8,
            8884097, 8, 0, /* 4514: pointer.func */
            8884097, 8, 0, /* 4517: pointer.func */
            0, 112, 11, /* 4520: struct.ssl3_enc_method */
            	2836, 0,
            	4514, 8,
            	4545, 16,
            	4548, 24,
            	2836, 32,
            	4551, 40,
            	4554, 56,
            	13, 64,
            	13, 80,
            	4557, 96,
            	4560, 104,
            8884097, 8, 0, /* 4545: pointer.func */
            8884097, 8, 0, /* 4548: pointer.func */
            8884097, 8, 0, /* 4551: pointer.func */
            8884097, 8, 0, /* 4554: pointer.func */
            8884097, 8, 0, /* 4557: pointer.func */
            8884097, 8, 0, /* 4560: pointer.func */
            8884097, 8, 0, /* 4563: pointer.func */
            8884097, 8, 0, /* 4566: pointer.func */
            0, 736, 50, /* 4569: struct.ssl_ctx_st */
            	4672, 0,
            	4774, 8,
            	4774, 16,
            	4798, 24,
            	4803, 32,
            	4839, 48,
            	4839, 56,
            	331, 80,
            	328, 88,
            	4922, 96,
            	1330, 152,
            	52, 160,
            	4925, 168,
            	52, 176,
            	325, 184,
            	4928, 192,
            	322, 200,
            	1240, 208,
            	2750, 224,
            	2750, 232,
            	2750, 240,
            	4893, 248,
            	298, 256,
            	249, 264,
            	220, 272,
            	1836, 304,
            	4220, 320,
            	52, 328,
            	4480, 376,
            	4931, 384,
            	4465, 392,
            	1272, 408,
            	55, 416,
            	52, 424,
            	4517, 480,
            	58, 488,
            	52, 496,
            	113, 504,
            	52, 512,
            	64, 520,
            	110, 528,
            	4934, 536,
            	100, 552,
            	100, 560,
            	21, 568,
            	87, 696,
            	52, 704,
            	18, 712,
            	52, 720,
            	2806, 728,
            1, 8, 1, /* 4672: pointer.struct.ssl_method_st */
            	4677, 0,
            0, 232, 28, /* 4677: struct.ssl_method_st */
            	4545, 8,
            	4736, 16,
            	4736, 24,
            	4545, 32,
            	4545, 40,
            	4739, 48,
            	4739, 56,
            	4742, 64,
            	4545, 72,
            	4545, 80,
            	4545, 88,
            	2833, 96,
            	1333, 104,
            	4563, 112,
            	4545, 120,
            	4745, 128,
            	4748, 136,
            	4751, 144,
            	4501, 152,
            	4754, 160,
            	4757, 168,
            	4760, 176,
            	4566, 184,
            	278, 192,
            	4763, 200,
            	4757, 208,
            	4768, 216,
            	4771, 224,
            8884097, 8, 0, /* 4736: pointer.func */
            8884097, 8, 0, /* 4739: pointer.func */
            8884097, 8, 0, /* 4742: pointer.func */
            8884097, 8, 0, /* 4745: pointer.func */
            8884097, 8, 0, /* 4748: pointer.func */
            8884097, 8, 0, /* 4751: pointer.func */
            8884097, 8, 0, /* 4754: pointer.func */
            8884097, 8, 0, /* 4757: pointer.func */
            8884097, 8, 0, /* 4760: pointer.func */
            1, 8, 1, /* 4763: pointer.struct.ssl3_enc_method */
            	4520, 0,
            8884097, 8, 0, /* 4768: pointer.func */
            8884097, 8, 0, /* 4771: pointer.func */
            1, 8, 1, /* 4774: pointer.struct.stack_st_SSL_CIPHER */
            	4779, 0,
            0, 32, 2, /* 4779: struct.stack_st_fake_SSL_CIPHER */
            	4786, 8,
            	208, 24,
            8884099, 8, 2, /* 4786: pointer_to_array_of_pointers_to_stack */
            	4793, 0,
            	205, 20,
            0, 8, 1, /* 4793: pointer.SSL_CIPHER */
            	4504, 0,
            1, 8, 1, /* 4798: pointer.struct.x509_store_st */
            	4229, 0,
            1, 8, 1, /* 4803: pointer.struct.lhash_st */
            	4808, 0,
            0, 176, 3, /* 4808: struct.lhash_st */
            	4817, 0,
            	208, 8,
            	4836, 16,
            8884099, 8, 2, /* 4817: pointer_to_array_of_pointers_to_stack */
            	4824, 0,
            	84, 28,
            1, 8, 1, /* 4824: pointer.struct.lhash_node_st */
            	4829, 0,
            0, 24, 2, /* 4829: struct.lhash_node_st */
            	52, 0,
            	4824, 8,
            8884097, 8, 0, /* 4836: pointer.func */
            1, 8, 1, /* 4839: pointer.struct.ssl_session_st */
            	4844, 0,
            0, 352, 14, /* 4844: struct.ssl_session_st */
            	64, 144,
            	64, 152,
            	4875, 168,
            	1872, 176,
            	339, 224,
            	4774, 240,
            	1240, 248,
            	4839, 264,
            	4839, 272,
            	64, 280,
            	200, 296,
            	200, 312,
            	200, 320,
            	64, 344,
            1, 8, 1, /* 4875: pointer.struct.sess_cert_st */
            	4880, 0,
            0, 248, 5, /* 4880: struct.sess_cert_st */
            	4893, 0,
            	1858, 16,
            	2755, 216,
            	1346, 224,
            	344, 232,
            1, 8, 1, /* 4893: pointer.struct.stack_st_X509 */
            	4898, 0,
            0, 32, 2, /* 4898: struct.stack_st_fake_X509 */
            	4905, 8,
            	208, 24,
            8884099, 8, 2, /* 4905: pointer_to_array_of_pointers_to_stack */
            	4912, 0,
            	205, 20,
            0, 8, 1, /* 4912: pointer.X509 */
            	4917, 0,
            0, 0, 1, /* 4917: X509 */
            	4053, 0,
            8884097, 8, 0, /* 4922: pointer.func */
            8884097, 8, 0, /* 4925: pointer.func */
            8884097, 8, 0, /* 4928: pointer.func */
            8884097, 8, 0, /* 4931: pointer.func */
            8884097, 8, 0, /* 4934: pointer.func */
            1, 8, 1, /* 4937: pointer.struct.ssl_ctx_st */
            	4569, 0,
            0, 1, 0, /* 4942: char */
        },
        .arg_entity_index = { 4937, 0, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    void (*new_arg_b)(struct ssl_ctx_st *,SSL_SESSION *) = *((void (**)(struct ssl_ctx_st *,SSL_SESSION *))new_args->args[1]);

    void (*orig_SSL_CTX_sess_set_remove_cb)(SSL_CTX *,void (*)(struct ssl_ctx_st *,SSL_SESSION *));
    orig_SSL_CTX_sess_set_remove_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_remove_cb");
    (*orig_SSL_CTX_sess_set_remove_cb)(new_arg_a,new_arg_b);

    syscall(889);

}

