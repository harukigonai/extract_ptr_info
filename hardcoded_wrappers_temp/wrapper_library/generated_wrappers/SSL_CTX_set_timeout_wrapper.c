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

long bb_SSL_CTX_set_timeout(SSL_CTX * arg_a,long arg_b);

long SSL_CTX_set_timeout(SSL_CTX * arg_a,long arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_set_timeout called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_set_timeout(arg_a,arg_b);
    else {
        long (*orig_SSL_CTX_set_timeout)(SSL_CTX *,long);
        orig_SSL_CTX_set_timeout = dlsym(RTLD_NEXT, "SSL_CTX_set_timeout");
        return orig_SSL_CTX_set_timeout(arg_a,arg_b);
    }
}

long bb_SSL_CTX_set_timeout(SSL_CTX * arg_a,long arg_b) 
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
            8884097, 8, 0, /* 18: pointer.func */
            0, 8, 1, /* 21: struct.ssl3_buf_freelist_entry_st */
            	26, 0,
            1, 8, 1, /* 26: pointer.struct.ssl3_buf_freelist_entry_st */
            	21, 0,
            1, 8, 1, /* 31: pointer.struct.ssl3_buf_freelist_st */
            	36, 0,
            0, 24, 1, /* 36: struct.ssl3_buf_freelist_st */
            	26, 16,
            8884097, 8, 0, /* 41: pointer.func */
            8884097, 8, 0, /* 44: pointer.func */
            8884097, 8, 0, /* 47: pointer.func */
            8884097, 8, 0, /* 50: pointer.func */
            8884097, 8, 0, /* 53: pointer.func */
            8884097, 8, 0, /* 56: pointer.func */
            1, 8, 1, /* 59: pointer.struct.buf_mem_st */
            	64, 0,
            0, 24, 1, /* 64: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 69: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 74: pointer.struct.stack_st_X509_NAME_ENTRY */
            	79, 0,
            0, 32, 2, /* 79: struct.stack_st_fake_X509_NAME_ENTRY */
            	86, 8,
            	150, 24,
            8884099, 8, 2, /* 86: pointer_to_array_of_pointers_to_stack */
            	93, 0,
            	147, 20,
            0, 8, 1, /* 93: pointer.X509_NAME_ENTRY */
            	98, 0,
            0, 0, 1, /* 98: X509_NAME_ENTRY */
            	103, 0,
            0, 24, 2, /* 103: struct.X509_name_entry_st */
            	110, 0,
            	132, 8,
            1, 8, 1, /* 110: pointer.struct.asn1_object_st */
            	115, 0,
            0, 40, 3, /* 115: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	124, 24,
            1, 8, 1, /* 124: pointer.unsigned char */
            	129, 0,
            0, 1, 0, /* 129: unsigned char */
            1, 8, 1, /* 132: pointer.struct.asn1_string_st */
            	137, 0,
            0, 24, 1, /* 137: struct.asn1_string_st */
            	142, 8,
            1, 8, 1, /* 142: pointer.unsigned char */
            	129, 0,
            0, 4, 0, /* 147: int */
            8884097, 8, 0, /* 150: pointer.func */
            1, 8, 1, /* 153: pointer.struct.stack_st_X509_NAME */
            	158, 0,
            0, 32, 2, /* 158: struct.stack_st_fake_X509_NAME */
            	165, 8,
            	150, 24,
            8884099, 8, 2, /* 165: pointer_to_array_of_pointers_to_stack */
            	172, 0,
            	147, 20,
            0, 8, 1, /* 172: pointer.X509_NAME */
            	177, 0,
            0, 0, 1, /* 177: X509_NAME */
            	182, 0,
            0, 40, 3, /* 182: struct.X509_name_st */
            	74, 0,
            	59, 16,
            	142, 24,
            8884097, 8, 0, /* 191: pointer.func */
            8884097, 8, 0, /* 194: pointer.func */
            8884097, 8, 0, /* 197: pointer.func */
            8884097, 8, 0, /* 200: pointer.func */
            0, 128, 14, /* 203: struct.srp_ctx_st */
            	234, 0,
            	47, 8,
            	237, 16,
            	240, 24,
            	69, 32,
            	243, 40,
            	243, 48,
            	243, 56,
            	243, 64,
            	243, 72,
            	243, 80,
            	243, 88,
            	243, 96,
            	69, 104,
            0, 8, 0, /* 234: pointer.void */
            8884097, 8, 0, /* 237: pointer.func */
            8884097, 8, 0, /* 240: pointer.func */
            1, 8, 1, /* 243: pointer.struct.bignum_st */
            	248, 0,
            0, 24, 1, /* 248: struct.bignum_st */
            	253, 0,
            1, 8, 1, /* 253: pointer.unsigned int */
            	258, 0,
            0, 4, 0, /* 258: unsigned int */
            0, 64, 7, /* 261: struct.comp_method_st */
            	10, 8,
            	200, 16,
            	197, 24,
            	194, 32,
            	194, 40,
            	278, 48,
            	278, 56,
            8884097, 8, 0, /* 278: pointer.func */
            1, 8, 1, /* 281: pointer.struct.comp_method_st */
            	261, 0,
            0, 0, 1, /* 286: SSL_COMP */
            	291, 0,
            0, 24, 2, /* 291: struct.ssl_comp_st */
            	10, 8,
            	281, 16,
            1, 8, 1, /* 298: pointer.struct.stack_st_SSL_COMP */
            	303, 0,
            0, 32, 2, /* 303: struct.stack_st_fake_SSL_COMP */
            	310, 8,
            	150, 24,
            8884099, 8, 2, /* 310: pointer_to_array_of_pointers_to_stack */
            	317, 0,
            	147, 20,
            0, 8, 1, /* 317: pointer.SSL_COMP */
            	286, 0,
            8884097, 8, 0, /* 322: pointer.func */
            8884097, 8, 0, /* 325: pointer.func */
            8884097, 8, 0, /* 328: pointer.func */
            0, 88, 1, /* 331: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 336: pointer.struct.ssl_cipher_st */
            	331, 0,
            1, 8, 1, /* 341: pointer.struct.ec_key_st */
            	346, 0,
            0, 0, 0, /* 346: struct.ec_key_st */
            1, 8, 1, /* 349: pointer.struct.dh_st */
            	354, 0,
            0, 144, 12, /* 354: struct.dh_st */
            	243, 8,
            	243, 16,
            	243, 32,
            	243, 40,
            	381, 56,
            	243, 64,
            	243, 72,
            	142, 80,
            	243, 96,
            	395, 112,
            	422, 128,
            	458, 136,
            1, 8, 1, /* 381: pointer.struct.bn_mont_ctx_st */
            	386, 0,
            0, 96, 3, /* 386: struct.bn_mont_ctx_st */
            	248, 8,
            	248, 32,
            	248, 56,
            0, 16, 1, /* 395: struct.crypto_ex_data_st */
            	400, 0,
            1, 8, 1, /* 400: pointer.struct.stack_st_void */
            	405, 0,
            0, 32, 1, /* 405: struct.stack_st_void */
            	410, 0,
            0, 32, 2, /* 410: struct.stack_st */
            	417, 8,
            	150, 24,
            1, 8, 1, /* 417: pointer.pointer.char */
            	69, 0,
            1, 8, 1, /* 422: pointer.struct.dh_method */
            	427, 0,
            0, 72, 8, /* 427: struct.dh_method */
            	10, 0,
            	446, 8,
            	449, 16,
            	452, 24,
            	446, 32,
            	446, 40,
            	69, 56,
            	455, 64,
            8884097, 8, 0, /* 446: pointer.func */
            8884097, 8, 0, /* 449: pointer.func */
            8884097, 8, 0, /* 452: pointer.func */
            8884097, 8, 0, /* 455: pointer.func */
            1, 8, 1, /* 458: pointer.struct.engine_st */
            	463, 0,
            0, 0, 0, /* 463: struct.engine_st */
            8884097, 8, 0, /* 466: pointer.func */
            8884097, 8, 0, /* 469: pointer.func */
            8884097, 8, 0, /* 472: pointer.func */
            8884097, 8, 0, /* 475: pointer.func */
            8884097, 8, 0, /* 478: pointer.func */
            8884097, 8, 0, /* 481: pointer.func */
            0, 120, 8, /* 484: struct.env_md_st */
            	481, 24,
            	478, 32,
            	475, 40,
            	472, 48,
            	481, 56,
            	469, 64,
            	466, 72,
            	503, 112,
            8884097, 8, 0, /* 503: pointer.func */
            1, 8, 1, /* 506: pointer.struct.x509_cert_aux_st */
            	511, 0,
            0, 40, 5, /* 511: struct.x509_cert_aux_st */
            	524, 0,
            	524, 8,
            	562, 16,
            	572, 24,
            	577, 32,
            1, 8, 1, /* 524: pointer.struct.stack_st_ASN1_OBJECT */
            	529, 0,
            0, 32, 2, /* 529: struct.stack_st_fake_ASN1_OBJECT */
            	536, 8,
            	150, 24,
            8884099, 8, 2, /* 536: pointer_to_array_of_pointers_to_stack */
            	543, 0,
            	147, 20,
            0, 8, 1, /* 543: pointer.ASN1_OBJECT */
            	548, 0,
            0, 0, 1, /* 548: ASN1_OBJECT */
            	553, 0,
            0, 40, 3, /* 553: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	124, 24,
            1, 8, 1, /* 562: pointer.struct.asn1_string_st */
            	567, 0,
            0, 24, 1, /* 567: struct.asn1_string_st */
            	142, 8,
            1, 8, 1, /* 572: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 577: pointer.struct.stack_st_X509_ALGOR */
            	582, 0,
            0, 32, 2, /* 582: struct.stack_st_fake_X509_ALGOR */
            	589, 8,
            	150, 24,
            8884099, 8, 2, /* 589: pointer_to_array_of_pointers_to_stack */
            	596, 0,
            	147, 20,
            0, 8, 1, /* 596: pointer.X509_ALGOR */
            	601, 0,
            0, 0, 1, /* 601: X509_ALGOR */
            	606, 0,
            0, 16, 2, /* 606: struct.X509_algor_st */
            	613, 0,
            	627, 8,
            1, 8, 1, /* 613: pointer.struct.asn1_object_st */
            	618, 0,
            0, 40, 3, /* 618: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	124, 24,
            1, 8, 1, /* 627: pointer.struct.asn1_type_st */
            	632, 0,
            0, 16, 1, /* 632: struct.asn1_type_st */
            	637, 8,
            0, 8, 20, /* 637: union.unknown */
            	69, 0,
            	680, 0,
            	613, 0,
            	690, 0,
            	695, 0,
            	700, 0,
            	705, 0,
            	710, 0,
            	715, 0,
            	720, 0,
            	725, 0,
            	730, 0,
            	735, 0,
            	740, 0,
            	745, 0,
            	750, 0,
            	755, 0,
            	680, 0,
            	680, 0,
            	760, 0,
            1, 8, 1, /* 680: pointer.struct.asn1_string_st */
            	685, 0,
            0, 24, 1, /* 685: struct.asn1_string_st */
            	142, 8,
            1, 8, 1, /* 690: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 695: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 700: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 705: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 710: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 715: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 720: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 725: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 730: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 735: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 740: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 745: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 750: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 755: pointer.struct.asn1_string_st */
            	685, 0,
            1, 8, 1, /* 760: pointer.struct.ASN1_VALUE_st */
            	765, 0,
            0, 0, 0, /* 765: struct.ASN1_VALUE_st */
            1, 8, 1, /* 768: pointer.struct.stack_st_GENERAL_NAME */
            	773, 0,
            0, 32, 2, /* 773: struct.stack_st_fake_GENERAL_NAME */
            	780, 8,
            	150, 24,
            8884099, 8, 2, /* 780: pointer_to_array_of_pointers_to_stack */
            	787, 0,
            	147, 20,
            0, 8, 1, /* 787: pointer.GENERAL_NAME */
            	792, 0,
            0, 0, 1, /* 792: GENERAL_NAME */
            	797, 0,
            0, 16, 1, /* 797: struct.GENERAL_NAME_st */
            	802, 8,
            0, 8, 15, /* 802: union.unknown */
            	69, 0,
            	835, 0,
            	954, 0,
            	954, 0,
            	861, 0,
            	1002, 0,
            	1050, 0,
            	954, 0,
            	939, 0,
            	847, 0,
            	939, 0,
            	1002, 0,
            	954, 0,
            	847, 0,
            	861, 0,
            1, 8, 1, /* 835: pointer.struct.otherName_st */
            	840, 0,
            0, 16, 2, /* 840: struct.otherName_st */
            	847, 0,
            	861, 8,
            1, 8, 1, /* 847: pointer.struct.asn1_object_st */
            	852, 0,
            0, 40, 3, /* 852: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	124, 24,
            1, 8, 1, /* 861: pointer.struct.asn1_type_st */
            	866, 0,
            0, 16, 1, /* 866: struct.asn1_type_st */
            	871, 8,
            0, 8, 20, /* 871: union.unknown */
            	69, 0,
            	914, 0,
            	847, 0,
            	924, 0,
            	929, 0,
            	934, 0,
            	939, 0,
            	944, 0,
            	949, 0,
            	954, 0,
            	959, 0,
            	964, 0,
            	969, 0,
            	974, 0,
            	979, 0,
            	984, 0,
            	989, 0,
            	914, 0,
            	914, 0,
            	994, 0,
            1, 8, 1, /* 914: pointer.struct.asn1_string_st */
            	919, 0,
            0, 24, 1, /* 919: struct.asn1_string_st */
            	142, 8,
            1, 8, 1, /* 924: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 929: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 934: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 939: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 944: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 949: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 954: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 959: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 964: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 969: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 974: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 979: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 984: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 989: pointer.struct.asn1_string_st */
            	919, 0,
            1, 8, 1, /* 994: pointer.struct.ASN1_VALUE_st */
            	999, 0,
            0, 0, 0, /* 999: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1002: pointer.struct.X509_name_st */
            	1007, 0,
            0, 40, 3, /* 1007: struct.X509_name_st */
            	1016, 0,
            	1040, 16,
            	142, 24,
            1, 8, 1, /* 1016: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1021, 0,
            0, 32, 2, /* 1021: struct.stack_st_fake_X509_NAME_ENTRY */
            	1028, 8,
            	150, 24,
            8884099, 8, 2, /* 1028: pointer_to_array_of_pointers_to_stack */
            	1035, 0,
            	147, 20,
            0, 8, 1, /* 1035: pointer.X509_NAME_ENTRY */
            	98, 0,
            1, 8, 1, /* 1040: pointer.struct.buf_mem_st */
            	1045, 0,
            0, 24, 1, /* 1045: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 1050: pointer.struct.EDIPartyName_st */
            	1055, 0,
            0, 16, 2, /* 1055: struct.EDIPartyName_st */
            	914, 0,
            	914, 8,
            1, 8, 1, /* 1062: pointer.struct.stack_st_DIST_POINT */
            	1067, 0,
            0, 32, 2, /* 1067: struct.stack_st_fake_DIST_POINT */
            	1074, 8,
            	150, 24,
            8884099, 8, 2, /* 1074: pointer_to_array_of_pointers_to_stack */
            	1081, 0,
            	147, 20,
            0, 8, 1, /* 1081: pointer.DIST_POINT */
            	1086, 0,
            0, 0, 1, /* 1086: DIST_POINT */
            	1091, 0,
            0, 32, 3, /* 1091: struct.DIST_POINT_st */
            	1100, 0,
            	1191, 8,
            	1119, 16,
            1, 8, 1, /* 1100: pointer.struct.DIST_POINT_NAME_st */
            	1105, 0,
            0, 24, 2, /* 1105: struct.DIST_POINT_NAME_st */
            	1112, 8,
            	1167, 16,
            0, 8, 2, /* 1112: union.unknown */
            	1119, 0,
            	1143, 0,
            1, 8, 1, /* 1119: pointer.struct.stack_st_GENERAL_NAME */
            	1124, 0,
            0, 32, 2, /* 1124: struct.stack_st_fake_GENERAL_NAME */
            	1131, 8,
            	150, 24,
            8884099, 8, 2, /* 1131: pointer_to_array_of_pointers_to_stack */
            	1138, 0,
            	147, 20,
            0, 8, 1, /* 1138: pointer.GENERAL_NAME */
            	792, 0,
            1, 8, 1, /* 1143: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1148, 0,
            0, 32, 2, /* 1148: struct.stack_st_fake_X509_NAME_ENTRY */
            	1155, 8,
            	150, 24,
            8884099, 8, 2, /* 1155: pointer_to_array_of_pointers_to_stack */
            	1162, 0,
            	147, 20,
            0, 8, 1, /* 1162: pointer.X509_NAME_ENTRY */
            	98, 0,
            1, 8, 1, /* 1167: pointer.struct.X509_name_st */
            	1172, 0,
            0, 40, 3, /* 1172: struct.X509_name_st */
            	1143, 0,
            	1181, 16,
            	142, 24,
            1, 8, 1, /* 1181: pointer.struct.buf_mem_st */
            	1186, 0,
            0, 24, 1, /* 1186: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 1191: pointer.struct.asn1_string_st */
            	1196, 0,
            0, 24, 1, /* 1196: struct.asn1_string_st */
            	142, 8,
            0, 0, 0, /* 1201: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1204: pointer.struct.X509_POLICY_CACHE_st */
            	1201, 0,
            0, 0, 0, /* 1209: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1212: pointer.struct.AUTHORITY_KEYID_st */
            	1209, 0,
            0, 24, 1, /* 1217: struct.ASN1_ENCODING_st */
            	142, 0,
            1, 8, 1, /* 1222: pointer.struct.stack_st_X509_EXTENSION */
            	1227, 0,
            0, 32, 2, /* 1227: struct.stack_st_fake_X509_EXTENSION */
            	1234, 8,
            	150, 24,
            8884099, 8, 2, /* 1234: pointer_to_array_of_pointers_to_stack */
            	1241, 0,
            	147, 20,
            0, 8, 1, /* 1241: pointer.X509_EXTENSION */
            	1246, 0,
            0, 0, 1, /* 1246: X509_EXTENSION */
            	1251, 0,
            0, 24, 2, /* 1251: struct.X509_extension_st */
            	1258, 0,
            	1272, 16,
            1, 8, 1, /* 1258: pointer.struct.asn1_object_st */
            	1263, 0,
            0, 40, 3, /* 1263: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	124, 24,
            1, 8, 1, /* 1272: pointer.struct.asn1_string_st */
            	1277, 0,
            0, 24, 1, /* 1277: struct.asn1_string_st */
            	142, 8,
            1, 8, 1, /* 1282: pointer.struct.dh_st */
            	354, 0,
            8884097, 8, 0, /* 1287: pointer.func */
            8884097, 8, 0, /* 1290: pointer.func */
            0, 16, 1, /* 1293: struct.crypto_ex_data_st */
            	1298, 0,
            1, 8, 1, /* 1298: pointer.struct.stack_st_void */
            	1303, 0,
            0, 32, 1, /* 1303: struct.stack_st_void */
            	1308, 0,
            0, 32, 2, /* 1308: struct.stack_st */
            	417, 8,
            	150, 24,
            8884097, 8, 0, /* 1315: pointer.func */
            1, 8, 1, /* 1318: pointer.struct.ec_key_st */
            	346, 0,
            0, 136, 11, /* 1323: struct.dsa_st */
            	1348, 24,
            	1348, 32,
            	1348, 40,
            	1348, 48,
            	1348, 56,
            	1348, 64,
            	1348, 72,
            	1358, 88,
            	1293, 104,
            	1372, 120,
            	1423, 128,
            1, 8, 1, /* 1348: pointer.struct.bignum_st */
            	1353, 0,
            0, 24, 1, /* 1353: struct.bignum_st */
            	253, 0,
            1, 8, 1, /* 1358: pointer.struct.bn_mont_ctx_st */
            	1363, 0,
            0, 96, 3, /* 1363: struct.bn_mont_ctx_st */
            	1353, 8,
            	1353, 32,
            	1353, 56,
            1, 8, 1, /* 1372: pointer.struct.dsa_method */
            	1377, 0,
            0, 96, 11, /* 1377: struct.dsa_method */
            	10, 0,
            	1402, 8,
            	1405, 16,
            	1408, 24,
            	1411, 32,
            	1414, 40,
            	1417, 48,
            	1417, 56,
            	69, 72,
            	1420, 80,
            	1417, 88,
            8884097, 8, 0, /* 1402: pointer.func */
            8884097, 8, 0, /* 1405: pointer.func */
            8884097, 8, 0, /* 1408: pointer.func */
            8884097, 8, 0, /* 1411: pointer.func */
            8884097, 8, 0, /* 1414: pointer.func */
            8884097, 8, 0, /* 1417: pointer.func */
            8884097, 8, 0, /* 1420: pointer.func */
            1, 8, 1, /* 1423: pointer.struct.engine_st */
            	1428, 0,
            0, 0, 0, /* 1428: struct.engine_st */
            1, 8, 1, /* 1431: pointer.struct.X509_crl_info_st */
            	1436, 0,
            0, 80, 8, /* 1436: struct.X509_crl_info_st */
            	1455, 0,
            	1465, 8,
            	1614, 16,
            	1662, 24,
            	1662, 32,
            	1667, 40,
            	1770, 48,
            	1794, 56,
            1, 8, 1, /* 1455: pointer.struct.asn1_string_st */
            	1460, 0,
            0, 24, 1, /* 1460: struct.asn1_string_st */
            	142, 8,
            1, 8, 1, /* 1465: pointer.struct.X509_algor_st */
            	1470, 0,
            0, 16, 2, /* 1470: struct.X509_algor_st */
            	1477, 0,
            	1491, 8,
            1, 8, 1, /* 1477: pointer.struct.asn1_object_st */
            	1482, 0,
            0, 40, 3, /* 1482: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	124, 24,
            1, 8, 1, /* 1491: pointer.struct.asn1_type_st */
            	1496, 0,
            0, 16, 1, /* 1496: struct.asn1_type_st */
            	1501, 8,
            0, 8, 20, /* 1501: union.unknown */
            	69, 0,
            	1544, 0,
            	1477, 0,
            	1455, 0,
            	1549, 0,
            	1554, 0,
            	1559, 0,
            	1564, 0,
            	1569, 0,
            	1574, 0,
            	1579, 0,
            	1584, 0,
            	1589, 0,
            	1594, 0,
            	1599, 0,
            	1604, 0,
            	1609, 0,
            	1544, 0,
            	1544, 0,
            	760, 0,
            1, 8, 1, /* 1544: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1549: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1554: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1559: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1564: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1569: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1574: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1579: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1584: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1589: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1594: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1599: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1604: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1609: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1614: pointer.struct.X509_name_st */
            	1619, 0,
            0, 40, 3, /* 1619: struct.X509_name_st */
            	1628, 0,
            	1652, 16,
            	142, 24,
            1, 8, 1, /* 1628: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1633, 0,
            0, 32, 2, /* 1633: struct.stack_st_fake_X509_NAME_ENTRY */
            	1640, 8,
            	150, 24,
            8884099, 8, 2, /* 1640: pointer_to_array_of_pointers_to_stack */
            	1647, 0,
            	147, 20,
            0, 8, 1, /* 1647: pointer.X509_NAME_ENTRY */
            	98, 0,
            1, 8, 1, /* 1652: pointer.struct.buf_mem_st */
            	1657, 0,
            0, 24, 1, /* 1657: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 1662: pointer.struct.asn1_string_st */
            	1460, 0,
            1, 8, 1, /* 1667: pointer.struct.stack_st_X509_REVOKED */
            	1672, 0,
            0, 32, 2, /* 1672: struct.stack_st_fake_X509_REVOKED */
            	1679, 8,
            	150, 24,
            8884099, 8, 2, /* 1679: pointer_to_array_of_pointers_to_stack */
            	1686, 0,
            	147, 20,
            0, 8, 1, /* 1686: pointer.X509_REVOKED */
            	1691, 0,
            0, 0, 1, /* 1691: X509_REVOKED */
            	1696, 0,
            0, 40, 4, /* 1696: struct.x509_revoked_st */
            	1707, 0,
            	1717, 8,
            	1722, 16,
            	1746, 24,
            1, 8, 1, /* 1707: pointer.struct.asn1_string_st */
            	1712, 0,
            0, 24, 1, /* 1712: struct.asn1_string_st */
            	142, 8,
            1, 8, 1, /* 1717: pointer.struct.asn1_string_st */
            	1712, 0,
            1, 8, 1, /* 1722: pointer.struct.stack_st_X509_EXTENSION */
            	1727, 0,
            0, 32, 2, /* 1727: struct.stack_st_fake_X509_EXTENSION */
            	1734, 8,
            	150, 24,
            8884099, 8, 2, /* 1734: pointer_to_array_of_pointers_to_stack */
            	1741, 0,
            	147, 20,
            0, 8, 1, /* 1741: pointer.X509_EXTENSION */
            	1246, 0,
            1, 8, 1, /* 1746: pointer.struct.stack_st_GENERAL_NAME */
            	1751, 0,
            0, 32, 2, /* 1751: struct.stack_st_fake_GENERAL_NAME */
            	1758, 8,
            	150, 24,
            8884099, 8, 2, /* 1758: pointer_to_array_of_pointers_to_stack */
            	1765, 0,
            	147, 20,
            0, 8, 1, /* 1765: pointer.GENERAL_NAME */
            	792, 0,
            1, 8, 1, /* 1770: pointer.struct.stack_st_X509_EXTENSION */
            	1775, 0,
            0, 32, 2, /* 1775: struct.stack_st_fake_X509_EXTENSION */
            	1782, 8,
            	150, 24,
            8884099, 8, 2, /* 1782: pointer_to_array_of_pointers_to_stack */
            	1789, 0,
            	147, 20,
            0, 8, 1, /* 1789: pointer.X509_EXTENSION */
            	1246, 0,
            0, 24, 1, /* 1794: struct.ASN1_ENCODING_st */
            	142, 0,
            1, 8, 1, /* 1799: pointer.struct.cert_st */
            	1804, 0,
            0, 296, 7, /* 1804: struct.cert_st */
            	1821, 0,
            	2729, 48,
            	56, 56,
            	349, 64,
            	53, 72,
            	341, 80,
            	50, 88,
            1, 8, 1, /* 1821: pointer.struct.cert_pkey_st */
            	1826, 0,
            0, 24, 3, /* 1826: struct.cert_pkey_st */
            	1835, 0,
            	2128, 8,
            	2724, 16,
            1, 8, 1, /* 1835: pointer.struct.x509_st */
            	1840, 0,
            0, 184, 12, /* 1840: struct.x509_st */
            	1867, 0,
            	1902, 8,
            	1991, 16,
            	69, 32,
            	395, 40,
            	572, 104,
            	1212, 112,
            	1204, 120,
            	1062, 128,
            	768, 136,
            	2716, 144,
            	506, 176,
            1, 8, 1, /* 1867: pointer.struct.x509_cinf_st */
            	1872, 0,
            0, 104, 11, /* 1872: struct.x509_cinf_st */
            	1897, 0,
            	1897, 8,
            	1902, 16,
            	2049, 24,
            	2097, 32,
            	2049, 40,
            	2114, 48,
            	1991, 56,
            	1991, 64,
            	1222, 72,
            	1217, 80,
            1, 8, 1, /* 1897: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 1902: pointer.struct.X509_algor_st */
            	1907, 0,
            0, 16, 2, /* 1907: struct.X509_algor_st */
            	1914, 0,
            	1928, 8,
            1, 8, 1, /* 1914: pointer.struct.asn1_object_st */
            	1919, 0,
            0, 40, 3, /* 1919: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	124, 24,
            1, 8, 1, /* 1928: pointer.struct.asn1_type_st */
            	1933, 0,
            0, 16, 1, /* 1933: struct.asn1_type_st */
            	1938, 8,
            0, 8, 20, /* 1938: union.unknown */
            	69, 0,
            	1981, 0,
            	1914, 0,
            	1897, 0,
            	1986, 0,
            	1991, 0,
            	572, 0,
            	1996, 0,
            	2001, 0,
            	2006, 0,
            	2011, 0,
            	2016, 0,
            	2021, 0,
            	2026, 0,
            	2031, 0,
            	2036, 0,
            	562, 0,
            	1981, 0,
            	1981, 0,
            	2041, 0,
            1, 8, 1, /* 1981: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 1986: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 1991: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 1996: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 2001: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 2006: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 2011: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 2016: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 2021: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 2026: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 2031: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 2036: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 2041: pointer.struct.ASN1_VALUE_st */
            	2046, 0,
            0, 0, 0, /* 2046: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2049: pointer.struct.X509_name_st */
            	2054, 0,
            0, 40, 3, /* 2054: struct.X509_name_st */
            	2063, 0,
            	2087, 16,
            	142, 24,
            1, 8, 1, /* 2063: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2068, 0,
            0, 32, 2, /* 2068: struct.stack_st_fake_X509_NAME_ENTRY */
            	2075, 8,
            	150, 24,
            8884099, 8, 2, /* 2075: pointer_to_array_of_pointers_to_stack */
            	2082, 0,
            	147, 20,
            0, 8, 1, /* 2082: pointer.X509_NAME_ENTRY */
            	98, 0,
            1, 8, 1, /* 2087: pointer.struct.buf_mem_st */
            	2092, 0,
            0, 24, 1, /* 2092: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 2097: pointer.struct.X509_val_st */
            	2102, 0,
            0, 16, 2, /* 2102: struct.X509_val_st */
            	2109, 0,
            	2109, 8,
            1, 8, 1, /* 2109: pointer.struct.asn1_string_st */
            	567, 0,
            1, 8, 1, /* 2114: pointer.struct.X509_pubkey_st */
            	2119, 0,
            0, 24, 3, /* 2119: struct.X509_pubkey_st */
            	1902, 0,
            	1991, 8,
            	2128, 16,
            1, 8, 1, /* 2128: pointer.struct.evp_pkey_st */
            	2133, 0,
            0, 56, 4, /* 2133: struct.evp_pkey_st */
            	2144, 16,
            	458, 24,
            	2152, 32,
            	2345, 48,
            1, 8, 1, /* 2144: pointer.struct.evp_pkey_asn1_method_st */
            	2149, 0,
            0, 0, 0, /* 2149: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 2152: union.unknown */
            	69, 0,
            	2165, 0,
            	2270, 0,
            	1282, 0,
            	1318, 0,
            1, 8, 1, /* 2165: pointer.struct.rsa_st */
            	2170, 0,
            0, 168, 17, /* 2170: struct.rsa_st */
            	2207, 16,
            	458, 24,
            	243, 32,
            	243, 40,
            	243, 48,
            	243, 56,
            	243, 64,
            	243, 72,
            	243, 80,
            	243, 88,
            	395, 96,
            	381, 120,
            	381, 128,
            	381, 136,
            	69, 144,
            	2262, 152,
            	2262, 160,
            1, 8, 1, /* 2207: pointer.struct.rsa_meth_st */
            	2212, 0,
            0, 112, 13, /* 2212: struct.rsa_meth_st */
            	10, 0,
            	2241, 8,
            	2241, 16,
            	2241, 24,
            	2241, 32,
            	2244, 40,
            	2247, 48,
            	2250, 56,
            	2250, 64,
            	69, 80,
            	2253, 88,
            	2256, 96,
            	2259, 104,
            8884097, 8, 0, /* 2241: pointer.func */
            8884097, 8, 0, /* 2244: pointer.func */
            8884097, 8, 0, /* 2247: pointer.func */
            8884097, 8, 0, /* 2250: pointer.func */
            8884097, 8, 0, /* 2253: pointer.func */
            8884097, 8, 0, /* 2256: pointer.func */
            8884097, 8, 0, /* 2259: pointer.func */
            1, 8, 1, /* 2262: pointer.struct.bn_blinding_st */
            	2267, 0,
            0, 0, 0, /* 2267: struct.bn_blinding_st */
            1, 8, 1, /* 2270: pointer.struct.dsa_st */
            	2275, 0,
            0, 136, 11, /* 2275: struct.dsa_st */
            	243, 24,
            	243, 32,
            	243, 40,
            	243, 48,
            	243, 56,
            	243, 64,
            	243, 72,
            	381, 88,
            	395, 104,
            	2300, 120,
            	458, 128,
            1, 8, 1, /* 2300: pointer.struct.dsa_method */
            	2305, 0,
            0, 96, 11, /* 2305: struct.dsa_method */
            	10, 0,
            	2330, 8,
            	2333, 16,
            	2336, 24,
            	1290, 32,
            	1287, 40,
            	2339, 48,
            	2339, 56,
            	69, 72,
            	2342, 80,
            	2339, 88,
            8884097, 8, 0, /* 2330: pointer.func */
            8884097, 8, 0, /* 2333: pointer.func */
            8884097, 8, 0, /* 2336: pointer.func */
            8884097, 8, 0, /* 2339: pointer.func */
            8884097, 8, 0, /* 2342: pointer.func */
            1, 8, 1, /* 2345: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2350, 0,
            0, 32, 2, /* 2350: struct.stack_st_fake_X509_ATTRIBUTE */
            	2357, 8,
            	150, 24,
            8884099, 8, 2, /* 2357: pointer_to_array_of_pointers_to_stack */
            	2364, 0,
            	147, 20,
            0, 8, 1, /* 2364: pointer.X509_ATTRIBUTE */
            	2369, 0,
            0, 0, 1, /* 2369: X509_ATTRIBUTE */
            	2374, 0,
            0, 24, 2, /* 2374: struct.x509_attributes_st */
            	2381, 0,
            	2395, 16,
            1, 8, 1, /* 2381: pointer.struct.asn1_object_st */
            	2386, 0,
            0, 40, 3, /* 2386: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	124, 24,
            0, 8, 3, /* 2395: union.unknown */
            	69, 0,
            	2404, 0,
            	2583, 0,
            1, 8, 1, /* 2404: pointer.struct.stack_st_ASN1_TYPE */
            	2409, 0,
            0, 32, 2, /* 2409: struct.stack_st_fake_ASN1_TYPE */
            	2416, 8,
            	150, 24,
            8884099, 8, 2, /* 2416: pointer_to_array_of_pointers_to_stack */
            	2423, 0,
            	147, 20,
            0, 8, 1, /* 2423: pointer.ASN1_TYPE */
            	2428, 0,
            0, 0, 1, /* 2428: ASN1_TYPE */
            	2433, 0,
            0, 16, 1, /* 2433: struct.asn1_type_st */
            	2438, 8,
            0, 8, 20, /* 2438: union.unknown */
            	69, 0,
            	2481, 0,
            	2491, 0,
            	2505, 0,
            	2510, 0,
            	2515, 0,
            	2520, 0,
            	2525, 0,
            	2530, 0,
            	2535, 0,
            	2540, 0,
            	2545, 0,
            	2550, 0,
            	2555, 0,
            	2560, 0,
            	2565, 0,
            	2570, 0,
            	2481, 0,
            	2481, 0,
            	2575, 0,
            1, 8, 1, /* 2481: pointer.struct.asn1_string_st */
            	2486, 0,
            0, 24, 1, /* 2486: struct.asn1_string_st */
            	142, 8,
            1, 8, 1, /* 2491: pointer.struct.asn1_object_st */
            	2496, 0,
            0, 40, 3, /* 2496: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	124, 24,
            1, 8, 1, /* 2505: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2510: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2515: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2520: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2525: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2530: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2535: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2540: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2545: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2550: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2555: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2560: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2565: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2570: pointer.struct.asn1_string_st */
            	2486, 0,
            1, 8, 1, /* 2575: pointer.struct.ASN1_VALUE_st */
            	2580, 0,
            0, 0, 0, /* 2580: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2583: pointer.struct.asn1_type_st */
            	2588, 0,
            0, 16, 1, /* 2588: struct.asn1_type_st */
            	2593, 8,
            0, 8, 20, /* 2593: union.unknown */
            	69, 0,
            	2636, 0,
            	2381, 0,
            	2646, 0,
            	2651, 0,
            	2656, 0,
            	2661, 0,
            	2666, 0,
            	2671, 0,
            	2676, 0,
            	2681, 0,
            	2686, 0,
            	2691, 0,
            	2696, 0,
            	2701, 0,
            	2706, 0,
            	2711, 0,
            	2636, 0,
            	2636, 0,
            	760, 0,
            1, 8, 1, /* 2636: pointer.struct.asn1_string_st */
            	2641, 0,
            0, 24, 1, /* 2641: struct.asn1_string_st */
            	142, 8,
            1, 8, 1, /* 2646: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2651: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2656: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2661: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2666: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2671: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2676: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2681: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2686: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2691: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2696: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2701: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2706: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2711: pointer.struct.asn1_string_st */
            	2641, 0,
            1, 8, 1, /* 2716: pointer.struct.NAME_CONSTRAINTS_st */
            	2721, 0,
            0, 0, 0, /* 2721: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2724: pointer.struct.env_md_st */
            	484, 0,
            1, 8, 1, /* 2729: pointer.struct.rsa_st */
            	2170, 0,
            1, 8, 1, /* 2734: pointer.struct.stack_st_DIST_POINT */
            	2739, 0,
            0, 32, 2, /* 2739: struct.stack_st_fake_DIST_POINT */
            	2746, 8,
            	150, 24,
            8884099, 8, 2, /* 2746: pointer_to_array_of_pointers_to_stack */
            	2753, 0,
            	147, 20,
            0, 8, 1, /* 2753: pointer.DIST_POINT */
            	1086, 0,
            1, 8, 1, /* 2758: pointer.struct.X509_POLICY_CACHE_st */
            	2763, 0,
            0, 0, 0, /* 2763: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2766: struct.AUTHORITY_KEYID_st */
            0, 0, 0, /* 2769: struct.ec_key_st */
            1, 8, 1, /* 2772: pointer.struct.AUTHORITY_KEYID_st */
            	2766, 0,
            1, 8, 1, /* 2777: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	2782, 0,
            0, 32, 2, /* 2782: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	2789, 8,
            	150, 24,
            8884099, 8, 2, /* 2789: pointer_to_array_of_pointers_to_stack */
            	2796, 0,
            	147, 20,
            0, 8, 1, /* 2796: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 2801: pointer.func */
            8884097, 8, 0, /* 2804: pointer.func */
            8884097, 8, 0, /* 2807: pointer.func */
            8884097, 8, 0, /* 2810: pointer.func */
            0, 104, 11, /* 2813: struct.x509_cinf_st */
            	2838, 0,
            	2838, 8,
            	2848, 16,
            	3005, 24,
            	3053, 32,
            	3005, 40,
            	3070, 48,
            	2937, 56,
            	2937, 64,
            	3458, 72,
            	3482, 80,
            1, 8, 1, /* 2838: pointer.struct.asn1_string_st */
            	2843, 0,
            0, 24, 1, /* 2843: struct.asn1_string_st */
            	142, 8,
            1, 8, 1, /* 2848: pointer.struct.X509_algor_st */
            	2853, 0,
            0, 16, 2, /* 2853: struct.X509_algor_st */
            	2860, 0,
            	2874, 8,
            1, 8, 1, /* 2860: pointer.struct.asn1_object_st */
            	2865, 0,
            0, 40, 3, /* 2865: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	124, 24,
            1, 8, 1, /* 2874: pointer.struct.asn1_type_st */
            	2879, 0,
            0, 16, 1, /* 2879: struct.asn1_type_st */
            	2884, 8,
            0, 8, 20, /* 2884: union.unknown */
            	69, 0,
            	2927, 0,
            	2860, 0,
            	2838, 0,
            	2932, 0,
            	2937, 0,
            	2942, 0,
            	2947, 0,
            	2952, 0,
            	2957, 0,
            	2962, 0,
            	2967, 0,
            	2972, 0,
            	2977, 0,
            	2982, 0,
            	2987, 0,
            	2992, 0,
            	2927, 0,
            	2927, 0,
            	2997, 0,
            1, 8, 1, /* 2927: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2932: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2937: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2942: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2947: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2952: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2957: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2962: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2967: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2972: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2977: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2982: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2987: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2992: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 2997: pointer.struct.ASN1_VALUE_st */
            	3002, 0,
            0, 0, 0, /* 3002: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3005: pointer.struct.X509_name_st */
            	3010, 0,
            0, 40, 3, /* 3010: struct.X509_name_st */
            	3019, 0,
            	3043, 16,
            	142, 24,
            1, 8, 1, /* 3019: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3024, 0,
            0, 32, 2, /* 3024: struct.stack_st_fake_X509_NAME_ENTRY */
            	3031, 8,
            	150, 24,
            8884099, 8, 2, /* 3031: pointer_to_array_of_pointers_to_stack */
            	3038, 0,
            	147, 20,
            0, 8, 1, /* 3038: pointer.X509_NAME_ENTRY */
            	98, 0,
            1, 8, 1, /* 3043: pointer.struct.buf_mem_st */
            	3048, 0,
            0, 24, 1, /* 3048: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 3053: pointer.struct.X509_val_st */
            	3058, 0,
            0, 16, 2, /* 3058: struct.X509_val_st */
            	3065, 0,
            	3065, 8,
            1, 8, 1, /* 3065: pointer.struct.asn1_string_st */
            	2843, 0,
            1, 8, 1, /* 3070: pointer.struct.X509_pubkey_st */
            	3075, 0,
            0, 24, 3, /* 3075: struct.X509_pubkey_st */
            	2848, 0,
            	2937, 8,
            	3084, 16,
            1, 8, 1, /* 3084: pointer.struct.evp_pkey_st */
            	3089, 0,
            0, 56, 4, /* 3089: struct.evp_pkey_st */
            	3100, 16,
            	3108, 24,
            	3116, 32,
            	3434, 48,
            1, 8, 1, /* 3100: pointer.struct.evp_pkey_asn1_method_st */
            	3105, 0,
            0, 0, 0, /* 3105: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3108: pointer.struct.engine_st */
            	3113, 0,
            0, 0, 0, /* 3113: struct.engine_st */
            0, 8, 5, /* 3116: union.unknown */
            	69, 0,
            	3129, 0,
            	3280, 0,
            	3358, 0,
            	3426, 0,
            1, 8, 1, /* 3129: pointer.struct.rsa_st */
            	3134, 0,
            0, 168, 17, /* 3134: struct.rsa_st */
            	3171, 16,
            	3108, 24,
            	3226, 32,
            	3226, 40,
            	3226, 48,
            	3226, 56,
            	3226, 64,
            	3226, 72,
            	3226, 80,
            	3226, 88,
            	3236, 96,
            	3258, 120,
            	3258, 128,
            	3258, 136,
            	69, 144,
            	3272, 152,
            	3272, 160,
            1, 8, 1, /* 3171: pointer.struct.rsa_meth_st */
            	3176, 0,
            0, 112, 13, /* 3176: struct.rsa_meth_st */
            	10, 0,
            	3205, 8,
            	3205, 16,
            	3205, 24,
            	3205, 32,
            	3208, 40,
            	3211, 48,
            	3214, 56,
            	3214, 64,
            	69, 80,
            	3217, 88,
            	3220, 96,
            	3223, 104,
            8884097, 8, 0, /* 3205: pointer.func */
            8884097, 8, 0, /* 3208: pointer.func */
            8884097, 8, 0, /* 3211: pointer.func */
            8884097, 8, 0, /* 3214: pointer.func */
            8884097, 8, 0, /* 3217: pointer.func */
            8884097, 8, 0, /* 3220: pointer.func */
            8884097, 8, 0, /* 3223: pointer.func */
            1, 8, 1, /* 3226: pointer.struct.bignum_st */
            	3231, 0,
            0, 24, 1, /* 3231: struct.bignum_st */
            	253, 0,
            0, 16, 1, /* 3236: struct.crypto_ex_data_st */
            	3241, 0,
            1, 8, 1, /* 3241: pointer.struct.stack_st_void */
            	3246, 0,
            0, 32, 1, /* 3246: struct.stack_st_void */
            	3251, 0,
            0, 32, 2, /* 3251: struct.stack_st */
            	417, 8,
            	150, 24,
            1, 8, 1, /* 3258: pointer.struct.bn_mont_ctx_st */
            	3263, 0,
            0, 96, 3, /* 3263: struct.bn_mont_ctx_st */
            	3231, 8,
            	3231, 32,
            	3231, 56,
            1, 8, 1, /* 3272: pointer.struct.bn_blinding_st */
            	3277, 0,
            0, 0, 0, /* 3277: struct.bn_blinding_st */
            1, 8, 1, /* 3280: pointer.struct.dsa_st */
            	3285, 0,
            0, 136, 11, /* 3285: struct.dsa_st */
            	3226, 24,
            	3226, 32,
            	3226, 40,
            	3226, 48,
            	3226, 56,
            	3226, 64,
            	3226, 72,
            	3258, 88,
            	3236, 104,
            	3310, 120,
            	3108, 128,
            1, 8, 1, /* 3310: pointer.struct.dsa_method */
            	3315, 0,
            0, 96, 11, /* 3315: struct.dsa_method */
            	10, 0,
            	3340, 8,
            	3343, 16,
            	3346, 24,
            	2807, 32,
            	3349, 40,
            	3352, 48,
            	3352, 56,
            	69, 72,
            	3355, 80,
            	3352, 88,
            8884097, 8, 0, /* 3340: pointer.func */
            8884097, 8, 0, /* 3343: pointer.func */
            8884097, 8, 0, /* 3346: pointer.func */
            8884097, 8, 0, /* 3349: pointer.func */
            8884097, 8, 0, /* 3352: pointer.func */
            8884097, 8, 0, /* 3355: pointer.func */
            1, 8, 1, /* 3358: pointer.struct.dh_st */
            	3363, 0,
            0, 144, 12, /* 3363: struct.dh_st */
            	3226, 8,
            	3226, 16,
            	3226, 32,
            	3226, 40,
            	3258, 56,
            	3226, 64,
            	3226, 72,
            	142, 80,
            	3226, 96,
            	3236, 112,
            	3390, 128,
            	3108, 136,
            1, 8, 1, /* 3390: pointer.struct.dh_method */
            	3395, 0,
            0, 72, 8, /* 3395: struct.dh_method */
            	10, 0,
            	3414, 8,
            	3417, 16,
            	3420, 24,
            	3414, 32,
            	3414, 40,
            	69, 56,
            	3423, 64,
            8884097, 8, 0, /* 3414: pointer.func */
            8884097, 8, 0, /* 3417: pointer.func */
            8884097, 8, 0, /* 3420: pointer.func */
            8884097, 8, 0, /* 3423: pointer.func */
            1, 8, 1, /* 3426: pointer.struct.ec_key_st */
            	3431, 0,
            0, 0, 0, /* 3431: struct.ec_key_st */
            1, 8, 1, /* 3434: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3439, 0,
            0, 32, 2, /* 3439: struct.stack_st_fake_X509_ATTRIBUTE */
            	3446, 8,
            	150, 24,
            8884099, 8, 2, /* 3446: pointer_to_array_of_pointers_to_stack */
            	3453, 0,
            	147, 20,
            0, 8, 1, /* 3453: pointer.X509_ATTRIBUTE */
            	2369, 0,
            1, 8, 1, /* 3458: pointer.struct.stack_st_X509_EXTENSION */
            	3463, 0,
            0, 32, 2, /* 3463: struct.stack_st_fake_X509_EXTENSION */
            	3470, 8,
            	150, 24,
            8884099, 8, 2, /* 3470: pointer_to_array_of_pointers_to_stack */
            	3477, 0,
            	147, 20,
            0, 8, 1, /* 3477: pointer.X509_EXTENSION */
            	1246, 0,
            0, 24, 1, /* 3482: struct.ASN1_ENCODING_st */
            	142, 0,
            0, 0, 0, /* 3487: struct.X509_POLICY_CACHE_st */
            8884097, 8, 0, /* 3490: pointer.func */
            0, 184, 12, /* 3493: struct.x509_st */
            	3520, 0,
            	1465, 8,
            	1554, 16,
            	69, 32,
            	1293, 40,
            	1559, 104,
            	2772, 112,
            	2758, 120,
            	2734, 128,
            	3820, 136,
            	3844, 144,
            	3852, 176,
            1, 8, 1, /* 3520: pointer.struct.x509_cinf_st */
            	3525, 0,
            0, 104, 11, /* 3525: struct.x509_cinf_st */
            	1455, 0,
            	1455, 8,
            	1465, 16,
            	1614, 24,
            	3550, 32,
            	1614, 40,
            	3562, 48,
            	1554, 56,
            	1554, 64,
            	1770, 72,
            	1794, 80,
            1, 8, 1, /* 3550: pointer.struct.X509_val_st */
            	3555, 0,
            0, 16, 2, /* 3555: struct.X509_val_st */
            	1662, 0,
            	1662, 8,
            1, 8, 1, /* 3562: pointer.struct.X509_pubkey_st */
            	3567, 0,
            0, 24, 3, /* 3567: struct.X509_pubkey_st */
            	1465, 0,
            	1554, 8,
            	3576, 16,
            1, 8, 1, /* 3576: pointer.struct.evp_pkey_st */
            	3581, 0,
            0, 56, 4, /* 3581: struct.evp_pkey_st */
            	3592, 16,
            	1423, 24,
            	3600, 32,
            	3796, 48,
            1, 8, 1, /* 3592: pointer.struct.evp_pkey_asn1_method_st */
            	3597, 0,
            0, 0, 0, /* 3597: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3600: union.unknown */
            	69, 0,
            	3613, 0,
            	3718, 0,
            	3723, 0,
            	3791, 0,
            1, 8, 1, /* 3613: pointer.struct.rsa_st */
            	3618, 0,
            0, 168, 17, /* 3618: struct.rsa_st */
            	3655, 16,
            	1423, 24,
            	1348, 32,
            	1348, 40,
            	1348, 48,
            	1348, 56,
            	1348, 64,
            	1348, 72,
            	1348, 80,
            	1348, 88,
            	1293, 96,
            	1358, 120,
            	1358, 128,
            	1358, 136,
            	69, 144,
            	3710, 152,
            	3710, 160,
            1, 8, 1, /* 3655: pointer.struct.rsa_meth_st */
            	3660, 0,
            0, 112, 13, /* 3660: struct.rsa_meth_st */
            	10, 0,
            	3689, 8,
            	3689, 16,
            	3689, 24,
            	3689, 32,
            	3692, 40,
            	3695, 48,
            	3698, 56,
            	3698, 64,
            	69, 80,
            	3701, 88,
            	3704, 96,
            	3707, 104,
            8884097, 8, 0, /* 3689: pointer.func */
            8884097, 8, 0, /* 3692: pointer.func */
            8884097, 8, 0, /* 3695: pointer.func */
            8884097, 8, 0, /* 3698: pointer.func */
            8884097, 8, 0, /* 3701: pointer.func */
            8884097, 8, 0, /* 3704: pointer.func */
            8884097, 8, 0, /* 3707: pointer.func */
            1, 8, 1, /* 3710: pointer.struct.bn_blinding_st */
            	3715, 0,
            0, 0, 0, /* 3715: struct.bn_blinding_st */
            1, 8, 1, /* 3718: pointer.struct.dsa_st */
            	1323, 0,
            1, 8, 1, /* 3723: pointer.struct.dh_st */
            	3728, 0,
            0, 144, 12, /* 3728: struct.dh_st */
            	1348, 8,
            	1348, 16,
            	1348, 32,
            	1348, 40,
            	1358, 56,
            	1348, 64,
            	1348, 72,
            	142, 80,
            	1348, 96,
            	1293, 112,
            	3755, 128,
            	1423, 136,
            1, 8, 1, /* 3755: pointer.struct.dh_method */
            	3760, 0,
            0, 72, 8, /* 3760: struct.dh_method */
            	10, 0,
            	3779, 8,
            	3782, 16,
            	3785, 24,
            	3779, 32,
            	3779, 40,
            	69, 56,
            	3788, 64,
            8884097, 8, 0, /* 3779: pointer.func */
            8884097, 8, 0, /* 3782: pointer.func */
            8884097, 8, 0, /* 3785: pointer.func */
            8884097, 8, 0, /* 3788: pointer.func */
            1, 8, 1, /* 3791: pointer.struct.ec_key_st */
            	2769, 0,
            1, 8, 1, /* 3796: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3801, 0,
            0, 32, 2, /* 3801: struct.stack_st_fake_X509_ATTRIBUTE */
            	3808, 8,
            	150, 24,
            8884099, 8, 2, /* 3808: pointer_to_array_of_pointers_to_stack */
            	3815, 0,
            	147, 20,
            0, 8, 1, /* 3815: pointer.X509_ATTRIBUTE */
            	2369, 0,
            1, 8, 1, /* 3820: pointer.struct.stack_st_GENERAL_NAME */
            	3825, 0,
            0, 32, 2, /* 3825: struct.stack_st_fake_GENERAL_NAME */
            	3832, 8,
            	150, 24,
            8884099, 8, 2, /* 3832: pointer_to_array_of_pointers_to_stack */
            	3839, 0,
            	147, 20,
            0, 8, 1, /* 3839: pointer.GENERAL_NAME */
            	792, 0,
            1, 8, 1, /* 3844: pointer.struct.NAME_CONSTRAINTS_st */
            	3849, 0,
            0, 0, 0, /* 3849: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3852: pointer.struct.x509_cert_aux_st */
            	3857, 0,
            0, 40, 5, /* 3857: struct.x509_cert_aux_st */
            	3870, 0,
            	3870, 8,
            	1609, 16,
            	1559, 24,
            	3894, 32,
            1, 8, 1, /* 3870: pointer.struct.stack_st_ASN1_OBJECT */
            	3875, 0,
            0, 32, 2, /* 3875: struct.stack_st_fake_ASN1_OBJECT */
            	3882, 8,
            	150, 24,
            8884099, 8, 2, /* 3882: pointer_to_array_of_pointers_to_stack */
            	3889, 0,
            	147, 20,
            0, 8, 1, /* 3889: pointer.ASN1_OBJECT */
            	548, 0,
            1, 8, 1, /* 3894: pointer.struct.stack_st_X509_ALGOR */
            	3899, 0,
            0, 32, 2, /* 3899: struct.stack_st_fake_X509_ALGOR */
            	3906, 8,
            	150, 24,
            8884099, 8, 2, /* 3906: pointer_to_array_of_pointers_to_stack */
            	3913, 0,
            	147, 20,
            0, 8, 1, /* 3913: pointer.X509_ALGOR */
            	601, 0,
            0, 184, 12, /* 3918: struct.x509_st */
            	3945, 0,
            	2848, 8,
            	2937, 16,
            	69, 32,
            	3236, 40,
            	2942, 104,
            	3950, 112,
            	3958, 120,
            	3963, 128,
            	3987, 136,
            	4011, 144,
            	4019, 176,
            1, 8, 1, /* 3945: pointer.struct.x509_cinf_st */
            	2813, 0,
            1, 8, 1, /* 3950: pointer.struct.AUTHORITY_KEYID_st */
            	3955, 0,
            0, 0, 0, /* 3955: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3958: pointer.struct.X509_POLICY_CACHE_st */
            	3487, 0,
            1, 8, 1, /* 3963: pointer.struct.stack_st_DIST_POINT */
            	3968, 0,
            0, 32, 2, /* 3968: struct.stack_st_fake_DIST_POINT */
            	3975, 8,
            	150, 24,
            8884099, 8, 2, /* 3975: pointer_to_array_of_pointers_to_stack */
            	3982, 0,
            	147, 20,
            0, 8, 1, /* 3982: pointer.DIST_POINT */
            	1086, 0,
            1, 8, 1, /* 3987: pointer.struct.stack_st_GENERAL_NAME */
            	3992, 0,
            0, 32, 2, /* 3992: struct.stack_st_fake_GENERAL_NAME */
            	3999, 8,
            	150, 24,
            8884099, 8, 2, /* 3999: pointer_to_array_of_pointers_to_stack */
            	4006, 0,
            	147, 20,
            0, 8, 1, /* 4006: pointer.GENERAL_NAME */
            	792, 0,
            1, 8, 1, /* 4011: pointer.struct.NAME_CONSTRAINTS_st */
            	4016, 0,
            0, 0, 0, /* 4016: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4019: pointer.struct.x509_cert_aux_st */
            	4024, 0,
            0, 40, 5, /* 4024: struct.x509_cert_aux_st */
            	4037, 0,
            	4037, 8,
            	2992, 16,
            	2942, 24,
            	4061, 32,
            1, 8, 1, /* 4037: pointer.struct.stack_st_ASN1_OBJECT */
            	4042, 0,
            0, 32, 2, /* 4042: struct.stack_st_fake_ASN1_OBJECT */
            	4049, 8,
            	150, 24,
            8884099, 8, 2, /* 4049: pointer_to_array_of_pointers_to_stack */
            	4056, 0,
            	147, 20,
            0, 8, 1, /* 4056: pointer.ASN1_OBJECT */
            	548, 0,
            1, 8, 1, /* 4061: pointer.struct.stack_st_X509_ALGOR */
            	4066, 0,
            0, 32, 2, /* 4066: struct.stack_st_fake_X509_ALGOR */
            	4073, 8,
            	150, 24,
            8884099, 8, 2, /* 4073: pointer_to_array_of_pointers_to_stack */
            	4080, 0,
            	147, 20,
            0, 8, 1, /* 4080: pointer.X509_ALGOR */
            	601, 0,
            8884097, 8, 0, /* 4085: pointer.func */
            8884097, 8, 0, /* 4088: pointer.func */
            0, 32, 1, /* 4091: struct.stack_st_GENERAL_NAME */
            	4096, 0,
            0, 32, 2, /* 4096: struct.stack_st */
            	417, 8,
            	150, 24,
            1, 8, 1, /* 4103: pointer.struct.x509_st */
            	3493, 0,
            8884097, 8, 0, /* 4108: pointer.func */
            0, 0, 1, /* 4111: SSL_CIPHER */
            	4116, 0,
            0, 88, 1, /* 4116: struct.ssl_cipher_st */
            	10, 8,
            8884097, 8, 0, /* 4121: pointer.func */
            0, 144, 15, /* 4124: struct.x509_store_st */
            	4157, 8,
            	4275, 16,
            	4478, 24,
            	4490, 32,
            	4493, 40,
            	4496, 48,
            	4499, 56,
            	4490, 64,
            	4502, 72,
            	4505, 80,
            	4508, 88,
            	2810, 96,
            	4511, 104,
            	4490, 112,
            	395, 120,
            1, 8, 1, /* 4157: pointer.struct.stack_st_X509_OBJECT */
            	4162, 0,
            0, 32, 2, /* 4162: struct.stack_st_fake_X509_OBJECT */
            	4169, 8,
            	150, 24,
            8884099, 8, 2, /* 4169: pointer_to_array_of_pointers_to_stack */
            	4176, 0,
            	147, 20,
            0, 8, 1, /* 4176: pointer.X509_OBJECT */
            	4181, 0,
            0, 0, 1, /* 4181: X509_OBJECT */
            	4186, 0,
            0, 16, 1, /* 4186: struct.x509_object_st */
            	4191, 8,
            0, 8, 4, /* 4191: union.unknown */
            	69, 0,
            	4103, 0,
            	4202, 0,
            	3576, 0,
            1, 8, 1, /* 4202: pointer.struct.X509_crl_st */
            	4207, 0,
            0, 120, 10, /* 4207: struct.X509_crl_st */
            	1431, 0,
            	1465, 8,
            	1554, 16,
            	2772, 32,
            	4230, 40,
            	1455, 56,
            	1455, 64,
            	4238, 96,
            	4267, 104,
            	234, 112,
            1, 8, 1, /* 4230: pointer.struct.ISSUING_DIST_POINT_st */
            	4235, 0,
            0, 0, 0, /* 4235: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 4238: pointer.struct.stack_st_GENERAL_NAMES */
            	4243, 0,
            0, 32, 2, /* 4243: struct.stack_st_fake_GENERAL_NAMES */
            	4250, 8,
            	150, 24,
            8884099, 8, 2, /* 4250: pointer_to_array_of_pointers_to_stack */
            	4257, 0,
            	147, 20,
            0, 8, 1, /* 4257: pointer.GENERAL_NAMES */
            	4262, 0,
            0, 0, 1, /* 4262: GENERAL_NAMES */
            	4091, 0,
            1, 8, 1, /* 4267: pointer.struct.x509_crl_method_st */
            	4272, 0,
            0, 0, 0, /* 4272: struct.x509_crl_method_st */
            1, 8, 1, /* 4275: pointer.struct.stack_st_X509_LOOKUP */
            	4280, 0,
            0, 32, 2, /* 4280: struct.stack_st_fake_X509_LOOKUP */
            	4287, 8,
            	150, 24,
            8884099, 8, 2, /* 4287: pointer_to_array_of_pointers_to_stack */
            	4294, 0,
            	147, 20,
            0, 8, 1, /* 4294: pointer.X509_LOOKUP */
            	4299, 0,
            0, 0, 1, /* 4299: X509_LOOKUP */
            	4304, 0,
            0, 32, 3, /* 4304: struct.x509_lookup_st */
            	4313, 8,
            	69, 16,
            	4356, 24,
            1, 8, 1, /* 4313: pointer.struct.x509_lookup_method_st */
            	4318, 0,
            0, 80, 10, /* 4318: struct.x509_lookup_method_st */
            	10, 0,
            	4341, 8,
            	2801, 16,
            	4341, 24,
            	4341, 32,
            	4344, 40,
            	4347, 48,
            	4108, 56,
            	4350, 64,
            	4353, 72,
            8884097, 8, 0, /* 4341: pointer.func */
            8884097, 8, 0, /* 4344: pointer.func */
            8884097, 8, 0, /* 4347: pointer.func */
            8884097, 8, 0, /* 4350: pointer.func */
            8884097, 8, 0, /* 4353: pointer.func */
            1, 8, 1, /* 4356: pointer.struct.x509_store_st */
            	4361, 0,
            0, 144, 15, /* 4361: struct.x509_store_st */
            	4394, 8,
            	4418, 16,
            	4442, 24,
            	4454, 32,
            	4457, 40,
            	4460, 48,
            	4463, 56,
            	4454, 64,
            	4466, 72,
            	4469, 80,
            	4472, 88,
            	4475, 96,
            	4121, 104,
            	4454, 112,
            	1293, 120,
            1, 8, 1, /* 4394: pointer.struct.stack_st_X509_OBJECT */
            	4399, 0,
            0, 32, 2, /* 4399: struct.stack_st_fake_X509_OBJECT */
            	4406, 8,
            	150, 24,
            8884099, 8, 2, /* 4406: pointer_to_array_of_pointers_to_stack */
            	4413, 0,
            	147, 20,
            0, 8, 1, /* 4413: pointer.X509_OBJECT */
            	4181, 0,
            1, 8, 1, /* 4418: pointer.struct.stack_st_X509_LOOKUP */
            	4423, 0,
            0, 32, 2, /* 4423: struct.stack_st_fake_X509_LOOKUP */
            	4430, 8,
            	150, 24,
            8884099, 8, 2, /* 4430: pointer_to_array_of_pointers_to_stack */
            	4437, 0,
            	147, 20,
            0, 8, 1, /* 4437: pointer.X509_LOOKUP */
            	4299, 0,
            1, 8, 1, /* 4442: pointer.struct.X509_VERIFY_PARAM_st */
            	4447, 0,
            0, 56, 2, /* 4447: struct.X509_VERIFY_PARAM_st */
            	69, 0,
            	3870, 48,
            8884097, 8, 0, /* 4454: pointer.func */
            8884097, 8, 0, /* 4457: pointer.func */
            8884097, 8, 0, /* 4460: pointer.func */
            8884097, 8, 0, /* 4463: pointer.func */
            8884097, 8, 0, /* 4466: pointer.func */
            8884097, 8, 0, /* 4469: pointer.func */
            8884097, 8, 0, /* 4472: pointer.func */
            8884097, 8, 0, /* 4475: pointer.func */
            1, 8, 1, /* 4478: pointer.struct.X509_VERIFY_PARAM_st */
            	4483, 0,
            0, 56, 2, /* 4483: struct.X509_VERIFY_PARAM_st */
            	69, 0,
            	524, 48,
            8884097, 8, 0, /* 4490: pointer.func */
            8884097, 8, 0, /* 4493: pointer.func */
            8884097, 8, 0, /* 4496: pointer.func */
            8884097, 8, 0, /* 4499: pointer.func */
            8884097, 8, 0, /* 4502: pointer.func */
            8884097, 8, 0, /* 4505: pointer.func */
            8884097, 8, 0, /* 4508: pointer.func */
            8884097, 8, 0, /* 4511: pointer.func */
            8884097, 8, 0, /* 4514: pointer.func */
            8884097, 8, 0, /* 4517: pointer.func */
            8884097, 8, 0, /* 4520: pointer.func */
            0, 112, 11, /* 4523: struct.ssl3_enc_method */
            	3490, 0,
            	4517, 8,
            	4548, 16,
            	4551, 24,
            	3490, 32,
            	4554, 40,
            	4557, 56,
            	10, 64,
            	10, 80,
            	4560, 96,
            	4563, 104,
            8884097, 8, 0, /* 4548: pointer.func */
            8884097, 8, 0, /* 4551: pointer.func */
            8884097, 8, 0, /* 4554: pointer.func */
            8884097, 8, 0, /* 4557: pointer.func */
            8884097, 8, 0, /* 4560: pointer.func */
            8884097, 8, 0, /* 4563: pointer.func */
            8884097, 8, 0, /* 4566: pointer.func */
            8884097, 8, 0, /* 4569: pointer.func */
            8884097, 8, 0, /* 4572: pointer.func */
            8884097, 8, 0, /* 4575: pointer.func */
            0, 736, 50, /* 4578: struct.ssl_ctx_st */
            	4681, 0,
            	4780, 8,
            	4780, 16,
            	4804, 24,
            	4809, 32,
            	4848, 48,
            	4848, 56,
            	328, 80,
            	4085, 88,
            	4931, 96,
            	1315, 152,
            	234, 160,
            	4934, 168,
            	234, 176,
            	325, 184,
            	4937, 192,
            	322, 200,
            	395, 208,
            	2724, 224,
            	2724, 232,
            	2724, 240,
            	4902, 248,
            	298, 256,
            	191, 264,
            	153, 272,
            	1799, 304,
            	4088, 320,
            	234, 328,
            	4493, 376,
            	4940, 384,
            	4478, 392,
            	458, 408,
            	47, 416,
            	234, 424,
            	4520, 480,
            	237, 488,
            	234, 496,
            	44, 504,
            	234, 512,
            	69, 520,
            	41, 528,
            	4943, 536,
            	31, 552,
            	31, 560,
            	203, 568,
            	18, 696,
            	234, 704,
            	15, 712,
            	234, 720,
            	2777, 728,
            1, 8, 1, /* 4681: pointer.struct.ssl_method_st */
            	4686, 0,
            0, 232, 28, /* 4686: struct.ssl_method_st */
            	4548, 8,
            	4575, 16,
            	4575, 24,
            	4548, 32,
            	4548, 40,
            	4745, 48,
            	4745, 56,
            	4748, 64,
            	4548, 72,
            	4548, 80,
            	4548, 88,
            	2804, 96,
            	4572, 104,
            	4566, 112,
            	4548, 120,
            	4751, 128,
            	4754, 136,
            	4757, 144,
            	4514, 152,
            	4760, 160,
            	4763, 168,
            	4766, 176,
            	4569, 184,
            	278, 192,
            	4769, 200,
            	4763, 208,
            	4774, 216,
            	4777, 224,
            8884097, 8, 0, /* 4745: pointer.func */
            8884097, 8, 0, /* 4748: pointer.func */
            8884097, 8, 0, /* 4751: pointer.func */
            8884097, 8, 0, /* 4754: pointer.func */
            8884097, 8, 0, /* 4757: pointer.func */
            8884097, 8, 0, /* 4760: pointer.func */
            8884097, 8, 0, /* 4763: pointer.func */
            8884097, 8, 0, /* 4766: pointer.func */
            1, 8, 1, /* 4769: pointer.struct.ssl3_enc_method */
            	4523, 0,
            8884097, 8, 0, /* 4774: pointer.func */
            8884097, 8, 0, /* 4777: pointer.func */
            1, 8, 1, /* 4780: pointer.struct.stack_st_SSL_CIPHER */
            	4785, 0,
            0, 32, 2, /* 4785: struct.stack_st_fake_SSL_CIPHER */
            	4792, 8,
            	150, 24,
            8884099, 8, 2, /* 4792: pointer_to_array_of_pointers_to_stack */
            	4799, 0,
            	147, 20,
            0, 8, 1, /* 4799: pointer.SSL_CIPHER */
            	4111, 0,
            1, 8, 1, /* 4804: pointer.struct.x509_store_st */
            	4124, 0,
            1, 8, 1, /* 4809: pointer.struct.lhash_st */
            	4814, 0,
            0, 176, 3, /* 4814: struct.lhash_st */
            	4823, 0,
            	150, 8,
            	4845, 16,
            1, 8, 1, /* 4823: pointer.pointer.struct.lhash_node_st */
            	4828, 0,
            1, 8, 1, /* 4828: pointer.struct.lhash_node_st */
            	4833, 0,
            0, 24, 2, /* 4833: struct.lhash_node_st */
            	234, 0,
            	4840, 8,
            1, 8, 1, /* 4840: pointer.struct.lhash_node_st */
            	4833, 0,
            8884097, 8, 0, /* 4845: pointer.func */
            1, 8, 1, /* 4848: pointer.struct.ssl_session_st */
            	4853, 0,
            0, 352, 14, /* 4853: struct.ssl_session_st */
            	69, 144,
            	69, 152,
            	4884, 168,
            	1835, 176,
            	336, 224,
            	4780, 240,
            	395, 248,
            	4848, 264,
            	4848, 272,
            	69, 280,
            	142, 296,
            	142, 312,
            	142, 320,
            	69, 344,
            1, 8, 1, /* 4884: pointer.struct.sess_cert_st */
            	4889, 0,
            0, 248, 5, /* 4889: struct.sess_cert_st */
            	4902, 0,
            	1821, 16,
            	2729, 216,
            	349, 224,
            	341, 232,
            1, 8, 1, /* 4902: pointer.struct.stack_st_X509 */
            	4907, 0,
            0, 32, 2, /* 4907: struct.stack_st_fake_X509 */
            	4914, 8,
            	150, 24,
            8884099, 8, 2, /* 4914: pointer_to_array_of_pointers_to_stack */
            	4921, 0,
            	147, 20,
            0, 8, 1, /* 4921: pointer.X509 */
            	4926, 0,
            0, 0, 1, /* 4926: X509 */
            	3918, 0,
            8884097, 8, 0, /* 4931: pointer.func */
            8884097, 8, 0, /* 4934: pointer.func */
            8884097, 8, 0, /* 4937: pointer.func */
            8884097, 8, 0, /* 4940: pointer.func */
            8884097, 8, 0, /* 4943: pointer.func */
            1, 8, 1, /* 4946: pointer.struct.ssl_ctx_st */
            	4578, 0,
            0, 1, 0, /* 4951: char */
            0, 8, 0, /* 4954: long int */
        },
        .arg_entity_index = { 4946, 4954, },
        .ret_entity_index = 4954,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    long new_arg_b = *((long *)new_args->args[1]);

    long *new_ret_ptr = (long *)new_args->ret;

    long (*orig_SSL_CTX_set_timeout)(SSL_CTX *,long);
    orig_SSL_CTX_set_timeout = dlsym(RTLD_NEXT, "SSL_CTX_set_timeout");
    *new_ret_ptr = (*orig_SSL_CTX_set_timeout)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

