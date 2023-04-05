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

void bb_SSL_CTX_sess_set_new_cb(SSL_CTX * arg_a,int (*arg_b)(struct ssl_st *, SSL_SESSION *));

void SSL_CTX_sess_set_new_cb(SSL_CTX * arg_a,int (*arg_b)(struct ssl_st *, SSL_SESSION *)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_sess_set_new_cb called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_sess_set_new_cb(arg_a,arg_b);
    else {
        void (*orig_SSL_CTX_sess_set_new_cb)(SSL_CTX *,int (*)(struct ssl_st *, SSL_SESSION *));
        orig_SSL_CTX_sess_set_new_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_new_cb");
        orig_SSL_CTX_sess_set_new_cb(arg_a,arg_b);
    }
}

void bb_SSL_CTX_sess_set_new_cb(SSL_CTX * arg_a,int (*arg_b)(struct ssl_st *, SSL_SESSION *)) 
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
            8884097, 8, 0, /* 84: pointer.func */
            0, 8, 1, /* 87: struct.ssl3_buf_freelist_entry_st */
            	92, 0,
            1, 8, 1, /* 92: pointer.struct.ssl3_buf_freelist_entry_st */
            	87, 0,
            1, 8, 1, /* 97: pointer.struct.ssl3_buf_freelist_st */
            	102, 0,
            0, 24, 1, /* 102: struct.ssl3_buf_freelist_st */
            	92, 16,
            8884097, 8, 0, /* 107: pointer.func */
            8884097, 8, 0, /* 110: pointer.func */
            8884097, 8, 0, /* 113: pointer.func */
            8884097, 8, 0, /* 116: pointer.func */
            0, 24, 1, /* 119: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 124: pointer.struct.buf_mem_st */
            	119, 0,
            1, 8, 1, /* 129: pointer.struct.stack_st_X509_NAME_ENTRY */
            	134, 0,
            0, 32, 2, /* 134: struct.stack_st_fake_X509_NAME_ENTRY */
            	141, 8,
            	205, 24,
            8884099, 8, 2, /* 141: pointer_to_array_of_pointers_to_stack */
            	148, 0,
            	202, 20,
            0, 8, 1, /* 148: pointer.X509_NAME_ENTRY */
            	153, 0,
            0, 0, 1, /* 153: X509_NAME_ENTRY */
            	158, 0,
            0, 24, 2, /* 158: struct.X509_name_entry_st */
            	165, 0,
            	187, 8,
            1, 8, 1, /* 165: pointer.struct.asn1_object_st */
            	170, 0,
            0, 40, 3, /* 170: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	179, 24,
            1, 8, 1, /* 179: pointer.unsigned char */
            	184, 0,
            0, 1, 0, /* 184: unsigned char */
            1, 8, 1, /* 187: pointer.struct.asn1_string_st */
            	192, 0,
            0, 24, 1, /* 192: struct.asn1_string_st */
            	197, 8,
            1, 8, 1, /* 197: pointer.unsigned char */
            	184, 0,
            0, 4, 0, /* 202: int */
            8884097, 8, 0, /* 205: pointer.func */
            0, 40, 3, /* 208: struct.X509_name_st */
            	129, 0,
            	124, 16,
            	197, 24,
            1, 8, 1, /* 217: pointer.struct.stack_st_X509_NAME */
            	222, 0,
            0, 32, 2, /* 222: struct.stack_st_fake_X509_NAME */
            	229, 8,
            	205, 24,
            8884099, 8, 2, /* 229: pointer_to_array_of_pointers_to_stack */
            	236, 0,
            	202, 20,
            0, 8, 1, /* 236: pointer.X509_NAME */
            	241, 0,
            0, 0, 1, /* 241: X509_NAME */
            	208, 0,
            8884097, 8, 0, /* 246: pointer.func */
            8884097, 8, 0, /* 249: pointer.func */
            8884097, 8, 0, /* 252: pointer.func */
            0, 64, 7, /* 255: struct.comp_method_st */
            	10, 8,
            	272, 16,
            	252, 24,
            	249, 32,
            	249, 40,
            	275, 48,
            	275, 56,
            8884097, 8, 0, /* 272: pointer.func */
            8884097, 8, 0, /* 275: pointer.func */
            1, 8, 1, /* 278: pointer.struct.comp_method_st */
            	255, 0,
            0, 0, 1, /* 283: SSL_COMP */
            	288, 0,
            0, 24, 2, /* 288: struct.ssl_comp_st */
            	10, 8,
            	278, 16,
            1, 8, 1, /* 295: pointer.struct.stack_st_SSL_COMP */
            	300, 0,
            0, 32, 2, /* 300: struct.stack_st_fake_SSL_COMP */
            	307, 8,
            	205, 24,
            8884099, 8, 2, /* 307: pointer_to_array_of_pointers_to_stack */
            	314, 0,
            	202, 20,
            0, 8, 1, /* 314: pointer.SSL_COMP */
            	283, 0,
            8884097, 8, 0, /* 319: pointer.func */
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
            8884097, 8, 0, /* 349: pointer.func */
            8884097, 8, 0, /* 352: pointer.func */
            8884097, 8, 0, /* 355: pointer.func */
            8884097, 8, 0, /* 358: pointer.func */
            0, 120, 8, /* 361: struct.env_md_st */
            	380, 24,
            	358, 32,
            	355, 40,
            	352, 48,
            	380, 56,
            	349, 64,
            	383, 72,
            	386, 112,
            8884097, 8, 0, /* 380: pointer.func */
            8884097, 8, 0, /* 383: pointer.func */
            8884097, 8, 0, /* 386: pointer.func */
            1, 8, 1, /* 389: pointer.struct.x509_cert_aux_st */
            	394, 0,
            0, 40, 5, /* 394: struct.x509_cert_aux_st */
            	407, 0,
            	407, 8,
            	445, 16,
            	455, 24,
            	460, 32,
            1, 8, 1, /* 407: pointer.struct.stack_st_ASN1_OBJECT */
            	412, 0,
            0, 32, 2, /* 412: struct.stack_st_fake_ASN1_OBJECT */
            	419, 8,
            	205, 24,
            8884099, 8, 2, /* 419: pointer_to_array_of_pointers_to_stack */
            	426, 0,
            	202, 20,
            0, 8, 1, /* 426: pointer.ASN1_OBJECT */
            	431, 0,
            0, 0, 1, /* 431: ASN1_OBJECT */
            	436, 0,
            0, 40, 3, /* 436: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	179, 24,
            1, 8, 1, /* 445: pointer.struct.asn1_string_st */
            	450, 0,
            0, 24, 1, /* 450: struct.asn1_string_st */
            	197, 8,
            1, 8, 1, /* 455: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 460: pointer.struct.stack_st_X509_ALGOR */
            	465, 0,
            0, 32, 2, /* 465: struct.stack_st_fake_X509_ALGOR */
            	472, 8,
            	205, 24,
            8884099, 8, 2, /* 472: pointer_to_array_of_pointers_to_stack */
            	479, 0,
            	202, 20,
            0, 8, 1, /* 479: pointer.X509_ALGOR */
            	484, 0,
            0, 0, 1, /* 484: X509_ALGOR */
            	489, 0,
            0, 16, 2, /* 489: struct.X509_algor_st */
            	496, 0,
            	510, 8,
            1, 8, 1, /* 496: pointer.struct.asn1_object_st */
            	501, 0,
            0, 40, 3, /* 501: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	179, 24,
            1, 8, 1, /* 510: pointer.struct.asn1_type_st */
            	515, 0,
            0, 16, 1, /* 515: struct.asn1_type_st */
            	520, 8,
            0, 8, 20, /* 520: union.unknown */
            	61, 0,
            	563, 0,
            	496, 0,
            	573, 0,
            	578, 0,
            	583, 0,
            	588, 0,
            	593, 0,
            	598, 0,
            	603, 0,
            	608, 0,
            	613, 0,
            	618, 0,
            	623, 0,
            	628, 0,
            	633, 0,
            	638, 0,
            	563, 0,
            	563, 0,
            	643, 0,
            1, 8, 1, /* 563: pointer.struct.asn1_string_st */
            	568, 0,
            0, 24, 1, /* 568: struct.asn1_string_st */
            	197, 8,
            1, 8, 1, /* 573: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 578: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 583: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 588: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 593: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 598: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 603: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 608: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 613: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 618: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 623: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 628: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 633: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 638: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 643: pointer.struct.ASN1_VALUE_st */
            	648, 0,
            0, 0, 0, /* 648: struct.ASN1_VALUE_st */
            1, 8, 1, /* 651: pointer.struct.stack_st_GENERAL_NAME */
            	656, 0,
            0, 32, 2, /* 656: struct.stack_st_fake_GENERAL_NAME */
            	663, 8,
            	205, 24,
            8884099, 8, 2, /* 663: pointer_to_array_of_pointers_to_stack */
            	670, 0,
            	202, 20,
            0, 8, 1, /* 670: pointer.GENERAL_NAME */
            	675, 0,
            0, 0, 1, /* 675: GENERAL_NAME */
            	680, 0,
            0, 16, 1, /* 680: struct.GENERAL_NAME_st */
            	685, 8,
            0, 8, 15, /* 685: union.unknown */
            	61, 0,
            	718, 0,
            	837, 0,
            	837, 0,
            	744, 0,
            	885, 0,
            	933, 0,
            	837, 0,
            	822, 0,
            	730, 0,
            	822, 0,
            	885, 0,
            	837, 0,
            	730, 0,
            	744, 0,
            1, 8, 1, /* 718: pointer.struct.otherName_st */
            	723, 0,
            0, 16, 2, /* 723: struct.otherName_st */
            	730, 0,
            	744, 8,
            1, 8, 1, /* 730: pointer.struct.asn1_object_st */
            	735, 0,
            0, 40, 3, /* 735: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	179, 24,
            1, 8, 1, /* 744: pointer.struct.asn1_type_st */
            	749, 0,
            0, 16, 1, /* 749: struct.asn1_type_st */
            	754, 8,
            0, 8, 20, /* 754: union.unknown */
            	61, 0,
            	797, 0,
            	730, 0,
            	807, 0,
            	812, 0,
            	817, 0,
            	822, 0,
            	827, 0,
            	832, 0,
            	837, 0,
            	842, 0,
            	847, 0,
            	852, 0,
            	857, 0,
            	862, 0,
            	867, 0,
            	872, 0,
            	797, 0,
            	797, 0,
            	877, 0,
            1, 8, 1, /* 797: pointer.struct.asn1_string_st */
            	802, 0,
            0, 24, 1, /* 802: struct.asn1_string_st */
            	197, 8,
            1, 8, 1, /* 807: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 812: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 817: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 822: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 827: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 832: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 837: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 842: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 847: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 852: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 857: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 862: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 867: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 872: pointer.struct.asn1_string_st */
            	802, 0,
            1, 8, 1, /* 877: pointer.struct.ASN1_VALUE_st */
            	882, 0,
            0, 0, 0, /* 882: struct.ASN1_VALUE_st */
            1, 8, 1, /* 885: pointer.struct.X509_name_st */
            	890, 0,
            0, 40, 3, /* 890: struct.X509_name_st */
            	899, 0,
            	923, 16,
            	197, 24,
            1, 8, 1, /* 899: pointer.struct.stack_st_X509_NAME_ENTRY */
            	904, 0,
            0, 32, 2, /* 904: struct.stack_st_fake_X509_NAME_ENTRY */
            	911, 8,
            	205, 24,
            8884099, 8, 2, /* 911: pointer_to_array_of_pointers_to_stack */
            	918, 0,
            	202, 20,
            0, 8, 1, /* 918: pointer.X509_NAME_ENTRY */
            	153, 0,
            1, 8, 1, /* 923: pointer.struct.buf_mem_st */
            	928, 0,
            0, 24, 1, /* 928: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 933: pointer.struct.EDIPartyName_st */
            	938, 0,
            0, 16, 2, /* 938: struct.EDIPartyName_st */
            	797, 0,
            	797, 8,
            1, 8, 1, /* 945: pointer.struct.stack_st_DIST_POINT */
            	950, 0,
            0, 32, 2, /* 950: struct.stack_st_fake_DIST_POINT */
            	957, 8,
            	205, 24,
            8884099, 8, 2, /* 957: pointer_to_array_of_pointers_to_stack */
            	964, 0,
            	202, 20,
            0, 8, 1, /* 964: pointer.DIST_POINT */
            	969, 0,
            0, 0, 1, /* 969: DIST_POINT */
            	974, 0,
            0, 32, 3, /* 974: struct.DIST_POINT_st */
            	983, 0,
            	1074, 8,
            	1002, 16,
            1, 8, 1, /* 983: pointer.struct.DIST_POINT_NAME_st */
            	988, 0,
            0, 24, 2, /* 988: struct.DIST_POINT_NAME_st */
            	995, 8,
            	1050, 16,
            0, 8, 2, /* 995: union.unknown */
            	1002, 0,
            	1026, 0,
            1, 8, 1, /* 1002: pointer.struct.stack_st_GENERAL_NAME */
            	1007, 0,
            0, 32, 2, /* 1007: struct.stack_st_fake_GENERAL_NAME */
            	1014, 8,
            	205, 24,
            8884099, 8, 2, /* 1014: pointer_to_array_of_pointers_to_stack */
            	1021, 0,
            	202, 20,
            0, 8, 1, /* 1021: pointer.GENERAL_NAME */
            	675, 0,
            1, 8, 1, /* 1026: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1031, 0,
            0, 32, 2, /* 1031: struct.stack_st_fake_X509_NAME_ENTRY */
            	1038, 8,
            	205, 24,
            8884099, 8, 2, /* 1038: pointer_to_array_of_pointers_to_stack */
            	1045, 0,
            	202, 20,
            0, 8, 1, /* 1045: pointer.X509_NAME_ENTRY */
            	153, 0,
            1, 8, 1, /* 1050: pointer.struct.X509_name_st */
            	1055, 0,
            0, 40, 3, /* 1055: struct.X509_name_st */
            	1026, 0,
            	1064, 16,
            	197, 24,
            1, 8, 1, /* 1064: pointer.struct.buf_mem_st */
            	1069, 0,
            0, 24, 1, /* 1069: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 1074: pointer.struct.asn1_string_st */
            	1079, 0,
            0, 24, 1, /* 1079: struct.asn1_string_st */
            	197, 8,
            0, 0, 0, /* 1084: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1087: pointer.struct.X509_POLICY_CACHE_st */
            	1084, 0,
            0, 0, 0, /* 1092: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1095: pointer.struct.AUTHORITY_KEYID_st */
            	1092, 0,
            0, 24, 1, /* 1100: struct.ASN1_ENCODING_st */
            	197, 0,
            1, 8, 1, /* 1105: pointer.struct.stack_st_X509_EXTENSION */
            	1110, 0,
            0, 32, 2, /* 1110: struct.stack_st_fake_X509_EXTENSION */
            	1117, 8,
            	205, 24,
            8884099, 8, 2, /* 1117: pointer_to_array_of_pointers_to_stack */
            	1124, 0,
            	202, 20,
            0, 8, 1, /* 1124: pointer.X509_EXTENSION */
            	1129, 0,
            0, 0, 1, /* 1129: X509_EXTENSION */
            	1134, 0,
            0, 24, 2, /* 1134: struct.X509_extension_st */
            	1141, 0,
            	1155, 16,
            1, 8, 1, /* 1141: pointer.struct.asn1_object_st */
            	1146, 0,
            0, 40, 3, /* 1146: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	179, 24,
            1, 8, 1, /* 1155: pointer.struct.asn1_string_st */
            	1160, 0,
            0, 24, 1, /* 1160: struct.asn1_string_st */
            	197, 8,
            8884097, 8, 0, /* 1165: pointer.func */
            0, 72, 8, /* 1168: struct.dh_method */
            	10, 0,
            	1187, 8,
            	1190, 16,
            	1165, 24,
            	1187, 32,
            	1187, 40,
            	61, 56,
            	1193, 64,
            8884097, 8, 0, /* 1187: pointer.func */
            8884097, 8, 0, /* 1190: pointer.func */
            8884097, 8, 0, /* 1193: pointer.func */
            0, 144, 12, /* 1196: struct.dh_st */
            	66, 8,
            	66, 16,
            	66, 32,
            	66, 40,
            	1223, 56,
            	66, 64,
            	66, 72,
            	197, 80,
            	66, 96,
            	1237, 112,
            	1264, 128,
            	1269, 136,
            1, 8, 1, /* 1223: pointer.struct.bn_mont_ctx_st */
            	1228, 0,
            0, 96, 3, /* 1228: struct.bn_mont_ctx_st */
            	71, 8,
            	71, 32,
            	71, 56,
            0, 16, 1, /* 1237: struct.crypto_ex_data_st */
            	1242, 0,
            1, 8, 1, /* 1242: pointer.struct.stack_st_void */
            	1247, 0,
            0, 32, 1, /* 1247: struct.stack_st_void */
            	1252, 0,
            0, 32, 2, /* 1252: struct.stack_st */
            	1259, 8,
            	205, 24,
            1, 8, 1, /* 1259: pointer.pointer.char */
            	61, 0,
            1, 8, 1, /* 1264: pointer.struct.dh_method */
            	1168, 0,
            1, 8, 1, /* 1269: pointer.struct.engine_st */
            	1274, 0,
            0, 0, 0, /* 1274: struct.engine_st */
            1, 8, 1, /* 1277: pointer.struct.dh_st */
            	1196, 0,
            0, 16, 1, /* 1282: struct.crypto_ex_data_st */
            	1287, 0,
            1, 8, 1, /* 1287: pointer.struct.stack_st_void */
            	1292, 0,
            0, 32, 1, /* 1292: struct.stack_st_void */
            	1297, 0,
            0, 32, 2, /* 1297: struct.stack_st */
            	1259, 8,
            	205, 24,
            1, 8, 1, /* 1304: pointer.struct.asn1_string_st */
            	1309, 0,
            0, 24, 1, /* 1309: struct.asn1_string_st */
            	197, 8,
            0, 24, 1, /* 1314: struct.buf_mem_st */
            	61, 8,
            8884097, 8, 0, /* 1319: pointer.func */
            0, 24, 1, /* 1322: struct.ASN1_ENCODING_st */
            	197, 0,
            8884097, 8, 0, /* 1327: pointer.func */
            8884097, 8, 0, /* 1330: pointer.func */
            1, 8, 1, /* 1333: pointer.struct.asn1_string_st */
            	1338, 0,
            0, 24, 1, /* 1338: struct.asn1_string_st */
            	197, 8,
            1, 8, 1, /* 1343: pointer.struct.dh_st */
            	1196, 0,
            0, 16, 2, /* 1348: struct.X509_algor_st */
            	1355, 0,
            	1369, 8,
            1, 8, 1, /* 1355: pointer.struct.asn1_object_st */
            	1360, 0,
            0, 40, 3, /* 1360: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	179, 24,
            1, 8, 1, /* 1369: pointer.struct.asn1_type_st */
            	1374, 0,
            0, 16, 1, /* 1374: struct.asn1_type_st */
            	1379, 8,
            0, 8, 20, /* 1379: union.unknown */
            	61, 0,
            	1422, 0,
            	1355, 0,
            	1427, 0,
            	1432, 0,
            	1437, 0,
            	1304, 0,
            	1442, 0,
            	1447, 0,
            	1452, 0,
            	1457, 0,
            	1462, 0,
            	1467, 0,
            	1472, 0,
            	1477, 0,
            	1482, 0,
            	1487, 0,
            	1422, 0,
            	1422, 0,
            	643, 0,
            1, 8, 1, /* 1422: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1427: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1432: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1437: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1442: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1447: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1452: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1457: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1462: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1467: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1472: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1477: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1482: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1487: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1492: pointer.struct.rsa_st */
            	1497, 0,
            0, 168, 17, /* 1497: struct.rsa_st */
            	1534, 16,
            	1589, 24,
            	1597, 32,
            	1597, 40,
            	1597, 48,
            	1597, 56,
            	1597, 64,
            	1597, 72,
            	1597, 80,
            	1597, 88,
            	1282, 96,
            	1607, 120,
            	1607, 128,
            	1607, 136,
            	61, 144,
            	1621, 152,
            	1621, 160,
            1, 8, 1, /* 1534: pointer.struct.rsa_meth_st */
            	1539, 0,
            0, 112, 13, /* 1539: struct.rsa_meth_st */
            	10, 0,
            	1568, 8,
            	1568, 16,
            	1568, 24,
            	1568, 32,
            	1571, 40,
            	1574, 48,
            	1577, 56,
            	1577, 64,
            	61, 80,
            	1580, 88,
            	1583, 96,
            	1586, 104,
            8884097, 8, 0, /* 1568: pointer.func */
            8884097, 8, 0, /* 1571: pointer.func */
            8884097, 8, 0, /* 1574: pointer.func */
            8884097, 8, 0, /* 1577: pointer.func */
            8884097, 8, 0, /* 1580: pointer.func */
            8884097, 8, 0, /* 1583: pointer.func */
            8884097, 8, 0, /* 1586: pointer.func */
            1, 8, 1, /* 1589: pointer.struct.engine_st */
            	1594, 0,
            0, 0, 0, /* 1594: struct.engine_st */
            1, 8, 1, /* 1597: pointer.struct.bignum_st */
            	1602, 0,
            0, 24, 1, /* 1602: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 1607: pointer.struct.bn_mont_ctx_st */
            	1612, 0,
            0, 96, 3, /* 1612: struct.bn_mont_ctx_st */
            	1602, 8,
            	1602, 32,
            	1602, 56,
            1, 8, 1, /* 1621: pointer.struct.bn_blinding_st */
            	1626, 0,
            0, 0, 0, /* 1626: struct.bn_blinding_st */
            1, 8, 1, /* 1629: pointer.struct.X509_crl_info_st */
            	1634, 0,
            0, 80, 8, /* 1634: struct.X509_crl_info_st */
            	1427, 0,
            	1653, 8,
            	1658, 16,
            	1701, 24,
            	1701, 32,
            	1706, 40,
            	1809, 48,
            	1322, 56,
            1, 8, 1, /* 1653: pointer.struct.X509_algor_st */
            	1348, 0,
            1, 8, 1, /* 1658: pointer.struct.X509_name_st */
            	1663, 0,
            0, 40, 3, /* 1663: struct.X509_name_st */
            	1672, 0,
            	1696, 16,
            	197, 24,
            1, 8, 1, /* 1672: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1677, 0,
            0, 32, 2, /* 1677: struct.stack_st_fake_X509_NAME_ENTRY */
            	1684, 8,
            	205, 24,
            8884099, 8, 2, /* 1684: pointer_to_array_of_pointers_to_stack */
            	1691, 0,
            	202, 20,
            0, 8, 1, /* 1691: pointer.X509_NAME_ENTRY */
            	153, 0,
            1, 8, 1, /* 1696: pointer.struct.buf_mem_st */
            	1314, 0,
            1, 8, 1, /* 1701: pointer.struct.asn1_string_st */
            	1309, 0,
            1, 8, 1, /* 1706: pointer.struct.stack_st_X509_REVOKED */
            	1711, 0,
            0, 32, 2, /* 1711: struct.stack_st_fake_X509_REVOKED */
            	1718, 8,
            	205, 24,
            8884099, 8, 2, /* 1718: pointer_to_array_of_pointers_to_stack */
            	1725, 0,
            	202, 20,
            0, 8, 1, /* 1725: pointer.X509_REVOKED */
            	1730, 0,
            0, 0, 1, /* 1730: X509_REVOKED */
            	1735, 0,
            0, 40, 4, /* 1735: struct.x509_revoked_st */
            	1746, 0,
            	1756, 8,
            	1761, 16,
            	1785, 24,
            1, 8, 1, /* 1746: pointer.struct.asn1_string_st */
            	1751, 0,
            0, 24, 1, /* 1751: struct.asn1_string_st */
            	197, 8,
            1, 8, 1, /* 1756: pointer.struct.asn1_string_st */
            	1751, 0,
            1, 8, 1, /* 1761: pointer.struct.stack_st_X509_EXTENSION */
            	1766, 0,
            0, 32, 2, /* 1766: struct.stack_st_fake_X509_EXTENSION */
            	1773, 8,
            	205, 24,
            8884099, 8, 2, /* 1773: pointer_to_array_of_pointers_to_stack */
            	1780, 0,
            	202, 20,
            0, 8, 1, /* 1780: pointer.X509_EXTENSION */
            	1129, 0,
            1, 8, 1, /* 1785: pointer.struct.stack_st_GENERAL_NAME */
            	1790, 0,
            0, 32, 2, /* 1790: struct.stack_st_fake_GENERAL_NAME */
            	1797, 8,
            	205, 24,
            8884099, 8, 2, /* 1797: pointer_to_array_of_pointers_to_stack */
            	1804, 0,
            	202, 20,
            0, 8, 1, /* 1804: pointer.GENERAL_NAME */
            	675, 0,
            1, 8, 1, /* 1809: pointer.struct.stack_st_X509_EXTENSION */
            	1814, 0,
            0, 32, 2, /* 1814: struct.stack_st_fake_X509_EXTENSION */
            	1821, 8,
            	205, 24,
            8884099, 8, 2, /* 1821: pointer_to_array_of_pointers_to_stack */
            	1828, 0,
            	202, 20,
            0, 8, 1, /* 1828: pointer.X509_EXTENSION */
            	1129, 0,
            1, 8, 1, /* 1833: pointer.struct.cert_st */
            	1838, 0,
            0, 296, 7, /* 1838: struct.cert_st */
            	1855, 0,
            	2752, 48,
            	116, 56,
            	1343, 64,
            	2757, 72,
            	341, 80,
            	113, 88,
            1, 8, 1, /* 1855: pointer.struct.cert_pkey_st */
            	1860, 0,
            0, 24, 3, /* 1860: struct.cert_pkey_st */
            	1869, 0,
            	2162, 8,
            	2747, 16,
            1, 8, 1, /* 1869: pointer.struct.x509_st */
            	1874, 0,
            0, 184, 12, /* 1874: struct.x509_st */
            	1901, 0,
            	1936, 8,
            	2025, 16,
            	61, 32,
            	1237, 40,
            	455, 104,
            	1095, 112,
            	1087, 120,
            	945, 128,
            	651, 136,
            	2739, 144,
            	389, 176,
            1, 8, 1, /* 1901: pointer.struct.x509_cinf_st */
            	1906, 0,
            0, 104, 11, /* 1906: struct.x509_cinf_st */
            	1931, 0,
            	1931, 8,
            	1936, 16,
            	2083, 24,
            	2131, 32,
            	2083, 40,
            	2148, 48,
            	2025, 56,
            	2025, 64,
            	1105, 72,
            	1100, 80,
            1, 8, 1, /* 1931: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 1936: pointer.struct.X509_algor_st */
            	1941, 0,
            0, 16, 2, /* 1941: struct.X509_algor_st */
            	1948, 0,
            	1962, 8,
            1, 8, 1, /* 1948: pointer.struct.asn1_object_st */
            	1953, 0,
            0, 40, 3, /* 1953: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	179, 24,
            1, 8, 1, /* 1962: pointer.struct.asn1_type_st */
            	1967, 0,
            0, 16, 1, /* 1967: struct.asn1_type_st */
            	1972, 8,
            0, 8, 20, /* 1972: union.unknown */
            	61, 0,
            	2015, 0,
            	1948, 0,
            	1931, 0,
            	2020, 0,
            	2025, 0,
            	455, 0,
            	2030, 0,
            	2035, 0,
            	2040, 0,
            	2045, 0,
            	2050, 0,
            	2055, 0,
            	2060, 0,
            	2065, 0,
            	2070, 0,
            	445, 0,
            	2015, 0,
            	2015, 0,
            	2075, 0,
            1, 8, 1, /* 2015: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2020: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2025: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2030: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2035: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2040: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2045: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2050: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2055: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2060: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2065: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2070: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2075: pointer.struct.ASN1_VALUE_st */
            	2080, 0,
            0, 0, 0, /* 2080: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2083: pointer.struct.X509_name_st */
            	2088, 0,
            0, 40, 3, /* 2088: struct.X509_name_st */
            	2097, 0,
            	2121, 16,
            	197, 24,
            1, 8, 1, /* 2097: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2102, 0,
            0, 32, 2, /* 2102: struct.stack_st_fake_X509_NAME_ENTRY */
            	2109, 8,
            	205, 24,
            8884099, 8, 2, /* 2109: pointer_to_array_of_pointers_to_stack */
            	2116, 0,
            	202, 20,
            0, 8, 1, /* 2116: pointer.X509_NAME_ENTRY */
            	153, 0,
            1, 8, 1, /* 2121: pointer.struct.buf_mem_st */
            	2126, 0,
            0, 24, 1, /* 2126: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 2131: pointer.struct.X509_val_st */
            	2136, 0,
            0, 16, 2, /* 2136: struct.X509_val_st */
            	2143, 0,
            	2143, 8,
            1, 8, 1, /* 2143: pointer.struct.asn1_string_st */
            	450, 0,
            1, 8, 1, /* 2148: pointer.struct.X509_pubkey_st */
            	2153, 0,
            0, 24, 3, /* 2153: struct.X509_pubkey_st */
            	1936, 0,
            	2025, 8,
            	2162, 16,
            1, 8, 1, /* 2162: pointer.struct.evp_pkey_st */
            	2167, 0,
            0, 56, 4, /* 2167: struct.evp_pkey_st */
            	2178, 16,
            	1269, 24,
            	2186, 32,
            	2387, 48,
            1, 8, 1, /* 2178: pointer.struct.evp_pkey_asn1_method_st */
            	2183, 0,
            0, 0, 0, /* 2183: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 2186: union.unknown */
            	61, 0,
            	2199, 0,
            	2304, 0,
            	1277, 0,
            	2382, 0,
            1, 8, 1, /* 2199: pointer.struct.rsa_st */
            	2204, 0,
            0, 168, 17, /* 2204: struct.rsa_st */
            	2241, 16,
            	1269, 24,
            	66, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	66, 80,
            	66, 88,
            	1237, 96,
            	1223, 120,
            	1223, 128,
            	1223, 136,
            	61, 144,
            	2296, 152,
            	2296, 160,
            1, 8, 1, /* 2241: pointer.struct.rsa_meth_st */
            	2246, 0,
            0, 112, 13, /* 2246: struct.rsa_meth_st */
            	10, 0,
            	2275, 8,
            	2275, 16,
            	2275, 24,
            	2275, 32,
            	2278, 40,
            	2281, 48,
            	2284, 56,
            	2284, 64,
            	61, 80,
            	2287, 88,
            	2290, 96,
            	2293, 104,
            8884097, 8, 0, /* 2275: pointer.func */
            8884097, 8, 0, /* 2278: pointer.func */
            8884097, 8, 0, /* 2281: pointer.func */
            8884097, 8, 0, /* 2284: pointer.func */
            8884097, 8, 0, /* 2287: pointer.func */
            8884097, 8, 0, /* 2290: pointer.func */
            8884097, 8, 0, /* 2293: pointer.func */
            1, 8, 1, /* 2296: pointer.struct.bn_blinding_st */
            	2301, 0,
            0, 0, 0, /* 2301: struct.bn_blinding_st */
            1, 8, 1, /* 2304: pointer.struct.dsa_st */
            	2309, 0,
            0, 136, 11, /* 2309: struct.dsa_st */
            	66, 24,
            	66, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	1223, 88,
            	1237, 104,
            	2334, 120,
            	1269, 128,
            1, 8, 1, /* 2334: pointer.struct.dsa_method */
            	2339, 0,
            0, 96, 11, /* 2339: struct.dsa_method */
            	10, 0,
            	2364, 8,
            	2367, 16,
            	2370, 24,
            	1319, 32,
            	2373, 40,
            	2376, 48,
            	2376, 56,
            	61, 72,
            	2379, 80,
            	2376, 88,
            8884097, 8, 0, /* 2364: pointer.func */
            8884097, 8, 0, /* 2367: pointer.func */
            8884097, 8, 0, /* 2370: pointer.func */
            8884097, 8, 0, /* 2373: pointer.func */
            8884097, 8, 0, /* 2376: pointer.func */
            8884097, 8, 0, /* 2379: pointer.func */
            1, 8, 1, /* 2382: pointer.struct.ec_key_st */
            	346, 0,
            1, 8, 1, /* 2387: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2392, 0,
            0, 32, 2, /* 2392: struct.stack_st_fake_X509_ATTRIBUTE */
            	2399, 8,
            	205, 24,
            8884099, 8, 2, /* 2399: pointer_to_array_of_pointers_to_stack */
            	2406, 0,
            	202, 20,
            0, 8, 1, /* 2406: pointer.X509_ATTRIBUTE */
            	2411, 0,
            0, 0, 1, /* 2411: X509_ATTRIBUTE */
            	2416, 0,
            0, 24, 2, /* 2416: struct.x509_attributes_st */
            	2423, 0,
            	2437, 16,
            1, 8, 1, /* 2423: pointer.struct.asn1_object_st */
            	2428, 0,
            0, 40, 3, /* 2428: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	179, 24,
            0, 8, 3, /* 2437: union.unknown */
            	61, 0,
            	2446, 0,
            	2616, 0,
            1, 8, 1, /* 2446: pointer.struct.stack_st_ASN1_TYPE */
            	2451, 0,
            0, 32, 2, /* 2451: struct.stack_st_fake_ASN1_TYPE */
            	2458, 8,
            	205, 24,
            8884099, 8, 2, /* 2458: pointer_to_array_of_pointers_to_stack */
            	2465, 0,
            	202, 20,
            0, 8, 1, /* 2465: pointer.ASN1_TYPE */
            	2470, 0,
            0, 0, 1, /* 2470: ASN1_TYPE */
            	2475, 0,
            0, 16, 1, /* 2475: struct.asn1_type_st */
            	2480, 8,
            0, 8, 20, /* 2480: union.unknown */
            	61, 0,
            	2523, 0,
            	2533, 0,
            	2538, 0,
            	2543, 0,
            	2548, 0,
            	2553, 0,
            	2558, 0,
            	2563, 0,
            	2568, 0,
            	2573, 0,
            	2578, 0,
            	2583, 0,
            	2588, 0,
            	2593, 0,
            	2598, 0,
            	2603, 0,
            	2523, 0,
            	2523, 0,
            	2608, 0,
            1, 8, 1, /* 2523: pointer.struct.asn1_string_st */
            	2528, 0,
            0, 24, 1, /* 2528: struct.asn1_string_st */
            	197, 8,
            1, 8, 1, /* 2533: pointer.struct.asn1_object_st */
            	436, 0,
            1, 8, 1, /* 2538: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2543: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2548: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2553: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2558: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2563: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2568: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2573: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2578: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2583: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2588: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2593: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2598: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2603: pointer.struct.asn1_string_st */
            	2528, 0,
            1, 8, 1, /* 2608: pointer.struct.ASN1_VALUE_st */
            	2613, 0,
            0, 0, 0, /* 2613: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2616: pointer.struct.asn1_type_st */
            	2621, 0,
            0, 16, 1, /* 2621: struct.asn1_type_st */
            	2626, 8,
            0, 8, 20, /* 2626: union.unknown */
            	61, 0,
            	1333, 0,
            	2423, 0,
            	2669, 0,
            	2674, 0,
            	2679, 0,
            	2684, 0,
            	2689, 0,
            	2694, 0,
            	2699, 0,
            	2704, 0,
            	2709, 0,
            	2714, 0,
            	2719, 0,
            	2724, 0,
            	2729, 0,
            	2734, 0,
            	1333, 0,
            	1333, 0,
            	643, 0,
            1, 8, 1, /* 2669: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2674: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2679: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2684: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2689: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2694: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2699: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2704: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2709: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2714: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2719: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2724: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2729: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2734: pointer.struct.asn1_string_st */
            	1338, 0,
            1, 8, 1, /* 2739: pointer.struct.NAME_CONSTRAINTS_st */
            	2744, 0,
            0, 0, 0, /* 2744: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2747: pointer.struct.env_md_st */
            	361, 0,
            1, 8, 1, /* 2752: pointer.struct.rsa_st */
            	2204, 0,
            8884097, 8, 0, /* 2757: pointer.func */
            1, 8, 1, /* 2760: pointer.struct.stack_st_DIST_POINT */
            	2765, 0,
            0, 32, 2, /* 2765: struct.stack_st_fake_DIST_POINT */
            	2772, 8,
            	205, 24,
            8884099, 8, 2, /* 2772: pointer_to_array_of_pointers_to_stack */
            	2779, 0,
            	202, 20,
            0, 8, 1, /* 2779: pointer.DIST_POINT */
            	969, 0,
            1, 8, 1, /* 2784: pointer.struct.X509_POLICY_CACHE_st */
            	2789, 0,
            0, 0, 0, /* 2789: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2792: struct.AUTHORITY_KEYID_st */
            0, 0, 0, /* 2795: struct.ec_key_st */
            1, 8, 1, /* 2798: pointer.struct.AUTHORITY_KEYID_st */
            	2792, 0,
            1, 8, 1, /* 2803: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	2808, 0,
            0, 32, 2, /* 2808: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	2815, 8,
            	205, 24,
            8884099, 8, 2, /* 2815: pointer_to_array_of_pointers_to_stack */
            	2822, 0,
            	202, 20,
            0, 8, 1, /* 2822: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 2827: pointer.func */
            8884097, 8, 0, /* 2830: pointer.func */
            8884097, 8, 0, /* 2833: pointer.func */
            1, 8, 1, /* 2836: pointer.struct.stack_st_X509_OBJECT */
            	2841, 0,
            0, 32, 2, /* 2841: struct.stack_st_fake_X509_OBJECT */
            	2848, 8,
            	205, 24,
            8884099, 8, 2, /* 2848: pointer_to_array_of_pointers_to_stack */
            	2855, 0,
            	202, 20,
            0, 8, 1, /* 2855: pointer.X509_OBJECT */
            	2860, 0,
            0, 0, 1, /* 2860: X509_OBJECT */
            	2865, 0,
            0, 16, 1, /* 2865: struct.x509_object_st */
            	2870, 8,
            0, 8, 4, /* 2870: union.unknown */
            	61, 0,
            	2881, 0,
            	3282, 0,
            	2969, 0,
            1, 8, 1, /* 2881: pointer.struct.x509_st */
            	2886, 0,
            0, 184, 12, /* 2886: struct.x509_st */
            	2913, 0,
            	1653, 8,
            	1437, 16,
            	61, 32,
            	1282, 40,
            	1304, 104,
            	2798, 112,
            	2784, 120,
            	2760, 128,
            	3184, 136,
            	3208, 144,
            	3216, 176,
            1, 8, 1, /* 2913: pointer.struct.x509_cinf_st */
            	2918, 0,
            0, 104, 11, /* 2918: struct.x509_cinf_st */
            	1427, 0,
            	1427, 8,
            	1653, 16,
            	1658, 24,
            	2943, 32,
            	1658, 40,
            	2955, 48,
            	1437, 56,
            	1437, 64,
            	1809, 72,
            	1322, 80,
            1, 8, 1, /* 2943: pointer.struct.X509_val_st */
            	2948, 0,
            0, 16, 2, /* 2948: struct.X509_val_st */
            	1701, 0,
            	1701, 8,
            1, 8, 1, /* 2955: pointer.struct.X509_pubkey_st */
            	2960, 0,
            0, 24, 3, /* 2960: struct.X509_pubkey_st */
            	1653, 0,
            	1437, 8,
            	2969, 16,
            1, 8, 1, /* 2969: pointer.struct.evp_pkey_st */
            	2974, 0,
            0, 56, 4, /* 2974: struct.evp_pkey_st */
            	2985, 16,
            	1589, 24,
            	2993, 32,
            	3160, 48,
            1, 8, 1, /* 2985: pointer.struct.evp_pkey_asn1_method_st */
            	2990, 0,
            0, 0, 0, /* 2990: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 2993: union.unknown */
            	61, 0,
            	1492, 0,
            	3006, 0,
            	3087, 0,
            	3155, 0,
            1, 8, 1, /* 3006: pointer.struct.dsa_st */
            	3011, 0,
            0, 136, 11, /* 3011: struct.dsa_st */
            	1597, 24,
            	1597, 32,
            	1597, 40,
            	1597, 48,
            	1597, 56,
            	1597, 64,
            	1597, 72,
            	1607, 88,
            	1282, 104,
            	3036, 120,
            	1589, 128,
            1, 8, 1, /* 3036: pointer.struct.dsa_method */
            	3041, 0,
            0, 96, 11, /* 3041: struct.dsa_method */
            	10, 0,
            	3066, 8,
            	3069, 16,
            	3072, 24,
            	3075, 32,
            	3078, 40,
            	3081, 48,
            	3081, 56,
            	61, 72,
            	3084, 80,
            	3081, 88,
            8884097, 8, 0, /* 3066: pointer.func */
            8884097, 8, 0, /* 3069: pointer.func */
            8884097, 8, 0, /* 3072: pointer.func */
            8884097, 8, 0, /* 3075: pointer.func */
            8884097, 8, 0, /* 3078: pointer.func */
            8884097, 8, 0, /* 3081: pointer.func */
            8884097, 8, 0, /* 3084: pointer.func */
            1, 8, 1, /* 3087: pointer.struct.dh_st */
            	3092, 0,
            0, 144, 12, /* 3092: struct.dh_st */
            	1597, 8,
            	1597, 16,
            	1597, 32,
            	1597, 40,
            	1607, 56,
            	1597, 64,
            	1597, 72,
            	197, 80,
            	1597, 96,
            	1282, 112,
            	3119, 128,
            	1589, 136,
            1, 8, 1, /* 3119: pointer.struct.dh_method */
            	3124, 0,
            0, 72, 8, /* 3124: struct.dh_method */
            	10, 0,
            	3143, 8,
            	3146, 16,
            	3149, 24,
            	3143, 32,
            	3143, 40,
            	61, 56,
            	3152, 64,
            8884097, 8, 0, /* 3143: pointer.func */
            8884097, 8, 0, /* 3146: pointer.func */
            8884097, 8, 0, /* 3149: pointer.func */
            8884097, 8, 0, /* 3152: pointer.func */
            1, 8, 1, /* 3155: pointer.struct.ec_key_st */
            	2795, 0,
            1, 8, 1, /* 3160: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3165, 0,
            0, 32, 2, /* 3165: struct.stack_st_fake_X509_ATTRIBUTE */
            	3172, 8,
            	205, 24,
            8884099, 8, 2, /* 3172: pointer_to_array_of_pointers_to_stack */
            	3179, 0,
            	202, 20,
            0, 8, 1, /* 3179: pointer.X509_ATTRIBUTE */
            	2411, 0,
            1, 8, 1, /* 3184: pointer.struct.stack_st_GENERAL_NAME */
            	3189, 0,
            0, 32, 2, /* 3189: struct.stack_st_fake_GENERAL_NAME */
            	3196, 8,
            	205, 24,
            8884099, 8, 2, /* 3196: pointer_to_array_of_pointers_to_stack */
            	3203, 0,
            	202, 20,
            0, 8, 1, /* 3203: pointer.GENERAL_NAME */
            	675, 0,
            1, 8, 1, /* 3208: pointer.struct.NAME_CONSTRAINTS_st */
            	3213, 0,
            0, 0, 0, /* 3213: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3216: pointer.struct.x509_cert_aux_st */
            	3221, 0,
            0, 40, 5, /* 3221: struct.x509_cert_aux_st */
            	3234, 0,
            	3234, 8,
            	1487, 16,
            	1304, 24,
            	3258, 32,
            1, 8, 1, /* 3234: pointer.struct.stack_st_ASN1_OBJECT */
            	3239, 0,
            0, 32, 2, /* 3239: struct.stack_st_fake_ASN1_OBJECT */
            	3246, 8,
            	205, 24,
            8884099, 8, 2, /* 3246: pointer_to_array_of_pointers_to_stack */
            	3253, 0,
            	202, 20,
            0, 8, 1, /* 3253: pointer.ASN1_OBJECT */
            	431, 0,
            1, 8, 1, /* 3258: pointer.struct.stack_st_X509_ALGOR */
            	3263, 0,
            0, 32, 2, /* 3263: struct.stack_st_fake_X509_ALGOR */
            	3270, 8,
            	205, 24,
            8884099, 8, 2, /* 3270: pointer_to_array_of_pointers_to_stack */
            	3277, 0,
            	202, 20,
            0, 8, 1, /* 3277: pointer.X509_ALGOR */
            	484, 0,
            1, 8, 1, /* 3282: pointer.struct.X509_crl_st */
            	3287, 0,
            0, 120, 10, /* 3287: struct.X509_crl_st */
            	1629, 0,
            	1653, 8,
            	1437, 16,
            	2798, 32,
            	3310, 40,
            	1427, 56,
            	1427, 64,
            	3318, 96,
            	3359, 104,
            	49, 112,
            1, 8, 1, /* 3310: pointer.struct.ISSUING_DIST_POINT_st */
            	3315, 0,
            0, 0, 0, /* 3315: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3318: pointer.struct.stack_st_GENERAL_NAMES */
            	3323, 0,
            0, 32, 2, /* 3323: struct.stack_st_fake_GENERAL_NAMES */
            	3330, 8,
            	205, 24,
            8884099, 8, 2, /* 3330: pointer_to_array_of_pointers_to_stack */
            	3337, 0,
            	202, 20,
            0, 8, 1, /* 3337: pointer.GENERAL_NAMES */
            	3342, 0,
            0, 0, 1, /* 3342: GENERAL_NAMES */
            	3347, 0,
            0, 32, 1, /* 3347: struct.stack_st_GENERAL_NAME */
            	3352, 0,
            0, 32, 2, /* 3352: struct.stack_st */
            	1259, 8,
            	205, 24,
            1, 8, 1, /* 3359: pointer.struct.x509_crl_method_st */
            	3364, 0,
            0, 0, 0, /* 3364: struct.x509_crl_method_st */
            8884097, 8, 0, /* 3367: pointer.func */
            8884097, 8, 0, /* 3370: pointer.func */
            0, 104, 11, /* 3373: struct.x509_cinf_st */
            	3398, 0,
            	3398, 8,
            	3408, 16,
            	3565, 24,
            	3613, 32,
            	3565, 40,
            	3630, 48,
            	3497, 56,
            	3497, 64,
            	4018, 72,
            	4042, 80,
            1, 8, 1, /* 3398: pointer.struct.asn1_string_st */
            	3403, 0,
            0, 24, 1, /* 3403: struct.asn1_string_st */
            	197, 8,
            1, 8, 1, /* 3408: pointer.struct.X509_algor_st */
            	3413, 0,
            0, 16, 2, /* 3413: struct.X509_algor_st */
            	3420, 0,
            	3434, 8,
            1, 8, 1, /* 3420: pointer.struct.asn1_object_st */
            	3425, 0,
            0, 40, 3, /* 3425: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	179, 24,
            1, 8, 1, /* 3434: pointer.struct.asn1_type_st */
            	3439, 0,
            0, 16, 1, /* 3439: struct.asn1_type_st */
            	3444, 8,
            0, 8, 20, /* 3444: union.unknown */
            	61, 0,
            	3487, 0,
            	3420, 0,
            	3398, 0,
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
            	3487, 0,
            	3487, 0,
            	3557, 0,
            1, 8, 1, /* 3487: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3492: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3497: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3502: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3507: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3512: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3517: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3522: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3527: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3532: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3537: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3542: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3547: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3552: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3557: pointer.struct.ASN1_VALUE_st */
            	3562, 0,
            0, 0, 0, /* 3562: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3565: pointer.struct.X509_name_st */
            	3570, 0,
            0, 40, 3, /* 3570: struct.X509_name_st */
            	3579, 0,
            	3603, 16,
            	197, 24,
            1, 8, 1, /* 3579: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3584, 0,
            0, 32, 2, /* 3584: struct.stack_st_fake_X509_NAME_ENTRY */
            	3591, 8,
            	205, 24,
            8884099, 8, 2, /* 3591: pointer_to_array_of_pointers_to_stack */
            	3598, 0,
            	202, 20,
            0, 8, 1, /* 3598: pointer.X509_NAME_ENTRY */
            	153, 0,
            1, 8, 1, /* 3603: pointer.struct.buf_mem_st */
            	3608, 0,
            0, 24, 1, /* 3608: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 3613: pointer.struct.X509_val_st */
            	3618, 0,
            0, 16, 2, /* 3618: struct.X509_val_st */
            	3625, 0,
            	3625, 8,
            1, 8, 1, /* 3625: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3630: pointer.struct.X509_pubkey_st */
            	3635, 0,
            0, 24, 3, /* 3635: struct.X509_pubkey_st */
            	3408, 0,
            	3497, 8,
            	3644, 16,
            1, 8, 1, /* 3644: pointer.struct.evp_pkey_st */
            	3649, 0,
            0, 56, 4, /* 3649: struct.evp_pkey_st */
            	3660, 16,
            	3668, 24,
            	3676, 32,
            	3994, 48,
            1, 8, 1, /* 3660: pointer.struct.evp_pkey_asn1_method_st */
            	3665, 0,
            0, 0, 0, /* 3665: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3668: pointer.struct.engine_st */
            	3673, 0,
            0, 0, 0, /* 3673: struct.engine_st */
            0, 8, 5, /* 3676: union.unknown */
            	61, 0,
            	3689, 0,
            	3840, 0,
            	3918, 0,
            	3986, 0,
            1, 8, 1, /* 3689: pointer.struct.rsa_st */
            	3694, 0,
            0, 168, 17, /* 3694: struct.rsa_st */
            	3731, 16,
            	3668, 24,
            	3786, 32,
            	3786, 40,
            	3786, 48,
            	3786, 56,
            	3786, 64,
            	3786, 72,
            	3786, 80,
            	3786, 88,
            	3796, 96,
            	3818, 120,
            	3818, 128,
            	3818, 136,
            	61, 144,
            	3832, 152,
            	3832, 160,
            1, 8, 1, /* 3731: pointer.struct.rsa_meth_st */
            	3736, 0,
            0, 112, 13, /* 3736: struct.rsa_meth_st */
            	10, 0,
            	3765, 8,
            	3765, 16,
            	3765, 24,
            	3765, 32,
            	3768, 40,
            	3771, 48,
            	3774, 56,
            	3774, 64,
            	61, 80,
            	3777, 88,
            	3780, 96,
            	3783, 104,
            8884097, 8, 0, /* 3765: pointer.func */
            8884097, 8, 0, /* 3768: pointer.func */
            8884097, 8, 0, /* 3771: pointer.func */
            8884097, 8, 0, /* 3774: pointer.func */
            8884097, 8, 0, /* 3777: pointer.func */
            8884097, 8, 0, /* 3780: pointer.func */
            8884097, 8, 0, /* 3783: pointer.func */
            1, 8, 1, /* 3786: pointer.struct.bignum_st */
            	3791, 0,
            0, 24, 1, /* 3791: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 3796: struct.crypto_ex_data_st */
            	3801, 0,
            1, 8, 1, /* 3801: pointer.struct.stack_st_void */
            	3806, 0,
            0, 32, 1, /* 3806: struct.stack_st_void */
            	3811, 0,
            0, 32, 2, /* 3811: struct.stack_st */
            	1259, 8,
            	205, 24,
            1, 8, 1, /* 3818: pointer.struct.bn_mont_ctx_st */
            	3823, 0,
            0, 96, 3, /* 3823: struct.bn_mont_ctx_st */
            	3791, 8,
            	3791, 32,
            	3791, 56,
            1, 8, 1, /* 3832: pointer.struct.bn_blinding_st */
            	3837, 0,
            0, 0, 0, /* 3837: struct.bn_blinding_st */
            1, 8, 1, /* 3840: pointer.struct.dsa_st */
            	3845, 0,
            0, 136, 11, /* 3845: struct.dsa_st */
            	3786, 24,
            	3786, 32,
            	3786, 40,
            	3786, 48,
            	3786, 56,
            	3786, 64,
            	3786, 72,
            	3818, 88,
            	3796, 104,
            	3870, 120,
            	3668, 128,
            1, 8, 1, /* 3870: pointer.struct.dsa_method */
            	3875, 0,
            0, 96, 11, /* 3875: struct.dsa_method */
            	10, 0,
            	3900, 8,
            	3903, 16,
            	3906, 24,
            	3367, 32,
            	3909, 40,
            	3912, 48,
            	3912, 56,
            	61, 72,
            	3915, 80,
            	3912, 88,
            8884097, 8, 0, /* 3900: pointer.func */
            8884097, 8, 0, /* 3903: pointer.func */
            8884097, 8, 0, /* 3906: pointer.func */
            8884097, 8, 0, /* 3909: pointer.func */
            8884097, 8, 0, /* 3912: pointer.func */
            8884097, 8, 0, /* 3915: pointer.func */
            1, 8, 1, /* 3918: pointer.struct.dh_st */
            	3923, 0,
            0, 144, 12, /* 3923: struct.dh_st */
            	3786, 8,
            	3786, 16,
            	3786, 32,
            	3786, 40,
            	3818, 56,
            	3786, 64,
            	3786, 72,
            	197, 80,
            	3786, 96,
            	3796, 112,
            	3950, 128,
            	3668, 136,
            1, 8, 1, /* 3950: pointer.struct.dh_method */
            	3955, 0,
            0, 72, 8, /* 3955: struct.dh_method */
            	10, 0,
            	3974, 8,
            	3977, 16,
            	3980, 24,
            	3974, 32,
            	3974, 40,
            	61, 56,
            	3983, 64,
            8884097, 8, 0, /* 3974: pointer.func */
            8884097, 8, 0, /* 3977: pointer.func */
            8884097, 8, 0, /* 3980: pointer.func */
            8884097, 8, 0, /* 3983: pointer.func */
            1, 8, 1, /* 3986: pointer.struct.ec_key_st */
            	3991, 0,
            0, 0, 0, /* 3991: struct.ec_key_st */
            1, 8, 1, /* 3994: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3999, 0,
            0, 32, 2, /* 3999: struct.stack_st_fake_X509_ATTRIBUTE */
            	4006, 8,
            	205, 24,
            8884099, 8, 2, /* 4006: pointer_to_array_of_pointers_to_stack */
            	4013, 0,
            	202, 20,
            0, 8, 1, /* 4013: pointer.X509_ATTRIBUTE */
            	2411, 0,
            1, 8, 1, /* 4018: pointer.struct.stack_st_X509_EXTENSION */
            	4023, 0,
            0, 32, 2, /* 4023: struct.stack_st_fake_X509_EXTENSION */
            	4030, 8,
            	205, 24,
            8884099, 8, 2, /* 4030: pointer_to_array_of_pointers_to_stack */
            	4037, 0,
            	202, 20,
            0, 8, 1, /* 4037: pointer.X509_EXTENSION */
            	1129, 0,
            0, 24, 1, /* 4042: struct.ASN1_ENCODING_st */
            	197, 0,
            0, 0, 0, /* 4047: struct.X509_POLICY_CACHE_st */
            0, 184, 12, /* 4050: struct.x509_st */
            	4077, 0,
            	3408, 8,
            	3497, 16,
            	61, 32,
            	3796, 40,
            	3502, 104,
            	4082, 112,
            	4090, 120,
            	4095, 128,
            	4119, 136,
            	4143, 144,
            	4151, 176,
            1, 8, 1, /* 4077: pointer.struct.x509_cinf_st */
            	3373, 0,
            1, 8, 1, /* 4082: pointer.struct.AUTHORITY_KEYID_st */
            	4087, 0,
            0, 0, 0, /* 4087: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4090: pointer.struct.X509_POLICY_CACHE_st */
            	4047, 0,
            1, 8, 1, /* 4095: pointer.struct.stack_st_DIST_POINT */
            	4100, 0,
            0, 32, 2, /* 4100: struct.stack_st_fake_DIST_POINT */
            	4107, 8,
            	205, 24,
            8884099, 8, 2, /* 4107: pointer_to_array_of_pointers_to_stack */
            	4114, 0,
            	202, 20,
            0, 8, 1, /* 4114: pointer.DIST_POINT */
            	969, 0,
            1, 8, 1, /* 4119: pointer.struct.stack_st_GENERAL_NAME */
            	4124, 0,
            0, 32, 2, /* 4124: struct.stack_st_fake_GENERAL_NAME */
            	4131, 8,
            	205, 24,
            8884099, 8, 2, /* 4131: pointer_to_array_of_pointers_to_stack */
            	4138, 0,
            	202, 20,
            0, 8, 1, /* 4138: pointer.GENERAL_NAME */
            	675, 0,
            1, 8, 1, /* 4143: pointer.struct.NAME_CONSTRAINTS_st */
            	4148, 0,
            0, 0, 0, /* 4148: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4151: pointer.struct.x509_cert_aux_st */
            	4156, 0,
            0, 40, 5, /* 4156: struct.x509_cert_aux_st */
            	4169, 0,
            	4169, 8,
            	3552, 16,
            	3502, 24,
            	4193, 32,
            1, 8, 1, /* 4169: pointer.struct.stack_st_ASN1_OBJECT */
            	4174, 0,
            0, 32, 2, /* 4174: struct.stack_st_fake_ASN1_OBJECT */
            	4181, 8,
            	205, 24,
            8884099, 8, 2, /* 4181: pointer_to_array_of_pointers_to_stack */
            	4188, 0,
            	202, 20,
            0, 8, 1, /* 4188: pointer.ASN1_OBJECT */
            	431, 0,
            1, 8, 1, /* 4193: pointer.struct.stack_st_X509_ALGOR */
            	4198, 0,
            0, 32, 2, /* 4198: struct.stack_st_fake_X509_ALGOR */
            	4205, 8,
            	205, 24,
            8884099, 8, 2, /* 4205: pointer_to_array_of_pointers_to_stack */
            	4212, 0,
            	202, 20,
            0, 8, 1, /* 4212: pointer.X509_ALGOR */
            	484, 0,
            8884097, 8, 0, /* 4217: pointer.func */
            8884097, 8, 0, /* 4220: pointer.func */
            8884097, 8, 0, /* 4223: pointer.func */
            0, 144, 15, /* 4226: struct.x509_store_st */
            	2836, 8,
            	4259, 16,
            	4462, 24,
            	4474, 32,
            	4477, 40,
            	4480, 48,
            	4483, 56,
            	4474, 64,
            	4486, 72,
            	4489, 80,
            	4492, 88,
            	3370, 96,
            	4495, 104,
            	4474, 112,
            	1237, 120,
            1, 8, 1, /* 4259: pointer.struct.stack_st_X509_LOOKUP */
            	4264, 0,
            0, 32, 2, /* 4264: struct.stack_st_fake_X509_LOOKUP */
            	4271, 8,
            	205, 24,
            8884099, 8, 2, /* 4271: pointer_to_array_of_pointers_to_stack */
            	4278, 0,
            	202, 20,
            0, 8, 1, /* 4278: pointer.X509_LOOKUP */
            	4283, 0,
            0, 0, 1, /* 4283: X509_LOOKUP */
            	4288, 0,
            0, 32, 3, /* 4288: struct.x509_lookup_st */
            	4297, 8,
            	61, 16,
            	4340, 24,
            1, 8, 1, /* 4297: pointer.struct.x509_lookup_method_st */
            	4302, 0,
            0, 80, 10, /* 4302: struct.x509_lookup_method_st */
            	10, 0,
            	4325, 8,
            	2827, 16,
            	4325, 24,
            	4325, 32,
            	4328, 40,
            	4331, 48,
            	4220, 56,
            	4334, 64,
            	4337, 72,
            8884097, 8, 0, /* 4325: pointer.func */
            8884097, 8, 0, /* 4328: pointer.func */
            8884097, 8, 0, /* 4331: pointer.func */
            8884097, 8, 0, /* 4334: pointer.func */
            8884097, 8, 0, /* 4337: pointer.func */
            1, 8, 1, /* 4340: pointer.struct.x509_store_st */
            	4345, 0,
            0, 144, 15, /* 4345: struct.x509_store_st */
            	4378, 8,
            	4402, 16,
            	4426, 24,
            	4438, 32,
            	4441, 40,
            	4444, 48,
            	4447, 56,
            	4438, 64,
            	4450, 72,
            	4453, 80,
            	4456, 88,
            	4459, 96,
            	4223, 104,
            	4438, 112,
            	1282, 120,
            1, 8, 1, /* 4378: pointer.struct.stack_st_X509_OBJECT */
            	4383, 0,
            0, 32, 2, /* 4383: struct.stack_st_fake_X509_OBJECT */
            	4390, 8,
            	205, 24,
            8884099, 8, 2, /* 4390: pointer_to_array_of_pointers_to_stack */
            	4397, 0,
            	202, 20,
            0, 8, 1, /* 4397: pointer.X509_OBJECT */
            	2860, 0,
            1, 8, 1, /* 4402: pointer.struct.stack_st_X509_LOOKUP */
            	4407, 0,
            0, 32, 2, /* 4407: struct.stack_st_fake_X509_LOOKUP */
            	4414, 8,
            	205, 24,
            8884099, 8, 2, /* 4414: pointer_to_array_of_pointers_to_stack */
            	4421, 0,
            	202, 20,
            0, 8, 1, /* 4421: pointer.X509_LOOKUP */
            	4283, 0,
            1, 8, 1, /* 4426: pointer.struct.X509_VERIFY_PARAM_st */
            	4431, 0,
            0, 56, 2, /* 4431: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	3234, 48,
            8884097, 8, 0, /* 4438: pointer.func */
            8884097, 8, 0, /* 4441: pointer.func */
            8884097, 8, 0, /* 4444: pointer.func */
            8884097, 8, 0, /* 4447: pointer.func */
            8884097, 8, 0, /* 4450: pointer.func */
            8884097, 8, 0, /* 4453: pointer.func */
            8884097, 8, 0, /* 4456: pointer.func */
            8884097, 8, 0, /* 4459: pointer.func */
            1, 8, 1, /* 4462: pointer.struct.X509_VERIFY_PARAM_st */
            	4467, 0,
            0, 56, 2, /* 4467: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	407, 48,
            8884097, 8, 0, /* 4474: pointer.func */
            8884097, 8, 0, /* 4477: pointer.func */
            8884097, 8, 0, /* 4480: pointer.func */
            8884097, 8, 0, /* 4483: pointer.func */
            8884097, 8, 0, /* 4486: pointer.func */
            8884097, 8, 0, /* 4489: pointer.func */
            8884097, 8, 0, /* 4492: pointer.func */
            8884097, 8, 0, /* 4495: pointer.func */
            8884097, 8, 0, /* 4498: pointer.func */
            0, 0, 1, /* 4501: SSL_CIPHER */
            	4506, 0,
            0, 88, 1, /* 4506: struct.ssl_cipher_st */
            	10, 8,
            8884097, 8, 0, /* 4511: pointer.func */
            8884097, 8, 0, /* 4514: pointer.func */
            0, 112, 11, /* 4517: struct.ssl3_enc_method */
            	2833, 0,
            	4511, 8,
            	4542, 16,
            	4545, 24,
            	2833, 32,
            	4548, 40,
            	4551, 56,
            	10, 64,
            	10, 80,
            	4554, 96,
            	4557, 104,
            8884097, 8, 0, /* 4542: pointer.func */
            8884097, 8, 0, /* 4545: pointer.func */
            8884097, 8, 0, /* 4548: pointer.func */
            8884097, 8, 0, /* 4551: pointer.func */
            8884097, 8, 0, /* 4554: pointer.func */
            8884097, 8, 0, /* 4557: pointer.func */
            8884097, 8, 0, /* 4560: pointer.func */
            8884097, 8, 0, /* 4563: pointer.func */
            0, 736, 50, /* 4566: struct.ssl_ctx_st */
            	4669, 0,
            	4771, 8,
            	4771, 16,
            	4795, 24,
            	4800, 32,
            	4836, 48,
            	4836, 56,
            	328, 80,
            	325, 88,
            	4919, 96,
            	1327, 152,
            	49, 160,
            	4922, 168,
            	49, 176,
            	322, 184,
            	4925, 192,
            	319, 200,
            	1237, 208,
            	2747, 224,
            	2747, 232,
            	2747, 240,
            	4890, 248,
            	295, 256,
            	246, 264,
            	217, 272,
            	1833, 304,
            	4217, 320,
            	49, 328,
            	4477, 376,
            	4928, 384,
            	4462, 392,
            	1269, 408,
            	52, 416,
            	49, 424,
            	4514, 480,
            	55, 488,
            	49, 496,
            	110, 504,
            	49, 512,
            	61, 520,
            	107, 528,
            	4931, 536,
            	97, 552,
            	97, 560,
            	18, 568,
            	84, 696,
            	49, 704,
            	15, 712,
            	49, 720,
            	2803, 728,
            1, 8, 1, /* 4669: pointer.struct.ssl_method_st */
            	4674, 0,
            0, 232, 28, /* 4674: struct.ssl_method_st */
            	4542, 8,
            	4733, 16,
            	4733, 24,
            	4542, 32,
            	4542, 40,
            	4736, 48,
            	4736, 56,
            	4739, 64,
            	4542, 72,
            	4542, 80,
            	4542, 88,
            	2830, 96,
            	1330, 104,
            	4560, 112,
            	4542, 120,
            	4742, 128,
            	4745, 136,
            	4748, 144,
            	4498, 152,
            	4751, 160,
            	4754, 168,
            	4757, 176,
            	4563, 184,
            	275, 192,
            	4760, 200,
            	4754, 208,
            	4765, 216,
            	4768, 224,
            8884097, 8, 0, /* 4733: pointer.func */
            8884097, 8, 0, /* 4736: pointer.func */
            8884097, 8, 0, /* 4739: pointer.func */
            8884097, 8, 0, /* 4742: pointer.func */
            8884097, 8, 0, /* 4745: pointer.func */
            8884097, 8, 0, /* 4748: pointer.func */
            8884097, 8, 0, /* 4751: pointer.func */
            8884097, 8, 0, /* 4754: pointer.func */
            8884097, 8, 0, /* 4757: pointer.func */
            1, 8, 1, /* 4760: pointer.struct.ssl3_enc_method */
            	4517, 0,
            8884097, 8, 0, /* 4765: pointer.func */
            8884097, 8, 0, /* 4768: pointer.func */
            1, 8, 1, /* 4771: pointer.struct.stack_st_SSL_CIPHER */
            	4776, 0,
            0, 32, 2, /* 4776: struct.stack_st_fake_SSL_CIPHER */
            	4783, 8,
            	205, 24,
            8884099, 8, 2, /* 4783: pointer_to_array_of_pointers_to_stack */
            	4790, 0,
            	202, 20,
            0, 8, 1, /* 4790: pointer.SSL_CIPHER */
            	4501, 0,
            1, 8, 1, /* 4795: pointer.struct.x509_store_st */
            	4226, 0,
            1, 8, 1, /* 4800: pointer.struct.lhash_st */
            	4805, 0,
            0, 176, 3, /* 4805: struct.lhash_st */
            	4814, 0,
            	205, 8,
            	4833, 16,
            8884099, 8, 2, /* 4814: pointer_to_array_of_pointers_to_stack */
            	4821, 0,
            	81, 28,
            1, 8, 1, /* 4821: pointer.struct.lhash_node_st */
            	4826, 0,
            0, 24, 2, /* 4826: struct.lhash_node_st */
            	49, 0,
            	4821, 8,
            8884097, 8, 0, /* 4833: pointer.func */
            1, 8, 1, /* 4836: pointer.struct.ssl_session_st */
            	4841, 0,
            0, 352, 14, /* 4841: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	4872, 168,
            	1869, 176,
            	336, 224,
            	4771, 240,
            	1237, 248,
            	4836, 264,
            	4836, 272,
            	61, 280,
            	197, 296,
            	197, 312,
            	197, 320,
            	61, 344,
            1, 8, 1, /* 4872: pointer.struct.sess_cert_st */
            	4877, 0,
            0, 248, 5, /* 4877: struct.sess_cert_st */
            	4890, 0,
            	1855, 16,
            	2752, 216,
            	1343, 224,
            	341, 232,
            1, 8, 1, /* 4890: pointer.struct.stack_st_X509 */
            	4895, 0,
            0, 32, 2, /* 4895: struct.stack_st_fake_X509 */
            	4902, 8,
            	205, 24,
            8884099, 8, 2, /* 4902: pointer_to_array_of_pointers_to_stack */
            	4909, 0,
            	202, 20,
            0, 8, 1, /* 4909: pointer.X509 */
            	4914, 0,
            0, 0, 1, /* 4914: X509 */
            	4050, 0,
            8884097, 8, 0, /* 4919: pointer.func */
            8884097, 8, 0, /* 4922: pointer.func */
            8884097, 8, 0, /* 4925: pointer.func */
            8884097, 8, 0, /* 4928: pointer.func */
            8884097, 8, 0, /* 4931: pointer.func */
            1, 8, 1, /* 4934: pointer.struct.ssl_ctx_st */
            	4566, 0,
            0, 1, 0, /* 4939: char */
        },
        .arg_entity_index = { 4934, 328, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    int (*new_arg_b)(struct ssl_st *, SSL_SESSION *) = *((int (**)(struct ssl_st *, SSL_SESSION *))new_args->args[1]);

    void (*orig_SSL_CTX_sess_set_new_cb)(SSL_CTX *,int (*)(struct ssl_st *, SSL_SESSION *));
    orig_SSL_CTX_sess_set_new_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_new_cb");
    (*orig_SSL_CTX_sess_set_new_cb)(new_arg_a,new_arg_b);

    syscall(889);

}

