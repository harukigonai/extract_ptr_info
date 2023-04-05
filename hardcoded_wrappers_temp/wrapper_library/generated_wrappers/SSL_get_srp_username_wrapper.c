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

char * bb_SSL_get_srp_username(SSL * arg_a);

char * SSL_get_srp_username(SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_srp_username called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_srp_username(arg_a);
    else {
        char * (*orig_SSL_get_srp_username)(SSL *);
        orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
        return orig_SSL_get_srp_username(arg_a);
    }
}

char * bb_SSL_get_srp_username(SSL * arg_a) 
{
    char * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 10: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            8884097, 8, 0, /* 15: pointer.func */
            8884097, 8, 0, /* 18: pointer.func */
            0, 16, 1, /* 21: struct.tls_session_ticket_ext_st */
            	26, 8,
            0, 8, 0, /* 26: pointer.void */
            1, 8, 1, /* 29: pointer.struct.tls_session_ticket_ext_st */
            	21, 0,
            1, 8, 1, /* 34: pointer.struct.asn1_string_st */
            	39, 0,
            0, 24, 1, /* 39: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 44: pointer.unsigned char */
            	49, 0,
            0, 1, 0, /* 49: unsigned char */
            1, 8, 1, /* 52: pointer.struct.buf_mem_st */
            	57, 0,
            0, 24, 1, /* 57: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 62: pointer.char */
            	8884096, 0,
            0, 40, 3, /* 67: struct.X509_name_st */
            	76, 0,
            	52, 16,
            	44, 24,
            1, 8, 1, /* 76: pointer.struct.stack_st_X509_NAME_ENTRY */
            	81, 0,
            0, 32, 2, /* 81: struct.stack_st_fake_X509_NAME_ENTRY */
            	88, 8,
            	144, 24,
            8884099, 8, 2, /* 88: pointer_to_array_of_pointers_to_stack */
            	95, 0,
            	141, 20,
            0, 8, 1, /* 95: pointer.X509_NAME_ENTRY */
            	100, 0,
            0, 0, 1, /* 100: X509_NAME_ENTRY */
            	105, 0,
            0, 24, 2, /* 105: struct.X509_name_entry_st */
            	112, 0,
            	131, 8,
            1, 8, 1, /* 112: pointer.struct.asn1_object_st */
            	117, 0,
            0, 40, 3, /* 117: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 126: pointer.unsigned char */
            	49, 0,
            1, 8, 1, /* 131: pointer.struct.asn1_string_st */
            	136, 0,
            0, 24, 1, /* 136: struct.asn1_string_st */
            	44, 8,
            0, 4, 0, /* 141: int */
            8884097, 8, 0, /* 144: pointer.func */
            1, 8, 1, /* 147: pointer.struct.X509_name_st */
            	67, 0,
            8884097, 8, 0, /* 152: pointer.func */
            0, 16, 1, /* 155: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 160: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	165, 0,
            0, 32, 2, /* 165: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	172, 8,
            	144, 24,
            8884099, 8, 2, /* 172: pointer_to_array_of_pointers_to_stack */
            	179, 0,
            	141, 20,
            0, 8, 1, /* 179: pointer.SRTP_PROTECTION_PROFILE */
            	184, 0,
            0, 0, 1, /* 184: SRTP_PROTECTION_PROFILE */
            	155, 0,
            8884097, 8, 0, /* 189: pointer.func */
            8884097, 8, 0, /* 192: pointer.func */
            8884097, 8, 0, /* 195: pointer.func */
            0, 128, 14, /* 198: struct.srp_ctx_st */
            	26, 0,
            	229, 8,
            	232, 16,
            	195, 24,
            	62, 32,
            	235, 40,
            	235, 48,
            	235, 56,
            	235, 64,
            	235, 72,
            	235, 80,
            	235, 88,
            	235, 96,
            	62, 104,
            8884097, 8, 0, /* 229: pointer.func */
            8884097, 8, 0, /* 232: pointer.func */
            1, 8, 1, /* 235: pointer.struct.bignum_st */
            	240, 0,
            0, 24, 1, /* 240: struct.bignum_st */
            	245, 0,
            1, 8, 1, /* 245: pointer.unsigned int */
            	250, 0,
            0, 4, 0, /* 250: unsigned int */
            0, 8, 1, /* 253: struct.ssl3_buf_freelist_entry_st */
            	258, 0,
            1, 8, 1, /* 258: pointer.struct.ssl3_buf_freelist_entry_st */
            	253, 0,
            8884097, 8, 0, /* 263: pointer.func */
            8884097, 8, 0, /* 266: pointer.func */
            8884097, 8, 0, /* 269: pointer.func */
            8884097, 8, 0, /* 272: pointer.func */
            0, 64, 7, /* 275: struct.comp_method_st */
            	5, 8,
            	272, 16,
            	269, 24,
            	266, 32,
            	266, 40,
            	292, 48,
            	292, 56,
            8884097, 8, 0, /* 292: pointer.func */
            1, 8, 1, /* 295: pointer.struct.comp_method_st */
            	275, 0,
            1, 8, 1, /* 300: pointer.struct.stack_st_SSL_COMP */
            	305, 0,
            0, 32, 2, /* 305: struct.stack_st_fake_SSL_COMP */
            	312, 8,
            	144, 24,
            8884099, 8, 2, /* 312: pointer_to_array_of_pointers_to_stack */
            	319, 0,
            	141, 20,
            0, 8, 1, /* 319: pointer.SSL_COMP */
            	324, 0,
            0, 0, 1, /* 324: SSL_COMP */
            	329, 0,
            0, 24, 2, /* 329: struct.ssl_comp_st */
            	5, 8,
            	295, 16,
            8884097, 8, 0, /* 336: pointer.func */
            8884097, 8, 0, /* 339: pointer.func */
            1, 8, 1, /* 342: pointer.struct.lhash_node_st */
            	347, 0,
            0, 24, 2, /* 347: struct.lhash_node_st */
            	26, 0,
            	342, 8,
            1, 8, 1, /* 354: pointer.struct.lhash_node_st */
            	347, 0,
            1, 8, 1, /* 359: pointer.pointer.struct.lhash_node_st */
            	354, 0,
            0, 176, 3, /* 364: struct.lhash_st */
            	359, 0,
            	144, 8,
            	373, 16,
            8884097, 8, 0, /* 373: pointer.func */
            8884097, 8, 0, /* 376: pointer.func */
            8884097, 8, 0, /* 379: pointer.func */
            8884097, 8, 0, /* 382: pointer.func */
            8884097, 8, 0, /* 385: pointer.func */
            8884097, 8, 0, /* 388: pointer.func */
            8884097, 8, 0, /* 391: pointer.func */
            8884097, 8, 0, /* 394: pointer.func */
            0, 0, 1, /* 397: OCSP_RESPID */
            	402, 0,
            0, 16, 1, /* 402: struct.ocsp_responder_id_st */
            	407, 8,
            0, 8, 2, /* 407: union.unknown */
            	147, 0,
            	34, 0,
            8884097, 8, 0, /* 414: pointer.func */
            8884097, 8, 0, /* 417: pointer.func */
            8884097, 8, 0, /* 420: pointer.func */
            8884097, 8, 0, /* 423: pointer.func */
            8884097, 8, 0, /* 426: pointer.func */
            8884097, 8, 0, /* 429: pointer.func */
            8884097, 8, 0, /* 432: pointer.func */
            1, 8, 1, /* 435: pointer.struct.stack_st_X509_LOOKUP */
            	440, 0,
            0, 32, 2, /* 440: struct.stack_st_fake_X509_LOOKUP */
            	447, 8,
            	144, 24,
            8884099, 8, 2, /* 447: pointer_to_array_of_pointers_to_stack */
            	454, 0,
            	141, 20,
            0, 8, 1, /* 454: pointer.X509_LOOKUP */
            	459, 0,
            0, 0, 1, /* 459: X509_LOOKUP */
            	464, 0,
            0, 32, 3, /* 464: struct.x509_lookup_st */
            	473, 8,
            	62, 16,
            	522, 24,
            1, 8, 1, /* 473: pointer.struct.x509_lookup_method_st */
            	478, 0,
            0, 80, 10, /* 478: struct.x509_lookup_method_st */
            	5, 0,
            	501, 8,
            	504, 16,
            	501, 24,
            	501, 32,
            	507, 40,
            	510, 48,
            	513, 56,
            	516, 64,
            	519, 72,
            8884097, 8, 0, /* 501: pointer.func */
            8884097, 8, 0, /* 504: pointer.func */
            8884097, 8, 0, /* 507: pointer.func */
            8884097, 8, 0, /* 510: pointer.func */
            8884097, 8, 0, /* 513: pointer.func */
            8884097, 8, 0, /* 516: pointer.func */
            8884097, 8, 0, /* 519: pointer.func */
            1, 8, 1, /* 522: pointer.struct.x509_store_st */
            	527, 0,
            0, 144, 15, /* 527: struct.x509_store_st */
            	560, 8,
            	435, 16,
            	2615, 24,
            	432, 32,
            	429, 40,
            	426, 48,
            	423, 56,
            	432, 64,
            	420, 72,
            	2627, 80,
            	2630, 88,
            	417, 96,
            	414, 104,
            	432, 112,
            	1065, 120,
            1, 8, 1, /* 560: pointer.struct.stack_st_X509_OBJECT */
            	565, 0,
            0, 32, 2, /* 565: struct.stack_st_fake_X509_OBJECT */
            	572, 8,
            	144, 24,
            8884099, 8, 2, /* 572: pointer_to_array_of_pointers_to_stack */
            	579, 0,
            	141, 20,
            0, 8, 1, /* 579: pointer.X509_OBJECT */
            	584, 0,
            0, 0, 1, /* 584: X509_OBJECT */
            	589, 0,
            0, 16, 1, /* 589: struct.x509_object_st */
            	594, 8,
            0, 8, 4, /* 594: union.unknown */
            	62, 0,
            	605, 0,
            	2403, 0,
            	913, 0,
            1, 8, 1, /* 605: pointer.struct.x509_st */
            	610, 0,
            0, 184, 12, /* 610: struct.x509_st */
            	637, 0,
            	677, 8,
            	766, 16,
            	62, 32,
            	1065, 40,
            	771, 104,
            	1707, 112,
            	1715, 120,
            	1723, 128,
            	2132, 136,
            	2156, 144,
            	2164, 176,
            1, 8, 1, /* 637: pointer.struct.x509_cinf_st */
            	642, 0,
            0, 104, 11, /* 642: struct.x509_cinf_st */
            	667, 0,
            	667, 8,
            	677, 16,
            	834, 24,
            	882, 32,
            	834, 40,
            	899, 48,
            	766, 56,
            	766, 64,
            	1642, 72,
            	1702, 80,
            1, 8, 1, /* 667: pointer.struct.asn1_string_st */
            	672, 0,
            0, 24, 1, /* 672: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 677: pointer.struct.X509_algor_st */
            	682, 0,
            0, 16, 2, /* 682: struct.X509_algor_st */
            	689, 0,
            	703, 8,
            1, 8, 1, /* 689: pointer.struct.asn1_object_st */
            	694, 0,
            0, 40, 3, /* 694: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 703: pointer.struct.asn1_type_st */
            	708, 0,
            0, 16, 1, /* 708: struct.asn1_type_st */
            	713, 8,
            0, 8, 20, /* 713: union.unknown */
            	62, 0,
            	756, 0,
            	689, 0,
            	667, 0,
            	761, 0,
            	766, 0,
            	771, 0,
            	776, 0,
            	781, 0,
            	786, 0,
            	791, 0,
            	796, 0,
            	801, 0,
            	806, 0,
            	811, 0,
            	816, 0,
            	821, 0,
            	756, 0,
            	756, 0,
            	826, 0,
            1, 8, 1, /* 756: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 761: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 766: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 771: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 776: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 781: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 786: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 791: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 796: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 801: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 806: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 811: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 816: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 821: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 826: pointer.struct.ASN1_VALUE_st */
            	831, 0,
            0, 0, 0, /* 831: struct.ASN1_VALUE_st */
            1, 8, 1, /* 834: pointer.struct.X509_name_st */
            	839, 0,
            0, 40, 3, /* 839: struct.X509_name_st */
            	848, 0,
            	872, 16,
            	44, 24,
            1, 8, 1, /* 848: pointer.struct.stack_st_X509_NAME_ENTRY */
            	853, 0,
            0, 32, 2, /* 853: struct.stack_st_fake_X509_NAME_ENTRY */
            	860, 8,
            	144, 24,
            8884099, 8, 2, /* 860: pointer_to_array_of_pointers_to_stack */
            	867, 0,
            	141, 20,
            0, 8, 1, /* 867: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 872: pointer.struct.buf_mem_st */
            	877, 0,
            0, 24, 1, /* 877: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 882: pointer.struct.X509_val_st */
            	887, 0,
            0, 16, 2, /* 887: struct.X509_val_st */
            	894, 0,
            	894, 8,
            1, 8, 1, /* 894: pointer.struct.asn1_string_st */
            	672, 0,
            1, 8, 1, /* 899: pointer.struct.X509_pubkey_st */
            	904, 0,
            0, 24, 3, /* 904: struct.X509_pubkey_st */
            	677, 0,
            	766, 8,
            	913, 16,
            1, 8, 1, /* 913: pointer.struct.evp_pkey_st */
            	918, 0,
            0, 56, 4, /* 918: struct.evp_pkey_st */
            	929, 16,
            	937, 24,
            	945, 32,
            	1271, 48,
            1, 8, 1, /* 929: pointer.struct.evp_pkey_asn1_method_st */
            	934, 0,
            0, 0, 0, /* 934: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 937: pointer.struct.engine_st */
            	942, 0,
            0, 0, 0, /* 942: struct.engine_st */
            0, 8, 5, /* 945: union.unknown */
            	62, 0,
            	958, 0,
            	1114, 0,
            	1195, 0,
            	1263, 0,
            1, 8, 1, /* 958: pointer.struct.rsa_st */
            	963, 0,
            0, 168, 17, /* 963: struct.rsa_st */
            	1000, 16,
            	937, 24,
            	1055, 32,
            	1055, 40,
            	1055, 48,
            	1055, 56,
            	1055, 64,
            	1055, 72,
            	1055, 80,
            	1055, 88,
            	1065, 96,
            	1092, 120,
            	1092, 128,
            	1092, 136,
            	62, 144,
            	1106, 152,
            	1106, 160,
            1, 8, 1, /* 1000: pointer.struct.rsa_meth_st */
            	1005, 0,
            0, 112, 13, /* 1005: struct.rsa_meth_st */
            	5, 0,
            	1034, 8,
            	1034, 16,
            	1034, 24,
            	1034, 32,
            	1037, 40,
            	1040, 48,
            	1043, 56,
            	1043, 64,
            	62, 80,
            	1046, 88,
            	1049, 96,
            	1052, 104,
            8884097, 8, 0, /* 1034: pointer.func */
            8884097, 8, 0, /* 1037: pointer.func */
            8884097, 8, 0, /* 1040: pointer.func */
            8884097, 8, 0, /* 1043: pointer.func */
            8884097, 8, 0, /* 1046: pointer.func */
            8884097, 8, 0, /* 1049: pointer.func */
            8884097, 8, 0, /* 1052: pointer.func */
            1, 8, 1, /* 1055: pointer.struct.bignum_st */
            	1060, 0,
            0, 24, 1, /* 1060: struct.bignum_st */
            	245, 0,
            0, 16, 1, /* 1065: struct.crypto_ex_data_st */
            	1070, 0,
            1, 8, 1, /* 1070: pointer.struct.stack_st_void */
            	1075, 0,
            0, 32, 1, /* 1075: struct.stack_st_void */
            	1080, 0,
            0, 32, 2, /* 1080: struct.stack_st */
            	1087, 8,
            	144, 24,
            1, 8, 1, /* 1087: pointer.pointer.char */
            	62, 0,
            1, 8, 1, /* 1092: pointer.struct.bn_mont_ctx_st */
            	1097, 0,
            0, 96, 3, /* 1097: struct.bn_mont_ctx_st */
            	1060, 8,
            	1060, 32,
            	1060, 56,
            1, 8, 1, /* 1106: pointer.struct.bn_blinding_st */
            	1111, 0,
            0, 0, 0, /* 1111: struct.bn_blinding_st */
            1, 8, 1, /* 1114: pointer.struct.dsa_st */
            	1119, 0,
            0, 136, 11, /* 1119: struct.dsa_st */
            	1055, 24,
            	1055, 32,
            	1055, 40,
            	1055, 48,
            	1055, 56,
            	1055, 64,
            	1055, 72,
            	1092, 88,
            	1065, 104,
            	1144, 120,
            	937, 128,
            1, 8, 1, /* 1144: pointer.struct.dsa_method */
            	1149, 0,
            0, 96, 11, /* 1149: struct.dsa_method */
            	5, 0,
            	1174, 8,
            	1177, 16,
            	1180, 24,
            	1183, 32,
            	1186, 40,
            	1189, 48,
            	1189, 56,
            	62, 72,
            	1192, 80,
            	1189, 88,
            8884097, 8, 0, /* 1174: pointer.func */
            8884097, 8, 0, /* 1177: pointer.func */
            8884097, 8, 0, /* 1180: pointer.func */
            8884097, 8, 0, /* 1183: pointer.func */
            8884097, 8, 0, /* 1186: pointer.func */
            8884097, 8, 0, /* 1189: pointer.func */
            8884097, 8, 0, /* 1192: pointer.func */
            1, 8, 1, /* 1195: pointer.struct.dh_st */
            	1200, 0,
            0, 144, 12, /* 1200: struct.dh_st */
            	1055, 8,
            	1055, 16,
            	1055, 32,
            	1055, 40,
            	1092, 56,
            	1055, 64,
            	1055, 72,
            	44, 80,
            	1055, 96,
            	1065, 112,
            	1227, 128,
            	937, 136,
            1, 8, 1, /* 1227: pointer.struct.dh_method */
            	1232, 0,
            0, 72, 8, /* 1232: struct.dh_method */
            	5, 0,
            	1251, 8,
            	1254, 16,
            	1257, 24,
            	1251, 32,
            	1251, 40,
            	62, 56,
            	1260, 64,
            8884097, 8, 0, /* 1251: pointer.func */
            8884097, 8, 0, /* 1254: pointer.func */
            8884097, 8, 0, /* 1257: pointer.func */
            8884097, 8, 0, /* 1260: pointer.func */
            1, 8, 1, /* 1263: pointer.struct.ec_key_st */
            	1268, 0,
            0, 0, 0, /* 1268: struct.ec_key_st */
            1, 8, 1, /* 1271: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1276, 0,
            0, 32, 2, /* 1276: struct.stack_st_fake_X509_ATTRIBUTE */
            	1283, 8,
            	144, 24,
            8884099, 8, 2, /* 1283: pointer_to_array_of_pointers_to_stack */
            	1290, 0,
            	141, 20,
            0, 8, 1, /* 1290: pointer.X509_ATTRIBUTE */
            	1295, 0,
            0, 0, 1, /* 1295: X509_ATTRIBUTE */
            	1300, 0,
            0, 24, 2, /* 1300: struct.x509_attributes_st */
            	1307, 0,
            	1321, 16,
            1, 8, 1, /* 1307: pointer.struct.asn1_object_st */
            	1312, 0,
            0, 40, 3, /* 1312: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            0, 8, 3, /* 1321: union.unknown */
            	62, 0,
            	1330, 0,
            	1509, 0,
            1, 8, 1, /* 1330: pointer.struct.stack_st_ASN1_TYPE */
            	1335, 0,
            0, 32, 2, /* 1335: struct.stack_st_fake_ASN1_TYPE */
            	1342, 8,
            	144, 24,
            8884099, 8, 2, /* 1342: pointer_to_array_of_pointers_to_stack */
            	1349, 0,
            	141, 20,
            0, 8, 1, /* 1349: pointer.ASN1_TYPE */
            	1354, 0,
            0, 0, 1, /* 1354: ASN1_TYPE */
            	1359, 0,
            0, 16, 1, /* 1359: struct.asn1_type_st */
            	1364, 8,
            0, 8, 20, /* 1364: union.unknown */
            	62, 0,
            	1407, 0,
            	1417, 0,
            	1431, 0,
            	1436, 0,
            	1441, 0,
            	1446, 0,
            	1451, 0,
            	1456, 0,
            	1461, 0,
            	1466, 0,
            	1471, 0,
            	1476, 0,
            	1481, 0,
            	1486, 0,
            	1491, 0,
            	1496, 0,
            	1407, 0,
            	1407, 0,
            	1501, 0,
            1, 8, 1, /* 1407: pointer.struct.asn1_string_st */
            	1412, 0,
            0, 24, 1, /* 1412: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 1417: pointer.struct.asn1_object_st */
            	1422, 0,
            0, 40, 3, /* 1422: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 1431: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1436: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1441: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1446: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1451: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1456: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1461: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1466: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1471: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1476: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1481: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1486: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1491: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1496: pointer.struct.asn1_string_st */
            	1412, 0,
            1, 8, 1, /* 1501: pointer.struct.ASN1_VALUE_st */
            	1506, 0,
            0, 0, 0, /* 1506: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1509: pointer.struct.asn1_type_st */
            	1514, 0,
            0, 16, 1, /* 1514: struct.asn1_type_st */
            	1519, 8,
            0, 8, 20, /* 1519: union.unknown */
            	62, 0,
            	1562, 0,
            	1307, 0,
            	1572, 0,
            	1577, 0,
            	1582, 0,
            	1587, 0,
            	1592, 0,
            	1597, 0,
            	1602, 0,
            	1607, 0,
            	1612, 0,
            	1617, 0,
            	1622, 0,
            	1627, 0,
            	1632, 0,
            	1637, 0,
            	1562, 0,
            	1562, 0,
            	826, 0,
            1, 8, 1, /* 1562: pointer.struct.asn1_string_st */
            	1567, 0,
            0, 24, 1, /* 1567: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 1572: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1577: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1582: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1587: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1592: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1597: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1602: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1607: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1612: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1617: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1622: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1627: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1632: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1637: pointer.struct.asn1_string_st */
            	1567, 0,
            1, 8, 1, /* 1642: pointer.struct.stack_st_X509_EXTENSION */
            	1647, 0,
            0, 32, 2, /* 1647: struct.stack_st_fake_X509_EXTENSION */
            	1654, 8,
            	144, 24,
            8884099, 8, 2, /* 1654: pointer_to_array_of_pointers_to_stack */
            	1661, 0,
            	141, 20,
            0, 8, 1, /* 1661: pointer.X509_EXTENSION */
            	1666, 0,
            0, 0, 1, /* 1666: X509_EXTENSION */
            	1671, 0,
            0, 24, 2, /* 1671: struct.X509_extension_st */
            	1678, 0,
            	1692, 16,
            1, 8, 1, /* 1678: pointer.struct.asn1_object_st */
            	1683, 0,
            0, 40, 3, /* 1683: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 1692: pointer.struct.asn1_string_st */
            	1697, 0,
            0, 24, 1, /* 1697: struct.asn1_string_st */
            	44, 8,
            0, 24, 1, /* 1702: struct.ASN1_ENCODING_st */
            	44, 0,
            1, 8, 1, /* 1707: pointer.struct.AUTHORITY_KEYID_st */
            	1712, 0,
            0, 0, 0, /* 1712: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1715: pointer.struct.X509_POLICY_CACHE_st */
            	1720, 0,
            0, 0, 0, /* 1720: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1723: pointer.struct.stack_st_DIST_POINT */
            	1728, 0,
            0, 32, 2, /* 1728: struct.stack_st_fake_DIST_POINT */
            	1735, 8,
            	144, 24,
            8884099, 8, 2, /* 1735: pointer_to_array_of_pointers_to_stack */
            	1742, 0,
            	141, 20,
            0, 8, 1, /* 1742: pointer.DIST_POINT */
            	1747, 0,
            0, 0, 1, /* 1747: DIST_POINT */
            	1752, 0,
            0, 32, 3, /* 1752: struct.DIST_POINT_st */
            	1761, 0,
            	2122, 8,
            	1780, 16,
            1, 8, 1, /* 1761: pointer.struct.DIST_POINT_NAME_st */
            	1766, 0,
            0, 24, 2, /* 1766: struct.DIST_POINT_NAME_st */
            	1773, 8,
            	2098, 16,
            0, 8, 2, /* 1773: union.unknown */
            	1780, 0,
            	2074, 0,
            1, 8, 1, /* 1780: pointer.struct.stack_st_GENERAL_NAME */
            	1785, 0,
            0, 32, 2, /* 1785: struct.stack_st_fake_GENERAL_NAME */
            	1792, 8,
            	144, 24,
            8884099, 8, 2, /* 1792: pointer_to_array_of_pointers_to_stack */
            	1799, 0,
            	141, 20,
            0, 8, 1, /* 1799: pointer.GENERAL_NAME */
            	1804, 0,
            0, 0, 1, /* 1804: GENERAL_NAME */
            	1809, 0,
            0, 16, 1, /* 1809: struct.GENERAL_NAME_st */
            	1814, 8,
            0, 8, 15, /* 1814: union.unknown */
            	62, 0,
            	1847, 0,
            	1966, 0,
            	1966, 0,
            	1873, 0,
            	2014, 0,
            	2062, 0,
            	1966, 0,
            	1951, 0,
            	1859, 0,
            	1951, 0,
            	2014, 0,
            	1966, 0,
            	1859, 0,
            	1873, 0,
            1, 8, 1, /* 1847: pointer.struct.otherName_st */
            	1852, 0,
            0, 16, 2, /* 1852: struct.otherName_st */
            	1859, 0,
            	1873, 8,
            1, 8, 1, /* 1859: pointer.struct.asn1_object_st */
            	1864, 0,
            0, 40, 3, /* 1864: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 1873: pointer.struct.asn1_type_st */
            	1878, 0,
            0, 16, 1, /* 1878: struct.asn1_type_st */
            	1883, 8,
            0, 8, 20, /* 1883: union.unknown */
            	62, 0,
            	1926, 0,
            	1859, 0,
            	1936, 0,
            	1941, 0,
            	1946, 0,
            	1951, 0,
            	1956, 0,
            	1961, 0,
            	1966, 0,
            	1971, 0,
            	1976, 0,
            	1981, 0,
            	1986, 0,
            	1991, 0,
            	1996, 0,
            	2001, 0,
            	1926, 0,
            	1926, 0,
            	2006, 0,
            1, 8, 1, /* 1926: pointer.struct.asn1_string_st */
            	1931, 0,
            0, 24, 1, /* 1931: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 1936: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1941: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1946: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1951: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1956: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1961: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1966: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1971: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1976: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1981: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1986: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1991: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 1996: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 2001: pointer.struct.asn1_string_st */
            	1931, 0,
            1, 8, 1, /* 2006: pointer.struct.ASN1_VALUE_st */
            	2011, 0,
            0, 0, 0, /* 2011: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2014: pointer.struct.X509_name_st */
            	2019, 0,
            0, 40, 3, /* 2019: struct.X509_name_st */
            	2028, 0,
            	2052, 16,
            	44, 24,
            1, 8, 1, /* 2028: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2033, 0,
            0, 32, 2, /* 2033: struct.stack_st_fake_X509_NAME_ENTRY */
            	2040, 8,
            	144, 24,
            8884099, 8, 2, /* 2040: pointer_to_array_of_pointers_to_stack */
            	2047, 0,
            	141, 20,
            0, 8, 1, /* 2047: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 2052: pointer.struct.buf_mem_st */
            	2057, 0,
            0, 24, 1, /* 2057: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 2062: pointer.struct.EDIPartyName_st */
            	2067, 0,
            0, 16, 2, /* 2067: struct.EDIPartyName_st */
            	1926, 0,
            	1926, 8,
            1, 8, 1, /* 2074: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2079, 0,
            0, 32, 2, /* 2079: struct.stack_st_fake_X509_NAME_ENTRY */
            	2086, 8,
            	144, 24,
            8884099, 8, 2, /* 2086: pointer_to_array_of_pointers_to_stack */
            	2093, 0,
            	141, 20,
            0, 8, 1, /* 2093: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 2098: pointer.struct.X509_name_st */
            	2103, 0,
            0, 40, 3, /* 2103: struct.X509_name_st */
            	2074, 0,
            	2112, 16,
            	44, 24,
            1, 8, 1, /* 2112: pointer.struct.buf_mem_st */
            	2117, 0,
            0, 24, 1, /* 2117: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 2122: pointer.struct.asn1_string_st */
            	2127, 0,
            0, 24, 1, /* 2127: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 2132: pointer.struct.stack_st_GENERAL_NAME */
            	2137, 0,
            0, 32, 2, /* 2137: struct.stack_st_fake_GENERAL_NAME */
            	2144, 8,
            	144, 24,
            8884099, 8, 2, /* 2144: pointer_to_array_of_pointers_to_stack */
            	2151, 0,
            	141, 20,
            0, 8, 1, /* 2151: pointer.GENERAL_NAME */
            	1804, 0,
            1, 8, 1, /* 2156: pointer.struct.NAME_CONSTRAINTS_st */
            	2161, 0,
            0, 0, 0, /* 2161: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2164: pointer.struct.x509_cert_aux_st */
            	2169, 0,
            0, 40, 5, /* 2169: struct.x509_cert_aux_st */
            	2182, 0,
            	2182, 8,
            	821, 16,
            	771, 24,
            	2220, 32,
            1, 8, 1, /* 2182: pointer.struct.stack_st_ASN1_OBJECT */
            	2187, 0,
            0, 32, 2, /* 2187: struct.stack_st_fake_ASN1_OBJECT */
            	2194, 8,
            	144, 24,
            8884099, 8, 2, /* 2194: pointer_to_array_of_pointers_to_stack */
            	2201, 0,
            	141, 20,
            0, 8, 1, /* 2201: pointer.ASN1_OBJECT */
            	2206, 0,
            0, 0, 1, /* 2206: ASN1_OBJECT */
            	2211, 0,
            0, 40, 3, /* 2211: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 2220: pointer.struct.stack_st_X509_ALGOR */
            	2225, 0,
            0, 32, 2, /* 2225: struct.stack_st_fake_X509_ALGOR */
            	2232, 8,
            	144, 24,
            8884099, 8, 2, /* 2232: pointer_to_array_of_pointers_to_stack */
            	2239, 0,
            	141, 20,
            0, 8, 1, /* 2239: pointer.X509_ALGOR */
            	2244, 0,
            0, 0, 1, /* 2244: X509_ALGOR */
            	2249, 0,
            0, 16, 2, /* 2249: struct.X509_algor_st */
            	2256, 0,
            	2270, 8,
            1, 8, 1, /* 2256: pointer.struct.asn1_object_st */
            	2261, 0,
            0, 40, 3, /* 2261: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 2270: pointer.struct.asn1_type_st */
            	2275, 0,
            0, 16, 1, /* 2275: struct.asn1_type_st */
            	2280, 8,
            0, 8, 20, /* 2280: union.unknown */
            	62, 0,
            	2323, 0,
            	2256, 0,
            	2333, 0,
            	2338, 0,
            	2343, 0,
            	2348, 0,
            	2353, 0,
            	2358, 0,
            	2363, 0,
            	2368, 0,
            	2373, 0,
            	2378, 0,
            	2383, 0,
            	2388, 0,
            	2393, 0,
            	2398, 0,
            	2323, 0,
            	2323, 0,
            	826, 0,
            1, 8, 1, /* 2323: pointer.struct.asn1_string_st */
            	2328, 0,
            0, 24, 1, /* 2328: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 2333: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2338: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2343: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2348: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2353: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2358: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2363: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2368: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2373: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2378: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2383: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2388: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2393: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2398: pointer.struct.asn1_string_st */
            	2328, 0,
            1, 8, 1, /* 2403: pointer.struct.X509_crl_st */
            	2408, 0,
            0, 120, 10, /* 2408: struct.X509_crl_st */
            	2431, 0,
            	677, 8,
            	766, 16,
            	1707, 32,
            	2558, 40,
            	667, 56,
            	667, 64,
            	2566, 96,
            	2607, 104,
            	26, 112,
            1, 8, 1, /* 2431: pointer.struct.X509_crl_info_st */
            	2436, 0,
            0, 80, 8, /* 2436: struct.X509_crl_info_st */
            	667, 0,
            	677, 8,
            	834, 16,
            	894, 24,
            	894, 32,
            	2455, 40,
            	1642, 48,
            	1702, 56,
            1, 8, 1, /* 2455: pointer.struct.stack_st_X509_REVOKED */
            	2460, 0,
            0, 32, 2, /* 2460: struct.stack_st_fake_X509_REVOKED */
            	2467, 8,
            	144, 24,
            8884099, 8, 2, /* 2467: pointer_to_array_of_pointers_to_stack */
            	2474, 0,
            	141, 20,
            0, 8, 1, /* 2474: pointer.X509_REVOKED */
            	2479, 0,
            0, 0, 1, /* 2479: X509_REVOKED */
            	2484, 0,
            0, 40, 4, /* 2484: struct.x509_revoked_st */
            	2495, 0,
            	2505, 8,
            	2510, 16,
            	2534, 24,
            1, 8, 1, /* 2495: pointer.struct.asn1_string_st */
            	2500, 0,
            0, 24, 1, /* 2500: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 2505: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2510: pointer.struct.stack_st_X509_EXTENSION */
            	2515, 0,
            0, 32, 2, /* 2515: struct.stack_st_fake_X509_EXTENSION */
            	2522, 8,
            	144, 24,
            8884099, 8, 2, /* 2522: pointer_to_array_of_pointers_to_stack */
            	2529, 0,
            	141, 20,
            0, 8, 1, /* 2529: pointer.X509_EXTENSION */
            	1666, 0,
            1, 8, 1, /* 2534: pointer.struct.stack_st_GENERAL_NAME */
            	2539, 0,
            0, 32, 2, /* 2539: struct.stack_st_fake_GENERAL_NAME */
            	2546, 8,
            	144, 24,
            8884099, 8, 2, /* 2546: pointer_to_array_of_pointers_to_stack */
            	2553, 0,
            	141, 20,
            0, 8, 1, /* 2553: pointer.GENERAL_NAME */
            	1804, 0,
            1, 8, 1, /* 2558: pointer.struct.ISSUING_DIST_POINT_st */
            	2563, 0,
            0, 0, 0, /* 2563: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2566: pointer.struct.stack_st_GENERAL_NAMES */
            	2571, 0,
            0, 32, 2, /* 2571: struct.stack_st_fake_GENERAL_NAMES */
            	2578, 8,
            	144, 24,
            8884099, 8, 2, /* 2578: pointer_to_array_of_pointers_to_stack */
            	2585, 0,
            	141, 20,
            0, 8, 1, /* 2585: pointer.GENERAL_NAMES */
            	2590, 0,
            0, 0, 1, /* 2590: GENERAL_NAMES */
            	2595, 0,
            0, 32, 1, /* 2595: struct.stack_st_GENERAL_NAME */
            	2600, 0,
            0, 32, 2, /* 2600: struct.stack_st */
            	1087, 8,
            	144, 24,
            1, 8, 1, /* 2607: pointer.struct.x509_crl_method_st */
            	2612, 0,
            0, 0, 0, /* 2612: struct.x509_crl_method_st */
            1, 8, 1, /* 2615: pointer.struct.X509_VERIFY_PARAM_st */
            	2620, 0,
            0, 56, 2, /* 2620: struct.X509_VERIFY_PARAM_st */
            	62, 0,
            	2182, 48,
            8884097, 8, 0, /* 2627: pointer.func */
            8884097, 8, 0, /* 2630: pointer.func */
            1, 8, 1, /* 2633: pointer.struct.stack_st_X509_LOOKUP */
            	2638, 0,
            0, 32, 2, /* 2638: struct.stack_st_fake_X509_LOOKUP */
            	2645, 8,
            	144, 24,
            8884099, 8, 2, /* 2645: pointer_to_array_of_pointers_to_stack */
            	2652, 0,
            	141, 20,
            0, 8, 1, /* 2652: pointer.X509_LOOKUP */
            	459, 0,
            1, 8, 1, /* 2657: pointer.struct.ssl3_buf_freelist_st */
            	2662, 0,
            0, 24, 1, /* 2662: struct.ssl3_buf_freelist_st */
            	258, 16,
            1, 8, 1, /* 2667: pointer.struct.stack_st_X509_EXTENSION */
            	2672, 0,
            0, 32, 2, /* 2672: struct.stack_st_fake_X509_EXTENSION */
            	2679, 8,
            	144, 24,
            8884099, 8, 2, /* 2679: pointer_to_array_of_pointers_to_stack */
            	2686, 0,
            	141, 20,
            0, 8, 1, /* 2686: pointer.X509_EXTENSION */
            	1666, 0,
            0, 168, 17, /* 2691: struct.rsa_st */
            	2728, 16,
            	2783, 24,
            	235, 32,
            	235, 40,
            	235, 48,
            	235, 56,
            	235, 64,
            	235, 72,
            	235, 80,
            	235, 88,
            	2791, 96,
            	2813, 120,
            	2813, 128,
            	2813, 136,
            	62, 144,
            	2827, 152,
            	2827, 160,
            1, 8, 1, /* 2728: pointer.struct.rsa_meth_st */
            	2733, 0,
            0, 112, 13, /* 2733: struct.rsa_meth_st */
            	5, 0,
            	2762, 8,
            	2762, 16,
            	2762, 24,
            	2762, 32,
            	2765, 40,
            	2768, 48,
            	2771, 56,
            	2771, 64,
            	62, 80,
            	2774, 88,
            	2777, 96,
            	2780, 104,
            8884097, 8, 0, /* 2762: pointer.func */
            8884097, 8, 0, /* 2765: pointer.func */
            8884097, 8, 0, /* 2768: pointer.func */
            8884097, 8, 0, /* 2771: pointer.func */
            8884097, 8, 0, /* 2774: pointer.func */
            8884097, 8, 0, /* 2777: pointer.func */
            8884097, 8, 0, /* 2780: pointer.func */
            1, 8, 1, /* 2783: pointer.struct.engine_st */
            	2788, 0,
            0, 0, 0, /* 2788: struct.engine_st */
            0, 16, 1, /* 2791: struct.crypto_ex_data_st */
            	2796, 0,
            1, 8, 1, /* 2796: pointer.struct.stack_st_void */
            	2801, 0,
            0, 32, 1, /* 2801: struct.stack_st_void */
            	2806, 0,
            0, 32, 2, /* 2806: struct.stack_st */
            	1087, 8,
            	144, 24,
            1, 8, 1, /* 2813: pointer.struct.bn_mont_ctx_st */
            	2818, 0,
            0, 96, 3, /* 2818: struct.bn_mont_ctx_st */
            	240, 8,
            	240, 32,
            	240, 56,
            1, 8, 1, /* 2827: pointer.struct.bn_blinding_st */
            	2832, 0,
            0, 0, 0, /* 2832: struct.bn_blinding_st */
            1, 8, 1, /* 2835: pointer.struct.asn1_string_st */
            	2840, 0,
            0, 24, 1, /* 2840: struct.asn1_string_st */
            	44, 8,
            8884097, 8, 0, /* 2845: pointer.func */
            8884097, 8, 0, /* 2848: pointer.func */
            8884097, 8, 0, /* 2851: pointer.func */
            0, 888, 7, /* 2854: struct.dtls1_state_st */
            	2871, 576,
            	2871, 592,
            	2876, 608,
            	2876, 616,
            	2871, 624,
            	2884, 648,
            	2884, 736,
            0, 16, 1, /* 2871: struct.record_pqueue_st */
            	2876, 8,
            1, 8, 1, /* 2876: pointer.struct._pqueue */
            	2881, 0,
            0, 0, 0, /* 2881: struct._pqueue */
            0, 88, 1, /* 2884: struct.hm_header_st */
            	2889, 48,
            0, 40, 4, /* 2889: struct.dtls1_retransmit_state */
            	2900, 0,
            	2953, 8,
            	3024, 16,
            	3067, 24,
            1, 8, 1, /* 2900: pointer.struct.evp_cipher_ctx_st */
            	2905, 0,
            0, 168, 4, /* 2905: struct.evp_cipher_ctx_st */
            	2916, 0,
            	2783, 8,
            	26, 96,
            	26, 120,
            1, 8, 1, /* 2916: pointer.struct.evp_cipher_st */
            	2921, 0,
            0, 88, 7, /* 2921: struct.evp_cipher_st */
            	2938, 24,
            	2941, 32,
            	2944, 40,
            	2947, 56,
            	2947, 64,
            	2950, 72,
            	26, 80,
            8884097, 8, 0, /* 2938: pointer.func */
            8884097, 8, 0, /* 2941: pointer.func */
            8884097, 8, 0, /* 2944: pointer.func */
            8884097, 8, 0, /* 2947: pointer.func */
            8884097, 8, 0, /* 2950: pointer.func */
            1, 8, 1, /* 2953: pointer.struct.env_md_ctx_st */
            	2958, 0,
            0, 48, 5, /* 2958: struct.env_md_ctx_st */
            	2971, 0,
            	2783, 8,
            	26, 24,
            	3016, 32,
            	2998, 40,
            1, 8, 1, /* 2971: pointer.struct.env_md_st */
            	2976, 0,
            0, 120, 8, /* 2976: struct.env_md_st */
            	2995, 24,
            	2998, 32,
            	3001, 40,
            	3004, 48,
            	2995, 56,
            	3007, 64,
            	3010, 72,
            	3013, 112,
            8884097, 8, 0, /* 2995: pointer.func */
            8884097, 8, 0, /* 2998: pointer.func */
            8884097, 8, 0, /* 3001: pointer.func */
            8884097, 8, 0, /* 3004: pointer.func */
            8884097, 8, 0, /* 3007: pointer.func */
            8884097, 8, 0, /* 3010: pointer.func */
            8884097, 8, 0, /* 3013: pointer.func */
            1, 8, 1, /* 3016: pointer.struct.evp_pkey_ctx_st */
            	3021, 0,
            0, 0, 0, /* 3021: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 3024: pointer.struct.comp_ctx_st */
            	3029, 0,
            0, 56, 2, /* 3029: struct.comp_ctx_st */
            	3036, 0,
            	2791, 40,
            1, 8, 1, /* 3036: pointer.struct.comp_method_st */
            	3041, 0,
            0, 64, 7, /* 3041: struct.comp_method_st */
            	5, 8,
            	3058, 16,
            	3061, 24,
            	3064, 32,
            	3064, 40,
            	292, 48,
            	292, 56,
            8884097, 8, 0, /* 3058: pointer.func */
            8884097, 8, 0, /* 3061: pointer.func */
            8884097, 8, 0, /* 3064: pointer.func */
            1, 8, 1, /* 3067: pointer.struct.ssl_session_st */
            	3072, 0,
            0, 352, 14, /* 3072: struct.ssl_session_st */
            	62, 144,
            	62, 152,
            	3103, 168,
            	4005, 176,
            	4705, 224,
            	4715, 240,
            	2791, 248,
            	4749, 264,
            	4749, 272,
            	62, 280,
            	44, 296,
            	44, 312,
            	44, 320,
            	62, 344,
            1, 8, 1, /* 3103: pointer.struct.sess_cert_st */
            	3108, 0,
            0, 248, 5, /* 3108: struct.sess_cert_st */
            	3121, 0,
            	3991, 16,
            	4690, 216,
            	4695, 224,
            	4700, 232,
            1, 8, 1, /* 3121: pointer.struct.stack_st_X509 */
            	3126, 0,
            0, 32, 2, /* 3126: struct.stack_st_fake_X509 */
            	3133, 8,
            	144, 24,
            8884099, 8, 2, /* 3133: pointer_to_array_of_pointers_to_stack */
            	3140, 0,
            	141, 20,
            0, 8, 1, /* 3140: pointer.X509 */
            	3145, 0,
            0, 0, 1, /* 3145: X509 */
            	3150, 0,
            0, 184, 12, /* 3150: struct.x509_st */
            	3177, 0,
            	3217, 8,
            	3306, 16,
            	62, 32,
            	3605, 40,
            	3311, 104,
            	3853, 112,
            	3861, 120,
            	3869, 128,
            	3893, 136,
            	3917, 144,
            	3925, 176,
            1, 8, 1, /* 3177: pointer.struct.x509_cinf_st */
            	3182, 0,
            0, 104, 11, /* 3182: struct.x509_cinf_st */
            	3207, 0,
            	3207, 8,
            	3217, 16,
            	3374, 24,
            	3422, 32,
            	3374, 40,
            	3439, 48,
            	3306, 56,
            	3306, 64,
            	3824, 72,
            	3848, 80,
            1, 8, 1, /* 3207: pointer.struct.asn1_string_st */
            	3212, 0,
            0, 24, 1, /* 3212: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 3217: pointer.struct.X509_algor_st */
            	3222, 0,
            0, 16, 2, /* 3222: struct.X509_algor_st */
            	3229, 0,
            	3243, 8,
            1, 8, 1, /* 3229: pointer.struct.asn1_object_st */
            	3234, 0,
            0, 40, 3, /* 3234: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 3243: pointer.struct.asn1_type_st */
            	3248, 0,
            0, 16, 1, /* 3248: struct.asn1_type_st */
            	3253, 8,
            0, 8, 20, /* 3253: union.unknown */
            	62, 0,
            	3296, 0,
            	3229, 0,
            	3207, 0,
            	3301, 0,
            	3306, 0,
            	3311, 0,
            	3316, 0,
            	3321, 0,
            	3326, 0,
            	3331, 0,
            	3336, 0,
            	3341, 0,
            	3346, 0,
            	3351, 0,
            	3356, 0,
            	3361, 0,
            	3296, 0,
            	3296, 0,
            	3366, 0,
            1, 8, 1, /* 3296: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3301: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3306: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3311: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3316: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3321: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3326: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3331: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3336: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3341: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3346: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3351: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3356: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3361: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3366: pointer.struct.ASN1_VALUE_st */
            	3371, 0,
            0, 0, 0, /* 3371: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3374: pointer.struct.X509_name_st */
            	3379, 0,
            0, 40, 3, /* 3379: struct.X509_name_st */
            	3388, 0,
            	3412, 16,
            	44, 24,
            1, 8, 1, /* 3388: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3393, 0,
            0, 32, 2, /* 3393: struct.stack_st_fake_X509_NAME_ENTRY */
            	3400, 8,
            	144, 24,
            8884099, 8, 2, /* 3400: pointer_to_array_of_pointers_to_stack */
            	3407, 0,
            	141, 20,
            0, 8, 1, /* 3407: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 3412: pointer.struct.buf_mem_st */
            	3417, 0,
            0, 24, 1, /* 3417: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 3422: pointer.struct.X509_val_st */
            	3427, 0,
            0, 16, 2, /* 3427: struct.X509_val_st */
            	3434, 0,
            	3434, 8,
            1, 8, 1, /* 3434: pointer.struct.asn1_string_st */
            	3212, 0,
            1, 8, 1, /* 3439: pointer.struct.X509_pubkey_st */
            	3444, 0,
            0, 24, 3, /* 3444: struct.X509_pubkey_st */
            	3217, 0,
            	3306, 8,
            	3453, 16,
            1, 8, 1, /* 3453: pointer.struct.evp_pkey_st */
            	3458, 0,
            0, 56, 4, /* 3458: struct.evp_pkey_st */
            	3469, 16,
            	3477, 24,
            	3485, 32,
            	3800, 48,
            1, 8, 1, /* 3469: pointer.struct.evp_pkey_asn1_method_st */
            	3474, 0,
            0, 0, 0, /* 3474: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3477: pointer.struct.engine_st */
            	3482, 0,
            0, 0, 0, /* 3482: struct.engine_st */
            0, 8, 5, /* 3485: union.unknown */
            	62, 0,
            	3498, 0,
            	3649, 0,
            	3730, 0,
            	3792, 0,
            1, 8, 1, /* 3498: pointer.struct.rsa_st */
            	3503, 0,
            0, 168, 17, /* 3503: struct.rsa_st */
            	3540, 16,
            	3477, 24,
            	3595, 32,
            	3595, 40,
            	3595, 48,
            	3595, 56,
            	3595, 64,
            	3595, 72,
            	3595, 80,
            	3595, 88,
            	3605, 96,
            	3627, 120,
            	3627, 128,
            	3627, 136,
            	62, 144,
            	3641, 152,
            	3641, 160,
            1, 8, 1, /* 3540: pointer.struct.rsa_meth_st */
            	3545, 0,
            0, 112, 13, /* 3545: struct.rsa_meth_st */
            	5, 0,
            	3574, 8,
            	3574, 16,
            	3574, 24,
            	3574, 32,
            	3577, 40,
            	3580, 48,
            	3583, 56,
            	3583, 64,
            	62, 80,
            	3586, 88,
            	3589, 96,
            	3592, 104,
            8884097, 8, 0, /* 3574: pointer.func */
            8884097, 8, 0, /* 3577: pointer.func */
            8884097, 8, 0, /* 3580: pointer.func */
            8884097, 8, 0, /* 3583: pointer.func */
            8884097, 8, 0, /* 3586: pointer.func */
            8884097, 8, 0, /* 3589: pointer.func */
            8884097, 8, 0, /* 3592: pointer.func */
            1, 8, 1, /* 3595: pointer.struct.bignum_st */
            	3600, 0,
            0, 24, 1, /* 3600: struct.bignum_st */
            	245, 0,
            0, 16, 1, /* 3605: struct.crypto_ex_data_st */
            	3610, 0,
            1, 8, 1, /* 3610: pointer.struct.stack_st_void */
            	3615, 0,
            0, 32, 1, /* 3615: struct.stack_st_void */
            	3620, 0,
            0, 32, 2, /* 3620: struct.stack_st */
            	1087, 8,
            	144, 24,
            1, 8, 1, /* 3627: pointer.struct.bn_mont_ctx_st */
            	3632, 0,
            0, 96, 3, /* 3632: struct.bn_mont_ctx_st */
            	3600, 8,
            	3600, 32,
            	3600, 56,
            1, 8, 1, /* 3641: pointer.struct.bn_blinding_st */
            	3646, 0,
            0, 0, 0, /* 3646: struct.bn_blinding_st */
            1, 8, 1, /* 3649: pointer.struct.dsa_st */
            	3654, 0,
            0, 136, 11, /* 3654: struct.dsa_st */
            	3595, 24,
            	3595, 32,
            	3595, 40,
            	3595, 48,
            	3595, 56,
            	3595, 64,
            	3595, 72,
            	3627, 88,
            	3605, 104,
            	3679, 120,
            	3477, 128,
            1, 8, 1, /* 3679: pointer.struct.dsa_method */
            	3684, 0,
            0, 96, 11, /* 3684: struct.dsa_method */
            	5, 0,
            	3709, 8,
            	3712, 16,
            	3715, 24,
            	3718, 32,
            	3721, 40,
            	3724, 48,
            	3724, 56,
            	62, 72,
            	3727, 80,
            	3724, 88,
            8884097, 8, 0, /* 3709: pointer.func */
            8884097, 8, 0, /* 3712: pointer.func */
            8884097, 8, 0, /* 3715: pointer.func */
            8884097, 8, 0, /* 3718: pointer.func */
            8884097, 8, 0, /* 3721: pointer.func */
            8884097, 8, 0, /* 3724: pointer.func */
            8884097, 8, 0, /* 3727: pointer.func */
            1, 8, 1, /* 3730: pointer.struct.dh_st */
            	3735, 0,
            0, 144, 12, /* 3735: struct.dh_st */
            	3595, 8,
            	3595, 16,
            	3595, 32,
            	3595, 40,
            	3627, 56,
            	3595, 64,
            	3595, 72,
            	44, 80,
            	3595, 96,
            	3605, 112,
            	3762, 128,
            	3477, 136,
            1, 8, 1, /* 3762: pointer.struct.dh_method */
            	3767, 0,
            0, 72, 8, /* 3767: struct.dh_method */
            	5, 0,
            	2848, 8,
            	3786, 16,
            	2845, 24,
            	2848, 32,
            	2848, 40,
            	62, 56,
            	3789, 64,
            8884097, 8, 0, /* 3786: pointer.func */
            8884097, 8, 0, /* 3789: pointer.func */
            1, 8, 1, /* 3792: pointer.struct.ec_key_st */
            	3797, 0,
            0, 0, 0, /* 3797: struct.ec_key_st */
            1, 8, 1, /* 3800: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3805, 0,
            0, 32, 2, /* 3805: struct.stack_st_fake_X509_ATTRIBUTE */
            	3812, 8,
            	144, 24,
            8884099, 8, 2, /* 3812: pointer_to_array_of_pointers_to_stack */
            	3819, 0,
            	141, 20,
            0, 8, 1, /* 3819: pointer.X509_ATTRIBUTE */
            	1295, 0,
            1, 8, 1, /* 3824: pointer.struct.stack_st_X509_EXTENSION */
            	3829, 0,
            0, 32, 2, /* 3829: struct.stack_st_fake_X509_EXTENSION */
            	3836, 8,
            	144, 24,
            8884099, 8, 2, /* 3836: pointer_to_array_of_pointers_to_stack */
            	3843, 0,
            	141, 20,
            0, 8, 1, /* 3843: pointer.X509_EXTENSION */
            	1666, 0,
            0, 24, 1, /* 3848: struct.ASN1_ENCODING_st */
            	44, 0,
            1, 8, 1, /* 3853: pointer.struct.AUTHORITY_KEYID_st */
            	3858, 0,
            0, 0, 0, /* 3858: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3861: pointer.struct.X509_POLICY_CACHE_st */
            	3866, 0,
            0, 0, 0, /* 3866: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3869: pointer.struct.stack_st_DIST_POINT */
            	3874, 0,
            0, 32, 2, /* 3874: struct.stack_st_fake_DIST_POINT */
            	3881, 8,
            	144, 24,
            8884099, 8, 2, /* 3881: pointer_to_array_of_pointers_to_stack */
            	3888, 0,
            	141, 20,
            0, 8, 1, /* 3888: pointer.DIST_POINT */
            	1747, 0,
            1, 8, 1, /* 3893: pointer.struct.stack_st_GENERAL_NAME */
            	3898, 0,
            0, 32, 2, /* 3898: struct.stack_st_fake_GENERAL_NAME */
            	3905, 8,
            	144, 24,
            8884099, 8, 2, /* 3905: pointer_to_array_of_pointers_to_stack */
            	3912, 0,
            	141, 20,
            0, 8, 1, /* 3912: pointer.GENERAL_NAME */
            	1804, 0,
            1, 8, 1, /* 3917: pointer.struct.NAME_CONSTRAINTS_st */
            	3922, 0,
            0, 0, 0, /* 3922: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3925: pointer.struct.x509_cert_aux_st */
            	3930, 0,
            0, 40, 5, /* 3930: struct.x509_cert_aux_st */
            	3943, 0,
            	3943, 8,
            	3361, 16,
            	3311, 24,
            	3967, 32,
            1, 8, 1, /* 3943: pointer.struct.stack_st_ASN1_OBJECT */
            	3948, 0,
            0, 32, 2, /* 3948: struct.stack_st_fake_ASN1_OBJECT */
            	3955, 8,
            	144, 24,
            8884099, 8, 2, /* 3955: pointer_to_array_of_pointers_to_stack */
            	3962, 0,
            	141, 20,
            0, 8, 1, /* 3962: pointer.ASN1_OBJECT */
            	2206, 0,
            1, 8, 1, /* 3967: pointer.struct.stack_st_X509_ALGOR */
            	3972, 0,
            0, 32, 2, /* 3972: struct.stack_st_fake_X509_ALGOR */
            	3979, 8,
            	144, 24,
            8884099, 8, 2, /* 3979: pointer_to_array_of_pointers_to_stack */
            	3986, 0,
            	141, 20,
            0, 8, 1, /* 3986: pointer.X509_ALGOR */
            	2244, 0,
            1, 8, 1, /* 3991: pointer.struct.cert_pkey_st */
            	3996, 0,
            0, 24, 3, /* 3996: struct.cert_pkey_st */
            	4005, 0,
            	4303, 8,
            	2971, 16,
            1, 8, 1, /* 4005: pointer.struct.x509_st */
            	4010, 0,
            0, 184, 12, /* 4010: struct.x509_st */
            	4037, 0,
            	4072, 8,
            	4161, 16,
            	62, 32,
            	2791, 40,
            	4166, 104,
            	4552, 112,
            	4560, 120,
            	4568, 128,
            	4592, 136,
            	4616, 144,
            	4624, 176,
            1, 8, 1, /* 4037: pointer.struct.x509_cinf_st */
            	4042, 0,
            0, 104, 11, /* 4042: struct.x509_cinf_st */
            	4067, 0,
            	4067, 8,
            	4072, 16,
            	4229, 24,
            	4277, 32,
            	4229, 40,
            	4289, 48,
            	4161, 56,
            	4161, 64,
            	4523, 72,
            	4547, 80,
            1, 8, 1, /* 4067: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4072: pointer.struct.X509_algor_st */
            	4077, 0,
            0, 16, 2, /* 4077: struct.X509_algor_st */
            	4084, 0,
            	4098, 8,
            1, 8, 1, /* 4084: pointer.struct.asn1_object_st */
            	4089, 0,
            0, 40, 3, /* 4089: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 4098: pointer.struct.asn1_type_st */
            	4103, 0,
            0, 16, 1, /* 4103: struct.asn1_type_st */
            	4108, 8,
            0, 8, 20, /* 4108: union.unknown */
            	62, 0,
            	4151, 0,
            	4084, 0,
            	4067, 0,
            	4156, 0,
            	4161, 0,
            	4166, 0,
            	4171, 0,
            	4176, 0,
            	4181, 0,
            	4186, 0,
            	4191, 0,
            	4196, 0,
            	4201, 0,
            	4206, 0,
            	4211, 0,
            	4216, 0,
            	4151, 0,
            	4151, 0,
            	4221, 0,
            1, 8, 1, /* 4151: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4156: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4161: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4166: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4171: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4176: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4181: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4186: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4191: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4196: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4201: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4206: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4211: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4216: pointer.struct.asn1_string_st */
            	2840, 0,
            1, 8, 1, /* 4221: pointer.struct.ASN1_VALUE_st */
            	4226, 0,
            0, 0, 0, /* 4226: struct.ASN1_VALUE_st */
            1, 8, 1, /* 4229: pointer.struct.X509_name_st */
            	4234, 0,
            0, 40, 3, /* 4234: struct.X509_name_st */
            	4243, 0,
            	4267, 16,
            	44, 24,
            1, 8, 1, /* 4243: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4248, 0,
            0, 32, 2, /* 4248: struct.stack_st_fake_X509_NAME_ENTRY */
            	4255, 8,
            	144, 24,
            8884099, 8, 2, /* 4255: pointer_to_array_of_pointers_to_stack */
            	4262, 0,
            	141, 20,
            0, 8, 1, /* 4262: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 4267: pointer.struct.buf_mem_st */
            	4272, 0,
            0, 24, 1, /* 4272: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 4277: pointer.struct.X509_val_st */
            	4282, 0,
            0, 16, 2, /* 4282: struct.X509_val_st */
            	2835, 0,
            	2835, 8,
            1, 8, 1, /* 4289: pointer.struct.X509_pubkey_st */
            	4294, 0,
            0, 24, 3, /* 4294: struct.X509_pubkey_st */
            	4072, 0,
            	4161, 8,
            	4303, 16,
            1, 8, 1, /* 4303: pointer.struct.evp_pkey_st */
            	4308, 0,
            0, 56, 4, /* 4308: struct.evp_pkey_st */
            	4319, 16,
            	2783, 24,
            	4327, 32,
            	4499, 48,
            1, 8, 1, /* 4319: pointer.struct.evp_pkey_asn1_method_st */
            	4324, 0,
            0, 0, 0, /* 4324: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 4327: union.unknown */
            	62, 0,
            	4340, 0,
            	4345, 0,
            	4426, 0,
            	4491, 0,
            1, 8, 1, /* 4340: pointer.struct.rsa_st */
            	2691, 0,
            1, 8, 1, /* 4345: pointer.struct.dsa_st */
            	4350, 0,
            0, 136, 11, /* 4350: struct.dsa_st */
            	235, 24,
            	235, 32,
            	235, 40,
            	235, 48,
            	235, 56,
            	235, 64,
            	235, 72,
            	2813, 88,
            	2791, 104,
            	4375, 120,
            	2783, 128,
            1, 8, 1, /* 4375: pointer.struct.dsa_method */
            	4380, 0,
            0, 96, 11, /* 4380: struct.dsa_method */
            	5, 0,
            	4405, 8,
            	4408, 16,
            	4411, 24,
            	4414, 32,
            	4417, 40,
            	4420, 48,
            	4420, 56,
            	62, 72,
            	4423, 80,
            	4420, 88,
            8884097, 8, 0, /* 4405: pointer.func */
            8884097, 8, 0, /* 4408: pointer.func */
            8884097, 8, 0, /* 4411: pointer.func */
            8884097, 8, 0, /* 4414: pointer.func */
            8884097, 8, 0, /* 4417: pointer.func */
            8884097, 8, 0, /* 4420: pointer.func */
            8884097, 8, 0, /* 4423: pointer.func */
            1, 8, 1, /* 4426: pointer.struct.dh_st */
            	4431, 0,
            0, 144, 12, /* 4431: struct.dh_st */
            	235, 8,
            	235, 16,
            	235, 32,
            	235, 40,
            	2813, 56,
            	235, 64,
            	235, 72,
            	44, 80,
            	235, 96,
            	2791, 112,
            	4458, 128,
            	2783, 136,
            1, 8, 1, /* 4458: pointer.struct.dh_method */
            	4463, 0,
            0, 72, 8, /* 4463: struct.dh_method */
            	5, 0,
            	4482, 8,
            	2851, 16,
            	4485, 24,
            	4482, 32,
            	4482, 40,
            	62, 56,
            	4488, 64,
            8884097, 8, 0, /* 4482: pointer.func */
            8884097, 8, 0, /* 4485: pointer.func */
            8884097, 8, 0, /* 4488: pointer.func */
            1, 8, 1, /* 4491: pointer.struct.ec_key_st */
            	4496, 0,
            0, 0, 0, /* 4496: struct.ec_key_st */
            1, 8, 1, /* 4499: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4504, 0,
            0, 32, 2, /* 4504: struct.stack_st_fake_X509_ATTRIBUTE */
            	4511, 8,
            	144, 24,
            8884099, 8, 2, /* 4511: pointer_to_array_of_pointers_to_stack */
            	4518, 0,
            	141, 20,
            0, 8, 1, /* 4518: pointer.X509_ATTRIBUTE */
            	1295, 0,
            1, 8, 1, /* 4523: pointer.struct.stack_st_X509_EXTENSION */
            	4528, 0,
            0, 32, 2, /* 4528: struct.stack_st_fake_X509_EXTENSION */
            	4535, 8,
            	144, 24,
            8884099, 8, 2, /* 4535: pointer_to_array_of_pointers_to_stack */
            	4542, 0,
            	141, 20,
            0, 8, 1, /* 4542: pointer.X509_EXTENSION */
            	1666, 0,
            0, 24, 1, /* 4547: struct.ASN1_ENCODING_st */
            	44, 0,
            1, 8, 1, /* 4552: pointer.struct.AUTHORITY_KEYID_st */
            	4557, 0,
            0, 0, 0, /* 4557: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4560: pointer.struct.X509_POLICY_CACHE_st */
            	4565, 0,
            0, 0, 0, /* 4565: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4568: pointer.struct.stack_st_DIST_POINT */
            	4573, 0,
            0, 32, 2, /* 4573: struct.stack_st_fake_DIST_POINT */
            	4580, 8,
            	144, 24,
            8884099, 8, 2, /* 4580: pointer_to_array_of_pointers_to_stack */
            	4587, 0,
            	141, 20,
            0, 8, 1, /* 4587: pointer.DIST_POINT */
            	1747, 0,
            1, 8, 1, /* 4592: pointer.struct.stack_st_GENERAL_NAME */
            	4597, 0,
            0, 32, 2, /* 4597: struct.stack_st_fake_GENERAL_NAME */
            	4604, 8,
            	144, 24,
            8884099, 8, 2, /* 4604: pointer_to_array_of_pointers_to_stack */
            	4611, 0,
            	141, 20,
            0, 8, 1, /* 4611: pointer.GENERAL_NAME */
            	1804, 0,
            1, 8, 1, /* 4616: pointer.struct.NAME_CONSTRAINTS_st */
            	4621, 0,
            0, 0, 0, /* 4621: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4624: pointer.struct.x509_cert_aux_st */
            	4629, 0,
            0, 40, 5, /* 4629: struct.x509_cert_aux_st */
            	4642, 0,
            	4642, 8,
            	4216, 16,
            	4166, 24,
            	4666, 32,
            1, 8, 1, /* 4642: pointer.struct.stack_st_ASN1_OBJECT */
            	4647, 0,
            0, 32, 2, /* 4647: struct.stack_st_fake_ASN1_OBJECT */
            	4654, 8,
            	144, 24,
            8884099, 8, 2, /* 4654: pointer_to_array_of_pointers_to_stack */
            	4661, 0,
            	141, 20,
            0, 8, 1, /* 4661: pointer.ASN1_OBJECT */
            	2206, 0,
            1, 8, 1, /* 4666: pointer.struct.stack_st_X509_ALGOR */
            	4671, 0,
            0, 32, 2, /* 4671: struct.stack_st_fake_X509_ALGOR */
            	4678, 8,
            	144, 24,
            8884099, 8, 2, /* 4678: pointer_to_array_of_pointers_to_stack */
            	4685, 0,
            	141, 20,
            0, 8, 1, /* 4685: pointer.X509_ALGOR */
            	2244, 0,
            1, 8, 1, /* 4690: pointer.struct.rsa_st */
            	2691, 0,
            1, 8, 1, /* 4695: pointer.struct.dh_st */
            	4431, 0,
            1, 8, 1, /* 4700: pointer.struct.ec_key_st */
            	4496, 0,
            1, 8, 1, /* 4705: pointer.struct.ssl_cipher_st */
            	4710, 0,
            0, 88, 1, /* 4710: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4715: pointer.struct.stack_st_SSL_CIPHER */
            	4720, 0,
            0, 32, 2, /* 4720: struct.stack_st_fake_SSL_CIPHER */
            	4727, 8,
            	144, 24,
            8884099, 8, 2, /* 4727: pointer_to_array_of_pointers_to_stack */
            	4734, 0,
            	141, 20,
            0, 8, 1, /* 4734: pointer.SSL_CIPHER */
            	4739, 0,
            0, 0, 1, /* 4739: SSL_CIPHER */
            	4744, 0,
            0, 88, 1, /* 4744: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4749: pointer.struct.ssl_session_st */
            	3072, 0,
            0, 24, 1, /* 4754: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 4759: pointer.struct.ssl3_enc_method */
            	4764, 0,
            0, 112, 11, /* 4764: struct.ssl3_enc_method */
            	4789, 0,
            	4792, 8,
            	4795, 16,
            	4798, 24,
            	4789, 32,
            	4801, 40,
            	4804, 56,
            	5, 64,
            	5, 80,
            	4807, 96,
            	4810, 104,
            8884097, 8, 0, /* 4789: pointer.func */
            8884097, 8, 0, /* 4792: pointer.func */
            8884097, 8, 0, /* 4795: pointer.func */
            8884097, 8, 0, /* 4798: pointer.func */
            8884097, 8, 0, /* 4801: pointer.func */
            8884097, 8, 0, /* 4804: pointer.func */
            8884097, 8, 0, /* 4807: pointer.func */
            8884097, 8, 0, /* 4810: pointer.func */
            8884097, 8, 0, /* 4813: pointer.func */
            8884097, 8, 0, /* 4816: pointer.func */
            0, 56, 2, /* 4819: struct.X509_VERIFY_PARAM_st */
            	62, 0,
            	4642, 48,
            1, 8, 1, /* 4826: pointer.struct.stack_st_X509_OBJECT */
            	4831, 0,
            0, 32, 2, /* 4831: struct.stack_st_fake_X509_OBJECT */
            	4838, 8,
            	144, 24,
            8884099, 8, 2, /* 4838: pointer_to_array_of_pointers_to_stack */
            	4845, 0,
            	141, 20,
            0, 8, 1, /* 4845: pointer.X509_OBJECT */
            	584, 0,
            8884097, 8, 0, /* 4850: pointer.func */
            1, 8, 1, /* 4853: pointer.struct.dtls1_state_st */
            	2854, 0,
            8884097, 8, 0, /* 4858: pointer.func */
            0, 344, 9, /* 4861: struct.ssl2_state_st */
            	126, 24,
            	44, 56,
            	44, 64,
            	44, 72,
            	44, 104,
            	44, 112,
            	44, 120,
            	44, 128,
            	44, 136,
            0, 40, 3, /* 4882: struct.X509_name_st */
            	4891, 0,
            	4915, 16,
            	44, 24,
            1, 8, 1, /* 4891: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4896, 0,
            0, 32, 2, /* 4896: struct.stack_st_fake_X509_NAME_ENTRY */
            	4903, 8,
            	144, 24,
            8884099, 8, 2, /* 4903: pointer_to_array_of_pointers_to_stack */
            	4910, 0,
            	141, 20,
            0, 8, 1, /* 4910: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 4915: pointer.struct.buf_mem_st */
            	4754, 0,
            8884097, 8, 0, /* 4920: pointer.func */
            8884097, 8, 0, /* 4923: pointer.func */
            8884097, 8, 0, /* 4926: pointer.func */
            1, 8, 1, /* 4929: pointer.pointer.struct.env_md_ctx_st */
            	2953, 0,
            8884097, 8, 0, /* 4934: pointer.func */
            8884097, 8, 0, /* 4937: pointer.func */
            8884097, 8, 0, /* 4940: pointer.func */
            8884097, 8, 0, /* 4943: pointer.func */
            8884097, 8, 0, /* 4946: pointer.func */
            0, 808, 51, /* 4949: struct.ssl_st */
            	5054, 8,
            	5151, 16,
            	5151, 24,
            	5151, 32,
            	4795, 48,
            	4267, 80,
            	26, 88,
            	44, 104,
            	5216, 120,
            	5221, 128,
            	4853, 136,
            	5323, 152,
            	26, 160,
            	5326, 176,
            	4715, 184,
            	4715, 192,
            	2900, 208,
            	2953, 216,
            	3024, 224,
            	2900, 232,
            	2953, 240,
            	3024, 248,
            	5331, 256,
            	3067, 304,
            	5362, 312,
            	5365, 328,
            	4813, 336,
            	5368, 352,
            	5371, 360,
            	5374, 368,
            	2791, 392,
            	5282, 408,
            	152, 464,
            	26, 472,
            	62, 480,
            	5540, 504,
            	2667, 512,
            	44, 520,
            	44, 544,
            	44, 560,
            	26, 568,
            	29, 584,
            	18, 592,
            	26, 600,
            	15, 608,
            	26, 616,
            	5374, 624,
            	44, 632,
            	160, 648,
            	10, 656,
            	198, 680,
            1, 8, 1, /* 5054: pointer.struct.ssl_method_st */
            	5059, 0,
            0, 232, 28, /* 5059: struct.ssl_method_st */
            	4795, 8,
            	4920, 16,
            	4920, 24,
            	4795, 32,
            	4795, 40,
            	5118, 48,
            	5118, 56,
            	5121, 64,
            	4795, 72,
            	4795, 80,
            	4795, 88,
            	5124, 96,
            	5127, 104,
            	5130, 112,
            	4795, 120,
            	5133, 128,
            	4943, 136,
            	4940, 144,
            	5136, 152,
            	5139, 160,
            	5142, 168,
            	4816, 176,
            	5145, 184,
            	292, 192,
            	4759, 200,
            	5142, 208,
            	5148, 216,
            	4934, 224,
            8884097, 8, 0, /* 5118: pointer.func */
            8884097, 8, 0, /* 5121: pointer.func */
            8884097, 8, 0, /* 5124: pointer.func */
            8884097, 8, 0, /* 5127: pointer.func */
            8884097, 8, 0, /* 5130: pointer.func */
            8884097, 8, 0, /* 5133: pointer.func */
            8884097, 8, 0, /* 5136: pointer.func */
            8884097, 8, 0, /* 5139: pointer.func */
            8884097, 8, 0, /* 5142: pointer.func */
            8884097, 8, 0, /* 5145: pointer.func */
            8884097, 8, 0, /* 5148: pointer.func */
            1, 8, 1, /* 5151: pointer.struct.bio_st */
            	5156, 0,
            0, 112, 7, /* 5156: struct.bio_st */
            	5173, 0,
            	5208, 8,
            	62, 16,
            	26, 48,
            	5211, 56,
            	5211, 64,
            	2791, 96,
            1, 8, 1, /* 5173: pointer.struct.bio_method_st */
            	5178, 0,
            0, 80, 9, /* 5178: struct.bio_method_st */
            	5, 8,
            	5199, 16,
            	5202, 24,
            	4923, 32,
            	5202, 40,
            	4946, 48,
            	5205, 56,
            	5205, 64,
            	4937, 72,
            8884097, 8, 0, /* 5199: pointer.func */
            8884097, 8, 0, /* 5202: pointer.func */
            8884097, 8, 0, /* 5205: pointer.func */
            8884097, 8, 0, /* 5208: pointer.func */
            1, 8, 1, /* 5211: pointer.struct.bio_st */
            	5156, 0,
            1, 8, 1, /* 5216: pointer.struct.ssl2_state_st */
            	4861, 0,
            1, 8, 1, /* 5221: pointer.struct.ssl3_state_st */
            	5226, 0,
            0, 1200, 10, /* 5226: struct.ssl3_state_st */
            	5249, 240,
            	5249, 264,
            	5254, 288,
            	5254, 344,
            	126, 432,
            	5151, 440,
            	4929, 448,
            	26, 496,
            	26, 512,
            	5263, 528,
            0, 24, 1, /* 5249: struct.ssl3_buffer_st */
            	44, 0,
            0, 56, 3, /* 5254: struct.ssl3_record_st */
            	44, 16,
            	44, 24,
            	44, 32,
            0, 528, 8, /* 5263: struct.unknown */
            	4705, 408,
            	4695, 416,
            	4700, 424,
            	5282, 464,
            	44, 480,
            	2916, 488,
            	2971, 496,
            	5311, 512,
            1, 8, 1, /* 5282: pointer.struct.stack_st_X509_NAME */
            	5287, 0,
            0, 32, 2, /* 5287: struct.stack_st_fake_X509_NAME */
            	5294, 8,
            	144, 24,
            8884099, 8, 2, /* 5294: pointer_to_array_of_pointers_to_stack */
            	5301, 0,
            	141, 20,
            0, 8, 1, /* 5301: pointer.X509_NAME */
            	5306, 0,
            0, 0, 1, /* 5306: X509_NAME */
            	4882, 0,
            1, 8, 1, /* 5311: pointer.struct.ssl_comp_st */
            	5316, 0,
            0, 24, 2, /* 5316: struct.ssl_comp_st */
            	5, 8,
            	3036, 16,
            8884097, 8, 0, /* 5323: pointer.func */
            1, 8, 1, /* 5326: pointer.struct.X509_VERIFY_PARAM_st */
            	4819, 0,
            1, 8, 1, /* 5331: pointer.struct.cert_st */
            	5336, 0,
            0, 296, 7, /* 5336: struct.cert_st */
            	3991, 0,
            	4690, 48,
            	5353, 56,
            	4695, 64,
            	5356, 72,
            	4700, 80,
            	5359, 88,
            8884097, 8, 0, /* 5353: pointer.func */
            8884097, 8, 0, /* 5356: pointer.func */
            8884097, 8, 0, /* 5359: pointer.func */
            8884097, 8, 0, /* 5362: pointer.func */
            8884097, 8, 0, /* 5365: pointer.func */
            8884097, 8, 0, /* 5368: pointer.func */
            8884097, 8, 0, /* 5371: pointer.func */
            1, 8, 1, /* 5374: pointer.struct.ssl_ctx_st */
            	5379, 0,
            0, 736, 50, /* 5379: struct.ssl_ctx_st */
            	5054, 0,
            	4715, 8,
            	4715, 16,
            	5482, 24,
            	5523, 32,
            	4749, 48,
            	4749, 56,
            	339, 80,
            	5528, 88,
            	336, 96,
            	4926, 152,
            	26, 160,
            	4850, 168,
            	26, 176,
            	4858, 184,
            	5531, 192,
            	5534, 200,
            	2791, 208,
            	2971, 224,
            	2971, 232,
            	2971, 240,
            	3121, 248,
            	300, 256,
            	4813, 264,
            	5282, 272,
            	5331, 304,
            	5323, 320,
            	26, 328,
            	5365, 376,
            	5362, 384,
            	5326, 392,
            	2783, 408,
            	229, 416,
            	26, 424,
            	5537, 480,
            	232, 488,
            	26, 496,
            	263, 504,
            	26, 512,
            	62, 520,
            	5368, 528,
            	5371, 536,
            	2657, 552,
            	2657, 560,
            	198, 568,
            	192, 696,
            	26, 704,
            	189, 712,
            	26, 720,
            	160, 728,
            1, 8, 1, /* 5482: pointer.struct.x509_store_st */
            	5487, 0,
            0, 144, 15, /* 5487: struct.x509_store_st */
            	4826, 8,
            	2633, 16,
            	5326, 24,
            	5520, 32,
            	5365, 40,
            	394, 48,
            	391, 56,
            	5520, 64,
            	388, 72,
            	385, 80,
            	382, 88,
            	379, 96,
            	376, 104,
            	5520, 112,
            	2791, 120,
            8884097, 8, 0, /* 5520: pointer.func */
            1, 8, 1, /* 5523: pointer.struct.lhash_st */
            	364, 0,
            8884097, 8, 0, /* 5528: pointer.func */
            8884097, 8, 0, /* 5531: pointer.func */
            8884097, 8, 0, /* 5534: pointer.func */
            8884097, 8, 0, /* 5537: pointer.func */
            1, 8, 1, /* 5540: pointer.struct.stack_st_OCSP_RESPID */
            	5545, 0,
            0, 32, 2, /* 5545: struct.stack_st_fake_OCSP_RESPID */
            	5552, 8,
            	144, 24,
            8884099, 8, 2, /* 5552: pointer_to_array_of_pointers_to_stack */
            	5559, 0,
            	141, 20,
            0, 8, 1, /* 5559: pointer.OCSP_RESPID */
            	397, 0,
            0, 1, 0, /* 5564: char */
            1, 8, 1, /* 5567: pointer.struct.ssl_st */
            	4949, 0,
        },
        .arg_entity_index = { 5567, },
        .ret_entity_index = 62,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    char * *new_ret_ptr = (char * *)new_args->ret;

    char * (*orig_SSL_get_srp_username)(SSL *);
    orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
    *new_ret_ptr = (*orig_SSL_get_srp_username)(new_arg_a);

    syscall(889);

    return ret;
}

