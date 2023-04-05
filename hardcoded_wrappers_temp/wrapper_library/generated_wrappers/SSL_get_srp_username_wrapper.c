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
            0, 128, 14, /* 195: struct.srp_ctx_st */
            	26, 0,
            	226, 8,
            	229, 16,
            	232, 24,
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
            8884097, 8, 0, /* 226: pointer.func */
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
            	292, 16,
            	272, 24,
            	269, 32,
            	269, 40,
            	295, 48,
            	295, 56,
            8884097, 8, 0, /* 292: pointer.func */
            8884097, 8, 0, /* 295: pointer.func */
            0, 0, 1, /* 298: SSL_COMP */
            	303, 0,
            0, 24, 2, /* 303: struct.ssl_comp_st */
            	5, 8,
            	310, 16,
            1, 8, 1, /* 310: pointer.struct.comp_method_st */
            	275, 0,
            1, 8, 1, /* 315: pointer.struct.stack_st_SSL_COMP */
            	320, 0,
            0, 32, 2, /* 320: struct.stack_st_fake_SSL_COMP */
            	327, 8,
            	144, 24,
            8884099, 8, 2, /* 327: pointer_to_array_of_pointers_to_stack */
            	334, 0,
            	141, 20,
            0, 8, 1, /* 334: pointer.SSL_COMP */
            	298, 0,
            8884097, 8, 0, /* 339: pointer.func */
            8884097, 8, 0, /* 342: pointer.func */
            1, 8, 1, /* 345: pointer.struct.lhash_node_st */
            	350, 0,
            0, 24, 2, /* 350: struct.lhash_node_st */
            	26, 0,
            	345, 8,
            0, 176, 3, /* 357: struct.lhash_st */
            	366, 0,
            	144, 8,
            	373, 16,
            8884099, 8, 2, /* 366: pointer_to_array_of_pointers_to_stack */
            	345, 0,
            	250, 28,
            8884097, 8, 0, /* 373: pointer.func */
            1, 8, 1, /* 376: pointer.struct.lhash_st */
            	357, 0,
            8884097, 8, 0, /* 381: pointer.func */
            8884097, 8, 0, /* 384: pointer.func */
            8884097, 8, 0, /* 387: pointer.func */
            8884097, 8, 0, /* 390: pointer.func */
            8884097, 8, 0, /* 393: pointer.func */
            8884097, 8, 0, /* 396: pointer.func */
            8884097, 8, 0, /* 399: pointer.func */
            0, 0, 1, /* 402: OCSP_RESPID */
            	407, 0,
            0, 16, 1, /* 407: struct.ocsp_responder_id_st */
            	412, 8,
            0, 8, 2, /* 412: union.unknown */
            	147, 0,
            	34, 0,
            8884097, 8, 0, /* 419: pointer.func */
            8884097, 8, 0, /* 422: pointer.func */
            8884097, 8, 0, /* 425: pointer.func */
            8884097, 8, 0, /* 428: pointer.func */
            8884097, 8, 0, /* 431: pointer.func */
            8884097, 8, 0, /* 434: pointer.func */
            8884097, 8, 0, /* 437: pointer.func */
            1, 8, 1, /* 440: pointer.struct.stack_st_X509_LOOKUP */
            	445, 0,
            0, 32, 2, /* 445: struct.stack_st_fake_X509_LOOKUP */
            	452, 8,
            	144, 24,
            8884099, 8, 2, /* 452: pointer_to_array_of_pointers_to_stack */
            	459, 0,
            	141, 20,
            0, 8, 1, /* 459: pointer.X509_LOOKUP */
            	464, 0,
            0, 0, 1, /* 464: X509_LOOKUP */
            	469, 0,
            0, 32, 3, /* 469: struct.x509_lookup_st */
            	478, 8,
            	62, 16,
            	527, 24,
            1, 8, 1, /* 478: pointer.struct.x509_lookup_method_st */
            	483, 0,
            0, 80, 10, /* 483: struct.x509_lookup_method_st */
            	5, 0,
            	506, 8,
            	509, 16,
            	506, 24,
            	506, 32,
            	512, 40,
            	515, 48,
            	518, 56,
            	521, 64,
            	524, 72,
            8884097, 8, 0, /* 506: pointer.func */
            8884097, 8, 0, /* 509: pointer.func */
            8884097, 8, 0, /* 512: pointer.func */
            8884097, 8, 0, /* 515: pointer.func */
            8884097, 8, 0, /* 518: pointer.func */
            8884097, 8, 0, /* 521: pointer.func */
            8884097, 8, 0, /* 524: pointer.func */
            1, 8, 1, /* 527: pointer.struct.x509_store_st */
            	532, 0,
            0, 144, 15, /* 532: struct.x509_store_st */
            	565, 8,
            	440, 16,
            	2611, 24,
            	437, 32,
            	434, 40,
            	431, 48,
            	428, 56,
            	437, 64,
            	425, 72,
            	2623, 80,
            	2626, 88,
            	422, 96,
            	419, 104,
            	437, 112,
            	1070, 120,
            1, 8, 1, /* 565: pointer.struct.stack_st_X509_OBJECT */
            	570, 0,
            0, 32, 2, /* 570: struct.stack_st_fake_X509_OBJECT */
            	577, 8,
            	144, 24,
            8884099, 8, 2, /* 577: pointer_to_array_of_pointers_to_stack */
            	584, 0,
            	141, 20,
            0, 8, 1, /* 584: pointer.X509_OBJECT */
            	589, 0,
            0, 0, 1, /* 589: X509_OBJECT */
            	594, 0,
            0, 16, 1, /* 594: struct.x509_object_st */
            	599, 8,
            0, 8, 4, /* 599: union.unknown */
            	62, 0,
            	610, 0,
            	2399, 0,
            	918, 0,
            1, 8, 1, /* 610: pointer.struct.x509_st */
            	615, 0,
            0, 184, 12, /* 615: struct.x509_st */
            	642, 0,
            	682, 8,
            	771, 16,
            	62, 32,
            	1070, 40,
            	776, 104,
            	1712, 112,
            	1720, 120,
            	1728, 128,
            	2137, 136,
            	2161, 144,
            	2169, 176,
            1, 8, 1, /* 642: pointer.struct.x509_cinf_st */
            	647, 0,
            0, 104, 11, /* 647: struct.x509_cinf_st */
            	672, 0,
            	672, 8,
            	682, 16,
            	839, 24,
            	887, 32,
            	839, 40,
            	904, 48,
            	771, 56,
            	771, 64,
            	1647, 72,
            	1707, 80,
            1, 8, 1, /* 672: pointer.struct.asn1_string_st */
            	677, 0,
            0, 24, 1, /* 677: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 682: pointer.struct.X509_algor_st */
            	687, 0,
            0, 16, 2, /* 687: struct.X509_algor_st */
            	694, 0,
            	708, 8,
            1, 8, 1, /* 694: pointer.struct.asn1_object_st */
            	699, 0,
            0, 40, 3, /* 699: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 708: pointer.struct.asn1_type_st */
            	713, 0,
            0, 16, 1, /* 713: struct.asn1_type_st */
            	718, 8,
            0, 8, 20, /* 718: union.unknown */
            	62, 0,
            	761, 0,
            	694, 0,
            	672, 0,
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
            	826, 0,
            	761, 0,
            	761, 0,
            	831, 0,
            1, 8, 1, /* 761: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 766: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 771: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 776: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 781: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 786: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 791: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 796: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 801: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 806: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 811: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 816: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 821: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 826: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 831: pointer.struct.ASN1_VALUE_st */
            	836, 0,
            0, 0, 0, /* 836: struct.ASN1_VALUE_st */
            1, 8, 1, /* 839: pointer.struct.X509_name_st */
            	844, 0,
            0, 40, 3, /* 844: struct.X509_name_st */
            	853, 0,
            	877, 16,
            	44, 24,
            1, 8, 1, /* 853: pointer.struct.stack_st_X509_NAME_ENTRY */
            	858, 0,
            0, 32, 2, /* 858: struct.stack_st_fake_X509_NAME_ENTRY */
            	865, 8,
            	144, 24,
            8884099, 8, 2, /* 865: pointer_to_array_of_pointers_to_stack */
            	872, 0,
            	141, 20,
            0, 8, 1, /* 872: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 877: pointer.struct.buf_mem_st */
            	882, 0,
            0, 24, 1, /* 882: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 887: pointer.struct.X509_val_st */
            	892, 0,
            0, 16, 2, /* 892: struct.X509_val_st */
            	899, 0,
            	899, 8,
            1, 8, 1, /* 899: pointer.struct.asn1_string_st */
            	677, 0,
            1, 8, 1, /* 904: pointer.struct.X509_pubkey_st */
            	909, 0,
            0, 24, 3, /* 909: struct.X509_pubkey_st */
            	682, 0,
            	771, 8,
            	918, 16,
            1, 8, 1, /* 918: pointer.struct.evp_pkey_st */
            	923, 0,
            0, 56, 4, /* 923: struct.evp_pkey_st */
            	934, 16,
            	942, 24,
            	950, 32,
            	1276, 48,
            1, 8, 1, /* 934: pointer.struct.evp_pkey_asn1_method_st */
            	939, 0,
            0, 0, 0, /* 939: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 942: pointer.struct.engine_st */
            	947, 0,
            0, 0, 0, /* 947: struct.engine_st */
            0, 8, 5, /* 950: union.unknown */
            	62, 0,
            	963, 0,
            	1119, 0,
            	1200, 0,
            	1268, 0,
            1, 8, 1, /* 963: pointer.struct.rsa_st */
            	968, 0,
            0, 168, 17, /* 968: struct.rsa_st */
            	1005, 16,
            	942, 24,
            	1060, 32,
            	1060, 40,
            	1060, 48,
            	1060, 56,
            	1060, 64,
            	1060, 72,
            	1060, 80,
            	1060, 88,
            	1070, 96,
            	1097, 120,
            	1097, 128,
            	1097, 136,
            	62, 144,
            	1111, 152,
            	1111, 160,
            1, 8, 1, /* 1005: pointer.struct.rsa_meth_st */
            	1010, 0,
            0, 112, 13, /* 1010: struct.rsa_meth_st */
            	5, 0,
            	1039, 8,
            	1039, 16,
            	1039, 24,
            	1039, 32,
            	1042, 40,
            	1045, 48,
            	1048, 56,
            	1048, 64,
            	62, 80,
            	1051, 88,
            	1054, 96,
            	1057, 104,
            8884097, 8, 0, /* 1039: pointer.func */
            8884097, 8, 0, /* 1042: pointer.func */
            8884097, 8, 0, /* 1045: pointer.func */
            8884097, 8, 0, /* 1048: pointer.func */
            8884097, 8, 0, /* 1051: pointer.func */
            8884097, 8, 0, /* 1054: pointer.func */
            8884097, 8, 0, /* 1057: pointer.func */
            1, 8, 1, /* 1060: pointer.struct.bignum_st */
            	1065, 0,
            0, 24, 1, /* 1065: struct.bignum_st */
            	245, 0,
            0, 16, 1, /* 1070: struct.crypto_ex_data_st */
            	1075, 0,
            1, 8, 1, /* 1075: pointer.struct.stack_st_void */
            	1080, 0,
            0, 32, 1, /* 1080: struct.stack_st_void */
            	1085, 0,
            0, 32, 2, /* 1085: struct.stack_st */
            	1092, 8,
            	144, 24,
            1, 8, 1, /* 1092: pointer.pointer.char */
            	62, 0,
            1, 8, 1, /* 1097: pointer.struct.bn_mont_ctx_st */
            	1102, 0,
            0, 96, 3, /* 1102: struct.bn_mont_ctx_st */
            	1065, 8,
            	1065, 32,
            	1065, 56,
            1, 8, 1, /* 1111: pointer.struct.bn_blinding_st */
            	1116, 0,
            0, 0, 0, /* 1116: struct.bn_blinding_st */
            1, 8, 1, /* 1119: pointer.struct.dsa_st */
            	1124, 0,
            0, 136, 11, /* 1124: struct.dsa_st */
            	1060, 24,
            	1060, 32,
            	1060, 40,
            	1060, 48,
            	1060, 56,
            	1060, 64,
            	1060, 72,
            	1097, 88,
            	1070, 104,
            	1149, 120,
            	942, 128,
            1, 8, 1, /* 1149: pointer.struct.dsa_method */
            	1154, 0,
            0, 96, 11, /* 1154: struct.dsa_method */
            	5, 0,
            	1179, 8,
            	1182, 16,
            	1185, 24,
            	1188, 32,
            	1191, 40,
            	1194, 48,
            	1194, 56,
            	62, 72,
            	1197, 80,
            	1194, 88,
            8884097, 8, 0, /* 1179: pointer.func */
            8884097, 8, 0, /* 1182: pointer.func */
            8884097, 8, 0, /* 1185: pointer.func */
            8884097, 8, 0, /* 1188: pointer.func */
            8884097, 8, 0, /* 1191: pointer.func */
            8884097, 8, 0, /* 1194: pointer.func */
            8884097, 8, 0, /* 1197: pointer.func */
            1, 8, 1, /* 1200: pointer.struct.dh_st */
            	1205, 0,
            0, 144, 12, /* 1205: struct.dh_st */
            	1060, 8,
            	1060, 16,
            	1060, 32,
            	1060, 40,
            	1097, 56,
            	1060, 64,
            	1060, 72,
            	44, 80,
            	1060, 96,
            	1070, 112,
            	1232, 128,
            	942, 136,
            1, 8, 1, /* 1232: pointer.struct.dh_method */
            	1237, 0,
            0, 72, 8, /* 1237: struct.dh_method */
            	5, 0,
            	1256, 8,
            	1259, 16,
            	1262, 24,
            	1256, 32,
            	1256, 40,
            	62, 56,
            	1265, 64,
            8884097, 8, 0, /* 1256: pointer.func */
            8884097, 8, 0, /* 1259: pointer.func */
            8884097, 8, 0, /* 1262: pointer.func */
            8884097, 8, 0, /* 1265: pointer.func */
            1, 8, 1, /* 1268: pointer.struct.ec_key_st */
            	1273, 0,
            0, 0, 0, /* 1273: struct.ec_key_st */
            1, 8, 1, /* 1276: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1281, 0,
            0, 32, 2, /* 1281: struct.stack_st_fake_X509_ATTRIBUTE */
            	1288, 8,
            	144, 24,
            8884099, 8, 2, /* 1288: pointer_to_array_of_pointers_to_stack */
            	1295, 0,
            	141, 20,
            0, 8, 1, /* 1295: pointer.X509_ATTRIBUTE */
            	1300, 0,
            0, 0, 1, /* 1300: X509_ATTRIBUTE */
            	1305, 0,
            0, 24, 2, /* 1305: struct.x509_attributes_st */
            	1312, 0,
            	1326, 16,
            1, 8, 1, /* 1312: pointer.struct.asn1_object_st */
            	1317, 0,
            0, 40, 3, /* 1317: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            0, 8, 3, /* 1326: union.unknown */
            	62, 0,
            	1335, 0,
            	1514, 0,
            1, 8, 1, /* 1335: pointer.struct.stack_st_ASN1_TYPE */
            	1340, 0,
            0, 32, 2, /* 1340: struct.stack_st_fake_ASN1_TYPE */
            	1347, 8,
            	144, 24,
            8884099, 8, 2, /* 1347: pointer_to_array_of_pointers_to_stack */
            	1354, 0,
            	141, 20,
            0, 8, 1, /* 1354: pointer.ASN1_TYPE */
            	1359, 0,
            0, 0, 1, /* 1359: ASN1_TYPE */
            	1364, 0,
            0, 16, 1, /* 1364: struct.asn1_type_st */
            	1369, 8,
            0, 8, 20, /* 1369: union.unknown */
            	62, 0,
            	1412, 0,
            	1422, 0,
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
            	1501, 0,
            	1412, 0,
            	1412, 0,
            	1506, 0,
            1, 8, 1, /* 1412: pointer.struct.asn1_string_st */
            	1417, 0,
            0, 24, 1, /* 1417: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 1422: pointer.struct.asn1_object_st */
            	1427, 0,
            0, 40, 3, /* 1427: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 1436: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1441: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1446: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1451: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1456: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1461: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1466: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1471: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1476: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1481: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1486: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1491: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1496: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1501: pointer.struct.asn1_string_st */
            	1417, 0,
            1, 8, 1, /* 1506: pointer.struct.ASN1_VALUE_st */
            	1511, 0,
            0, 0, 0, /* 1511: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1514: pointer.struct.asn1_type_st */
            	1519, 0,
            0, 16, 1, /* 1519: struct.asn1_type_st */
            	1524, 8,
            0, 8, 20, /* 1524: union.unknown */
            	62, 0,
            	1567, 0,
            	1312, 0,
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
            	1642, 0,
            	1567, 0,
            	1567, 0,
            	831, 0,
            1, 8, 1, /* 1567: pointer.struct.asn1_string_st */
            	1572, 0,
            0, 24, 1, /* 1572: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 1577: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1582: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1587: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1592: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1597: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1602: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1607: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1612: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1617: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1622: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1627: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1632: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1637: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1642: pointer.struct.asn1_string_st */
            	1572, 0,
            1, 8, 1, /* 1647: pointer.struct.stack_st_X509_EXTENSION */
            	1652, 0,
            0, 32, 2, /* 1652: struct.stack_st_fake_X509_EXTENSION */
            	1659, 8,
            	144, 24,
            8884099, 8, 2, /* 1659: pointer_to_array_of_pointers_to_stack */
            	1666, 0,
            	141, 20,
            0, 8, 1, /* 1666: pointer.X509_EXTENSION */
            	1671, 0,
            0, 0, 1, /* 1671: X509_EXTENSION */
            	1676, 0,
            0, 24, 2, /* 1676: struct.X509_extension_st */
            	1683, 0,
            	1697, 16,
            1, 8, 1, /* 1683: pointer.struct.asn1_object_st */
            	1688, 0,
            0, 40, 3, /* 1688: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 1697: pointer.struct.asn1_string_st */
            	1702, 0,
            0, 24, 1, /* 1702: struct.asn1_string_st */
            	44, 8,
            0, 24, 1, /* 1707: struct.ASN1_ENCODING_st */
            	44, 0,
            1, 8, 1, /* 1712: pointer.struct.AUTHORITY_KEYID_st */
            	1717, 0,
            0, 0, 0, /* 1717: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1720: pointer.struct.X509_POLICY_CACHE_st */
            	1725, 0,
            0, 0, 0, /* 1725: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1728: pointer.struct.stack_st_DIST_POINT */
            	1733, 0,
            0, 32, 2, /* 1733: struct.stack_st_fake_DIST_POINT */
            	1740, 8,
            	144, 24,
            8884099, 8, 2, /* 1740: pointer_to_array_of_pointers_to_stack */
            	1747, 0,
            	141, 20,
            0, 8, 1, /* 1747: pointer.DIST_POINT */
            	1752, 0,
            0, 0, 1, /* 1752: DIST_POINT */
            	1757, 0,
            0, 32, 3, /* 1757: struct.DIST_POINT_st */
            	1766, 0,
            	2127, 8,
            	1785, 16,
            1, 8, 1, /* 1766: pointer.struct.DIST_POINT_NAME_st */
            	1771, 0,
            0, 24, 2, /* 1771: struct.DIST_POINT_NAME_st */
            	1778, 8,
            	2103, 16,
            0, 8, 2, /* 1778: union.unknown */
            	1785, 0,
            	2079, 0,
            1, 8, 1, /* 1785: pointer.struct.stack_st_GENERAL_NAME */
            	1790, 0,
            0, 32, 2, /* 1790: struct.stack_st_fake_GENERAL_NAME */
            	1797, 8,
            	144, 24,
            8884099, 8, 2, /* 1797: pointer_to_array_of_pointers_to_stack */
            	1804, 0,
            	141, 20,
            0, 8, 1, /* 1804: pointer.GENERAL_NAME */
            	1809, 0,
            0, 0, 1, /* 1809: GENERAL_NAME */
            	1814, 0,
            0, 16, 1, /* 1814: struct.GENERAL_NAME_st */
            	1819, 8,
            0, 8, 15, /* 1819: union.unknown */
            	62, 0,
            	1852, 0,
            	1971, 0,
            	1971, 0,
            	1878, 0,
            	2019, 0,
            	2067, 0,
            	1971, 0,
            	1956, 0,
            	1864, 0,
            	1956, 0,
            	2019, 0,
            	1971, 0,
            	1864, 0,
            	1878, 0,
            1, 8, 1, /* 1852: pointer.struct.otherName_st */
            	1857, 0,
            0, 16, 2, /* 1857: struct.otherName_st */
            	1864, 0,
            	1878, 8,
            1, 8, 1, /* 1864: pointer.struct.asn1_object_st */
            	1869, 0,
            0, 40, 3, /* 1869: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 1878: pointer.struct.asn1_type_st */
            	1883, 0,
            0, 16, 1, /* 1883: struct.asn1_type_st */
            	1888, 8,
            0, 8, 20, /* 1888: union.unknown */
            	62, 0,
            	1931, 0,
            	1864, 0,
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
            	2006, 0,
            	1931, 0,
            	1931, 0,
            	2011, 0,
            1, 8, 1, /* 1931: pointer.struct.asn1_string_st */
            	1936, 0,
            0, 24, 1, /* 1936: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 1941: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 1946: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 1951: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 1956: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 1961: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 1966: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 1971: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 1976: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 1981: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 1986: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 1991: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 1996: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 2001: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 2006: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 2011: pointer.struct.ASN1_VALUE_st */
            	2016, 0,
            0, 0, 0, /* 2016: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2019: pointer.struct.X509_name_st */
            	2024, 0,
            0, 40, 3, /* 2024: struct.X509_name_st */
            	2033, 0,
            	2057, 16,
            	44, 24,
            1, 8, 1, /* 2033: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2038, 0,
            0, 32, 2, /* 2038: struct.stack_st_fake_X509_NAME_ENTRY */
            	2045, 8,
            	144, 24,
            8884099, 8, 2, /* 2045: pointer_to_array_of_pointers_to_stack */
            	2052, 0,
            	141, 20,
            0, 8, 1, /* 2052: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 2057: pointer.struct.buf_mem_st */
            	2062, 0,
            0, 24, 1, /* 2062: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 2067: pointer.struct.EDIPartyName_st */
            	2072, 0,
            0, 16, 2, /* 2072: struct.EDIPartyName_st */
            	1931, 0,
            	1931, 8,
            1, 8, 1, /* 2079: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2084, 0,
            0, 32, 2, /* 2084: struct.stack_st_fake_X509_NAME_ENTRY */
            	2091, 8,
            	144, 24,
            8884099, 8, 2, /* 2091: pointer_to_array_of_pointers_to_stack */
            	2098, 0,
            	141, 20,
            0, 8, 1, /* 2098: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 2103: pointer.struct.X509_name_st */
            	2108, 0,
            0, 40, 3, /* 2108: struct.X509_name_st */
            	2079, 0,
            	2117, 16,
            	44, 24,
            1, 8, 1, /* 2117: pointer.struct.buf_mem_st */
            	2122, 0,
            0, 24, 1, /* 2122: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 2127: pointer.struct.asn1_string_st */
            	2132, 0,
            0, 24, 1, /* 2132: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 2137: pointer.struct.stack_st_GENERAL_NAME */
            	2142, 0,
            0, 32, 2, /* 2142: struct.stack_st_fake_GENERAL_NAME */
            	2149, 8,
            	144, 24,
            8884099, 8, 2, /* 2149: pointer_to_array_of_pointers_to_stack */
            	2156, 0,
            	141, 20,
            0, 8, 1, /* 2156: pointer.GENERAL_NAME */
            	1809, 0,
            1, 8, 1, /* 2161: pointer.struct.NAME_CONSTRAINTS_st */
            	2166, 0,
            0, 0, 0, /* 2166: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2169: pointer.struct.x509_cert_aux_st */
            	2174, 0,
            0, 40, 5, /* 2174: struct.x509_cert_aux_st */
            	2187, 0,
            	2187, 8,
            	826, 16,
            	776, 24,
            	2216, 32,
            1, 8, 1, /* 2187: pointer.struct.stack_st_ASN1_OBJECT */
            	2192, 0,
            0, 32, 2, /* 2192: struct.stack_st_fake_ASN1_OBJECT */
            	2199, 8,
            	144, 24,
            8884099, 8, 2, /* 2199: pointer_to_array_of_pointers_to_stack */
            	2206, 0,
            	141, 20,
            0, 8, 1, /* 2206: pointer.ASN1_OBJECT */
            	2211, 0,
            0, 0, 1, /* 2211: ASN1_OBJECT */
            	1427, 0,
            1, 8, 1, /* 2216: pointer.struct.stack_st_X509_ALGOR */
            	2221, 0,
            0, 32, 2, /* 2221: struct.stack_st_fake_X509_ALGOR */
            	2228, 8,
            	144, 24,
            8884099, 8, 2, /* 2228: pointer_to_array_of_pointers_to_stack */
            	2235, 0,
            	141, 20,
            0, 8, 1, /* 2235: pointer.X509_ALGOR */
            	2240, 0,
            0, 0, 1, /* 2240: X509_ALGOR */
            	2245, 0,
            0, 16, 2, /* 2245: struct.X509_algor_st */
            	2252, 0,
            	2266, 8,
            1, 8, 1, /* 2252: pointer.struct.asn1_object_st */
            	2257, 0,
            0, 40, 3, /* 2257: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 2266: pointer.struct.asn1_type_st */
            	2271, 0,
            0, 16, 1, /* 2271: struct.asn1_type_st */
            	2276, 8,
            0, 8, 20, /* 2276: union.unknown */
            	62, 0,
            	2319, 0,
            	2252, 0,
            	2329, 0,
            	2334, 0,
            	2339, 0,
            	2344, 0,
            	2349, 0,
            	2354, 0,
            	2359, 0,
            	2364, 0,
            	2369, 0,
            	2374, 0,
            	2379, 0,
            	2384, 0,
            	2389, 0,
            	2394, 0,
            	2319, 0,
            	2319, 0,
            	831, 0,
            1, 8, 1, /* 2319: pointer.struct.asn1_string_st */
            	2324, 0,
            0, 24, 1, /* 2324: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 2329: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2334: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2339: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2344: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2349: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2354: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2359: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2364: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2369: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2374: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2379: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2384: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2389: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2394: pointer.struct.asn1_string_st */
            	2324, 0,
            1, 8, 1, /* 2399: pointer.struct.X509_crl_st */
            	2404, 0,
            0, 120, 10, /* 2404: struct.X509_crl_st */
            	2427, 0,
            	682, 8,
            	771, 16,
            	1712, 32,
            	2554, 40,
            	672, 56,
            	672, 64,
            	2562, 96,
            	2603, 104,
            	26, 112,
            1, 8, 1, /* 2427: pointer.struct.X509_crl_info_st */
            	2432, 0,
            0, 80, 8, /* 2432: struct.X509_crl_info_st */
            	672, 0,
            	682, 8,
            	839, 16,
            	899, 24,
            	899, 32,
            	2451, 40,
            	1647, 48,
            	1707, 56,
            1, 8, 1, /* 2451: pointer.struct.stack_st_X509_REVOKED */
            	2456, 0,
            0, 32, 2, /* 2456: struct.stack_st_fake_X509_REVOKED */
            	2463, 8,
            	144, 24,
            8884099, 8, 2, /* 2463: pointer_to_array_of_pointers_to_stack */
            	2470, 0,
            	141, 20,
            0, 8, 1, /* 2470: pointer.X509_REVOKED */
            	2475, 0,
            0, 0, 1, /* 2475: X509_REVOKED */
            	2480, 0,
            0, 40, 4, /* 2480: struct.x509_revoked_st */
            	2491, 0,
            	2501, 8,
            	2506, 16,
            	2530, 24,
            1, 8, 1, /* 2491: pointer.struct.asn1_string_st */
            	2496, 0,
            0, 24, 1, /* 2496: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 2501: pointer.struct.asn1_string_st */
            	2496, 0,
            1, 8, 1, /* 2506: pointer.struct.stack_st_X509_EXTENSION */
            	2511, 0,
            0, 32, 2, /* 2511: struct.stack_st_fake_X509_EXTENSION */
            	2518, 8,
            	144, 24,
            8884099, 8, 2, /* 2518: pointer_to_array_of_pointers_to_stack */
            	2525, 0,
            	141, 20,
            0, 8, 1, /* 2525: pointer.X509_EXTENSION */
            	1671, 0,
            1, 8, 1, /* 2530: pointer.struct.stack_st_GENERAL_NAME */
            	2535, 0,
            0, 32, 2, /* 2535: struct.stack_st_fake_GENERAL_NAME */
            	2542, 8,
            	144, 24,
            8884099, 8, 2, /* 2542: pointer_to_array_of_pointers_to_stack */
            	2549, 0,
            	141, 20,
            0, 8, 1, /* 2549: pointer.GENERAL_NAME */
            	1809, 0,
            1, 8, 1, /* 2554: pointer.struct.ISSUING_DIST_POINT_st */
            	2559, 0,
            0, 0, 0, /* 2559: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2562: pointer.struct.stack_st_GENERAL_NAMES */
            	2567, 0,
            0, 32, 2, /* 2567: struct.stack_st_fake_GENERAL_NAMES */
            	2574, 8,
            	144, 24,
            8884099, 8, 2, /* 2574: pointer_to_array_of_pointers_to_stack */
            	2581, 0,
            	141, 20,
            0, 8, 1, /* 2581: pointer.GENERAL_NAMES */
            	2586, 0,
            0, 0, 1, /* 2586: GENERAL_NAMES */
            	2591, 0,
            0, 32, 1, /* 2591: struct.stack_st_GENERAL_NAME */
            	2596, 0,
            0, 32, 2, /* 2596: struct.stack_st */
            	1092, 8,
            	144, 24,
            1, 8, 1, /* 2603: pointer.struct.x509_crl_method_st */
            	2608, 0,
            0, 0, 0, /* 2608: struct.x509_crl_method_st */
            1, 8, 1, /* 2611: pointer.struct.X509_VERIFY_PARAM_st */
            	2616, 0,
            0, 56, 2, /* 2616: struct.X509_VERIFY_PARAM_st */
            	62, 0,
            	2187, 48,
            8884097, 8, 0, /* 2623: pointer.func */
            8884097, 8, 0, /* 2626: pointer.func */
            1, 8, 1, /* 2629: pointer.struct.stack_st_X509_LOOKUP */
            	2634, 0,
            0, 32, 2, /* 2634: struct.stack_st_fake_X509_LOOKUP */
            	2641, 8,
            	144, 24,
            8884099, 8, 2, /* 2641: pointer_to_array_of_pointers_to_stack */
            	2648, 0,
            	141, 20,
            0, 8, 1, /* 2648: pointer.X509_LOOKUP */
            	464, 0,
            1, 8, 1, /* 2653: pointer.struct.ssl3_buf_freelist_st */
            	2658, 0,
            0, 24, 1, /* 2658: struct.ssl3_buf_freelist_st */
            	258, 16,
            1, 8, 1, /* 2663: pointer.struct.stack_st_X509_EXTENSION */
            	2668, 0,
            0, 32, 2, /* 2668: struct.stack_st_fake_X509_EXTENSION */
            	2675, 8,
            	144, 24,
            8884099, 8, 2, /* 2675: pointer_to_array_of_pointers_to_stack */
            	2682, 0,
            	141, 20,
            0, 8, 1, /* 2682: pointer.X509_EXTENSION */
            	1671, 0,
            0, 168, 17, /* 2687: struct.rsa_st */
            	2724, 16,
            	2779, 24,
            	235, 32,
            	235, 40,
            	235, 48,
            	235, 56,
            	235, 64,
            	235, 72,
            	235, 80,
            	235, 88,
            	2787, 96,
            	2809, 120,
            	2809, 128,
            	2809, 136,
            	62, 144,
            	2823, 152,
            	2823, 160,
            1, 8, 1, /* 2724: pointer.struct.rsa_meth_st */
            	2729, 0,
            0, 112, 13, /* 2729: struct.rsa_meth_st */
            	5, 0,
            	2758, 8,
            	2758, 16,
            	2758, 24,
            	2758, 32,
            	2761, 40,
            	2764, 48,
            	2767, 56,
            	2767, 64,
            	62, 80,
            	2770, 88,
            	2773, 96,
            	2776, 104,
            8884097, 8, 0, /* 2758: pointer.func */
            8884097, 8, 0, /* 2761: pointer.func */
            8884097, 8, 0, /* 2764: pointer.func */
            8884097, 8, 0, /* 2767: pointer.func */
            8884097, 8, 0, /* 2770: pointer.func */
            8884097, 8, 0, /* 2773: pointer.func */
            8884097, 8, 0, /* 2776: pointer.func */
            1, 8, 1, /* 2779: pointer.struct.engine_st */
            	2784, 0,
            0, 0, 0, /* 2784: struct.engine_st */
            0, 16, 1, /* 2787: struct.crypto_ex_data_st */
            	2792, 0,
            1, 8, 1, /* 2792: pointer.struct.stack_st_void */
            	2797, 0,
            0, 32, 1, /* 2797: struct.stack_st_void */
            	2802, 0,
            0, 32, 2, /* 2802: struct.stack_st */
            	1092, 8,
            	144, 24,
            1, 8, 1, /* 2809: pointer.struct.bn_mont_ctx_st */
            	2814, 0,
            0, 96, 3, /* 2814: struct.bn_mont_ctx_st */
            	240, 8,
            	240, 32,
            	240, 56,
            1, 8, 1, /* 2823: pointer.struct.bn_blinding_st */
            	2828, 0,
            0, 0, 0, /* 2828: struct.bn_blinding_st */
            1, 8, 1, /* 2831: pointer.struct.asn1_string_st */
            	2836, 0,
            0, 24, 1, /* 2836: struct.asn1_string_st */
            	44, 8,
            0, 0, 0, /* 2841: struct.ec_key_st */
            1, 8, 1, /* 2844: pointer.struct.ec_key_st */
            	2841, 0,
            0, 40, 3, /* 2849: struct.X509_name_st */
            	2858, 0,
            	2882, 16,
            	44, 24,
            1, 8, 1, /* 2858: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2863, 0,
            0, 32, 2, /* 2863: struct.stack_st_fake_X509_NAME_ENTRY */
            	2870, 8,
            	144, 24,
            8884099, 8, 2, /* 2870: pointer_to_array_of_pointers_to_stack */
            	2877, 0,
            	141, 20,
            0, 8, 1, /* 2877: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 2882: pointer.struct.buf_mem_st */
            	2887, 0,
            0, 24, 1, /* 2887: struct.buf_mem_st */
            	62, 8,
            8884097, 8, 0, /* 2892: pointer.func */
            0, 296, 7, /* 2895: struct.cert_st */
            	2912, 0,
            	3659, 48,
            	3664, 56,
            	3667, 64,
            	3672, 72,
            	3675, 80,
            	3680, 88,
            1, 8, 1, /* 2912: pointer.struct.cert_pkey_st */
            	2917, 0,
            0, 24, 3, /* 2917: struct.cert_pkey_st */
            	2926, 0,
            	3224, 8,
            	3614, 16,
            1, 8, 1, /* 2926: pointer.struct.x509_st */
            	2931, 0,
            0, 184, 12, /* 2931: struct.x509_st */
            	2958, 0,
            	2993, 8,
            	3082, 16,
            	62, 32,
            	2787, 40,
            	3087, 104,
            	3476, 112,
            	3484, 120,
            	3492, 128,
            	3516, 136,
            	3540, 144,
            	3548, 176,
            1, 8, 1, /* 2958: pointer.struct.x509_cinf_st */
            	2963, 0,
            0, 104, 11, /* 2963: struct.x509_cinf_st */
            	2988, 0,
            	2988, 8,
            	2993, 16,
            	3150, 24,
            	3198, 32,
            	3150, 40,
            	3210, 48,
            	3082, 56,
            	3082, 64,
            	3447, 72,
            	3471, 80,
            1, 8, 1, /* 2988: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 2993: pointer.struct.X509_algor_st */
            	2998, 0,
            0, 16, 2, /* 2998: struct.X509_algor_st */
            	3005, 0,
            	3019, 8,
            1, 8, 1, /* 3005: pointer.struct.asn1_object_st */
            	3010, 0,
            0, 40, 3, /* 3010: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 3019: pointer.struct.asn1_type_st */
            	3024, 0,
            0, 16, 1, /* 3024: struct.asn1_type_st */
            	3029, 8,
            0, 8, 20, /* 3029: union.unknown */
            	62, 0,
            	3072, 0,
            	3005, 0,
            	2988, 0,
            	3077, 0,
            	3082, 0,
            	3087, 0,
            	3092, 0,
            	3097, 0,
            	3102, 0,
            	3107, 0,
            	3112, 0,
            	3117, 0,
            	3122, 0,
            	3127, 0,
            	3132, 0,
            	3137, 0,
            	3072, 0,
            	3072, 0,
            	3142, 0,
            1, 8, 1, /* 3072: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3077: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3082: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3087: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3092: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3097: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3102: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3107: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3112: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3117: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3122: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3127: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3132: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3137: pointer.struct.asn1_string_st */
            	2836, 0,
            1, 8, 1, /* 3142: pointer.struct.ASN1_VALUE_st */
            	3147, 0,
            0, 0, 0, /* 3147: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3150: pointer.struct.X509_name_st */
            	3155, 0,
            0, 40, 3, /* 3155: struct.X509_name_st */
            	3164, 0,
            	3188, 16,
            	44, 24,
            1, 8, 1, /* 3164: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3169, 0,
            0, 32, 2, /* 3169: struct.stack_st_fake_X509_NAME_ENTRY */
            	3176, 8,
            	144, 24,
            8884099, 8, 2, /* 3176: pointer_to_array_of_pointers_to_stack */
            	3183, 0,
            	141, 20,
            0, 8, 1, /* 3183: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 3188: pointer.struct.buf_mem_st */
            	3193, 0,
            0, 24, 1, /* 3193: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 3198: pointer.struct.X509_val_st */
            	3203, 0,
            0, 16, 2, /* 3203: struct.X509_val_st */
            	2831, 0,
            	2831, 8,
            1, 8, 1, /* 3210: pointer.struct.X509_pubkey_st */
            	3215, 0,
            0, 24, 3, /* 3215: struct.X509_pubkey_st */
            	2993, 0,
            	3082, 8,
            	3224, 16,
            1, 8, 1, /* 3224: pointer.struct.evp_pkey_st */
            	3229, 0,
            0, 56, 4, /* 3229: struct.evp_pkey_st */
            	3240, 16,
            	2779, 24,
            	3248, 32,
            	3423, 48,
            1, 8, 1, /* 3240: pointer.struct.evp_pkey_asn1_method_st */
            	3245, 0,
            0, 0, 0, /* 3245: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3248: union.unknown */
            	62, 0,
            	3261, 0,
            	3266, 0,
            	3347, 0,
            	3415, 0,
            1, 8, 1, /* 3261: pointer.struct.rsa_st */
            	2687, 0,
            1, 8, 1, /* 3266: pointer.struct.dsa_st */
            	3271, 0,
            0, 136, 11, /* 3271: struct.dsa_st */
            	235, 24,
            	235, 32,
            	235, 40,
            	235, 48,
            	235, 56,
            	235, 64,
            	235, 72,
            	2809, 88,
            	2787, 104,
            	3296, 120,
            	2779, 128,
            1, 8, 1, /* 3296: pointer.struct.dsa_method */
            	3301, 0,
            0, 96, 11, /* 3301: struct.dsa_method */
            	5, 0,
            	3326, 8,
            	3329, 16,
            	3332, 24,
            	3335, 32,
            	3338, 40,
            	3341, 48,
            	3341, 56,
            	62, 72,
            	3344, 80,
            	3341, 88,
            8884097, 8, 0, /* 3326: pointer.func */
            8884097, 8, 0, /* 3329: pointer.func */
            8884097, 8, 0, /* 3332: pointer.func */
            8884097, 8, 0, /* 3335: pointer.func */
            8884097, 8, 0, /* 3338: pointer.func */
            8884097, 8, 0, /* 3341: pointer.func */
            8884097, 8, 0, /* 3344: pointer.func */
            1, 8, 1, /* 3347: pointer.struct.dh_st */
            	3352, 0,
            0, 144, 12, /* 3352: struct.dh_st */
            	235, 8,
            	235, 16,
            	235, 32,
            	235, 40,
            	2809, 56,
            	235, 64,
            	235, 72,
            	44, 80,
            	235, 96,
            	2787, 112,
            	3379, 128,
            	2779, 136,
            1, 8, 1, /* 3379: pointer.struct.dh_method */
            	3384, 0,
            0, 72, 8, /* 3384: struct.dh_method */
            	5, 0,
            	3403, 8,
            	3406, 16,
            	3409, 24,
            	3403, 32,
            	3403, 40,
            	62, 56,
            	3412, 64,
            8884097, 8, 0, /* 3403: pointer.func */
            8884097, 8, 0, /* 3406: pointer.func */
            8884097, 8, 0, /* 3409: pointer.func */
            8884097, 8, 0, /* 3412: pointer.func */
            1, 8, 1, /* 3415: pointer.struct.ec_key_st */
            	3420, 0,
            0, 0, 0, /* 3420: struct.ec_key_st */
            1, 8, 1, /* 3423: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3428, 0,
            0, 32, 2, /* 3428: struct.stack_st_fake_X509_ATTRIBUTE */
            	3435, 8,
            	144, 24,
            8884099, 8, 2, /* 3435: pointer_to_array_of_pointers_to_stack */
            	3442, 0,
            	141, 20,
            0, 8, 1, /* 3442: pointer.X509_ATTRIBUTE */
            	1300, 0,
            1, 8, 1, /* 3447: pointer.struct.stack_st_X509_EXTENSION */
            	3452, 0,
            0, 32, 2, /* 3452: struct.stack_st_fake_X509_EXTENSION */
            	3459, 8,
            	144, 24,
            8884099, 8, 2, /* 3459: pointer_to_array_of_pointers_to_stack */
            	3466, 0,
            	141, 20,
            0, 8, 1, /* 3466: pointer.X509_EXTENSION */
            	1671, 0,
            0, 24, 1, /* 3471: struct.ASN1_ENCODING_st */
            	44, 0,
            1, 8, 1, /* 3476: pointer.struct.AUTHORITY_KEYID_st */
            	3481, 0,
            0, 0, 0, /* 3481: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3484: pointer.struct.X509_POLICY_CACHE_st */
            	3489, 0,
            0, 0, 0, /* 3489: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3492: pointer.struct.stack_st_DIST_POINT */
            	3497, 0,
            0, 32, 2, /* 3497: struct.stack_st_fake_DIST_POINT */
            	3504, 8,
            	144, 24,
            8884099, 8, 2, /* 3504: pointer_to_array_of_pointers_to_stack */
            	3511, 0,
            	141, 20,
            0, 8, 1, /* 3511: pointer.DIST_POINT */
            	1752, 0,
            1, 8, 1, /* 3516: pointer.struct.stack_st_GENERAL_NAME */
            	3521, 0,
            0, 32, 2, /* 3521: struct.stack_st_fake_GENERAL_NAME */
            	3528, 8,
            	144, 24,
            8884099, 8, 2, /* 3528: pointer_to_array_of_pointers_to_stack */
            	3535, 0,
            	141, 20,
            0, 8, 1, /* 3535: pointer.GENERAL_NAME */
            	1809, 0,
            1, 8, 1, /* 3540: pointer.struct.NAME_CONSTRAINTS_st */
            	3545, 0,
            0, 0, 0, /* 3545: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3548: pointer.struct.x509_cert_aux_st */
            	3553, 0,
            0, 40, 5, /* 3553: struct.x509_cert_aux_st */
            	3566, 0,
            	3566, 8,
            	3137, 16,
            	3087, 24,
            	3590, 32,
            1, 8, 1, /* 3566: pointer.struct.stack_st_ASN1_OBJECT */
            	3571, 0,
            0, 32, 2, /* 3571: struct.stack_st_fake_ASN1_OBJECT */
            	3578, 8,
            	144, 24,
            8884099, 8, 2, /* 3578: pointer_to_array_of_pointers_to_stack */
            	3585, 0,
            	141, 20,
            0, 8, 1, /* 3585: pointer.ASN1_OBJECT */
            	2211, 0,
            1, 8, 1, /* 3590: pointer.struct.stack_st_X509_ALGOR */
            	3595, 0,
            0, 32, 2, /* 3595: struct.stack_st_fake_X509_ALGOR */
            	3602, 8,
            	144, 24,
            8884099, 8, 2, /* 3602: pointer_to_array_of_pointers_to_stack */
            	3609, 0,
            	141, 20,
            0, 8, 1, /* 3609: pointer.X509_ALGOR */
            	2240, 0,
            1, 8, 1, /* 3614: pointer.struct.env_md_st */
            	3619, 0,
            0, 120, 8, /* 3619: struct.env_md_st */
            	3638, 24,
            	3641, 32,
            	3644, 40,
            	3647, 48,
            	3638, 56,
            	3650, 64,
            	3653, 72,
            	3656, 112,
            8884097, 8, 0, /* 3638: pointer.func */
            8884097, 8, 0, /* 3641: pointer.func */
            8884097, 8, 0, /* 3644: pointer.func */
            8884097, 8, 0, /* 3647: pointer.func */
            8884097, 8, 0, /* 3650: pointer.func */
            8884097, 8, 0, /* 3653: pointer.func */
            8884097, 8, 0, /* 3656: pointer.func */
            1, 8, 1, /* 3659: pointer.struct.rsa_st */
            	2687, 0,
            8884097, 8, 0, /* 3664: pointer.func */
            1, 8, 1, /* 3667: pointer.struct.dh_st */
            	3352, 0,
            8884097, 8, 0, /* 3672: pointer.func */
            1, 8, 1, /* 3675: pointer.struct.ec_key_st */
            	3420, 0,
            8884097, 8, 0, /* 3680: pointer.func */
            8884097, 8, 0, /* 3683: pointer.func */
            8884097, 8, 0, /* 3686: pointer.func */
            0, 888, 7, /* 3689: struct.dtls1_state_st */
            	3706, 576,
            	3706, 592,
            	3711, 608,
            	3711, 616,
            	3706, 624,
            	3719, 648,
            	3719, 736,
            0, 16, 1, /* 3706: struct.record_pqueue_st */
            	3711, 8,
            1, 8, 1, /* 3711: pointer.struct._pqueue */
            	3716, 0,
            0, 0, 0, /* 3716: struct._pqueue */
            0, 88, 1, /* 3719: struct.hm_header_st */
            	3724, 48,
            0, 40, 4, /* 3724: struct.dtls1_retransmit_state */
            	3735, 0,
            	3788, 8,
            	3814, 16,
            	3857, 24,
            1, 8, 1, /* 3735: pointer.struct.evp_cipher_ctx_st */
            	3740, 0,
            0, 168, 4, /* 3740: struct.evp_cipher_ctx_st */
            	3751, 0,
            	2779, 8,
            	26, 96,
            	26, 120,
            1, 8, 1, /* 3751: pointer.struct.evp_cipher_st */
            	3756, 0,
            0, 88, 7, /* 3756: struct.evp_cipher_st */
            	3773, 24,
            	3776, 32,
            	3779, 40,
            	3782, 56,
            	3782, 64,
            	3785, 72,
            	26, 80,
            8884097, 8, 0, /* 3773: pointer.func */
            8884097, 8, 0, /* 3776: pointer.func */
            8884097, 8, 0, /* 3779: pointer.func */
            8884097, 8, 0, /* 3782: pointer.func */
            8884097, 8, 0, /* 3785: pointer.func */
            1, 8, 1, /* 3788: pointer.struct.env_md_ctx_st */
            	3793, 0,
            0, 48, 5, /* 3793: struct.env_md_ctx_st */
            	3614, 0,
            	2779, 8,
            	26, 24,
            	3806, 32,
            	3641, 40,
            1, 8, 1, /* 3806: pointer.struct.evp_pkey_ctx_st */
            	3811, 0,
            0, 0, 0, /* 3811: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 3814: pointer.struct.comp_ctx_st */
            	3819, 0,
            0, 56, 2, /* 3819: struct.comp_ctx_st */
            	3826, 0,
            	2787, 40,
            1, 8, 1, /* 3826: pointer.struct.comp_method_st */
            	3831, 0,
            0, 64, 7, /* 3831: struct.comp_method_st */
            	5, 8,
            	3848, 16,
            	3851, 24,
            	3854, 32,
            	3854, 40,
            	295, 48,
            	295, 56,
            8884097, 8, 0, /* 3848: pointer.func */
            8884097, 8, 0, /* 3851: pointer.func */
            8884097, 8, 0, /* 3854: pointer.func */
            1, 8, 1, /* 3857: pointer.struct.ssl_session_st */
            	3862, 0,
            0, 352, 14, /* 3862: struct.ssl_session_st */
            	62, 144,
            	62, 152,
            	3893, 168,
            	2926, 176,
            	4773, 224,
            	4783, 240,
            	2787, 248,
            	4817, 264,
            	4817, 272,
            	62, 280,
            	44, 296,
            	44, 312,
            	44, 320,
            	62, 344,
            1, 8, 1, /* 3893: pointer.struct.sess_cert_st */
            	3898, 0,
            0, 248, 5, /* 3898: struct.sess_cert_st */
            	3911, 0,
            	2912, 16,
            	3659, 216,
            	3667, 224,
            	3675, 232,
            1, 8, 1, /* 3911: pointer.struct.stack_st_X509 */
            	3916, 0,
            0, 32, 2, /* 3916: struct.stack_st_fake_X509 */
            	3923, 8,
            	144, 24,
            8884099, 8, 2, /* 3923: pointer_to_array_of_pointers_to_stack */
            	3930, 0,
            	141, 20,
            0, 8, 1, /* 3930: pointer.X509 */
            	3935, 0,
            0, 0, 1, /* 3935: X509 */
            	3940, 0,
            0, 184, 12, /* 3940: struct.x509_st */
            	3967, 0,
            	4007, 8,
            	4096, 16,
            	62, 32,
            	4395, 40,
            	4101, 104,
            	4635, 112,
            	4643, 120,
            	4651, 128,
            	4675, 136,
            	4699, 144,
            	4707, 176,
            1, 8, 1, /* 3967: pointer.struct.x509_cinf_st */
            	3972, 0,
            0, 104, 11, /* 3972: struct.x509_cinf_st */
            	3997, 0,
            	3997, 8,
            	4007, 16,
            	4164, 24,
            	4212, 32,
            	4164, 40,
            	4229, 48,
            	4096, 56,
            	4096, 64,
            	4606, 72,
            	4630, 80,
            1, 8, 1, /* 3997: pointer.struct.asn1_string_st */
            	4002, 0,
            0, 24, 1, /* 4002: struct.asn1_string_st */
            	44, 8,
            1, 8, 1, /* 4007: pointer.struct.X509_algor_st */
            	4012, 0,
            0, 16, 2, /* 4012: struct.X509_algor_st */
            	4019, 0,
            	4033, 8,
            1, 8, 1, /* 4019: pointer.struct.asn1_object_st */
            	4024, 0,
            0, 40, 3, /* 4024: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	126, 24,
            1, 8, 1, /* 4033: pointer.struct.asn1_type_st */
            	4038, 0,
            0, 16, 1, /* 4038: struct.asn1_type_st */
            	4043, 8,
            0, 8, 20, /* 4043: union.unknown */
            	62, 0,
            	4086, 0,
            	4019, 0,
            	3997, 0,
            	4091, 0,
            	4096, 0,
            	4101, 0,
            	4106, 0,
            	4111, 0,
            	4116, 0,
            	4121, 0,
            	4126, 0,
            	4131, 0,
            	4136, 0,
            	4141, 0,
            	4146, 0,
            	4151, 0,
            	4086, 0,
            	4086, 0,
            	4156, 0,
            1, 8, 1, /* 4086: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4091: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4096: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4101: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4106: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4111: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4116: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4121: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4126: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4131: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4136: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4141: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4146: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4151: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4156: pointer.struct.ASN1_VALUE_st */
            	4161, 0,
            0, 0, 0, /* 4161: struct.ASN1_VALUE_st */
            1, 8, 1, /* 4164: pointer.struct.X509_name_st */
            	4169, 0,
            0, 40, 3, /* 4169: struct.X509_name_st */
            	4178, 0,
            	4202, 16,
            	44, 24,
            1, 8, 1, /* 4178: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4183, 0,
            0, 32, 2, /* 4183: struct.stack_st_fake_X509_NAME_ENTRY */
            	4190, 8,
            	144, 24,
            8884099, 8, 2, /* 4190: pointer_to_array_of_pointers_to_stack */
            	4197, 0,
            	141, 20,
            0, 8, 1, /* 4197: pointer.X509_NAME_ENTRY */
            	100, 0,
            1, 8, 1, /* 4202: pointer.struct.buf_mem_st */
            	4207, 0,
            0, 24, 1, /* 4207: struct.buf_mem_st */
            	62, 8,
            1, 8, 1, /* 4212: pointer.struct.X509_val_st */
            	4217, 0,
            0, 16, 2, /* 4217: struct.X509_val_st */
            	4224, 0,
            	4224, 8,
            1, 8, 1, /* 4224: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4229: pointer.struct.X509_pubkey_st */
            	4234, 0,
            0, 24, 3, /* 4234: struct.X509_pubkey_st */
            	4007, 0,
            	4096, 8,
            	4243, 16,
            1, 8, 1, /* 4243: pointer.struct.evp_pkey_st */
            	4248, 0,
            0, 56, 4, /* 4248: struct.evp_pkey_st */
            	4259, 16,
            	4267, 24,
            	4275, 32,
            	4582, 48,
            1, 8, 1, /* 4259: pointer.struct.evp_pkey_asn1_method_st */
            	4264, 0,
            0, 0, 0, /* 4264: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 4267: pointer.struct.engine_st */
            	4272, 0,
            0, 0, 0, /* 4272: struct.engine_st */
            0, 8, 5, /* 4275: union.unknown */
            	62, 0,
            	4288, 0,
            	4439, 0,
            	4520, 0,
            	2844, 0,
            1, 8, 1, /* 4288: pointer.struct.rsa_st */
            	4293, 0,
            0, 168, 17, /* 4293: struct.rsa_st */
            	4330, 16,
            	4267, 24,
            	4385, 32,
            	4385, 40,
            	4385, 48,
            	4385, 56,
            	4385, 64,
            	4385, 72,
            	4385, 80,
            	4385, 88,
            	4395, 96,
            	4417, 120,
            	4417, 128,
            	4417, 136,
            	62, 144,
            	4431, 152,
            	4431, 160,
            1, 8, 1, /* 4330: pointer.struct.rsa_meth_st */
            	4335, 0,
            0, 112, 13, /* 4335: struct.rsa_meth_st */
            	5, 0,
            	4364, 8,
            	4364, 16,
            	4364, 24,
            	4364, 32,
            	4367, 40,
            	4370, 48,
            	4373, 56,
            	4373, 64,
            	62, 80,
            	4376, 88,
            	4379, 96,
            	4382, 104,
            8884097, 8, 0, /* 4364: pointer.func */
            8884097, 8, 0, /* 4367: pointer.func */
            8884097, 8, 0, /* 4370: pointer.func */
            8884097, 8, 0, /* 4373: pointer.func */
            8884097, 8, 0, /* 4376: pointer.func */
            8884097, 8, 0, /* 4379: pointer.func */
            8884097, 8, 0, /* 4382: pointer.func */
            1, 8, 1, /* 4385: pointer.struct.bignum_st */
            	4390, 0,
            0, 24, 1, /* 4390: struct.bignum_st */
            	245, 0,
            0, 16, 1, /* 4395: struct.crypto_ex_data_st */
            	4400, 0,
            1, 8, 1, /* 4400: pointer.struct.stack_st_void */
            	4405, 0,
            0, 32, 1, /* 4405: struct.stack_st_void */
            	4410, 0,
            0, 32, 2, /* 4410: struct.stack_st */
            	1092, 8,
            	144, 24,
            1, 8, 1, /* 4417: pointer.struct.bn_mont_ctx_st */
            	4422, 0,
            0, 96, 3, /* 4422: struct.bn_mont_ctx_st */
            	4390, 8,
            	4390, 32,
            	4390, 56,
            1, 8, 1, /* 4431: pointer.struct.bn_blinding_st */
            	4436, 0,
            0, 0, 0, /* 4436: struct.bn_blinding_st */
            1, 8, 1, /* 4439: pointer.struct.dsa_st */
            	4444, 0,
            0, 136, 11, /* 4444: struct.dsa_st */
            	4385, 24,
            	4385, 32,
            	4385, 40,
            	4385, 48,
            	4385, 56,
            	4385, 64,
            	4385, 72,
            	4417, 88,
            	4395, 104,
            	4469, 120,
            	4267, 128,
            1, 8, 1, /* 4469: pointer.struct.dsa_method */
            	4474, 0,
            0, 96, 11, /* 4474: struct.dsa_method */
            	5, 0,
            	4499, 8,
            	4502, 16,
            	4505, 24,
            	4508, 32,
            	4511, 40,
            	4514, 48,
            	4514, 56,
            	62, 72,
            	4517, 80,
            	4514, 88,
            8884097, 8, 0, /* 4499: pointer.func */
            8884097, 8, 0, /* 4502: pointer.func */
            8884097, 8, 0, /* 4505: pointer.func */
            8884097, 8, 0, /* 4508: pointer.func */
            8884097, 8, 0, /* 4511: pointer.func */
            8884097, 8, 0, /* 4514: pointer.func */
            8884097, 8, 0, /* 4517: pointer.func */
            1, 8, 1, /* 4520: pointer.struct.dh_st */
            	4525, 0,
            0, 144, 12, /* 4525: struct.dh_st */
            	4385, 8,
            	4385, 16,
            	4385, 32,
            	4385, 40,
            	4417, 56,
            	4385, 64,
            	4385, 72,
            	44, 80,
            	4385, 96,
            	4395, 112,
            	4552, 128,
            	4267, 136,
            1, 8, 1, /* 4552: pointer.struct.dh_method */
            	4557, 0,
            0, 72, 8, /* 4557: struct.dh_method */
            	5, 0,
            	3686, 8,
            	4576, 16,
            	2892, 24,
            	3686, 32,
            	3686, 40,
            	62, 56,
            	4579, 64,
            8884097, 8, 0, /* 4576: pointer.func */
            8884097, 8, 0, /* 4579: pointer.func */
            1, 8, 1, /* 4582: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4587, 0,
            0, 32, 2, /* 4587: struct.stack_st_fake_X509_ATTRIBUTE */
            	4594, 8,
            	144, 24,
            8884099, 8, 2, /* 4594: pointer_to_array_of_pointers_to_stack */
            	4601, 0,
            	141, 20,
            0, 8, 1, /* 4601: pointer.X509_ATTRIBUTE */
            	1300, 0,
            1, 8, 1, /* 4606: pointer.struct.stack_st_X509_EXTENSION */
            	4611, 0,
            0, 32, 2, /* 4611: struct.stack_st_fake_X509_EXTENSION */
            	4618, 8,
            	144, 24,
            8884099, 8, 2, /* 4618: pointer_to_array_of_pointers_to_stack */
            	4625, 0,
            	141, 20,
            0, 8, 1, /* 4625: pointer.X509_EXTENSION */
            	1671, 0,
            0, 24, 1, /* 4630: struct.ASN1_ENCODING_st */
            	44, 0,
            1, 8, 1, /* 4635: pointer.struct.AUTHORITY_KEYID_st */
            	4640, 0,
            0, 0, 0, /* 4640: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4643: pointer.struct.X509_POLICY_CACHE_st */
            	4648, 0,
            0, 0, 0, /* 4648: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4651: pointer.struct.stack_st_DIST_POINT */
            	4656, 0,
            0, 32, 2, /* 4656: struct.stack_st_fake_DIST_POINT */
            	4663, 8,
            	144, 24,
            8884099, 8, 2, /* 4663: pointer_to_array_of_pointers_to_stack */
            	4670, 0,
            	141, 20,
            0, 8, 1, /* 4670: pointer.DIST_POINT */
            	1752, 0,
            1, 8, 1, /* 4675: pointer.struct.stack_st_GENERAL_NAME */
            	4680, 0,
            0, 32, 2, /* 4680: struct.stack_st_fake_GENERAL_NAME */
            	4687, 8,
            	144, 24,
            8884099, 8, 2, /* 4687: pointer_to_array_of_pointers_to_stack */
            	4694, 0,
            	141, 20,
            0, 8, 1, /* 4694: pointer.GENERAL_NAME */
            	1809, 0,
            1, 8, 1, /* 4699: pointer.struct.NAME_CONSTRAINTS_st */
            	4704, 0,
            0, 0, 0, /* 4704: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4707: pointer.struct.x509_cert_aux_st */
            	4712, 0,
            0, 40, 5, /* 4712: struct.x509_cert_aux_st */
            	4725, 0,
            	4725, 8,
            	4151, 16,
            	4101, 24,
            	4749, 32,
            1, 8, 1, /* 4725: pointer.struct.stack_st_ASN1_OBJECT */
            	4730, 0,
            0, 32, 2, /* 4730: struct.stack_st_fake_ASN1_OBJECT */
            	4737, 8,
            	144, 24,
            8884099, 8, 2, /* 4737: pointer_to_array_of_pointers_to_stack */
            	4744, 0,
            	141, 20,
            0, 8, 1, /* 4744: pointer.ASN1_OBJECT */
            	2211, 0,
            1, 8, 1, /* 4749: pointer.struct.stack_st_X509_ALGOR */
            	4754, 0,
            0, 32, 2, /* 4754: struct.stack_st_fake_X509_ALGOR */
            	4761, 8,
            	144, 24,
            8884099, 8, 2, /* 4761: pointer_to_array_of_pointers_to_stack */
            	4768, 0,
            	141, 20,
            0, 8, 1, /* 4768: pointer.X509_ALGOR */
            	2240, 0,
            1, 8, 1, /* 4773: pointer.struct.ssl_cipher_st */
            	4778, 0,
            0, 88, 1, /* 4778: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4783: pointer.struct.stack_st_SSL_CIPHER */
            	4788, 0,
            0, 32, 2, /* 4788: struct.stack_st_fake_SSL_CIPHER */
            	4795, 8,
            	144, 24,
            8884099, 8, 2, /* 4795: pointer_to_array_of_pointers_to_stack */
            	4802, 0,
            	141, 20,
            0, 8, 1, /* 4802: pointer.SSL_CIPHER */
            	4807, 0,
            0, 0, 1, /* 4807: SSL_CIPHER */
            	4812, 0,
            0, 88, 1, /* 4812: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4817: pointer.struct.ssl_session_st */
            	3862, 0,
            1, 8, 1, /* 4822: pointer.struct.ssl3_enc_method */
            	4827, 0,
            0, 112, 11, /* 4827: struct.ssl3_enc_method */
            	4852, 0,
            	4855, 8,
            	4858, 16,
            	4861, 24,
            	4852, 32,
            	4864, 40,
            	4867, 56,
            	5, 64,
            	5, 80,
            	4870, 96,
            	4873, 104,
            8884097, 8, 0, /* 4852: pointer.func */
            8884097, 8, 0, /* 4855: pointer.func */
            8884097, 8, 0, /* 4858: pointer.func */
            8884097, 8, 0, /* 4861: pointer.func */
            8884097, 8, 0, /* 4864: pointer.func */
            8884097, 8, 0, /* 4867: pointer.func */
            8884097, 8, 0, /* 4870: pointer.func */
            8884097, 8, 0, /* 4873: pointer.func */
            8884097, 8, 0, /* 4876: pointer.func */
            8884097, 8, 0, /* 4879: pointer.func */
            0, 56, 2, /* 4882: struct.X509_VERIFY_PARAM_st */
            	62, 0,
            	3566, 48,
            1, 8, 1, /* 4889: pointer.struct.stack_st_X509_OBJECT */
            	4894, 0,
            0, 32, 2, /* 4894: struct.stack_st_fake_X509_OBJECT */
            	4901, 8,
            	144, 24,
            8884099, 8, 2, /* 4901: pointer_to_array_of_pointers_to_stack */
            	4908, 0,
            	141, 20,
            0, 8, 1, /* 4908: pointer.X509_OBJECT */
            	589, 0,
            8884097, 8, 0, /* 4913: pointer.func */
            1, 8, 1, /* 4916: pointer.struct.dtls1_state_st */
            	3689, 0,
            8884097, 8, 0, /* 4921: pointer.func */
            0, 344, 9, /* 4924: struct.ssl2_state_st */
            	126, 24,
            	44, 56,
            	44, 64,
            	44, 72,
            	44, 104,
            	44, 112,
            	44, 120,
            	44, 128,
            	44, 136,
            8884097, 8, 0, /* 4945: pointer.func */
            8884097, 8, 0, /* 4948: pointer.func */
            8884097, 8, 0, /* 4951: pointer.func */
            1, 8, 1, /* 4954: pointer.pointer.struct.env_md_ctx_st */
            	3788, 0,
            8884097, 8, 0, /* 4959: pointer.func */
            8884097, 8, 0, /* 4962: pointer.func */
            0, 1200, 10, /* 4965: struct.ssl3_state_st */
            	4988, 240,
            	4988, 264,
            	4993, 288,
            	4993, 344,
            	126, 432,
            	5002, 440,
            	4954, 448,
            	26, 496,
            	26, 512,
            	5070, 528,
            0, 24, 1, /* 4988: struct.ssl3_buffer_st */
            	44, 0,
            0, 56, 3, /* 4993: struct.ssl3_record_st */
            	44, 16,
            	44, 24,
            	44, 32,
            1, 8, 1, /* 5002: pointer.struct.bio_st */
            	5007, 0,
            0, 112, 7, /* 5007: struct.bio_st */
            	5024, 0,
            	5062, 8,
            	62, 16,
            	26, 48,
            	5065, 56,
            	5065, 64,
            	2787, 96,
            1, 8, 1, /* 5024: pointer.struct.bio_method_st */
            	5029, 0,
            0, 80, 9, /* 5029: struct.bio_method_st */
            	5, 8,
            	5050, 16,
            	5053, 24,
            	4948, 32,
            	5053, 40,
            	5056, 48,
            	5059, 56,
            	5059, 64,
            	4962, 72,
            8884097, 8, 0, /* 5050: pointer.func */
            8884097, 8, 0, /* 5053: pointer.func */
            8884097, 8, 0, /* 5056: pointer.func */
            8884097, 8, 0, /* 5059: pointer.func */
            8884097, 8, 0, /* 5062: pointer.func */
            1, 8, 1, /* 5065: pointer.struct.bio_st */
            	5007, 0,
            0, 528, 8, /* 5070: struct.unknown */
            	4773, 408,
            	3667, 416,
            	3675, 424,
            	5089, 464,
            	44, 480,
            	3751, 488,
            	3614, 496,
            	5118, 512,
            1, 8, 1, /* 5089: pointer.struct.stack_st_X509_NAME */
            	5094, 0,
            0, 32, 2, /* 5094: struct.stack_st_fake_X509_NAME */
            	5101, 8,
            	144, 24,
            8884099, 8, 2, /* 5101: pointer_to_array_of_pointers_to_stack */
            	5108, 0,
            	141, 20,
            0, 8, 1, /* 5108: pointer.X509_NAME */
            	5113, 0,
            0, 0, 1, /* 5113: X509_NAME */
            	2849, 0,
            1, 8, 1, /* 5118: pointer.struct.ssl_comp_st */
            	5123, 0,
            0, 24, 2, /* 5123: struct.ssl_comp_st */
            	5, 8,
            	3826, 16,
            8884097, 8, 0, /* 5130: pointer.func */
            0, 808, 51, /* 5133: struct.ssl_st */
            	5238, 8,
            	5002, 16,
            	5002, 24,
            	5002, 32,
            	4858, 48,
            	3188, 80,
            	26, 88,
            	44, 104,
            	5335, 120,
            	5340, 128,
            	4916, 136,
            	5345, 152,
            	26, 160,
            	5348, 176,
            	4783, 184,
            	4783, 192,
            	3735, 208,
            	3788, 216,
            	3814, 224,
            	3735, 232,
            	3788, 240,
            	3814, 248,
            	5353, 256,
            	3857, 304,
            	5358, 312,
            	5361, 328,
            	4876, 336,
            	5364, 352,
            	5367, 360,
            	5370, 368,
            	2787, 392,
            	5089, 408,
            	152, 464,
            	26, 472,
            	62, 480,
            	5528, 504,
            	2663, 512,
            	44, 520,
            	44, 544,
            	44, 560,
            	26, 568,
            	29, 584,
            	18, 592,
            	26, 600,
            	15, 608,
            	26, 616,
            	5370, 624,
            	44, 632,
            	160, 648,
            	10, 656,
            	195, 680,
            1, 8, 1, /* 5238: pointer.struct.ssl_method_st */
            	5243, 0,
            0, 232, 28, /* 5243: struct.ssl_method_st */
            	4858, 8,
            	4945, 16,
            	4945, 24,
            	4858, 32,
            	4858, 40,
            	5130, 48,
            	5130, 56,
            	5302, 64,
            	4858, 72,
            	4858, 80,
            	4858, 88,
            	5305, 96,
            	5308, 104,
            	5311, 112,
            	4858, 120,
            	5314, 128,
            	3683, 136,
            	5317, 144,
            	5320, 152,
            	5323, 160,
            	5326, 168,
            	4879, 176,
            	5329, 184,
            	295, 192,
            	4822, 200,
            	5326, 208,
            	5332, 216,
            	4959, 224,
            8884097, 8, 0, /* 5302: pointer.func */
            8884097, 8, 0, /* 5305: pointer.func */
            8884097, 8, 0, /* 5308: pointer.func */
            8884097, 8, 0, /* 5311: pointer.func */
            8884097, 8, 0, /* 5314: pointer.func */
            8884097, 8, 0, /* 5317: pointer.func */
            8884097, 8, 0, /* 5320: pointer.func */
            8884097, 8, 0, /* 5323: pointer.func */
            8884097, 8, 0, /* 5326: pointer.func */
            8884097, 8, 0, /* 5329: pointer.func */
            8884097, 8, 0, /* 5332: pointer.func */
            1, 8, 1, /* 5335: pointer.struct.ssl2_state_st */
            	4924, 0,
            1, 8, 1, /* 5340: pointer.struct.ssl3_state_st */
            	4965, 0,
            8884097, 8, 0, /* 5345: pointer.func */
            1, 8, 1, /* 5348: pointer.struct.X509_VERIFY_PARAM_st */
            	4882, 0,
            1, 8, 1, /* 5353: pointer.struct.cert_st */
            	2895, 0,
            8884097, 8, 0, /* 5358: pointer.func */
            8884097, 8, 0, /* 5361: pointer.func */
            8884097, 8, 0, /* 5364: pointer.func */
            8884097, 8, 0, /* 5367: pointer.func */
            1, 8, 1, /* 5370: pointer.struct.ssl_ctx_st */
            	5375, 0,
            0, 736, 50, /* 5375: struct.ssl_ctx_st */
            	5238, 0,
            	4783, 8,
            	4783, 16,
            	5478, 24,
            	376, 32,
            	4817, 48,
            	4817, 56,
            	342, 80,
            	5519, 88,
            	339, 96,
            	4951, 152,
            	26, 160,
            	4913, 168,
            	26, 176,
            	4921, 184,
            	5522, 192,
            	5525, 200,
            	2787, 208,
            	3614, 224,
            	3614, 232,
            	3614, 240,
            	3911, 248,
            	315, 256,
            	4876, 264,
            	5089, 272,
            	5353, 304,
            	5345, 320,
            	26, 328,
            	5361, 376,
            	5358, 384,
            	5348, 392,
            	2779, 408,
            	226, 416,
            	26, 424,
            	266, 480,
            	229, 488,
            	26, 496,
            	263, 504,
            	26, 512,
            	62, 520,
            	5364, 528,
            	5367, 536,
            	2653, 552,
            	2653, 560,
            	195, 568,
            	192, 696,
            	26, 704,
            	189, 712,
            	26, 720,
            	160, 728,
            1, 8, 1, /* 5478: pointer.struct.x509_store_st */
            	5483, 0,
            0, 144, 15, /* 5483: struct.x509_store_st */
            	4889, 8,
            	2629, 16,
            	5348, 24,
            	5516, 32,
            	5361, 40,
            	399, 48,
            	396, 56,
            	5516, 64,
            	393, 72,
            	390, 80,
            	387, 88,
            	384, 96,
            	381, 104,
            	5516, 112,
            	2787, 120,
            8884097, 8, 0, /* 5516: pointer.func */
            8884097, 8, 0, /* 5519: pointer.func */
            8884097, 8, 0, /* 5522: pointer.func */
            8884097, 8, 0, /* 5525: pointer.func */
            1, 8, 1, /* 5528: pointer.struct.stack_st_OCSP_RESPID */
            	5533, 0,
            0, 32, 2, /* 5533: struct.stack_st_fake_OCSP_RESPID */
            	5540, 8,
            	144, 24,
            8884099, 8, 2, /* 5540: pointer_to_array_of_pointers_to_stack */
            	5547, 0,
            	141, 20,
            0, 8, 1, /* 5547: pointer.OCSP_RESPID */
            	402, 0,
            0, 1, 0, /* 5552: char */
            1, 8, 1, /* 5555: pointer.struct.ssl_st */
            	5133, 0,
        },
        .arg_entity_index = { 5555, },
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

