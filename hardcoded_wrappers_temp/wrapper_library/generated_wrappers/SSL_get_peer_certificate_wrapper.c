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

X509 * bb_SSL_get_peer_certificate(const SSL * arg_a);

X509 * SSL_get_peer_certificate(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_peer_certificate called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_peer_certificate(arg_a);
    else {
        X509 * (*orig_SSL_get_peer_certificate)(const SSL *);
        orig_SSL_get_peer_certificate = dlsym(RTLD_NEXT, "SSL_get_peer_certificate");
        return orig_SSL_get_peer_certificate(arg_a);
    }
}

X509 * bb_SSL_get_peer_certificate(const SSL * arg_a) 
{
    X509 * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 10: pointer.struct.stack_st_X509_EXTENSION */
            	15, 0,
            0, 32, 2, /* 15: struct.stack_st_fake_X509_EXTENSION */
            	22, 8,
            	86, 24,
            8884099, 8, 2, /* 22: pointer_to_array_of_pointers_to_stack */
            	29, 0,
            	83, 20,
            0, 8, 1, /* 29: pointer.X509_EXTENSION */
            	34, 0,
            0, 0, 1, /* 34: X509_EXTENSION */
            	39, 0,
            0, 24, 2, /* 39: struct.X509_extension_st */
            	46, 0,
            	68, 16,
            1, 8, 1, /* 46: pointer.struct.asn1_object_st */
            	51, 0,
            0, 40, 3, /* 51: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 60: pointer.unsigned char */
            	65, 0,
            0, 1, 0, /* 65: unsigned char */
            1, 8, 1, /* 68: pointer.struct.asn1_string_st */
            	73, 0,
            0, 24, 1, /* 73: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 78: pointer.unsigned char */
            	65, 0,
            0, 4, 0, /* 83: int */
            8884097, 8, 0, /* 86: pointer.func */
            0, 24, 1, /* 89: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 94: pointer.struct.asn1_string_st */
            	89, 0,
            0, 40, 3, /* 99: struct.X509_name_st */
            	108, 0,
            	168, 16,
            	78, 24,
            1, 8, 1, /* 108: pointer.struct.stack_st_X509_NAME_ENTRY */
            	113, 0,
            0, 32, 2, /* 113: struct.stack_st_fake_X509_NAME_ENTRY */
            	120, 8,
            	86, 24,
            8884099, 8, 2, /* 120: pointer_to_array_of_pointers_to_stack */
            	127, 0,
            	83, 20,
            0, 8, 1, /* 127: pointer.X509_NAME_ENTRY */
            	132, 0,
            0, 0, 1, /* 132: X509_NAME_ENTRY */
            	137, 0,
            0, 24, 2, /* 137: struct.X509_name_entry_st */
            	144, 0,
            	158, 8,
            1, 8, 1, /* 144: pointer.struct.asn1_object_st */
            	149, 0,
            0, 40, 3, /* 149: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 158: pointer.struct.asn1_string_st */
            	163, 0,
            0, 24, 1, /* 163: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 168: pointer.struct.buf_mem_st */
            	173, 0,
            0, 24, 1, /* 173: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 178: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 183: pointer.struct.X509_name_st */
            	99, 0,
            0, 16, 1, /* 188: struct.ocsp_responder_id_st */
            	193, 8,
            0, 8, 2, /* 193: union.unknown */
            	183, 0,
            	94, 0,
            1, 8, 1, /* 200: pointer.struct.stack_st_OCSP_RESPID */
            	205, 0,
            0, 32, 2, /* 205: struct.stack_st_fake_OCSP_RESPID */
            	212, 8,
            	86, 24,
            8884099, 8, 2, /* 212: pointer_to_array_of_pointers_to_stack */
            	219, 0,
            	83, 20,
            0, 8, 1, /* 219: pointer.OCSP_RESPID */
            	224, 0,
            0, 0, 1, /* 224: OCSP_RESPID */
            	188, 0,
            0, 0, 1, /* 229: SRTP_PROTECTION_PROFILE */
            	234, 0,
            0, 16, 1, /* 234: struct.srtp_protection_profile_st */
            	5, 0,
            8884097, 8, 0, /* 239: pointer.func */
            0, 128, 14, /* 242: struct.srp_ctx_st */
            	273, 0,
            	276, 8,
            	279, 16,
            	282, 24,
            	178, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	285, 96,
            	178, 104,
            0, 8, 0, /* 273: pointer.void */
            8884097, 8, 0, /* 276: pointer.func */
            8884097, 8, 0, /* 279: pointer.func */
            8884097, 8, 0, /* 282: pointer.func */
            1, 8, 1, /* 285: pointer.struct.bignum_st */
            	290, 0,
            0, 24, 1, /* 290: struct.bignum_st */
            	295, 0,
            1, 8, 1, /* 295: pointer.unsigned int */
            	300, 0,
            0, 4, 0, /* 300: unsigned int */
            1, 8, 1, /* 303: pointer.struct.ssl3_buf_freelist_entry_st */
            	308, 0,
            0, 8, 1, /* 308: struct.ssl3_buf_freelist_entry_st */
            	303, 0,
            8884097, 8, 0, /* 313: pointer.func */
            8884097, 8, 0, /* 316: pointer.func */
            8884097, 8, 0, /* 319: pointer.func */
            0, 64, 7, /* 322: struct.comp_method_st */
            	5, 8,
            	339, 16,
            	319, 24,
            	316, 32,
            	316, 40,
            	342, 48,
            	342, 56,
            8884097, 8, 0, /* 339: pointer.func */
            8884097, 8, 0, /* 342: pointer.func */
            1, 8, 1, /* 345: pointer.struct.comp_method_st */
            	322, 0,
            0, 0, 1, /* 350: SSL_COMP */
            	355, 0,
            0, 24, 2, /* 355: struct.ssl_comp_st */
            	5, 8,
            	345, 16,
            1, 8, 1, /* 362: pointer.struct.stack_st_SSL_COMP */
            	367, 0,
            0, 32, 2, /* 367: struct.stack_st_fake_SSL_COMP */
            	374, 8,
            	86, 24,
            8884099, 8, 2, /* 374: pointer_to_array_of_pointers_to_stack */
            	381, 0,
            	83, 20,
            0, 8, 1, /* 381: pointer.SSL_COMP */
            	350, 0,
            8884097, 8, 0, /* 386: pointer.func */
            8884097, 8, 0, /* 389: pointer.func */
            1, 8, 1, /* 392: pointer.struct.lhash_node_st */
            	397, 0,
            0, 24, 2, /* 397: struct.lhash_node_st */
            	273, 0,
            	392, 8,
            0, 176, 3, /* 404: struct.lhash_st */
            	413, 0,
            	86, 8,
            	420, 16,
            8884099, 8, 2, /* 413: pointer_to_array_of_pointers_to_stack */
            	392, 0,
            	300, 28,
            8884097, 8, 0, /* 420: pointer.func */
            1, 8, 1, /* 423: pointer.struct.lhash_st */
            	404, 0,
            8884097, 8, 0, /* 428: pointer.func */
            8884097, 8, 0, /* 431: pointer.func */
            8884097, 8, 0, /* 434: pointer.func */
            8884097, 8, 0, /* 437: pointer.func */
            8884097, 8, 0, /* 440: pointer.func */
            8884097, 8, 0, /* 443: pointer.func */
            8884097, 8, 0, /* 446: pointer.func */
            8884097, 8, 0, /* 449: pointer.func */
            8884097, 8, 0, /* 452: pointer.func */
            8884097, 8, 0, /* 455: pointer.func */
            8884097, 8, 0, /* 458: pointer.func */
            1, 8, 1, /* 461: pointer.struct.stack_st_X509_LOOKUP */
            	466, 0,
            0, 32, 2, /* 466: struct.stack_st_fake_X509_LOOKUP */
            	473, 8,
            	86, 24,
            8884099, 8, 2, /* 473: pointer_to_array_of_pointers_to_stack */
            	480, 0,
            	83, 20,
            0, 8, 1, /* 480: pointer.X509_LOOKUP */
            	485, 0,
            0, 0, 1, /* 485: X509_LOOKUP */
            	490, 0,
            0, 32, 3, /* 490: struct.x509_lookup_st */
            	499, 8,
            	178, 16,
            	548, 24,
            1, 8, 1, /* 499: pointer.struct.x509_lookup_method_st */
            	504, 0,
            0, 80, 10, /* 504: struct.x509_lookup_method_st */
            	5, 0,
            	527, 8,
            	530, 16,
            	527, 24,
            	527, 32,
            	533, 40,
            	536, 48,
            	539, 56,
            	542, 64,
            	545, 72,
            8884097, 8, 0, /* 527: pointer.func */
            8884097, 8, 0, /* 530: pointer.func */
            8884097, 8, 0, /* 533: pointer.func */
            8884097, 8, 0, /* 536: pointer.func */
            8884097, 8, 0, /* 539: pointer.func */
            8884097, 8, 0, /* 542: pointer.func */
            8884097, 8, 0, /* 545: pointer.func */
            1, 8, 1, /* 548: pointer.struct.x509_store_st */
            	553, 0,
            0, 144, 15, /* 553: struct.x509_store_st */
            	586, 8,
            	461, 16,
            	2596, 24,
            	455, 32,
            	452, 40,
            	449, 48,
            	446, 56,
            	455, 64,
            	443, 72,
            	2608, 80,
            	2611, 88,
            	440, 96,
            	437, 104,
            	455, 112,
            	1091, 120,
            1, 8, 1, /* 586: pointer.struct.stack_st_X509_OBJECT */
            	591, 0,
            0, 32, 2, /* 591: struct.stack_st_fake_X509_OBJECT */
            	598, 8,
            	86, 24,
            8884099, 8, 2, /* 598: pointer_to_array_of_pointers_to_stack */
            	605, 0,
            	83, 20,
            0, 8, 1, /* 605: pointer.X509_OBJECT */
            	610, 0,
            0, 0, 1, /* 610: X509_OBJECT */
            	615, 0,
            0, 16, 1, /* 615: struct.x509_object_st */
            	620, 8,
            0, 8, 4, /* 620: union.unknown */
            	178, 0,
            	631, 0,
            	2384, 0,
            	939, 0,
            1, 8, 1, /* 631: pointer.struct.x509_st */
            	636, 0,
            0, 184, 12, /* 636: struct.x509_st */
            	663, 0,
            	703, 8,
            	792, 16,
            	178, 32,
            	1091, 40,
            	797, 104,
            	1697, 112,
            	1705, 120,
            	1713, 128,
            	2122, 136,
            	2146, 144,
            	2154, 176,
            1, 8, 1, /* 663: pointer.struct.x509_cinf_st */
            	668, 0,
            0, 104, 11, /* 668: struct.x509_cinf_st */
            	693, 0,
            	693, 8,
            	703, 16,
            	860, 24,
            	908, 32,
            	860, 40,
            	925, 48,
            	792, 56,
            	792, 64,
            	1668, 72,
            	1692, 80,
            1, 8, 1, /* 693: pointer.struct.asn1_string_st */
            	698, 0,
            0, 24, 1, /* 698: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 703: pointer.struct.X509_algor_st */
            	708, 0,
            0, 16, 2, /* 708: struct.X509_algor_st */
            	715, 0,
            	729, 8,
            1, 8, 1, /* 715: pointer.struct.asn1_object_st */
            	720, 0,
            0, 40, 3, /* 720: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 729: pointer.struct.asn1_type_st */
            	734, 0,
            0, 16, 1, /* 734: struct.asn1_type_st */
            	739, 8,
            0, 8, 20, /* 739: union.unknown */
            	178, 0,
            	782, 0,
            	715, 0,
            	693, 0,
            	787, 0,
            	792, 0,
            	797, 0,
            	802, 0,
            	807, 0,
            	812, 0,
            	817, 0,
            	822, 0,
            	827, 0,
            	832, 0,
            	837, 0,
            	842, 0,
            	847, 0,
            	782, 0,
            	782, 0,
            	852, 0,
            1, 8, 1, /* 782: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 787: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 792: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 797: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 802: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 807: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 812: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 817: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 822: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 827: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 832: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 837: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 842: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 847: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 852: pointer.struct.ASN1_VALUE_st */
            	857, 0,
            0, 0, 0, /* 857: struct.ASN1_VALUE_st */
            1, 8, 1, /* 860: pointer.struct.X509_name_st */
            	865, 0,
            0, 40, 3, /* 865: struct.X509_name_st */
            	874, 0,
            	898, 16,
            	78, 24,
            1, 8, 1, /* 874: pointer.struct.stack_st_X509_NAME_ENTRY */
            	879, 0,
            0, 32, 2, /* 879: struct.stack_st_fake_X509_NAME_ENTRY */
            	886, 8,
            	86, 24,
            8884099, 8, 2, /* 886: pointer_to_array_of_pointers_to_stack */
            	893, 0,
            	83, 20,
            0, 8, 1, /* 893: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 898: pointer.struct.buf_mem_st */
            	903, 0,
            0, 24, 1, /* 903: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 908: pointer.struct.X509_val_st */
            	913, 0,
            0, 16, 2, /* 913: struct.X509_val_st */
            	920, 0,
            	920, 8,
            1, 8, 1, /* 920: pointer.struct.asn1_string_st */
            	698, 0,
            1, 8, 1, /* 925: pointer.struct.X509_pubkey_st */
            	930, 0,
            0, 24, 3, /* 930: struct.X509_pubkey_st */
            	703, 0,
            	792, 8,
            	939, 16,
            1, 8, 1, /* 939: pointer.struct.evp_pkey_st */
            	944, 0,
            0, 56, 4, /* 944: struct.evp_pkey_st */
            	955, 16,
            	963, 24,
            	971, 32,
            	1297, 48,
            1, 8, 1, /* 955: pointer.struct.evp_pkey_asn1_method_st */
            	960, 0,
            0, 0, 0, /* 960: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 963: pointer.struct.engine_st */
            	968, 0,
            0, 0, 0, /* 968: struct.engine_st */
            0, 8, 5, /* 971: union.unknown */
            	178, 0,
            	984, 0,
            	1140, 0,
            	1221, 0,
            	1289, 0,
            1, 8, 1, /* 984: pointer.struct.rsa_st */
            	989, 0,
            0, 168, 17, /* 989: struct.rsa_st */
            	1026, 16,
            	963, 24,
            	1081, 32,
            	1081, 40,
            	1081, 48,
            	1081, 56,
            	1081, 64,
            	1081, 72,
            	1081, 80,
            	1081, 88,
            	1091, 96,
            	1118, 120,
            	1118, 128,
            	1118, 136,
            	178, 144,
            	1132, 152,
            	1132, 160,
            1, 8, 1, /* 1026: pointer.struct.rsa_meth_st */
            	1031, 0,
            0, 112, 13, /* 1031: struct.rsa_meth_st */
            	5, 0,
            	1060, 8,
            	1060, 16,
            	1060, 24,
            	1060, 32,
            	1063, 40,
            	1066, 48,
            	1069, 56,
            	1069, 64,
            	178, 80,
            	1072, 88,
            	1075, 96,
            	1078, 104,
            8884097, 8, 0, /* 1060: pointer.func */
            8884097, 8, 0, /* 1063: pointer.func */
            8884097, 8, 0, /* 1066: pointer.func */
            8884097, 8, 0, /* 1069: pointer.func */
            8884097, 8, 0, /* 1072: pointer.func */
            8884097, 8, 0, /* 1075: pointer.func */
            8884097, 8, 0, /* 1078: pointer.func */
            1, 8, 1, /* 1081: pointer.struct.bignum_st */
            	1086, 0,
            0, 24, 1, /* 1086: struct.bignum_st */
            	295, 0,
            0, 16, 1, /* 1091: struct.crypto_ex_data_st */
            	1096, 0,
            1, 8, 1, /* 1096: pointer.struct.stack_st_void */
            	1101, 0,
            0, 32, 1, /* 1101: struct.stack_st_void */
            	1106, 0,
            0, 32, 2, /* 1106: struct.stack_st */
            	1113, 8,
            	86, 24,
            1, 8, 1, /* 1113: pointer.pointer.char */
            	178, 0,
            1, 8, 1, /* 1118: pointer.struct.bn_mont_ctx_st */
            	1123, 0,
            0, 96, 3, /* 1123: struct.bn_mont_ctx_st */
            	1086, 8,
            	1086, 32,
            	1086, 56,
            1, 8, 1, /* 1132: pointer.struct.bn_blinding_st */
            	1137, 0,
            0, 0, 0, /* 1137: struct.bn_blinding_st */
            1, 8, 1, /* 1140: pointer.struct.dsa_st */
            	1145, 0,
            0, 136, 11, /* 1145: struct.dsa_st */
            	1081, 24,
            	1081, 32,
            	1081, 40,
            	1081, 48,
            	1081, 56,
            	1081, 64,
            	1081, 72,
            	1118, 88,
            	1091, 104,
            	1170, 120,
            	963, 128,
            1, 8, 1, /* 1170: pointer.struct.dsa_method */
            	1175, 0,
            0, 96, 11, /* 1175: struct.dsa_method */
            	5, 0,
            	1200, 8,
            	1203, 16,
            	1206, 24,
            	1209, 32,
            	1212, 40,
            	1215, 48,
            	1215, 56,
            	178, 72,
            	1218, 80,
            	1215, 88,
            8884097, 8, 0, /* 1200: pointer.func */
            8884097, 8, 0, /* 1203: pointer.func */
            8884097, 8, 0, /* 1206: pointer.func */
            8884097, 8, 0, /* 1209: pointer.func */
            8884097, 8, 0, /* 1212: pointer.func */
            8884097, 8, 0, /* 1215: pointer.func */
            8884097, 8, 0, /* 1218: pointer.func */
            1, 8, 1, /* 1221: pointer.struct.dh_st */
            	1226, 0,
            0, 144, 12, /* 1226: struct.dh_st */
            	1081, 8,
            	1081, 16,
            	1081, 32,
            	1081, 40,
            	1118, 56,
            	1081, 64,
            	1081, 72,
            	78, 80,
            	1081, 96,
            	1091, 112,
            	1253, 128,
            	963, 136,
            1, 8, 1, /* 1253: pointer.struct.dh_method */
            	1258, 0,
            0, 72, 8, /* 1258: struct.dh_method */
            	5, 0,
            	1277, 8,
            	1280, 16,
            	1283, 24,
            	1277, 32,
            	1277, 40,
            	178, 56,
            	1286, 64,
            8884097, 8, 0, /* 1277: pointer.func */
            8884097, 8, 0, /* 1280: pointer.func */
            8884097, 8, 0, /* 1283: pointer.func */
            8884097, 8, 0, /* 1286: pointer.func */
            1, 8, 1, /* 1289: pointer.struct.ec_key_st */
            	1294, 0,
            0, 0, 0, /* 1294: struct.ec_key_st */
            1, 8, 1, /* 1297: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1302, 0,
            0, 32, 2, /* 1302: struct.stack_st_fake_X509_ATTRIBUTE */
            	1309, 8,
            	86, 24,
            8884099, 8, 2, /* 1309: pointer_to_array_of_pointers_to_stack */
            	1316, 0,
            	83, 20,
            0, 8, 1, /* 1316: pointer.X509_ATTRIBUTE */
            	1321, 0,
            0, 0, 1, /* 1321: X509_ATTRIBUTE */
            	1326, 0,
            0, 24, 2, /* 1326: struct.x509_attributes_st */
            	1333, 0,
            	1347, 16,
            1, 8, 1, /* 1333: pointer.struct.asn1_object_st */
            	1338, 0,
            0, 40, 3, /* 1338: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            0, 8, 3, /* 1347: union.unknown */
            	178, 0,
            	1356, 0,
            	1535, 0,
            1, 8, 1, /* 1356: pointer.struct.stack_st_ASN1_TYPE */
            	1361, 0,
            0, 32, 2, /* 1361: struct.stack_st_fake_ASN1_TYPE */
            	1368, 8,
            	86, 24,
            8884099, 8, 2, /* 1368: pointer_to_array_of_pointers_to_stack */
            	1375, 0,
            	83, 20,
            0, 8, 1, /* 1375: pointer.ASN1_TYPE */
            	1380, 0,
            0, 0, 1, /* 1380: ASN1_TYPE */
            	1385, 0,
            0, 16, 1, /* 1385: struct.asn1_type_st */
            	1390, 8,
            0, 8, 20, /* 1390: union.unknown */
            	178, 0,
            	1433, 0,
            	1443, 0,
            	1457, 0,
            	1462, 0,
            	1467, 0,
            	1472, 0,
            	1477, 0,
            	1482, 0,
            	1487, 0,
            	1492, 0,
            	1497, 0,
            	1502, 0,
            	1507, 0,
            	1512, 0,
            	1517, 0,
            	1522, 0,
            	1433, 0,
            	1433, 0,
            	1527, 0,
            1, 8, 1, /* 1433: pointer.struct.asn1_string_st */
            	1438, 0,
            0, 24, 1, /* 1438: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1443: pointer.struct.asn1_object_st */
            	1448, 0,
            0, 40, 3, /* 1448: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1457: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1462: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1467: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1472: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1477: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1482: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1487: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1492: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1497: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1502: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1507: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1512: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1517: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1522: pointer.struct.asn1_string_st */
            	1438, 0,
            1, 8, 1, /* 1527: pointer.struct.ASN1_VALUE_st */
            	1532, 0,
            0, 0, 0, /* 1532: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1535: pointer.struct.asn1_type_st */
            	1540, 0,
            0, 16, 1, /* 1540: struct.asn1_type_st */
            	1545, 8,
            0, 8, 20, /* 1545: union.unknown */
            	178, 0,
            	1588, 0,
            	1333, 0,
            	1598, 0,
            	1603, 0,
            	1608, 0,
            	1613, 0,
            	1618, 0,
            	1623, 0,
            	1628, 0,
            	1633, 0,
            	1638, 0,
            	1643, 0,
            	1648, 0,
            	1653, 0,
            	1658, 0,
            	1663, 0,
            	1588, 0,
            	1588, 0,
            	852, 0,
            1, 8, 1, /* 1588: pointer.struct.asn1_string_st */
            	1593, 0,
            0, 24, 1, /* 1593: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1598: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1603: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1608: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1613: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1618: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1623: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1628: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1633: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1638: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1643: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1648: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1653: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1658: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1663: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1668: pointer.struct.stack_st_X509_EXTENSION */
            	1673, 0,
            0, 32, 2, /* 1673: struct.stack_st_fake_X509_EXTENSION */
            	1680, 8,
            	86, 24,
            8884099, 8, 2, /* 1680: pointer_to_array_of_pointers_to_stack */
            	1687, 0,
            	83, 20,
            0, 8, 1, /* 1687: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 1692: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 1697: pointer.struct.AUTHORITY_KEYID_st */
            	1702, 0,
            0, 0, 0, /* 1702: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1705: pointer.struct.X509_POLICY_CACHE_st */
            	1710, 0,
            0, 0, 0, /* 1710: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1713: pointer.struct.stack_st_DIST_POINT */
            	1718, 0,
            0, 32, 2, /* 1718: struct.stack_st_fake_DIST_POINT */
            	1725, 8,
            	86, 24,
            8884099, 8, 2, /* 1725: pointer_to_array_of_pointers_to_stack */
            	1732, 0,
            	83, 20,
            0, 8, 1, /* 1732: pointer.DIST_POINT */
            	1737, 0,
            0, 0, 1, /* 1737: DIST_POINT */
            	1742, 0,
            0, 32, 3, /* 1742: struct.DIST_POINT_st */
            	1751, 0,
            	2112, 8,
            	1770, 16,
            1, 8, 1, /* 1751: pointer.struct.DIST_POINT_NAME_st */
            	1756, 0,
            0, 24, 2, /* 1756: struct.DIST_POINT_NAME_st */
            	1763, 8,
            	2088, 16,
            0, 8, 2, /* 1763: union.unknown */
            	1770, 0,
            	2064, 0,
            1, 8, 1, /* 1770: pointer.struct.stack_st_GENERAL_NAME */
            	1775, 0,
            0, 32, 2, /* 1775: struct.stack_st_fake_GENERAL_NAME */
            	1782, 8,
            	86, 24,
            8884099, 8, 2, /* 1782: pointer_to_array_of_pointers_to_stack */
            	1789, 0,
            	83, 20,
            0, 8, 1, /* 1789: pointer.GENERAL_NAME */
            	1794, 0,
            0, 0, 1, /* 1794: GENERAL_NAME */
            	1799, 0,
            0, 16, 1, /* 1799: struct.GENERAL_NAME_st */
            	1804, 8,
            0, 8, 15, /* 1804: union.unknown */
            	178, 0,
            	1837, 0,
            	1956, 0,
            	1956, 0,
            	1863, 0,
            	2004, 0,
            	2052, 0,
            	1956, 0,
            	1941, 0,
            	1849, 0,
            	1941, 0,
            	2004, 0,
            	1956, 0,
            	1849, 0,
            	1863, 0,
            1, 8, 1, /* 1837: pointer.struct.otherName_st */
            	1842, 0,
            0, 16, 2, /* 1842: struct.otherName_st */
            	1849, 0,
            	1863, 8,
            1, 8, 1, /* 1849: pointer.struct.asn1_object_st */
            	1854, 0,
            0, 40, 3, /* 1854: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1863: pointer.struct.asn1_type_st */
            	1868, 0,
            0, 16, 1, /* 1868: struct.asn1_type_st */
            	1873, 8,
            0, 8, 20, /* 1873: union.unknown */
            	178, 0,
            	1916, 0,
            	1849, 0,
            	1926, 0,
            	1931, 0,
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
            	1916, 0,
            	1916, 0,
            	1996, 0,
            1, 8, 1, /* 1916: pointer.struct.asn1_string_st */
            	1921, 0,
            0, 24, 1, /* 1921: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1926: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1931: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1936: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1941: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1946: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1951: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1956: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1961: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1966: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1971: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1976: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1981: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1986: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1991: pointer.struct.asn1_string_st */
            	1921, 0,
            1, 8, 1, /* 1996: pointer.struct.ASN1_VALUE_st */
            	2001, 0,
            0, 0, 0, /* 2001: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2004: pointer.struct.X509_name_st */
            	2009, 0,
            0, 40, 3, /* 2009: struct.X509_name_st */
            	2018, 0,
            	2042, 16,
            	78, 24,
            1, 8, 1, /* 2018: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2023, 0,
            0, 32, 2, /* 2023: struct.stack_st_fake_X509_NAME_ENTRY */
            	2030, 8,
            	86, 24,
            8884099, 8, 2, /* 2030: pointer_to_array_of_pointers_to_stack */
            	2037, 0,
            	83, 20,
            0, 8, 1, /* 2037: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 2042: pointer.struct.buf_mem_st */
            	2047, 0,
            0, 24, 1, /* 2047: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 2052: pointer.struct.EDIPartyName_st */
            	2057, 0,
            0, 16, 2, /* 2057: struct.EDIPartyName_st */
            	1916, 0,
            	1916, 8,
            1, 8, 1, /* 2064: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2069, 0,
            0, 32, 2, /* 2069: struct.stack_st_fake_X509_NAME_ENTRY */
            	2076, 8,
            	86, 24,
            8884099, 8, 2, /* 2076: pointer_to_array_of_pointers_to_stack */
            	2083, 0,
            	83, 20,
            0, 8, 1, /* 2083: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 2088: pointer.struct.X509_name_st */
            	2093, 0,
            0, 40, 3, /* 2093: struct.X509_name_st */
            	2064, 0,
            	2102, 16,
            	78, 24,
            1, 8, 1, /* 2102: pointer.struct.buf_mem_st */
            	2107, 0,
            0, 24, 1, /* 2107: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 2112: pointer.struct.asn1_string_st */
            	2117, 0,
            0, 24, 1, /* 2117: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2122: pointer.struct.stack_st_GENERAL_NAME */
            	2127, 0,
            0, 32, 2, /* 2127: struct.stack_st_fake_GENERAL_NAME */
            	2134, 8,
            	86, 24,
            8884099, 8, 2, /* 2134: pointer_to_array_of_pointers_to_stack */
            	2141, 0,
            	83, 20,
            0, 8, 1, /* 2141: pointer.GENERAL_NAME */
            	1794, 0,
            1, 8, 1, /* 2146: pointer.struct.NAME_CONSTRAINTS_st */
            	2151, 0,
            0, 0, 0, /* 2151: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2154: pointer.struct.x509_cert_aux_st */
            	2159, 0,
            0, 40, 5, /* 2159: struct.x509_cert_aux_st */
            	2172, 0,
            	2172, 8,
            	847, 16,
            	797, 24,
            	2201, 32,
            1, 8, 1, /* 2172: pointer.struct.stack_st_ASN1_OBJECT */
            	2177, 0,
            0, 32, 2, /* 2177: struct.stack_st_fake_ASN1_OBJECT */
            	2184, 8,
            	86, 24,
            8884099, 8, 2, /* 2184: pointer_to_array_of_pointers_to_stack */
            	2191, 0,
            	83, 20,
            0, 8, 1, /* 2191: pointer.ASN1_OBJECT */
            	2196, 0,
            0, 0, 1, /* 2196: ASN1_OBJECT */
            	1448, 0,
            1, 8, 1, /* 2201: pointer.struct.stack_st_X509_ALGOR */
            	2206, 0,
            0, 32, 2, /* 2206: struct.stack_st_fake_X509_ALGOR */
            	2213, 8,
            	86, 24,
            8884099, 8, 2, /* 2213: pointer_to_array_of_pointers_to_stack */
            	2220, 0,
            	83, 20,
            0, 8, 1, /* 2220: pointer.X509_ALGOR */
            	2225, 0,
            0, 0, 1, /* 2225: X509_ALGOR */
            	2230, 0,
            0, 16, 2, /* 2230: struct.X509_algor_st */
            	2237, 0,
            	2251, 8,
            1, 8, 1, /* 2237: pointer.struct.asn1_object_st */
            	2242, 0,
            0, 40, 3, /* 2242: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2251: pointer.struct.asn1_type_st */
            	2256, 0,
            0, 16, 1, /* 2256: struct.asn1_type_st */
            	2261, 8,
            0, 8, 20, /* 2261: union.unknown */
            	178, 0,
            	2304, 0,
            	2237, 0,
            	2314, 0,
            	2319, 0,
            	2324, 0,
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
            	2304, 0,
            	2304, 0,
            	852, 0,
            1, 8, 1, /* 2304: pointer.struct.asn1_string_st */
            	2309, 0,
            0, 24, 1, /* 2309: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2314: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2319: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2324: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2329: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2334: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2339: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2344: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2349: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2354: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2359: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2364: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2369: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2374: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2379: pointer.struct.asn1_string_st */
            	2309, 0,
            1, 8, 1, /* 2384: pointer.struct.X509_crl_st */
            	2389, 0,
            0, 120, 10, /* 2389: struct.X509_crl_st */
            	2412, 0,
            	703, 8,
            	792, 16,
            	1697, 32,
            	2539, 40,
            	693, 56,
            	693, 64,
            	2547, 96,
            	2588, 104,
            	273, 112,
            1, 8, 1, /* 2412: pointer.struct.X509_crl_info_st */
            	2417, 0,
            0, 80, 8, /* 2417: struct.X509_crl_info_st */
            	693, 0,
            	703, 8,
            	860, 16,
            	920, 24,
            	920, 32,
            	2436, 40,
            	1668, 48,
            	1692, 56,
            1, 8, 1, /* 2436: pointer.struct.stack_st_X509_REVOKED */
            	2441, 0,
            0, 32, 2, /* 2441: struct.stack_st_fake_X509_REVOKED */
            	2448, 8,
            	86, 24,
            8884099, 8, 2, /* 2448: pointer_to_array_of_pointers_to_stack */
            	2455, 0,
            	83, 20,
            0, 8, 1, /* 2455: pointer.X509_REVOKED */
            	2460, 0,
            0, 0, 1, /* 2460: X509_REVOKED */
            	2465, 0,
            0, 40, 4, /* 2465: struct.x509_revoked_st */
            	2476, 0,
            	2486, 8,
            	2491, 16,
            	2515, 24,
            1, 8, 1, /* 2476: pointer.struct.asn1_string_st */
            	2481, 0,
            0, 24, 1, /* 2481: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2486: pointer.struct.asn1_string_st */
            	2481, 0,
            1, 8, 1, /* 2491: pointer.struct.stack_st_X509_EXTENSION */
            	2496, 0,
            0, 32, 2, /* 2496: struct.stack_st_fake_X509_EXTENSION */
            	2503, 8,
            	86, 24,
            8884099, 8, 2, /* 2503: pointer_to_array_of_pointers_to_stack */
            	2510, 0,
            	83, 20,
            0, 8, 1, /* 2510: pointer.X509_EXTENSION */
            	34, 0,
            1, 8, 1, /* 2515: pointer.struct.stack_st_GENERAL_NAME */
            	2520, 0,
            0, 32, 2, /* 2520: struct.stack_st_fake_GENERAL_NAME */
            	2527, 8,
            	86, 24,
            8884099, 8, 2, /* 2527: pointer_to_array_of_pointers_to_stack */
            	2534, 0,
            	83, 20,
            0, 8, 1, /* 2534: pointer.GENERAL_NAME */
            	1794, 0,
            1, 8, 1, /* 2539: pointer.struct.ISSUING_DIST_POINT_st */
            	2544, 0,
            0, 0, 0, /* 2544: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2547: pointer.struct.stack_st_GENERAL_NAMES */
            	2552, 0,
            0, 32, 2, /* 2552: struct.stack_st_fake_GENERAL_NAMES */
            	2559, 8,
            	86, 24,
            8884099, 8, 2, /* 2559: pointer_to_array_of_pointers_to_stack */
            	2566, 0,
            	83, 20,
            0, 8, 1, /* 2566: pointer.GENERAL_NAMES */
            	2571, 0,
            0, 0, 1, /* 2571: GENERAL_NAMES */
            	2576, 0,
            0, 32, 1, /* 2576: struct.stack_st_GENERAL_NAME */
            	2581, 0,
            0, 32, 2, /* 2581: struct.stack_st */
            	1113, 8,
            	86, 24,
            1, 8, 1, /* 2588: pointer.struct.x509_crl_method_st */
            	2593, 0,
            0, 0, 0, /* 2593: struct.x509_crl_method_st */
            1, 8, 1, /* 2596: pointer.struct.X509_VERIFY_PARAM_st */
            	2601, 0,
            0, 56, 2, /* 2601: struct.X509_VERIFY_PARAM_st */
            	178, 0,
            	2172, 48,
            8884097, 8, 0, /* 2608: pointer.func */
            8884097, 8, 0, /* 2611: pointer.func */
            0, 16, 1, /* 2614: struct.tls_session_ticket_ext_st */
            	273, 8,
            1, 8, 1, /* 2619: pointer.struct.tls_session_ticket_ext_st */
            	2614, 0,
            8884097, 8, 0, /* 2624: pointer.func */
            8884097, 8, 0, /* 2627: pointer.func */
            0, 56, 4, /* 2630: struct.evp_pkey_st */
            	2641, 16,
            	2649, 24,
            	2657, 32,
            	2978, 48,
            1, 8, 1, /* 2641: pointer.struct.evp_pkey_asn1_method_st */
            	2646, 0,
            0, 0, 0, /* 2646: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2649: pointer.struct.engine_st */
            	2654, 0,
            0, 0, 0, /* 2654: struct.engine_st */
            0, 8, 5, /* 2657: union.unknown */
            	178, 0,
            	2670, 0,
            	2821, 0,
            	2902, 0,
            	2970, 0,
            1, 8, 1, /* 2670: pointer.struct.rsa_st */
            	2675, 0,
            0, 168, 17, /* 2675: struct.rsa_st */
            	2712, 16,
            	2649, 24,
            	2767, 32,
            	2767, 40,
            	2767, 48,
            	2767, 56,
            	2767, 64,
            	2767, 72,
            	2767, 80,
            	2767, 88,
            	2777, 96,
            	2799, 120,
            	2799, 128,
            	2799, 136,
            	178, 144,
            	2813, 152,
            	2813, 160,
            1, 8, 1, /* 2712: pointer.struct.rsa_meth_st */
            	2717, 0,
            0, 112, 13, /* 2717: struct.rsa_meth_st */
            	5, 0,
            	2746, 8,
            	2746, 16,
            	2746, 24,
            	2746, 32,
            	2749, 40,
            	2752, 48,
            	2755, 56,
            	2755, 64,
            	178, 80,
            	2758, 88,
            	2761, 96,
            	2764, 104,
            8884097, 8, 0, /* 2746: pointer.func */
            8884097, 8, 0, /* 2749: pointer.func */
            8884097, 8, 0, /* 2752: pointer.func */
            8884097, 8, 0, /* 2755: pointer.func */
            8884097, 8, 0, /* 2758: pointer.func */
            8884097, 8, 0, /* 2761: pointer.func */
            8884097, 8, 0, /* 2764: pointer.func */
            1, 8, 1, /* 2767: pointer.struct.bignum_st */
            	2772, 0,
            0, 24, 1, /* 2772: struct.bignum_st */
            	295, 0,
            0, 16, 1, /* 2777: struct.crypto_ex_data_st */
            	2782, 0,
            1, 8, 1, /* 2782: pointer.struct.stack_st_void */
            	2787, 0,
            0, 32, 1, /* 2787: struct.stack_st_void */
            	2792, 0,
            0, 32, 2, /* 2792: struct.stack_st */
            	1113, 8,
            	86, 24,
            1, 8, 1, /* 2799: pointer.struct.bn_mont_ctx_st */
            	2804, 0,
            0, 96, 3, /* 2804: struct.bn_mont_ctx_st */
            	2772, 8,
            	2772, 32,
            	2772, 56,
            1, 8, 1, /* 2813: pointer.struct.bn_blinding_st */
            	2818, 0,
            0, 0, 0, /* 2818: struct.bn_blinding_st */
            1, 8, 1, /* 2821: pointer.struct.dsa_st */
            	2826, 0,
            0, 136, 11, /* 2826: struct.dsa_st */
            	2767, 24,
            	2767, 32,
            	2767, 40,
            	2767, 48,
            	2767, 56,
            	2767, 64,
            	2767, 72,
            	2799, 88,
            	2777, 104,
            	2851, 120,
            	2649, 128,
            1, 8, 1, /* 2851: pointer.struct.dsa_method */
            	2856, 0,
            0, 96, 11, /* 2856: struct.dsa_method */
            	5, 0,
            	2881, 8,
            	2884, 16,
            	2887, 24,
            	2890, 32,
            	2893, 40,
            	2896, 48,
            	2896, 56,
            	178, 72,
            	2899, 80,
            	2896, 88,
            8884097, 8, 0, /* 2881: pointer.func */
            8884097, 8, 0, /* 2884: pointer.func */
            8884097, 8, 0, /* 2887: pointer.func */
            8884097, 8, 0, /* 2890: pointer.func */
            8884097, 8, 0, /* 2893: pointer.func */
            8884097, 8, 0, /* 2896: pointer.func */
            8884097, 8, 0, /* 2899: pointer.func */
            1, 8, 1, /* 2902: pointer.struct.dh_st */
            	2907, 0,
            0, 144, 12, /* 2907: struct.dh_st */
            	2767, 8,
            	2767, 16,
            	2767, 32,
            	2767, 40,
            	2799, 56,
            	2767, 64,
            	2767, 72,
            	78, 80,
            	2767, 96,
            	2777, 112,
            	2934, 128,
            	2649, 136,
            1, 8, 1, /* 2934: pointer.struct.dh_method */
            	2939, 0,
            0, 72, 8, /* 2939: struct.dh_method */
            	5, 0,
            	2958, 8,
            	2961, 16,
            	2964, 24,
            	2958, 32,
            	2958, 40,
            	178, 56,
            	2967, 64,
            8884097, 8, 0, /* 2958: pointer.func */
            8884097, 8, 0, /* 2961: pointer.func */
            8884097, 8, 0, /* 2964: pointer.func */
            8884097, 8, 0, /* 2967: pointer.func */
            1, 8, 1, /* 2970: pointer.struct.ec_key_st */
            	2975, 0,
            0, 0, 0, /* 2975: struct.ec_key_st */
            1, 8, 1, /* 2978: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2983, 0,
            0, 32, 2, /* 2983: struct.stack_st_fake_X509_ATTRIBUTE */
            	2990, 8,
            	86, 24,
            8884099, 8, 2, /* 2990: pointer_to_array_of_pointers_to_stack */
            	2997, 0,
            	83, 20,
            0, 8, 1, /* 2997: pointer.X509_ATTRIBUTE */
            	1321, 0,
            1, 8, 1, /* 3002: pointer.struct.stack_st_X509_LOOKUP */
            	3007, 0,
            0, 32, 2, /* 3007: struct.stack_st_fake_X509_LOOKUP */
            	3014, 8,
            	86, 24,
            8884099, 8, 2, /* 3014: pointer_to_array_of_pointers_to_stack */
            	3021, 0,
            	83, 20,
            0, 8, 1, /* 3021: pointer.X509_LOOKUP */
            	485, 0,
            1, 8, 1, /* 3026: pointer.struct.stack_st_X509_ALGOR */
            	3031, 0,
            0, 32, 2, /* 3031: struct.stack_st_fake_X509_ALGOR */
            	3038, 8,
            	86, 24,
            8884099, 8, 2, /* 3038: pointer_to_array_of_pointers_to_stack */
            	3045, 0,
            	83, 20,
            0, 8, 1, /* 3045: pointer.X509_ALGOR */
            	2225, 0,
            1, 8, 1, /* 3050: pointer.struct.stack_st_ASN1_OBJECT */
            	3055, 0,
            0, 32, 2, /* 3055: struct.stack_st_fake_ASN1_OBJECT */
            	3062, 8,
            	86, 24,
            8884099, 8, 2, /* 3062: pointer_to_array_of_pointers_to_stack */
            	3069, 0,
            	83, 20,
            0, 8, 1, /* 3069: pointer.ASN1_OBJECT */
            	2196, 0,
            8884097, 8, 0, /* 3074: pointer.func */
            1, 8, 1, /* 3077: pointer.struct.x509_cert_aux_st */
            	3082, 0,
            0, 40, 5, /* 3082: struct.x509_cert_aux_st */
            	3050, 0,
            	3050, 8,
            	3095, 16,
            	3105, 24,
            	3026, 32,
            1, 8, 1, /* 3095: pointer.struct.asn1_string_st */
            	3100, 0,
            0, 24, 1, /* 3100: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 3105: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3110: pointer.struct.ASN1_VALUE_st */
            	3115, 0,
            0, 0, 0, /* 3115: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3118: pointer.struct.GENERAL_NAME_st */
            	1799, 0,
            8884097, 8, 0, /* 3123: pointer.func */
            1, 8, 1, /* 3126: pointer.struct.stack_st_ASN1_OBJECT */
            	3131, 0,
            0, 32, 2, /* 3131: struct.stack_st_fake_ASN1_OBJECT */
            	3138, 8,
            	86, 24,
            8884099, 8, 2, /* 3138: pointer_to_array_of_pointers_to_stack */
            	3145, 0,
            	83, 20,
            0, 8, 1, /* 3145: pointer.ASN1_OBJECT */
            	2196, 0,
            0, 72, 8, /* 3150: struct.dh_method */
            	5, 0,
            	3169, 8,
            	3172, 16,
            	3175, 24,
            	3169, 32,
            	3169, 40,
            	178, 56,
            	3178, 64,
            8884097, 8, 0, /* 3169: pointer.func */
            8884097, 8, 0, /* 3172: pointer.func */
            8884097, 8, 0, /* 3175: pointer.func */
            8884097, 8, 0, /* 3178: pointer.func */
            0, 16, 2, /* 3181: struct.X509_val_st */
            	3188, 0,
            	3188, 8,
            1, 8, 1, /* 3188: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3193: pointer.struct.asn1_string_st */
            	3198, 0,
            0, 24, 1, /* 3198: struct.asn1_string_st */
            	78, 8,
            8884097, 8, 0, /* 3203: pointer.func */
            1, 8, 1, /* 3206: pointer.struct.buf_mem_st */
            	3211, 0,
            0, 24, 1, /* 3211: struct.buf_mem_st */
            	178, 8,
            0, 296, 7, /* 3216: struct.cert_st */
            	3233, 0,
            	4079, 48,
            	4084, 56,
            	4087, 64,
            	4092, 72,
            	4095, 80,
            	4100, 88,
            1, 8, 1, /* 3233: pointer.struct.cert_pkey_st */
            	3238, 0,
            0, 24, 3, /* 3238: struct.cert_pkey_st */
            	3247, 0,
            	3528, 8,
            	4034, 16,
            1, 8, 1, /* 3247: pointer.struct.x509_st */
            	3252, 0,
            0, 184, 12, /* 3252: struct.x509_st */
            	3279, 0,
            	3314, 8,
            	3403, 16,
            	178, 32,
            	3667, 40,
            	3105, 104,
            	3890, 112,
            	3928, 120,
            	3936, 128,
            	3960, 136,
            	3984, 144,
            	3077, 176,
            1, 8, 1, /* 3279: pointer.struct.x509_cinf_st */
            	3284, 0,
            0, 104, 11, /* 3284: struct.x509_cinf_st */
            	3309, 0,
            	3309, 8,
            	3314, 16,
            	3461, 24,
            	3509, 32,
            	3461, 40,
            	3514, 48,
            	3403, 56,
            	3403, 64,
            	3861, 72,
            	3885, 80,
            1, 8, 1, /* 3309: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3314: pointer.struct.X509_algor_st */
            	3319, 0,
            0, 16, 2, /* 3319: struct.X509_algor_st */
            	3326, 0,
            	3340, 8,
            1, 8, 1, /* 3326: pointer.struct.asn1_object_st */
            	3331, 0,
            0, 40, 3, /* 3331: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 3340: pointer.struct.asn1_type_st */
            	3345, 0,
            0, 16, 1, /* 3345: struct.asn1_type_st */
            	3350, 8,
            0, 8, 20, /* 3350: union.unknown */
            	178, 0,
            	3393, 0,
            	3326, 0,
            	3309, 0,
            	3398, 0,
            	3403, 0,
            	3105, 0,
            	3408, 0,
            	3413, 0,
            	3418, 0,
            	3423, 0,
            	3428, 0,
            	3433, 0,
            	3438, 0,
            	3443, 0,
            	3448, 0,
            	3095, 0,
            	3393, 0,
            	3393, 0,
            	3453, 0,
            1, 8, 1, /* 3393: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3398: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3403: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3408: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3413: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3418: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3423: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3428: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3433: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3438: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3443: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3448: pointer.struct.asn1_string_st */
            	3100, 0,
            1, 8, 1, /* 3453: pointer.struct.ASN1_VALUE_st */
            	3458, 0,
            0, 0, 0, /* 3458: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3461: pointer.struct.X509_name_st */
            	3466, 0,
            0, 40, 3, /* 3466: struct.X509_name_st */
            	3475, 0,
            	3499, 16,
            	78, 24,
            1, 8, 1, /* 3475: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3480, 0,
            0, 32, 2, /* 3480: struct.stack_st_fake_X509_NAME_ENTRY */
            	3487, 8,
            	86, 24,
            8884099, 8, 2, /* 3487: pointer_to_array_of_pointers_to_stack */
            	3494, 0,
            	83, 20,
            0, 8, 1, /* 3494: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 3499: pointer.struct.buf_mem_st */
            	3504, 0,
            0, 24, 1, /* 3504: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 3509: pointer.struct.X509_val_st */
            	3181, 0,
            1, 8, 1, /* 3514: pointer.struct.X509_pubkey_st */
            	3519, 0,
            0, 24, 3, /* 3519: struct.X509_pubkey_st */
            	3314, 0,
            	3403, 8,
            	3528, 16,
            1, 8, 1, /* 3528: pointer.struct.evp_pkey_st */
            	3533, 0,
            0, 56, 4, /* 3533: struct.evp_pkey_st */
            	3544, 16,
            	3552, 24,
            	3560, 32,
            	3837, 48,
            1, 8, 1, /* 3544: pointer.struct.evp_pkey_asn1_method_st */
            	3549, 0,
            0, 0, 0, /* 3549: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3552: pointer.struct.engine_st */
            	3557, 0,
            0, 0, 0, /* 3557: struct.engine_st */
            0, 8, 5, /* 3560: union.unknown */
            	178, 0,
            	3573, 0,
            	3711, 0,
            	3792, 0,
            	3829, 0,
            1, 8, 1, /* 3573: pointer.struct.rsa_st */
            	3578, 0,
            0, 168, 17, /* 3578: struct.rsa_st */
            	3615, 16,
            	3552, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	3667, 96,
            	3689, 120,
            	3689, 128,
            	3689, 136,
            	178, 144,
            	3703, 152,
            	3703, 160,
            1, 8, 1, /* 3615: pointer.struct.rsa_meth_st */
            	3620, 0,
            0, 112, 13, /* 3620: struct.rsa_meth_st */
            	5, 0,
            	3649, 8,
            	3649, 16,
            	3649, 24,
            	3649, 32,
            	3652, 40,
            	3655, 48,
            	3074, 56,
            	3074, 64,
            	178, 80,
            	3658, 88,
            	3661, 96,
            	3664, 104,
            8884097, 8, 0, /* 3649: pointer.func */
            8884097, 8, 0, /* 3652: pointer.func */
            8884097, 8, 0, /* 3655: pointer.func */
            8884097, 8, 0, /* 3658: pointer.func */
            8884097, 8, 0, /* 3661: pointer.func */
            8884097, 8, 0, /* 3664: pointer.func */
            0, 16, 1, /* 3667: struct.crypto_ex_data_st */
            	3672, 0,
            1, 8, 1, /* 3672: pointer.struct.stack_st_void */
            	3677, 0,
            0, 32, 1, /* 3677: struct.stack_st_void */
            	3682, 0,
            0, 32, 2, /* 3682: struct.stack_st */
            	1113, 8,
            	86, 24,
            1, 8, 1, /* 3689: pointer.struct.bn_mont_ctx_st */
            	3694, 0,
            0, 96, 3, /* 3694: struct.bn_mont_ctx_st */
            	290, 8,
            	290, 32,
            	290, 56,
            1, 8, 1, /* 3703: pointer.struct.bn_blinding_st */
            	3708, 0,
            0, 0, 0, /* 3708: struct.bn_blinding_st */
            1, 8, 1, /* 3711: pointer.struct.dsa_st */
            	3716, 0,
            0, 136, 11, /* 3716: struct.dsa_st */
            	285, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	3689, 88,
            	3667, 104,
            	3741, 120,
            	3552, 128,
            1, 8, 1, /* 3741: pointer.struct.dsa_method */
            	3746, 0,
            0, 96, 11, /* 3746: struct.dsa_method */
            	5, 0,
            	3771, 8,
            	3774, 16,
            	3777, 24,
            	3780, 32,
            	3783, 40,
            	3786, 48,
            	3786, 56,
            	178, 72,
            	3789, 80,
            	3786, 88,
            8884097, 8, 0, /* 3771: pointer.func */
            8884097, 8, 0, /* 3774: pointer.func */
            8884097, 8, 0, /* 3777: pointer.func */
            8884097, 8, 0, /* 3780: pointer.func */
            8884097, 8, 0, /* 3783: pointer.func */
            8884097, 8, 0, /* 3786: pointer.func */
            8884097, 8, 0, /* 3789: pointer.func */
            1, 8, 1, /* 3792: pointer.struct.dh_st */
            	3797, 0,
            0, 144, 12, /* 3797: struct.dh_st */
            	285, 8,
            	285, 16,
            	285, 32,
            	285, 40,
            	3689, 56,
            	285, 64,
            	285, 72,
            	78, 80,
            	285, 96,
            	3667, 112,
            	3824, 128,
            	3552, 136,
            1, 8, 1, /* 3824: pointer.struct.dh_method */
            	3150, 0,
            1, 8, 1, /* 3829: pointer.struct.ec_key_st */
            	3834, 0,
            0, 0, 0, /* 3834: struct.ec_key_st */
            1, 8, 1, /* 3837: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3842, 0,
            0, 32, 2, /* 3842: struct.stack_st_fake_X509_ATTRIBUTE */
            	3849, 8,
            	86, 24,
            8884099, 8, 2, /* 3849: pointer_to_array_of_pointers_to_stack */
            	3856, 0,
            	83, 20,
            0, 8, 1, /* 3856: pointer.X509_ATTRIBUTE */
            	1321, 0,
            1, 8, 1, /* 3861: pointer.struct.stack_st_X509_EXTENSION */
            	3866, 0,
            0, 32, 2, /* 3866: struct.stack_st_fake_X509_EXTENSION */
            	3873, 8,
            	86, 24,
            8884099, 8, 2, /* 3873: pointer_to_array_of_pointers_to_stack */
            	3880, 0,
            	83, 20,
            0, 8, 1, /* 3880: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 3885: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 3890: pointer.struct.AUTHORITY_KEYID_st */
            	3895, 0,
            0, 24, 3, /* 3895: struct.AUTHORITY_KEYID_st */
            	3105, 0,
            	3904, 8,
            	3309, 16,
            1, 8, 1, /* 3904: pointer.struct.stack_st_GENERAL_NAME */
            	3909, 0,
            0, 32, 2, /* 3909: struct.stack_st_fake_GENERAL_NAME */
            	3916, 8,
            	86, 24,
            8884099, 8, 2, /* 3916: pointer_to_array_of_pointers_to_stack */
            	3923, 0,
            	83, 20,
            0, 8, 1, /* 3923: pointer.GENERAL_NAME */
            	1794, 0,
            1, 8, 1, /* 3928: pointer.struct.X509_POLICY_CACHE_st */
            	3933, 0,
            0, 0, 0, /* 3933: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3936: pointer.struct.stack_st_DIST_POINT */
            	3941, 0,
            0, 32, 2, /* 3941: struct.stack_st_fake_DIST_POINT */
            	3948, 8,
            	86, 24,
            8884099, 8, 2, /* 3948: pointer_to_array_of_pointers_to_stack */
            	3955, 0,
            	83, 20,
            0, 8, 1, /* 3955: pointer.DIST_POINT */
            	1737, 0,
            1, 8, 1, /* 3960: pointer.struct.stack_st_GENERAL_NAME */
            	3965, 0,
            0, 32, 2, /* 3965: struct.stack_st_fake_GENERAL_NAME */
            	3972, 8,
            	86, 24,
            8884099, 8, 2, /* 3972: pointer_to_array_of_pointers_to_stack */
            	3979, 0,
            	83, 20,
            0, 8, 1, /* 3979: pointer.GENERAL_NAME */
            	1794, 0,
            1, 8, 1, /* 3984: pointer.struct.NAME_CONSTRAINTS_st */
            	3989, 0,
            0, 16, 2, /* 3989: struct.NAME_CONSTRAINTS_st */
            	3996, 0,
            	3996, 8,
            1, 8, 1, /* 3996: pointer.struct.stack_st_GENERAL_SUBTREE */
            	4001, 0,
            0, 32, 2, /* 4001: struct.stack_st_fake_GENERAL_SUBTREE */
            	4008, 8,
            	86, 24,
            8884099, 8, 2, /* 4008: pointer_to_array_of_pointers_to_stack */
            	4015, 0,
            	83, 20,
            0, 8, 1, /* 4015: pointer.GENERAL_SUBTREE */
            	4020, 0,
            0, 0, 1, /* 4020: GENERAL_SUBTREE */
            	4025, 0,
            0, 24, 3, /* 4025: struct.GENERAL_SUBTREE_st */
            	3118, 0,
            	1926, 8,
            	1926, 16,
            1, 8, 1, /* 4034: pointer.struct.env_md_st */
            	4039, 0,
            0, 120, 8, /* 4039: struct.env_md_st */
            	4058, 24,
            	4061, 32,
            	4064, 40,
            	4067, 48,
            	4058, 56,
            	4070, 64,
            	4073, 72,
            	4076, 112,
            8884097, 8, 0, /* 4058: pointer.func */
            8884097, 8, 0, /* 4061: pointer.func */
            8884097, 8, 0, /* 4064: pointer.func */
            8884097, 8, 0, /* 4067: pointer.func */
            8884097, 8, 0, /* 4070: pointer.func */
            8884097, 8, 0, /* 4073: pointer.func */
            8884097, 8, 0, /* 4076: pointer.func */
            1, 8, 1, /* 4079: pointer.struct.rsa_st */
            	3578, 0,
            8884097, 8, 0, /* 4084: pointer.func */
            1, 8, 1, /* 4087: pointer.struct.dh_st */
            	3797, 0,
            8884097, 8, 0, /* 4092: pointer.func */
            1, 8, 1, /* 4095: pointer.struct.ec_key_st */
            	3834, 0,
            8884097, 8, 0, /* 4100: pointer.func */
            0, 0, 0, /* 4103: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 4106: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4111, 0,
            0, 32, 2, /* 4111: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4118, 8,
            	86, 24,
            8884099, 8, 2, /* 4118: pointer_to_array_of_pointers_to_stack */
            	4125, 0,
            	83, 20,
            0, 8, 1, /* 4125: pointer.SRTP_PROTECTION_PROFILE */
            	229, 0,
            8884097, 8, 0, /* 4130: pointer.func */
            8884097, 8, 0, /* 4133: pointer.func */
            8884097, 8, 0, /* 4136: pointer.func */
            1, 8, 1, /* 4139: pointer.struct.X509_pubkey_st */
            	4144, 0,
            0, 24, 3, /* 4144: struct.X509_pubkey_st */
            	4153, 0,
            	4247, 8,
            	4302, 16,
            1, 8, 1, /* 4153: pointer.struct.X509_algor_st */
            	4158, 0,
            0, 16, 2, /* 4158: struct.X509_algor_st */
            	4165, 0,
            	4179, 8,
            1, 8, 1, /* 4165: pointer.struct.asn1_object_st */
            	4170, 0,
            0, 40, 3, /* 4170: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 4179: pointer.struct.asn1_type_st */
            	4184, 0,
            0, 16, 1, /* 4184: struct.asn1_type_st */
            	4189, 8,
            0, 8, 20, /* 4189: union.unknown */
            	178, 0,
            	4232, 0,
            	4165, 0,
            	4237, 0,
            	4242, 0,
            	4247, 0,
            	4252, 0,
            	4257, 0,
            	4262, 0,
            	4267, 0,
            	4272, 0,
            	4277, 0,
            	4282, 0,
            	4287, 0,
            	4292, 0,
            	4297, 0,
            	3193, 0,
            	4232, 0,
            	4232, 0,
            	3110, 0,
            1, 8, 1, /* 4232: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4237: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4242: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4247: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4252: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4257: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4262: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4267: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4272: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4277: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4282: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4287: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4292: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4297: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4302: pointer.struct.evp_pkey_st */
            	2630, 0,
            8884097, 8, 0, /* 4307: pointer.func */
            0, 184, 12, /* 4310: struct.x509_st */
            	4337, 0,
            	4153, 8,
            	4247, 16,
            	178, 32,
            	2777, 40,
            	4252, 104,
            	4461, 112,
            	4469, 120,
            	4477, 128,
            	4501, 136,
            	4525, 144,
            	4533, 176,
            1, 8, 1, /* 4337: pointer.struct.x509_cinf_st */
            	4342, 0,
            0, 104, 11, /* 4342: struct.x509_cinf_st */
            	4237, 0,
            	4237, 8,
            	4153, 16,
            	4367, 24,
            	4415, 32,
            	4367, 40,
            	4139, 48,
            	4247, 56,
            	4247, 64,
            	4432, 72,
            	4456, 80,
            1, 8, 1, /* 4367: pointer.struct.X509_name_st */
            	4372, 0,
            0, 40, 3, /* 4372: struct.X509_name_st */
            	4381, 0,
            	4405, 16,
            	78, 24,
            1, 8, 1, /* 4381: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4386, 0,
            0, 32, 2, /* 4386: struct.stack_st_fake_X509_NAME_ENTRY */
            	4393, 8,
            	86, 24,
            8884099, 8, 2, /* 4393: pointer_to_array_of_pointers_to_stack */
            	4400, 0,
            	83, 20,
            0, 8, 1, /* 4400: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 4405: pointer.struct.buf_mem_st */
            	4410, 0,
            0, 24, 1, /* 4410: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 4415: pointer.struct.X509_val_st */
            	4420, 0,
            0, 16, 2, /* 4420: struct.X509_val_st */
            	4427, 0,
            	4427, 8,
            1, 8, 1, /* 4427: pointer.struct.asn1_string_st */
            	3198, 0,
            1, 8, 1, /* 4432: pointer.struct.stack_st_X509_EXTENSION */
            	4437, 0,
            0, 32, 2, /* 4437: struct.stack_st_fake_X509_EXTENSION */
            	4444, 8,
            	86, 24,
            8884099, 8, 2, /* 4444: pointer_to_array_of_pointers_to_stack */
            	4451, 0,
            	83, 20,
            0, 8, 1, /* 4451: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 4456: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 4461: pointer.struct.AUTHORITY_KEYID_st */
            	4466, 0,
            0, 0, 0, /* 4466: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4469: pointer.struct.X509_POLICY_CACHE_st */
            	4474, 0,
            0, 0, 0, /* 4474: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4477: pointer.struct.stack_st_DIST_POINT */
            	4482, 0,
            0, 32, 2, /* 4482: struct.stack_st_fake_DIST_POINT */
            	4489, 8,
            	86, 24,
            8884099, 8, 2, /* 4489: pointer_to_array_of_pointers_to_stack */
            	4496, 0,
            	83, 20,
            0, 8, 1, /* 4496: pointer.DIST_POINT */
            	1737, 0,
            1, 8, 1, /* 4501: pointer.struct.stack_st_GENERAL_NAME */
            	4506, 0,
            0, 32, 2, /* 4506: struct.stack_st_fake_GENERAL_NAME */
            	4513, 8,
            	86, 24,
            8884099, 8, 2, /* 4513: pointer_to_array_of_pointers_to_stack */
            	4520, 0,
            	83, 20,
            0, 8, 1, /* 4520: pointer.GENERAL_NAME */
            	1794, 0,
            1, 8, 1, /* 4525: pointer.struct.NAME_CONSTRAINTS_st */
            	4530, 0,
            0, 0, 0, /* 4530: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4533: pointer.struct.x509_cert_aux_st */
            	4538, 0,
            0, 40, 5, /* 4538: struct.x509_cert_aux_st */
            	3126, 0,
            	3126, 8,
            	3193, 16,
            	4252, 24,
            	4551, 32,
            1, 8, 1, /* 4551: pointer.struct.stack_st_X509_ALGOR */
            	4556, 0,
            0, 32, 2, /* 4556: struct.stack_st_fake_X509_ALGOR */
            	4563, 8,
            	86, 24,
            8884099, 8, 2, /* 4563: pointer_to_array_of_pointers_to_stack */
            	4570, 0,
            	83, 20,
            0, 8, 1, /* 4570: pointer.X509_ALGOR */
            	2225, 0,
            8884097, 8, 0, /* 4575: pointer.func */
            1, 8, 1, /* 4578: pointer.struct.ssl_session_st */
            	4583, 0,
            0, 352, 14, /* 4583: struct.ssl_session_st */
            	178, 144,
            	178, 152,
            	4614, 168,
            	3247, 176,
            	4661, 224,
            	4671, 240,
            	3667, 248,
            	4578, 264,
            	4578, 272,
            	178, 280,
            	78, 296,
            	78, 312,
            	78, 320,
            	178, 344,
            1, 8, 1, /* 4614: pointer.struct.sess_cert_st */
            	4619, 0,
            0, 248, 5, /* 4619: struct.sess_cert_st */
            	4632, 0,
            	3233, 16,
            	4079, 216,
            	4087, 224,
            	4095, 232,
            1, 8, 1, /* 4632: pointer.struct.stack_st_X509 */
            	4637, 0,
            0, 32, 2, /* 4637: struct.stack_st_fake_X509 */
            	4644, 8,
            	86, 24,
            8884099, 8, 2, /* 4644: pointer_to_array_of_pointers_to_stack */
            	4651, 0,
            	83, 20,
            0, 8, 1, /* 4651: pointer.X509 */
            	4656, 0,
            0, 0, 1, /* 4656: X509 */
            	4310, 0,
            1, 8, 1, /* 4661: pointer.struct.ssl_cipher_st */
            	4666, 0,
            0, 88, 1, /* 4666: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4671: pointer.struct.stack_st_SSL_CIPHER */
            	4676, 0,
            0, 32, 2, /* 4676: struct.stack_st_fake_SSL_CIPHER */
            	4683, 8,
            	86, 24,
            8884099, 8, 2, /* 4683: pointer_to_array_of_pointers_to_stack */
            	4690, 0,
            	83, 20,
            0, 8, 1, /* 4690: pointer.SSL_CIPHER */
            	4695, 0,
            0, 0, 1, /* 4695: SSL_CIPHER */
            	4700, 0,
            0, 88, 1, /* 4700: struct.ssl_cipher_st */
            	5, 8,
            8884097, 8, 0, /* 4705: pointer.func */
            0, 0, 0, /* 4708: struct._pqueue */
            0, 1, 0, /* 4711: char */
            8884097, 8, 0, /* 4714: pointer.func */
            8884097, 8, 0, /* 4717: pointer.func */
            1, 8, 1, /* 4720: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4725, 0,
            0, 32, 2, /* 4725: struct.stack_st_fake_X509_NAME_ENTRY */
            	4732, 8,
            	86, 24,
            8884099, 8, 2, /* 4732: pointer_to_array_of_pointers_to_stack */
            	4739, 0,
            	83, 20,
            0, 8, 1, /* 4739: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 4744: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            8884097, 8, 0, /* 4749: pointer.func */
            8884097, 8, 0, /* 4752: pointer.func */
            0, 16, 1, /* 4755: struct.record_pqueue_st */
            	4760, 8,
            1, 8, 1, /* 4760: pointer.struct._pqueue */
            	4708, 0,
            1, 8, 1, /* 4765: pointer.struct.ssl_session_st */
            	4583, 0,
            1, 8, 1, /* 4770: pointer.struct.X509_VERIFY_PARAM_st */
            	4775, 0,
            0, 56, 2, /* 4775: struct.X509_VERIFY_PARAM_st */
            	178, 0,
            	3050, 48,
            8884097, 8, 0, /* 4782: pointer.func */
            0, 80, 9, /* 4785: struct.bio_method_st */
            	5, 8,
            	4806, 16,
            	4136, 24,
            	4809, 32,
            	4136, 40,
            	4812, 48,
            	4815, 56,
            	4815, 64,
            	4818, 72,
            8884097, 8, 0, /* 4806: pointer.func */
            8884097, 8, 0, /* 4809: pointer.func */
            8884097, 8, 0, /* 4812: pointer.func */
            8884097, 8, 0, /* 4815: pointer.func */
            8884097, 8, 0, /* 4818: pointer.func */
            8884097, 8, 0, /* 4821: pointer.func */
            8884097, 8, 0, /* 4824: pointer.func */
            1, 8, 1, /* 4827: pointer.struct.ssl2_state_st */
            	4832, 0,
            0, 344, 9, /* 4832: struct.ssl2_state_st */
            	60, 24,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 104,
            	78, 112,
            	78, 120,
            	78, 128,
            	78, 136,
            8884097, 8, 0, /* 4853: pointer.func */
            1, 8, 1, /* 4856: pointer.struct.ssl_st */
            	4861, 0,
            0, 808, 51, /* 4861: struct.ssl_st */
            	4966, 8,
            	5105, 16,
            	5105, 24,
            	5105, 32,
            	5030, 48,
            	3499, 80,
            	273, 88,
            	78, 104,
            	4827, 120,
            	5137, 128,
            	5344, 136,
            	5410, 152,
            	273, 160,
            	4770, 176,
            	4671, 184,
            	4671, 192,
            	5382, 208,
            	5184, 216,
            	5398, 224,
            	5382, 232,
            	5184, 240,
            	5398, 248,
            	5413, 256,
            	4765, 304,
            	5418, 312,
            	5421, 328,
            	5424, 336,
            	5427, 352,
            	5430, 360,
            	5433, 368,
            	3667, 392,
            	5226, 408,
            	5634, 464,
            	273, 472,
            	178, 480,
            	200, 504,
            	10, 512,
            	78, 520,
            	78, 544,
            	78, 560,
            	273, 568,
            	2619, 584,
            	3203, 592,
            	273, 600,
            	4717, 608,
            	273, 616,
            	5433, 624,
            	78, 632,
            	4106, 648,
            	4744, 656,
            	242, 680,
            1, 8, 1, /* 4966: pointer.struct.ssl_method_st */
            	4971, 0,
            0, 232, 28, /* 4971: struct.ssl_method_st */
            	5030, 8,
            	5033, 16,
            	5033, 24,
            	5030, 32,
            	5030, 40,
            	5036, 48,
            	5036, 56,
            	3123, 64,
            	5030, 72,
            	5030, 80,
            	5030, 88,
            	5039, 96,
            	5042, 104,
            	4749, 112,
            	5030, 120,
            	5045, 128,
            	4853, 136,
            	5048, 144,
            	5051, 152,
            	5054, 160,
            	4824, 168,
            	4130, 176,
            	5057, 184,
            	342, 192,
            	5060, 200,
            	4824, 208,
            	5099, 216,
            	5102, 224,
            8884097, 8, 0, /* 5030: pointer.func */
            8884097, 8, 0, /* 5033: pointer.func */
            8884097, 8, 0, /* 5036: pointer.func */
            8884097, 8, 0, /* 5039: pointer.func */
            8884097, 8, 0, /* 5042: pointer.func */
            8884097, 8, 0, /* 5045: pointer.func */
            8884097, 8, 0, /* 5048: pointer.func */
            8884097, 8, 0, /* 5051: pointer.func */
            8884097, 8, 0, /* 5054: pointer.func */
            8884097, 8, 0, /* 5057: pointer.func */
            1, 8, 1, /* 5060: pointer.struct.ssl3_enc_method */
            	5065, 0,
            0, 112, 11, /* 5065: struct.ssl3_enc_method */
            	4752, 0,
            	5090, 8,
            	5030, 16,
            	5093, 24,
            	4752, 32,
            	5096, 40,
            	4575, 56,
            	5, 64,
            	5, 80,
            	4782, 96,
            	4821, 104,
            8884097, 8, 0, /* 5090: pointer.func */
            8884097, 8, 0, /* 5093: pointer.func */
            8884097, 8, 0, /* 5096: pointer.func */
            8884097, 8, 0, /* 5099: pointer.func */
            8884097, 8, 0, /* 5102: pointer.func */
            1, 8, 1, /* 5105: pointer.struct.bio_st */
            	5110, 0,
            0, 112, 7, /* 5110: struct.bio_st */
            	5127, 0,
            	4705, 8,
            	178, 16,
            	273, 48,
            	5132, 56,
            	5132, 64,
            	3667, 96,
            1, 8, 1, /* 5127: pointer.struct.bio_method_st */
            	4785, 0,
            1, 8, 1, /* 5132: pointer.struct.bio_st */
            	5110, 0,
            1, 8, 1, /* 5137: pointer.struct.ssl3_state_st */
            	5142, 0,
            0, 1200, 10, /* 5142: struct.ssl3_state_st */
            	5165, 240,
            	5165, 264,
            	5170, 288,
            	5170, 344,
            	60, 432,
            	5105, 440,
            	5179, 448,
            	273, 496,
            	273, 512,
            	5207, 528,
            0, 24, 1, /* 5165: struct.ssl3_buffer_st */
            	78, 0,
            0, 56, 3, /* 5170: struct.ssl3_record_st */
            	78, 16,
            	78, 24,
            	78, 32,
            1, 8, 1, /* 5179: pointer.pointer.struct.env_md_ctx_st */
            	5184, 0,
            1, 8, 1, /* 5184: pointer.struct.env_md_ctx_st */
            	5189, 0,
            0, 48, 5, /* 5189: struct.env_md_ctx_st */
            	4034, 0,
            	3552, 8,
            	273, 24,
            	5202, 32,
            	4061, 40,
            1, 8, 1, /* 5202: pointer.struct.evp_pkey_ctx_st */
            	4103, 0,
            0, 528, 8, /* 5207: struct.unknown */
            	4661, 408,
            	4087, 416,
            	4095, 424,
            	5226, 464,
            	78, 480,
            	5264, 488,
            	4034, 496,
            	5301, 512,
            1, 8, 1, /* 5226: pointer.struct.stack_st_X509_NAME */
            	5231, 0,
            0, 32, 2, /* 5231: struct.stack_st_fake_X509_NAME */
            	5238, 8,
            	86, 24,
            8884099, 8, 2, /* 5238: pointer_to_array_of_pointers_to_stack */
            	5245, 0,
            	83, 20,
            0, 8, 1, /* 5245: pointer.X509_NAME */
            	5250, 0,
            0, 0, 1, /* 5250: X509_NAME */
            	5255, 0,
            0, 40, 3, /* 5255: struct.X509_name_st */
            	4720, 0,
            	3206, 16,
            	78, 24,
            1, 8, 1, /* 5264: pointer.struct.evp_cipher_st */
            	5269, 0,
            0, 88, 7, /* 5269: struct.evp_cipher_st */
            	5286, 24,
            	5289, 32,
            	5292, 40,
            	5295, 56,
            	5295, 64,
            	5298, 72,
            	273, 80,
            8884097, 8, 0, /* 5286: pointer.func */
            8884097, 8, 0, /* 5289: pointer.func */
            8884097, 8, 0, /* 5292: pointer.func */
            8884097, 8, 0, /* 5295: pointer.func */
            8884097, 8, 0, /* 5298: pointer.func */
            1, 8, 1, /* 5301: pointer.struct.ssl_comp_st */
            	5306, 0,
            0, 24, 2, /* 5306: struct.ssl_comp_st */
            	5, 8,
            	5313, 16,
            1, 8, 1, /* 5313: pointer.struct.comp_method_st */
            	5318, 0,
            0, 64, 7, /* 5318: struct.comp_method_st */
            	5, 8,
            	5335, 16,
            	5338, 24,
            	5341, 32,
            	5341, 40,
            	342, 48,
            	342, 56,
            8884097, 8, 0, /* 5335: pointer.func */
            8884097, 8, 0, /* 5338: pointer.func */
            8884097, 8, 0, /* 5341: pointer.func */
            1, 8, 1, /* 5344: pointer.struct.dtls1_state_st */
            	5349, 0,
            0, 888, 7, /* 5349: struct.dtls1_state_st */
            	4755, 576,
            	4755, 592,
            	4760, 608,
            	4760, 616,
            	4755, 624,
            	5366, 648,
            	5366, 736,
            0, 88, 1, /* 5366: struct.hm_header_st */
            	5371, 48,
            0, 40, 4, /* 5371: struct.dtls1_retransmit_state */
            	5382, 0,
            	5184, 8,
            	5398, 16,
            	4765, 24,
            1, 8, 1, /* 5382: pointer.struct.evp_cipher_ctx_st */
            	5387, 0,
            0, 168, 4, /* 5387: struct.evp_cipher_ctx_st */
            	5264, 0,
            	3552, 8,
            	273, 96,
            	273, 120,
            1, 8, 1, /* 5398: pointer.struct.comp_ctx_st */
            	5403, 0,
            0, 56, 2, /* 5403: struct.comp_ctx_st */
            	5313, 0,
            	3667, 40,
            8884097, 8, 0, /* 5410: pointer.func */
            1, 8, 1, /* 5413: pointer.struct.cert_st */
            	3216, 0,
            8884097, 8, 0, /* 5418: pointer.func */
            8884097, 8, 0, /* 5421: pointer.func */
            8884097, 8, 0, /* 5424: pointer.func */
            8884097, 8, 0, /* 5427: pointer.func */
            8884097, 8, 0, /* 5430: pointer.func */
            1, 8, 1, /* 5433: pointer.struct.ssl_ctx_st */
            	5438, 0,
            0, 736, 50, /* 5438: struct.ssl_ctx_st */
            	4966, 0,
            	4671, 8,
            	4671, 16,
            	5541, 24,
            	423, 32,
            	4578, 48,
            	4578, 56,
            	458, 80,
            	5612, 88,
            	389, 96,
            	2624, 152,
            	273, 160,
            	5615, 168,
            	273, 176,
            	5618, 184,
            	5621, 192,
            	386, 200,
            	3667, 208,
            	4034, 224,
            	4034, 232,
            	4034, 240,
            	4632, 248,
            	362, 256,
            	5424, 264,
            	5226, 272,
            	5413, 304,
            	5410, 320,
            	273, 328,
            	5421, 376,
            	5418, 384,
            	4770, 392,
            	3552, 408,
            	276, 416,
            	273, 424,
            	2627, 480,
            	279, 488,
            	273, 496,
            	313, 504,
            	273, 512,
            	178, 520,
            	5427, 528,
            	5430, 536,
            	5624, 552,
            	5624, 560,
            	242, 568,
            	239, 696,
            	273, 704,
            	4133, 712,
            	273, 720,
            	4106, 728,
            1, 8, 1, /* 5541: pointer.struct.x509_store_st */
            	5546, 0,
            0, 144, 15, /* 5546: struct.x509_store_st */
            	5579, 8,
            	3002, 16,
            	4770, 24,
            	434, 32,
            	5421, 40,
            	4307, 48,
            	5603, 56,
            	434, 64,
            	5606, 72,
            	431, 80,
            	4714, 88,
            	428, 96,
            	5609, 104,
            	434, 112,
            	3667, 120,
            1, 8, 1, /* 5579: pointer.struct.stack_st_X509_OBJECT */
            	5584, 0,
            0, 32, 2, /* 5584: struct.stack_st_fake_X509_OBJECT */
            	5591, 8,
            	86, 24,
            8884099, 8, 2, /* 5591: pointer_to_array_of_pointers_to_stack */
            	5598, 0,
            	83, 20,
            0, 8, 1, /* 5598: pointer.X509_OBJECT */
            	610, 0,
            8884097, 8, 0, /* 5603: pointer.func */
            8884097, 8, 0, /* 5606: pointer.func */
            8884097, 8, 0, /* 5609: pointer.func */
            8884097, 8, 0, /* 5612: pointer.func */
            8884097, 8, 0, /* 5615: pointer.func */
            8884097, 8, 0, /* 5618: pointer.func */
            8884097, 8, 0, /* 5621: pointer.func */
            1, 8, 1, /* 5624: pointer.struct.ssl3_buf_freelist_st */
            	5629, 0,
            0, 24, 1, /* 5629: struct.ssl3_buf_freelist_st */
            	303, 16,
            8884097, 8, 0, /* 5634: pointer.func */
        },
        .arg_entity_index = { 4856, },
        .ret_entity_index = 3247,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    X509 * *new_ret_ptr = (X509 * *)new_args->ret;

    X509 * (*orig_SSL_get_peer_certificate)(const SSL *);
    orig_SSL_get_peer_certificate = dlsym(RTLD_NEXT, "SSL_get_peer_certificate");
    *new_ret_ptr = (*orig_SSL_get_peer_certificate)(new_arg_a);

    syscall(889);

    return ret;
}

