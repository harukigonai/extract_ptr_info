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

void bb_SSL_set_verify(SSL * arg_a,int arg_b,int (*arg_c)(int, X509_STORE_CTX *));

void SSL_set_verify(SSL * arg_a,int arg_b,int (*arg_c)(int, X509_STORE_CTX *)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_set_verify called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_set_verify(arg_a,arg_b,arg_c);
    else {
        void (*orig_SSL_set_verify)(SSL *,int,int (*)(int, X509_STORE_CTX *));
        orig_SSL_set_verify = dlsym(RTLD_NEXT, "SSL_set_verify");
        orig_SSL_set_verify(arg_a,arg_b,arg_c);
    }
}

void bb_SSL_set_verify(SSL * arg_a,int arg_b,int (*arg_c)(int, X509_STORE_CTX *)) 
{
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
            1, 8, 1, /* 2630: pointer.struct.dh_st */
            	2635, 0,
            0, 144, 12, /* 2635: struct.dh_st */
            	285, 8,
            	285, 16,
            	285, 32,
            	285, 40,
            	2662, 56,
            	285, 64,
            	285, 72,
            	78, 80,
            	285, 96,
            	2676, 112,
            	2698, 128,
            	2734, 136,
            1, 8, 1, /* 2662: pointer.struct.bn_mont_ctx_st */
            	2667, 0,
            0, 96, 3, /* 2667: struct.bn_mont_ctx_st */
            	290, 8,
            	290, 32,
            	290, 56,
            0, 16, 1, /* 2676: struct.crypto_ex_data_st */
            	2681, 0,
            1, 8, 1, /* 2681: pointer.struct.stack_st_void */
            	2686, 0,
            0, 32, 1, /* 2686: struct.stack_st_void */
            	2691, 0,
            0, 32, 2, /* 2691: struct.stack_st */
            	1113, 8,
            	86, 24,
            1, 8, 1, /* 2698: pointer.struct.dh_method */
            	2703, 0,
            0, 72, 8, /* 2703: struct.dh_method */
            	5, 0,
            	2722, 8,
            	2725, 16,
            	2728, 24,
            	2722, 32,
            	2722, 40,
            	178, 56,
            	2731, 64,
            8884097, 8, 0, /* 2722: pointer.func */
            8884097, 8, 0, /* 2725: pointer.func */
            8884097, 8, 0, /* 2728: pointer.func */
            8884097, 8, 0, /* 2731: pointer.func */
            1, 8, 1, /* 2734: pointer.struct.engine_st */
            	2739, 0,
            0, 0, 0, /* 2739: struct.engine_st */
            8884097, 8, 0, /* 2742: pointer.func */
            1, 8, 1, /* 2745: pointer.struct.ssl_session_st */
            	2750, 0,
            0, 352, 14, /* 2750: struct.ssl_session_st */
            	178, 144,
            	178, 152,
            	2781, 168,
            	3689, 176,
            	4556, 224,
            	4566, 240,
            	2676, 248,
            	4600, 264,
            	4600, 272,
            	178, 280,
            	78, 296,
            	78, 312,
            	78, 320,
            	178, 344,
            1, 8, 1, /* 2781: pointer.struct.sess_cert_st */
            	2786, 0,
            0, 248, 5, /* 2786: struct.sess_cert_st */
            	2799, 0,
            	3675, 16,
            	4546, 216,
            	2630, 224,
            	4551, 232,
            1, 8, 1, /* 2799: pointer.struct.stack_st_X509 */
            	2804, 0,
            0, 32, 2, /* 2804: struct.stack_st_fake_X509 */
            	2811, 8,
            	86, 24,
            8884099, 8, 2, /* 2811: pointer_to_array_of_pointers_to_stack */
            	2818, 0,
            	83, 20,
            0, 8, 1, /* 2818: pointer.X509 */
            	2823, 0,
            0, 0, 1, /* 2823: X509 */
            	2828, 0,
            0, 184, 12, /* 2828: struct.x509_st */
            	2855, 0,
            	2895, 8,
            	2984, 16,
            	178, 32,
            	3283, 40,
            	2989, 104,
            	3537, 112,
            	3545, 120,
            	3553, 128,
            	3577, 136,
            	3601, 144,
            	3609, 176,
            1, 8, 1, /* 2855: pointer.struct.x509_cinf_st */
            	2860, 0,
            0, 104, 11, /* 2860: struct.x509_cinf_st */
            	2885, 0,
            	2885, 8,
            	2895, 16,
            	3052, 24,
            	3100, 32,
            	3052, 40,
            	3117, 48,
            	2984, 56,
            	2984, 64,
            	3508, 72,
            	3532, 80,
            1, 8, 1, /* 2885: pointer.struct.asn1_string_st */
            	2890, 0,
            0, 24, 1, /* 2890: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2895: pointer.struct.X509_algor_st */
            	2900, 0,
            0, 16, 2, /* 2900: struct.X509_algor_st */
            	2907, 0,
            	2921, 8,
            1, 8, 1, /* 2907: pointer.struct.asn1_object_st */
            	2912, 0,
            0, 40, 3, /* 2912: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2921: pointer.struct.asn1_type_st */
            	2926, 0,
            0, 16, 1, /* 2926: struct.asn1_type_st */
            	2931, 8,
            0, 8, 20, /* 2931: union.unknown */
            	178, 0,
            	2974, 0,
            	2907, 0,
            	2885, 0,
            	2979, 0,
            	2984, 0,
            	2989, 0,
            	2994, 0,
            	2999, 0,
            	3004, 0,
            	3009, 0,
            	3014, 0,
            	3019, 0,
            	3024, 0,
            	3029, 0,
            	3034, 0,
            	3039, 0,
            	2974, 0,
            	2974, 0,
            	3044, 0,
            1, 8, 1, /* 2974: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2979: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2984: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2989: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2994: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2999: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3004: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3009: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3014: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3019: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3024: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3029: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3034: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3039: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3044: pointer.struct.ASN1_VALUE_st */
            	3049, 0,
            0, 0, 0, /* 3049: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3052: pointer.struct.X509_name_st */
            	3057, 0,
            0, 40, 3, /* 3057: struct.X509_name_st */
            	3066, 0,
            	3090, 16,
            	78, 24,
            1, 8, 1, /* 3066: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3071, 0,
            0, 32, 2, /* 3071: struct.stack_st_fake_X509_NAME_ENTRY */
            	3078, 8,
            	86, 24,
            8884099, 8, 2, /* 3078: pointer_to_array_of_pointers_to_stack */
            	3085, 0,
            	83, 20,
            0, 8, 1, /* 3085: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 3090: pointer.struct.buf_mem_st */
            	3095, 0,
            0, 24, 1, /* 3095: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 3100: pointer.struct.X509_val_st */
            	3105, 0,
            0, 16, 2, /* 3105: struct.X509_val_st */
            	3112, 0,
            	3112, 8,
            1, 8, 1, /* 3112: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3117: pointer.struct.X509_pubkey_st */
            	3122, 0,
            0, 24, 3, /* 3122: struct.X509_pubkey_st */
            	2895, 0,
            	2984, 8,
            	3131, 16,
            1, 8, 1, /* 3131: pointer.struct.evp_pkey_st */
            	3136, 0,
            0, 56, 4, /* 3136: struct.evp_pkey_st */
            	3147, 16,
            	3155, 24,
            	3163, 32,
            	3484, 48,
            1, 8, 1, /* 3147: pointer.struct.evp_pkey_asn1_method_st */
            	3152, 0,
            0, 0, 0, /* 3152: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3155: pointer.struct.engine_st */
            	3160, 0,
            0, 0, 0, /* 3160: struct.engine_st */
            0, 8, 5, /* 3163: union.unknown */
            	178, 0,
            	3176, 0,
            	3327, 0,
            	3408, 0,
            	3476, 0,
            1, 8, 1, /* 3176: pointer.struct.rsa_st */
            	3181, 0,
            0, 168, 17, /* 3181: struct.rsa_st */
            	3218, 16,
            	3155, 24,
            	3273, 32,
            	3273, 40,
            	3273, 48,
            	3273, 56,
            	3273, 64,
            	3273, 72,
            	3273, 80,
            	3273, 88,
            	3283, 96,
            	3305, 120,
            	3305, 128,
            	3305, 136,
            	178, 144,
            	3319, 152,
            	3319, 160,
            1, 8, 1, /* 3218: pointer.struct.rsa_meth_st */
            	3223, 0,
            0, 112, 13, /* 3223: struct.rsa_meth_st */
            	5, 0,
            	3252, 8,
            	3252, 16,
            	3252, 24,
            	3252, 32,
            	3255, 40,
            	3258, 48,
            	3261, 56,
            	3261, 64,
            	178, 80,
            	3264, 88,
            	3267, 96,
            	3270, 104,
            8884097, 8, 0, /* 3252: pointer.func */
            8884097, 8, 0, /* 3255: pointer.func */
            8884097, 8, 0, /* 3258: pointer.func */
            8884097, 8, 0, /* 3261: pointer.func */
            8884097, 8, 0, /* 3264: pointer.func */
            8884097, 8, 0, /* 3267: pointer.func */
            8884097, 8, 0, /* 3270: pointer.func */
            1, 8, 1, /* 3273: pointer.struct.bignum_st */
            	3278, 0,
            0, 24, 1, /* 3278: struct.bignum_st */
            	295, 0,
            0, 16, 1, /* 3283: struct.crypto_ex_data_st */
            	3288, 0,
            1, 8, 1, /* 3288: pointer.struct.stack_st_void */
            	3293, 0,
            0, 32, 1, /* 3293: struct.stack_st_void */
            	3298, 0,
            0, 32, 2, /* 3298: struct.stack_st */
            	1113, 8,
            	86, 24,
            1, 8, 1, /* 3305: pointer.struct.bn_mont_ctx_st */
            	3310, 0,
            0, 96, 3, /* 3310: struct.bn_mont_ctx_st */
            	3278, 8,
            	3278, 32,
            	3278, 56,
            1, 8, 1, /* 3319: pointer.struct.bn_blinding_st */
            	3324, 0,
            0, 0, 0, /* 3324: struct.bn_blinding_st */
            1, 8, 1, /* 3327: pointer.struct.dsa_st */
            	3332, 0,
            0, 136, 11, /* 3332: struct.dsa_st */
            	3273, 24,
            	3273, 32,
            	3273, 40,
            	3273, 48,
            	3273, 56,
            	3273, 64,
            	3273, 72,
            	3305, 88,
            	3283, 104,
            	3357, 120,
            	3155, 128,
            1, 8, 1, /* 3357: pointer.struct.dsa_method */
            	3362, 0,
            0, 96, 11, /* 3362: struct.dsa_method */
            	5, 0,
            	3387, 8,
            	3390, 16,
            	3393, 24,
            	3396, 32,
            	3399, 40,
            	3402, 48,
            	3402, 56,
            	178, 72,
            	3405, 80,
            	3402, 88,
            8884097, 8, 0, /* 3387: pointer.func */
            8884097, 8, 0, /* 3390: pointer.func */
            8884097, 8, 0, /* 3393: pointer.func */
            8884097, 8, 0, /* 3396: pointer.func */
            8884097, 8, 0, /* 3399: pointer.func */
            8884097, 8, 0, /* 3402: pointer.func */
            8884097, 8, 0, /* 3405: pointer.func */
            1, 8, 1, /* 3408: pointer.struct.dh_st */
            	3413, 0,
            0, 144, 12, /* 3413: struct.dh_st */
            	3273, 8,
            	3273, 16,
            	3273, 32,
            	3273, 40,
            	3305, 56,
            	3273, 64,
            	3273, 72,
            	78, 80,
            	3273, 96,
            	3283, 112,
            	3440, 128,
            	3155, 136,
            1, 8, 1, /* 3440: pointer.struct.dh_method */
            	3445, 0,
            0, 72, 8, /* 3445: struct.dh_method */
            	5, 0,
            	3464, 8,
            	3467, 16,
            	3470, 24,
            	3464, 32,
            	3464, 40,
            	178, 56,
            	3473, 64,
            8884097, 8, 0, /* 3464: pointer.func */
            8884097, 8, 0, /* 3467: pointer.func */
            8884097, 8, 0, /* 3470: pointer.func */
            8884097, 8, 0, /* 3473: pointer.func */
            1, 8, 1, /* 3476: pointer.struct.ec_key_st */
            	3481, 0,
            0, 0, 0, /* 3481: struct.ec_key_st */
            1, 8, 1, /* 3484: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3489, 0,
            0, 32, 2, /* 3489: struct.stack_st_fake_X509_ATTRIBUTE */
            	3496, 8,
            	86, 24,
            8884099, 8, 2, /* 3496: pointer_to_array_of_pointers_to_stack */
            	3503, 0,
            	83, 20,
            0, 8, 1, /* 3503: pointer.X509_ATTRIBUTE */
            	1321, 0,
            1, 8, 1, /* 3508: pointer.struct.stack_st_X509_EXTENSION */
            	3513, 0,
            0, 32, 2, /* 3513: struct.stack_st_fake_X509_EXTENSION */
            	3520, 8,
            	86, 24,
            8884099, 8, 2, /* 3520: pointer_to_array_of_pointers_to_stack */
            	3527, 0,
            	83, 20,
            0, 8, 1, /* 3527: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 3532: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 3537: pointer.struct.AUTHORITY_KEYID_st */
            	3542, 0,
            0, 0, 0, /* 3542: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3545: pointer.struct.X509_POLICY_CACHE_st */
            	3550, 0,
            0, 0, 0, /* 3550: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3553: pointer.struct.stack_st_DIST_POINT */
            	3558, 0,
            0, 32, 2, /* 3558: struct.stack_st_fake_DIST_POINT */
            	3565, 8,
            	86, 24,
            8884099, 8, 2, /* 3565: pointer_to_array_of_pointers_to_stack */
            	3572, 0,
            	83, 20,
            0, 8, 1, /* 3572: pointer.DIST_POINT */
            	1737, 0,
            1, 8, 1, /* 3577: pointer.struct.stack_st_GENERAL_NAME */
            	3582, 0,
            0, 32, 2, /* 3582: struct.stack_st_fake_GENERAL_NAME */
            	3589, 8,
            	86, 24,
            8884099, 8, 2, /* 3589: pointer_to_array_of_pointers_to_stack */
            	3596, 0,
            	83, 20,
            0, 8, 1, /* 3596: pointer.GENERAL_NAME */
            	1794, 0,
            1, 8, 1, /* 3601: pointer.struct.NAME_CONSTRAINTS_st */
            	3606, 0,
            0, 0, 0, /* 3606: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3609: pointer.struct.x509_cert_aux_st */
            	3614, 0,
            0, 40, 5, /* 3614: struct.x509_cert_aux_st */
            	3627, 0,
            	3627, 8,
            	3039, 16,
            	2989, 24,
            	3651, 32,
            1, 8, 1, /* 3627: pointer.struct.stack_st_ASN1_OBJECT */
            	3632, 0,
            0, 32, 2, /* 3632: struct.stack_st_fake_ASN1_OBJECT */
            	3639, 8,
            	86, 24,
            8884099, 8, 2, /* 3639: pointer_to_array_of_pointers_to_stack */
            	3646, 0,
            	83, 20,
            0, 8, 1, /* 3646: pointer.ASN1_OBJECT */
            	2196, 0,
            1, 8, 1, /* 3651: pointer.struct.stack_st_X509_ALGOR */
            	3656, 0,
            0, 32, 2, /* 3656: struct.stack_st_fake_X509_ALGOR */
            	3663, 8,
            	86, 24,
            8884099, 8, 2, /* 3663: pointer_to_array_of_pointers_to_stack */
            	3670, 0,
            	83, 20,
            0, 8, 1, /* 3670: pointer.X509_ALGOR */
            	2225, 0,
            1, 8, 1, /* 3675: pointer.struct.cert_pkey_st */
            	3680, 0,
            0, 24, 3, /* 3680: struct.cert_pkey_st */
            	3689, 0,
            	3997, 8,
            	4501, 16,
            1, 8, 1, /* 3689: pointer.struct.x509_st */
            	3694, 0,
            0, 184, 12, /* 3694: struct.x509_st */
            	3721, 0,
            	3761, 8,
            	3850, 16,
            	178, 32,
            	2676, 40,
            	3855, 104,
            	4286, 112,
            	4324, 120,
            	4332, 128,
            	4356, 136,
            	4380, 144,
            	4435, 176,
            1, 8, 1, /* 3721: pointer.struct.x509_cinf_st */
            	3726, 0,
            0, 104, 11, /* 3726: struct.x509_cinf_st */
            	3751, 0,
            	3751, 8,
            	3761, 16,
            	3918, 24,
            	3966, 32,
            	3918, 40,
            	3983, 48,
            	3850, 56,
            	3850, 64,
            	4257, 72,
            	4281, 80,
            1, 8, 1, /* 3751: pointer.struct.asn1_string_st */
            	3756, 0,
            0, 24, 1, /* 3756: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 3761: pointer.struct.X509_algor_st */
            	3766, 0,
            0, 16, 2, /* 3766: struct.X509_algor_st */
            	3773, 0,
            	3787, 8,
            1, 8, 1, /* 3773: pointer.struct.asn1_object_st */
            	3778, 0,
            0, 40, 3, /* 3778: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 3787: pointer.struct.asn1_type_st */
            	3792, 0,
            0, 16, 1, /* 3792: struct.asn1_type_st */
            	3797, 8,
            0, 8, 20, /* 3797: union.unknown */
            	178, 0,
            	3840, 0,
            	3773, 0,
            	3751, 0,
            	3845, 0,
            	3850, 0,
            	3855, 0,
            	3860, 0,
            	3865, 0,
            	3870, 0,
            	3875, 0,
            	3880, 0,
            	3885, 0,
            	3890, 0,
            	3895, 0,
            	3900, 0,
            	3905, 0,
            	3840, 0,
            	3840, 0,
            	3910, 0,
            1, 8, 1, /* 3840: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3845: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3850: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3855: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3860: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3865: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3870: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3875: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3880: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3885: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3890: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3895: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3900: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3905: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3910: pointer.struct.ASN1_VALUE_st */
            	3915, 0,
            0, 0, 0, /* 3915: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3918: pointer.struct.X509_name_st */
            	3923, 0,
            0, 40, 3, /* 3923: struct.X509_name_st */
            	3932, 0,
            	3956, 16,
            	78, 24,
            1, 8, 1, /* 3932: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3937, 0,
            0, 32, 2, /* 3937: struct.stack_st_fake_X509_NAME_ENTRY */
            	3944, 8,
            	86, 24,
            8884099, 8, 2, /* 3944: pointer_to_array_of_pointers_to_stack */
            	3951, 0,
            	83, 20,
            0, 8, 1, /* 3951: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 3956: pointer.struct.buf_mem_st */
            	3961, 0,
            0, 24, 1, /* 3961: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 3966: pointer.struct.X509_val_st */
            	3971, 0,
            0, 16, 2, /* 3971: struct.X509_val_st */
            	3978, 0,
            	3978, 8,
            1, 8, 1, /* 3978: pointer.struct.asn1_string_st */
            	3756, 0,
            1, 8, 1, /* 3983: pointer.struct.X509_pubkey_st */
            	3988, 0,
            0, 24, 3, /* 3988: struct.X509_pubkey_st */
            	3761, 0,
            	3850, 8,
            	3997, 16,
            1, 8, 1, /* 3997: pointer.struct.evp_pkey_st */
            	4002, 0,
            0, 56, 4, /* 4002: struct.evp_pkey_st */
            	4013, 16,
            	2734, 24,
            	4021, 32,
            	4233, 48,
            1, 8, 1, /* 4013: pointer.struct.evp_pkey_asn1_method_st */
            	4018, 0,
            0, 0, 0, /* 4018: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 4021: union.unknown */
            	178, 0,
            	4034, 0,
            	4139, 0,
            	4220, 0,
            	4225, 0,
            1, 8, 1, /* 4034: pointer.struct.rsa_st */
            	4039, 0,
            0, 168, 17, /* 4039: struct.rsa_st */
            	4076, 16,
            	2734, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	2676, 96,
            	2662, 120,
            	2662, 128,
            	2662, 136,
            	178, 144,
            	4131, 152,
            	4131, 160,
            1, 8, 1, /* 4076: pointer.struct.rsa_meth_st */
            	4081, 0,
            0, 112, 13, /* 4081: struct.rsa_meth_st */
            	5, 0,
            	4110, 8,
            	4110, 16,
            	4110, 24,
            	4110, 32,
            	4113, 40,
            	4116, 48,
            	4119, 56,
            	4119, 64,
            	178, 80,
            	4122, 88,
            	4125, 96,
            	4128, 104,
            8884097, 8, 0, /* 4110: pointer.func */
            8884097, 8, 0, /* 4113: pointer.func */
            8884097, 8, 0, /* 4116: pointer.func */
            8884097, 8, 0, /* 4119: pointer.func */
            8884097, 8, 0, /* 4122: pointer.func */
            8884097, 8, 0, /* 4125: pointer.func */
            8884097, 8, 0, /* 4128: pointer.func */
            1, 8, 1, /* 4131: pointer.struct.bn_blinding_st */
            	4136, 0,
            0, 0, 0, /* 4136: struct.bn_blinding_st */
            1, 8, 1, /* 4139: pointer.struct.dsa_st */
            	4144, 0,
            0, 136, 11, /* 4144: struct.dsa_st */
            	285, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	2662, 88,
            	2676, 104,
            	4169, 120,
            	2734, 128,
            1, 8, 1, /* 4169: pointer.struct.dsa_method */
            	4174, 0,
            0, 96, 11, /* 4174: struct.dsa_method */
            	5, 0,
            	4199, 8,
            	4202, 16,
            	4205, 24,
            	4208, 32,
            	4211, 40,
            	4214, 48,
            	4214, 56,
            	178, 72,
            	4217, 80,
            	4214, 88,
            8884097, 8, 0, /* 4199: pointer.func */
            8884097, 8, 0, /* 4202: pointer.func */
            8884097, 8, 0, /* 4205: pointer.func */
            8884097, 8, 0, /* 4208: pointer.func */
            8884097, 8, 0, /* 4211: pointer.func */
            8884097, 8, 0, /* 4214: pointer.func */
            8884097, 8, 0, /* 4217: pointer.func */
            1, 8, 1, /* 4220: pointer.struct.dh_st */
            	2635, 0,
            1, 8, 1, /* 4225: pointer.struct.ec_key_st */
            	4230, 0,
            0, 0, 0, /* 4230: struct.ec_key_st */
            1, 8, 1, /* 4233: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4238, 0,
            0, 32, 2, /* 4238: struct.stack_st_fake_X509_ATTRIBUTE */
            	4245, 8,
            	86, 24,
            8884099, 8, 2, /* 4245: pointer_to_array_of_pointers_to_stack */
            	4252, 0,
            	83, 20,
            0, 8, 1, /* 4252: pointer.X509_ATTRIBUTE */
            	1321, 0,
            1, 8, 1, /* 4257: pointer.struct.stack_st_X509_EXTENSION */
            	4262, 0,
            0, 32, 2, /* 4262: struct.stack_st_fake_X509_EXTENSION */
            	4269, 8,
            	86, 24,
            8884099, 8, 2, /* 4269: pointer_to_array_of_pointers_to_stack */
            	4276, 0,
            	83, 20,
            0, 8, 1, /* 4276: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 4281: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 4286: pointer.struct.AUTHORITY_KEYID_st */
            	4291, 0,
            0, 24, 3, /* 4291: struct.AUTHORITY_KEYID_st */
            	3855, 0,
            	4300, 8,
            	3751, 16,
            1, 8, 1, /* 4300: pointer.struct.stack_st_GENERAL_NAME */
            	4305, 0,
            0, 32, 2, /* 4305: struct.stack_st_fake_GENERAL_NAME */
            	4312, 8,
            	86, 24,
            8884099, 8, 2, /* 4312: pointer_to_array_of_pointers_to_stack */
            	4319, 0,
            	83, 20,
            0, 8, 1, /* 4319: pointer.GENERAL_NAME */
            	1794, 0,
            1, 8, 1, /* 4324: pointer.struct.X509_POLICY_CACHE_st */
            	4329, 0,
            0, 0, 0, /* 4329: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4332: pointer.struct.stack_st_DIST_POINT */
            	4337, 0,
            0, 32, 2, /* 4337: struct.stack_st_fake_DIST_POINT */
            	4344, 8,
            	86, 24,
            8884099, 8, 2, /* 4344: pointer_to_array_of_pointers_to_stack */
            	4351, 0,
            	83, 20,
            0, 8, 1, /* 4351: pointer.DIST_POINT */
            	1737, 0,
            1, 8, 1, /* 4356: pointer.struct.stack_st_GENERAL_NAME */
            	4361, 0,
            0, 32, 2, /* 4361: struct.stack_st_fake_GENERAL_NAME */
            	4368, 8,
            	86, 24,
            8884099, 8, 2, /* 4368: pointer_to_array_of_pointers_to_stack */
            	4375, 0,
            	83, 20,
            0, 8, 1, /* 4375: pointer.GENERAL_NAME */
            	1794, 0,
            1, 8, 1, /* 4380: pointer.struct.NAME_CONSTRAINTS_st */
            	4385, 0,
            0, 16, 2, /* 4385: struct.NAME_CONSTRAINTS_st */
            	4392, 0,
            	4392, 8,
            1, 8, 1, /* 4392: pointer.struct.stack_st_GENERAL_SUBTREE */
            	4397, 0,
            0, 32, 2, /* 4397: struct.stack_st_fake_GENERAL_SUBTREE */
            	4404, 8,
            	86, 24,
            8884099, 8, 2, /* 4404: pointer_to_array_of_pointers_to_stack */
            	4411, 0,
            	83, 20,
            0, 8, 1, /* 4411: pointer.GENERAL_SUBTREE */
            	4416, 0,
            0, 0, 1, /* 4416: GENERAL_SUBTREE */
            	4421, 0,
            0, 24, 3, /* 4421: struct.GENERAL_SUBTREE_st */
            	4430, 0,
            	1926, 8,
            	1926, 16,
            1, 8, 1, /* 4430: pointer.struct.GENERAL_NAME_st */
            	1799, 0,
            1, 8, 1, /* 4435: pointer.struct.x509_cert_aux_st */
            	4440, 0,
            0, 40, 5, /* 4440: struct.x509_cert_aux_st */
            	4453, 0,
            	4453, 8,
            	3905, 16,
            	3855, 24,
            	4477, 32,
            1, 8, 1, /* 4453: pointer.struct.stack_st_ASN1_OBJECT */
            	4458, 0,
            0, 32, 2, /* 4458: struct.stack_st_fake_ASN1_OBJECT */
            	4465, 8,
            	86, 24,
            8884099, 8, 2, /* 4465: pointer_to_array_of_pointers_to_stack */
            	4472, 0,
            	83, 20,
            0, 8, 1, /* 4472: pointer.ASN1_OBJECT */
            	2196, 0,
            1, 8, 1, /* 4477: pointer.struct.stack_st_X509_ALGOR */
            	4482, 0,
            0, 32, 2, /* 4482: struct.stack_st_fake_X509_ALGOR */
            	4489, 8,
            	86, 24,
            8884099, 8, 2, /* 4489: pointer_to_array_of_pointers_to_stack */
            	4496, 0,
            	83, 20,
            0, 8, 1, /* 4496: pointer.X509_ALGOR */
            	2225, 0,
            1, 8, 1, /* 4501: pointer.struct.env_md_st */
            	4506, 0,
            0, 120, 8, /* 4506: struct.env_md_st */
            	4525, 24,
            	4528, 32,
            	4531, 40,
            	4534, 48,
            	4525, 56,
            	4537, 64,
            	4540, 72,
            	4543, 112,
            8884097, 8, 0, /* 4525: pointer.func */
            8884097, 8, 0, /* 4528: pointer.func */
            8884097, 8, 0, /* 4531: pointer.func */
            8884097, 8, 0, /* 4534: pointer.func */
            8884097, 8, 0, /* 4537: pointer.func */
            8884097, 8, 0, /* 4540: pointer.func */
            8884097, 8, 0, /* 4543: pointer.func */
            1, 8, 1, /* 4546: pointer.struct.rsa_st */
            	4039, 0,
            1, 8, 1, /* 4551: pointer.struct.ec_key_st */
            	4230, 0,
            1, 8, 1, /* 4556: pointer.struct.ssl_cipher_st */
            	4561, 0,
            0, 88, 1, /* 4561: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4566: pointer.struct.stack_st_SSL_CIPHER */
            	4571, 0,
            0, 32, 2, /* 4571: struct.stack_st_fake_SSL_CIPHER */
            	4578, 8,
            	86, 24,
            8884099, 8, 2, /* 4578: pointer_to_array_of_pointers_to_stack */
            	4585, 0,
            	83, 20,
            0, 8, 1, /* 4585: pointer.SSL_CIPHER */
            	4590, 0,
            0, 0, 1, /* 4590: SSL_CIPHER */
            	4595, 0,
            0, 88, 1, /* 4595: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4600: pointer.struct.ssl_session_st */
            	2750, 0,
            8884097, 8, 0, /* 4605: pointer.func */
            0, 40, 3, /* 4608: struct.X509_name_st */
            	4617, 0,
            	4641, 16,
            	78, 24,
            1, 8, 1, /* 4617: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4622, 0,
            0, 32, 2, /* 4622: struct.stack_st_fake_X509_NAME_ENTRY */
            	4629, 8,
            	86, 24,
            8884099, 8, 2, /* 4629: pointer_to_array_of_pointers_to_stack */
            	4636, 0,
            	83, 20,
            0, 8, 1, /* 4636: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 4641: pointer.struct.buf_mem_st */
            	4646, 0,
            0, 24, 1, /* 4646: struct.buf_mem_st */
            	178, 8,
            8884097, 8, 0, /* 4651: pointer.func */
            1, 8, 1, /* 4654: pointer.struct.comp_method_st */
            	4659, 0,
            0, 64, 7, /* 4659: struct.comp_method_st */
            	5, 8,
            	4676, 16,
            	4679, 24,
            	4682, 32,
            	4682, 40,
            	342, 48,
            	342, 56,
            8884097, 8, 0, /* 4676: pointer.func */
            8884097, 8, 0, /* 4679: pointer.func */
            8884097, 8, 0, /* 4682: pointer.func */
            0, 24, 2, /* 4685: struct.ssl_comp_st */
            	5, 8,
            	4654, 16,
            8884097, 8, 0, /* 4692: pointer.func */
            8884097, 8, 0, /* 4695: pointer.func */
            8884097, 8, 0, /* 4698: pointer.func */
            8884097, 8, 0, /* 4701: pointer.func */
            8884097, 8, 0, /* 4704: pointer.func */
            8884097, 8, 0, /* 4707: pointer.func */
            8884097, 8, 0, /* 4710: pointer.func */
            1, 8, 1, /* 4713: pointer.struct.comp_ctx_st */
            	4718, 0,
            0, 56, 2, /* 4718: struct.comp_ctx_st */
            	4654, 0,
            	2676, 40,
            0, 40, 4, /* 4725: struct.dtls1_retransmit_state */
            	4736, 0,
            	4786, 8,
            	4713, 16,
            	2745, 24,
            1, 8, 1, /* 4736: pointer.struct.evp_cipher_ctx_st */
            	4741, 0,
            0, 168, 4, /* 4741: struct.evp_cipher_ctx_st */
            	4752, 0,
            	2734, 8,
            	273, 96,
            	273, 120,
            1, 8, 1, /* 4752: pointer.struct.evp_cipher_st */
            	4757, 0,
            0, 88, 7, /* 4757: struct.evp_cipher_st */
            	4774, 24,
            	4777, 32,
            	4704, 40,
            	4780, 56,
            	4780, 64,
            	4783, 72,
            	273, 80,
            8884097, 8, 0, /* 4774: pointer.func */
            8884097, 8, 0, /* 4777: pointer.func */
            8884097, 8, 0, /* 4780: pointer.func */
            8884097, 8, 0, /* 4783: pointer.func */
            1, 8, 1, /* 4786: pointer.struct.env_md_ctx_st */
            	4791, 0,
            0, 48, 5, /* 4791: struct.env_md_ctx_st */
            	4501, 0,
            	2734, 8,
            	273, 24,
            	4804, 32,
            	4528, 40,
            1, 8, 1, /* 4804: pointer.struct.evp_pkey_ctx_st */
            	4809, 0,
            0, 0, 0, /* 4809: struct.evp_pkey_ctx_st */
            0, 0, 0, /* 4812: struct._pqueue */
            0, 16, 1, /* 4815: struct.record_pqueue_st */
            	4820, 8,
            1, 8, 1, /* 4820: pointer.struct._pqueue */
            	4812, 0,
            8884097, 8, 0, /* 4825: pointer.func */
            8884097, 8, 0, /* 4828: pointer.func */
            8884097, 8, 0, /* 4831: pointer.func */
            1, 8, 1, /* 4834: pointer.struct.ssl3_enc_method */
            	4839, 0,
            0, 112, 11, /* 4839: struct.ssl3_enc_method */
            	4864, 0,
            	4867, 8,
            	4870, 16,
            	4828, 24,
            	4864, 32,
            	4873, 40,
            	4876, 56,
            	5, 64,
            	5, 80,
            	4879, 96,
            	4831, 104,
            8884097, 8, 0, /* 4864: pointer.func */
            8884097, 8, 0, /* 4867: pointer.func */
            8884097, 8, 0, /* 4870: pointer.func */
            8884097, 8, 0, /* 4873: pointer.func */
            8884097, 8, 0, /* 4876: pointer.func */
            8884097, 8, 0, /* 4879: pointer.func */
            0, 80, 9, /* 4882: struct.bio_method_st */
            	5, 8,
            	4903, 16,
            	4906, 24,
            	4909, 32,
            	4906, 40,
            	4912, 48,
            	4915, 56,
            	4915, 64,
            	4918, 72,
            8884097, 8, 0, /* 4903: pointer.func */
            8884097, 8, 0, /* 4906: pointer.func */
            8884097, 8, 0, /* 4909: pointer.func */
            8884097, 8, 0, /* 4912: pointer.func */
            8884097, 8, 0, /* 4915: pointer.func */
            8884097, 8, 0, /* 4918: pointer.func */
            1, 8, 1, /* 4921: pointer.struct.bio_st */
            	4926, 0,
            0, 112, 7, /* 4926: struct.bio_st */
            	4943, 0,
            	4948, 8,
            	178, 16,
            	273, 48,
            	4921, 56,
            	4921, 64,
            	2676, 96,
            1, 8, 1, /* 4943: pointer.struct.bio_method_st */
            	4882, 0,
            8884097, 8, 0, /* 4948: pointer.func */
            0, 1200, 10, /* 4951: struct.ssl3_state_st */
            	4974, 240,
            	4974, 264,
            	4979, 288,
            	4979, 344,
            	60, 432,
            	4988, 440,
            	4993, 448,
            	273, 496,
            	273, 512,
            	4998, 528,
            0, 24, 1, /* 4974: struct.ssl3_buffer_st */
            	78, 0,
            0, 56, 3, /* 4979: struct.ssl3_record_st */
            	78, 16,
            	78, 24,
            	78, 32,
            1, 8, 1, /* 4988: pointer.struct.bio_st */
            	4926, 0,
            1, 8, 1, /* 4993: pointer.pointer.struct.env_md_ctx_st */
            	4786, 0,
            0, 528, 8, /* 4998: struct.unknown */
            	4556, 408,
            	2630, 416,
            	4551, 424,
            	5017, 464,
            	78, 480,
            	4752, 488,
            	4501, 496,
            	5046, 512,
            1, 8, 1, /* 5017: pointer.struct.stack_st_X509_NAME */
            	5022, 0,
            0, 32, 2, /* 5022: struct.stack_st_fake_X509_NAME */
            	5029, 8,
            	86, 24,
            8884099, 8, 2, /* 5029: pointer_to_array_of_pointers_to_stack */
            	5036, 0,
            	83, 20,
            0, 8, 1, /* 5036: pointer.X509_NAME */
            	5041, 0,
            0, 0, 1, /* 5041: X509_NAME */
            	4608, 0,
            1, 8, 1, /* 5046: pointer.struct.ssl_comp_st */
            	4685, 0,
            8884097, 8, 0, /* 5051: pointer.func */
            8884097, 8, 0, /* 5054: pointer.func */
            8884097, 8, 0, /* 5057: pointer.func */
            8884097, 8, 0, /* 5060: pointer.func */
            0, 888, 7, /* 5063: struct.dtls1_state_st */
            	4815, 576,
            	4815, 592,
            	4820, 608,
            	4820, 616,
            	4815, 624,
            	5080, 648,
            	5080, 736,
            0, 88, 1, /* 5080: struct.hm_header_st */
            	4725, 48,
            0, 736, 50, /* 5085: struct.ssl_ctx_st */
            	5188, 0,
            	4566, 8,
            	4566, 16,
            	5279, 24,
            	423, 32,
            	4600, 48,
            	4600, 56,
            	458, 80,
            	4651, 88,
            	389, 96,
            	2624, 152,
            	273, 160,
            	4701, 168,
            	273, 176,
            	4605, 184,
            	4698, 192,
            	386, 200,
            	2676, 208,
            	4501, 224,
            	4501, 232,
            	4501, 240,
            	2799, 248,
            	362, 256,
            	4825, 264,
            	5017, 272,
            	5389, 304,
            	5420, 320,
            	273, 328,
            	5377, 376,
            	5423, 384,
            	5365, 392,
            	2734, 408,
            	276, 416,
            	273, 424,
            	2627, 480,
            	279, 488,
            	273, 496,
            	313, 504,
            	273, 512,
            	178, 520,
            	5426, 528,
            	5429, 536,
            	5432, 552,
            	5432, 560,
            	242, 568,
            	239, 696,
            	273, 704,
            	5442, 712,
            	273, 720,
            	5445, 728,
            1, 8, 1, /* 5188: pointer.struct.ssl_method_st */
            	5193, 0,
            0, 232, 28, /* 5193: struct.ssl_method_st */
            	4870, 8,
            	2742, 16,
            	2742, 24,
            	4870, 32,
            	4870, 40,
            	5252, 48,
            	5252, 56,
            	5060, 64,
            	4870, 72,
            	4870, 80,
            	4870, 88,
            	5057, 96,
            	5051, 104,
            	5255, 112,
            	4870, 120,
            	5054, 128,
            	5258, 136,
            	4710, 144,
            	5261, 152,
            	5264, 160,
            	5267, 168,
            	5270, 176,
            	5273, 184,
            	342, 192,
            	4834, 200,
            	5267, 208,
            	4695, 216,
            	5276, 224,
            8884097, 8, 0, /* 5252: pointer.func */
            8884097, 8, 0, /* 5255: pointer.func */
            8884097, 8, 0, /* 5258: pointer.func */
            8884097, 8, 0, /* 5261: pointer.func */
            8884097, 8, 0, /* 5264: pointer.func */
            8884097, 8, 0, /* 5267: pointer.func */
            8884097, 8, 0, /* 5270: pointer.func */
            8884097, 8, 0, /* 5273: pointer.func */
            8884097, 8, 0, /* 5276: pointer.func */
            1, 8, 1, /* 5279: pointer.struct.x509_store_st */
            	5284, 0,
            0, 144, 15, /* 5284: struct.x509_store_st */
            	5317, 8,
            	5341, 16,
            	5365, 24,
            	434, 32,
            	5377, 40,
            	5380, 48,
            	5383, 56,
            	434, 64,
            	4707, 72,
            	431, 80,
            	5386, 88,
            	428, 96,
            	4692, 104,
            	434, 112,
            	2676, 120,
            1, 8, 1, /* 5317: pointer.struct.stack_st_X509_OBJECT */
            	5322, 0,
            0, 32, 2, /* 5322: struct.stack_st_fake_X509_OBJECT */
            	5329, 8,
            	86, 24,
            8884099, 8, 2, /* 5329: pointer_to_array_of_pointers_to_stack */
            	5336, 0,
            	83, 20,
            0, 8, 1, /* 5336: pointer.X509_OBJECT */
            	610, 0,
            1, 8, 1, /* 5341: pointer.struct.stack_st_X509_LOOKUP */
            	5346, 0,
            0, 32, 2, /* 5346: struct.stack_st_fake_X509_LOOKUP */
            	5353, 8,
            	86, 24,
            8884099, 8, 2, /* 5353: pointer_to_array_of_pointers_to_stack */
            	5360, 0,
            	83, 20,
            0, 8, 1, /* 5360: pointer.X509_LOOKUP */
            	485, 0,
            1, 8, 1, /* 5365: pointer.struct.X509_VERIFY_PARAM_st */
            	5370, 0,
            0, 56, 2, /* 5370: struct.X509_VERIFY_PARAM_st */
            	178, 0,
            	4453, 48,
            8884097, 8, 0, /* 5377: pointer.func */
            8884097, 8, 0, /* 5380: pointer.func */
            8884097, 8, 0, /* 5383: pointer.func */
            8884097, 8, 0, /* 5386: pointer.func */
            1, 8, 1, /* 5389: pointer.struct.cert_st */
            	5394, 0,
            0, 296, 7, /* 5394: struct.cert_st */
            	3675, 0,
            	4546, 48,
            	5411, 56,
            	2630, 64,
            	5414, 72,
            	4551, 80,
            	5417, 88,
            8884097, 8, 0, /* 5411: pointer.func */
            8884097, 8, 0, /* 5414: pointer.func */
            8884097, 8, 0, /* 5417: pointer.func */
            8884097, 8, 0, /* 5420: pointer.func */
            8884097, 8, 0, /* 5423: pointer.func */
            8884097, 8, 0, /* 5426: pointer.func */
            8884097, 8, 0, /* 5429: pointer.func */
            1, 8, 1, /* 5432: pointer.struct.ssl3_buf_freelist_st */
            	5437, 0,
            0, 24, 1, /* 5437: struct.ssl3_buf_freelist_st */
            	303, 16,
            8884097, 8, 0, /* 5442: pointer.func */
            1, 8, 1, /* 5445: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	5450, 0,
            0, 32, 2, /* 5450: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	5457, 8,
            	86, 24,
            8884099, 8, 2, /* 5457: pointer_to_array_of_pointers_to_stack */
            	5464, 0,
            	83, 20,
            0, 8, 1, /* 5464: pointer.SRTP_PROTECTION_PROFILE */
            	229, 0,
            1, 8, 1, /* 5469: pointer.struct.ssl2_state_st */
            	5474, 0,
            0, 344, 9, /* 5474: struct.ssl2_state_st */
            	60, 24,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 104,
            	78, 112,
            	78, 120,
            	78, 128,
            	78, 136,
            0, 808, 51, /* 5495: struct.ssl_st */
            	5188, 8,
            	4988, 16,
            	4988, 24,
            	4988, 32,
            	4870, 48,
            	3956, 80,
            	273, 88,
            	78, 104,
            	5469, 120,
            	5600, 128,
            	5605, 136,
            	5420, 152,
            	273, 160,
            	5365, 176,
            	4566, 184,
            	4566, 192,
            	4736, 208,
            	4786, 216,
            	4713, 224,
            	4736, 232,
            	4786, 240,
            	4713, 248,
            	5389, 256,
            	2745, 304,
            	5423, 312,
            	5377, 328,
            	4825, 336,
            	5426, 352,
            	5429, 360,
            	5610, 368,
            	2676, 392,
            	5017, 408,
            	5615, 464,
            	273, 472,
            	178, 480,
            	200, 504,
            	10, 512,
            	78, 520,
            	78, 544,
            	78, 560,
            	273, 568,
            	2619, 584,
            	5618, 592,
            	273, 600,
            	5621, 608,
            	273, 616,
            	5610, 624,
            	78, 632,
            	5445, 648,
            	5624, 656,
            	242, 680,
            1, 8, 1, /* 5600: pointer.struct.ssl3_state_st */
            	4951, 0,
            1, 8, 1, /* 5605: pointer.struct.dtls1_state_st */
            	5063, 0,
            1, 8, 1, /* 5610: pointer.struct.ssl_ctx_st */
            	5085, 0,
            8884097, 8, 0, /* 5615: pointer.func */
            8884097, 8, 0, /* 5618: pointer.func */
            8884097, 8, 0, /* 5621: pointer.func */
            1, 8, 1, /* 5624: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            0, 1, 0, /* 5629: char */
            1, 8, 1, /* 5632: pointer.struct.ssl_st */
            	5495, 0,
        },
        .arg_entity_index = { 5632, 83, 5377, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int (*new_arg_c)(int, X509_STORE_CTX *) = *((int (**)(int, X509_STORE_CTX *))new_args->args[2]);

    void (*orig_SSL_set_verify)(SSL *,int,int (*)(int, X509_STORE_CTX *));
    orig_SSL_set_verify = dlsym(RTLD_NEXT, "SSL_set_verify");
    (*orig_SSL_set_verify)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

}

