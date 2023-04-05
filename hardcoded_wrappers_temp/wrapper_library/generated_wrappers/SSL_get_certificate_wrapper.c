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

X509 * bb_SSL_get_certificate(const SSL * arg_a);

X509 * SSL_get_certificate(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_certificate called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_certificate(arg_a);
    else {
        X509 * (*orig_SSL_get_certificate)(const SSL *);
        orig_SSL_get_certificate = dlsym(RTLD_NEXT, "SSL_get_certificate");
        return orig_SSL_get_certificate(arg_a);
    }
}

X509 * bb_SSL_get_certificate(const SSL * arg_a) 
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
            0, 24, 1, /* 94: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 99: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 104: pointer.struct.stack_st_X509_NAME_ENTRY */
            	109, 0,
            0, 32, 2, /* 109: struct.stack_st_fake_X509_NAME_ENTRY */
            	116, 8,
            	86, 24,
            8884099, 8, 2, /* 116: pointer_to_array_of_pointers_to_stack */
            	123, 0,
            	83, 20,
            0, 8, 1, /* 123: pointer.X509_NAME_ENTRY */
            	128, 0,
            0, 0, 1, /* 128: X509_NAME_ENTRY */
            	133, 0,
            0, 24, 2, /* 133: struct.X509_name_entry_st */
            	140, 0,
            	154, 8,
            1, 8, 1, /* 140: pointer.struct.asn1_object_st */
            	145, 0,
            0, 40, 3, /* 145: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 154: pointer.struct.asn1_string_st */
            	159, 0,
            0, 24, 1, /* 159: struct.asn1_string_st */
            	78, 8,
            0, 40, 3, /* 164: struct.X509_name_st */
            	104, 0,
            	173, 16,
            	78, 24,
            1, 8, 1, /* 173: pointer.struct.buf_mem_st */
            	94, 0,
            1, 8, 1, /* 178: pointer.struct.X509_name_st */
            	164, 0,
            0, 8, 2, /* 183: union.unknown */
            	178, 0,
            	190, 0,
            1, 8, 1, /* 190: pointer.struct.asn1_string_st */
            	89, 0,
            1, 8, 1, /* 195: pointer.struct.stack_st_OCSP_RESPID */
            	200, 0,
            0, 32, 2, /* 200: struct.stack_st_fake_OCSP_RESPID */
            	207, 8,
            	86, 24,
            8884099, 8, 2, /* 207: pointer_to_array_of_pointers_to_stack */
            	214, 0,
            	83, 20,
            0, 8, 1, /* 214: pointer.OCSP_RESPID */
            	219, 0,
            0, 0, 1, /* 219: OCSP_RESPID */
            	224, 0,
            0, 16, 1, /* 224: struct.ocsp_responder_id_st */
            	183, 8,
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
            	99, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	285, 96,
            	99, 104,
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
            0, 64, 7, /* 319: struct.comp_method_st */
            	5, 8,
            	336, 16,
            	316, 24,
            	339, 32,
            	339, 40,
            	342, 48,
            	342, 56,
            8884097, 8, 0, /* 336: pointer.func */
            8884097, 8, 0, /* 339: pointer.func */
            8884097, 8, 0, /* 342: pointer.func */
            1, 8, 1, /* 345: pointer.struct.comp_method_st */
            	319, 0,
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
            1, 8, 1, /* 404: pointer.struct.lhash_node_st */
            	397, 0,
            1, 8, 1, /* 409: pointer.pointer.struct.lhash_node_st */
            	404, 0,
            0, 176, 3, /* 414: struct.lhash_st */
            	409, 0,
            	86, 8,
            	423, 16,
            8884097, 8, 0, /* 423: pointer.func */
            1, 8, 1, /* 426: pointer.struct.lhash_st */
            	414, 0,
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
            8884097, 8, 0, /* 461: pointer.func */
            1, 8, 1, /* 464: pointer.struct.stack_st_X509_LOOKUP */
            	469, 0,
            0, 32, 2, /* 469: struct.stack_st_fake_X509_LOOKUP */
            	476, 8,
            	86, 24,
            8884099, 8, 2, /* 476: pointer_to_array_of_pointers_to_stack */
            	483, 0,
            	83, 20,
            0, 8, 1, /* 483: pointer.X509_LOOKUP */
            	488, 0,
            0, 0, 1, /* 488: X509_LOOKUP */
            	493, 0,
            0, 32, 3, /* 493: struct.x509_lookup_st */
            	502, 8,
            	99, 16,
            	551, 24,
            1, 8, 1, /* 502: pointer.struct.x509_lookup_method_st */
            	507, 0,
            0, 80, 10, /* 507: struct.x509_lookup_method_st */
            	5, 0,
            	530, 8,
            	533, 16,
            	530, 24,
            	530, 32,
            	536, 40,
            	539, 48,
            	542, 56,
            	545, 64,
            	548, 72,
            8884097, 8, 0, /* 530: pointer.func */
            8884097, 8, 0, /* 533: pointer.func */
            8884097, 8, 0, /* 536: pointer.func */
            8884097, 8, 0, /* 539: pointer.func */
            8884097, 8, 0, /* 542: pointer.func */
            8884097, 8, 0, /* 545: pointer.func */
            8884097, 8, 0, /* 548: pointer.func */
            1, 8, 1, /* 551: pointer.struct.x509_store_st */
            	556, 0,
            0, 144, 15, /* 556: struct.x509_store_st */
            	589, 8,
            	464, 16,
            	2466, 24,
            	458, 32,
            	455, 40,
            	2478, 48,
            	452, 56,
            	458, 64,
            	449, 72,
            	446, 80,
            	2481, 88,
            	443, 96,
            	440, 104,
            	458, 112,
            	1094, 120,
            1, 8, 1, /* 589: pointer.struct.stack_st_X509_OBJECT */
            	594, 0,
            0, 32, 2, /* 594: struct.stack_st_fake_X509_OBJECT */
            	601, 8,
            	86, 24,
            8884099, 8, 2, /* 601: pointer_to_array_of_pointers_to_stack */
            	608, 0,
            	83, 20,
            0, 8, 1, /* 608: pointer.X509_OBJECT */
            	613, 0,
            0, 0, 1, /* 613: X509_OBJECT */
            	618, 0,
            0, 16, 1, /* 618: struct.x509_object_st */
            	623, 8,
            0, 8, 4, /* 623: union.unknown */
            	99, 0,
            	634, 0,
            	2254, 0,
            	942, 0,
            1, 8, 1, /* 634: pointer.struct.x509_st */
            	639, 0,
            0, 184, 12, /* 639: struct.x509_st */
            	666, 0,
            	706, 8,
            	795, 16,
            	99, 32,
            	1094, 40,
            	800, 104,
            	1700, 112,
            	1708, 120,
            	1716, 128,
            	2125, 136,
            	2149, 144,
            	2157, 176,
            1, 8, 1, /* 666: pointer.struct.x509_cinf_st */
            	671, 0,
            0, 104, 11, /* 671: struct.x509_cinf_st */
            	696, 0,
            	696, 8,
            	706, 16,
            	863, 24,
            	911, 32,
            	863, 40,
            	928, 48,
            	795, 56,
            	795, 64,
            	1671, 72,
            	1695, 80,
            1, 8, 1, /* 696: pointer.struct.asn1_string_st */
            	701, 0,
            0, 24, 1, /* 701: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 706: pointer.struct.X509_algor_st */
            	711, 0,
            0, 16, 2, /* 711: struct.X509_algor_st */
            	718, 0,
            	732, 8,
            1, 8, 1, /* 718: pointer.struct.asn1_object_st */
            	723, 0,
            0, 40, 3, /* 723: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 732: pointer.struct.asn1_type_st */
            	737, 0,
            0, 16, 1, /* 737: struct.asn1_type_st */
            	742, 8,
            0, 8, 20, /* 742: union.unknown */
            	99, 0,
            	785, 0,
            	718, 0,
            	696, 0,
            	790, 0,
            	795, 0,
            	800, 0,
            	805, 0,
            	810, 0,
            	815, 0,
            	820, 0,
            	825, 0,
            	830, 0,
            	835, 0,
            	840, 0,
            	845, 0,
            	850, 0,
            	785, 0,
            	785, 0,
            	855, 0,
            1, 8, 1, /* 785: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 790: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 795: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 800: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 805: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 810: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 815: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 820: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 825: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 830: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 835: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 840: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 845: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 850: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 855: pointer.struct.ASN1_VALUE_st */
            	860, 0,
            0, 0, 0, /* 860: struct.ASN1_VALUE_st */
            1, 8, 1, /* 863: pointer.struct.X509_name_st */
            	868, 0,
            0, 40, 3, /* 868: struct.X509_name_st */
            	877, 0,
            	901, 16,
            	78, 24,
            1, 8, 1, /* 877: pointer.struct.stack_st_X509_NAME_ENTRY */
            	882, 0,
            0, 32, 2, /* 882: struct.stack_st_fake_X509_NAME_ENTRY */
            	889, 8,
            	86, 24,
            8884099, 8, 2, /* 889: pointer_to_array_of_pointers_to_stack */
            	896, 0,
            	83, 20,
            0, 8, 1, /* 896: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 901: pointer.struct.buf_mem_st */
            	906, 0,
            0, 24, 1, /* 906: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 911: pointer.struct.X509_val_st */
            	916, 0,
            0, 16, 2, /* 916: struct.X509_val_st */
            	923, 0,
            	923, 8,
            1, 8, 1, /* 923: pointer.struct.asn1_string_st */
            	701, 0,
            1, 8, 1, /* 928: pointer.struct.X509_pubkey_st */
            	933, 0,
            0, 24, 3, /* 933: struct.X509_pubkey_st */
            	706, 0,
            	795, 8,
            	942, 16,
            1, 8, 1, /* 942: pointer.struct.evp_pkey_st */
            	947, 0,
            0, 56, 4, /* 947: struct.evp_pkey_st */
            	958, 16,
            	966, 24,
            	974, 32,
            	1300, 48,
            1, 8, 1, /* 958: pointer.struct.evp_pkey_asn1_method_st */
            	963, 0,
            0, 0, 0, /* 963: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 966: pointer.struct.engine_st */
            	971, 0,
            0, 0, 0, /* 971: struct.engine_st */
            0, 8, 5, /* 974: union.unknown */
            	99, 0,
            	987, 0,
            	1143, 0,
            	1224, 0,
            	1292, 0,
            1, 8, 1, /* 987: pointer.struct.rsa_st */
            	992, 0,
            0, 168, 17, /* 992: struct.rsa_st */
            	1029, 16,
            	966, 24,
            	1084, 32,
            	1084, 40,
            	1084, 48,
            	1084, 56,
            	1084, 64,
            	1084, 72,
            	1084, 80,
            	1084, 88,
            	1094, 96,
            	1121, 120,
            	1121, 128,
            	1121, 136,
            	99, 144,
            	1135, 152,
            	1135, 160,
            1, 8, 1, /* 1029: pointer.struct.rsa_meth_st */
            	1034, 0,
            0, 112, 13, /* 1034: struct.rsa_meth_st */
            	5, 0,
            	1063, 8,
            	1063, 16,
            	1063, 24,
            	1063, 32,
            	1066, 40,
            	1069, 48,
            	1072, 56,
            	1072, 64,
            	99, 80,
            	1075, 88,
            	1078, 96,
            	1081, 104,
            8884097, 8, 0, /* 1063: pointer.func */
            8884097, 8, 0, /* 1066: pointer.func */
            8884097, 8, 0, /* 1069: pointer.func */
            8884097, 8, 0, /* 1072: pointer.func */
            8884097, 8, 0, /* 1075: pointer.func */
            8884097, 8, 0, /* 1078: pointer.func */
            8884097, 8, 0, /* 1081: pointer.func */
            1, 8, 1, /* 1084: pointer.struct.bignum_st */
            	1089, 0,
            0, 24, 1, /* 1089: struct.bignum_st */
            	295, 0,
            0, 16, 1, /* 1094: struct.crypto_ex_data_st */
            	1099, 0,
            1, 8, 1, /* 1099: pointer.struct.stack_st_void */
            	1104, 0,
            0, 32, 1, /* 1104: struct.stack_st_void */
            	1109, 0,
            0, 32, 2, /* 1109: struct.stack_st */
            	1116, 8,
            	86, 24,
            1, 8, 1, /* 1116: pointer.pointer.char */
            	99, 0,
            1, 8, 1, /* 1121: pointer.struct.bn_mont_ctx_st */
            	1126, 0,
            0, 96, 3, /* 1126: struct.bn_mont_ctx_st */
            	1089, 8,
            	1089, 32,
            	1089, 56,
            1, 8, 1, /* 1135: pointer.struct.bn_blinding_st */
            	1140, 0,
            0, 0, 0, /* 1140: struct.bn_blinding_st */
            1, 8, 1, /* 1143: pointer.struct.dsa_st */
            	1148, 0,
            0, 136, 11, /* 1148: struct.dsa_st */
            	1084, 24,
            	1084, 32,
            	1084, 40,
            	1084, 48,
            	1084, 56,
            	1084, 64,
            	1084, 72,
            	1121, 88,
            	1094, 104,
            	1173, 120,
            	966, 128,
            1, 8, 1, /* 1173: pointer.struct.dsa_method */
            	1178, 0,
            0, 96, 11, /* 1178: struct.dsa_method */
            	5, 0,
            	1203, 8,
            	1206, 16,
            	1209, 24,
            	1212, 32,
            	1215, 40,
            	1218, 48,
            	1218, 56,
            	99, 72,
            	1221, 80,
            	1218, 88,
            8884097, 8, 0, /* 1203: pointer.func */
            8884097, 8, 0, /* 1206: pointer.func */
            8884097, 8, 0, /* 1209: pointer.func */
            8884097, 8, 0, /* 1212: pointer.func */
            8884097, 8, 0, /* 1215: pointer.func */
            8884097, 8, 0, /* 1218: pointer.func */
            8884097, 8, 0, /* 1221: pointer.func */
            1, 8, 1, /* 1224: pointer.struct.dh_st */
            	1229, 0,
            0, 144, 12, /* 1229: struct.dh_st */
            	1084, 8,
            	1084, 16,
            	1084, 32,
            	1084, 40,
            	1121, 56,
            	1084, 64,
            	1084, 72,
            	78, 80,
            	1084, 96,
            	1094, 112,
            	1256, 128,
            	966, 136,
            1, 8, 1, /* 1256: pointer.struct.dh_method */
            	1261, 0,
            0, 72, 8, /* 1261: struct.dh_method */
            	5, 0,
            	1280, 8,
            	1283, 16,
            	1286, 24,
            	1280, 32,
            	1280, 40,
            	99, 56,
            	1289, 64,
            8884097, 8, 0, /* 1280: pointer.func */
            8884097, 8, 0, /* 1283: pointer.func */
            8884097, 8, 0, /* 1286: pointer.func */
            8884097, 8, 0, /* 1289: pointer.func */
            1, 8, 1, /* 1292: pointer.struct.ec_key_st */
            	1297, 0,
            0, 0, 0, /* 1297: struct.ec_key_st */
            1, 8, 1, /* 1300: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1305, 0,
            0, 32, 2, /* 1305: struct.stack_st_fake_X509_ATTRIBUTE */
            	1312, 8,
            	86, 24,
            8884099, 8, 2, /* 1312: pointer_to_array_of_pointers_to_stack */
            	1319, 0,
            	83, 20,
            0, 8, 1, /* 1319: pointer.X509_ATTRIBUTE */
            	1324, 0,
            0, 0, 1, /* 1324: X509_ATTRIBUTE */
            	1329, 0,
            0, 24, 2, /* 1329: struct.x509_attributes_st */
            	1336, 0,
            	1350, 16,
            1, 8, 1, /* 1336: pointer.struct.asn1_object_st */
            	1341, 0,
            0, 40, 3, /* 1341: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            0, 8, 3, /* 1350: union.unknown */
            	99, 0,
            	1359, 0,
            	1538, 0,
            1, 8, 1, /* 1359: pointer.struct.stack_st_ASN1_TYPE */
            	1364, 0,
            0, 32, 2, /* 1364: struct.stack_st_fake_ASN1_TYPE */
            	1371, 8,
            	86, 24,
            8884099, 8, 2, /* 1371: pointer_to_array_of_pointers_to_stack */
            	1378, 0,
            	83, 20,
            0, 8, 1, /* 1378: pointer.ASN1_TYPE */
            	1383, 0,
            0, 0, 1, /* 1383: ASN1_TYPE */
            	1388, 0,
            0, 16, 1, /* 1388: struct.asn1_type_st */
            	1393, 8,
            0, 8, 20, /* 1393: union.unknown */
            	99, 0,
            	1436, 0,
            	1446, 0,
            	1460, 0,
            	1465, 0,
            	1470, 0,
            	1475, 0,
            	1480, 0,
            	1485, 0,
            	1490, 0,
            	1495, 0,
            	1500, 0,
            	1505, 0,
            	1510, 0,
            	1515, 0,
            	1520, 0,
            	1525, 0,
            	1436, 0,
            	1436, 0,
            	1530, 0,
            1, 8, 1, /* 1436: pointer.struct.asn1_string_st */
            	1441, 0,
            0, 24, 1, /* 1441: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1446: pointer.struct.asn1_object_st */
            	1451, 0,
            0, 40, 3, /* 1451: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1460: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1465: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1470: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1475: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1480: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1485: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1490: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1495: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1500: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1505: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1510: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1515: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1520: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1525: pointer.struct.asn1_string_st */
            	1441, 0,
            1, 8, 1, /* 1530: pointer.struct.ASN1_VALUE_st */
            	1535, 0,
            0, 0, 0, /* 1535: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1538: pointer.struct.asn1_type_st */
            	1543, 0,
            0, 16, 1, /* 1543: struct.asn1_type_st */
            	1548, 8,
            0, 8, 20, /* 1548: union.unknown */
            	99, 0,
            	1591, 0,
            	1336, 0,
            	1601, 0,
            	1606, 0,
            	1611, 0,
            	1616, 0,
            	1621, 0,
            	1626, 0,
            	1631, 0,
            	1636, 0,
            	1641, 0,
            	1646, 0,
            	1651, 0,
            	1656, 0,
            	1661, 0,
            	1666, 0,
            	1591, 0,
            	1591, 0,
            	855, 0,
            1, 8, 1, /* 1591: pointer.struct.asn1_string_st */
            	1596, 0,
            0, 24, 1, /* 1596: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1601: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1606: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1611: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1616: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1621: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1626: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1631: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1636: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1641: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1646: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1651: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1656: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1661: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1666: pointer.struct.asn1_string_st */
            	1596, 0,
            1, 8, 1, /* 1671: pointer.struct.stack_st_X509_EXTENSION */
            	1676, 0,
            0, 32, 2, /* 1676: struct.stack_st_fake_X509_EXTENSION */
            	1683, 8,
            	86, 24,
            8884099, 8, 2, /* 1683: pointer_to_array_of_pointers_to_stack */
            	1690, 0,
            	83, 20,
            0, 8, 1, /* 1690: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 1695: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 1700: pointer.struct.AUTHORITY_KEYID_st */
            	1705, 0,
            0, 0, 0, /* 1705: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1708: pointer.struct.X509_POLICY_CACHE_st */
            	1713, 0,
            0, 0, 0, /* 1713: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1716: pointer.struct.stack_st_DIST_POINT */
            	1721, 0,
            0, 32, 2, /* 1721: struct.stack_st_fake_DIST_POINT */
            	1728, 8,
            	86, 24,
            8884099, 8, 2, /* 1728: pointer_to_array_of_pointers_to_stack */
            	1735, 0,
            	83, 20,
            0, 8, 1, /* 1735: pointer.DIST_POINT */
            	1740, 0,
            0, 0, 1, /* 1740: DIST_POINT */
            	1745, 0,
            0, 32, 3, /* 1745: struct.DIST_POINT_st */
            	1754, 0,
            	2115, 8,
            	1773, 16,
            1, 8, 1, /* 1754: pointer.struct.DIST_POINT_NAME_st */
            	1759, 0,
            0, 24, 2, /* 1759: struct.DIST_POINT_NAME_st */
            	1766, 8,
            	2091, 16,
            0, 8, 2, /* 1766: union.unknown */
            	1773, 0,
            	2067, 0,
            1, 8, 1, /* 1773: pointer.struct.stack_st_GENERAL_NAME */
            	1778, 0,
            0, 32, 2, /* 1778: struct.stack_st_fake_GENERAL_NAME */
            	1785, 8,
            	86, 24,
            8884099, 8, 2, /* 1785: pointer_to_array_of_pointers_to_stack */
            	1792, 0,
            	83, 20,
            0, 8, 1, /* 1792: pointer.GENERAL_NAME */
            	1797, 0,
            0, 0, 1, /* 1797: GENERAL_NAME */
            	1802, 0,
            0, 16, 1, /* 1802: struct.GENERAL_NAME_st */
            	1807, 8,
            0, 8, 15, /* 1807: union.unknown */
            	99, 0,
            	1840, 0,
            	1959, 0,
            	1959, 0,
            	1866, 0,
            	2007, 0,
            	2055, 0,
            	1959, 0,
            	1944, 0,
            	1852, 0,
            	1944, 0,
            	2007, 0,
            	1959, 0,
            	1852, 0,
            	1866, 0,
            1, 8, 1, /* 1840: pointer.struct.otherName_st */
            	1845, 0,
            0, 16, 2, /* 1845: struct.otherName_st */
            	1852, 0,
            	1866, 8,
            1, 8, 1, /* 1852: pointer.struct.asn1_object_st */
            	1857, 0,
            0, 40, 3, /* 1857: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1866: pointer.struct.asn1_type_st */
            	1871, 0,
            0, 16, 1, /* 1871: struct.asn1_type_st */
            	1876, 8,
            0, 8, 20, /* 1876: union.unknown */
            	99, 0,
            	1919, 0,
            	1852, 0,
            	1929, 0,
            	1934, 0,
            	1939, 0,
            	1944, 0,
            	1949, 0,
            	1954, 0,
            	1959, 0,
            	1964, 0,
            	1969, 0,
            	1974, 0,
            	1979, 0,
            	1984, 0,
            	1989, 0,
            	1994, 0,
            	1919, 0,
            	1919, 0,
            	1999, 0,
            1, 8, 1, /* 1919: pointer.struct.asn1_string_st */
            	1924, 0,
            0, 24, 1, /* 1924: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1929: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1934: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1939: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1944: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1949: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1954: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1959: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1964: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1969: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1974: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1979: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1984: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1989: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1994: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1999: pointer.struct.ASN1_VALUE_st */
            	2004, 0,
            0, 0, 0, /* 2004: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2007: pointer.struct.X509_name_st */
            	2012, 0,
            0, 40, 3, /* 2012: struct.X509_name_st */
            	2021, 0,
            	2045, 16,
            	78, 24,
            1, 8, 1, /* 2021: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2026, 0,
            0, 32, 2, /* 2026: struct.stack_st_fake_X509_NAME_ENTRY */
            	2033, 8,
            	86, 24,
            8884099, 8, 2, /* 2033: pointer_to_array_of_pointers_to_stack */
            	2040, 0,
            	83, 20,
            0, 8, 1, /* 2040: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 2045: pointer.struct.buf_mem_st */
            	2050, 0,
            0, 24, 1, /* 2050: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 2055: pointer.struct.EDIPartyName_st */
            	2060, 0,
            0, 16, 2, /* 2060: struct.EDIPartyName_st */
            	1919, 0,
            	1919, 8,
            1, 8, 1, /* 2067: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2072, 0,
            0, 32, 2, /* 2072: struct.stack_st_fake_X509_NAME_ENTRY */
            	2079, 8,
            	86, 24,
            8884099, 8, 2, /* 2079: pointer_to_array_of_pointers_to_stack */
            	2086, 0,
            	83, 20,
            0, 8, 1, /* 2086: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 2091: pointer.struct.X509_name_st */
            	2096, 0,
            0, 40, 3, /* 2096: struct.X509_name_st */
            	2067, 0,
            	2105, 16,
            	78, 24,
            1, 8, 1, /* 2105: pointer.struct.buf_mem_st */
            	2110, 0,
            0, 24, 1, /* 2110: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 2115: pointer.struct.asn1_string_st */
            	2120, 0,
            0, 24, 1, /* 2120: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2125: pointer.struct.stack_st_GENERAL_NAME */
            	2130, 0,
            0, 32, 2, /* 2130: struct.stack_st_fake_GENERAL_NAME */
            	2137, 8,
            	86, 24,
            8884099, 8, 2, /* 2137: pointer_to_array_of_pointers_to_stack */
            	2144, 0,
            	83, 20,
            0, 8, 1, /* 2144: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 2149: pointer.struct.NAME_CONSTRAINTS_st */
            	2154, 0,
            0, 0, 0, /* 2154: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2157: pointer.struct.x509_cert_aux_st */
            	2162, 0,
            0, 40, 5, /* 2162: struct.x509_cert_aux_st */
            	2175, 0,
            	2175, 8,
            	850, 16,
            	800, 24,
            	2213, 32,
            1, 8, 1, /* 2175: pointer.struct.stack_st_ASN1_OBJECT */
            	2180, 0,
            0, 32, 2, /* 2180: struct.stack_st_fake_ASN1_OBJECT */
            	2187, 8,
            	86, 24,
            8884099, 8, 2, /* 2187: pointer_to_array_of_pointers_to_stack */
            	2194, 0,
            	83, 20,
            0, 8, 1, /* 2194: pointer.ASN1_OBJECT */
            	2199, 0,
            0, 0, 1, /* 2199: ASN1_OBJECT */
            	2204, 0,
            0, 40, 3, /* 2204: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2213: pointer.struct.stack_st_X509_ALGOR */
            	2218, 0,
            0, 32, 2, /* 2218: struct.stack_st_fake_X509_ALGOR */
            	2225, 8,
            	86, 24,
            8884099, 8, 2, /* 2225: pointer_to_array_of_pointers_to_stack */
            	2232, 0,
            	83, 20,
            0, 8, 1, /* 2232: pointer.X509_ALGOR */
            	2237, 0,
            0, 0, 1, /* 2237: X509_ALGOR */
            	2242, 0,
            0, 16, 2, /* 2242: struct.X509_algor_st */
            	1446, 0,
            	2249, 8,
            1, 8, 1, /* 2249: pointer.struct.asn1_type_st */
            	1388, 0,
            1, 8, 1, /* 2254: pointer.struct.X509_crl_st */
            	2259, 0,
            0, 120, 10, /* 2259: struct.X509_crl_st */
            	2282, 0,
            	706, 8,
            	795, 16,
            	1700, 32,
            	2409, 40,
            	696, 56,
            	696, 64,
            	2417, 96,
            	2458, 104,
            	273, 112,
            1, 8, 1, /* 2282: pointer.struct.X509_crl_info_st */
            	2287, 0,
            0, 80, 8, /* 2287: struct.X509_crl_info_st */
            	696, 0,
            	706, 8,
            	863, 16,
            	923, 24,
            	923, 32,
            	2306, 40,
            	1671, 48,
            	1695, 56,
            1, 8, 1, /* 2306: pointer.struct.stack_st_X509_REVOKED */
            	2311, 0,
            0, 32, 2, /* 2311: struct.stack_st_fake_X509_REVOKED */
            	2318, 8,
            	86, 24,
            8884099, 8, 2, /* 2318: pointer_to_array_of_pointers_to_stack */
            	2325, 0,
            	83, 20,
            0, 8, 1, /* 2325: pointer.X509_REVOKED */
            	2330, 0,
            0, 0, 1, /* 2330: X509_REVOKED */
            	2335, 0,
            0, 40, 4, /* 2335: struct.x509_revoked_st */
            	2346, 0,
            	2356, 8,
            	2361, 16,
            	2385, 24,
            1, 8, 1, /* 2346: pointer.struct.asn1_string_st */
            	2351, 0,
            0, 24, 1, /* 2351: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2356: pointer.struct.asn1_string_st */
            	2351, 0,
            1, 8, 1, /* 2361: pointer.struct.stack_st_X509_EXTENSION */
            	2366, 0,
            0, 32, 2, /* 2366: struct.stack_st_fake_X509_EXTENSION */
            	2373, 8,
            	86, 24,
            8884099, 8, 2, /* 2373: pointer_to_array_of_pointers_to_stack */
            	2380, 0,
            	83, 20,
            0, 8, 1, /* 2380: pointer.X509_EXTENSION */
            	34, 0,
            1, 8, 1, /* 2385: pointer.struct.stack_st_GENERAL_NAME */
            	2390, 0,
            0, 32, 2, /* 2390: struct.stack_st_fake_GENERAL_NAME */
            	2397, 8,
            	86, 24,
            8884099, 8, 2, /* 2397: pointer_to_array_of_pointers_to_stack */
            	2404, 0,
            	83, 20,
            0, 8, 1, /* 2404: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 2409: pointer.struct.ISSUING_DIST_POINT_st */
            	2414, 0,
            0, 0, 0, /* 2414: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2417: pointer.struct.stack_st_GENERAL_NAMES */
            	2422, 0,
            0, 32, 2, /* 2422: struct.stack_st_fake_GENERAL_NAMES */
            	2429, 8,
            	86, 24,
            8884099, 8, 2, /* 2429: pointer_to_array_of_pointers_to_stack */
            	2436, 0,
            	83, 20,
            0, 8, 1, /* 2436: pointer.GENERAL_NAMES */
            	2441, 0,
            0, 0, 1, /* 2441: GENERAL_NAMES */
            	2446, 0,
            0, 32, 1, /* 2446: struct.stack_st_GENERAL_NAME */
            	2451, 0,
            0, 32, 2, /* 2451: struct.stack_st */
            	1116, 8,
            	86, 24,
            1, 8, 1, /* 2458: pointer.struct.x509_crl_method_st */
            	2463, 0,
            0, 0, 0, /* 2463: struct.x509_crl_method_st */
            1, 8, 1, /* 2466: pointer.struct.X509_VERIFY_PARAM_st */
            	2471, 0,
            0, 56, 2, /* 2471: struct.X509_VERIFY_PARAM_st */
            	99, 0,
            	2175, 48,
            8884097, 8, 0, /* 2478: pointer.func */
            8884097, 8, 0, /* 2481: pointer.func */
            1, 8, 1, /* 2484: pointer.struct.stack_st_X509_LOOKUP */
            	2489, 0,
            0, 32, 2, /* 2489: struct.stack_st_fake_X509_LOOKUP */
            	2496, 8,
            	86, 24,
            8884099, 8, 2, /* 2496: pointer_to_array_of_pointers_to_stack */
            	2503, 0,
            	83, 20,
            0, 8, 1, /* 2503: pointer.X509_LOOKUP */
            	488, 0,
            0, 16, 1, /* 2508: struct.tls_session_ticket_ext_st */
            	273, 8,
            1, 8, 1, /* 2513: pointer.struct.tls_session_ticket_ext_st */
            	2508, 0,
            8884097, 8, 0, /* 2518: pointer.func */
            8884097, 8, 0, /* 2521: pointer.func */
            0, 0, 0, /* 2524: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2527: pointer.struct.ASN1_VALUE_st */
            	2524, 0,
            1, 8, 1, /* 2532: pointer.struct.asn1_string_st */
            	2537, 0,
            0, 24, 1, /* 2537: struct.asn1_string_st */
            	78, 8,
            0, 16, 1, /* 2542: struct.crypto_ex_data_st */
            	2547, 0,
            1, 8, 1, /* 2547: pointer.struct.stack_st_void */
            	2552, 0,
            0, 32, 1, /* 2552: struct.stack_st_void */
            	2557, 0,
            0, 32, 2, /* 2557: struct.stack_st */
            	1116, 8,
            	86, 24,
            8884097, 8, 0, /* 2564: pointer.func */
            0, 8, 20, /* 2567: union.unknown */
            	99, 0,
            	2610, 0,
            	2615, 0,
            	2629, 0,
            	2634, 0,
            	2639, 0,
            	2644, 0,
            	2649, 0,
            	2654, 0,
            	2532, 0,
            	2659, 0,
            	2664, 0,
            	2669, 0,
            	2674, 0,
            	2679, 0,
            	2684, 0,
            	2689, 0,
            	2610, 0,
            	2610, 0,
            	2527, 0,
            1, 8, 1, /* 2610: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2615: pointer.struct.asn1_object_st */
            	2620, 0,
            0, 40, 3, /* 2620: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2629: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2634: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2639: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2644: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2649: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2654: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2659: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2664: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2669: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2674: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2679: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2684: pointer.struct.asn1_string_st */
            	2537, 0,
            1, 8, 1, /* 2689: pointer.struct.asn1_string_st */
            	2537, 0,
            0, 168, 17, /* 2694: struct.rsa_st */
            	2731, 16,
            	2786, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	2542, 96,
            	2794, 120,
            	2794, 128,
            	2794, 136,
            	99, 144,
            	2808, 152,
            	2808, 160,
            1, 8, 1, /* 2731: pointer.struct.rsa_meth_st */
            	2736, 0,
            0, 112, 13, /* 2736: struct.rsa_meth_st */
            	5, 0,
            	2765, 8,
            	2765, 16,
            	2765, 24,
            	2765, 32,
            	2768, 40,
            	2771, 48,
            	2774, 56,
            	2774, 64,
            	99, 80,
            	2777, 88,
            	2780, 96,
            	2783, 104,
            8884097, 8, 0, /* 2765: pointer.func */
            8884097, 8, 0, /* 2768: pointer.func */
            8884097, 8, 0, /* 2771: pointer.func */
            8884097, 8, 0, /* 2774: pointer.func */
            8884097, 8, 0, /* 2777: pointer.func */
            8884097, 8, 0, /* 2780: pointer.func */
            8884097, 8, 0, /* 2783: pointer.func */
            1, 8, 1, /* 2786: pointer.struct.engine_st */
            	2791, 0,
            0, 0, 0, /* 2791: struct.engine_st */
            1, 8, 1, /* 2794: pointer.struct.bn_mont_ctx_st */
            	2799, 0,
            0, 96, 3, /* 2799: struct.bn_mont_ctx_st */
            	290, 8,
            	290, 32,
            	290, 56,
            1, 8, 1, /* 2808: pointer.struct.bn_blinding_st */
            	2813, 0,
            0, 0, 0, /* 2813: struct.bn_blinding_st */
            0, 16, 2, /* 2816: struct.otherName_st */
            	2615, 0,
            	2823, 8,
            1, 8, 1, /* 2823: pointer.struct.asn1_type_st */
            	2828, 0,
            0, 16, 1, /* 2828: struct.asn1_type_st */
            	2567, 8,
            0, 296, 7, /* 2833: struct.cert_st */
            	2850, 0,
            	3787, 48,
            	3792, 56,
            	3795, 64,
            	3800, 72,
            	3803, 80,
            	3808, 88,
            1, 8, 1, /* 2850: pointer.struct.cert_pkey_st */
            	2855, 0,
            0, 24, 3, /* 2855: struct.cert_pkey_st */
            	2864, 0,
            	3172, 8,
            	3742, 16,
            1, 8, 1, /* 2864: pointer.struct.x509_st */
            	2869, 0,
            0, 184, 12, /* 2869: struct.x509_st */
            	2896, 0,
            	2936, 8,
            	3025, 16,
            	99, 32,
            	2542, 40,
            	3030, 104,
            	3424, 112,
            	3462, 120,
            	3470, 128,
            	3494, 136,
            	3518, 144,
            	3676, 176,
            1, 8, 1, /* 2896: pointer.struct.x509_cinf_st */
            	2901, 0,
            0, 104, 11, /* 2901: struct.x509_cinf_st */
            	2926, 0,
            	2926, 8,
            	2936, 16,
            	3093, 24,
            	3141, 32,
            	3093, 40,
            	3158, 48,
            	3025, 56,
            	3025, 64,
            	3395, 72,
            	3419, 80,
            1, 8, 1, /* 2926: pointer.struct.asn1_string_st */
            	2931, 0,
            0, 24, 1, /* 2931: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2936: pointer.struct.X509_algor_st */
            	2941, 0,
            0, 16, 2, /* 2941: struct.X509_algor_st */
            	2948, 0,
            	2962, 8,
            1, 8, 1, /* 2948: pointer.struct.asn1_object_st */
            	2953, 0,
            0, 40, 3, /* 2953: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2962: pointer.struct.asn1_type_st */
            	2967, 0,
            0, 16, 1, /* 2967: struct.asn1_type_st */
            	2972, 8,
            0, 8, 20, /* 2972: union.unknown */
            	99, 0,
            	3015, 0,
            	2948, 0,
            	2926, 0,
            	3020, 0,
            	3025, 0,
            	3030, 0,
            	3035, 0,
            	3040, 0,
            	3045, 0,
            	3050, 0,
            	3055, 0,
            	3060, 0,
            	3065, 0,
            	3070, 0,
            	3075, 0,
            	3080, 0,
            	3015, 0,
            	3015, 0,
            	3085, 0,
            1, 8, 1, /* 3015: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3020: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3025: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3030: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3035: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3040: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3045: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3050: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3055: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3060: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3065: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3070: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3075: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3080: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3085: pointer.struct.ASN1_VALUE_st */
            	3090, 0,
            0, 0, 0, /* 3090: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3093: pointer.struct.X509_name_st */
            	3098, 0,
            0, 40, 3, /* 3098: struct.X509_name_st */
            	3107, 0,
            	3131, 16,
            	78, 24,
            1, 8, 1, /* 3107: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3112, 0,
            0, 32, 2, /* 3112: struct.stack_st_fake_X509_NAME_ENTRY */
            	3119, 8,
            	86, 24,
            8884099, 8, 2, /* 3119: pointer_to_array_of_pointers_to_stack */
            	3126, 0,
            	83, 20,
            0, 8, 1, /* 3126: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 3131: pointer.struct.buf_mem_st */
            	3136, 0,
            0, 24, 1, /* 3136: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 3141: pointer.struct.X509_val_st */
            	3146, 0,
            0, 16, 2, /* 3146: struct.X509_val_st */
            	3153, 0,
            	3153, 8,
            1, 8, 1, /* 3153: pointer.struct.asn1_string_st */
            	2931, 0,
            1, 8, 1, /* 3158: pointer.struct.X509_pubkey_st */
            	3163, 0,
            0, 24, 3, /* 3163: struct.X509_pubkey_st */
            	2936, 0,
            	3025, 8,
            	3172, 16,
            1, 8, 1, /* 3172: pointer.struct.evp_pkey_st */
            	3177, 0,
            0, 56, 4, /* 3177: struct.evp_pkey_st */
            	3188, 16,
            	2786, 24,
            	3196, 32,
            	3371, 48,
            1, 8, 1, /* 3188: pointer.struct.evp_pkey_asn1_method_st */
            	3193, 0,
            0, 0, 0, /* 3193: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3196: union.unknown */
            	99, 0,
            	3209, 0,
            	3214, 0,
            	3295, 0,
            	3363, 0,
            1, 8, 1, /* 3209: pointer.struct.rsa_st */
            	2694, 0,
            1, 8, 1, /* 3214: pointer.struct.dsa_st */
            	3219, 0,
            0, 136, 11, /* 3219: struct.dsa_st */
            	285, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	2794, 88,
            	2542, 104,
            	3244, 120,
            	2786, 128,
            1, 8, 1, /* 3244: pointer.struct.dsa_method */
            	3249, 0,
            0, 96, 11, /* 3249: struct.dsa_method */
            	5, 0,
            	3274, 8,
            	3277, 16,
            	3280, 24,
            	3283, 32,
            	3286, 40,
            	3289, 48,
            	3289, 56,
            	99, 72,
            	3292, 80,
            	3289, 88,
            8884097, 8, 0, /* 3274: pointer.func */
            8884097, 8, 0, /* 3277: pointer.func */
            8884097, 8, 0, /* 3280: pointer.func */
            8884097, 8, 0, /* 3283: pointer.func */
            8884097, 8, 0, /* 3286: pointer.func */
            8884097, 8, 0, /* 3289: pointer.func */
            8884097, 8, 0, /* 3292: pointer.func */
            1, 8, 1, /* 3295: pointer.struct.dh_st */
            	3300, 0,
            0, 144, 12, /* 3300: struct.dh_st */
            	285, 8,
            	285, 16,
            	285, 32,
            	285, 40,
            	2794, 56,
            	285, 64,
            	285, 72,
            	78, 80,
            	285, 96,
            	2542, 112,
            	3327, 128,
            	2786, 136,
            1, 8, 1, /* 3327: pointer.struct.dh_method */
            	3332, 0,
            0, 72, 8, /* 3332: struct.dh_method */
            	5, 0,
            	3351, 8,
            	3354, 16,
            	3357, 24,
            	3351, 32,
            	3351, 40,
            	99, 56,
            	3360, 64,
            8884097, 8, 0, /* 3351: pointer.func */
            8884097, 8, 0, /* 3354: pointer.func */
            8884097, 8, 0, /* 3357: pointer.func */
            8884097, 8, 0, /* 3360: pointer.func */
            1, 8, 1, /* 3363: pointer.struct.ec_key_st */
            	3368, 0,
            0, 0, 0, /* 3368: struct.ec_key_st */
            1, 8, 1, /* 3371: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3376, 0,
            0, 32, 2, /* 3376: struct.stack_st_fake_X509_ATTRIBUTE */
            	3383, 8,
            	86, 24,
            8884099, 8, 2, /* 3383: pointer_to_array_of_pointers_to_stack */
            	3390, 0,
            	83, 20,
            0, 8, 1, /* 3390: pointer.X509_ATTRIBUTE */
            	1324, 0,
            1, 8, 1, /* 3395: pointer.struct.stack_st_X509_EXTENSION */
            	3400, 0,
            0, 32, 2, /* 3400: struct.stack_st_fake_X509_EXTENSION */
            	3407, 8,
            	86, 24,
            8884099, 8, 2, /* 3407: pointer_to_array_of_pointers_to_stack */
            	3414, 0,
            	83, 20,
            0, 8, 1, /* 3414: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 3419: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 3424: pointer.struct.AUTHORITY_KEYID_st */
            	3429, 0,
            0, 24, 3, /* 3429: struct.AUTHORITY_KEYID_st */
            	3030, 0,
            	3438, 8,
            	2926, 16,
            1, 8, 1, /* 3438: pointer.struct.stack_st_GENERAL_NAME */
            	3443, 0,
            0, 32, 2, /* 3443: struct.stack_st_fake_GENERAL_NAME */
            	3450, 8,
            	86, 24,
            8884099, 8, 2, /* 3450: pointer_to_array_of_pointers_to_stack */
            	3457, 0,
            	83, 20,
            0, 8, 1, /* 3457: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 3462: pointer.struct.X509_POLICY_CACHE_st */
            	3467, 0,
            0, 0, 0, /* 3467: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3470: pointer.struct.stack_st_DIST_POINT */
            	3475, 0,
            0, 32, 2, /* 3475: struct.stack_st_fake_DIST_POINT */
            	3482, 8,
            	86, 24,
            8884099, 8, 2, /* 3482: pointer_to_array_of_pointers_to_stack */
            	3489, 0,
            	83, 20,
            0, 8, 1, /* 3489: pointer.DIST_POINT */
            	1740, 0,
            1, 8, 1, /* 3494: pointer.struct.stack_st_GENERAL_NAME */
            	3499, 0,
            0, 32, 2, /* 3499: struct.stack_st_fake_GENERAL_NAME */
            	3506, 8,
            	86, 24,
            8884099, 8, 2, /* 3506: pointer_to_array_of_pointers_to_stack */
            	3513, 0,
            	83, 20,
            0, 8, 1, /* 3513: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 3518: pointer.struct.NAME_CONSTRAINTS_st */
            	3523, 0,
            0, 16, 2, /* 3523: struct.NAME_CONSTRAINTS_st */
            	3530, 0,
            	3530, 8,
            1, 8, 1, /* 3530: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3535, 0,
            0, 32, 2, /* 3535: struct.stack_st_fake_GENERAL_SUBTREE */
            	3542, 8,
            	86, 24,
            8884099, 8, 2, /* 3542: pointer_to_array_of_pointers_to_stack */
            	3549, 0,
            	83, 20,
            0, 8, 1, /* 3549: pointer.GENERAL_SUBTREE */
            	3554, 0,
            0, 0, 1, /* 3554: GENERAL_SUBTREE */
            	3559, 0,
            0, 24, 3, /* 3559: struct.GENERAL_SUBTREE_st */
            	3568, 0,
            	2629, 8,
            	2629, 16,
            1, 8, 1, /* 3568: pointer.struct.GENERAL_NAME_st */
            	3573, 0,
            0, 16, 1, /* 3573: struct.GENERAL_NAME_st */
            	3578, 8,
            0, 8, 15, /* 3578: union.unknown */
            	99, 0,
            	3611, 0,
            	2532, 0,
            	2532, 0,
            	2823, 0,
            	3616, 0,
            	3664, 0,
            	2532, 0,
            	2644, 0,
            	2615, 0,
            	2644, 0,
            	3616, 0,
            	2532, 0,
            	2615, 0,
            	2823, 0,
            1, 8, 1, /* 3611: pointer.struct.otherName_st */
            	2816, 0,
            1, 8, 1, /* 3616: pointer.struct.X509_name_st */
            	3621, 0,
            0, 40, 3, /* 3621: struct.X509_name_st */
            	3630, 0,
            	3654, 16,
            	78, 24,
            1, 8, 1, /* 3630: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3635, 0,
            0, 32, 2, /* 3635: struct.stack_st_fake_X509_NAME_ENTRY */
            	3642, 8,
            	86, 24,
            8884099, 8, 2, /* 3642: pointer_to_array_of_pointers_to_stack */
            	3649, 0,
            	83, 20,
            0, 8, 1, /* 3649: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 3654: pointer.struct.buf_mem_st */
            	3659, 0,
            0, 24, 1, /* 3659: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 3664: pointer.struct.EDIPartyName_st */
            	3669, 0,
            0, 16, 2, /* 3669: struct.EDIPartyName_st */
            	2610, 0,
            	2610, 8,
            1, 8, 1, /* 3676: pointer.struct.x509_cert_aux_st */
            	3681, 0,
            0, 40, 5, /* 3681: struct.x509_cert_aux_st */
            	3694, 0,
            	3694, 8,
            	3080, 16,
            	3030, 24,
            	3718, 32,
            1, 8, 1, /* 3694: pointer.struct.stack_st_ASN1_OBJECT */
            	3699, 0,
            0, 32, 2, /* 3699: struct.stack_st_fake_ASN1_OBJECT */
            	3706, 8,
            	86, 24,
            8884099, 8, 2, /* 3706: pointer_to_array_of_pointers_to_stack */
            	3713, 0,
            	83, 20,
            0, 8, 1, /* 3713: pointer.ASN1_OBJECT */
            	2199, 0,
            1, 8, 1, /* 3718: pointer.struct.stack_st_X509_ALGOR */
            	3723, 0,
            0, 32, 2, /* 3723: struct.stack_st_fake_X509_ALGOR */
            	3730, 8,
            	86, 24,
            8884099, 8, 2, /* 3730: pointer_to_array_of_pointers_to_stack */
            	3737, 0,
            	83, 20,
            0, 8, 1, /* 3737: pointer.X509_ALGOR */
            	2237, 0,
            1, 8, 1, /* 3742: pointer.struct.env_md_st */
            	3747, 0,
            0, 120, 8, /* 3747: struct.env_md_st */
            	3766, 24,
            	3769, 32,
            	3772, 40,
            	3775, 48,
            	3766, 56,
            	3778, 64,
            	3781, 72,
            	3784, 112,
            8884097, 8, 0, /* 3766: pointer.func */
            8884097, 8, 0, /* 3769: pointer.func */
            8884097, 8, 0, /* 3772: pointer.func */
            8884097, 8, 0, /* 3775: pointer.func */
            8884097, 8, 0, /* 3778: pointer.func */
            8884097, 8, 0, /* 3781: pointer.func */
            8884097, 8, 0, /* 3784: pointer.func */
            1, 8, 1, /* 3787: pointer.struct.rsa_st */
            	2694, 0,
            8884097, 8, 0, /* 3792: pointer.func */
            1, 8, 1, /* 3795: pointer.struct.dh_st */
            	3300, 0,
            8884097, 8, 0, /* 3800: pointer.func */
            1, 8, 1, /* 3803: pointer.struct.ec_key_st */
            	3368, 0,
            8884097, 8, 0, /* 3808: pointer.func */
            1, 8, 1, /* 3811: pointer.struct.ASN1_VALUE_st */
            	3816, 0,
            0, 0, 0, /* 3816: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 3819: pointer.func */
            1, 8, 1, /* 3822: pointer.struct.stack_st_ASN1_OBJECT */
            	3827, 0,
            0, 32, 2, /* 3827: struct.stack_st_fake_ASN1_OBJECT */
            	3834, 8,
            	86, 24,
            8884099, 8, 2, /* 3834: pointer_to_array_of_pointers_to_stack */
            	3841, 0,
            	83, 20,
            0, 8, 1, /* 3841: pointer.ASN1_OBJECT */
            	2199, 0,
            0, 144, 12, /* 3846: struct.dh_st */
            	3873, 8,
            	3873, 16,
            	3873, 32,
            	3873, 40,
            	3883, 56,
            	3873, 64,
            	3873, 72,
            	78, 80,
            	3873, 96,
            	3897, 112,
            	3919, 128,
            	3955, 136,
            1, 8, 1, /* 3873: pointer.struct.bignum_st */
            	3878, 0,
            0, 24, 1, /* 3878: struct.bignum_st */
            	295, 0,
            1, 8, 1, /* 3883: pointer.struct.bn_mont_ctx_st */
            	3888, 0,
            0, 96, 3, /* 3888: struct.bn_mont_ctx_st */
            	3878, 8,
            	3878, 32,
            	3878, 56,
            0, 16, 1, /* 3897: struct.crypto_ex_data_st */
            	3902, 0,
            1, 8, 1, /* 3902: pointer.struct.stack_st_void */
            	3907, 0,
            0, 32, 1, /* 3907: struct.stack_st_void */
            	3912, 0,
            0, 32, 2, /* 3912: struct.stack_st */
            	1116, 8,
            	86, 24,
            1, 8, 1, /* 3919: pointer.struct.dh_method */
            	3924, 0,
            0, 72, 8, /* 3924: struct.dh_method */
            	5, 0,
            	3943, 8,
            	3946, 16,
            	3949, 24,
            	3943, 32,
            	3943, 40,
            	99, 56,
            	3952, 64,
            8884097, 8, 0, /* 3943: pointer.func */
            8884097, 8, 0, /* 3946: pointer.func */
            8884097, 8, 0, /* 3949: pointer.func */
            8884097, 8, 0, /* 3952: pointer.func */
            1, 8, 1, /* 3955: pointer.struct.engine_st */
            	3960, 0,
            0, 0, 0, /* 3960: struct.engine_st */
            0, 1, 0, /* 3963: char */
            8884097, 8, 0, /* 3966: pointer.func */
            8884097, 8, 0, /* 3969: pointer.func */
            1, 8, 1, /* 3972: pointer.struct.sess_cert_st */
            	3977, 0,
            0, 248, 5, /* 3977: struct.sess_cert_st */
            	3990, 0,
            	2850, 16,
            	3787, 216,
            	3795, 224,
            	3803, 232,
            1, 8, 1, /* 3990: pointer.struct.stack_st_X509 */
            	3995, 0,
            0, 32, 2, /* 3995: struct.stack_st_fake_X509 */
            	4002, 8,
            	86, 24,
            8884099, 8, 2, /* 4002: pointer_to_array_of_pointers_to_stack */
            	4009, 0,
            	83, 20,
            0, 8, 1, /* 4009: pointer.X509 */
            	4014, 0,
            0, 0, 1, /* 4014: X509 */
            	4019, 0,
            0, 184, 12, /* 4019: struct.x509_st */
            	4046, 0,
            	4086, 8,
            	4175, 16,
            	99, 32,
            	3897, 40,
            	4180, 104,
            	4603, 112,
            	4611, 120,
            	4619, 128,
            	4643, 136,
            	4667, 144,
            	4675, 176,
            1, 8, 1, /* 4046: pointer.struct.x509_cinf_st */
            	4051, 0,
            0, 104, 11, /* 4051: struct.x509_cinf_st */
            	4076, 0,
            	4076, 8,
            	4086, 16,
            	4235, 24,
            	4283, 32,
            	4235, 40,
            	4300, 48,
            	4175, 56,
            	4175, 64,
            	4574, 72,
            	4598, 80,
            1, 8, 1, /* 4076: pointer.struct.asn1_string_st */
            	4081, 0,
            0, 24, 1, /* 4081: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 4086: pointer.struct.X509_algor_st */
            	4091, 0,
            0, 16, 2, /* 4091: struct.X509_algor_st */
            	4098, 0,
            	4112, 8,
            1, 8, 1, /* 4098: pointer.struct.asn1_object_st */
            	4103, 0,
            0, 40, 3, /* 4103: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 4112: pointer.struct.asn1_type_st */
            	4117, 0,
            0, 16, 1, /* 4117: struct.asn1_type_st */
            	4122, 8,
            0, 8, 20, /* 4122: union.unknown */
            	99, 0,
            	4165, 0,
            	4098, 0,
            	4076, 0,
            	4170, 0,
            	4175, 0,
            	4180, 0,
            	4185, 0,
            	4190, 0,
            	4195, 0,
            	4200, 0,
            	4205, 0,
            	4210, 0,
            	4215, 0,
            	4220, 0,
            	4225, 0,
            	4230, 0,
            	4165, 0,
            	4165, 0,
            	3811, 0,
            1, 8, 1, /* 4165: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4170: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4175: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4180: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4185: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4190: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4195: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4200: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4205: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4210: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4215: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4220: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4225: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4230: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4235: pointer.struct.X509_name_st */
            	4240, 0,
            0, 40, 3, /* 4240: struct.X509_name_st */
            	4249, 0,
            	4273, 16,
            	78, 24,
            1, 8, 1, /* 4249: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4254, 0,
            0, 32, 2, /* 4254: struct.stack_st_fake_X509_NAME_ENTRY */
            	4261, 8,
            	86, 24,
            8884099, 8, 2, /* 4261: pointer_to_array_of_pointers_to_stack */
            	4268, 0,
            	83, 20,
            0, 8, 1, /* 4268: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 4273: pointer.struct.buf_mem_st */
            	4278, 0,
            0, 24, 1, /* 4278: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 4283: pointer.struct.X509_val_st */
            	4288, 0,
            0, 16, 2, /* 4288: struct.X509_val_st */
            	4295, 0,
            	4295, 8,
            1, 8, 1, /* 4295: pointer.struct.asn1_string_st */
            	4081, 0,
            1, 8, 1, /* 4300: pointer.struct.X509_pubkey_st */
            	4305, 0,
            0, 24, 3, /* 4305: struct.X509_pubkey_st */
            	4086, 0,
            	4175, 8,
            	4314, 16,
            1, 8, 1, /* 4314: pointer.struct.evp_pkey_st */
            	4319, 0,
            0, 56, 4, /* 4319: struct.evp_pkey_st */
            	4330, 16,
            	3955, 24,
            	4338, 32,
            	4550, 48,
            1, 8, 1, /* 4330: pointer.struct.evp_pkey_asn1_method_st */
            	4335, 0,
            0, 0, 0, /* 4335: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 4338: union.unknown */
            	99, 0,
            	4351, 0,
            	4456, 0,
            	4537, 0,
            	4542, 0,
            1, 8, 1, /* 4351: pointer.struct.rsa_st */
            	4356, 0,
            0, 168, 17, /* 4356: struct.rsa_st */
            	4393, 16,
            	3955, 24,
            	3873, 32,
            	3873, 40,
            	3873, 48,
            	3873, 56,
            	3873, 64,
            	3873, 72,
            	3873, 80,
            	3873, 88,
            	3897, 96,
            	3883, 120,
            	3883, 128,
            	3883, 136,
            	99, 144,
            	4448, 152,
            	4448, 160,
            1, 8, 1, /* 4393: pointer.struct.rsa_meth_st */
            	4398, 0,
            0, 112, 13, /* 4398: struct.rsa_meth_st */
            	5, 0,
            	4427, 8,
            	4427, 16,
            	4427, 24,
            	4427, 32,
            	4430, 40,
            	4433, 48,
            	4436, 56,
            	4436, 64,
            	99, 80,
            	4439, 88,
            	4442, 96,
            	4445, 104,
            8884097, 8, 0, /* 4427: pointer.func */
            8884097, 8, 0, /* 4430: pointer.func */
            8884097, 8, 0, /* 4433: pointer.func */
            8884097, 8, 0, /* 4436: pointer.func */
            8884097, 8, 0, /* 4439: pointer.func */
            8884097, 8, 0, /* 4442: pointer.func */
            8884097, 8, 0, /* 4445: pointer.func */
            1, 8, 1, /* 4448: pointer.struct.bn_blinding_st */
            	4453, 0,
            0, 0, 0, /* 4453: struct.bn_blinding_st */
            1, 8, 1, /* 4456: pointer.struct.dsa_st */
            	4461, 0,
            0, 136, 11, /* 4461: struct.dsa_st */
            	3873, 24,
            	3873, 32,
            	3873, 40,
            	3873, 48,
            	3873, 56,
            	3873, 64,
            	3873, 72,
            	3883, 88,
            	3897, 104,
            	4486, 120,
            	3955, 128,
            1, 8, 1, /* 4486: pointer.struct.dsa_method */
            	4491, 0,
            0, 96, 11, /* 4491: struct.dsa_method */
            	5, 0,
            	4516, 8,
            	4519, 16,
            	4522, 24,
            	4525, 32,
            	4528, 40,
            	4531, 48,
            	4531, 56,
            	99, 72,
            	4534, 80,
            	4531, 88,
            8884097, 8, 0, /* 4516: pointer.func */
            8884097, 8, 0, /* 4519: pointer.func */
            8884097, 8, 0, /* 4522: pointer.func */
            8884097, 8, 0, /* 4525: pointer.func */
            8884097, 8, 0, /* 4528: pointer.func */
            8884097, 8, 0, /* 4531: pointer.func */
            8884097, 8, 0, /* 4534: pointer.func */
            1, 8, 1, /* 4537: pointer.struct.dh_st */
            	3846, 0,
            1, 8, 1, /* 4542: pointer.struct.ec_key_st */
            	4547, 0,
            0, 0, 0, /* 4547: struct.ec_key_st */
            1, 8, 1, /* 4550: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4555, 0,
            0, 32, 2, /* 4555: struct.stack_st_fake_X509_ATTRIBUTE */
            	4562, 8,
            	86, 24,
            8884099, 8, 2, /* 4562: pointer_to_array_of_pointers_to_stack */
            	4569, 0,
            	83, 20,
            0, 8, 1, /* 4569: pointer.X509_ATTRIBUTE */
            	1324, 0,
            1, 8, 1, /* 4574: pointer.struct.stack_st_X509_EXTENSION */
            	4579, 0,
            0, 32, 2, /* 4579: struct.stack_st_fake_X509_EXTENSION */
            	4586, 8,
            	86, 24,
            8884099, 8, 2, /* 4586: pointer_to_array_of_pointers_to_stack */
            	4593, 0,
            	83, 20,
            0, 8, 1, /* 4593: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 4598: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 4603: pointer.struct.AUTHORITY_KEYID_st */
            	4608, 0,
            0, 0, 0, /* 4608: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4611: pointer.struct.X509_POLICY_CACHE_st */
            	4616, 0,
            0, 0, 0, /* 4616: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4619: pointer.struct.stack_st_DIST_POINT */
            	4624, 0,
            0, 32, 2, /* 4624: struct.stack_st_fake_DIST_POINT */
            	4631, 8,
            	86, 24,
            8884099, 8, 2, /* 4631: pointer_to_array_of_pointers_to_stack */
            	4638, 0,
            	83, 20,
            0, 8, 1, /* 4638: pointer.DIST_POINT */
            	1740, 0,
            1, 8, 1, /* 4643: pointer.struct.stack_st_GENERAL_NAME */
            	4648, 0,
            0, 32, 2, /* 4648: struct.stack_st_fake_GENERAL_NAME */
            	4655, 8,
            	86, 24,
            8884099, 8, 2, /* 4655: pointer_to_array_of_pointers_to_stack */
            	4662, 0,
            	83, 20,
            0, 8, 1, /* 4662: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 4667: pointer.struct.NAME_CONSTRAINTS_st */
            	4672, 0,
            0, 0, 0, /* 4672: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4675: pointer.struct.x509_cert_aux_st */
            	4680, 0,
            0, 40, 5, /* 4680: struct.x509_cert_aux_st */
            	3822, 0,
            	3822, 8,
            	4230, 16,
            	4180, 24,
            	4693, 32,
            1, 8, 1, /* 4693: pointer.struct.stack_st_X509_ALGOR */
            	4698, 0,
            0, 32, 2, /* 4698: struct.stack_st_fake_X509_ALGOR */
            	4705, 8,
            	86, 24,
            8884099, 8, 2, /* 4705: pointer_to_array_of_pointers_to_stack */
            	4712, 0,
            	83, 20,
            0, 8, 1, /* 4712: pointer.X509_ALGOR */
            	2237, 0,
            0, 0, 0, /* 4717: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 4720: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4725, 0,
            0, 32, 2, /* 4725: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4732, 8,
            	86, 24,
            8884099, 8, 2, /* 4732: pointer_to_array_of_pointers_to_stack */
            	4739, 0,
            	83, 20,
            0, 8, 1, /* 4739: pointer.SRTP_PROTECTION_PROFILE */
            	229, 0,
            8884097, 8, 0, /* 4744: pointer.func */
            0, 0, 1, /* 4747: X509_NAME */
            	4240, 0,
            8884097, 8, 0, /* 4752: pointer.func */
            8884097, 8, 0, /* 4755: pointer.func */
            8884097, 8, 0, /* 4758: pointer.func */
            0, 0, 0, /* 4761: struct._pqueue */
            8884097, 8, 0, /* 4764: pointer.func */
            1, 8, 1, /* 4767: pointer.struct.ssl_session_st */
            	4772, 0,
            0, 352, 14, /* 4772: struct.ssl_session_st */
            	99, 144,
            	99, 152,
            	3972, 168,
            	2864, 176,
            	4803, 224,
            	4813, 240,
            	2542, 248,
            	4767, 264,
            	4767, 272,
            	99, 280,
            	78, 296,
            	78, 312,
            	78, 320,
            	99, 344,
            1, 8, 1, /* 4803: pointer.struct.ssl_cipher_st */
            	4808, 0,
            0, 88, 1, /* 4808: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4813: pointer.struct.stack_st_SSL_CIPHER */
            	4818, 0,
            0, 32, 2, /* 4818: struct.stack_st_fake_SSL_CIPHER */
            	4825, 8,
            	86, 24,
            8884099, 8, 2, /* 4825: pointer_to_array_of_pointers_to_stack */
            	4832, 0,
            	83, 20,
            0, 8, 1, /* 4832: pointer.SSL_CIPHER */
            	4837, 0,
            0, 0, 1, /* 4837: SSL_CIPHER */
            	4842, 0,
            0, 88, 1, /* 4842: struct.ssl_cipher_st */
            	5, 8,
            8884097, 8, 0, /* 4847: pointer.func */
            8884097, 8, 0, /* 4850: pointer.func */
            8884097, 8, 0, /* 4853: pointer.func */
            1, 8, 1, /* 4856: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            8884097, 8, 0, /* 4861: pointer.func */
            8884097, 8, 0, /* 4864: pointer.func */
            0, 16, 1, /* 4867: struct.record_pqueue_st */
            	4872, 8,
            1, 8, 1, /* 4872: pointer.struct._pqueue */
            	4761, 0,
            1, 8, 1, /* 4877: pointer.struct.bio_st */
            	4882, 0,
            0, 112, 7, /* 4882: struct.bio_st */
            	4899, 0,
            	4847, 8,
            	99, 16,
            	273, 48,
            	4940, 56,
            	4940, 64,
            	2542, 96,
            1, 8, 1, /* 4899: pointer.struct.bio_method_st */
            	4904, 0,
            0, 80, 9, /* 4904: struct.bio_method_st */
            	5, 8,
            	4925, 16,
            	4755, 24,
            	4928, 32,
            	4755, 40,
            	4931, 48,
            	4934, 56,
            	4934, 64,
            	4937, 72,
            8884097, 8, 0, /* 4925: pointer.func */
            8884097, 8, 0, /* 4928: pointer.func */
            8884097, 8, 0, /* 4931: pointer.func */
            8884097, 8, 0, /* 4934: pointer.func */
            8884097, 8, 0, /* 4937: pointer.func */
            1, 8, 1, /* 4940: pointer.struct.bio_st */
            	4882, 0,
            1, 8, 1, /* 4945: pointer.struct.X509_VERIFY_PARAM_st */
            	4950, 0,
            0, 56, 2, /* 4950: struct.X509_VERIFY_PARAM_st */
            	99, 0,
            	3694, 48,
            8884097, 8, 0, /* 4957: pointer.func */
            8884097, 8, 0, /* 4960: pointer.func */
            1, 8, 1, /* 4963: pointer.struct.ssl2_state_st */
            	4968, 0,
            0, 344, 9, /* 4968: struct.ssl2_state_st */
            	60, 24,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 104,
            	78, 112,
            	78, 120,
            	78, 128,
            	78, 136,
            8884097, 8, 0, /* 4989: pointer.func */
            1, 8, 1, /* 4992: pointer.struct.ssl_st */
            	4997, 0,
            0, 808, 51, /* 4997: struct.ssl_st */
            	5102, 8,
            	4877, 16,
            	4877, 24,
            	4877, 32,
            	5166, 48,
            	3131, 80,
            	273, 88,
            	78, 104,
            	4963, 120,
            	5244, 128,
            	5437, 136,
            	5508, 152,
            	273, 160,
            	4945, 176,
            	4813, 184,
            	4813, 192,
            	5475, 208,
            	5291, 216,
            	5491, 224,
            	5475, 232,
            	5291, 240,
            	5491, 248,
            	5511, 256,
            	5503, 304,
            	5516, 312,
            	5519, 328,
            	5522, 336,
            	5525, 352,
            	5528, 360,
            	5531, 368,
            	2542, 392,
            	5333, 408,
            	4758, 464,
            	273, 472,
            	99, 480,
            	195, 504,
            	10, 512,
            	78, 520,
            	78, 544,
            	78, 560,
            	273, 568,
            	2513, 584,
            	2564, 592,
            	273, 600,
            	4853, 608,
            	273, 616,
            	5531, 624,
            	78, 632,
            	4720, 648,
            	4856, 656,
            	242, 680,
            1, 8, 1, /* 5102: pointer.struct.ssl_method_st */
            	5107, 0,
            0, 232, 28, /* 5107: struct.ssl_method_st */
            	5166, 8,
            	5169, 16,
            	5169, 24,
            	5166, 32,
            	5166, 40,
            	5172, 48,
            	5172, 56,
            	3819, 64,
            	5166, 72,
            	5166, 80,
            	5166, 88,
            	5175, 96,
            	5178, 104,
            	4861, 112,
            	5166, 120,
            	5181, 128,
            	4989, 136,
            	5184, 144,
            	5187, 152,
            	5190, 160,
            	5193, 168,
            	4744, 176,
            	5196, 184,
            	342, 192,
            	5199, 200,
            	5193, 208,
            	5238, 216,
            	5241, 224,
            8884097, 8, 0, /* 5166: pointer.func */
            8884097, 8, 0, /* 5169: pointer.func */
            8884097, 8, 0, /* 5172: pointer.func */
            8884097, 8, 0, /* 5175: pointer.func */
            8884097, 8, 0, /* 5178: pointer.func */
            8884097, 8, 0, /* 5181: pointer.func */
            8884097, 8, 0, /* 5184: pointer.func */
            8884097, 8, 0, /* 5187: pointer.func */
            8884097, 8, 0, /* 5190: pointer.func */
            8884097, 8, 0, /* 5193: pointer.func */
            8884097, 8, 0, /* 5196: pointer.func */
            1, 8, 1, /* 5199: pointer.struct.ssl3_enc_method */
            	5204, 0,
            0, 112, 11, /* 5204: struct.ssl3_enc_method */
            	4864, 0,
            	5229, 8,
            	5166, 16,
            	5232, 24,
            	4864, 32,
            	5235, 40,
            	3966, 56,
            	5, 64,
            	5, 80,
            	4957, 96,
            	4960, 104,
            8884097, 8, 0, /* 5229: pointer.func */
            8884097, 8, 0, /* 5232: pointer.func */
            8884097, 8, 0, /* 5235: pointer.func */
            8884097, 8, 0, /* 5238: pointer.func */
            8884097, 8, 0, /* 5241: pointer.func */
            1, 8, 1, /* 5244: pointer.struct.ssl3_state_st */
            	5249, 0,
            0, 1200, 10, /* 5249: struct.ssl3_state_st */
            	5272, 240,
            	5272, 264,
            	5277, 288,
            	5277, 344,
            	60, 432,
            	4877, 440,
            	5286, 448,
            	273, 496,
            	273, 512,
            	5314, 528,
            0, 24, 1, /* 5272: struct.ssl3_buffer_st */
            	78, 0,
            0, 56, 3, /* 5277: struct.ssl3_record_st */
            	78, 16,
            	78, 24,
            	78, 32,
            1, 8, 1, /* 5286: pointer.pointer.struct.env_md_ctx_st */
            	5291, 0,
            1, 8, 1, /* 5291: pointer.struct.env_md_ctx_st */
            	5296, 0,
            0, 48, 5, /* 5296: struct.env_md_ctx_st */
            	3742, 0,
            	2786, 8,
            	273, 24,
            	5309, 32,
            	3769, 40,
            1, 8, 1, /* 5309: pointer.struct.evp_pkey_ctx_st */
            	4717, 0,
            0, 528, 8, /* 5314: struct.unknown */
            	4803, 408,
            	3795, 416,
            	3803, 424,
            	5333, 464,
            	78, 480,
            	5357, 488,
            	3742, 496,
            	5394, 512,
            1, 8, 1, /* 5333: pointer.struct.stack_st_X509_NAME */
            	5338, 0,
            0, 32, 2, /* 5338: struct.stack_st_fake_X509_NAME */
            	5345, 8,
            	86, 24,
            8884099, 8, 2, /* 5345: pointer_to_array_of_pointers_to_stack */
            	5352, 0,
            	83, 20,
            0, 8, 1, /* 5352: pointer.X509_NAME */
            	4747, 0,
            1, 8, 1, /* 5357: pointer.struct.evp_cipher_st */
            	5362, 0,
            0, 88, 7, /* 5362: struct.evp_cipher_st */
            	5379, 24,
            	5382, 32,
            	5385, 40,
            	5388, 56,
            	5388, 64,
            	5391, 72,
            	273, 80,
            8884097, 8, 0, /* 5379: pointer.func */
            8884097, 8, 0, /* 5382: pointer.func */
            8884097, 8, 0, /* 5385: pointer.func */
            8884097, 8, 0, /* 5388: pointer.func */
            8884097, 8, 0, /* 5391: pointer.func */
            1, 8, 1, /* 5394: pointer.struct.ssl_comp_st */
            	5399, 0,
            0, 24, 2, /* 5399: struct.ssl_comp_st */
            	5, 8,
            	5406, 16,
            1, 8, 1, /* 5406: pointer.struct.comp_method_st */
            	5411, 0,
            0, 64, 7, /* 5411: struct.comp_method_st */
            	5, 8,
            	5428, 16,
            	5431, 24,
            	5434, 32,
            	5434, 40,
            	342, 48,
            	342, 56,
            8884097, 8, 0, /* 5428: pointer.func */
            8884097, 8, 0, /* 5431: pointer.func */
            8884097, 8, 0, /* 5434: pointer.func */
            1, 8, 1, /* 5437: pointer.struct.dtls1_state_st */
            	5442, 0,
            0, 888, 7, /* 5442: struct.dtls1_state_st */
            	4867, 576,
            	4867, 592,
            	4872, 608,
            	4872, 616,
            	4867, 624,
            	5459, 648,
            	5459, 736,
            0, 88, 1, /* 5459: struct.hm_header_st */
            	5464, 48,
            0, 40, 4, /* 5464: struct.dtls1_retransmit_state */
            	5475, 0,
            	5291, 8,
            	5491, 16,
            	5503, 24,
            1, 8, 1, /* 5475: pointer.struct.evp_cipher_ctx_st */
            	5480, 0,
            0, 168, 4, /* 5480: struct.evp_cipher_ctx_st */
            	5357, 0,
            	2786, 8,
            	273, 96,
            	273, 120,
            1, 8, 1, /* 5491: pointer.struct.comp_ctx_st */
            	5496, 0,
            0, 56, 2, /* 5496: struct.comp_ctx_st */
            	5406, 0,
            	2542, 40,
            1, 8, 1, /* 5503: pointer.struct.ssl_session_st */
            	4772, 0,
            8884097, 8, 0, /* 5508: pointer.func */
            1, 8, 1, /* 5511: pointer.struct.cert_st */
            	2833, 0,
            8884097, 8, 0, /* 5516: pointer.func */
            8884097, 8, 0, /* 5519: pointer.func */
            8884097, 8, 0, /* 5522: pointer.func */
            8884097, 8, 0, /* 5525: pointer.func */
            8884097, 8, 0, /* 5528: pointer.func */
            1, 8, 1, /* 5531: pointer.struct.ssl_ctx_st */
            	5536, 0,
            0, 736, 50, /* 5536: struct.ssl_ctx_st */
            	5102, 0,
            	4813, 8,
            	4813, 16,
            	5639, 24,
            	426, 32,
            	4767, 48,
            	4767, 56,
            	461, 80,
            	5707, 88,
            	389, 96,
            	2518, 152,
            	273, 160,
            	5710, 168,
            	273, 176,
            	5713, 184,
            	5716, 192,
            	386, 200,
            	2542, 208,
            	3742, 224,
            	3742, 232,
            	3742, 240,
            	3990, 248,
            	362, 256,
            	5522, 264,
            	5333, 272,
            	5511, 304,
            	5508, 320,
            	273, 328,
            	5519, 376,
            	5516, 384,
            	4945, 392,
            	2786, 408,
            	276, 416,
            	273, 424,
            	2521, 480,
            	279, 488,
            	273, 496,
            	313, 504,
            	273, 512,
            	99, 520,
            	5525, 528,
            	5528, 536,
            	5719, 552,
            	5719, 560,
            	242, 568,
            	239, 696,
            	273, 704,
            	4752, 712,
            	273, 720,
            	4720, 728,
            1, 8, 1, /* 5639: pointer.struct.x509_store_st */
            	5644, 0,
            0, 144, 15, /* 5644: struct.x509_store_st */
            	5677, 8,
            	2484, 16,
            	4945, 24,
            	437, 32,
            	5519, 40,
            	434, 48,
            	5701, 56,
            	437, 64,
            	3969, 72,
            	431, 80,
            	4850, 88,
            	4764, 96,
            	5704, 104,
            	437, 112,
            	2542, 120,
            1, 8, 1, /* 5677: pointer.struct.stack_st_X509_OBJECT */
            	5682, 0,
            0, 32, 2, /* 5682: struct.stack_st_fake_X509_OBJECT */
            	5689, 8,
            	86, 24,
            8884099, 8, 2, /* 5689: pointer_to_array_of_pointers_to_stack */
            	5696, 0,
            	83, 20,
            0, 8, 1, /* 5696: pointer.X509_OBJECT */
            	613, 0,
            8884097, 8, 0, /* 5701: pointer.func */
            8884097, 8, 0, /* 5704: pointer.func */
            8884097, 8, 0, /* 5707: pointer.func */
            8884097, 8, 0, /* 5710: pointer.func */
            8884097, 8, 0, /* 5713: pointer.func */
            8884097, 8, 0, /* 5716: pointer.func */
            1, 8, 1, /* 5719: pointer.struct.ssl3_buf_freelist_st */
            	5724, 0,
            0, 24, 1, /* 5724: struct.ssl3_buf_freelist_st */
            	303, 16,
        },
        .arg_entity_index = { 4992, },
        .ret_entity_index = 2864,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    X509 * *new_ret_ptr = (X509 * *)new_args->ret;

    X509 * (*orig_SSL_get_certificate)(const SSL *);
    orig_SSL_get_certificate = dlsym(RTLD_NEXT, "SSL_get_certificate");
    *new_ret_ptr = (*orig_SSL_get_certificate)(new_arg_a);

    syscall(889);

    return ret;
}

