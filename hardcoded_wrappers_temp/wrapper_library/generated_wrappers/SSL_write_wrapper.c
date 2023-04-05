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

int bb_SSL_write(SSL * arg_a,const void * arg_b,int arg_c);

int SSL_write(SSL * arg_a,const void * arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_write called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_write(arg_a,arg_b,arg_c);
    else {
        int (*orig_SSL_write)(SSL *,const void *,int);
        orig_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
        return orig_SSL_write(arg_a,arg_b,arg_c);
    }
}

int bb_SSL_write(SSL * arg_a,const void * arg_b,int arg_c) 
{
    int ret;

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
            1, 8, 1, /* 2524: pointer.struct.rsa_st */
            	2529, 0,
            0, 168, 17, /* 2529: struct.rsa_st */
            	2566, 16,
            	2621, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	2629, 96,
            	2651, 120,
            	2651, 128,
            	2651, 136,
            	99, 144,
            	2665, 152,
            	2665, 160,
            1, 8, 1, /* 2566: pointer.struct.rsa_meth_st */
            	2571, 0,
            0, 112, 13, /* 2571: struct.rsa_meth_st */
            	5, 0,
            	2600, 8,
            	2600, 16,
            	2600, 24,
            	2600, 32,
            	2603, 40,
            	2606, 48,
            	2609, 56,
            	2609, 64,
            	99, 80,
            	2612, 88,
            	2615, 96,
            	2618, 104,
            8884097, 8, 0, /* 2600: pointer.func */
            8884097, 8, 0, /* 2603: pointer.func */
            8884097, 8, 0, /* 2606: pointer.func */
            8884097, 8, 0, /* 2609: pointer.func */
            8884097, 8, 0, /* 2612: pointer.func */
            8884097, 8, 0, /* 2615: pointer.func */
            8884097, 8, 0, /* 2618: pointer.func */
            1, 8, 1, /* 2621: pointer.struct.engine_st */
            	2626, 0,
            0, 0, 0, /* 2626: struct.engine_st */
            0, 16, 1, /* 2629: struct.crypto_ex_data_st */
            	2634, 0,
            1, 8, 1, /* 2634: pointer.struct.stack_st_void */
            	2639, 0,
            0, 32, 1, /* 2639: struct.stack_st_void */
            	2644, 0,
            0, 32, 2, /* 2644: struct.stack_st */
            	1116, 8,
            	86, 24,
            1, 8, 1, /* 2651: pointer.struct.bn_mont_ctx_st */
            	2656, 0,
            0, 96, 3, /* 2656: struct.bn_mont_ctx_st */
            	290, 8,
            	290, 32,
            	290, 56,
            1, 8, 1, /* 2665: pointer.struct.bn_blinding_st */
            	2670, 0,
            0, 0, 0, /* 2670: struct.bn_blinding_st */
            1, 8, 1, /* 2673: pointer.struct.asn1_string_st */
            	2678, 0,
            0, 24, 1, /* 2678: struct.asn1_string_st */
            	78, 8,
            8884097, 8, 0, /* 2683: pointer.func */
            0, 184, 12, /* 2686: struct.x509_st */
            	2713, 0,
            	2753, 8,
            	2842, 16,
            	99, 32,
            	2629, 40,
            	2847, 104,
            	3241, 112,
            	3279, 120,
            	3287, 128,
            	3311, 136,
            	3335, 144,
            	3645, 176,
            1, 8, 1, /* 2713: pointer.struct.x509_cinf_st */
            	2718, 0,
            0, 104, 11, /* 2718: struct.x509_cinf_st */
            	2743, 0,
            	2743, 8,
            	2753, 16,
            	2910, 24,
            	2958, 32,
            	2910, 40,
            	2975, 48,
            	2842, 56,
            	2842, 64,
            	3212, 72,
            	3236, 80,
            1, 8, 1, /* 2743: pointer.struct.asn1_string_st */
            	2748, 0,
            0, 24, 1, /* 2748: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2753: pointer.struct.X509_algor_st */
            	2758, 0,
            0, 16, 2, /* 2758: struct.X509_algor_st */
            	2765, 0,
            	2779, 8,
            1, 8, 1, /* 2765: pointer.struct.asn1_object_st */
            	2770, 0,
            0, 40, 3, /* 2770: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2779: pointer.struct.asn1_type_st */
            	2784, 0,
            0, 16, 1, /* 2784: struct.asn1_type_st */
            	2789, 8,
            0, 8, 20, /* 2789: union.unknown */
            	99, 0,
            	2832, 0,
            	2765, 0,
            	2743, 0,
            	2837, 0,
            	2842, 0,
            	2847, 0,
            	2852, 0,
            	2857, 0,
            	2862, 0,
            	2867, 0,
            	2872, 0,
            	2877, 0,
            	2882, 0,
            	2887, 0,
            	2892, 0,
            	2897, 0,
            	2832, 0,
            	2832, 0,
            	2902, 0,
            1, 8, 1, /* 2832: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2837: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2842: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2847: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2852: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2857: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2862: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2867: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2872: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2877: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2882: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2887: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2892: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2897: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2902: pointer.struct.ASN1_VALUE_st */
            	2907, 0,
            0, 0, 0, /* 2907: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2910: pointer.struct.X509_name_st */
            	2915, 0,
            0, 40, 3, /* 2915: struct.X509_name_st */
            	2924, 0,
            	2948, 16,
            	78, 24,
            1, 8, 1, /* 2924: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2929, 0,
            0, 32, 2, /* 2929: struct.stack_st_fake_X509_NAME_ENTRY */
            	2936, 8,
            	86, 24,
            8884099, 8, 2, /* 2936: pointer_to_array_of_pointers_to_stack */
            	2943, 0,
            	83, 20,
            0, 8, 1, /* 2943: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 2948: pointer.struct.buf_mem_st */
            	2953, 0,
            0, 24, 1, /* 2953: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 2958: pointer.struct.X509_val_st */
            	2963, 0,
            0, 16, 2, /* 2963: struct.X509_val_st */
            	2970, 0,
            	2970, 8,
            1, 8, 1, /* 2970: pointer.struct.asn1_string_st */
            	2748, 0,
            1, 8, 1, /* 2975: pointer.struct.X509_pubkey_st */
            	2980, 0,
            0, 24, 3, /* 2980: struct.X509_pubkey_st */
            	2753, 0,
            	2842, 8,
            	2989, 16,
            1, 8, 1, /* 2989: pointer.struct.evp_pkey_st */
            	2994, 0,
            0, 56, 4, /* 2994: struct.evp_pkey_st */
            	3005, 16,
            	2621, 24,
            	3013, 32,
            	3188, 48,
            1, 8, 1, /* 3005: pointer.struct.evp_pkey_asn1_method_st */
            	3010, 0,
            0, 0, 0, /* 3010: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3013: union.unknown */
            	99, 0,
            	3026, 0,
            	3031, 0,
            	3112, 0,
            	3180, 0,
            1, 8, 1, /* 3026: pointer.struct.rsa_st */
            	2529, 0,
            1, 8, 1, /* 3031: pointer.struct.dsa_st */
            	3036, 0,
            0, 136, 11, /* 3036: struct.dsa_st */
            	285, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	2651, 88,
            	2629, 104,
            	3061, 120,
            	2621, 128,
            1, 8, 1, /* 3061: pointer.struct.dsa_method */
            	3066, 0,
            0, 96, 11, /* 3066: struct.dsa_method */
            	5, 0,
            	3091, 8,
            	3094, 16,
            	3097, 24,
            	3100, 32,
            	3103, 40,
            	3106, 48,
            	3106, 56,
            	99, 72,
            	3109, 80,
            	3106, 88,
            8884097, 8, 0, /* 3091: pointer.func */
            8884097, 8, 0, /* 3094: pointer.func */
            8884097, 8, 0, /* 3097: pointer.func */
            8884097, 8, 0, /* 3100: pointer.func */
            8884097, 8, 0, /* 3103: pointer.func */
            8884097, 8, 0, /* 3106: pointer.func */
            8884097, 8, 0, /* 3109: pointer.func */
            1, 8, 1, /* 3112: pointer.struct.dh_st */
            	3117, 0,
            0, 144, 12, /* 3117: struct.dh_st */
            	285, 8,
            	285, 16,
            	285, 32,
            	285, 40,
            	2651, 56,
            	285, 64,
            	285, 72,
            	78, 80,
            	285, 96,
            	2629, 112,
            	3144, 128,
            	2621, 136,
            1, 8, 1, /* 3144: pointer.struct.dh_method */
            	3149, 0,
            0, 72, 8, /* 3149: struct.dh_method */
            	5, 0,
            	3168, 8,
            	3171, 16,
            	3174, 24,
            	3168, 32,
            	3168, 40,
            	99, 56,
            	3177, 64,
            8884097, 8, 0, /* 3168: pointer.func */
            8884097, 8, 0, /* 3171: pointer.func */
            8884097, 8, 0, /* 3174: pointer.func */
            8884097, 8, 0, /* 3177: pointer.func */
            1, 8, 1, /* 3180: pointer.struct.ec_key_st */
            	3185, 0,
            0, 0, 0, /* 3185: struct.ec_key_st */
            1, 8, 1, /* 3188: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3193, 0,
            0, 32, 2, /* 3193: struct.stack_st_fake_X509_ATTRIBUTE */
            	3200, 8,
            	86, 24,
            8884099, 8, 2, /* 3200: pointer_to_array_of_pointers_to_stack */
            	3207, 0,
            	83, 20,
            0, 8, 1, /* 3207: pointer.X509_ATTRIBUTE */
            	1324, 0,
            1, 8, 1, /* 3212: pointer.struct.stack_st_X509_EXTENSION */
            	3217, 0,
            0, 32, 2, /* 3217: struct.stack_st_fake_X509_EXTENSION */
            	3224, 8,
            	86, 24,
            8884099, 8, 2, /* 3224: pointer_to_array_of_pointers_to_stack */
            	3231, 0,
            	83, 20,
            0, 8, 1, /* 3231: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 3236: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 3241: pointer.struct.AUTHORITY_KEYID_st */
            	3246, 0,
            0, 24, 3, /* 3246: struct.AUTHORITY_KEYID_st */
            	2847, 0,
            	3255, 8,
            	2743, 16,
            1, 8, 1, /* 3255: pointer.struct.stack_st_GENERAL_NAME */
            	3260, 0,
            0, 32, 2, /* 3260: struct.stack_st_fake_GENERAL_NAME */
            	3267, 8,
            	86, 24,
            8884099, 8, 2, /* 3267: pointer_to_array_of_pointers_to_stack */
            	3274, 0,
            	83, 20,
            0, 8, 1, /* 3274: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 3279: pointer.struct.X509_POLICY_CACHE_st */
            	3284, 0,
            0, 0, 0, /* 3284: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3287: pointer.struct.stack_st_DIST_POINT */
            	3292, 0,
            0, 32, 2, /* 3292: struct.stack_st_fake_DIST_POINT */
            	3299, 8,
            	86, 24,
            8884099, 8, 2, /* 3299: pointer_to_array_of_pointers_to_stack */
            	3306, 0,
            	83, 20,
            0, 8, 1, /* 3306: pointer.DIST_POINT */
            	1740, 0,
            1, 8, 1, /* 3311: pointer.struct.stack_st_GENERAL_NAME */
            	3316, 0,
            0, 32, 2, /* 3316: struct.stack_st_fake_GENERAL_NAME */
            	3323, 8,
            	86, 24,
            8884099, 8, 2, /* 3323: pointer_to_array_of_pointers_to_stack */
            	3330, 0,
            	83, 20,
            0, 8, 1, /* 3330: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 3335: pointer.struct.NAME_CONSTRAINTS_st */
            	3340, 0,
            0, 16, 2, /* 3340: struct.NAME_CONSTRAINTS_st */
            	3347, 0,
            	3347, 8,
            1, 8, 1, /* 3347: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3352, 0,
            0, 32, 2, /* 3352: struct.stack_st_fake_GENERAL_SUBTREE */
            	3359, 8,
            	86, 24,
            8884099, 8, 2, /* 3359: pointer_to_array_of_pointers_to_stack */
            	3366, 0,
            	83, 20,
            0, 8, 1, /* 3366: pointer.GENERAL_SUBTREE */
            	3371, 0,
            0, 0, 1, /* 3371: GENERAL_SUBTREE */
            	3376, 0,
            0, 24, 3, /* 3376: struct.GENERAL_SUBTREE_st */
            	3385, 0,
            	3512, 8,
            	3512, 16,
            1, 8, 1, /* 3385: pointer.struct.GENERAL_NAME_st */
            	3390, 0,
            0, 16, 1, /* 3390: struct.GENERAL_NAME_st */
            	3395, 8,
            0, 8, 15, /* 3395: union.unknown */
            	99, 0,
            	3428, 0,
            	3537, 0,
            	3537, 0,
            	3454, 0,
            	3585, 0,
            	3633, 0,
            	3537, 0,
            	3522, 0,
            	3440, 0,
            	3522, 0,
            	3585, 0,
            	3537, 0,
            	3440, 0,
            	3454, 0,
            1, 8, 1, /* 3428: pointer.struct.otherName_st */
            	3433, 0,
            0, 16, 2, /* 3433: struct.otherName_st */
            	3440, 0,
            	3454, 8,
            1, 8, 1, /* 3440: pointer.struct.asn1_object_st */
            	3445, 0,
            0, 40, 3, /* 3445: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 3454: pointer.struct.asn1_type_st */
            	3459, 0,
            0, 16, 1, /* 3459: struct.asn1_type_st */
            	3464, 8,
            0, 8, 20, /* 3464: union.unknown */
            	99, 0,
            	3507, 0,
            	3440, 0,
            	3512, 0,
            	3517, 0,
            	2673, 0,
            	3522, 0,
            	3527, 0,
            	3532, 0,
            	3537, 0,
            	3542, 0,
            	3547, 0,
            	3552, 0,
            	3557, 0,
            	3562, 0,
            	3567, 0,
            	3572, 0,
            	3507, 0,
            	3507, 0,
            	3577, 0,
            1, 8, 1, /* 3507: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3512: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3517: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3522: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3527: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3532: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3537: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3542: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3547: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3552: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3557: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3562: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3567: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3572: pointer.struct.asn1_string_st */
            	2678, 0,
            1, 8, 1, /* 3577: pointer.struct.ASN1_VALUE_st */
            	3582, 0,
            0, 0, 0, /* 3582: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3585: pointer.struct.X509_name_st */
            	3590, 0,
            0, 40, 3, /* 3590: struct.X509_name_st */
            	3599, 0,
            	3623, 16,
            	78, 24,
            1, 8, 1, /* 3599: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3604, 0,
            0, 32, 2, /* 3604: struct.stack_st_fake_X509_NAME_ENTRY */
            	3611, 8,
            	86, 24,
            8884099, 8, 2, /* 3611: pointer_to_array_of_pointers_to_stack */
            	3618, 0,
            	83, 20,
            0, 8, 1, /* 3618: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 3623: pointer.struct.buf_mem_st */
            	3628, 0,
            0, 24, 1, /* 3628: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 3633: pointer.struct.EDIPartyName_st */
            	3638, 0,
            0, 16, 2, /* 3638: struct.EDIPartyName_st */
            	3507, 0,
            	3507, 8,
            1, 8, 1, /* 3645: pointer.struct.x509_cert_aux_st */
            	3650, 0,
            0, 40, 5, /* 3650: struct.x509_cert_aux_st */
            	3663, 0,
            	3663, 8,
            	2897, 16,
            	2847, 24,
            	3687, 32,
            1, 8, 1, /* 3663: pointer.struct.stack_st_ASN1_OBJECT */
            	3668, 0,
            0, 32, 2, /* 3668: struct.stack_st_fake_ASN1_OBJECT */
            	3675, 8,
            	86, 24,
            8884099, 8, 2, /* 3675: pointer_to_array_of_pointers_to_stack */
            	3682, 0,
            	83, 20,
            0, 8, 1, /* 3682: pointer.ASN1_OBJECT */
            	2199, 0,
            1, 8, 1, /* 3687: pointer.struct.stack_st_X509_ALGOR */
            	3692, 0,
            0, 32, 2, /* 3692: struct.stack_st_fake_X509_ALGOR */
            	3699, 8,
            	86, 24,
            8884099, 8, 2, /* 3699: pointer_to_array_of_pointers_to_stack */
            	3706, 0,
            	83, 20,
            0, 8, 1, /* 3706: pointer.X509_ALGOR */
            	2237, 0,
            1, 8, 1, /* 3711: pointer.struct.ec_key_st */
            	3716, 0,
            0, 0, 0, /* 3716: struct.ec_key_st */
            8884097, 8, 0, /* 3719: pointer.func */
            1, 8, 1, /* 3722: pointer.struct.X509_algor_st */
            	3727, 0,
            0, 16, 2, /* 3727: struct.X509_algor_st */
            	3734, 0,
            	3748, 8,
            1, 8, 1, /* 3734: pointer.struct.asn1_object_st */
            	3739, 0,
            0, 40, 3, /* 3739: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 3748: pointer.struct.asn1_type_st */
            	3753, 0,
            0, 16, 1, /* 3753: struct.asn1_type_st */
            	3758, 8,
            0, 8, 20, /* 3758: union.unknown */
            	99, 0,
            	3801, 0,
            	3734, 0,
            	3811, 0,
            	3816, 0,
            	3821, 0,
            	3826, 0,
            	3831, 0,
            	3836, 0,
            	3841, 0,
            	3846, 0,
            	3851, 0,
            	3856, 0,
            	3861, 0,
            	3866, 0,
            	3871, 0,
            	3876, 0,
            	3801, 0,
            	3801, 0,
            	3881, 0,
            1, 8, 1, /* 3801: pointer.struct.asn1_string_st */
            	3806, 0,
            0, 24, 1, /* 3806: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 3811: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3816: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3821: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3826: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3831: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3836: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3841: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3846: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3851: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3856: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3861: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3866: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3871: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3876: pointer.struct.asn1_string_st */
            	3806, 0,
            1, 8, 1, /* 3881: pointer.struct.ASN1_VALUE_st */
            	3886, 0,
            0, 0, 0, /* 3886: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 3889: pointer.func */
            0, 72, 8, /* 3892: struct.dh_method */
            	5, 0,
            	3911, 8,
            	3914, 16,
            	3889, 24,
            	3911, 32,
            	3911, 40,
            	99, 56,
            	3917, 64,
            8884097, 8, 0, /* 3911: pointer.func */
            8884097, 8, 0, /* 3914: pointer.func */
            8884097, 8, 0, /* 3917: pointer.func */
            8884097, 8, 0, /* 3920: pointer.func */
            8884097, 8, 0, /* 3923: pointer.func */
            8884097, 8, 0, /* 3926: pointer.func */
            1, 8, 1, /* 3929: pointer.struct.comp_method_st */
            	3934, 0,
            0, 64, 7, /* 3934: struct.comp_method_st */
            	5, 8,
            	3951, 16,
            	3954, 24,
            	3957, 32,
            	3957, 40,
            	342, 48,
            	342, 56,
            8884097, 8, 0, /* 3951: pointer.func */
            8884097, 8, 0, /* 3954: pointer.func */
            8884097, 8, 0, /* 3957: pointer.func */
            0, 24, 2, /* 3960: struct.ssl_comp_st */
            	5, 8,
            	3929, 16,
            1, 8, 1, /* 3967: pointer.struct.dsa_st */
            	3972, 0,
            0, 136, 11, /* 3972: struct.dsa_st */
            	3997, 24,
            	3997, 32,
            	3997, 40,
            	3997, 48,
            	3997, 56,
            	3997, 64,
            	3997, 72,
            	4007, 88,
            	4021, 104,
            	4043, 120,
            	4085, 128,
            1, 8, 1, /* 3997: pointer.struct.bignum_st */
            	4002, 0,
            0, 24, 1, /* 4002: struct.bignum_st */
            	295, 0,
            1, 8, 1, /* 4007: pointer.struct.bn_mont_ctx_st */
            	4012, 0,
            0, 96, 3, /* 4012: struct.bn_mont_ctx_st */
            	4002, 8,
            	4002, 32,
            	4002, 56,
            0, 16, 1, /* 4021: struct.crypto_ex_data_st */
            	4026, 0,
            1, 8, 1, /* 4026: pointer.struct.stack_st_void */
            	4031, 0,
            0, 32, 1, /* 4031: struct.stack_st_void */
            	4036, 0,
            0, 32, 2, /* 4036: struct.stack_st */
            	1116, 8,
            	86, 24,
            1, 8, 1, /* 4043: pointer.struct.dsa_method */
            	4048, 0,
            0, 96, 11, /* 4048: struct.dsa_method */
            	5, 0,
            	3926, 8,
            	4073, 16,
            	4076, 24,
            	3923, 32,
            	4079, 40,
            	3920, 48,
            	3920, 56,
            	99, 72,
            	4082, 80,
            	3920, 88,
            8884097, 8, 0, /* 4073: pointer.func */
            8884097, 8, 0, /* 4076: pointer.func */
            8884097, 8, 0, /* 4079: pointer.func */
            8884097, 8, 0, /* 4082: pointer.func */
            1, 8, 1, /* 4085: pointer.struct.engine_st */
            	4090, 0,
            0, 0, 0, /* 4090: struct.engine_st */
            1, 8, 1, /* 4093: pointer.struct.bn_blinding_st */
            	4098, 0,
            0, 0, 0, /* 4098: struct.bn_blinding_st */
            8884097, 8, 0, /* 4101: pointer.func */
            8884097, 8, 0, /* 4104: pointer.func */
            0, 56, 4, /* 4107: struct.evp_pkey_st */
            	4118, 16,
            	4085, 24,
            	4126, 32,
            	4273, 48,
            1, 8, 1, /* 4118: pointer.struct.evp_pkey_asn1_method_st */
            	4123, 0,
            0, 0, 0, /* 4123: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 4126: union.unknown */
            	99, 0,
            	4139, 0,
            	3967, 0,
            	4236, 0,
            	3711, 0,
            1, 8, 1, /* 4139: pointer.struct.rsa_st */
            	4144, 0,
            0, 168, 17, /* 4144: struct.rsa_st */
            	4181, 16,
            	4085, 24,
            	3997, 32,
            	3997, 40,
            	3997, 48,
            	3997, 56,
            	3997, 64,
            	3997, 72,
            	3997, 80,
            	3997, 88,
            	4021, 96,
            	4007, 120,
            	4007, 128,
            	4007, 136,
            	99, 144,
            	4093, 152,
            	4093, 160,
            1, 8, 1, /* 4181: pointer.struct.rsa_meth_st */
            	4186, 0,
            0, 112, 13, /* 4186: struct.rsa_meth_st */
            	5, 0,
            	4215, 8,
            	4215, 16,
            	4215, 24,
            	4215, 32,
            	4218, 40,
            	4221, 48,
            	4224, 56,
            	4224, 64,
            	99, 80,
            	4227, 88,
            	4230, 96,
            	4233, 104,
            8884097, 8, 0, /* 4215: pointer.func */
            8884097, 8, 0, /* 4218: pointer.func */
            8884097, 8, 0, /* 4221: pointer.func */
            8884097, 8, 0, /* 4224: pointer.func */
            8884097, 8, 0, /* 4227: pointer.func */
            8884097, 8, 0, /* 4230: pointer.func */
            8884097, 8, 0, /* 4233: pointer.func */
            1, 8, 1, /* 4236: pointer.struct.dh_st */
            	4241, 0,
            0, 144, 12, /* 4241: struct.dh_st */
            	3997, 8,
            	3997, 16,
            	3997, 32,
            	3997, 40,
            	4007, 56,
            	3997, 64,
            	3997, 72,
            	78, 80,
            	3997, 96,
            	4021, 112,
            	4268, 128,
            	4085, 136,
            1, 8, 1, /* 4268: pointer.struct.dh_method */
            	3892, 0,
            1, 8, 1, /* 4273: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4278, 0,
            0, 32, 2, /* 4278: struct.stack_st_fake_X509_ATTRIBUTE */
            	4285, 8,
            	86, 24,
            8884099, 8, 2, /* 4285: pointer_to_array_of_pointers_to_stack */
            	4292, 0,
            	83, 20,
            0, 8, 1, /* 4292: pointer.X509_ATTRIBUTE */
            	1324, 0,
            1, 8, 1, /* 4297: pointer.struct.asn1_string_st */
            	3806, 0,
            8884097, 8, 0, /* 4302: pointer.func */
            1, 8, 1, /* 4305: pointer.struct.X509_val_st */
            	4310, 0,
            0, 16, 2, /* 4310: struct.X509_val_st */
            	4297, 0,
            	4297, 8,
            1, 8, 1, /* 4317: pointer.struct.bio_st */
            	4322, 0,
            0, 112, 7, /* 4322: struct.bio_st */
            	4339, 0,
            	4383, 8,
            	99, 16,
            	273, 48,
            	4386, 56,
            	4386, 64,
            	2629, 96,
            1, 8, 1, /* 4339: pointer.struct.bio_method_st */
            	4344, 0,
            0, 80, 9, /* 4344: struct.bio_method_st */
            	5, 8,
            	4365, 16,
            	4368, 24,
            	4371, 32,
            	4368, 40,
            	4374, 48,
            	4377, 56,
            	4377, 64,
            	4380, 72,
            8884097, 8, 0, /* 4365: pointer.func */
            8884097, 8, 0, /* 4368: pointer.func */
            8884097, 8, 0, /* 4371: pointer.func */
            8884097, 8, 0, /* 4374: pointer.func */
            8884097, 8, 0, /* 4377: pointer.func */
            8884097, 8, 0, /* 4380: pointer.func */
            8884097, 8, 0, /* 4383: pointer.func */
            1, 8, 1, /* 4386: pointer.struct.bio_st */
            	4322, 0,
            8884097, 8, 0, /* 4391: pointer.func */
            1, 8, 1, /* 4394: pointer.struct.AUTHORITY_KEYID_st */
            	4399, 0,
            0, 0, 0, /* 4399: struct.AUTHORITY_KEYID_st */
            8884097, 8, 0, /* 4402: pointer.func */
            0, 0, 0, /* 4405: struct.X509_POLICY_CACHE_st */
            8884097, 8, 0, /* 4408: pointer.func */
            1, 8, 1, /* 4411: pointer.struct.x509_cinf_st */
            	4416, 0,
            0, 104, 11, /* 4416: struct.x509_cinf_st */
            	3811, 0,
            	3811, 8,
            	3722, 16,
            	4441, 24,
            	4305, 32,
            	4441, 40,
            	4489, 48,
            	3821, 56,
            	3821, 64,
            	4508, 72,
            	4532, 80,
            1, 8, 1, /* 4441: pointer.struct.X509_name_st */
            	4446, 0,
            0, 40, 3, /* 4446: struct.X509_name_st */
            	4455, 0,
            	4479, 16,
            	78, 24,
            1, 8, 1, /* 4455: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4460, 0,
            0, 32, 2, /* 4460: struct.stack_st_fake_X509_NAME_ENTRY */
            	4467, 8,
            	86, 24,
            8884099, 8, 2, /* 4467: pointer_to_array_of_pointers_to_stack */
            	4474, 0,
            	83, 20,
            0, 8, 1, /* 4474: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 4479: pointer.struct.buf_mem_st */
            	4484, 0,
            0, 24, 1, /* 4484: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 4489: pointer.struct.X509_pubkey_st */
            	4494, 0,
            0, 24, 3, /* 4494: struct.X509_pubkey_st */
            	3722, 0,
            	3821, 8,
            	4503, 16,
            1, 8, 1, /* 4503: pointer.struct.evp_pkey_st */
            	4107, 0,
            1, 8, 1, /* 4508: pointer.struct.stack_st_X509_EXTENSION */
            	4513, 0,
            0, 32, 2, /* 4513: struct.stack_st_fake_X509_EXTENSION */
            	4520, 8,
            	86, 24,
            8884099, 8, 2, /* 4520: pointer_to_array_of_pointers_to_stack */
            	4527, 0,
            	83, 20,
            0, 8, 1, /* 4527: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 4532: struct.ASN1_ENCODING_st */
            	78, 0,
            0, 0, 1, /* 4537: X509 */
            	4542, 0,
            0, 184, 12, /* 4542: struct.x509_st */
            	4411, 0,
            	3722, 8,
            	3821, 16,
            	99, 32,
            	4021, 40,
            	3826, 104,
            	4394, 112,
            	4569, 120,
            	4574, 128,
            	4598, 136,
            	4622, 144,
            	4630, 176,
            1, 8, 1, /* 4569: pointer.struct.X509_POLICY_CACHE_st */
            	4405, 0,
            1, 8, 1, /* 4574: pointer.struct.stack_st_DIST_POINT */
            	4579, 0,
            0, 32, 2, /* 4579: struct.stack_st_fake_DIST_POINT */
            	4586, 8,
            	86, 24,
            8884099, 8, 2, /* 4586: pointer_to_array_of_pointers_to_stack */
            	4593, 0,
            	83, 20,
            0, 8, 1, /* 4593: pointer.DIST_POINT */
            	1740, 0,
            1, 8, 1, /* 4598: pointer.struct.stack_st_GENERAL_NAME */
            	4603, 0,
            0, 32, 2, /* 4603: struct.stack_st_fake_GENERAL_NAME */
            	4610, 8,
            	86, 24,
            8884099, 8, 2, /* 4610: pointer_to_array_of_pointers_to_stack */
            	4617, 0,
            	83, 20,
            0, 8, 1, /* 4617: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 4622: pointer.struct.NAME_CONSTRAINTS_st */
            	4627, 0,
            0, 0, 0, /* 4627: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4630: pointer.struct.x509_cert_aux_st */
            	4635, 0,
            0, 40, 5, /* 4635: struct.x509_cert_aux_st */
            	4648, 0,
            	4648, 8,
            	3876, 16,
            	3826, 24,
            	4672, 32,
            1, 8, 1, /* 4648: pointer.struct.stack_st_ASN1_OBJECT */
            	4653, 0,
            0, 32, 2, /* 4653: struct.stack_st_fake_ASN1_OBJECT */
            	4660, 8,
            	86, 24,
            8884099, 8, 2, /* 4660: pointer_to_array_of_pointers_to_stack */
            	4667, 0,
            	83, 20,
            0, 8, 1, /* 4667: pointer.ASN1_OBJECT */
            	2199, 0,
            1, 8, 1, /* 4672: pointer.struct.stack_st_X509_ALGOR */
            	4677, 0,
            0, 32, 2, /* 4677: struct.stack_st_fake_X509_ALGOR */
            	4684, 8,
            	86, 24,
            8884099, 8, 2, /* 4684: pointer_to_array_of_pointers_to_stack */
            	4691, 0,
            	83, 20,
            0, 8, 1, /* 4691: pointer.X509_ALGOR */
            	2237, 0,
            8884097, 8, 0, /* 4696: pointer.func */
            1, 8, 1, /* 4699: pointer.struct.sess_cert_st */
            	4704, 0,
            0, 248, 5, /* 4704: struct.sess_cert_st */
            	4717, 0,
            	4741, 16,
            	2524, 216,
            	4802, 224,
            	4807, 232,
            1, 8, 1, /* 4717: pointer.struct.stack_st_X509 */
            	4722, 0,
            0, 32, 2, /* 4722: struct.stack_st_fake_X509 */
            	4729, 8,
            	86, 24,
            8884099, 8, 2, /* 4729: pointer_to_array_of_pointers_to_stack */
            	4736, 0,
            	83, 20,
            0, 8, 1, /* 4736: pointer.X509 */
            	4537, 0,
            1, 8, 1, /* 4741: pointer.struct.cert_pkey_st */
            	4746, 0,
            0, 24, 3, /* 4746: struct.cert_pkey_st */
            	4755, 0,
            	2989, 8,
            	4760, 16,
            1, 8, 1, /* 4755: pointer.struct.x509_st */
            	2686, 0,
            1, 8, 1, /* 4760: pointer.struct.env_md_st */
            	4765, 0,
            0, 120, 8, /* 4765: struct.env_md_st */
            	4784, 24,
            	4787, 32,
            	4790, 40,
            	4793, 48,
            	4784, 56,
            	4302, 64,
            	4796, 72,
            	4799, 112,
            8884097, 8, 0, /* 4784: pointer.func */
            8884097, 8, 0, /* 4787: pointer.func */
            8884097, 8, 0, /* 4790: pointer.func */
            8884097, 8, 0, /* 4793: pointer.func */
            8884097, 8, 0, /* 4796: pointer.func */
            8884097, 8, 0, /* 4799: pointer.func */
            1, 8, 1, /* 4802: pointer.struct.dh_st */
            	3117, 0,
            1, 8, 1, /* 4807: pointer.struct.ec_key_st */
            	3185, 0,
            1, 8, 1, /* 4812: pointer.struct.ssl_session_st */
            	4817, 0,
            0, 352, 14, /* 4817: struct.ssl_session_st */
            	99, 144,
            	99, 152,
            	4699, 168,
            	4755, 176,
            	4848, 224,
            	4858, 240,
            	2629, 248,
            	4892, 264,
            	4892, 272,
            	99, 280,
            	78, 296,
            	78, 312,
            	78, 320,
            	99, 344,
            1, 8, 1, /* 4848: pointer.struct.ssl_cipher_st */
            	4853, 0,
            0, 88, 1, /* 4853: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4858: pointer.struct.stack_st_SSL_CIPHER */
            	4863, 0,
            0, 32, 2, /* 4863: struct.stack_st_fake_SSL_CIPHER */
            	4870, 8,
            	86, 24,
            8884099, 8, 2, /* 4870: pointer_to_array_of_pointers_to_stack */
            	4877, 0,
            	83, 20,
            0, 8, 1, /* 4877: pointer.SSL_CIPHER */
            	4882, 0,
            0, 0, 1, /* 4882: SSL_CIPHER */
            	4887, 0,
            0, 88, 1, /* 4887: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4892: pointer.struct.ssl_session_st */
            	4817, 0,
            1, 8, 1, /* 4897: pointer.struct.comp_ctx_st */
            	4902, 0,
            0, 56, 2, /* 4902: struct.comp_ctx_st */
            	3929, 0,
            	2629, 40,
            0, 168, 4, /* 4909: struct.evp_cipher_ctx_st */
            	4920, 0,
            	2621, 8,
            	273, 96,
            	273, 120,
            1, 8, 1, /* 4920: pointer.struct.evp_cipher_st */
            	4925, 0,
            0, 88, 7, /* 4925: struct.evp_cipher_st */
            	4942, 24,
            	4945, 32,
            	4408, 40,
            	4948, 56,
            	4948, 64,
            	4951, 72,
            	273, 80,
            8884097, 8, 0, /* 4942: pointer.func */
            8884097, 8, 0, /* 4945: pointer.func */
            8884097, 8, 0, /* 4948: pointer.func */
            8884097, 8, 0, /* 4951: pointer.func */
            0, 40, 4, /* 4954: struct.dtls1_retransmit_state */
            	4965, 0,
            	4970, 8,
            	4897, 16,
            	4812, 24,
            1, 8, 1, /* 4965: pointer.struct.evp_cipher_ctx_st */
            	4909, 0,
            1, 8, 1, /* 4970: pointer.struct.env_md_ctx_st */
            	4975, 0,
            0, 48, 5, /* 4975: struct.env_md_ctx_st */
            	4760, 0,
            	2621, 8,
            	273, 24,
            	4988, 32,
            	4787, 40,
            1, 8, 1, /* 4988: pointer.struct.evp_pkey_ctx_st */
            	4993, 0,
            0, 0, 0, /* 4993: struct.evp_pkey_ctx_st */
            8884097, 8, 0, /* 4996: pointer.func */
            1, 8, 1, /* 4999: pointer.struct._pqueue */
            	5004, 0,
            0, 0, 0, /* 5004: struct._pqueue */
            0, 16, 1, /* 5007: struct.record_pqueue_st */
            	4999, 8,
            8884097, 8, 0, /* 5012: pointer.func */
            8884097, 8, 0, /* 5015: pointer.func */
            8884097, 8, 0, /* 5018: pointer.func */
            1, 8, 1, /* 5021: pointer.struct.ssl3_enc_method */
            	5026, 0,
            0, 112, 11, /* 5026: struct.ssl3_enc_method */
            	5051, 0,
            	5054, 8,
            	5057, 16,
            	5015, 24,
            	5051, 32,
            	5060, 40,
            	5063, 56,
            	5, 64,
            	5, 80,
            	5066, 96,
            	5018, 104,
            8884097, 8, 0, /* 5051: pointer.func */
            8884097, 8, 0, /* 5054: pointer.func */
            8884097, 8, 0, /* 5057: pointer.func */
            8884097, 8, 0, /* 5060: pointer.func */
            8884097, 8, 0, /* 5063: pointer.func */
            8884097, 8, 0, /* 5066: pointer.func */
            0, 0, 1, /* 5069: X509_NAME */
            	4446, 0,
            0, 1200, 10, /* 5074: struct.ssl3_state_st */
            	5097, 240,
            	5097, 264,
            	5102, 288,
            	5102, 344,
            	60, 432,
            	4317, 440,
            	5111, 448,
            	273, 496,
            	273, 512,
            	5116, 528,
            0, 24, 1, /* 5097: struct.ssl3_buffer_st */
            	78, 0,
            0, 56, 3, /* 5102: struct.ssl3_record_st */
            	78, 16,
            	78, 24,
            	78, 32,
            1, 8, 1, /* 5111: pointer.pointer.struct.env_md_ctx_st */
            	4970, 0,
            0, 528, 8, /* 5116: struct.unknown */
            	4848, 408,
            	4802, 416,
            	4807, 424,
            	5135, 464,
            	78, 480,
            	4920, 488,
            	4760, 496,
            	5159, 512,
            1, 8, 1, /* 5135: pointer.struct.stack_st_X509_NAME */
            	5140, 0,
            0, 32, 2, /* 5140: struct.stack_st_fake_X509_NAME */
            	5147, 8,
            	86, 24,
            8884099, 8, 2, /* 5147: pointer_to_array_of_pointers_to_stack */
            	5154, 0,
            	83, 20,
            0, 8, 1, /* 5154: pointer.X509_NAME */
            	5069, 0,
            1, 8, 1, /* 5159: pointer.struct.ssl_comp_st */
            	3960, 0,
            8884097, 8, 0, /* 5164: pointer.func */
            8884097, 8, 0, /* 5167: pointer.func */
            8884097, 8, 0, /* 5170: pointer.func */
            1, 8, 1, /* 5173: pointer.struct.ssl_st */
            	5178, 0,
            0, 808, 51, /* 5178: struct.ssl_st */
            	5283, 8,
            	4317, 16,
            	4317, 24,
            	4317, 32,
            	5057, 48,
            	2948, 80,
            	273, 88,
            	78, 104,
            	5380, 120,
            	5406, 128,
            	5411, 136,
            	5438, 152,
            	273, 160,
            	5441, 176,
            	4858, 184,
            	4858, 192,
            	4965, 208,
            	4970, 216,
            	4897, 224,
            	4965, 232,
            	4970, 240,
            	4897, 248,
            	5453, 256,
            	4812, 304,
            	5484, 312,
            	5487, 328,
            	5012, 336,
            	5490, 352,
            	5493, 360,
            	5496, 368,
            	2629, 392,
            	5135, 408,
            	5715, 464,
            	273, 472,
            	99, 480,
            	195, 504,
            	10, 512,
            	78, 520,
            	78, 544,
            	78, 560,
            	273, 568,
            	2513, 584,
            	5718, 592,
            	273, 600,
            	2683, 608,
            	273, 616,
            	5496, 624,
            	78, 632,
            	5691, 648,
            	5721, 656,
            	242, 680,
            1, 8, 1, /* 5283: pointer.struct.ssl_method_st */
            	5288, 0,
            0, 232, 28, /* 5288: struct.ssl_method_st */
            	5057, 8,
            	5347, 16,
            	5347, 24,
            	5057, 32,
            	5057, 40,
            	5350, 48,
            	5350, 56,
            	5170, 64,
            	5057, 72,
            	5057, 80,
            	5057, 88,
            	5167, 96,
            	5164, 104,
            	5353, 112,
            	5057, 120,
            	5356, 128,
            	5359, 136,
            	4996, 144,
            	5362, 152,
            	5365, 160,
            	5368, 168,
            	5371, 176,
            	5374, 184,
            	342, 192,
            	5021, 200,
            	5368, 208,
            	4104, 216,
            	5377, 224,
            8884097, 8, 0, /* 5347: pointer.func */
            8884097, 8, 0, /* 5350: pointer.func */
            8884097, 8, 0, /* 5353: pointer.func */
            8884097, 8, 0, /* 5356: pointer.func */
            8884097, 8, 0, /* 5359: pointer.func */
            8884097, 8, 0, /* 5362: pointer.func */
            8884097, 8, 0, /* 5365: pointer.func */
            8884097, 8, 0, /* 5368: pointer.func */
            8884097, 8, 0, /* 5371: pointer.func */
            8884097, 8, 0, /* 5374: pointer.func */
            8884097, 8, 0, /* 5377: pointer.func */
            1, 8, 1, /* 5380: pointer.struct.ssl2_state_st */
            	5385, 0,
            0, 344, 9, /* 5385: struct.ssl2_state_st */
            	60, 24,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 104,
            	78, 112,
            	78, 120,
            	78, 128,
            	78, 136,
            1, 8, 1, /* 5406: pointer.struct.ssl3_state_st */
            	5074, 0,
            1, 8, 1, /* 5411: pointer.struct.dtls1_state_st */
            	5416, 0,
            0, 888, 7, /* 5416: struct.dtls1_state_st */
            	5007, 576,
            	5007, 592,
            	4999, 608,
            	4999, 616,
            	5007, 624,
            	5433, 648,
            	5433, 736,
            0, 88, 1, /* 5433: struct.hm_header_st */
            	4954, 48,
            8884097, 8, 0, /* 5438: pointer.func */
            1, 8, 1, /* 5441: pointer.struct.X509_VERIFY_PARAM_st */
            	5446, 0,
            0, 56, 2, /* 5446: struct.X509_VERIFY_PARAM_st */
            	99, 0,
            	3663, 48,
            1, 8, 1, /* 5453: pointer.struct.cert_st */
            	5458, 0,
            0, 296, 7, /* 5458: struct.cert_st */
            	4741, 0,
            	2524, 48,
            	5475, 56,
            	4802, 64,
            	5478, 72,
            	4807, 80,
            	5481, 88,
            8884097, 8, 0, /* 5475: pointer.func */
            8884097, 8, 0, /* 5478: pointer.func */
            8884097, 8, 0, /* 5481: pointer.func */
            8884097, 8, 0, /* 5484: pointer.func */
            8884097, 8, 0, /* 5487: pointer.func */
            8884097, 8, 0, /* 5490: pointer.func */
            8884097, 8, 0, /* 5493: pointer.func */
            1, 8, 1, /* 5496: pointer.struct.ssl_ctx_st */
            	5501, 0,
            0, 736, 50, /* 5501: struct.ssl_ctx_st */
            	5283, 0,
            	4858, 8,
            	4858, 16,
            	5604, 24,
            	426, 32,
            	4892, 48,
            	4892, 56,
            	461, 80,
            	3719, 88,
            	389, 96,
            	2518, 152,
            	273, 160,
            	4402, 168,
            	273, 176,
            	5675, 184,
            	4391, 192,
            	386, 200,
            	2629, 208,
            	4760, 224,
            	4760, 232,
            	4760, 240,
            	4717, 248,
            	362, 256,
            	5012, 264,
            	5135, 272,
            	5453, 304,
            	5438, 320,
            	273, 328,
            	5487, 376,
            	5484, 384,
            	5441, 392,
            	2621, 408,
            	276, 416,
            	273, 424,
            	2521, 480,
            	279, 488,
            	273, 496,
            	313, 504,
            	273, 512,
            	99, 520,
            	5490, 528,
            	5493, 536,
            	5678, 552,
            	5678, 560,
            	242, 568,
            	239, 696,
            	273, 704,
            	5688, 712,
            	273, 720,
            	5691, 728,
            1, 8, 1, /* 5604: pointer.struct.x509_store_st */
            	5609, 0,
            0, 144, 15, /* 5609: struct.x509_store_st */
            	5642, 8,
            	2484, 16,
            	5441, 24,
            	437, 32,
            	5487, 40,
            	434, 48,
            	5666, 56,
            	437, 64,
            	4696, 72,
            	431, 80,
            	5669, 88,
            	5672, 96,
            	4101, 104,
            	437, 112,
            	2629, 120,
            1, 8, 1, /* 5642: pointer.struct.stack_st_X509_OBJECT */
            	5647, 0,
            0, 32, 2, /* 5647: struct.stack_st_fake_X509_OBJECT */
            	5654, 8,
            	86, 24,
            8884099, 8, 2, /* 5654: pointer_to_array_of_pointers_to_stack */
            	5661, 0,
            	83, 20,
            0, 8, 1, /* 5661: pointer.X509_OBJECT */
            	613, 0,
            8884097, 8, 0, /* 5666: pointer.func */
            8884097, 8, 0, /* 5669: pointer.func */
            8884097, 8, 0, /* 5672: pointer.func */
            8884097, 8, 0, /* 5675: pointer.func */
            1, 8, 1, /* 5678: pointer.struct.ssl3_buf_freelist_st */
            	5683, 0,
            0, 24, 1, /* 5683: struct.ssl3_buf_freelist_st */
            	303, 16,
            8884097, 8, 0, /* 5688: pointer.func */
            1, 8, 1, /* 5691: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	5696, 0,
            0, 32, 2, /* 5696: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	5703, 8,
            	86, 24,
            8884099, 8, 2, /* 5703: pointer_to_array_of_pointers_to_stack */
            	5710, 0,
            	83, 20,
            0, 8, 1, /* 5710: pointer.SRTP_PROTECTION_PROFILE */
            	229, 0,
            8884097, 8, 0, /* 5715: pointer.func */
            8884097, 8, 0, /* 5718: pointer.func */
            1, 8, 1, /* 5721: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            0, 1, 0, /* 5726: char */
        },
        .arg_entity_index = { 5173, 273, 83, },
        .ret_entity_index = 83,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    const void * new_arg_b = *((const void * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_write)(SSL *,const void *,int);
    orig_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
    *new_ret_ptr = (*orig_SSL_write)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

