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

void bb_SSL_CTX_set_info_callback(SSL_CTX *arg_a, void (*arg_b)(const SSL *,int,int));

void SSL_CTX_set_info_callback(SSL_CTX *arg_a, void (*arg_b)(const SSL *,int,int)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_set_info_callback called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_set_info_callback(arg_a,arg_b);
    else {
        void (*orig_SSL_CTX_set_info_callback)(SSL_CTX *, void (*)(const SSL *,int,int));
        orig_SSL_CTX_set_info_callback = dlsym(RTLD_NEXT, "SSL_CTX_set_info_callback");
        orig_SSL_CTX_set_info_callback(arg_a,arg_b);
    }
}

void bb_SSL_CTX_set_info_callback(SSL_CTX *arg_a, void (*arg_b)(const SSL *,int,int)) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            4097, 8, 0, /* 6: pointer.func */
            1, 8, 1, /* 9: pointer.struct.ssl3_buf_freelist_entry_st */
            	14, 0,
            0, 8, 1, /* 14: struct.ssl3_buf_freelist_entry_st */
            	9, 0,
            4097, 8, 0, /* 19: pointer.func */
            4097, 8, 0, /* 22: pointer.func */
            4097, 8, 0, /* 25: pointer.func */
            4097, 8, 0, /* 28: pointer.func */
            4097, 8, 0, /* 31: pointer.func */
            4097, 8, 0, /* 34: pointer.func */
            0, 88, 1, /* 37: struct.ssl_cipher_st */
            	42, 8,
            1, 8, 1, /* 42: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 47: pointer.func */
            1, 8, 1, /* 50: pointer.struct.ssl3_buf_freelist_st */
            	55, 0,
            0, 24, 1, /* 55: struct.ssl3_buf_freelist_st */
            	9, 16,
            4097, 8, 0, /* 60: pointer.func */
            0, 40, 5, /* 63: struct.ec_extra_data_st */
            	76, 0,
            	81, 8,
            	84, 16,
            	47, 24,
            	47, 32,
            1, 8, 1, /* 76: pointer.struct.ec_extra_data_st */
            	63, 0,
            0, 8, 0, /* 81: pointer.void */
            4097, 8, 0, /* 84: pointer.func */
            0, 88, 4, /* 87: struct.ec_point_st */
            	98, 0,
            	243, 8,
            	243, 32,
            	243, 56,
            1, 8, 1, /* 98: pointer.struct.ec_method_st */
            	103, 0,
            0, 304, 37, /* 103: struct.ec_method_st */
            	180, 8,
            	183, 16,
            	183, 24,
            	186, 32,
            	189, 40,
            	189, 48,
            	180, 56,
            	192, 64,
            	195, 72,
            	198, 80,
            	198, 88,
            	201, 96,
            	204, 104,
            	207, 112,
            	207, 120,
            	210, 128,
            	210, 136,
            	213, 144,
            	216, 152,
            	219, 160,
            	222, 168,
            	225, 176,
            	228, 184,
            	204, 192,
            	228, 200,
            	225, 208,
            	228, 216,
            	231, 224,
            	234, 232,
            	192, 240,
            	180, 248,
            	189, 256,
            	237, 264,
            	189, 272,
            	237, 280,
            	237, 288,
            	240, 296,
            4097, 8, 0, /* 180: pointer.func */
            4097, 8, 0, /* 183: pointer.func */
            4097, 8, 0, /* 186: pointer.func */
            4097, 8, 0, /* 189: pointer.func */
            4097, 8, 0, /* 192: pointer.func */
            4097, 8, 0, /* 195: pointer.func */
            4097, 8, 0, /* 198: pointer.func */
            4097, 8, 0, /* 201: pointer.func */
            4097, 8, 0, /* 204: pointer.func */
            4097, 8, 0, /* 207: pointer.func */
            4097, 8, 0, /* 210: pointer.func */
            4097, 8, 0, /* 213: pointer.func */
            4097, 8, 0, /* 216: pointer.func */
            4097, 8, 0, /* 219: pointer.func */
            4097, 8, 0, /* 222: pointer.func */
            4097, 8, 0, /* 225: pointer.func */
            4097, 8, 0, /* 228: pointer.func */
            4097, 8, 0, /* 231: pointer.func */
            4097, 8, 0, /* 234: pointer.func */
            4097, 8, 0, /* 237: pointer.func */
            4097, 8, 0, /* 240: pointer.func */
            0, 24, 1, /* 243: struct.bignum_st */
            	248, 0,
            1, 8, 1, /* 248: pointer.int */
            	253, 0,
            0, 4, 0, /* 253: int */
            1, 8, 1, /* 256: pointer.struct.ec_point_st */
            	87, 0,
            4097, 8, 0, /* 261: pointer.func */
            4097, 8, 0, /* 264: pointer.func */
            1, 8, 1, /* 267: pointer.struct.cert_st */
            	272, 0,
            0, 296, 8, /* 272: struct.cert_st */
            	291, 0,
            	1058, 48,
            	28, 56,
            	1146, 64,
            	264, 72,
            	1178, 80,
            	261, 88,
            	1229, 96,
            1, 8, 1, /* 291: pointer.struct.cert_pkey_st */
            	296, 0,
            0, 24, 3, /* 296: struct.cert_pkey_st */
            	305, 0,
            	493, 8,
            	1013, 16,
            1, 8, 1, /* 305: pointer.struct.x509_st */
            	310, 0,
            0, 184, 12, /* 310: struct.x509_st */
            	337, 0,
            	377, 8,
            	367, 16,
            	42, 32,
            	933, 40,
            	367, 104,
            	943, 112,
            	957, 120,
            	432, 128,
            	432, 136,
            	983, 144,
            	995, 176,
            1, 8, 1, /* 337: pointer.struct.x509_cinf_st */
            	342, 0,
            0, 104, 11, /* 342: struct.x509_cinf_st */
            	367, 0,
            	367, 8,
            	377, 16,
            	418, 24,
            	467, 32,
            	418, 40,
            	479, 48,
            	367, 56,
            	367, 64,
            	432, 72,
            	938, 80,
            1, 8, 1, /* 367: pointer.struct.asn1_string_st */
            	372, 0,
            0, 24, 1, /* 372: struct.asn1_string_st */
            	42, 8,
            1, 8, 1, /* 377: pointer.struct.X509_algor_st */
            	382, 0,
            0, 16, 2, /* 382: struct.X509_algor_st */
            	389, 0,
            	403, 8,
            1, 8, 1, /* 389: pointer.struct.asn1_object_st */
            	394, 0,
            0, 40, 3, /* 394: struct.asn1_object_st */
            	42, 0,
            	42, 8,
            	42, 24,
            1, 8, 1, /* 403: pointer.struct.asn1_type_st */
            	408, 0,
            0, 16, 1, /* 408: struct.asn1_type_st */
            	413, 8,
            0, 8, 1, /* 413: struct.fnames */
            	42, 0,
            1, 8, 1, /* 418: pointer.struct.X509_name_st */
            	423, 0,
            0, 40, 3, /* 423: struct.X509_name_st */
            	432, 0,
            	457, 16,
            	42, 24,
            1, 8, 1, /* 432: pointer.struct.stack_st_OPENSSL_STRING */
            	437, 0,
            0, 32, 1, /* 437: struct.stack_st_OPENSSL_STRING */
            	442, 0,
            0, 32, 2, /* 442: struct.stack_st */
            	449, 8,
            	454, 24,
            1, 8, 1, /* 449: pointer.pointer.char */
            	42, 0,
            4097, 8, 0, /* 454: pointer.func */
            1, 8, 1, /* 457: pointer.struct.buf_mem_st */
            	462, 0,
            0, 24, 1, /* 462: struct.buf_mem_st */
            	42, 8,
            1, 8, 1, /* 467: pointer.struct.X509_val_st */
            	472, 0,
            0, 16, 2, /* 472: struct.X509_val_st */
            	367, 0,
            	367, 8,
            1, 8, 1, /* 479: pointer.struct.X509_pubkey_st */
            	484, 0,
            0, 24, 3, /* 484: struct.X509_pubkey_st */
            	377, 0,
            	367, 8,
            	493, 16,
            1, 8, 1, /* 493: pointer.struct.evp_pkey_st */
            	498, 0,
            0, 56, 4, /* 498: struct.evp_pkey_st */
            	509, 16,
            	612, 24,
            	413, 32,
            	432, 48,
            1, 8, 1, /* 509: pointer.struct.evp_pkey_asn1_method_st */
            	514, 0,
            0, 208, 24, /* 514: struct.evp_pkey_asn1_method_st */
            	42, 16,
            	42, 24,
            	565, 32,
            	573, 40,
            	576, 48,
            	579, 56,
            	582, 64,
            	585, 72,
            	579, 80,
            	588, 88,
            	588, 96,
            	591, 104,
            	594, 112,
            	588, 120,
            	576, 128,
            	576, 136,
            	579, 144,
            	597, 152,
            	600, 160,
            	603, 168,
            	591, 176,
            	594, 184,
            	606, 192,
            	609, 200,
            1, 8, 1, /* 565: pointer.struct.unnamed */
            	570, 0,
            0, 0, 0, /* 570: struct.unnamed */
            4097, 8, 0, /* 573: pointer.func */
            4097, 8, 0, /* 576: pointer.func */
            4097, 8, 0, /* 579: pointer.func */
            4097, 8, 0, /* 582: pointer.func */
            4097, 8, 0, /* 585: pointer.func */
            4097, 8, 0, /* 588: pointer.func */
            4097, 8, 0, /* 591: pointer.func */
            4097, 8, 0, /* 594: pointer.func */
            4097, 8, 0, /* 597: pointer.func */
            4097, 8, 0, /* 600: pointer.func */
            4097, 8, 0, /* 603: pointer.func */
            4097, 8, 0, /* 606: pointer.func */
            4097, 8, 0, /* 609: pointer.func */
            1, 8, 1, /* 612: pointer.struct.engine_st */
            	617, 0,
            0, 216, 24, /* 617: struct.engine_st */
            	42, 0,
            	42, 8,
            	668, 16,
            	723, 24,
            	774, 32,
            	810, 40,
            	827, 48,
            	854, 56,
            	889, 64,
            	897, 72,
            	900, 80,
            	903, 88,
            	906, 96,
            	909, 104,
            	909, 112,
            	909, 120,
            	912, 128,
            	915, 136,
            	915, 144,
            	918, 152,
            	921, 160,
            	933, 184,
            	612, 200,
            	612, 208,
            1, 8, 1, /* 668: pointer.struct.rsa_meth_st */
            	673, 0,
            0, 112, 13, /* 673: struct.rsa_meth_st */
            	42, 0,
            	702, 8,
            	702, 16,
            	702, 24,
            	702, 32,
            	705, 40,
            	708, 48,
            	711, 56,
            	711, 64,
            	42, 80,
            	714, 88,
            	717, 96,
            	720, 104,
            4097, 8, 0, /* 702: pointer.func */
            4097, 8, 0, /* 705: pointer.func */
            4097, 8, 0, /* 708: pointer.func */
            4097, 8, 0, /* 711: pointer.func */
            4097, 8, 0, /* 714: pointer.func */
            4097, 8, 0, /* 717: pointer.func */
            4097, 8, 0, /* 720: pointer.func */
            1, 8, 1, /* 723: pointer.struct.dsa_method */
            	728, 0,
            0, 96, 11, /* 728: struct.dsa_method */
            	42, 0,
            	753, 8,
            	756, 16,
            	759, 24,
            	762, 32,
            	765, 40,
            	768, 48,
            	768, 56,
            	42, 72,
            	771, 80,
            	768, 88,
            4097, 8, 0, /* 753: pointer.func */
            4097, 8, 0, /* 756: pointer.func */
            4097, 8, 0, /* 759: pointer.func */
            4097, 8, 0, /* 762: pointer.func */
            4097, 8, 0, /* 765: pointer.func */
            4097, 8, 0, /* 768: pointer.func */
            4097, 8, 0, /* 771: pointer.func */
            1, 8, 1, /* 774: pointer.struct.dh_method */
            	779, 0,
            0, 72, 8, /* 779: struct.dh_method */
            	42, 0,
            	798, 8,
            	801, 16,
            	804, 24,
            	798, 32,
            	798, 40,
            	42, 56,
            	807, 64,
            4097, 8, 0, /* 798: pointer.func */
            4097, 8, 0, /* 801: pointer.func */
            4097, 8, 0, /* 804: pointer.func */
            4097, 8, 0, /* 807: pointer.func */
            1, 8, 1, /* 810: pointer.struct.ecdh_method */
            	815, 0,
            0, 32, 3, /* 815: struct.ecdh_method */
            	42, 0,
            	824, 8,
            	42, 24,
            4097, 8, 0, /* 824: pointer.func */
            1, 8, 1, /* 827: pointer.struct.ecdsa_method */
            	832, 0,
            0, 48, 5, /* 832: struct.ecdsa_method */
            	42, 0,
            	845, 8,
            	848, 16,
            	851, 24,
            	42, 40,
            4097, 8, 0, /* 845: pointer.func */
            4097, 8, 0, /* 848: pointer.func */
            4097, 8, 0, /* 851: pointer.func */
            1, 8, 1, /* 854: pointer.struct.rand_meth_st */
            	859, 0,
            0, 48, 6, /* 859: struct.rand_meth_st */
            	874, 0,
            	877, 8,
            	880, 16,
            	883, 24,
            	877, 32,
            	886, 40,
            4097, 8, 0, /* 874: pointer.func */
            4097, 8, 0, /* 877: pointer.func */
            4097, 8, 0, /* 880: pointer.func */
            4097, 8, 0, /* 883: pointer.func */
            4097, 8, 0, /* 886: pointer.func */
            1, 8, 1, /* 889: pointer.struct.store_method_st */
            	894, 0,
            0, 0, 0, /* 894: struct.store_method_st */
            4097, 8, 0, /* 897: pointer.func */
            4097, 8, 0, /* 900: pointer.func */
            4097, 8, 0, /* 903: pointer.func */
            4097, 8, 0, /* 906: pointer.func */
            4097, 8, 0, /* 909: pointer.func */
            4097, 8, 0, /* 912: pointer.func */
            4097, 8, 0, /* 915: pointer.func */
            4097, 8, 0, /* 918: pointer.func */
            1, 8, 1, /* 921: pointer.struct.ENGINE_CMD_DEFN_st */
            	926, 0,
            0, 32, 2, /* 926: struct.ENGINE_CMD_DEFN_st */
            	42, 8,
            	42, 16,
            0, 16, 1, /* 933: struct.crypto_ex_data_st */
            	432, 0,
            0, 24, 1, /* 938: struct.ASN1_ENCODING_st */
            	42, 0,
            1, 8, 1, /* 943: pointer.struct.AUTHORITY_KEYID_st */
            	948, 0,
            0, 24, 3, /* 948: struct.AUTHORITY_KEYID_st */
            	367, 0,
            	432, 8,
            	367, 16,
            1, 8, 1, /* 957: pointer.struct.X509_POLICY_CACHE_st */
            	962, 0,
            0, 40, 2, /* 962: struct.X509_POLICY_CACHE_st */
            	969, 0,
            	432, 8,
            1, 8, 1, /* 969: pointer.struct.X509_POLICY_DATA_st */
            	974, 0,
            0, 32, 3, /* 974: struct.X509_POLICY_DATA_st */
            	389, 8,
            	432, 16,
            	432, 24,
            1, 8, 1, /* 983: pointer.struct.NAME_CONSTRAINTS_st */
            	988, 0,
            0, 16, 2, /* 988: struct.NAME_CONSTRAINTS_st */
            	432, 0,
            	432, 8,
            1, 8, 1, /* 995: pointer.struct.x509_cert_aux_st */
            	1000, 0,
            0, 40, 5, /* 1000: struct.x509_cert_aux_st */
            	432, 0,
            	432, 8,
            	367, 16,
            	367, 24,
            	432, 32,
            1, 8, 1, /* 1013: pointer.struct.env_md_st */
            	1018, 0,
            0, 120, 8, /* 1018: struct.env_md_st */
            	1037, 24,
            	1040, 32,
            	1043, 40,
            	1046, 48,
            	1037, 56,
            	1049, 64,
            	1052, 72,
            	1055, 112,
            4097, 8, 0, /* 1037: pointer.func */
            4097, 8, 0, /* 1040: pointer.func */
            4097, 8, 0, /* 1043: pointer.func */
            4097, 8, 0, /* 1046: pointer.func */
            4097, 8, 0, /* 1049: pointer.func */
            4097, 8, 0, /* 1052: pointer.func */
            4097, 8, 0, /* 1055: pointer.func */
            1, 8, 1, /* 1058: pointer.struct.rsa_st */
            	1063, 0,
            0, 168, 17, /* 1063: struct.rsa_st */
            	668, 16,
            	612, 24,
            	1100, 32,
            	1100, 40,
            	1100, 48,
            	1100, 56,
            	1100, 64,
            	1100, 72,
            	1100, 80,
            	1100, 88,
            	933, 96,
            	1105, 120,
            	1105, 128,
            	1105, 136,
            	42, 144,
            	1119, 152,
            	1119, 160,
            1, 8, 1, /* 1100: pointer.struct.bignum_st */
            	243, 0,
            1, 8, 1, /* 1105: pointer.struct.bn_mont_ctx_st */
            	1110, 0,
            0, 96, 3, /* 1110: struct.bn_mont_ctx_st */
            	243, 8,
            	243, 32,
            	243, 56,
            1, 8, 1, /* 1119: pointer.struct.bn_blinding_st */
            	1124, 0,
            0, 88, 7, /* 1124: struct.bn_blinding_st */
            	1100, 0,
            	1100, 8,
            	1100, 16,
            	1100, 24,
            	1141, 40,
            	1105, 72,
            	708, 80,
            0, 16, 1, /* 1141: struct.iovec */
            	42, 0,
            1, 8, 1, /* 1146: pointer.struct.dh_st */
            	1151, 0,
            0, 144, 12, /* 1151: struct.dh_st */
            	1100, 8,
            	1100, 16,
            	1100, 32,
            	1100, 40,
            	1105, 56,
            	1100, 64,
            	1100, 72,
            	42, 80,
            	1100, 96,
            	933, 112,
            	774, 128,
            	612, 136,
            1, 8, 1, /* 1178: pointer.struct.ec_key_st */
            	1183, 0,
            0, 56, 4, /* 1183: struct.ec_key_st */
            	1194, 8,
            	256, 16,
            	1100, 24,
            	76, 48,
            1, 8, 1, /* 1194: pointer.struct.ec_group_st */
            	1199, 0,
            0, 232, 12, /* 1199: struct.ec_group_st */
            	98, 0,
            	256, 8,
            	243, 16,
            	243, 40,
            	42, 80,
            	76, 96,
            	243, 104,
            	243, 152,
            	243, 176,
            	42, 208,
            	42, 216,
            	1226, 224,
            4097, 8, 0, /* 1226: pointer.func */
            0, 192, 8, /* 1229: array[8].struct.cert_pkey_st */
            	296, 0,
            	296, 24,
            	296, 48,
            	296, 72,
            	296, 96,
            	296, 120,
            	296, 144,
            	296, 168,
            4097, 8, 0, /* 1248: pointer.func */
            0, 128, 14, /* 1251: struct.srp_ctx_st */
            	42, 0,
            	22, 8,
            	6, 16,
            	0, 24,
            	42, 32,
            	1100, 40,
            	1100, 48,
            	1100, 56,
            	1100, 64,
            	1100, 72,
            	1100, 80,
            	1100, 88,
            	1100, 96,
            	42, 104,
            0, 352, 14, /* 1282: struct.ssl_session_st */
            	42, 144,
            	42, 152,
            	1313, 168,
            	305, 176,
            	1333, 224,
            	432, 240,
            	933, 248,
            	1338, 264,
            	1338, 272,
            	42, 280,
            	42, 296,
            	42, 312,
            	42, 320,
            	42, 344,
            1, 8, 1, /* 1313: pointer.struct.sess_cert_st */
            	1318, 0,
            0, 248, 6, /* 1318: struct.sess_cert_st */
            	432, 0,
            	291, 16,
            	1229, 24,
            	1058, 216,
            	1146, 224,
            	1178, 232,
            1, 8, 1, /* 1333: pointer.struct.ssl_cipher_st */
            	37, 0,
            1, 8, 1, /* 1338: pointer.struct.ssl_session_st */
            	1282, 0,
            4097, 8, 0, /* 1343: pointer.func */
            0, 176, 3, /* 1346: struct.lhash_st */
            	1355, 0,
            	454, 8,
            	1372, 16,
            1, 8, 1, /* 1355: pointer.pointer.struct.lhash_node_st */
            	1360, 0,
            1, 8, 1, /* 1360: pointer.struct.lhash_node_st */
            	1365, 0,
            0, 24, 2, /* 1365: struct.lhash_node_st */
            	81, 0,
            	1360, 8,
            4097, 8, 0, /* 1372: pointer.func */
            4097, 8, 0, /* 1375: pointer.func */
            1, 8, 1, /* 1378: pointer.struct.ssl_method_st */
            	1383, 0,
            0, 232, 28, /* 1383: struct.ssl_method_st */
            	1442, 8,
            	1445, 16,
            	1445, 24,
            	1442, 32,
            	1442, 40,
            	1448, 48,
            	1448, 56,
            	1448, 64,
            	1442, 72,
            	1442, 80,
            	1442, 88,
            	1451, 96,
            	1454, 104,
            	1457, 112,
            	1442, 120,
            	1460, 128,
            	1463, 136,
            	1466, 144,
            	1469, 152,
            	1442, 160,
            	886, 168,
            	1472, 176,
            	1475, 184,
            	1478, 192,
            	1481, 200,
            	886, 208,
            	1529, 216,
            	1532, 224,
            4097, 8, 0, /* 1442: pointer.func */
            4097, 8, 0, /* 1445: pointer.func */
            4097, 8, 0, /* 1448: pointer.func */
            4097, 8, 0, /* 1451: pointer.func */
            4097, 8, 0, /* 1454: pointer.func */
            4097, 8, 0, /* 1457: pointer.func */
            4097, 8, 0, /* 1460: pointer.func */
            4097, 8, 0, /* 1463: pointer.func */
            4097, 8, 0, /* 1466: pointer.func */
            4097, 8, 0, /* 1469: pointer.func */
            4097, 8, 0, /* 1472: pointer.func */
            4097, 8, 0, /* 1475: pointer.func */
            4097, 8, 0, /* 1478: pointer.func */
            1, 8, 1, /* 1481: pointer.struct.ssl3_enc_method */
            	1486, 0,
            0, 112, 11, /* 1486: struct.ssl3_enc_method */
            	1511, 0,
            	1448, 8,
            	1442, 16,
            	1514, 24,
            	1511, 32,
            	1517, 40,
            	1520, 56,
            	42, 64,
            	42, 80,
            	1523, 96,
            	1526, 104,
            4097, 8, 0, /* 1511: pointer.func */
            4097, 8, 0, /* 1514: pointer.func */
            4097, 8, 0, /* 1517: pointer.func */
            4097, 8, 0, /* 1520: pointer.func */
            4097, 8, 0, /* 1523: pointer.func */
            4097, 8, 0, /* 1526: pointer.func */
            4097, 8, 0, /* 1529: pointer.func */
            4097, 8, 0, /* 1532: pointer.func */
            0, 144, 15, /* 1535: struct.x509_store_st */
            	432, 8,
            	432, 16,
            	1568, 24,
            	1580, 32,
            	1583, 40,
            	1375, 48,
            	1586, 56,
            	1580, 64,
            	1589, 72,
            	1343, 80,
            	1592, 88,
            	1595, 96,
            	1595, 104,
            	1580, 112,
            	933, 120,
            1, 8, 1, /* 1568: pointer.struct.X509_VERIFY_PARAM_st */
            	1573, 0,
            0, 56, 2, /* 1573: struct.X509_VERIFY_PARAM_st */
            	42, 0,
            	432, 48,
            4097, 8, 0, /* 1580: pointer.func */
            4097, 8, 0, /* 1583: pointer.func */
            4097, 8, 0, /* 1586: pointer.func */
            4097, 8, 0, /* 1589: pointer.func */
            4097, 8, 0, /* 1592: pointer.func */
            4097, 8, 0, /* 1595: pointer.func */
            1, 8, 1, /* 1598: pointer.struct.x509_store_st */
            	1535, 0,
            4097, 8, 0, /* 1603: pointer.func */
            4097, 8, 0, /* 1606: pointer.func */
            4097, 8, 0, /* 1609: pointer.func */
            4097, 8, 0, /* 1612: pointer.func */
            0, 736, 50, /* 1615: struct.ssl_ctx_st */
            	1378, 0,
            	432, 8,
            	432, 16,
            	1598, 24,
            	1718, 32,
            	1338, 48,
            	1338, 56,
            	34, 80,
            	1723, 88,
            	31, 96,
            	1726, 152,
            	42, 160,
            	1729, 168,
            	42, 176,
            	1248, 184,
            	60, 192,
            	1448, 200,
            	933, 208,
            	1013, 224,
            	1013, 232,
            	1013, 240,
            	432, 248,
            	432, 256,
            	1603, 264,
            	432, 272,
            	267, 304,
            	25, 320,
            	42, 328,
            	1583, 376,
            	60, 384,
            	1568, 392,
            	612, 408,
            	22, 416,
            	42, 424,
            	19, 480,
            	6, 488,
            	42, 496,
            	1609, 504,
            	42, 512,
            	42, 520,
            	3, 528,
            	1514, 536,
            	50, 552,
            	50, 560,
            	1251, 568,
            	1612, 696,
            	42, 704,
            	1606, 712,
            	42, 720,
            	432, 728,
            1, 8, 1, /* 1718: pointer.struct.lhash_st */
            	1346, 0,
            4097, 8, 0, /* 1723: pointer.func */
            4097, 8, 0, /* 1726: pointer.func */
            4097, 8, 0, /* 1729: pointer.func */
            1, 8, 1, /* 1732: pointer.struct.ssl_ctx_st */
            	1615, 0,
            0, 1, 0, /* 1737: char */
        },
        .arg_entity_index = { 1732, 1603, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX *new_arg_a = *((SSL_CTX * *)new_args->args[0]);

     void (*new_arg_b)(const SSL *,int,int) = *(( void (**)(const SSL *,int,int))new_args->args[1]);

    void (*orig_SSL_CTX_set_info_callback)(SSL_CTX *, void (*)(const SSL *,int,int));
    orig_SSL_CTX_set_info_callback = dlsym(RTLD_NEXT, "SSL_CTX_set_info_callback");
    (*orig_SSL_CTX_set_info_callback)(new_arg_a,new_arg_b);

    syscall(889);

}

