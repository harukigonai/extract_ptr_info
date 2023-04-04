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
            4097, 8, 0, /* 37: pointer.func */
            0, 88, 1, /* 40: struct.ssl_cipher_st */
            	45, 8,
            1, 8, 1, /* 45: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 50: pointer.func */
            1, 8, 1, /* 53: pointer.struct.ssl3_buf_freelist_st */
            	58, 0,
            0, 24, 1, /* 58: struct.ssl3_buf_freelist_st */
            	9, 16,
            4097, 8, 0, /* 63: pointer.func */
            0, 40, 5, /* 66: struct.ec_extra_data_st */
            	79, 0,
            	84, 8,
            	87, 16,
            	50, 24,
            	50, 32,
            1, 8, 1, /* 79: pointer.struct.ec_extra_data_st */
            	66, 0,
            0, 8, 0, /* 84: pointer.void */
            4097, 8, 0, /* 87: pointer.func */
            0, 88, 4, /* 90: struct.ec_point_st */
            	101, 0,
            	246, 8,
            	246, 32,
            	246, 56,
            1, 8, 1, /* 101: pointer.struct.ec_method_st */
            	106, 0,
            0, 304, 37, /* 106: struct.ec_method_st */
            	183, 8,
            	186, 16,
            	186, 24,
            	189, 32,
            	192, 40,
            	192, 48,
            	183, 56,
            	195, 64,
            	198, 72,
            	201, 80,
            	201, 88,
            	204, 96,
            	207, 104,
            	210, 112,
            	210, 120,
            	213, 128,
            	213, 136,
            	216, 144,
            	219, 152,
            	222, 160,
            	225, 168,
            	228, 176,
            	231, 184,
            	207, 192,
            	231, 200,
            	228, 208,
            	231, 216,
            	234, 224,
            	237, 232,
            	195, 240,
            	183, 248,
            	192, 256,
            	240, 264,
            	192, 272,
            	240, 280,
            	240, 288,
            	243, 296,
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
            4097, 8, 0, /* 243: pointer.func */
            0, 24, 1, /* 246: struct.bignum_st */
            	251, 0,
            1, 8, 1, /* 251: pointer.int */
            	256, 0,
            0, 4, 0, /* 256: int */
            4097, 8, 0, /* 259: pointer.func */
            4097, 8, 0, /* 262: pointer.func */
            1, 8, 1, /* 265: pointer.struct.cert_st */
            	270, 0,
            0, 296, 8, /* 270: struct.cert_st */
            	289, 0,
            	1056, 48,
            	28, 56,
            	1144, 64,
            	262, 72,
            	1176, 80,
            	259, 88,
            	1232, 96,
            1, 8, 1, /* 289: pointer.struct.cert_pkey_st */
            	294, 0,
            0, 24, 3, /* 294: struct.cert_pkey_st */
            	303, 0,
            	491, 8,
            	1011, 16,
            1, 8, 1, /* 303: pointer.struct.x509_st */
            	308, 0,
            0, 184, 12, /* 308: struct.x509_st */
            	335, 0,
            	375, 8,
            	365, 16,
            	45, 32,
            	931, 40,
            	365, 104,
            	941, 112,
            	955, 120,
            	430, 128,
            	430, 136,
            	981, 144,
            	993, 176,
            1, 8, 1, /* 335: pointer.struct.x509_cinf_st */
            	340, 0,
            0, 104, 11, /* 340: struct.x509_cinf_st */
            	365, 0,
            	365, 8,
            	375, 16,
            	416, 24,
            	465, 32,
            	416, 40,
            	477, 48,
            	365, 56,
            	365, 64,
            	430, 72,
            	936, 80,
            1, 8, 1, /* 365: pointer.struct.asn1_string_st */
            	370, 0,
            0, 24, 1, /* 370: struct.asn1_string_st */
            	45, 8,
            1, 8, 1, /* 375: pointer.struct.X509_algor_st */
            	380, 0,
            0, 16, 2, /* 380: struct.X509_algor_st */
            	387, 0,
            	401, 8,
            1, 8, 1, /* 387: pointer.struct.asn1_object_st */
            	392, 0,
            0, 40, 3, /* 392: struct.asn1_object_st */
            	45, 0,
            	45, 8,
            	45, 24,
            1, 8, 1, /* 401: pointer.struct.asn1_type_st */
            	406, 0,
            0, 16, 1, /* 406: struct.asn1_type_st */
            	411, 8,
            0, 8, 1, /* 411: struct.fnames */
            	45, 0,
            1, 8, 1, /* 416: pointer.struct.X509_name_st */
            	421, 0,
            0, 40, 3, /* 421: struct.X509_name_st */
            	430, 0,
            	455, 16,
            	45, 24,
            1, 8, 1, /* 430: pointer.struct.stack_st_OPENSSL_STRING */
            	435, 0,
            0, 32, 1, /* 435: struct.stack_st_OPENSSL_STRING */
            	440, 0,
            0, 32, 2, /* 440: struct.stack_st */
            	447, 8,
            	452, 24,
            1, 8, 1, /* 447: pointer.pointer.char */
            	45, 0,
            4097, 8, 0, /* 452: pointer.func */
            1, 8, 1, /* 455: pointer.struct.buf_mem_st */
            	460, 0,
            0, 24, 1, /* 460: struct.buf_mem_st */
            	45, 8,
            1, 8, 1, /* 465: pointer.struct.X509_val_st */
            	470, 0,
            0, 16, 2, /* 470: struct.X509_val_st */
            	365, 0,
            	365, 8,
            1, 8, 1, /* 477: pointer.struct.X509_pubkey_st */
            	482, 0,
            0, 24, 3, /* 482: struct.X509_pubkey_st */
            	375, 0,
            	365, 8,
            	491, 16,
            1, 8, 1, /* 491: pointer.struct.evp_pkey_st */
            	496, 0,
            0, 56, 4, /* 496: struct.evp_pkey_st */
            	507, 16,
            	610, 24,
            	411, 32,
            	430, 48,
            1, 8, 1, /* 507: pointer.struct.evp_pkey_asn1_method_st */
            	512, 0,
            0, 208, 24, /* 512: struct.evp_pkey_asn1_method_st */
            	45, 16,
            	45, 24,
            	563, 32,
            	571, 40,
            	574, 48,
            	577, 56,
            	580, 64,
            	583, 72,
            	577, 80,
            	586, 88,
            	586, 96,
            	589, 104,
            	592, 112,
            	586, 120,
            	574, 128,
            	574, 136,
            	577, 144,
            	595, 152,
            	598, 160,
            	601, 168,
            	589, 176,
            	592, 184,
            	604, 192,
            	607, 200,
            1, 8, 1, /* 563: pointer.struct.unnamed */
            	568, 0,
            0, 0, 0, /* 568: struct.unnamed */
            4097, 8, 0, /* 571: pointer.func */
            4097, 8, 0, /* 574: pointer.func */
            4097, 8, 0, /* 577: pointer.func */
            4097, 8, 0, /* 580: pointer.func */
            4097, 8, 0, /* 583: pointer.func */
            4097, 8, 0, /* 586: pointer.func */
            4097, 8, 0, /* 589: pointer.func */
            4097, 8, 0, /* 592: pointer.func */
            4097, 8, 0, /* 595: pointer.func */
            4097, 8, 0, /* 598: pointer.func */
            4097, 8, 0, /* 601: pointer.func */
            4097, 8, 0, /* 604: pointer.func */
            4097, 8, 0, /* 607: pointer.func */
            1, 8, 1, /* 610: pointer.struct.engine_st */
            	615, 0,
            0, 216, 24, /* 615: struct.engine_st */
            	45, 0,
            	45, 8,
            	666, 16,
            	721, 24,
            	772, 32,
            	808, 40,
            	825, 48,
            	852, 56,
            	887, 64,
            	895, 72,
            	898, 80,
            	901, 88,
            	904, 96,
            	907, 104,
            	907, 112,
            	907, 120,
            	910, 128,
            	913, 136,
            	913, 144,
            	916, 152,
            	919, 160,
            	931, 184,
            	610, 200,
            	610, 208,
            1, 8, 1, /* 666: pointer.struct.rsa_meth_st */
            	671, 0,
            0, 112, 13, /* 671: struct.rsa_meth_st */
            	45, 0,
            	700, 8,
            	700, 16,
            	700, 24,
            	700, 32,
            	703, 40,
            	706, 48,
            	709, 56,
            	709, 64,
            	45, 80,
            	712, 88,
            	715, 96,
            	718, 104,
            4097, 8, 0, /* 700: pointer.func */
            4097, 8, 0, /* 703: pointer.func */
            4097, 8, 0, /* 706: pointer.func */
            4097, 8, 0, /* 709: pointer.func */
            4097, 8, 0, /* 712: pointer.func */
            4097, 8, 0, /* 715: pointer.func */
            4097, 8, 0, /* 718: pointer.func */
            1, 8, 1, /* 721: pointer.struct.dsa_method */
            	726, 0,
            0, 96, 11, /* 726: struct.dsa_method */
            	45, 0,
            	751, 8,
            	754, 16,
            	757, 24,
            	760, 32,
            	763, 40,
            	766, 48,
            	766, 56,
            	45, 72,
            	769, 80,
            	766, 88,
            4097, 8, 0, /* 751: pointer.func */
            4097, 8, 0, /* 754: pointer.func */
            4097, 8, 0, /* 757: pointer.func */
            4097, 8, 0, /* 760: pointer.func */
            4097, 8, 0, /* 763: pointer.func */
            4097, 8, 0, /* 766: pointer.func */
            4097, 8, 0, /* 769: pointer.func */
            1, 8, 1, /* 772: pointer.struct.dh_method */
            	777, 0,
            0, 72, 8, /* 777: struct.dh_method */
            	45, 0,
            	796, 8,
            	799, 16,
            	802, 24,
            	796, 32,
            	796, 40,
            	45, 56,
            	805, 64,
            4097, 8, 0, /* 796: pointer.func */
            4097, 8, 0, /* 799: pointer.func */
            4097, 8, 0, /* 802: pointer.func */
            4097, 8, 0, /* 805: pointer.func */
            1, 8, 1, /* 808: pointer.struct.ecdh_method */
            	813, 0,
            0, 32, 3, /* 813: struct.ecdh_method */
            	45, 0,
            	822, 8,
            	45, 24,
            4097, 8, 0, /* 822: pointer.func */
            1, 8, 1, /* 825: pointer.struct.ecdsa_method */
            	830, 0,
            0, 48, 5, /* 830: struct.ecdsa_method */
            	45, 0,
            	843, 8,
            	846, 16,
            	849, 24,
            	45, 40,
            4097, 8, 0, /* 843: pointer.func */
            4097, 8, 0, /* 846: pointer.func */
            4097, 8, 0, /* 849: pointer.func */
            1, 8, 1, /* 852: pointer.struct.rand_meth_st */
            	857, 0,
            0, 48, 6, /* 857: struct.rand_meth_st */
            	872, 0,
            	875, 8,
            	878, 16,
            	881, 24,
            	875, 32,
            	884, 40,
            4097, 8, 0, /* 872: pointer.func */
            4097, 8, 0, /* 875: pointer.func */
            4097, 8, 0, /* 878: pointer.func */
            4097, 8, 0, /* 881: pointer.func */
            4097, 8, 0, /* 884: pointer.func */
            1, 8, 1, /* 887: pointer.struct.store_method_st */
            	892, 0,
            0, 0, 0, /* 892: struct.store_method_st */
            4097, 8, 0, /* 895: pointer.func */
            4097, 8, 0, /* 898: pointer.func */
            4097, 8, 0, /* 901: pointer.func */
            4097, 8, 0, /* 904: pointer.func */
            4097, 8, 0, /* 907: pointer.func */
            4097, 8, 0, /* 910: pointer.func */
            4097, 8, 0, /* 913: pointer.func */
            4097, 8, 0, /* 916: pointer.func */
            1, 8, 1, /* 919: pointer.struct.ENGINE_CMD_DEFN_st */
            	924, 0,
            0, 32, 2, /* 924: struct.ENGINE_CMD_DEFN_st */
            	45, 8,
            	45, 16,
            0, 16, 1, /* 931: struct.crypto_ex_data_st */
            	430, 0,
            0, 24, 1, /* 936: struct.ASN1_ENCODING_st */
            	45, 0,
            1, 8, 1, /* 941: pointer.struct.AUTHORITY_KEYID_st */
            	946, 0,
            0, 24, 3, /* 946: struct.AUTHORITY_KEYID_st */
            	365, 0,
            	430, 8,
            	365, 16,
            1, 8, 1, /* 955: pointer.struct.X509_POLICY_CACHE_st */
            	960, 0,
            0, 40, 2, /* 960: struct.X509_POLICY_CACHE_st */
            	967, 0,
            	430, 8,
            1, 8, 1, /* 967: pointer.struct.X509_POLICY_DATA_st */
            	972, 0,
            0, 32, 3, /* 972: struct.X509_POLICY_DATA_st */
            	387, 8,
            	430, 16,
            	430, 24,
            1, 8, 1, /* 981: pointer.struct.NAME_CONSTRAINTS_st */
            	986, 0,
            0, 16, 2, /* 986: struct.NAME_CONSTRAINTS_st */
            	430, 0,
            	430, 8,
            1, 8, 1, /* 993: pointer.struct.x509_cert_aux_st */
            	998, 0,
            0, 40, 5, /* 998: struct.x509_cert_aux_st */
            	430, 0,
            	430, 8,
            	365, 16,
            	365, 24,
            	430, 32,
            1, 8, 1, /* 1011: pointer.struct.env_md_st */
            	1016, 0,
            0, 120, 8, /* 1016: struct.env_md_st */
            	1035, 24,
            	1038, 32,
            	1041, 40,
            	1044, 48,
            	1035, 56,
            	1047, 64,
            	1050, 72,
            	1053, 112,
            4097, 8, 0, /* 1035: pointer.func */
            4097, 8, 0, /* 1038: pointer.func */
            4097, 8, 0, /* 1041: pointer.func */
            4097, 8, 0, /* 1044: pointer.func */
            4097, 8, 0, /* 1047: pointer.func */
            4097, 8, 0, /* 1050: pointer.func */
            4097, 8, 0, /* 1053: pointer.func */
            1, 8, 1, /* 1056: pointer.struct.rsa_st */
            	1061, 0,
            0, 168, 17, /* 1061: struct.rsa_st */
            	666, 16,
            	610, 24,
            	1098, 32,
            	1098, 40,
            	1098, 48,
            	1098, 56,
            	1098, 64,
            	1098, 72,
            	1098, 80,
            	1098, 88,
            	931, 96,
            	1103, 120,
            	1103, 128,
            	1103, 136,
            	45, 144,
            	1117, 152,
            	1117, 160,
            1, 8, 1, /* 1098: pointer.struct.bignum_st */
            	246, 0,
            1, 8, 1, /* 1103: pointer.struct.bn_mont_ctx_st */
            	1108, 0,
            0, 96, 3, /* 1108: struct.bn_mont_ctx_st */
            	246, 8,
            	246, 32,
            	246, 56,
            1, 8, 1, /* 1117: pointer.struct.bn_blinding_st */
            	1122, 0,
            0, 88, 7, /* 1122: struct.bn_blinding_st */
            	1098, 0,
            	1098, 8,
            	1098, 16,
            	1098, 24,
            	1139, 40,
            	1103, 72,
            	706, 80,
            0, 16, 1, /* 1139: struct.iovec */
            	45, 0,
            1, 8, 1, /* 1144: pointer.struct.dh_st */
            	1149, 0,
            0, 144, 12, /* 1149: struct.dh_st */
            	1098, 8,
            	1098, 16,
            	1098, 32,
            	1098, 40,
            	1103, 56,
            	1098, 64,
            	1098, 72,
            	45, 80,
            	1098, 96,
            	931, 112,
            	772, 128,
            	610, 136,
            1, 8, 1, /* 1176: pointer.struct.ec_key_st */
            	1181, 0,
            0, 56, 4, /* 1181: struct.ec_key_st */
            	1192, 8,
            	1224, 16,
            	1098, 24,
            	79, 48,
            1, 8, 1, /* 1192: pointer.struct.ec_group_st */
            	1197, 0,
            0, 232, 12, /* 1197: struct.ec_group_st */
            	101, 0,
            	1224, 8,
            	246, 16,
            	246, 40,
            	45, 80,
            	79, 96,
            	246, 104,
            	246, 152,
            	246, 176,
            	45, 208,
            	45, 216,
            	1229, 224,
            1, 8, 1, /* 1224: pointer.struct.ec_point_st */
            	90, 0,
            4097, 8, 0, /* 1229: pointer.func */
            0, 192, 8, /* 1232: array[8].struct.cert_pkey_st */
            	294, 0,
            	294, 24,
            	294, 48,
            	294, 72,
            	294, 96,
            	294, 120,
            	294, 144,
            	294, 168,
            4097, 8, 0, /* 1251: pointer.func */
            0, 128, 14, /* 1254: struct.srp_ctx_st */
            	45, 0,
            	22, 8,
            	6, 16,
            	0, 24,
            	45, 32,
            	1098, 40,
            	1098, 48,
            	1098, 56,
            	1098, 64,
            	1098, 72,
            	1098, 80,
            	1098, 88,
            	1098, 96,
            	45, 104,
            0, 352, 14, /* 1285: struct.ssl_session_st */
            	45, 144,
            	45, 152,
            	1316, 168,
            	303, 176,
            	1336, 224,
            	430, 240,
            	931, 248,
            	1341, 264,
            	1341, 272,
            	45, 280,
            	45, 296,
            	45, 312,
            	45, 320,
            	45, 344,
            1, 8, 1, /* 1316: pointer.struct.sess_cert_st */
            	1321, 0,
            0, 248, 6, /* 1321: struct.sess_cert_st */
            	430, 0,
            	289, 16,
            	1232, 24,
            	1056, 216,
            	1144, 224,
            	1176, 232,
            1, 8, 1, /* 1336: pointer.struct.ssl_cipher_st */
            	40, 0,
            1, 8, 1, /* 1341: pointer.struct.ssl_session_st */
            	1285, 0,
            4097, 8, 0, /* 1346: pointer.func */
            0, 176, 3, /* 1349: struct.lhash_st */
            	1358, 0,
            	452, 8,
            	1375, 16,
            1, 8, 1, /* 1358: pointer.pointer.struct.lhash_node_st */
            	1363, 0,
            1, 8, 1, /* 1363: pointer.struct.lhash_node_st */
            	1368, 0,
            0, 24, 2, /* 1368: struct.lhash_node_st */
            	84, 0,
            	1363, 8,
            4097, 8, 0, /* 1375: pointer.func */
            4097, 8, 0, /* 1378: pointer.func */
            4097, 8, 0, /* 1381: pointer.func */
            0, 144, 15, /* 1384: struct.x509_store_st */
            	430, 8,
            	430, 16,
            	1417, 24,
            	1429, 32,
            	1432, 40,
            	1378, 48,
            	1435, 56,
            	1429, 64,
            	1438, 72,
            	1346, 80,
            	1441, 88,
            	1444, 96,
            	1444, 104,
            	1429, 112,
            	931, 120,
            1, 8, 1, /* 1417: pointer.struct.X509_VERIFY_PARAM_st */
            	1422, 0,
            0, 56, 2, /* 1422: struct.X509_VERIFY_PARAM_st */
            	45, 0,
            	430, 48,
            4097, 8, 0, /* 1429: pointer.func */
            4097, 8, 0, /* 1432: pointer.func */
            4097, 8, 0, /* 1435: pointer.func */
            4097, 8, 0, /* 1438: pointer.func */
            4097, 8, 0, /* 1441: pointer.func */
            4097, 8, 0, /* 1444: pointer.func */
            1, 8, 1, /* 1447: pointer.struct.x509_store_st */
            	1384, 0,
            4097, 8, 0, /* 1452: pointer.func */
            4097, 8, 0, /* 1455: pointer.func */
            4097, 8, 0, /* 1458: pointer.func */
            4097, 8, 0, /* 1461: pointer.func */
            4097, 8, 0, /* 1464: pointer.func */
            1, 8, 1, /* 1467: pointer.struct.ssl_method_st */
            	1472, 0,
            0, 232, 28, /* 1472: struct.ssl_method_st */
            	1531, 8,
            	1534, 16,
            	1534, 24,
            	1531, 32,
            	1531, 40,
            	1537, 48,
            	1537, 56,
            	1537, 64,
            	1531, 72,
            	1531, 80,
            	1531, 88,
            	1540, 96,
            	1543, 104,
            	1464, 112,
            	1531, 120,
            	1546, 128,
            	1549, 136,
            	1552, 144,
            	1458, 152,
            	1531, 160,
            	884, 168,
            	1555, 176,
            	1558, 184,
            	1561, 192,
            	1564, 200,
            	884, 208,
            	1606, 216,
            	1461, 224,
            4097, 8, 0, /* 1531: pointer.func */
            4097, 8, 0, /* 1534: pointer.func */
            4097, 8, 0, /* 1537: pointer.func */
            4097, 8, 0, /* 1540: pointer.func */
            4097, 8, 0, /* 1543: pointer.func */
            4097, 8, 0, /* 1546: pointer.func */
            4097, 8, 0, /* 1549: pointer.func */
            4097, 8, 0, /* 1552: pointer.func */
            4097, 8, 0, /* 1555: pointer.func */
            4097, 8, 0, /* 1558: pointer.func */
            4097, 8, 0, /* 1561: pointer.func */
            1, 8, 1, /* 1564: pointer.struct.ssl3_enc_method */
            	1569, 0,
            0, 112, 11, /* 1569: struct.ssl3_enc_method */
            	1381, 0,
            	1537, 8,
            	1531, 16,
            	1594, 24,
            	1381, 32,
            	1597, 40,
            	1600, 56,
            	45, 64,
            	45, 80,
            	1603, 96,
            	1455, 104,
            4097, 8, 0, /* 1594: pointer.func */
            4097, 8, 0, /* 1597: pointer.func */
            4097, 8, 0, /* 1600: pointer.func */
            4097, 8, 0, /* 1603: pointer.func */
            4097, 8, 0, /* 1606: pointer.func */
            4097, 8, 0, /* 1609: pointer.func */
            4097, 8, 0, /* 1612: pointer.func */
            0, 736, 50, /* 1615: struct.ssl_ctx_st */
            	1467, 0,
            	430, 8,
            	430, 16,
            	1447, 24,
            	1718, 32,
            	1341, 48,
            	1341, 56,
            	37, 80,
            	1723, 88,
            	34, 96,
            	1726, 152,
            	45, 160,
            	1729, 168,
            	45, 176,
            	1251, 184,
            	63, 192,
            	1537, 200,
            	931, 208,
            	1011, 224,
            	1011, 232,
            	1011, 240,
            	430, 248,
            	430, 256,
            	31, 264,
            	430, 272,
            	265, 304,
            	25, 320,
            	45, 328,
            	1432, 376,
            	63, 384,
            	1417, 392,
            	610, 408,
            	22, 416,
            	45, 424,
            	19, 480,
            	6, 488,
            	45, 496,
            	1609, 504,
            	45, 512,
            	45, 520,
            	3, 528,
            	1594, 536,
            	53, 552,
            	53, 560,
            	1254, 568,
            	1612, 696,
            	45, 704,
            	1452, 712,
            	45, 720,
            	430, 728,
            1, 8, 1, /* 1718: pointer.struct.lhash_st */
            	1349, 0,
            4097, 8, 0, /* 1723: pointer.func */
            4097, 8, 0, /* 1726: pointer.func */
            4097, 8, 0, /* 1729: pointer.func */
            1, 8, 1, /* 1732: pointer.struct.ssl_ctx_st */
            	1615, 0,
            0, 8, 0, /* 1737: long */
            0, 1, 0, /* 1740: char */
        },
        .arg_entity_index = { 1732, 1737, },
        .ret_entity_index = 1737,
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

