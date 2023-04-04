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
            1, 8, 1, /* 259: pointer.struct.ec_point_st */
            	90, 0,
            4097, 8, 0, /* 264: pointer.func */
            4097, 8, 0, /* 267: pointer.func */
            1, 8, 1, /* 270: pointer.struct.cert_st */
            	275, 0,
            0, 296, 8, /* 275: struct.cert_st */
            	294, 0,
            	1061, 48,
            	28, 56,
            	1149, 64,
            	267, 72,
            	1181, 80,
            	264, 88,
            	1232, 96,
            1, 8, 1, /* 294: pointer.struct.cert_pkey_st */
            	299, 0,
            0, 24, 3, /* 299: struct.cert_pkey_st */
            	308, 0,
            	496, 8,
            	1016, 16,
            1, 8, 1, /* 308: pointer.struct.x509_st */
            	313, 0,
            0, 184, 12, /* 313: struct.x509_st */
            	340, 0,
            	380, 8,
            	370, 16,
            	45, 32,
            	936, 40,
            	370, 104,
            	946, 112,
            	960, 120,
            	435, 128,
            	435, 136,
            	986, 144,
            	998, 176,
            1, 8, 1, /* 340: pointer.struct.x509_cinf_st */
            	345, 0,
            0, 104, 11, /* 345: struct.x509_cinf_st */
            	370, 0,
            	370, 8,
            	380, 16,
            	421, 24,
            	470, 32,
            	421, 40,
            	482, 48,
            	370, 56,
            	370, 64,
            	435, 72,
            	941, 80,
            1, 8, 1, /* 370: pointer.struct.asn1_string_st */
            	375, 0,
            0, 24, 1, /* 375: struct.asn1_string_st */
            	45, 8,
            1, 8, 1, /* 380: pointer.struct.X509_algor_st */
            	385, 0,
            0, 16, 2, /* 385: struct.X509_algor_st */
            	392, 0,
            	406, 8,
            1, 8, 1, /* 392: pointer.struct.asn1_object_st */
            	397, 0,
            0, 40, 3, /* 397: struct.asn1_object_st */
            	45, 0,
            	45, 8,
            	45, 24,
            1, 8, 1, /* 406: pointer.struct.asn1_type_st */
            	411, 0,
            0, 16, 1, /* 411: struct.asn1_type_st */
            	416, 8,
            0, 8, 1, /* 416: struct.fnames */
            	45, 0,
            1, 8, 1, /* 421: pointer.struct.X509_name_st */
            	426, 0,
            0, 40, 3, /* 426: struct.X509_name_st */
            	435, 0,
            	460, 16,
            	45, 24,
            1, 8, 1, /* 435: pointer.struct.stack_st_OPENSSL_STRING */
            	440, 0,
            0, 32, 1, /* 440: struct.stack_st_OPENSSL_STRING */
            	445, 0,
            0, 32, 2, /* 445: struct.stack_st */
            	452, 8,
            	457, 24,
            1, 8, 1, /* 452: pointer.pointer.char */
            	45, 0,
            4097, 8, 0, /* 457: pointer.func */
            1, 8, 1, /* 460: pointer.struct.buf_mem_st */
            	465, 0,
            0, 24, 1, /* 465: struct.buf_mem_st */
            	45, 8,
            1, 8, 1, /* 470: pointer.struct.X509_val_st */
            	475, 0,
            0, 16, 2, /* 475: struct.X509_val_st */
            	370, 0,
            	370, 8,
            1, 8, 1, /* 482: pointer.struct.X509_pubkey_st */
            	487, 0,
            0, 24, 3, /* 487: struct.X509_pubkey_st */
            	380, 0,
            	370, 8,
            	496, 16,
            1, 8, 1, /* 496: pointer.struct.evp_pkey_st */
            	501, 0,
            0, 56, 4, /* 501: struct.evp_pkey_st */
            	512, 16,
            	615, 24,
            	416, 32,
            	435, 48,
            1, 8, 1, /* 512: pointer.struct.evp_pkey_asn1_method_st */
            	517, 0,
            0, 208, 24, /* 517: struct.evp_pkey_asn1_method_st */
            	45, 16,
            	45, 24,
            	568, 32,
            	576, 40,
            	579, 48,
            	582, 56,
            	585, 64,
            	588, 72,
            	582, 80,
            	591, 88,
            	591, 96,
            	594, 104,
            	597, 112,
            	591, 120,
            	579, 128,
            	579, 136,
            	582, 144,
            	600, 152,
            	603, 160,
            	606, 168,
            	594, 176,
            	597, 184,
            	609, 192,
            	612, 200,
            1, 8, 1, /* 568: pointer.struct.unnamed */
            	573, 0,
            0, 0, 0, /* 573: struct.unnamed */
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
            4097, 8, 0, /* 612: pointer.func */
            1, 8, 1, /* 615: pointer.struct.engine_st */
            	620, 0,
            0, 216, 24, /* 620: struct.engine_st */
            	45, 0,
            	45, 8,
            	671, 16,
            	726, 24,
            	777, 32,
            	813, 40,
            	830, 48,
            	857, 56,
            	892, 64,
            	900, 72,
            	903, 80,
            	906, 88,
            	909, 96,
            	912, 104,
            	912, 112,
            	912, 120,
            	915, 128,
            	918, 136,
            	918, 144,
            	921, 152,
            	924, 160,
            	936, 184,
            	615, 200,
            	615, 208,
            1, 8, 1, /* 671: pointer.struct.rsa_meth_st */
            	676, 0,
            0, 112, 13, /* 676: struct.rsa_meth_st */
            	45, 0,
            	705, 8,
            	705, 16,
            	705, 24,
            	705, 32,
            	708, 40,
            	711, 48,
            	714, 56,
            	714, 64,
            	45, 80,
            	717, 88,
            	720, 96,
            	723, 104,
            4097, 8, 0, /* 705: pointer.func */
            4097, 8, 0, /* 708: pointer.func */
            4097, 8, 0, /* 711: pointer.func */
            4097, 8, 0, /* 714: pointer.func */
            4097, 8, 0, /* 717: pointer.func */
            4097, 8, 0, /* 720: pointer.func */
            4097, 8, 0, /* 723: pointer.func */
            1, 8, 1, /* 726: pointer.struct.dsa_method */
            	731, 0,
            0, 96, 11, /* 731: struct.dsa_method */
            	45, 0,
            	756, 8,
            	759, 16,
            	762, 24,
            	765, 32,
            	768, 40,
            	771, 48,
            	771, 56,
            	45, 72,
            	774, 80,
            	771, 88,
            4097, 8, 0, /* 756: pointer.func */
            4097, 8, 0, /* 759: pointer.func */
            4097, 8, 0, /* 762: pointer.func */
            4097, 8, 0, /* 765: pointer.func */
            4097, 8, 0, /* 768: pointer.func */
            4097, 8, 0, /* 771: pointer.func */
            4097, 8, 0, /* 774: pointer.func */
            1, 8, 1, /* 777: pointer.struct.dh_method */
            	782, 0,
            0, 72, 8, /* 782: struct.dh_method */
            	45, 0,
            	801, 8,
            	804, 16,
            	807, 24,
            	801, 32,
            	801, 40,
            	45, 56,
            	810, 64,
            4097, 8, 0, /* 801: pointer.func */
            4097, 8, 0, /* 804: pointer.func */
            4097, 8, 0, /* 807: pointer.func */
            4097, 8, 0, /* 810: pointer.func */
            1, 8, 1, /* 813: pointer.struct.ecdh_method */
            	818, 0,
            0, 32, 3, /* 818: struct.ecdh_method */
            	45, 0,
            	827, 8,
            	45, 24,
            4097, 8, 0, /* 827: pointer.func */
            1, 8, 1, /* 830: pointer.struct.ecdsa_method */
            	835, 0,
            0, 48, 5, /* 835: struct.ecdsa_method */
            	45, 0,
            	848, 8,
            	851, 16,
            	854, 24,
            	45, 40,
            4097, 8, 0, /* 848: pointer.func */
            4097, 8, 0, /* 851: pointer.func */
            4097, 8, 0, /* 854: pointer.func */
            1, 8, 1, /* 857: pointer.struct.rand_meth_st */
            	862, 0,
            0, 48, 6, /* 862: struct.rand_meth_st */
            	877, 0,
            	880, 8,
            	883, 16,
            	886, 24,
            	880, 32,
            	889, 40,
            4097, 8, 0, /* 877: pointer.func */
            4097, 8, 0, /* 880: pointer.func */
            4097, 8, 0, /* 883: pointer.func */
            4097, 8, 0, /* 886: pointer.func */
            4097, 8, 0, /* 889: pointer.func */
            1, 8, 1, /* 892: pointer.struct.store_method_st */
            	897, 0,
            0, 0, 0, /* 897: struct.store_method_st */
            4097, 8, 0, /* 900: pointer.func */
            4097, 8, 0, /* 903: pointer.func */
            4097, 8, 0, /* 906: pointer.func */
            4097, 8, 0, /* 909: pointer.func */
            4097, 8, 0, /* 912: pointer.func */
            4097, 8, 0, /* 915: pointer.func */
            4097, 8, 0, /* 918: pointer.func */
            4097, 8, 0, /* 921: pointer.func */
            1, 8, 1, /* 924: pointer.struct.ENGINE_CMD_DEFN_st */
            	929, 0,
            0, 32, 2, /* 929: struct.ENGINE_CMD_DEFN_st */
            	45, 8,
            	45, 16,
            0, 16, 1, /* 936: struct.crypto_ex_data_st */
            	435, 0,
            0, 24, 1, /* 941: struct.ASN1_ENCODING_st */
            	45, 0,
            1, 8, 1, /* 946: pointer.struct.AUTHORITY_KEYID_st */
            	951, 0,
            0, 24, 3, /* 951: struct.AUTHORITY_KEYID_st */
            	370, 0,
            	435, 8,
            	370, 16,
            1, 8, 1, /* 960: pointer.struct.X509_POLICY_CACHE_st */
            	965, 0,
            0, 40, 2, /* 965: struct.X509_POLICY_CACHE_st */
            	972, 0,
            	435, 8,
            1, 8, 1, /* 972: pointer.struct.X509_POLICY_DATA_st */
            	977, 0,
            0, 32, 3, /* 977: struct.X509_POLICY_DATA_st */
            	392, 8,
            	435, 16,
            	435, 24,
            1, 8, 1, /* 986: pointer.struct.NAME_CONSTRAINTS_st */
            	991, 0,
            0, 16, 2, /* 991: struct.NAME_CONSTRAINTS_st */
            	435, 0,
            	435, 8,
            1, 8, 1, /* 998: pointer.struct.x509_cert_aux_st */
            	1003, 0,
            0, 40, 5, /* 1003: struct.x509_cert_aux_st */
            	435, 0,
            	435, 8,
            	370, 16,
            	370, 24,
            	435, 32,
            1, 8, 1, /* 1016: pointer.struct.env_md_st */
            	1021, 0,
            0, 120, 8, /* 1021: struct.env_md_st */
            	1040, 24,
            	1043, 32,
            	1046, 40,
            	1049, 48,
            	1040, 56,
            	1052, 64,
            	1055, 72,
            	1058, 112,
            4097, 8, 0, /* 1040: pointer.func */
            4097, 8, 0, /* 1043: pointer.func */
            4097, 8, 0, /* 1046: pointer.func */
            4097, 8, 0, /* 1049: pointer.func */
            4097, 8, 0, /* 1052: pointer.func */
            4097, 8, 0, /* 1055: pointer.func */
            4097, 8, 0, /* 1058: pointer.func */
            1, 8, 1, /* 1061: pointer.struct.rsa_st */
            	1066, 0,
            0, 168, 17, /* 1066: struct.rsa_st */
            	671, 16,
            	615, 24,
            	1103, 32,
            	1103, 40,
            	1103, 48,
            	1103, 56,
            	1103, 64,
            	1103, 72,
            	1103, 80,
            	1103, 88,
            	936, 96,
            	1108, 120,
            	1108, 128,
            	1108, 136,
            	45, 144,
            	1122, 152,
            	1122, 160,
            1, 8, 1, /* 1103: pointer.struct.bignum_st */
            	246, 0,
            1, 8, 1, /* 1108: pointer.struct.bn_mont_ctx_st */
            	1113, 0,
            0, 96, 3, /* 1113: struct.bn_mont_ctx_st */
            	246, 8,
            	246, 32,
            	246, 56,
            1, 8, 1, /* 1122: pointer.struct.bn_blinding_st */
            	1127, 0,
            0, 88, 7, /* 1127: struct.bn_blinding_st */
            	1103, 0,
            	1103, 8,
            	1103, 16,
            	1103, 24,
            	1144, 40,
            	1108, 72,
            	711, 80,
            0, 16, 1, /* 1144: struct.iovec */
            	45, 0,
            1, 8, 1, /* 1149: pointer.struct.dh_st */
            	1154, 0,
            0, 144, 12, /* 1154: struct.dh_st */
            	1103, 8,
            	1103, 16,
            	1103, 32,
            	1103, 40,
            	1108, 56,
            	1103, 64,
            	1103, 72,
            	45, 80,
            	1103, 96,
            	936, 112,
            	777, 128,
            	615, 136,
            1, 8, 1, /* 1181: pointer.struct.ec_key_st */
            	1186, 0,
            0, 56, 4, /* 1186: struct.ec_key_st */
            	1197, 8,
            	259, 16,
            	1103, 24,
            	79, 48,
            1, 8, 1, /* 1197: pointer.struct.ec_group_st */
            	1202, 0,
            0, 232, 12, /* 1202: struct.ec_group_st */
            	101, 0,
            	259, 8,
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
            4097, 8, 0, /* 1229: pointer.func */
            0, 192, 8, /* 1232: array[8].struct.cert_pkey_st */
            	299, 0,
            	299, 24,
            	299, 48,
            	299, 72,
            	299, 96,
            	299, 120,
            	299, 144,
            	299, 168,
            4097, 8, 0, /* 1251: pointer.func */
            0, 128, 14, /* 1254: struct.srp_ctx_st */
            	45, 0,
            	22, 8,
            	6, 16,
            	0, 24,
            	45, 32,
            	1103, 40,
            	1103, 48,
            	1103, 56,
            	1103, 64,
            	1103, 72,
            	1103, 80,
            	1103, 88,
            	1103, 96,
            	45, 104,
            0, 352, 14, /* 1285: struct.ssl_session_st */
            	45, 144,
            	45, 152,
            	1316, 168,
            	308, 176,
            	1336, 224,
            	435, 240,
            	936, 248,
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
            	435, 0,
            	294, 16,
            	1232, 24,
            	1061, 216,
            	1149, 224,
            	1181, 232,
            1, 8, 1, /* 1336: pointer.struct.ssl_cipher_st */
            	40, 0,
            1, 8, 1, /* 1341: pointer.struct.ssl_session_st */
            	1285, 0,
            4097, 8, 0, /* 1346: pointer.func */
            0, 176, 3, /* 1349: struct.lhash_st */
            	1358, 0,
            	457, 8,
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
            1, 8, 1, /* 1381: pointer.struct.ssl_method_st */
            	1386, 0,
            0, 232, 28, /* 1386: struct.ssl_method_st */
            	1445, 8,
            	1448, 16,
            	1448, 24,
            	1445, 32,
            	1445, 40,
            	1451, 48,
            	1451, 56,
            	1451, 64,
            	1445, 72,
            	1445, 80,
            	1445, 88,
            	1454, 96,
            	1457, 104,
            	1460, 112,
            	1445, 120,
            	1463, 128,
            	1466, 136,
            	1469, 144,
            	1472, 152,
            	1445, 160,
            	889, 168,
            	1475, 176,
            	1478, 184,
            	1481, 192,
            	1484, 200,
            	889, 208,
            	1532, 216,
            	1535, 224,
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
            4097, 8, 0, /* 1481: pointer.func */
            1, 8, 1, /* 1484: pointer.struct.ssl3_enc_method */
            	1489, 0,
            0, 112, 11, /* 1489: struct.ssl3_enc_method */
            	1514, 0,
            	1451, 8,
            	1445, 16,
            	1517, 24,
            	1514, 32,
            	1520, 40,
            	1523, 56,
            	45, 64,
            	45, 80,
            	1526, 96,
            	1529, 104,
            4097, 8, 0, /* 1514: pointer.func */
            4097, 8, 0, /* 1517: pointer.func */
            4097, 8, 0, /* 1520: pointer.func */
            4097, 8, 0, /* 1523: pointer.func */
            4097, 8, 0, /* 1526: pointer.func */
            4097, 8, 0, /* 1529: pointer.func */
            4097, 8, 0, /* 1532: pointer.func */
            4097, 8, 0, /* 1535: pointer.func */
            0, 144, 15, /* 1538: struct.x509_store_st */
            	435, 8,
            	435, 16,
            	1571, 24,
            	1583, 32,
            	1586, 40,
            	1378, 48,
            	1589, 56,
            	1583, 64,
            	1592, 72,
            	1346, 80,
            	1595, 88,
            	1598, 96,
            	1598, 104,
            	1583, 112,
            	936, 120,
            1, 8, 1, /* 1571: pointer.struct.X509_VERIFY_PARAM_st */
            	1576, 0,
            0, 56, 2, /* 1576: struct.X509_VERIFY_PARAM_st */
            	45, 0,
            	435, 48,
            4097, 8, 0, /* 1583: pointer.func */
            4097, 8, 0, /* 1586: pointer.func */
            4097, 8, 0, /* 1589: pointer.func */
            4097, 8, 0, /* 1592: pointer.func */
            4097, 8, 0, /* 1595: pointer.func */
            4097, 8, 0, /* 1598: pointer.func */
            1, 8, 1, /* 1601: pointer.struct.x509_store_st */
            	1538, 0,
            4097, 8, 0, /* 1606: pointer.func */
            4097, 8, 0, /* 1609: pointer.func */
            4097, 8, 0, /* 1612: pointer.func */
            0, 736, 50, /* 1615: struct.ssl_ctx_st */
            	1381, 0,
            	435, 8,
            	435, 16,
            	1601, 24,
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
            	1451, 200,
            	936, 208,
            	1016, 224,
            	1016, 232,
            	1016, 240,
            	435, 248,
            	435, 256,
            	31, 264,
            	435, 272,
            	270, 304,
            	25, 320,
            	45, 328,
            	1586, 376,
            	63, 384,
            	1571, 392,
            	615, 408,
            	22, 416,
            	45, 424,
            	19, 480,
            	6, 488,
            	45, 496,
            	1609, 504,
            	45, 512,
            	45, 520,
            	3, 528,
            	1517, 536,
            	53, 552,
            	53, 560,
            	1254, 568,
            	1612, 696,
            	45, 704,
            	1606, 712,
            	45, 720,
            	435, 728,
            1, 8, 1, /* 1718: pointer.struct.lhash_st */
            	1349, 0,
            4097, 8, 0, /* 1723: pointer.func */
            4097, 8, 0, /* 1726: pointer.func */
            4097, 8, 0, /* 1729: pointer.func */
            1, 8, 1, /* 1732: pointer.struct.ssl_ctx_st */
            	1615, 0,
            0, 1, 0, /* 1737: char */
        },
        .arg_entity_index = { 1732, 37, },
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

