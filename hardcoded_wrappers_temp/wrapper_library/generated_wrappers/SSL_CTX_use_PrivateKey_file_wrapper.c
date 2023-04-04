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

int bb_SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c);

int SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_use_PrivateKey_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_use_PrivateKey_file(arg_a,arg_b,arg_c);
    else {
        int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *,const char *,int);
        orig_SSL_CTX_use_PrivateKey_file = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey_file");
        return orig_SSL_CTX_use_PrivateKey_file(arg_a,arg_b,arg_c);
    }
}

int bb_SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            1, 8, 1, /* 6: pointer.struct.ssl3_buf_freelist_entry_st */
            	11, 0,
            0, 8, 1, /* 11: struct.ssl3_buf_freelist_entry_st */
            	6, 0,
            4097, 8, 0, /* 16: pointer.func */
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
            1, 8, 1, /* 50: pointer.struct.ssl3_buf_freelist_st */
            	55, 0,
            0, 24, 1, /* 55: struct.ssl3_buf_freelist_st */
            	6, 16,
            0, 40, 5, /* 60: struct.ec_extra_data_st */
            	73, 0,
            	78, 8,
            	81, 16,
            	84, 24,
            	84, 32,
            1, 8, 1, /* 73: pointer.struct.ec_extra_data_st */
            	60, 0,
            0, 8, 0, /* 78: pointer.void */
            4097, 8, 0, /* 81: pointer.func */
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
            0, 144, 12, /* 267: struct.dh_st */
            	294, 8,
            	294, 16,
            	294, 32,
            	294, 40,
            	299, 56,
            	294, 64,
            	294, 72,
            	45, 80,
            	294, 96,
            	313, 112,
            	343, 128,
            	379, 136,
            1, 8, 1, /* 294: pointer.struct.bignum_st */
            	243, 0,
            1, 8, 1, /* 299: pointer.struct.bn_mont_ctx_st */
            	304, 0,
            0, 96, 3, /* 304: struct.bn_mont_ctx_st */
            	243, 8,
            	243, 32,
            	243, 56,
            0, 16, 1, /* 313: struct.crypto_ex_data_st */
            	318, 0,
            1, 8, 1, /* 318: pointer.struct.stack_st_OPENSSL_STRING */
            	323, 0,
            0, 32, 1, /* 323: struct.stack_st_OPENSSL_STRING */
            	328, 0,
            0, 32, 2, /* 328: struct.stack_st */
            	335, 8,
            	340, 24,
            1, 8, 1, /* 335: pointer.pointer.char */
            	45, 0,
            4097, 8, 0, /* 340: pointer.func */
            1, 8, 1, /* 343: pointer.struct.dh_method */
            	348, 0,
            0, 72, 8, /* 348: struct.dh_method */
            	45, 0,
            	367, 8,
            	370, 16,
            	373, 24,
            	367, 32,
            	367, 40,
            	45, 56,
            	376, 64,
            4097, 8, 0, /* 367: pointer.func */
            4097, 8, 0, /* 370: pointer.func */
            4097, 8, 0, /* 373: pointer.func */
            4097, 8, 0, /* 376: pointer.func */
            1, 8, 1, /* 379: pointer.struct.engine_st */
            	384, 0,
            0, 216, 24, /* 384: struct.engine_st */
            	45, 0,
            	45, 8,
            	435, 16,
            	490, 24,
            	343, 32,
            	541, 40,
            	558, 48,
            	585, 56,
            	620, 64,
            	628, 72,
            	631, 80,
            	634, 88,
            	637, 96,
            	640, 104,
            	640, 112,
            	640, 120,
            	643, 128,
            	646, 136,
            	646, 144,
            	649, 152,
            	652, 160,
            	313, 184,
            	379, 200,
            	379, 208,
            1, 8, 1, /* 435: pointer.struct.rsa_meth_st */
            	440, 0,
            0, 112, 13, /* 440: struct.rsa_meth_st */
            	45, 0,
            	469, 8,
            	469, 16,
            	469, 24,
            	469, 32,
            	472, 40,
            	475, 48,
            	478, 56,
            	478, 64,
            	45, 80,
            	481, 88,
            	484, 96,
            	487, 104,
            4097, 8, 0, /* 469: pointer.func */
            4097, 8, 0, /* 472: pointer.func */
            4097, 8, 0, /* 475: pointer.func */
            4097, 8, 0, /* 478: pointer.func */
            4097, 8, 0, /* 481: pointer.func */
            4097, 8, 0, /* 484: pointer.func */
            4097, 8, 0, /* 487: pointer.func */
            1, 8, 1, /* 490: pointer.struct.dsa_method */
            	495, 0,
            0, 96, 11, /* 495: struct.dsa_method */
            	45, 0,
            	520, 8,
            	523, 16,
            	526, 24,
            	529, 32,
            	532, 40,
            	535, 48,
            	535, 56,
            	45, 72,
            	538, 80,
            	535, 88,
            4097, 8, 0, /* 520: pointer.func */
            4097, 8, 0, /* 523: pointer.func */
            4097, 8, 0, /* 526: pointer.func */
            4097, 8, 0, /* 529: pointer.func */
            4097, 8, 0, /* 532: pointer.func */
            4097, 8, 0, /* 535: pointer.func */
            4097, 8, 0, /* 538: pointer.func */
            1, 8, 1, /* 541: pointer.struct.ecdh_method */
            	546, 0,
            0, 32, 3, /* 546: struct.ecdh_method */
            	45, 0,
            	555, 8,
            	45, 24,
            4097, 8, 0, /* 555: pointer.func */
            1, 8, 1, /* 558: pointer.struct.ecdsa_method */
            	563, 0,
            0, 48, 5, /* 563: struct.ecdsa_method */
            	45, 0,
            	576, 8,
            	579, 16,
            	582, 24,
            	45, 40,
            4097, 8, 0, /* 576: pointer.func */
            4097, 8, 0, /* 579: pointer.func */
            4097, 8, 0, /* 582: pointer.func */
            1, 8, 1, /* 585: pointer.struct.rand_meth_st */
            	590, 0,
            0, 48, 6, /* 590: struct.rand_meth_st */
            	605, 0,
            	608, 8,
            	611, 16,
            	614, 24,
            	608, 32,
            	617, 40,
            4097, 8, 0, /* 605: pointer.func */
            4097, 8, 0, /* 608: pointer.func */
            4097, 8, 0, /* 611: pointer.func */
            4097, 8, 0, /* 614: pointer.func */
            4097, 8, 0, /* 617: pointer.func */
            1, 8, 1, /* 620: pointer.struct.store_method_st */
            	625, 0,
            0, 0, 0, /* 625: struct.store_method_st */
            4097, 8, 0, /* 628: pointer.func */
            4097, 8, 0, /* 631: pointer.func */
            4097, 8, 0, /* 634: pointer.func */
            4097, 8, 0, /* 637: pointer.func */
            4097, 8, 0, /* 640: pointer.func */
            4097, 8, 0, /* 643: pointer.func */
            4097, 8, 0, /* 646: pointer.func */
            4097, 8, 0, /* 649: pointer.func */
            1, 8, 1, /* 652: pointer.struct.ENGINE_CMD_DEFN_st */
            	657, 0,
            0, 32, 2, /* 657: struct.ENGINE_CMD_DEFN_st */
            	45, 8,
            	45, 16,
            1, 8, 1, /* 664: pointer.struct.dh_st */
            	267, 0,
            0, 56, 4, /* 669: struct.ec_key_st */
            	680, 8,
            	256, 16,
            	294, 24,
            	73, 48,
            1, 8, 1, /* 680: pointer.struct.ec_group_st */
            	685, 0,
            0, 232, 12, /* 685: struct.ec_group_st */
            	98, 0,
            	256, 8,
            	243, 16,
            	243, 40,
            	45, 80,
            	73, 96,
            	243, 104,
            	243, 152,
            	243, 176,
            	45, 208,
            	45, 216,
            	712, 224,
            4097, 8, 0, /* 712: pointer.func */
            0, 88, 7, /* 715: struct.bn_blinding_st */
            	294, 0,
            	294, 8,
            	294, 16,
            	294, 24,
            	732, 40,
            	299, 72,
            	475, 80,
            0, 16, 1, /* 732: struct.iovec */
            	45, 0,
            0, 128, 14, /* 737: struct.srp_ctx_st */
            	45, 0,
            	768, 8,
            	22, 16,
            	3, 24,
            	45, 32,
            	294, 40,
            	294, 48,
            	294, 56,
            	294, 64,
            	294, 72,
            	294, 80,
            	294, 88,
            	294, 96,
            	45, 104,
            4097, 8, 0, /* 768: pointer.func */
            0, 192, 8, /* 771: array[8].struct.cert_pkey_st */
            	790, 0,
            	790, 24,
            	790, 48,
            	790, 72,
            	790, 96,
            	790, 120,
            	790, 144,
            	790, 168,
            0, 24, 3, /* 790: struct.cert_pkey_st */
            	799, 0,
            	962, 8,
            	1156, 16,
            1, 8, 1, /* 799: pointer.struct.x509_st */
            	804, 0,
            0, 184, 12, /* 804: struct.x509_st */
            	831, 0,
            	871, 8,
            	861, 16,
            	45, 32,
            	313, 40,
            	861, 104,
            	1086, 112,
            	1100, 120,
            	318, 128,
            	318, 136,
            	1126, 144,
            	1138, 176,
            1, 8, 1, /* 831: pointer.struct.x509_cinf_st */
            	836, 0,
            0, 104, 11, /* 836: struct.x509_cinf_st */
            	861, 0,
            	861, 8,
            	871, 16,
            	912, 24,
            	936, 32,
            	912, 40,
            	948, 48,
            	861, 56,
            	861, 64,
            	318, 72,
            	1081, 80,
            1, 8, 1, /* 861: pointer.struct.asn1_string_st */
            	866, 0,
            0, 24, 1, /* 866: struct.asn1_string_st */
            	45, 8,
            1, 8, 1, /* 871: pointer.struct.X509_algor_st */
            	876, 0,
            0, 16, 2, /* 876: struct.X509_algor_st */
            	883, 0,
            	897, 8,
            1, 8, 1, /* 883: pointer.struct.asn1_object_st */
            	888, 0,
            0, 40, 3, /* 888: struct.asn1_object_st */
            	45, 0,
            	45, 8,
            	45, 24,
            1, 8, 1, /* 897: pointer.struct.asn1_type_st */
            	902, 0,
            0, 16, 1, /* 902: struct.asn1_type_st */
            	907, 8,
            0, 8, 1, /* 907: struct.fnames */
            	45, 0,
            1, 8, 1, /* 912: pointer.struct.X509_name_st */
            	917, 0,
            0, 40, 3, /* 917: struct.X509_name_st */
            	318, 0,
            	926, 16,
            	45, 24,
            1, 8, 1, /* 926: pointer.struct.buf_mem_st */
            	931, 0,
            0, 24, 1, /* 931: struct.buf_mem_st */
            	45, 8,
            1, 8, 1, /* 936: pointer.struct.X509_val_st */
            	941, 0,
            0, 16, 2, /* 941: struct.X509_val_st */
            	861, 0,
            	861, 8,
            1, 8, 1, /* 948: pointer.struct.X509_pubkey_st */
            	953, 0,
            0, 24, 3, /* 953: struct.X509_pubkey_st */
            	871, 0,
            	861, 8,
            	962, 16,
            1, 8, 1, /* 962: pointer.struct.evp_pkey_st */
            	967, 0,
            0, 56, 4, /* 967: struct.evp_pkey_st */
            	978, 16,
            	379, 24,
            	907, 32,
            	318, 48,
            1, 8, 1, /* 978: pointer.struct.evp_pkey_asn1_method_st */
            	983, 0,
            0, 208, 24, /* 983: struct.evp_pkey_asn1_method_st */
            	45, 16,
            	45, 24,
            	1034, 32,
            	1042, 40,
            	1045, 48,
            	1048, 56,
            	1051, 64,
            	1054, 72,
            	1048, 80,
            	1057, 88,
            	1057, 96,
            	1060, 104,
            	1063, 112,
            	1057, 120,
            	1045, 128,
            	1045, 136,
            	1048, 144,
            	1066, 152,
            	1069, 160,
            	1072, 168,
            	1060, 176,
            	1063, 184,
            	1075, 192,
            	1078, 200,
            1, 8, 1, /* 1034: pointer.struct.unnamed */
            	1039, 0,
            0, 0, 0, /* 1039: struct.unnamed */
            4097, 8, 0, /* 1042: pointer.func */
            4097, 8, 0, /* 1045: pointer.func */
            4097, 8, 0, /* 1048: pointer.func */
            4097, 8, 0, /* 1051: pointer.func */
            4097, 8, 0, /* 1054: pointer.func */
            4097, 8, 0, /* 1057: pointer.func */
            4097, 8, 0, /* 1060: pointer.func */
            4097, 8, 0, /* 1063: pointer.func */
            4097, 8, 0, /* 1066: pointer.func */
            4097, 8, 0, /* 1069: pointer.func */
            4097, 8, 0, /* 1072: pointer.func */
            4097, 8, 0, /* 1075: pointer.func */
            4097, 8, 0, /* 1078: pointer.func */
            0, 24, 1, /* 1081: struct.ASN1_ENCODING_st */
            	45, 0,
            1, 8, 1, /* 1086: pointer.struct.AUTHORITY_KEYID_st */
            	1091, 0,
            0, 24, 3, /* 1091: struct.AUTHORITY_KEYID_st */
            	861, 0,
            	318, 8,
            	861, 16,
            1, 8, 1, /* 1100: pointer.struct.X509_POLICY_CACHE_st */
            	1105, 0,
            0, 40, 2, /* 1105: struct.X509_POLICY_CACHE_st */
            	1112, 0,
            	318, 8,
            1, 8, 1, /* 1112: pointer.struct.X509_POLICY_DATA_st */
            	1117, 0,
            0, 32, 3, /* 1117: struct.X509_POLICY_DATA_st */
            	883, 8,
            	318, 16,
            	318, 24,
            1, 8, 1, /* 1126: pointer.struct.NAME_CONSTRAINTS_st */
            	1131, 0,
            0, 16, 2, /* 1131: struct.NAME_CONSTRAINTS_st */
            	318, 0,
            	318, 8,
            1, 8, 1, /* 1138: pointer.struct.x509_cert_aux_st */
            	1143, 0,
            0, 40, 5, /* 1143: struct.x509_cert_aux_st */
            	318, 0,
            	318, 8,
            	861, 16,
            	861, 24,
            	318, 32,
            1, 8, 1, /* 1156: pointer.struct.env_md_st */
            	1161, 0,
            0, 120, 8, /* 1161: struct.env_md_st */
            	1180, 24,
            	1183, 32,
            	1186, 40,
            	1189, 48,
            	1180, 56,
            	1192, 64,
            	1195, 72,
            	1198, 112,
            4097, 8, 0, /* 1180: pointer.func */
            4097, 8, 0, /* 1183: pointer.func */
            4097, 8, 0, /* 1186: pointer.func */
            4097, 8, 0, /* 1189: pointer.func */
            4097, 8, 0, /* 1192: pointer.func */
            4097, 8, 0, /* 1195: pointer.func */
            4097, 8, 0, /* 1198: pointer.func */
            1, 8, 1, /* 1201: pointer.struct.cert_st */
            	1206, 0,
            0, 296, 8, /* 1206: struct.cert_st */
            	1225, 0,
            	1230, 48,
            	1277, 56,
            	664, 64,
            	1280, 72,
            	1283, 80,
            	28, 88,
            	771, 96,
            1, 8, 1, /* 1225: pointer.struct.cert_pkey_st */
            	790, 0,
            1, 8, 1, /* 1230: pointer.struct.rsa_st */
            	1235, 0,
            0, 168, 17, /* 1235: struct.rsa_st */
            	435, 16,
            	379, 24,
            	294, 32,
            	294, 40,
            	294, 48,
            	294, 56,
            	294, 64,
            	294, 72,
            	294, 80,
            	294, 88,
            	313, 96,
            	299, 120,
            	299, 128,
            	299, 136,
            	45, 144,
            	1272, 152,
            	1272, 160,
            1, 8, 1, /* 1272: pointer.struct.bn_blinding_st */
            	715, 0,
            4097, 8, 0, /* 1277: pointer.func */
            4097, 8, 0, /* 1280: pointer.func */
            1, 8, 1, /* 1283: pointer.struct.ec_key_st */
            	669, 0,
            0, 352, 14, /* 1288: struct.ssl_session_st */
            	45, 144,
            	45, 152,
            	1319, 168,
            	799, 176,
            	1339, 224,
            	318, 240,
            	313, 248,
            	1344, 264,
            	1344, 272,
            	45, 280,
            	45, 296,
            	45, 312,
            	45, 320,
            	45, 344,
            1, 8, 1, /* 1319: pointer.struct.sess_cert_st */
            	1324, 0,
            0, 248, 6, /* 1324: struct.sess_cert_st */
            	318, 0,
            	1225, 16,
            	771, 24,
            	1230, 216,
            	664, 224,
            	1283, 232,
            1, 8, 1, /* 1339: pointer.struct.ssl_cipher_st */
            	40, 0,
            1, 8, 1, /* 1344: pointer.struct.ssl_session_st */
            	1288, 0,
            4097, 8, 0, /* 1349: pointer.func */
            0, 176, 3, /* 1352: struct.lhash_st */
            	1361, 0,
            	340, 8,
            	1378, 16,
            1, 8, 1, /* 1361: pointer.pointer.struct.lhash_node_st */
            	1366, 0,
            1, 8, 1, /* 1366: pointer.struct.lhash_node_st */
            	1371, 0,
            0, 24, 2, /* 1371: struct.lhash_node_st */
            	78, 0,
            	1366, 8,
            4097, 8, 0, /* 1378: pointer.func */
            4097, 8, 0, /* 1381: pointer.func */
            4097, 8, 0, /* 1384: pointer.func */
            0, 144, 15, /* 1387: struct.x509_store_st */
            	318, 8,
            	318, 16,
            	1420, 24,
            	1432, 32,
            	1435, 40,
            	1438, 48,
            	1441, 56,
            	1432, 64,
            	1349, 72,
            	1444, 80,
            	1447, 88,
            	1450, 96,
            	1450, 104,
            	1432, 112,
            	313, 120,
            1, 8, 1, /* 1420: pointer.struct.X509_VERIFY_PARAM_st */
            	1425, 0,
            0, 56, 2, /* 1425: struct.X509_VERIFY_PARAM_st */
            	45, 0,
            	318, 48,
            4097, 8, 0, /* 1432: pointer.func */
            4097, 8, 0, /* 1435: pointer.func */
            4097, 8, 0, /* 1438: pointer.func */
            4097, 8, 0, /* 1441: pointer.func */
            4097, 8, 0, /* 1444: pointer.func */
            4097, 8, 0, /* 1447: pointer.func */
            4097, 8, 0, /* 1450: pointer.func */
            4097, 8, 0, /* 1453: pointer.func */
            4097, 8, 0, /* 1456: pointer.func */
            1, 8, 1, /* 1459: pointer.struct.x509_store_st */
            	1387, 0,
            4097, 8, 0, /* 1464: pointer.func */
            4097, 8, 0, /* 1467: pointer.func */
            0, 232, 28, /* 1470: struct.ssl_method_st */
            	1529, 8,
            	1467, 16,
            	1467, 24,
            	1529, 32,
            	1529, 40,
            	1532, 48,
            	1532, 56,
            	1532, 64,
            	1529, 72,
            	1529, 80,
            	1529, 88,
            	1464, 96,
            	1456, 104,
            	1535, 112,
            	1529, 120,
            	1538, 128,
            	1541, 136,
            	1544, 144,
            	1453, 152,
            	1529, 160,
            	617, 168,
            	1547, 176,
            	1550, 184,
            	1384, 192,
            	1553, 200,
            	617, 208,
            	1598, 216,
            	1601, 224,
            4097, 8, 0, /* 1529: pointer.func */
            4097, 8, 0, /* 1532: pointer.func */
            4097, 8, 0, /* 1535: pointer.func */
            4097, 8, 0, /* 1538: pointer.func */
            4097, 8, 0, /* 1541: pointer.func */
            4097, 8, 0, /* 1544: pointer.func */
            4097, 8, 0, /* 1547: pointer.func */
            4097, 8, 0, /* 1550: pointer.func */
            1, 8, 1, /* 1553: pointer.struct.ssl3_enc_method */
            	1558, 0,
            0, 112, 11, /* 1558: struct.ssl3_enc_method */
            	1583, 0,
            	1532, 8,
            	1529, 16,
            	1586, 24,
            	1583, 32,
            	1589, 40,
            	1592, 56,
            	45, 64,
            	45, 80,
            	1595, 96,
            	1381, 104,
            4097, 8, 0, /* 1583: pointer.func */
            4097, 8, 0, /* 1586: pointer.func */
            4097, 8, 0, /* 1589: pointer.func */
            4097, 8, 0, /* 1592: pointer.func */
            4097, 8, 0, /* 1595: pointer.func */
            4097, 8, 0, /* 1598: pointer.func */
            4097, 8, 0, /* 1601: pointer.func */
            1, 8, 1, /* 1604: pointer.struct.ssl_method_st */
            	1470, 0,
            0, 736, 50, /* 1609: struct.ssl_ctx_st */
            	1604, 0,
            	318, 8,
            	318, 16,
            	1459, 24,
            	1712, 32,
            	1344, 48,
            	1344, 56,
            	37, 80,
            	1717, 88,
            	1720, 96,
            	1723, 152,
            	45, 160,
            	1726, 168,
            	45, 176,
            	34, 184,
            	31, 192,
            	1532, 200,
            	313, 208,
            	1156, 224,
            	1156, 232,
            	1156, 240,
            	318, 248,
            	318, 256,
            	264, 264,
            	318, 272,
            	1201, 304,
            	25, 320,
            	45, 328,
            	1435, 376,
            	31, 384,
            	1420, 392,
            	379, 408,
            	768, 416,
            	45, 424,
            	261, 480,
            	22, 488,
            	45, 496,
            	19, 504,
            	45, 512,
            	45, 520,
            	16, 528,
            	1586, 536,
            	50, 552,
            	50, 560,
            	737, 568,
            	1729, 696,
            	45, 704,
            	0, 712,
            	45, 720,
            	318, 728,
            1, 8, 1, /* 1712: pointer.struct.lhash_st */
            	1352, 0,
            4097, 8, 0, /* 1717: pointer.func */
            4097, 8, 0, /* 1720: pointer.func */
            4097, 8, 0, /* 1723: pointer.func */
            4097, 8, 0, /* 1726: pointer.func */
            4097, 8, 0, /* 1729: pointer.func */
            0, 1, 0, /* 1732: char */
            1, 8, 1, /* 1735: pointer.struct.ssl_ctx_st */
            	1609, 0,
        },
        .arg_entity_index = { 1735, 45, 253, },
        .ret_entity_index = 253,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *,const char *,int);
    orig_SSL_CTX_use_PrivateKey_file = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey_file");
    *new_ret_ptr = (*orig_SSL_CTX_use_PrivateKey_file)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

