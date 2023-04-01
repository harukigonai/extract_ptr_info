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
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            0, 8, 1, /* 6: struct.ssl3_buf_freelist_entry_st */
            	11, 0,
            1, 8, 1, /* 11: pointer.struct.ssl3_buf_freelist_entry_st */
            	6, 0,
            0, 0, 0, /* 16: func */
            4097, 8, 0, /* 19: pointer.func */
            0, 16, 0, /* 22: array[16].char */
            0, 0, 0, /* 25: func */
            4097, 8, 0, /* 28: pointer.func */
            4097, 8, 0, /* 31: pointer.func */
            0, 0, 0, /* 34: func */
            1, 8, 1, /* 37: pointer.struct.cert_st.2861 */
            	42, 0,
            0, 296, 5, /* 42: struct.cert_st.2861 */
            	55, 0,
            	505, 48,
            	604, 64,
            	636, 80,
            	718, 96,
            1, 8, 1, /* 55: pointer.struct.cert_pkey_st */
            	60, 0,
            0, 24, 3, /* 60: struct.cert_pkey_st */
            	69, 0,
            	257, 8,
            	497, 16,
            1, 8, 1, /* 69: pointer.struct.x509_st */
            	74, 0,
            0, 184, 12, /* 74: struct.x509_st */
            	101, 0,
            	146, 8,
            	131, 16,
            	141, 32,
            	417, 40,
            	131, 104,
            	427, 112,
            	441, 120,
            	201, 128,
            	201, 136,
            	467, 144,
            	479, 176,
            1, 8, 1, /* 101: pointer.struct.x509_cinf_st */
            	106, 0,
            0, 104, 11, /* 106: struct.x509_cinf_st */
            	131, 0,
            	131, 8,
            	146, 16,
            	187, 24,
            	231, 32,
            	187, 40,
            	243, 48,
            	131, 56,
            	131, 64,
            	201, 72,
            	422, 80,
            1, 8, 1, /* 131: pointer.struct.asn1_string_st */
            	136, 0,
            0, 24, 1, /* 136: struct.asn1_string_st */
            	141, 8,
            1, 8, 1, /* 141: pointer.char */
            	4096, 0,
            1, 8, 1, /* 146: pointer.struct.X509_algor_st */
            	151, 0,
            0, 16, 2, /* 151: struct.X509_algor_st */
            	158, 0,
            	172, 8,
            1, 8, 1, /* 158: pointer.struct.asn1_object_st */
            	163, 0,
            0, 40, 3, /* 163: struct.asn1_object_st */
            	141, 0,
            	141, 8,
            	141, 24,
            1, 8, 1, /* 172: pointer.struct.asn1_type_st */
            	177, 0,
            0, 16, 1, /* 177: struct.asn1_type_st */
            	182, 8,
            0, 8, 1, /* 182: struct.fnames */
            	141, 0,
            1, 8, 1, /* 187: pointer.struct.X509_name_st */
            	192, 0,
            0, 40, 3, /* 192: struct.X509_name_st */
            	201, 0,
            	221, 16,
            	141, 24,
            1, 8, 1, /* 201: pointer.struct.stack_st_OPENSSL_STRING */
            	206, 0,
            0, 32, 1, /* 206: struct.stack_st_OPENSSL_STRING */
            	211, 0,
            0, 32, 1, /* 211: struct.stack_st */
            	216, 8,
            1, 8, 1, /* 216: pointer.pointer.char */
            	141, 0,
            1, 8, 1, /* 221: pointer.struct.buf_mem_st */
            	226, 0,
            0, 24, 1, /* 226: struct.buf_mem_st */
            	141, 8,
            1, 8, 1, /* 231: pointer.struct.X509_val_st */
            	236, 0,
            0, 16, 2, /* 236: struct.X509_val_st */
            	131, 0,
            	131, 8,
            1, 8, 1, /* 243: pointer.struct.X509_pubkey_st */
            	248, 0,
            0, 24, 3, /* 248: struct.X509_pubkey_st */
            	146, 0,
            	131, 8,
            	257, 16,
            1, 8, 1, /* 257: pointer.struct.evp_pkey_st */
            	262, 0,
            0, 56, 4, /* 262: struct.evp_pkey_st */
            	273, 16,
            	295, 24,
            	182, 32,
            	201, 48,
            1, 8, 1, /* 273: pointer.struct.evp_pkey_asn1_method_st */
            	278, 0,
            0, 208, 3, /* 278: struct.evp_pkey_asn1_method_st */
            	141, 16,
            	141, 24,
            	287, 32,
            1, 8, 1, /* 287: pointer.struct.unnamed */
            	292, 0,
            0, 0, 0, /* 292: struct.unnamed */
            1, 8, 1, /* 295: pointer.struct.engine_st */
            	300, 0,
            0, 216, 13, /* 300: struct.engine_st */
            	141, 0,
            	141, 8,
            	329, 16,
            	341, 24,
            	353, 32,
            	365, 40,
            	377, 48,
            	389, 56,
            	397, 64,
            	405, 160,
            	417, 184,
            	295, 200,
            	295, 208,
            1, 8, 1, /* 329: pointer.struct.rsa_meth_st */
            	334, 0,
            0, 112, 2, /* 334: struct.rsa_meth_st */
            	141, 0,
            	141, 80,
            1, 8, 1, /* 341: pointer.struct.dsa_method.1040 */
            	346, 0,
            0, 96, 2, /* 346: struct.dsa_method.1040 */
            	141, 0,
            	141, 72,
            1, 8, 1, /* 353: pointer.struct.dh_method */
            	358, 0,
            0, 72, 2, /* 358: struct.dh_method */
            	141, 0,
            	141, 56,
            1, 8, 1, /* 365: pointer.struct.ecdh_method */
            	370, 0,
            0, 32, 2, /* 370: struct.ecdh_method */
            	141, 0,
            	141, 24,
            1, 8, 1, /* 377: pointer.struct.ecdsa_method */
            	382, 0,
            0, 48, 2, /* 382: struct.ecdsa_method */
            	141, 0,
            	141, 40,
            1, 8, 1, /* 389: pointer.struct.rand_meth_st */
            	394, 0,
            0, 48, 0, /* 394: struct.rand_meth_st */
            1, 8, 1, /* 397: pointer.struct.store_method_st */
            	402, 0,
            0, 0, 0, /* 402: struct.store_method_st */
            1, 8, 1, /* 405: pointer.struct.ENGINE_CMD_DEFN_st */
            	410, 0,
            0, 32, 2, /* 410: struct.ENGINE_CMD_DEFN_st */
            	141, 8,
            	141, 16,
            0, 16, 1, /* 417: struct.crypto_ex_data_st */
            	201, 0,
            0, 24, 1, /* 422: struct.ASN1_ENCODING_st */
            	141, 0,
            1, 8, 1, /* 427: pointer.struct.AUTHORITY_KEYID_st */
            	432, 0,
            0, 24, 3, /* 432: struct.AUTHORITY_KEYID_st */
            	131, 0,
            	201, 8,
            	131, 16,
            1, 8, 1, /* 441: pointer.struct.X509_POLICY_CACHE_st */
            	446, 0,
            0, 40, 2, /* 446: struct.X509_POLICY_CACHE_st */
            	453, 0,
            	201, 8,
            1, 8, 1, /* 453: pointer.struct.X509_POLICY_DATA_st */
            	458, 0,
            0, 32, 3, /* 458: struct.X509_POLICY_DATA_st */
            	158, 8,
            	201, 16,
            	201, 24,
            1, 8, 1, /* 467: pointer.struct.NAME_CONSTRAINTS_st */
            	472, 0,
            0, 16, 2, /* 472: struct.NAME_CONSTRAINTS_st */
            	201, 0,
            	201, 8,
            1, 8, 1, /* 479: pointer.struct.x509_cert_aux_st */
            	484, 0,
            0, 40, 5, /* 484: struct.x509_cert_aux_st */
            	201, 0,
            	201, 8,
            	131, 16,
            	131, 24,
            	201, 32,
            1, 8, 1, /* 497: pointer.struct.env_md_st */
            	502, 0,
            0, 120, 0, /* 502: struct.env_md_st */
            1, 8, 1, /* 505: pointer.struct.rsa_st */
            	510, 0,
            0, 168, 17, /* 510: struct.rsa_st */
            	329, 16,
            	295, 24,
            	547, 32,
            	547, 40,
            	547, 48,
            	547, 56,
            	547, 64,
            	547, 72,
            	547, 80,
            	547, 88,
            	417, 96,
            	565, 120,
            	565, 128,
            	565, 136,
            	141, 144,
            	579, 152,
            	579, 160,
            1, 8, 1, /* 547: pointer.struct.bignum_st */
            	552, 0,
            0, 24, 1, /* 552: struct.bignum_st */
            	557, 0,
            1, 8, 1, /* 557: pointer.int */
            	562, 0,
            0, 4, 0, /* 562: int */
            1, 8, 1, /* 565: pointer.struct.bn_mont_ctx_st */
            	570, 0,
            0, 96, 3, /* 570: struct.bn_mont_ctx_st */
            	552, 8,
            	552, 32,
            	552, 56,
            1, 8, 1, /* 579: pointer.struct.bn_blinding_st */
            	584, 0,
            0, 88, 6, /* 584: struct.bn_blinding_st */
            	547, 0,
            	547, 8,
            	547, 16,
            	547, 24,
            	599, 40,
            	565, 72,
            0, 16, 1, /* 599: struct.iovec */
            	141, 0,
            1, 8, 1, /* 604: pointer.struct.dh_st */
            	609, 0,
            0, 144, 12, /* 609: struct.dh_st */
            	547, 8,
            	547, 16,
            	547, 32,
            	547, 40,
            	565, 56,
            	547, 64,
            	547, 72,
            	141, 80,
            	547, 96,
            	417, 112,
            	353, 128,
            	295, 136,
            1, 8, 1, /* 636: pointer.struct.ec_key_st.284 */
            	641, 0,
            0, 56, 4, /* 641: struct.ec_key_st.284 */
            	652, 8,
            	690, 16,
            	547, 24,
            	706, 48,
            1, 8, 1, /* 652: pointer.struct.ec_group_st */
            	657, 0,
            0, 232, 11, /* 657: struct.ec_group_st */
            	682, 0,
            	690, 8,
            	552, 16,
            	552, 40,
            	141, 80,
            	706, 96,
            	552, 104,
            	552, 152,
            	552, 176,
            	141, 208,
            	141, 216,
            1, 8, 1, /* 682: pointer.struct.ec_method_st */
            	687, 0,
            0, 304, 0, /* 687: struct.ec_method_st */
            1, 8, 1, /* 690: pointer.struct.ec_point_st */
            	695, 0,
            0, 88, 4, /* 695: struct.ec_point_st */
            	682, 0,
            	552, 8,
            	552, 32,
            	552, 56,
            1, 8, 1, /* 706: pointer.struct.ec_extra_data_st */
            	711, 0,
            0, 40, 2, /* 711: struct.ec_extra_data_st */
            	706, 0,
            	141, 8,
            0, 192, 8, /* 718: array[8].struct.cert_pkey_st */
            	60, 0,
            	60, 24,
            	60, 48,
            	60, 72,
            	60, 96,
            	60, 120,
            	60, 144,
            	60, 168,
            0, 0, 0, /* 737: func */
            4097, 8, 0, /* 740: pointer.func */
            4097, 8, 0, /* 743: pointer.func */
            0, 0, 0, /* 746: func */
            4097, 8, 0, /* 749: pointer.func */
            0, 0, 0, /* 752: func */
            4097, 8, 0, /* 755: pointer.func */
            0, 44, 0, /* 758: struct.apr_time_exp_t */
            0, 0, 0, /* 761: func */
            4097, 8, 0, /* 764: pointer.func */
            0, 0, 0, /* 767: func */
            0, 88, 1, /* 770: struct.ssl_cipher_st */
            	141, 8,
            1, 8, 1, /* 775: pointer.struct.ssl_cipher_st */
            	770, 0,
            0, 0, 0, /* 780: func */
            4097, 8, 0, /* 783: pointer.func */
            0, 0, 0, /* 786: func */
            4097, 8, 0, /* 789: pointer.func */
            0, 0, 0, /* 792: func */
            4097, 8, 0, /* 795: pointer.func */
            0, 0, 0, /* 798: func */
            4097, 8, 0, /* 801: pointer.func */
            0, 0, 0, /* 804: func */
            4097, 8, 0, /* 807: pointer.func */
            0, 0, 0, /* 810: func */
            4097, 8, 0, /* 813: pointer.func */
            0, 0, 0, /* 816: func */
            4097, 8, 0, /* 819: pointer.func */
            0, 0, 0, /* 822: func */
            0, 0, 0, /* 825: func */
            4097, 8, 0, /* 828: pointer.func */
            0, 0, 0, /* 831: func */
            4097, 8, 0, /* 834: pointer.func */
            0, 0, 0, /* 837: func */
            4097, 8, 0, /* 840: pointer.func */
            0, 0, 0, /* 843: func */
            0, 0, 0, /* 846: func */
            4097, 8, 0, /* 849: pointer.func */
            0, 0, 0, /* 852: func */
            0, 0, 0, /* 855: func */
            4097, 8, 0, /* 858: pointer.func */
            0, 0, 0, /* 861: func */
            0, 0, 0, /* 864: func */
            0, 0, 0, /* 867: func */
            0, 0, 0, /* 870: func */
            0, 24, 1, /* 873: struct.ssl3_buf_freelist_st */
            	11, 16,
            4097, 8, 0, /* 878: pointer.func */
            0, 8, 0, /* 881: array[2].int */
            4097, 8, 0, /* 884: pointer.func */
            0, 0, 0, /* 887: func */
            0, 0, 0, /* 890: func */
            4097, 8, 0, /* 893: pointer.func */
            0, 20, 0, /* 896: array[5].int */
            0, 0, 0, /* 899: func */
            0, 0, 0, /* 902: func */
            0, 0, 0, /* 905: func */
            0, 0, 0, /* 908: func */
            4097, 8, 0, /* 911: pointer.func */
            0, 32, 0, /* 914: array[32].char */
            4097, 8, 0, /* 917: pointer.func */
            4097, 8, 0, /* 920: pointer.func */
            4097, 8, 0, /* 923: pointer.func */
            0, 0, 0, /* 926: func */
            4097, 8, 0, /* 929: pointer.func */
            0, 0, 0, /* 932: func */
            4097, 8, 0, /* 935: pointer.func */
            0, 0, 0, /* 938: func */
            4097, 8, 0, /* 941: pointer.func */
            4097, 8, 0, /* 944: pointer.func */
            4097, 8, 0, /* 947: pointer.func */
            0, 0, 0, /* 950: func */
            4097, 8, 0, /* 953: pointer.func */
            0, 24, 0, /* 956: array[6].int */
            4097, 8, 0, /* 959: pointer.func */
            0, 248, 6, /* 962: struct.sess_cert_st */
            	201, 0,
            	55, 16,
            	718, 24,
            	505, 216,
            	604, 224,
            	636, 232,
            0, 232, 1, /* 977: struct.ssl_method_st.2838 */
            	982, 200,
            1, 8, 1, /* 982: pointer.struct.ssl3_enc_method.2837 */
            	987, 0,
            0, 112, 2, /* 987: struct.ssl3_enc_method.2837 */
            	141, 64,
            	141, 80,
            4097, 8, 0, /* 994: pointer.func */
            0, 0, 0, /* 997: func */
            0, 48, 0, /* 1000: array[48].char */
            0, 0, 0, /* 1003: func */
            0, 0, 0, /* 1006: func */
            4097, 8, 0, /* 1009: pointer.func */
            0, 0, 0, /* 1012: func */
            0, 1, 0, /* 1015: char */
            0, 4, 0, /* 1018: struct.in_addr */
            0, 0, 0, /* 1021: func */
            0, 0, 0, /* 1024: func */
            0, 0, 0, /* 1027: func */
            0, 0, 0, /* 1030: func */
            4097, 8, 0, /* 1033: pointer.func */
            4097, 8, 0, /* 1036: pointer.func */
            4097, 8, 0, /* 1039: pointer.func */
            0, 0, 0, /* 1042: func */
            0, 352, 14, /* 1045: struct.ssl_session_st */
            	141, 144,
            	141, 152,
            	1076, 168,
            	69, 176,
            	775, 224,
            	201, 240,
            	417, 248,
            	1081, 264,
            	1081, 272,
            	141, 280,
            	141, 296,
            	141, 312,
            	141, 320,
            	141, 344,
            1, 8, 1, /* 1076: pointer.struct.sess_cert_st */
            	962, 0,
            1, 8, 1, /* 1081: pointer.struct.ssl_session_st */
            	1045, 0,
            0, 0, 0, /* 1086: func */
            4097, 8, 0, /* 1089: pointer.func */
            0, 0, 0, /* 1092: func */
            4097, 8, 0, /* 1095: pointer.func */
            0, 144, 4, /* 1098: struct.x509_store_st */
            	201, 8,
            	201, 16,
            	1109, 24,
            	417, 120,
            1, 8, 1, /* 1109: pointer.struct.X509_VERIFY_PARAM_st */
            	1114, 0,
            0, 56, 2, /* 1114: struct.X509_VERIFY_PARAM_st */
            	141, 0,
            	201, 48,
            1, 8, 1, /* 1121: pointer.struct.x509_store_st */
            	1098, 0,
            4097, 8, 0, /* 1126: pointer.func */
            0, 0, 0, /* 1129: func */
            0, 0, 0, /* 1132: func */
            4097, 8, 0, /* 1135: pointer.func */
            4097, 8, 0, /* 1138: pointer.func */
            4097, 8, 0, /* 1141: pointer.func */
            0, 0, 0, /* 1144: func */
            4097, 8, 0, /* 1147: pointer.func */
            0, 0, 0, /* 1150: func */
            0, 0, 0, /* 1153: func */
            0, 0, 0, /* 1156: func */
            1, 8, 1, /* 1159: pointer.struct.in_addr */
            	1018, 0,
            0, 0, 0, /* 1164: func */
            4097, 8, 0, /* 1167: pointer.func */
            4097, 8, 0, /* 1170: pointer.func */
            0, 0, 0, /* 1173: func */
            0, 0, 0, /* 1176: func */
            4097, 8, 0, /* 1179: pointer.func */
            0, 0, 0, /* 1182: func */
            4097, 8, 0, /* 1185: pointer.func */
            0, 0, 0, /* 1188: func */
            4097, 8, 0, /* 1191: pointer.func */
            0, 0, 0, /* 1194: func */
            4097, 8, 0, /* 1197: pointer.func */
            0, 8, 0, /* 1200: long */
            0, 0, 0, /* 1203: func */
            0, 0, 0, /* 1206: func */
            4097, 8, 0, /* 1209: pointer.func */
            0, 0, 0, /* 1212: func */
            4097, 8, 0, /* 1215: pointer.func */
            4097, 8, 0, /* 1218: pointer.func */
            0, 0, 0, /* 1221: func */
            4097, 8, 0, /* 1224: pointer.func */
            4097, 8, 0, /* 1227: pointer.func */
            1, 8, 1, /* 1230: pointer.struct.ssl_ctx_st.2836 */
            	1235, 0,
            0, 736, 30, /* 1235: struct.ssl_ctx_st.2836 */
            	1298, 0,
            	201, 8,
            	201, 16,
            	1121, 24,
            	1159, 32,
            	1081, 48,
            	1081, 56,
            	141, 160,
            	141, 176,
            	417, 208,
            	497, 224,
            	497, 232,
            	497, 240,
            	201, 248,
            	201, 256,
            	201, 272,
            	37, 304,
            	141, 328,
            	1109, 392,
            	295, 408,
            	141, 424,
            	141, 496,
            	141, 512,
            	141, 520,
            	1303, 552,
            	1303, 560,
            	1308, 568,
            	141, 704,
            	141, 720,
            	201, 728,
            1, 8, 1, /* 1298: pointer.struct.ssl_method_st.2838 */
            	977, 0,
            1, 8, 1, /* 1303: pointer.struct.ssl3_buf_freelist_st */
            	873, 0,
            0, 128, 11, /* 1308: struct.srp_ctx_st.2835 */
            	141, 0,
            	141, 32,
            	547, 40,
            	547, 48,
            	547, 56,
            	547, 64,
            	547, 72,
            	547, 80,
            	547, 88,
            	547, 96,
            	141, 104,
            0, 0, 0, /* 1333: func */
            4097, 8, 0, /* 1336: pointer.func */
            4097, 8, 0, /* 1339: pointer.func */
            0, 0, 0, /* 1342: func */
            0, 0, 0, /* 1345: func */
            0, 0, 0, /* 1348: func */
            0, 0, 0, /* 1351: func */
            4097, 8, 0, /* 1354: pointer.func */
            4097, 8, 0, /* 1357: pointer.func */
            0, 0, 0, /* 1360: func */
            4097, 8, 0, /* 1363: pointer.func */
            0, 8, 0, /* 1366: array[8].char */
            0, 0, 0, /* 1369: func */
            4097, 8, 0, /* 1372: pointer.func */
            0, 0, 0, /* 1375: func */
            0, 0, 0, /* 1378: func */
            4097, 8, 0, /* 1381: pointer.func */
            4097, 8, 0, /* 1384: pointer.func */
            4097, 8, 0, /* 1387: pointer.func */
            0, 0, 0, /* 1390: func */
            4097, 8, 0, /* 1393: pointer.func */
            4097, 8, 0, /* 1396: pointer.func */
            4097, 8, 0, /* 1399: pointer.func */
            4097, 8, 0, /* 1402: pointer.func */
            4097, 8, 0, /* 1405: pointer.func */
            4097, 8, 0, /* 1408: pointer.func */
            0, 0, 0, /* 1411: func */
            0, 0, 0, /* 1414: func */
            0, 0, 0, /* 1417: func */
            0, 0, 0, /* 1420: func */
            0, 0, 0, /* 1423: func */
            0, 0, 0, /* 1426: func */
            0, 0, 0, /* 1429: func */
            0, 0, 0, /* 1432: func */
            4097, 8, 0, /* 1435: pointer.func */
            4097, 8, 0, /* 1438: pointer.func */
            4097, 8, 0, /* 1441: pointer.func */
            0, 0, 0, /* 1444: func */
            4097, 8, 0, /* 1447: pointer.func */
            4097, 8, 0, /* 1450: pointer.func */
            4097, 8, 0, /* 1453: pointer.func */
            0, 0, 0, /* 1456: func */
            4097, 8, 0, /* 1459: pointer.func */
            4097, 8, 0, /* 1462: pointer.func */
            4097, 8, 0, /* 1465: pointer.func */
            4097, 8, 0, /* 1468: pointer.func */
            0, 0, 0, /* 1471: func */
            4097, 8, 0, /* 1474: pointer.func */
            4097, 8, 0, /* 1477: pointer.func */
            4097, 8, 0, /* 1480: pointer.func */
            4097, 8, 0, /* 1483: pointer.func */
            0, 0, 0, /* 1486: func */
            4097, 8, 0, /* 1489: pointer.func */
            0, 0, 0, /* 1492: func */
            0, 0, 0, /* 1495: func */
            0, 0, 0, /* 1498: func */
            4097, 8, 0, /* 1501: pointer.func */
            4097, 8, 0, /* 1504: pointer.func */
            0, 20, 0, /* 1507: array[20].char */
            4097, 8, 0, /* 1510: pointer.func */
            4097, 8, 0, /* 1513: pointer.func */
            0, 0, 0, /* 1516: func */
            4097, 8, 0, /* 1519: pointer.func */
            4097, 8, 0, /* 1522: pointer.func */
            4097, 8, 0, /* 1525: pointer.func */
            4097, 8, 0, /* 1528: pointer.func */
            0, 0, 0, /* 1531: func */
            4097, 8, 0, /* 1534: pointer.func */
            0, 0, 0, /* 1537: func */
            4097, 8, 0, /* 1540: pointer.func */
            0, 0, 0, /* 1543: func */
            0, 0, 0, /* 1546: func */
            4097, 8, 0, /* 1549: pointer.func */
            4097, 8, 0, /* 1552: pointer.func */
            0, 0, 0, /* 1555: func */
            4097, 8, 0, /* 1558: pointer.func */
            4097, 8, 0, /* 1561: pointer.func */
            0, 0, 0, /* 1564: func */
            0, 0, 0, /* 1567: func */
            0, 0, 0, /* 1570: func */
            4097, 8, 0, /* 1573: pointer.func */
            4097, 8, 0, /* 1576: pointer.func */
            0, 0, 0, /* 1579: func */
            4097, 8, 0, /* 1582: pointer.func */
            0, 0, 0, /* 1585: func */
            4097, 8, 0, /* 1588: pointer.func */
            4097, 8, 0, /* 1591: pointer.func */
            0, 0, 0, /* 1594: func */
            0, 0, 0, /* 1597: func */
            4097, 8, 0, /* 1600: pointer.func */
            4097, 8, 0, /* 1603: pointer.func */
            0, 0, 0, /* 1606: func */
            0, 0, 0, /* 1609: func */
            4097, 8, 0, /* 1612: pointer.func */
            4097, 8, 0, /* 1615: pointer.func */
            4097, 8, 0, /* 1618: pointer.func */
            0, 0, 0, /* 1621: func */
            4097, 8, 0, /* 1624: pointer.func */
            0, 0, 0, /* 1627: func */
            0, 0, 0, /* 1630: func */
            0, 0, 0, /* 1633: func */
            4097, 8, 0, /* 1636: pointer.func */
            4097, 8, 0, /* 1639: pointer.func */
            0, 0, 0, /* 1642: func */
            4097, 8, 0, /* 1645: pointer.func */
            0, 0, 0, /* 1648: func */
            4097, 8, 0, /* 1651: pointer.func */
            0, 0, 0, /* 1654: func */
            4097, 8, 0, /* 1657: pointer.func */
            0, 0, 0, /* 1660: func */
            0, 0, 0, /* 1663: func */
            4097, 8, 0, /* 1666: pointer.func */
            0, 0, 0, /* 1669: func */
            4097, 8, 0, /* 1672: pointer.func */
            0, 0, 0, /* 1675: func */
            4097, 8, 0, /* 1678: pointer.func */
            4097, 8, 0, /* 1681: pointer.func */
            4097, 8, 0, /* 1684: pointer.func */
            0, 0, 0, /* 1687: func */
            0, 0, 0, /* 1690: func */
            0, 0, 0, /* 1693: func */
            0, 0, 0, /* 1696: func */
            4097, 8, 0, /* 1699: pointer.func */
            4097, 8, 0, /* 1702: pointer.func */
            0, 0, 0, /* 1705: func */
            4097, 8, 0, /* 1708: pointer.func */
            0, 0, 0, /* 1711: func */
            0, 0, 0, /* 1714: func */
            4097, 8, 0, /* 1717: pointer.func */
            0, 0, 0, /* 1720: func */
            0, 0, 0, /* 1723: func */
            4097, 8, 0, /* 1726: pointer.func */
            4097, 8, 0, /* 1729: pointer.func */
            0, 0, 0, /* 1732: func */
            4097, 8, 0, /* 1735: pointer.func */
            0, 0, 0, /* 1738: func */
            0, 0, 0, /* 1741: func */
        },
        .arg_entity_index = { 1230, 141, 562, },
        .ret_entity_index = 562,
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

