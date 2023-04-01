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

X509_STORE * bb_SSL_CTX_get_cert_store(const SSL_CTX * arg_a);

X509_STORE * SSL_CTX_get_cert_store(const SSL_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_get_cert_store called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_get_cert_store(arg_a);
    else {
        X509_STORE * (*orig_SSL_CTX_get_cert_store)(const SSL_CTX *);
        orig_SSL_CTX_get_cert_store = dlsym(RTLD_NEXT, "SSL_CTX_get_cert_store");
        return orig_SSL_CTX_get_cert_store(arg_a);
    }
}

X509_STORE * bb_SSL_CTX_get_cert_store(const SSL_CTX * arg_a) 
{
    X509_STORE * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 1, /* 0: struct.ssl3_buf_freelist_entry_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.struct.ssl3_buf_freelist_entry_st */
            	0, 0,
            1, 8, 1, /* 10: pointer.struct.ssl3_buf_freelist_st */
            	15, 0,
            0, 24, 1, /* 15: struct.ssl3_buf_freelist_st */
            	5, 16,
            0, 0, 0, /* 20: func */
            4097, 8, 0, /* 23: pointer.func */
            4097, 8, 0, /* 26: pointer.func */
            0, 16, 0, /* 29: array[16].char */
            0, 0, 0, /* 32: func */
            0, 0, 0, /* 35: func */
            4097, 8, 0, /* 38: pointer.func */
            0, 0, 0, /* 41: func */
            0, 0, 0, /* 44: func */
            4097, 8, 0, /* 47: pointer.func */
            0, 296, 5, /* 50: struct.cert_st.745 */
            	63, 0,
            	513, 48,
            	612, 64,
            	644, 80,
            	726, 96,
            1, 8, 1, /* 63: pointer.struct.cert_pkey_st */
            	68, 0,
            0, 24, 3, /* 68: struct.cert_pkey_st */
            	77, 0,
            	265, 8,
            	505, 16,
            1, 8, 1, /* 77: pointer.struct.x509_st */
            	82, 0,
            0, 184, 12, /* 82: struct.x509_st */
            	109, 0,
            	154, 8,
            	139, 16,
            	149, 32,
            	425, 40,
            	139, 104,
            	435, 112,
            	449, 120,
            	209, 128,
            	209, 136,
            	475, 144,
            	487, 176,
            1, 8, 1, /* 109: pointer.struct.x509_cinf_st */
            	114, 0,
            0, 104, 11, /* 114: struct.x509_cinf_st */
            	139, 0,
            	139, 8,
            	154, 16,
            	195, 24,
            	239, 32,
            	195, 40,
            	251, 48,
            	139, 56,
            	139, 64,
            	209, 72,
            	430, 80,
            1, 8, 1, /* 139: pointer.struct.asn1_string_st */
            	144, 0,
            0, 24, 1, /* 144: struct.asn1_string_st */
            	149, 8,
            1, 8, 1, /* 149: pointer.char */
            	4096, 0,
            1, 8, 1, /* 154: pointer.struct.X509_algor_st */
            	159, 0,
            0, 16, 2, /* 159: struct.X509_algor_st */
            	166, 0,
            	180, 8,
            1, 8, 1, /* 166: pointer.struct.asn1_object_st */
            	171, 0,
            0, 40, 3, /* 171: struct.asn1_object_st */
            	149, 0,
            	149, 8,
            	149, 24,
            1, 8, 1, /* 180: pointer.struct.asn1_type_st */
            	185, 0,
            0, 16, 1, /* 185: struct.asn1_type_st */
            	190, 8,
            0, 8, 1, /* 190: struct.fnames */
            	149, 0,
            1, 8, 1, /* 195: pointer.struct.X509_name_st */
            	200, 0,
            0, 40, 3, /* 200: struct.X509_name_st */
            	209, 0,
            	229, 16,
            	149, 24,
            1, 8, 1, /* 209: pointer.struct.stack_st_OPENSSL_STRING */
            	214, 0,
            0, 32, 1, /* 214: struct.stack_st_OPENSSL_STRING */
            	219, 0,
            0, 32, 1, /* 219: struct.stack_st */
            	224, 8,
            1, 8, 1, /* 224: pointer.pointer.char */
            	149, 0,
            1, 8, 1, /* 229: pointer.struct.buf_mem_st */
            	234, 0,
            0, 24, 1, /* 234: struct.buf_mem_st */
            	149, 8,
            1, 8, 1, /* 239: pointer.struct.X509_val_st */
            	244, 0,
            0, 16, 2, /* 244: struct.X509_val_st */
            	139, 0,
            	139, 8,
            1, 8, 1, /* 251: pointer.struct.X509_pubkey_st */
            	256, 0,
            0, 24, 3, /* 256: struct.X509_pubkey_st */
            	154, 0,
            	139, 8,
            	265, 16,
            1, 8, 1, /* 265: pointer.struct.evp_pkey_st */
            	270, 0,
            0, 56, 4, /* 270: struct.evp_pkey_st */
            	281, 16,
            	303, 24,
            	190, 32,
            	209, 48,
            1, 8, 1, /* 281: pointer.struct.evp_pkey_asn1_method_st */
            	286, 0,
            0, 208, 3, /* 286: struct.evp_pkey_asn1_method_st */
            	149, 16,
            	149, 24,
            	295, 32,
            1, 8, 1, /* 295: pointer.struct.unnamed */
            	300, 0,
            0, 0, 0, /* 300: struct.unnamed */
            1, 8, 1, /* 303: pointer.struct.engine_st */
            	308, 0,
            0, 216, 13, /* 308: struct.engine_st */
            	149, 0,
            	149, 8,
            	337, 16,
            	349, 24,
            	361, 32,
            	373, 40,
            	385, 48,
            	397, 56,
            	405, 64,
            	413, 160,
            	425, 184,
            	303, 200,
            	303, 208,
            1, 8, 1, /* 337: pointer.struct.rsa_meth_st */
            	342, 0,
            0, 112, 2, /* 342: struct.rsa_meth_st */
            	149, 0,
            	149, 80,
            1, 8, 1, /* 349: pointer.struct.dsa_method.1040 */
            	354, 0,
            0, 96, 2, /* 354: struct.dsa_method.1040 */
            	149, 0,
            	149, 72,
            1, 8, 1, /* 361: pointer.struct.dh_method */
            	366, 0,
            0, 72, 2, /* 366: struct.dh_method */
            	149, 0,
            	149, 56,
            1, 8, 1, /* 373: pointer.struct.ecdh_method */
            	378, 0,
            0, 32, 2, /* 378: struct.ecdh_method */
            	149, 0,
            	149, 24,
            1, 8, 1, /* 385: pointer.struct.ecdsa_method */
            	390, 0,
            0, 48, 2, /* 390: struct.ecdsa_method */
            	149, 0,
            	149, 40,
            1, 8, 1, /* 397: pointer.struct.rand_meth_st */
            	402, 0,
            0, 48, 0, /* 402: struct.rand_meth_st */
            1, 8, 1, /* 405: pointer.struct.store_method_st */
            	410, 0,
            0, 0, 0, /* 410: struct.store_method_st */
            1, 8, 1, /* 413: pointer.struct.ENGINE_CMD_DEFN_st */
            	418, 0,
            0, 32, 2, /* 418: struct.ENGINE_CMD_DEFN_st */
            	149, 8,
            	149, 16,
            0, 16, 1, /* 425: struct.crypto_ex_data_st */
            	209, 0,
            0, 24, 1, /* 430: struct.ASN1_ENCODING_st */
            	149, 0,
            1, 8, 1, /* 435: pointer.struct.AUTHORITY_KEYID_st */
            	440, 0,
            0, 24, 3, /* 440: struct.AUTHORITY_KEYID_st */
            	139, 0,
            	209, 8,
            	139, 16,
            1, 8, 1, /* 449: pointer.struct.X509_POLICY_CACHE_st */
            	454, 0,
            0, 40, 2, /* 454: struct.X509_POLICY_CACHE_st */
            	461, 0,
            	209, 8,
            1, 8, 1, /* 461: pointer.struct.X509_POLICY_DATA_st */
            	466, 0,
            0, 32, 3, /* 466: struct.X509_POLICY_DATA_st */
            	166, 8,
            	209, 16,
            	209, 24,
            1, 8, 1, /* 475: pointer.struct.NAME_CONSTRAINTS_st */
            	480, 0,
            0, 16, 2, /* 480: struct.NAME_CONSTRAINTS_st */
            	209, 0,
            	209, 8,
            1, 8, 1, /* 487: pointer.struct.x509_cert_aux_st */
            	492, 0,
            0, 40, 5, /* 492: struct.x509_cert_aux_st */
            	209, 0,
            	209, 8,
            	139, 16,
            	139, 24,
            	209, 32,
            1, 8, 1, /* 505: pointer.struct.env_md_st */
            	510, 0,
            0, 120, 0, /* 510: struct.env_md_st */
            1, 8, 1, /* 513: pointer.struct.rsa_st */
            	518, 0,
            0, 168, 17, /* 518: struct.rsa_st */
            	337, 16,
            	303, 24,
            	555, 32,
            	555, 40,
            	555, 48,
            	555, 56,
            	555, 64,
            	555, 72,
            	555, 80,
            	555, 88,
            	425, 96,
            	573, 120,
            	573, 128,
            	573, 136,
            	149, 144,
            	587, 152,
            	587, 160,
            1, 8, 1, /* 555: pointer.struct.bignum_st */
            	560, 0,
            0, 24, 1, /* 560: struct.bignum_st */
            	565, 0,
            1, 8, 1, /* 565: pointer.int */
            	570, 0,
            0, 4, 0, /* 570: int */
            1, 8, 1, /* 573: pointer.struct.bn_mont_ctx_st */
            	578, 0,
            0, 96, 3, /* 578: struct.bn_mont_ctx_st */
            	560, 8,
            	560, 32,
            	560, 56,
            1, 8, 1, /* 587: pointer.struct.bn_blinding_st */
            	592, 0,
            0, 88, 6, /* 592: struct.bn_blinding_st */
            	555, 0,
            	555, 8,
            	555, 16,
            	555, 24,
            	607, 40,
            	573, 72,
            0, 16, 1, /* 607: struct.iovec */
            	149, 0,
            1, 8, 1, /* 612: pointer.struct.dh_st */
            	617, 0,
            0, 144, 12, /* 617: struct.dh_st */
            	555, 8,
            	555, 16,
            	555, 32,
            	555, 40,
            	573, 56,
            	555, 64,
            	555, 72,
            	149, 80,
            	555, 96,
            	425, 112,
            	361, 128,
            	303, 136,
            1, 8, 1, /* 644: pointer.struct.ec_key_st.284 */
            	649, 0,
            0, 56, 4, /* 649: struct.ec_key_st.284 */
            	660, 8,
            	698, 16,
            	555, 24,
            	714, 48,
            1, 8, 1, /* 660: pointer.struct.ec_group_st */
            	665, 0,
            0, 232, 11, /* 665: struct.ec_group_st */
            	690, 0,
            	698, 8,
            	560, 16,
            	560, 40,
            	149, 80,
            	714, 96,
            	560, 104,
            	560, 152,
            	560, 176,
            	149, 208,
            	149, 216,
            1, 8, 1, /* 690: pointer.struct.ec_method_st */
            	695, 0,
            0, 304, 0, /* 695: struct.ec_method_st */
            1, 8, 1, /* 698: pointer.struct.ec_point_st */
            	703, 0,
            0, 88, 4, /* 703: struct.ec_point_st */
            	690, 0,
            	560, 8,
            	560, 32,
            	560, 56,
            1, 8, 1, /* 714: pointer.struct.ec_extra_data_st */
            	719, 0,
            0, 40, 2, /* 719: struct.ec_extra_data_st */
            	714, 0,
            	149, 8,
            0, 192, 8, /* 726: array[8].struct.cert_pkey_st */
            	68, 0,
            	68, 24,
            	68, 48,
            	68, 72,
            	68, 96,
            	68, 120,
            	68, 144,
            	68, 168,
            4097, 8, 0, /* 745: pointer.func */
            0, 0, 0, /* 748: func */
            0, 0, 0, /* 751: func */
            0, 0, 0, /* 754: func */
            4097, 8, 0, /* 757: pointer.func */
            0, 0, 0, /* 760: func */
            4097, 8, 0, /* 763: pointer.func */
            0, 0, 0, /* 766: func */
            4097, 8, 0, /* 769: pointer.func */
            0, 44, 0, /* 772: struct.apr_time_exp_t */
            0, 0, 0, /* 775: func */
            4097, 8, 0, /* 778: pointer.func */
            0, 88, 1, /* 781: struct.ssl_cipher_st */
            	149, 8,
            1, 8, 1, /* 786: pointer.struct.ssl_cipher_st */
            	781, 0,
            0, 0, 0, /* 791: func */
            0, 0, 0, /* 794: func */
            4097, 8, 0, /* 797: pointer.func */
            0, 0, 0, /* 800: func */
            4097, 8, 0, /* 803: pointer.func */
            4097, 8, 0, /* 806: pointer.func */
            0, 0, 0, /* 809: func */
            4097, 8, 0, /* 812: pointer.func */
            0, 0, 0, /* 815: func */
            4097, 8, 0, /* 818: pointer.func */
            0, 0, 0, /* 821: func */
            4097, 8, 0, /* 824: pointer.func */
            4097, 8, 0, /* 827: pointer.func */
            0, 0, 0, /* 830: func */
            0, 0, 0, /* 833: func */
            4097, 8, 0, /* 836: pointer.func */
            0, 0, 0, /* 839: func */
            4097, 8, 0, /* 842: pointer.func */
            0, 0, 0, /* 845: func */
            4097, 8, 0, /* 848: pointer.func */
            0, 0, 0, /* 851: func */
            4097, 8, 0, /* 854: pointer.func */
            0, 0, 0, /* 857: func */
            0, 0, 0, /* 860: func */
            4097, 8, 0, /* 863: pointer.func */
            0, 0, 0, /* 866: func */
            0, 0, 0, /* 869: func */
            0, 0, 0, /* 872: func */
            0, 0, 0, /* 875: func */
            1, 8, 1, /* 878: pointer.struct.cert_st.745 */
            	50, 0,
            4097, 8, 0, /* 883: pointer.func */
            0, 8, 0, /* 886: array[2].int */
            4097, 8, 0, /* 889: pointer.func */
            0, 0, 0, /* 892: func */
            4097, 8, 0, /* 895: pointer.func */
            0, 0, 0, /* 898: func */
            0, 0, 0, /* 901: func */
            0, 0, 0, /* 904: func */
            0, 0, 0, /* 907: func */
            0, 0, 0, /* 910: func */
            0, 0, 0, /* 913: func */
            4097, 8, 0, /* 916: pointer.func */
            4097, 8, 0, /* 919: pointer.func */
            0, 0, 0, /* 922: func */
            0, 0, 0, /* 925: func */
            4097, 8, 0, /* 928: pointer.func */
            4097, 8, 0, /* 931: pointer.func */
            4097, 8, 0, /* 934: pointer.func */
            4097, 8, 0, /* 937: pointer.func */
            0, 0, 0, /* 940: func */
            4097, 8, 0, /* 943: pointer.func */
            0, 0, 0, /* 946: func */
            0, 0, 0, /* 949: func */
            0, 24, 0, /* 952: array[6].int */
            4097, 8, 0, /* 955: pointer.func */
            0, 248, 6, /* 958: struct.sess_cert_st */
            	209, 0,
            	63, 16,
            	726, 24,
            	513, 216,
            	612, 224,
            	644, 232,
            0, 32, 0, /* 973: array[32].char */
            1, 8, 1, /* 976: pointer.struct.in_addr */
            	981, 0,
            0, 4, 0, /* 981: struct.in_addr */
            4097, 8, 0, /* 984: pointer.func */
            0, 48, 0, /* 987: array[48].char */
            0, 0, 0, /* 990: func */
            4097, 8, 0, /* 993: pointer.func */
            4097, 8, 0, /* 996: pointer.func */
            0, 0, 0, /* 999: func */
            0, 8, 0, /* 1002: array[8].char */
            0, 0, 0, /* 1005: func */
            0, 0, 0, /* 1008: func */
            0, 0, 0, /* 1011: func */
            0, 0, 0, /* 1014: func */
            4097, 8, 0, /* 1017: pointer.func */
            0, 352, 14, /* 1020: struct.ssl_session_st */
            	149, 144,
            	149, 152,
            	1051, 168,
            	77, 176,
            	786, 224,
            	209, 240,
            	425, 248,
            	1056, 264,
            	1056, 272,
            	149, 280,
            	149, 296,
            	149, 312,
            	149, 320,
            	149, 344,
            1, 8, 1, /* 1051: pointer.struct.sess_cert_st */
            	958, 0,
            1, 8, 1, /* 1056: pointer.struct.ssl_session_st */
            	1020, 0,
            0, 0, 0, /* 1061: func */
            0, 0, 0, /* 1064: func */
            4097, 8, 0, /* 1067: pointer.func */
            0, 0, 0, /* 1070: func */
            0, 128, 11, /* 1073: struct.srp_ctx_st.751 */
            	149, 0,
            	149, 32,
            	555, 40,
            	555, 48,
            	555, 56,
            	555, 64,
            	555, 72,
            	555, 80,
            	555, 88,
            	555, 96,
            	149, 104,
            0, 0, 0, /* 1098: func */
            4097, 8, 0, /* 1101: pointer.func */
            0, 0, 0, /* 1104: func */
            4097, 8, 0, /* 1107: pointer.func */
            4097, 8, 0, /* 1110: pointer.func */
            4097, 8, 0, /* 1113: pointer.func */
            4097, 8, 0, /* 1116: pointer.func */
            4097, 8, 0, /* 1119: pointer.func */
            4097, 8, 0, /* 1122: pointer.func */
            4097, 8, 0, /* 1125: pointer.func */
            0, 0, 0, /* 1128: func */
            0, 0, 0, /* 1131: func */
            4097, 8, 0, /* 1134: pointer.func */
            1, 8, 1, /* 1137: pointer.struct.ssl3_enc_method.753 */
            	1142, 0,
            0, 112, 4, /* 1142: struct.ssl3_enc_method.753 */
            	295, 0,
            	295, 32,
            	149, 64,
            	149, 80,
            4097, 8, 0, /* 1153: pointer.func */
            0, 0, 0, /* 1156: func */
            4097, 8, 0, /* 1159: pointer.func */
            0, 0, 0, /* 1162: func */
            4097, 8, 0, /* 1165: pointer.func */
            0, 0, 0, /* 1168: func */
            0, 0, 0, /* 1171: func */
            4097, 8, 0, /* 1174: pointer.func */
            4097, 8, 0, /* 1177: pointer.func */
            0, 0, 0, /* 1180: func */
            4097, 8, 0, /* 1183: pointer.func */
            0, 0, 0, /* 1186: func */
            4097, 8, 0, /* 1189: pointer.func */
            4097, 8, 0, /* 1192: pointer.func */
            4097, 8, 0, /* 1195: pointer.func */
            0, 0, 0, /* 1198: func */
            0, 0, 0, /* 1201: func */
            4097, 8, 0, /* 1204: pointer.func */
            4097, 8, 0, /* 1207: pointer.func */
            4097, 8, 0, /* 1210: pointer.func */
            0, 0, 0, /* 1213: func */
            0, 0, 0, /* 1216: func */
            0, 0, 0, /* 1219: func */
            0, 0, 0, /* 1222: func */
            0, 8, 0, /* 1225: long */
            1, 8, 1, /* 1228: pointer.struct.x509_store_st */
            	1233, 0,
            0, 144, 4, /* 1233: struct.x509_store_st */
            	209, 8,
            	209, 16,
            	1244, 24,
            	425, 120,
            1, 8, 1, /* 1244: pointer.struct.X509_VERIFY_PARAM_st */
            	1249, 0,
            0, 56, 2, /* 1249: struct.X509_VERIFY_PARAM_st */
            	149, 0,
            	209, 48,
            4097, 8, 0, /* 1256: pointer.func */
            0, 0, 0, /* 1259: func */
            4097, 8, 0, /* 1262: pointer.func */
            0, 0, 0, /* 1265: func */
            0, 0, 0, /* 1268: func */
            0, 0, 0, /* 1271: func */
            0, 0, 0, /* 1274: func */
            0, 0, 0, /* 1277: func */
            0, 0, 0, /* 1280: func */
            4097, 8, 0, /* 1283: pointer.func */
            4097, 8, 0, /* 1286: pointer.func */
            4097, 8, 0, /* 1289: pointer.func */
            4097, 8, 0, /* 1292: pointer.func */
            4097, 8, 0, /* 1295: pointer.func */
            4097, 8, 0, /* 1298: pointer.func */
            0, 0, 0, /* 1301: func */
            0, 0, 0, /* 1304: func */
            0, 0, 0, /* 1307: func */
            0, 0, 0, /* 1310: func */
            4097, 8, 0, /* 1313: pointer.func */
            4097, 8, 0, /* 1316: pointer.func */
            4097, 8, 0, /* 1319: pointer.func */
            4097, 8, 0, /* 1322: pointer.func */
            4097, 8, 0, /* 1325: pointer.func */
            4097, 8, 0, /* 1328: pointer.func */
            4097, 8, 0, /* 1331: pointer.func */
            4097, 8, 0, /* 1334: pointer.func */
            0, 0, 0, /* 1337: func */
            0, 232, 1, /* 1340: struct.ssl_method_st.754 */
            	1137, 200,
            0, 0, 0, /* 1345: func */
            4097, 8, 0, /* 1348: pointer.func */
            0, 0, 0, /* 1351: func */
            4097, 8, 0, /* 1354: pointer.func */
            4097, 8, 0, /* 1357: pointer.func */
            4097, 8, 0, /* 1360: pointer.func */
            0, 1, 0, /* 1363: char */
            0, 0, 0, /* 1366: func */
            0, 0, 0, /* 1369: func */
            0, 0, 0, /* 1372: func */
            0, 20, 0, /* 1375: array[5].int */
            0, 0, 0, /* 1378: func */
            4097, 8, 0, /* 1381: pointer.func */
            0, 736, 30, /* 1384: struct.ssl_ctx_st.752 */
            	1447, 0,
            	209, 8,
            	209, 16,
            	1228, 24,
            	976, 32,
            	1056, 48,
            	1056, 56,
            	149, 160,
            	149, 176,
            	425, 208,
            	505, 224,
            	505, 232,
            	505, 240,
            	209, 248,
            	209, 256,
            	209, 272,
            	878, 304,
            	149, 328,
            	1244, 392,
            	303, 408,
            	149, 424,
            	149, 496,
            	149, 512,
            	149, 520,
            	10, 552,
            	10, 560,
            	1073, 568,
            	149, 704,
            	149, 720,
            	209, 728,
            1, 8, 1, /* 1447: pointer.struct.ssl_method_st.754 */
            	1340, 0,
            0, 0, 0, /* 1452: func */
            0, 0, 0, /* 1455: func */
            0, 0, 0, /* 1458: func */
            0, 0, 0, /* 1461: func */
            0, 0, 0, /* 1464: func */
            1, 8, 1, /* 1467: pointer.struct.ssl_ctx_st.752 */
            	1384, 0,
            4097, 8, 0, /* 1472: pointer.func */
            0, 0, 0, /* 1475: func */
            0, 0, 0, /* 1478: func */
            0, 0, 0, /* 1481: func */
            0, 0, 0, /* 1484: func */
            4097, 8, 0, /* 1487: pointer.func */
            0, 0, 0, /* 1490: func */
            4097, 8, 0, /* 1493: pointer.func */
            0, 0, 0, /* 1496: func */
            4097, 8, 0, /* 1499: pointer.func */
            4097, 8, 0, /* 1502: pointer.func */
            4097, 8, 0, /* 1505: pointer.func */
            4097, 8, 0, /* 1508: pointer.func */
            4097, 8, 0, /* 1511: pointer.func */
            0, 20, 0, /* 1514: array[20].char */
            4097, 8, 0, /* 1517: pointer.func */
            0, 0, 0, /* 1520: func */
            4097, 8, 0, /* 1523: pointer.func */
            4097, 8, 0, /* 1526: pointer.func */
            4097, 8, 0, /* 1529: pointer.func */
            4097, 8, 0, /* 1532: pointer.func */
            0, 0, 0, /* 1535: func */
            4097, 8, 0, /* 1538: pointer.func */
            4097, 8, 0, /* 1541: pointer.func */
            0, 0, 0, /* 1544: func */
            4097, 8, 0, /* 1547: pointer.func */
            4097, 8, 0, /* 1550: pointer.func */
            0, 0, 0, /* 1553: func */
            4097, 8, 0, /* 1556: pointer.func */
            0, 0, 0, /* 1559: func */
            4097, 8, 0, /* 1562: pointer.func */
            0, 0, 0, /* 1565: func */
            0, 0, 0, /* 1568: func */
            0, 0, 0, /* 1571: func */
            4097, 8, 0, /* 1574: pointer.func */
            4097, 8, 0, /* 1577: pointer.func */
            0, 0, 0, /* 1580: func */
            4097, 8, 0, /* 1583: pointer.func */
            0, 0, 0, /* 1586: func */
            4097, 8, 0, /* 1589: pointer.func */
            0, 0, 0, /* 1592: func */
            0, 0, 0, /* 1595: func */
            0, 0, 0, /* 1598: func */
            0, 0, 0, /* 1601: func */
            4097, 8, 0, /* 1604: pointer.func */
            4097, 8, 0, /* 1607: pointer.func */
            4097, 8, 0, /* 1610: pointer.func */
            4097, 8, 0, /* 1613: pointer.func */
            4097, 8, 0, /* 1616: pointer.func */
            4097, 8, 0, /* 1619: pointer.func */
            0, 0, 0, /* 1622: func */
            0, 0, 0, /* 1625: func */
            0, 0, 0, /* 1628: func */
            4097, 8, 0, /* 1631: pointer.func */
            0, 0, 0, /* 1634: func */
            0, 0, 0, /* 1637: func */
            0, 0, 0, /* 1640: func */
            4097, 8, 0, /* 1643: pointer.func */
            0, 0, 0, /* 1646: func */
            4097, 8, 0, /* 1649: pointer.func */
            4097, 8, 0, /* 1652: pointer.func */
            4097, 8, 0, /* 1655: pointer.func */
            0, 0, 0, /* 1658: func */
            0, 0, 0, /* 1661: func */
            4097, 8, 0, /* 1664: pointer.func */
            4097, 8, 0, /* 1667: pointer.func */
            4097, 8, 0, /* 1670: pointer.func */
            0, 0, 0, /* 1673: func */
            4097, 8, 0, /* 1676: pointer.func */
            4097, 8, 0, /* 1679: pointer.func */
            4097, 8, 0, /* 1682: pointer.func */
            4097, 8, 0, /* 1685: pointer.func */
            4097, 8, 0, /* 1688: pointer.func */
            0, 0, 0, /* 1691: func */
            0, 0, 0, /* 1694: func */
            4097, 8, 0, /* 1697: pointer.func */
            4097, 8, 0, /* 1700: pointer.func */
            0, 0, 0, /* 1703: func */
            4097, 8, 0, /* 1706: pointer.func */
            4097, 8, 0, /* 1709: pointer.func */
            0, 0, 0, /* 1712: func */
            0, 0, 0, /* 1715: func */
            4097, 8, 0, /* 1718: pointer.func */
            0, 0, 0, /* 1721: func */
            0, 0, 0, /* 1724: func */
            4097, 8, 0, /* 1727: pointer.func */
            4097, 8, 0, /* 1730: pointer.func */
            0, 0, 0, /* 1733: func */
            0, 0, 0, /* 1736: func */
            0, 0, 0, /* 1739: func */
        },
        .arg_entity_index = { 1467, },
        .ret_entity_index = 1228,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL_CTX * new_arg_a = *((const SSL_CTX * *)new_args->args[0]);

    X509_STORE * *new_ret_ptr = (X509_STORE * *)new_args->ret;

    X509_STORE * (*orig_SSL_CTX_get_cert_store)(const SSL_CTX *);
    orig_SSL_CTX_get_cert_store = dlsym(RTLD_NEXT, "SSL_CTX_get_cert_store");
    *new_ret_ptr = (*orig_SSL_CTX_get_cert_store)(new_arg_a);

    syscall(889);

    return ret;
}

