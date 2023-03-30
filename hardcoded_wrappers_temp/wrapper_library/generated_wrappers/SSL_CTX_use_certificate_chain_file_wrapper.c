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

int bb_SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b);

int SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b) 
{
    printf("SSL_CTX_use_certificate_chain_file called\n");
    if (!syscall(890))
        return bb_SSL_CTX_use_certificate_chain_file(arg_a,arg_b);
    else {
        int (*orig_SSL_CTX_use_certificate_chain_file)(SSL_CTX *,const char *);
        orig_SSL_CTX_use_certificate_chain_file = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate_chain_file");
        return orig_SSL_CTX_use_certificate_chain_file(arg_a,arg_b);
    }
}

int bb_SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 8, 0, /* 3: pointer.func */
            0, 8, 0, /* 6: pointer.func */
            1, 8, 1, /* 9: pointer.struct.ssl3_buf_freelist_entry_st */
            	14, 0,
            0, 8, 1, /* 14: struct.ssl3_buf_freelist_entry_st */
            	9, 0,
            0, 8, 0, /* 19: pointer.func */
            0, 0, 0, /* 22: func */
            0, 8, 0, /* 25: pointer.func */
            0, 8, 0, /* 28: pointer.func */
            0, 16, 0, /* 31: array[16].char */
            0, 8, 0, /* 34: pointer.func */
            0, 0, 0, /* 37: func */
            0, 8, 0, /* 40: pointer.func */
            0, 8, 0, /* 43: pointer.func */
            0, 0, 0, /* 46: func */
            0, 8, 0, /* 49: pointer.func */
            0, 0, 0, /* 52: func */
            0, 0, 0, /* 55: func */
            0, 8, 0, /* 58: pointer.func */
            0, 44, 0, /* 61: struct.apr_time_exp_t */
            0, 0, 0, /* 64: func */
            1, 8, 1, /* 67: pointer.struct.ssl_cipher_st */
            	72, 0,
            0, 88, 1, /* 72: struct.ssl_cipher_st */
            	77, 8,
            1, 8, 1, /* 77: pointer.char */
            	82, 0,
            0, 1, 0, /* 82: char */
            0, 24, 0, /* 85: array[6].int */
            0, 8, 0, /* 88: pointer.func */
            0, 40, 2, /* 91: struct.ec_extra_data_st */
            	98, 0,
            	77, 8,
            1, 8, 1, /* 98: pointer.struct.ec_extra_data_st */
            	91, 0,
            0, 88, 4, /* 103: struct.ec_point_st */
            	114, 0,
            	122, 8,
            	122, 32,
            	122, 56,
            1, 8, 1, /* 114: pointer.struct.ec_method_st */
            	119, 0,
            0, 304, 0, /* 119: struct.ec_method_st */
            0, 24, 1, /* 122: struct.bignum_st */
            	127, 0,
            1, 8, 1, /* 127: pointer.int */
            	132, 0,
            0, 4, 0, /* 132: int */
            0, 0, 0, /* 135: func */
            0, 8, 0, /* 138: pointer.func */
            0, 0, 0, /* 141: func */
            0, 8, 0, /* 144: pointer.func */
            0, 0, 0, /* 147: func */
            0, 0, 0, /* 150: func */
            0, 8, 0, /* 153: pointer.func */
            0, 8, 0, /* 156: pointer.func */
            0, 0, 0, /* 159: func */
            0, 0, 0, /* 162: func */
            0, 8, 0, /* 165: pointer.func */
            0, 0, 0, /* 168: func */
            0, 0, 0, /* 171: func */
            0, 8, 0, /* 174: pointer.func */
            0, 0, 0, /* 177: func */
            0, 8, 0, /* 180: pointer.func */
            0, 0, 0, /* 183: func */
            0, 8, 0, /* 186: pointer.func */
            0, 0, 0, /* 189: func */
            0, 8, 0, /* 192: pointer.func */
            0, 0, 0, /* 195: func */
            0, 8, 0, /* 198: pointer.func */
            0, 8, 0, /* 201: pointer.func */
            0, 0, 0, /* 204: func */
            0, 8, 0, /* 207: pointer.func */
            0, 0, 0, /* 210: func */
            0, 0, 0, /* 213: func */
            0, 0, 0, /* 216: func */
            0, 8, 0, /* 219: pointer.func */
            0, 0, 0, /* 222: func */
            0, 8, 0, /* 225: pointer.func */
            0, 8, 0, /* 228: pointer.func */
            0, 8, 0, /* 231: pointer.func */
            0, 232, 11, /* 234: struct.ec_group_st */
            	114, 0,
            	259, 8,
            	122, 16,
            	122, 40,
            	77, 80,
            	98, 96,
            	122, 104,
            	122, 152,
            	122, 176,
            	77, 208,
            	77, 216,
            1, 8, 1, /* 259: pointer.struct.ec_point_st */
            	103, 0,
            1, 8, 1, /* 264: pointer.struct.ec_group_st */
            	234, 0,
            0, 56, 4, /* 269: struct.ec_key_st.284 */
            	264, 8,
            	259, 16,
            	280, 24,
            	98, 48,
            1, 8, 1, /* 280: pointer.struct.bignum_st */
            	122, 0,
            1, 8, 1, /* 285: pointer.struct.ec_key_st.284 */
            	269, 0,
            0, 144, 12, /* 290: struct.dh_st */
            	280, 8,
            	280, 16,
            	280, 32,
            	280, 40,
            	317, 56,
            	280, 64,
            	280, 72,
            	77, 80,
            	280, 96,
            	331, 112,
            	356, 128,
            	368, 136,
            1, 8, 1, /* 317: pointer.struct.bn_mont_ctx_st */
            	322, 0,
            0, 96, 3, /* 322: struct.bn_mont_ctx_st */
            	122, 8,
            	122, 32,
            	122, 56,
            0, 16, 1, /* 331: struct.crypto_ex_data_st */
            	336, 0,
            1, 8, 1, /* 336: pointer.struct.stack_st_OPENSSL_STRING */
            	341, 0,
            0, 32, 1, /* 341: struct.stack_st_OPENSSL_STRING */
            	346, 0,
            0, 32, 1, /* 346: struct.stack_st */
            	351, 8,
            1, 8, 1, /* 351: pointer.pointer.char */
            	77, 0,
            1, 8, 1, /* 356: pointer.struct.dh_method */
            	361, 0,
            0, 72, 2, /* 361: struct.dh_method */
            	77, 0,
            	77, 56,
            1, 8, 1, /* 368: pointer.struct.engine_st */
            	373, 0,
            0, 216, 13, /* 373: struct.engine_st */
            	77, 0,
            	77, 8,
            	402, 16,
            	414, 24,
            	356, 32,
            	426, 40,
            	438, 48,
            	450, 56,
            	458, 64,
            	466, 160,
            	331, 184,
            	368, 200,
            	368, 208,
            1, 8, 1, /* 402: pointer.struct.rsa_meth_st */
            	407, 0,
            0, 112, 2, /* 407: struct.rsa_meth_st */
            	77, 0,
            	77, 80,
            1, 8, 1, /* 414: pointer.struct.dsa_method.1040 */
            	419, 0,
            0, 96, 2, /* 419: struct.dsa_method.1040 */
            	77, 0,
            	77, 72,
            1, 8, 1, /* 426: pointer.struct.ecdh_method */
            	431, 0,
            0, 32, 2, /* 431: struct.ecdh_method */
            	77, 0,
            	77, 24,
            1, 8, 1, /* 438: pointer.struct.ecdsa_method */
            	443, 0,
            0, 48, 2, /* 443: struct.ecdsa_method */
            	77, 0,
            	77, 40,
            1, 8, 1, /* 450: pointer.struct.rand_meth_st */
            	455, 0,
            0, 48, 0, /* 455: struct.rand_meth_st */
            1, 8, 1, /* 458: pointer.struct.store_method_st */
            	463, 0,
            0, 0, 0, /* 463: struct.store_method_st */
            1, 8, 1, /* 466: pointer.struct.ENGINE_CMD_DEFN_st */
            	471, 0,
            0, 32, 2, /* 471: struct.ENGINE_CMD_DEFN_st */
            	77, 8,
            	77, 16,
            1, 8, 1, /* 478: pointer.struct.dh_st */
            	290, 0,
            0, 88, 6, /* 483: struct.bn_blinding_st */
            	280, 0,
            	280, 8,
            	280, 16,
            	280, 24,
            	498, 40,
            	317, 72,
            0, 16, 1, /* 498: struct.iovec */
            	77, 0,
            0, 8, 0, /* 503: array[2].int */
            1, 8, 1, /* 506: pointer.struct.rsa_st */
            	511, 0,
            0, 168, 17, /* 511: struct.rsa_st */
            	402, 16,
            	368, 24,
            	280, 32,
            	280, 40,
            	280, 48,
            	280, 56,
            	280, 64,
            	280, 72,
            	280, 80,
            	280, 88,
            	331, 96,
            	317, 120,
            	317, 128,
            	317, 136,
            	77, 144,
            	548, 152,
            	548, 160,
            1, 8, 1, /* 548: pointer.struct.bn_blinding_st */
            	483, 0,
            0, 8, 0, /* 553: pointer.func */
            0, 0, 0, /* 556: func */
            0, 0, 0, /* 559: func */
            0, 8, 0, /* 562: pointer.func */
            0, 0, 0, /* 565: func */
            0, 8, 0, /* 568: pointer.func */
            1, 8, 1, /* 571: pointer.struct.unnamed */
            	576, 0,
            0, 0, 0, /* 576: struct.unnamed */
            0, 24, 3, /* 579: struct.X509_pubkey_st */
            	588, 0,
            	629, 8,
            	639, 16,
            1, 8, 1, /* 588: pointer.struct.X509_algor_st */
            	593, 0,
            0, 16, 2, /* 593: struct.X509_algor_st */
            	600, 0,
            	614, 8,
            1, 8, 1, /* 600: pointer.struct.asn1_object_st */
            	605, 0,
            0, 40, 3, /* 605: struct.asn1_object_st */
            	77, 0,
            	77, 8,
            	77, 24,
            1, 8, 1, /* 614: pointer.struct.asn1_type_st */
            	619, 0,
            0, 16, 1, /* 619: struct.asn1_type_st */
            	624, 8,
            0, 8, 1, /* 624: struct.fnames */
            	77, 0,
            1, 8, 1, /* 629: pointer.struct.asn1_string_st */
            	634, 0,
            0, 24, 1, /* 634: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 639: pointer.struct.evp_pkey_st */
            	644, 0,
            0, 56, 4, /* 644: struct.evp_pkey_st */
            	655, 16,
            	368, 24,
            	624, 32,
            	336, 48,
            1, 8, 1, /* 655: pointer.struct.evp_pkey_asn1_method_st */
            	660, 0,
            0, 208, 3, /* 660: struct.evp_pkey_asn1_method_st */
            	77, 16,
            	77, 24,
            	571, 32,
            1, 8, 1, /* 669: pointer.struct.X509_val_st */
            	674, 0,
            0, 16, 2, /* 674: struct.X509_val_st */
            	629, 0,
            	629, 8,
            0, 4, 0, /* 681: struct.in_addr */
            0, 0, 0, /* 684: func */
            0, 8, 0, /* 687: pointer.func */
            0, 0, 0, /* 690: func */
            0, 184, 12, /* 693: struct.x509_st */
            	720, 0,
            	588, 8,
            	629, 16,
            	77, 32,
            	331, 40,
            	629, 104,
            	784, 112,
            	798, 120,
            	336, 128,
            	336, 136,
            	824, 144,
            	836, 176,
            1, 8, 1, /* 720: pointer.struct.x509_cinf_st */
            	725, 0,
            0, 104, 11, /* 725: struct.x509_cinf_st */
            	629, 0,
            	629, 8,
            	588, 16,
            	750, 24,
            	669, 32,
            	750, 40,
            	774, 48,
            	629, 56,
            	629, 64,
            	336, 72,
            	779, 80,
            1, 8, 1, /* 750: pointer.struct.X509_name_st */
            	755, 0,
            0, 40, 3, /* 755: struct.X509_name_st */
            	336, 0,
            	764, 16,
            	77, 24,
            1, 8, 1, /* 764: pointer.struct.buf_mem_st */
            	769, 0,
            0, 24, 1, /* 769: struct.buf_mem_st */
            	77, 8,
            1, 8, 1, /* 774: pointer.struct.X509_pubkey_st */
            	579, 0,
            0, 24, 1, /* 779: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 784: pointer.struct.AUTHORITY_KEYID_st */
            	789, 0,
            0, 24, 3, /* 789: struct.AUTHORITY_KEYID_st */
            	629, 0,
            	336, 8,
            	629, 16,
            1, 8, 1, /* 798: pointer.struct.X509_POLICY_CACHE_st */
            	803, 0,
            0, 40, 2, /* 803: struct.X509_POLICY_CACHE_st */
            	810, 0,
            	336, 8,
            1, 8, 1, /* 810: pointer.struct.X509_POLICY_DATA_st */
            	815, 0,
            0, 32, 3, /* 815: struct.X509_POLICY_DATA_st */
            	600, 8,
            	336, 16,
            	336, 24,
            1, 8, 1, /* 824: pointer.struct.NAME_CONSTRAINTS_st */
            	829, 0,
            0, 16, 2, /* 829: struct.NAME_CONSTRAINTS_st */
            	336, 0,
            	336, 8,
            1, 8, 1, /* 836: pointer.struct.x509_cert_aux_st */
            	841, 0,
            0, 40, 5, /* 841: struct.x509_cert_aux_st */
            	336, 0,
            	336, 8,
            	629, 16,
            	629, 24,
            	336, 32,
            0, 0, 0, /* 854: func */
            0, 248, 6, /* 857: struct.sess_cert_st */
            	336, 0,
            	872, 16,
            	899, 24,
            	506, 216,
            	478, 224,
            	285, 232,
            1, 8, 1, /* 872: pointer.struct.cert_pkey_st */
            	877, 0,
            0, 24, 3, /* 877: struct.cert_pkey_st */
            	886, 0,
            	639, 8,
            	891, 16,
            1, 8, 1, /* 886: pointer.struct.x509_st */
            	693, 0,
            1, 8, 1, /* 891: pointer.struct.env_md_st */
            	896, 0,
            0, 120, 0, /* 896: struct.env_md_st */
            0, 192, 8, /* 899: array[8].struct.cert_pkey_st */
            	877, 0,
            	877, 24,
            	877, 48,
            	877, 72,
            	877, 96,
            	877, 120,
            	877, 144,
            	877, 168,
            0, 8, 0, /* 918: pointer.func */
            0, 352, 14, /* 921: struct.ssl_session_st */
            	77, 144,
            	77, 152,
            	952, 168,
            	886, 176,
            	67, 224,
            	336, 240,
            	331, 248,
            	957, 264,
            	957, 272,
            	77, 280,
            	77, 296,
            	77, 312,
            	77, 320,
            	77, 344,
            1, 8, 1, /* 952: pointer.struct.sess_cert_st */
            	857, 0,
            1, 8, 1, /* 957: pointer.struct.ssl_session_st */
            	921, 0,
            0, 8, 0, /* 962: pointer.func */
            1, 8, 1, /* 965: pointer.struct.in_addr */
            	681, 0,
            0, 8, 0, /* 970: pointer.func */
            0, 8, 0, /* 973: pointer.func */
            0, 0, 0, /* 976: func */
            0, 8, 0, /* 979: pointer.func */
            0, 8, 0, /* 982: pointer.func */
            0, 8, 0, /* 985: pointer.func */
            0, 0, 0, /* 988: func */
            0, 8, 0, /* 991: pointer.func */
            0, 0, 0, /* 994: func */
            0, 8, 0, /* 997: pointer.func */
            0, 8, 0, /* 1000: long */
            0, 0, 0, /* 1003: func */
            0, 144, 4, /* 1006: struct.x509_store_st */
            	336, 8,
            	336, 16,
            	1017, 24,
            	331, 120,
            1, 8, 1, /* 1017: pointer.struct.X509_VERIFY_PARAM_st */
            	1022, 0,
            0, 56, 2, /* 1022: struct.X509_VERIFY_PARAM_st */
            	77, 0,
            	336, 48,
            0, 0, 0, /* 1029: func */
            0, 0, 0, /* 1032: func */
            1, 8, 1, /* 1035: pointer.struct.x509_store_st */
            	1006, 0,
            0, 0, 0, /* 1040: func */
            0, 8, 0, /* 1043: pointer.func */
            0, 8, 0, /* 1046: pointer.func */
            0, 8, 0, /* 1049: pointer.func */
            0, 0, 0, /* 1052: func */
            0, 8, 0, /* 1055: pointer.func */
            0, 0, 0, /* 1058: func */
            0, 0, 0, /* 1061: func */
            0, 8, 0, /* 1064: pointer.func */
            0, 0, 0, /* 1067: func */
            0, 8, 0, /* 1070: pointer.func */
            0, 0, 0, /* 1073: func */
            0, 0, 0, /* 1076: func */
            0, 0, 0, /* 1079: func */
            0, 8, 0, /* 1082: pointer.func */
            0, 0, 0, /* 1085: func */
            0, 8, 0, /* 1088: pointer.func */
            0, 32, 0, /* 1091: array[32].char */
            0, 0, 0, /* 1094: func */
            0, 0, 0, /* 1097: func */
            0, 8, 0, /* 1100: pointer.func */
            0, 8, 0, /* 1103: pointer.func */
            0, 8, 0, /* 1106: pointer.func */
            0, 8, 0, /* 1109: pointer.func */
            0, 8, 0, /* 1112: pointer.func */
            0, 8, 0, /* 1115: pointer.func */
            0, 8, 0, /* 1118: pointer.func */
            0, 0, 0, /* 1121: func */
            0, 8, 0, /* 1124: pointer.func */
            0, 8, 0, /* 1127: pointer.func */
            0, 8, 0, /* 1130: pointer.func */
            0, 736, 30, /* 1133: struct.ssl_ctx_st.2836 */
            	1196, 0,
            	336, 8,
            	336, 16,
            	1035, 24,
            	965, 32,
            	957, 48,
            	957, 56,
            	77, 160,
            	77, 176,
            	331, 208,
            	891, 224,
            	891, 232,
            	891, 240,
            	336, 248,
            	336, 256,
            	336, 272,
            	1218, 304,
            	77, 328,
            	1017, 392,
            	368, 408,
            	77, 424,
            	77, 496,
            	77, 512,
            	77, 520,
            	1236, 552,
            	1236, 560,
            	1246, 568,
            	77, 704,
            	77, 720,
            	336, 728,
            1, 8, 1, /* 1196: pointer.struct.ssl_method_st.2838 */
            	1201, 0,
            0, 232, 1, /* 1201: struct.ssl_method_st.2838 */
            	1206, 200,
            1, 8, 1, /* 1206: pointer.struct.ssl3_enc_method.2837 */
            	1211, 0,
            0, 112, 2, /* 1211: struct.ssl3_enc_method.2837 */
            	77, 64,
            	77, 80,
            1, 8, 1, /* 1218: pointer.struct.cert_st.2861 */
            	1223, 0,
            0, 296, 5, /* 1223: struct.cert_st.2861 */
            	872, 0,
            	506, 48,
            	478, 64,
            	285, 80,
            	899, 96,
            1, 8, 1, /* 1236: pointer.struct.ssl3_buf_freelist_st */
            	1241, 0,
            0, 24, 1, /* 1241: struct.ssl3_buf_freelist_st */
            	9, 16,
            0, 128, 11, /* 1246: struct.srp_ctx_st.2835 */
            	77, 0,
            	77, 32,
            	280, 40,
            	280, 48,
            	280, 56,
            	280, 64,
            	280, 72,
            	280, 80,
            	280, 88,
            	280, 96,
            	77, 104,
            0, 0, 0, /* 1271: func */
            0, 0, 0, /* 1274: func */
            0, 8, 0, /* 1277: pointer.func */
            0, 0, 0, /* 1280: func */
            0, 8, 0, /* 1283: pointer.func */
            1, 8, 1, /* 1286: pointer.struct.ssl_ctx_st.2836 */
            	1133, 0,
            0, 8, 0, /* 1291: pointer.func */
            0, 8, 0, /* 1294: pointer.func */
            0, 8, 0, /* 1297: array[8].char */
            0, 8, 0, /* 1300: pointer.func */
            0, 0, 0, /* 1303: func */
            0, 0, 0, /* 1306: func */
            0, 8, 0, /* 1309: pointer.func */
            0, 8, 0, /* 1312: pointer.func */
            0, 8, 0, /* 1315: pointer.func */
            0, 8, 0, /* 1318: pointer.func */
            0, 0, 0, /* 1321: func */
            0, 8, 0, /* 1324: pointer.func */
            0, 8, 0, /* 1327: pointer.func */
            0, 8, 0, /* 1330: pointer.func */
            0, 8, 0, /* 1333: pointer.func */
            0, 0, 0, /* 1336: func */
            0, 0, 0, /* 1339: func */
            0, 8, 0, /* 1342: pointer.func */
            0, 8, 0, /* 1345: pointer.func */
            0, 0, 0, /* 1348: func */
            0, 8, 0, /* 1351: pointer.func */
            0, 0, 0, /* 1354: func */
            0, 0, 0, /* 1357: func */
            0, 0, 0, /* 1360: func */
            0, 8, 0, /* 1363: pointer.func */
            0, 8, 0, /* 1366: pointer.func */
            0, 20, 0, /* 1369: array[5].int */
            0, 0, 0, /* 1372: func */
            0, 8, 0, /* 1375: pointer.func */
            0, 8, 0, /* 1378: pointer.func */
            0, 0, 0, /* 1381: func */
            0, 0, 0, /* 1384: func */
            0, 0, 0, /* 1387: func */
            0, 8, 0, /* 1390: pointer.func */
            0, 0, 0, /* 1393: func */
            0, 0, 0, /* 1396: func */
            0, 0, 0, /* 1399: func */
            0, 8, 0, /* 1402: pointer.func */
            0, 0, 0, /* 1405: func */
            0, 0, 0, /* 1408: func */
            0, 8, 0, /* 1411: pointer.func */
            0, 8, 0, /* 1414: pointer.func */
            0, 0, 0, /* 1417: func */
            0, 0, 0, /* 1420: func */
            0, 8, 0, /* 1423: pointer.func */
            0, 8, 0, /* 1426: pointer.func */
            0, 0, 0, /* 1429: func */
            0, 0, 0, /* 1432: func */
            0, 8, 0, /* 1435: pointer.func */
            0, 0, 0, /* 1438: func */
            0, 0, 0, /* 1441: func */
            0, 0, 0, /* 1444: func */
            0, 0, 0, /* 1447: func */
            0, 0, 0, /* 1450: func */
            0, 8, 0, /* 1453: pointer.func */
            0, 0, 0, /* 1456: func */
            0, 8, 0, /* 1459: pointer.func */
            0, 0, 0, /* 1462: func */
            0, 0, 0, /* 1465: func */
            0, 0, 0, /* 1468: func */
            0, 0, 0, /* 1471: func */
            0, 8, 0, /* 1474: pointer.func */
            0, 8, 0, /* 1477: pointer.func */
            0, 0, 0, /* 1480: func */
            0, 0, 0, /* 1483: func */
            0, 8, 0, /* 1486: pointer.func */
            0, 0, 0, /* 1489: func */
            0, 0, 0, /* 1492: func */
            0, 0, 0, /* 1495: func */
            0, 0, 0, /* 1498: func */
            0, 0, 0, /* 1501: func */
            0, 8, 0, /* 1504: pointer.func */
            0, 8, 0, /* 1507: pointer.func */
            0, 48, 0, /* 1510: array[48].char */
            0, 0, 0, /* 1513: func */
            0, 8, 0, /* 1516: pointer.func */
            0, 0, 0, /* 1519: func */
            0, 0, 0, /* 1522: func */
            0, 0, 0, /* 1525: func */
            0, 8, 0, /* 1528: pointer.func */
            0, 8, 0, /* 1531: pointer.func */
            0, 0, 0, /* 1534: func */
            0, 8, 0, /* 1537: pointer.func */
            0, 0, 0, /* 1540: func */
            0, 0, 0, /* 1543: func */
            0, 20, 0, /* 1546: array[20].char */
            0, 8, 0, /* 1549: pointer.func */
            0, 0, 0, /* 1552: func */
            0, 8, 0, /* 1555: pointer.func */
            0, 8, 0, /* 1558: pointer.func */
            0, 0, 0, /* 1561: func */
            0, 0, 0, /* 1564: func */
            0, 0, 0, /* 1567: func */
            0, 8, 0, /* 1570: pointer.func */
            0, 8, 0, /* 1573: pointer.func */
            0, 0, 0, /* 1576: func */
            0, 8, 0, /* 1579: pointer.func */
            0, 8, 0, /* 1582: pointer.func */
            0, 8, 0, /* 1585: pointer.func */
            0, 8, 0, /* 1588: pointer.func */
            0, 0, 0, /* 1591: func */
            0, 8, 0, /* 1594: pointer.func */
            0, 0, 0, /* 1597: func */
            0, 0, 0, /* 1600: func */
            0, 8, 0, /* 1603: pointer.func */
            0, 8, 0, /* 1606: pointer.func */
            0, 0, 0, /* 1609: func */
            0, 0, 0, /* 1612: func */
            0, 8, 0, /* 1615: pointer.func */
            0, 0, 0, /* 1618: func */
            0, 0, 0, /* 1621: func */
            0, 8, 0, /* 1624: pointer.func */
            0, 0, 0, /* 1627: func */
            0, 8, 0, /* 1630: pointer.func */
            0, 0, 0, /* 1633: func */
            0, 0, 0, /* 1636: func */
            0, 0, 0, /* 1639: func */
            0, 8, 0, /* 1642: pointer.func */
            0, 0, 0, /* 1645: func */
            0, 0, 0, /* 1648: func */
            0, 8, 0, /* 1651: pointer.func */
            0, 8, 0, /* 1654: pointer.func */
            0, 0, 0, /* 1657: func */
            0, 8, 0, /* 1660: pointer.func */
            0, 8, 0, /* 1663: pointer.func */
            0, 0, 0, /* 1666: func */
            0, 0, 0, /* 1669: func */
            0, 0, 0, /* 1672: func */
            0, 0, 0, /* 1675: func */
            0, 8, 0, /* 1678: pointer.func */
            0, 8, 0, /* 1681: pointer.func */
            0, 8, 0, /* 1684: pointer.func */
            0, 8, 0, /* 1687: pointer.func */
            0, 8, 0, /* 1690: pointer.func */
            0, 0, 0, /* 1693: func */
            0, 8, 0, /* 1696: pointer.func */
            0, 8, 0, /* 1699: pointer.func */
            0, 8, 0, /* 1702: pointer.func */
            0, 0, 0, /* 1705: func */
            0, 8, 0, /* 1708: pointer.func */
            0, 8, 0, /* 1711: pointer.func */
            0, 0, 0, /* 1714: func */
            0, 0, 0, /* 1717: func */
            0, 0, 0, /* 1720: func */
            0, 0, 0, /* 1723: func */
            0, 0, 0, /* 1726: func */
            0, 0, 0, /* 1729: func */
            0, 0, 0, /* 1732: func */
            0, 8, 0, /* 1735: pointer.func */
            0, 8, 0, /* 1738: pointer.func */
            0, 8, 0, /* 1741: pointer.func */
        },
        .arg_entity_index = { 1286, 77, },
        .ret_entity_index = 132,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_use_certificate_chain_file)(SSL_CTX *,const char *);
    orig_SSL_CTX_use_certificate_chain_file = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate_chain_file");
    *new_ret_ptr = (*orig_SSL_CTX_use_certificate_chain_file)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

