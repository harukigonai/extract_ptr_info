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
            0, 0, 0, /* 0: func */
            0, 8, 1, /* 3: struct.ssl3_buf_freelist_entry_st */
            	8, 0,
            1, 8, 1, /* 8: pointer.struct.ssl3_buf_freelist_entry_st */
            	3, 0,
            0, 0, 0, /* 13: func */
            0, 0, 0, /* 16: func */
            0, 0, 0, /* 19: func */
            0, 16, 0, /* 22: array[16].char */
            0, 0, 0, /* 25: func */
            4097, 0, 0, /* 28: pointer.func */
            1, 8, 1, /* 31: pointer.struct.ssl3_buf_freelist_st */
            	36, 0,
            0, 24, 1, /* 36: struct.ssl3_buf_freelist_st */
            	8, 16,
            0, 0, 0, /* 41: func */
            4097, 0, 0, /* 44: pointer.func */
            4097, 0, 0, /* 47: pointer.func */
            4097, 0, 0, /* 50: pointer.func */
            4097, 0, 0, /* 53: pointer.func */
            0, 0, 0, /* 56: func */
            4097, 0, 0, /* 59: pointer.func */
            0, 44, 0, /* 62: struct.apr_time_exp_t */
            0, 88, 1, /* 65: struct.ssl_cipher_st */
            	70, 8,
            1, 8, 1, /* 70: pointer.char */
            	4096, 0,
            1, 8, 1, /* 75: pointer.struct.ssl_cipher_st */
            	65, 0,
            0, 0, 0, /* 80: func */
            0, 0, 0, /* 83: func */
            4097, 0, 0, /* 86: pointer.func */
            0, 40, 2, /* 89: struct.ec_extra_data_st */
            	96, 0,
            	70, 8,
            1, 8, 1, /* 96: pointer.struct.ec_extra_data_st */
            	89, 0,
            0, 88, 4, /* 101: struct.ec_point_st */
            	112, 0,
            	120, 8,
            	120, 32,
            	120, 56,
            1, 8, 1, /* 112: pointer.struct.ec_method_st */
            	117, 0,
            0, 304, 0, /* 117: struct.ec_method_st */
            0, 24, 1, /* 120: struct.bignum_st */
            	125, 0,
            1, 8, 1, /* 125: pointer.int */
            	130, 0,
            0, 4, 0, /* 130: int */
            1, 8, 1, /* 133: pointer.struct.ec_point_st */
            	101, 0,
            0, 0, 0, /* 138: func */
            4097, 0, 0, /* 141: pointer.func */
            0, 0, 0, /* 144: func */
            4097, 0, 0, /* 147: pointer.func */
            0, 0, 0, /* 150: func */
            4097, 0, 0, /* 153: pointer.func */
            0, 0, 0, /* 156: func */
            4097, 0, 0, /* 159: pointer.func */
            0, 0, 0, /* 162: func */
            4097, 0, 0, /* 165: pointer.func */
            0, 0, 0, /* 168: func */
            4097, 0, 0, /* 171: pointer.func */
            0, 0, 0, /* 174: func */
            0, 0, 0, /* 177: func */
            4097, 0, 0, /* 180: pointer.func */
            0, 0, 0, /* 183: func */
            4097, 0, 0, /* 186: pointer.func */
            0, 0, 0, /* 189: func */
            4097, 0, 0, /* 192: pointer.func */
            0, 0, 0, /* 195: func */
            0, 0, 0, /* 198: func */
            4097, 0, 0, /* 201: pointer.func */
            0, 0, 0, /* 204: func */
            4097, 0, 0, /* 207: pointer.func */
            0, 0, 0, /* 210: func */
            4097, 0, 0, /* 213: pointer.func */
            0, 0, 0, /* 216: func */
            0, 0, 0, /* 219: func */
            0, 0, 0, /* 222: func */
            0, 0, 0, /* 225: func */
            0, 56, 4, /* 228: struct.ec_key_st.284 */
            	239, 8,
            	133, 16,
            	269, 24,
            	96, 48,
            1, 8, 1, /* 239: pointer.struct.ec_group_st */
            	244, 0,
            0, 232, 11, /* 244: struct.ec_group_st */
            	112, 0,
            	133, 8,
            	120, 16,
            	120, 40,
            	70, 80,
            	96, 96,
            	120, 104,
            	120, 152,
            	120, 176,
            	70, 208,
            	70, 216,
            1, 8, 1, /* 269: pointer.struct.bignum_st */
            	120, 0,
            1, 8, 1, /* 274: pointer.struct.ec_key_st.284 */
            	228, 0,
            1, 8, 1, /* 279: pointer.struct.dh_st */
            	284, 0,
            0, 144, 12, /* 284: struct.dh_st */
            	269, 8,
            	269, 16,
            	269, 32,
            	269, 40,
            	311, 56,
            	269, 64,
            	269, 72,
            	70, 80,
            	269, 96,
            	325, 112,
            	350, 128,
            	362, 136,
            1, 8, 1, /* 311: pointer.struct.bn_mont_ctx_st */
            	316, 0,
            0, 96, 3, /* 316: struct.bn_mont_ctx_st */
            	120, 8,
            	120, 32,
            	120, 56,
            0, 16, 1, /* 325: struct.crypto_ex_data_st */
            	330, 0,
            1, 8, 1, /* 330: pointer.struct.stack_st_OPENSSL_STRING */
            	335, 0,
            0, 32, 1, /* 335: struct.stack_st_OPENSSL_STRING */
            	340, 0,
            0, 32, 1, /* 340: struct.stack_st */
            	345, 8,
            1, 8, 1, /* 345: pointer.pointer.char */
            	70, 0,
            1, 8, 1, /* 350: pointer.struct.dh_method */
            	355, 0,
            0, 72, 2, /* 355: struct.dh_method */
            	70, 0,
            	70, 56,
            1, 8, 1, /* 362: pointer.struct.engine_st */
            	367, 0,
            0, 216, 13, /* 367: struct.engine_st */
            	70, 0,
            	70, 8,
            	396, 16,
            	408, 24,
            	350, 32,
            	420, 40,
            	432, 48,
            	444, 56,
            	452, 64,
            	460, 160,
            	325, 184,
            	362, 200,
            	362, 208,
            1, 8, 1, /* 396: pointer.struct.rsa_meth_st */
            	401, 0,
            0, 112, 2, /* 401: struct.rsa_meth_st */
            	70, 0,
            	70, 80,
            1, 8, 1, /* 408: pointer.struct.dsa_method.1040 */
            	413, 0,
            0, 96, 2, /* 413: struct.dsa_method.1040 */
            	70, 0,
            	70, 72,
            1, 8, 1, /* 420: pointer.struct.ecdh_method */
            	425, 0,
            0, 32, 2, /* 425: struct.ecdh_method */
            	70, 0,
            	70, 24,
            1, 8, 1, /* 432: pointer.struct.ecdsa_method */
            	437, 0,
            0, 48, 2, /* 437: struct.ecdsa_method */
            	70, 0,
            	70, 40,
            1, 8, 1, /* 444: pointer.struct.rand_meth_st */
            	449, 0,
            0, 48, 0, /* 449: struct.rand_meth_st */
            1, 8, 1, /* 452: pointer.struct.store_method_st */
            	457, 0,
            0, 0, 0, /* 457: struct.store_method_st */
            1, 8, 1, /* 460: pointer.struct.ENGINE_CMD_DEFN_st */
            	465, 0,
            0, 32, 2, /* 465: struct.ENGINE_CMD_DEFN_st */
            	70, 8,
            	70, 16,
            0, 16, 1, /* 472: struct.iovec */
            	70, 0,
            4097, 0, 0, /* 477: pointer.func */
            4097, 0, 0, /* 480: pointer.func */
            1, 8, 1, /* 483: pointer.struct.bn_blinding_st */
            	488, 0,
            0, 88, 6, /* 488: struct.bn_blinding_st */
            	269, 0,
            	269, 8,
            	269, 16,
            	269, 24,
            	472, 40,
            	311, 72,
            4097, 0, 0, /* 503: pointer.func */
            4097, 0, 0, /* 506: pointer.func */
            0, 8, 0, /* 509: array[2].int */
            0, 0, 0, /* 512: func */
            4097, 0, 0, /* 515: pointer.func */
            0, 0, 0, /* 518: func */
            0, 0, 0, /* 521: func */
            0, 168, 17, /* 524: struct.rsa_st */
            	396, 16,
            	362, 24,
            	269, 32,
            	269, 40,
            	269, 48,
            	269, 56,
            	269, 64,
            	269, 72,
            	269, 80,
            	269, 88,
            	325, 96,
            	311, 120,
            	311, 128,
            	311, 136,
            	70, 144,
            	483, 152,
            	483, 160,
            1, 8, 1, /* 561: pointer.struct.rsa_st */
            	524, 0,
            0, 0, 0, /* 566: func */
            0, 0, 0, /* 569: func */
            4097, 0, 0, /* 572: pointer.func */
            0, 0, 0, /* 575: func */
            0, 0, 0, /* 578: func */
            0, 0, 0, /* 581: func */
            4097, 0, 0, /* 584: pointer.func */
            0, 0, 0, /* 587: func */
            0, 32, 0, /* 590: array[32].char */
            1, 8, 1, /* 593: pointer.struct.in_addr */
            	598, 0,
            0, 4, 0, /* 598: struct.in_addr */
            4097, 0, 0, /* 601: pointer.func */
            4097, 0, 0, /* 604: pointer.func */
            0, 56, 4, /* 607: struct.evp_pkey_st */
            	618, 16,
            	362, 24,
            	640, 32,
            	330, 48,
            1, 8, 1, /* 618: pointer.struct.evp_pkey_asn1_method_st */
            	623, 0,
            0, 208, 3, /* 623: struct.evp_pkey_asn1_method_st */
            	70, 16,
            	70, 24,
            	632, 32,
            1, 8, 1, /* 632: pointer.struct.unnamed */
            	637, 0,
            0, 0, 0, /* 637: struct.unnamed */
            0, 8, 1, /* 640: struct.fnames */
            	70, 0,
            0, 0, 0, /* 645: func */
            0, 40, 3, /* 648: struct.X509_name_st */
            	330, 0,
            	657, 16,
            	70, 24,
            1, 8, 1, /* 657: pointer.struct.buf_mem_st */
            	662, 0,
            0, 24, 1, /* 662: struct.buf_mem_st */
            	70, 8,
            4097, 0, 0, /* 667: pointer.func */
            0, 0, 0, /* 670: func */
            4097, 0, 0, /* 673: pointer.func */
            0, 16, 1, /* 676: struct.asn1_type_st */
            	640, 8,
            0, 16, 2, /* 681: struct.X509_algor_st */
            	688, 0,
            	702, 8,
            1, 8, 1, /* 688: pointer.struct.asn1_object_st */
            	693, 0,
            0, 40, 3, /* 693: struct.asn1_object_st */
            	70, 0,
            	70, 8,
            	70, 24,
            1, 8, 1, /* 702: pointer.struct.asn1_type_st */
            	676, 0,
            0, 24, 1, /* 707: struct.asn1_string_st */
            	70, 8,
            1, 8, 1, /* 712: pointer.struct.asn1_string_st */
            	707, 0,
            0, 0, 0, /* 717: func */
            4097, 0, 0, /* 720: pointer.func */
            0, 184, 12, /* 723: struct.x509_st */
            	750, 0,
            	780, 8,
            	712, 16,
            	70, 32,
            	325, 40,
            	712, 104,
            	826, 112,
            	840, 120,
            	330, 128,
            	330, 136,
            	866, 144,
            	878, 176,
            1, 8, 1, /* 750: pointer.struct.x509_cinf_st */
            	755, 0,
            0, 104, 11, /* 755: struct.x509_cinf_st */
            	712, 0,
            	712, 8,
            	780, 16,
            	785, 24,
            	790, 32,
            	785, 40,
            	802, 48,
            	712, 56,
            	712, 64,
            	330, 72,
            	821, 80,
            1, 8, 1, /* 780: pointer.struct.X509_algor_st */
            	681, 0,
            1, 8, 1, /* 785: pointer.struct.X509_name_st */
            	648, 0,
            1, 8, 1, /* 790: pointer.struct.X509_val_st */
            	795, 0,
            0, 16, 2, /* 795: struct.X509_val_st */
            	712, 0,
            	712, 8,
            1, 8, 1, /* 802: pointer.struct.X509_pubkey_st */
            	807, 0,
            0, 24, 3, /* 807: struct.X509_pubkey_st */
            	780, 0,
            	712, 8,
            	816, 16,
            1, 8, 1, /* 816: pointer.struct.evp_pkey_st */
            	607, 0,
            0, 24, 1, /* 821: struct.ASN1_ENCODING_st */
            	70, 0,
            1, 8, 1, /* 826: pointer.struct.AUTHORITY_KEYID_st */
            	831, 0,
            0, 24, 3, /* 831: struct.AUTHORITY_KEYID_st */
            	712, 0,
            	330, 8,
            	712, 16,
            1, 8, 1, /* 840: pointer.struct.X509_POLICY_CACHE_st */
            	845, 0,
            0, 40, 2, /* 845: struct.X509_POLICY_CACHE_st */
            	852, 0,
            	330, 8,
            1, 8, 1, /* 852: pointer.struct.X509_POLICY_DATA_st */
            	857, 0,
            0, 32, 3, /* 857: struct.X509_POLICY_DATA_st */
            	688, 8,
            	330, 16,
            	330, 24,
            1, 8, 1, /* 866: pointer.struct.NAME_CONSTRAINTS_st */
            	871, 0,
            0, 16, 2, /* 871: struct.NAME_CONSTRAINTS_st */
            	330, 0,
            	330, 8,
            1, 8, 1, /* 878: pointer.struct.x509_cert_aux_st */
            	883, 0,
            0, 40, 5, /* 883: struct.x509_cert_aux_st */
            	330, 0,
            	330, 8,
            	712, 16,
            	712, 24,
            	330, 32,
            0, 0, 0, /* 896: func */
            0, 24, 0, /* 899: array[6].int */
            4097, 0, 0, /* 902: pointer.func */
            0, 248, 6, /* 905: struct.sess_cert_st */
            	330, 0,
            	920, 16,
            	947, 24,
            	561, 216,
            	279, 224,
            	274, 232,
            1, 8, 1, /* 920: pointer.struct.cert_pkey_st */
            	925, 0,
            0, 24, 3, /* 925: struct.cert_pkey_st */
            	934, 0,
            	816, 8,
            	939, 16,
            1, 8, 1, /* 934: pointer.struct.x509_st */
            	723, 0,
            1, 8, 1, /* 939: pointer.struct.env_md_st */
            	944, 0,
            0, 120, 0, /* 944: struct.env_md_st */
            0, 192, 8, /* 947: array[8].struct.cert_pkey_st */
            	925, 0,
            	925, 24,
            	925, 48,
            	925, 72,
            	925, 96,
            	925, 120,
            	925, 144,
            	925, 168,
            0, 0, 0, /* 966: func */
            0, 0, 0, /* 969: func */
            4097, 0, 0, /* 972: pointer.func */
            4097, 0, 0, /* 975: pointer.func */
            0, 8, 0, /* 978: array[8].char */
            0, 0, 0, /* 981: func */
            0, 0, 0, /* 984: func */
            4097, 0, 0, /* 987: pointer.func */
            0, 0, 0, /* 990: func */
            4097, 0, 0, /* 993: pointer.func */
            0, 0, 0, /* 996: func */
            0, 1, 0, /* 999: char */
            0, 0, 0, /* 1002: func */
            4097, 0, 0, /* 1005: pointer.func */
            4097, 0, 0, /* 1008: pointer.func */
            0, 0, 0, /* 1011: func */
            4097, 0, 0, /* 1014: pointer.func */
            4097, 0, 0, /* 1017: pointer.func */
            0, 0, 0, /* 1020: func */
            4097, 0, 0, /* 1023: pointer.func */
            4097, 0, 0, /* 1026: pointer.func */
            4097, 0, 0, /* 1029: pointer.func */
            0, 352, 14, /* 1032: struct.ssl_session_st */
            	70, 144,
            	70, 152,
            	1063, 168,
            	934, 176,
            	75, 224,
            	330, 240,
            	325, 248,
            	1068, 264,
            	1068, 272,
            	70, 280,
            	70, 296,
            	70, 312,
            	70, 320,
            	70, 344,
            1, 8, 1, /* 1063: pointer.struct.sess_cert_st */
            	905, 0,
            1, 8, 1, /* 1068: pointer.struct.ssl_session_st */
            	1032, 0,
            0, 0, 0, /* 1073: func */
            4097, 0, 0, /* 1076: pointer.func */
            4097, 0, 0, /* 1079: pointer.func */
            0, 56, 2, /* 1082: struct.X509_VERIFY_PARAM_st */
            	70, 0,
            	330, 48,
            4097, 0, 0, /* 1089: pointer.func */
            4097, 0, 0, /* 1092: pointer.func */
            0, 144, 4, /* 1095: struct.x509_store_st */
            	330, 8,
            	330, 16,
            	1106, 24,
            	325, 120,
            1, 8, 1, /* 1106: pointer.struct.X509_VERIFY_PARAM_st */
            	1082, 0,
            4097, 0, 0, /* 1111: pointer.func */
            4097, 0, 0, /* 1114: pointer.func */
            4097, 0, 0, /* 1117: pointer.func */
            0, 20, 0, /* 1120: array[5].int */
            4097, 0, 0, /* 1123: pointer.func */
            0, 0, 0, /* 1126: func */
            0, 0, 0, /* 1129: func */
            0, 0, 0, /* 1132: func */
            0, 8, 0, /* 1135: long */
            4097, 0, 0, /* 1138: pointer.func */
            4097, 0, 0, /* 1141: pointer.func */
            4097, 0, 0, /* 1144: pointer.func */
            4097, 0, 0, /* 1147: pointer.func */
            4097, 0, 0, /* 1150: pointer.func */
            0, 0, 0, /* 1153: func */
            4097, 0, 0, /* 1156: pointer.func */
            0, 0, 0, /* 1159: func */
            0, 0, 0, /* 1162: func */
            0, 0, 0, /* 1165: func */
            0, 0, 0, /* 1168: func */
            0, 0, 0, /* 1171: func */
            4097, 0, 0, /* 1174: pointer.func */
            4097, 0, 0, /* 1177: pointer.func */
            0, 0, 0, /* 1180: func */
            4097, 0, 0, /* 1183: pointer.func */
            0, 0, 0, /* 1186: func */
            4097, 0, 0, /* 1189: pointer.func */
            4097, 0, 0, /* 1192: pointer.func */
            4097, 0, 0, /* 1195: pointer.func */
            0, 0, 0, /* 1198: func */
            4097, 0, 0, /* 1201: pointer.func */
            0, 0, 0, /* 1204: func */
            0, 0, 0, /* 1207: func */
            1, 8, 1, /* 1210: pointer.struct.x509_store_st */
            	1095, 0,
            4097, 0, 0, /* 1215: pointer.func */
            0, 0, 0, /* 1218: func */
            0, 0, 0, /* 1221: func */
            0, 0, 0, /* 1224: func */
            4097, 0, 0, /* 1227: pointer.func */
            4097, 0, 0, /* 1230: pointer.func */
            4097, 0, 0, /* 1233: pointer.func */
            0, 0, 0, /* 1236: func */
            0, 0, 0, /* 1239: func */
            0, 0, 0, /* 1242: func */
            0, 0, 0, /* 1245: func */
            4097, 0, 0, /* 1248: pointer.func */
            4097, 0, 0, /* 1251: pointer.func */
            4097, 0, 0, /* 1254: pointer.func */
            0, 0, 0, /* 1257: func */
            0, 0, 0, /* 1260: func */
            0, 0, 0, /* 1263: func */
            0, 232, 1, /* 1266: struct.ssl_method_st.924 */
            	1271, 200,
            1, 8, 1, /* 1271: pointer.struct.ssl3_enc_method.923 */
            	1276, 0,
            0, 112, 2, /* 1276: struct.ssl3_enc_method.923 */
            	70, 64,
            	70, 80,
            0, 0, 0, /* 1283: func */
            0, 0, 0, /* 1286: func */
            4097, 0, 0, /* 1289: pointer.func */
            4097, 0, 0, /* 1292: pointer.func */
            4097, 0, 0, /* 1295: pointer.func */
            0, 0, 0, /* 1298: func */
            0, 0, 0, /* 1301: func */
            4097, 0, 0, /* 1304: pointer.func */
            0, 128, 11, /* 1307: struct.srp_ctx_st.921 */
            	70, 0,
            	70, 32,
            	269, 40,
            	269, 48,
            	269, 56,
            	269, 64,
            	269, 72,
            	269, 80,
            	269, 88,
            	269, 96,
            	70, 104,
            4097, 0, 0, /* 1332: pointer.func */
            0, 0, 0, /* 1335: func */
            0, 0, 0, /* 1338: func */
            0, 296, 5, /* 1341: struct.cert_st.915 */
            	920, 0,
            	561, 48,
            	279, 64,
            	274, 80,
            	947, 96,
            0, 48, 0, /* 1354: array[48].char */
            0, 0, 0, /* 1357: func */
            4097, 0, 0, /* 1360: pointer.func */
            0, 0, 0, /* 1363: func */
            4097, 0, 0, /* 1366: pointer.func */
            0, 0, 0, /* 1369: func */
            4097, 0, 0, /* 1372: pointer.func */
            4097, 0, 0, /* 1375: pointer.func */
            4097, 0, 0, /* 1378: pointer.func */
            0, 0, 0, /* 1381: func */
            4097, 0, 0, /* 1384: pointer.func */
            4097, 0, 0, /* 1387: pointer.func */
            0, 0, 0, /* 1390: func */
            4097, 0, 0, /* 1393: pointer.func */
            0, 0, 0, /* 1396: func */
            4097, 0, 0, /* 1399: pointer.func */
            4097, 0, 0, /* 1402: pointer.func */
            0, 0, 0, /* 1405: func */
            4097, 0, 0, /* 1408: pointer.func */
            4097, 0, 0, /* 1411: pointer.func */
            4097, 0, 0, /* 1414: pointer.func */
            0, 0, 0, /* 1417: func */
            4097, 0, 0, /* 1420: pointer.func */
            0, 0, 0, /* 1423: func */
            0, 0, 0, /* 1426: func */
            0, 0, 0, /* 1429: func */
            0, 0, 0, /* 1432: func */
            0, 0, 0, /* 1435: func */
            0, 0, 0, /* 1438: func */
            0, 0, 0, /* 1441: func */
            4097, 0, 0, /* 1444: pointer.func */
            0, 0, 0, /* 1447: func */
            4097, 0, 0, /* 1450: pointer.func */
            4097, 0, 0, /* 1453: pointer.func */
            0, 0, 0, /* 1456: func */
            4097, 0, 0, /* 1459: pointer.func */
            0, 20, 0, /* 1462: array[20].char */
            4097, 0, 0, /* 1465: pointer.func */
            4097, 0, 0, /* 1468: pointer.func */
            0, 0, 0, /* 1471: func */
            0, 0, 0, /* 1474: func */
            4097, 0, 0, /* 1477: pointer.func */
            4097, 0, 0, /* 1480: pointer.func */
            4097, 0, 0, /* 1483: pointer.func */
            4097, 0, 0, /* 1486: pointer.func */
            4097, 0, 0, /* 1489: pointer.func */
            0, 0, 0, /* 1492: func */
            4097, 0, 0, /* 1495: pointer.func */
            0, 0, 0, /* 1498: func */
            1, 8, 1, /* 1501: pointer.struct.ssl_ctx_st.922 */
            	1506, 0,
            0, 736, 30, /* 1506: struct.ssl_ctx_st.922 */
            	1569, 0,
            	330, 8,
            	330, 16,
            	1210, 24,
            	593, 32,
            	1068, 48,
            	1068, 56,
            	70, 160,
            	70, 176,
            	325, 208,
            	939, 224,
            	939, 232,
            	939, 240,
            	330, 248,
            	330, 256,
            	330, 272,
            	1574, 304,
            	70, 328,
            	1106, 392,
            	362, 408,
            	70, 424,
            	70, 496,
            	70, 512,
            	70, 520,
            	31, 552,
            	31, 560,
            	1307, 568,
            	70, 704,
            	70, 720,
            	330, 728,
            1, 8, 1, /* 1569: pointer.struct.ssl_method_st.924 */
            	1266, 0,
            1, 8, 1, /* 1574: pointer.struct.cert_st.915 */
            	1341, 0,
            4097, 0, 0, /* 1579: pointer.func */
            4097, 0, 0, /* 1582: pointer.func */
            0, 0, 0, /* 1585: func */
            4097, 0, 0, /* 1588: pointer.func */
            0, 0, 0, /* 1591: func */
            4097, 0, 0, /* 1594: pointer.func */
            0, 0, 0, /* 1597: func */
            4097, 0, 0, /* 1600: pointer.func */
            0, 0, 0, /* 1603: func */
            0, 0, 0, /* 1606: func */
            4097, 0, 0, /* 1609: pointer.func */
            4097, 0, 0, /* 1612: pointer.func */
            0, 0, 0, /* 1615: func */
            4097, 0, 0, /* 1618: pointer.func */
            0, 0, 0, /* 1621: func */
            4097, 0, 0, /* 1624: pointer.func */
            4097, 0, 0, /* 1627: pointer.func */
            4097, 0, 0, /* 1630: pointer.func */
            4097, 0, 0, /* 1633: pointer.func */
            4097, 0, 0, /* 1636: pointer.func */
            0, 0, 0, /* 1639: func */
            4097, 0, 0, /* 1642: pointer.func */
            0, 0, 0, /* 1645: func */
            0, 0, 0, /* 1648: func */
            0, 0, 0, /* 1651: func */
            4097, 0, 0, /* 1654: pointer.func */
            0, 0, 0, /* 1657: func */
            0, 0, 0, /* 1660: func */
            4097, 0, 0, /* 1663: pointer.func */
            0, 0, 0, /* 1666: func */
            4097, 0, 0, /* 1669: pointer.func */
            4097, 0, 0, /* 1672: pointer.func */
            0, 0, 0, /* 1675: func */
            4097, 0, 0, /* 1678: pointer.func */
            0, 0, 0, /* 1681: func */
            4097, 0, 0, /* 1684: pointer.func */
            4097, 0, 0, /* 1687: pointer.func */
            4097, 0, 0, /* 1690: pointer.func */
            4097, 0, 0, /* 1693: pointer.func */
            4097, 0, 0, /* 1696: pointer.func */
            0, 0, 0, /* 1699: func */
            0, 0, 0, /* 1702: func */
            0, 0, 0, /* 1705: func */
            0, 0, 0, /* 1708: func */
            0, 0, 0, /* 1711: func */
            0, 0, 0, /* 1714: func */
            0, 0, 0, /* 1717: func */
            4097, 0, 0, /* 1720: pointer.func */
            0, 0, 0, /* 1723: func */
            0, 0, 0, /* 1726: func */
            4097, 0, 0, /* 1729: pointer.func */
            4097, 0, 0, /* 1732: pointer.func */
            0, 0, 0, /* 1735: func */
            0, 0, 0, /* 1738: func */
            0, 0, 0, /* 1741: func */
        },
        .arg_entity_index = { 1501, 1135, },
        .ret_entity_index = 1135,
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

