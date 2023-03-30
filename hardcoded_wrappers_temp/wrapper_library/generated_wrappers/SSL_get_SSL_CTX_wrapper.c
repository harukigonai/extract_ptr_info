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

SSL_CTX * bb_SSL_get_SSL_CTX(const SSL * arg_a);

SSL_CTX * SSL_get_SSL_CTX(const SSL * arg_a) 
{
    printf("SSL_get_SSL_CTX called\n");
    if (!syscall(890))
        return bb_SSL_get_SSL_CTX(arg_a);
    else {
        SSL_CTX * (*orig_SSL_get_SSL_CTX)(const SSL *);
        orig_SSL_get_SSL_CTX = dlsym(RTLD_NEXT, "SSL_get_SSL_CTX");
        return orig_SSL_get_SSL_CTX(arg_a);
    }
}

SSL_CTX * bb_SSL_get_SSL_CTX(const SSL * arg_a) 
{
    SSL_CTX * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 8, 0, /* 3: pointer.func */
            0, 16, 1, /* 6: struct.tls_session_ticket_ext_st */
            	11, 8,
            1, 8, 1, /* 11: pointer.char */
            	16, 0,
            0, 1, 0, /* 16: char */
            0, 8, 0, /* 19: pointer.func */
            0, 12, 0, /* 22: struct.ap_unix_identity_t */
            0, 56, 2, /* 25: struct.comp_ctx_st */
            	32, 0,
            	42, 40,
            1, 8, 1, /* 32: pointer.struct.comp_method_st */
            	37, 0,
            0, 64, 1, /* 37: struct.comp_method_st */
            	11, 8,
            0, 16, 1, /* 42: struct.crypto_ex_data_st */
            	47, 0,
            1, 8, 1, /* 47: pointer.struct.stack_st_OPENSSL_STRING */
            	52, 0,
            0, 32, 1, /* 52: struct.stack_st_OPENSSL_STRING */
            	57, 0,
            0, 32, 1, /* 57: struct.stack_st */
            	62, 8,
            1, 8, 1, /* 62: pointer.pointer.char */
            	11, 0,
            0, 168, 4, /* 67: struct.evp_cipher_ctx_st */
            	78, 0,
            	88, 8,
            	11, 96,
            	11, 120,
            1, 8, 1, /* 78: pointer.struct.evp_cipher_st */
            	83, 0,
            0, 88, 1, /* 83: struct.evp_cipher_st */
            	11, 80,
            1, 8, 1, /* 88: pointer.struct.engine_st */
            	93, 0,
            0, 216, 13, /* 93: struct.engine_st */
            	11, 0,
            	11, 8,
            	122, 16,
            	134, 24,
            	146, 32,
            	158, 40,
            	170, 48,
            	182, 56,
            	190, 64,
            	198, 160,
            	42, 184,
            	88, 200,
            	88, 208,
            1, 8, 1, /* 122: pointer.struct.rsa_meth_st */
            	127, 0,
            0, 112, 2, /* 127: struct.rsa_meth_st */
            	11, 0,
            	11, 80,
            1, 8, 1, /* 134: pointer.struct.dsa_method.1040 */
            	139, 0,
            0, 96, 2, /* 139: struct.dsa_method.1040 */
            	11, 0,
            	11, 72,
            1, 8, 1, /* 146: pointer.struct.dh_method */
            	151, 0,
            0, 72, 2, /* 151: struct.dh_method */
            	11, 0,
            	11, 56,
            1, 8, 1, /* 158: pointer.struct.ecdh_method */
            	163, 0,
            0, 32, 2, /* 163: struct.ecdh_method */
            	11, 0,
            	11, 24,
            1, 8, 1, /* 170: pointer.struct.ecdsa_method */
            	175, 0,
            0, 48, 2, /* 175: struct.ecdsa_method */
            	11, 0,
            	11, 40,
            1, 8, 1, /* 182: pointer.struct.rand_meth_st */
            	187, 0,
            0, 48, 0, /* 187: struct.rand_meth_st */
            1, 8, 1, /* 190: pointer.struct.store_method_st */
            	195, 0,
            0, 0, 0, /* 195: struct.store_method_st */
            1, 8, 1, /* 198: pointer.struct.ENGINE_CMD_DEFN_st */
            	203, 0,
            0, 32, 2, /* 203: struct.ENGINE_CMD_DEFN_st */
            	11, 8,
            	11, 16,
            1, 8, 1, /* 210: pointer.struct.evp_cipher_ctx_st */
            	67, 0,
            0, 40, 4, /* 215: struct.dtls1_retransmit_state */
            	210, 0,
            	226, 8,
            	351, 16,
            	356, 24,
            1, 8, 1, /* 226: pointer.struct.env_md_ctx_st */
            	231, 0,
            0, 48, 4, /* 231: struct.env_md_ctx_st */
            	242, 0,
            	88, 8,
            	11, 24,
            	250, 32,
            1, 8, 1, /* 242: pointer.struct.env_md_st */
            	247, 0,
            0, 120, 0, /* 247: struct.env_md_st */
            1, 8, 1, /* 250: pointer.struct.evp_pkey_ctx_st */
            	255, 0,
            0, 80, 8, /* 255: struct.evp_pkey_ctx_st */
            	274, 0,
            	88, 8,
            	308, 16,
            	308, 24,
            	11, 40,
            	11, 48,
            	300, 56,
            	343, 64,
            1, 8, 1, /* 274: pointer.struct.evp_pkey_method_st */
            	279, 0,
            0, 208, 9, /* 279: struct.evp_pkey_method_st */
            	300, 8,
            	300, 32,
            	300, 48,
            	300, 64,
            	300, 80,
            	300, 96,
            	300, 144,
            	300, 160,
            	300, 176,
            1, 8, 1, /* 300: pointer.struct.unnamed */
            	305, 0,
            0, 0, 0, /* 305: struct.unnamed */
            1, 8, 1, /* 308: pointer.struct.evp_pkey_st */
            	313, 0,
            0, 56, 4, /* 313: struct.evp_pkey_st */
            	324, 16,
            	88, 24,
            	338, 32,
            	47, 48,
            1, 8, 1, /* 324: pointer.struct.evp_pkey_asn1_method_st */
            	329, 0,
            0, 208, 3, /* 329: struct.evp_pkey_asn1_method_st */
            	11, 16,
            	11, 24,
            	300, 32,
            0, 8, 1, /* 338: struct.fnames */
            	11, 0,
            1, 8, 1, /* 343: pointer.int */
            	348, 0,
            0, 4, 0, /* 348: int */
            1, 8, 1, /* 351: pointer.struct.comp_ctx_st */
            	25, 0,
            1, 8, 1, /* 356: pointer.struct.ssl_session_st */
            	361, 0,
            0, 352, 14, /* 361: struct.ssl_session_st */
            	11, 144,
            	11, 152,
            	392, 168,
            	426, 176,
            	883, 224,
            	47, 240,
            	42, 248,
            	356, 264,
            	356, 272,
            	11, 280,
            	11, 296,
            	11, 312,
            	11, 320,
            	11, 344,
            1, 8, 1, /* 392: pointer.struct.sess_cert_st */
            	397, 0,
            0, 248, 6, /* 397: struct.sess_cert_st */
            	47, 0,
            	412, 16,
            	659, 24,
            	678, 216,
            	769, 224,
            	801, 232,
            1, 8, 1, /* 412: pointer.struct.cert_pkey_st */
            	417, 0,
            0, 24, 3, /* 417: struct.cert_pkey_st */
            	426, 0,
            	308, 8,
            	242, 16,
            1, 8, 1, /* 426: pointer.struct.x509_st */
            	431, 0,
            0, 184, 12, /* 431: struct.x509_st */
            	458, 0,
            	498, 8,
            	488, 16,
            	11, 32,
            	42, 40,
            	488, 104,
            	589, 112,
            	603, 120,
            	47, 128,
            	47, 136,
            	629, 144,
            	641, 176,
            1, 8, 1, /* 458: pointer.struct.x509_cinf_st */
            	463, 0,
            0, 104, 11, /* 463: struct.x509_cinf_st */
            	488, 0,
            	488, 8,
            	498, 16,
            	534, 24,
            	558, 32,
            	534, 40,
            	570, 48,
            	488, 56,
            	488, 64,
            	47, 72,
            	584, 80,
            1, 8, 1, /* 488: pointer.struct.asn1_string_st */
            	493, 0,
            0, 24, 1, /* 493: struct.asn1_string_st */
            	11, 8,
            1, 8, 1, /* 498: pointer.struct.X509_algor_st */
            	503, 0,
            0, 16, 2, /* 503: struct.X509_algor_st */
            	510, 0,
            	524, 8,
            1, 8, 1, /* 510: pointer.struct.asn1_object_st */
            	515, 0,
            0, 40, 3, /* 515: struct.asn1_object_st */
            	11, 0,
            	11, 8,
            	11, 24,
            1, 8, 1, /* 524: pointer.struct.asn1_type_st */
            	529, 0,
            0, 16, 1, /* 529: struct.asn1_type_st */
            	338, 8,
            1, 8, 1, /* 534: pointer.struct.X509_name_st */
            	539, 0,
            0, 40, 3, /* 539: struct.X509_name_st */
            	47, 0,
            	548, 16,
            	11, 24,
            1, 8, 1, /* 548: pointer.struct.buf_mem_st */
            	553, 0,
            0, 24, 1, /* 553: struct.buf_mem_st */
            	11, 8,
            1, 8, 1, /* 558: pointer.struct.X509_val_st */
            	563, 0,
            0, 16, 2, /* 563: struct.X509_val_st */
            	488, 0,
            	488, 8,
            1, 8, 1, /* 570: pointer.struct.X509_pubkey_st */
            	575, 0,
            0, 24, 3, /* 575: struct.X509_pubkey_st */
            	498, 0,
            	488, 8,
            	308, 16,
            0, 24, 1, /* 584: struct.ASN1_ENCODING_st */
            	11, 0,
            1, 8, 1, /* 589: pointer.struct.AUTHORITY_KEYID_st */
            	594, 0,
            0, 24, 3, /* 594: struct.AUTHORITY_KEYID_st */
            	488, 0,
            	47, 8,
            	488, 16,
            1, 8, 1, /* 603: pointer.struct.X509_POLICY_CACHE_st */
            	608, 0,
            0, 40, 2, /* 608: struct.X509_POLICY_CACHE_st */
            	615, 0,
            	47, 8,
            1, 8, 1, /* 615: pointer.struct.X509_POLICY_DATA_st */
            	620, 0,
            0, 32, 3, /* 620: struct.X509_POLICY_DATA_st */
            	510, 8,
            	47, 16,
            	47, 24,
            1, 8, 1, /* 629: pointer.struct.NAME_CONSTRAINTS_st */
            	634, 0,
            0, 16, 2, /* 634: struct.NAME_CONSTRAINTS_st */
            	47, 0,
            	47, 8,
            1, 8, 1, /* 641: pointer.struct.x509_cert_aux_st */
            	646, 0,
            0, 40, 5, /* 646: struct.x509_cert_aux_st */
            	47, 0,
            	47, 8,
            	488, 16,
            	488, 24,
            	47, 32,
            0, 192, 8, /* 659: array[8].struct.cert_pkey_st */
            	417, 0,
            	417, 24,
            	417, 48,
            	417, 72,
            	417, 96,
            	417, 120,
            	417, 144,
            	417, 168,
            1, 8, 1, /* 678: pointer.struct.rsa_st */
            	683, 0,
            0, 168, 17, /* 683: struct.rsa_st */
            	122, 16,
            	88, 24,
            	720, 32,
            	720, 40,
            	720, 48,
            	720, 56,
            	720, 64,
            	720, 72,
            	720, 80,
            	720, 88,
            	42, 96,
            	730, 120,
            	730, 128,
            	730, 136,
            	11, 144,
            	744, 152,
            	744, 160,
            1, 8, 1, /* 720: pointer.struct.bignum_st */
            	725, 0,
            0, 24, 1, /* 725: struct.bignum_st */
            	343, 0,
            1, 8, 1, /* 730: pointer.struct.bn_mont_ctx_st */
            	735, 0,
            0, 96, 3, /* 735: struct.bn_mont_ctx_st */
            	725, 8,
            	725, 32,
            	725, 56,
            1, 8, 1, /* 744: pointer.struct.bn_blinding_st */
            	749, 0,
            0, 88, 6, /* 749: struct.bn_blinding_st */
            	720, 0,
            	720, 8,
            	720, 16,
            	720, 24,
            	764, 40,
            	730, 72,
            0, 16, 1, /* 764: struct.iovec */
            	11, 0,
            1, 8, 1, /* 769: pointer.struct.dh_st */
            	774, 0,
            0, 144, 12, /* 774: struct.dh_st */
            	720, 8,
            	720, 16,
            	720, 32,
            	720, 40,
            	730, 56,
            	720, 64,
            	720, 72,
            	11, 80,
            	720, 96,
            	42, 112,
            	146, 128,
            	88, 136,
            1, 8, 1, /* 801: pointer.struct.ec_key_st.284 */
            	806, 0,
            0, 56, 4, /* 806: struct.ec_key_st.284 */
            	817, 8,
            	855, 16,
            	720, 24,
            	871, 48,
            1, 8, 1, /* 817: pointer.struct.ec_group_st */
            	822, 0,
            0, 232, 11, /* 822: struct.ec_group_st */
            	847, 0,
            	855, 8,
            	725, 16,
            	725, 40,
            	11, 80,
            	871, 96,
            	725, 104,
            	725, 152,
            	725, 176,
            	11, 208,
            	11, 216,
            1, 8, 1, /* 847: pointer.struct.ec_method_st */
            	852, 0,
            0, 304, 0, /* 852: struct.ec_method_st */
            1, 8, 1, /* 855: pointer.struct.ec_point_st */
            	860, 0,
            0, 88, 4, /* 860: struct.ec_point_st */
            	847, 0,
            	725, 8,
            	725, 32,
            	725, 56,
            1, 8, 1, /* 871: pointer.struct.ec_extra_data_st */
            	876, 0,
            0, 40, 2, /* 876: struct.ec_extra_data_st */
            	871, 0,
            	11, 8,
            1, 8, 1, /* 883: pointer.struct.ssl_cipher_st */
            	888, 0,
            0, 88, 1, /* 888: struct.ssl_cipher_st */
            	11, 8,
            0, 88, 1, /* 893: struct.hm_header_st */
            	215, 48,
            0, 24, 2, /* 898: struct._pitem */
            	11, 8,
            	905, 16,
            1, 8, 1, /* 905: pointer.struct._pitem */
            	898, 0,
            0, 16, 1, /* 910: struct.record_pqueue_st */
            	915, 8,
            1, 8, 1, /* 915: pointer.struct._pqueue */
            	920, 0,
            0, 16, 1, /* 920: struct._pqueue */
            	905, 0,
            0, 16, 0, /* 925: union.anon.142 */
            1, 8, 1, /* 928: pointer.struct.dtls1_state_st */
            	933, 0,
            0, 888, 7, /* 933: struct.dtls1_state_st */
            	910, 576,
            	910, 592,
            	915, 608,
            	915, 616,
            	910, 624,
            	893, 648,
            	893, 736,
            0, 0, 0, /* 950: func */
            0, 24, 2, /* 953: struct.ssl_comp_st */
            	11, 8,
            	32, 16,
            0, 8, 0, /* 960: pointer.func */
            0, 0, 0, /* 963: func */
            0, 8, 0, /* 966: pointer.func */
            0, 0, 0, /* 969: func */
            0, 8, 0, /* 972: pointer.func */
            0, 0, 0, /* 975: func */
            0, 0, 0, /* 978: func */
            0, 8, 0, /* 981: pointer.func */
            0, 9, 0, /* 984: array[9].char */
            0, 128, 0, /* 987: array[128].char */
            0, 0, 0, /* 990: func */
            0, 0, 0, /* 993: func */
            0, 0, 0, /* 996: func */
            0, 8, 0, /* 999: pointer.func */
            0, 8, 0, /* 1002: pointer.func */
            0, 0, 0, /* 1005: func */
            0, 0, 0, /* 1008: func */
            0, 0, 0, /* 1011: func */
            0, 0, 0, /* 1014: func */
            0, 8, 0, /* 1017: pointer.func */
            0, 0, 0, /* 1020: func */
            0, 8, 0, /* 1023: pointer.func */
            0, 8, 0, /* 1026: pointer.func */
            0, 4, 0, /* 1029: array[4].char */
            0, 56, 3, /* 1032: struct.ssl3_record_st */
            	11, 16,
            	11, 24,
            	11, 32,
            0, 64, 0, /* 1041: array[64].char */
            0, 1200, 10, /* 1044: struct.ssl3_state_st */
            	1067, 240,
            	1067, 264,
            	1032, 288,
            	1032, 344,
            	11, 432,
            	1072, 440,
            	1102, 448,
            	11, 496,
            	11, 512,
            	1107, 528,
            0, 24, 1, /* 1067: struct.ssl3_buffer_st */
            	11, 0,
            1, 8, 1, /* 1072: pointer.struct.bio_st */
            	1077, 0,
            0, 112, 6, /* 1077: struct.bio_st */
            	1092, 0,
            	11, 16,
            	11, 48,
            	1072, 56,
            	1072, 64,
            	42, 96,
            1, 8, 1, /* 1092: pointer.struct.bio_method_st */
            	1097, 0,
            0, 80, 1, /* 1097: struct.bio_method_st */
            	11, 8,
            1, 8, 1, /* 1102: pointer.pointer.struct.env_md_ctx_st */
            	226, 0,
            0, 528, 8, /* 1107: struct.anon.0 */
            	883, 408,
            	769, 416,
            	801, 424,
            	47, 464,
            	11, 480,
            	78, 488,
            	242, 496,
            	1126, 512,
            1, 8, 1, /* 1126: pointer.struct.ssl_comp_st */
            	953, 0,
            1, 8, 1, /* 1131: pointer.struct.ssl3_state_st */
            	1044, 0,
            0, 344, 9, /* 1136: struct.ssl2_state_st */
            	11, 24,
            	11, 56,
            	11, 64,
            	11, 72,
            	11, 104,
            	11, 112,
            	11, 120,
            	11, 128,
            	11, 136,
            0, 8, 0, /* 1157: pointer.func */
            0, 0, 0, /* 1160: func */
            0, 8, 0, /* 1163: pointer.func */
            0, 0, 0, /* 1166: func */
            0, 8, 0, /* 1169: pointer.func */
            0, 0, 0, /* 1172: func */
            0, 0, 0, /* 1175: func */
            0, 8, 0, /* 1178: pointer.func */
            0, 0, 0, /* 1181: func */
            0, 8, 0, /* 1184: pointer.func */
            0, 0, 0, /* 1187: func */
            0, 8, 0, /* 1190: pointer.func */
            0, 0, 0, /* 1193: func */
            0, 8, 0, /* 1196: pointer.func */
            0, 0, 0, /* 1199: func */
            0, 8, 0, /* 1202: pointer.func */
            0, 0, 0, /* 1205: func */
            0, 8, 0, /* 1208: pointer.func */
            0, 0, 0, /* 1211: func */
            0, 8, 0, /* 1214: pointer.func */
            0, 16, 0, /* 1217: array[16].char */
            0, 0, 0, /* 1220: func */
            0, 8, 0, /* 1223: pointer.func */
            0, 0, 0, /* 1226: func */
            0, 0, 0, /* 1229: func */
            0, 8, 0, /* 1232: pointer.func */
            0, 0, 0, /* 1235: func */
            0, 0, 0, /* 1238: func */
            0, 8, 0, /* 1241: pointer.func */
            0, 8, 0, /* 1244: pointer.func */
            1, 8, 1, /* 1247: pointer.struct.ssl3_buf_freelist_entry_st */
            	1252, 0,
            0, 8, 1, /* 1252: struct.ssl3_buf_freelist_entry_st */
            	1247, 0,
            0, 0, 0, /* 1257: func */
            0, 8, 0, /* 1260: pointer.func */
            0, 8, 0, /* 1263: pointer.func */
            0, 296, 5, /* 1266: struct.cert_st.745 */
            	412, 0,
            	678, 48,
            	769, 64,
            	801, 80,
            	659, 96,
            1, 8, 1, /* 1279: pointer.struct.cert_st.745 */
            	1266, 0,
            0, 0, 0, /* 1284: func */
            0, 8, 0, /* 1287: pointer.func */
            0, 0, 0, /* 1290: func */
            0, 8, 0, /* 1293: pointer.func */
            0, 44, 0, /* 1296: struct.apr_time_exp_t */
            0, 0, 0, /* 1299: func */
            0, 8, 0, /* 1302: pointer.func */
            0, 24, 0, /* 1305: array[6].int */
            0, 8, 0, /* 1308: pointer.func */
            0, 0, 0, /* 1311: func */
            0, 8, 0, /* 1314: pointer.func */
            0, 0, 0, /* 1317: func */
            0, 8, 0, /* 1320: pointer.func */
            0, 0, 0, /* 1323: func */
            0, 0, 0, /* 1326: func */
            0, 8, 0, /* 1329: pointer.func */
            0, 8, 0, /* 1332: pointer.func */
            0, 0, 0, /* 1335: func */
            0, 8, 0, /* 1338: pointer.func */
            0, 0, 0, /* 1341: func */
            0, 8, 0, /* 1344: pointer.func */
            0, 0, 0, /* 1347: func */
            0, 0, 0, /* 1350: func */
            0, 0, 0, /* 1353: func */
            0, 8, 0, /* 1356: pointer.func */
            0, 8, 0, /* 1359: pointer.func */
            0, 0, 0, /* 1362: func */
            0, 8, 0, /* 1365: pointer.func */
            0, 8, 0, /* 1368: pointer.func */
            0, 0, 0, /* 1371: func */
            0, 8, 0, /* 1374: pointer.func */
            0, 8, 0, /* 1377: pointer.func */
            1, 8, 1, /* 1380: pointer.struct.ssl_st.776 */
            	1385, 0,
            0, 808, 41, /* 1385: struct.ssl_st.776 */
            	1470, 8,
            	1072, 16,
            	1072, 24,
            	1072, 32,
            	548, 80,
            	11, 88,
            	11, 104,
            	1496, 120,
            	1131, 128,
            	928, 136,
            	11, 160,
            	1501, 176,
            	47, 184,
            	47, 192,
            	210, 208,
            	226, 216,
            	351, 224,
            	210, 232,
            	226, 240,
            	351, 248,
            	1279, 256,
            	356, 304,
            	1513, 368,
            	42, 392,
            	47, 408,
            	11, 472,
            	11, 480,
            	47, 504,
            	47, 512,
            	11, 520,
            	11, 544,
            	11, 560,
            	11, 568,
            	1640, 584,
            	11, 600,
            	11, 616,
            	1513, 624,
            	11, 632,
            	47, 648,
            	1645, 656,
            	1615, 680,
            1, 8, 1, /* 1470: pointer.struct.ssl_method_st.754 */
            	1475, 0,
            0, 232, 1, /* 1475: struct.ssl_method_st.754 */
            	1480, 200,
            1, 8, 1, /* 1480: pointer.struct.ssl3_enc_method.753 */
            	1485, 0,
            0, 112, 4, /* 1485: struct.ssl3_enc_method.753 */
            	300, 0,
            	300, 32,
            	11, 64,
            	11, 80,
            1, 8, 1, /* 1496: pointer.struct.ssl2_state_st */
            	1136, 0,
            1, 8, 1, /* 1501: pointer.struct.X509_VERIFY_PARAM_st */
            	1506, 0,
            0, 56, 2, /* 1506: struct.X509_VERIFY_PARAM_st */
            	11, 0,
            	47, 48,
            1, 8, 1, /* 1513: pointer.struct.ssl_ctx_st.752 */
            	1518, 0,
            0, 736, 30, /* 1518: struct.ssl_ctx_st.752 */
            	1470, 0,
            	47, 8,
            	47, 16,
            	1581, 24,
            	1597, 32,
            	356, 48,
            	356, 56,
            	11, 160,
            	11, 176,
            	42, 208,
            	242, 224,
            	242, 232,
            	242, 240,
            	47, 248,
            	47, 256,
            	47, 272,
            	1279, 304,
            	11, 328,
            	1501, 392,
            	88, 408,
            	11, 424,
            	11, 496,
            	11, 512,
            	11, 520,
            	1605, 552,
            	1605, 560,
            	1615, 568,
            	11, 704,
            	11, 720,
            	47, 728,
            1, 8, 1, /* 1581: pointer.struct.x509_store_st */
            	1586, 0,
            0, 144, 4, /* 1586: struct.x509_store_st */
            	47, 8,
            	47, 16,
            	1501, 24,
            	42, 120,
            1, 8, 1, /* 1597: pointer.struct.in_addr */
            	1602, 0,
            0, 4, 0, /* 1602: struct.in_addr */
            1, 8, 1, /* 1605: pointer.struct.ssl3_buf_freelist_st */
            	1610, 0,
            0, 24, 1, /* 1610: struct.ssl3_buf_freelist_st */
            	1247, 16,
            0, 128, 11, /* 1615: struct.srp_ctx_st.751 */
            	11, 0,
            	11, 32,
            	720, 40,
            	720, 48,
            	720, 56,
            	720, 64,
            	720, 72,
            	720, 80,
            	720, 88,
            	720, 96,
            	11, 104,
            1, 8, 1, /* 1640: pointer.struct.tls_session_ticket_ext_st */
            	6, 0,
            1, 8, 1, /* 1645: pointer.struct.iovec */
            	764, 0,
            0, 0, 0, /* 1650: func */
            0, 8, 0, /* 1653: pointer.func */
            0, 8, 0, /* 1656: pointer.func */
            0, 0, 0, /* 1659: func */
            0, 8, 0, /* 1662: pointer.func */
            0, 0, 0, /* 1665: func */
            0, 0, 0, /* 1668: func */
            0, 0, 0, /* 1671: func */
            0, 8, 0, /* 1674: pointer.func */
            0, 0, 0, /* 1677: func */
            0, 8, 0, /* 1680: pointer.func */
            0, 8, 0, /* 1683: pointer.func */
            0, 8, 0, /* 1686: pointer.func */
            0, 8, 0, /* 1689: array[2].int */
            0, 8, 0, /* 1692: pointer.func */
            0, 0, 0, /* 1695: func */
            0, 0, 0, /* 1698: func */
            0, 8, 0, /* 1701: pointer.func */
            0, 0, 0, /* 1704: func */
            0, 0, 0, /* 1707: func */
            0, 8, 0, /* 1710: pointer.func */
            0, 0, 0, /* 1713: func */
            0, 8, 0, /* 1716: pointer.func */
            0, 0, 0, /* 1719: func */
            0, 0, 0, /* 1722: func */
            0, 8, 0, /* 1725: pointer.func */
            0, 8, 0, /* 1728: pointer.func */
            0, 0, 0, /* 1731: func */
            0, 8, 0, /* 1734: pointer.func */
            0, 8, 0, /* 1737: pointer.func */
            0, 0, 0, /* 1740: func */
            0, 8, 0, /* 1743: pointer.func */
            0, 8, 0, /* 1746: pointer.func */
            0, 0, 0, /* 1749: func */
            0, 0, 0, /* 1752: func */
            0, 0, 0, /* 1755: func */
            0, 8, 0, /* 1758: pointer.func */
            0, 8, 0, /* 1761: pointer.func */
            0, 8, 0, /* 1764: pointer.func */
            0, 0, 0, /* 1767: func */
            0, 8, 0, /* 1770: pointer.func */
            0, 8, 0, /* 1773: pointer.func */
            0, 8, 0, /* 1776: pointer.func */
            0, 8, 0, /* 1779: pointer.func */
            0, 8, 0, /* 1782: pointer.func */
            0, 8, 0, /* 1785: pointer.func */
            0, 0, 0, /* 1788: func */
            0, 8, 0, /* 1791: pointer.func */
            0, 0, 0, /* 1794: func */
            0, 8, 0, /* 1797: long */
            0, 0, 0, /* 1800: func */
            0, 8, 0, /* 1803: pointer.func */
            0, 8, 0, /* 1806: pointer.func */
            0, 0, 0, /* 1809: func */
            0, 8, 0, /* 1812: pointer.func */
            0, 8, 0, /* 1815: pointer.func */
            0, 8, 0, /* 1818: pointer.func */
            0, 8, 0, /* 1821: pointer.func */
            0, 0, 0, /* 1824: func */
            0, 0, 0, /* 1827: func */
            0, 8, 0, /* 1830: pointer.func */
            0, 0, 0, /* 1833: func */
            0, 8, 0, /* 1836: pointer.func */
            0, 8, 0, /* 1839: pointer.func */
            0, 0, 0, /* 1842: func */
            0, 0, 0, /* 1845: func */
            0, 8, 0, /* 1848: pointer.func */
            0, 8, 0, /* 1851: pointer.func */
            0, 0, 0, /* 1854: func */
            0, 0, 0, /* 1857: func */
            0, 8, 0, /* 1860: pointer.func */
            0, 0, 0, /* 1863: func */
            0, 8, 0, /* 1866: pointer.func */
            0, 8, 0, /* 1869: pointer.func */
            0, 12, 0, /* 1872: array[12].char */
            0, 0, 0, /* 1875: func */
            0, 0, 0, /* 1878: func */
            0, 8, 0, /* 1881: pointer.func */
            0, 0, 0, /* 1884: func */
            0, 8, 0, /* 1887: pointer.func */
            0, 8, 0, /* 1890: pointer.func */
            0, 0, 0, /* 1893: func */
            0, 20, 0, /* 1896: array[5].int */
            0, 0, 0, /* 1899: func */
            0, 8, 0, /* 1902: pointer.func */
            0, 0, 0, /* 1905: func */
            0, 0, 0, /* 1908: func */
            0, 0, 0, /* 1911: func */
            0, 8, 0, /* 1914: pointer.func */
            0, 0, 0, /* 1917: func */
            0, 8, 0, /* 1920: pointer.func */
            0, 16, 0, /* 1923: struct.rlimit */
            0, 8, 0, /* 1926: pointer.func */
            0, 8, 0, /* 1929: pointer.func */
            0, 0, 0, /* 1932: func */
            0, 8, 0, /* 1935: pointer.func */
            0, 0, 0, /* 1938: func */
            0, 8, 0, /* 1941: pointer.func */
            0, 0, 0, /* 1944: func */
            0, 0, 0, /* 1947: func */
            0, 0, 0, /* 1950: func */
            0, 8, 0, /* 1953: pointer.func */
            0, 8, 0, /* 1956: pointer.func */
            0, 0, 0, /* 1959: func */
            0, 8, 0, /* 1962: pointer.func */
            0, 0, 0, /* 1965: func */
            0, 0, 0, /* 1968: func */
            0, 0, 0, /* 1971: func */
            0, 0, 0, /* 1974: func */
            0, 8, 0, /* 1977: pointer.func */
            0, 8, 0, /* 1980: pointer.func */
            0, 0, 0, /* 1983: func */
            0, 0, 0, /* 1986: func */
            0, 8, 0, /* 1989: pointer.func */
            0, 0, 0, /* 1992: func */
            0, 0, 0, /* 1995: func */
            0, 8, 0, /* 1998: pointer.func */
            0, 0, 0, /* 2001: func */
            0, 0, 0, /* 2004: func */
            0, 8, 0, /* 2007: pointer.func */
            0, 0, 0, /* 2010: func */
            0, 8, 0, /* 2013: pointer.func */
            0, 8, 0, /* 2016: pointer.func */
            0, 0, 0, /* 2019: func */
            0, 8, 0, /* 2022: pointer.func */
            0, 0, 0, /* 2025: func */
            0, 2, 0, /* 2028: short */
            0, 0, 0, /* 2031: func */
            0, 0, 0, /* 2034: func */
            0, 8, 0, /* 2037: pointer.func */
            0, 72, 0, /* 2040: struct.anon.25 */
            0, 8, 0, /* 2043: pointer.func */
            0, 8, 0, /* 2046: array[8].char */
            0, 0, 0, /* 2049: func */
            0, 32, 0, /* 2052: array[32].char */
            0, 8, 0, /* 2055: pointer.func */
            0, 2, 0, /* 2058: array[2].char */
            0, 8, 0, /* 2061: pointer.func */
            0, 8, 0, /* 2064: pointer.func */
            0, 8, 0, /* 2067: pointer.func */
            0, 8, 0, /* 2070: pointer.func */
            0, 8, 0, /* 2073: pointer.func */
            0, 0, 0, /* 2076: func */
            0, 8, 0, /* 2079: pointer.func */
            0, 8, 0, /* 2082: pointer.func */
            0, 8, 0, /* 2085: pointer.func */
            0, 0, 0, /* 2088: func */
            0, 0, 0, /* 2091: func */
            0, 0, 0, /* 2094: func */
            0, 8, 0, /* 2097: pointer.func */
            0, 0, 0, /* 2100: func */
            0, 0, 0, /* 2103: func */
            0, 0, 0, /* 2106: func */
            0, 0, 0, /* 2109: func */
            0, 8, 0, /* 2112: pointer.func */
            0, 0, 0, /* 2115: func */
            0, 0, 0, /* 2118: func */
            0, 8, 0, /* 2121: pointer.func */
            0, 0, 0, /* 2124: func */
            0, 0, 0, /* 2127: func */
            0, 8, 0, /* 2130: pointer.func */
            0, 48, 0, /* 2133: array[48].char */
            0, 0, 0, /* 2136: func */
            0, 0, 0, /* 2139: func */
            0, 8, 0, /* 2142: pointer.func */
            0, 8, 0, /* 2145: pointer.func */
            0, 256, 0, /* 2148: array[256].char */
            0, 8, 0, /* 2151: pointer.func */
            0, 0, 0, /* 2154: func */
            0, 0, 0, /* 2157: func */
            0, 20, 0, /* 2160: array[20].char */
            0, 8, 0, /* 2163: pointer.func */
            0, 8, 0, /* 2166: pointer.func */
            0, 8, 0, /* 2169: pointer.func */
            0, 0, 0, /* 2172: func */
            0, 8, 0, /* 2175: pointer.func */
            0, 0, 0, /* 2178: func */
            0, 8, 0, /* 2181: pointer.func */
            0, 8, 0, /* 2184: pointer.func */
            0, 0, 0, /* 2187: func */
            0, 0, 0, /* 2190: func */
            0, 0, 0, /* 2193: func */
            0, 8, 0, /* 2196: pointer.func */
            0, 8, 0, /* 2199: pointer.func */
            0, 0, 0, /* 2202: func */
            0, 0, 0, /* 2205: func */
            0, 8, 0, /* 2208: pointer.func */
            0, 0, 0, /* 2211: func */
            0, 0, 0, /* 2214: func */
            0, 0, 0, /* 2217: func */
            0, 8, 0, /* 2220: pointer.func */
            0, 8, 0, /* 2223: pointer.func */
            0, 8, 0, /* 2226: pointer.func */
            0, 0, 0, /* 2229: func */
            0, 0, 0, /* 2232: func */
            0, 8, 0, /* 2235: pointer.func */
            0, 0, 0, /* 2238: func */
            0, 8, 0, /* 2241: pointer.func */
            0, 0, 0, /* 2244: func */
            0, 8, 0, /* 2247: pointer.func */
            0, 8, 0, /* 2250: pointer.func */
            0, 0, 0, /* 2253: func */
            0, 8, 0, /* 2256: pointer.func */
            0, 0, 0, /* 2259: func */
            0, 8, 0, /* 2262: pointer.func */
            0, 8, 0, /* 2265: pointer.func */
            0, 0, 0, /* 2268: func */
            0, 0, 0, /* 2271: func */
            0, 0, 0, /* 2274: func */
            0, 8, 0, /* 2277: pointer.func */
            0, 8, 0, /* 2280: pointer.func */
            0, 0, 0, /* 2283: func */
            0, 8, 0, /* 2286: pointer.func */
            0, 0, 0, /* 2289: func */
            0, 8, 0, /* 2292: pointer.func */
            0, 0, 0, /* 2295: func */
            0, 0, 0, /* 2298: func */
            0, 8, 0, /* 2301: pointer.func */
            0, 8, 0, /* 2304: pointer.func */
            0, 0, 0, /* 2307: func */
            0, 8, 0, /* 2310: pointer.func */
            0, 0, 0, /* 2313: func */
            0, 8, 0, /* 2316: pointer.func */
            0, 0, 0, /* 2319: func */
            0, 8, 0, /* 2322: pointer.func */
            0, 8, 0, /* 2325: pointer.func */
            0, 0, 0, /* 2328: func */
            0, 0, 0, /* 2331: func */
            0, 0, 0, /* 2334: func */
            0, 8, 0, /* 2337: pointer.func */
            0, 8, 0, /* 2340: pointer.func */
            0, 0, 0, /* 2343: func */
            0, 8, 0, /* 2346: pointer.func */
            0, 0, 0, /* 2349: func */
            0, 0, 0, /* 2352: func */
            0, 0, 0, /* 2355: func */
        },
        .arg_entity_index = { 1380, },
        .ret_entity_index = 1513,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    SSL_CTX * *new_ret_ptr = (SSL_CTX * *)new_args->ret;

    SSL_CTX * (*orig_SSL_get_SSL_CTX)(const SSL *);
    orig_SSL_get_SSL_CTX = dlsym(RTLD_NEXT, "SSL_get_SSL_CTX");
    *new_ret_ptr = (*orig_SSL_get_SSL_CTX)(new_arg_a);

    syscall(889);

    return ret;
}

