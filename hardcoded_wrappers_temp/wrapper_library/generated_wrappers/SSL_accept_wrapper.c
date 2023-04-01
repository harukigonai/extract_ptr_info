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

int bb_SSL_accept(SSL * arg_a);

int SSL_accept(SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_accept called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_accept(arg_a);
    else {
        int (*orig_SSL_accept)(SSL *);
        orig_SSL_accept = dlsym(RTLD_NEXT, "SSL_accept");
        return orig_SSL_accept(arg_a);
    }
}

int bb_SSL_accept(SSL * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.iovec */
            	5, 0,
            0, 16, 1, /* 5: struct.iovec */
            	10, 0,
            1, 8, 1, /* 10: pointer.char */
            	4096, 0,
            0, 0, 0, /* 15: func */
            0, 16, 1, /* 18: struct.tls_session_ticket_ext_st */
            	10, 8,
            1, 8, 1, /* 23: pointer.struct.tls_session_ticket_ext_st */
            	18, 0,
            4097, 8, 0, /* 28: pointer.func */
            0, 8, 1, /* 31: struct.ssl3_buf_freelist_entry_st */
            	36, 0,
            1, 8, 1, /* 36: pointer.struct.ssl3_buf_freelist_entry_st */
            	31, 0,
            1, 8, 1, /* 41: pointer.struct.ssl3_buf_freelist_st */
            	46, 0,
            0, 24, 1, /* 46: struct.ssl3_buf_freelist_st */
            	36, 16,
            0, 0, 0, /* 51: func */
            4097, 8, 0, /* 54: pointer.func */
            4097, 8, 0, /* 57: pointer.func */
            0, 0, 0, /* 60: func */
            4097, 8, 0, /* 63: pointer.func */
            0, 0, 0, /* 66: func */
            4097, 8, 0, /* 69: pointer.func */
            0, 0, 0, /* 72: func */
            0, 44, 0, /* 75: struct.apr_time_exp_t */
            0, 0, 0, /* 78: func */
            4097, 8, 0, /* 81: pointer.func */
            1, 8, 1, /* 84: pointer.struct.in_addr */
            	89, 0,
            0, 4, 0, /* 89: struct.in_addr */
            4097, 8, 0, /* 92: pointer.func */
            0, 0, 0, /* 95: func */
            0, 0, 0, /* 98: func */
            0, 0, 0, /* 101: func */
            4097, 8, 0, /* 104: pointer.func */
            0, 0, 0, /* 107: func */
            0, 144, 4, /* 110: struct.x509_store_st */
            	121, 8,
            	121, 16,
            	141, 24,
            	153, 120,
            1, 8, 1, /* 121: pointer.struct.stack_st_OPENSSL_STRING */
            	126, 0,
            0, 32, 1, /* 126: struct.stack_st_OPENSSL_STRING */
            	131, 0,
            0, 32, 1, /* 131: struct.stack_st */
            	136, 8,
            1, 8, 1, /* 136: pointer.pointer.char */
            	10, 0,
            1, 8, 1, /* 141: pointer.struct.X509_VERIFY_PARAM_st */
            	146, 0,
            0, 56, 2, /* 146: struct.X509_VERIFY_PARAM_st */
            	10, 0,
            	121, 48,
            0, 16, 1, /* 153: struct.crypto_ex_data_st */
            	121, 0,
            1, 8, 1, /* 158: pointer.struct.x509_store_st */
            	110, 0,
            4097, 8, 0, /* 163: pointer.func */
            0, 0, 0, /* 166: func */
            0, 0, 0, /* 169: func */
            0, 0, 0, /* 172: func */
            4097, 8, 0, /* 175: pointer.func */
            0, 0, 0, /* 178: func */
            0, 0, 0, /* 181: func */
            4097, 8, 0, /* 184: pointer.func */
            0, 296, 5, /* 187: struct.cert_st.745 */
            	200, 0,
            	620, 48,
            	714, 64,
            	746, 80,
            	828, 96,
            1, 8, 1, /* 200: pointer.struct.cert_pkey_st */
            	205, 0,
            0, 24, 3, /* 205: struct.cert_pkey_st */
            	214, 0,
            	377, 8,
            	612, 16,
            1, 8, 1, /* 214: pointer.struct.x509_st */
            	219, 0,
            0, 184, 12, /* 219: struct.x509_st */
            	246, 0,
            	286, 8,
            	276, 16,
            	10, 32,
            	153, 40,
            	276, 104,
            	542, 112,
            	556, 120,
            	121, 128,
            	121, 136,
            	582, 144,
            	594, 176,
            1, 8, 1, /* 246: pointer.struct.x509_cinf_st */
            	251, 0,
            0, 104, 11, /* 251: struct.x509_cinf_st */
            	276, 0,
            	276, 8,
            	286, 16,
            	327, 24,
            	351, 32,
            	327, 40,
            	363, 48,
            	276, 56,
            	276, 64,
            	121, 72,
            	537, 80,
            1, 8, 1, /* 276: pointer.struct.asn1_string_st */
            	281, 0,
            0, 24, 1, /* 281: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 286: pointer.struct.X509_algor_st */
            	291, 0,
            0, 16, 2, /* 291: struct.X509_algor_st */
            	298, 0,
            	312, 8,
            1, 8, 1, /* 298: pointer.struct.asn1_object_st */
            	303, 0,
            0, 40, 3, /* 303: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	10, 24,
            1, 8, 1, /* 312: pointer.struct.asn1_type_st */
            	317, 0,
            0, 16, 1, /* 317: struct.asn1_type_st */
            	322, 8,
            0, 8, 1, /* 322: struct.fnames */
            	10, 0,
            1, 8, 1, /* 327: pointer.struct.X509_name_st */
            	332, 0,
            0, 40, 3, /* 332: struct.X509_name_st */
            	121, 0,
            	341, 16,
            	10, 24,
            1, 8, 1, /* 341: pointer.struct.buf_mem_st */
            	346, 0,
            0, 24, 1, /* 346: struct.buf_mem_st */
            	10, 8,
            1, 8, 1, /* 351: pointer.struct.X509_val_st */
            	356, 0,
            0, 16, 2, /* 356: struct.X509_val_st */
            	276, 0,
            	276, 8,
            1, 8, 1, /* 363: pointer.struct.X509_pubkey_st */
            	368, 0,
            0, 24, 3, /* 368: struct.X509_pubkey_st */
            	286, 0,
            	276, 8,
            	377, 16,
            1, 8, 1, /* 377: pointer.struct.evp_pkey_st */
            	382, 0,
            0, 56, 4, /* 382: struct.evp_pkey_st */
            	393, 16,
            	415, 24,
            	322, 32,
            	121, 48,
            1, 8, 1, /* 393: pointer.struct.evp_pkey_asn1_method_st */
            	398, 0,
            0, 208, 3, /* 398: struct.evp_pkey_asn1_method_st */
            	10, 16,
            	10, 24,
            	407, 32,
            1, 8, 1, /* 407: pointer.struct.unnamed */
            	412, 0,
            0, 0, 0, /* 412: struct.unnamed */
            1, 8, 1, /* 415: pointer.struct.engine_st */
            	420, 0,
            0, 216, 13, /* 420: struct.engine_st */
            	10, 0,
            	10, 8,
            	449, 16,
            	461, 24,
            	473, 32,
            	485, 40,
            	497, 48,
            	509, 56,
            	517, 64,
            	525, 160,
            	153, 184,
            	415, 200,
            	415, 208,
            1, 8, 1, /* 449: pointer.struct.rsa_meth_st */
            	454, 0,
            0, 112, 2, /* 454: struct.rsa_meth_st */
            	10, 0,
            	10, 80,
            1, 8, 1, /* 461: pointer.struct.dsa_method.1040 */
            	466, 0,
            0, 96, 2, /* 466: struct.dsa_method.1040 */
            	10, 0,
            	10, 72,
            1, 8, 1, /* 473: pointer.struct.dh_method */
            	478, 0,
            0, 72, 2, /* 478: struct.dh_method */
            	10, 0,
            	10, 56,
            1, 8, 1, /* 485: pointer.struct.ecdh_method */
            	490, 0,
            0, 32, 2, /* 490: struct.ecdh_method */
            	10, 0,
            	10, 24,
            1, 8, 1, /* 497: pointer.struct.ecdsa_method */
            	502, 0,
            0, 48, 2, /* 502: struct.ecdsa_method */
            	10, 0,
            	10, 40,
            1, 8, 1, /* 509: pointer.struct.rand_meth_st */
            	514, 0,
            0, 48, 0, /* 514: struct.rand_meth_st */
            1, 8, 1, /* 517: pointer.struct.store_method_st */
            	522, 0,
            0, 0, 0, /* 522: struct.store_method_st */
            1, 8, 1, /* 525: pointer.struct.ENGINE_CMD_DEFN_st */
            	530, 0,
            0, 32, 2, /* 530: struct.ENGINE_CMD_DEFN_st */
            	10, 8,
            	10, 16,
            0, 24, 1, /* 537: struct.ASN1_ENCODING_st */
            	10, 0,
            1, 8, 1, /* 542: pointer.struct.AUTHORITY_KEYID_st */
            	547, 0,
            0, 24, 3, /* 547: struct.AUTHORITY_KEYID_st */
            	276, 0,
            	121, 8,
            	276, 16,
            1, 8, 1, /* 556: pointer.struct.X509_POLICY_CACHE_st */
            	561, 0,
            0, 40, 2, /* 561: struct.X509_POLICY_CACHE_st */
            	568, 0,
            	121, 8,
            1, 8, 1, /* 568: pointer.struct.X509_POLICY_DATA_st */
            	573, 0,
            0, 32, 3, /* 573: struct.X509_POLICY_DATA_st */
            	298, 8,
            	121, 16,
            	121, 24,
            1, 8, 1, /* 582: pointer.struct.NAME_CONSTRAINTS_st */
            	587, 0,
            0, 16, 2, /* 587: struct.NAME_CONSTRAINTS_st */
            	121, 0,
            	121, 8,
            1, 8, 1, /* 594: pointer.struct.x509_cert_aux_st */
            	599, 0,
            0, 40, 5, /* 599: struct.x509_cert_aux_st */
            	121, 0,
            	121, 8,
            	276, 16,
            	276, 24,
            	121, 32,
            1, 8, 1, /* 612: pointer.struct.env_md_st */
            	617, 0,
            0, 120, 0, /* 617: struct.env_md_st */
            1, 8, 1, /* 620: pointer.struct.rsa_st */
            	625, 0,
            0, 168, 17, /* 625: struct.rsa_st */
            	449, 16,
            	415, 24,
            	662, 32,
            	662, 40,
            	662, 48,
            	662, 56,
            	662, 64,
            	662, 72,
            	662, 80,
            	662, 88,
            	153, 96,
            	680, 120,
            	680, 128,
            	680, 136,
            	10, 144,
            	694, 152,
            	694, 160,
            1, 8, 1, /* 662: pointer.struct.bignum_st */
            	667, 0,
            0, 24, 1, /* 667: struct.bignum_st */
            	672, 0,
            1, 8, 1, /* 672: pointer.int */
            	677, 0,
            0, 4, 0, /* 677: int */
            1, 8, 1, /* 680: pointer.struct.bn_mont_ctx_st */
            	685, 0,
            0, 96, 3, /* 685: struct.bn_mont_ctx_st */
            	667, 8,
            	667, 32,
            	667, 56,
            1, 8, 1, /* 694: pointer.struct.bn_blinding_st */
            	699, 0,
            0, 88, 6, /* 699: struct.bn_blinding_st */
            	662, 0,
            	662, 8,
            	662, 16,
            	662, 24,
            	5, 40,
            	680, 72,
            1, 8, 1, /* 714: pointer.struct.dh_st */
            	719, 0,
            0, 144, 12, /* 719: struct.dh_st */
            	662, 8,
            	662, 16,
            	662, 32,
            	662, 40,
            	680, 56,
            	662, 64,
            	662, 72,
            	10, 80,
            	662, 96,
            	153, 112,
            	473, 128,
            	415, 136,
            1, 8, 1, /* 746: pointer.struct.ec_key_st.284 */
            	751, 0,
            0, 56, 4, /* 751: struct.ec_key_st.284 */
            	762, 8,
            	800, 16,
            	662, 24,
            	816, 48,
            1, 8, 1, /* 762: pointer.struct.ec_group_st */
            	767, 0,
            0, 232, 11, /* 767: struct.ec_group_st */
            	792, 0,
            	800, 8,
            	667, 16,
            	667, 40,
            	10, 80,
            	816, 96,
            	667, 104,
            	667, 152,
            	667, 176,
            	10, 208,
            	10, 216,
            1, 8, 1, /* 792: pointer.struct.ec_method_st */
            	797, 0,
            0, 304, 0, /* 797: struct.ec_method_st */
            1, 8, 1, /* 800: pointer.struct.ec_point_st */
            	805, 0,
            0, 88, 4, /* 805: struct.ec_point_st */
            	792, 0,
            	667, 8,
            	667, 32,
            	667, 56,
            1, 8, 1, /* 816: pointer.struct.ec_extra_data_st */
            	821, 0,
            0, 40, 2, /* 821: struct.ec_extra_data_st */
            	816, 0,
            	10, 8,
            0, 192, 8, /* 828: array[8].struct.cert_pkey_st */
            	205, 0,
            	205, 24,
            	205, 48,
            	205, 72,
            	205, 96,
            	205, 120,
            	205, 144,
            	205, 168,
            0, 0, 0, /* 847: func */
            0, 12, 0, /* 850: struct.ap_unix_identity_t */
            4097, 8, 0, /* 853: pointer.func */
            0, 0, 0, /* 856: func */
            0, 248, 6, /* 859: struct.sess_cert_st */
            	121, 0,
            	200, 16,
            	828, 24,
            	620, 216,
            	714, 224,
            	746, 232,
            0, 352, 14, /* 874: struct.ssl_session_st */
            	10, 144,
            	10, 152,
            	905, 168,
            	214, 176,
            	910, 224,
            	121, 240,
            	153, 248,
            	920, 264,
            	920, 272,
            	10, 280,
            	10, 296,
            	10, 312,
            	10, 320,
            	10, 344,
            1, 8, 1, /* 905: pointer.struct.sess_cert_st */
            	859, 0,
            1, 8, 1, /* 910: pointer.struct.ssl_cipher_st */
            	915, 0,
            0, 88, 1, /* 915: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 920: pointer.struct.ssl_session_st */
            	874, 0,
            0, 56, 2, /* 925: struct.comp_ctx_st */
            	932, 0,
            	153, 40,
            1, 8, 1, /* 932: pointer.struct.comp_method_st */
            	937, 0,
            0, 64, 1, /* 937: struct.comp_method_st */
            	10, 8,
            1, 8, 1, /* 942: pointer.struct.comp_ctx_st */
            	925, 0,
            0, 168, 4, /* 947: struct.evp_cipher_ctx_st */
            	958, 0,
            	415, 8,
            	10, 96,
            	10, 120,
            1, 8, 1, /* 958: pointer.struct.evp_cipher_st */
            	963, 0,
            0, 88, 1, /* 963: struct.evp_cipher_st */
            	10, 80,
            4097, 8, 0, /* 968: pointer.func */
            1, 8, 1, /* 971: pointer.struct._pitem */
            	976, 0,
            0, 24, 2, /* 976: struct._pitem */
            	10, 8,
            	971, 16,
            4097, 8, 0, /* 983: pointer.func */
            0, 16, 0, /* 986: union.anon.142 */
            0, 2, 0, /* 989: short */
            0, 256, 0, /* 992: array[256].char */
            1, 8, 1, /* 995: pointer.struct.dtls1_state_st */
            	1000, 0,
            0, 888, 7, /* 1000: struct.dtls1_state_st */
            	1017, 576,
            	1017, 592,
            	1022, 608,
            	1022, 616,
            	1017, 624,
            	1032, 648,
            	1032, 736,
            0, 16, 1, /* 1017: struct.record_pqueue_st */
            	1022, 8,
            1, 8, 1, /* 1022: pointer.struct._pqueue */
            	1027, 0,
            0, 16, 1, /* 1027: struct._pqueue */
            	971, 0,
            0, 88, 1, /* 1032: struct.hm_header_st */
            	1037, 48,
            0, 40, 4, /* 1037: struct.dtls1_retransmit_state */
            	1048, 0,
            	1053, 8,
            	942, 16,
            	920, 24,
            1, 8, 1, /* 1048: pointer.struct.evp_cipher_ctx_st */
            	947, 0,
            1, 8, 1, /* 1053: pointer.struct.env_md_ctx_st */
            	1058, 0,
            0, 48, 4, /* 1058: struct.env_md_ctx_st */
            	612, 0,
            	415, 8,
            	10, 24,
            	1069, 32,
            1, 8, 1, /* 1069: pointer.struct.evp_pkey_ctx_st */
            	1074, 0,
            0, 80, 8, /* 1074: struct.evp_pkey_ctx_st */
            	1093, 0,
            	415, 8,
            	377, 16,
            	377, 24,
            	10, 40,
            	10, 48,
            	407, 56,
            	672, 64,
            1, 8, 1, /* 1093: pointer.struct.evp_pkey_method_st */
            	1098, 0,
            0, 208, 9, /* 1098: struct.evp_pkey_method_st */
            	407, 8,
            	407, 32,
            	407, 48,
            	407, 64,
            	407, 80,
            	407, 96,
            	407, 144,
            	407, 160,
            	407, 176,
            0, 0, 0, /* 1119: func */
            0, 0, 0, /* 1122: func */
            0, 0, 0, /* 1125: func */
            4097, 8, 0, /* 1128: pointer.func */
            0, 24, 2, /* 1131: struct.ssl_comp_st */
            	10, 8,
            	932, 16,
            4097, 8, 0, /* 1138: pointer.func */
            0, 0, 0, /* 1141: func */
            4097, 8, 0, /* 1144: pointer.func */
            0, 0, 0, /* 1147: func */
            4097, 8, 0, /* 1150: pointer.func */
            0, 0, 0, /* 1153: func */
            4097, 8, 0, /* 1156: pointer.func */
            0, 9, 0, /* 1159: array[9].char */
            0, 0, 0, /* 1162: func */
            4097, 8, 0, /* 1165: pointer.func */
            4097, 8, 0, /* 1168: pointer.func */
            0, 0, 0, /* 1171: func */
            4097, 8, 0, /* 1174: pointer.func */
            0, 0, 0, /* 1177: func */
            4097, 8, 0, /* 1180: pointer.func */
            0, 0, 0, /* 1183: func */
            4097, 8, 0, /* 1186: pointer.func */
            4097, 8, 0, /* 1189: pointer.func */
            0, 0, 0, /* 1192: func */
            4097, 8, 0, /* 1195: pointer.func */
            0, 0, 0, /* 1198: func */
            4097, 8, 0, /* 1201: pointer.func */
            0, 0, 0, /* 1204: func */
            4097, 8, 0, /* 1207: pointer.func */
            1, 8, 1, /* 1210: pointer.struct.ssl_ctx_st.752 */
            	1215, 0,
            0, 736, 30, /* 1215: struct.ssl_ctx_st.752 */
            	1278, 0,
            	121, 8,
            	121, 16,
            	158, 24,
            	84, 32,
            	920, 48,
            	920, 56,
            	10, 160,
            	10, 176,
            	153, 208,
            	612, 224,
            	612, 232,
            	612, 240,
            	121, 248,
            	121, 256,
            	121, 272,
            	1304, 304,
            	10, 328,
            	141, 392,
            	415, 408,
            	10, 424,
            	10, 496,
            	10, 512,
            	10, 520,
            	41, 552,
            	41, 560,
            	1309, 568,
            	10, 704,
            	10, 720,
            	121, 728,
            1, 8, 1, /* 1278: pointer.struct.ssl_method_st.754 */
            	1283, 0,
            0, 232, 1, /* 1283: struct.ssl_method_st.754 */
            	1288, 200,
            1, 8, 1, /* 1288: pointer.struct.ssl3_enc_method.753 */
            	1293, 0,
            0, 112, 4, /* 1293: struct.ssl3_enc_method.753 */
            	407, 0,
            	407, 32,
            	10, 64,
            	10, 80,
            1, 8, 1, /* 1304: pointer.struct.cert_st.745 */
            	187, 0,
            0, 128, 11, /* 1309: struct.srp_ctx_st.751 */
            	10, 0,
            	10, 32,
            	662, 40,
            	662, 48,
            	662, 56,
            	662, 64,
            	662, 72,
            	662, 80,
            	662, 88,
            	662, 96,
            	10, 104,
            0, 0, 0, /* 1334: func */
            4097, 8, 0, /* 1337: pointer.func */
            0, 0, 0, /* 1340: func */
            4097, 8, 0, /* 1343: pointer.func */
            0, 0, 0, /* 1346: func */
            4097, 8, 0, /* 1349: pointer.func */
            0, 0, 0, /* 1352: func */
            4097, 8, 0, /* 1355: pointer.func */
            0, 0, 0, /* 1358: func */
            4097, 8, 0, /* 1361: pointer.func */
            0, 0, 0, /* 1364: func */
            0, 0, 0, /* 1367: func */
            0, 0, 0, /* 1370: func */
            4097, 8, 0, /* 1373: pointer.func */
            0, 0, 0, /* 1376: func */
            0, 0, 0, /* 1379: func */
            4097, 8, 0, /* 1382: pointer.func */
            0, 0, 0, /* 1385: func */
            0, 0, 0, /* 1388: func */
            0, 0, 0, /* 1391: func */
            0, 8, 0, /* 1394: array[2].int */
            4097, 8, 0, /* 1397: pointer.func */
            0, 12, 0, /* 1400: array[12].char */
            4097, 8, 0, /* 1403: pointer.func */
            0, 128, 0, /* 1406: array[128].char */
            0, 528, 8, /* 1409: struct.anon.0 */
            	910, 408,
            	714, 416,
            	746, 424,
            	121, 464,
            	10, 480,
            	958, 488,
            	612, 496,
            	1428, 512,
            1, 8, 1, /* 1428: pointer.struct.ssl_comp_st */
            	1131, 0,
            0, 0, 0, /* 1433: func */
            0, 0, 0, /* 1436: func */
            4097, 8, 0, /* 1439: pointer.func */
            4097, 8, 0, /* 1442: pointer.func */
            0, 0, 0, /* 1445: func */
            4097, 8, 0, /* 1448: pointer.func */
            0, 0, 0, /* 1451: func */
            0, 0, 0, /* 1454: func */
            4097, 8, 0, /* 1457: pointer.func */
            0, 20, 0, /* 1460: array[5].int */
            1, 8, 1, /* 1463: pointer.struct.bio_method_st */
            	1468, 0,
            0, 80, 1, /* 1468: struct.bio_method_st */
            	10, 8,
            0, 1, 0, /* 1473: char */
            0, 0, 0, /* 1476: func */
            0, 0, 0, /* 1479: func */
            4097, 8, 0, /* 1482: pointer.func */
            0, 0, 0, /* 1485: func */
            4097, 8, 0, /* 1488: pointer.func */
            0, 0, 0, /* 1491: func */
            0, 0, 0, /* 1494: func */
            0, 0, 0, /* 1497: func */
            0, 0, 0, /* 1500: func */
            0, 24, 1, /* 1503: struct.ssl3_buffer_st */
            	10, 0,
            4097, 8, 0, /* 1508: pointer.func */
            4097, 8, 0, /* 1511: pointer.func */
            4097, 8, 0, /* 1514: pointer.func */
            0, 56, 3, /* 1517: struct.ssl3_record_st */
            	10, 16,
            	10, 24,
            	10, 32,
            0, 0, 0, /* 1526: func */
            0, 2, 0, /* 1529: array[2].char */
            0, 72, 0, /* 1532: struct.anon.25 */
            0, 48, 0, /* 1535: array[48].char */
            0, 1200, 10, /* 1538: struct.ssl3_state_st */
            	1503, 240,
            	1503, 264,
            	1517, 288,
            	1517, 344,
            	10, 432,
            	1561, 440,
            	1581, 448,
            	10, 496,
            	10, 512,
            	1409, 528,
            1, 8, 1, /* 1561: pointer.struct.bio_st */
            	1566, 0,
            0, 112, 6, /* 1566: struct.bio_st */
            	1463, 0,
            	10, 16,
            	10, 48,
            	1561, 56,
            	1561, 64,
            	153, 96,
            1, 8, 1, /* 1581: pointer.pointer.struct.env_md_ctx_st */
            	1053, 0,
            4097, 8, 0, /* 1586: pointer.func */
            0, 0, 0, /* 1589: func */
            0, 32, 0, /* 1592: array[32].char */
            4097, 8, 0, /* 1595: pointer.func */
            4097, 8, 0, /* 1598: pointer.func */
            4097, 8, 0, /* 1601: pointer.func */
            4097, 8, 0, /* 1604: pointer.func */
            0, 0, 0, /* 1607: func */
            0, 8, 0, /* 1610: long */
            4097, 8, 0, /* 1613: pointer.func */
            4097, 8, 0, /* 1616: pointer.func */
            0, 0, 0, /* 1619: func */
            0, 0, 0, /* 1622: func */
            0, 0, 0, /* 1625: func */
            0, 4, 0, /* 1628: array[4].char */
            0, 0, 0, /* 1631: func */
            0, 0, 0, /* 1634: func */
            4097, 8, 0, /* 1637: pointer.func */
            0, 0, 0, /* 1640: func */
            0, 0, 0, /* 1643: func */
            4097, 8, 0, /* 1646: pointer.func */
            4097, 8, 0, /* 1649: pointer.func */
            4097, 8, 0, /* 1652: pointer.func */
            0, 0, 0, /* 1655: func */
            4097, 8, 0, /* 1658: pointer.func */
            4097, 8, 0, /* 1661: pointer.func */
            0, 0, 0, /* 1664: func */
            4097, 8, 0, /* 1667: pointer.func */
            4097, 8, 0, /* 1670: pointer.func */
            4097, 8, 0, /* 1673: pointer.func */
            4097, 8, 0, /* 1676: pointer.func */
            4097, 8, 0, /* 1679: pointer.func */
            0, 808, 41, /* 1682: struct.ssl_st.776 */
            	1278, 8,
            	1561, 16,
            	1561, 24,
            	1561, 32,
            	341, 80,
            	10, 88,
            	10, 104,
            	1767, 120,
            	1793, 128,
            	995, 136,
            	10, 160,
            	141, 176,
            	121, 184,
            	121, 192,
            	1048, 208,
            	1053, 216,
            	942, 224,
            	1048, 232,
            	1053, 240,
            	942, 248,
            	1304, 256,
            	920, 304,
            	1210, 368,
            	153, 392,
            	121, 408,
            	10, 472,
            	10, 480,
            	121, 504,
            	121, 512,
            	10, 520,
            	10, 544,
            	10, 560,
            	10, 568,
            	23, 584,
            	10, 600,
            	10, 616,
            	1210, 624,
            	10, 632,
            	121, 648,
            	0, 656,
            	1309, 680,
            1, 8, 1, /* 1767: pointer.struct.ssl2_state_st */
            	1772, 0,
            0, 344, 9, /* 1772: struct.ssl2_state_st */
            	10, 24,
            	10, 56,
            	10, 64,
            	10, 72,
            	10, 104,
            	10, 112,
            	10, 120,
            	10, 128,
            	10, 136,
            1, 8, 1, /* 1793: pointer.struct.ssl3_state_st */
            	1538, 0,
            0, 0, 0, /* 1798: func */
            4097, 8, 0, /* 1801: pointer.func */
            0, 0, 0, /* 1804: func */
            4097, 8, 0, /* 1807: pointer.func */
            4097, 8, 0, /* 1810: pointer.func */
            4097, 8, 0, /* 1813: pointer.func */
            0, 0, 0, /* 1816: func */
            4097, 8, 0, /* 1819: pointer.func */
            4097, 8, 0, /* 1822: pointer.func */
            1, 8, 1, /* 1825: pointer.struct.ssl_st.776 */
            	1682, 0,
            4097, 8, 0, /* 1830: pointer.func */
            0, 0, 0, /* 1833: func */
            0, 0, 0, /* 1836: func */
            0, 0, 0, /* 1839: func */
            4097, 8, 0, /* 1842: pointer.func */
            0, 16, 0, /* 1845: array[16].char */
            0, 0, 0, /* 1848: func */
            0, 0, 0, /* 1851: func */
            4097, 8, 0, /* 1854: pointer.func */
            0, 0, 0, /* 1857: func */
            0, 8, 0, /* 1860: array[8].char */
            0, 0, 0, /* 1863: func */
            0, 0, 0, /* 1866: func */
            4097, 8, 0, /* 1869: pointer.func */
            0, 0, 0, /* 1872: func */
            4097, 8, 0, /* 1875: pointer.func */
            0, 0, 0, /* 1878: func */
            0, 0, 0, /* 1881: func */
            0, 0, 0, /* 1884: func */
            0, 0, 0, /* 1887: func */
            0, 0, 0, /* 1890: func */
            4097, 8, 0, /* 1893: pointer.func */
            0, 0, 0, /* 1896: func */
            0, 0, 0, /* 1899: func */
            0, 0, 0, /* 1902: func */
            4097, 8, 0, /* 1905: pointer.func */
            0, 0, 0, /* 1908: func */
            0, 0, 0, /* 1911: func */
            0, 0, 0, /* 1914: func */
            0, 0, 0, /* 1917: func */
            0, 0, 0, /* 1920: func */
            4097, 8, 0, /* 1923: pointer.func */
            0, 0, 0, /* 1926: func */
            4097, 8, 0, /* 1929: pointer.func */
            0, 0, 0, /* 1932: func */
            0, 0, 0, /* 1935: func */
            4097, 8, 0, /* 1938: pointer.func */
            0, 0, 0, /* 1941: func */
            0, 0, 0, /* 1944: func */
            0, 0, 0, /* 1947: func */
            0, 0, 0, /* 1950: func */
            4097, 8, 0, /* 1953: pointer.func */
            4097, 8, 0, /* 1956: pointer.func */
            4097, 8, 0, /* 1959: pointer.func */
            0, 0, 0, /* 1962: func */
            4097, 8, 0, /* 1965: pointer.func */
            4097, 8, 0, /* 1968: pointer.func */
            4097, 8, 0, /* 1971: pointer.func */
            0, 0, 0, /* 1974: func */
            0, 0, 0, /* 1977: func */
            0, 0, 0, /* 1980: func */
            4097, 8, 0, /* 1983: pointer.func */
            4097, 8, 0, /* 1986: pointer.func */
            4097, 8, 0, /* 1989: pointer.func */
            0, 0, 0, /* 1992: func */
            4097, 8, 0, /* 1995: pointer.func */
            0, 0, 0, /* 1998: func */
            0, 0, 0, /* 2001: func */
            0, 0, 0, /* 2004: func */
            4097, 8, 0, /* 2007: pointer.func */
            4097, 8, 0, /* 2010: pointer.func */
            0, 0, 0, /* 2013: func */
            0, 0, 0, /* 2016: func */
            4097, 8, 0, /* 2019: pointer.func */
            0, 0, 0, /* 2022: func */
            4097, 8, 0, /* 2025: pointer.func */
            0, 0, 0, /* 2028: func */
            4097, 8, 0, /* 2031: pointer.func */
            4097, 8, 0, /* 2034: pointer.func */
            0, 0, 0, /* 2037: func */
            0, 64, 0, /* 2040: array[64].char */
            4097, 8, 0, /* 2043: pointer.func */
            4097, 8, 0, /* 2046: pointer.func */
            0, 0, 0, /* 2049: func */
            0, 24, 0, /* 2052: array[6].int */
            4097, 8, 0, /* 2055: pointer.func */
            4097, 8, 0, /* 2058: pointer.func */
            0, 0, 0, /* 2061: func */
            0, 0, 0, /* 2064: func */
            0, 0, 0, /* 2067: func */
            4097, 8, 0, /* 2070: pointer.func */
            0, 0, 0, /* 2073: func */
            0, 0, 0, /* 2076: func */
            4097, 8, 0, /* 2079: pointer.func */
            4097, 8, 0, /* 2082: pointer.func */
            4097, 8, 0, /* 2085: pointer.func */
            0, 0, 0, /* 2088: func */
            4097, 8, 0, /* 2091: pointer.func */
            4097, 8, 0, /* 2094: pointer.func */
            4097, 8, 0, /* 2097: pointer.func */
            0, 0, 0, /* 2100: func */
            4097, 8, 0, /* 2103: pointer.func */
            0, 0, 0, /* 2106: func */
            4097, 8, 0, /* 2109: pointer.func */
            4097, 8, 0, /* 2112: pointer.func */
            0, 0, 0, /* 2115: func */
            0, 0, 0, /* 2118: func */
            4097, 8, 0, /* 2121: pointer.func */
            4097, 8, 0, /* 2124: pointer.func */
            4097, 8, 0, /* 2127: pointer.func */
            4097, 8, 0, /* 2130: pointer.func */
            4097, 8, 0, /* 2133: pointer.func */
            4097, 8, 0, /* 2136: pointer.func */
            4097, 8, 0, /* 2139: pointer.func */
            4097, 8, 0, /* 2142: pointer.func */
            0, 0, 0, /* 2145: func */
            4097, 8, 0, /* 2148: pointer.func */
            4097, 8, 0, /* 2151: pointer.func */
            0, 0, 0, /* 2154: func */
            0, 0, 0, /* 2157: func */
            4097, 8, 0, /* 2160: pointer.func */
            0, 0, 0, /* 2163: func */
            0, 0, 0, /* 2166: func */
            0, 0, 0, /* 2169: func */
            4097, 8, 0, /* 2172: pointer.func */
            0, 0, 0, /* 2175: func */
            0, 0, 0, /* 2178: func */
            0, 0, 0, /* 2181: func */
            4097, 8, 0, /* 2184: pointer.func */
            4097, 8, 0, /* 2187: pointer.func */
            4097, 8, 0, /* 2190: pointer.func */
            4097, 8, 0, /* 2193: pointer.func */
            0, 20, 0, /* 2196: array[20].char */
            4097, 8, 0, /* 2199: pointer.func */
            0, 0, 0, /* 2202: func */
            4097, 8, 0, /* 2205: pointer.func */
            4097, 8, 0, /* 2208: pointer.func */
            4097, 8, 0, /* 2211: pointer.func */
            4097, 8, 0, /* 2214: pointer.func */
            4097, 8, 0, /* 2217: pointer.func */
            4097, 8, 0, /* 2220: pointer.func */
            0, 0, 0, /* 2223: func */
            4097, 8, 0, /* 2226: pointer.func */
            0, 0, 0, /* 2229: func */
            4097, 8, 0, /* 2232: pointer.func */
            4097, 8, 0, /* 2235: pointer.func */
            0, 0, 0, /* 2238: func */
            4097, 8, 0, /* 2241: pointer.func */
            0, 0, 0, /* 2244: func */
            0, 0, 0, /* 2247: func */
            0, 0, 0, /* 2250: func */
            4097, 8, 0, /* 2253: pointer.func */
            4097, 8, 0, /* 2256: pointer.func */
            4097, 8, 0, /* 2259: pointer.func */
            4097, 8, 0, /* 2262: pointer.func */
            0, 0, 0, /* 2265: func */
            4097, 8, 0, /* 2268: pointer.func */
            0, 0, 0, /* 2271: func */
            4097, 8, 0, /* 2274: pointer.func */
            0, 0, 0, /* 2277: func */
            0, 0, 0, /* 2280: func */
            4097, 8, 0, /* 2283: pointer.func */
            0, 0, 0, /* 2286: func */
            4097, 8, 0, /* 2289: pointer.func */
            0, 16, 0, /* 2292: struct.rlimit */
            0, 0, 0, /* 2295: func */
            0, 0, 0, /* 2298: func */
            0, 0, 0, /* 2301: func */
            4097, 8, 0, /* 2304: pointer.func */
            0, 0, 0, /* 2307: func */
            0, 0, 0, /* 2310: func */
            0, 0, 0, /* 2313: func */
            4097, 8, 0, /* 2316: pointer.func */
            4097, 8, 0, /* 2319: pointer.func */
            0, 0, 0, /* 2322: func */
            0, 0, 0, /* 2325: func */
            0, 0, 0, /* 2328: func */
            4097, 8, 0, /* 2331: pointer.func */
            4097, 8, 0, /* 2334: pointer.func */
            4097, 8, 0, /* 2337: pointer.func */
            4097, 8, 0, /* 2340: pointer.func */
            0, 0, 0, /* 2343: func */
            0, 0, 0, /* 2346: func */
            4097, 8, 0, /* 2349: pointer.func */
            4097, 8, 0, /* 2352: pointer.func */
            4097, 8, 0, /* 2355: pointer.func */
        },
        .arg_entity_index = { 1825, },
        .ret_entity_index = 677,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_accept)(SSL *);
    orig_SSL_accept = dlsym(RTLD_NEXT, "SSL_accept");
    *new_ret_ptr = (*orig_SSL_accept)(new_arg_a);

    syscall(889);

    return ret;
}

