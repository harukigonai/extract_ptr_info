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

void bb_SSL_CTX_set_default_passwd_cb(SSL_CTX * arg_a,pem_password_cb * arg_b);

void SSL_CTX_set_default_passwd_cb(SSL_CTX * arg_a,pem_password_cb * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_set_default_passwd_cb called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_set_default_passwd_cb(arg_a,arg_b);
    else {
        void (*orig_SSL_CTX_set_default_passwd_cb)(SSL_CTX *,pem_password_cb *);
        orig_SSL_CTX_set_default_passwd_cb = dlsym(RTLD_NEXT, "SSL_CTX_set_default_passwd_cb");
        orig_SSL_CTX_set_default_passwd_cb(arg_a,arg_b);
    }
}

void bb_SSL_CTX_set_default_passwd_cb(SSL_CTX * arg_a,pem_password_cb * arg_b) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 32, 1, /* 0: struct.stack_st_SRTP_PROTECTION_PROFILE */
            	5, 0,
            0, 32, 2, /* 5: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 12: pointer.pointer.char */
            	17, 0,
            1, 8, 1, /* 17: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 22: pointer.func */
            0, 8, 1, /* 25: struct.ssl3_buf_freelist_entry_st */
            	30, 0,
            1, 8, 1, /* 30: pointer.struct.ssl3_buf_freelist_entry_st */
            	25, 0,
            1, 8, 1, /* 35: pointer.struct.ssl3_buf_freelist_st */
            	40, 0,
            0, 24, 1, /* 40: struct.ssl3_buf_freelist_st */
            	30, 16,
            4097, 8, 0, /* 45: pointer.func */
            4097, 8, 0, /* 48: pointer.func */
            4097, 8, 0, /* 51: pointer.func */
            4097, 8, 0, /* 54: pointer.func */
            0, 296, 7, /* 57: struct.cert_st */
            	74, 0,
            	931, 48,
            	936, 56,
            	939, 64,
            	944, 72,
            	947, 80,
            	54, 88,
            1, 8, 1, /* 74: pointer.struct.cert_pkey_st */
            	79, 0,
            0, 24, 3, /* 79: struct.cert_pkey_st */
            	88, 0,
            	400, 8,
            	886, 16,
            1, 8, 1, /* 88: pointer.struct.x509_st */
            	93, 0,
            0, 184, 12, /* 93: struct.x509_st */
            	120, 0,
            	168, 8,
            	267, 16,
            	17, 32,
            	560, 40,
            	272, 104,
            	779, 112,
            	803, 120,
            	811, 128,
            	821, 136,
            	826, 144,
            	848, 176,
            1, 8, 1, /* 120: pointer.struct.x509_cinf_st */
            	125, 0,
            0, 104, 11, /* 125: struct.x509_cinf_st */
            	150, 0,
            	150, 8,
            	168, 16,
            	335, 24,
            	369, 32,
            	335, 40,
            	386, 48,
            	267, 56,
            	267, 64,
            	764, 72,
            	774, 80,
            1, 8, 1, /* 150: pointer.struct.asn1_string_st */
            	155, 0,
            0, 24, 1, /* 155: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 160: pointer.unsigned char */
            	165, 0,
            0, 1, 0, /* 165: unsigned char */
            1, 8, 1, /* 168: pointer.struct.X509_algor_st */
            	173, 0,
            0, 16, 2, /* 173: struct.X509_algor_st */
            	180, 0,
            	204, 8,
            1, 8, 1, /* 180: pointer.struct.asn1_object_st */
            	185, 0,
            0, 40, 3, /* 185: struct.asn1_object_st */
            	194, 0,
            	194, 8,
            	199, 24,
            1, 8, 1, /* 194: pointer.char */
            	4096, 0,
            1, 8, 1, /* 199: pointer.unsigned char */
            	165, 0,
            1, 8, 1, /* 204: pointer.struct.asn1_type_st */
            	209, 0,
            0, 16, 1, /* 209: struct.asn1_type_st */
            	214, 8,
            0, 8, 20, /* 214: union.unknown */
            	17, 0,
            	257, 0,
            	180, 0,
            	150, 0,
            	262, 0,
            	267, 0,
            	272, 0,
            	277, 0,
            	282, 0,
            	287, 0,
            	292, 0,
            	297, 0,
            	302, 0,
            	307, 0,
            	312, 0,
            	317, 0,
            	322, 0,
            	257, 0,
            	257, 0,
            	327, 0,
            1, 8, 1, /* 257: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 262: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 267: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 272: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 277: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 282: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 287: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 292: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 297: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 302: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 307: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 312: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 317: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 322: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 327: pointer.struct.ASN1_VALUE_st */
            	332, 0,
            0, 0, 0, /* 332: struct.ASN1_VALUE_st */
            1, 8, 1, /* 335: pointer.struct.X509_name_st */
            	340, 0,
            0, 40, 3, /* 340: struct.X509_name_st */
            	349, 0,
            	359, 16,
            	160, 24,
            1, 8, 1, /* 349: pointer.struct.stack_st_X509_NAME_ENTRY */
            	354, 0,
            0, 32, 1, /* 354: struct.stack_st_X509_NAME_ENTRY */
            	5, 0,
            1, 8, 1, /* 359: pointer.struct.buf_mem_st */
            	364, 0,
            0, 24, 1, /* 364: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 369: pointer.struct.X509_val_st */
            	374, 0,
            0, 16, 2, /* 374: struct.X509_val_st */
            	381, 0,
            	381, 8,
            1, 8, 1, /* 381: pointer.struct.asn1_string_st */
            	155, 0,
            1, 8, 1, /* 386: pointer.struct.X509_pubkey_st */
            	391, 0,
            0, 24, 3, /* 391: struct.X509_pubkey_st */
            	168, 0,
            	267, 8,
            	400, 16,
            1, 8, 1, /* 400: pointer.struct.evp_pkey_st */
            	405, 0,
            0, 56, 4, /* 405: struct.evp_pkey_st */
            	416, 16,
            	424, 24,
            	432, 32,
            	754, 48,
            1, 8, 1, /* 416: pointer.struct.evp_pkey_asn1_method_st */
            	421, 0,
            0, 0, 0, /* 421: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 424: pointer.struct.engine_st */
            	429, 0,
            0, 0, 0, /* 429: struct.engine_st */
            0, 8, 5, /* 432: union.unknown */
            	17, 0,
            	445, 0,
            	597, 0,
            	678, 0,
            	746, 0,
            1, 8, 1, /* 445: pointer.struct.rsa_st */
            	450, 0,
            0, 168, 17, /* 450: struct.rsa_st */
            	487, 16,
            	424, 24,
            	542, 32,
            	542, 40,
            	542, 48,
            	542, 56,
            	542, 64,
            	542, 72,
            	542, 80,
            	542, 88,
            	560, 96,
            	575, 120,
            	575, 128,
            	575, 136,
            	17, 144,
            	589, 152,
            	589, 160,
            1, 8, 1, /* 487: pointer.struct.rsa_meth_st */
            	492, 0,
            0, 112, 13, /* 492: struct.rsa_meth_st */
            	194, 0,
            	521, 8,
            	521, 16,
            	521, 24,
            	521, 32,
            	524, 40,
            	527, 48,
            	530, 56,
            	530, 64,
            	17, 80,
            	533, 88,
            	536, 96,
            	539, 104,
            4097, 8, 0, /* 521: pointer.func */
            4097, 8, 0, /* 524: pointer.func */
            4097, 8, 0, /* 527: pointer.func */
            4097, 8, 0, /* 530: pointer.func */
            4097, 8, 0, /* 533: pointer.func */
            4097, 8, 0, /* 536: pointer.func */
            4097, 8, 0, /* 539: pointer.func */
            1, 8, 1, /* 542: pointer.struct.bignum_st */
            	547, 0,
            0, 24, 1, /* 547: struct.bignum_st */
            	552, 0,
            1, 8, 1, /* 552: pointer.unsigned int */
            	557, 0,
            0, 4, 0, /* 557: unsigned int */
            0, 16, 1, /* 560: struct.crypto_ex_data_st */
            	565, 0,
            1, 8, 1, /* 565: pointer.struct.stack_st_void */
            	570, 0,
            0, 32, 1, /* 570: struct.stack_st_void */
            	5, 0,
            1, 8, 1, /* 575: pointer.struct.bn_mont_ctx_st */
            	580, 0,
            0, 96, 3, /* 580: struct.bn_mont_ctx_st */
            	547, 8,
            	547, 32,
            	547, 56,
            1, 8, 1, /* 589: pointer.struct.bn_blinding_st */
            	594, 0,
            0, 0, 0, /* 594: struct.bn_blinding_st */
            1, 8, 1, /* 597: pointer.struct.dsa_st */
            	602, 0,
            0, 136, 11, /* 602: struct.dsa_st */
            	542, 24,
            	542, 32,
            	542, 40,
            	542, 48,
            	542, 56,
            	542, 64,
            	542, 72,
            	575, 88,
            	560, 104,
            	627, 120,
            	424, 128,
            1, 8, 1, /* 627: pointer.struct.dsa_method */
            	632, 0,
            0, 96, 11, /* 632: struct.dsa_method */
            	194, 0,
            	657, 8,
            	660, 16,
            	663, 24,
            	666, 32,
            	669, 40,
            	672, 48,
            	672, 56,
            	17, 72,
            	675, 80,
            	672, 88,
            4097, 8, 0, /* 657: pointer.func */
            4097, 8, 0, /* 660: pointer.func */
            4097, 8, 0, /* 663: pointer.func */
            4097, 8, 0, /* 666: pointer.func */
            4097, 8, 0, /* 669: pointer.func */
            4097, 8, 0, /* 672: pointer.func */
            4097, 8, 0, /* 675: pointer.func */
            1, 8, 1, /* 678: pointer.struct.dh_st */
            	683, 0,
            0, 144, 12, /* 683: struct.dh_st */
            	542, 8,
            	542, 16,
            	542, 32,
            	542, 40,
            	575, 56,
            	542, 64,
            	542, 72,
            	160, 80,
            	542, 96,
            	560, 112,
            	710, 128,
            	424, 136,
            1, 8, 1, /* 710: pointer.struct.dh_method */
            	715, 0,
            0, 72, 8, /* 715: struct.dh_method */
            	194, 0,
            	734, 8,
            	737, 16,
            	740, 24,
            	734, 32,
            	734, 40,
            	17, 56,
            	743, 64,
            4097, 8, 0, /* 734: pointer.func */
            4097, 8, 0, /* 737: pointer.func */
            4097, 8, 0, /* 740: pointer.func */
            4097, 8, 0, /* 743: pointer.func */
            1, 8, 1, /* 746: pointer.struct.ec_key_st */
            	751, 0,
            0, 0, 0, /* 751: struct.ec_key_st */
            1, 8, 1, /* 754: pointer.struct.stack_st_X509_ATTRIBUTE */
            	759, 0,
            0, 32, 1, /* 759: struct.stack_st_X509_ATTRIBUTE */
            	5, 0,
            1, 8, 1, /* 764: pointer.struct.stack_st_X509_EXTENSION */
            	769, 0,
            0, 32, 1, /* 769: struct.stack_st_X509_EXTENSION */
            	5, 0,
            0, 24, 1, /* 774: struct.ASN1_ENCODING_st */
            	160, 0,
            1, 8, 1, /* 779: pointer.struct.AUTHORITY_KEYID_st */
            	784, 0,
            0, 24, 3, /* 784: struct.AUTHORITY_KEYID_st */
            	272, 0,
            	793, 8,
            	150, 16,
            1, 8, 1, /* 793: pointer.struct.stack_st_GENERAL_NAME */
            	798, 0,
            0, 32, 1, /* 798: struct.stack_st_GENERAL_NAME */
            	5, 0,
            1, 8, 1, /* 803: pointer.struct.X509_POLICY_CACHE_st */
            	808, 0,
            0, 0, 0, /* 808: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 811: pointer.struct.stack_st_DIST_POINT */
            	816, 0,
            0, 32, 1, /* 816: struct.stack_st_DIST_POINT */
            	5, 0,
            1, 8, 1, /* 821: pointer.struct.stack_st_GENERAL_NAME */
            	798, 0,
            1, 8, 1, /* 826: pointer.struct.NAME_CONSTRAINTS_st */
            	831, 0,
            0, 16, 2, /* 831: struct.NAME_CONSTRAINTS_st */
            	838, 0,
            	838, 8,
            1, 8, 1, /* 838: pointer.struct.stack_st_GENERAL_SUBTREE */
            	843, 0,
            0, 32, 1, /* 843: struct.stack_st_GENERAL_SUBTREE */
            	5, 0,
            1, 8, 1, /* 848: pointer.struct.x509_cert_aux_st */
            	853, 0,
            0, 40, 5, /* 853: struct.x509_cert_aux_st */
            	866, 0,
            	866, 8,
            	322, 16,
            	272, 24,
            	876, 32,
            1, 8, 1, /* 866: pointer.struct.stack_st_ASN1_OBJECT */
            	871, 0,
            0, 32, 1, /* 871: struct.stack_st_ASN1_OBJECT */
            	5, 0,
            1, 8, 1, /* 876: pointer.struct.stack_st_X509_ALGOR */
            	881, 0,
            0, 32, 1, /* 881: struct.stack_st_X509_ALGOR */
            	5, 0,
            1, 8, 1, /* 886: pointer.struct.env_md_st */
            	891, 0,
            0, 120, 8, /* 891: struct.env_md_st */
            	910, 24,
            	913, 32,
            	916, 40,
            	919, 48,
            	910, 56,
            	922, 64,
            	925, 72,
            	928, 112,
            4097, 8, 0, /* 910: pointer.func */
            4097, 8, 0, /* 913: pointer.func */
            4097, 8, 0, /* 916: pointer.func */
            4097, 8, 0, /* 919: pointer.func */
            4097, 8, 0, /* 922: pointer.func */
            4097, 8, 0, /* 925: pointer.func */
            4097, 8, 0, /* 928: pointer.func */
            1, 8, 1, /* 931: pointer.struct.rsa_st */
            	450, 0,
            4097, 8, 0, /* 936: pointer.func */
            1, 8, 1, /* 939: pointer.struct.dh_st */
            	683, 0,
            4097, 8, 0, /* 944: pointer.func */
            1, 8, 1, /* 947: pointer.struct.ec_key_st */
            	751, 0,
            0, 32, 1, /* 952: struct.stack_st_X509_NAME */
            	5, 0,
            1, 8, 1, /* 957: pointer.struct.stack_st_SSL_COMP */
            	962, 0,
            0, 32, 1, /* 962: struct.stack_st_SSL_COMP */
            	5, 0,
            4097, 8, 0, /* 967: pointer.func */
            4097, 8, 0, /* 970: pointer.func */
            4097, 8, 0, /* 973: pointer.func */
            4097, 8, 0, /* 976: pointer.func */
            4097, 8, 0, /* 979: pointer.func */
            0, 128, 14, /* 982: struct.srp_ctx_st */
            	1013, 0,
            	48, 8,
            	1016, 16,
            	1019, 24,
            	17, 32,
            	542, 40,
            	542, 48,
            	542, 56,
            	542, 64,
            	542, 72,
            	542, 80,
            	542, 88,
            	542, 96,
            	17, 104,
            0, 8, 0, /* 1013: pointer.void */
            4097, 8, 0, /* 1016: pointer.func */
            4097, 8, 0, /* 1019: pointer.func */
            4097, 8, 0, /* 1022: pointer.func */
            0, 88, 1, /* 1025: struct.ssl_cipher_st */
            	194, 8,
            1, 8, 1, /* 1030: pointer.struct.ssl_cipher_st */
            	1025, 0,
            4097, 8, 0, /* 1035: pointer.func */
            1, 8, 1, /* 1038: pointer.struct.cert_st */
            	57, 0,
            4097, 8, 0, /* 1043: pointer.func */
            4097, 8, 0, /* 1046: pointer.func */
            0, 248, 5, /* 1049: struct.sess_cert_st */
            	1062, 0,
            	74, 16,
            	931, 216,
            	939, 224,
            	947, 232,
            1, 8, 1, /* 1062: pointer.struct.stack_st_X509 */
            	1067, 0,
            0, 32, 1, /* 1067: struct.stack_st_X509 */
            	5, 0,
            1, 8, 1, /* 1072: pointer.struct.stack_st_X509_OBJECT */
            	1077, 0,
            0, 32, 1, /* 1077: struct.stack_st_X509_OBJECT */
            	5, 0,
            4097, 8, 0, /* 1082: pointer.func */
            4097, 8, 0, /* 1085: pointer.func */
            0, 32, 1, /* 1088: struct.stack_st_X509_LOOKUP */
            	5, 0,
            4097, 8, 0, /* 1093: pointer.func */
            1, 8, 1, /* 1096: pointer.struct.stack_st_X509_LOOKUP */
            	1088, 0,
            4097, 8, 0, /* 1101: pointer.func */
            0, 144, 15, /* 1104: struct.x509_store_st */
            	1072, 8,
            	1096, 16,
            	1137, 24,
            	1149, 32,
            	1152, 40,
            	1155, 48,
            	1158, 56,
            	1149, 64,
            	1161, 72,
            	1164, 80,
            	1167, 88,
            	1170, 96,
            	1173, 104,
            	1149, 112,
            	560, 120,
            1, 8, 1, /* 1137: pointer.struct.X509_VERIFY_PARAM_st */
            	1142, 0,
            0, 56, 2, /* 1142: struct.X509_VERIFY_PARAM_st */
            	17, 0,
            	866, 48,
            4097, 8, 0, /* 1149: pointer.func */
            4097, 8, 0, /* 1152: pointer.func */
            4097, 8, 0, /* 1155: pointer.func */
            4097, 8, 0, /* 1158: pointer.func */
            4097, 8, 0, /* 1161: pointer.func */
            4097, 8, 0, /* 1164: pointer.func */
            4097, 8, 0, /* 1167: pointer.func */
            4097, 8, 0, /* 1170: pointer.func */
            4097, 8, 0, /* 1173: pointer.func */
            4097, 8, 0, /* 1176: pointer.func */
            0, 32, 1, /* 1179: struct.stack_st_SSL_CIPHER */
            	5, 0,
            1, 8, 1, /* 1184: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	0, 0,
            4097, 8, 0, /* 1189: pointer.func */
            0, 24, 2, /* 1192: struct.lhash_node_st */
            	1013, 0,
            	1199, 8,
            1, 8, 1, /* 1199: pointer.struct.lhash_node_st */
            	1192, 0,
            4097, 8, 0, /* 1204: pointer.func */
            1, 8, 1, /* 1207: pointer.struct.stack_st_X509_NAME */
            	952, 0,
            1, 8, 1, /* 1212: pointer.struct.ssl_session_st */
            	1217, 0,
            0, 352, 14, /* 1217: struct.ssl_session_st */
            	17, 144,
            	17, 152,
            	1248, 168,
            	88, 176,
            	1030, 224,
            	1253, 240,
            	560, 248,
            	1212, 264,
            	1212, 272,
            	17, 280,
            	160, 296,
            	160, 312,
            	160, 320,
            	17, 344,
            1, 8, 1, /* 1248: pointer.struct.sess_cert_st */
            	1049, 0,
            1, 8, 1, /* 1253: pointer.struct.stack_st_SSL_CIPHER */
            	1179, 0,
            4097, 8, 0, /* 1258: pointer.func */
            4097, 8, 0, /* 1261: pointer.func */
            4097, 8, 0, /* 1264: pointer.func */
            4097, 8, 0, /* 1267: pointer.func */
            4097, 8, 0, /* 1270: pointer.func */
            0, 1, 0, /* 1273: char */
            4097, 8, 0, /* 1276: pointer.func */
            4097, 8, 0, /* 1279: pointer.func */
            1, 8, 1, /* 1282: pointer.struct.ssl_method_st */
            	1287, 0,
            0, 232, 28, /* 1287: struct.ssl_method_st */
            	1346, 8,
            	1349, 16,
            	1349, 24,
            	1346, 32,
            	1346, 40,
            	1352, 48,
            	1352, 56,
            	1355, 64,
            	1346, 72,
            	1346, 80,
            	1346, 88,
            	1358, 96,
            	1204, 104,
            	1258, 112,
            	1346, 120,
            	1189, 128,
            	1361, 136,
            	1364, 144,
            	1367, 152,
            	1370, 160,
            	1267, 168,
            	1373, 176,
            	1376, 184,
            	1379, 192,
            	1382, 200,
            	1267, 208,
            	1421, 216,
            	1264, 224,
            4097, 8, 0, /* 1346: pointer.func */
            4097, 8, 0, /* 1349: pointer.func */
            4097, 8, 0, /* 1352: pointer.func */
            4097, 8, 0, /* 1355: pointer.func */
            4097, 8, 0, /* 1358: pointer.func */
            4097, 8, 0, /* 1361: pointer.func */
            4097, 8, 0, /* 1364: pointer.func */
            4097, 8, 0, /* 1367: pointer.func */
            4097, 8, 0, /* 1370: pointer.func */
            4097, 8, 0, /* 1373: pointer.func */
            4097, 8, 0, /* 1376: pointer.func */
            4097, 8, 0, /* 1379: pointer.func */
            1, 8, 1, /* 1382: pointer.struct.ssl3_enc_method */
            	1387, 0,
            0, 112, 11, /* 1387: struct.ssl3_enc_method */
            	1279, 0,
            	1082, 8,
            	1346, 16,
            	1412, 24,
            	1279, 32,
            	1270, 40,
            	1415, 56,
            	194, 64,
            	194, 80,
            	1101, 96,
            	1418, 104,
            4097, 8, 0, /* 1412: pointer.func */
            4097, 8, 0, /* 1415: pointer.func */
            4097, 8, 0, /* 1418: pointer.func */
            4097, 8, 0, /* 1421: pointer.func */
            0, 736, 50, /* 1424: struct.ssl_ctx_st */
            	1282, 0,
            	1253, 8,
            	1253, 16,
            	1527, 24,
            	1532, 32,
            	1212, 48,
            	1212, 56,
            	1022, 80,
            	979, 88,
            	976, 96,
            	973, 152,
            	1013, 160,
            	1556, 168,
            	1013, 176,
            	1046, 184,
            	970, 192,
            	967, 200,
            	560, 208,
            	886, 224,
            	886, 232,
            	886, 240,
            	1062, 248,
            	957, 256,
            	1093, 264,
            	1207, 272,
            	1038, 304,
            	51, 320,
            	1013, 328,
            	1152, 376,
            	1559, 384,
            	1137, 392,
            	424, 408,
            	48, 416,
            	1013, 424,
            	1276, 480,
            	1016, 488,
            	1013, 496,
            	1043, 504,
            	1013, 512,
            	17, 520,
            	45, 528,
            	1035, 536,
            	35, 552,
            	35, 560,
            	982, 568,
            	1176, 696,
            	1013, 704,
            	1085, 712,
            	1013, 720,
            	1184, 728,
            1, 8, 1, /* 1527: pointer.struct.x509_store_st */
            	1104, 0,
            1, 8, 1, /* 1532: pointer.struct.lhash_st */
            	1537, 0,
            0, 176, 3, /* 1537: struct.lhash_st */
            	1546, 0,
            	22, 8,
            	1261, 16,
            1, 8, 1, /* 1546: pointer.pointer.struct.lhash_node_st */
            	1551, 0,
            1, 8, 1, /* 1551: pointer.struct.lhash_node_st */
            	1192, 0,
            4097, 8, 0, /* 1556: pointer.func */
            4097, 8, 0, /* 1559: pointer.func */
            1, 8, 1, /* 1562: pointer.struct.ssl_ctx_st */
            	1424, 0,
        },
        .arg_entity_index = { 1562, 1556, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    pem_password_cb * new_arg_b = *((pem_password_cb * *)new_args->args[1]);

    void (*orig_SSL_CTX_set_default_passwd_cb)(SSL_CTX *,pem_password_cb *);
    orig_SSL_CTX_set_default_passwd_cb = dlsym(RTLD_NEXT, "SSL_CTX_set_default_passwd_cb");
    (*orig_SSL_CTX_set_default_passwd_cb)(new_arg_a,new_arg_b);

    syscall(889);

}

