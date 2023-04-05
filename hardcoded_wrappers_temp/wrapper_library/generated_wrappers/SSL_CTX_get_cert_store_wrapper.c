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
            4097, 8, 0, /* 982: pointer.func */
            0, 128, 14, /* 985: struct.srp_ctx_st */
            	1016, 0,
            	48, 8,
            	1019, 16,
            	1022, 24,
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
            0, 8, 0, /* 1016: pointer.void */
            4097, 8, 0, /* 1019: pointer.func */
            4097, 8, 0, /* 1022: pointer.func */
            4097, 8, 0, /* 1025: pointer.func */
            0, 88, 1, /* 1028: struct.ssl_cipher_st */
            	194, 8,
            1, 8, 1, /* 1033: pointer.struct.ssl_cipher_st */
            	1028, 0,
            4097, 8, 0, /* 1038: pointer.func */
            1, 8, 1, /* 1041: pointer.struct.cert_st */
            	57, 0,
            4097, 8, 0, /* 1046: pointer.func */
            4097, 8, 0, /* 1049: pointer.func */
            4097, 8, 0, /* 1052: pointer.func */
            0, 176, 3, /* 1055: struct.lhash_st */
            	1064, 0,
            	22, 8,
            	1086, 16,
            1, 8, 1, /* 1064: pointer.pointer.struct.lhash_node_st */
            	1069, 0,
            1, 8, 1, /* 1069: pointer.struct.lhash_node_st */
            	1074, 0,
            0, 24, 2, /* 1074: struct.lhash_node_st */
            	1016, 0,
            	1081, 8,
            1, 8, 1, /* 1081: pointer.struct.lhash_node_st */
            	1074, 0,
            4097, 8, 0, /* 1086: pointer.func */
            4097, 8, 0, /* 1089: pointer.func */
            0, 112, 11, /* 1092: struct.ssl3_enc_method */
            	1117, 0,
            	1120, 8,
            	1123, 16,
            	1126, 24,
            	1117, 32,
            	1129, 40,
            	1089, 56,
            	194, 64,
            	194, 80,
            	1052, 96,
            	1132, 104,
            4097, 8, 0, /* 1117: pointer.func */
            4097, 8, 0, /* 1120: pointer.func */
            4097, 8, 0, /* 1123: pointer.func */
            4097, 8, 0, /* 1126: pointer.func */
            4097, 8, 0, /* 1129: pointer.func */
            4097, 8, 0, /* 1132: pointer.func */
            4097, 8, 0, /* 1135: pointer.func */
            4097, 8, 0, /* 1138: pointer.func */
            4097, 8, 0, /* 1141: pointer.func */
            1, 8, 1, /* 1144: pointer.struct.stack_st_X509_NAME */
            	952, 0,
            1, 8, 1, /* 1149: pointer.struct.ssl_session_st */
            	1154, 0,
            0, 352, 14, /* 1154: struct.ssl_session_st */
            	17, 144,
            	17, 152,
            	1185, 168,
            	88, 176,
            	1033, 224,
            	1213, 240,
            	560, 248,
            	1149, 264,
            	1149, 272,
            	17, 280,
            	160, 296,
            	160, 312,
            	160, 320,
            	17, 344,
            1, 8, 1, /* 1185: pointer.struct.sess_cert_st */
            	1190, 0,
            0, 248, 5, /* 1190: struct.sess_cert_st */
            	1203, 0,
            	74, 16,
            	931, 216,
            	939, 224,
            	947, 232,
            1, 8, 1, /* 1203: pointer.struct.stack_st_X509 */
            	1208, 0,
            0, 32, 1, /* 1208: struct.stack_st_X509 */
            	5, 0,
            1, 8, 1, /* 1213: pointer.struct.stack_st_SSL_CIPHER */
            	1218, 0,
            0, 32, 1, /* 1218: struct.stack_st_SSL_CIPHER */
            	5, 0,
            4097, 8, 0, /* 1223: pointer.func */
            4097, 8, 0, /* 1226: pointer.func */
            4097, 8, 0, /* 1229: pointer.func */
            4097, 8, 0, /* 1232: pointer.func */
            0, 32, 1, /* 1235: struct.stack_st_X509_LOOKUP */
            	5, 0,
            1, 8, 1, /* 1240: pointer.struct.stack_st_X509_OBJECT */
            	1245, 0,
            0, 32, 1, /* 1245: struct.stack_st_X509_OBJECT */
            	5, 0,
            1, 8, 1, /* 1250: pointer.struct.x509_store_st */
            	1255, 0,
            0, 144, 15, /* 1255: struct.x509_store_st */
            	1240, 8,
            	1288, 16,
            	1293, 24,
            	1305, 32,
            	1308, 40,
            	1311, 48,
            	1314, 56,
            	1305, 64,
            	1317, 72,
            	1320, 80,
            	1323, 88,
            	1326, 96,
            	1329, 104,
            	1305, 112,
            	560, 120,
            1, 8, 1, /* 1288: pointer.struct.stack_st_X509_LOOKUP */
            	1235, 0,
            1, 8, 1, /* 1293: pointer.struct.X509_VERIFY_PARAM_st */
            	1298, 0,
            0, 56, 2, /* 1298: struct.X509_VERIFY_PARAM_st */
            	17, 0,
            	866, 48,
            4097, 8, 0, /* 1305: pointer.func */
            4097, 8, 0, /* 1308: pointer.func */
            4097, 8, 0, /* 1311: pointer.func */
            4097, 8, 0, /* 1314: pointer.func */
            4097, 8, 0, /* 1317: pointer.func */
            4097, 8, 0, /* 1320: pointer.func */
            4097, 8, 0, /* 1323: pointer.func */
            4097, 8, 0, /* 1326: pointer.func */
            4097, 8, 0, /* 1329: pointer.func */
            4097, 8, 0, /* 1332: pointer.func */
            1, 8, 1, /* 1335: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	0, 0,
            0, 736, 50, /* 1340: struct.ssl_ctx_st */
            	1443, 0,
            	1213, 8,
            	1213, 16,
            	1545, 24,
            	1550, 32,
            	1149, 48,
            	1149, 56,
            	1025, 80,
            	982, 88,
            	979, 96,
            	976, 152,
            	1016, 160,
            	973, 168,
            	1016, 176,
            	1049, 184,
            	970, 192,
            	967, 200,
            	560, 208,
            	886, 224,
            	886, 232,
            	886, 240,
            	1203, 248,
            	957, 256,
            	1332, 264,
            	1144, 272,
            	1041, 304,
            	51, 320,
            	1016, 328,
            	1308, 376,
            	1555, 384,
            	1293, 392,
            	424, 408,
            	48, 416,
            	1016, 424,
            	1558, 480,
            	1019, 488,
            	1016, 496,
            	1046, 504,
            	1016, 512,
            	17, 520,
            	45, 528,
            	1038, 536,
            	35, 552,
            	35, 560,
            	985, 568,
            	1561, 696,
            	1016, 704,
            	1232, 712,
            	1016, 720,
            	1335, 728,
            1, 8, 1, /* 1443: pointer.struct.ssl_method_st */
            	1448, 0,
            0, 232, 28, /* 1448: struct.ssl_method_st */
            	1123, 8,
            	1507, 16,
            	1507, 24,
            	1123, 32,
            	1123, 40,
            	1510, 48,
            	1510, 56,
            	1513, 64,
            	1123, 72,
            	1123, 80,
            	1123, 88,
            	1226, 96,
            	1141, 104,
            	1138, 112,
            	1123, 120,
            	1516, 128,
            	1519, 136,
            	1135, 144,
            	1223, 152,
            	1522, 160,
            	1229, 168,
            	1525, 176,
            	1528, 184,
            	1531, 192,
            	1534, 200,
            	1229, 208,
            	1539, 216,
            	1542, 224,
            4097, 8, 0, /* 1507: pointer.func */
            4097, 8, 0, /* 1510: pointer.func */
            4097, 8, 0, /* 1513: pointer.func */
            4097, 8, 0, /* 1516: pointer.func */
            4097, 8, 0, /* 1519: pointer.func */
            4097, 8, 0, /* 1522: pointer.func */
            4097, 8, 0, /* 1525: pointer.func */
            4097, 8, 0, /* 1528: pointer.func */
            4097, 8, 0, /* 1531: pointer.func */
            1, 8, 1, /* 1534: pointer.struct.ssl3_enc_method */
            	1092, 0,
            4097, 8, 0, /* 1539: pointer.func */
            4097, 8, 0, /* 1542: pointer.func */
            1, 8, 1, /* 1545: pointer.struct.x509_store_st */
            	1255, 0,
            1, 8, 1, /* 1550: pointer.struct.lhash_st */
            	1055, 0,
            4097, 8, 0, /* 1555: pointer.func */
            4097, 8, 0, /* 1558: pointer.func */
            4097, 8, 0, /* 1561: pointer.func */
            0, 1, 0, /* 1564: char */
            1, 8, 1, /* 1567: pointer.struct.ssl_ctx_st */
            	1340, 0,
        },
        .arg_entity_index = { 1567, },
        .ret_entity_index = 1250,
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

