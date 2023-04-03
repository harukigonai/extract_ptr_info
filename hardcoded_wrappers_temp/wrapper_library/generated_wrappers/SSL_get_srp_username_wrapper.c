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

char * bb_SSL_get_srp_username(SSL * arg_a);

char * SSL_get_srp_username(SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_srp_username called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_srp_username(arg_a);
    else {
        char * (*orig_SSL_get_srp_username)(SSL *);
        orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
        return orig_SSL_get_srp_username(arg_a);
    }
}

char * bb_SSL_get_srp_username(SSL * arg_a) 
{
    char * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            4097, 8, 0, /* 6: pointer.func */
            0, 0, 0, /* 9: func */
            4097, 8, 0, /* 12: pointer.func */
            0, 0, 0, /* 15: func */
            4097, 8, 0, /* 18: pointer.func */
            0, 0, 0, /* 21: func */
            4097, 8, 0, /* 24: pointer.func */
            0, 0, 0, /* 27: func */
            0, 0, 0, /* 30: func */
            0, 44, 0, /* 33: struct.apr_time_exp_t */
            0, 0, 0, /* 36: func */
            4097, 8, 0, /* 39: pointer.func */
            0, 4, 0, /* 42: struct.in_addr */
            1, 8, 1, /* 45: pointer.struct.in_addr */
            	42, 0,
            4097, 8, 0, /* 50: pointer.func */
            4097, 8, 0, /* 53: pointer.func */
            0, 0, 0, /* 56: func */
            0, 0, 0, /* 59: func */
            0, 0, 0, /* 62: func */
            4097, 8, 0, /* 65: pointer.func */
            0, 0, 0, /* 68: func */
            0, 0, 0, /* 71: func */
            0, 0, 0, /* 74: func */
            4097, 8, 0, /* 77: pointer.func */
            0, 0, 0, /* 80: func */
            4097, 8, 0, /* 83: pointer.func */
            0, 0, 0, /* 86: func */
            0, 296, 8, /* 89: struct.cert_st */
            	108, 0,
            	880, 48,
            	981, 56,
            	984, 64,
            	1016, 72,
            	1019, 80,
            	1255, 88,
            	1258, 96,
            1, 8, 1, /* 108: pointer.struct.cert_pkey_st */
            	113, 0,
            0, 24, 3, /* 113: struct.cert_pkey_st */
            	122, 0,
            	315, 8,
            	835, 16,
            1, 8, 1, /* 122: pointer.struct.x509_st */
            	127, 0,
            0, 184, 12, /* 127: struct.x509_st */
            	154, 0,
            	199, 8,
            	184, 16,
            	194, 32,
            	755, 40,
            	184, 104,
            	765, 112,
            	779, 120,
            	254, 128,
            	254, 136,
            	805, 144,
            	817, 176,
            1, 8, 1, /* 154: pointer.struct.x509_cinf_st */
            	159, 0,
            0, 104, 11, /* 159: struct.x509_cinf_st */
            	184, 0,
            	184, 8,
            	199, 16,
            	240, 24,
            	289, 32,
            	240, 40,
            	301, 48,
            	184, 56,
            	184, 64,
            	254, 72,
            	760, 80,
            1, 8, 1, /* 184: pointer.struct.asn1_string_st */
            	189, 0,
            0, 24, 1, /* 189: struct.asn1_string_st */
            	194, 8,
            1, 8, 1, /* 194: pointer.char */
            	4096, 0,
            1, 8, 1, /* 199: pointer.struct.X509_algor_st */
            	204, 0,
            0, 16, 2, /* 204: struct.X509_algor_st */
            	211, 0,
            	225, 8,
            1, 8, 1, /* 211: pointer.struct.asn1_object_st */
            	216, 0,
            0, 40, 3, /* 216: struct.asn1_object_st */
            	194, 0,
            	194, 8,
            	194, 24,
            1, 8, 1, /* 225: pointer.struct.asn1_type_st */
            	230, 0,
            0, 16, 1, /* 230: struct.asn1_type_st */
            	235, 8,
            0, 8, 1, /* 235: struct.fnames */
            	194, 0,
            1, 8, 1, /* 240: pointer.struct.X509_name_st */
            	245, 0,
            0, 40, 3, /* 245: struct.X509_name_st */
            	254, 0,
            	279, 16,
            	194, 24,
            1, 8, 1, /* 254: pointer.struct.stack_st_OPENSSL_STRING */
            	259, 0,
            0, 32, 1, /* 259: struct.stack_st_OPENSSL_STRING */
            	264, 0,
            0, 32, 2, /* 264: struct.stack_st */
            	271, 8,
            	276, 24,
            1, 8, 1, /* 271: pointer.pointer.char */
            	194, 0,
            4097, 8, 0, /* 276: pointer.func */
            1, 8, 1, /* 279: pointer.struct.buf_mem_st */
            	284, 0,
            0, 24, 1, /* 284: struct.buf_mem_st */
            	194, 8,
            1, 8, 1, /* 289: pointer.struct.X509_val_st */
            	294, 0,
            0, 16, 2, /* 294: struct.X509_val_st */
            	184, 0,
            	184, 8,
            1, 8, 1, /* 301: pointer.struct.X509_pubkey_st */
            	306, 0,
            0, 24, 3, /* 306: struct.X509_pubkey_st */
            	199, 0,
            	184, 8,
            	315, 16,
            1, 8, 1, /* 315: pointer.struct.evp_pkey_st */
            	320, 0,
            0, 56, 4, /* 320: struct.evp_pkey_st */
            	331, 16,
            	434, 24,
            	235, 32,
            	254, 48,
            1, 8, 1, /* 331: pointer.struct.evp_pkey_asn1_method_st */
            	336, 0,
            0, 208, 24, /* 336: struct.evp_pkey_asn1_method_st */
            	194, 16,
            	194, 24,
            	387, 32,
            	395, 40,
            	398, 48,
            	401, 56,
            	404, 64,
            	407, 72,
            	401, 80,
            	410, 88,
            	410, 96,
            	413, 104,
            	416, 112,
            	410, 120,
            	398, 128,
            	398, 136,
            	401, 144,
            	419, 152,
            	422, 160,
            	425, 168,
            	413, 176,
            	416, 184,
            	428, 192,
            	431, 200,
            1, 8, 1, /* 387: pointer.struct.unnamed */
            	392, 0,
            0, 0, 0, /* 392: struct.unnamed */
            4097, 8, 0, /* 395: pointer.func */
            4097, 8, 0, /* 398: pointer.func */
            4097, 8, 0, /* 401: pointer.func */
            4097, 8, 0, /* 404: pointer.func */
            4097, 8, 0, /* 407: pointer.func */
            4097, 8, 0, /* 410: pointer.func */
            4097, 8, 0, /* 413: pointer.func */
            4097, 8, 0, /* 416: pointer.func */
            4097, 8, 0, /* 419: pointer.func */
            4097, 8, 0, /* 422: pointer.func */
            4097, 8, 0, /* 425: pointer.func */
            4097, 8, 0, /* 428: pointer.func */
            4097, 8, 0, /* 431: pointer.func */
            1, 8, 1, /* 434: pointer.struct.engine_st */
            	439, 0,
            0, 216, 24, /* 439: struct.engine_st */
            	194, 0,
            	194, 8,
            	490, 16,
            	545, 24,
            	596, 32,
            	632, 40,
            	649, 48,
            	676, 56,
            	711, 64,
            	719, 72,
            	722, 80,
            	725, 88,
            	728, 96,
            	731, 104,
            	731, 112,
            	731, 120,
            	734, 128,
            	737, 136,
            	737, 144,
            	740, 152,
            	743, 160,
            	755, 184,
            	434, 200,
            	434, 208,
            1, 8, 1, /* 490: pointer.struct.rsa_meth_st */
            	495, 0,
            0, 112, 13, /* 495: struct.rsa_meth_st */
            	194, 0,
            	524, 8,
            	524, 16,
            	524, 24,
            	524, 32,
            	527, 40,
            	530, 48,
            	533, 56,
            	533, 64,
            	194, 80,
            	536, 88,
            	539, 96,
            	542, 104,
            4097, 8, 0, /* 524: pointer.func */
            4097, 8, 0, /* 527: pointer.func */
            4097, 8, 0, /* 530: pointer.func */
            4097, 8, 0, /* 533: pointer.func */
            4097, 8, 0, /* 536: pointer.func */
            4097, 8, 0, /* 539: pointer.func */
            4097, 8, 0, /* 542: pointer.func */
            1, 8, 1, /* 545: pointer.struct.dsa_method */
            	550, 0,
            0, 96, 11, /* 550: struct.dsa_method */
            	194, 0,
            	575, 8,
            	578, 16,
            	581, 24,
            	584, 32,
            	587, 40,
            	590, 48,
            	590, 56,
            	194, 72,
            	593, 80,
            	590, 88,
            4097, 8, 0, /* 575: pointer.func */
            4097, 8, 0, /* 578: pointer.func */
            4097, 8, 0, /* 581: pointer.func */
            4097, 8, 0, /* 584: pointer.func */
            4097, 8, 0, /* 587: pointer.func */
            4097, 8, 0, /* 590: pointer.func */
            4097, 8, 0, /* 593: pointer.func */
            1, 8, 1, /* 596: pointer.struct.dh_method */
            	601, 0,
            0, 72, 8, /* 601: struct.dh_method */
            	194, 0,
            	620, 8,
            	623, 16,
            	626, 24,
            	620, 32,
            	620, 40,
            	194, 56,
            	629, 64,
            4097, 8, 0, /* 620: pointer.func */
            4097, 8, 0, /* 623: pointer.func */
            4097, 8, 0, /* 626: pointer.func */
            4097, 8, 0, /* 629: pointer.func */
            1, 8, 1, /* 632: pointer.struct.ecdh_method */
            	637, 0,
            0, 32, 3, /* 637: struct.ecdh_method */
            	194, 0,
            	646, 8,
            	194, 24,
            4097, 8, 0, /* 646: pointer.func */
            1, 8, 1, /* 649: pointer.struct.ecdsa_method */
            	654, 0,
            0, 48, 5, /* 654: struct.ecdsa_method */
            	194, 0,
            	667, 8,
            	670, 16,
            	673, 24,
            	194, 40,
            4097, 8, 0, /* 667: pointer.func */
            4097, 8, 0, /* 670: pointer.func */
            4097, 8, 0, /* 673: pointer.func */
            1, 8, 1, /* 676: pointer.struct.rand_meth_st */
            	681, 0,
            0, 48, 6, /* 681: struct.rand_meth_st */
            	696, 0,
            	699, 8,
            	702, 16,
            	705, 24,
            	699, 32,
            	708, 40,
            4097, 8, 0, /* 696: pointer.func */
            4097, 8, 0, /* 699: pointer.func */
            4097, 8, 0, /* 702: pointer.func */
            4097, 8, 0, /* 705: pointer.func */
            4097, 8, 0, /* 708: pointer.func */
            1, 8, 1, /* 711: pointer.struct.store_method_st */
            	716, 0,
            0, 0, 0, /* 716: struct.store_method_st */
            4097, 8, 0, /* 719: pointer.func */
            4097, 8, 0, /* 722: pointer.func */
            4097, 8, 0, /* 725: pointer.func */
            4097, 8, 0, /* 728: pointer.func */
            4097, 8, 0, /* 731: pointer.func */
            4097, 8, 0, /* 734: pointer.func */
            4097, 8, 0, /* 737: pointer.func */
            4097, 8, 0, /* 740: pointer.func */
            1, 8, 1, /* 743: pointer.struct.ENGINE_CMD_DEFN_st */
            	748, 0,
            0, 32, 2, /* 748: struct.ENGINE_CMD_DEFN_st */
            	194, 8,
            	194, 16,
            0, 16, 1, /* 755: struct.crypto_ex_data_st */
            	254, 0,
            0, 24, 1, /* 760: struct.ASN1_ENCODING_st */
            	194, 0,
            1, 8, 1, /* 765: pointer.struct.AUTHORITY_KEYID_st */
            	770, 0,
            0, 24, 3, /* 770: struct.AUTHORITY_KEYID_st */
            	184, 0,
            	254, 8,
            	184, 16,
            1, 8, 1, /* 779: pointer.struct.X509_POLICY_CACHE_st */
            	784, 0,
            0, 40, 2, /* 784: struct.X509_POLICY_CACHE_st */
            	791, 0,
            	254, 8,
            1, 8, 1, /* 791: pointer.struct.X509_POLICY_DATA_st */
            	796, 0,
            0, 32, 3, /* 796: struct.X509_POLICY_DATA_st */
            	211, 8,
            	254, 16,
            	254, 24,
            1, 8, 1, /* 805: pointer.struct.NAME_CONSTRAINTS_st */
            	810, 0,
            0, 16, 2, /* 810: struct.NAME_CONSTRAINTS_st */
            	254, 0,
            	254, 8,
            1, 8, 1, /* 817: pointer.struct.x509_cert_aux_st */
            	822, 0,
            0, 40, 5, /* 822: struct.x509_cert_aux_st */
            	254, 0,
            	254, 8,
            	184, 16,
            	184, 24,
            	254, 32,
            1, 8, 1, /* 835: pointer.struct.env_md_st */
            	840, 0,
            0, 120, 8, /* 840: struct.env_md_st */
            	859, 24,
            	862, 32,
            	865, 40,
            	868, 48,
            	859, 56,
            	871, 64,
            	874, 72,
            	877, 112,
            4097, 8, 0, /* 859: pointer.func */
            4097, 8, 0, /* 862: pointer.func */
            4097, 8, 0, /* 865: pointer.func */
            4097, 8, 0, /* 868: pointer.func */
            4097, 8, 0, /* 871: pointer.func */
            4097, 8, 0, /* 874: pointer.func */
            4097, 8, 0, /* 877: pointer.func */
            1, 8, 1, /* 880: pointer.struct.rsa_st */
            	885, 0,
            0, 168, 17, /* 885: struct.rsa_st */
            	490, 16,
            	434, 24,
            	922, 32,
            	922, 40,
            	922, 48,
            	922, 56,
            	922, 64,
            	922, 72,
            	922, 80,
            	922, 88,
            	755, 96,
            	940, 120,
            	940, 128,
            	940, 136,
            	194, 144,
            	954, 152,
            	954, 160,
            1, 8, 1, /* 922: pointer.struct.bignum_st */
            	927, 0,
            0, 24, 1, /* 927: struct.bignum_st */
            	932, 0,
            1, 8, 1, /* 932: pointer.int */
            	937, 0,
            0, 4, 0, /* 937: int */
            1, 8, 1, /* 940: pointer.struct.bn_mont_ctx_st */
            	945, 0,
            0, 96, 3, /* 945: struct.bn_mont_ctx_st */
            	927, 8,
            	927, 32,
            	927, 56,
            1, 8, 1, /* 954: pointer.struct.bn_blinding_st */
            	959, 0,
            0, 88, 7, /* 959: struct.bn_blinding_st */
            	922, 0,
            	922, 8,
            	922, 16,
            	922, 24,
            	976, 40,
            	940, 72,
            	530, 80,
            0, 16, 1, /* 976: struct.iovec */
            	194, 0,
            4097, 8, 0, /* 981: pointer.func */
            1, 8, 1, /* 984: pointer.struct.dh_st */
            	989, 0,
            0, 144, 12, /* 989: struct.dh_st */
            	922, 8,
            	922, 16,
            	922, 32,
            	922, 40,
            	940, 56,
            	922, 64,
            	922, 72,
            	194, 80,
            	922, 96,
            	755, 112,
            	596, 128,
            	434, 136,
            4097, 8, 0, /* 1016: pointer.func */
            1, 8, 1, /* 1019: pointer.struct.ec_key_st */
            	1024, 0,
            0, 56, 4, /* 1024: struct.ec_key_st */
            	1035, 8,
            	1212, 16,
            	922, 24,
            	1228, 48,
            1, 8, 1, /* 1035: pointer.struct.ec_group_st */
            	1040, 0,
            0, 232, 12, /* 1040: struct.ec_group_st */
            	1067, 0,
            	1212, 8,
            	927, 16,
            	927, 40,
            	194, 80,
            	1228, 96,
            	927, 104,
            	927, 152,
            	927, 176,
            	194, 208,
            	194, 216,
            	1252, 224,
            1, 8, 1, /* 1067: pointer.struct.ec_method_st */
            	1072, 0,
            0, 304, 37, /* 1072: struct.ec_method_st */
            	1149, 8,
            	1152, 16,
            	1152, 24,
            	1155, 32,
            	1158, 40,
            	1158, 48,
            	1149, 56,
            	1161, 64,
            	1164, 72,
            	1167, 80,
            	1167, 88,
            	1170, 96,
            	1173, 104,
            	1176, 112,
            	1176, 120,
            	1179, 128,
            	1179, 136,
            	1182, 144,
            	1185, 152,
            	1188, 160,
            	1191, 168,
            	1194, 176,
            	1197, 184,
            	1173, 192,
            	1197, 200,
            	1194, 208,
            	1197, 216,
            	1200, 224,
            	1203, 232,
            	1161, 240,
            	1149, 248,
            	1158, 256,
            	1206, 264,
            	1158, 272,
            	1206, 280,
            	1206, 288,
            	1209, 296,
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
            4097, 8, 0, /* 1179: pointer.func */
            4097, 8, 0, /* 1182: pointer.func */
            4097, 8, 0, /* 1185: pointer.func */
            4097, 8, 0, /* 1188: pointer.func */
            4097, 8, 0, /* 1191: pointer.func */
            4097, 8, 0, /* 1194: pointer.func */
            4097, 8, 0, /* 1197: pointer.func */
            4097, 8, 0, /* 1200: pointer.func */
            4097, 8, 0, /* 1203: pointer.func */
            4097, 8, 0, /* 1206: pointer.func */
            4097, 8, 0, /* 1209: pointer.func */
            1, 8, 1, /* 1212: pointer.struct.ec_point_st */
            	1217, 0,
            0, 88, 4, /* 1217: struct.ec_point_st */
            	1067, 0,
            	927, 8,
            	927, 32,
            	927, 56,
            1, 8, 1, /* 1228: pointer.struct.ec_extra_data_st */
            	1233, 0,
            0, 40, 5, /* 1233: struct.ec_extra_data_st */
            	1228, 0,
            	194, 8,
            	1246, 16,
            	1249, 24,
            	1249, 32,
            4097, 8, 0, /* 1246: pointer.func */
            4097, 8, 0, /* 1249: pointer.func */
            4097, 8, 0, /* 1252: pointer.func */
            4097, 8, 0, /* 1255: pointer.func */
            0, 192, 8, /* 1258: array[8].struct.cert_pkey_st */
            	113, 0,
            	113, 24,
            	113, 48,
            	113, 72,
            	113, 96,
            	113, 120,
            	113, 144,
            	113, 168,
            1, 8, 1, /* 1277: pointer.struct.cert_st */
            	89, 0,
            1, 8, 1, /* 1282: pointer.struct.X509_VERIFY_PARAM_st */
            	1287, 0,
            0, 56, 2, /* 1287: struct.X509_VERIFY_PARAM_st */
            	194, 0,
            	254, 48,
            4097, 8, 0, /* 1294: pointer.func */
            0, 16, 0, /* 1297: struct.rlimit */
            1, 8, 1, /* 1300: pointer.struct.ssl3_buf_freelist_st */
            	1305, 0,
            0, 24, 1, /* 1305: struct.ssl3_buf_freelist_st */
            	1310, 16,
            1, 8, 1, /* 1310: pointer.struct.ssl3_buf_freelist_entry_st */
            	1315, 0,
            0, 8, 1, /* 1315: struct.ssl3_buf_freelist_entry_st */
            	1310, 0,
            0, 128, 14, /* 1320: struct.srp_ctx_st */
            	1351, 0,
            	1354, 8,
            	18, 16,
            	12, 24,
            	194, 32,
            	922, 40,
            	922, 48,
            	922, 56,
            	922, 64,
            	922, 72,
            	922, 80,
            	922, 88,
            	922, 96,
            	194, 104,
            0, 8, 0, /* 1351: pointer.void */
            4097, 8, 0, /* 1354: pointer.func */
            0, 20, 0, /* 1357: array[20].char */
            4097, 8, 0, /* 1360: pointer.func */
            0, 352, 14, /* 1363: struct.ssl_session_st */
            	194, 144,
            	194, 152,
            	1394, 168,
            	122, 176,
            	1414, 224,
            	254, 240,
            	755, 248,
            	1424, 264,
            	1424, 272,
            	194, 280,
            	194, 296,
            	194, 312,
            	194, 320,
            	194, 344,
            1, 8, 1, /* 1394: pointer.struct.sess_cert_st */
            	1399, 0,
            0, 248, 6, /* 1399: struct.sess_cert_st */
            	254, 0,
            	108, 16,
            	1258, 24,
            	880, 216,
            	984, 224,
            	1019, 232,
            1, 8, 1, /* 1414: pointer.struct.ssl_cipher_st */
            	1419, 0,
            0, 88, 1, /* 1419: struct.ssl_cipher_st */
            	194, 8,
            1, 8, 1, /* 1424: pointer.struct.ssl_session_st */
            	1363, 0,
            0, 56, 2, /* 1429: struct.comp_ctx_st */
            	1436, 0,
            	755, 40,
            1, 8, 1, /* 1436: pointer.struct.comp_method_st */
            	1441, 0,
            0, 64, 7, /* 1441: struct.comp_method_st */
            	194, 8,
            	1458, 16,
            	1461, 24,
            	1464, 32,
            	1464, 40,
            	1467, 48,
            	1467, 56,
            4097, 8, 0, /* 1458: pointer.func */
            4097, 8, 0, /* 1461: pointer.func */
            4097, 8, 0, /* 1464: pointer.func */
            4097, 8, 0, /* 1467: pointer.func */
            0, 88, 1, /* 1470: struct.hm_header_st */
            	1475, 48,
            0, 40, 4, /* 1475: struct.dtls1_retransmit_state */
            	1486, 0,
            	1539, 8,
            	1672, 16,
            	1424, 24,
            1, 8, 1, /* 1486: pointer.struct.evp_cipher_ctx_st */
            	1491, 0,
            0, 168, 4, /* 1491: struct.evp_cipher_ctx_st */
            	1502, 0,
            	434, 8,
            	1351, 96,
            	1351, 120,
            1, 8, 1, /* 1502: pointer.struct.evp_cipher_st */
            	1507, 0,
            0, 88, 7, /* 1507: struct.evp_cipher_st */
            	1524, 24,
            	1527, 32,
            	1530, 40,
            	1533, 56,
            	1533, 64,
            	1536, 72,
            	1351, 80,
            4097, 8, 0, /* 1524: pointer.func */
            4097, 8, 0, /* 1527: pointer.func */
            4097, 8, 0, /* 1530: pointer.func */
            4097, 8, 0, /* 1533: pointer.func */
            4097, 8, 0, /* 1536: pointer.func */
            1, 8, 1, /* 1539: pointer.struct.env_md_ctx_st */
            	1544, 0,
            0, 48, 5, /* 1544: struct.env_md_ctx_st */
            	835, 0,
            	434, 8,
            	1351, 24,
            	1557, 32,
            	862, 40,
            1, 8, 1, /* 1557: pointer.struct.evp_pkey_ctx_st */
            	1562, 0,
            0, 80, 8, /* 1562: struct.evp_pkey_ctx_st */
            	1581, 0,
            	434, 8,
            	315, 16,
            	315, 24,
            	194, 40,
            	194, 48,
            	387, 56,
            	932, 64,
            1, 8, 1, /* 1581: pointer.struct.evp_pkey_method_st */
            	1586, 0,
            0, 208, 25, /* 1586: struct.evp_pkey_method_st */
            	387, 8,
            	1639, 16,
            	1642, 24,
            	387, 32,
            	1645, 40,
            	387, 48,
            	1645, 56,
            	387, 64,
            	1648, 72,
            	387, 80,
            	1651, 88,
            	387, 96,
            	1648, 104,
            	1654, 112,
            	1657, 120,
            	1654, 128,
            	1660, 136,
            	387, 144,
            	1648, 152,
            	387, 160,
            	1648, 168,
            	387, 176,
            	1663, 184,
            	1666, 192,
            	1669, 200,
            4097, 8, 0, /* 1639: pointer.func */
            4097, 8, 0, /* 1642: pointer.func */
            4097, 8, 0, /* 1645: pointer.func */
            4097, 8, 0, /* 1648: pointer.func */
            4097, 8, 0, /* 1651: pointer.func */
            4097, 8, 0, /* 1654: pointer.func */
            4097, 8, 0, /* 1657: pointer.func */
            4097, 8, 0, /* 1660: pointer.func */
            4097, 8, 0, /* 1663: pointer.func */
            4097, 8, 0, /* 1666: pointer.func */
            4097, 8, 0, /* 1669: pointer.func */
            1, 8, 1, /* 1672: pointer.struct.comp_ctx_st */
            	1429, 0,
            1, 8, 1, /* 1677: pointer.struct._pitem */
            	1682, 0,
            0, 24, 2, /* 1682: struct._pitem */
            	194, 8,
            	1677, 16,
            0, 16, 1, /* 1689: struct._pqueue */
            	1677, 0,
            0, 16, 0, /* 1694: union.anon */
            1, 8, 1, /* 1697: pointer.struct.dtls1_state_st */
            	1702, 0,
            0, 888, 7, /* 1702: struct.dtls1_state_st */
            	1719, 576,
            	1719, 592,
            	1724, 608,
            	1724, 616,
            	1719, 624,
            	1470, 648,
            	1470, 736,
            0, 16, 1, /* 1719: struct.record_pqueue_st */
            	1724, 8,
            1, 8, 1, /* 1724: pointer.struct._pqueue */
            	1689, 0,
            0, 0, 0, /* 1729: func */
            1, 8, 1, /* 1732: pointer.struct.ssl_comp_st */
            	1737, 0,
            0, 24, 2, /* 1737: struct.ssl_comp_st */
            	194, 8,
            	1436, 16,
            0, 0, 0, /* 1744: func */
            0, 0, 0, /* 1747: func */
            0, 0, 0, /* 1750: func */
            0, 0, 0, /* 1753: func */
            0, 0, 0, /* 1756: func */
            4097, 8, 0, /* 1759: pointer.func */
            0, 9, 0, /* 1762: array[9].char */
            0, 0, 0, /* 1765: func */
            0, 0, 0, /* 1768: func */
            0, 0, 0, /* 1771: func */
            0, 0, 0, /* 1774: func */
            0, 0, 0, /* 1777: func */
            0, 0, 0, /* 1780: func */
            0, 0, 0, /* 1783: func */
            0, 0, 0, /* 1786: func */
            0, 0, 0, /* 1789: func */
            0, 0, 0, /* 1792: func */
            0, 12, 0, /* 1795: struct.ap_unix_identity_t */
            0, 0, 0, /* 1798: func */
            0, 0, 0, /* 1801: func */
            0, 0, 0, /* 1804: func */
            0, 0, 0, /* 1807: func */
            0, 0, 0, /* 1810: func */
            0, 0, 0, /* 1813: func */
            0, 0, 0, /* 1816: func */
            0, 0, 0, /* 1819: func */
            0, 0, 0, /* 1822: func */
            0, 0, 0, /* 1825: func */
            4097, 8, 0, /* 1828: pointer.func */
            0, 0, 0, /* 1831: func */
            4097, 8, 0, /* 1834: pointer.func */
            4097, 8, 0, /* 1837: pointer.func */
            0, 0, 0, /* 1840: func */
            0, 0, 0, /* 1843: func */
            0, 8, 0, /* 1846: array[2].int */
            0, 528, 8, /* 1849: struct.anon */
            	1414, 408,
            	984, 416,
            	1019, 424,
            	254, 464,
            	194, 480,
            	1502, 488,
            	835, 496,
            	1732, 512,
            0, 0, 0, /* 1868: func */
            0, 0, 0, /* 1871: func */
            0, 0, 0, /* 1874: func */
            0, 0, 0, /* 1877: func */
            4097, 8, 0, /* 1880: pointer.func */
            4097, 8, 0, /* 1883: pointer.func */
            0, 0, 0, /* 1886: func */
            0, 0, 0, /* 1889: func */
            0, 16, 1, /* 1892: struct.tls_session_ticket_ext_st */
            	1351, 8,
            0, 0, 0, /* 1897: func */
            1, 8, 1, /* 1900: pointer.struct.tls_session_ticket_ext_st */
            	1892, 0,
            0, 0, 0, /* 1905: func */
            1, 8, 1, /* 1908: pointer.struct.ssl3_state_st */
            	1913, 0,
            0, 1200, 10, /* 1913: struct.ssl3_state_st */
            	1936, 240,
            	1936, 264,
            	1941, 288,
            	1941, 344,
            	194, 432,
            	1950, 440,
            	2016, 448,
            	1351, 496,
            	1351, 512,
            	1849, 528,
            0, 24, 1, /* 1936: struct.ssl3_buffer_st */
            	194, 0,
            0, 56, 3, /* 1941: struct.ssl3_record_st */
            	194, 16,
            	194, 24,
            	194, 32,
            1, 8, 1, /* 1950: pointer.struct.bio_st */
            	1955, 0,
            0, 112, 7, /* 1955: struct.bio_st */
            	1972, 0,
            	2013, 8,
            	194, 16,
            	1351, 48,
            	1950, 56,
            	1950, 64,
            	755, 96,
            1, 8, 1, /* 1972: pointer.struct.bio_method_st */
            	1977, 0,
            0, 80, 9, /* 1977: struct.bio_method_st */
            	194, 8,
            	1998, 16,
            	1998, 24,
            	2001, 32,
            	1998, 40,
            	2004, 48,
            	2007, 56,
            	2007, 64,
            	2010, 72,
            4097, 8, 0, /* 1998: pointer.func */
            4097, 8, 0, /* 2001: pointer.func */
            4097, 8, 0, /* 2004: pointer.func */
            4097, 8, 0, /* 2007: pointer.func */
            4097, 8, 0, /* 2010: pointer.func */
            4097, 8, 0, /* 2013: pointer.func */
            1, 8, 1, /* 2016: pointer.pointer.struct.env_md_ctx_st */
            	1539, 0,
            0, 0, 0, /* 2021: func */
            0, 72, 0, /* 2024: struct.anon */
            0, 16, 0, /* 2027: array[16].char */
            0, 8, 0, /* 2030: long */
            1, 8, 1, /* 2033: pointer.struct.iovec */
            	976, 0,
            0, 2, 0, /* 2038: short */
            0, 0, 0, /* 2041: func */
            0, 0, 0, /* 2044: func */
            4097, 8, 0, /* 2047: pointer.func */
            0, 808, 51, /* 2050: struct.ssl_st */
            	2155, 8,
            	1950, 16,
            	1950, 24,
            	1950, 32,
            	387, 48,
            	279, 80,
            	1351, 88,
            	194, 104,
            	2306, 120,
            	1908, 128,
            	1697, 136,
            	1294, 152,
            	1351, 160,
            	1282, 176,
            	254, 184,
            	254, 192,
            	1486, 208,
            	1539, 216,
            	1672, 224,
            	1486, 232,
            	1539, 240,
            	1672, 248,
            	1277, 256,
            	1424, 304,
            	2332, 312,
            	83, 328,
            	2335, 336,
            	77, 352,
            	2285, 360,
            	2338, 368,
            	755, 392,
            	254, 408,
            	2047, 464,
            	1351, 472,
            	194, 480,
            	254, 504,
            	254, 512,
            	194, 520,
            	194, 544,
            	194, 560,
            	1351, 568,
            	1900, 584,
            	2288, 592,
            	1351, 600,
            	2499, 608,
            	1351, 616,
            	2338, 624,
            	194, 632,
            	254, 648,
            	2033, 656,
            	1320, 680,
            1, 8, 1, /* 2155: pointer.struct.ssl_method_st */
            	2160, 0,
            0, 232, 28, /* 2160: struct.ssl_method_st */
            	2219, 8,
            	2222, 16,
            	2222, 24,
            	2219, 32,
            	2219, 40,
            	2225, 48,
            	2225, 56,
            	2225, 64,
            	2219, 72,
            	2219, 80,
            	2219, 88,
            	2228, 96,
            	2231, 104,
            	2234, 112,
            	2219, 120,
            	2237, 128,
            	2240, 136,
            	2243, 144,
            	1880, 152,
            	2219, 160,
            	708, 168,
            	2246, 176,
            	2249, 184,
            	1467, 192,
            	2252, 200,
            	708, 208,
            	2300, 216,
            	2303, 224,
            4097, 8, 0, /* 2219: pointer.func */
            4097, 8, 0, /* 2222: pointer.func */
            4097, 8, 0, /* 2225: pointer.func */
            4097, 8, 0, /* 2228: pointer.func */
            4097, 8, 0, /* 2231: pointer.func */
            4097, 8, 0, /* 2234: pointer.func */
            4097, 8, 0, /* 2237: pointer.func */
            4097, 8, 0, /* 2240: pointer.func */
            4097, 8, 0, /* 2243: pointer.func */
            4097, 8, 0, /* 2246: pointer.func */
            4097, 8, 0, /* 2249: pointer.func */
            1, 8, 1, /* 2252: pointer.struct.ssl3_enc_method */
            	2257, 0,
            0, 112, 11, /* 2257: struct.ssl3_enc_method */
            	2282, 0,
            	2225, 8,
            	2219, 16,
            	2285, 24,
            	2282, 32,
            	2288, 40,
            	2291, 56,
            	194, 64,
            	194, 80,
            	2294, 96,
            	2297, 104,
            4097, 8, 0, /* 2282: pointer.func */
            4097, 8, 0, /* 2285: pointer.func */
            4097, 8, 0, /* 2288: pointer.func */
            4097, 8, 0, /* 2291: pointer.func */
            4097, 8, 0, /* 2294: pointer.func */
            4097, 8, 0, /* 2297: pointer.func */
            4097, 8, 0, /* 2300: pointer.func */
            4097, 8, 0, /* 2303: pointer.func */
            1, 8, 1, /* 2306: pointer.struct.ssl2_state_st */
            	2311, 0,
            0, 344, 9, /* 2311: struct.ssl2_state_st */
            	194, 24,
            	194, 56,
            	194, 64,
            	194, 72,
            	194, 104,
            	194, 112,
            	194, 120,
            	194, 128,
            	194, 136,
            4097, 8, 0, /* 2332: pointer.func */
            4097, 8, 0, /* 2335: pointer.func */
            1, 8, 1, /* 2338: pointer.struct.ssl_ctx_st */
            	2343, 0,
            0, 736, 50, /* 2343: struct.ssl_ctx_st */
            	2155, 0,
            	254, 8,
            	254, 16,
            	2446, 24,
            	45, 32,
            	1424, 48,
            	1424, 56,
            	2487, 80,
            	1883, 88,
            	39, 96,
            	2490, 152,
            	1351, 160,
            	2493, 168,
            	1351, 176,
            	2496, 184,
            	2332, 192,
            	2225, 200,
            	755, 208,
            	835, 224,
            	835, 232,
            	835, 240,
            	254, 248,
            	254, 256,
            	2335, 264,
            	254, 272,
            	1277, 304,
            	1294, 320,
            	1351, 328,
            	83, 376,
            	2332, 384,
            	1282, 392,
            	434, 408,
            	1354, 416,
            	1351, 424,
            	24, 480,
            	18, 488,
            	1351, 496,
            	1834, 504,
            	1351, 512,
            	194, 520,
            	77, 528,
            	2285, 536,
            	1300, 552,
            	1300, 560,
            	1320, 568,
            	6, 696,
            	1351, 704,
            	1360, 712,
            	1351, 720,
            	254, 728,
            1, 8, 1, /* 2446: pointer.struct.x509_store_st */
            	2451, 0,
            0, 144, 15, /* 2451: struct.x509_store_st */
            	254, 8,
            	254, 16,
            	1282, 24,
            	1759, 32,
            	387, 40,
            	2484, 48,
            	65, 56,
            	1759, 64,
            	1837, 72,
            	1828, 80,
            	53, 88,
            	50, 96,
            	50, 104,
            	1759, 112,
            	755, 120,
            4097, 8, 0, /* 2484: pointer.func */
            4097, 8, 0, /* 2487: pointer.func */
            4097, 8, 0, /* 2490: pointer.func */
            4097, 8, 0, /* 2493: pointer.func */
            4097, 8, 0, /* 2496: pointer.func */
            4097, 8, 0, /* 2499: pointer.func */
            0, 0, 0, /* 2502: func */
            0, 0, 0, /* 2505: func */
            0, 0, 0, /* 2508: func */
            0, 0, 0, /* 2511: func */
            0, 0, 0, /* 2514: func */
            0, 0, 0, /* 2517: func */
            0, 0, 0, /* 2520: func */
            0, 0, 0, /* 2523: func */
            0, 0, 0, /* 2526: func */
            0, 0, 0, /* 2529: func */
            0, 0, 0, /* 2532: func */
            0, 0, 0, /* 2535: func */
            0, 0, 0, /* 2538: func */
            0, 0, 0, /* 2541: func */
            0, 0, 0, /* 2544: func */
            0, 0, 0, /* 2547: func */
            0, 0, 0, /* 2550: func */
            0, 0, 0, /* 2553: func */
            0, 0, 0, /* 2556: func */
            0, 0, 0, /* 2559: func */
            0, 0, 0, /* 2562: func */
            0, 0, 0, /* 2565: func */
            0, 0, 0, /* 2568: func */
            0, 0, 0, /* 2571: func */
            0, 0, 0, /* 2574: func */
            0, 0, 0, /* 2577: func */
            0, 0, 0, /* 2580: func */
            0, 0, 0, /* 2583: func */
            0, 1, 0, /* 2586: char */
            0, 0, 0, /* 2589: func */
            0, 0, 0, /* 2592: func */
            0, 0, 0, /* 2595: func */
            0, 0, 0, /* 2598: func */
            0, 0, 0, /* 2601: func */
            0, 0, 0, /* 2604: func */
            0, 0, 0, /* 2607: func */
            0, 0, 0, /* 2610: func */
            0, 0, 0, /* 2613: func */
            0, 0, 0, /* 2616: func */
            0, 0, 0, /* 2619: func */
            0, 4, 0, /* 2622: array[4].char */
            0, 0, 0, /* 2625: func */
            0, 0, 0, /* 2628: func */
            0, 0, 0, /* 2631: func */
            0, 0, 0, /* 2634: func */
            0, 0, 0, /* 2637: func */
            0, 0, 0, /* 2640: func */
            0, 0, 0, /* 2643: func */
            0, 256, 0, /* 2646: array[256].char */
            0, 48, 0, /* 2649: array[48].char */
            0, 24, 0, /* 2652: array[6].int */
            0, 2, 0, /* 2655: array[2].char */
            0, 0, 0, /* 2658: func */
            0, 0, 0, /* 2661: func */
            0, 0, 0, /* 2664: func */
            0, 0, 0, /* 2667: func */
            0, 0, 0, /* 2670: func */
            0, 0, 0, /* 2673: func */
            0, 0, 0, /* 2676: func */
            0, 0, 0, /* 2679: func */
            0, 0, 0, /* 2682: func */
            0, 32, 0, /* 2685: array[32].char */
            0, 0, 0, /* 2688: func */
            0, 8, 0, /* 2691: array[8].char */
            0, 0, 0, /* 2694: func */
            0, 0, 0, /* 2697: func */
            0, 0, 0, /* 2700: func */
            0, 20, 0, /* 2703: array[5].int */
            0, 0, 0, /* 2706: func */
            0, 0, 0, /* 2709: func */
            0, 128, 0, /* 2712: array[128].char */
            0, 0, 0, /* 2715: func */
            0, 0, 0, /* 2718: func */
            0, 0, 0, /* 2721: func */
            0, 0, 0, /* 2724: func */
            0, 0, 0, /* 2727: func */
            0, 0, 0, /* 2730: func */
            0, 0, 0, /* 2733: func */
            0, 0, 0, /* 2736: func */
            0, 0, 0, /* 2739: func */
            0, 0, 0, /* 2742: func */
            1, 8, 1, /* 2745: pointer.struct.ssl_st */
            	2050, 0,
            0, 0, 0, /* 2750: func */
            0, 0, 0, /* 2753: func */
            0, 0, 0, /* 2756: func */
            0, 0, 0, /* 2759: func */
            0, 0, 0, /* 2762: func */
            0, 0, 0, /* 2765: func */
            0, 0, 0, /* 2768: func */
            0, 0, 0, /* 2771: func */
            0, 0, 0, /* 2774: func */
            0, 64, 0, /* 2777: array[64].char */
            0, 0, 0, /* 2780: func */
            0, 0, 0, /* 2783: func */
            0, 0, 0, /* 2786: func */
            0, 0, 0, /* 2789: func */
            0, 0, 0, /* 2792: func */
            0, 0, 0, /* 2795: func */
            0, 12, 0, /* 2798: array[12].char */
            0, 0, 0, /* 2801: func */
            0, 0, 0, /* 2804: func */
            0, 0, 0, /* 2807: func */
            0, 0, 0, /* 2810: func */
            0, 0, 0, /* 2813: func */
            0, 0, 0, /* 2816: func */
            0, 0, 0, /* 2819: func */
            0, 0, 0, /* 2822: func */
            0, 0, 0, /* 2825: func */
            0, 0, 0, /* 2828: func */
            0, 0, 0, /* 2831: func */
            0, 0, 0, /* 2834: func */
            0, 0, 0, /* 2837: func */
            0, 0, 0, /* 2840: func */
        },
        .arg_entity_index = { 2745, },
        .ret_entity_index = 194,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    char * *new_ret_ptr = (char * *)new_args->ret;

    char * (*orig_SSL_get_srp_username)(SSL *);
    orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
    *new_ret_ptr = (*orig_SSL_get_srp_username)(new_arg_a);

    syscall(889);

    return ret;
}

