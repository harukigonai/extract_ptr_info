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

void bb_SSL_CTX_set_verify(SSL_CTX * arg_a,int arg_b,int (*arg_c)(int, X509_STORE_CTX *));

void SSL_CTX_set_verify(SSL_CTX * arg_a,int arg_b,int (*arg_c)(int, X509_STORE_CTX *)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_set_verify called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_set_verify(arg_a,arg_b,arg_c);
    else {
        void (*orig_SSL_CTX_set_verify)(SSL_CTX *,int,int (*)(int, X509_STORE_CTX *));
        orig_SSL_CTX_set_verify = dlsym(RTLD_NEXT, "SSL_CTX_set_verify");
        orig_SSL_CTX_set_verify(arg_a,arg_b,arg_c);
    }
}

void bb_SSL_CTX_set_verify(SSL_CTX * arg_a,int arg_b,int (*arg_c)(int, X509_STORE_CTX *)) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            4097, 8, 0, /* 6: pointer.func */
            0, 128, 14, /* 9: struct.srp_ctx_st */
            	40, 0,
            	43, 8,
            	46, 16,
            	6, 24,
            	49, 32,
            	54, 40,
            	54, 48,
            	54, 56,
            	54, 64,
            	54, 72,
            	54, 80,
            	54, 88,
            	54, 96,
            	49, 104,
            0, 8, 0, /* 40: pointer.void */
            4097, 8, 0, /* 43: pointer.func */
            4097, 8, 0, /* 46: pointer.func */
            0, 8, 1, /* 49: pointer.char */
            	4096, 0,
            0, 8, 1, /* 54: pointer.struct.bignum_st */
            	59, 0,
            0, 24, 1, /* 59: struct.bignum_st */
            	64, 0,
            0, 8, 1, /* 64: pointer.int */
            	69, 0,
            0, 4, 0, /* 69: int */
            0, 0, 0, /* 72: func */
            4097, 8, 0, /* 75: pointer.func */
            0, 0, 0, /* 78: func */
            0, 0, 0, /* 81: func */
            0, 0, 0, /* 84: func */
            4097, 8, 0, /* 87: pointer.func */
            0, 16, 0, /* 90: array[16].char */
            0, 0, 0, /* 93: func */
            0, 0, 0, /* 96: func */
            4097, 8, 0, /* 99: pointer.func */
            0, 0, 0, /* 102: func */
            4097, 8, 0, /* 105: pointer.func */
            0, 0, 0, /* 108: func */
            4097, 8, 0, /* 111: pointer.func */
            0, 0, 0, /* 114: func */
            0, 296, 8, /* 117: struct.cert_st */
            	136, 0,
            	903, 48,
            	986, 56,
            	989, 64,
            	111, 72,
            	1021, 80,
            	105, 88,
            	1257, 96,
            0, 8, 1, /* 136: pointer.struct.cert_pkey_st */
            	141, 0,
            0, 24, 3, /* 141: struct.cert_pkey_st */
            	150, 0,
            	338, 8,
            	858, 16,
            0, 8, 1, /* 150: pointer.struct.x509_st */
            	155, 0,
            0, 184, 12, /* 155: struct.x509_st */
            	182, 0,
            	222, 8,
            	212, 16,
            	49, 32,
            	778, 40,
            	212, 104,
            	788, 112,
            	802, 120,
            	277, 128,
            	277, 136,
            	828, 144,
            	840, 176,
            0, 8, 1, /* 182: pointer.struct.x509_cinf_st */
            	187, 0,
            0, 104, 11, /* 187: struct.x509_cinf_st */
            	212, 0,
            	212, 8,
            	222, 16,
            	263, 24,
            	312, 32,
            	263, 40,
            	324, 48,
            	212, 56,
            	212, 64,
            	277, 72,
            	783, 80,
            0, 8, 1, /* 212: pointer.struct.asn1_string_st */
            	217, 0,
            0, 24, 1, /* 217: struct.asn1_string_st */
            	49, 8,
            0, 8, 1, /* 222: pointer.struct.X509_algor_st */
            	227, 0,
            0, 16, 2, /* 227: struct.X509_algor_st */
            	234, 0,
            	248, 8,
            0, 8, 1, /* 234: pointer.struct.asn1_object_st */
            	239, 0,
            0, 40, 3, /* 239: struct.asn1_object_st */
            	49, 0,
            	49, 8,
            	49, 24,
            0, 8, 1, /* 248: pointer.struct.asn1_type_st */
            	253, 0,
            0, 16, 1, /* 253: struct.asn1_type_st */
            	258, 8,
            0, 8, 1, /* 258: struct.fnames */
            	49, 0,
            0, 8, 1, /* 263: pointer.struct.X509_name_st */
            	268, 0,
            0, 40, 3, /* 268: struct.X509_name_st */
            	277, 0,
            	302, 16,
            	49, 24,
            0, 8, 1, /* 277: pointer.struct.stack_st_OPENSSL_STRING */
            	282, 0,
            0, 32, 1, /* 282: struct.stack_st_OPENSSL_STRING */
            	287, 0,
            0, 32, 2, /* 287: struct.stack_st */
            	294, 8,
            	299, 24,
            0, 8, 1, /* 294: pointer.pointer.char */
            	49, 0,
            4097, 8, 0, /* 299: pointer.func */
            0, 8, 1, /* 302: pointer.struct.buf_mem_st */
            	307, 0,
            0, 24, 1, /* 307: struct.buf_mem_st */
            	49, 8,
            0, 8, 1, /* 312: pointer.struct.X509_val_st */
            	317, 0,
            0, 16, 2, /* 317: struct.X509_val_st */
            	212, 0,
            	212, 8,
            0, 8, 1, /* 324: pointer.struct.X509_pubkey_st */
            	329, 0,
            0, 24, 3, /* 329: struct.X509_pubkey_st */
            	222, 0,
            	212, 8,
            	338, 16,
            0, 8, 1, /* 338: pointer.struct.evp_pkey_st */
            	343, 0,
            0, 56, 4, /* 343: struct.evp_pkey_st */
            	354, 16,
            	457, 24,
            	258, 32,
            	277, 48,
            0, 8, 1, /* 354: pointer.struct.evp_pkey_asn1_method_st */
            	359, 0,
            0, 208, 24, /* 359: struct.evp_pkey_asn1_method_st */
            	49, 16,
            	49, 24,
            	410, 32,
            	418, 40,
            	421, 48,
            	424, 56,
            	427, 64,
            	430, 72,
            	424, 80,
            	433, 88,
            	433, 96,
            	436, 104,
            	439, 112,
            	433, 120,
            	421, 128,
            	421, 136,
            	424, 144,
            	442, 152,
            	445, 160,
            	448, 168,
            	436, 176,
            	439, 184,
            	451, 192,
            	454, 200,
            0, 8, 1, /* 410: pointer.struct.unnamed */
            	415, 0,
            0, 0, 0, /* 415: struct.unnamed */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            4097, 8, 0, /* 430: pointer.func */
            4097, 8, 0, /* 433: pointer.func */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            4097, 8, 0, /* 442: pointer.func */
            4097, 8, 0, /* 445: pointer.func */
            4097, 8, 0, /* 448: pointer.func */
            4097, 8, 0, /* 451: pointer.func */
            4097, 8, 0, /* 454: pointer.func */
            0, 8, 1, /* 457: pointer.struct.engine_st */
            	462, 0,
            0, 216, 24, /* 462: struct.engine_st */
            	49, 0,
            	49, 8,
            	513, 16,
            	568, 24,
            	619, 32,
            	655, 40,
            	672, 48,
            	699, 56,
            	734, 64,
            	742, 72,
            	745, 80,
            	748, 88,
            	751, 96,
            	754, 104,
            	754, 112,
            	754, 120,
            	757, 128,
            	760, 136,
            	760, 144,
            	763, 152,
            	766, 160,
            	778, 184,
            	457, 200,
            	457, 208,
            0, 8, 1, /* 513: pointer.struct.rsa_meth_st */
            	518, 0,
            0, 112, 13, /* 518: struct.rsa_meth_st */
            	49, 0,
            	547, 8,
            	547, 16,
            	547, 24,
            	547, 32,
            	550, 40,
            	553, 48,
            	556, 56,
            	556, 64,
            	49, 80,
            	559, 88,
            	562, 96,
            	565, 104,
            4097, 8, 0, /* 547: pointer.func */
            4097, 8, 0, /* 550: pointer.func */
            4097, 8, 0, /* 553: pointer.func */
            4097, 8, 0, /* 556: pointer.func */
            4097, 8, 0, /* 559: pointer.func */
            4097, 8, 0, /* 562: pointer.func */
            4097, 8, 0, /* 565: pointer.func */
            0, 8, 1, /* 568: pointer.struct.dsa_method */
            	573, 0,
            0, 96, 11, /* 573: struct.dsa_method */
            	49, 0,
            	598, 8,
            	601, 16,
            	604, 24,
            	607, 32,
            	610, 40,
            	613, 48,
            	613, 56,
            	49, 72,
            	616, 80,
            	613, 88,
            4097, 8, 0, /* 598: pointer.func */
            4097, 8, 0, /* 601: pointer.func */
            4097, 8, 0, /* 604: pointer.func */
            4097, 8, 0, /* 607: pointer.func */
            4097, 8, 0, /* 610: pointer.func */
            4097, 8, 0, /* 613: pointer.func */
            4097, 8, 0, /* 616: pointer.func */
            0, 8, 1, /* 619: pointer.struct.dh_method */
            	624, 0,
            0, 72, 8, /* 624: struct.dh_method */
            	49, 0,
            	643, 8,
            	646, 16,
            	649, 24,
            	643, 32,
            	643, 40,
            	49, 56,
            	652, 64,
            4097, 8, 0, /* 643: pointer.func */
            4097, 8, 0, /* 646: pointer.func */
            4097, 8, 0, /* 649: pointer.func */
            4097, 8, 0, /* 652: pointer.func */
            0, 8, 1, /* 655: pointer.struct.ecdh_method */
            	660, 0,
            0, 32, 3, /* 660: struct.ecdh_method */
            	49, 0,
            	669, 8,
            	49, 24,
            4097, 8, 0, /* 669: pointer.func */
            0, 8, 1, /* 672: pointer.struct.ecdsa_method */
            	677, 0,
            0, 48, 5, /* 677: struct.ecdsa_method */
            	49, 0,
            	690, 8,
            	693, 16,
            	696, 24,
            	49, 40,
            4097, 8, 0, /* 690: pointer.func */
            4097, 8, 0, /* 693: pointer.func */
            4097, 8, 0, /* 696: pointer.func */
            0, 8, 1, /* 699: pointer.struct.rand_meth_st */
            	704, 0,
            0, 48, 6, /* 704: struct.rand_meth_st */
            	719, 0,
            	722, 8,
            	725, 16,
            	728, 24,
            	722, 32,
            	731, 40,
            4097, 8, 0, /* 719: pointer.func */
            4097, 8, 0, /* 722: pointer.func */
            4097, 8, 0, /* 725: pointer.func */
            4097, 8, 0, /* 728: pointer.func */
            4097, 8, 0, /* 731: pointer.func */
            0, 8, 1, /* 734: pointer.struct.store_method_st */
            	739, 0,
            0, 0, 0, /* 739: struct.store_method_st */
            4097, 8, 0, /* 742: pointer.func */
            4097, 8, 0, /* 745: pointer.func */
            4097, 8, 0, /* 748: pointer.func */
            4097, 8, 0, /* 751: pointer.func */
            4097, 8, 0, /* 754: pointer.func */
            4097, 8, 0, /* 757: pointer.func */
            4097, 8, 0, /* 760: pointer.func */
            4097, 8, 0, /* 763: pointer.func */
            0, 8, 1, /* 766: pointer.struct.ENGINE_CMD_DEFN_st */
            	771, 0,
            0, 32, 2, /* 771: struct.ENGINE_CMD_DEFN_st */
            	49, 8,
            	49, 16,
            0, 16, 1, /* 778: struct.crypto_ex_data_st */
            	277, 0,
            0, 24, 1, /* 783: struct.ASN1_ENCODING_st */
            	49, 0,
            0, 8, 1, /* 788: pointer.struct.AUTHORITY_KEYID_st */
            	793, 0,
            0, 24, 3, /* 793: struct.AUTHORITY_KEYID_st */
            	212, 0,
            	277, 8,
            	212, 16,
            0, 8, 1, /* 802: pointer.struct.X509_POLICY_CACHE_st */
            	807, 0,
            0, 40, 2, /* 807: struct.X509_POLICY_CACHE_st */
            	814, 0,
            	277, 8,
            0, 8, 1, /* 814: pointer.struct.X509_POLICY_DATA_st */
            	819, 0,
            0, 32, 3, /* 819: struct.X509_POLICY_DATA_st */
            	234, 8,
            	277, 16,
            	277, 24,
            0, 8, 1, /* 828: pointer.struct.NAME_CONSTRAINTS_st */
            	833, 0,
            0, 16, 2, /* 833: struct.NAME_CONSTRAINTS_st */
            	277, 0,
            	277, 8,
            0, 8, 1, /* 840: pointer.struct.x509_cert_aux_st */
            	845, 0,
            0, 40, 5, /* 845: struct.x509_cert_aux_st */
            	277, 0,
            	277, 8,
            	212, 16,
            	212, 24,
            	277, 32,
            0, 8, 1, /* 858: pointer.struct.env_md_st */
            	863, 0,
            0, 120, 8, /* 863: struct.env_md_st */
            	882, 24,
            	885, 32,
            	888, 40,
            	891, 48,
            	882, 56,
            	894, 64,
            	897, 72,
            	900, 112,
            4097, 8, 0, /* 882: pointer.func */
            4097, 8, 0, /* 885: pointer.func */
            4097, 8, 0, /* 888: pointer.func */
            4097, 8, 0, /* 891: pointer.func */
            4097, 8, 0, /* 894: pointer.func */
            4097, 8, 0, /* 897: pointer.func */
            4097, 8, 0, /* 900: pointer.func */
            0, 8, 1, /* 903: pointer.struct.rsa_st */
            	908, 0,
            0, 168, 17, /* 908: struct.rsa_st */
            	513, 16,
            	457, 24,
            	54, 32,
            	54, 40,
            	54, 48,
            	54, 56,
            	54, 64,
            	54, 72,
            	54, 80,
            	54, 88,
            	778, 96,
            	945, 120,
            	945, 128,
            	945, 136,
            	49, 144,
            	959, 152,
            	959, 160,
            0, 8, 1, /* 945: pointer.struct.bn_mont_ctx_st */
            	950, 0,
            0, 96, 3, /* 950: struct.bn_mont_ctx_st */
            	59, 8,
            	59, 32,
            	59, 56,
            0, 8, 1, /* 959: pointer.struct.bn_blinding_st */
            	964, 0,
            0, 88, 7, /* 964: struct.bn_blinding_st */
            	54, 0,
            	54, 8,
            	54, 16,
            	54, 24,
            	981, 40,
            	945, 72,
            	553, 80,
            0, 16, 1, /* 981: struct.iovec */
            	49, 0,
            4097, 8, 0, /* 986: pointer.func */
            0, 8, 1, /* 989: pointer.struct.dh_st */
            	994, 0,
            0, 144, 12, /* 994: struct.dh_st */
            	54, 8,
            	54, 16,
            	54, 32,
            	54, 40,
            	945, 56,
            	54, 64,
            	54, 72,
            	49, 80,
            	54, 96,
            	778, 112,
            	619, 128,
            	457, 136,
            0, 8, 1, /* 1021: pointer.struct.ec_key_st */
            	1026, 0,
            0, 56, 4, /* 1026: struct.ec_key_st */
            	1037, 8,
            	1214, 16,
            	54, 24,
            	1230, 48,
            0, 8, 1, /* 1037: pointer.struct.ec_group_st */
            	1042, 0,
            0, 232, 12, /* 1042: struct.ec_group_st */
            	1069, 0,
            	1214, 8,
            	59, 16,
            	59, 40,
            	49, 80,
            	1230, 96,
            	59, 104,
            	59, 152,
            	59, 176,
            	49, 208,
            	49, 216,
            	1254, 224,
            0, 8, 1, /* 1069: pointer.struct.ec_method_st */
            	1074, 0,
            0, 304, 37, /* 1074: struct.ec_method_st */
            	1151, 8,
            	1154, 16,
            	1154, 24,
            	1157, 32,
            	1160, 40,
            	1160, 48,
            	1151, 56,
            	1163, 64,
            	1166, 72,
            	1169, 80,
            	1169, 88,
            	1172, 96,
            	1175, 104,
            	1178, 112,
            	1178, 120,
            	1181, 128,
            	1181, 136,
            	1184, 144,
            	1187, 152,
            	1190, 160,
            	1193, 168,
            	1196, 176,
            	1199, 184,
            	1175, 192,
            	1199, 200,
            	1196, 208,
            	1199, 216,
            	1202, 224,
            	1205, 232,
            	1163, 240,
            	1151, 248,
            	1160, 256,
            	1208, 264,
            	1160, 272,
            	1208, 280,
            	1208, 288,
            	1211, 296,
            4097, 8, 0, /* 1151: pointer.func */
            4097, 8, 0, /* 1154: pointer.func */
            4097, 8, 0, /* 1157: pointer.func */
            4097, 8, 0, /* 1160: pointer.func */
            4097, 8, 0, /* 1163: pointer.func */
            4097, 8, 0, /* 1166: pointer.func */
            4097, 8, 0, /* 1169: pointer.func */
            4097, 8, 0, /* 1172: pointer.func */
            4097, 8, 0, /* 1175: pointer.func */
            4097, 8, 0, /* 1178: pointer.func */
            4097, 8, 0, /* 1181: pointer.func */
            4097, 8, 0, /* 1184: pointer.func */
            4097, 8, 0, /* 1187: pointer.func */
            4097, 8, 0, /* 1190: pointer.func */
            4097, 8, 0, /* 1193: pointer.func */
            4097, 8, 0, /* 1196: pointer.func */
            4097, 8, 0, /* 1199: pointer.func */
            4097, 8, 0, /* 1202: pointer.func */
            4097, 8, 0, /* 1205: pointer.func */
            4097, 8, 0, /* 1208: pointer.func */
            4097, 8, 0, /* 1211: pointer.func */
            0, 8, 1, /* 1214: pointer.struct.ec_point_st */
            	1219, 0,
            0, 88, 4, /* 1219: struct.ec_point_st */
            	1069, 0,
            	59, 8,
            	59, 32,
            	59, 56,
            0, 8, 1, /* 1230: pointer.struct.ec_extra_data_st */
            	1235, 0,
            0, 40, 5, /* 1235: struct.ec_extra_data_st */
            	1230, 0,
            	49, 8,
            	1248, 16,
            	1251, 24,
            	1251, 32,
            4097, 8, 0, /* 1248: pointer.func */
            4097, 8, 0, /* 1251: pointer.func */
            4097, 8, 0, /* 1254: pointer.func */
            0, 192, 8, /* 1257: array[8].struct.cert_pkey_st */
            	141, 0,
            	141, 24,
            	141, 48,
            	141, 72,
            	141, 96,
            	141, 120,
            	141, 144,
            	141, 168,
            0, 8, 1, /* 1276: pointer.struct.cert_st */
            	117, 0,
            0, 0, 0, /* 1281: func */
            4097, 8, 0, /* 1284: pointer.func */
            4097, 8, 0, /* 1287: pointer.func */
            0, 0, 0, /* 1290: func */
            4097, 8, 0, /* 1293: pointer.func */
            4097, 8, 0, /* 1296: pointer.func */
            0, 44, 0, /* 1299: struct.apr_time_exp_t */
            4097, 8, 0, /* 1302: pointer.func */
            0, 88, 1, /* 1305: struct.ssl_cipher_st */
            	49, 8,
            0, 8, 1, /* 1310: pointer.struct.ssl_cipher_st */
            	1305, 0,
            0, 0, 0, /* 1315: func */
            4097, 8, 0, /* 1318: pointer.func */
            0, 24, 0, /* 1321: array[6].int */
            0, 0, 0, /* 1324: func */
            0, 0, 0, /* 1327: func */
            0, 0, 0, /* 1330: func */
            0, 0, 0, /* 1333: func */
            0, 0, 0, /* 1336: func */
            0, 0, 0, /* 1339: func */
            0, 0, 0, /* 1342: func */
            0, 0, 0, /* 1345: func */
            0, 0, 0, /* 1348: func */
            0, 0, 0, /* 1351: func */
            0, 0, 0, /* 1354: func */
            0, 0, 0, /* 1357: func */
            0, 0, 0, /* 1360: func */
            0, 24, 1, /* 1363: struct.ssl3_buf_freelist_st */
            	1368, 16,
            0, 8, 1, /* 1368: pointer.struct.ssl3_buf_freelist_entry_st */
            	1373, 0,
            0, 8, 1, /* 1373: struct.ssl3_buf_freelist_entry_st */
            	1368, 0,
            0, 0, 0, /* 1378: func */
            0, 0, 0, /* 1381: func */
            0, 0, 0, /* 1384: func */
            0, 0, 0, /* 1387: func */
            0, 8, 1, /* 1390: pointer.struct.ssl3_buf_freelist_st */
            	1363, 0,
            0, 8, 0, /* 1395: array[2].int */
            0, 0, 0, /* 1398: func */
            0, 0, 0, /* 1401: func */
            0, 0, 0, /* 1404: func */
            0, 0, 0, /* 1407: func */
            0, 0, 0, /* 1410: func */
            4097, 8, 0, /* 1413: pointer.func */
            0, 0, 0, /* 1416: func */
            0, 0, 0, /* 1419: func */
            4097, 8, 0, /* 1422: pointer.func */
            0, 0, 0, /* 1425: func */
            0, 0, 0, /* 1428: func */
            0, 0, 0, /* 1431: func */
            0, 0, 0, /* 1434: func */
            4097, 8, 0, /* 1437: pointer.func */
            4097, 8, 0, /* 1440: pointer.func */
            0, 0, 0, /* 1443: func */
            0, 0, 0, /* 1446: func */
            0, 0, 0, /* 1449: func */
            0, 352, 14, /* 1452: struct.ssl_session_st */
            	49, 144,
            	49, 152,
            	1483, 168,
            	150, 176,
            	1310, 224,
            	277, 240,
            	778, 248,
            	1503, 264,
            	1503, 272,
            	49, 280,
            	49, 296,
            	49, 312,
            	49, 320,
            	49, 344,
            0, 8, 1, /* 1483: pointer.struct.sess_cert_st */
            	1488, 0,
            0, 248, 6, /* 1488: struct.sess_cert_st */
            	277, 0,
            	136, 16,
            	1257, 24,
            	903, 216,
            	989, 224,
            	1021, 232,
            0, 8, 1, /* 1503: pointer.struct.ssl_session_st */
            	1452, 0,
            0, 8, 1, /* 1508: pointer.struct.in_addr */
            	1513, 0,
            0, 4, 0, /* 1513: struct.in_addr */
            0, 0, 0, /* 1516: func */
            0, 0, 0, /* 1519: func */
            4097, 8, 0, /* 1522: pointer.func */
            4097, 8, 0, /* 1525: pointer.func */
            0, 0, 0, /* 1528: func */
            4097, 8, 0, /* 1531: pointer.func */
            0, 0, 0, /* 1534: func */
            0, 8, 1, /* 1537: pointer.struct.X509_VERIFY_PARAM_st */
            	1542, 0,
            0, 56, 2, /* 1542: struct.X509_VERIFY_PARAM_st */
            	49, 0,
            	277, 48,
            0, 0, 0, /* 1549: func */
            4097, 8, 0, /* 1552: pointer.func */
            0, 0, 0, /* 1555: func */
            0, 0, 0, /* 1558: func */
            0, 0, 0, /* 1561: func */
            0, 0, 0, /* 1564: func */
            0, 0, 0, /* 1567: func */
            0, 8, 1, /* 1570: pointer.struct.x509_store_st */
            	1575, 0,
            0, 144, 15, /* 1575: struct.x509_store_st */
            	277, 8,
            	277, 16,
            	1537, 24,
            	1608, 32,
            	1611, 40,
            	1552, 48,
            	1531, 56,
            	1608, 64,
            	1614, 72,
            	1525, 80,
            	1617, 88,
            	1422, 96,
            	1422, 104,
            	1608, 112,
            	778, 120,
            4097, 8, 0, /* 1608: pointer.func */
            4097, 8, 0, /* 1611: pointer.func */
            4097, 8, 0, /* 1614: pointer.func */
            4097, 8, 0, /* 1617: pointer.func */
            4097, 8, 0, /* 1620: pointer.func */
            0, 0, 0, /* 1623: func */
            0, 0, 0, /* 1626: func */
            4097, 8, 0, /* 1629: pointer.func */
            4097, 8, 0, /* 1632: pointer.func */
            4097, 8, 0, /* 1635: pointer.func */
            0, 0, 0, /* 1638: func */
            0, 8, 1, /* 1641: pointer.struct.ssl3_enc_method */
            	1646, 0,
            0, 112, 11, /* 1646: struct.ssl3_enc_method */
            	410, 0,
            	1671, 8,
            	1629, 16,
            	1674, 24,
            	410, 32,
            	1677, 40,
            	1680, 56,
            	49, 64,
            	49, 80,
            	1683, 96,
            	1686, 104,
            4097, 8, 0, /* 1671: pointer.func */
            4097, 8, 0, /* 1674: pointer.func */
            4097, 8, 0, /* 1677: pointer.func */
            4097, 8, 0, /* 1680: pointer.func */
            4097, 8, 0, /* 1683: pointer.func */
            4097, 8, 0, /* 1686: pointer.func */
            0, 0, 0, /* 1689: func */
            0, 0, 0, /* 1692: func */
            4097, 8, 0, /* 1695: pointer.func */
            0, 0, 0, /* 1698: func */
            0, 0, 0, /* 1701: func */
            0, 232, 28, /* 1704: struct.ssl_method_st */
            	1629, 8,
            	1440, 16,
            	1440, 24,
            	1629, 32,
            	1629, 40,
            	1671, 48,
            	1671, 56,
            	1671, 64,
            	1629, 72,
            	1629, 80,
            	1629, 88,
            	1763, 96,
            	1766, 104,
            	1437, 112,
            	1629, 120,
            	1769, 128,
            	1772, 136,
            	1632, 144,
            	1695, 152,
            	1629, 160,
            	731, 168,
            	1620, 176,
            	1775, 184,
            	1778, 192,
            	1641, 200,
            	731, 208,
            	1635, 216,
            	1781, 224,
            4097, 8, 0, /* 1763: pointer.func */
            4097, 8, 0, /* 1766: pointer.func */
            4097, 8, 0, /* 1769: pointer.func */
            4097, 8, 0, /* 1772: pointer.func */
            4097, 8, 0, /* 1775: pointer.func */
            4097, 8, 0, /* 1778: pointer.func */
            4097, 8, 0, /* 1781: pointer.func */
            0, 20, 0, /* 1784: array[20].char */
            0, 0, 0, /* 1787: func */
            0, 0, 0, /* 1790: func */
            0, 0, 0, /* 1793: func */
            0, 0, 0, /* 1796: func */
            0, 1, 0, /* 1799: char */
            0, 0, 0, /* 1802: func */
            0, 8, 1, /* 1805: pointer.struct.ssl_method_st */
            	1704, 0,
            0, 0, 0, /* 1810: func */
            0, 0, 0, /* 1813: func */
            0, 0, 0, /* 1816: func */
            0, 0, 0, /* 1819: func */
            0, 0, 0, /* 1822: func */
            0, 0, 0, /* 1825: func */
            0, 0, 0, /* 1828: func */
            0, 0, 0, /* 1831: func */
            0, 0, 0, /* 1834: func */
            0, 48, 0, /* 1837: array[48].char */
            0, 8, 1, /* 1840: pointer.struct.ssl_ctx_st */
            	1845, 0,
            0, 736, 50, /* 1845: struct.ssl_ctx_st */
            	1805, 0,
            	277, 8,
            	277, 16,
            	1570, 24,
            	1508, 32,
            	1503, 48,
            	1503, 56,
            	1948, 80,
            	1522, 88,
            	1302, 96,
            	1296, 152,
            	40, 160,
            	1293, 168,
            	40, 176,
            	1287, 184,
            	1284, 192,
            	1671, 200,
            	778, 208,
            	858, 224,
            	858, 232,
            	858, 240,
            	277, 248,
            	277, 256,
            	1318, 264,
            	277, 272,
            	1276, 304,
            	99, 320,
            	40, 328,
            	1611, 376,
            	1284, 384,
            	1537, 392,
            	457, 408,
            	43, 416,
            	40, 424,
            	87, 480,
            	46, 488,
            	40, 496,
            	1413, 504,
            	40, 512,
            	49, 520,
            	75, 528,
            	1674, 536,
            	1390, 552,
            	1390, 560,
            	9, 568,
            	3, 696,
            	40, 704,
            	0, 712,
            	40, 720,
            	277, 728,
            4097, 8, 0, /* 1948: pointer.func */
            0, 8, 0, /* 1951: array[8].char */
            0, 0, 0, /* 1954: func */
            0, 0, 0, /* 1957: func */
            0, 0, 0, /* 1960: func */
            0, 0, 0, /* 1963: func */
            0, 0, 0, /* 1966: func */
            0, 0, 0, /* 1969: func */
            0, 0, 0, /* 1972: func */
            0, 0, 0, /* 1975: func */
            0, 0, 0, /* 1978: func */
            0, 0, 0, /* 1981: func */
            0, 0, 0, /* 1984: func */
            0, 0, 0, /* 1987: func */
            0, 0, 0, /* 1990: func */
            0, 0, 0, /* 1993: func */
            0, 0, 0, /* 1996: func */
            0, 8, 0, /* 1999: long */
            0, 0, 0, /* 2002: func */
            0, 0, 0, /* 2005: func */
            0, 0, 0, /* 2008: func */
            0, 0, 0, /* 2011: func */
            0, 0, 0, /* 2014: func */
            0, 0, 0, /* 2017: func */
            0, 0, 0, /* 2020: func */
            0, 0, 0, /* 2023: func */
            0, 0, 0, /* 2026: func */
            0, 0, 0, /* 2029: func */
            0, 0, 0, /* 2032: func */
            0, 0, 0, /* 2035: func */
            0, 0, 0, /* 2038: func */
            0, 0, 0, /* 2041: func */
            0, 0, 0, /* 2044: func */
            0, 0, 0, /* 2047: func */
            0, 0, 0, /* 2050: func */
            0, 0, 0, /* 2053: func */
            0, 0, 0, /* 2056: func */
            0, 20, 0, /* 2059: array[5].int */
            0, 0, 0, /* 2062: func */
            0, 0, 0, /* 2065: func */
            0, 0, 0, /* 2068: func */
            0, 0, 0, /* 2071: func */
            0, 0, 0, /* 2074: func */
            0, 0, 0, /* 2077: func */
            0, 0, 0, /* 2080: func */
            0, 0, 0, /* 2083: func */
            0, 0, 0, /* 2086: func */
            0, 0, 0, /* 2089: func */
            0, 0, 0, /* 2092: func */
            0, 0, 0, /* 2095: func */
            0, 0, 0, /* 2098: func */
            0, 0, 0, /* 2101: func */
            0, 32, 0, /* 2104: array[32].char */
            0, 0, 0, /* 2107: func */
            0, 0, 0, /* 2110: func */
            0, 0, 0, /* 2113: func */
            0, 0, 0, /* 2116: func */
            0, 0, 0, /* 2119: func */
            0, 0, 0, /* 2122: func */
        },
        .arg_entity_index = { 1840, 69, 1611, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int (*new_arg_c)(int, X509_STORE_CTX *) = *((int (**)(int, X509_STORE_CTX *))new_args->args[2]);

    void (*orig_SSL_CTX_set_verify)(SSL_CTX *,int,int (*)(int, X509_STORE_CTX *));
    orig_SSL_CTX_set_verify = dlsym(RTLD_NEXT, "SSL_CTX_set_verify");
    (*orig_SSL_CTX_set_verify)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

}

