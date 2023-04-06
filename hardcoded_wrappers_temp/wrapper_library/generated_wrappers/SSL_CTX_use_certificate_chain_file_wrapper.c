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
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_use_certificate_chain_file called %lu\n", in_lib);
    if (!in_lib)
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
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            0, 24, 1, /* 10: struct.bignum_st */
            	15, 0,
            1, 8, 1, /* 15: pointer.unsigned int */
            	20, 0,
            0, 4, 0, /* 20: unsigned int */
            8884097, 8, 0, /* 23: pointer.func */
            0, 8, 1, /* 26: struct.ssl3_buf_freelist_entry_st */
            	31, 0,
            1, 8, 1, /* 31: pointer.struct.ssl3_buf_freelist_entry_st */
            	26, 0,
            0, 24, 1, /* 36: struct.ssl3_buf_freelist_st */
            	31, 16,
            8884097, 8, 0, /* 41: pointer.func */
            8884097, 8, 0, /* 44: pointer.func */
            8884097, 8, 0, /* 47: pointer.func */
            8884097, 8, 0, /* 50: pointer.func */
            8884097, 8, 0, /* 53: pointer.func */
            1, 8, 1, /* 56: pointer.struct.dh_st */
            	61, 0,
            0, 144, 12, /* 61: struct.dh_st */
            	88, 8,
            	88, 16,
            	88, 32,
            	88, 40,
            	98, 56,
            	88, 64,
            	88, 72,
            	112, 80,
            	88, 96,
            	120, 112,
            	155, 128,
            	191, 136,
            1, 8, 1, /* 88: pointer.struct.bignum_st */
            	93, 0,
            0, 24, 1, /* 93: struct.bignum_st */
            	15, 0,
            1, 8, 1, /* 98: pointer.struct.bn_mont_ctx_st */
            	103, 0,
            0, 96, 3, /* 103: struct.bn_mont_ctx_st */
            	93, 8,
            	93, 32,
            	93, 56,
            1, 8, 1, /* 112: pointer.unsigned char */
            	117, 0,
            0, 1, 0, /* 117: unsigned char */
            0, 16, 1, /* 120: struct.crypto_ex_data_st */
            	125, 0,
            1, 8, 1, /* 125: pointer.struct.stack_st_void */
            	130, 0,
            0, 32, 1, /* 130: struct.stack_st_void */
            	135, 0,
            0, 32, 2, /* 135: struct.stack_st */
            	142, 8,
            	152, 24,
            1, 8, 1, /* 142: pointer.pointer.char */
            	147, 0,
            1, 8, 1, /* 147: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 152: pointer.func */
            1, 8, 1, /* 155: pointer.struct.dh_method */
            	160, 0,
            0, 72, 8, /* 160: struct.dh_method */
            	5, 0,
            	179, 8,
            	182, 16,
            	185, 24,
            	179, 32,
            	179, 40,
            	147, 56,
            	188, 64,
            8884097, 8, 0, /* 179: pointer.func */
            8884097, 8, 0, /* 182: pointer.func */
            8884097, 8, 0, /* 185: pointer.func */
            8884097, 8, 0, /* 188: pointer.func */
            1, 8, 1, /* 191: pointer.struct.engine_st */
            	196, 0,
            0, 216, 24, /* 196: struct.engine_st */
            	5, 0,
            	5, 8,
            	247, 16,
            	302, 24,
            	353, 32,
            	389, 40,
            	406, 48,
            	433, 56,
            	468, 64,
            	476, 72,
            	479, 80,
            	482, 88,
            	485, 96,
            	488, 104,
            	488, 112,
            	488, 120,
            	491, 128,
            	494, 136,
            	494, 144,
            	497, 152,
            	500, 160,
            	512, 184,
            	534, 200,
            	534, 208,
            1, 8, 1, /* 247: pointer.struct.rsa_meth_st */
            	252, 0,
            0, 112, 13, /* 252: struct.rsa_meth_st */
            	5, 0,
            	281, 8,
            	281, 16,
            	281, 24,
            	281, 32,
            	284, 40,
            	287, 48,
            	290, 56,
            	290, 64,
            	147, 80,
            	293, 88,
            	296, 96,
            	299, 104,
            8884097, 8, 0, /* 281: pointer.func */
            8884097, 8, 0, /* 284: pointer.func */
            8884097, 8, 0, /* 287: pointer.func */
            8884097, 8, 0, /* 290: pointer.func */
            8884097, 8, 0, /* 293: pointer.func */
            8884097, 8, 0, /* 296: pointer.func */
            8884097, 8, 0, /* 299: pointer.func */
            1, 8, 1, /* 302: pointer.struct.dsa_method */
            	307, 0,
            0, 96, 11, /* 307: struct.dsa_method */
            	5, 0,
            	332, 8,
            	335, 16,
            	338, 24,
            	341, 32,
            	344, 40,
            	347, 48,
            	347, 56,
            	147, 72,
            	350, 80,
            	347, 88,
            8884097, 8, 0, /* 332: pointer.func */
            8884097, 8, 0, /* 335: pointer.func */
            8884097, 8, 0, /* 338: pointer.func */
            8884097, 8, 0, /* 341: pointer.func */
            8884097, 8, 0, /* 344: pointer.func */
            8884097, 8, 0, /* 347: pointer.func */
            8884097, 8, 0, /* 350: pointer.func */
            1, 8, 1, /* 353: pointer.struct.dh_method */
            	358, 0,
            0, 72, 8, /* 358: struct.dh_method */
            	5, 0,
            	377, 8,
            	380, 16,
            	383, 24,
            	377, 32,
            	377, 40,
            	147, 56,
            	386, 64,
            8884097, 8, 0, /* 377: pointer.func */
            8884097, 8, 0, /* 380: pointer.func */
            8884097, 8, 0, /* 383: pointer.func */
            8884097, 8, 0, /* 386: pointer.func */
            1, 8, 1, /* 389: pointer.struct.ecdh_method */
            	394, 0,
            0, 32, 3, /* 394: struct.ecdh_method */
            	5, 0,
            	403, 8,
            	147, 24,
            8884097, 8, 0, /* 403: pointer.func */
            1, 8, 1, /* 406: pointer.struct.ecdsa_method */
            	411, 0,
            0, 48, 5, /* 411: struct.ecdsa_method */
            	5, 0,
            	424, 8,
            	427, 16,
            	430, 24,
            	147, 40,
            8884097, 8, 0, /* 424: pointer.func */
            8884097, 8, 0, /* 427: pointer.func */
            8884097, 8, 0, /* 430: pointer.func */
            1, 8, 1, /* 433: pointer.struct.rand_meth_st */
            	438, 0,
            0, 48, 6, /* 438: struct.rand_meth_st */
            	453, 0,
            	456, 8,
            	459, 16,
            	462, 24,
            	456, 32,
            	465, 40,
            8884097, 8, 0, /* 453: pointer.func */
            8884097, 8, 0, /* 456: pointer.func */
            8884097, 8, 0, /* 459: pointer.func */
            8884097, 8, 0, /* 462: pointer.func */
            8884097, 8, 0, /* 465: pointer.func */
            1, 8, 1, /* 468: pointer.struct.store_method_st */
            	473, 0,
            0, 0, 0, /* 473: struct.store_method_st */
            8884097, 8, 0, /* 476: pointer.func */
            8884097, 8, 0, /* 479: pointer.func */
            8884097, 8, 0, /* 482: pointer.func */
            8884097, 8, 0, /* 485: pointer.func */
            8884097, 8, 0, /* 488: pointer.func */
            8884097, 8, 0, /* 491: pointer.func */
            8884097, 8, 0, /* 494: pointer.func */
            8884097, 8, 0, /* 497: pointer.func */
            1, 8, 1, /* 500: pointer.struct.ENGINE_CMD_DEFN_st */
            	505, 0,
            0, 32, 2, /* 505: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 512: struct.crypto_ex_data_st */
            	517, 0,
            1, 8, 1, /* 517: pointer.struct.stack_st_void */
            	522, 0,
            0, 32, 1, /* 522: struct.stack_st_void */
            	527, 0,
            0, 32, 2, /* 527: struct.stack_st */
            	142, 8,
            	152, 24,
            1, 8, 1, /* 534: pointer.struct.engine_st */
            	196, 0,
            1, 8, 1, /* 539: pointer.struct.rsa_st */
            	544, 0,
            0, 168, 17, /* 544: struct.rsa_st */
            	581, 16,
            	191, 24,
            	636, 32,
            	636, 40,
            	636, 48,
            	636, 56,
            	636, 64,
            	636, 72,
            	636, 80,
            	636, 88,
            	646, 96,
            	668, 120,
            	668, 128,
            	668, 136,
            	147, 144,
            	682, 152,
            	682, 160,
            1, 8, 1, /* 581: pointer.struct.rsa_meth_st */
            	586, 0,
            0, 112, 13, /* 586: struct.rsa_meth_st */
            	5, 0,
            	615, 8,
            	615, 16,
            	615, 24,
            	615, 32,
            	618, 40,
            	621, 48,
            	624, 56,
            	624, 64,
            	147, 80,
            	627, 88,
            	630, 96,
            	633, 104,
            8884097, 8, 0, /* 615: pointer.func */
            8884097, 8, 0, /* 618: pointer.func */
            8884097, 8, 0, /* 621: pointer.func */
            8884097, 8, 0, /* 624: pointer.func */
            8884097, 8, 0, /* 627: pointer.func */
            8884097, 8, 0, /* 630: pointer.func */
            8884097, 8, 0, /* 633: pointer.func */
            1, 8, 1, /* 636: pointer.struct.bignum_st */
            	641, 0,
            0, 24, 1, /* 641: struct.bignum_st */
            	15, 0,
            0, 16, 1, /* 646: struct.crypto_ex_data_st */
            	651, 0,
            1, 8, 1, /* 651: pointer.struct.stack_st_void */
            	656, 0,
            0, 32, 1, /* 656: struct.stack_st_void */
            	661, 0,
            0, 32, 2, /* 661: struct.stack_st */
            	142, 8,
            	152, 24,
            1, 8, 1, /* 668: pointer.struct.bn_mont_ctx_st */
            	673, 0,
            0, 96, 3, /* 673: struct.bn_mont_ctx_st */
            	641, 8,
            	641, 32,
            	641, 56,
            1, 8, 1, /* 682: pointer.struct.bn_blinding_st */
            	687, 0,
            0, 88, 7, /* 687: struct.bn_blinding_st */
            	704, 0,
            	704, 8,
            	704, 16,
            	704, 24,
            	714, 40,
            	722, 72,
            	736, 80,
            1, 8, 1, /* 704: pointer.struct.bignum_st */
            	709, 0,
            0, 24, 1, /* 709: struct.bignum_st */
            	15, 0,
            0, 16, 1, /* 714: struct.crypto_threadid_st */
            	719, 0,
            0, 8, 0, /* 719: pointer.void */
            1, 8, 1, /* 722: pointer.struct.bn_mont_ctx_st */
            	727, 0,
            0, 96, 3, /* 727: struct.bn_mont_ctx_st */
            	709, 8,
            	709, 32,
            	709, 56,
            8884097, 8, 0, /* 736: pointer.func */
            8884097, 8, 0, /* 739: pointer.func */
            8884097, 8, 0, /* 742: pointer.func */
            8884097, 8, 0, /* 745: pointer.func */
            1, 8, 1, /* 748: pointer.struct.env_md_st */
            	753, 0,
            0, 120, 8, /* 753: struct.env_md_st */
            	772, 24,
            	745, 32,
            	742, 40,
            	739, 48,
            	772, 56,
            	775, 64,
            	778, 72,
            	781, 112,
            8884097, 8, 0, /* 772: pointer.func */
            8884097, 8, 0, /* 775: pointer.func */
            8884097, 8, 0, /* 778: pointer.func */
            8884097, 8, 0, /* 781: pointer.func */
            1, 8, 1, /* 784: pointer.struct.dh_st */
            	61, 0,
            0, 8, 5, /* 789: union.unknown */
            	147, 0,
            	802, 0,
            	807, 0,
            	784, 0,
            	939, 0,
            1, 8, 1, /* 802: pointer.struct.rsa_st */
            	544, 0,
            1, 8, 1, /* 807: pointer.struct.dsa_st */
            	812, 0,
            0, 136, 11, /* 812: struct.dsa_st */
            	837, 24,
            	837, 32,
            	837, 40,
            	837, 48,
            	837, 56,
            	837, 64,
            	837, 72,
            	847, 88,
            	861, 104,
            	883, 120,
            	934, 128,
            1, 8, 1, /* 837: pointer.struct.bignum_st */
            	842, 0,
            0, 24, 1, /* 842: struct.bignum_st */
            	15, 0,
            1, 8, 1, /* 847: pointer.struct.bn_mont_ctx_st */
            	852, 0,
            0, 96, 3, /* 852: struct.bn_mont_ctx_st */
            	842, 8,
            	842, 32,
            	842, 56,
            0, 16, 1, /* 861: struct.crypto_ex_data_st */
            	866, 0,
            1, 8, 1, /* 866: pointer.struct.stack_st_void */
            	871, 0,
            0, 32, 1, /* 871: struct.stack_st_void */
            	876, 0,
            0, 32, 2, /* 876: struct.stack_st */
            	142, 8,
            	152, 24,
            1, 8, 1, /* 883: pointer.struct.dsa_method */
            	888, 0,
            0, 96, 11, /* 888: struct.dsa_method */
            	5, 0,
            	913, 8,
            	916, 16,
            	919, 24,
            	922, 32,
            	925, 40,
            	928, 48,
            	928, 56,
            	147, 72,
            	931, 80,
            	928, 88,
            8884097, 8, 0, /* 913: pointer.func */
            8884097, 8, 0, /* 916: pointer.func */
            8884097, 8, 0, /* 919: pointer.func */
            8884097, 8, 0, /* 922: pointer.func */
            8884097, 8, 0, /* 925: pointer.func */
            8884097, 8, 0, /* 928: pointer.func */
            8884097, 8, 0, /* 931: pointer.func */
            1, 8, 1, /* 934: pointer.struct.engine_st */
            	196, 0,
            1, 8, 1, /* 939: pointer.struct.ec_key_st */
            	944, 0,
            0, 56, 4, /* 944: struct.ec_key_st */
            	955, 8,
            	1389, 16,
            	1394, 24,
            	1404, 48,
            1, 8, 1, /* 955: pointer.struct.ec_group_st */
            	960, 0,
            0, 232, 12, /* 960: struct.ec_group_st */
            	987, 0,
            	1159, 8,
            	1352, 16,
            	1352, 40,
            	112, 80,
            	1357, 96,
            	1352, 104,
            	1352, 152,
            	1352, 176,
            	719, 208,
            	719, 216,
            	1386, 224,
            1, 8, 1, /* 987: pointer.struct.ec_method_st */
            	992, 0,
            0, 304, 37, /* 992: struct.ec_method_st */
            	1069, 8,
            	1072, 16,
            	1072, 24,
            	1075, 32,
            	1078, 40,
            	1081, 48,
            	1084, 56,
            	1087, 64,
            	1090, 72,
            	1093, 80,
            	1093, 88,
            	1096, 96,
            	1099, 104,
            	1102, 112,
            	1105, 120,
            	1108, 128,
            	1111, 136,
            	1114, 144,
            	1117, 152,
            	1120, 160,
            	1123, 168,
            	1126, 176,
            	1129, 184,
            	1132, 192,
            	1135, 200,
            	1138, 208,
            	1129, 216,
            	1141, 224,
            	1144, 232,
            	1147, 240,
            	1084, 248,
            	1150, 256,
            	1153, 264,
            	1150, 272,
            	1153, 280,
            	1153, 288,
            	1156, 296,
            8884097, 8, 0, /* 1069: pointer.func */
            8884097, 8, 0, /* 1072: pointer.func */
            8884097, 8, 0, /* 1075: pointer.func */
            8884097, 8, 0, /* 1078: pointer.func */
            8884097, 8, 0, /* 1081: pointer.func */
            8884097, 8, 0, /* 1084: pointer.func */
            8884097, 8, 0, /* 1087: pointer.func */
            8884097, 8, 0, /* 1090: pointer.func */
            8884097, 8, 0, /* 1093: pointer.func */
            8884097, 8, 0, /* 1096: pointer.func */
            8884097, 8, 0, /* 1099: pointer.func */
            8884097, 8, 0, /* 1102: pointer.func */
            8884097, 8, 0, /* 1105: pointer.func */
            8884097, 8, 0, /* 1108: pointer.func */
            8884097, 8, 0, /* 1111: pointer.func */
            8884097, 8, 0, /* 1114: pointer.func */
            8884097, 8, 0, /* 1117: pointer.func */
            8884097, 8, 0, /* 1120: pointer.func */
            8884097, 8, 0, /* 1123: pointer.func */
            8884097, 8, 0, /* 1126: pointer.func */
            8884097, 8, 0, /* 1129: pointer.func */
            8884097, 8, 0, /* 1132: pointer.func */
            8884097, 8, 0, /* 1135: pointer.func */
            8884097, 8, 0, /* 1138: pointer.func */
            8884097, 8, 0, /* 1141: pointer.func */
            8884097, 8, 0, /* 1144: pointer.func */
            8884097, 8, 0, /* 1147: pointer.func */
            8884097, 8, 0, /* 1150: pointer.func */
            8884097, 8, 0, /* 1153: pointer.func */
            8884097, 8, 0, /* 1156: pointer.func */
            1, 8, 1, /* 1159: pointer.struct.ec_point_st */
            	1164, 0,
            0, 88, 4, /* 1164: struct.ec_point_st */
            	1175, 0,
            	1347, 8,
            	1347, 32,
            	1347, 56,
            1, 8, 1, /* 1175: pointer.struct.ec_method_st */
            	1180, 0,
            0, 304, 37, /* 1180: struct.ec_method_st */
            	1257, 8,
            	1260, 16,
            	1260, 24,
            	1263, 32,
            	1266, 40,
            	1269, 48,
            	1272, 56,
            	1275, 64,
            	1278, 72,
            	1281, 80,
            	1281, 88,
            	1284, 96,
            	1287, 104,
            	1290, 112,
            	1293, 120,
            	1296, 128,
            	1299, 136,
            	1302, 144,
            	1305, 152,
            	1308, 160,
            	1311, 168,
            	1314, 176,
            	1317, 184,
            	1320, 192,
            	1323, 200,
            	1326, 208,
            	1317, 216,
            	1329, 224,
            	1332, 232,
            	1335, 240,
            	1272, 248,
            	1338, 256,
            	1341, 264,
            	1338, 272,
            	1341, 280,
            	1341, 288,
            	1344, 296,
            8884097, 8, 0, /* 1257: pointer.func */
            8884097, 8, 0, /* 1260: pointer.func */
            8884097, 8, 0, /* 1263: pointer.func */
            8884097, 8, 0, /* 1266: pointer.func */
            8884097, 8, 0, /* 1269: pointer.func */
            8884097, 8, 0, /* 1272: pointer.func */
            8884097, 8, 0, /* 1275: pointer.func */
            8884097, 8, 0, /* 1278: pointer.func */
            8884097, 8, 0, /* 1281: pointer.func */
            8884097, 8, 0, /* 1284: pointer.func */
            8884097, 8, 0, /* 1287: pointer.func */
            8884097, 8, 0, /* 1290: pointer.func */
            8884097, 8, 0, /* 1293: pointer.func */
            8884097, 8, 0, /* 1296: pointer.func */
            8884097, 8, 0, /* 1299: pointer.func */
            8884097, 8, 0, /* 1302: pointer.func */
            8884097, 8, 0, /* 1305: pointer.func */
            8884097, 8, 0, /* 1308: pointer.func */
            8884097, 8, 0, /* 1311: pointer.func */
            8884097, 8, 0, /* 1314: pointer.func */
            8884097, 8, 0, /* 1317: pointer.func */
            8884097, 8, 0, /* 1320: pointer.func */
            8884097, 8, 0, /* 1323: pointer.func */
            8884097, 8, 0, /* 1326: pointer.func */
            8884097, 8, 0, /* 1329: pointer.func */
            8884097, 8, 0, /* 1332: pointer.func */
            8884097, 8, 0, /* 1335: pointer.func */
            8884097, 8, 0, /* 1338: pointer.func */
            8884097, 8, 0, /* 1341: pointer.func */
            8884097, 8, 0, /* 1344: pointer.func */
            0, 24, 1, /* 1347: struct.bignum_st */
            	15, 0,
            0, 24, 1, /* 1352: struct.bignum_st */
            	15, 0,
            1, 8, 1, /* 1357: pointer.struct.ec_extra_data_st */
            	1362, 0,
            0, 40, 5, /* 1362: struct.ec_extra_data_st */
            	1375, 0,
            	719, 8,
            	1380, 16,
            	1383, 24,
            	1383, 32,
            1, 8, 1, /* 1375: pointer.struct.ec_extra_data_st */
            	1362, 0,
            8884097, 8, 0, /* 1380: pointer.func */
            8884097, 8, 0, /* 1383: pointer.func */
            8884097, 8, 0, /* 1386: pointer.func */
            1, 8, 1, /* 1389: pointer.struct.ec_point_st */
            	1164, 0,
            1, 8, 1, /* 1394: pointer.struct.bignum_st */
            	1399, 0,
            0, 24, 1, /* 1399: struct.bignum_st */
            	15, 0,
            1, 8, 1, /* 1404: pointer.struct.ec_extra_data_st */
            	1409, 0,
            0, 40, 5, /* 1409: struct.ec_extra_data_st */
            	1422, 0,
            	719, 8,
            	1380, 16,
            	1383, 24,
            	1383, 32,
            1, 8, 1, /* 1422: pointer.struct.ec_extra_data_st */
            	1409, 0,
            0, 56, 4, /* 1427: struct.evp_pkey_st */
            	1438, 16,
            	1539, 24,
            	789, 32,
            	1544, 48,
            1, 8, 1, /* 1438: pointer.struct.evp_pkey_asn1_method_st */
            	1443, 0,
            0, 208, 24, /* 1443: struct.evp_pkey_asn1_method_st */
            	147, 16,
            	147, 24,
            	1494, 32,
            	1497, 40,
            	1500, 48,
            	1503, 56,
            	1506, 64,
            	1509, 72,
            	1503, 80,
            	1512, 88,
            	1512, 96,
            	1515, 104,
            	1518, 112,
            	1512, 120,
            	1521, 128,
            	1500, 136,
            	1503, 144,
            	1524, 152,
            	1527, 160,
            	1530, 168,
            	1515, 176,
            	1518, 184,
            	1533, 192,
            	1536, 200,
            8884097, 8, 0, /* 1494: pointer.func */
            8884097, 8, 0, /* 1497: pointer.func */
            8884097, 8, 0, /* 1500: pointer.func */
            8884097, 8, 0, /* 1503: pointer.func */
            8884097, 8, 0, /* 1506: pointer.func */
            8884097, 8, 0, /* 1509: pointer.func */
            8884097, 8, 0, /* 1512: pointer.func */
            8884097, 8, 0, /* 1515: pointer.func */
            8884097, 8, 0, /* 1518: pointer.func */
            8884097, 8, 0, /* 1521: pointer.func */
            8884097, 8, 0, /* 1524: pointer.func */
            8884097, 8, 0, /* 1527: pointer.func */
            8884097, 8, 0, /* 1530: pointer.func */
            8884097, 8, 0, /* 1533: pointer.func */
            8884097, 8, 0, /* 1536: pointer.func */
            1, 8, 1, /* 1539: pointer.struct.engine_st */
            	196, 0,
            1, 8, 1, /* 1544: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1549, 0,
            0, 32, 2, /* 1549: struct.stack_st_fake_X509_ATTRIBUTE */
            	1556, 8,
            	152, 24,
            8884099, 8, 2, /* 1556: pointer_to_array_of_pointers_to_stack */
            	1563, 0,
            	1787, 20,
            0, 8, 1, /* 1563: pointer.X509_ATTRIBUTE */
            	1568, 0,
            0, 0, 1, /* 1568: X509_ATTRIBUTE */
            	1573, 0,
            0, 24, 2, /* 1573: struct.x509_attributes_st */
            	1580, 0,
            	1599, 16,
            1, 8, 1, /* 1580: pointer.struct.asn1_object_st */
            	1585, 0,
            0, 40, 3, /* 1585: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1594, 24,
            1, 8, 1, /* 1594: pointer.unsigned char */
            	117, 0,
            0, 8, 3, /* 1599: union.unknown */
            	147, 0,
            	1608, 0,
            	1790, 0,
            1, 8, 1, /* 1608: pointer.struct.stack_st_ASN1_TYPE */
            	1613, 0,
            0, 32, 2, /* 1613: struct.stack_st_fake_ASN1_TYPE */
            	1620, 8,
            	152, 24,
            8884099, 8, 2, /* 1620: pointer_to_array_of_pointers_to_stack */
            	1627, 0,
            	1787, 20,
            0, 8, 1, /* 1627: pointer.ASN1_TYPE */
            	1632, 0,
            0, 0, 1, /* 1632: ASN1_TYPE */
            	1637, 0,
            0, 16, 1, /* 1637: struct.asn1_type_st */
            	1642, 8,
            0, 8, 20, /* 1642: union.unknown */
            	147, 0,
            	1685, 0,
            	1695, 0,
            	1709, 0,
            	1714, 0,
            	1719, 0,
            	1724, 0,
            	1729, 0,
            	1734, 0,
            	1739, 0,
            	1744, 0,
            	1749, 0,
            	1754, 0,
            	1759, 0,
            	1764, 0,
            	1769, 0,
            	1774, 0,
            	1685, 0,
            	1685, 0,
            	1779, 0,
            1, 8, 1, /* 1685: pointer.struct.asn1_string_st */
            	1690, 0,
            0, 24, 1, /* 1690: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 1695: pointer.struct.asn1_object_st */
            	1700, 0,
            0, 40, 3, /* 1700: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1594, 24,
            1, 8, 1, /* 1709: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1714: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1719: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1724: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1729: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1734: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1739: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1744: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1749: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1754: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1759: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1764: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1769: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1774: pointer.struct.asn1_string_st */
            	1690, 0,
            1, 8, 1, /* 1779: pointer.struct.ASN1_VALUE_st */
            	1784, 0,
            0, 0, 0, /* 1784: struct.ASN1_VALUE_st */
            0, 4, 0, /* 1787: int */
            1, 8, 1, /* 1790: pointer.struct.asn1_type_st */
            	1795, 0,
            0, 16, 1, /* 1795: struct.asn1_type_st */
            	1800, 8,
            0, 8, 20, /* 1800: union.unknown */
            	147, 0,
            	1843, 0,
            	1580, 0,
            	1853, 0,
            	1858, 0,
            	1863, 0,
            	1868, 0,
            	1873, 0,
            	1878, 0,
            	1883, 0,
            	1888, 0,
            	1893, 0,
            	1898, 0,
            	1903, 0,
            	1908, 0,
            	1913, 0,
            	1918, 0,
            	1843, 0,
            	1843, 0,
            	1923, 0,
            1, 8, 1, /* 1843: pointer.struct.asn1_string_st */
            	1848, 0,
            0, 24, 1, /* 1848: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 1853: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1858: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1863: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1868: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1873: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1878: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1883: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1888: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1893: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1898: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1903: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1908: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1913: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1918: pointer.struct.asn1_string_st */
            	1848, 0,
            1, 8, 1, /* 1923: pointer.struct.ASN1_VALUE_st */
            	1928, 0,
            0, 0, 0, /* 1928: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1931: pointer.struct.asn1_string_st */
            	1936, 0,
            0, 24, 1, /* 1936: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 1941: pointer.struct.stack_st_ASN1_OBJECT */
            	1946, 0,
            0, 32, 2, /* 1946: struct.stack_st_fake_ASN1_OBJECT */
            	1953, 8,
            	152, 24,
            8884099, 8, 2, /* 1953: pointer_to_array_of_pointers_to_stack */
            	1960, 0,
            	1787, 20,
            0, 8, 1, /* 1960: pointer.ASN1_OBJECT */
            	1965, 0,
            0, 0, 1, /* 1965: ASN1_OBJECT */
            	1970, 0,
            0, 40, 3, /* 1970: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1594, 24,
            1, 8, 1, /* 1979: pointer.struct.x509_cert_aux_st */
            	1984, 0,
            0, 40, 5, /* 1984: struct.x509_cert_aux_st */
            	1941, 0,
            	1941, 8,
            	1931, 16,
            	1997, 24,
            	2002, 32,
            1, 8, 1, /* 1997: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 2002: pointer.struct.stack_st_X509_ALGOR */
            	2007, 0,
            0, 32, 2, /* 2007: struct.stack_st_fake_X509_ALGOR */
            	2014, 8,
            	152, 24,
            8884099, 8, 2, /* 2014: pointer_to_array_of_pointers_to_stack */
            	2021, 0,
            	1787, 20,
            0, 8, 1, /* 2021: pointer.X509_ALGOR */
            	2026, 0,
            0, 0, 1, /* 2026: X509_ALGOR */
            	2031, 0,
            0, 16, 2, /* 2031: struct.X509_algor_st */
            	2038, 0,
            	2052, 8,
            1, 8, 1, /* 2038: pointer.struct.asn1_object_st */
            	2043, 0,
            0, 40, 3, /* 2043: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1594, 24,
            1, 8, 1, /* 2052: pointer.struct.asn1_type_st */
            	2057, 0,
            0, 16, 1, /* 2057: struct.asn1_type_st */
            	2062, 8,
            0, 8, 20, /* 2062: union.unknown */
            	147, 0,
            	2105, 0,
            	2038, 0,
            	2115, 0,
            	2120, 0,
            	2125, 0,
            	2130, 0,
            	2135, 0,
            	2140, 0,
            	2145, 0,
            	2150, 0,
            	2155, 0,
            	2160, 0,
            	2165, 0,
            	2170, 0,
            	2175, 0,
            	2180, 0,
            	2105, 0,
            	2105, 0,
            	2185, 0,
            1, 8, 1, /* 2105: pointer.struct.asn1_string_st */
            	2110, 0,
            0, 24, 1, /* 2110: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 2115: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2120: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2125: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2130: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2135: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2140: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2145: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2150: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2155: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2160: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2165: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2170: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2175: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2180: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2185: pointer.struct.ASN1_VALUE_st */
            	2190, 0,
            0, 0, 0, /* 2190: struct.ASN1_VALUE_st */
            0, 32, 2, /* 2193: struct.stack_st */
            	142, 8,
            	152, 24,
            0, 32, 1, /* 2200: struct.stack_st_void */
            	2193, 0,
            0, 24, 1, /* 2205: struct.ASN1_ENCODING_st */
            	112, 0,
            1, 8, 1, /* 2210: pointer.struct.stack_st_X509_EXTENSION */
            	2215, 0,
            0, 32, 2, /* 2215: struct.stack_st_fake_X509_EXTENSION */
            	2222, 8,
            	152, 24,
            8884099, 8, 2, /* 2222: pointer_to_array_of_pointers_to_stack */
            	2229, 0,
            	1787, 20,
            0, 8, 1, /* 2229: pointer.X509_EXTENSION */
            	2234, 0,
            0, 0, 1, /* 2234: X509_EXTENSION */
            	2239, 0,
            0, 24, 2, /* 2239: struct.X509_extension_st */
            	2246, 0,
            	2260, 16,
            1, 8, 1, /* 2246: pointer.struct.asn1_object_st */
            	2251, 0,
            0, 40, 3, /* 2251: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1594, 24,
            1, 8, 1, /* 2260: pointer.struct.asn1_string_st */
            	2265, 0,
            0, 24, 1, /* 2265: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 2270: pointer.struct.X509_pubkey_st */
            	2275, 0,
            0, 24, 3, /* 2275: struct.X509_pubkey_st */
            	2284, 0,
            	2289, 8,
            	2299, 16,
            1, 8, 1, /* 2284: pointer.struct.X509_algor_st */
            	2031, 0,
            1, 8, 1, /* 2289: pointer.struct.asn1_string_st */
            	2294, 0,
            0, 24, 1, /* 2294: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 2299: pointer.struct.evp_pkey_st */
            	2304, 0,
            0, 56, 4, /* 2304: struct.evp_pkey_st */
            	2315, 16,
            	934, 24,
            	2320, 32,
            	2353, 48,
            1, 8, 1, /* 2315: pointer.struct.evp_pkey_asn1_method_st */
            	1443, 0,
            0, 8, 5, /* 2320: union.unknown */
            	147, 0,
            	2333, 0,
            	2338, 0,
            	2343, 0,
            	2348, 0,
            1, 8, 1, /* 2333: pointer.struct.rsa_st */
            	544, 0,
            1, 8, 1, /* 2338: pointer.struct.dsa_st */
            	812, 0,
            1, 8, 1, /* 2343: pointer.struct.dh_st */
            	61, 0,
            1, 8, 1, /* 2348: pointer.struct.ec_key_st */
            	944, 0,
            1, 8, 1, /* 2353: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2358, 0,
            0, 32, 2, /* 2358: struct.stack_st_fake_X509_ATTRIBUTE */
            	2365, 8,
            	152, 24,
            8884099, 8, 2, /* 2365: pointer_to_array_of_pointers_to_stack */
            	2372, 0,
            	1787, 20,
            0, 8, 1, /* 2372: pointer.X509_ATTRIBUTE */
            	1568, 0,
            1, 8, 1, /* 2377: pointer.struct.X509_val_st */
            	2382, 0,
            0, 16, 2, /* 2382: struct.X509_val_st */
            	2389, 0,
            	2389, 8,
            1, 8, 1, /* 2389: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 2394: pointer.struct.buf_mem_st */
            	2399, 0,
            0, 24, 1, /* 2399: struct.buf_mem_st */
            	147, 8,
            1, 8, 1, /* 2404: pointer.struct.X509_name_st */
            	2409, 0,
            0, 40, 3, /* 2409: struct.X509_name_st */
            	2418, 0,
            	2394, 16,
            	112, 24,
            1, 8, 1, /* 2418: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2423, 0,
            0, 32, 2, /* 2423: struct.stack_st_fake_X509_NAME_ENTRY */
            	2430, 8,
            	152, 24,
            8884099, 8, 2, /* 2430: pointer_to_array_of_pointers_to_stack */
            	2437, 0,
            	1787, 20,
            0, 8, 1, /* 2437: pointer.X509_NAME_ENTRY */
            	2442, 0,
            0, 0, 1, /* 2442: X509_NAME_ENTRY */
            	2447, 0,
            0, 24, 2, /* 2447: struct.X509_name_entry_st */
            	2454, 0,
            	2468, 8,
            1, 8, 1, /* 2454: pointer.struct.asn1_object_st */
            	2459, 0,
            0, 40, 3, /* 2459: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1594, 24,
            1, 8, 1, /* 2468: pointer.struct.asn1_string_st */
            	2473, 0,
            0, 24, 1, /* 2473: struct.asn1_string_st */
            	112, 8,
            0, 184, 12, /* 2478: struct.x509_st */
            	2505, 0,
            	2540, 8,
            	2545, 16,
            	147, 32,
            	2550, 40,
            	1997, 104,
            	2560, 112,
            	2883, 120,
            	3305, 128,
            	3444, 136,
            	3468, 144,
            	1979, 176,
            1, 8, 1, /* 2505: pointer.struct.x509_cinf_st */
            	2510, 0,
            0, 104, 11, /* 2510: struct.x509_cinf_st */
            	2535, 0,
            	2535, 8,
            	2540, 16,
            	2404, 24,
            	2377, 32,
            	2404, 40,
            	2270, 48,
            	2545, 56,
            	2545, 64,
            	2210, 72,
            	2205, 80,
            1, 8, 1, /* 2535: pointer.struct.asn1_string_st */
            	1936, 0,
            1, 8, 1, /* 2540: pointer.struct.X509_algor_st */
            	2031, 0,
            1, 8, 1, /* 2545: pointer.struct.asn1_string_st */
            	1936, 0,
            0, 16, 1, /* 2550: struct.crypto_ex_data_st */
            	2555, 0,
            1, 8, 1, /* 2555: pointer.struct.stack_st_void */
            	2200, 0,
            1, 8, 1, /* 2560: pointer.struct.AUTHORITY_KEYID_st */
            	2565, 0,
            0, 24, 3, /* 2565: struct.AUTHORITY_KEYID_st */
            	2574, 0,
            	2584, 8,
            	2878, 16,
            1, 8, 1, /* 2574: pointer.struct.asn1_string_st */
            	2579, 0,
            0, 24, 1, /* 2579: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 2584: pointer.struct.stack_st_GENERAL_NAME */
            	2589, 0,
            0, 32, 2, /* 2589: struct.stack_st_fake_GENERAL_NAME */
            	2596, 8,
            	152, 24,
            8884099, 8, 2, /* 2596: pointer_to_array_of_pointers_to_stack */
            	2603, 0,
            	1787, 20,
            0, 8, 1, /* 2603: pointer.GENERAL_NAME */
            	2608, 0,
            0, 0, 1, /* 2608: GENERAL_NAME */
            	2613, 0,
            0, 16, 1, /* 2613: struct.GENERAL_NAME_st */
            	2618, 8,
            0, 8, 15, /* 2618: union.unknown */
            	147, 0,
            	2651, 0,
            	2770, 0,
            	2770, 0,
            	2677, 0,
            	2818, 0,
            	2866, 0,
            	2770, 0,
            	2755, 0,
            	2663, 0,
            	2755, 0,
            	2818, 0,
            	2770, 0,
            	2663, 0,
            	2677, 0,
            1, 8, 1, /* 2651: pointer.struct.otherName_st */
            	2656, 0,
            0, 16, 2, /* 2656: struct.otherName_st */
            	2663, 0,
            	2677, 8,
            1, 8, 1, /* 2663: pointer.struct.asn1_object_st */
            	2668, 0,
            0, 40, 3, /* 2668: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1594, 24,
            1, 8, 1, /* 2677: pointer.struct.asn1_type_st */
            	2682, 0,
            0, 16, 1, /* 2682: struct.asn1_type_st */
            	2687, 8,
            0, 8, 20, /* 2687: union.unknown */
            	147, 0,
            	2730, 0,
            	2663, 0,
            	2740, 0,
            	2745, 0,
            	2750, 0,
            	2755, 0,
            	2760, 0,
            	2765, 0,
            	2770, 0,
            	2775, 0,
            	2780, 0,
            	2785, 0,
            	2790, 0,
            	2795, 0,
            	2800, 0,
            	2805, 0,
            	2730, 0,
            	2730, 0,
            	2810, 0,
            1, 8, 1, /* 2730: pointer.struct.asn1_string_st */
            	2735, 0,
            0, 24, 1, /* 2735: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 2740: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2745: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2750: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2755: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2760: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2765: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2770: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2775: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2780: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2785: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2790: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2795: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2800: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2805: pointer.struct.asn1_string_st */
            	2735, 0,
            1, 8, 1, /* 2810: pointer.struct.ASN1_VALUE_st */
            	2815, 0,
            0, 0, 0, /* 2815: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2818: pointer.struct.X509_name_st */
            	2823, 0,
            0, 40, 3, /* 2823: struct.X509_name_st */
            	2832, 0,
            	2856, 16,
            	112, 24,
            1, 8, 1, /* 2832: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2837, 0,
            0, 32, 2, /* 2837: struct.stack_st_fake_X509_NAME_ENTRY */
            	2844, 8,
            	152, 24,
            8884099, 8, 2, /* 2844: pointer_to_array_of_pointers_to_stack */
            	2851, 0,
            	1787, 20,
            0, 8, 1, /* 2851: pointer.X509_NAME_ENTRY */
            	2442, 0,
            1, 8, 1, /* 2856: pointer.struct.buf_mem_st */
            	2861, 0,
            0, 24, 1, /* 2861: struct.buf_mem_st */
            	147, 8,
            1, 8, 1, /* 2866: pointer.struct.EDIPartyName_st */
            	2871, 0,
            0, 16, 2, /* 2871: struct.EDIPartyName_st */
            	2730, 0,
            	2730, 8,
            1, 8, 1, /* 2878: pointer.struct.asn1_string_st */
            	2579, 0,
            1, 8, 1, /* 2883: pointer.struct.X509_POLICY_CACHE_st */
            	2888, 0,
            0, 40, 2, /* 2888: struct.X509_POLICY_CACHE_st */
            	2895, 0,
            	3205, 8,
            1, 8, 1, /* 2895: pointer.struct.X509_POLICY_DATA_st */
            	2900, 0,
            0, 32, 3, /* 2900: struct.X509_POLICY_DATA_st */
            	2909, 8,
            	2923, 16,
            	3181, 24,
            1, 8, 1, /* 2909: pointer.struct.asn1_object_st */
            	2914, 0,
            0, 40, 3, /* 2914: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1594, 24,
            1, 8, 1, /* 2923: pointer.struct.stack_st_POLICYQUALINFO */
            	2928, 0,
            0, 32, 2, /* 2928: struct.stack_st_fake_POLICYQUALINFO */
            	2935, 8,
            	152, 24,
            8884099, 8, 2, /* 2935: pointer_to_array_of_pointers_to_stack */
            	2942, 0,
            	1787, 20,
            0, 8, 1, /* 2942: pointer.POLICYQUALINFO */
            	2947, 0,
            0, 0, 1, /* 2947: POLICYQUALINFO */
            	2952, 0,
            0, 16, 2, /* 2952: struct.POLICYQUALINFO_st */
            	2959, 0,
            	2973, 8,
            1, 8, 1, /* 2959: pointer.struct.asn1_object_st */
            	2964, 0,
            0, 40, 3, /* 2964: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1594, 24,
            0, 8, 3, /* 2973: union.unknown */
            	2982, 0,
            	2992, 0,
            	3055, 0,
            1, 8, 1, /* 2982: pointer.struct.asn1_string_st */
            	2987, 0,
            0, 24, 1, /* 2987: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 2992: pointer.struct.USERNOTICE_st */
            	2997, 0,
            0, 16, 2, /* 2997: struct.USERNOTICE_st */
            	3004, 0,
            	3016, 8,
            1, 8, 1, /* 3004: pointer.struct.NOTICEREF_st */
            	3009, 0,
            0, 16, 2, /* 3009: struct.NOTICEREF_st */
            	3016, 0,
            	3021, 8,
            1, 8, 1, /* 3016: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3021: pointer.struct.stack_st_ASN1_INTEGER */
            	3026, 0,
            0, 32, 2, /* 3026: struct.stack_st_fake_ASN1_INTEGER */
            	3033, 8,
            	152, 24,
            8884099, 8, 2, /* 3033: pointer_to_array_of_pointers_to_stack */
            	3040, 0,
            	1787, 20,
            0, 8, 1, /* 3040: pointer.ASN1_INTEGER */
            	3045, 0,
            0, 0, 1, /* 3045: ASN1_INTEGER */
            	3050, 0,
            0, 24, 1, /* 3050: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 3055: pointer.struct.asn1_type_st */
            	3060, 0,
            0, 16, 1, /* 3060: struct.asn1_type_st */
            	3065, 8,
            0, 8, 20, /* 3065: union.unknown */
            	147, 0,
            	3016, 0,
            	2959, 0,
            	3108, 0,
            	3113, 0,
            	3118, 0,
            	3123, 0,
            	3128, 0,
            	3133, 0,
            	2982, 0,
            	3138, 0,
            	3143, 0,
            	3148, 0,
            	3153, 0,
            	3158, 0,
            	3163, 0,
            	3168, 0,
            	3016, 0,
            	3016, 0,
            	3173, 0,
            1, 8, 1, /* 3108: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3113: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3118: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3123: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3128: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3133: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3138: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3143: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3148: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3153: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3158: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3163: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3168: pointer.struct.asn1_string_st */
            	2987, 0,
            1, 8, 1, /* 3173: pointer.struct.ASN1_VALUE_st */
            	3178, 0,
            0, 0, 0, /* 3178: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3181: pointer.struct.stack_st_ASN1_OBJECT */
            	3186, 0,
            0, 32, 2, /* 3186: struct.stack_st_fake_ASN1_OBJECT */
            	3193, 8,
            	152, 24,
            8884099, 8, 2, /* 3193: pointer_to_array_of_pointers_to_stack */
            	3200, 0,
            	1787, 20,
            0, 8, 1, /* 3200: pointer.ASN1_OBJECT */
            	1965, 0,
            1, 8, 1, /* 3205: pointer.struct.stack_st_X509_POLICY_DATA */
            	3210, 0,
            0, 32, 2, /* 3210: struct.stack_st_fake_X509_POLICY_DATA */
            	3217, 8,
            	152, 24,
            8884099, 8, 2, /* 3217: pointer_to_array_of_pointers_to_stack */
            	3224, 0,
            	1787, 20,
            0, 8, 1, /* 3224: pointer.X509_POLICY_DATA */
            	3229, 0,
            0, 0, 1, /* 3229: X509_POLICY_DATA */
            	3234, 0,
            0, 32, 3, /* 3234: struct.X509_POLICY_DATA_st */
            	3243, 8,
            	3257, 16,
            	3281, 24,
            1, 8, 1, /* 3243: pointer.struct.asn1_object_st */
            	3248, 0,
            0, 40, 3, /* 3248: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1594, 24,
            1, 8, 1, /* 3257: pointer.struct.stack_st_POLICYQUALINFO */
            	3262, 0,
            0, 32, 2, /* 3262: struct.stack_st_fake_POLICYQUALINFO */
            	3269, 8,
            	152, 24,
            8884099, 8, 2, /* 3269: pointer_to_array_of_pointers_to_stack */
            	3276, 0,
            	1787, 20,
            0, 8, 1, /* 3276: pointer.POLICYQUALINFO */
            	2947, 0,
            1, 8, 1, /* 3281: pointer.struct.stack_st_ASN1_OBJECT */
            	3286, 0,
            0, 32, 2, /* 3286: struct.stack_st_fake_ASN1_OBJECT */
            	3293, 8,
            	152, 24,
            8884099, 8, 2, /* 3293: pointer_to_array_of_pointers_to_stack */
            	3300, 0,
            	1787, 20,
            0, 8, 1, /* 3300: pointer.ASN1_OBJECT */
            	1965, 0,
            1, 8, 1, /* 3305: pointer.struct.stack_st_DIST_POINT */
            	3310, 0,
            0, 32, 2, /* 3310: struct.stack_st_fake_DIST_POINT */
            	3317, 8,
            	152, 24,
            8884099, 8, 2, /* 3317: pointer_to_array_of_pointers_to_stack */
            	3324, 0,
            	1787, 20,
            0, 8, 1, /* 3324: pointer.DIST_POINT */
            	3329, 0,
            0, 0, 1, /* 3329: DIST_POINT */
            	3334, 0,
            0, 32, 3, /* 3334: struct.DIST_POINT_st */
            	3343, 0,
            	3434, 8,
            	3362, 16,
            1, 8, 1, /* 3343: pointer.struct.DIST_POINT_NAME_st */
            	3348, 0,
            0, 24, 2, /* 3348: struct.DIST_POINT_NAME_st */
            	3355, 8,
            	3410, 16,
            0, 8, 2, /* 3355: union.unknown */
            	3362, 0,
            	3386, 0,
            1, 8, 1, /* 3362: pointer.struct.stack_st_GENERAL_NAME */
            	3367, 0,
            0, 32, 2, /* 3367: struct.stack_st_fake_GENERAL_NAME */
            	3374, 8,
            	152, 24,
            8884099, 8, 2, /* 3374: pointer_to_array_of_pointers_to_stack */
            	3381, 0,
            	1787, 20,
            0, 8, 1, /* 3381: pointer.GENERAL_NAME */
            	2608, 0,
            1, 8, 1, /* 3386: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3391, 0,
            0, 32, 2, /* 3391: struct.stack_st_fake_X509_NAME_ENTRY */
            	3398, 8,
            	152, 24,
            8884099, 8, 2, /* 3398: pointer_to_array_of_pointers_to_stack */
            	3405, 0,
            	1787, 20,
            0, 8, 1, /* 3405: pointer.X509_NAME_ENTRY */
            	2442, 0,
            1, 8, 1, /* 3410: pointer.struct.X509_name_st */
            	3415, 0,
            0, 40, 3, /* 3415: struct.X509_name_st */
            	3386, 0,
            	3424, 16,
            	112, 24,
            1, 8, 1, /* 3424: pointer.struct.buf_mem_st */
            	3429, 0,
            0, 24, 1, /* 3429: struct.buf_mem_st */
            	147, 8,
            1, 8, 1, /* 3434: pointer.struct.asn1_string_st */
            	3439, 0,
            0, 24, 1, /* 3439: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 3444: pointer.struct.stack_st_GENERAL_NAME */
            	3449, 0,
            0, 32, 2, /* 3449: struct.stack_st_fake_GENERAL_NAME */
            	3456, 8,
            	152, 24,
            8884099, 8, 2, /* 3456: pointer_to_array_of_pointers_to_stack */
            	3463, 0,
            	1787, 20,
            0, 8, 1, /* 3463: pointer.GENERAL_NAME */
            	2608, 0,
            1, 8, 1, /* 3468: pointer.struct.NAME_CONSTRAINTS_st */
            	3473, 0,
            0, 16, 2, /* 3473: struct.NAME_CONSTRAINTS_st */
            	3480, 0,
            	3480, 8,
            1, 8, 1, /* 3480: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3485, 0,
            0, 32, 2, /* 3485: struct.stack_st_fake_GENERAL_SUBTREE */
            	3492, 8,
            	152, 24,
            8884099, 8, 2, /* 3492: pointer_to_array_of_pointers_to_stack */
            	3499, 0,
            	1787, 20,
            0, 8, 1, /* 3499: pointer.GENERAL_SUBTREE */
            	3504, 0,
            0, 0, 1, /* 3504: GENERAL_SUBTREE */
            	3509, 0,
            0, 24, 3, /* 3509: struct.GENERAL_SUBTREE_st */
            	3518, 0,
            	3650, 8,
            	3650, 16,
            1, 8, 1, /* 3518: pointer.struct.GENERAL_NAME_st */
            	3523, 0,
            0, 16, 1, /* 3523: struct.GENERAL_NAME_st */
            	3528, 8,
            0, 8, 15, /* 3528: union.unknown */
            	147, 0,
            	3561, 0,
            	3680, 0,
            	3680, 0,
            	3587, 0,
            	3720, 0,
            	3768, 0,
            	3680, 0,
            	3665, 0,
            	3573, 0,
            	3665, 0,
            	3720, 0,
            	3680, 0,
            	3573, 0,
            	3587, 0,
            1, 8, 1, /* 3561: pointer.struct.otherName_st */
            	3566, 0,
            0, 16, 2, /* 3566: struct.otherName_st */
            	3573, 0,
            	3587, 8,
            1, 8, 1, /* 3573: pointer.struct.asn1_object_st */
            	3578, 0,
            0, 40, 3, /* 3578: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1594, 24,
            1, 8, 1, /* 3587: pointer.struct.asn1_type_st */
            	3592, 0,
            0, 16, 1, /* 3592: struct.asn1_type_st */
            	3597, 8,
            0, 8, 20, /* 3597: union.unknown */
            	147, 0,
            	3640, 0,
            	3573, 0,
            	3650, 0,
            	3655, 0,
            	3660, 0,
            	3665, 0,
            	3670, 0,
            	3675, 0,
            	3680, 0,
            	3685, 0,
            	3690, 0,
            	3695, 0,
            	3700, 0,
            	3705, 0,
            	3710, 0,
            	3715, 0,
            	3640, 0,
            	3640, 0,
            	3173, 0,
            1, 8, 1, /* 3640: pointer.struct.asn1_string_st */
            	3645, 0,
            0, 24, 1, /* 3645: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 3650: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3655: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3660: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3665: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3670: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3675: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3680: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3685: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3690: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3695: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3700: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3705: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3710: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3715: pointer.struct.asn1_string_st */
            	3645, 0,
            1, 8, 1, /* 3720: pointer.struct.X509_name_st */
            	3725, 0,
            0, 40, 3, /* 3725: struct.X509_name_st */
            	3734, 0,
            	3758, 16,
            	112, 24,
            1, 8, 1, /* 3734: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3739, 0,
            0, 32, 2, /* 3739: struct.stack_st_fake_X509_NAME_ENTRY */
            	3746, 8,
            	152, 24,
            8884099, 8, 2, /* 3746: pointer_to_array_of_pointers_to_stack */
            	3753, 0,
            	1787, 20,
            0, 8, 1, /* 3753: pointer.X509_NAME_ENTRY */
            	2442, 0,
            1, 8, 1, /* 3758: pointer.struct.buf_mem_st */
            	3763, 0,
            0, 24, 1, /* 3763: struct.buf_mem_st */
            	147, 8,
            1, 8, 1, /* 3768: pointer.struct.EDIPartyName_st */
            	3773, 0,
            0, 16, 2, /* 3773: struct.EDIPartyName_st */
            	3640, 0,
            	3640, 8,
            0, 24, 3, /* 3780: struct.cert_pkey_st */
            	3789, 0,
            	3794, 8,
            	748, 16,
            1, 8, 1, /* 3789: pointer.struct.x509_st */
            	2478, 0,
            1, 8, 1, /* 3794: pointer.struct.evp_pkey_st */
            	1427, 0,
            1, 8, 1, /* 3799: pointer.struct.cert_st */
            	3804, 0,
            0, 296, 7, /* 3804: struct.cert_st */
            	3821, 0,
            	539, 48,
            	3826, 56,
            	56, 64,
            	3829, 72,
            	3832, 80,
            	3837, 88,
            1, 8, 1, /* 3821: pointer.struct.cert_pkey_st */
            	3780, 0,
            8884097, 8, 0, /* 3826: pointer.func */
            8884097, 8, 0, /* 3829: pointer.func */
            1, 8, 1, /* 3832: pointer.struct.ec_key_st */
            	944, 0,
            8884097, 8, 0, /* 3837: pointer.func */
            8884097, 8, 0, /* 3840: pointer.func */
            0, 0, 1, /* 3843: X509_NAME */
            	3848, 0,
            0, 40, 3, /* 3848: struct.X509_name_st */
            	3857, 0,
            	3881, 16,
            	112, 24,
            1, 8, 1, /* 3857: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3862, 0,
            0, 32, 2, /* 3862: struct.stack_st_fake_X509_NAME_ENTRY */
            	3869, 8,
            	152, 24,
            8884099, 8, 2, /* 3869: pointer_to_array_of_pointers_to_stack */
            	3876, 0,
            	1787, 20,
            0, 8, 1, /* 3876: pointer.X509_NAME_ENTRY */
            	2442, 0,
            1, 8, 1, /* 3881: pointer.struct.buf_mem_st */
            	3886, 0,
            0, 24, 1, /* 3886: struct.buf_mem_st */
            	147, 8,
            8884097, 8, 0, /* 3891: pointer.func */
            8884097, 8, 0, /* 3894: pointer.func */
            0, 64, 7, /* 3897: struct.comp_method_st */
            	5, 8,
            	3914, 16,
            	3894, 24,
            	3891, 32,
            	3891, 40,
            	3917, 48,
            	3917, 56,
            8884097, 8, 0, /* 3914: pointer.func */
            8884097, 8, 0, /* 3917: pointer.func */
            1, 8, 1, /* 3920: pointer.struct.comp_method_st */
            	3897, 0,
            1, 8, 1, /* 3925: pointer.struct.stack_st_X509 */
            	3930, 0,
            0, 32, 2, /* 3930: struct.stack_st_fake_X509 */
            	3937, 8,
            	152, 24,
            8884099, 8, 2, /* 3937: pointer_to_array_of_pointers_to_stack */
            	3944, 0,
            	1787, 20,
            0, 8, 1, /* 3944: pointer.X509 */
            	3949, 0,
            0, 0, 1, /* 3949: X509 */
            	3954, 0,
            0, 184, 12, /* 3954: struct.x509_st */
            	3981, 0,
            	4021, 8,
            	4053, 16,
            	147, 32,
            	861, 40,
            	4087, 104,
            	4092, 112,
            	4097, 120,
            	4102, 128,
            	4126, 136,
            	4150, 144,
            	4155, 176,
            1, 8, 1, /* 3981: pointer.struct.x509_cinf_st */
            	3986, 0,
            0, 104, 11, /* 3986: struct.x509_cinf_st */
            	4011, 0,
            	4011, 8,
            	4021, 16,
            	4026, 24,
            	4031, 32,
            	4026, 40,
            	4048, 48,
            	4053, 56,
            	4053, 64,
            	4058, 72,
            	4082, 80,
            1, 8, 1, /* 4011: pointer.struct.asn1_string_st */
            	4016, 0,
            0, 24, 1, /* 4016: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 4021: pointer.struct.X509_algor_st */
            	2031, 0,
            1, 8, 1, /* 4026: pointer.struct.X509_name_st */
            	3848, 0,
            1, 8, 1, /* 4031: pointer.struct.X509_val_st */
            	4036, 0,
            0, 16, 2, /* 4036: struct.X509_val_st */
            	4043, 0,
            	4043, 8,
            1, 8, 1, /* 4043: pointer.struct.asn1_string_st */
            	4016, 0,
            1, 8, 1, /* 4048: pointer.struct.X509_pubkey_st */
            	2275, 0,
            1, 8, 1, /* 4053: pointer.struct.asn1_string_st */
            	4016, 0,
            1, 8, 1, /* 4058: pointer.struct.stack_st_X509_EXTENSION */
            	4063, 0,
            0, 32, 2, /* 4063: struct.stack_st_fake_X509_EXTENSION */
            	4070, 8,
            	152, 24,
            8884099, 8, 2, /* 4070: pointer_to_array_of_pointers_to_stack */
            	4077, 0,
            	1787, 20,
            0, 8, 1, /* 4077: pointer.X509_EXTENSION */
            	2234, 0,
            0, 24, 1, /* 4082: struct.ASN1_ENCODING_st */
            	112, 0,
            1, 8, 1, /* 4087: pointer.struct.asn1_string_st */
            	4016, 0,
            1, 8, 1, /* 4092: pointer.struct.AUTHORITY_KEYID_st */
            	2565, 0,
            1, 8, 1, /* 4097: pointer.struct.X509_POLICY_CACHE_st */
            	2888, 0,
            1, 8, 1, /* 4102: pointer.struct.stack_st_DIST_POINT */
            	4107, 0,
            0, 32, 2, /* 4107: struct.stack_st_fake_DIST_POINT */
            	4114, 8,
            	152, 24,
            8884099, 8, 2, /* 4114: pointer_to_array_of_pointers_to_stack */
            	4121, 0,
            	1787, 20,
            0, 8, 1, /* 4121: pointer.DIST_POINT */
            	3329, 0,
            1, 8, 1, /* 4126: pointer.struct.stack_st_GENERAL_NAME */
            	4131, 0,
            0, 32, 2, /* 4131: struct.stack_st_fake_GENERAL_NAME */
            	4138, 8,
            	152, 24,
            8884099, 8, 2, /* 4138: pointer_to_array_of_pointers_to_stack */
            	4145, 0,
            	1787, 20,
            0, 8, 1, /* 4145: pointer.GENERAL_NAME */
            	2608, 0,
            1, 8, 1, /* 4150: pointer.struct.NAME_CONSTRAINTS_st */
            	3473, 0,
            1, 8, 1, /* 4155: pointer.struct.x509_cert_aux_st */
            	4160, 0,
            0, 40, 5, /* 4160: struct.x509_cert_aux_st */
            	4173, 0,
            	4173, 8,
            	4197, 16,
            	4087, 24,
            	4202, 32,
            1, 8, 1, /* 4173: pointer.struct.stack_st_ASN1_OBJECT */
            	4178, 0,
            0, 32, 2, /* 4178: struct.stack_st_fake_ASN1_OBJECT */
            	4185, 8,
            	152, 24,
            8884099, 8, 2, /* 4185: pointer_to_array_of_pointers_to_stack */
            	4192, 0,
            	1787, 20,
            0, 8, 1, /* 4192: pointer.ASN1_OBJECT */
            	1965, 0,
            1, 8, 1, /* 4197: pointer.struct.asn1_string_st */
            	4016, 0,
            1, 8, 1, /* 4202: pointer.struct.stack_st_X509_ALGOR */
            	4207, 0,
            0, 32, 2, /* 4207: struct.stack_st_fake_X509_ALGOR */
            	4214, 8,
            	152, 24,
            8884099, 8, 2, /* 4214: pointer_to_array_of_pointers_to_stack */
            	4221, 0,
            	1787, 20,
            0, 8, 1, /* 4221: pointer.X509_ALGOR */
            	2026, 0,
            8884097, 8, 0, /* 4226: pointer.func */
            8884097, 8, 0, /* 4229: pointer.func */
            8884097, 8, 0, /* 4232: pointer.func */
            8884097, 8, 0, /* 4235: pointer.func */
            8884097, 8, 0, /* 4238: pointer.func */
            8884097, 8, 0, /* 4241: pointer.func */
            8884097, 8, 0, /* 4244: pointer.func */
            8884097, 8, 0, /* 4247: pointer.func */
            8884097, 8, 0, /* 4250: pointer.func */
            0, 88, 1, /* 4253: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4258: pointer.struct.ssl_cipher_st */
            	4253, 0,
            1, 8, 1, /* 4263: pointer.struct.stack_st_X509_ALGOR */
            	4268, 0,
            0, 32, 2, /* 4268: struct.stack_st_fake_X509_ALGOR */
            	4275, 8,
            	152, 24,
            8884099, 8, 2, /* 4275: pointer_to_array_of_pointers_to_stack */
            	4282, 0,
            	1787, 20,
            0, 8, 1, /* 4282: pointer.X509_ALGOR */
            	2026, 0,
            1, 8, 1, /* 4287: pointer.struct.asn1_string_st */
            	4292, 0,
            0, 24, 1, /* 4292: struct.asn1_string_st */
            	112, 8,
            0, 40, 5, /* 4297: struct.x509_cert_aux_st */
            	4310, 0,
            	4310, 8,
            	4287, 16,
            	4334, 24,
            	4263, 32,
            1, 8, 1, /* 4310: pointer.struct.stack_st_ASN1_OBJECT */
            	4315, 0,
            0, 32, 2, /* 4315: struct.stack_st_fake_ASN1_OBJECT */
            	4322, 8,
            	152, 24,
            8884099, 8, 2, /* 4322: pointer_to_array_of_pointers_to_stack */
            	4329, 0,
            	1787, 20,
            0, 8, 1, /* 4329: pointer.ASN1_OBJECT */
            	1965, 0,
            1, 8, 1, /* 4334: pointer.struct.asn1_string_st */
            	4292, 0,
            1, 8, 1, /* 4339: pointer.struct.x509_cert_aux_st */
            	4297, 0,
            1, 8, 1, /* 4344: pointer.struct.asn1_string_st */
            	4292, 0,
            1, 8, 1, /* 4349: pointer.struct.X509_val_st */
            	4354, 0,
            0, 16, 2, /* 4354: struct.X509_val_st */
            	4344, 0,
            	4344, 8,
            0, 24, 1, /* 4361: struct.buf_mem_st */
            	147, 8,
            0, 40, 3, /* 4366: struct.X509_name_st */
            	4375, 0,
            	4399, 16,
            	112, 24,
            1, 8, 1, /* 4375: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4380, 0,
            0, 32, 2, /* 4380: struct.stack_st_fake_X509_NAME_ENTRY */
            	4387, 8,
            	152, 24,
            8884099, 8, 2, /* 4387: pointer_to_array_of_pointers_to_stack */
            	4394, 0,
            	1787, 20,
            0, 8, 1, /* 4394: pointer.X509_NAME_ENTRY */
            	2442, 0,
            1, 8, 1, /* 4399: pointer.struct.buf_mem_st */
            	4361, 0,
            1, 8, 1, /* 4404: pointer.struct.X509_algor_st */
            	2031, 0,
            1, 8, 1, /* 4409: pointer.struct.asn1_string_st */
            	4292, 0,
            0, 104, 11, /* 4414: struct.x509_cinf_st */
            	4409, 0,
            	4409, 8,
            	4404, 16,
            	4439, 24,
            	4349, 32,
            	4439, 40,
            	4444, 48,
            	4449, 56,
            	4449, 64,
            	4454, 72,
            	4478, 80,
            1, 8, 1, /* 4439: pointer.struct.X509_name_st */
            	4366, 0,
            1, 8, 1, /* 4444: pointer.struct.X509_pubkey_st */
            	2275, 0,
            1, 8, 1, /* 4449: pointer.struct.asn1_string_st */
            	4292, 0,
            1, 8, 1, /* 4454: pointer.struct.stack_st_X509_EXTENSION */
            	4459, 0,
            0, 32, 2, /* 4459: struct.stack_st_fake_X509_EXTENSION */
            	4466, 8,
            	152, 24,
            8884099, 8, 2, /* 4466: pointer_to_array_of_pointers_to_stack */
            	4473, 0,
            	1787, 20,
            0, 8, 1, /* 4473: pointer.X509_EXTENSION */
            	2234, 0,
            0, 24, 1, /* 4478: struct.ASN1_ENCODING_st */
            	112, 0,
            1, 8, 1, /* 4483: pointer.struct.x509_cinf_st */
            	4414, 0,
            1, 8, 1, /* 4488: pointer.struct.x509_st */
            	4493, 0,
            0, 184, 12, /* 4493: struct.x509_st */
            	4483, 0,
            	4404, 8,
            	4449, 16,
            	147, 32,
            	4520, 40,
            	4334, 104,
            	2560, 112,
            	2883, 120,
            	3305, 128,
            	3444, 136,
            	3468, 144,
            	4339, 176,
            0, 16, 1, /* 4520: struct.crypto_ex_data_st */
            	4525, 0,
            1, 8, 1, /* 4525: pointer.struct.stack_st_void */
            	4530, 0,
            0, 32, 1, /* 4530: struct.stack_st_void */
            	4535, 0,
            0, 32, 2, /* 4535: struct.stack_st */
            	142, 8,
            	152, 24,
            1, 8, 1, /* 4542: pointer.struct.rsa_st */
            	544, 0,
            8884097, 8, 0, /* 4547: pointer.func */
            8884097, 8, 0, /* 4550: pointer.func */
            8884097, 8, 0, /* 4553: pointer.func */
            1, 8, 1, /* 4556: pointer.struct.env_md_st */
            	4561, 0,
            0, 120, 8, /* 4561: struct.env_md_st */
            	4580, 24,
            	4553, 32,
            	4583, 40,
            	4550, 48,
            	4580, 56,
            	775, 64,
            	778, 72,
            	4547, 112,
            8884097, 8, 0, /* 4580: pointer.func */
            8884097, 8, 0, /* 4583: pointer.func */
            1, 8, 1, /* 4586: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4591, 0,
            0, 32, 2, /* 4591: struct.stack_st_fake_X509_ATTRIBUTE */
            	4598, 8,
            	152, 24,
            8884099, 8, 2, /* 4598: pointer_to_array_of_pointers_to_stack */
            	4605, 0,
            	1787, 20,
            0, 8, 1, /* 4605: pointer.X509_ATTRIBUTE */
            	1568, 0,
            1, 8, 1, /* 4610: pointer.struct.dh_st */
            	61, 0,
            1, 8, 1, /* 4615: pointer.struct.dsa_st */
            	812, 0,
            0, 8, 5, /* 4620: union.unknown */
            	147, 0,
            	4633, 0,
            	4615, 0,
            	4610, 0,
            	939, 0,
            1, 8, 1, /* 4633: pointer.struct.rsa_st */
            	544, 0,
            0, 56, 4, /* 4638: struct.evp_pkey_st */
            	1438, 16,
            	1539, 24,
            	4620, 32,
            	4586, 48,
            1, 8, 1, /* 4649: pointer.struct.stack_st_X509_ALGOR */
            	4654, 0,
            0, 32, 2, /* 4654: struct.stack_st_fake_X509_ALGOR */
            	4661, 8,
            	152, 24,
            8884099, 8, 2, /* 4661: pointer_to_array_of_pointers_to_stack */
            	4668, 0,
            	1787, 20,
            0, 8, 1, /* 4668: pointer.X509_ALGOR */
            	2026, 0,
            1, 8, 1, /* 4673: pointer.struct.asn1_string_st */
            	4678, 0,
            0, 24, 1, /* 4678: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 4683: pointer.struct.stack_st_ASN1_OBJECT */
            	4688, 0,
            0, 32, 2, /* 4688: struct.stack_st_fake_ASN1_OBJECT */
            	4695, 8,
            	152, 24,
            8884099, 8, 2, /* 4695: pointer_to_array_of_pointers_to_stack */
            	4702, 0,
            	1787, 20,
            0, 8, 1, /* 4702: pointer.ASN1_OBJECT */
            	1965, 0,
            0, 40, 5, /* 4707: struct.x509_cert_aux_st */
            	4683, 0,
            	4683, 8,
            	4673, 16,
            	4720, 24,
            	4649, 32,
            1, 8, 1, /* 4720: pointer.struct.asn1_string_st */
            	4678, 0,
            0, 32, 2, /* 4725: struct.stack_st */
            	142, 8,
            	152, 24,
            0, 32, 1, /* 4732: struct.stack_st_void */
            	4725, 0,
            1, 8, 1, /* 4737: pointer.struct.stack_st_void */
            	4732, 0,
            0, 16, 1, /* 4742: struct.crypto_ex_data_st */
            	4737, 0,
            0, 24, 1, /* 4747: struct.ASN1_ENCODING_st */
            	112, 0,
            1, 8, 1, /* 4752: pointer.struct.stack_st_X509_EXTENSION */
            	4757, 0,
            0, 32, 2, /* 4757: struct.stack_st_fake_X509_EXTENSION */
            	4764, 8,
            	152, 24,
            8884099, 8, 2, /* 4764: pointer_to_array_of_pointers_to_stack */
            	4771, 0,
            	1787, 20,
            0, 8, 1, /* 4771: pointer.X509_EXTENSION */
            	2234, 0,
            1, 8, 1, /* 4776: pointer.struct.asn1_string_st */
            	4678, 0,
            0, 16, 2, /* 4781: struct.X509_val_st */
            	4776, 0,
            	4776, 8,
            1, 8, 1, /* 4788: pointer.struct.X509_val_st */
            	4781, 0,
            0, 24, 1, /* 4793: struct.buf_mem_st */
            	147, 8,
            1, 8, 1, /* 4798: pointer.struct.buf_mem_st */
            	4793, 0,
            1, 8, 1, /* 4803: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4808, 0,
            0, 32, 2, /* 4808: struct.stack_st_fake_X509_NAME_ENTRY */
            	4815, 8,
            	152, 24,
            8884099, 8, 2, /* 4815: pointer_to_array_of_pointers_to_stack */
            	4822, 0,
            	1787, 20,
            0, 8, 1, /* 4822: pointer.X509_NAME_ENTRY */
            	2442, 0,
            1, 8, 1, /* 4827: pointer.struct.X509_algor_st */
            	2031, 0,
            0, 104, 11, /* 4832: struct.x509_cinf_st */
            	4857, 0,
            	4857, 8,
            	4827, 16,
            	4862, 24,
            	4788, 32,
            	4862, 40,
            	4876, 48,
            	4881, 56,
            	4881, 64,
            	4752, 72,
            	4747, 80,
            1, 8, 1, /* 4857: pointer.struct.asn1_string_st */
            	4678, 0,
            1, 8, 1, /* 4862: pointer.struct.X509_name_st */
            	4867, 0,
            0, 40, 3, /* 4867: struct.X509_name_st */
            	4803, 0,
            	4798, 16,
            	112, 24,
            1, 8, 1, /* 4876: pointer.struct.X509_pubkey_st */
            	2275, 0,
            1, 8, 1, /* 4881: pointer.struct.asn1_string_st */
            	4678, 0,
            1, 8, 1, /* 4886: pointer.struct.x509_cinf_st */
            	4832, 0,
            1, 8, 1, /* 4891: pointer.struct.x509_st */
            	4896, 0,
            0, 184, 12, /* 4896: struct.x509_st */
            	4886, 0,
            	4827, 8,
            	4881, 16,
            	147, 32,
            	4742, 40,
            	4720, 104,
            	2560, 112,
            	2883, 120,
            	3305, 128,
            	3444, 136,
            	3468, 144,
            	4923, 176,
            1, 8, 1, /* 4923: pointer.struct.x509_cert_aux_st */
            	4707, 0,
            0, 24, 3, /* 4928: struct.cert_pkey_st */
            	4891, 0,
            	4937, 8,
            	4556, 16,
            1, 8, 1, /* 4937: pointer.struct.evp_pkey_st */
            	4638, 0,
            1, 8, 1, /* 4942: pointer.struct.cert_pkey_st */
            	4928, 0,
            8884097, 8, 0, /* 4947: pointer.func */
            0, 248, 5, /* 4950: struct.sess_cert_st */
            	4963, 0,
            	4942, 16,
            	4542, 216,
            	4987, 224,
            	3832, 232,
            1, 8, 1, /* 4963: pointer.struct.stack_st_X509 */
            	4968, 0,
            0, 32, 2, /* 4968: struct.stack_st_fake_X509 */
            	4975, 8,
            	152, 24,
            8884099, 8, 2, /* 4975: pointer_to_array_of_pointers_to_stack */
            	4982, 0,
            	1787, 20,
            0, 8, 1, /* 4982: pointer.X509 */
            	3949, 0,
            1, 8, 1, /* 4987: pointer.struct.dh_st */
            	61, 0,
            1, 8, 1, /* 4992: pointer.struct.sess_cert_st */
            	4950, 0,
            1, 8, 1, /* 4997: pointer.struct.lhash_node_st */
            	5002, 0,
            0, 24, 2, /* 5002: struct.lhash_node_st */
            	719, 0,
            	4997, 8,
            1, 8, 1, /* 5009: pointer.struct.lhash_st */
            	5014, 0,
            0, 176, 3, /* 5014: struct.lhash_st */
            	5023, 0,
            	152, 8,
            	5030, 16,
            8884099, 8, 2, /* 5023: pointer_to_array_of_pointers_to_stack */
            	4997, 0,
            	20, 28,
            8884097, 8, 0, /* 5030: pointer.func */
            8884097, 8, 0, /* 5033: pointer.func */
            8884097, 8, 0, /* 5036: pointer.func */
            8884097, 8, 0, /* 5039: pointer.func */
            8884097, 8, 0, /* 5042: pointer.func */
            8884097, 8, 0, /* 5045: pointer.func */
            1, 8, 1, /* 5048: pointer.struct.X509_VERIFY_PARAM_st */
            	5053, 0,
            0, 56, 2, /* 5053: struct.X509_VERIFY_PARAM_st */
            	147, 0,
            	4310, 48,
            8884097, 8, 0, /* 5060: pointer.func */
            8884097, 8, 0, /* 5063: pointer.func */
            8884097, 8, 0, /* 5066: pointer.func */
            8884097, 8, 0, /* 5069: pointer.func */
            8884097, 8, 0, /* 5072: pointer.func */
            1, 8, 1, /* 5075: pointer.struct.X509_VERIFY_PARAM_st */
            	5080, 0,
            0, 56, 2, /* 5080: struct.X509_VERIFY_PARAM_st */
            	147, 0,
            	5087, 48,
            1, 8, 1, /* 5087: pointer.struct.stack_st_ASN1_OBJECT */
            	5092, 0,
            0, 32, 2, /* 5092: struct.stack_st_fake_ASN1_OBJECT */
            	5099, 8,
            	152, 24,
            8884099, 8, 2, /* 5099: pointer_to_array_of_pointers_to_stack */
            	5106, 0,
            	1787, 20,
            0, 8, 1, /* 5106: pointer.ASN1_OBJECT */
            	1965, 0,
            1, 8, 1, /* 5111: pointer.struct.stack_st_X509_LOOKUP */
            	5116, 0,
            0, 32, 2, /* 5116: struct.stack_st_fake_X509_LOOKUP */
            	5123, 8,
            	152, 24,
            8884099, 8, 2, /* 5123: pointer_to_array_of_pointers_to_stack */
            	5130, 0,
            	1787, 20,
            0, 8, 1, /* 5130: pointer.X509_LOOKUP */
            	5135, 0,
            0, 0, 1, /* 5135: X509_LOOKUP */
            	5140, 0,
            0, 32, 3, /* 5140: struct.x509_lookup_st */
            	5149, 8,
            	147, 16,
            	5198, 24,
            1, 8, 1, /* 5149: pointer.struct.x509_lookup_method_st */
            	5154, 0,
            0, 80, 10, /* 5154: struct.x509_lookup_method_st */
            	5, 0,
            	5177, 8,
            	5180, 16,
            	5177, 24,
            	5177, 32,
            	5183, 40,
            	5186, 48,
            	5189, 56,
            	5192, 64,
            	5195, 72,
            8884097, 8, 0, /* 5177: pointer.func */
            8884097, 8, 0, /* 5180: pointer.func */
            8884097, 8, 0, /* 5183: pointer.func */
            8884097, 8, 0, /* 5186: pointer.func */
            8884097, 8, 0, /* 5189: pointer.func */
            8884097, 8, 0, /* 5192: pointer.func */
            8884097, 8, 0, /* 5195: pointer.func */
            1, 8, 1, /* 5198: pointer.struct.x509_store_st */
            	5203, 0,
            0, 144, 15, /* 5203: struct.x509_store_st */
            	5236, 8,
            	5111, 16,
            	5075, 24,
            	5072, 32,
            	5886, 40,
            	5889, 48,
            	5069, 56,
            	5072, 64,
            	5892, 72,
            	5066, 80,
            	5895, 88,
            	5063, 96,
            	5060, 104,
            	5072, 112,
            	5462, 120,
            1, 8, 1, /* 5236: pointer.struct.stack_st_X509_OBJECT */
            	5241, 0,
            0, 32, 2, /* 5241: struct.stack_st_fake_X509_OBJECT */
            	5248, 8,
            	152, 24,
            8884099, 8, 2, /* 5248: pointer_to_array_of_pointers_to_stack */
            	5255, 0,
            	1787, 20,
            0, 8, 1, /* 5255: pointer.X509_OBJECT */
            	5260, 0,
            0, 0, 1, /* 5260: X509_OBJECT */
            	5265, 0,
            0, 16, 1, /* 5265: struct.x509_object_st */
            	5270, 8,
            0, 8, 4, /* 5270: union.unknown */
            	147, 0,
            	5281, 0,
            	5599, 0,
            	5808, 0,
            1, 8, 1, /* 5281: pointer.struct.x509_st */
            	5286, 0,
            0, 184, 12, /* 5286: struct.x509_st */
            	5313, 0,
            	5353, 8,
            	5428, 16,
            	147, 32,
            	5462, 40,
            	5484, 104,
            	5489, 112,
            	5494, 120,
            	5499, 128,
            	5523, 136,
            	5547, 144,
            	5552, 176,
            1, 8, 1, /* 5313: pointer.struct.x509_cinf_st */
            	5318, 0,
            0, 104, 11, /* 5318: struct.x509_cinf_st */
            	5343, 0,
            	5343, 8,
            	5353, 16,
            	5358, 24,
            	5406, 32,
            	5358, 40,
            	5423, 48,
            	5428, 56,
            	5428, 64,
            	5433, 72,
            	5457, 80,
            1, 8, 1, /* 5343: pointer.struct.asn1_string_st */
            	5348, 0,
            0, 24, 1, /* 5348: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 5353: pointer.struct.X509_algor_st */
            	2031, 0,
            1, 8, 1, /* 5358: pointer.struct.X509_name_st */
            	5363, 0,
            0, 40, 3, /* 5363: struct.X509_name_st */
            	5372, 0,
            	5396, 16,
            	112, 24,
            1, 8, 1, /* 5372: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5377, 0,
            0, 32, 2, /* 5377: struct.stack_st_fake_X509_NAME_ENTRY */
            	5384, 8,
            	152, 24,
            8884099, 8, 2, /* 5384: pointer_to_array_of_pointers_to_stack */
            	5391, 0,
            	1787, 20,
            0, 8, 1, /* 5391: pointer.X509_NAME_ENTRY */
            	2442, 0,
            1, 8, 1, /* 5396: pointer.struct.buf_mem_st */
            	5401, 0,
            0, 24, 1, /* 5401: struct.buf_mem_st */
            	147, 8,
            1, 8, 1, /* 5406: pointer.struct.X509_val_st */
            	5411, 0,
            0, 16, 2, /* 5411: struct.X509_val_st */
            	5418, 0,
            	5418, 8,
            1, 8, 1, /* 5418: pointer.struct.asn1_string_st */
            	5348, 0,
            1, 8, 1, /* 5423: pointer.struct.X509_pubkey_st */
            	2275, 0,
            1, 8, 1, /* 5428: pointer.struct.asn1_string_st */
            	5348, 0,
            1, 8, 1, /* 5433: pointer.struct.stack_st_X509_EXTENSION */
            	5438, 0,
            0, 32, 2, /* 5438: struct.stack_st_fake_X509_EXTENSION */
            	5445, 8,
            	152, 24,
            8884099, 8, 2, /* 5445: pointer_to_array_of_pointers_to_stack */
            	5452, 0,
            	1787, 20,
            0, 8, 1, /* 5452: pointer.X509_EXTENSION */
            	2234, 0,
            0, 24, 1, /* 5457: struct.ASN1_ENCODING_st */
            	112, 0,
            0, 16, 1, /* 5462: struct.crypto_ex_data_st */
            	5467, 0,
            1, 8, 1, /* 5467: pointer.struct.stack_st_void */
            	5472, 0,
            0, 32, 1, /* 5472: struct.stack_st_void */
            	5477, 0,
            0, 32, 2, /* 5477: struct.stack_st */
            	142, 8,
            	152, 24,
            1, 8, 1, /* 5484: pointer.struct.asn1_string_st */
            	5348, 0,
            1, 8, 1, /* 5489: pointer.struct.AUTHORITY_KEYID_st */
            	2565, 0,
            1, 8, 1, /* 5494: pointer.struct.X509_POLICY_CACHE_st */
            	2888, 0,
            1, 8, 1, /* 5499: pointer.struct.stack_st_DIST_POINT */
            	5504, 0,
            0, 32, 2, /* 5504: struct.stack_st_fake_DIST_POINT */
            	5511, 8,
            	152, 24,
            8884099, 8, 2, /* 5511: pointer_to_array_of_pointers_to_stack */
            	5518, 0,
            	1787, 20,
            0, 8, 1, /* 5518: pointer.DIST_POINT */
            	3329, 0,
            1, 8, 1, /* 5523: pointer.struct.stack_st_GENERAL_NAME */
            	5528, 0,
            0, 32, 2, /* 5528: struct.stack_st_fake_GENERAL_NAME */
            	5535, 8,
            	152, 24,
            8884099, 8, 2, /* 5535: pointer_to_array_of_pointers_to_stack */
            	5542, 0,
            	1787, 20,
            0, 8, 1, /* 5542: pointer.GENERAL_NAME */
            	2608, 0,
            1, 8, 1, /* 5547: pointer.struct.NAME_CONSTRAINTS_st */
            	3473, 0,
            1, 8, 1, /* 5552: pointer.struct.x509_cert_aux_st */
            	5557, 0,
            0, 40, 5, /* 5557: struct.x509_cert_aux_st */
            	5087, 0,
            	5087, 8,
            	5570, 16,
            	5484, 24,
            	5575, 32,
            1, 8, 1, /* 5570: pointer.struct.asn1_string_st */
            	5348, 0,
            1, 8, 1, /* 5575: pointer.struct.stack_st_X509_ALGOR */
            	5580, 0,
            0, 32, 2, /* 5580: struct.stack_st_fake_X509_ALGOR */
            	5587, 8,
            	152, 24,
            8884099, 8, 2, /* 5587: pointer_to_array_of_pointers_to_stack */
            	5594, 0,
            	1787, 20,
            0, 8, 1, /* 5594: pointer.X509_ALGOR */
            	2026, 0,
            1, 8, 1, /* 5599: pointer.struct.X509_crl_st */
            	5604, 0,
            0, 120, 10, /* 5604: struct.X509_crl_st */
            	5627, 0,
            	5353, 8,
            	5428, 16,
            	5489, 32,
            	5730, 40,
            	5343, 56,
            	5343, 64,
            	5742, 96,
            	5783, 104,
            	719, 112,
            1, 8, 1, /* 5627: pointer.struct.X509_crl_info_st */
            	5632, 0,
            0, 80, 8, /* 5632: struct.X509_crl_info_st */
            	5343, 0,
            	5353, 8,
            	5358, 16,
            	5418, 24,
            	5418, 32,
            	5651, 40,
            	5433, 48,
            	5457, 56,
            1, 8, 1, /* 5651: pointer.struct.stack_st_X509_REVOKED */
            	5656, 0,
            0, 32, 2, /* 5656: struct.stack_st_fake_X509_REVOKED */
            	5663, 8,
            	152, 24,
            8884099, 8, 2, /* 5663: pointer_to_array_of_pointers_to_stack */
            	5670, 0,
            	1787, 20,
            0, 8, 1, /* 5670: pointer.X509_REVOKED */
            	5675, 0,
            0, 0, 1, /* 5675: X509_REVOKED */
            	5680, 0,
            0, 40, 4, /* 5680: struct.x509_revoked_st */
            	5691, 0,
            	5701, 8,
            	5706, 16,
            	4126, 24,
            1, 8, 1, /* 5691: pointer.struct.asn1_string_st */
            	5696, 0,
            0, 24, 1, /* 5696: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 5701: pointer.struct.asn1_string_st */
            	5696, 0,
            1, 8, 1, /* 5706: pointer.struct.stack_st_X509_EXTENSION */
            	5711, 0,
            0, 32, 2, /* 5711: struct.stack_st_fake_X509_EXTENSION */
            	5718, 8,
            	152, 24,
            8884099, 8, 2, /* 5718: pointer_to_array_of_pointers_to_stack */
            	5725, 0,
            	1787, 20,
            0, 8, 1, /* 5725: pointer.X509_EXTENSION */
            	2234, 0,
            1, 8, 1, /* 5730: pointer.struct.ISSUING_DIST_POINT_st */
            	5735, 0,
            0, 32, 2, /* 5735: struct.ISSUING_DIST_POINT_st */
            	3343, 0,
            	3434, 16,
            1, 8, 1, /* 5742: pointer.struct.stack_st_GENERAL_NAMES */
            	5747, 0,
            0, 32, 2, /* 5747: struct.stack_st_fake_GENERAL_NAMES */
            	5754, 8,
            	152, 24,
            8884099, 8, 2, /* 5754: pointer_to_array_of_pointers_to_stack */
            	5761, 0,
            	1787, 20,
            0, 8, 1, /* 5761: pointer.GENERAL_NAMES */
            	5766, 0,
            0, 0, 1, /* 5766: GENERAL_NAMES */
            	5771, 0,
            0, 32, 1, /* 5771: struct.stack_st_GENERAL_NAME */
            	5776, 0,
            0, 32, 2, /* 5776: struct.stack_st */
            	142, 8,
            	152, 24,
            1, 8, 1, /* 5783: pointer.struct.x509_crl_method_st */
            	5788, 0,
            0, 40, 4, /* 5788: struct.x509_crl_method_st */
            	5799, 8,
            	5799, 16,
            	5802, 24,
            	5805, 32,
            8884097, 8, 0, /* 5799: pointer.func */
            8884097, 8, 0, /* 5802: pointer.func */
            8884097, 8, 0, /* 5805: pointer.func */
            1, 8, 1, /* 5808: pointer.struct.evp_pkey_st */
            	5813, 0,
            0, 56, 4, /* 5813: struct.evp_pkey_st */
            	5824, 16,
            	191, 24,
            	5829, 32,
            	5862, 48,
            1, 8, 1, /* 5824: pointer.struct.evp_pkey_asn1_method_st */
            	1443, 0,
            0, 8, 5, /* 5829: union.unknown */
            	147, 0,
            	5842, 0,
            	5847, 0,
            	5852, 0,
            	5857, 0,
            1, 8, 1, /* 5842: pointer.struct.rsa_st */
            	544, 0,
            1, 8, 1, /* 5847: pointer.struct.dsa_st */
            	812, 0,
            1, 8, 1, /* 5852: pointer.struct.dh_st */
            	61, 0,
            1, 8, 1, /* 5857: pointer.struct.ec_key_st */
            	944, 0,
            1, 8, 1, /* 5862: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5867, 0,
            0, 32, 2, /* 5867: struct.stack_st_fake_X509_ATTRIBUTE */
            	5874, 8,
            	152, 24,
            8884099, 8, 2, /* 5874: pointer_to_array_of_pointers_to_stack */
            	5881, 0,
            	1787, 20,
            0, 8, 1, /* 5881: pointer.X509_ATTRIBUTE */
            	1568, 0,
            8884097, 8, 0, /* 5886: pointer.func */
            8884097, 8, 0, /* 5889: pointer.func */
            8884097, 8, 0, /* 5892: pointer.func */
            8884097, 8, 0, /* 5895: pointer.func */
            1, 8, 1, /* 5898: pointer.struct.stack_st_X509_LOOKUP */
            	5903, 0,
            0, 32, 2, /* 5903: struct.stack_st_fake_X509_LOOKUP */
            	5910, 8,
            	152, 24,
            8884099, 8, 2, /* 5910: pointer_to_array_of_pointers_to_stack */
            	5917, 0,
            	1787, 20,
            0, 8, 1, /* 5917: pointer.X509_LOOKUP */
            	5135, 0,
            0, 120, 8, /* 5922: struct.env_md_st */
            	4235, 24,
            	4232, 32,
            	4229, 40,
            	5941, 48,
            	4235, 56,
            	775, 64,
            	778, 72,
            	4226, 112,
            8884097, 8, 0, /* 5941: pointer.func */
            0, 24, 2, /* 5944: struct.ssl_comp_st */
            	5, 8,
            	3920, 16,
            1, 8, 1, /* 5951: pointer.struct.ssl_method_st */
            	5956, 0,
            0, 232, 28, /* 5956: struct.ssl_method_st */
            	6015, 8,
            	6018, 16,
            	6018, 24,
            	6015, 32,
            	6015, 40,
            	6021, 48,
            	6021, 56,
            	6024, 64,
            	6015, 72,
            	6015, 80,
            	6015, 88,
            	6027, 96,
            	6030, 104,
            	6033, 112,
            	6015, 120,
            	6036, 128,
            	6039, 136,
            	6042, 144,
            	6045, 152,
            	6048, 160,
            	465, 168,
            	6051, 176,
            	6054, 184,
            	3917, 192,
            	6057, 200,
            	465, 208,
            	6111, 216,
            	6114, 224,
            8884097, 8, 0, /* 6015: pointer.func */
            8884097, 8, 0, /* 6018: pointer.func */
            8884097, 8, 0, /* 6021: pointer.func */
            8884097, 8, 0, /* 6024: pointer.func */
            8884097, 8, 0, /* 6027: pointer.func */
            8884097, 8, 0, /* 6030: pointer.func */
            8884097, 8, 0, /* 6033: pointer.func */
            8884097, 8, 0, /* 6036: pointer.func */
            8884097, 8, 0, /* 6039: pointer.func */
            8884097, 8, 0, /* 6042: pointer.func */
            8884097, 8, 0, /* 6045: pointer.func */
            8884097, 8, 0, /* 6048: pointer.func */
            8884097, 8, 0, /* 6051: pointer.func */
            8884097, 8, 0, /* 6054: pointer.func */
            1, 8, 1, /* 6057: pointer.struct.ssl3_enc_method */
            	6062, 0,
            0, 112, 11, /* 6062: struct.ssl3_enc_method */
            	6087, 0,
            	6090, 8,
            	6093, 16,
            	6096, 24,
            	6087, 32,
            	6099, 40,
            	6102, 56,
            	5, 64,
            	5, 80,
            	6105, 96,
            	6108, 104,
            8884097, 8, 0, /* 6087: pointer.func */
            8884097, 8, 0, /* 6090: pointer.func */
            8884097, 8, 0, /* 6093: pointer.func */
            8884097, 8, 0, /* 6096: pointer.func */
            8884097, 8, 0, /* 6099: pointer.func */
            8884097, 8, 0, /* 6102: pointer.func */
            8884097, 8, 0, /* 6105: pointer.func */
            8884097, 8, 0, /* 6108: pointer.func */
            8884097, 8, 0, /* 6111: pointer.func */
            8884097, 8, 0, /* 6114: pointer.func */
            8884097, 8, 0, /* 6117: pointer.func */
            0, 0, 1, /* 6120: SRTP_PROTECTION_PROFILE */
            	0, 0,
            0, 144, 15, /* 6125: struct.x509_store_st */
            	6158, 8,
            	5898, 16,
            	5048, 24,
            	5045, 32,
            	6182, 40,
            	5042, 48,
            	6185, 56,
            	5045, 64,
            	5039, 72,
            	5036, 80,
            	6188, 88,
            	6191, 96,
            	5033, 104,
            	5045, 112,
            	4520, 120,
            1, 8, 1, /* 6158: pointer.struct.stack_st_X509_OBJECT */
            	6163, 0,
            0, 32, 2, /* 6163: struct.stack_st_fake_X509_OBJECT */
            	6170, 8,
            	152, 24,
            8884099, 8, 2, /* 6170: pointer_to_array_of_pointers_to_stack */
            	6177, 0,
            	1787, 20,
            0, 8, 1, /* 6177: pointer.X509_OBJECT */
            	5260, 0,
            8884097, 8, 0, /* 6182: pointer.func */
            8884097, 8, 0, /* 6185: pointer.func */
            8884097, 8, 0, /* 6188: pointer.func */
            8884097, 8, 0, /* 6191: pointer.func */
            0, 88, 1, /* 6194: struct.ssl_cipher_st */
            	5, 8,
            8884097, 8, 0, /* 6199: pointer.func */
            8884097, 8, 0, /* 6202: pointer.func */
            1, 8, 1, /* 6205: pointer.struct.ssl_session_st */
            	6210, 0,
            0, 352, 14, /* 6210: struct.ssl_session_st */
            	147, 144,
            	147, 152,
            	4992, 168,
            	4488, 176,
            	4258, 224,
            	6241, 240,
            	4520, 248,
            	6205, 264,
            	6205, 272,
            	147, 280,
            	112, 296,
            	112, 312,
            	112, 320,
            	147, 344,
            1, 8, 1, /* 6241: pointer.struct.stack_st_SSL_CIPHER */
            	6246, 0,
            0, 32, 2, /* 6246: struct.stack_st_fake_SSL_CIPHER */
            	6253, 8,
            	152, 24,
            8884099, 8, 2, /* 6253: pointer_to_array_of_pointers_to_stack */
            	6260, 0,
            	1787, 20,
            0, 8, 1, /* 6260: pointer.SSL_CIPHER */
            	6265, 0,
            0, 0, 1, /* 6265: SSL_CIPHER */
            	6194, 0,
            1, 8, 1, /* 6270: pointer.struct.x509_store_st */
            	6125, 0,
            0, 1, 0, /* 6275: char */
            8884097, 8, 0, /* 6278: pointer.func */
            1, 8, 1, /* 6281: pointer.struct.ssl_ctx_st */
            	6286, 0,
            0, 736, 50, /* 6286: struct.ssl_ctx_st */
            	5951, 0,
            	6241, 8,
            	6241, 16,
            	6270, 24,
            	5009, 32,
            	6205, 48,
            	6205, 56,
            	6202, 80,
            	4250, 88,
            	4247, 96,
            	4244, 152,
            	719, 160,
            	4241, 168,
            	719, 176,
            	4238, 184,
            	6389, 192,
            	6392, 200,
            	4520, 208,
            	6395, 224,
            	6395, 232,
            	6395, 240,
            	3925, 248,
            	6400, 256,
            	3840, 264,
            	6429, 272,
            	3799, 304,
            	53, 320,
            	719, 328,
            	6182, 376,
            	6278, 384,
            	5048, 392,
            	1539, 408,
            	47, 416,
            	719, 424,
            	44, 480,
            	6117, 488,
            	719, 496,
            	6453, 504,
            	719, 512,
            	147, 520,
            	6199, 528,
            	41, 536,
            	6456, 552,
            	6456, 560,
            	6461, 568,
            	4947, 696,
            	719, 704,
            	50, 712,
            	719, 720,
            	6497, 728,
            8884097, 8, 0, /* 6389: pointer.func */
            8884097, 8, 0, /* 6392: pointer.func */
            1, 8, 1, /* 6395: pointer.struct.env_md_st */
            	5922, 0,
            1, 8, 1, /* 6400: pointer.struct.stack_st_SSL_COMP */
            	6405, 0,
            0, 32, 2, /* 6405: struct.stack_st_fake_SSL_COMP */
            	6412, 8,
            	152, 24,
            8884099, 8, 2, /* 6412: pointer_to_array_of_pointers_to_stack */
            	6419, 0,
            	1787, 20,
            0, 8, 1, /* 6419: pointer.SSL_COMP */
            	6424, 0,
            0, 0, 1, /* 6424: SSL_COMP */
            	5944, 0,
            1, 8, 1, /* 6429: pointer.struct.stack_st_X509_NAME */
            	6434, 0,
            0, 32, 2, /* 6434: struct.stack_st_fake_X509_NAME */
            	6441, 8,
            	152, 24,
            8884099, 8, 2, /* 6441: pointer_to_array_of_pointers_to_stack */
            	6448, 0,
            	1787, 20,
            0, 8, 1, /* 6448: pointer.X509_NAME */
            	3843, 0,
            8884097, 8, 0, /* 6453: pointer.func */
            1, 8, 1, /* 6456: pointer.struct.ssl3_buf_freelist_st */
            	36, 0,
            0, 128, 14, /* 6461: struct.srp_ctx_st */
            	719, 0,
            	47, 8,
            	6117, 16,
            	23, 24,
            	147, 32,
            	6492, 40,
            	6492, 48,
            	6492, 56,
            	6492, 64,
            	6492, 72,
            	6492, 80,
            	6492, 88,
            	6492, 96,
            	147, 104,
            1, 8, 1, /* 6492: pointer.struct.bignum_st */
            	10, 0,
            1, 8, 1, /* 6497: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6502, 0,
            0, 32, 2, /* 6502: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6509, 8,
            	152, 24,
            8884099, 8, 2, /* 6509: pointer_to_array_of_pointers_to_stack */
            	6516, 0,
            	1787, 20,
            0, 8, 1, /* 6516: pointer.SRTP_PROTECTION_PROFILE */
            	6120, 0,
        },
        .arg_entity_index = { 6281, 5, },
        .ret_entity_index = 1787,
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

