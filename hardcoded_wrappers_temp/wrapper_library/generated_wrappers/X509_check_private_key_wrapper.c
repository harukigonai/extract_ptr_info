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

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b);

int X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_check_private_key called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_check_private_key(arg_a,arg_b);
    else {
        int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
        orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
        return orig_X509_check_private_key(arg_a,arg_b);
    }
}

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.ec_key_st */
            	5, 0,
            0, 56, 4, /* 5: struct.ec_key_st */
            	16, 8,
            	469, 16,
            	474, 24,
            	484, 48,
            1, 8, 1, /* 16: pointer.struct.ec_group_st */
            	21, 0,
            0, 232, 12, /* 21: struct.ec_group_st */
            	48, 0,
            	220, 8,
            	421, 16,
            	421, 40,
            	426, 80,
            	434, 96,
            	421, 104,
            	421, 152,
            	421, 176,
            	457, 208,
            	457, 216,
            	466, 224,
            1, 8, 1, /* 48: pointer.struct.ec_method_st */
            	53, 0,
            0, 304, 37, /* 53: struct.ec_method_st */
            	130, 8,
            	133, 16,
            	133, 24,
            	136, 32,
            	139, 40,
            	142, 48,
            	145, 56,
            	148, 64,
            	151, 72,
            	154, 80,
            	154, 88,
            	157, 96,
            	160, 104,
            	163, 112,
            	166, 120,
            	169, 128,
            	172, 136,
            	175, 144,
            	178, 152,
            	181, 160,
            	184, 168,
            	187, 176,
            	190, 184,
            	193, 192,
            	196, 200,
            	199, 208,
            	190, 216,
            	202, 224,
            	205, 232,
            	208, 240,
            	145, 248,
            	211, 256,
            	214, 264,
            	211, 272,
            	214, 280,
            	214, 288,
            	217, 296,
            8884097, 8, 0, /* 130: pointer.func */
            8884097, 8, 0, /* 133: pointer.func */
            8884097, 8, 0, /* 136: pointer.func */
            8884097, 8, 0, /* 139: pointer.func */
            8884097, 8, 0, /* 142: pointer.func */
            8884097, 8, 0, /* 145: pointer.func */
            8884097, 8, 0, /* 148: pointer.func */
            8884097, 8, 0, /* 151: pointer.func */
            8884097, 8, 0, /* 154: pointer.func */
            8884097, 8, 0, /* 157: pointer.func */
            8884097, 8, 0, /* 160: pointer.func */
            8884097, 8, 0, /* 163: pointer.func */
            8884097, 8, 0, /* 166: pointer.func */
            8884097, 8, 0, /* 169: pointer.func */
            8884097, 8, 0, /* 172: pointer.func */
            8884097, 8, 0, /* 175: pointer.func */
            8884097, 8, 0, /* 178: pointer.func */
            8884097, 8, 0, /* 181: pointer.func */
            8884097, 8, 0, /* 184: pointer.func */
            8884097, 8, 0, /* 187: pointer.func */
            8884097, 8, 0, /* 190: pointer.func */
            8884097, 8, 0, /* 193: pointer.func */
            8884097, 8, 0, /* 196: pointer.func */
            8884097, 8, 0, /* 199: pointer.func */
            8884097, 8, 0, /* 202: pointer.func */
            8884097, 8, 0, /* 205: pointer.func */
            8884097, 8, 0, /* 208: pointer.func */
            8884097, 8, 0, /* 211: pointer.func */
            8884097, 8, 0, /* 214: pointer.func */
            8884097, 8, 0, /* 217: pointer.func */
            1, 8, 1, /* 220: pointer.struct.ec_point_st */
            	225, 0,
            0, 88, 4, /* 225: struct.ec_point_st */
            	236, 0,
            	408, 8,
            	408, 32,
            	408, 56,
            1, 8, 1, /* 236: pointer.struct.ec_method_st */
            	241, 0,
            0, 304, 37, /* 241: struct.ec_method_st */
            	318, 8,
            	321, 16,
            	321, 24,
            	324, 32,
            	327, 40,
            	330, 48,
            	333, 56,
            	336, 64,
            	339, 72,
            	342, 80,
            	342, 88,
            	345, 96,
            	348, 104,
            	351, 112,
            	354, 120,
            	357, 128,
            	360, 136,
            	363, 144,
            	366, 152,
            	369, 160,
            	372, 168,
            	375, 176,
            	378, 184,
            	381, 192,
            	384, 200,
            	387, 208,
            	378, 216,
            	390, 224,
            	393, 232,
            	396, 240,
            	333, 248,
            	399, 256,
            	402, 264,
            	399, 272,
            	402, 280,
            	402, 288,
            	405, 296,
            8884097, 8, 0, /* 318: pointer.func */
            8884097, 8, 0, /* 321: pointer.func */
            8884097, 8, 0, /* 324: pointer.func */
            8884097, 8, 0, /* 327: pointer.func */
            8884097, 8, 0, /* 330: pointer.func */
            8884097, 8, 0, /* 333: pointer.func */
            8884097, 8, 0, /* 336: pointer.func */
            8884097, 8, 0, /* 339: pointer.func */
            8884097, 8, 0, /* 342: pointer.func */
            8884097, 8, 0, /* 345: pointer.func */
            8884097, 8, 0, /* 348: pointer.func */
            8884097, 8, 0, /* 351: pointer.func */
            8884097, 8, 0, /* 354: pointer.func */
            8884097, 8, 0, /* 357: pointer.func */
            8884097, 8, 0, /* 360: pointer.func */
            8884097, 8, 0, /* 363: pointer.func */
            8884097, 8, 0, /* 366: pointer.func */
            8884097, 8, 0, /* 369: pointer.func */
            8884097, 8, 0, /* 372: pointer.func */
            8884097, 8, 0, /* 375: pointer.func */
            8884097, 8, 0, /* 378: pointer.func */
            8884097, 8, 0, /* 381: pointer.func */
            8884097, 8, 0, /* 384: pointer.func */
            8884097, 8, 0, /* 387: pointer.func */
            8884097, 8, 0, /* 390: pointer.func */
            8884097, 8, 0, /* 393: pointer.func */
            8884097, 8, 0, /* 396: pointer.func */
            8884097, 8, 0, /* 399: pointer.func */
            8884097, 8, 0, /* 402: pointer.func */
            8884097, 8, 0, /* 405: pointer.func */
            0, 24, 1, /* 408: struct.bignum_st */
            	413, 0,
            1, 8, 1, /* 413: pointer.unsigned int */
            	418, 0,
            0, 4, 0, /* 418: unsigned int */
            0, 24, 1, /* 421: struct.bignum_st */
            	413, 0,
            1, 8, 1, /* 426: pointer.unsigned char */
            	431, 0,
            0, 1, 0, /* 431: unsigned char */
            1, 8, 1, /* 434: pointer.struct.ec_extra_data_st */
            	439, 0,
            0, 40, 5, /* 439: struct.ec_extra_data_st */
            	452, 0,
            	457, 8,
            	460, 16,
            	463, 24,
            	463, 32,
            1, 8, 1, /* 452: pointer.struct.ec_extra_data_st */
            	439, 0,
            0, 8, 0, /* 457: pointer.void */
            8884097, 8, 0, /* 460: pointer.func */
            8884097, 8, 0, /* 463: pointer.func */
            8884097, 8, 0, /* 466: pointer.func */
            1, 8, 1, /* 469: pointer.struct.ec_point_st */
            	225, 0,
            1, 8, 1, /* 474: pointer.struct.bignum_st */
            	479, 0,
            0, 24, 1, /* 479: struct.bignum_st */
            	413, 0,
            1, 8, 1, /* 484: pointer.struct.ec_extra_data_st */
            	489, 0,
            0, 40, 5, /* 489: struct.ec_extra_data_st */
            	502, 0,
            	457, 8,
            	460, 16,
            	463, 24,
            	463, 32,
            1, 8, 1, /* 502: pointer.struct.ec_extra_data_st */
            	489, 0,
            1, 8, 1, /* 507: pointer.struct.dh_st */
            	512, 0,
            0, 144, 12, /* 512: struct.dh_st */
            	539, 8,
            	539, 16,
            	539, 32,
            	539, 40,
            	549, 56,
            	539, 64,
            	539, 72,
            	426, 80,
            	539, 96,
            	563, 112,
            	598, 128,
            	639, 136,
            1, 8, 1, /* 539: pointer.struct.bignum_st */
            	544, 0,
            0, 24, 1, /* 544: struct.bignum_st */
            	413, 0,
            1, 8, 1, /* 549: pointer.struct.bn_mont_ctx_st */
            	554, 0,
            0, 96, 3, /* 554: struct.bn_mont_ctx_st */
            	544, 8,
            	544, 32,
            	544, 56,
            0, 16, 1, /* 563: struct.crypto_ex_data_st */
            	568, 0,
            1, 8, 1, /* 568: pointer.struct.stack_st_void */
            	573, 0,
            0, 32, 1, /* 573: struct.stack_st_void */
            	578, 0,
            0, 32, 2, /* 578: struct.stack_st */
            	585, 8,
            	595, 24,
            1, 8, 1, /* 585: pointer.pointer.char */
            	590, 0,
            1, 8, 1, /* 590: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 595: pointer.func */
            1, 8, 1, /* 598: pointer.struct.dh_method */
            	603, 0,
            0, 72, 8, /* 603: struct.dh_method */
            	622, 0,
            	627, 8,
            	630, 16,
            	633, 24,
            	627, 32,
            	627, 40,
            	590, 56,
            	636, 64,
            1, 8, 1, /* 622: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 627: pointer.func */
            8884097, 8, 0, /* 630: pointer.func */
            8884097, 8, 0, /* 633: pointer.func */
            8884097, 8, 0, /* 636: pointer.func */
            1, 8, 1, /* 639: pointer.struct.engine_st */
            	644, 0,
            0, 216, 24, /* 644: struct.engine_st */
            	622, 0,
            	622, 8,
            	695, 16,
            	750, 24,
            	801, 32,
            	837, 40,
            	854, 48,
            	881, 56,
            	916, 64,
            	924, 72,
            	927, 80,
            	930, 88,
            	933, 96,
            	936, 104,
            	936, 112,
            	936, 120,
            	939, 128,
            	942, 136,
            	942, 144,
            	945, 152,
            	948, 160,
            	960, 184,
            	982, 200,
            	982, 208,
            1, 8, 1, /* 695: pointer.struct.rsa_meth_st */
            	700, 0,
            0, 112, 13, /* 700: struct.rsa_meth_st */
            	622, 0,
            	729, 8,
            	729, 16,
            	729, 24,
            	729, 32,
            	732, 40,
            	735, 48,
            	738, 56,
            	738, 64,
            	590, 80,
            	741, 88,
            	744, 96,
            	747, 104,
            8884097, 8, 0, /* 729: pointer.func */
            8884097, 8, 0, /* 732: pointer.func */
            8884097, 8, 0, /* 735: pointer.func */
            8884097, 8, 0, /* 738: pointer.func */
            8884097, 8, 0, /* 741: pointer.func */
            8884097, 8, 0, /* 744: pointer.func */
            8884097, 8, 0, /* 747: pointer.func */
            1, 8, 1, /* 750: pointer.struct.dsa_method */
            	755, 0,
            0, 96, 11, /* 755: struct.dsa_method */
            	622, 0,
            	780, 8,
            	783, 16,
            	786, 24,
            	789, 32,
            	792, 40,
            	795, 48,
            	795, 56,
            	590, 72,
            	798, 80,
            	795, 88,
            8884097, 8, 0, /* 780: pointer.func */
            8884097, 8, 0, /* 783: pointer.func */
            8884097, 8, 0, /* 786: pointer.func */
            8884097, 8, 0, /* 789: pointer.func */
            8884097, 8, 0, /* 792: pointer.func */
            8884097, 8, 0, /* 795: pointer.func */
            8884097, 8, 0, /* 798: pointer.func */
            1, 8, 1, /* 801: pointer.struct.dh_method */
            	806, 0,
            0, 72, 8, /* 806: struct.dh_method */
            	622, 0,
            	825, 8,
            	828, 16,
            	831, 24,
            	825, 32,
            	825, 40,
            	590, 56,
            	834, 64,
            8884097, 8, 0, /* 825: pointer.func */
            8884097, 8, 0, /* 828: pointer.func */
            8884097, 8, 0, /* 831: pointer.func */
            8884097, 8, 0, /* 834: pointer.func */
            1, 8, 1, /* 837: pointer.struct.ecdh_method */
            	842, 0,
            0, 32, 3, /* 842: struct.ecdh_method */
            	622, 0,
            	851, 8,
            	590, 24,
            8884097, 8, 0, /* 851: pointer.func */
            1, 8, 1, /* 854: pointer.struct.ecdsa_method */
            	859, 0,
            0, 48, 5, /* 859: struct.ecdsa_method */
            	622, 0,
            	872, 8,
            	875, 16,
            	878, 24,
            	590, 40,
            8884097, 8, 0, /* 872: pointer.func */
            8884097, 8, 0, /* 875: pointer.func */
            8884097, 8, 0, /* 878: pointer.func */
            1, 8, 1, /* 881: pointer.struct.rand_meth_st */
            	886, 0,
            0, 48, 6, /* 886: struct.rand_meth_st */
            	901, 0,
            	904, 8,
            	907, 16,
            	910, 24,
            	904, 32,
            	913, 40,
            8884097, 8, 0, /* 901: pointer.func */
            8884097, 8, 0, /* 904: pointer.func */
            8884097, 8, 0, /* 907: pointer.func */
            8884097, 8, 0, /* 910: pointer.func */
            8884097, 8, 0, /* 913: pointer.func */
            1, 8, 1, /* 916: pointer.struct.store_method_st */
            	921, 0,
            0, 0, 0, /* 921: struct.store_method_st */
            8884097, 8, 0, /* 924: pointer.func */
            8884097, 8, 0, /* 927: pointer.func */
            8884097, 8, 0, /* 930: pointer.func */
            8884097, 8, 0, /* 933: pointer.func */
            8884097, 8, 0, /* 936: pointer.func */
            8884097, 8, 0, /* 939: pointer.func */
            8884097, 8, 0, /* 942: pointer.func */
            8884097, 8, 0, /* 945: pointer.func */
            1, 8, 1, /* 948: pointer.struct.ENGINE_CMD_DEFN_st */
            	953, 0,
            0, 32, 2, /* 953: struct.ENGINE_CMD_DEFN_st */
            	622, 8,
            	622, 16,
            0, 16, 1, /* 960: struct.crypto_ex_data_st */
            	965, 0,
            1, 8, 1, /* 965: pointer.struct.stack_st_void */
            	970, 0,
            0, 32, 1, /* 970: struct.stack_st_void */
            	975, 0,
            0, 32, 2, /* 975: struct.stack_st */
            	585, 8,
            	595, 24,
            1, 8, 1, /* 982: pointer.struct.engine_st */
            	644, 0,
            1, 8, 1, /* 987: pointer.struct.dsa_st */
            	992, 0,
            0, 136, 11, /* 992: struct.dsa_st */
            	1017, 24,
            	1017, 32,
            	1017, 40,
            	1017, 48,
            	1017, 56,
            	1017, 64,
            	1017, 72,
            	1027, 88,
            	1041, 104,
            	1063, 120,
            	1114, 128,
            1, 8, 1, /* 1017: pointer.struct.bignum_st */
            	1022, 0,
            0, 24, 1, /* 1022: struct.bignum_st */
            	413, 0,
            1, 8, 1, /* 1027: pointer.struct.bn_mont_ctx_st */
            	1032, 0,
            0, 96, 3, /* 1032: struct.bn_mont_ctx_st */
            	1022, 8,
            	1022, 32,
            	1022, 56,
            0, 16, 1, /* 1041: struct.crypto_ex_data_st */
            	1046, 0,
            1, 8, 1, /* 1046: pointer.struct.stack_st_void */
            	1051, 0,
            0, 32, 1, /* 1051: struct.stack_st_void */
            	1056, 0,
            0, 32, 2, /* 1056: struct.stack_st */
            	585, 8,
            	595, 24,
            1, 8, 1, /* 1063: pointer.struct.dsa_method */
            	1068, 0,
            0, 96, 11, /* 1068: struct.dsa_method */
            	622, 0,
            	1093, 8,
            	1096, 16,
            	1099, 24,
            	1102, 32,
            	1105, 40,
            	1108, 48,
            	1108, 56,
            	590, 72,
            	1111, 80,
            	1108, 88,
            8884097, 8, 0, /* 1093: pointer.func */
            8884097, 8, 0, /* 1096: pointer.func */
            8884097, 8, 0, /* 1099: pointer.func */
            8884097, 8, 0, /* 1102: pointer.func */
            8884097, 8, 0, /* 1105: pointer.func */
            8884097, 8, 0, /* 1108: pointer.func */
            8884097, 8, 0, /* 1111: pointer.func */
            1, 8, 1, /* 1114: pointer.struct.engine_st */
            	644, 0,
            1, 8, 1, /* 1119: pointer.struct.rsa_st */
            	1124, 0,
            0, 168, 17, /* 1124: struct.rsa_st */
            	1161, 16,
            	639, 24,
            	1216, 32,
            	1216, 40,
            	1216, 48,
            	1216, 56,
            	1216, 64,
            	1216, 72,
            	1216, 80,
            	1216, 88,
            	1226, 96,
            	1248, 120,
            	1248, 128,
            	1248, 136,
            	590, 144,
            	1262, 152,
            	1262, 160,
            1, 8, 1, /* 1161: pointer.struct.rsa_meth_st */
            	1166, 0,
            0, 112, 13, /* 1166: struct.rsa_meth_st */
            	622, 0,
            	1195, 8,
            	1195, 16,
            	1195, 24,
            	1195, 32,
            	1198, 40,
            	1201, 48,
            	1204, 56,
            	1204, 64,
            	590, 80,
            	1207, 88,
            	1210, 96,
            	1213, 104,
            8884097, 8, 0, /* 1195: pointer.func */
            8884097, 8, 0, /* 1198: pointer.func */
            8884097, 8, 0, /* 1201: pointer.func */
            8884097, 8, 0, /* 1204: pointer.func */
            8884097, 8, 0, /* 1207: pointer.func */
            8884097, 8, 0, /* 1210: pointer.func */
            8884097, 8, 0, /* 1213: pointer.func */
            1, 8, 1, /* 1216: pointer.struct.bignum_st */
            	1221, 0,
            0, 24, 1, /* 1221: struct.bignum_st */
            	413, 0,
            0, 16, 1, /* 1226: struct.crypto_ex_data_st */
            	1231, 0,
            1, 8, 1, /* 1231: pointer.struct.stack_st_void */
            	1236, 0,
            0, 32, 1, /* 1236: struct.stack_st_void */
            	1241, 0,
            0, 32, 2, /* 1241: struct.stack_st */
            	585, 8,
            	595, 24,
            1, 8, 1, /* 1248: pointer.struct.bn_mont_ctx_st */
            	1253, 0,
            0, 96, 3, /* 1253: struct.bn_mont_ctx_st */
            	1221, 8,
            	1221, 32,
            	1221, 56,
            1, 8, 1, /* 1262: pointer.struct.bn_blinding_st */
            	1267, 0,
            0, 88, 7, /* 1267: struct.bn_blinding_st */
            	1284, 0,
            	1284, 8,
            	1284, 16,
            	1284, 24,
            	1294, 40,
            	1299, 72,
            	1313, 80,
            1, 8, 1, /* 1284: pointer.struct.bignum_st */
            	1289, 0,
            0, 24, 1, /* 1289: struct.bignum_st */
            	413, 0,
            0, 16, 1, /* 1294: struct.crypto_threadid_st */
            	457, 0,
            1, 8, 1, /* 1299: pointer.struct.bn_mont_ctx_st */
            	1304, 0,
            0, 96, 3, /* 1304: struct.bn_mont_ctx_st */
            	1289, 8,
            	1289, 32,
            	1289, 56,
            8884097, 8, 0, /* 1313: pointer.func */
            1, 8, 1, /* 1316: pointer.struct.asn1_string_st */
            	1321, 0,
            0, 24, 1, /* 1321: struct.asn1_string_st */
            	426, 8,
            1, 8, 1, /* 1326: pointer.struct.stack_st_ASN1_OBJECT */
            	1331, 0,
            0, 32, 2, /* 1331: struct.stack_st_fake_ASN1_OBJECT */
            	1338, 8,
            	595, 24,
            8884099, 8, 2, /* 1338: pointer_to_array_of_pointers_to_stack */
            	1345, 0,
            	1369, 20,
            0, 8, 1, /* 1345: pointer.ASN1_OBJECT */
            	1350, 0,
            0, 0, 1, /* 1350: ASN1_OBJECT */
            	1355, 0,
            0, 40, 3, /* 1355: struct.asn1_object_st */
            	622, 0,
            	622, 8,
            	1364, 24,
            1, 8, 1, /* 1364: pointer.unsigned char */
            	431, 0,
            0, 4, 0, /* 1369: int */
            0, 40, 5, /* 1372: struct.x509_cert_aux_st */
            	1326, 0,
            	1326, 8,
            	1316, 16,
            	1385, 24,
            	1390, 32,
            1, 8, 1, /* 1385: pointer.struct.asn1_string_st */
            	1321, 0,
            1, 8, 1, /* 1390: pointer.struct.stack_st_X509_ALGOR */
            	1395, 0,
            0, 32, 2, /* 1395: struct.stack_st_fake_X509_ALGOR */
            	1402, 8,
            	595, 24,
            8884099, 8, 2, /* 1402: pointer_to_array_of_pointers_to_stack */
            	1409, 0,
            	1369, 20,
            0, 8, 1, /* 1409: pointer.X509_ALGOR */
            	1414, 0,
            0, 0, 1, /* 1414: X509_ALGOR */
            	1419, 0,
            0, 16, 2, /* 1419: struct.X509_algor_st */
            	1426, 0,
            	1440, 8,
            1, 8, 1, /* 1426: pointer.struct.asn1_object_st */
            	1431, 0,
            0, 40, 3, /* 1431: struct.asn1_object_st */
            	622, 0,
            	622, 8,
            	1364, 24,
            1, 8, 1, /* 1440: pointer.struct.asn1_type_st */
            	1445, 0,
            0, 16, 1, /* 1445: struct.asn1_type_st */
            	1450, 8,
            0, 8, 20, /* 1450: union.unknown */
            	590, 0,
            	1493, 0,
            	1426, 0,
            	1503, 0,
            	1508, 0,
            	1513, 0,
            	1518, 0,
            	1523, 0,
            	1528, 0,
            	1533, 0,
            	1538, 0,
            	1543, 0,
            	1548, 0,
            	1553, 0,
            	1558, 0,
            	1563, 0,
            	1568, 0,
            	1493, 0,
            	1493, 0,
            	1573, 0,
            1, 8, 1, /* 1493: pointer.struct.asn1_string_st */
            	1498, 0,
            0, 24, 1, /* 1498: struct.asn1_string_st */
            	426, 8,
            1, 8, 1, /* 1503: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1508: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1513: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1518: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1523: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1528: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1533: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1538: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1543: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1548: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1553: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1558: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1563: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1568: pointer.struct.asn1_string_st */
            	1498, 0,
            1, 8, 1, /* 1573: pointer.struct.ASN1_VALUE_st */
            	1578, 0,
            0, 0, 0, /* 1578: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1581: pointer.struct.x509_cert_aux_st */
            	1372, 0,
            0, 16, 2, /* 1586: struct.EDIPartyName_st */
            	1593, 0,
            	1593, 8,
            1, 8, 1, /* 1593: pointer.struct.asn1_string_st */
            	1598, 0,
            0, 24, 1, /* 1598: struct.asn1_string_st */
            	426, 8,
            1, 8, 1, /* 1603: pointer.struct.EDIPartyName_st */
            	1586, 0,
            0, 24, 1, /* 1608: struct.buf_mem_st */
            	590, 8,
            1, 8, 1, /* 1613: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1618, 0,
            0, 32, 2, /* 1618: struct.stack_st_fake_X509_NAME_ENTRY */
            	1625, 8,
            	595, 24,
            8884099, 8, 2, /* 1625: pointer_to_array_of_pointers_to_stack */
            	1632, 0,
            	1369, 20,
            0, 8, 1, /* 1632: pointer.X509_NAME_ENTRY */
            	1637, 0,
            0, 0, 1, /* 1637: X509_NAME_ENTRY */
            	1642, 0,
            0, 24, 2, /* 1642: struct.X509_name_entry_st */
            	1649, 0,
            	1663, 8,
            1, 8, 1, /* 1649: pointer.struct.asn1_object_st */
            	1654, 0,
            0, 40, 3, /* 1654: struct.asn1_object_st */
            	622, 0,
            	622, 8,
            	1364, 24,
            1, 8, 1, /* 1663: pointer.struct.asn1_string_st */
            	1668, 0,
            0, 24, 1, /* 1668: struct.asn1_string_st */
            	426, 8,
            1, 8, 1, /* 1673: pointer.struct.X509_name_st */
            	1678, 0,
            0, 40, 3, /* 1678: struct.X509_name_st */
            	1613, 0,
            	1687, 16,
            	426, 24,
            1, 8, 1, /* 1687: pointer.struct.buf_mem_st */
            	1608, 0,
            1, 8, 1, /* 1692: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1697: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1702: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1707: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1712: pointer.struct.asn1_string_st */
            	1598, 0,
            0, 8, 20, /* 1717: union.unknown */
            	590, 0,
            	1593, 0,
            	1760, 0,
            	1774, 0,
            	1779, 0,
            	1784, 0,
            	1712, 0,
            	1789, 0,
            	1794, 0,
            	1799, 0,
            	1707, 0,
            	1702, 0,
            	1804, 0,
            	1697, 0,
            	1692, 0,
            	1809, 0,
            	1814, 0,
            	1593, 0,
            	1593, 0,
            	1819, 0,
            1, 8, 1, /* 1760: pointer.struct.asn1_object_st */
            	1765, 0,
            0, 40, 3, /* 1765: struct.asn1_object_st */
            	622, 0,
            	622, 8,
            	1364, 24,
            1, 8, 1, /* 1774: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1779: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1784: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1789: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1794: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1799: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1804: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1809: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1814: pointer.struct.asn1_string_st */
            	1598, 0,
            1, 8, 1, /* 1819: pointer.struct.ASN1_VALUE_st */
            	1824, 0,
            0, 0, 0, /* 1824: struct.ASN1_VALUE_st */
            0, 16, 1, /* 1827: struct.GENERAL_NAME_st */
            	1832, 8,
            0, 8, 15, /* 1832: union.unknown */
            	590, 0,
            	1865, 0,
            	1799, 0,
            	1799, 0,
            	1877, 0,
            	1673, 0,
            	1603, 0,
            	1799, 0,
            	1712, 0,
            	1760, 0,
            	1712, 0,
            	1673, 0,
            	1799, 0,
            	1760, 0,
            	1877, 0,
            1, 8, 1, /* 1865: pointer.struct.otherName_st */
            	1870, 0,
            0, 16, 2, /* 1870: struct.otherName_st */
            	1760, 0,
            	1877, 8,
            1, 8, 1, /* 1877: pointer.struct.asn1_type_st */
            	1882, 0,
            0, 16, 1, /* 1882: struct.asn1_type_st */
            	1717, 8,
            0, 24, 3, /* 1887: struct.GENERAL_SUBTREE_st */
            	1896, 0,
            	1774, 8,
            	1774, 16,
            1, 8, 1, /* 1896: pointer.struct.GENERAL_NAME_st */
            	1827, 0,
            0, 0, 1, /* 1901: GENERAL_SUBTREE */
            	1887, 0,
            0, 16, 2, /* 1906: struct.NAME_CONSTRAINTS_st */
            	1913, 0,
            	1913, 8,
            1, 8, 1, /* 1913: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1918, 0,
            0, 32, 2, /* 1918: struct.stack_st_fake_GENERAL_SUBTREE */
            	1925, 8,
            	595, 24,
            8884099, 8, 2, /* 1925: pointer_to_array_of_pointers_to_stack */
            	1932, 0,
            	1369, 20,
            0, 8, 1, /* 1932: pointer.GENERAL_SUBTREE */
            	1901, 0,
            1, 8, 1, /* 1937: pointer.struct.NAME_CONSTRAINTS_st */
            	1906, 0,
            0, 8, 5, /* 1942: union.unknown */
            	590, 0,
            	1119, 0,
            	987, 0,
            	507, 0,
            	0, 0,
            1, 8, 1, /* 1955: pointer.struct.stack_st_GENERAL_NAME */
            	1960, 0,
            0, 32, 2, /* 1960: struct.stack_st_fake_GENERAL_NAME */
            	1967, 8,
            	595, 24,
            8884099, 8, 2, /* 1967: pointer_to_array_of_pointers_to_stack */
            	1974, 0,
            	1369, 20,
            0, 8, 1, /* 1974: pointer.GENERAL_NAME */
            	1979, 0,
            0, 0, 1, /* 1979: GENERAL_NAME */
            	1984, 0,
            0, 16, 1, /* 1984: struct.GENERAL_NAME_st */
            	1989, 8,
            0, 8, 15, /* 1989: union.unknown */
            	590, 0,
            	2022, 0,
            	2141, 0,
            	2141, 0,
            	2048, 0,
            	2189, 0,
            	2237, 0,
            	2141, 0,
            	2126, 0,
            	2034, 0,
            	2126, 0,
            	2189, 0,
            	2141, 0,
            	2034, 0,
            	2048, 0,
            1, 8, 1, /* 2022: pointer.struct.otherName_st */
            	2027, 0,
            0, 16, 2, /* 2027: struct.otherName_st */
            	2034, 0,
            	2048, 8,
            1, 8, 1, /* 2034: pointer.struct.asn1_object_st */
            	2039, 0,
            0, 40, 3, /* 2039: struct.asn1_object_st */
            	622, 0,
            	622, 8,
            	1364, 24,
            1, 8, 1, /* 2048: pointer.struct.asn1_type_st */
            	2053, 0,
            0, 16, 1, /* 2053: struct.asn1_type_st */
            	2058, 8,
            0, 8, 20, /* 2058: union.unknown */
            	590, 0,
            	2101, 0,
            	2034, 0,
            	2111, 0,
            	2116, 0,
            	2121, 0,
            	2126, 0,
            	2131, 0,
            	2136, 0,
            	2141, 0,
            	2146, 0,
            	2151, 0,
            	2156, 0,
            	2161, 0,
            	2166, 0,
            	2171, 0,
            	2176, 0,
            	2101, 0,
            	2101, 0,
            	2181, 0,
            1, 8, 1, /* 2101: pointer.struct.asn1_string_st */
            	2106, 0,
            0, 24, 1, /* 2106: struct.asn1_string_st */
            	426, 8,
            1, 8, 1, /* 2111: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2116: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2121: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2126: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2131: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2136: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2141: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2146: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2151: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2156: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2161: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2166: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2171: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2176: pointer.struct.asn1_string_st */
            	2106, 0,
            1, 8, 1, /* 2181: pointer.struct.ASN1_VALUE_st */
            	2186, 0,
            0, 0, 0, /* 2186: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2189: pointer.struct.X509_name_st */
            	2194, 0,
            0, 40, 3, /* 2194: struct.X509_name_st */
            	2203, 0,
            	2227, 16,
            	426, 24,
            1, 8, 1, /* 2203: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2208, 0,
            0, 32, 2, /* 2208: struct.stack_st_fake_X509_NAME_ENTRY */
            	2215, 8,
            	595, 24,
            8884099, 8, 2, /* 2215: pointer_to_array_of_pointers_to_stack */
            	2222, 0,
            	1369, 20,
            0, 8, 1, /* 2222: pointer.X509_NAME_ENTRY */
            	1637, 0,
            1, 8, 1, /* 2227: pointer.struct.buf_mem_st */
            	2232, 0,
            0, 24, 1, /* 2232: struct.buf_mem_st */
            	590, 8,
            1, 8, 1, /* 2237: pointer.struct.EDIPartyName_st */
            	2242, 0,
            0, 16, 2, /* 2242: struct.EDIPartyName_st */
            	2101, 0,
            	2101, 8,
            0, 24, 1, /* 2249: struct.asn1_string_st */
            	426, 8,
            1, 8, 1, /* 2254: pointer.struct.buf_mem_st */
            	2259, 0,
            0, 24, 1, /* 2259: struct.buf_mem_st */
            	590, 8,
            0, 40, 3, /* 2264: struct.X509_name_st */
            	2273, 0,
            	2254, 16,
            	426, 24,
            1, 8, 1, /* 2273: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2278, 0,
            0, 32, 2, /* 2278: struct.stack_st_fake_X509_NAME_ENTRY */
            	2285, 8,
            	595, 24,
            8884099, 8, 2, /* 2285: pointer_to_array_of_pointers_to_stack */
            	2292, 0,
            	1369, 20,
            0, 8, 1, /* 2292: pointer.X509_NAME_ENTRY */
            	1637, 0,
            1, 8, 1, /* 2297: pointer.struct.stack_st_ASN1_OBJECT */
            	2302, 0,
            0, 32, 2, /* 2302: struct.stack_st_fake_ASN1_OBJECT */
            	2309, 8,
            	595, 24,
            8884099, 8, 2, /* 2309: pointer_to_array_of_pointers_to_stack */
            	2316, 0,
            	1369, 20,
            0, 8, 1, /* 2316: pointer.ASN1_OBJECT */
            	1350, 0,
            1, 8, 1, /* 2321: pointer.struct.stack_st_POLICYQUALINFO */
            	2326, 0,
            0, 32, 2, /* 2326: struct.stack_st_fake_POLICYQUALINFO */
            	2333, 8,
            	595, 24,
            8884099, 8, 2, /* 2333: pointer_to_array_of_pointers_to_stack */
            	2340, 0,
            	1369, 20,
            0, 8, 1, /* 2340: pointer.POLICYQUALINFO */
            	2345, 0,
            0, 0, 1, /* 2345: POLICYQUALINFO */
            	2350, 0,
            0, 16, 2, /* 2350: struct.POLICYQUALINFO_st */
            	2357, 0,
            	2371, 8,
            1, 8, 1, /* 2357: pointer.struct.asn1_object_st */
            	2362, 0,
            0, 40, 3, /* 2362: struct.asn1_object_st */
            	622, 0,
            	622, 8,
            	1364, 24,
            0, 8, 3, /* 2371: union.unknown */
            	2380, 0,
            	2390, 0,
            	2453, 0,
            1, 8, 1, /* 2380: pointer.struct.asn1_string_st */
            	2385, 0,
            0, 24, 1, /* 2385: struct.asn1_string_st */
            	426, 8,
            1, 8, 1, /* 2390: pointer.struct.USERNOTICE_st */
            	2395, 0,
            0, 16, 2, /* 2395: struct.USERNOTICE_st */
            	2402, 0,
            	2414, 8,
            1, 8, 1, /* 2402: pointer.struct.NOTICEREF_st */
            	2407, 0,
            0, 16, 2, /* 2407: struct.NOTICEREF_st */
            	2414, 0,
            	2419, 8,
            1, 8, 1, /* 2414: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2419: pointer.struct.stack_st_ASN1_INTEGER */
            	2424, 0,
            0, 32, 2, /* 2424: struct.stack_st_fake_ASN1_INTEGER */
            	2431, 8,
            	595, 24,
            8884099, 8, 2, /* 2431: pointer_to_array_of_pointers_to_stack */
            	2438, 0,
            	1369, 20,
            0, 8, 1, /* 2438: pointer.ASN1_INTEGER */
            	2443, 0,
            0, 0, 1, /* 2443: ASN1_INTEGER */
            	2448, 0,
            0, 24, 1, /* 2448: struct.asn1_string_st */
            	426, 8,
            1, 8, 1, /* 2453: pointer.struct.asn1_type_st */
            	2458, 0,
            0, 16, 1, /* 2458: struct.asn1_type_st */
            	2463, 8,
            0, 8, 20, /* 2463: union.unknown */
            	590, 0,
            	2414, 0,
            	2357, 0,
            	2506, 0,
            	2511, 0,
            	2516, 0,
            	2521, 0,
            	2526, 0,
            	2531, 0,
            	2380, 0,
            	2536, 0,
            	2541, 0,
            	2546, 0,
            	2551, 0,
            	2556, 0,
            	2561, 0,
            	2566, 0,
            	2414, 0,
            	2414, 0,
            	1819, 0,
            1, 8, 1, /* 2506: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2511: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2516: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2521: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2526: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2531: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2536: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2541: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2546: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2551: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2556: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2561: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2566: pointer.struct.asn1_string_st */
            	2385, 0,
            1, 8, 1, /* 2571: pointer.struct.asn1_object_st */
            	2576, 0,
            0, 40, 3, /* 2576: struct.asn1_object_st */
            	622, 0,
            	622, 8,
            	1364, 24,
            0, 8, 2, /* 2585: union.unknown */
            	2592, 0,
            	2273, 0,
            1, 8, 1, /* 2592: pointer.struct.stack_st_GENERAL_NAME */
            	2597, 0,
            0, 32, 2, /* 2597: struct.stack_st_fake_GENERAL_NAME */
            	2604, 8,
            	595, 24,
            8884099, 8, 2, /* 2604: pointer_to_array_of_pointers_to_stack */
            	2611, 0,
            	1369, 20,
            0, 8, 1, /* 2611: pointer.GENERAL_NAME */
            	1979, 0,
            1, 8, 1, /* 2616: pointer.struct.stack_st_X509_POLICY_DATA */
            	2621, 0,
            0, 32, 2, /* 2621: struct.stack_st_fake_X509_POLICY_DATA */
            	2628, 8,
            	595, 24,
            8884099, 8, 2, /* 2628: pointer_to_array_of_pointers_to_stack */
            	2635, 0,
            	1369, 20,
            0, 8, 1, /* 2635: pointer.X509_POLICY_DATA */
            	2640, 0,
            0, 0, 1, /* 2640: X509_POLICY_DATA */
            	2645, 0,
            0, 32, 3, /* 2645: struct.X509_POLICY_DATA_st */
            	2571, 8,
            	2321, 16,
            	2297, 24,
            1, 8, 1, /* 2654: pointer.struct.asn1_object_st */
            	2659, 0,
            0, 40, 3, /* 2659: struct.asn1_object_st */
            	622, 0,
            	622, 8,
            	1364, 24,
            0, 32, 3, /* 2668: struct.X509_POLICY_DATA_st */
            	2654, 8,
            	2677, 16,
            	2701, 24,
            1, 8, 1, /* 2677: pointer.struct.stack_st_POLICYQUALINFO */
            	2682, 0,
            0, 32, 2, /* 2682: struct.stack_st_fake_POLICYQUALINFO */
            	2689, 8,
            	595, 24,
            8884099, 8, 2, /* 2689: pointer_to_array_of_pointers_to_stack */
            	2696, 0,
            	1369, 20,
            0, 8, 1, /* 2696: pointer.POLICYQUALINFO */
            	2345, 0,
            1, 8, 1, /* 2701: pointer.struct.stack_st_ASN1_OBJECT */
            	2706, 0,
            0, 32, 2, /* 2706: struct.stack_st_fake_ASN1_OBJECT */
            	2713, 8,
            	595, 24,
            8884099, 8, 2, /* 2713: pointer_to_array_of_pointers_to_stack */
            	2720, 0,
            	1369, 20,
            0, 8, 1, /* 2720: pointer.ASN1_OBJECT */
            	1350, 0,
            0, 40, 2, /* 2725: struct.X509_POLICY_CACHE_st */
            	2732, 0,
            	2616, 8,
            1, 8, 1, /* 2732: pointer.struct.X509_POLICY_DATA_st */
            	2668, 0,
            1, 8, 1, /* 2737: pointer.struct.asn1_string_st */
            	2742, 0,
            0, 24, 1, /* 2742: struct.asn1_string_st */
            	426, 8,
            1, 8, 1, /* 2747: pointer.struct.stack_st_GENERAL_NAME */
            	2752, 0,
            0, 32, 2, /* 2752: struct.stack_st_fake_GENERAL_NAME */
            	2759, 8,
            	595, 24,
            8884099, 8, 2, /* 2759: pointer_to_array_of_pointers_to_stack */
            	2766, 0,
            	1369, 20,
            0, 8, 1, /* 2766: pointer.GENERAL_NAME */
            	1979, 0,
            1, 8, 1, /* 2771: pointer.struct.asn1_string_st */
            	2742, 0,
            1, 8, 1, /* 2776: pointer.struct.AUTHORITY_KEYID_st */
            	2781, 0,
            0, 24, 3, /* 2781: struct.AUTHORITY_KEYID_st */
            	2771, 0,
            	2747, 8,
            	2737, 16,
            0, 32, 1, /* 2790: struct.stack_st_void */
            	2795, 0,
            0, 32, 2, /* 2795: struct.stack_st */
            	585, 8,
            	595, 24,
            0, 16, 1, /* 2802: struct.crypto_ex_data_st */
            	2807, 0,
            1, 8, 1, /* 2807: pointer.struct.stack_st_void */
            	2790, 0,
            0, 40, 3, /* 2812: struct.asn1_object_st */
            	622, 0,
            	622, 8,
            	1364, 24,
            0, 24, 2, /* 2821: struct.X509_extension_st */
            	2828, 0,
            	2833, 16,
            1, 8, 1, /* 2828: pointer.struct.asn1_object_st */
            	2812, 0,
            1, 8, 1, /* 2833: pointer.struct.asn1_string_st */
            	2838, 0,
            0, 24, 1, /* 2838: struct.asn1_string_st */
            	426, 8,
            0, 0, 1, /* 2843: X509_EXTENSION */
            	2821, 0,
            1, 8, 1, /* 2848: pointer.struct.stack_st_X509_EXTENSION */
            	2853, 0,
            0, 32, 2, /* 2853: struct.stack_st_fake_X509_EXTENSION */
            	2860, 8,
            	595, 24,
            8884099, 8, 2, /* 2860: pointer_to_array_of_pointers_to_stack */
            	2867, 0,
            	1369, 20,
            0, 8, 1, /* 2867: pointer.X509_EXTENSION */
            	2843, 0,
            1, 8, 1, /* 2872: pointer.struct.asn1_string_st */
            	1321, 0,
            1, 8, 1, /* 2877: pointer.struct.ASN1_VALUE_st */
            	2882, 0,
            0, 0, 0, /* 2882: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2885: pointer.struct.asn1_string_st */
            	2890, 0,
            0, 24, 1, /* 2890: struct.asn1_string_st */
            	426, 8,
            0, 24, 1, /* 2895: struct.ASN1_ENCODING_st */
            	426, 0,
            1, 8, 1, /* 2900: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2905: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2910: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2915: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2920: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2925: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2930: pointer.struct.asn1_string_st */
            	2249, 0,
            1, 8, 1, /* 2935: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2940: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2945: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2950: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2955: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 2960: pointer.struct.asn1_string_st */
            	2890, 0,
            0, 16, 1, /* 2965: struct.asn1_type_st */
            	2970, 8,
            0, 8, 20, /* 2970: union.unknown */
            	590, 0,
            	2960, 0,
            	3013, 0,
            	3027, 0,
            	2955, 0,
            	2950, 0,
            	2945, 0,
            	2940, 0,
            	2935, 0,
            	2925, 0,
            	2920, 0,
            	2915, 0,
            	2910, 0,
            	2905, 0,
            	2900, 0,
            	3032, 0,
            	2885, 0,
            	2960, 0,
            	2960, 0,
            	2877, 0,
            1, 8, 1, /* 3013: pointer.struct.asn1_object_st */
            	3018, 0,
            0, 40, 3, /* 3018: struct.asn1_object_st */
            	622, 0,
            	622, 8,
            	1364, 24,
            1, 8, 1, /* 3027: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3032: pointer.struct.asn1_string_st */
            	2890, 0,
            1, 8, 1, /* 3037: pointer.struct.ASN1_VALUE_st */
            	3042, 0,
            0, 0, 0, /* 3042: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3045: pointer.struct.asn1_string_st */
            	3050, 0,
            0, 24, 1, /* 3050: struct.asn1_string_st */
            	426, 8,
            1, 8, 1, /* 3055: pointer.struct.asn1_string_st */
            	3050, 0,
            1, 8, 1, /* 3060: pointer.struct.asn1_string_st */
            	3050, 0,
            1, 8, 1, /* 3065: pointer.struct.asn1_string_st */
            	3050, 0,
            1, 8, 1, /* 3070: pointer.struct.asn1_string_st */
            	3050, 0,
            1, 8, 1, /* 3075: pointer.struct.asn1_string_st */
            	3050, 0,
            1, 8, 1, /* 3080: pointer.struct.asn1_string_st */
            	3050, 0,
            1, 8, 1, /* 3085: pointer.struct.asn1_string_st */
            	3050, 0,
            1, 8, 1, /* 3090: pointer.struct.asn1_string_st */
            	3050, 0,
            0, 40, 3, /* 3095: struct.asn1_object_st */
            	622, 0,
            	622, 8,
            	1364, 24,
            1, 8, 1, /* 3104: pointer.struct.asn1_object_st */
            	3095, 0,
            1, 8, 1, /* 3109: pointer.struct.asn1_string_st */
            	3050, 0,
            0, 8, 20, /* 3114: union.unknown */
            	590, 0,
            	3109, 0,
            	3104, 0,
            	3090, 0,
            	3085, 0,
            	3157, 0,
            	3080, 0,
            	3162, 0,
            	3167, 0,
            	3075, 0,
            	3070, 0,
            	3172, 0,
            	3065, 0,
            	3060, 0,
            	3055, 0,
            	3177, 0,
            	3045, 0,
            	3109, 0,
            	3109, 0,
            	3037, 0,
            1, 8, 1, /* 3157: pointer.struct.asn1_string_st */
            	3050, 0,
            1, 8, 1, /* 3162: pointer.struct.asn1_string_st */
            	3050, 0,
            1, 8, 1, /* 3167: pointer.struct.asn1_string_st */
            	3050, 0,
            1, 8, 1, /* 3172: pointer.struct.asn1_string_st */
            	3050, 0,
            1, 8, 1, /* 3177: pointer.struct.asn1_string_st */
            	3050, 0,
            0, 16, 1, /* 3182: struct.asn1_type_st */
            	3114, 8,
            0, 0, 1, /* 3187: ASN1_TYPE */
            	3182, 0,
            1, 8, 1, /* 3192: pointer.struct.stack_st_ASN1_TYPE */
            	3197, 0,
            0, 32, 2, /* 3197: struct.stack_st_fake_ASN1_TYPE */
            	3204, 8,
            	595, 24,
            8884099, 8, 2, /* 3204: pointer_to_array_of_pointers_to_stack */
            	3211, 0,
            	1369, 20,
            0, 8, 1, /* 3211: pointer.ASN1_TYPE */
            	3187, 0,
            0, 8, 3, /* 3216: union.unknown */
            	590, 0,
            	3192, 0,
            	3225, 0,
            1, 8, 1, /* 3225: pointer.struct.asn1_type_st */
            	2965, 0,
            0, 24, 2, /* 3230: struct.x509_attributes_st */
            	3013, 0,
            	3216, 16,
            0, 0, 1, /* 3237: DIST_POINT */
            	3242, 0,
            0, 32, 3, /* 3242: struct.DIST_POINT_st */
            	3251, 0,
            	2930, 8,
            	2592, 16,
            1, 8, 1, /* 3251: pointer.struct.DIST_POINT_NAME_st */
            	3256, 0,
            0, 24, 2, /* 3256: struct.DIST_POINT_NAME_st */
            	2585, 8,
            	3263, 16,
            1, 8, 1, /* 3263: pointer.struct.X509_name_st */
            	2264, 0,
            1, 8, 1, /* 3268: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3273, 0,
            0, 32, 2, /* 3273: struct.stack_st_fake_X509_ATTRIBUTE */
            	3280, 8,
            	595, 24,
            8884099, 8, 2, /* 3280: pointer_to_array_of_pointers_to_stack */
            	3287, 0,
            	1369, 20,
            0, 8, 1, /* 3287: pointer.X509_ATTRIBUTE */
            	3292, 0,
            0, 0, 1, /* 3292: X509_ATTRIBUTE */
            	3230, 0,
            8884097, 8, 0, /* 3297: pointer.func */
            0, 8, 5, /* 3300: union.unknown */
            	590, 0,
            	3313, 0,
            	3318, 0,
            	3323, 0,
            	3328, 0,
            1, 8, 1, /* 3313: pointer.struct.rsa_st */
            	1124, 0,
            1, 8, 1, /* 3318: pointer.struct.dsa_st */
            	992, 0,
            1, 8, 1, /* 3323: pointer.struct.dh_st */
            	512, 0,
            1, 8, 1, /* 3328: pointer.struct.ec_key_st */
            	5, 0,
            1, 8, 1, /* 3333: pointer.struct.X509_val_st */
            	3338, 0,
            0, 16, 2, /* 3338: struct.X509_val_st */
            	3345, 0,
            	3345, 8,
            1, 8, 1, /* 3345: pointer.struct.asn1_string_st */
            	1321, 0,
            8884097, 8, 0, /* 3350: pointer.func */
            1, 8, 1, /* 3353: pointer.struct.asn1_string_st */
            	3358, 0,
            0, 24, 1, /* 3358: struct.asn1_string_st */
            	426, 8,
            8884097, 8, 0, /* 3363: pointer.func */
            8884097, 8, 0, /* 3366: pointer.func */
            1, 8, 1, /* 3369: pointer.struct.evp_pkey_st */
            	3374, 0,
            0, 56, 4, /* 3374: struct.evp_pkey_st */
            	3385, 16,
            	639, 24,
            	1942, 32,
            	3474, 48,
            1, 8, 1, /* 3385: pointer.struct.evp_pkey_asn1_method_st */
            	3390, 0,
            0, 208, 24, /* 3390: struct.evp_pkey_asn1_method_st */
            	590, 16,
            	590, 24,
            	3441, 32,
            	3444, 40,
            	3447, 48,
            	3450, 56,
            	3453, 64,
            	3456, 72,
            	3450, 80,
            	3366, 88,
            	3366, 96,
            	3459, 104,
            	3462, 112,
            	3366, 120,
            	3465, 128,
            	3447, 136,
            	3450, 144,
            	3297, 152,
            	3350, 160,
            	3468, 168,
            	3459, 176,
            	3462, 184,
            	3471, 192,
            	3363, 200,
            8884097, 8, 0, /* 3441: pointer.func */
            8884097, 8, 0, /* 3444: pointer.func */
            8884097, 8, 0, /* 3447: pointer.func */
            8884097, 8, 0, /* 3450: pointer.func */
            8884097, 8, 0, /* 3453: pointer.func */
            8884097, 8, 0, /* 3456: pointer.func */
            8884097, 8, 0, /* 3459: pointer.func */
            8884097, 8, 0, /* 3462: pointer.func */
            8884097, 8, 0, /* 3465: pointer.func */
            8884097, 8, 0, /* 3468: pointer.func */
            8884097, 8, 0, /* 3471: pointer.func */
            1, 8, 1, /* 3474: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3479, 0,
            0, 32, 2, /* 3479: struct.stack_st_fake_X509_ATTRIBUTE */
            	3486, 8,
            	595, 24,
            8884099, 8, 2, /* 3486: pointer_to_array_of_pointers_to_stack */
            	3493, 0,
            	1369, 20,
            0, 8, 1, /* 3493: pointer.X509_ATTRIBUTE */
            	3292, 0,
            1, 8, 1, /* 3498: pointer.struct.evp_pkey_asn1_method_st */
            	3390, 0,
            1, 8, 1, /* 3503: pointer.struct.buf_mem_st */
            	3508, 0,
            0, 24, 1, /* 3508: struct.buf_mem_st */
            	590, 8,
            1, 8, 1, /* 3513: pointer.struct.stack_st_DIST_POINT */
            	3518, 0,
            0, 32, 2, /* 3518: struct.stack_st_fake_DIST_POINT */
            	3525, 8,
            	595, 24,
            8884099, 8, 2, /* 3525: pointer_to_array_of_pointers_to_stack */
            	3532, 0,
            	1369, 20,
            0, 8, 1, /* 3532: pointer.DIST_POINT */
            	3237, 0,
            1, 8, 1, /* 3537: pointer.struct.x509_cinf_st */
            	3542, 0,
            0, 104, 11, /* 3542: struct.x509_cinf_st */
            	3567, 0,
            	3567, 8,
            	3572, 16,
            	3577, 24,
            	3333, 32,
            	3577, 40,
            	3615, 48,
            	2872, 56,
            	2872, 64,
            	2848, 72,
            	2895, 80,
            1, 8, 1, /* 3567: pointer.struct.asn1_string_st */
            	1321, 0,
            1, 8, 1, /* 3572: pointer.struct.X509_algor_st */
            	1419, 0,
            1, 8, 1, /* 3577: pointer.struct.X509_name_st */
            	3582, 0,
            0, 40, 3, /* 3582: struct.X509_name_st */
            	3591, 0,
            	3503, 16,
            	426, 24,
            1, 8, 1, /* 3591: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3596, 0,
            0, 32, 2, /* 3596: struct.stack_st_fake_X509_NAME_ENTRY */
            	3603, 8,
            	595, 24,
            8884099, 8, 2, /* 3603: pointer_to_array_of_pointers_to_stack */
            	3610, 0,
            	1369, 20,
            0, 8, 1, /* 3610: pointer.X509_NAME_ENTRY */
            	1637, 0,
            1, 8, 1, /* 3615: pointer.struct.X509_pubkey_st */
            	3620, 0,
            0, 24, 3, /* 3620: struct.X509_pubkey_st */
            	3629, 0,
            	3353, 8,
            	3634, 16,
            1, 8, 1, /* 3629: pointer.struct.X509_algor_st */
            	1419, 0,
            1, 8, 1, /* 3634: pointer.struct.evp_pkey_st */
            	3639, 0,
            0, 56, 4, /* 3639: struct.evp_pkey_st */
            	3498, 16,
            	1114, 24,
            	3300, 32,
            	3268, 48,
            0, 1, 0, /* 3650: char */
            0, 184, 12, /* 3653: struct.x509_st */
            	3537, 0,
            	3572, 8,
            	2872, 16,
            	590, 32,
            	2802, 40,
            	1385, 104,
            	2776, 112,
            	3680, 120,
            	3513, 128,
            	1955, 136,
            	1937, 144,
            	1581, 176,
            1, 8, 1, /* 3680: pointer.struct.X509_POLICY_CACHE_st */
            	2725, 0,
            1, 8, 1, /* 3685: pointer.struct.x509_st */
            	3653, 0,
        },
        .arg_entity_index = { 3685, 3369, },
        .ret_entity_index = 1369,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * new_arg_b = *((EVP_PKEY * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
    orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
    *new_ret_ptr = (*orig_X509_check_private_key)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

