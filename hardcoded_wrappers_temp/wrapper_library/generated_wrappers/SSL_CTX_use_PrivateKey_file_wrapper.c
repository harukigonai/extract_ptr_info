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

int bb_SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c);

int SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_use_PrivateKey_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_use_PrivateKey_file(arg_a,arg_b,arg_c);
    else {
        int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *,const char *,int);
        orig_SSL_CTX_use_PrivateKey_file = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey_file");
        return orig_SSL_CTX_use_PrivateKey_file(arg_a,arg_b,arg_c);
    }
}

int bb_SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            0, 0, 1, /* 10: SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 15: pointer.func */
            0, 24, 1, /* 18: struct.bignum_st */
            	23, 0,
            8884099, 8, 2, /* 23: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 4, 0, /* 30: unsigned int */
            0, 4, 0, /* 33: int */
            8884097, 8, 0, /* 36: pointer.func */
            8884097, 8, 0, /* 39: pointer.func */
            8884097, 8, 0, /* 42: pointer.func */
            8884097, 8, 0, /* 45: pointer.func */
            1, 8, 1, /* 48: pointer.struct.dh_st */
            	53, 0,
            0, 144, 12, /* 53: struct.dh_st */
            	80, 8,
            	80, 16,
            	80, 32,
            	80, 40,
            	97, 56,
            	80, 64,
            	80, 72,
            	111, 80,
            	80, 96,
            	119, 112,
            	154, 128,
            	190, 136,
            1, 8, 1, /* 80: pointer.struct.bignum_st */
            	85, 0,
            0, 24, 1, /* 85: struct.bignum_st */
            	90, 0,
            8884099, 8, 2, /* 90: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 97: pointer.struct.bn_mont_ctx_st */
            	102, 0,
            0, 96, 3, /* 102: struct.bn_mont_ctx_st */
            	85, 8,
            	85, 32,
            	85, 56,
            1, 8, 1, /* 111: pointer.unsigned char */
            	116, 0,
            0, 1, 0, /* 116: unsigned char */
            0, 16, 1, /* 119: struct.crypto_ex_data_st */
            	124, 0,
            1, 8, 1, /* 124: pointer.struct.stack_st_void */
            	129, 0,
            0, 32, 1, /* 129: struct.stack_st_void */
            	134, 0,
            0, 32, 2, /* 134: struct.stack_st */
            	141, 8,
            	151, 24,
            1, 8, 1, /* 141: pointer.pointer.char */
            	146, 0,
            1, 8, 1, /* 146: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 151: pointer.func */
            1, 8, 1, /* 154: pointer.struct.dh_method */
            	159, 0,
            0, 72, 8, /* 159: struct.dh_method */
            	5, 0,
            	178, 8,
            	181, 16,
            	184, 24,
            	178, 32,
            	178, 40,
            	146, 56,
            	187, 64,
            8884097, 8, 0, /* 178: pointer.func */
            8884097, 8, 0, /* 181: pointer.func */
            8884097, 8, 0, /* 184: pointer.func */
            8884097, 8, 0, /* 187: pointer.func */
            1, 8, 1, /* 190: pointer.struct.engine_st */
            	195, 0,
            0, 216, 24, /* 195: struct.engine_st */
            	5, 0,
            	5, 8,
            	246, 16,
            	301, 24,
            	352, 32,
            	388, 40,
            	405, 48,
            	432, 56,
            	467, 64,
            	475, 72,
            	478, 80,
            	481, 88,
            	484, 96,
            	487, 104,
            	487, 112,
            	487, 120,
            	490, 128,
            	493, 136,
            	493, 144,
            	496, 152,
            	499, 160,
            	511, 184,
            	533, 200,
            	533, 208,
            1, 8, 1, /* 246: pointer.struct.rsa_meth_st */
            	251, 0,
            0, 112, 13, /* 251: struct.rsa_meth_st */
            	5, 0,
            	280, 8,
            	280, 16,
            	280, 24,
            	280, 32,
            	283, 40,
            	286, 48,
            	289, 56,
            	289, 64,
            	146, 80,
            	292, 88,
            	295, 96,
            	298, 104,
            8884097, 8, 0, /* 280: pointer.func */
            8884097, 8, 0, /* 283: pointer.func */
            8884097, 8, 0, /* 286: pointer.func */
            8884097, 8, 0, /* 289: pointer.func */
            8884097, 8, 0, /* 292: pointer.func */
            8884097, 8, 0, /* 295: pointer.func */
            8884097, 8, 0, /* 298: pointer.func */
            1, 8, 1, /* 301: pointer.struct.dsa_method */
            	306, 0,
            0, 96, 11, /* 306: struct.dsa_method */
            	5, 0,
            	331, 8,
            	334, 16,
            	337, 24,
            	340, 32,
            	343, 40,
            	346, 48,
            	346, 56,
            	146, 72,
            	349, 80,
            	346, 88,
            8884097, 8, 0, /* 331: pointer.func */
            8884097, 8, 0, /* 334: pointer.func */
            8884097, 8, 0, /* 337: pointer.func */
            8884097, 8, 0, /* 340: pointer.func */
            8884097, 8, 0, /* 343: pointer.func */
            8884097, 8, 0, /* 346: pointer.func */
            8884097, 8, 0, /* 349: pointer.func */
            1, 8, 1, /* 352: pointer.struct.dh_method */
            	357, 0,
            0, 72, 8, /* 357: struct.dh_method */
            	5, 0,
            	376, 8,
            	379, 16,
            	382, 24,
            	376, 32,
            	376, 40,
            	146, 56,
            	385, 64,
            8884097, 8, 0, /* 376: pointer.func */
            8884097, 8, 0, /* 379: pointer.func */
            8884097, 8, 0, /* 382: pointer.func */
            8884097, 8, 0, /* 385: pointer.func */
            1, 8, 1, /* 388: pointer.struct.ecdh_method */
            	393, 0,
            0, 32, 3, /* 393: struct.ecdh_method */
            	5, 0,
            	402, 8,
            	146, 24,
            8884097, 8, 0, /* 402: pointer.func */
            1, 8, 1, /* 405: pointer.struct.ecdsa_method */
            	410, 0,
            0, 48, 5, /* 410: struct.ecdsa_method */
            	5, 0,
            	423, 8,
            	426, 16,
            	429, 24,
            	146, 40,
            8884097, 8, 0, /* 423: pointer.func */
            8884097, 8, 0, /* 426: pointer.func */
            8884097, 8, 0, /* 429: pointer.func */
            1, 8, 1, /* 432: pointer.struct.rand_meth_st */
            	437, 0,
            0, 48, 6, /* 437: struct.rand_meth_st */
            	452, 0,
            	455, 8,
            	458, 16,
            	461, 24,
            	455, 32,
            	464, 40,
            8884097, 8, 0, /* 452: pointer.func */
            8884097, 8, 0, /* 455: pointer.func */
            8884097, 8, 0, /* 458: pointer.func */
            8884097, 8, 0, /* 461: pointer.func */
            8884097, 8, 0, /* 464: pointer.func */
            1, 8, 1, /* 467: pointer.struct.store_method_st */
            	472, 0,
            0, 0, 0, /* 472: struct.store_method_st */
            8884097, 8, 0, /* 475: pointer.func */
            8884097, 8, 0, /* 478: pointer.func */
            8884097, 8, 0, /* 481: pointer.func */
            8884097, 8, 0, /* 484: pointer.func */
            8884097, 8, 0, /* 487: pointer.func */
            8884097, 8, 0, /* 490: pointer.func */
            8884097, 8, 0, /* 493: pointer.func */
            8884097, 8, 0, /* 496: pointer.func */
            1, 8, 1, /* 499: pointer.struct.ENGINE_CMD_DEFN_st */
            	504, 0,
            0, 32, 2, /* 504: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 511: struct.crypto_ex_data_st */
            	516, 0,
            1, 8, 1, /* 516: pointer.struct.stack_st_void */
            	521, 0,
            0, 32, 1, /* 521: struct.stack_st_void */
            	526, 0,
            0, 32, 2, /* 526: struct.stack_st */
            	141, 8,
            	151, 24,
            1, 8, 1, /* 533: pointer.struct.engine_st */
            	195, 0,
            1, 8, 1, /* 538: pointer.struct.rsa_st */
            	543, 0,
            0, 168, 17, /* 543: struct.rsa_st */
            	580, 16,
            	635, 24,
            	640, 32,
            	640, 40,
            	640, 48,
            	640, 56,
            	640, 64,
            	640, 72,
            	640, 80,
            	640, 88,
            	657, 96,
            	679, 120,
            	679, 128,
            	679, 136,
            	146, 144,
            	693, 152,
            	693, 160,
            1, 8, 1, /* 580: pointer.struct.rsa_meth_st */
            	585, 0,
            0, 112, 13, /* 585: struct.rsa_meth_st */
            	5, 0,
            	614, 8,
            	614, 16,
            	614, 24,
            	614, 32,
            	617, 40,
            	620, 48,
            	623, 56,
            	623, 64,
            	146, 80,
            	626, 88,
            	629, 96,
            	632, 104,
            8884097, 8, 0, /* 614: pointer.func */
            8884097, 8, 0, /* 617: pointer.func */
            8884097, 8, 0, /* 620: pointer.func */
            8884097, 8, 0, /* 623: pointer.func */
            8884097, 8, 0, /* 626: pointer.func */
            8884097, 8, 0, /* 629: pointer.func */
            8884097, 8, 0, /* 632: pointer.func */
            1, 8, 1, /* 635: pointer.struct.engine_st */
            	195, 0,
            1, 8, 1, /* 640: pointer.struct.bignum_st */
            	645, 0,
            0, 24, 1, /* 645: struct.bignum_st */
            	650, 0,
            8884099, 8, 2, /* 650: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 16, 1, /* 657: struct.crypto_ex_data_st */
            	662, 0,
            1, 8, 1, /* 662: pointer.struct.stack_st_void */
            	667, 0,
            0, 32, 1, /* 667: struct.stack_st_void */
            	672, 0,
            0, 32, 2, /* 672: struct.stack_st */
            	141, 8,
            	151, 24,
            1, 8, 1, /* 679: pointer.struct.bn_mont_ctx_st */
            	684, 0,
            0, 96, 3, /* 684: struct.bn_mont_ctx_st */
            	645, 8,
            	645, 32,
            	645, 56,
            1, 8, 1, /* 693: pointer.struct.bn_blinding_st */
            	698, 0,
            0, 88, 7, /* 698: struct.bn_blinding_st */
            	715, 0,
            	715, 8,
            	715, 16,
            	715, 24,
            	732, 40,
            	740, 72,
            	754, 80,
            1, 8, 1, /* 715: pointer.struct.bignum_st */
            	720, 0,
            0, 24, 1, /* 720: struct.bignum_st */
            	725, 0,
            8884099, 8, 2, /* 725: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 16, 1, /* 732: struct.crypto_threadid_st */
            	737, 0,
            0, 8, 0, /* 737: pointer.void */
            1, 8, 1, /* 740: pointer.struct.bn_mont_ctx_st */
            	745, 0,
            0, 96, 3, /* 745: struct.bn_mont_ctx_st */
            	720, 8,
            	720, 32,
            	720, 56,
            8884097, 8, 0, /* 754: pointer.func */
            8884097, 8, 0, /* 757: pointer.func */
            8884097, 8, 0, /* 760: pointer.func */
            8884097, 8, 0, /* 763: pointer.func */
            1, 8, 1, /* 766: pointer.struct.env_md_st */
            	771, 0,
            0, 120, 8, /* 771: struct.env_md_st */
            	790, 24,
            	763, 32,
            	760, 40,
            	757, 48,
            	790, 56,
            	793, 64,
            	796, 72,
            	799, 112,
            8884097, 8, 0, /* 790: pointer.func */
            8884097, 8, 0, /* 793: pointer.func */
            8884097, 8, 0, /* 796: pointer.func */
            8884097, 8, 0, /* 799: pointer.func */
            1, 8, 1, /* 802: pointer.struct.dh_st */
            	53, 0,
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
            	854, 88,
            	868, 104,
            	890, 120,
            	941, 128,
            1, 8, 1, /* 837: pointer.struct.bignum_st */
            	842, 0,
            0, 24, 1, /* 842: struct.bignum_st */
            	847, 0,
            8884099, 8, 2, /* 847: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 854: pointer.struct.bn_mont_ctx_st */
            	859, 0,
            0, 96, 3, /* 859: struct.bn_mont_ctx_st */
            	842, 8,
            	842, 32,
            	842, 56,
            0, 16, 1, /* 868: struct.crypto_ex_data_st */
            	873, 0,
            1, 8, 1, /* 873: pointer.struct.stack_st_void */
            	878, 0,
            0, 32, 1, /* 878: struct.stack_st_void */
            	883, 0,
            0, 32, 2, /* 883: struct.stack_st */
            	141, 8,
            	151, 24,
            1, 8, 1, /* 890: pointer.struct.dsa_method */
            	895, 0,
            0, 96, 11, /* 895: struct.dsa_method */
            	5, 0,
            	920, 8,
            	923, 16,
            	926, 24,
            	929, 32,
            	932, 40,
            	935, 48,
            	935, 56,
            	146, 72,
            	938, 80,
            	935, 88,
            8884097, 8, 0, /* 920: pointer.func */
            8884097, 8, 0, /* 923: pointer.func */
            8884097, 8, 0, /* 926: pointer.func */
            8884097, 8, 0, /* 929: pointer.func */
            8884097, 8, 0, /* 932: pointer.func */
            8884097, 8, 0, /* 935: pointer.func */
            8884097, 8, 0, /* 938: pointer.func */
            1, 8, 1, /* 941: pointer.struct.engine_st */
            	195, 0,
            0, 8, 5, /* 946: union.unknown */
            	146, 0,
            	959, 0,
            	807, 0,
            	802, 0,
            	964, 0,
            1, 8, 1, /* 959: pointer.struct.rsa_st */
            	543, 0,
            1, 8, 1, /* 964: pointer.struct.ec_key_st */
            	969, 0,
            0, 56, 4, /* 969: struct.ec_key_st */
            	980, 8,
            	1428, 16,
            	1433, 24,
            	1450, 48,
            1, 8, 1, /* 980: pointer.struct.ec_group_st */
            	985, 0,
            0, 232, 12, /* 985: struct.ec_group_st */
            	1012, 0,
            	1184, 8,
            	1384, 16,
            	1384, 40,
            	111, 80,
            	1396, 96,
            	1384, 104,
            	1384, 152,
            	1384, 176,
            	737, 208,
            	737, 216,
            	1425, 224,
            1, 8, 1, /* 1012: pointer.struct.ec_method_st */
            	1017, 0,
            0, 304, 37, /* 1017: struct.ec_method_st */
            	1094, 8,
            	1097, 16,
            	1097, 24,
            	1100, 32,
            	1103, 40,
            	1106, 48,
            	1109, 56,
            	1112, 64,
            	1115, 72,
            	1118, 80,
            	1118, 88,
            	1121, 96,
            	1124, 104,
            	1127, 112,
            	1130, 120,
            	1133, 128,
            	1136, 136,
            	1139, 144,
            	1142, 152,
            	1145, 160,
            	1148, 168,
            	1151, 176,
            	1154, 184,
            	1157, 192,
            	1160, 200,
            	1163, 208,
            	1154, 216,
            	1166, 224,
            	1169, 232,
            	1172, 240,
            	1109, 248,
            	1175, 256,
            	1178, 264,
            	1175, 272,
            	1178, 280,
            	1178, 288,
            	1181, 296,
            8884097, 8, 0, /* 1094: pointer.func */
            8884097, 8, 0, /* 1097: pointer.func */
            8884097, 8, 0, /* 1100: pointer.func */
            8884097, 8, 0, /* 1103: pointer.func */
            8884097, 8, 0, /* 1106: pointer.func */
            8884097, 8, 0, /* 1109: pointer.func */
            8884097, 8, 0, /* 1112: pointer.func */
            8884097, 8, 0, /* 1115: pointer.func */
            8884097, 8, 0, /* 1118: pointer.func */
            8884097, 8, 0, /* 1121: pointer.func */
            8884097, 8, 0, /* 1124: pointer.func */
            8884097, 8, 0, /* 1127: pointer.func */
            8884097, 8, 0, /* 1130: pointer.func */
            8884097, 8, 0, /* 1133: pointer.func */
            8884097, 8, 0, /* 1136: pointer.func */
            8884097, 8, 0, /* 1139: pointer.func */
            8884097, 8, 0, /* 1142: pointer.func */
            8884097, 8, 0, /* 1145: pointer.func */
            8884097, 8, 0, /* 1148: pointer.func */
            8884097, 8, 0, /* 1151: pointer.func */
            8884097, 8, 0, /* 1154: pointer.func */
            8884097, 8, 0, /* 1157: pointer.func */
            8884097, 8, 0, /* 1160: pointer.func */
            8884097, 8, 0, /* 1163: pointer.func */
            8884097, 8, 0, /* 1166: pointer.func */
            8884097, 8, 0, /* 1169: pointer.func */
            8884097, 8, 0, /* 1172: pointer.func */
            8884097, 8, 0, /* 1175: pointer.func */
            8884097, 8, 0, /* 1178: pointer.func */
            8884097, 8, 0, /* 1181: pointer.func */
            1, 8, 1, /* 1184: pointer.struct.ec_point_st */
            	1189, 0,
            0, 88, 4, /* 1189: struct.ec_point_st */
            	1200, 0,
            	1372, 8,
            	1372, 32,
            	1372, 56,
            1, 8, 1, /* 1200: pointer.struct.ec_method_st */
            	1205, 0,
            0, 304, 37, /* 1205: struct.ec_method_st */
            	1282, 8,
            	1285, 16,
            	1285, 24,
            	1288, 32,
            	1291, 40,
            	1294, 48,
            	1297, 56,
            	1300, 64,
            	1303, 72,
            	1306, 80,
            	1306, 88,
            	1309, 96,
            	1312, 104,
            	1315, 112,
            	1318, 120,
            	1321, 128,
            	1324, 136,
            	1327, 144,
            	1330, 152,
            	1333, 160,
            	1336, 168,
            	1339, 176,
            	1342, 184,
            	1345, 192,
            	1348, 200,
            	1351, 208,
            	1342, 216,
            	1354, 224,
            	1357, 232,
            	1360, 240,
            	1297, 248,
            	1363, 256,
            	1366, 264,
            	1363, 272,
            	1366, 280,
            	1366, 288,
            	1369, 296,
            8884097, 8, 0, /* 1282: pointer.func */
            8884097, 8, 0, /* 1285: pointer.func */
            8884097, 8, 0, /* 1288: pointer.func */
            8884097, 8, 0, /* 1291: pointer.func */
            8884097, 8, 0, /* 1294: pointer.func */
            8884097, 8, 0, /* 1297: pointer.func */
            8884097, 8, 0, /* 1300: pointer.func */
            8884097, 8, 0, /* 1303: pointer.func */
            8884097, 8, 0, /* 1306: pointer.func */
            8884097, 8, 0, /* 1309: pointer.func */
            8884097, 8, 0, /* 1312: pointer.func */
            8884097, 8, 0, /* 1315: pointer.func */
            8884097, 8, 0, /* 1318: pointer.func */
            8884097, 8, 0, /* 1321: pointer.func */
            8884097, 8, 0, /* 1324: pointer.func */
            8884097, 8, 0, /* 1327: pointer.func */
            8884097, 8, 0, /* 1330: pointer.func */
            8884097, 8, 0, /* 1333: pointer.func */
            8884097, 8, 0, /* 1336: pointer.func */
            8884097, 8, 0, /* 1339: pointer.func */
            8884097, 8, 0, /* 1342: pointer.func */
            8884097, 8, 0, /* 1345: pointer.func */
            8884097, 8, 0, /* 1348: pointer.func */
            8884097, 8, 0, /* 1351: pointer.func */
            8884097, 8, 0, /* 1354: pointer.func */
            8884097, 8, 0, /* 1357: pointer.func */
            8884097, 8, 0, /* 1360: pointer.func */
            8884097, 8, 0, /* 1363: pointer.func */
            8884097, 8, 0, /* 1366: pointer.func */
            8884097, 8, 0, /* 1369: pointer.func */
            0, 24, 1, /* 1372: struct.bignum_st */
            	1377, 0,
            8884099, 8, 2, /* 1377: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 24, 1, /* 1384: struct.bignum_st */
            	1389, 0,
            8884099, 8, 2, /* 1389: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 1396: pointer.struct.ec_extra_data_st */
            	1401, 0,
            0, 40, 5, /* 1401: struct.ec_extra_data_st */
            	1414, 0,
            	737, 8,
            	1419, 16,
            	1422, 24,
            	1422, 32,
            1, 8, 1, /* 1414: pointer.struct.ec_extra_data_st */
            	1401, 0,
            8884097, 8, 0, /* 1419: pointer.func */
            8884097, 8, 0, /* 1422: pointer.func */
            8884097, 8, 0, /* 1425: pointer.func */
            1, 8, 1, /* 1428: pointer.struct.ec_point_st */
            	1189, 0,
            1, 8, 1, /* 1433: pointer.struct.bignum_st */
            	1438, 0,
            0, 24, 1, /* 1438: struct.bignum_st */
            	1443, 0,
            8884099, 8, 2, /* 1443: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 1450: pointer.struct.ec_extra_data_st */
            	1455, 0,
            0, 40, 5, /* 1455: struct.ec_extra_data_st */
            	1468, 0,
            	737, 8,
            	1419, 16,
            	1422, 24,
            	1422, 32,
            1, 8, 1, /* 1468: pointer.struct.ec_extra_data_st */
            	1455, 0,
            0, 56, 4, /* 1473: struct.evp_pkey_st */
            	1484, 16,
            	1585, 24,
            	946, 32,
            	1590, 48,
            1, 8, 1, /* 1484: pointer.struct.evp_pkey_asn1_method_st */
            	1489, 0,
            0, 208, 24, /* 1489: struct.evp_pkey_asn1_method_st */
            	146, 16,
            	146, 24,
            	1540, 32,
            	1543, 40,
            	1546, 48,
            	1549, 56,
            	1552, 64,
            	1555, 72,
            	1549, 80,
            	1558, 88,
            	1558, 96,
            	1561, 104,
            	1564, 112,
            	1558, 120,
            	1567, 128,
            	1546, 136,
            	1549, 144,
            	1570, 152,
            	1573, 160,
            	1576, 168,
            	1561, 176,
            	1564, 184,
            	1579, 192,
            	1582, 200,
            8884097, 8, 0, /* 1540: pointer.func */
            8884097, 8, 0, /* 1543: pointer.func */
            8884097, 8, 0, /* 1546: pointer.func */
            8884097, 8, 0, /* 1549: pointer.func */
            8884097, 8, 0, /* 1552: pointer.func */
            8884097, 8, 0, /* 1555: pointer.func */
            8884097, 8, 0, /* 1558: pointer.func */
            8884097, 8, 0, /* 1561: pointer.func */
            8884097, 8, 0, /* 1564: pointer.func */
            8884097, 8, 0, /* 1567: pointer.func */
            8884097, 8, 0, /* 1570: pointer.func */
            8884097, 8, 0, /* 1573: pointer.func */
            8884097, 8, 0, /* 1576: pointer.func */
            8884097, 8, 0, /* 1579: pointer.func */
            8884097, 8, 0, /* 1582: pointer.func */
            1, 8, 1, /* 1585: pointer.struct.engine_st */
            	195, 0,
            1, 8, 1, /* 1590: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1595, 0,
            0, 32, 2, /* 1595: struct.stack_st_fake_X509_ATTRIBUTE */
            	1602, 8,
            	151, 24,
            8884099, 8, 2, /* 1602: pointer_to_array_of_pointers_to_stack */
            	1609, 0,
            	33, 20,
            0, 8, 1, /* 1609: pointer.X509_ATTRIBUTE */
            	1614, 0,
            0, 0, 1, /* 1614: X509_ATTRIBUTE */
            	1619, 0,
            0, 24, 2, /* 1619: struct.x509_attributes_st */
            	1626, 0,
            	1645, 16,
            1, 8, 1, /* 1626: pointer.struct.asn1_object_st */
            	1631, 0,
            0, 40, 3, /* 1631: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1640, 24,
            1, 8, 1, /* 1640: pointer.unsigned char */
            	116, 0,
            0, 8, 3, /* 1645: union.unknown */
            	146, 0,
            	1654, 0,
            	1833, 0,
            1, 8, 1, /* 1654: pointer.struct.stack_st_ASN1_TYPE */
            	1659, 0,
            0, 32, 2, /* 1659: struct.stack_st_fake_ASN1_TYPE */
            	1666, 8,
            	151, 24,
            8884099, 8, 2, /* 1666: pointer_to_array_of_pointers_to_stack */
            	1673, 0,
            	33, 20,
            0, 8, 1, /* 1673: pointer.ASN1_TYPE */
            	1678, 0,
            0, 0, 1, /* 1678: ASN1_TYPE */
            	1683, 0,
            0, 16, 1, /* 1683: struct.asn1_type_st */
            	1688, 8,
            0, 8, 20, /* 1688: union.unknown */
            	146, 0,
            	1731, 0,
            	1741, 0,
            	1755, 0,
            	1760, 0,
            	1765, 0,
            	1770, 0,
            	1775, 0,
            	1780, 0,
            	1785, 0,
            	1790, 0,
            	1795, 0,
            	1800, 0,
            	1805, 0,
            	1810, 0,
            	1815, 0,
            	1820, 0,
            	1731, 0,
            	1731, 0,
            	1825, 0,
            1, 8, 1, /* 1731: pointer.struct.asn1_string_st */
            	1736, 0,
            0, 24, 1, /* 1736: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 1741: pointer.struct.asn1_object_st */
            	1746, 0,
            0, 40, 3, /* 1746: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1640, 24,
            1, 8, 1, /* 1755: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1760: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1765: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1770: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1775: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1780: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1785: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1790: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1795: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1800: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1805: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1810: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1815: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1820: pointer.struct.asn1_string_st */
            	1736, 0,
            1, 8, 1, /* 1825: pointer.struct.ASN1_VALUE_st */
            	1830, 0,
            0, 0, 0, /* 1830: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1833: pointer.struct.asn1_type_st */
            	1838, 0,
            0, 16, 1, /* 1838: struct.asn1_type_st */
            	1843, 8,
            0, 8, 20, /* 1843: union.unknown */
            	146, 0,
            	1886, 0,
            	1626, 0,
            	1896, 0,
            	1901, 0,
            	1906, 0,
            	1911, 0,
            	1916, 0,
            	1921, 0,
            	1926, 0,
            	1931, 0,
            	1936, 0,
            	1941, 0,
            	1946, 0,
            	1951, 0,
            	1956, 0,
            	1961, 0,
            	1886, 0,
            	1886, 0,
            	1966, 0,
            1, 8, 1, /* 1886: pointer.struct.asn1_string_st */
            	1891, 0,
            0, 24, 1, /* 1891: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 1896: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1901: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1906: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1911: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1916: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1921: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1926: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1931: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1936: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1941: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1946: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1951: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1956: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1961: pointer.struct.asn1_string_st */
            	1891, 0,
            1, 8, 1, /* 1966: pointer.struct.ASN1_VALUE_st */
            	1971, 0,
            0, 0, 0, /* 1971: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1974: pointer.struct.stack_st_X509_ALGOR */
            	1979, 0,
            0, 32, 2, /* 1979: struct.stack_st_fake_X509_ALGOR */
            	1986, 8,
            	151, 24,
            8884099, 8, 2, /* 1986: pointer_to_array_of_pointers_to_stack */
            	1993, 0,
            	33, 20,
            0, 8, 1, /* 1993: pointer.X509_ALGOR */
            	1998, 0,
            0, 0, 1, /* 1998: X509_ALGOR */
            	2003, 0,
            0, 16, 2, /* 2003: struct.X509_algor_st */
            	2010, 0,
            	2024, 8,
            1, 8, 1, /* 2010: pointer.struct.asn1_object_st */
            	2015, 0,
            0, 40, 3, /* 2015: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1640, 24,
            1, 8, 1, /* 2024: pointer.struct.asn1_type_st */
            	2029, 0,
            0, 16, 1, /* 2029: struct.asn1_type_st */
            	2034, 8,
            0, 8, 20, /* 2034: union.unknown */
            	146, 0,
            	2077, 0,
            	2010, 0,
            	2087, 0,
            	2092, 0,
            	2097, 0,
            	2102, 0,
            	2107, 0,
            	2112, 0,
            	2117, 0,
            	2122, 0,
            	2127, 0,
            	2132, 0,
            	2137, 0,
            	2142, 0,
            	2147, 0,
            	2152, 0,
            	2077, 0,
            	2077, 0,
            	1966, 0,
            1, 8, 1, /* 2077: pointer.struct.asn1_string_st */
            	2082, 0,
            0, 24, 1, /* 2082: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 2087: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2092: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2097: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2102: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2107: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2112: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2117: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2122: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2127: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2132: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2137: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2142: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2147: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2152: pointer.struct.asn1_string_st */
            	2082, 0,
            1, 8, 1, /* 2157: pointer.struct.asn1_string_st */
            	2162, 0,
            0, 24, 1, /* 2162: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 2167: pointer.struct.x509_cert_aux_st */
            	2172, 0,
            0, 40, 5, /* 2172: struct.x509_cert_aux_st */
            	2185, 0,
            	2185, 8,
            	2157, 16,
            	2223, 24,
            	1974, 32,
            1, 8, 1, /* 2185: pointer.struct.stack_st_ASN1_OBJECT */
            	2190, 0,
            0, 32, 2, /* 2190: struct.stack_st_fake_ASN1_OBJECT */
            	2197, 8,
            	151, 24,
            8884099, 8, 2, /* 2197: pointer_to_array_of_pointers_to_stack */
            	2204, 0,
            	33, 20,
            0, 8, 1, /* 2204: pointer.ASN1_OBJECT */
            	2209, 0,
            0, 0, 1, /* 2209: ASN1_OBJECT */
            	2214, 0,
            0, 40, 3, /* 2214: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1640, 24,
            1, 8, 1, /* 2223: pointer.struct.asn1_string_st */
            	2162, 0,
            0, 32, 1, /* 2228: struct.stack_st_void */
            	2233, 0,
            0, 32, 2, /* 2233: struct.stack_st */
            	141, 8,
            	151, 24,
            0, 24, 1, /* 2240: struct.ASN1_ENCODING_st */
            	111, 0,
            1, 8, 1, /* 2245: pointer.struct.stack_st_X509_EXTENSION */
            	2250, 0,
            0, 32, 2, /* 2250: struct.stack_st_fake_X509_EXTENSION */
            	2257, 8,
            	151, 24,
            8884099, 8, 2, /* 2257: pointer_to_array_of_pointers_to_stack */
            	2264, 0,
            	33, 20,
            0, 8, 1, /* 2264: pointer.X509_EXTENSION */
            	2269, 0,
            0, 0, 1, /* 2269: X509_EXTENSION */
            	2274, 0,
            0, 24, 2, /* 2274: struct.X509_extension_st */
            	2281, 0,
            	2295, 16,
            1, 8, 1, /* 2281: pointer.struct.asn1_object_st */
            	2286, 0,
            0, 40, 3, /* 2286: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1640, 24,
            1, 8, 1, /* 2295: pointer.struct.asn1_string_st */
            	2300, 0,
            0, 24, 1, /* 2300: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 2305: pointer.struct.X509_pubkey_st */
            	2310, 0,
            0, 24, 3, /* 2310: struct.X509_pubkey_st */
            	2319, 0,
            	2324, 8,
            	2334, 16,
            1, 8, 1, /* 2319: pointer.struct.X509_algor_st */
            	2003, 0,
            1, 8, 1, /* 2324: pointer.struct.asn1_string_st */
            	2329, 0,
            0, 24, 1, /* 2329: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 2334: pointer.struct.evp_pkey_st */
            	2339, 0,
            0, 56, 4, /* 2339: struct.evp_pkey_st */
            	2350, 16,
            	2355, 24,
            	2360, 32,
            	2393, 48,
            1, 8, 1, /* 2350: pointer.struct.evp_pkey_asn1_method_st */
            	1489, 0,
            1, 8, 1, /* 2355: pointer.struct.engine_st */
            	195, 0,
            0, 8, 5, /* 2360: union.unknown */
            	146, 0,
            	2373, 0,
            	2378, 0,
            	2383, 0,
            	2388, 0,
            1, 8, 1, /* 2373: pointer.struct.rsa_st */
            	543, 0,
            1, 8, 1, /* 2378: pointer.struct.dsa_st */
            	812, 0,
            1, 8, 1, /* 2383: pointer.struct.dh_st */
            	53, 0,
            1, 8, 1, /* 2388: pointer.struct.ec_key_st */
            	969, 0,
            1, 8, 1, /* 2393: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2398, 0,
            0, 32, 2, /* 2398: struct.stack_st_fake_X509_ATTRIBUTE */
            	2405, 8,
            	151, 24,
            8884099, 8, 2, /* 2405: pointer_to_array_of_pointers_to_stack */
            	2412, 0,
            	33, 20,
            0, 8, 1, /* 2412: pointer.X509_ATTRIBUTE */
            	1614, 0,
            1, 8, 1, /* 2417: pointer.struct.X509_val_st */
            	2422, 0,
            0, 16, 2, /* 2422: struct.X509_val_st */
            	2429, 0,
            	2429, 8,
            1, 8, 1, /* 2429: pointer.struct.asn1_string_st */
            	2162, 0,
            1, 8, 1, /* 2434: pointer.struct.buf_mem_st */
            	2439, 0,
            0, 24, 1, /* 2439: struct.buf_mem_st */
            	146, 8,
            1, 8, 1, /* 2444: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2449, 0,
            0, 32, 2, /* 2449: struct.stack_st_fake_X509_NAME_ENTRY */
            	2456, 8,
            	151, 24,
            8884099, 8, 2, /* 2456: pointer_to_array_of_pointers_to_stack */
            	2463, 0,
            	33, 20,
            0, 8, 1, /* 2463: pointer.X509_NAME_ENTRY */
            	2468, 0,
            0, 0, 1, /* 2468: X509_NAME_ENTRY */
            	2473, 0,
            0, 24, 2, /* 2473: struct.X509_name_entry_st */
            	2480, 0,
            	2494, 8,
            1, 8, 1, /* 2480: pointer.struct.asn1_object_st */
            	2485, 0,
            0, 40, 3, /* 2485: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1640, 24,
            1, 8, 1, /* 2494: pointer.struct.asn1_string_st */
            	2499, 0,
            0, 24, 1, /* 2499: struct.asn1_string_st */
            	111, 8,
            0, 24, 1, /* 2504: struct.ssl3_buf_freelist_st */
            	2509, 16,
            1, 8, 1, /* 2509: pointer.struct.ssl3_buf_freelist_entry_st */
            	2514, 0,
            0, 8, 1, /* 2514: struct.ssl3_buf_freelist_entry_st */
            	2509, 0,
            1, 8, 1, /* 2519: pointer.struct.X509_name_st */
            	2524, 0,
            0, 40, 3, /* 2524: struct.X509_name_st */
            	2444, 0,
            	2434, 16,
            	111, 24,
            1, 8, 1, /* 2533: pointer.struct.asn1_string_st */
            	2162, 0,
            1, 8, 1, /* 2538: pointer.struct.cert_st */
            	2543, 0,
            0, 296, 7, /* 2543: struct.cert_st */
            	2560, 0,
            	538, 48,
            	3876, 56,
            	48, 64,
            	45, 72,
            	3879, 80,
            	3884, 88,
            1, 8, 1, /* 2560: pointer.struct.cert_pkey_st */
            	2565, 0,
            0, 24, 3, /* 2565: struct.cert_pkey_st */
            	2574, 0,
            	3871, 8,
            	766, 16,
            1, 8, 1, /* 2574: pointer.struct.x509_st */
            	2579, 0,
            0, 184, 12, /* 2579: struct.x509_st */
            	2606, 0,
            	2636, 8,
            	2641, 16,
            	146, 32,
            	2646, 40,
            	2223, 104,
            	2656, 112,
            	2979, 120,
            	3396, 128,
            	3535, 136,
            	3559, 144,
            	2167, 176,
            1, 8, 1, /* 2606: pointer.struct.x509_cinf_st */
            	2611, 0,
            0, 104, 11, /* 2611: struct.x509_cinf_st */
            	2533, 0,
            	2533, 8,
            	2636, 16,
            	2519, 24,
            	2417, 32,
            	2519, 40,
            	2305, 48,
            	2641, 56,
            	2641, 64,
            	2245, 72,
            	2240, 80,
            1, 8, 1, /* 2636: pointer.struct.X509_algor_st */
            	2003, 0,
            1, 8, 1, /* 2641: pointer.struct.asn1_string_st */
            	2162, 0,
            0, 16, 1, /* 2646: struct.crypto_ex_data_st */
            	2651, 0,
            1, 8, 1, /* 2651: pointer.struct.stack_st_void */
            	2228, 0,
            1, 8, 1, /* 2656: pointer.struct.AUTHORITY_KEYID_st */
            	2661, 0,
            0, 24, 3, /* 2661: struct.AUTHORITY_KEYID_st */
            	2670, 0,
            	2680, 8,
            	2974, 16,
            1, 8, 1, /* 2670: pointer.struct.asn1_string_st */
            	2675, 0,
            0, 24, 1, /* 2675: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 2680: pointer.struct.stack_st_GENERAL_NAME */
            	2685, 0,
            0, 32, 2, /* 2685: struct.stack_st_fake_GENERAL_NAME */
            	2692, 8,
            	151, 24,
            8884099, 8, 2, /* 2692: pointer_to_array_of_pointers_to_stack */
            	2699, 0,
            	33, 20,
            0, 8, 1, /* 2699: pointer.GENERAL_NAME */
            	2704, 0,
            0, 0, 1, /* 2704: GENERAL_NAME */
            	2709, 0,
            0, 16, 1, /* 2709: struct.GENERAL_NAME_st */
            	2714, 8,
            0, 8, 15, /* 2714: union.unknown */
            	146, 0,
            	2747, 0,
            	2866, 0,
            	2866, 0,
            	2773, 0,
            	2914, 0,
            	2962, 0,
            	2866, 0,
            	2851, 0,
            	2759, 0,
            	2851, 0,
            	2914, 0,
            	2866, 0,
            	2759, 0,
            	2773, 0,
            1, 8, 1, /* 2747: pointer.struct.otherName_st */
            	2752, 0,
            0, 16, 2, /* 2752: struct.otherName_st */
            	2759, 0,
            	2773, 8,
            1, 8, 1, /* 2759: pointer.struct.asn1_object_st */
            	2764, 0,
            0, 40, 3, /* 2764: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1640, 24,
            1, 8, 1, /* 2773: pointer.struct.asn1_type_st */
            	2778, 0,
            0, 16, 1, /* 2778: struct.asn1_type_st */
            	2783, 8,
            0, 8, 20, /* 2783: union.unknown */
            	146, 0,
            	2826, 0,
            	2759, 0,
            	2836, 0,
            	2841, 0,
            	2846, 0,
            	2851, 0,
            	2856, 0,
            	2861, 0,
            	2866, 0,
            	2871, 0,
            	2876, 0,
            	2881, 0,
            	2886, 0,
            	2891, 0,
            	2896, 0,
            	2901, 0,
            	2826, 0,
            	2826, 0,
            	2906, 0,
            1, 8, 1, /* 2826: pointer.struct.asn1_string_st */
            	2831, 0,
            0, 24, 1, /* 2831: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 2836: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2841: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2846: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2851: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2856: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2861: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2866: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2871: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2876: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2881: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2886: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2891: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2896: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2901: pointer.struct.asn1_string_st */
            	2831, 0,
            1, 8, 1, /* 2906: pointer.struct.ASN1_VALUE_st */
            	2911, 0,
            0, 0, 0, /* 2911: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2914: pointer.struct.X509_name_st */
            	2919, 0,
            0, 40, 3, /* 2919: struct.X509_name_st */
            	2928, 0,
            	2952, 16,
            	111, 24,
            1, 8, 1, /* 2928: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2933, 0,
            0, 32, 2, /* 2933: struct.stack_st_fake_X509_NAME_ENTRY */
            	2940, 8,
            	151, 24,
            8884099, 8, 2, /* 2940: pointer_to_array_of_pointers_to_stack */
            	2947, 0,
            	33, 20,
            0, 8, 1, /* 2947: pointer.X509_NAME_ENTRY */
            	2468, 0,
            1, 8, 1, /* 2952: pointer.struct.buf_mem_st */
            	2957, 0,
            0, 24, 1, /* 2957: struct.buf_mem_st */
            	146, 8,
            1, 8, 1, /* 2962: pointer.struct.EDIPartyName_st */
            	2967, 0,
            0, 16, 2, /* 2967: struct.EDIPartyName_st */
            	2826, 0,
            	2826, 8,
            1, 8, 1, /* 2974: pointer.struct.asn1_string_st */
            	2675, 0,
            1, 8, 1, /* 2979: pointer.struct.X509_POLICY_CACHE_st */
            	2984, 0,
            0, 40, 2, /* 2984: struct.X509_POLICY_CACHE_st */
            	2991, 0,
            	3296, 8,
            1, 8, 1, /* 2991: pointer.struct.X509_POLICY_DATA_st */
            	2996, 0,
            0, 32, 3, /* 2996: struct.X509_POLICY_DATA_st */
            	3005, 8,
            	3019, 16,
            	3272, 24,
            1, 8, 1, /* 3005: pointer.struct.asn1_object_st */
            	3010, 0,
            0, 40, 3, /* 3010: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1640, 24,
            1, 8, 1, /* 3019: pointer.struct.stack_st_POLICYQUALINFO */
            	3024, 0,
            0, 32, 2, /* 3024: struct.stack_st_fake_POLICYQUALINFO */
            	3031, 8,
            	151, 24,
            8884099, 8, 2, /* 3031: pointer_to_array_of_pointers_to_stack */
            	3038, 0,
            	33, 20,
            0, 8, 1, /* 3038: pointer.POLICYQUALINFO */
            	3043, 0,
            0, 0, 1, /* 3043: POLICYQUALINFO */
            	3048, 0,
            0, 16, 2, /* 3048: struct.POLICYQUALINFO_st */
            	3055, 0,
            	3069, 8,
            1, 8, 1, /* 3055: pointer.struct.asn1_object_st */
            	3060, 0,
            0, 40, 3, /* 3060: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1640, 24,
            0, 8, 3, /* 3069: union.unknown */
            	3078, 0,
            	3088, 0,
            	3146, 0,
            1, 8, 1, /* 3078: pointer.struct.asn1_string_st */
            	3083, 0,
            0, 24, 1, /* 3083: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 3088: pointer.struct.USERNOTICE_st */
            	3093, 0,
            0, 16, 2, /* 3093: struct.USERNOTICE_st */
            	3100, 0,
            	3112, 8,
            1, 8, 1, /* 3100: pointer.struct.NOTICEREF_st */
            	3105, 0,
            0, 16, 2, /* 3105: struct.NOTICEREF_st */
            	3112, 0,
            	3117, 8,
            1, 8, 1, /* 3112: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3117: pointer.struct.stack_st_ASN1_INTEGER */
            	3122, 0,
            0, 32, 2, /* 3122: struct.stack_st_fake_ASN1_INTEGER */
            	3129, 8,
            	151, 24,
            8884099, 8, 2, /* 3129: pointer_to_array_of_pointers_to_stack */
            	3136, 0,
            	33, 20,
            0, 8, 1, /* 3136: pointer.ASN1_INTEGER */
            	3141, 0,
            0, 0, 1, /* 3141: ASN1_INTEGER */
            	2082, 0,
            1, 8, 1, /* 3146: pointer.struct.asn1_type_st */
            	3151, 0,
            0, 16, 1, /* 3151: struct.asn1_type_st */
            	3156, 8,
            0, 8, 20, /* 3156: union.unknown */
            	146, 0,
            	3112, 0,
            	3055, 0,
            	3199, 0,
            	3204, 0,
            	3209, 0,
            	3214, 0,
            	3219, 0,
            	3224, 0,
            	3078, 0,
            	3229, 0,
            	3234, 0,
            	3239, 0,
            	3244, 0,
            	3249, 0,
            	3254, 0,
            	3259, 0,
            	3112, 0,
            	3112, 0,
            	3264, 0,
            1, 8, 1, /* 3199: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3204: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3209: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3214: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3219: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3224: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3229: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3234: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3239: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3244: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3249: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3254: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3259: pointer.struct.asn1_string_st */
            	3083, 0,
            1, 8, 1, /* 3264: pointer.struct.ASN1_VALUE_st */
            	3269, 0,
            0, 0, 0, /* 3269: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3272: pointer.struct.stack_st_ASN1_OBJECT */
            	3277, 0,
            0, 32, 2, /* 3277: struct.stack_st_fake_ASN1_OBJECT */
            	3284, 8,
            	151, 24,
            8884099, 8, 2, /* 3284: pointer_to_array_of_pointers_to_stack */
            	3291, 0,
            	33, 20,
            0, 8, 1, /* 3291: pointer.ASN1_OBJECT */
            	2209, 0,
            1, 8, 1, /* 3296: pointer.struct.stack_st_X509_POLICY_DATA */
            	3301, 0,
            0, 32, 2, /* 3301: struct.stack_st_fake_X509_POLICY_DATA */
            	3308, 8,
            	151, 24,
            8884099, 8, 2, /* 3308: pointer_to_array_of_pointers_to_stack */
            	3315, 0,
            	33, 20,
            0, 8, 1, /* 3315: pointer.X509_POLICY_DATA */
            	3320, 0,
            0, 0, 1, /* 3320: X509_POLICY_DATA */
            	3325, 0,
            0, 32, 3, /* 3325: struct.X509_POLICY_DATA_st */
            	3334, 8,
            	3348, 16,
            	3372, 24,
            1, 8, 1, /* 3334: pointer.struct.asn1_object_st */
            	3339, 0,
            0, 40, 3, /* 3339: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1640, 24,
            1, 8, 1, /* 3348: pointer.struct.stack_st_POLICYQUALINFO */
            	3353, 0,
            0, 32, 2, /* 3353: struct.stack_st_fake_POLICYQUALINFO */
            	3360, 8,
            	151, 24,
            8884099, 8, 2, /* 3360: pointer_to_array_of_pointers_to_stack */
            	3367, 0,
            	33, 20,
            0, 8, 1, /* 3367: pointer.POLICYQUALINFO */
            	3043, 0,
            1, 8, 1, /* 3372: pointer.struct.stack_st_ASN1_OBJECT */
            	3377, 0,
            0, 32, 2, /* 3377: struct.stack_st_fake_ASN1_OBJECT */
            	3384, 8,
            	151, 24,
            8884099, 8, 2, /* 3384: pointer_to_array_of_pointers_to_stack */
            	3391, 0,
            	33, 20,
            0, 8, 1, /* 3391: pointer.ASN1_OBJECT */
            	2209, 0,
            1, 8, 1, /* 3396: pointer.struct.stack_st_DIST_POINT */
            	3401, 0,
            0, 32, 2, /* 3401: struct.stack_st_fake_DIST_POINT */
            	3408, 8,
            	151, 24,
            8884099, 8, 2, /* 3408: pointer_to_array_of_pointers_to_stack */
            	3415, 0,
            	33, 20,
            0, 8, 1, /* 3415: pointer.DIST_POINT */
            	3420, 0,
            0, 0, 1, /* 3420: DIST_POINT */
            	3425, 0,
            0, 32, 3, /* 3425: struct.DIST_POINT_st */
            	3434, 0,
            	3525, 8,
            	3453, 16,
            1, 8, 1, /* 3434: pointer.struct.DIST_POINT_NAME_st */
            	3439, 0,
            0, 24, 2, /* 3439: struct.DIST_POINT_NAME_st */
            	3446, 8,
            	3501, 16,
            0, 8, 2, /* 3446: union.unknown */
            	3453, 0,
            	3477, 0,
            1, 8, 1, /* 3453: pointer.struct.stack_st_GENERAL_NAME */
            	3458, 0,
            0, 32, 2, /* 3458: struct.stack_st_fake_GENERAL_NAME */
            	3465, 8,
            	151, 24,
            8884099, 8, 2, /* 3465: pointer_to_array_of_pointers_to_stack */
            	3472, 0,
            	33, 20,
            0, 8, 1, /* 3472: pointer.GENERAL_NAME */
            	2704, 0,
            1, 8, 1, /* 3477: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3482, 0,
            0, 32, 2, /* 3482: struct.stack_st_fake_X509_NAME_ENTRY */
            	3489, 8,
            	151, 24,
            8884099, 8, 2, /* 3489: pointer_to_array_of_pointers_to_stack */
            	3496, 0,
            	33, 20,
            0, 8, 1, /* 3496: pointer.X509_NAME_ENTRY */
            	2468, 0,
            1, 8, 1, /* 3501: pointer.struct.X509_name_st */
            	3506, 0,
            0, 40, 3, /* 3506: struct.X509_name_st */
            	3477, 0,
            	3515, 16,
            	111, 24,
            1, 8, 1, /* 3515: pointer.struct.buf_mem_st */
            	3520, 0,
            0, 24, 1, /* 3520: struct.buf_mem_st */
            	146, 8,
            1, 8, 1, /* 3525: pointer.struct.asn1_string_st */
            	3530, 0,
            0, 24, 1, /* 3530: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 3535: pointer.struct.stack_st_GENERAL_NAME */
            	3540, 0,
            0, 32, 2, /* 3540: struct.stack_st_fake_GENERAL_NAME */
            	3547, 8,
            	151, 24,
            8884099, 8, 2, /* 3547: pointer_to_array_of_pointers_to_stack */
            	3554, 0,
            	33, 20,
            0, 8, 1, /* 3554: pointer.GENERAL_NAME */
            	2704, 0,
            1, 8, 1, /* 3559: pointer.struct.NAME_CONSTRAINTS_st */
            	3564, 0,
            0, 16, 2, /* 3564: struct.NAME_CONSTRAINTS_st */
            	3571, 0,
            	3571, 8,
            1, 8, 1, /* 3571: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3576, 0,
            0, 32, 2, /* 3576: struct.stack_st_fake_GENERAL_SUBTREE */
            	3583, 8,
            	151, 24,
            8884099, 8, 2, /* 3583: pointer_to_array_of_pointers_to_stack */
            	3590, 0,
            	33, 20,
            0, 8, 1, /* 3590: pointer.GENERAL_SUBTREE */
            	3595, 0,
            0, 0, 1, /* 3595: GENERAL_SUBTREE */
            	3600, 0,
            0, 24, 3, /* 3600: struct.GENERAL_SUBTREE_st */
            	3609, 0,
            	3741, 8,
            	3741, 16,
            1, 8, 1, /* 3609: pointer.struct.GENERAL_NAME_st */
            	3614, 0,
            0, 16, 1, /* 3614: struct.GENERAL_NAME_st */
            	3619, 8,
            0, 8, 15, /* 3619: union.unknown */
            	146, 0,
            	3652, 0,
            	3771, 0,
            	3771, 0,
            	3678, 0,
            	3811, 0,
            	3859, 0,
            	3771, 0,
            	3756, 0,
            	3664, 0,
            	3756, 0,
            	3811, 0,
            	3771, 0,
            	3664, 0,
            	3678, 0,
            1, 8, 1, /* 3652: pointer.struct.otherName_st */
            	3657, 0,
            0, 16, 2, /* 3657: struct.otherName_st */
            	3664, 0,
            	3678, 8,
            1, 8, 1, /* 3664: pointer.struct.asn1_object_st */
            	3669, 0,
            0, 40, 3, /* 3669: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	1640, 24,
            1, 8, 1, /* 3678: pointer.struct.asn1_type_st */
            	3683, 0,
            0, 16, 1, /* 3683: struct.asn1_type_st */
            	3688, 8,
            0, 8, 20, /* 3688: union.unknown */
            	146, 0,
            	3731, 0,
            	3664, 0,
            	3741, 0,
            	3746, 0,
            	3751, 0,
            	3756, 0,
            	3761, 0,
            	3766, 0,
            	3771, 0,
            	3776, 0,
            	3781, 0,
            	3786, 0,
            	3791, 0,
            	3796, 0,
            	3801, 0,
            	3806, 0,
            	3731, 0,
            	3731, 0,
            	3264, 0,
            1, 8, 1, /* 3731: pointer.struct.asn1_string_st */
            	3736, 0,
            0, 24, 1, /* 3736: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 3741: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3746: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3751: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3756: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3761: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3766: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3771: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3776: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3781: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3786: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3791: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3796: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3801: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3806: pointer.struct.asn1_string_st */
            	3736, 0,
            1, 8, 1, /* 3811: pointer.struct.X509_name_st */
            	3816, 0,
            0, 40, 3, /* 3816: struct.X509_name_st */
            	3825, 0,
            	3849, 16,
            	111, 24,
            1, 8, 1, /* 3825: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3830, 0,
            0, 32, 2, /* 3830: struct.stack_st_fake_X509_NAME_ENTRY */
            	3837, 8,
            	151, 24,
            8884099, 8, 2, /* 3837: pointer_to_array_of_pointers_to_stack */
            	3844, 0,
            	33, 20,
            0, 8, 1, /* 3844: pointer.X509_NAME_ENTRY */
            	2468, 0,
            1, 8, 1, /* 3849: pointer.struct.buf_mem_st */
            	3854, 0,
            0, 24, 1, /* 3854: struct.buf_mem_st */
            	146, 8,
            1, 8, 1, /* 3859: pointer.struct.EDIPartyName_st */
            	3864, 0,
            0, 16, 2, /* 3864: struct.EDIPartyName_st */
            	3731, 0,
            	3731, 8,
            1, 8, 1, /* 3871: pointer.struct.evp_pkey_st */
            	1473, 0,
            8884097, 8, 0, /* 3876: pointer.func */
            1, 8, 1, /* 3879: pointer.struct.ec_key_st */
            	969, 0,
            8884097, 8, 0, /* 3884: pointer.func */
            0, 24, 1, /* 3887: struct.buf_mem_st */
            	146, 8,
            1, 8, 1, /* 3892: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3897, 0,
            0, 32, 2, /* 3897: struct.stack_st_fake_X509_NAME_ENTRY */
            	3904, 8,
            	151, 24,
            8884099, 8, 2, /* 3904: pointer_to_array_of_pointers_to_stack */
            	3911, 0,
            	33, 20,
            0, 8, 1, /* 3911: pointer.X509_NAME_ENTRY */
            	2468, 0,
            0, 0, 1, /* 3916: X509_NAME */
            	3921, 0,
            0, 40, 3, /* 3921: struct.X509_name_st */
            	3892, 0,
            	3930, 16,
            	111, 24,
            1, 8, 1, /* 3930: pointer.struct.buf_mem_st */
            	3887, 0,
            8884097, 8, 0, /* 3935: pointer.func */
            8884097, 8, 0, /* 3938: pointer.func */
            8884097, 8, 0, /* 3941: pointer.func */
            8884097, 8, 0, /* 3944: pointer.func */
            0, 64, 7, /* 3947: struct.comp_method_st */
            	5, 8,
            	3944, 16,
            	3941, 24,
            	3938, 32,
            	3938, 40,
            	3964, 48,
            	3964, 56,
            8884097, 8, 0, /* 3964: pointer.func */
            1, 8, 1, /* 3967: pointer.struct.comp_method_st */
            	3947, 0,
            1, 8, 1, /* 3972: pointer.struct.stack_st_X509 */
            	3977, 0,
            0, 32, 2, /* 3977: struct.stack_st_fake_X509 */
            	3984, 8,
            	151, 24,
            8884099, 8, 2, /* 3984: pointer_to_array_of_pointers_to_stack */
            	3991, 0,
            	33, 20,
            0, 8, 1, /* 3991: pointer.X509 */
            	3996, 0,
            0, 0, 1, /* 3996: X509 */
            	4001, 0,
            0, 184, 12, /* 4001: struct.x509_st */
            	4028, 0,
            	4068, 8,
            	4143, 16,
            	146, 32,
            	4177, 40,
            	4199, 104,
            	4204, 112,
            	4209, 120,
            	4214, 128,
            	4238, 136,
            	4262, 144,
            	4267, 176,
            1, 8, 1, /* 4028: pointer.struct.x509_cinf_st */
            	4033, 0,
            0, 104, 11, /* 4033: struct.x509_cinf_st */
            	4058, 0,
            	4058, 8,
            	4068, 16,
            	4073, 24,
            	4121, 32,
            	4073, 40,
            	4138, 48,
            	4143, 56,
            	4143, 64,
            	4148, 72,
            	4172, 80,
            1, 8, 1, /* 4058: pointer.struct.asn1_string_st */
            	4063, 0,
            0, 24, 1, /* 4063: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 4068: pointer.struct.X509_algor_st */
            	2003, 0,
            1, 8, 1, /* 4073: pointer.struct.X509_name_st */
            	4078, 0,
            0, 40, 3, /* 4078: struct.X509_name_st */
            	4087, 0,
            	4111, 16,
            	111, 24,
            1, 8, 1, /* 4087: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4092, 0,
            0, 32, 2, /* 4092: struct.stack_st_fake_X509_NAME_ENTRY */
            	4099, 8,
            	151, 24,
            8884099, 8, 2, /* 4099: pointer_to_array_of_pointers_to_stack */
            	4106, 0,
            	33, 20,
            0, 8, 1, /* 4106: pointer.X509_NAME_ENTRY */
            	2468, 0,
            1, 8, 1, /* 4111: pointer.struct.buf_mem_st */
            	4116, 0,
            0, 24, 1, /* 4116: struct.buf_mem_st */
            	146, 8,
            1, 8, 1, /* 4121: pointer.struct.X509_val_st */
            	4126, 0,
            0, 16, 2, /* 4126: struct.X509_val_st */
            	4133, 0,
            	4133, 8,
            1, 8, 1, /* 4133: pointer.struct.asn1_string_st */
            	4063, 0,
            1, 8, 1, /* 4138: pointer.struct.X509_pubkey_st */
            	2310, 0,
            1, 8, 1, /* 4143: pointer.struct.asn1_string_st */
            	4063, 0,
            1, 8, 1, /* 4148: pointer.struct.stack_st_X509_EXTENSION */
            	4153, 0,
            0, 32, 2, /* 4153: struct.stack_st_fake_X509_EXTENSION */
            	4160, 8,
            	151, 24,
            8884099, 8, 2, /* 4160: pointer_to_array_of_pointers_to_stack */
            	4167, 0,
            	33, 20,
            0, 8, 1, /* 4167: pointer.X509_EXTENSION */
            	2269, 0,
            0, 24, 1, /* 4172: struct.ASN1_ENCODING_st */
            	111, 0,
            0, 16, 1, /* 4177: struct.crypto_ex_data_st */
            	4182, 0,
            1, 8, 1, /* 4182: pointer.struct.stack_st_void */
            	4187, 0,
            0, 32, 1, /* 4187: struct.stack_st_void */
            	4192, 0,
            0, 32, 2, /* 4192: struct.stack_st */
            	141, 8,
            	151, 24,
            1, 8, 1, /* 4199: pointer.struct.asn1_string_st */
            	4063, 0,
            1, 8, 1, /* 4204: pointer.struct.AUTHORITY_KEYID_st */
            	2661, 0,
            1, 8, 1, /* 4209: pointer.struct.X509_POLICY_CACHE_st */
            	2984, 0,
            1, 8, 1, /* 4214: pointer.struct.stack_st_DIST_POINT */
            	4219, 0,
            0, 32, 2, /* 4219: struct.stack_st_fake_DIST_POINT */
            	4226, 8,
            	151, 24,
            8884099, 8, 2, /* 4226: pointer_to_array_of_pointers_to_stack */
            	4233, 0,
            	33, 20,
            0, 8, 1, /* 4233: pointer.DIST_POINT */
            	3420, 0,
            1, 8, 1, /* 4238: pointer.struct.stack_st_GENERAL_NAME */
            	4243, 0,
            0, 32, 2, /* 4243: struct.stack_st_fake_GENERAL_NAME */
            	4250, 8,
            	151, 24,
            8884099, 8, 2, /* 4250: pointer_to_array_of_pointers_to_stack */
            	4257, 0,
            	33, 20,
            0, 8, 1, /* 4257: pointer.GENERAL_NAME */
            	2704, 0,
            1, 8, 1, /* 4262: pointer.struct.NAME_CONSTRAINTS_st */
            	3564, 0,
            1, 8, 1, /* 4267: pointer.struct.x509_cert_aux_st */
            	4272, 0,
            0, 40, 5, /* 4272: struct.x509_cert_aux_st */
            	4285, 0,
            	4285, 8,
            	4309, 16,
            	4199, 24,
            	4314, 32,
            1, 8, 1, /* 4285: pointer.struct.stack_st_ASN1_OBJECT */
            	4290, 0,
            0, 32, 2, /* 4290: struct.stack_st_fake_ASN1_OBJECT */
            	4297, 8,
            	151, 24,
            8884099, 8, 2, /* 4297: pointer_to_array_of_pointers_to_stack */
            	4304, 0,
            	33, 20,
            0, 8, 1, /* 4304: pointer.ASN1_OBJECT */
            	2209, 0,
            1, 8, 1, /* 4309: pointer.struct.asn1_string_st */
            	4063, 0,
            1, 8, 1, /* 4314: pointer.struct.stack_st_X509_ALGOR */
            	4319, 0,
            0, 32, 2, /* 4319: struct.stack_st_fake_X509_ALGOR */
            	4326, 8,
            	151, 24,
            8884099, 8, 2, /* 4326: pointer_to_array_of_pointers_to_stack */
            	4333, 0,
            	33, 20,
            0, 8, 1, /* 4333: pointer.X509_ALGOR */
            	1998, 0,
            8884097, 8, 0, /* 4338: pointer.func */
            8884097, 8, 0, /* 4341: pointer.func */
            8884097, 8, 0, /* 4344: pointer.func */
            8884097, 8, 0, /* 4347: pointer.func */
            8884097, 8, 0, /* 4350: pointer.func */
            8884097, 8, 0, /* 4353: pointer.func */
            8884097, 8, 0, /* 4356: pointer.func */
            8884097, 8, 0, /* 4359: pointer.func */
            8884097, 8, 0, /* 4362: pointer.func */
            8884097, 8, 0, /* 4365: pointer.func */
            8884097, 8, 0, /* 4368: pointer.func */
            0, 88, 1, /* 4371: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4376: pointer.struct.ssl_cipher_st */
            	4371, 0,
            1, 8, 1, /* 4381: pointer.struct.asn1_string_st */
            	4386, 0,
            0, 24, 1, /* 4386: struct.asn1_string_st */
            	111, 8,
            0, 24, 1, /* 4391: struct.ASN1_ENCODING_st */
            	111, 0,
            1, 8, 1, /* 4396: pointer.struct.X509_val_st */
            	4401, 0,
            0, 16, 2, /* 4401: struct.X509_val_st */
            	4408, 0,
            	4408, 8,
            1, 8, 1, /* 4408: pointer.struct.asn1_string_st */
            	4386, 0,
            0, 24, 1, /* 4413: struct.buf_mem_st */
            	146, 8,
            0, 40, 3, /* 4418: struct.X509_name_st */
            	4427, 0,
            	4451, 16,
            	111, 24,
            1, 8, 1, /* 4427: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4432, 0,
            0, 32, 2, /* 4432: struct.stack_st_fake_X509_NAME_ENTRY */
            	4439, 8,
            	151, 24,
            8884099, 8, 2, /* 4439: pointer_to_array_of_pointers_to_stack */
            	4446, 0,
            	33, 20,
            0, 8, 1, /* 4446: pointer.X509_NAME_ENTRY */
            	2468, 0,
            1, 8, 1, /* 4451: pointer.struct.buf_mem_st */
            	4413, 0,
            1, 8, 1, /* 4456: pointer.struct.X509_algor_st */
            	2003, 0,
            1, 8, 1, /* 4461: pointer.struct.asn1_string_st */
            	4386, 0,
            0, 104, 11, /* 4466: struct.x509_cinf_st */
            	4461, 0,
            	4461, 8,
            	4456, 16,
            	4491, 24,
            	4396, 32,
            	4491, 40,
            	4496, 48,
            	4501, 56,
            	4501, 64,
            	4506, 72,
            	4391, 80,
            1, 8, 1, /* 4491: pointer.struct.X509_name_st */
            	4418, 0,
            1, 8, 1, /* 4496: pointer.struct.X509_pubkey_st */
            	2310, 0,
            1, 8, 1, /* 4501: pointer.struct.asn1_string_st */
            	4386, 0,
            1, 8, 1, /* 4506: pointer.struct.stack_st_X509_EXTENSION */
            	4511, 0,
            0, 32, 2, /* 4511: struct.stack_st_fake_X509_EXTENSION */
            	4518, 8,
            	151, 24,
            8884099, 8, 2, /* 4518: pointer_to_array_of_pointers_to_stack */
            	4525, 0,
            	33, 20,
            0, 8, 1, /* 4525: pointer.X509_EXTENSION */
            	2269, 0,
            1, 8, 1, /* 4530: pointer.struct.x509_cinf_st */
            	4466, 0,
            1, 8, 1, /* 4535: pointer.struct.x509_st */
            	4540, 0,
            0, 184, 12, /* 4540: struct.x509_st */
            	4530, 0,
            	4456, 8,
            	4501, 16,
            	146, 32,
            	4567, 40,
            	4589, 104,
            	2656, 112,
            	2979, 120,
            	3396, 128,
            	3535, 136,
            	3559, 144,
            	4594, 176,
            0, 16, 1, /* 4567: struct.crypto_ex_data_st */
            	4572, 0,
            1, 8, 1, /* 4572: pointer.struct.stack_st_void */
            	4577, 0,
            0, 32, 1, /* 4577: struct.stack_st_void */
            	4582, 0,
            0, 32, 2, /* 4582: struct.stack_st */
            	141, 8,
            	151, 24,
            1, 8, 1, /* 4589: pointer.struct.asn1_string_st */
            	4386, 0,
            1, 8, 1, /* 4594: pointer.struct.x509_cert_aux_st */
            	4599, 0,
            0, 40, 5, /* 4599: struct.x509_cert_aux_st */
            	4612, 0,
            	4612, 8,
            	4381, 16,
            	4589, 24,
            	4636, 32,
            1, 8, 1, /* 4612: pointer.struct.stack_st_ASN1_OBJECT */
            	4617, 0,
            0, 32, 2, /* 4617: struct.stack_st_fake_ASN1_OBJECT */
            	4624, 8,
            	151, 24,
            8884099, 8, 2, /* 4624: pointer_to_array_of_pointers_to_stack */
            	4631, 0,
            	33, 20,
            0, 8, 1, /* 4631: pointer.ASN1_OBJECT */
            	2209, 0,
            1, 8, 1, /* 4636: pointer.struct.stack_st_X509_ALGOR */
            	4641, 0,
            0, 32, 2, /* 4641: struct.stack_st_fake_X509_ALGOR */
            	4648, 8,
            	151, 24,
            8884099, 8, 2, /* 4648: pointer_to_array_of_pointers_to_stack */
            	4655, 0,
            	33, 20,
            0, 8, 1, /* 4655: pointer.X509_ALGOR */
            	1998, 0,
            1, 8, 1, /* 4660: pointer.struct.dh_st */
            	53, 0,
            8884097, 8, 0, /* 4665: pointer.func */
            8884097, 8, 0, /* 4668: pointer.func */
            0, 120, 8, /* 4671: struct.env_md_st */
            	4690, 24,
            	4693, 32,
            	4668, 40,
            	4696, 48,
            	4690, 56,
            	793, 64,
            	796, 72,
            	4665, 112,
            8884097, 8, 0, /* 4690: pointer.func */
            8884097, 8, 0, /* 4693: pointer.func */
            8884097, 8, 0, /* 4696: pointer.func */
            1, 8, 1, /* 4699: pointer.struct.dsa_st */
            	812, 0,
            1, 8, 1, /* 4704: pointer.struct.rsa_st */
            	543, 0,
            0, 8, 5, /* 4709: union.unknown */
            	146, 0,
            	4704, 0,
            	4699, 0,
            	4722, 0,
            	964, 0,
            1, 8, 1, /* 4722: pointer.struct.dh_st */
            	53, 0,
            0, 56, 4, /* 4727: struct.evp_pkey_st */
            	1484, 16,
            	1585, 24,
            	4709, 32,
            	4738, 48,
            1, 8, 1, /* 4738: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4743, 0,
            0, 32, 2, /* 4743: struct.stack_st_fake_X509_ATTRIBUTE */
            	4750, 8,
            	151, 24,
            8884099, 8, 2, /* 4750: pointer_to_array_of_pointers_to_stack */
            	4757, 0,
            	33, 20,
            0, 8, 1, /* 4757: pointer.X509_ATTRIBUTE */
            	1614, 0,
            1, 8, 1, /* 4762: pointer.struct.asn1_string_st */
            	4767, 0,
            0, 24, 1, /* 4767: struct.asn1_string_st */
            	111, 8,
            0, 40, 5, /* 4772: struct.x509_cert_aux_st */
            	4785, 0,
            	4785, 8,
            	4762, 16,
            	4809, 24,
            	4814, 32,
            1, 8, 1, /* 4785: pointer.struct.stack_st_ASN1_OBJECT */
            	4790, 0,
            0, 32, 2, /* 4790: struct.stack_st_fake_ASN1_OBJECT */
            	4797, 8,
            	151, 24,
            8884099, 8, 2, /* 4797: pointer_to_array_of_pointers_to_stack */
            	4804, 0,
            	33, 20,
            0, 8, 1, /* 4804: pointer.ASN1_OBJECT */
            	2209, 0,
            1, 8, 1, /* 4809: pointer.struct.asn1_string_st */
            	4767, 0,
            1, 8, 1, /* 4814: pointer.struct.stack_st_X509_ALGOR */
            	4819, 0,
            0, 32, 2, /* 4819: struct.stack_st_fake_X509_ALGOR */
            	4826, 8,
            	151, 24,
            8884099, 8, 2, /* 4826: pointer_to_array_of_pointers_to_stack */
            	4833, 0,
            	33, 20,
            0, 8, 1, /* 4833: pointer.X509_ALGOR */
            	1998, 0,
            0, 32, 2, /* 4838: struct.stack_st */
            	141, 8,
            	151, 24,
            0, 32, 1, /* 4845: struct.stack_st_void */
            	4838, 0,
            0, 16, 1, /* 4850: struct.crypto_ex_data_st */
            	4855, 0,
            1, 8, 1, /* 4855: pointer.struct.stack_st_void */
            	4845, 0,
            0, 24, 1, /* 4860: struct.ASN1_ENCODING_st */
            	111, 0,
            1, 8, 1, /* 4865: pointer.struct.stack_st_X509_EXTENSION */
            	4870, 0,
            0, 32, 2, /* 4870: struct.stack_st_fake_X509_EXTENSION */
            	4877, 8,
            	151, 24,
            8884099, 8, 2, /* 4877: pointer_to_array_of_pointers_to_stack */
            	4884, 0,
            	33, 20,
            0, 8, 1, /* 4884: pointer.X509_EXTENSION */
            	2269, 0,
            1, 8, 1, /* 4889: pointer.struct.asn1_string_st */
            	4767, 0,
            1, 8, 1, /* 4894: pointer.struct.X509_pubkey_st */
            	2310, 0,
            0, 16, 2, /* 4899: struct.X509_val_st */
            	4906, 0,
            	4906, 8,
            1, 8, 1, /* 4906: pointer.struct.asn1_string_st */
            	4767, 0,
            0, 24, 1, /* 4911: struct.buf_mem_st */
            	146, 8,
            1, 8, 1, /* 4916: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4921, 0,
            0, 32, 2, /* 4921: struct.stack_st_fake_X509_NAME_ENTRY */
            	4928, 8,
            	151, 24,
            8884099, 8, 2, /* 4928: pointer_to_array_of_pointers_to_stack */
            	4935, 0,
            	33, 20,
            0, 8, 1, /* 4935: pointer.X509_NAME_ENTRY */
            	2468, 0,
            1, 8, 1, /* 4940: pointer.struct.X509_algor_st */
            	2003, 0,
            1, 8, 1, /* 4945: pointer.struct.asn1_string_st */
            	4767, 0,
            1, 8, 1, /* 4950: pointer.struct.x509_cinf_st */
            	4955, 0,
            0, 104, 11, /* 4955: struct.x509_cinf_st */
            	4945, 0,
            	4945, 8,
            	4940, 16,
            	4980, 24,
            	4999, 32,
            	4980, 40,
            	4894, 48,
            	4889, 56,
            	4889, 64,
            	4865, 72,
            	4860, 80,
            1, 8, 1, /* 4980: pointer.struct.X509_name_st */
            	4985, 0,
            0, 40, 3, /* 4985: struct.X509_name_st */
            	4916, 0,
            	4994, 16,
            	111, 24,
            1, 8, 1, /* 4994: pointer.struct.buf_mem_st */
            	4911, 0,
            1, 8, 1, /* 4999: pointer.struct.X509_val_st */
            	4899, 0,
            1, 8, 1, /* 5004: pointer.struct.cert_pkey_st */
            	5009, 0,
            0, 24, 3, /* 5009: struct.cert_pkey_st */
            	5018, 0,
            	5055, 8,
            	5060, 16,
            1, 8, 1, /* 5018: pointer.struct.x509_st */
            	5023, 0,
            0, 184, 12, /* 5023: struct.x509_st */
            	4950, 0,
            	4940, 8,
            	4889, 16,
            	146, 32,
            	4850, 40,
            	4809, 104,
            	2656, 112,
            	2979, 120,
            	3396, 128,
            	3535, 136,
            	3559, 144,
            	5050, 176,
            1, 8, 1, /* 5050: pointer.struct.x509_cert_aux_st */
            	4772, 0,
            1, 8, 1, /* 5055: pointer.struct.evp_pkey_st */
            	4727, 0,
            1, 8, 1, /* 5060: pointer.struct.env_md_st */
            	4671, 0,
            1, 8, 1, /* 5065: pointer.struct.sess_cert_st */
            	5070, 0,
            0, 248, 5, /* 5070: struct.sess_cert_st */
            	5083, 0,
            	5004, 16,
            	5107, 216,
            	4660, 224,
            	3879, 232,
            1, 8, 1, /* 5083: pointer.struct.stack_st_X509 */
            	5088, 0,
            0, 32, 2, /* 5088: struct.stack_st_fake_X509 */
            	5095, 8,
            	151, 24,
            8884099, 8, 2, /* 5095: pointer_to_array_of_pointers_to_stack */
            	5102, 0,
            	33, 20,
            0, 8, 1, /* 5102: pointer.X509 */
            	3996, 0,
            1, 8, 1, /* 5107: pointer.struct.rsa_st */
            	543, 0,
            0, 352, 14, /* 5112: struct.ssl_session_st */
            	146, 144,
            	146, 152,
            	5065, 168,
            	4535, 176,
            	4376, 224,
            	5143, 240,
            	4567, 248,
            	5177, 264,
            	5177, 272,
            	146, 280,
            	111, 296,
            	111, 312,
            	111, 320,
            	146, 344,
            1, 8, 1, /* 5143: pointer.struct.stack_st_SSL_CIPHER */
            	5148, 0,
            0, 32, 2, /* 5148: struct.stack_st_fake_SSL_CIPHER */
            	5155, 8,
            	151, 24,
            8884099, 8, 2, /* 5155: pointer_to_array_of_pointers_to_stack */
            	5162, 0,
            	33, 20,
            0, 8, 1, /* 5162: pointer.SSL_CIPHER */
            	5167, 0,
            0, 0, 1, /* 5167: SSL_CIPHER */
            	5172, 0,
            0, 88, 1, /* 5172: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 5177: pointer.struct.ssl_session_st */
            	5112, 0,
            1, 8, 1, /* 5182: pointer.struct.lhash_node_st */
            	5187, 0,
            0, 24, 2, /* 5187: struct.lhash_node_st */
            	737, 0,
            	5182, 8,
            0, 176, 3, /* 5194: struct.lhash_st */
            	5203, 0,
            	151, 8,
            	5210, 16,
            8884099, 8, 2, /* 5203: pointer_to_array_of_pointers_to_stack */
            	5182, 0,
            	30, 28,
            8884097, 8, 0, /* 5210: pointer.func */
            1, 8, 1, /* 5213: pointer.struct.lhash_st */
            	5194, 0,
            8884097, 8, 0, /* 5218: pointer.func */
            8884097, 8, 0, /* 5221: pointer.func */
            8884097, 8, 0, /* 5224: pointer.func */
            8884097, 8, 0, /* 5227: pointer.func */
            1, 8, 1, /* 5230: pointer.struct.X509_VERIFY_PARAM_st */
            	5235, 0,
            0, 56, 2, /* 5235: struct.X509_VERIFY_PARAM_st */
            	146, 0,
            	4612, 48,
            8884097, 8, 0, /* 5242: pointer.func */
            8884097, 8, 0, /* 5245: pointer.func */
            8884097, 8, 0, /* 5248: pointer.func */
            1, 8, 1, /* 5251: pointer.struct.X509_VERIFY_PARAM_st */
            	5256, 0,
            0, 56, 2, /* 5256: struct.X509_VERIFY_PARAM_st */
            	146, 0,
            	5263, 48,
            1, 8, 1, /* 5263: pointer.struct.stack_st_ASN1_OBJECT */
            	5268, 0,
            0, 32, 2, /* 5268: struct.stack_st_fake_ASN1_OBJECT */
            	5275, 8,
            	151, 24,
            8884099, 8, 2, /* 5275: pointer_to_array_of_pointers_to_stack */
            	5282, 0,
            	33, 20,
            0, 8, 1, /* 5282: pointer.ASN1_OBJECT */
            	2209, 0,
            1, 8, 1, /* 5287: pointer.struct.stack_st_X509_LOOKUP */
            	5292, 0,
            0, 32, 2, /* 5292: struct.stack_st_fake_X509_LOOKUP */
            	5299, 8,
            	151, 24,
            8884099, 8, 2, /* 5299: pointer_to_array_of_pointers_to_stack */
            	5306, 0,
            	33, 20,
            0, 8, 1, /* 5306: pointer.X509_LOOKUP */
            	5311, 0,
            0, 0, 1, /* 5311: X509_LOOKUP */
            	5316, 0,
            0, 32, 3, /* 5316: struct.x509_lookup_st */
            	5325, 8,
            	146, 16,
            	5374, 24,
            1, 8, 1, /* 5325: pointer.struct.x509_lookup_method_st */
            	5330, 0,
            0, 80, 10, /* 5330: struct.x509_lookup_method_st */
            	5, 0,
            	5353, 8,
            	5356, 16,
            	5353, 24,
            	5353, 32,
            	5359, 40,
            	5362, 48,
            	5365, 56,
            	5368, 64,
            	5371, 72,
            8884097, 8, 0, /* 5353: pointer.func */
            8884097, 8, 0, /* 5356: pointer.func */
            8884097, 8, 0, /* 5359: pointer.func */
            8884097, 8, 0, /* 5362: pointer.func */
            8884097, 8, 0, /* 5365: pointer.func */
            8884097, 8, 0, /* 5368: pointer.func */
            8884097, 8, 0, /* 5371: pointer.func */
            1, 8, 1, /* 5374: pointer.struct.x509_store_st */
            	5379, 0,
            0, 144, 15, /* 5379: struct.x509_store_st */
            	5412, 8,
            	5287, 16,
            	5251, 24,
            	5248, 32,
            	5245, 40,
            	6192, 48,
            	6195, 56,
            	5248, 64,
            	6198, 72,
            	6201, 80,
            	6204, 88,
            	5242, 96,
            	6207, 104,
            	5248, 112,
            	5638, 120,
            1, 8, 1, /* 5412: pointer.struct.stack_st_X509_OBJECT */
            	5417, 0,
            0, 32, 2, /* 5417: struct.stack_st_fake_X509_OBJECT */
            	5424, 8,
            	151, 24,
            8884099, 8, 2, /* 5424: pointer_to_array_of_pointers_to_stack */
            	5431, 0,
            	33, 20,
            0, 8, 1, /* 5431: pointer.X509_OBJECT */
            	5436, 0,
            0, 0, 1, /* 5436: X509_OBJECT */
            	5441, 0,
            0, 16, 1, /* 5441: struct.x509_object_st */
            	5446, 8,
            0, 8, 4, /* 5446: union.unknown */
            	146, 0,
            	5457, 0,
            	5775, 0,
            	6109, 0,
            1, 8, 1, /* 5457: pointer.struct.x509_st */
            	5462, 0,
            0, 184, 12, /* 5462: struct.x509_st */
            	5489, 0,
            	5529, 8,
            	5604, 16,
            	146, 32,
            	5638, 40,
            	5660, 104,
            	5665, 112,
            	5670, 120,
            	5675, 128,
            	5699, 136,
            	5723, 144,
            	5728, 176,
            1, 8, 1, /* 5489: pointer.struct.x509_cinf_st */
            	5494, 0,
            0, 104, 11, /* 5494: struct.x509_cinf_st */
            	5519, 0,
            	5519, 8,
            	5529, 16,
            	5534, 24,
            	5582, 32,
            	5534, 40,
            	5599, 48,
            	5604, 56,
            	5604, 64,
            	5609, 72,
            	5633, 80,
            1, 8, 1, /* 5519: pointer.struct.asn1_string_st */
            	5524, 0,
            0, 24, 1, /* 5524: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 5529: pointer.struct.X509_algor_st */
            	2003, 0,
            1, 8, 1, /* 5534: pointer.struct.X509_name_st */
            	5539, 0,
            0, 40, 3, /* 5539: struct.X509_name_st */
            	5548, 0,
            	5572, 16,
            	111, 24,
            1, 8, 1, /* 5548: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5553, 0,
            0, 32, 2, /* 5553: struct.stack_st_fake_X509_NAME_ENTRY */
            	5560, 8,
            	151, 24,
            8884099, 8, 2, /* 5560: pointer_to_array_of_pointers_to_stack */
            	5567, 0,
            	33, 20,
            0, 8, 1, /* 5567: pointer.X509_NAME_ENTRY */
            	2468, 0,
            1, 8, 1, /* 5572: pointer.struct.buf_mem_st */
            	5577, 0,
            0, 24, 1, /* 5577: struct.buf_mem_st */
            	146, 8,
            1, 8, 1, /* 5582: pointer.struct.X509_val_st */
            	5587, 0,
            0, 16, 2, /* 5587: struct.X509_val_st */
            	5594, 0,
            	5594, 8,
            1, 8, 1, /* 5594: pointer.struct.asn1_string_st */
            	5524, 0,
            1, 8, 1, /* 5599: pointer.struct.X509_pubkey_st */
            	2310, 0,
            1, 8, 1, /* 5604: pointer.struct.asn1_string_st */
            	5524, 0,
            1, 8, 1, /* 5609: pointer.struct.stack_st_X509_EXTENSION */
            	5614, 0,
            0, 32, 2, /* 5614: struct.stack_st_fake_X509_EXTENSION */
            	5621, 8,
            	151, 24,
            8884099, 8, 2, /* 5621: pointer_to_array_of_pointers_to_stack */
            	5628, 0,
            	33, 20,
            0, 8, 1, /* 5628: pointer.X509_EXTENSION */
            	2269, 0,
            0, 24, 1, /* 5633: struct.ASN1_ENCODING_st */
            	111, 0,
            0, 16, 1, /* 5638: struct.crypto_ex_data_st */
            	5643, 0,
            1, 8, 1, /* 5643: pointer.struct.stack_st_void */
            	5648, 0,
            0, 32, 1, /* 5648: struct.stack_st_void */
            	5653, 0,
            0, 32, 2, /* 5653: struct.stack_st */
            	141, 8,
            	151, 24,
            1, 8, 1, /* 5660: pointer.struct.asn1_string_st */
            	5524, 0,
            1, 8, 1, /* 5665: pointer.struct.AUTHORITY_KEYID_st */
            	2661, 0,
            1, 8, 1, /* 5670: pointer.struct.X509_POLICY_CACHE_st */
            	2984, 0,
            1, 8, 1, /* 5675: pointer.struct.stack_st_DIST_POINT */
            	5680, 0,
            0, 32, 2, /* 5680: struct.stack_st_fake_DIST_POINT */
            	5687, 8,
            	151, 24,
            8884099, 8, 2, /* 5687: pointer_to_array_of_pointers_to_stack */
            	5694, 0,
            	33, 20,
            0, 8, 1, /* 5694: pointer.DIST_POINT */
            	3420, 0,
            1, 8, 1, /* 5699: pointer.struct.stack_st_GENERAL_NAME */
            	5704, 0,
            0, 32, 2, /* 5704: struct.stack_st_fake_GENERAL_NAME */
            	5711, 8,
            	151, 24,
            8884099, 8, 2, /* 5711: pointer_to_array_of_pointers_to_stack */
            	5718, 0,
            	33, 20,
            0, 8, 1, /* 5718: pointer.GENERAL_NAME */
            	2704, 0,
            1, 8, 1, /* 5723: pointer.struct.NAME_CONSTRAINTS_st */
            	3564, 0,
            1, 8, 1, /* 5728: pointer.struct.x509_cert_aux_st */
            	5733, 0,
            0, 40, 5, /* 5733: struct.x509_cert_aux_st */
            	5263, 0,
            	5263, 8,
            	5746, 16,
            	5660, 24,
            	5751, 32,
            1, 8, 1, /* 5746: pointer.struct.asn1_string_st */
            	5524, 0,
            1, 8, 1, /* 5751: pointer.struct.stack_st_X509_ALGOR */
            	5756, 0,
            0, 32, 2, /* 5756: struct.stack_st_fake_X509_ALGOR */
            	5763, 8,
            	151, 24,
            8884099, 8, 2, /* 5763: pointer_to_array_of_pointers_to_stack */
            	5770, 0,
            	33, 20,
            0, 8, 1, /* 5770: pointer.X509_ALGOR */
            	1998, 0,
            1, 8, 1, /* 5775: pointer.struct.X509_crl_st */
            	5780, 0,
            0, 120, 10, /* 5780: struct.X509_crl_st */
            	5803, 0,
            	5529, 8,
            	5604, 16,
            	5665, 32,
            	5930, 40,
            	5519, 56,
            	5519, 64,
            	6043, 96,
            	6084, 104,
            	737, 112,
            1, 8, 1, /* 5803: pointer.struct.X509_crl_info_st */
            	5808, 0,
            0, 80, 8, /* 5808: struct.X509_crl_info_st */
            	5519, 0,
            	5529, 8,
            	5534, 16,
            	5594, 24,
            	5594, 32,
            	5827, 40,
            	5609, 48,
            	5633, 56,
            1, 8, 1, /* 5827: pointer.struct.stack_st_X509_REVOKED */
            	5832, 0,
            0, 32, 2, /* 5832: struct.stack_st_fake_X509_REVOKED */
            	5839, 8,
            	151, 24,
            8884099, 8, 2, /* 5839: pointer_to_array_of_pointers_to_stack */
            	5846, 0,
            	33, 20,
            0, 8, 1, /* 5846: pointer.X509_REVOKED */
            	5851, 0,
            0, 0, 1, /* 5851: X509_REVOKED */
            	5856, 0,
            0, 40, 4, /* 5856: struct.x509_revoked_st */
            	5867, 0,
            	5877, 8,
            	5882, 16,
            	5906, 24,
            1, 8, 1, /* 5867: pointer.struct.asn1_string_st */
            	5872, 0,
            0, 24, 1, /* 5872: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 5877: pointer.struct.asn1_string_st */
            	5872, 0,
            1, 8, 1, /* 5882: pointer.struct.stack_st_X509_EXTENSION */
            	5887, 0,
            0, 32, 2, /* 5887: struct.stack_st_fake_X509_EXTENSION */
            	5894, 8,
            	151, 24,
            8884099, 8, 2, /* 5894: pointer_to_array_of_pointers_to_stack */
            	5901, 0,
            	33, 20,
            0, 8, 1, /* 5901: pointer.X509_EXTENSION */
            	2269, 0,
            1, 8, 1, /* 5906: pointer.struct.stack_st_GENERAL_NAME */
            	5911, 0,
            0, 32, 2, /* 5911: struct.stack_st_fake_GENERAL_NAME */
            	5918, 8,
            	151, 24,
            8884099, 8, 2, /* 5918: pointer_to_array_of_pointers_to_stack */
            	5925, 0,
            	33, 20,
            0, 8, 1, /* 5925: pointer.GENERAL_NAME */
            	2704, 0,
            1, 8, 1, /* 5930: pointer.struct.ISSUING_DIST_POINT_st */
            	5935, 0,
            0, 32, 2, /* 5935: struct.ISSUING_DIST_POINT_st */
            	5942, 0,
            	6033, 16,
            1, 8, 1, /* 5942: pointer.struct.DIST_POINT_NAME_st */
            	5947, 0,
            0, 24, 2, /* 5947: struct.DIST_POINT_NAME_st */
            	5954, 8,
            	6009, 16,
            0, 8, 2, /* 5954: union.unknown */
            	5961, 0,
            	5985, 0,
            1, 8, 1, /* 5961: pointer.struct.stack_st_GENERAL_NAME */
            	5966, 0,
            0, 32, 2, /* 5966: struct.stack_st_fake_GENERAL_NAME */
            	5973, 8,
            	151, 24,
            8884099, 8, 2, /* 5973: pointer_to_array_of_pointers_to_stack */
            	5980, 0,
            	33, 20,
            0, 8, 1, /* 5980: pointer.GENERAL_NAME */
            	2704, 0,
            1, 8, 1, /* 5985: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5990, 0,
            0, 32, 2, /* 5990: struct.stack_st_fake_X509_NAME_ENTRY */
            	5997, 8,
            	151, 24,
            8884099, 8, 2, /* 5997: pointer_to_array_of_pointers_to_stack */
            	6004, 0,
            	33, 20,
            0, 8, 1, /* 6004: pointer.X509_NAME_ENTRY */
            	2468, 0,
            1, 8, 1, /* 6009: pointer.struct.X509_name_st */
            	6014, 0,
            0, 40, 3, /* 6014: struct.X509_name_st */
            	5985, 0,
            	6023, 16,
            	111, 24,
            1, 8, 1, /* 6023: pointer.struct.buf_mem_st */
            	6028, 0,
            0, 24, 1, /* 6028: struct.buf_mem_st */
            	146, 8,
            1, 8, 1, /* 6033: pointer.struct.asn1_string_st */
            	6038, 0,
            0, 24, 1, /* 6038: struct.asn1_string_st */
            	111, 8,
            1, 8, 1, /* 6043: pointer.struct.stack_st_GENERAL_NAMES */
            	6048, 0,
            0, 32, 2, /* 6048: struct.stack_st_fake_GENERAL_NAMES */
            	6055, 8,
            	151, 24,
            8884099, 8, 2, /* 6055: pointer_to_array_of_pointers_to_stack */
            	6062, 0,
            	33, 20,
            0, 8, 1, /* 6062: pointer.GENERAL_NAMES */
            	6067, 0,
            0, 0, 1, /* 6067: GENERAL_NAMES */
            	6072, 0,
            0, 32, 1, /* 6072: struct.stack_st_GENERAL_NAME */
            	6077, 0,
            0, 32, 2, /* 6077: struct.stack_st */
            	141, 8,
            	151, 24,
            1, 8, 1, /* 6084: pointer.struct.x509_crl_method_st */
            	6089, 0,
            0, 40, 4, /* 6089: struct.x509_crl_method_st */
            	6100, 8,
            	6100, 16,
            	6103, 24,
            	6106, 32,
            8884097, 8, 0, /* 6100: pointer.func */
            8884097, 8, 0, /* 6103: pointer.func */
            8884097, 8, 0, /* 6106: pointer.func */
            1, 8, 1, /* 6109: pointer.struct.evp_pkey_st */
            	6114, 0,
            0, 56, 4, /* 6114: struct.evp_pkey_st */
            	6125, 16,
            	6130, 24,
            	6135, 32,
            	6168, 48,
            1, 8, 1, /* 6125: pointer.struct.evp_pkey_asn1_method_st */
            	1489, 0,
            1, 8, 1, /* 6130: pointer.struct.engine_st */
            	195, 0,
            0, 8, 5, /* 6135: union.unknown */
            	146, 0,
            	6148, 0,
            	6153, 0,
            	6158, 0,
            	6163, 0,
            1, 8, 1, /* 6148: pointer.struct.rsa_st */
            	543, 0,
            1, 8, 1, /* 6153: pointer.struct.dsa_st */
            	812, 0,
            1, 8, 1, /* 6158: pointer.struct.dh_st */
            	53, 0,
            1, 8, 1, /* 6163: pointer.struct.ec_key_st */
            	969, 0,
            1, 8, 1, /* 6168: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6173, 0,
            0, 32, 2, /* 6173: struct.stack_st_fake_X509_ATTRIBUTE */
            	6180, 8,
            	151, 24,
            8884099, 8, 2, /* 6180: pointer_to_array_of_pointers_to_stack */
            	6187, 0,
            	33, 20,
            0, 8, 1, /* 6187: pointer.X509_ATTRIBUTE */
            	1614, 0,
            8884097, 8, 0, /* 6192: pointer.func */
            8884097, 8, 0, /* 6195: pointer.func */
            8884097, 8, 0, /* 6198: pointer.func */
            8884097, 8, 0, /* 6201: pointer.func */
            8884097, 8, 0, /* 6204: pointer.func */
            8884097, 8, 0, /* 6207: pointer.func */
            1, 8, 1, /* 6210: pointer.struct.stack_st_X509_LOOKUP */
            	6215, 0,
            0, 32, 2, /* 6215: struct.stack_st_fake_X509_LOOKUP */
            	6222, 8,
            	151, 24,
            8884099, 8, 2, /* 6222: pointer_to_array_of_pointers_to_stack */
            	6229, 0,
            	33, 20,
            0, 8, 1, /* 6229: pointer.X509_LOOKUP */
            	5311, 0,
            0, 24, 2, /* 6234: struct.ssl_comp_st */
            	5, 8,
            	3967, 16,
            8884097, 8, 0, /* 6241: pointer.func */
            8884097, 8, 0, /* 6244: pointer.func */
            8884097, 8, 0, /* 6247: pointer.func */
            8884097, 8, 0, /* 6250: pointer.func */
            1, 8, 1, /* 6253: pointer.struct.stack_st_X509_OBJECT */
            	6258, 0,
            0, 32, 2, /* 6258: struct.stack_st_fake_X509_OBJECT */
            	6265, 8,
            	151, 24,
            8884099, 8, 2, /* 6265: pointer_to_array_of_pointers_to_stack */
            	6272, 0,
            	33, 20,
            0, 8, 1, /* 6272: pointer.X509_OBJECT */
            	5436, 0,
            1, 8, 1, /* 6277: pointer.struct.ssl3_buf_freelist_st */
            	2504, 0,
            8884097, 8, 0, /* 6282: pointer.func */
            1, 8, 1, /* 6285: pointer.struct.ssl_method_st */
            	6290, 0,
            0, 232, 28, /* 6290: struct.ssl_method_st */
            	6349, 8,
            	6352, 16,
            	6352, 24,
            	6349, 32,
            	6349, 40,
            	6355, 48,
            	6355, 56,
            	6358, 64,
            	6349, 72,
            	6349, 80,
            	6349, 88,
            	6361, 96,
            	6247, 104,
            	6364, 112,
            	6349, 120,
            	6367, 128,
            	6370, 136,
            	6373, 144,
            	6241, 152,
            	6376, 160,
            	464, 168,
            	6379, 176,
            	6382, 184,
            	3964, 192,
            	6385, 200,
            	464, 208,
            	6439, 216,
            	6442, 224,
            8884097, 8, 0, /* 6349: pointer.func */
            8884097, 8, 0, /* 6352: pointer.func */
            8884097, 8, 0, /* 6355: pointer.func */
            8884097, 8, 0, /* 6358: pointer.func */
            8884097, 8, 0, /* 6361: pointer.func */
            8884097, 8, 0, /* 6364: pointer.func */
            8884097, 8, 0, /* 6367: pointer.func */
            8884097, 8, 0, /* 6370: pointer.func */
            8884097, 8, 0, /* 6373: pointer.func */
            8884097, 8, 0, /* 6376: pointer.func */
            8884097, 8, 0, /* 6379: pointer.func */
            8884097, 8, 0, /* 6382: pointer.func */
            1, 8, 1, /* 6385: pointer.struct.ssl3_enc_method */
            	6390, 0,
            0, 112, 11, /* 6390: struct.ssl3_enc_method */
            	6415, 0,
            	6418, 8,
            	6421, 16,
            	6424, 24,
            	6415, 32,
            	6427, 40,
            	6430, 56,
            	5, 64,
            	5, 80,
            	6433, 96,
            	6436, 104,
            8884097, 8, 0, /* 6415: pointer.func */
            8884097, 8, 0, /* 6418: pointer.func */
            8884097, 8, 0, /* 6421: pointer.func */
            8884097, 8, 0, /* 6424: pointer.func */
            8884097, 8, 0, /* 6427: pointer.func */
            8884097, 8, 0, /* 6430: pointer.func */
            8884097, 8, 0, /* 6433: pointer.func */
            8884097, 8, 0, /* 6436: pointer.func */
            8884097, 8, 0, /* 6439: pointer.func */
            8884097, 8, 0, /* 6442: pointer.func */
            8884099, 8, 2, /* 6445: pointer_to_array_of_pointers_to_stack */
            	6452, 0,
            	33, 20,
            0, 8, 1, /* 6452: pointer.SRTP_PROTECTION_PROFILE */
            	10, 0,
            1, 8, 1, /* 6457: pointer.struct.stack_st_X509_NAME */
            	6462, 0,
            0, 32, 2, /* 6462: struct.stack_st_fake_X509_NAME */
            	6469, 8,
            	151, 24,
            8884099, 8, 2, /* 6469: pointer_to_array_of_pointers_to_stack */
            	6476, 0,
            	33, 20,
            0, 8, 1, /* 6476: pointer.X509_NAME */
            	3916, 0,
            0, 0, 1, /* 6481: SSL_COMP */
            	6234, 0,
            0, 1, 0, /* 6486: char */
            1, 8, 1, /* 6489: pointer.struct.ssl_ctx_st */
            	6494, 0,
            0, 736, 50, /* 6494: struct.ssl_ctx_st */
            	6285, 0,
            	5143, 8,
            	5143, 16,
            	6597, 24,
            	5213, 32,
            	5177, 48,
            	5177, 56,
            	6647, 80,
            	4368, 88,
            	4365, 96,
            	4362, 152,
            	737, 160,
            	4359, 168,
            	737, 176,
            	4356, 184,
            	4353, 192,
            	4350, 200,
            	4567, 208,
            	6650, 224,
            	6650, 232,
            	6650, 240,
            	3972, 248,
            	6674, 256,
            	3935, 264,
            	6457, 272,
            	2538, 304,
            	6698, 320,
            	737, 328,
            	6635, 376,
            	6701, 384,
            	5230, 392,
            	1585, 408,
            	6282, 416,
            	737, 424,
            	42, 480,
            	6704, 488,
            	737, 496,
            	6707, 504,
            	737, 512,
            	146, 520,
            	6710, 528,
            	39, 536,
            	6277, 552,
            	6277, 560,
            	6713, 568,
            	15, 696,
            	737, 704,
            	6749, 712,
            	737, 720,
            	6752, 728,
            1, 8, 1, /* 6597: pointer.struct.x509_store_st */
            	6602, 0,
            0, 144, 15, /* 6602: struct.x509_store_st */
            	6253, 8,
            	6210, 16,
            	5230, 24,
            	6244, 32,
            	6635, 40,
            	5227, 48,
            	6638, 56,
            	6244, 64,
            	5224, 72,
            	5221, 80,
            	6641, 88,
            	6644, 96,
            	5218, 104,
            	6244, 112,
            	4567, 120,
            8884097, 8, 0, /* 6635: pointer.func */
            8884097, 8, 0, /* 6638: pointer.func */
            8884097, 8, 0, /* 6641: pointer.func */
            8884097, 8, 0, /* 6644: pointer.func */
            8884097, 8, 0, /* 6647: pointer.func */
            1, 8, 1, /* 6650: pointer.struct.env_md_st */
            	6655, 0,
            0, 120, 8, /* 6655: struct.env_md_st */
            	4347, 24,
            	4344, 32,
            	6250, 40,
            	4341, 48,
            	4347, 56,
            	793, 64,
            	796, 72,
            	4338, 112,
            1, 8, 1, /* 6674: pointer.struct.stack_st_SSL_COMP */
            	6679, 0,
            0, 32, 2, /* 6679: struct.stack_st_fake_SSL_COMP */
            	6686, 8,
            	151, 24,
            8884099, 8, 2, /* 6686: pointer_to_array_of_pointers_to_stack */
            	6693, 0,
            	33, 20,
            0, 8, 1, /* 6693: pointer.SSL_COMP */
            	6481, 0,
            8884097, 8, 0, /* 6698: pointer.func */
            8884097, 8, 0, /* 6701: pointer.func */
            8884097, 8, 0, /* 6704: pointer.func */
            8884097, 8, 0, /* 6707: pointer.func */
            8884097, 8, 0, /* 6710: pointer.func */
            0, 128, 14, /* 6713: struct.srp_ctx_st */
            	737, 0,
            	6282, 8,
            	6704, 16,
            	36, 24,
            	146, 32,
            	6744, 40,
            	6744, 48,
            	6744, 56,
            	6744, 64,
            	6744, 72,
            	6744, 80,
            	6744, 88,
            	6744, 96,
            	146, 104,
            1, 8, 1, /* 6744: pointer.struct.bignum_st */
            	18, 0,
            8884097, 8, 0, /* 6749: pointer.func */
            1, 8, 1, /* 6752: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6757, 0,
            0, 32, 2, /* 6757: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6445, 8,
            	151, 24,
        },
        .arg_entity_index = { 6489, 5, 33, },
        .ret_entity_index = 33,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *,const char *,int);
    orig_SSL_CTX_use_PrivateKey_file = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey_file");
    *new_ret_ptr = (*orig_SSL_CTX_use_PrivateKey_file)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

