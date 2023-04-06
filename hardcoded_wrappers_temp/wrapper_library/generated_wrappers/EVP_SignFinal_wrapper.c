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

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d);

int EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_SignFinal called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    else {
        int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
        orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
        return orig_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    }
}

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5, 0,
            0, 32, 2, /* 5: struct.stack_st_fake_X509_ATTRIBUTE */
            	12, 8,
            	264, 24,
            8884099, 8, 2, /* 12: pointer_to_array_of_pointers_to_stack */
            	19, 0,
            	261, 20,
            0, 8, 1, /* 19: pointer.X509_ATTRIBUTE */
            	24, 0,
            0, 0, 1, /* 24: X509_ATTRIBUTE */
            	29, 0,
            0, 24, 2, /* 29: struct.x509_attributes_st */
            	36, 0,
            	63, 16,
            1, 8, 1, /* 36: pointer.struct.asn1_object_st */
            	41, 0,
            0, 40, 3, /* 41: struct.asn1_object_st */
            	50, 0,
            	50, 8,
            	55, 24,
            1, 8, 1, /* 50: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 55: pointer.unsigned char */
            	60, 0,
            0, 1, 0, /* 60: unsigned char */
            0, 8, 3, /* 63: union.unknown */
            	72, 0,
            	77, 0,
            	267, 0,
            1, 8, 1, /* 72: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 77: pointer.struct.stack_st_ASN1_TYPE */
            	82, 0,
            0, 32, 2, /* 82: struct.stack_st_fake_ASN1_TYPE */
            	89, 8,
            	264, 24,
            8884099, 8, 2, /* 89: pointer_to_array_of_pointers_to_stack */
            	96, 0,
            	261, 20,
            0, 8, 1, /* 96: pointer.ASN1_TYPE */
            	101, 0,
            0, 0, 1, /* 101: ASN1_TYPE */
            	106, 0,
            0, 16, 1, /* 106: struct.asn1_type_st */
            	111, 8,
            0, 8, 20, /* 111: union.unknown */
            	72, 0,
            	154, 0,
            	169, 0,
            	183, 0,
            	188, 0,
            	193, 0,
            	198, 0,
            	203, 0,
            	208, 0,
            	213, 0,
            	218, 0,
            	223, 0,
            	228, 0,
            	233, 0,
            	238, 0,
            	243, 0,
            	248, 0,
            	154, 0,
            	154, 0,
            	253, 0,
            1, 8, 1, /* 154: pointer.struct.asn1_string_st */
            	159, 0,
            0, 24, 1, /* 159: struct.asn1_string_st */
            	164, 8,
            1, 8, 1, /* 164: pointer.unsigned char */
            	60, 0,
            1, 8, 1, /* 169: pointer.struct.asn1_object_st */
            	174, 0,
            0, 40, 3, /* 174: struct.asn1_object_st */
            	50, 0,
            	50, 8,
            	55, 24,
            1, 8, 1, /* 183: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 188: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 193: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 198: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 203: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 208: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 213: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 218: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 223: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 228: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 233: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 238: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 243: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 248: pointer.struct.asn1_string_st */
            	159, 0,
            1, 8, 1, /* 253: pointer.struct.ASN1_VALUE_st */
            	258, 0,
            0, 0, 0, /* 258: struct.ASN1_VALUE_st */
            0, 4, 0, /* 261: int */
            8884097, 8, 0, /* 264: pointer.func */
            1, 8, 1, /* 267: pointer.struct.asn1_type_st */
            	272, 0,
            0, 16, 1, /* 272: struct.asn1_type_st */
            	277, 8,
            0, 8, 20, /* 277: union.unknown */
            	72, 0,
            	320, 0,
            	36, 0,
            	330, 0,
            	335, 0,
            	340, 0,
            	345, 0,
            	350, 0,
            	355, 0,
            	360, 0,
            	365, 0,
            	370, 0,
            	375, 0,
            	380, 0,
            	385, 0,
            	390, 0,
            	395, 0,
            	320, 0,
            	320, 0,
            	400, 0,
            1, 8, 1, /* 320: pointer.struct.asn1_string_st */
            	325, 0,
            0, 24, 1, /* 325: struct.asn1_string_st */
            	164, 8,
            1, 8, 1, /* 330: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 335: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 340: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 345: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 350: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 355: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 360: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 365: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 370: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 375: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 380: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 385: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 390: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 395: pointer.struct.asn1_string_st */
            	325, 0,
            1, 8, 1, /* 400: pointer.struct.ASN1_VALUE_st */
            	405, 0,
            0, 0, 0, /* 405: struct.ASN1_VALUE_st */
            1, 8, 1, /* 408: pointer.struct.dsa_st */
            	413, 0,
            0, 136, 11, /* 413: struct.dsa_st */
            	438, 24,
            	438, 32,
            	438, 40,
            	438, 48,
            	438, 56,
            	438, 64,
            	438, 72,
            	456, 88,
            	470, 104,
            	497, 120,
            	548, 128,
            1, 8, 1, /* 438: pointer.struct.bignum_st */
            	443, 0,
            0, 24, 1, /* 443: struct.bignum_st */
            	448, 0,
            1, 8, 1, /* 448: pointer.unsigned int */
            	453, 0,
            0, 4, 0, /* 453: unsigned int */
            1, 8, 1, /* 456: pointer.struct.bn_mont_ctx_st */
            	461, 0,
            0, 96, 3, /* 461: struct.bn_mont_ctx_st */
            	443, 8,
            	443, 32,
            	443, 56,
            0, 16, 1, /* 470: struct.crypto_ex_data_st */
            	475, 0,
            1, 8, 1, /* 475: pointer.struct.stack_st_void */
            	480, 0,
            0, 32, 1, /* 480: struct.stack_st_void */
            	485, 0,
            0, 32, 2, /* 485: struct.stack_st */
            	492, 8,
            	264, 24,
            1, 8, 1, /* 492: pointer.pointer.char */
            	72, 0,
            1, 8, 1, /* 497: pointer.struct.dsa_method */
            	502, 0,
            0, 96, 11, /* 502: struct.dsa_method */
            	50, 0,
            	527, 8,
            	530, 16,
            	533, 24,
            	536, 32,
            	539, 40,
            	542, 48,
            	542, 56,
            	72, 72,
            	545, 80,
            	542, 88,
            8884097, 8, 0, /* 527: pointer.func */
            8884097, 8, 0, /* 530: pointer.func */
            8884097, 8, 0, /* 533: pointer.func */
            8884097, 8, 0, /* 536: pointer.func */
            8884097, 8, 0, /* 539: pointer.func */
            8884097, 8, 0, /* 542: pointer.func */
            8884097, 8, 0, /* 545: pointer.func */
            1, 8, 1, /* 548: pointer.struct.engine_st */
            	553, 0,
            0, 216, 24, /* 553: struct.engine_st */
            	50, 0,
            	50, 8,
            	604, 16,
            	659, 24,
            	710, 32,
            	746, 40,
            	763, 48,
            	790, 56,
            	825, 64,
            	833, 72,
            	836, 80,
            	839, 88,
            	842, 96,
            	845, 104,
            	845, 112,
            	845, 120,
            	848, 128,
            	851, 136,
            	851, 144,
            	854, 152,
            	857, 160,
            	869, 184,
            	891, 200,
            	891, 208,
            1, 8, 1, /* 604: pointer.struct.rsa_meth_st */
            	609, 0,
            0, 112, 13, /* 609: struct.rsa_meth_st */
            	50, 0,
            	638, 8,
            	638, 16,
            	638, 24,
            	638, 32,
            	641, 40,
            	644, 48,
            	647, 56,
            	647, 64,
            	72, 80,
            	650, 88,
            	653, 96,
            	656, 104,
            8884097, 8, 0, /* 638: pointer.func */
            8884097, 8, 0, /* 641: pointer.func */
            8884097, 8, 0, /* 644: pointer.func */
            8884097, 8, 0, /* 647: pointer.func */
            8884097, 8, 0, /* 650: pointer.func */
            8884097, 8, 0, /* 653: pointer.func */
            8884097, 8, 0, /* 656: pointer.func */
            1, 8, 1, /* 659: pointer.struct.dsa_method */
            	664, 0,
            0, 96, 11, /* 664: struct.dsa_method */
            	50, 0,
            	689, 8,
            	692, 16,
            	695, 24,
            	698, 32,
            	701, 40,
            	704, 48,
            	704, 56,
            	72, 72,
            	707, 80,
            	704, 88,
            8884097, 8, 0, /* 689: pointer.func */
            8884097, 8, 0, /* 692: pointer.func */
            8884097, 8, 0, /* 695: pointer.func */
            8884097, 8, 0, /* 698: pointer.func */
            8884097, 8, 0, /* 701: pointer.func */
            8884097, 8, 0, /* 704: pointer.func */
            8884097, 8, 0, /* 707: pointer.func */
            1, 8, 1, /* 710: pointer.struct.dh_method */
            	715, 0,
            0, 72, 8, /* 715: struct.dh_method */
            	50, 0,
            	734, 8,
            	737, 16,
            	740, 24,
            	734, 32,
            	734, 40,
            	72, 56,
            	743, 64,
            8884097, 8, 0, /* 734: pointer.func */
            8884097, 8, 0, /* 737: pointer.func */
            8884097, 8, 0, /* 740: pointer.func */
            8884097, 8, 0, /* 743: pointer.func */
            1, 8, 1, /* 746: pointer.struct.ecdh_method */
            	751, 0,
            0, 32, 3, /* 751: struct.ecdh_method */
            	50, 0,
            	760, 8,
            	72, 24,
            8884097, 8, 0, /* 760: pointer.func */
            1, 8, 1, /* 763: pointer.struct.ecdsa_method */
            	768, 0,
            0, 48, 5, /* 768: struct.ecdsa_method */
            	50, 0,
            	781, 8,
            	784, 16,
            	787, 24,
            	72, 40,
            8884097, 8, 0, /* 781: pointer.func */
            8884097, 8, 0, /* 784: pointer.func */
            8884097, 8, 0, /* 787: pointer.func */
            1, 8, 1, /* 790: pointer.struct.rand_meth_st */
            	795, 0,
            0, 48, 6, /* 795: struct.rand_meth_st */
            	810, 0,
            	813, 8,
            	816, 16,
            	819, 24,
            	813, 32,
            	822, 40,
            8884097, 8, 0, /* 810: pointer.func */
            8884097, 8, 0, /* 813: pointer.func */
            8884097, 8, 0, /* 816: pointer.func */
            8884097, 8, 0, /* 819: pointer.func */
            8884097, 8, 0, /* 822: pointer.func */
            1, 8, 1, /* 825: pointer.struct.store_method_st */
            	830, 0,
            0, 0, 0, /* 830: struct.store_method_st */
            8884097, 8, 0, /* 833: pointer.func */
            8884097, 8, 0, /* 836: pointer.func */
            8884097, 8, 0, /* 839: pointer.func */
            8884097, 8, 0, /* 842: pointer.func */
            8884097, 8, 0, /* 845: pointer.func */
            8884097, 8, 0, /* 848: pointer.func */
            8884097, 8, 0, /* 851: pointer.func */
            8884097, 8, 0, /* 854: pointer.func */
            1, 8, 1, /* 857: pointer.struct.ENGINE_CMD_DEFN_st */
            	862, 0,
            0, 32, 2, /* 862: struct.ENGINE_CMD_DEFN_st */
            	50, 8,
            	50, 16,
            0, 16, 1, /* 869: struct.crypto_ex_data_st */
            	874, 0,
            1, 8, 1, /* 874: pointer.struct.stack_st_void */
            	879, 0,
            0, 32, 1, /* 879: struct.stack_st_void */
            	884, 0,
            0, 32, 2, /* 884: struct.stack_st */
            	492, 8,
            	264, 24,
            1, 8, 1, /* 891: pointer.struct.engine_st */
            	553, 0,
            1, 8, 1, /* 896: pointer.struct.rsa_st */
            	901, 0,
            0, 168, 17, /* 901: struct.rsa_st */
            	938, 16,
            	993, 24,
            	998, 32,
            	998, 40,
            	998, 48,
            	998, 56,
            	998, 64,
            	998, 72,
            	998, 80,
            	998, 88,
            	1008, 96,
            	1030, 120,
            	1030, 128,
            	1030, 136,
            	72, 144,
            	1044, 152,
            	1044, 160,
            1, 8, 1, /* 938: pointer.struct.rsa_meth_st */
            	943, 0,
            0, 112, 13, /* 943: struct.rsa_meth_st */
            	50, 0,
            	972, 8,
            	972, 16,
            	972, 24,
            	972, 32,
            	975, 40,
            	978, 48,
            	981, 56,
            	981, 64,
            	72, 80,
            	984, 88,
            	987, 96,
            	990, 104,
            8884097, 8, 0, /* 972: pointer.func */
            8884097, 8, 0, /* 975: pointer.func */
            8884097, 8, 0, /* 978: pointer.func */
            8884097, 8, 0, /* 981: pointer.func */
            8884097, 8, 0, /* 984: pointer.func */
            8884097, 8, 0, /* 987: pointer.func */
            8884097, 8, 0, /* 990: pointer.func */
            1, 8, 1, /* 993: pointer.struct.engine_st */
            	553, 0,
            1, 8, 1, /* 998: pointer.struct.bignum_st */
            	1003, 0,
            0, 24, 1, /* 1003: struct.bignum_st */
            	448, 0,
            0, 16, 1, /* 1008: struct.crypto_ex_data_st */
            	1013, 0,
            1, 8, 1, /* 1013: pointer.struct.stack_st_void */
            	1018, 0,
            0, 32, 1, /* 1018: struct.stack_st_void */
            	1023, 0,
            0, 32, 2, /* 1023: struct.stack_st */
            	492, 8,
            	264, 24,
            1, 8, 1, /* 1030: pointer.struct.bn_mont_ctx_st */
            	1035, 0,
            0, 96, 3, /* 1035: struct.bn_mont_ctx_st */
            	1003, 8,
            	1003, 32,
            	1003, 56,
            1, 8, 1, /* 1044: pointer.struct.bn_blinding_st */
            	1049, 0,
            0, 88, 7, /* 1049: struct.bn_blinding_st */
            	1066, 0,
            	1066, 8,
            	1066, 16,
            	1066, 24,
            	1076, 40,
            	1084, 72,
            	1098, 80,
            1, 8, 1, /* 1066: pointer.struct.bignum_st */
            	1071, 0,
            0, 24, 1, /* 1071: struct.bignum_st */
            	448, 0,
            0, 16, 1, /* 1076: struct.crypto_threadid_st */
            	1081, 0,
            0, 8, 0, /* 1081: pointer.void */
            1, 8, 1, /* 1084: pointer.struct.bn_mont_ctx_st */
            	1089, 0,
            0, 96, 3, /* 1089: struct.bn_mont_ctx_st */
            	1071, 8,
            	1071, 32,
            	1071, 56,
            8884097, 8, 0, /* 1098: pointer.func */
            0, 8, 5, /* 1101: union.unknown */
            	72, 0,
            	896, 0,
            	408, 0,
            	1114, 0,
            	1228, 0,
            1, 8, 1, /* 1114: pointer.struct.dh_st */
            	1119, 0,
            0, 144, 12, /* 1119: struct.dh_st */
            	1146, 8,
            	1146, 16,
            	1146, 32,
            	1146, 40,
            	1156, 56,
            	1146, 64,
            	1146, 72,
            	164, 80,
            	1146, 96,
            	1170, 112,
            	1192, 128,
            	993, 136,
            1, 8, 1, /* 1146: pointer.struct.bignum_st */
            	1151, 0,
            0, 24, 1, /* 1151: struct.bignum_st */
            	448, 0,
            1, 8, 1, /* 1156: pointer.struct.bn_mont_ctx_st */
            	1161, 0,
            0, 96, 3, /* 1161: struct.bn_mont_ctx_st */
            	1151, 8,
            	1151, 32,
            	1151, 56,
            0, 16, 1, /* 1170: struct.crypto_ex_data_st */
            	1175, 0,
            1, 8, 1, /* 1175: pointer.struct.stack_st_void */
            	1180, 0,
            0, 32, 1, /* 1180: struct.stack_st_void */
            	1185, 0,
            0, 32, 2, /* 1185: struct.stack_st */
            	492, 8,
            	264, 24,
            1, 8, 1, /* 1192: pointer.struct.dh_method */
            	1197, 0,
            0, 72, 8, /* 1197: struct.dh_method */
            	50, 0,
            	1216, 8,
            	1219, 16,
            	1222, 24,
            	1216, 32,
            	1216, 40,
            	72, 56,
            	1225, 64,
            8884097, 8, 0, /* 1216: pointer.func */
            8884097, 8, 0, /* 1219: pointer.func */
            8884097, 8, 0, /* 1222: pointer.func */
            8884097, 8, 0, /* 1225: pointer.func */
            1, 8, 1, /* 1228: pointer.struct.ec_key_st */
            	1233, 0,
            0, 56, 4, /* 1233: struct.ec_key_st */
            	1244, 8,
            	1678, 16,
            	1683, 24,
            	1693, 48,
            1, 8, 1, /* 1244: pointer.struct.ec_group_st */
            	1249, 0,
            0, 232, 12, /* 1249: struct.ec_group_st */
            	1276, 0,
            	1448, 8,
            	1641, 16,
            	1641, 40,
            	164, 80,
            	1646, 96,
            	1641, 104,
            	1641, 152,
            	1641, 176,
            	1081, 208,
            	1081, 216,
            	1675, 224,
            1, 8, 1, /* 1276: pointer.struct.ec_method_st */
            	1281, 0,
            0, 304, 37, /* 1281: struct.ec_method_st */
            	1358, 8,
            	1361, 16,
            	1361, 24,
            	1364, 32,
            	1367, 40,
            	1370, 48,
            	1373, 56,
            	1376, 64,
            	1379, 72,
            	1382, 80,
            	1382, 88,
            	1385, 96,
            	1388, 104,
            	1391, 112,
            	1394, 120,
            	1397, 128,
            	1400, 136,
            	1403, 144,
            	1406, 152,
            	1409, 160,
            	1412, 168,
            	1415, 176,
            	1418, 184,
            	1421, 192,
            	1424, 200,
            	1427, 208,
            	1418, 216,
            	1430, 224,
            	1433, 232,
            	1436, 240,
            	1373, 248,
            	1439, 256,
            	1442, 264,
            	1439, 272,
            	1442, 280,
            	1442, 288,
            	1445, 296,
            8884097, 8, 0, /* 1358: pointer.func */
            8884097, 8, 0, /* 1361: pointer.func */
            8884097, 8, 0, /* 1364: pointer.func */
            8884097, 8, 0, /* 1367: pointer.func */
            8884097, 8, 0, /* 1370: pointer.func */
            8884097, 8, 0, /* 1373: pointer.func */
            8884097, 8, 0, /* 1376: pointer.func */
            8884097, 8, 0, /* 1379: pointer.func */
            8884097, 8, 0, /* 1382: pointer.func */
            8884097, 8, 0, /* 1385: pointer.func */
            8884097, 8, 0, /* 1388: pointer.func */
            8884097, 8, 0, /* 1391: pointer.func */
            8884097, 8, 0, /* 1394: pointer.func */
            8884097, 8, 0, /* 1397: pointer.func */
            8884097, 8, 0, /* 1400: pointer.func */
            8884097, 8, 0, /* 1403: pointer.func */
            8884097, 8, 0, /* 1406: pointer.func */
            8884097, 8, 0, /* 1409: pointer.func */
            8884097, 8, 0, /* 1412: pointer.func */
            8884097, 8, 0, /* 1415: pointer.func */
            8884097, 8, 0, /* 1418: pointer.func */
            8884097, 8, 0, /* 1421: pointer.func */
            8884097, 8, 0, /* 1424: pointer.func */
            8884097, 8, 0, /* 1427: pointer.func */
            8884097, 8, 0, /* 1430: pointer.func */
            8884097, 8, 0, /* 1433: pointer.func */
            8884097, 8, 0, /* 1436: pointer.func */
            8884097, 8, 0, /* 1439: pointer.func */
            8884097, 8, 0, /* 1442: pointer.func */
            8884097, 8, 0, /* 1445: pointer.func */
            1, 8, 1, /* 1448: pointer.struct.ec_point_st */
            	1453, 0,
            0, 88, 4, /* 1453: struct.ec_point_st */
            	1464, 0,
            	1636, 8,
            	1636, 32,
            	1636, 56,
            1, 8, 1, /* 1464: pointer.struct.ec_method_st */
            	1469, 0,
            0, 304, 37, /* 1469: struct.ec_method_st */
            	1546, 8,
            	1549, 16,
            	1549, 24,
            	1552, 32,
            	1555, 40,
            	1558, 48,
            	1561, 56,
            	1564, 64,
            	1567, 72,
            	1570, 80,
            	1570, 88,
            	1573, 96,
            	1576, 104,
            	1579, 112,
            	1582, 120,
            	1585, 128,
            	1588, 136,
            	1591, 144,
            	1594, 152,
            	1597, 160,
            	1600, 168,
            	1603, 176,
            	1606, 184,
            	1609, 192,
            	1612, 200,
            	1615, 208,
            	1606, 216,
            	1618, 224,
            	1621, 232,
            	1624, 240,
            	1561, 248,
            	1627, 256,
            	1630, 264,
            	1627, 272,
            	1630, 280,
            	1630, 288,
            	1633, 296,
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
            8884097, 8, 0, /* 1585: pointer.func */
            8884097, 8, 0, /* 1588: pointer.func */
            8884097, 8, 0, /* 1591: pointer.func */
            8884097, 8, 0, /* 1594: pointer.func */
            8884097, 8, 0, /* 1597: pointer.func */
            8884097, 8, 0, /* 1600: pointer.func */
            8884097, 8, 0, /* 1603: pointer.func */
            8884097, 8, 0, /* 1606: pointer.func */
            8884097, 8, 0, /* 1609: pointer.func */
            8884097, 8, 0, /* 1612: pointer.func */
            8884097, 8, 0, /* 1615: pointer.func */
            8884097, 8, 0, /* 1618: pointer.func */
            8884097, 8, 0, /* 1621: pointer.func */
            8884097, 8, 0, /* 1624: pointer.func */
            8884097, 8, 0, /* 1627: pointer.func */
            8884097, 8, 0, /* 1630: pointer.func */
            8884097, 8, 0, /* 1633: pointer.func */
            0, 24, 1, /* 1636: struct.bignum_st */
            	448, 0,
            0, 24, 1, /* 1641: struct.bignum_st */
            	448, 0,
            1, 8, 1, /* 1646: pointer.struct.ec_extra_data_st */
            	1651, 0,
            0, 40, 5, /* 1651: struct.ec_extra_data_st */
            	1664, 0,
            	1081, 8,
            	1669, 16,
            	1672, 24,
            	1672, 32,
            1, 8, 1, /* 1664: pointer.struct.ec_extra_data_st */
            	1651, 0,
            8884097, 8, 0, /* 1669: pointer.func */
            8884097, 8, 0, /* 1672: pointer.func */
            8884097, 8, 0, /* 1675: pointer.func */
            1, 8, 1, /* 1678: pointer.struct.ec_point_st */
            	1453, 0,
            1, 8, 1, /* 1683: pointer.struct.bignum_st */
            	1688, 0,
            0, 24, 1, /* 1688: struct.bignum_st */
            	448, 0,
            1, 8, 1, /* 1693: pointer.struct.ec_extra_data_st */
            	1698, 0,
            0, 40, 5, /* 1698: struct.ec_extra_data_st */
            	1711, 0,
            	1081, 8,
            	1669, 16,
            	1672, 24,
            	1672, 32,
            1, 8, 1, /* 1711: pointer.struct.ec_extra_data_st */
            	1698, 0,
            0, 56, 4, /* 1716: struct.evp_pkey_st */
            	1727, 16,
            	1828, 24,
            	1101, 32,
            	0, 48,
            1, 8, 1, /* 1727: pointer.struct.evp_pkey_asn1_method_st */
            	1732, 0,
            0, 208, 24, /* 1732: struct.evp_pkey_asn1_method_st */
            	72, 16,
            	72, 24,
            	1783, 32,
            	1786, 40,
            	1789, 48,
            	1792, 56,
            	1795, 64,
            	1798, 72,
            	1792, 80,
            	1801, 88,
            	1801, 96,
            	1804, 104,
            	1807, 112,
            	1801, 120,
            	1810, 128,
            	1789, 136,
            	1792, 144,
            	1813, 152,
            	1816, 160,
            	1819, 168,
            	1804, 176,
            	1807, 184,
            	1822, 192,
            	1825, 200,
            8884097, 8, 0, /* 1783: pointer.func */
            8884097, 8, 0, /* 1786: pointer.func */
            8884097, 8, 0, /* 1789: pointer.func */
            8884097, 8, 0, /* 1792: pointer.func */
            8884097, 8, 0, /* 1795: pointer.func */
            8884097, 8, 0, /* 1798: pointer.func */
            8884097, 8, 0, /* 1801: pointer.func */
            8884097, 8, 0, /* 1804: pointer.func */
            8884097, 8, 0, /* 1807: pointer.func */
            8884097, 8, 0, /* 1810: pointer.func */
            8884097, 8, 0, /* 1813: pointer.func */
            8884097, 8, 0, /* 1816: pointer.func */
            8884097, 8, 0, /* 1819: pointer.func */
            8884097, 8, 0, /* 1822: pointer.func */
            8884097, 8, 0, /* 1825: pointer.func */
            1, 8, 1, /* 1828: pointer.struct.engine_st */
            	553, 0,
            1, 8, 1, /* 1833: pointer.int */
            	261, 0,
            1, 8, 1, /* 1838: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1843, 0,
            0, 32, 2, /* 1843: struct.stack_st_fake_X509_ATTRIBUTE */
            	1850, 8,
            	264, 24,
            8884099, 8, 2, /* 1850: pointer_to_array_of_pointers_to_stack */
            	1857, 0,
            	261, 20,
            0, 8, 1, /* 1857: pointer.X509_ATTRIBUTE */
            	24, 0,
            1, 8, 1, /* 1862: pointer.struct.dh_st */
            	1119, 0,
            1, 8, 1, /* 1867: pointer.struct.evp_pkey_ctx_st */
            	1872, 0,
            0, 80, 8, /* 1872: struct.evp_pkey_ctx_st */
            	1891, 0,
            	1985, 8,
            	1990, 16,
            	1990, 24,
            	1081, 40,
            	1081, 48,
            	2039, 56,
            	1833, 64,
            1, 8, 1, /* 1891: pointer.struct.evp_pkey_method_st */
            	1896, 0,
            0, 208, 25, /* 1896: struct.evp_pkey_method_st */
            	1949, 8,
            	1952, 16,
            	1955, 24,
            	1949, 32,
            	1958, 40,
            	1949, 48,
            	1958, 56,
            	1949, 64,
            	1961, 72,
            	1949, 80,
            	1964, 88,
            	1949, 96,
            	1961, 104,
            	1967, 112,
            	1970, 120,
            	1967, 128,
            	1973, 136,
            	1949, 144,
            	1961, 152,
            	1949, 160,
            	1961, 168,
            	1949, 176,
            	1976, 184,
            	1979, 192,
            	1982, 200,
            8884097, 8, 0, /* 1949: pointer.func */
            8884097, 8, 0, /* 1952: pointer.func */
            8884097, 8, 0, /* 1955: pointer.func */
            8884097, 8, 0, /* 1958: pointer.func */
            8884097, 8, 0, /* 1961: pointer.func */
            8884097, 8, 0, /* 1964: pointer.func */
            8884097, 8, 0, /* 1967: pointer.func */
            8884097, 8, 0, /* 1970: pointer.func */
            8884097, 8, 0, /* 1973: pointer.func */
            8884097, 8, 0, /* 1976: pointer.func */
            8884097, 8, 0, /* 1979: pointer.func */
            8884097, 8, 0, /* 1982: pointer.func */
            1, 8, 1, /* 1985: pointer.struct.engine_st */
            	553, 0,
            1, 8, 1, /* 1990: pointer.struct.evp_pkey_st */
            	1995, 0,
            0, 56, 4, /* 1995: struct.evp_pkey_st */
            	2006, 16,
            	1985, 24,
            	2011, 32,
            	1838, 48,
            1, 8, 1, /* 2006: pointer.struct.evp_pkey_asn1_method_st */
            	1732, 0,
            0, 8, 5, /* 2011: union.unknown */
            	72, 0,
            	2024, 0,
            	2029, 0,
            	1862, 0,
            	2034, 0,
            1, 8, 1, /* 2024: pointer.struct.rsa_st */
            	901, 0,
            1, 8, 1, /* 2029: pointer.struct.dsa_st */
            	413, 0,
            1, 8, 1, /* 2034: pointer.struct.ec_key_st */
            	1233, 0,
            8884097, 8, 0, /* 2039: pointer.func */
            1, 8, 1, /* 2042: pointer.struct.evp_pkey_st */
            	1716, 0,
            8884097, 8, 0, /* 2047: pointer.func */
            0, 1, 0, /* 2050: char */
            8884097, 8, 0, /* 2053: pointer.func */
            0, 120, 8, /* 2056: struct.env_md_st */
            	2053, 24,
            	2075, 32,
            	2078, 40,
            	2081, 48,
            	2053, 56,
            	2084, 64,
            	2047, 72,
            	2087, 112,
            8884097, 8, 0, /* 2075: pointer.func */
            8884097, 8, 0, /* 2078: pointer.func */
            8884097, 8, 0, /* 2081: pointer.func */
            8884097, 8, 0, /* 2084: pointer.func */
            8884097, 8, 0, /* 2087: pointer.func */
            0, 48, 5, /* 2090: struct.env_md_ctx_st */
            	2103, 0,
            	1828, 8,
            	1081, 24,
            	1867, 32,
            	2075, 40,
            1, 8, 1, /* 2103: pointer.struct.env_md_st */
            	2056, 0,
            1, 8, 1, /* 2108: pointer.struct.env_md_ctx_st */
            	2090, 0,
        },
        .arg_entity_index = { 2108, 164, 448, 2042, },
        .ret_entity_index = 261,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    unsigned char * new_arg_b = *((unsigned char * *)new_args->args[1]);

    unsigned int * new_arg_c = *((unsigned int * *)new_args->args[2]);

    EVP_PKEY * new_arg_d = *((EVP_PKEY * *)new_args->args[3]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
    orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
    *new_ret_ptr = (*orig_EVP_SignFinal)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

