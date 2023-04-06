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
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            0, 128, 14, /* 10: struct.srp_ctx_st */
            	41, 0,
            	44, 8,
            	47, 16,
            	50, 24,
            	53, 32,
            	58, 40,
            	58, 48,
            	58, 56,
            	58, 64,
            	58, 72,
            	58, 80,
            	58, 88,
            	58, 96,
            	53, 104,
            0, 8, 0, /* 41: pointer.void */
            8884097, 8, 0, /* 44: pointer.func */
            8884097, 8, 0, /* 47: pointer.func */
            8884097, 8, 0, /* 50: pointer.func */
            1, 8, 1, /* 53: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 58: pointer.struct.bignum_st */
            	63, 0,
            0, 24, 1, /* 63: struct.bignum_st */
            	68, 0,
            1, 8, 1, /* 68: pointer.unsigned int */
            	73, 0,
            0, 4, 0, /* 73: unsigned int */
            0, 8, 1, /* 76: struct.ssl3_buf_freelist_entry_st */
            	81, 0,
            1, 8, 1, /* 81: pointer.struct.ssl3_buf_freelist_entry_st */
            	76, 0,
            8884097, 8, 0, /* 86: pointer.func */
            1, 8, 1, /* 89: pointer.struct.dh_st */
            	94, 0,
            0, 144, 12, /* 94: struct.dh_st */
            	121, 8,
            	121, 16,
            	121, 32,
            	121, 40,
            	131, 56,
            	121, 64,
            	121, 72,
            	145, 80,
            	121, 96,
            	153, 112,
            	183, 128,
            	219, 136,
            1, 8, 1, /* 121: pointer.struct.bignum_st */
            	126, 0,
            0, 24, 1, /* 126: struct.bignum_st */
            	68, 0,
            1, 8, 1, /* 131: pointer.struct.bn_mont_ctx_st */
            	136, 0,
            0, 96, 3, /* 136: struct.bn_mont_ctx_st */
            	126, 8,
            	126, 32,
            	126, 56,
            1, 8, 1, /* 145: pointer.unsigned char */
            	150, 0,
            0, 1, 0, /* 150: unsigned char */
            0, 16, 1, /* 153: struct.crypto_ex_data_st */
            	158, 0,
            1, 8, 1, /* 158: pointer.struct.stack_st_void */
            	163, 0,
            0, 32, 1, /* 163: struct.stack_st_void */
            	168, 0,
            0, 32, 2, /* 168: struct.stack_st */
            	175, 8,
            	180, 24,
            1, 8, 1, /* 175: pointer.pointer.char */
            	53, 0,
            8884097, 8, 0, /* 180: pointer.func */
            1, 8, 1, /* 183: pointer.struct.dh_method */
            	188, 0,
            0, 72, 8, /* 188: struct.dh_method */
            	5, 0,
            	207, 8,
            	210, 16,
            	213, 24,
            	207, 32,
            	207, 40,
            	53, 56,
            	216, 64,
            8884097, 8, 0, /* 207: pointer.func */
            8884097, 8, 0, /* 210: pointer.func */
            8884097, 8, 0, /* 213: pointer.func */
            8884097, 8, 0, /* 216: pointer.func */
            1, 8, 1, /* 219: pointer.struct.engine_st */
            	224, 0,
            0, 216, 24, /* 224: struct.engine_st */
            	5, 0,
            	5, 8,
            	275, 16,
            	330, 24,
            	381, 32,
            	417, 40,
            	434, 48,
            	461, 56,
            	496, 64,
            	504, 72,
            	507, 80,
            	510, 88,
            	513, 96,
            	516, 104,
            	516, 112,
            	516, 120,
            	519, 128,
            	522, 136,
            	522, 144,
            	525, 152,
            	528, 160,
            	540, 184,
            	562, 200,
            	562, 208,
            1, 8, 1, /* 275: pointer.struct.rsa_meth_st */
            	280, 0,
            0, 112, 13, /* 280: struct.rsa_meth_st */
            	5, 0,
            	309, 8,
            	309, 16,
            	309, 24,
            	309, 32,
            	312, 40,
            	315, 48,
            	318, 56,
            	318, 64,
            	53, 80,
            	321, 88,
            	324, 96,
            	327, 104,
            8884097, 8, 0, /* 309: pointer.func */
            8884097, 8, 0, /* 312: pointer.func */
            8884097, 8, 0, /* 315: pointer.func */
            8884097, 8, 0, /* 318: pointer.func */
            8884097, 8, 0, /* 321: pointer.func */
            8884097, 8, 0, /* 324: pointer.func */
            8884097, 8, 0, /* 327: pointer.func */
            1, 8, 1, /* 330: pointer.struct.dsa_method */
            	335, 0,
            0, 96, 11, /* 335: struct.dsa_method */
            	5, 0,
            	360, 8,
            	363, 16,
            	366, 24,
            	369, 32,
            	372, 40,
            	375, 48,
            	375, 56,
            	53, 72,
            	378, 80,
            	375, 88,
            8884097, 8, 0, /* 360: pointer.func */
            8884097, 8, 0, /* 363: pointer.func */
            8884097, 8, 0, /* 366: pointer.func */
            8884097, 8, 0, /* 369: pointer.func */
            8884097, 8, 0, /* 372: pointer.func */
            8884097, 8, 0, /* 375: pointer.func */
            8884097, 8, 0, /* 378: pointer.func */
            1, 8, 1, /* 381: pointer.struct.dh_method */
            	386, 0,
            0, 72, 8, /* 386: struct.dh_method */
            	5, 0,
            	405, 8,
            	408, 16,
            	411, 24,
            	405, 32,
            	405, 40,
            	53, 56,
            	414, 64,
            8884097, 8, 0, /* 405: pointer.func */
            8884097, 8, 0, /* 408: pointer.func */
            8884097, 8, 0, /* 411: pointer.func */
            8884097, 8, 0, /* 414: pointer.func */
            1, 8, 1, /* 417: pointer.struct.ecdh_method */
            	422, 0,
            0, 32, 3, /* 422: struct.ecdh_method */
            	5, 0,
            	431, 8,
            	53, 24,
            8884097, 8, 0, /* 431: pointer.func */
            1, 8, 1, /* 434: pointer.struct.ecdsa_method */
            	439, 0,
            0, 48, 5, /* 439: struct.ecdsa_method */
            	5, 0,
            	452, 8,
            	455, 16,
            	458, 24,
            	53, 40,
            8884097, 8, 0, /* 452: pointer.func */
            8884097, 8, 0, /* 455: pointer.func */
            8884097, 8, 0, /* 458: pointer.func */
            1, 8, 1, /* 461: pointer.struct.rand_meth_st */
            	466, 0,
            0, 48, 6, /* 466: struct.rand_meth_st */
            	481, 0,
            	484, 8,
            	487, 16,
            	490, 24,
            	484, 32,
            	493, 40,
            8884097, 8, 0, /* 481: pointer.func */
            8884097, 8, 0, /* 484: pointer.func */
            8884097, 8, 0, /* 487: pointer.func */
            8884097, 8, 0, /* 490: pointer.func */
            8884097, 8, 0, /* 493: pointer.func */
            1, 8, 1, /* 496: pointer.struct.store_method_st */
            	501, 0,
            0, 0, 0, /* 501: struct.store_method_st */
            8884097, 8, 0, /* 504: pointer.func */
            8884097, 8, 0, /* 507: pointer.func */
            8884097, 8, 0, /* 510: pointer.func */
            8884097, 8, 0, /* 513: pointer.func */
            8884097, 8, 0, /* 516: pointer.func */
            8884097, 8, 0, /* 519: pointer.func */
            8884097, 8, 0, /* 522: pointer.func */
            8884097, 8, 0, /* 525: pointer.func */
            1, 8, 1, /* 528: pointer.struct.ENGINE_CMD_DEFN_st */
            	533, 0,
            0, 32, 2, /* 533: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 540: struct.crypto_ex_data_st */
            	545, 0,
            1, 8, 1, /* 545: pointer.struct.stack_st_void */
            	550, 0,
            0, 32, 1, /* 550: struct.stack_st_void */
            	555, 0,
            0, 32, 2, /* 555: struct.stack_st */
            	175, 8,
            	180, 24,
            1, 8, 1, /* 562: pointer.struct.engine_st */
            	224, 0,
            1, 8, 1, /* 567: pointer.struct.rsa_st */
            	572, 0,
            0, 168, 17, /* 572: struct.rsa_st */
            	609, 16,
            	219, 24,
            	664, 32,
            	664, 40,
            	664, 48,
            	664, 56,
            	664, 64,
            	664, 72,
            	664, 80,
            	664, 88,
            	674, 96,
            	696, 120,
            	696, 128,
            	696, 136,
            	53, 144,
            	710, 152,
            	710, 160,
            1, 8, 1, /* 609: pointer.struct.rsa_meth_st */
            	614, 0,
            0, 112, 13, /* 614: struct.rsa_meth_st */
            	5, 0,
            	643, 8,
            	643, 16,
            	643, 24,
            	643, 32,
            	646, 40,
            	649, 48,
            	652, 56,
            	652, 64,
            	53, 80,
            	655, 88,
            	658, 96,
            	661, 104,
            8884097, 8, 0, /* 643: pointer.func */
            8884097, 8, 0, /* 646: pointer.func */
            8884097, 8, 0, /* 649: pointer.func */
            8884097, 8, 0, /* 652: pointer.func */
            8884097, 8, 0, /* 655: pointer.func */
            8884097, 8, 0, /* 658: pointer.func */
            8884097, 8, 0, /* 661: pointer.func */
            1, 8, 1, /* 664: pointer.struct.bignum_st */
            	669, 0,
            0, 24, 1, /* 669: struct.bignum_st */
            	68, 0,
            0, 16, 1, /* 674: struct.crypto_ex_data_st */
            	679, 0,
            1, 8, 1, /* 679: pointer.struct.stack_st_void */
            	684, 0,
            0, 32, 1, /* 684: struct.stack_st_void */
            	689, 0,
            0, 32, 2, /* 689: struct.stack_st */
            	175, 8,
            	180, 24,
            1, 8, 1, /* 696: pointer.struct.bn_mont_ctx_st */
            	701, 0,
            0, 96, 3, /* 701: struct.bn_mont_ctx_st */
            	669, 8,
            	669, 32,
            	669, 56,
            1, 8, 1, /* 710: pointer.struct.bn_blinding_st */
            	715, 0,
            0, 88, 7, /* 715: struct.bn_blinding_st */
            	732, 0,
            	732, 8,
            	732, 16,
            	732, 24,
            	742, 40,
            	747, 72,
            	761, 80,
            1, 8, 1, /* 732: pointer.struct.bignum_st */
            	737, 0,
            0, 24, 1, /* 737: struct.bignum_st */
            	68, 0,
            0, 16, 1, /* 742: struct.crypto_threadid_st */
            	41, 0,
            1, 8, 1, /* 747: pointer.struct.bn_mont_ctx_st */
            	752, 0,
            0, 96, 3, /* 752: struct.bn_mont_ctx_st */
            	737, 8,
            	737, 32,
            	737, 56,
            8884097, 8, 0, /* 761: pointer.func */
            8884097, 8, 0, /* 764: pointer.func */
            8884097, 8, 0, /* 767: pointer.func */
            1, 8, 1, /* 770: pointer.struct.env_md_st */
            	775, 0,
            0, 120, 8, /* 775: struct.env_md_st */
            	794, 24,
            	767, 32,
            	797, 40,
            	764, 48,
            	794, 56,
            	800, 64,
            	803, 72,
            	806, 112,
            8884097, 8, 0, /* 794: pointer.func */
            8884097, 8, 0, /* 797: pointer.func */
            8884097, 8, 0, /* 800: pointer.func */
            8884097, 8, 0, /* 803: pointer.func */
            8884097, 8, 0, /* 806: pointer.func */
            1, 8, 1, /* 809: pointer.struct.stack_st_X509_ATTRIBUTE */
            	814, 0,
            0, 32, 2, /* 814: struct.stack_st_fake_X509_ATTRIBUTE */
            	821, 8,
            	180, 24,
            8884099, 8, 2, /* 821: pointer_to_array_of_pointers_to_stack */
            	828, 0,
            	1052, 20,
            0, 8, 1, /* 828: pointer.X509_ATTRIBUTE */
            	833, 0,
            0, 0, 1, /* 833: X509_ATTRIBUTE */
            	838, 0,
            0, 24, 2, /* 838: struct.x509_attributes_st */
            	845, 0,
            	864, 16,
            1, 8, 1, /* 845: pointer.struct.asn1_object_st */
            	850, 0,
            0, 40, 3, /* 850: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	859, 24,
            1, 8, 1, /* 859: pointer.unsigned char */
            	150, 0,
            0, 8, 3, /* 864: union.unknown */
            	53, 0,
            	873, 0,
            	1055, 0,
            1, 8, 1, /* 873: pointer.struct.stack_st_ASN1_TYPE */
            	878, 0,
            0, 32, 2, /* 878: struct.stack_st_fake_ASN1_TYPE */
            	885, 8,
            	180, 24,
            8884099, 8, 2, /* 885: pointer_to_array_of_pointers_to_stack */
            	892, 0,
            	1052, 20,
            0, 8, 1, /* 892: pointer.ASN1_TYPE */
            	897, 0,
            0, 0, 1, /* 897: ASN1_TYPE */
            	902, 0,
            0, 16, 1, /* 902: struct.asn1_type_st */
            	907, 8,
            0, 8, 20, /* 907: union.unknown */
            	53, 0,
            	950, 0,
            	960, 0,
            	974, 0,
            	979, 0,
            	984, 0,
            	989, 0,
            	994, 0,
            	999, 0,
            	1004, 0,
            	1009, 0,
            	1014, 0,
            	1019, 0,
            	1024, 0,
            	1029, 0,
            	1034, 0,
            	1039, 0,
            	950, 0,
            	950, 0,
            	1044, 0,
            1, 8, 1, /* 950: pointer.struct.asn1_string_st */
            	955, 0,
            0, 24, 1, /* 955: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 960: pointer.struct.asn1_object_st */
            	965, 0,
            0, 40, 3, /* 965: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	859, 24,
            1, 8, 1, /* 974: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 979: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 984: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 989: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 994: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 999: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 1004: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 1009: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 1014: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 1019: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 1024: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 1029: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 1034: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 1039: pointer.struct.asn1_string_st */
            	955, 0,
            1, 8, 1, /* 1044: pointer.struct.ASN1_VALUE_st */
            	1049, 0,
            0, 0, 0, /* 1049: struct.ASN1_VALUE_st */
            0, 4, 0, /* 1052: int */
            1, 8, 1, /* 1055: pointer.struct.asn1_type_st */
            	1060, 0,
            0, 16, 1, /* 1060: struct.asn1_type_st */
            	1065, 8,
            0, 8, 20, /* 1065: union.unknown */
            	53, 0,
            	1108, 0,
            	845, 0,
            	1118, 0,
            	1123, 0,
            	1128, 0,
            	1133, 0,
            	1138, 0,
            	1143, 0,
            	1148, 0,
            	1153, 0,
            	1158, 0,
            	1163, 0,
            	1168, 0,
            	1173, 0,
            	1178, 0,
            	1183, 0,
            	1108, 0,
            	1108, 0,
            	1188, 0,
            1, 8, 1, /* 1108: pointer.struct.asn1_string_st */
            	1113, 0,
            0, 24, 1, /* 1113: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 1118: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1123: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1128: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1133: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1138: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1143: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1148: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1153: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1158: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1163: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1168: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1173: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1178: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1183: pointer.struct.asn1_string_st */
            	1113, 0,
            1, 8, 1, /* 1188: pointer.struct.ASN1_VALUE_st */
            	1193, 0,
            0, 0, 0, /* 1193: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1196: pointer.struct.dh_st */
            	94, 0,
            1, 8, 1, /* 1201: pointer.struct.rsa_st */
            	572, 0,
            0, 8, 5, /* 1206: union.unknown */
            	53, 0,
            	1201, 0,
            	1219, 0,
            	1196, 0,
            	1351, 0,
            1, 8, 1, /* 1219: pointer.struct.dsa_st */
            	1224, 0,
            0, 136, 11, /* 1224: struct.dsa_st */
            	1249, 24,
            	1249, 32,
            	1249, 40,
            	1249, 48,
            	1249, 56,
            	1249, 64,
            	1249, 72,
            	1259, 88,
            	1273, 104,
            	1295, 120,
            	1346, 128,
            1, 8, 1, /* 1249: pointer.struct.bignum_st */
            	1254, 0,
            0, 24, 1, /* 1254: struct.bignum_st */
            	68, 0,
            1, 8, 1, /* 1259: pointer.struct.bn_mont_ctx_st */
            	1264, 0,
            0, 96, 3, /* 1264: struct.bn_mont_ctx_st */
            	1254, 8,
            	1254, 32,
            	1254, 56,
            0, 16, 1, /* 1273: struct.crypto_ex_data_st */
            	1278, 0,
            1, 8, 1, /* 1278: pointer.struct.stack_st_void */
            	1283, 0,
            0, 32, 1, /* 1283: struct.stack_st_void */
            	1288, 0,
            0, 32, 2, /* 1288: struct.stack_st */
            	175, 8,
            	180, 24,
            1, 8, 1, /* 1295: pointer.struct.dsa_method */
            	1300, 0,
            0, 96, 11, /* 1300: struct.dsa_method */
            	5, 0,
            	1325, 8,
            	1328, 16,
            	1331, 24,
            	1334, 32,
            	1337, 40,
            	1340, 48,
            	1340, 56,
            	53, 72,
            	1343, 80,
            	1340, 88,
            8884097, 8, 0, /* 1325: pointer.func */
            8884097, 8, 0, /* 1328: pointer.func */
            8884097, 8, 0, /* 1331: pointer.func */
            8884097, 8, 0, /* 1334: pointer.func */
            8884097, 8, 0, /* 1337: pointer.func */
            8884097, 8, 0, /* 1340: pointer.func */
            8884097, 8, 0, /* 1343: pointer.func */
            1, 8, 1, /* 1346: pointer.struct.engine_st */
            	224, 0,
            1, 8, 1, /* 1351: pointer.struct.ec_key_st */
            	1356, 0,
            0, 56, 4, /* 1356: struct.ec_key_st */
            	1367, 8,
            	1801, 16,
            	1806, 24,
            	1816, 48,
            1, 8, 1, /* 1367: pointer.struct.ec_group_st */
            	1372, 0,
            0, 232, 12, /* 1372: struct.ec_group_st */
            	1399, 0,
            	1571, 8,
            	1764, 16,
            	1764, 40,
            	145, 80,
            	1769, 96,
            	1764, 104,
            	1764, 152,
            	1764, 176,
            	41, 208,
            	41, 216,
            	1798, 224,
            1, 8, 1, /* 1399: pointer.struct.ec_method_st */
            	1404, 0,
            0, 304, 37, /* 1404: struct.ec_method_st */
            	1481, 8,
            	1484, 16,
            	1484, 24,
            	1487, 32,
            	1490, 40,
            	1493, 48,
            	1496, 56,
            	1499, 64,
            	1502, 72,
            	1505, 80,
            	1505, 88,
            	1508, 96,
            	1511, 104,
            	1514, 112,
            	1517, 120,
            	1520, 128,
            	1523, 136,
            	1526, 144,
            	1529, 152,
            	1532, 160,
            	1535, 168,
            	1538, 176,
            	1541, 184,
            	1544, 192,
            	1547, 200,
            	1550, 208,
            	1541, 216,
            	1553, 224,
            	1556, 232,
            	1559, 240,
            	1496, 248,
            	1562, 256,
            	1565, 264,
            	1562, 272,
            	1565, 280,
            	1565, 288,
            	1568, 296,
            8884097, 8, 0, /* 1481: pointer.func */
            8884097, 8, 0, /* 1484: pointer.func */
            8884097, 8, 0, /* 1487: pointer.func */
            8884097, 8, 0, /* 1490: pointer.func */
            8884097, 8, 0, /* 1493: pointer.func */
            8884097, 8, 0, /* 1496: pointer.func */
            8884097, 8, 0, /* 1499: pointer.func */
            8884097, 8, 0, /* 1502: pointer.func */
            8884097, 8, 0, /* 1505: pointer.func */
            8884097, 8, 0, /* 1508: pointer.func */
            8884097, 8, 0, /* 1511: pointer.func */
            8884097, 8, 0, /* 1514: pointer.func */
            8884097, 8, 0, /* 1517: pointer.func */
            8884097, 8, 0, /* 1520: pointer.func */
            8884097, 8, 0, /* 1523: pointer.func */
            8884097, 8, 0, /* 1526: pointer.func */
            8884097, 8, 0, /* 1529: pointer.func */
            8884097, 8, 0, /* 1532: pointer.func */
            8884097, 8, 0, /* 1535: pointer.func */
            8884097, 8, 0, /* 1538: pointer.func */
            8884097, 8, 0, /* 1541: pointer.func */
            8884097, 8, 0, /* 1544: pointer.func */
            8884097, 8, 0, /* 1547: pointer.func */
            8884097, 8, 0, /* 1550: pointer.func */
            8884097, 8, 0, /* 1553: pointer.func */
            8884097, 8, 0, /* 1556: pointer.func */
            8884097, 8, 0, /* 1559: pointer.func */
            8884097, 8, 0, /* 1562: pointer.func */
            8884097, 8, 0, /* 1565: pointer.func */
            8884097, 8, 0, /* 1568: pointer.func */
            1, 8, 1, /* 1571: pointer.struct.ec_point_st */
            	1576, 0,
            0, 88, 4, /* 1576: struct.ec_point_st */
            	1587, 0,
            	1759, 8,
            	1759, 32,
            	1759, 56,
            1, 8, 1, /* 1587: pointer.struct.ec_method_st */
            	1592, 0,
            0, 304, 37, /* 1592: struct.ec_method_st */
            	1669, 8,
            	1672, 16,
            	1672, 24,
            	1675, 32,
            	1678, 40,
            	1681, 48,
            	1684, 56,
            	1687, 64,
            	1690, 72,
            	1693, 80,
            	1693, 88,
            	1696, 96,
            	1699, 104,
            	1702, 112,
            	1705, 120,
            	1708, 128,
            	1711, 136,
            	1714, 144,
            	1717, 152,
            	1720, 160,
            	1723, 168,
            	1726, 176,
            	1729, 184,
            	1732, 192,
            	1735, 200,
            	1738, 208,
            	1729, 216,
            	1741, 224,
            	1744, 232,
            	1747, 240,
            	1684, 248,
            	1750, 256,
            	1753, 264,
            	1750, 272,
            	1753, 280,
            	1753, 288,
            	1756, 296,
            8884097, 8, 0, /* 1669: pointer.func */
            8884097, 8, 0, /* 1672: pointer.func */
            8884097, 8, 0, /* 1675: pointer.func */
            8884097, 8, 0, /* 1678: pointer.func */
            8884097, 8, 0, /* 1681: pointer.func */
            8884097, 8, 0, /* 1684: pointer.func */
            8884097, 8, 0, /* 1687: pointer.func */
            8884097, 8, 0, /* 1690: pointer.func */
            8884097, 8, 0, /* 1693: pointer.func */
            8884097, 8, 0, /* 1696: pointer.func */
            8884097, 8, 0, /* 1699: pointer.func */
            8884097, 8, 0, /* 1702: pointer.func */
            8884097, 8, 0, /* 1705: pointer.func */
            8884097, 8, 0, /* 1708: pointer.func */
            8884097, 8, 0, /* 1711: pointer.func */
            8884097, 8, 0, /* 1714: pointer.func */
            8884097, 8, 0, /* 1717: pointer.func */
            8884097, 8, 0, /* 1720: pointer.func */
            8884097, 8, 0, /* 1723: pointer.func */
            8884097, 8, 0, /* 1726: pointer.func */
            8884097, 8, 0, /* 1729: pointer.func */
            8884097, 8, 0, /* 1732: pointer.func */
            8884097, 8, 0, /* 1735: pointer.func */
            8884097, 8, 0, /* 1738: pointer.func */
            8884097, 8, 0, /* 1741: pointer.func */
            8884097, 8, 0, /* 1744: pointer.func */
            8884097, 8, 0, /* 1747: pointer.func */
            8884097, 8, 0, /* 1750: pointer.func */
            8884097, 8, 0, /* 1753: pointer.func */
            8884097, 8, 0, /* 1756: pointer.func */
            0, 24, 1, /* 1759: struct.bignum_st */
            	68, 0,
            0, 24, 1, /* 1764: struct.bignum_st */
            	68, 0,
            1, 8, 1, /* 1769: pointer.struct.ec_extra_data_st */
            	1774, 0,
            0, 40, 5, /* 1774: struct.ec_extra_data_st */
            	1787, 0,
            	41, 8,
            	1792, 16,
            	1795, 24,
            	1795, 32,
            1, 8, 1, /* 1787: pointer.struct.ec_extra_data_st */
            	1774, 0,
            8884097, 8, 0, /* 1792: pointer.func */
            8884097, 8, 0, /* 1795: pointer.func */
            8884097, 8, 0, /* 1798: pointer.func */
            1, 8, 1, /* 1801: pointer.struct.ec_point_st */
            	1576, 0,
            1, 8, 1, /* 1806: pointer.struct.bignum_st */
            	1811, 0,
            0, 24, 1, /* 1811: struct.bignum_st */
            	68, 0,
            1, 8, 1, /* 1816: pointer.struct.ec_extra_data_st */
            	1821, 0,
            0, 40, 5, /* 1821: struct.ec_extra_data_st */
            	1834, 0,
            	41, 8,
            	1792, 16,
            	1795, 24,
            	1795, 32,
            1, 8, 1, /* 1834: pointer.struct.ec_extra_data_st */
            	1821, 0,
            8884097, 8, 0, /* 1839: pointer.func */
            0, 56, 4, /* 1842: struct.evp_pkey_st */
            	1853, 16,
            	1954, 24,
            	1206, 32,
            	809, 48,
            1, 8, 1, /* 1853: pointer.struct.evp_pkey_asn1_method_st */
            	1858, 0,
            0, 208, 24, /* 1858: struct.evp_pkey_asn1_method_st */
            	53, 16,
            	53, 24,
            	1909, 32,
            	1912, 40,
            	1915, 48,
            	1918, 56,
            	1921, 64,
            	1924, 72,
            	1918, 80,
            	1927, 88,
            	1927, 96,
            	1930, 104,
            	1933, 112,
            	1927, 120,
            	1936, 128,
            	1915, 136,
            	1918, 144,
            	1939, 152,
            	1942, 160,
            	1945, 168,
            	1930, 176,
            	1933, 184,
            	1948, 192,
            	1951, 200,
            8884097, 8, 0, /* 1909: pointer.func */
            8884097, 8, 0, /* 1912: pointer.func */
            8884097, 8, 0, /* 1915: pointer.func */
            8884097, 8, 0, /* 1918: pointer.func */
            8884097, 8, 0, /* 1921: pointer.func */
            8884097, 8, 0, /* 1924: pointer.func */
            8884097, 8, 0, /* 1927: pointer.func */
            8884097, 8, 0, /* 1930: pointer.func */
            8884097, 8, 0, /* 1933: pointer.func */
            8884097, 8, 0, /* 1936: pointer.func */
            8884097, 8, 0, /* 1939: pointer.func */
            8884097, 8, 0, /* 1942: pointer.func */
            8884097, 8, 0, /* 1945: pointer.func */
            8884097, 8, 0, /* 1948: pointer.func */
            8884097, 8, 0, /* 1951: pointer.func */
            1, 8, 1, /* 1954: pointer.struct.engine_st */
            	224, 0,
            1, 8, 1, /* 1959: pointer.struct.asn1_string_st */
            	1964, 0,
            0, 24, 1, /* 1964: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 1969: pointer.struct.stack_st_ASN1_OBJECT */
            	1974, 0,
            0, 32, 2, /* 1974: struct.stack_st_fake_ASN1_OBJECT */
            	1981, 8,
            	180, 24,
            8884099, 8, 2, /* 1981: pointer_to_array_of_pointers_to_stack */
            	1988, 0,
            	1052, 20,
            0, 8, 1, /* 1988: pointer.ASN1_OBJECT */
            	1993, 0,
            0, 0, 1, /* 1993: ASN1_OBJECT */
            	1998, 0,
            0, 40, 3, /* 1998: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	859, 24,
            1, 8, 1, /* 2007: pointer.struct.x509_cert_aux_st */
            	2012, 0,
            0, 40, 5, /* 2012: struct.x509_cert_aux_st */
            	1969, 0,
            	1969, 8,
            	1959, 16,
            	2025, 24,
            	2030, 32,
            1, 8, 1, /* 2025: pointer.struct.asn1_string_st */
            	1964, 0,
            1, 8, 1, /* 2030: pointer.struct.stack_st_X509_ALGOR */
            	2035, 0,
            0, 32, 2, /* 2035: struct.stack_st_fake_X509_ALGOR */
            	2042, 8,
            	180, 24,
            8884099, 8, 2, /* 2042: pointer_to_array_of_pointers_to_stack */
            	2049, 0,
            	1052, 20,
            0, 8, 1, /* 2049: pointer.X509_ALGOR */
            	2054, 0,
            0, 0, 1, /* 2054: X509_ALGOR */
            	2059, 0,
            0, 16, 2, /* 2059: struct.X509_algor_st */
            	2066, 0,
            	2080, 8,
            1, 8, 1, /* 2066: pointer.struct.asn1_object_st */
            	2071, 0,
            0, 40, 3, /* 2071: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	859, 24,
            1, 8, 1, /* 2080: pointer.struct.asn1_type_st */
            	2085, 0,
            0, 16, 1, /* 2085: struct.asn1_type_st */
            	2090, 8,
            0, 8, 20, /* 2090: union.unknown */
            	53, 0,
            	2133, 0,
            	2066, 0,
            	2143, 0,
            	2148, 0,
            	2153, 0,
            	2158, 0,
            	2163, 0,
            	2168, 0,
            	2173, 0,
            	2178, 0,
            	2183, 0,
            	2188, 0,
            	2193, 0,
            	2198, 0,
            	2203, 0,
            	2208, 0,
            	2133, 0,
            	2133, 0,
            	2213, 0,
            1, 8, 1, /* 2133: pointer.struct.asn1_string_st */
            	2138, 0,
            0, 24, 1, /* 2138: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 2143: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2148: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2153: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2158: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2163: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2168: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2173: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2178: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2183: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2188: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2193: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2198: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2203: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2208: pointer.struct.asn1_string_st */
            	2138, 0,
            1, 8, 1, /* 2213: pointer.struct.ASN1_VALUE_st */
            	2218, 0,
            0, 0, 0, /* 2218: struct.ASN1_VALUE_st */
            0, 32, 2, /* 2221: struct.stack_st */
            	175, 8,
            	180, 24,
            0, 32, 1, /* 2228: struct.stack_st_void */
            	2221, 0,
            0, 24, 1, /* 2233: struct.ASN1_ENCODING_st */
            	145, 0,
            1, 8, 1, /* 2238: pointer.struct.stack_st_X509_EXTENSION */
            	2243, 0,
            0, 32, 2, /* 2243: struct.stack_st_fake_X509_EXTENSION */
            	2250, 8,
            	180, 24,
            8884099, 8, 2, /* 2250: pointer_to_array_of_pointers_to_stack */
            	2257, 0,
            	1052, 20,
            0, 8, 1, /* 2257: pointer.X509_EXTENSION */
            	2262, 0,
            0, 0, 1, /* 2262: X509_EXTENSION */
            	2267, 0,
            0, 24, 2, /* 2267: struct.X509_extension_st */
            	2274, 0,
            	2288, 16,
            1, 8, 1, /* 2274: pointer.struct.asn1_object_st */
            	2279, 0,
            0, 40, 3, /* 2279: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	859, 24,
            1, 8, 1, /* 2288: pointer.struct.asn1_string_st */
            	2293, 0,
            0, 24, 1, /* 2293: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 2298: pointer.struct.X509_pubkey_st */
            	2303, 0,
            0, 24, 3, /* 2303: struct.X509_pubkey_st */
            	2312, 0,
            	2317, 8,
            	2327, 16,
            1, 8, 1, /* 2312: pointer.struct.X509_algor_st */
            	2059, 0,
            1, 8, 1, /* 2317: pointer.struct.asn1_string_st */
            	2322, 0,
            0, 24, 1, /* 2322: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 2327: pointer.struct.evp_pkey_st */
            	2332, 0,
            0, 56, 4, /* 2332: struct.evp_pkey_st */
            	2343, 16,
            	1346, 24,
            	2348, 32,
            	2381, 48,
            1, 8, 1, /* 2343: pointer.struct.evp_pkey_asn1_method_st */
            	1858, 0,
            0, 8, 5, /* 2348: union.unknown */
            	53, 0,
            	2361, 0,
            	2366, 0,
            	2371, 0,
            	2376, 0,
            1, 8, 1, /* 2361: pointer.struct.rsa_st */
            	572, 0,
            1, 8, 1, /* 2366: pointer.struct.dsa_st */
            	1224, 0,
            1, 8, 1, /* 2371: pointer.struct.dh_st */
            	94, 0,
            1, 8, 1, /* 2376: pointer.struct.ec_key_st */
            	1356, 0,
            1, 8, 1, /* 2381: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2386, 0,
            0, 32, 2, /* 2386: struct.stack_st_fake_X509_ATTRIBUTE */
            	2393, 8,
            	180, 24,
            8884099, 8, 2, /* 2393: pointer_to_array_of_pointers_to_stack */
            	2400, 0,
            	1052, 20,
            0, 8, 1, /* 2400: pointer.X509_ATTRIBUTE */
            	833, 0,
            1, 8, 1, /* 2405: pointer.struct.X509_val_st */
            	2410, 0,
            0, 16, 2, /* 2410: struct.X509_val_st */
            	2417, 0,
            	2417, 8,
            1, 8, 1, /* 2417: pointer.struct.asn1_string_st */
            	1964, 0,
            1, 8, 1, /* 2422: pointer.struct.buf_mem_st */
            	2427, 0,
            0, 24, 1, /* 2427: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 2432: pointer.struct.X509_name_st */
            	2437, 0,
            0, 40, 3, /* 2437: struct.X509_name_st */
            	2446, 0,
            	2422, 16,
            	145, 24,
            1, 8, 1, /* 2446: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2451, 0,
            0, 32, 2, /* 2451: struct.stack_st_fake_X509_NAME_ENTRY */
            	2458, 8,
            	180, 24,
            8884099, 8, 2, /* 2458: pointer_to_array_of_pointers_to_stack */
            	2465, 0,
            	1052, 20,
            0, 8, 1, /* 2465: pointer.X509_NAME_ENTRY */
            	2470, 0,
            0, 0, 1, /* 2470: X509_NAME_ENTRY */
            	2475, 0,
            0, 24, 2, /* 2475: struct.X509_name_entry_st */
            	2482, 0,
            	2496, 8,
            1, 8, 1, /* 2482: pointer.struct.asn1_object_st */
            	2487, 0,
            0, 40, 3, /* 2487: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	859, 24,
            1, 8, 1, /* 2496: pointer.struct.asn1_string_st */
            	2501, 0,
            0, 24, 1, /* 2501: struct.asn1_string_st */
            	145, 8,
            8884097, 8, 0, /* 2506: pointer.func */
            0, 104, 11, /* 2509: struct.x509_cinf_st */
            	2534, 0,
            	2534, 8,
            	2539, 16,
            	2432, 24,
            	2405, 32,
            	2432, 40,
            	2298, 48,
            	2544, 56,
            	2544, 64,
            	2238, 72,
            	2233, 80,
            1, 8, 1, /* 2534: pointer.struct.asn1_string_st */
            	1964, 0,
            1, 8, 1, /* 2539: pointer.struct.X509_algor_st */
            	2059, 0,
            1, 8, 1, /* 2544: pointer.struct.asn1_string_st */
            	1964, 0,
            0, 184, 12, /* 2549: struct.x509_st */
            	2576, 0,
            	2539, 8,
            	2544, 16,
            	53, 32,
            	2581, 40,
            	2025, 104,
            	2591, 112,
            	2914, 120,
            	3336, 128,
            	3475, 136,
            	3499, 144,
            	2007, 176,
            1, 8, 1, /* 2576: pointer.struct.x509_cinf_st */
            	2509, 0,
            0, 16, 1, /* 2581: struct.crypto_ex_data_st */
            	2586, 0,
            1, 8, 1, /* 2586: pointer.struct.stack_st_void */
            	2228, 0,
            1, 8, 1, /* 2591: pointer.struct.AUTHORITY_KEYID_st */
            	2596, 0,
            0, 24, 3, /* 2596: struct.AUTHORITY_KEYID_st */
            	2605, 0,
            	2615, 8,
            	2909, 16,
            1, 8, 1, /* 2605: pointer.struct.asn1_string_st */
            	2610, 0,
            0, 24, 1, /* 2610: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 2615: pointer.struct.stack_st_GENERAL_NAME */
            	2620, 0,
            0, 32, 2, /* 2620: struct.stack_st_fake_GENERAL_NAME */
            	2627, 8,
            	180, 24,
            8884099, 8, 2, /* 2627: pointer_to_array_of_pointers_to_stack */
            	2634, 0,
            	1052, 20,
            0, 8, 1, /* 2634: pointer.GENERAL_NAME */
            	2639, 0,
            0, 0, 1, /* 2639: GENERAL_NAME */
            	2644, 0,
            0, 16, 1, /* 2644: struct.GENERAL_NAME_st */
            	2649, 8,
            0, 8, 15, /* 2649: union.unknown */
            	53, 0,
            	2682, 0,
            	2801, 0,
            	2801, 0,
            	2708, 0,
            	2849, 0,
            	2897, 0,
            	2801, 0,
            	2786, 0,
            	2694, 0,
            	2786, 0,
            	2849, 0,
            	2801, 0,
            	2694, 0,
            	2708, 0,
            1, 8, 1, /* 2682: pointer.struct.otherName_st */
            	2687, 0,
            0, 16, 2, /* 2687: struct.otherName_st */
            	2694, 0,
            	2708, 8,
            1, 8, 1, /* 2694: pointer.struct.asn1_object_st */
            	2699, 0,
            0, 40, 3, /* 2699: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	859, 24,
            1, 8, 1, /* 2708: pointer.struct.asn1_type_st */
            	2713, 0,
            0, 16, 1, /* 2713: struct.asn1_type_st */
            	2718, 8,
            0, 8, 20, /* 2718: union.unknown */
            	53, 0,
            	2761, 0,
            	2694, 0,
            	2771, 0,
            	2776, 0,
            	2781, 0,
            	2786, 0,
            	2791, 0,
            	2796, 0,
            	2801, 0,
            	2806, 0,
            	2811, 0,
            	2816, 0,
            	2821, 0,
            	2826, 0,
            	2831, 0,
            	2836, 0,
            	2761, 0,
            	2761, 0,
            	2841, 0,
            1, 8, 1, /* 2761: pointer.struct.asn1_string_st */
            	2766, 0,
            0, 24, 1, /* 2766: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 2771: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2776: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2781: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2786: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2791: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2796: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2801: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2806: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2811: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2816: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2821: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2826: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2831: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2836: pointer.struct.asn1_string_st */
            	2766, 0,
            1, 8, 1, /* 2841: pointer.struct.ASN1_VALUE_st */
            	2846, 0,
            0, 0, 0, /* 2846: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2849: pointer.struct.X509_name_st */
            	2854, 0,
            0, 40, 3, /* 2854: struct.X509_name_st */
            	2863, 0,
            	2887, 16,
            	145, 24,
            1, 8, 1, /* 2863: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2868, 0,
            0, 32, 2, /* 2868: struct.stack_st_fake_X509_NAME_ENTRY */
            	2875, 8,
            	180, 24,
            8884099, 8, 2, /* 2875: pointer_to_array_of_pointers_to_stack */
            	2882, 0,
            	1052, 20,
            0, 8, 1, /* 2882: pointer.X509_NAME_ENTRY */
            	2470, 0,
            1, 8, 1, /* 2887: pointer.struct.buf_mem_st */
            	2892, 0,
            0, 24, 1, /* 2892: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 2897: pointer.struct.EDIPartyName_st */
            	2902, 0,
            0, 16, 2, /* 2902: struct.EDIPartyName_st */
            	2761, 0,
            	2761, 8,
            1, 8, 1, /* 2909: pointer.struct.asn1_string_st */
            	2610, 0,
            1, 8, 1, /* 2914: pointer.struct.X509_POLICY_CACHE_st */
            	2919, 0,
            0, 40, 2, /* 2919: struct.X509_POLICY_CACHE_st */
            	2926, 0,
            	3236, 8,
            1, 8, 1, /* 2926: pointer.struct.X509_POLICY_DATA_st */
            	2931, 0,
            0, 32, 3, /* 2931: struct.X509_POLICY_DATA_st */
            	2940, 8,
            	2954, 16,
            	3212, 24,
            1, 8, 1, /* 2940: pointer.struct.asn1_object_st */
            	2945, 0,
            0, 40, 3, /* 2945: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	859, 24,
            1, 8, 1, /* 2954: pointer.struct.stack_st_POLICYQUALINFO */
            	2959, 0,
            0, 32, 2, /* 2959: struct.stack_st_fake_POLICYQUALINFO */
            	2966, 8,
            	180, 24,
            8884099, 8, 2, /* 2966: pointer_to_array_of_pointers_to_stack */
            	2973, 0,
            	1052, 20,
            0, 8, 1, /* 2973: pointer.POLICYQUALINFO */
            	2978, 0,
            0, 0, 1, /* 2978: POLICYQUALINFO */
            	2983, 0,
            0, 16, 2, /* 2983: struct.POLICYQUALINFO_st */
            	2990, 0,
            	3004, 8,
            1, 8, 1, /* 2990: pointer.struct.asn1_object_st */
            	2995, 0,
            0, 40, 3, /* 2995: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	859, 24,
            0, 8, 3, /* 3004: union.unknown */
            	3013, 0,
            	3023, 0,
            	3086, 0,
            1, 8, 1, /* 3013: pointer.struct.asn1_string_st */
            	3018, 0,
            0, 24, 1, /* 3018: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 3023: pointer.struct.USERNOTICE_st */
            	3028, 0,
            0, 16, 2, /* 3028: struct.USERNOTICE_st */
            	3035, 0,
            	3047, 8,
            1, 8, 1, /* 3035: pointer.struct.NOTICEREF_st */
            	3040, 0,
            0, 16, 2, /* 3040: struct.NOTICEREF_st */
            	3047, 0,
            	3052, 8,
            1, 8, 1, /* 3047: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3052: pointer.struct.stack_st_ASN1_INTEGER */
            	3057, 0,
            0, 32, 2, /* 3057: struct.stack_st_fake_ASN1_INTEGER */
            	3064, 8,
            	180, 24,
            8884099, 8, 2, /* 3064: pointer_to_array_of_pointers_to_stack */
            	3071, 0,
            	1052, 20,
            0, 8, 1, /* 3071: pointer.ASN1_INTEGER */
            	3076, 0,
            0, 0, 1, /* 3076: ASN1_INTEGER */
            	3081, 0,
            0, 24, 1, /* 3081: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 3086: pointer.struct.asn1_type_st */
            	3091, 0,
            0, 16, 1, /* 3091: struct.asn1_type_st */
            	3096, 8,
            0, 8, 20, /* 3096: union.unknown */
            	53, 0,
            	3047, 0,
            	2990, 0,
            	3139, 0,
            	3144, 0,
            	3149, 0,
            	3154, 0,
            	3159, 0,
            	3164, 0,
            	3013, 0,
            	3169, 0,
            	3174, 0,
            	3179, 0,
            	3184, 0,
            	3189, 0,
            	3194, 0,
            	3199, 0,
            	3047, 0,
            	3047, 0,
            	3204, 0,
            1, 8, 1, /* 3139: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3144: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3149: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3154: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3159: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3164: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3169: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3174: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3179: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3184: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3189: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3194: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3199: pointer.struct.asn1_string_st */
            	3018, 0,
            1, 8, 1, /* 3204: pointer.struct.ASN1_VALUE_st */
            	3209, 0,
            0, 0, 0, /* 3209: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3212: pointer.struct.stack_st_ASN1_OBJECT */
            	3217, 0,
            0, 32, 2, /* 3217: struct.stack_st_fake_ASN1_OBJECT */
            	3224, 8,
            	180, 24,
            8884099, 8, 2, /* 3224: pointer_to_array_of_pointers_to_stack */
            	3231, 0,
            	1052, 20,
            0, 8, 1, /* 3231: pointer.ASN1_OBJECT */
            	1993, 0,
            1, 8, 1, /* 3236: pointer.struct.stack_st_X509_POLICY_DATA */
            	3241, 0,
            0, 32, 2, /* 3241: struct.stack_st_fake_X509_POLICY_DATA */
            	3248, 8,
            	180, 24,
            8884099, 8, 2, /* 3248: pointer_to_array_of_pointers_to_stack */
            	3255, 0,
            	1052, 20,
            0, 8, 1, /* 3255: pointer.X509_POLICY_DATA */
            	3260, 0,
            0, 0, 1, /* 3260: X509_POLICY_DATA */
            	3265, 0,
            0, 32, 3, /* 3265: struct.X509_POLICY_DATA_st */
            	3274, 8,
            	3288, 16,
            	3312, 24,
            1, 8, 1, /* 3274: pointer.struct.asn1_object_st */
            	3279, 0,
            0, 40, 3, /* 3279: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	859, 24,
            1, 8, 1, /* 3288: pointer.struct.stack_st_POLICYQUALINFO */
            	3293, 0,
            0, 32, 2, /* 3293: struct.stack_st_fake_POLICYQUALINFO */
            	3300, 8,
            	180, 24,
            8884099, 8, 2, /* 3300: pointer_to_array_of_pointers_to_stack */
            	3307, 0,
            	1052, 20,
            0, 8, 1, /* 3307: pointer.POLICYQUALINFO */
            	2978, 0,
            1, 8, 1, /* 3312: pointer.struct.stack_st_ASN1_OBJECT */
            	3317, 0,
            0, 32, 2, /* 3317: struct.stack_st_fake_ASN1_OBJECT */
            	3324, 8,
            	180, 24,
            8884099, 8, 2, /* 3324: pointer_to_array_of_pointers_to_stack */
            	3331, 0,
            	1052, 20,
            0, 8, 1, /* 3331: pointer.ASN1_OBJECT */
            	1993, 0,
            1, 8, 1, /* 3336: pointer.struct.stack_st_DIST_POINT */
            	3341, 0,
            0, 32, 2, /* 3341: struct.stack_st_fake_DIST_POINT */
            	3348, 8,
            	180, 24,
            8884099, 8, 2, /* 3348: pointer_to_array_of_pointers_to_stack */
            	3355, 0,
            	1052, 20,
            0, 8, 1, /* 3355: pointer.DIST_POINT */
            	3360, 0,
            0, 0, 1, /* 3360: DIST_POINT */
            	3365, 0,
            0, 32, 3, /* 3365: struct.DIST_POINT_st */
            	3374, 0,
            	3465, 8,
            	3393, 16,
            1, 8, 1, /* 3374: pointer.struct.DIST_POINT_NAME_st */
            	3379, 0,
            0, 24, 2, /* 3379: struct.DIST_POINT_NAME_st */
            	3386, 8,
            	3441, 16,
            0, 8, 2, /* 3386: union.unknown */
            	3393, 0,
            	3417, 0,
            1, 8, 1, /* 3393: pointer.struct.stack_st_GENERAL_NAME */
            	3398, 0,
            0, 32, 2, /* 3398: struct.stack_st_fake_GENERAL_NAME */
            	3405, 8,
            	180, 24,
            8884099, 8, 2, /* 3405: pointer_to_array_of_pointers_to_stack */
            	3412, 0,
            	1052, 20,
            0, 8, 1, /* 3412: pointer.GENERAL_NAME */
            	2639, 0,
            1, 8, 1, /* 3417: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3422, 0,
            0, 32, 2, /* 3422: struct.stack_st_fake_X509_NAME_ENTRY */
            	3429, 8,
            	180, 24,
            8884099, 8, 2, /* 3429: pointer_to_array_of_pointers_to_stack */
            	3436, 0,
            	1052, 20,
            0, 8, 1, /* 3436: pointer.X509_NAME_ENTRY */
            	2470, 0,
            1, 8, 1, /* 3441: pointer.struct.X509_name_st */
            	3446, 0,
            0, 40, 3, /* 3446: struct.X509_name_st */
            	3417, 0,
            	3455, 16,
            	145, 24,
            1, 8, 1, /* 3455: pointer.struct.buf_mem_st */
            	3460, 0,
            0, 24, 1, /* 3460: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 3465: pointer.struct.asn1_string_st */
            	3470, 0,
            0, 24, 1, /* 3470: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 3475: pointer.struct.stack_st_GENERAL_NAME */
            	3480, 0,
            0, 32, 2, /* 3480: struct.stack_st_fake_GENERAL_NAME */
            	3487, 8,
            	180, 24,
            8884099, 8, 2, /* 3487: pointer_to_array_of_pointers_to_stack */
            	3494, 0,
            	1052, 20,
            0, 8, 1, /* 3494: pointer.GENERAL_NAME */
            	2639, 0,
            1, 8, 1, /* 3499: pointer.struct.NAME_CONSTRAINTS_st */
            	3504, 0,
            0, 16, 2, /* 3504: struct.NAME_CONSTRAINTS_st */
            	3511, 0,
            	3511, 8,
            1, 8, 1, /* 3511: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3516, 0,
            0, 32, 2, /* 3516: struct.stack_st_fake_GENERAL_SUBTREE */
            	3523, 8,
            	180, 24,
            8884099, 8, 2, /* 3523: pointer_to_array_of_pointers_to_stack */
            	3530, 0,
            	1052, 20,
            0, 8, 1, /* 3530: pointer.GENERAL_SUBTREE */
            	3535, 0,
            0, 0, 1, /* 3535: GENERAL_SUBTREE */
            	3540, 0,
            0, 24, 3, /* 3540: struct.GENERAL_SUBTREE_st */
            	3549, 0,
            	3681, 8,
            	3681, 16,
            1, 8, 1, /* 3549: pointer.struct.GENERAL_NAME_st */
            	3554, 0,
            0, 16, 1, /* 3554: struct.GENERAL_NAME_st */
            	3559, 8,
            0, 8, 15, /* 3559: union.unknown */
            	53, 0,
            	3592, 0,
            	3711, 0,
            	3711, 0,
            	3618, 0,
            	3751, 0,
            	3799, 0,
            	3711, 0,
            	3696, 0,
            	3604, 0,
            	3696, 0,
            	3751, 0,
            	3711, 0,
            	3604, 0,
            	3618, 0,
            1, 8, 1, /* 3592: pointer.struct.otherName_st */
            	3597, 0,
            0, 16, 2, /* 3597: struct.otherName_st */
            	3604, 0,
            	3618, 8,
            1, 8, 1, /* 3604: pointer.struct.asn1_object_st */
            	3609, 0,
            0, 40, 3, /* 3609: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	859, 24,
            1, 8, 1, /* 3618: pointer.struct.asn1_type_st */
            	3623, 0,
            0, 16, 1, /* 3623: struct.asn1_type_st */
            	3628, 8,
            0, 8, 20, /* 3628: union.unknown */
            	53, 0,
            	3671, 0,
            	3604, 0,
            	3681, 0,
            	3686, 0,
            	3691, 0,
            	3696, 0,
            	3701, 0,
            	3706, 0,
            	3711, 0,
            	3716, 0,
            	3721, 0,
            	3726, 0,
            	3731, 0,
            	3736, 0,
            	3741, 0,
            	3746, 0,
            	3671, 0,
            	3671, 0,
            	3204, 0,
            1, 8, 1, /* 3671: pointer.struct.asn1_string_st */
            	3676, 0,
            0, 24, 1, /* 3676: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 3681: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3686: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3691: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3696: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3701: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3706: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3711: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3716: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3721: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3726: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3731: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3736: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3741: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3746: pointer.struct.asn1_string_st */
            	3676, 0,
            1, 8, 1, /* 3751: pointer.struct.X509_name_st */
            	3756, 0,
            0, 40, 3, /* 3756: struct.X509_name_st */
            	3765, 0,
            	3789, 16,
            	145, 24,
            1, 8, 1, /* 3765: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3770, 0,
            0, 32, 2, /* 3770: struct.stack_st_fake_X509_NAME_ENTRY */
            	3777, 8,
            	180, 24,
            8884099, 8, 2, /* 3777: pointer_to_array_of_pointers_to_stack */
            	3784, 0,
            	1052, 20,
            0, 8, 1, /* 3784: pointer.X509_NAME_ENTRY */
            	2470, 0,
            1, 8, 1, /* 3789: pointer.struct.buf_mem_st */
            	3794, 0,
            0, 24, 1, /* 3794: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 3799: pointer.struct.EDIPartyName_st */
            	3804, 0,
            0, 16, 2, /* 3804: struct.EDIPartyName_st */
            	3671, 0,
            	3671, 8,
            0, 24, 3, /* 3811: struct.cert_pkey_st */
            	3820, 0,
            	3825, 8,
            	770, 16,
            1, 8, 1, /* 3820: pointer.struct.x509_st */
            	2549, 0,
            1, 8, 1, /* 3825: pointer.struct.evp_pkey_st */
            	1842, 0,
            1, 8, 1, /* 3830: pointer.struct.cert_st */
            	3835, 0,
            0, 296, 7, /* 3835: struct.cert_st */
            	3852, 0,
            	567, 48,
            	3857, 56,
            	89, 64,
            	3860, 72,
            	3863, 80,
            	3868, 88,
            1, 8, 1, /* 3852: pointer.struct.cert_pkey_st */
            	3811, 0,
            8884097, 8, 0, /* 3857: pointer.func */
            8884097, 8, 0, /* 3860: pointer.func */
            1, 8, 1, /* 3863: pointer.struct.ec_key_st */
            	1356, 0,
            8884097, 8, 0, /* 3868: pointer.func */
            1, 8, 1, /* 3871: pointer.struct.stack_st_X509_NAME */
            	3876, 0,
            0, 32, 2, /* 3876: struct.stack_st_fake_X509_NAME */
            	3883, 8,
            	180, 24,
            8884099, 8, 2, /* 3883: pointer_to_array_of_pointers_to_stack */
            	3890, 0,
            	1052, 20,
            0, 8, 1, /* 3890: pointer.X509_NAME */
            	3895, 0,
            0, 0, 1, /* 3895: X509_NAME */
            	3900, 0,
            0, 40, 3, /* 3900: struct.X509_name_st */
            	3909, 0,
            	3933, 16,
            	145, 24,
            1, 8, 1, /* 3909: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3914, 0,
            0, 32, 2, /* 3914: struct.stack_st_fake_X509_NAME_ENTRY */
            	3921, 8,
            	180, 24,
            8884099, 8, 2, /* 3921: pointer_to_array_of_pointers_to_stack */
            	3928, 0,
            	1052, 20,
            0, 8, 1, /* 3928: pointer.X509_NAME_ENTRY */
            	2470, 0,
            1, 8, 1, /* 3933: pointer.struct.buf_mem_st */
            	3938, 0,
            0, 24, 1, /* 3938: struct.buf_mem_st */
            	53, 8,
            8884097, 8, 0, /* 3943: pointer.func */
            8884097, 8, 0, /* 3946: pointer.func */
            8884097, 8, 0, /* 3949: pointer.func */
            0, 64, 7, /* 3952: struct.comp_method_st */
            	5, 8,
            	3969, 16,
            	3949, 24,
            	3946, 32,
            	3946, 40,
            	3972, 48,
            	3972, 56,
            8884097, 8, 0, /* 3969: pointer.func */
            8884097, 8, 0, /* 3972: pointer.func */
            1, 8, 1, /* 3975: pointer.struct.comp_method_st */
            	3952, 0,
            0, 0, 1, /* 3980: SSL_COMP */
            	3985, 0,
            0, 24, 2, /* 3985: struct.ssl_comp_st */
            	5, 8,
            	3975, 16,
            1, 8, 1, /* 3992: pointer.struct.stack_st_SSL_COMP */
            	3997, 0,
            0, 32, 2, /* 3997: struct.stack_st_fake_SSL_COMP */
            	4004, 8,
            	180, 24,
            8884099, 8, 2, /* 4004: pointer_to_array_of_pointers_to_stack */
            	4011, 0,
            	1052, 20,
            0, 8, 1, /* 4011: pointer.SSL_COMP */
            	3980, 0,
            1, 8, 1, /* 4016: pointer.struct.stack_st_X509 */
            	4021, 0,
            0, 32, 2, /* 4021: struct.stack_st_fake_X509 */
            	4028, 8,
            	180, 24,
            8884099, 8, 2, /* 4028: pointer_to_array_of_pointers_to_stack */
            	4035, 0,
            	1052, 20,
            0, 8, 1, /* 4035: pointer.X509 */
            	4040, 0,
            0, 0, 1, /* 4040: X509 */
            	4045, 0,
            0, 184, 12, /* 4045: struct.x509_st */
            	4072, 0,
            	4112, 8,
            	4144, 16,
            	53, 32,
            	1273, 40,
            	4178, 104,
            	4183, 112,
            	4188, 120,
            	4193, 128,
            	4217, 136,
            	4241, 144,
            	4246, 176,
            1, 8, 1, /* 4072: pointer.struct.x509_cinf_st */
            	4077, 0,
            0, 104, 11, /* 4077: struct.x509_cinf_st */
            	4102, 0,
            	4102, 8,
            	4112, 16,
            	4117, 24,
            	4122, 32,
            	4117, 40,
            	4139, 48,
            	4144, 56,
            	4144, 64,
            	4149, 72,
            	4173, 80,
            1, 8, 1, /* 4102: pointer.struct.asn1_string_st */
            	4107, 0,
            0, 24, 1, /* 4107: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 4112: pointer.struct.X509_algor_st */
            	2059, 0,
            1, 8, 1, /* 4117: pointer.struct.X509_name_st */
            	3900, 0,
            1, 8, 1, /* 4122: pointer.struct.X509_val_st */
            	4127, 0,
            0, 16, 2, /* 4127: struct.X509_val_st */
            	4134, 0,
            	4134, 8,
            1, 8, 1, /* 4134: pointer.struct.asn1_string_st */
            	4107, 0,
            1, 8, 1, /* 4139: pointer.struct.X509_pubkey_st */
            	2303, 0,
            1, 8, 1, /* 4144: pointer.struct.asn1_string_st */
            	4107, 0,
            1, 8, 1, /* 4149: pointer.struct.stack_st_X509_EXTENSION */
            	4154, 0,
            0, 32, 2, /* 4154: struct.stack_st_fake_X509_EXTENSION */
            	4161, 8,
            	180, 24,
            8884099, 8, 2, /* 4161: pointer_to_array_of_pointers_to_stack */
            	4168, 0,
            	1052, 20,
            0, 8, 1, /* 4168: pointer.X509_EXTENSION */
            	2262, 0,
            0, 24, 1, /* 4173: struct.ASN1_ENCODING_st */
            	145, 0,
            1, 8, 1, /* 4178: pointer.struct.asn1_string_st */
            	4107, 0,
            1, 8, 1, /* 4183: pointer.struct.AUTHORITY_KEYID_st */
            	2596, 0,
            1, 8, 1, /* 4188: pointer.struct.X509_POLICY_CACHE_st */
            	2919, 0,
            1, 8, 1, /* 4193: pointer.struct.stack_st_DIST_POINT */
            	4198, 0,
            0, 32, 2, /* 4198: struct.stack_st_fake_DIST_POINT */
            	4205, 8,
            	180, 24,
            8884099, 8, 2, /* 4205: pointer_to_array_of_pointers_to_stack */
            	4212, 0,
            	1052, 20,
            0, 8, 1, /* 4212: pointer.DIST_POINT */
            	3360, 0,
            1, 8, 1, /* 4217: pointer.struct.stack_st_GENERAL_NAME */
            	4222, 0,
            0, 32, 2, /* 4222: struct.stack_st_fake_GENERAL_NAME */
            	4229, 8,
            	180, 24,
            8884099, 8, 2, /* 4229: pointer_to_array_of_pointers_to_stack */
            	4236, 0,
            	1052, 20,
            0, 8, 1, /* 4236: pointer.GENERAL_NAME */
            	2639, 0,
            1, 8, 1, /* 4241: pointer.struct.NAME_CONSTRAINTS_st */
            	3504, 0,
            1, 8, 1, /* 4246: pointer.struct.x509_cert_aux_st */
            	4251, 0,
            0, 40, 5, /* 4251: struct.x509_cert_aux_st */
            	4264, 0,
            	4264, 8,
            	4288, 16,
            	4178, 24,
            	4293, 32,
            1, 8, 1, /* 4264: pointer.struct.stack_st_ASN1_OBJECT */
            	4269, 0,
            0, 32, 2, /* 4269: struct.stack_st_fake_ASN1_OBJECT */
            	4276, 8,
            	180, 24,
            8884099, 8, 2, /* 4276: pointer_to_array_of_pointers_to_stack */
            	4283, 0,
            	1052, 20,
            0, 8, 1, /* 4283: pointer.ASN1_OBJECT */
            	1993, 0,
            1, 8, 1, /* 4288: pointer.struct.asn1_string_st */
            	4107, 0,
            1, 8, 1, /* 4293: pointer.struct.stack_st_X509_ALGOR */
            	4298, 0,
            0, 32, 2, /* 4298: struct.stack_st_fake_X509_ALGOR */
            	4305, 8,
            	180, 24,
            8884099, 8, 2, /* 4305: pointer_to_array_of_pointers_to_stack */
            	4312, 0,
            	1052, 20,
            0, 8, 1, /* 4312: pointer.X509_ALGOR */
            	2054, 0,
            8884097, 8, 0, /* 4317: pointer.func */
            8884097, 8, 0, /* 4320: pointer.func */
            8884097, 8, 0, /* 4323: pointer.func */
            8884097, 8, 0, /* 4326: pointer.func */
            8884097, 8, 0, /* 4329: pointer.func */
            8884097, 8, 0, /* 4332: pointer.func */
            0, 88, 1, /* 4335: struct.ssl_cipher_st */
            	5, 8,
            0, 40, 5, /* 4340: struct.x509_cert_aux_st */
            	4353, 0,
            	4353, 8,
            	4377, 16,
            	4387, 24,
            	4392, 32,
            1, 8, 1, /* 4353: pointer.struct.stack_st_ASN1_OBJECT */
            	4358, 0,
            0, 32, 2, /* 4358: struct.stack_st_fake_ASN1_OBJECT */
            	4365, 8,
            	180, 24,
            8884099, 8, 2, /* 4365: pointer_to_array_of_pointers_to_stack */
            	4372, 0,
            	1052, 20,
            0, 8, 1, /* 4372: pointer.ASN1_OBJECT */
            	1993, 0,
            1, 8, 1, /* 4377: pointer.struct.asn1_string_st */
            	4382, 0,
            0, 24, 1, /* 4382: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 4387: pointer.struct.asn1_string_st */
            	4382, 0,
            1, 8, 1, /* 4392: pointer.struct.stack_st_X509_ALGOR */
            	4397, 0,
            0, 32, 2, /* 4397: struct.stack_st_fake_X509_ALGOR */
            	4404, 8,
            	180, 24,
            8884099, 8, 2, /* 4404: pointer_to_array_of_pointers_to_stack */
            	4411, 0,
            	1052, 20,
            0, 8, 1, /* 4411: pointer.X509_ALGOR */
            	2054, 0,
            1, 8, 1, /* 4416: pointer.struct.x509_cert_aux_st */
            	4340, 0,
            1, 8, 1, /* 4421: pointer.struct.stack_st_GENERAL_NAME */
            	4426, 0,
            0, 32, 2, /* 4426: struct.stack_st_fake_GENERAL_NAME */
            	4433, 8,
            	180, 24,
            8884099, 8, 2, /* 4433: pointer_to_array_of_pointers_to_stack */
            	4440, 0,
            	1052, 20,
            0, 8, 1, /* 4440: pointer.GENERAL_NAME */
            	2639, 0,
            1, 8, 1, /* 4445: pointer.struct.stack_st_DIST_POINT */
            	4450, 0,
            0, 32, 2, /* 4450: struct.stack_st_fake_DIST_POINT */
            	4457, 8,
            	180, 24,
            8884099, 8, 2, /* 4457: pointer_to_array_of_pointers_to_stack */
            	4464, 0,
            	1052, 20,
            0, 8, 1, /* 4464: pointer.DIST_POINT */
            	3360, 0,
            0, 24, 1, /* 4469: struct.ASN1_ENCODING_st */
            	145, 0,
            1, 8, 1, /* 4474: pointer.struct.stack_st_X509_EXTENSION */
            	4479, 0,
            0, 32, 2, /* 4479: struct.stack_st_fake_X509_EXTENSION */
            	4486, 8,
            	180, 24,
            8884099, 8, 2, /* 4486: pointer_to_array_of_pointers_to_stack */
            	4493, 0,
            	1052, 20,
            0, 8, 1, /* 4493: pointer.X509_EXTENSION */
            	2262, 0,
            1, 8, 1, /* 4498: pointer.struct.X509_pubkey_st */
            	2303, 0,
            0, 16, 2, /* 4503: struct.X509_val_st */
            	4510, 0,
            	4510, 8,
            1, 8, 1, /* 4510: pointer.struct.asn1_string_st */
            	4382, 0,
            1, 8, 1, /* 4515: pointer.struct.buf_mem_st */
            	4520, 0,
            0, 24, 1, /* 4520: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 4525: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4530, 0,
            0, 32, 2, /* 4530: struct.stack_st_fake_X509_NAME_ENTRY */
            	4537, 8,
            	180, 24,
            8884099, 8, 2, /* 4537: pointer_to_array_of_pointers_to_stack */
            	4544, 0,
            	1052, 20,
            0, 8, 1, /* 4544: pointer.X509_NAME_ENTRY */
            	2470, 0,
            1, 8, 1, /* 4549: pointer.struct.X509_name_st */
            	4554, 0,
            0, 40, 3, /* 4554: struct.X509_name_st */
            	4525, 0,
            	4515, 16,
            	145, 24,
            1, 8, 1, /* 4563: pointer.struct.X509_algor_st */
            	2059, 0,
            0, 24, 1, /* 4568: struct.ssl3_buf_freelist_st */
            	81, 16,
            1, 8, 1, /* 4573: pointer.struct.asn1_string_st */
            	4382, 0,
            1, 8, 1, /* 4578: pointer.struct.rsa_st */
            	572, 0,
            8884097, 8, 0, /* 4583: pointer.func */
            8884097, 8, 0, /* 4586: pointer.func */
            8884097, 8, 0, /* 4589: pointer.func */
            1, 8, 1, /* 4592: pointer.struct.env_md_st */
            	4597, 0,
            0, 120, 8, /* 4597: struct.env_md_st */
            	4616, 24,
            	4589, 32,
            	4619, 40,
            	4586, 48,
            	4616, 56,
            	800, 64,
            	803, 72,
            	4583, 112,
            8884097, 8, 0, /* 4616: pointer.func */
            8884097, 8, 0, /* 4619: pointer.func */
            1, 8, 1, /* 4622: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4627, 0,
            0, 32, 2, /* 4627: struct.stack_st_fake_X509_ATTRIBUTE */
            	4634, 8,
            	180, 24,
            8884099, 8, 2, /* 4634: pointer_to_array_of_pointers_to_stack */
            	4641, 0,
            	1052, 20,
            0, 8, 1, /* 4641: pointer.X509_ATTRIBUTE */
            	833, 0,
            1, 8, 1, /* 4646: pointer.struct.dh_st */
            	94, 0,
            1, 8, 1, /* 4651: pointer.struct.dsa_st */
            	1224, 0,
            0, 8, 5, /* 4656: union.unknown */
            	53, 0,
            	4669, 0,
            	4651, 0,
            	4646, 0,
            	1351, 0,
            1, 8, 1, /* 4669: pointer.struct.rsa_st */
            	572, 0,
            0, 56, 4, /* 4674: struct.evp_pkey_st */
            	1853, 16,
            	1954, 24,
            	4656, 32,
            	4622, 48,
            1, 8, 1, /* 4685: pointer.struct.stack_st_X509_ALGOR */
            	4690, 0,
            0, 32, 2, /* 4690: struct.stack_st_fake_X509_ALGOR */
            	4697, 8,
            	180, 24,
            8884099, 8, 2, /* 4697: pointer_to_array_of_pointers_to_stack */
            	4704, 0,
            	1052, 20,
            0, 8, 1, /* 4704: pointer.X509_ALGOR */
            	2054, 0,
            1, 8, 1, /* 4709: pointer.struct.NAME_CONSTRAINTS_st */
            	3504, 0,
            1, 8, 1, /* 4714: pointer.struct.asn1_string_st */
            	4719, 0,
            0, 24, 1, /* 4719: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 4724: pointer.struct.stack_st_ASN1_OBJECT */
            	4729, 0,
            0, 32, 2, /* 4729: struct.stack_st_fake_ASN1_OBJECT */
            	4736, 8,
            	180, 24,
            8884099, 8, 2, /* 4736: pointer_to_array_of_pointers_to_stack */
            	4743, 0,
            	1052, 20,
            0, 8, 1, /* 4743: pointer.ASN1_OBJECT */
            	1993, 0,
            0, 40, 5, /* 4748: struct.x509_cert_aux_st */
            	4724, 0,
            	4724, 8,
            	4714, 16,
            	4761, 24,
            	4685, 32,
            1, 8, 1, /* 4761: pointer.struct.asn1_string_st */
            	4719, 0,
            0, 32, 2, /* 4766: struct.stack_st */
            	175, 8,
            	180, 24,
            0, 32, 1, /* 4773: struct.stack_st_void */
            	4766, 0,
            1, 8, 1, /* 4778: pointer.struct.stack_st_void */
            	4773, 0,
            0, 16, 1, /* 4783: struct.crypto_ex_data_st */
            	4778, 0,
            0, 24, 1, /* 4788: struct.ASN1_ENCODING_st */
            	145, 0,
            1, 8, 1, /* 4793: pointer.struct.stack_st_X509_EXTENSION */
            	4798, 0,
            0, 32, 2, /* 4798: struct.stack_st_fake_X509_EXTENSION */
            	4805, 8,
            	180, 24,
            8884099, 8, 2, /* 4805: pointer_to_array_of_pointers_to_stack */
            	4812, 0,
            	1052, 20,
            0, 8, 1, /* 4812: pointer.X509_EXTENSION */
            	2262, 0,
            1, 8, 1, /* 4817: pointer.struct.asn1_string_st */
            	4719, 0,
            0, 16, 2, /* 4822: struct.X509_val_st */
            	4817, 0,
            	4817, 8,
            1, 8, 1, /* 4829: pointer.struct.X509_val_st */
            	4822, 0,
            0, 24, 1, /* 4834: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 4839: pointer.struct.buf_mem_st */
            	4834, 0,
            1, 8, 1, /* 4844: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4849, 0,
            0, 32, 2, /* 4849: struct.stack_st_fake_X509_NAME_ENTRY */
            	4856, 8,
            	180, 24,
            8884099, 8, 2, /* 4856: pointer_to_array_of_pointers_to_stack */
            	4863, 0,
            	1052, 20,
            0, 8, 1, /* 4863: pointer.X509_NAME_ENTRY */
            	2470, 0,
            1, 8, 1, /* 4868: pointer.struct.X509_algor_st */
            	2059, 0,
            0, 104, 11, /* 4873: struct.x509_cinf_st */
            	4898, 0,
            	4898, 8,
            	4868, 16,
            	4903, 24,
            	4829, 32,
            	4903, 40,
            	4917, 48,
            	4922, 56,
            	4922, 64,
            	4793, 72,
            	4788, 80,
            1, 8, 1, /* 4898: pointer.struct.asn1_string_st */
            	4719, 0,
            1, 8, 1, /* 4903: pointer.struct.X509_name_st */
            	4908, 0,
            0, 40, 3, /* 4908: struct.X509_name_st */
            	4844, 0,
            	4839, 16,
            	145, 24,
            1, 8, 1, /* 4917: pointer.struct.X509_pubkey_st */
            	2303, 0,
            1, 8, 1, /* 4922: pointer.struct.asn1_string_st */
            	4719, 0,
            1, 8, 1, /* 4927: pointer.struct.x509_cinf_st */
            	4873, 0,
            1, 8, 1, /* 4932: pointer.struct.x509_st */
            	4937, 0,
            0, 184, 12, /* 4937: struct.x509_st */
            	4927, 0,
            	4868, 8,
            	4922, 16,
            	53, 32,
            	4783, 40,
            	4761, 104,
            	2591, 112,
            	2914, 120,
            	3336, 128,
            	3475, 136,
            	3499, 144,
            	4964, 176,
            1, 8, 1, /* 4964: pointer.struct.x509_cert_aux_st */
            	4748, 0,
            0, 24, 3, /* 4969: struct.cert_pkey_st */
            	4932, 0,
            	4978, 8,
            	4592, 16,
            1, 8, 1, /* 4978: pointer.struct.evp_pkey_st */
            	4674, 0,
            1, 8, 1, /* 4983: pointer.struct.cert_pkey_st */
            	4969, 0,
            8884097, 8, 0, /* 4988: pointer.func */
            0, 352, 14, /* 4991: struct.ssl_session_st */
            	53, 144,
            	53, 152,
            	5022, 168,
            	5069, 176,
            	5168, 224,
            	5173, 240,
            	5141, 248,
            	5207, 264,
            	5207, 272,
            	53, 280,
            	145, 296,
            	145, 312,
            	145, 320,
            	53, 344,
            1, 8, 1, /* 5022: pointer.struct.sess_cert_st */
            	5027, 0,
            0, 248, 5, /* 5027: struct.sess_cert_st */
            	5040, 0,
            	4983, 16,
            	4578, 216,
            	5064, 224,
            	3863, 232,
            1, 8, 1, /* 5040: pointer.struct.stack_st_X509 */
            	5045, 0,
            0, 32, 2, /* 5045: struct.stack_st_fake_X509 */
            	5052, 8,
            	180, 24,
            8884099, 8, 2, /* 5052: pointer_to_array_of_pointers_to_stack */
            	5059, 0,
            	1052, 20,
            0, 8, 1, /* 5059: pointer.X509 */
            	4040, 0,
            1, 8, 1, /* 5064: pointer.struct.dh_st */
            	94, 0,
            1, 8, 1, /* 5069: pointer.struct.x509_st */
            	5074, 0,
            0, 184, 12, /* 5074: struct.x509_st */
            	5101, 0,
            	4563, 8,
            	5136, 16,
            	53, 32,
            	5141, 40,
            	4387, 104,
            	5163, 112,
            	2914, 120,
            	4445, 128,
            	4421, 136,
            	4709, 144,
            	4416, 176,
            1, 8, 1, /* 5101: pointer.struct.x509_cinf_st */
            	5106, 0,
            0, 104, 11, /* 5106: struct.x509_cinf_st */
            	4573, 0,
            	4573, 8,
            	4563, 16,
            	4549, 24,
            	5131, 32,
            	4549, 40,
            	4498, 48,
            	5136, 56,
            	5136, 64,
            	4474, 72,
            	4469, 80,
            1, 8, 1, /* 5131: pointer.struct.X509_val_st */
            	4503, 0,
            1, 8, 1, /* 5136: pointer.struct.asn1_string_st */
            	4382, 0,
            0, 16, 1, /* 5141: struct.crypto_ex_data_st */
            	5146, 0,
            1, 8, 1, /* 5146: pointer.struct.stack_st_void */
            	5151, 0,
            0, 32, 1, /* 5151: struct.stack_st_void */
            	5156, 0,
            0, 32, 2, /* 5156: struct.stack_st */
            	175, 8,
            	180, 24,
            1, 8, 1, /* 5163: pointer.struct.AUTHORITY_KEYID_st */
            	2596, 0,
            1, 8, 1, /* 5168: pointer.struct.ssl_cipher_st */
            	4335, 0,
            1, 8, 1, /* 5173: pointer.struct.stack_st_SSL_CIPHER */
            	5178, 0,
            0, 32, 2, /* 5178: struct.stack_st_fake_SSL_CIPHER */
            	5185, 8,
            	180, 24,
            8884099, 8, 2, /* 5185: pointer_to_array_of_pointers_to_stack */
            	5192, 0,
            	1052, 20,
            0, 8, 1, /* 5192: pointer.SSL_CIPHER */
            	5197, 0,
            0, 0, 1, /* 5197: SSL_CIPHER */
            	5202, 0,
            0, 88, 1, /* 5202: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 5207: pointer.struct.ssl_session_st */
            	4991, 0,
            1, 8, 1, /* 5212: pointer.struct.lhash_node_st */
            	5217, 0,
            0, 24, 2, /* 5217: struct.lhash_node_st */
            	41, 0,
            	5212, 8,
            1, 8, 1, /* 5224: pointer.struct.lhash_st */
            	5229, 0,
            0, 176, 3, /* 5229: struct.lhash_st */
            	5238, 0,
            	180, 8,
            	5245, 16,
            8884099, 8, 2, /* 5238: pointer_to_array_of_pointers_to_stack */
            	5212, 0,
            	73, 28,
            8884097, 8, 0, /* 5245: pointer.func */
            8884097, 8, 0, /* 5248: pointer.func */
            8884097, 8, 0, /* 5251: pointer.func */
            8884097, 8, 0, /* 5254: pointer.func */
            8884097, 8, 0, /* 5257: pointer.func */
            8884097, 8, 0, /* 5260: pointer.func */
            8884097, 8, 0, /* 5263: pointer.func */
            1, 8, 1, /* 5266: pointer.struct.X509_VERIFY_PARAM_st */
            	5271, 0,
            0, 56, 2, /* 5271: struct.X509_VERIFY_PARAM_st */
            	53, 0,
            	5278, 48,
            1, 8, 1, /* 5278: pointer.struct.stack_st_ASN1_OBJECT */
            	5283, 0,
            0, 32, 2, /* 5283: struct.stack_st_fake_ASN1_OBJECT */
            	5290, 8,
            	180, 24,
            8884099, 8, 2, /* 5290: pointer_to_array_of_pointers_to_stack */
            	5297, 0,
            	1052, 20,
            0, 8, 1, /* 5297: pointer.ASN1_OBJECT */
            	1993, 0,
            8884097, 8, 0, /* 5302: pointer.func */
            1, 8, 1, /* 5305: pointer.struct.stack_st_X509_LOOKUP */
            	5310, 0,
            0, 32, 2, /* 5310: struct.stack_st_fake_X509_LOOKUP */
            	5317, 8,
            	180, 24,
            8884099, 8, 2, /* 5317: pointer_to_array_of_pointers_to_stack */
            	5324, 0,
            	1052, 20,
            0, 8, 1, /* 5324: pointer.X509_LOOKUP */
            	5329, 0,
            0, 0, 1, /* 5329: X509_LOOKUP */
            	5334, 0,
            0, 32, 3, /* 5334: struct.x509_lookup_st */
            	5343, 8,
            	53, 16,
            	5392, 24,
            1, 8, 1, /* 5343: pointer.struct.x509_lookup_method_st */
            	5348, 0,
            0, 80, 10, /* 5348: struct.x509_lookup_method_st */
            	5, 0,
            	5371, 8,
            	5374, 16,
            	5371, 24,
            	5371, 32,
            	5377, 40,
            	5380, 48,
            	5383, 56,
            	5386, 64,
            	5389, 72,
            8884097, 8, 0, /* 5371: pointer.func */
            8884097, 8, 0, /* 5374: pointer.func */
            8884097, 8, 0, /* 5377: pointer.func */
            8884097, 8, 0, /* 5380: pointer.func */
            8884097, 8, 0, /* 5383: pointer.func */
            8884097, 8, 0, /* 5386: pointer.func */
            8884097, 8, 0, /* 5389: pointer.func */
            1, 8, 1, /* 5392: pointer.struct.x509_store_st */
            	5397, 0,
            0, 144, 15, /* 5397: struct.x509_store_st */
            	5430, 8,
            	5305, 16,
            	5266, 24,
            	5263, 32,
            	6080, 40,
            	6083, 48,
            	5260, 56,
            	5263, 64,
            	6086, 72,
            	5257, 80,
            	6089, 88,
            	5254, 96,
            	5251, 104,
            	5263, 112,
            	5656, 120,
            1, 8, 1, /* 5430: pointer.struct.stack_st_X509_OBJECT */
            	5435, 0,
            0, 32, 2, /* 5435: struct.stack_st_fake_X509_OBJECT */
            	5442, 8,
            	180, 24,
            8884099, 8, 2, /* 5442: pointer_to_array_of_pointers_to_stack */
            	5449, 0,
            	1052, 20,
            0, 8, 1, /* 5449: pointer.X509_OBJECT */
            	5454, 0,
            0, 0, 1, /* 5454: X509_OBJECT */
            	5459, 0,
            0, 16, 1, /* 5459: struct.x509_object_st */
            	5464, 8,
            0, 8, 4, /* 5464: union.unknown */
            	53, 0,
            	5475, 0,
            	5793, 0,
            	6002, 0,
            1, 8, 1, /* 5475: pointer.struct.x509_st */
            	5480, 0,
            0, 184, 12, /* 5480: struct.x509_st */
            	5507, 0,
            	5547, 8,
            	5622, 16,
            	53, 32,
            	5656, 40,
            	5678, 104,
            	5683, 112,
            	5688, 120,
            	5693, 128,
            	5717, 136,
            	5741, 144,
            	5746, 176,
            1, 8, 1, /* 5507: pointer.struct.x509_cinf_st */
            	5512, 0,
            0, 104, 11, /* 5512: struct.x509_cinf_st */
            	5537, 0,
            	5537, 8,
            	5547, 16,
            	5552, 24,
            	5600, 32,
            	5552, 40,
            	5617, 48,
            	5622, 56,
            	5622, 64,
            	5627, 72,
            	5651, 80,
            1, 8, 1, /* 5537: pointer.struct.asn1_string_st */
            	5542, 0,
            0, 24, 1, /* 5542: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 5547: pointer.struct.X509_algor_st */
            	2059, 0,
            1, 8, 1, /* 5552: pointer.struct.X509_name_st */
            	5557, 0,
            0, 40, 3, /* 5557: struct.X509_name_st */
            	5566, 0,
            	5590, 16,
            	145, 24,
            1, 8, 1, /* 5566: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5571, 0,
            0, 32, 2, /* 5571: struct.stack_st_fake_X509_NAME_ENTRY */
            	5578, 8,
            	180, 24,
            8884099, 8, 2, /* 5578: pointer_to_array_of_pointers_to_stack */
            	5585, 0,
            	1052, 20,
            0, 8, 1, /* 5585: pointer.X509_NAME_ENTRY */
            	2470, 0,
            1, 8, 1, /* 5590: pointer.struct.buf_mem_st */
            	5595, 0,
            0, 24, 1, /* 5595: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 5600: pointer.struct.X509_val_st */
            	5605, 0,
            0, 16, 2, /* 5605: struct.X509_val_st */
            	5612, 0,
            	5612, 8,
            1, 8, 1, /* 5612: pointer.struct.asn1_string_st */
            	5542, 0,
            1, 8, 1, /* 5617: pointer.struct.X509_pubkey_st */
            	2303, 0,
            1, 8, 1, /* 5622: pointer.struct.asn1_string_st */
            	5542, 0,
            1, 8, 1, /* 5627: pointer.struct.stack_st_X509_EXTENSION */
            	5632, 0,
            0, 32, 2, /* 5632: struct.stack_st_fake_X509_EXTENSION */
            	5639, 8,
            	180, 24,
            8884099, 8, 2, /* 5639: pointer_to_array_of_pointers_to_stack */
            	5646, 0,
            	1052, 20,
            0, 8, 1, /* 5646: pointer.X509_EXTENSION */
            	2262, 0,
            0, 24, 1, /* 5651: struct.ASN1_ENCODING_st */
            	145, 0,
            0, 16, 1, /* 5656: struct.crypto_ex_data_st */
            	5661, 0,
            1, 8, 1, /* 5661: pointer.struct.stack_st_void */
            	5666, 0,
            0, 32, 1, /* 5666: struct.stack_st_void */
            	5671, 0,
            0, 32, 2, /* 5671: struct.stack_st */
            	175, 8,
            	180, 24,
            1, 8, 1, /* 5678: pointer.struct.asn1_string_st */
            	5542, 0,
            1, 8, 1, /* 5683: pointer.struct.AUTHORITY_KEYID_st */
            	2596, 0,
            1, 8, 1, /* 5688: pointer.struct.X509_POLICY_CACHE_st */
            	2919, 0,
            1, 8, 1, /* 5693: pointer.struct.stack_st_DIST_POINT */
            	5698, 0,
            0, 32, 2, /* 5698: struct.stack_st_fake_DIST_POINT */
            	5705, 8,
            	180, 24,
            8884099, 8, 2, /* 5705: pointer_to_array_of_pointers_to_stack */
            	5712, 0,
            	1052, 20,
            0, 8, 1, /* 5712: pointer.DIST_POINT */
            	3360, 0,
            1, 8, 1, /* 5717: pointer.struct.stack_st_GENERAL_NAME */
            	5722, 0,
            0, 32, 2, /* 5722: struct.stack_st_fake_GENERAL_NAME */
            	5729, 8,
            	180, 24,
            8884099, 8, 2, /* 5729: pointer_to_array_of_pointers_to_stack */
            	5736, 0,
            	1052, 20,
            0, 8, 1, /* 5736: pointer.GENERAL_NAME */
            	2639, 0,
            1, 8, 1, /* 5741: pointer.struct.NAME_CONSTRAINTS_st */
            	3504, 0,
            1, 8, 1, /* 5746: pointer.struct.x509_cert_aux_st */
            	5751, 0,
            0, 40, 5, /* 5751: struct.x509_cert_aux_st */
            	5278, 0,
            	5278, 8,
            	5764, 16,
            	5678, 24,
            	5769, 32,
            1, 8, 1, /* 5764: pointer.struct.asn1_string_st */
            	5542, 0,
            1, 8, 1, /* 5769: pointer.struct.stack_st_X509_ALGOR */
            	5774, 0,
            0, 32, 2, /* 5774: struct.stack_st_fake_X509_ALGOR */
            	5781, 8,
            	180, 24,
            8884099, 8, 2, /* 5781: pointer_to_array_of_pointers_to_stack */
            	5788, 0,
            	1052, 20,
            0, 8, 1, /* 5788: pointer.X509_ALGOR */
            	2054, 0,
            1, 8, 1, /* 5793: pointer.struct.X509_crl_st */
            	5798, 0,
            0, 120, 10, /* 5798: struct.X509_crl_st */
            	5821, 0,
            	5547, 8,
            	5622, 16,
            	5683, 32,
            	5924, 40,
            	5537, 56,
            	5537, 64,
            	5936, 96,
            	5977, 104,
            	41, 112,
            1, 8, 1, /* 5821: pointer.struct.X509_crl_info_st */
            	5826, 0,
            0, 80, 8, /* 5826: struct.X509_crl_info_st */
            	5537, 0,
            	5547, 8,
            	5552, 16,
            	5612, 24,
            	5612, 32,
            	5845, 40,
            	5627, 48,
            	5651, 56,
            1, 8, 1, /* 5845: pointer.struct.stack_st_X509_REVOKED */
            	5850, 0,
            0, 32, 2, /* 5850: struct.stack_st_fake_X509_REVOKED */
            	5857, 8,
            	180, 24,
            8884099, 8, 2, /* 5857: pointer_to_array_of_pointers_to_stack */
            	5864, 0,
            	1052, 20,
            0, 8, 1, /* 5864: pointer.X509_REVOKED */
            	5869, 0,
            0, 0, 1, /* 5869: X509_REVOKED */
            	5874, 0,
            0, 40, 4, /* 5874: struct.x509_revoked_st */
            	5885, 0,
            	5895, 8,
            	5900, 16,
            	4217, 24,
            1, 8, 1, /* 5885: pointer.struct.asn1_string_st */
            	5890, 0,
            0, 24, 1, /* 5890: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 5895: pointer.struct.asn1_string_st */
            	5890, 0,
            1, 8, 1, /* 5900: pointer.struct.stack_st_X509_EXTENSION */
            	5905, 0,
            0, 32, 2, /* 5905: struct.stack_st_fake_X509_EXTENSION */
            	5912, 8,
            	180, 24,
            8884099, 8, 2, /* 5912: pointer_to_array_of_pointers_to_stack */
            	5919, 0,
            	1052, 20,
            0, 8, 1, /* 5919: pointer.X509_EXTENSION */
            	2262, 0,
            1, 8, 1, /* 5924: pointer.struct.ISSUING_DIST_POINT_st */
            	5929, 0,
            0, 32, 2, /* 5929: struct.ISSUING_DIST_POINT_st */
            	3374, 0,
            	3465, 16,
            1, 8, 1, /* 5936: pointer.struct.stack_st_GENERAL_NAMES */
            	5941, 0,
            0, 32, 2, /* 5941: struct.stack_st_fake_GENERAL_NAMES */
            	5948, 8,
            	180, 24,
            8884099, 8, 2, /* 5948: pointer_to_array_of_pointers_to_stack */
            	5955, 0,
            	1052, 20,
            0, 8, 1, /* 5955: pointer.GENERAL_NAMES */
            	5960, 0,
            0, 0, 1, /* 5960: GENERAL_NAMES */
            	5965, 0,
            0, 32, 1, /* 5965: struct.stack_st_GENERAL_NAME */
            	5970, 0,
            0, 32, 2, /* 5970: struct.stack_st */
            	175, 8,
            	180, 24,
            1, 8, 1, /* 5977: pointer.struct.x509_crl_method_st */
            	5982, 0,
            0, 40, 4, /* 5982: struct.x509_crl_method_st */
            	5993, 8,
            	5993, 16,
            	5996, 24,
            	5999, 32,
            8884097, 8, 0, /* 5993: pointer.func */
            8884097, 8, 0, /* 5996: pointer.func */
            8884097, 8, 0, /* 5999: pointer.func */
            1, 8, 1, /* 6002: pointer.struct.evp_pkey_st */
            	6007, 0,
            0, 56, 4, /* 6007: struct.evp_pkey_st */
            	6018, 16,
            	219, 24,
            	6023, 32,
            	6056, 48,
            1, 8, 1, /* 6018: pointer.struct.evp_pkey_asn1_method_st */
            	1858, 0,
            0, 8, 5, /* 6023: union.unknown */
            	53, 0,
            	6036, 0,
            	6041, 0,
            	6046, 0,
            	6051, 0,
            1, 8, 1, /* 6036: pointer.struct.rsa_st */
            	572, 0,
            1, 8, 1, /* 6041: pointer.struct.dsa_st */
            	1224, 0,
            1, 8, 1, /* 6046: pointer.struct.dh_st */
            	94, 0,
            1, 8, 1, /* 6051: pointer.struct.ec_key_st */
            	1356, 0,
            1, 8, 1, /* 6056: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6061, 0,
            0, 32, 2, /* 6061: struct.stack_st_fake_X509_ATTRIBUTE */
            	6068, 8,
            	180, 24,
            8884099, 8, 2, /* 6068: pointer_to_array_of_pointers_to_stack */
            	6075, 0,
            	1052, 20,
            0, 8, 1, /* 6075: pointer.X509_ATTRIBUTE */
            	833, 0,
            8884097, 8, 0, /* 6080: pointer.func */
            8884097, 8, 0, /* 6083: pointer.func */
            8884097, 8, 0, /* 6086: pointer.func */
            8884097, 8, 0, /* 6089: pointer.func */
            1, 8, 1, /* 6092: pointer.struct.stack_st_X509_LOOKUP */
            	6097, 0,
            0, 32, 2, /* 6097: struct.stack_st_fake_X509_LOOKUP */
            	6104, 8,
            	180, 24,
            8884099, 8, 2, /* 6104: pointer_to_array_of_pointers_to_stack */
            	6111, 0,
            	1052, 20,
            0, 8, 1, /* 6111: pointer.X509_LOOKUP */
            	5329, 0,
            8884097, 8, 0, /* 6116: pointer.func */
            1, 8, 1, /* 6119: pointer.struct.ssl3_buf_freelist_st */
            	4568, 0,
            8884097, 8, 0, /* 6124: pointer.func */
            8884097, 8, 0, /* 6127: pointer.func */
            0, 120, 8, /* 6130: struct.env_md_st */
            	6149, 24,
            	6152, 32,
            	4320, 40,
            	4317, 48,
            	6149, 56,
            	800, 64,
            	803, 72,
            	6155, 112,
            8884097, 8, 0, /* 6149: pointer.func */
            8884097, 8, 0, /* 6152: pointer.func */
            8884097, 8, 0, /* 6155: pointer.func */
            0, 0, 1, /* 6158: SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 6163: pointer.func */
            8884097, 8, 0, /* 6166: pointer.func */
            8884097, 8, 0, /* 6169: pointer.func */
            0, 56, 2, /* 6172: struct.X509_VERIFY_PARAM_st */
            	53, 0,
            	4353, 48,
            1, 8, 1, /* 6179: pointer.struct.ssl3_enc_method */
            	6184, 0,
            0, 112, 11, /* 6184: struct.ssl3_enc_method */
            	6209, 0,
            	6212, 8,
            	6215, 16,
            	6218, 24,
            	6209, 32,
            	6221, 40,
            	6224, 56,
            	5, 64,
            	5, 80,
            	6227, 96,
            	6230, 104,
            8884097, 8, 0, /* 6209: pointer.func */
            8884097, 8, 0, /* 6212: pointer.func */
            8884097, 8, 0, /* 6215: pointer.func */
            8884097, 8, 0, /* 6218: pointer.func */
            8884097, 8, 0, /* 6221: pointer.func */
            8884097, 8, 0, /* 6224: pointer.func */
            8884097, 8, 0, /* 6227: pointer.func */
            8884097, 8, 0, /* 6230: pointer.func */
            1, 8, 1, /* 6233: pointer.struct.stack_st_X509_OBJECT */
            	6238, 0,
            0, 32, 2, /* 6238: struct.stack_st_fake_X509_OBJECT */
            	6245, 8,
            	180, 24,
            8884099, 8, 2, /* 6245: pointer_to_array_of_pointers_to_stack */
            	6252, 0,
            	1052, 20,
            0, 8, 1, /* 6252: pointer.X509_OBJECT */
            	5454, 0,
            8884097, 8, 0, /* 6257: pointer.func */
            8884097, 8, 0, /* 6260: pointer.func */
            8884097, 8, 0, /* 6263: pointer.func */
            8884097, 8, 0, /* 6266: pointer.func */
            1, 8, 1, /* 6269: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6274, 0,
            0, 32, 2, /* 6274: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6281, 8,
            	180, 24,
            8884099, 8, 2, /* 6281: pointer_to_array_of_pointers_to_stack */
            	6288, 0,
            	1052, 20,
            0, 8, 1, /* 6288: pointer.SRTP_PROTECTION_PROFILE */
            	6158, 0,
            8884097, 8, 0, /* 6293: pointer.func */
            0, 144, 15, /* 6296: struct.x509_store_st */
            	6233, 8,
            	6092, 16,
            	6329, 24,
            	5248, 32,
            	6263, 40,
            	6163, 48,
            	6334, 56,
            	5248, 64,
            	6124, 72,
            	6169, 80,
            	6337, 88,
            	6340, 96,
            	6343, 104,
            	5248, 112,
            	5141, 120,
            1, 8, 1, /* 6329: pointer.struct.X509_VERIFY_PARAM_st */
            	6172, 0,
            8884097, 8, 0, /* 6334: pointer.func */
            8884097, 8, 0, /* 6337: pointer.func */
            8884097, 8, 0, /* 6340: pointer.func */
            8884097, 8, 0, /* 6343: pointer.func */
            0, 1, 0, /* 6346: char */
            8884097, 8, 0, /* 6349: pointer.func */
            8884097, 8, 0, /* 6352: pointer.func */
            8884097, 8, 0, /* 6355: pointer.func */
            1, 8, 1, /* 6358: pointer.struct.ssl_ctx_st */
            	6363, 0,
            0, 736, 50, /* 6363: struct.ssl_ctx_st */
            	6466, 0,
            	5173, 8,
            	5173, 16,
            	6554, 24,
            	5224, 32,
            	5207, 48,
            	5207, 56,
            	5302, 80,
            	4988, 88,
            	4332, 96,
            	6116, 152,
            	41, 160,
            	4329, 168,
            	41, 176,
            	6559, 184,
            	4326, 192,
            	4323, 200,
            	5141, 208,
            	6562, 224,
            	6562, 232,
            	6562, 240,
            	4016, 248,
            	3992, 256,
            	3943, 264,
            	3871, 272,
            	3830, 304,
            	6567, 320,
            	41, 328,
            	6263, 376,
            	6570, 384,
            	6329, 392,
            	1954, 408,
            	44, 416,
            	41, 424,
            	86, 480,
            	47, 488,
            	41, 496,
            	1839, 504,
            	41, 512,
            	53, 520,
            	2506, 528,
            	6127, 536,
            	6119, 552,
            	6119, 560,
            	10, 568,
            	6573, 696,
            	41, 704,
            	6576, 712,
            	41, 720,
            	6269, 728,
            1, 8, 1, /* 6466: pointer.struct.ssl_method_st */
            	6471, 0,
            0, 232, 28, /* 6471: struct.ssl_method_st */
            	6530, 8,
            	6533, 16,
            	6533, 24,
            	6530, 32,
            	6530, 40,
            	6349, 48,
            	6349, 56,
            	6536, 64,
            	6530, 72,
            	6530, 80,
            	6530, 88,
            	6352, 96,
            	6260, 104,
            	6293, 112,
            	6530, 120,
            	6539, 128,
            	6355, 136,
            	6542, 144,
            	6545, 152,
            	6548, 160,
            	493, 168,
            	6266, 176,
            	6166, 184,
            	3972, 192,
            	6179, 200,
            	493, 208,
            	6257, 216,
            	6551, 224,
            8884097, 8, 0, /* 6530: pointer.func */
            8884097, 8, 0, /* 6533: pointer.func */
            8884097, 8, 0, /* 6536: pointer.func */
            8884097, 8, 0, /* 6539: pointer.func */
            8884097, 8, 0, /* 6542: pointer.func */
            8884097, 8, 0, /* 6545: pointer.func */
            8884097, 8, 0, /* 6548: pointer.func */
            8884097, 8, 0, /* 6551: pointer.func */
            1, 8, 1, /* 6554: pointer.struct.x509_store_st */
            	6296, 0,
            8884097, 8, 0, /* 6559: pointer.func */
            1, 8, 1, /* 6562: pointer.struct.env_md_st */
            	6130, 0,
            8884097, 8, 0, /* 6567: pointer.func */
            8884097, 8, 0, /* 6570: pointer.func */
            8884097, 8, 0, /* 6573: pointer.func */
            8884097, 8, 0, /* 6576: pointer.func */
        },
        .arg_entity_index = { 6358, 1052, 6263, },
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

