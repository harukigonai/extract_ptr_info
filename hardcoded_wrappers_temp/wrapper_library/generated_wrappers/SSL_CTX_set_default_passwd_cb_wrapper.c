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
            0, 88, 1, /* 4332: struct.ssl_cipher_st */
            	5, 8,
            0, 40, 5, /* 4337: struct.x509_cert_aux_st */
            	4350, 0,
            	4350, 8,
            	4374, 16,
            	4384, 24,
            	4389, 32,
            1, 8, 1, /* 4350: pointer.struct.stack_st_ASN1_OBJECT */
            	4355, 0,
            0, 32, 2, /* 4355: struct.stack_st_fake_ASN1_OBJECT */
            	4362, 8,
            	180, 24,
            8884099, 8, 2, /* 4362: pointer_to_array_of_pointers_to_stack */
            	4369, 0,
            	1052, 20,
            0, 8, 1, /* 4369: pointer.ASN1_OBJECT */
            	1993, 0,
            1, 8, 1, /* 4374: pointer.struct.asn1_string_st */
            	4379, 0,
            0, 24, 1, /* 4379: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 4384: pointer.struct.asn1_string_st */
            	4379, 0,
            1, 8, 1, /* 4389: pointer.struct.stack_st_X509_ALGOR */
            	4394, 0,
            0, 32, 2, /* 4394: struct.stack_st_fake_X509_ALGOR */
            	4401, 8,
            	180, 24,
            8884099, 8, 2, /* 4401: pointer_to_array_of_pointers_to_stack */
            	4408, 0,
            	1052, 20,
            0, 8, 1, /* 4408: pointer.X509_ALGOR */
            	2054, 0,
            1, 8, 1, /* 4413: pointer.struct.x509_cert_aux_st */
            	4337, 0,
            1, 8, 1, /* 4418: pointer.struct.stack_st_GENERAL_NAME */
            	4423, 0,
            0, 32, 2, /* 4423: struct.stack_st_fake_GENERAL_NAME */
            	4430, 8,
            	180, 24,
            8884099, 8, 2, /* 4430: pointer_to_array_of_pointers_to_stack */
            	4437, 0,
            	1052, 20,
            0, 8, 1, /* 4437: pointer.GENERAL_NAME */
            	2639, 0,
            1, 8, 1, /* 4442: pointer.struct.stack_st_DIST_POINT */
            	4447, 0,
            0, 32, 2, /* 4447: struct.stack_st_fake_DIST_POINT */
            	4454, 8,
            	180, 24,
            8884099, 8, 2, /* 4454: pointer_to_array_of_pointers_to_stack */
            	4461, 0,
            	1052, 20,
            0, 8, 1, /* 4461: pointer.DIST_POINT */
            	3360, 0,
            0, 24, 1, /* 4466: struct.ASN1_ENCODING_st */
            	145, 0,
            1, 8, 1, /* 4471: pointer.struct.stack_st_X509_EXTENSION */
            	4476, 0,
            0, 32, 2, /* 4476: struct.stack_st_fake_X509_EXTENSION */
            	4483, 8,
            	180, 24,
            8884099, 8, 2, /* 4483: pointer_to_array_of_pointers_to_stack */
            	4490, 0,
            	1052, 20,
            0, 8, 1, /* 4490: pointer.X509_EXTENSION */
            	2262, 0,
            1, 8, 1, /* 4495: pointer.struct.X509_pubkey_st */
            	2303, 0,
            0, 16, 2, /* 4500: struct.X509_val_st */
            	4507, 0,
            	4507, 8,
            1, 8, 1, /* 4507: pointer.struct.asn1_string_st */
            	4379, 0,
            1, 8, 1, /* 4512: pointer.struct.buf_mem_st */
            	4517, 0,
            0, 24, 1, /* 4517: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 4522: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4527, 0,
            0, 32, 2, /* 4527: struct.stack_st_fake_X509_NAME_ENTRY */
            	4534, 8,
            	180, 24,
            8884099, 8, 2, /* 4534: pointer_to_array_of_pointers_to_stack */
            	4541, 0,
            	1052, 20,
            0, 8, 1, /* 4541: pointer.X509_NAME_ENTRY */
            	2470, 0,
            1, 8, 1, /* 4546: pointer.struct.X509_name_st */
            	4551, 0,
            0, 40, 3, /* 4551: struct.X509_name_st */
            	4522, 0,
            	4512, 16,
            	145, 24,
            1, 8, 1, /* 4560: pointer.struct.X509_algor_st */
            	2059, 0,
            0, 24, 1, /* 4565: struct.ssl3_buf_freelist_st */
            	81, 16,
            1, 8, 1, /* 4570: pointer.struct.asn1_string_st */
            	4379, 0,
            1, 8, 1, /* 4575: pointer.struct.rsa_st */
            	572, 0,
            8884097, 8, 0, /* 4580: pointer.func */
            8884097, 8, 0, /* 4583: pointer.func */
            8884097, 8, 0, /* 4586: pointer.func */
            1, 8, 1, /* 4589: pointer.struct.env_md_st */
            	4594, 0,
            0, 120, 8, /* 4594: struct.env_md_st */
            	4613, 24,
            	4586, 32,
            	4616, 40,
            	4583, 48,
            	4613, 56,
            	800, 64,
            	803, 72,
            	4580, 112,
            8884097, 8, 0, /* 4613: pointer.func */
            8884097, 8, 0, /* 4616: pointer.func */
            1, 8, 1, /* 4619: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4624, 0,
            0, 32, 2, /* 4624: struct.stack_st_fake_X509_ATTRIBUTE */
            	4631, 8,
            	180, 24,
            8884099, 8, 2, /* 4631: pointer_to_array_of_pointers_to_stack */
            	4638, 0,
            	1052, 20,
            0, 8, 1, /* 4638: pointer.X509_ATTRIBUTE */
            	833, 0,
            1, 8, 1, /* 4643: pointer.struct.dh_st */
            	94, 0,
            1, 8, 1, /* 4648: pointer.struct.dsa_st */
            	1224, 0,
            0, 8, 5, /* 4653: union.unknown */
            	53, 0,
            	4666, 0,
            	4648, 0,
            	4643, 0,
            	1351, 0,
            1, 8, 1, /* 4666: pointer.struct.rsa_st */
            	572, 0,
            0, 56, 4, /* 4671: struct.evp_pkey_st */
            	1853, 16,
            	1954, 24,
            	4653, 32,
            	4619, 48,
            1, 8, 1, /* 4682: pointer.struct.stack_st_X509_ALGOR */
            	4687, 0,
            0, 32, 2, /* 4687: struct.stack_st_fake_X509_ALGOR */
            	4694, 8,
            	180, 24,
            8884099, 8, 2, /* 4694: pointer_to_array_of_pointers_to_stack */
            	4701, 0,
            	1052, 20,
            0, 8, 1, /* 4701: pointer.X509_ALGOR */
            	2054, 0,
            1, 8, 1, /* 4706: pointer.struct.NAME_CONSTRAINTS_st */
            	3504, 0,
            1, 8, 1, /* 4711: pointer.struct.asn1_string_st */
            	4716, 0,
            0, 24, 1, /* 4716: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 4721: pointer.struct.stack_st_ASN1_OBJECT */
            	4726, 0,
            0, 32, 2, /* 4726: struct.stack_st_fake_ASN1_OBJECT */
            	4733, 8,
            	180, 24,
            8884099, 8, 2, /* 4733: pointer_to_array_of_pointers_to_stack */
            	4740, 0,
            	1052, 20,
            0, 8, 1, /* 4740: pointer.ASN1_OBJECT */
            	1993, 0,
            0, 40, 5, /* 4745: struct.x509_cert_aux_st */
            	4721, 0,
            	4721, 8,
            	4711, 16,
            	4758, 24,
            	4682, 32,
            1, 8, 1, /* 4758: pointer.struct.asn1_string_st */
            	4716, 0,
            0, 32, 2, /* 4763: struct.stack_st */
            	175, 8,
            	180, 24,
            0, 32, 1, /* 4770: struct.stack_st_void */
            	4763, 0,
            1, 8, 1, /* 4775: pointer.struct.stack_st_void */
            	4770, 0,
            0, 16, 1, /* 4780: struct.crypto_ex_data_st */
            	4775, 0,
            0, 24, 1, /* 4785: struct.ASN1_ENCODING_st */
            	145, 0,
            1, 8, 1, /* 4790: pointer.struct.stack_st_X509_EXTENSION */
            	4795, 0,
            0, 32, 2, /* 4795: struct.stack_st_fake_X509_EXTENSION */
            	4802, 8,
            	180, 24,
            8884099, 8, 2, /* 4802: pointer_to_array_of_pointers_to_stack */
            	4809, 0,
            	1052, 20,
            0, 8, 1, /* 4809: pointer.X509_EXTENSION */
            	2262, 0,
            1, 8, 1, /* 4814: pointer.struct.asn1_string_st */
            	4716, 0,
            0, 16, 2, /* 4819: struct.X509_val_st */
            	4814, 0,
            	4814, 8,
            1, 8, 1, /* 4826: pointer.struct.X509_val_st */
            	4819, 0,
            0, 24, 1, /* 4831: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 4836: pointer.struct.buf_mem_st */
            	4831, 0,
            1, 8, 1, /* 4841: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4846, 0,
            0, 32, 2, /* 4846: struct.stack_st_fake_X509_NAME_ENTRY */
            	4853, 8,
            	180, 24,
            8884099, 8, 2, /* 4853: pointer_to_array_of_pointers_to_stack */
            	4860, 0,
            	1052, 20,
            0, 8, 1, /* 4860: pointer.X509_NAME_ENTRY */
            	2470, 0,
            1, 8, 1, /* 4865: pointer.struct.X509_algor_st */
            	2059, 0,
            0, 104, 11, /* 4870: struct.x509_cinf_st */
            	4895, 0,
            	4895, 8,
            	4865, 16,
            	4900, 24,
            	4826, 32,
            	4900, 40,
            	4914, 48,
            	4919, 56,
            	4919, 64,
            	4790, 72,
            	4785, 80,
            1, 8, 1, /* 4895: pointer.struct.asn1_string_st */
            	4716, 0,
            1, 8, 1, /* 4900: pointer.struct.X509_name_st */
            	4905, 0,
            0, 40, 3, /* 4905: struct.X509_name_st */
            	4841, 0,
            	4836, 16,
            	145, 24,
            1, 8, 1, /* 4914: pointer.struct.X509_pubkey_st */
            	2303, 0,
            1, 8, 1, /* 4919: pointer.struct.asn1_string_st */
            	4716, 0,
            1, 8, 1, /* 4924: pointer.struct.x509_cinf_st */
            	4870, 0,
            1, 8, 1, /* 4929: pointer.struct.x509_st */
            	4934, 0,
            0, 184, 12, /* 4934: struct.x509_st */
            	4924, 0,
            	4865, 8,
            	4919, 16,
            	53, 32,
            	4780, 40,
            	4758, 104,
            	2591, 112,
            	2914, 120,
            	3336, 128,
            	3475, 136,
            	3499, 144,
            	4961, 176,
            1, 8, 1, /* 4961: pointer.struct.x509_cert_aux_st */
            	4745, 0,
            0, 24, 3, /* 4966: struct.cert_pkey_st */
            	4929, 0,
            	4975, 8,
            	4589, 16,
            1, 8, 1, /* 4975: pointer.struct.evp_pkey_st */
            	4671, 0,
            1, 8, 1, /* 4980: pointer.struct.cert_pkey_st */
            	4966, 0,
            8884097, 8, 0, /* 4985: pointer.func */
            0, 352, 14, /* 4988: struct.ssl_session_st */
            	53, 144,
            	53, 152,
            	5019, 168,
            	5066, 176,
            	5165, 224,
            	5170, 240,
            	5138, 248,
            	5204, 264,
            	5204, 272,
            	53, 280,
            	145, 296,
            	145, 312,
            	145, 320,
            	53, 344,
            1, 8, 1, /* 5019: pointer.struct.sess_cert_st */
            	5024, 0,
            0, 248, 5, /* 5024: struct.sess_cert_st */
            	5037, 0,
            	4980, 16,
            	4575, 216,
            	5061, 224,
            	3863, 232,
            1, 8, 1, /* 5037: pointer.struct.stack_st_X509 */
            	5042, 0,
            0, 32, 2, /* 5042: struct.stack_st_fake_X509 */
            	5049, 8,
            	180, 24,
            8884099, 8, 2, /* 5049: pointer_to_array_of_pointers_to_stack */
            	5056, 0,
            	1052, 20,
            0, 8, 1, /* 5056: pointer.X509 */
            	4040, 0,
            1, 8, 1, /* 5061: pointer.struct.dh_st */
            	94, 0,
            1, 8, 1, /* 5066: pointer.struct.x509_st */
            	5071, 0,
            0, 184, 12, /* 5071: struct.x509_st */
            	5098, 0,
            	4560, 8,
            	5133, 16,
            	53, 32,
            	5138, 40,
            	4384, 104,
            	5160, 112,
            	2914, 120,
            	4442, 128,
            	4418, 136,
            	4706, 144,
            	4413, 176,
            1, 8, 1, /* 5098: pointer.struct.x509_cinf_st */
            	5103, 0,
            0, 104, 11, /* 5103: struct.x509_cinf_st */
            	4570, 0,
            	4570, 8,
            	4560, 16,
            	4546, 24,
            	5128, 32,
            	4546, 40,
            	4495, 48,
            	5133, 56,
            	5133, 64,
            	4471, 72,
            	4466, 80,
            1, 8, 1, /* 5128: pointer.struct.X509_val_st */
            	4500, 0,
            1, 8, 1, /* 5133: pointer.struct.asn1_string_st */
            	4379, 0,
            0, 16, 1, /* 5138: struct.crypto_ex_data_st */
            	5143, 0,
            1, 8, 1, /* 5143: pointer.struct.stack_st_void */
            	5148, 0,
            0, 32, 1, /* 5148: struct.stack_st_void */
            	5153, 0,
            0, 32, 2, /* 5153: struct.stack_st */
            	175, 8,
            	180, 24,
            1, 8, 1, /* 5160: pointer.struct.AUTHORITY_KEYID_st */
            	2596, 0,
            1, 8, 1, /* 5165: pointer.struct.ssl_cipher_st */
            	4332, 0,
            1, 8, 1, /* 5170: pointer.struct.stack_st_SSL_CIPHER */
            	5175, 0,
            0, 32, 2, /* 5175: struct.stack_st_fake_SSL_CIPHER */
            	5182, 8,
            	180, 24,
            8884099, 8, 2, /* 5182: pointer_to_array_of_pointers_to_stack */
            	5189, 0,
            	1052, 20,
            0, 8, 1, /* 5189: pointer.SSL_CIPHER */
            	5194, 0,
            0, 0, 1, /* 5194: SSL_CIPHER */
            	5199, 0,
            0, 88, 1, /* 5199: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 5204: pointer.struct.ssl_session_st */
            	4988, 0,
            1, 8, 1, /* 5209: pointer.struct.lhash_node_st */
            	5214, 0,
            0, 24, 2, /* 5214: struct.lhash_node_st */
            	41, 0,
            	5209, 8,
            1, 8, 1, /* 5221: pointer.struct.lhash_st */
            	5226, 0,
            0, 176, 3, /* 5226: struct.lhash_st */
            	5235, 0,
            	180, 8,
            	5242, 16,
            8884099, 8, 2, /* 5235: pointer_to_array_of_pointers_to_stack */
            	5209, 0,
            	73, 28,
            8884097, 8, 0, /* 5242: pointer.func */
            8884097, 8, 0, /* 5245: pointer.func */
            8884097, 8, 0, /* 5248: pointer.func */
            8884097, 8, 0, /* 5251: pointer.func */
            8884097, 8, 0, /* 5254: pointer.func */
            8884097, 8, 0, /* 5257: pointer.func */
            8884097, 8, 0, /* 5260: pointer.func */
            1, 8, 1, /* 5263: pointer.struct.X509_VERIFY_PARAM_st */
            	5268, 0,
            0, 56, 2, /* 5268: struct.X509_VERIFY_PARAM_st */
            	53, 0,
            	5275, 48,
            1, 8, 1, /* 5275: pointer.struct.stack_st_ASN1_OBJECT */
            	5280, 0,
            0, 32, 2, /* 5280: struct.stack_st_fake_ASN1_OBJECT */
            	5287, 8,
            	180, 24,
            8884099, 8, 2, /* 5287: pointer_to_array_of_pointers_to_stack */
            	5294, 0,
            	1052, 20,
            0, 8, 1, /* 5294: pointer.ASN1_OBJECT */
            	1993, 0,
            8884097, 8, 0, /* 5299: pointer.func */
            1, 8, 1, /* 5302: pointer.struct.stack_st_X509_LOOKUP */
            	5307, 0,
            0, 32, 2, /* 5307: struct.stack_st_fake_X509_LOOKUP */
            	5314, 8,
            	180, 24,
            8884099, 8, 2, /* 5314: pointer_to_array_of_pointers_to_stack */
            	5321, 0,
            	1052, 20,
            0, 8, 1, /* 5321: pointer.X509_LOOKUP */
            	5326, 0,
            0, 0, 1, /* 5326: X509_LOOKUP */
            	5331, 0,
            0, 32, 3, /* 5331: struct.x509_lookup_st */
            	5340, 8,
            	53, 16,
            	5389, 24,
            1, 8, 1, /* 5340: pointer.struct.x509_lookup_method_st */
            	5345, 0,
            0, 80, 10, /* 5345: struct.x509_lookup_method_st */
            	5, 0,
            	5368, 8,
            	5371, 16,
            	5368, 24,
            	5368, 32,
            	5374, 40,
            	5377, 48,
            	5380, 56,
            	5383, 64,
            	5386, 72,
            8884097, 8, 0, /* 5368: pointer.func */
            8884097, 8, 0, /* 5371: pointer.func */
            8884097, 8, 0, /* 5374: pointer.func */
            8884097, 8, 0, /* 5377: pointer.func */
            8884097, 8, 0, /* 5380: pointer.func */
            8884097, 8, 0, /* 5383: pointer.func */
            8884097, 8, 0, /* 5386: pointer.func */
            1, 8, 1, /* 5389: pointer.struct.x509_store_st */
            	5394, 0,
            0, 144, 15, /* 5394: struct.x509_store_st */
            	5427, 8,
            	5302, 16,
            	5263, 24,
            	5260, 32,
            	6077, 40,
            	6080, 48,
            	5257, 56,
            	5260, 64,
            	6083, 72,
            	5254, 80,
            	6086, 88,
            	5251, 96,
            	5248, 104,
            	5260, 112,
            	5653, 120,
            1, 8, 1, /* 5427: pointer.struct.stack_st_X509_OBJECT */
            	5432, 0,
            0, 32, 2, /* 5432: struct.stack_st_fake_X509_OBJECT */
            	5439, 8,
            	180, 24,
            8884099, 8, 2, /* 5439: pointer_to_array_of_pointers_to_stack */
            	5446, 0,
            	1052, 20,
            0, 8, 1, /* 5446: pointer.X509_OBJECT */
            	5451, 0,
            0, 0, 1, /* 5451: X509_OBJECT */
            	5456, 0,
            0, 16, 1, /* 5456: struct.x509_object_st */
            	5461, 8,
            0, 8, 4, /* 5461: union.unknown */
            	53, 0,
            	5472, 0,
            	5790, 0,
            	5999, 0,
            1, 8, 1, /* 5472: pointer.struct.x509_st */
            	5477, 0,
            0, 184, 12, /* 5477: struct.x509_st */
            	5504, 0,
            	5544, 8,
            	5619, 16,
            	53, 32,
            	5653, 40,
            	5675, 104,
            	5680, 112,
            	5685, 120,
            	5690, 128,
            	5714, 136,
            	5738, 144,
            	5743, 176,
            1, 8, 1, /* 5504: pointer.struct.x509_cinf_st */
            	5509, 0,
            0, 104, 11, /* 5509: struct.x509_cinf_st */
            	5534, 0,
            	5534, 8,
            	5544, 16,
            	5549, 24,
            	5597, 32,
            	5549, 40,
            	5614, 48,
            	5619, 56,
            	5619, 64,
            	5624, 72,
            	5648, 80,
            1, 8, 1, /* 5534: pointer.struct.asn1_string_st */
            	5539, 0,
            0, 24, 1, /* 5539: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 5544: pointer.struct.X509_algor_st */
            	2059, 0,
            1, 8, 1, /* 5549: pointer.struct.X509_name_st */
            	5554, 0,
            0, 40, 3, /* 5554: struct.X509_name_st */
            	5563, 0,
            	5587, 16,
            	145, 24,
            1, 8, 1, /* 5563: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5568, 0,
            0, 32, 2, /* 5568: struct.stack_st_fake_X509_NAME_ENTRY */
            	5575, 8,
            	180, 24,
            8884099, 8, 2, /* 5575: pointer_to_array_of_pointers_to_stack */
            	5582, 0,
            	1052, 20,
            0, 8, 1, /* 5582: pointer.X509_NAME_ENTRY */
            	2470, 0,
            1, 8, 1, /* 5587: pointer.struct.buf_mem_st */
            	5592, 0,
            0, 24, 1, /* 5592: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 5597: pointer.struct.X509_val_st */
            	5602, 0,
            0, 16, 2, /* 5602: struct.X509_val_st */
            	5609, 0,
            	5609, 8,
            1, 8, 1, /* 5609: pointer.struct.asn1_string_st */
            	5539, 0,
            1, 8, 1, /* 5614: pointer.struct.X509_pubkey_st */
            	2303, 0,
            1, 8, 1, /* 5619: pointer.struct.asn1_string_st */
            	5539, 0,
            1, 8, 1, /* 5624: pointer.struct.stack_st_X509_EXTENSION */
            	5629, 0,
            0, 32, 2, /* 5629: struct.stack_st_fake_X509_EXTENSION */
            	5636, 8,
            	180, 24,
            8884099, 8, 2, /* 5636: pointer_to_array_of_pointers_to_stack */
            	5643, 0,
            	1052, 20,
            0, 8, 1, /* 5643: pointer.X509_EXTENSION */
            	2262, 0,
            0, 24, 1, /* 5648: struct.ASN1_ENCODING_st */
            	145, 0,
            0, 16, 1, /* 5653: struct.crypto_ex_data_st */
            	5658, 0,
            1, 8, 1, /* 5658: pointer.struct.stack_st_void */
            	5663, 0,
            0, 32, 1, /* 5663: struct.stack_st_void */
            	5668, 0,
            0, 32, 2, /* 5668: struct.stack_st */
            	175, 8,
            	180, 24,
            1, 8, 1, /* 5675: pointer.struct.asn1_string_st */
            	5539, 0,
            1, 8, 1, /* 5680: pointer.struct.AUTHORITY_KEYID_st */
            	2596, 0,
            1, 8, 1, /* 5685: pointer.struct.X509_POLICY_CACHE_st */
            	2919, 0,
            1, 8, 1, /* 5690: pointer.struct.stack_st_DIST_POINT */
            	5695, 0,
            0, 32, 2, /* 5695: struct.stack_st_fake_DIST_POINT */
            	5702, 8,
            	180, 24,
            8884099, 8, 2, /* 5702: pointer_to_array_of_pointers_to_stack */
            	5709, 0,
            	1052, 20,
            0, 8, 1, /* 5709: pointer.DIST_POINT */
            	3360, 0,
            1, 8, 1, /* 5714: pointer.struct.stack_st_GENERAL_NAME */
            	5719, 0,
            0, 32, 2, /* 5719: struct.stack_st_fake_GENERAL_NAME */
            	5726, 8,
            	180, 24,
            8884099, 8, 2, /* 5726: pointer_to_array_of_pointers_to_stack */
            	5733, 0,
            	1052, 20,
            0, 8, 1, /* 5733: pointer.GENERAL_NAME */
            	2639, 0,
            1, 8, 1, /* 5738: pointer.struct.NAME_CONSTRAINTS_st */
            	3504, 0,
            1, 8, 1, /* 5743: pointer.struct.x509_cert_aux_st */
            	5748, 0,
            0, 40, 5, /* 5748: struct.x509_cert_aux_st */
            	5275, 0,
            	5275, 8,
            	5761, 16,
            	5675, 24,
            	5766, 32,
            1, 8, 1, /* 5761: pointer.struct.asn1_string_st */
            	5539, 0,
            1, 8, 1, /* 5766: pointer.struct.stack_st_X509_ALGOR */
            	5771, 0,
            0, 32, 2, /* 5771: struct.stack_st_fake_X509_ALGOR */
            	5778, 8,
            	180, 24,
            8884099, 8, 2, /* 5778: pointer_to_array_of_pointers_to_stack */
            	5785, 0,
            	1052, 20,
            0, 8, 1, /* 5785: pointer.X509_ALGOR */
            	2054, 0,
            1, 8, 1, /* 5790: pointer.struct.X509_crl_st */
            	5795, 0,
            0, 120, 10, /* 5795: struct.X509_crl_st */
            	5818, 0,
            	5544, 8,
            	5619, 16,
            	5680, 32,
            	5921, 40,
            	5534, 56,
            	5534, 64,
            	5933, 96,
            	5974, 104,
            	41, 112,
            1, 8, 1, /* 5818: pointer.struct.X509_crl_info_st */
            	5823, 0,
            0, 80, 8, /* 5823: struct.X509_crl_info_st */
            	5534, 0,
            	5544, 8,
            	5549, 16,
            	5609, 24,
            	5609, 32,
            	5842, 40,
            	5624, 48,
            	5648, 56,
            1, 8, 1, /* 5842: pointer.struct.stack_st_X509_REVOKED */
            	5847, 0,
            0, 32, 2, /* 5847: struct.stack_st_fake_X509_REVOKED */
            	5854, 8,
            	180, 24,
            8884099, 8, 2, /* 5854: pointer_to_array_of_pointers_to_stack */
            	5861, 0,
            	1052, 20,
            0, 8, 1, /* 5861: pointer.X509_REVOKED */
            	5866, 0,
            0, 0, 1, /* 5866: X509_REVOKED */
            	5871, 0,
            0, 40, 4, /* 5871: struct.x509_revoked_st */
            	5882, 0,
            	5892, 8,
            	5897, 16,
            	4217, 24,
            1, 8, 1, /* 5882: pointer.struct.asn1_string_st */
            	5887, 0,
            0, 24, 1, /* 5887: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 5892: pointer.struct.asn1_string_st */
            	5887, 0,
            1, 8, 1, /* 5897: pointer.struct.stack_st_X509_EXTENSION */
            	5902, 0,
            0, 32, 2, /* 5902: struct.stack_st_fake_X509_EXTENSION */
            	5909, 8,
            	180, 24,
            8884099, 8, 2, /* 5909: pointer_to_array_of_pointers_to_stack */
            	5916, 0,
            	1052, 20,
            0, 8, 1, /* 5916: pointer.X509_EXTENSION */
            	2262, 0,
            1, 8, 1, /* 5921: pointer.struct.ISSUING_DIST_POINT_st */
            	5926, 0,
            0, 32, 2, /* 5926: struct.ISSUING_DIST_POINT_st */
            	3374, 0,
            	3465, 16,
            1, 8, 1, /* 5933: pointer.struct.stack_st_GENERAL_NAMES */
            	5938, 0,
            0, 32, 2, /* 5938: struct.stack_st_fake_GENERAL_NAMES */
            	5945, 8,
            	180, 24,
            8884099, 8, 2, /* 5945: pointer_to_array_of_pointers_to_stack */
            	5952, 0,
            	1052, 20,
            0, 8, 1, /* 5952: pointer.GENERAL_NAMES */
            	5957, 0,
            0, 0, 1, /* 5957: GENERAL_NAMES */
            	5962, 0,
            0, 32, 1, /* 5962: struct.stack_st_GENERAL_NAME */
            	5967, 0,
            0, 32, 2, /* 5967: struct.stack_st */
            	175, 8,
            	180, 24,
            1, 8, 1, /* 5974: pointer.struct.x509_crl_method_st */
            	5979, 0,
            0, 40, 4, /* 5979: struct.x509_crl_method_st */
            	5990, 8,
            	5990, 16,
            	5993, 24,
            	5996, 32,
            8884097, 8, 0, /* 5990: pointer.func */
            8884097, 8, 0, /* 5993: pointer.func */
            8884097, 8, 0, /* 5996: pointer.func */
            1, 8, 1, /* 5999: pointer.struct.evp_pkey_st */
            	6004, 0,
            0, 56, 4, /* 6004: struct.evp_pkey_st */
            	6015, 16,
            	219, 24,
            	6020, 32,
            	6053, 48,
            1, 8, 1, /* 6015: pointer.struct.evp_pkey_asn1_method_st */
            	1858, 0,
            0, 8, 5, /* 6020: union.unknown */
            	53, 0,
            	6033, 0,
            	6038, 0,
            	6043, 0,
            	6048, 0,
            1, 8, 1, /* 6033: pointer.struct.rsa_st */
            	572, 0,
            1, 8, 1, /* 6038: pointer.struct.dsa_st */
            	1224, 0,
            1, 8, 1, /* 6043: pointer.struct.dh_st */
            	94, 0,
            1, 8, 1, /* 6048: pointer.struct.ec_key_st */
            	1356, 0,
            1, 8, 1, /* 6053: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6058, 0,
            0, 32, 2, /* 6058: struct.stack_st_fake_X509_ATTRIBUTE */
            	6065, 8,
            	180, 24,
            8884099, 8, 2, /* 6065: pointer_to_array_of_pointers_to_stack */
            	6072, 0,
            	1052, 20,
            0, 8, 1, /* 6072: pointer.X509_ATTRIBUTE */
            	833, 0,
            8884097, 8, 0, /* 6077: pointer.func */
            8884097, 8, 0, /* 6080: pointer.func */
            8884097, 8, 0, /* 6083: pointer.func */
            8884097, 8, 0, /* 6086: pointer.func */
            1, 8, 1, /* 6089: pointer.struct.stack_st_X509_LOOKUP */
            	6094, 0,
            0, 32, 2, /* 6094: struct.stack_st_fake_X509_LOOKUP */
            	6101, 8,
            	180, 24,
            8884099, 8, 2, /* 6101: pointer_to_array_of_pointers_to_stack */
            	6108, 0,
            	1052, 20,
            0, 8, 1, /* 6108: pointer.X509_LOOKUP */
            	5326, 0,
            8884097, 8, 0, /* 6113: pointer.func */
            1, 8, 1, /* 6116: pointer.struct.ssl3_buf_freelist_st */
            	4565, 0,
            8884097, 8, 0, /* 6121: pointer.func */
            8884097, 8, 0, /* 6124: pointer.func */
            0, 120, 8, /* 6127: struct.env_md_st */
            	6146, 24,
            	6149, 32,
            	4320, 40,
            	4317, 48,
            	6146, 56,
            	800, 64,
            	803, 72,
            	6152, 112,
            8884097, 8, 0, /* 6146: pointer.func */
            8884097, 8, 0, /* 6149: pointer.func */
            8884097, 8, 0, /* 6152: pointer.func */
            0, 0, 1, /* 6155: SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 6160: pointer.func */
            8884097, 8, 0, /* 6163: pointer.func */
            8884097, 8, 0, /* 6166: pointer.func */
            0, 56, 2, /* 6169: struct.X509_VERIFY_PARAM_st */
            	53, 0,
            	4350, 48,
            1, 8, 1, /* 6176: pointer.struct.ssl3_enc_method */
            	6181, 0,
            0, 112, 11, /* 6181: struct.ssl3_enc_method */
            	6206, 0,
            	6209, 8,
            	6212, 16,
            	6215, 24,
            	6206, 32,
            	6218, 40,
            	6221, 56,
            	5, 64,
            	5, 80,
            	6224, 96,
            	6227, 104,
            8884097, 8, 0, /* 6206: pointer.func */
            8884097, 8, 0, /* 6209: pointer.func */
            8884097, 8, 0, /* 6212: pointer.func */
            8884097, 8, 0, /* 6215: pointer.func */
            8884097, 8, 0, /* 6218: pointer.func */
            8884097, 8, 0, /* 6221: pointer.func */
            8884097, 8, 0, /* 6224: pointer.func */
            8884097, 8, 0, /* 6227: pointer.func */
            1, 8, 1, /* 6230: pointer.struct.stack_st_X509_OBJECT */
            	6235, 0,
            0, 32, 2, /* 6235: struct.stack_st_fake_X509_OBJECT */
            	6242, 8,
            	180, 24,
            8884099, 8, 2, /* 6242: pointer_to_array_of_pointers_to_stack */
            	6249, 0,
            	1052, 20,
            0, 8, 1, /* 6249: pointer.X509_OBJECT */
            	5451, 0,
            8884097, 8, 0, /* 6254: pointer.func */
            8884097, 8, 0, /* 6257: pointer.func */
            8884097, 8, 0, /* 6260: pointer.func */
            8884097, 8, 0, /* 6263: pointer.func */
            0, 144, 15, /* 6266: struct.x509_store_st */
            	6230, 8,
            	6089, 16,
            	6299, 24,
            	5245, 32,
            	6263, 40,
            	6160, 48,
            	6304, 56,
            	5245, 64,
            	6121, 72,
            	6166, 80,
            	6307, 88,
            	6310, 96,
            	6313, 104,
            	5245, 112,
            	5138, 120,
            1, 8, 1, /* 6299: pointer.struct.X509_VERIFY_PARAM_st */
            	6169, 0,
            8884097, 8, 0, /* 6304: pointer.func */
            8884097, 8, 0, /* 6307: pointer.func */
            8884097, 8, 0, /* 6310: pointer.func */
            8884097, 8, 0, /* 6313: pointer.func */
            0, 1, 0, /* 6316: char */
            8884097, 8, 0, /* 6319: pointer.func */
            8884097, 8, 0, /* 6322: pointer.func */
            8884097, 8, 0, /* 6325: pointer.func */
            1, 8, 1, /* 6328: pointer.struct.ssl_ctx_st */
            	6333, 0,
            0, 736, 50, /* 6333: struct.ssl_ctx_st */
            	6436, 0,
            	5170, 8,
            	5170, 16,
            	6527, 24,
            	5221, 32,
            	5204, 48,
            	5204, 56,
            	5299, 80,
            	4985, 88,
            	4329, 96,
            	6113, 152,
            	41, 160,
            	6532, 168,
            	41, 176,
            	6535, 184,
            	4326, 192,
            	4323, 200,
            	5138, 208,
            	6538, 224,
            	6538, 232,
            	6538, 240,
            	4016, 248,
            	3992, 256,
            	3943, 264,
            	3871, 272,
            	3830, 304,
            	6543, 320,
            	41, 328,
            	6263, 376,
            	6546, 384,
            	6299, 392,
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
            	6124, 536,
            	6116, 552,
            	6116, 560,
            	10, 568,
            	6549, 696,
            	41, 704,
            	6552, 712,
            	41, 720,
            	6555, 728,
            1, 8, 1, /* 6436: pointer.struct.ssl_method_st */
            	6441, 0,
            0, 232, 28, /* 6441: struct.ssl_method_st */
            	6260, 8,
            	6500, 16,
            	6500, 24,
            	6260, 32,
            	6260, 40,
            	6319, 48,
            	6319, 56,
            	6503, 64,
            	6260, 72,
            	6260, 80,
            	6260, 88,
            	6322, 96,
            	6254, 104,
            	6257, 112,
            	6260, 120,
            	6506, 128,
            	6325, 136,
            	6509, 144,
            	6512, 152,
            	6515, 160,
            	493, 168,
            	6518, 176,
            	6163, 184,
            	3972, 192,
            	6176, 200,
            	493, 208,
            	6521, 216,
            	6524, 224,
            8884097, 8, 0, /* 6500: pointer.func */
            8884097, 8, 0, /* 6503: pointer.func */
            8884097, 8, 0, /* 6506: pointer.func */
            8884097, 8, 0, /* 6509: pointer.func */
            8884097, 8, 0, /* 6512: pointer.func */
            8884097, 8, 0, /* 6515: pointer.func */
            8884097, 8, 0, /* 6518: pointer.func */
            8884097, 8, 0, /* 6521: pointer.func */
            8884097, 8, 0, /* 6524: pointer.func */
            1, 8, 1, /* 6527: pointer.struct.x509_store_st */
            	6266, 0,
            8884097, 8, 0, /* 6532: pointer.func */
            8884097, 8, 0, /* 6535: pointer.func */
            1, 8, 1, /* 6538: pointer.struct.env_md_st */
            	6127, 0,
            8884097, 8, 0, /* 6543: pointer.func */
            8884097, 8, 0, /* 6546: pointer.func */
            8884097, 8, 0, /* 6549: pointer.func */
            8884097, 8, 0, /* 6552: pointer.func */
            1, 8, 1, /* 6555: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6560, 0,
            0, 32, 2, /* 6560: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6567, 8,
            	180, 24,
            8884099, 8, 2, /* 6567: pointer_to_array_of_pointers_to_stack */
            	6574, 0,
            	1052, 20,
            0, 8, 1, /* 6574: pointer.SRTP_PROTECTION_PROFILE */
            	6155, 0,
        },
        .arg_entity_index = { 6328, 6532, },
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

