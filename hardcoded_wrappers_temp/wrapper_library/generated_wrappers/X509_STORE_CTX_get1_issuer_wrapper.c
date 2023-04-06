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

int bb_X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c);

int X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_STORE_CTX_get1_issuer called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_STORE_CTX_get1_issuer(arg_a,arg_b,arg_c);
    else {
        int (*orig_X509_STORE_CTX_get1_issuer)(X509 **,X509_STORE_CTX *,X509 *);
        orig_X509_STORE_CTX_get1_issuer = dlsym(RTLD_NEXT, "X509_STORE_CTX_get1_issuer");
        return orig_X509_STORE_CTX_get1_issuer(arg_a,arg_b,arg_c);
    }
}

int bb_X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.pointer.struct.x509_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.struct.x509_st */
            	10, 0,
            0, 184, 12, /* 10: struct.x509_st */
            	37, 0,
            	85, 8,
            	2207, 16,
            	174, 32,
            	2277, 40,
            	2299, 104,
            	2304, 112,
            	2627, 120,
            	3063, 128,
            	3202, 136,
            	3226, 144,
            	3538, 176,
            1, 8, 1, /* 37: pointer.struct.x509_cinf_st */
            	42, 0,
            0, 104, 11, /* 42: struct.x509_cinf_st */
            	67, 0,
            	67, 8,
            	85, 16,
            	267, 24,
            	357, 32,
            	267, 40,
            	374, 48,
            	2207, 56,
            	2207, 64,
            	2212, 72,
            	2272, 80,
            1, 8, 1, /* 67: pointer.struct.asn1_string_st */
            	72, 0,
            0, 24, 1, /* 72: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 77: pointer.unsigned char */
            	82, 0,
            0, 1, 0, /* 82: unsigned char */
            1, 8, 1, /* 85: pointer.struct.X509_algor_st */
            	90, 0,
            0, 16, 2, /* 90: struct.X509_algor_st */
            	97, 0,
            	121, 8,
            1, 8, 1, /* 97: pointer.struct.asn1_object_st */
            	102, 0,
            0, 40, 3, /* 102: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 111: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 116: pointer.unsigned char */
            	82, 0,
            1, 8, 1, /* 121: pointer.struct.asn1_type_st */
            	126, 0,
            0, 16, 1, /* 126: struct.asn1_type_st */
            	131, 8,
            0, 8, 20, /* 131: union.unknown */
            	174, 0,
            	179, 0,
            	97, 0,
            	189, 0,
            	194, 0,
            	199, 0,
            	204, 0,
            	209, 0,
            	214, 0,
            	219, 0,
            	224, 0,
            	229, 0,
            	234, 0,
            	239, 0,
            	244, 0,
            	249, 0,
            	254, 0,
            	179, 0,
            	179, 0,
            	259, 0,
            1, 8, 1, /* 174: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 179: pointer.struct.asn1_string_st */
            	184, 0,
            0, 24, 1, /* 184: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 189: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 194: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 199: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 204: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 209: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 214: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 219: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 224: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 229: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 234: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 239: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 244: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 249: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 254: pointer.struct.asn1_string_st */
            	184, 0,
            1, 8, 1, /* 259: pointer.struct.ASN1_VALUE_st */
            	264, 0,
            0, 0, 0, /* 264: struct.ASN1_VALUE_st */
            1, 8, 1, /* 267: pointer.struct.X509_name_st */
            	272, 0,
            0, 40, 3, /* 272: struct.X509_name_st */
            	281, 0,
            	347, 16,
            	77, 24,
            1, 8, 1, /* 281: pointer.struct.stack_st_X509_NAME_ENTRY */
            	286, 0,
            0, 32, 2, /* 286: struct.stack_st_fake_X509_NAME_ENTRY */
            	293, 8,
            	344, 24,
            8884099, 8, 2, /* 293: pointer_to_array_of_pointers_to_stack */
            	300, 0,
            	341, 20,
            0, 8, 1, /* 300: pointer.X509_NAME_ENTRY */
            	305, 0,
            0, 0, 1, /* 305: X509_NAME_ENTRY */
            	310, 0,
            0, 24, 2, /* 310: struct.X509_name_entry_st */
            	317, 0,
            	331, 8,
            1, 8, 1, /* 317: pointer.struct.asn1_object_st */
            	322, 0,
            0, 40, 3, /* 322: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 331: pointer.struct.asn1_string_st */
            	336, 0,
            0, 24, 1, /* 336: struct.asn1_string_st */
            	77, 8,
            0, 4, 0, /* 341: int */
            8884097, 8, 0, /* 344: pointer.func */
            1, 8, 1, /* 347: pointer.struct.buf_mem_st */
            	352, 0,
            0, 24, 1, /* 352: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 357: pointer.struct.X509_val_st */
            	362, 0,
            0, 16, 2, /* 362: struct.X509_val_st */
            	369, 0,
            	369, 8,
            1, 8, 1, /* 369: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 374: pointer.struct.X509_pubkey_st */
            	379, 0,
            0, 24, 3, /* 379: struct.X509_pubkey_st */
            	388, 0,
            	393, 8,
            	403, 16,
            1, 8, 1, /* 388: pointer.struct.X509_algor_st */
            	90, 0,
            1, 8, 1, /* 393: pointer.struct.asn1_string_st */
            	398, 0,
            0, 24, 1, /* 398: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 403: pointer.struct.evp_pkey_st */
            	408, 0,
            0, 56, 4, /* 408: struct.evp_pkey_st */
            	419, 16,
            	520, 24,
            	873, 32,
            	1828, 48,
            1, 8, 1, /* 419: pointer.struct.evp_pkey_asn1_method_st */
            	424, 0,
            0, 208, 24, /* 424: struct.evp_pkey_asn1_method_st */
            	174, 16,
            	174, 24,
            	475, 32,
            	478, 40,
            	481, 48,
            	484, 56,
            	487, 64,
            	490, 72,
            	484, 80,
            	493, 88,
            	493, 96,
            	496, 104,
            	499, 112,
            	493, 120,
            	502, 128,
            	481, 136,
            	484, 144,
            	505, 152,
            	508, 160,
            	511, 168,
            	496, 176,
            	499, 184,
            	514, 192,
            	517, 200,
            8884097, 8, 0, /* 475: pointer.func */
            8884097, 8, 0, /* 478: pointer.func */
            8884097, 8, 0, /* 481: pointer.func */
            8884097, 8, 0, /* 484: pointer.func */
            8884097, 8, 0, /* 487: pointer.func */
            8884097, 8, 0, /* 490: pointer.func */
            8884097, 8, 0, /* 493: pointer.func */
            8884097, 8, 0, /* 496: pointer.func */
            8884097, 8, 0, /* 499: pointer.func */
            8884097, 8, 0, /* 502: pointer.func */
            8884097, 8, 0, /* 505: pointer.func */
            8884097, 8, 0, /* 508: pointer.func */
            8884097, 8, 0, /* 511: pointer.func */
            8884097, 8, 0, /* 514: pointer.func */
            8884097, 8, 0, /* 517: pointer.func */
            1, 8, 1, /* 520: pointer.struct.engine_st */
            	525, 0,
            0, 216, 24, /* 525: struct.engine_st */
            	111, 0,
            	111, 8,
            	576, 16,
            	631, 24,
            	682, 32,
            	718, 40,
            	735, 48,
            	762, 56,
            	797, 64,
            	805, 72,
            	808, 80,
            	811, 88,
            	814, 96,
            	817, 104,
            	817, 112,
            	817, 120,
            	820, 128,
            	823, 136,
            	823, 144,
            	826, 152,
            	829, 160,
            	841, 184,
            	868, 200,
            	868, 208,
            1, 8, 1, /* 576: pointer.struct.rsa_meth_st */
            	581, 0,
            0, 112, 13, /* 581: struct.rsa_meth_st */
            	111, 0,
            	610, 8,
            	610, 16,
            	610, 24,
            	610, 32,
            	613, 40,
            	616, 48,
            	619, 56,
            	619, 64,
            	174, 80,
            	622, 88,
            	625, 96,
            	628, 104,
            8884097, 8, 0, /* 610: pointer.func */
            8884097, 8, 0, /* 613: pointer.func */
            8884097, 8, 0, /* 616: pointer.func */
            8884097, 8, 0, /* 619: pointer.func */
            8884097, 8, 0, /* 622: pointer.func */
            8884097, 8, 0, /* 625: pointer.func */
            8884097, 8, 0, /* 628: pointer.func */
            1, 8, 1, /* 631: pointer.struct.dsa_method */
            	636, 0,
            0, 96, 11, /* 636: struct.dsa_method */
            	111, 0,
            	661, 8,
            	664, 16,
            	667, 24,
            	670, 32,
            	673, 40,
            	676, 48,
            	676, 56,
            	174, 72,
            	679, 80,
            	676, 88,
            8884097, 8, 0, /* 661: pointer.func */
            8884097, 8, 0, /* 664: pointer.func */
            8884097, 8, 0, /* 667: pointer.func */
            8884097, 8, 0, /* 670: pointer.func */
            8884097, 8, 0, /* 673: pointer.func */
            8884097, 8, 0, /* 676: pointer.func */
            8884097, 8, 0, /* 679: pointer.func */
            1, 8, 1, /* 682: pointer.struct.dh_method */
            	687, 0,
            0, 72, 8, /* 687: struct.dh_method */
            	111, 0,
            	706, 8,
            	709, 16,
            	712, 24,
            	706, 32,
            	706, 40,
            	174, 56,
            	715, 64,
            8884097, 8, 0, /* 706: pointer.func */
            8884097, 8, 0, /* 709: pointer.func */
            8884097, 8, 0, /* 712: pointer.func */
            8884097, 8, 0, /* 715: pointer.func */
            1, 8, 1, /* 718: pointer.struct.ecdh_method */
            	723, 0,
            0, 32, 3, /* 723: struct.ecdh_method */
            	111, 0,
            	732, 8,
            	174, 24,
            8884097, 8, 0, /* 732: pointer.func */
            1, 8, 1, /* 735: pointer.struct.ecdsa_method */
            	740, 0,
            0, 48, 5, /* 740: struct.ecdsa_method */
            	111, 0,
            	753, 8,
            	756, 16,
            	759, 24,
            	174, 40,
            8884097, 8, 0, /* 753: pointer.func */
            8884097, 8, 0, /* 756: pointer.func */
            8884097, 8, 0, /* 759: pointer.func */
            1, 8, 1, /* 762: pointer.struct.rand_meth_st */
            	767, 0,
            0, 48, 6, /* 767: struct.rand_meth_st */
            	782, 0,
            	785, 8,
            	788, 16,
            	791, 24,
            	785, 32,
            	794, 40,
            8884097, 8, 0, /* 782: pointer.func */
            8884097, 8, 0, /* 785: pointer.func */
            8884097, 8, 0, /* 788: pointer.func */
            8884097, 8, 0, /* 791: pointer.func */
            8884097, 8, 0, /* 794: pointer.func */
            1, 8, 1, /* 797: pointer.struct.store_method_st */
            	802, 0,
            0, 0, 0, /* 802: struct.store_method_st */
            8884097, 8, 0, /* 805: pointer.func */
            8884097, 8, 0, /* 808: pointer.func */
            8884097, 8, 0, /* 811: pointer.func */
            8884097, 8, 0, /* 814: pointer.func */
            8884097, 8, 0, /* 817: pointer.func */
            8884097, 8, 0, /* 820: pointer.func */
            8884097, 8, 0, /* 823: pointer.func */
            8884097, 8, 0, /* 826: pointer.func */
            1, 8, 1, /* 829: pointer.struct.ENGINE_CMD_DEFN_st */
            	834, 0,
            0, 32, 2, /* 834: struct.ENGINE_CMD_DEFN_st */
            	111, 8,
            	111, 16,
            0, 16, 1, /* 841: struct.crypto_ex_data_st */
            	846, 0,
            1, 8, 1, /* 846: pointer.struct.stack_st_void */
            	851, 0,
            0, 32, 1, /* 851: struct.stack_st_void */
            	856, 0,
            0, 32, 2, /* 856: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 863: pointer.pointer.char */
            	174, 0,
            1, 8, 1, /* 868: pointer.struct.engine_st */
            	525, 0,
            0, 8, 5, /* 873: union.unknown */
            	174, 0,
            	886, 0,
            	1099, 0,
            	1226, 0,
            	1340, 0,
            1, 8, 1, /* 886: pointer.struct.rsa_st */
            	891, 0,
            0, 168, 17, /* 891: struct.rsa_st */
            	928, 16,
            	983, 24,
            	988, 32,
            	988, 40,
            	988, 48,
            	988, 56,
            	988, 64,
            	988, 72,
            	988, 80,
            	988, 88,
            	1006, 96,
            	1028, 120,
            	1028, 128,
            	1028, 136,
            	174, 144,
            	1042, 152,
            	1042, 160,
            1, 8, 1, /* 928: pointer.struct.rsa_meth_st */
            	933, 0,
            0, 112, 13, /* 933: struct.rsa_meth_st */
            	111, 0,
            	962, 8,
            	962, 16,
            	962, 24,
            	962, 32,
            	965, 40,
            	968, 48,
            	971, 56,
            	971, 64,
            	174, 80,
            	974, 88,
            	977, 96,
            	980, 104,
            8884097, 8, 0, /* 962: pointer.func */
            8884097, 8, 0, /* 965: pointer.func */
            8884097, 8, 0, /* 968: pointer.func */
            8884097, 8, 0, /* 971: pointer.func */
            8884097, 8, 0, /* 974: pointer.func */
            8884097, 8, 0, /* 977: pointer.func */
            8884097, 8, 0, /* 980: pointer.func */
            1, 8, 1, /* 983: pointer.struct.engine_st */
            	525, 0,
            1, 8, 1, /* 988: pointer.struct.bignum_st */
            	993, 0,
            0, 24, 1, /* 993: struct.bignum_st */
            	998, 0,
            1, 8, 1, /* 998: pointer.unsigned int */
            	1003, 0,
            0, 4, 0, /* 1003: unsigned int */
            0, 16, 1, /* 1006: struct.crypto_ex_data_st */
            	1011, 0,
            1, 8, 1, /* 1011: pointer.struct.stack_st_void */
            	1016, 0,
            0, 32, 1, /* 1016: struct.stack_st_void */
            	1021, 0,
            0, 32, 2, /* 1021: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 1028: pointer.struct.bn_mont_ctx_st */
            	1033, 0,
            0, 96, 3, /* 1033: struct.bn_mont_ctx_st */
            	993, 8,
            	993, 32,
            	993, 56,
            1, 8, 1, /* 1042: pointer.struct.bn_blinding_st */
            	1047, 0,
            0, 88, 7, /* 1047: struct.bn_blinding_st */
            	1064, 0,
            	1064, 8,
            	1064, 16,
            	1064, 24,
            	1074, 40,
            	1082, 72,
            	1096, 80,
            1, 8, 1, /* 1064: pointer.struct.bignum_st */
            	1069, 0,
            0, 24, 1, /* 1069: struct.bignum_st */
            	998, 0,
            0, 16, 1, /* 1074: struct.crypto_threadid_st */
            	1079, 0,
            0, 8, 0, /* 1079: pointer.void */
            1, 8, 1, /* 1082: pointer.struct.bn_mont_ctx_st */
            	1087, 0,
            0, 96, 3, /* 1087: struct.bn_mont_ctx_st */
            	1069, 8,
            	1069, 32,
            	1069, 56,
            8884097, 8, 0, /* 1096: pointer.func */
            1, 8, 1, /* 1099: pointer.struct.dsa_st */
            	1104, 0,
            0, 136, 11, /* 1104: struct.dsa_st */
            	1129, 24,
            	1129, 32,
            	1129, 40,
            	1129, 48,
            	1129, 56,
            	1129, 64,
            	1129, 72,
            	1139, 88,
            	1153, 104,
            	1175, 120,
            	520, 128,
            1, 8, 1, /* 1129: pointer.struct.bignum_st */
            	1134, 0,
            0, 24, 1, /* 1134: struct.bignum_st */
            	998, 0,
            1, 8, 1, /* 1139: pointer.struct.bn_mont_ctx_st */
            	1144, 0,
            0, 96, 3, /* 1144: struct.bn_mont_ctx_st */
            	1134, 8,
            	1134, 32,
            	1134, 56,
            0, 16, 1, /* 1153: struct.crypto_ex_data_st */
            	1158, 0,
            1, 8, 1, /* 1158: pointer.struct.stack_st_void */
            	1163, 0,
            0, 32, 1, /* 1163: struct.stack_st_void */
            	1168, 0,
            0, 32, 2, /* 1168: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 1175: pointer.struct.dsa_method */
            	1180, 0,
            0, 96, 11, /* 1180: struct.dsa_method */
            	111, 0,
            	1205, 8,
            	1208, 16,
            	1211, 24,
            	1214, 32,
            	1217, 40,
            	1220, 48,
            	1220, 56,
            	174, 72,
            	1223, 80,
            	1220, 88,
            8884097, 8, 0, /* 1205: pointer.func */
            8884097, 8, 0, /* 1208: pointer.func */
            8884097, 8, 0, /* 1211: pointer.func */
            8884097, 8, 0, /* 1214: pointer.func */
            8884097, 8, 0, /* 1217: pointer.func */
            8884097, 8, 0, /* 1220: pointer.func */
            8884097, 8, 0, /* 1223: pointer.func */
            1, 8, 1, /* 1226: pointer.struct.dh_st */
            	1231, 0,
            0, 144, 12, /* 1231: struct.dh_st */
            	1258, 8,
            	1258, 16,
            	1258, 32,
            	1258, 40,
            	1268, 56,
            	1258, 64,
            	1258, 72,
            	77, 80,
            	1258, 96,
            	1282, 112,
            	1304, 128,
            	983, 136,
            1, 8, 1, /* 1258: pointer.struct.bignum_st */
            	1263, 0,
            0, 24, 1, /* 1263: struct.bignum_st */
            	998, 0,
            1, 8, 1, /* 1268: pointer.struct.bn_mont_ctx_st */
            	1273, 0,
            0, 96, 3, /* 1273: struct.bn_mont_ctx_st */
            	1263, 8,
            	1263, 32,
            	1263, 56,
            0, 16, 1, /* 1282: struct.crypto_ex_data_st */
            	1287, 0,
            1, 8, 1, /* 1287: pointer.struct.stack_st_void */
            	1292, 0,
            0, 32, 1, /* 1292: struct.stack_st_void */
            	1297, 0,
            0, 32, 2, /* 1297: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 1304: pointer.struct.dh_method */
            	1309, 0,
            0, 72, 8, /* 1309: struct.dh_method */
            	111, 0,
            	1328, 8,
            	1331, 16,
            	1334, 24,
            	1328, 32,
            	1328, 40,
            	174, 56,
            	1337, 64,
            8884097, 8, 0, /* 1328: pointer.func */
            8884097, 8, 0, /* 1331: pointer.func */
            8884097, 8, 0, /* 1334: pointer.func */
            8884097, 8, 0, /* 1337: pointer.func */
            1, 8, 1, /* 1340: pointer.struct.ec_key_st */
            	1345, 0,
            0, 56, 4, /* 1345: struct.ec_key_st */
            	1356, 8,
            	1790, 16,
            	1795, 24,
            	1805, 48,
            1, 8, 1, /* 1356: pointer.struct.ec_group_st */
            	1361, 0,
            0, 232, 12, /* 1361: struct.ec_group_st */
            	1388, 0,
            	1560, 8,
            	1753, 16,
            	1753, 40,
            	77, 80,
            	1758, 96,
            	1753, 104,
            	1753, 152,
            	1753, 176,
            	1079, 208,
            	1079, 216,
            	1787, 224,
            1, 8, 1, /* 1388: pointer.struct.ec_method_st */
            	1393, 0,
            0, 304, 37, /* 1393: struct.ec_method_st */
            	1470, 8,
            	1473, 16,
            	1473, 24,
            	1476, 32,
            	1479, 40,
            	1482, 48,
            	1485, 56,
            	1488, 64,
            	1491, 72,
            	1494, 80,
            	1494, 88,
            	1497, 96,
            	1500, 104,
            	1503, 112,
            	1506, 120,
            	1509, 128,
            	1512, 136,
            	1515, 144,
            	1518, 152,
            	1521, 160,
            	1524, 168,
            	1527, 176,
            	1530, 184,
            	1533, 192,
            	1536, 200,
            	1539, 208,
            	1530, 216,
            	1542, 224,
            	1545, 232,
            	1548, 240,
            	1485, 248,
            	1551, 256,
            	1554, 264,
            	1551, 272,
            	1554, 280,
            	1554, 288,
            	1557, 296,
            8884097, 8, 0, /* 1470: pointer.func */
            8884097, 8, 0, /* 1473: pointer.func */
            8884097, 8, 0, /* 1476: pointer.func */
            8884097, 8, 0, /* 1479: pointer.func */
            8884097, 8, 0, /* 1482: pointer.func */
            8884097, 8, 0, /* 1485: pointer.func */
            8884097, 8, 0, /* 1488: pointer.func */
            8884097, 8, 0, /* 1491: pointer.func */
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
            8884097, 8, 0, /* 1539: pointer.func */
            8884097, 8, 0, /* 1542: pointer.func */
            8884097, 8, 0, /* 1545: pointer.func */
            8884097, 8, 0, /* 1548: pointer.func */
            8884097, 8, 0, /* 1551: pointer.func */
            8884097, 8, 0, /* 1554: pointer.func */
            8884097, 8, 0, /* 1557: pointer.func */
            1, 8, 1, /* 1560: pointer.struct.ec_point_st */
            	1565, 0,
            0, 88, 4, /* 1565: struct.ec_point_st */
            	1576, 0,
            	1748, 8,
            	1748, 32,
            	1748, 56,
            1, 8, 1, /* 1576: pointer.struct.ec_method_st */
            	1581, 0,
            0, 304, 37, /* 1581: struct.ec_method_st */
            	1658, 8,
            	1661, 16,
            	1661, 24,
            	1664, 32,
            	1667, 40,
            	1670, 48,
            	1673, 56,
            	1676, 64,
            	1679, 72,
            	1682, 80,
            	1682, 88,
            	1685, 96,
            	1688, 104,
            	1691, 112,
            	1694, 120,
            	1697, 128,
            	1700, 136,
            	1703, 144,
            	1706, 152,
            	1709, 160,
            	1712, 168,
            	1715, 176,
            	1718, 184,
            	1721, 192,
            	1724, 200,
            	1727, 208,
            	1718, 216,
            	1730, 224,
            	1733, 232,
            	1736, 240,
            	1673, 248,
            	1739, 256,
            	1742, 264,
            	1739, 272,
            	1742, 280,
            	1742, 288,
            	1745, 296,
            8884097, 8, 0, /* 1658: pointer.func */
            8884097, 8, 0, /* 1661: pointer.func */
            8884097, 8, 0, /* 1664: pointer.func */
            8884097, 8, 0, /* 1667: pointer.func */
            8884097, 8, 0, /* 1670: pointer.func */
            8884097, 8, 0, /* 1673: pointer.func */
            8884097, 8, 0, /* 1676: pointer.func */
            8884097, 8, 0, /* 1679: pointer.func */
            8884097, 8, 0, /* 1682: pointer.func */
            8884097, 8, 0, /* 1685: pointer.func */
            8884097, 8, 0, /* 1688: pointer.func */
            8884097, 8, 0, /* 1691: pointer.func */
            8884097, 8, 0, /* 1694: pointer.func */
            8884097, 8, 0, /* 1697: pointer.func */
            8884097, 8, 0, /* 1700: pointer.func */
            8884097, 8, 0, /* 1703: pointer.func */
            8884097, 8, 0, /* 1706: pointer.func */
            8884097, 8, 0, /* 1709: pointer.func */
            8884097, 8, 0, /* 1712: pointer.func */
            8884097, 8, 0, /* 1715: pointer.func */
            8884097, 8, 0, /* 1718: pointer.func */
            8884097, 8, 0, /* 1721: pointer.func */
            8884097, 8, 0, /* 1724: pointer.func */
            8884097, 8, 0, /* 1727: pointer.func */
            8884097, 8, 0, /* 1730: pointer.func */
            8884097, 8, 0, /* 1733: pointer.func */
            8884097, 8, 0, /* 1736: pointer.func */
            8884097, 8, 0, /* 1739: pointer.func */
            8884097, 8, 0, /* 1742: pointer.func */
            8884097, 8, 0, /* 1745: pointer.func */
            0, 24, 1, /* 1748: struct.bignum_st */
            	998, 0,
            0, 24, 1, /* 1753: struct.bignum_st */
            	998, 0,
            1, 8, 1, /* 1758: pointer.struct.ec_extra_data_st */
            	1763, 0,
            0, 40, 5, /* 1763: struct.ec_extra_data_st */
            	1776, 0,
            	1079, 8,
            	1781, 16,
            	1784, 24,
            	1784, 32,
            1, 8, 1, /* 1776: pointer.struct.ec_extra_data_st */
            	1763, 0,
            8884097, 8, 0, /* 1781: pointer.func */
            8884097, 8, 0, /* 1784: pointer.func */
            8884097, 8, 0, /* 1787: pointer.func */
            1, 8, 1, /* 1790: pointer.struct.ec_point_st */
            	1565, 0,
            1, 8, 1, /* 1795: pointer.struct.bignum_st */
            	1800, 0,
            0, 24, 1, /* 1800: struct.bignum_st */
            	998, 0,
            1, 8, 1, /* 1805: pointer.struct.ec_extra_data_st */
            	1810, 0,
            0, 40, 5, /* 1810: struct.ec_extra_data_st */
            	1823, 0,
            	1079, 8,
            	1781, 16,
            	1784, 24,
            	1784, 32,
            1, 8, 1, /* 1823: pointer.struct.ec_extra_data_st */
            	1810, 0,
            1, 8, 1, /* 1828: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1833, 0,
            0, 32, 2, /* 1833: struct.stack_st_fake_X509_ATTRIBUTE */
            	1840, 8,
            	344, 24,
            8884099, 8, 2, /* 1840: pointer_to_array_of_pointers_to_stack */
            	1847, 0,
            	341, 20,
            0, 8, 1, /* 1847: pointer.X509_ATTRIBUTE */
            	1852, 0,
            0, 0, 1, /* 1852: X509_ATTRIBUTE */
            	1857, 0,
            0, 24, 2, /* 1857: struct.x509_attributes_st */
            	1864, 0,
            	1878, 16,
            1, 8, 1, /* 1864: pointer.struct.asn1_object_st */
            	1869, 0,
            0, 40, 3, /* 1869: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            0, 8, 3, /* 1878: union.unknown */
            	174, 0,
            	1887, 0,
            	2066, 0,
            1, 8, 1, /* 1887: pointer.struct.stack_st_ASN1_TYPE */
            	1892, 0,
            0, 32, 2, /* 1892: struct.stack_st_fake_ASN1_TYPE */
            	1899, 8,
            	344, 24,
            8884099, 8, 2, /* 1899: pointer_to_array_of_pointers_to_stack */
            	1906, 0,
            	341, 20,
            0, 8, 1, /* 1906: pointer.ASN1_TYPE */
            	1911, 0,
            0, 0, 1, /* 1911: ASN1_TYPE */
            	1916, 0,
            0, 16, 1, /* 1916: struct.asn1_type_st */
            	1921, 8,
            0, 8, 20, /* 1921: union.unknown */
            	174, 0,
            	1964, 0,
            	1974, 0,
            	1988, 0,
            	1993, 0,
            	1998, 0,
            	2003, 0,
            	2008, 0,
            	2013, 0,
            	2018, 0,
            	2023, 0,
            	2028, 0,
            	2033, 0,
            	2038, 0,
            	2043, 0,
            	2048, 0,
            	2053, 0,
            	1964, 0,
            	1964, 0,
            	2058, 0,
            1, 8, 1, /* 1964: pointer.struct.asn1_string_st */
            	1969, 0,
            0, 24, 1, /* 1969: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 1974: pointer.struct.asn1_object_st */
            	1979, 0,
            0, 40, 3, /* 1979: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 1988: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 1993: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 1998: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2003: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2008: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2013: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2018: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2023: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2028: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2033: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2038: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2043: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2048: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2053: pointer.struct.asn1_string_st */
            	1969, 0,
            1, 8, 1, /* 2058: pointer.struct.ASN1_VALUE_st */
            	2063, 0,
            0, 0, 0, /* 2063: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2066: pointer.struct.asn1_type_st */
            	2071, 0,
            0, 16, 1, /* 2071: struct.asn1_type_st */
            	2076, 8,
            0, 8, 20, /* 2076: union.unknown */
            	174, 0,
            	2119, 0,
            	1864, 0,
            	2129, 0,
            	2134, 0,
            	2139, 0,
            	2144, 0,
            	2149, 0,
            	2154, 0,
            	2159, 0,
            	2164, 0,
            	2169, 0,
            	2174, 0,
            	2179, 0,
            	2184, 0,
            	2189, 0,
            	2194, 0,
            	2119, 0,
            	2119, 0,
            	2199, 0,
            1, 8, 1, /* 2119: pointer.struct.asn1_string_st */
            	2124, 0,
            0, 24, 1, /* 2124: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2129: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2134: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2139: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2144: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2149: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2154: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2159: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2164: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2169: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2174: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2179: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2184: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2189: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2194: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2199: pointer.struct.ASN1_VALUE_st */
            	2204, 0,
            0, 0, 0, /* 2204: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2207: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 2212: pointer.struct.stack_st_X509_EXTENSION */
            	2217, 0,
            0, 32, 2, /* 2217: struct.stack_st_fake_X509_EXTENSION */
            	2224, 8,
            	344, 24,
            8884099, 8, 2, /* 2224: pointer_to_array_of_pointers_to_stack */
            	2231, 0,
            	341, 20,
            0, 8, 1, /* 2231: pointer.X509_EXTENSION */
            	2236, 0,
            0, 0, 1, /* 2236: X509_EXTENSION */
            	2241, 0,
            0, 24, 2, /* 2241: struct.X509_extension_st */
            	2248, 0,
            	2262, 16,
            1, 8, 1, /* 2248: pointer.struct.asn1_object_st */
            	2253, 0,
            0, 40, 3, /* 2253: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2262: pointer.struct.asn1_string_st */
            	2267, 0,
            0, 24, 1, /* 2267: struct.asn1_string_st */
            	77, 8,
            0, 24, 1, /* 2272: struct.ASN1_ENCODING_st */
            	77, 0,
            0, 16, 1, /* 2277: struct.crypto_ex_data_st */
            	2282, 0,
            1, 8, 1, /* 2282: pointer.struct.stack_st_void */
            	2287, 0,
            0, 32, 1, /* 2287: struct.stack_st_void */
            	2292, 0,
            0, 32, 2, /* 2292: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 2299: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 2304: pointer.struct.AUTHORITY_KEYID_st */
            	2309, 0,
            0, 24, 3, /* 2309: struct.AUTHORITY_KEYID_st */
            	2318, 0,
            	2328, 8,
            	2622, 16,
            1, 8, 1, /* 2318: pointer.struct.asn1_string_st */
            	2323, 0,
            0, 24, 1, /* 2323: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2328: pointer.struct.stack_st_GENERAL_NAME */
            	2333, 0,
            0, 32, 2, /* 2333: struct.stack_st_fake_GENERAL_NAME */
            	2340, 8,
            	344, 24,
            8884099, 8, 2, /* 2340: pointer_to_array_of_pointers_to_stack */
            	2347, 0,
            	341, 20,
            0, 8, 1, /* 2347: pointer.GENERAL_NAME */
            	2352, 0,
            0, 0, 1, /* 2352: GENERAL_NAME */
            	2357, 0,
            0, 16, 1, /* 2357: struct.GENERAL_NAME_st */
            	2362, 8,
            0, 8, 15, /* 2362: union.unknown */
            	174, 0,
            	2395, 0,
            	2514, 0,
            	2514, 0,
            	2421, 0,
            	2562, 0,
            	2610, 0,
            	2514, 0,
            	2499, 0,
            	2407, 0,
            	2499, 0,
            	2562, 0,
            	2514, 0,
            	2407, 0,
            	2421, 0,
            1, 8, 1, /* 2395: pointer.struct.otherName_st */
            	2400, 0,
            0, 16, 2, /* 2400: struct.otherName_st */
            	2407, 0,
            	2421, 8,
            1, 8, 1, /* 2407: pointer.struct.asn1_object_st */
            	2412, 0,
            0, 40, 3, /* 2412: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2421: pointer.struct.asn1_type_st */
            	2426, 0,
            0, 16, 1, /* 2426: struct.asn1_type_st */
            	2431, 8,
            0, 8, 20, /* 2431: union.unknown */
            	174, 0,
            	2474, 0,
            	2407, 0,
            	2484, 0,
            	2489, 0,
            	2494, 0,
            	2499, 0,
            	2504, 0,
            	2509, 0,
            	2514, 0,
            	2519, 0,
            	2524, 0,
            	2529, 0,
            	2534, 0,
            	2539, 0,
            	2544, 0,
            	2549, 0,
            	2474, 0,
            	2474, 0,
            	2554, 0,
            1, 8, 1, /* 2474: pointer.struct.asn1_string_st */
            	2479, 0,
            0, 24, 1, /* 2479: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2484: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2489: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2494: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2499: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2504: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2509: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2514: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2519: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2524: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2529: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2534: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2539: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2544: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2549: pointer.struct.asn1_string_st */
            	2479, 0,
            1, 8, 1, /* 2554: pointer.struct.ASN1_VALUE_st */
            	2559, 0,
            0, 0, 0, /* 2559: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2562: pointer.struct.X509_name_st */
            	2567, 0,
            0, 40, 3, /* 2567: struct.X509_name_st */
            	2576, 0,
            	2600, 16,
            	77, 24,
            1, 8, 1, /* 2576: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2581, 0,
            0, 32, 2, /* 2581: struct.stack_st_fake_X509_NAME_ENTRY */
            	2588, 8,
            	344, 24,
            8884099, 8, 2, /* 2588: pointer_to_array_of_pointers_to_stack */
            	2595, 0,
            	341, 20,
            0, 8, 1, /* 2595: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 2600: pointer.struct.buf_mem_st */
            	2605, 0,
            0, 24, 1, /* 2605: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 2610: pointer.struct.EDIPartyName_st */
            	2615, 0,
            0, 16, 2, /* 2615: struct.EDIPartyName_st */
            	2474, 0,
            	2474, 8,
            1, 8, 1, /* 2622: pointer.struct.asn1_string_st */
            	2323, 0,
            1, 8, 1, /* 2627: pointer.struct.X509_POLICY_CACHE_st */
            	2632, 0,
            0, 40, 2, /* 2632: struct.X509_POLICY_CACHE_st */
            	2639, 0,
            	2963, 8,
            1, 8, 1, /* 2639: pointer.struct.X509_POLICY_DATA_st */
            	2644, 0,
            0, 32, 3, /* 2644: struct.X509_POLICY_DATA_st */
            	2653, 8,
            	2667, 16,
            	2925, 24,
            1, 8, 1, /* 2653: pointer.struct.asn1_object_st */
            	2658, 0,
            0, 40, 3, /* 2658: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2667: pointer.struct.stack_st_POLICYQUALINFO */
            	2672, 0,
            0, 32, 2, /* 2672: struct.stack_st_fake_POLICYQUALINFO */
            	2679, 8,
            	344, 24,
            8884099, 8, 2, /* 2679: pointer_to_array_of_pointers_to_stack */
            	2686, 0,
            	341, 20,
            0, 8, 1, /* 2686: pointer.POLICYQUALINFO */
            	2691, 0,
            0, 0, 1, /* 2691: POLICYQUALINFO */
            	2696, 0,
            0, 16, 2, /* 2696: struct.POLICYQUALINFO_st */
            	2703, 0,
            	2717, 8,
            1, 8, 1, /* 2703: pointer.struct.asn1_object_st */
            	2708, 0,
            0, 40, 3, /* 2708: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            0, 8, 3, /* 2717: union.unknown */
            	2726, 0,
            	2736, 0,
            	2799, 0,
            1, 8, 1, /* 2726: pointer.struct.asn1_string_st */
            	2731, 0,
            0, 24, 1, /* 2731: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2736: pointer.struct.USERNOTICE_st */
            	2741, 0,
            0, 16, 2, /* 2741: struct.USERNOTICE_st */
            	2748, 0,
            	2760, 8,
            1, 8, 1, /* 2748: pointer.struct.NOTICEREF_st */
            	2753, 0,
            0, 16, 2, /* 2753: struct.NOTICEREF_st */
            	2760, 0,
            	2765, 8,
            1, 8, 1, /* 2760: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2765: pointer.struct.stack_st_ASN1_INTEGER */
            	2770, 0,
            0, 32, 2, /* 2770: struct.stack_st_fake_ASN1_INTEGER */
            	2777, 8,
            	344, 24,
            8884099, 8, 2, /* 2777: pointer_to_array_of_pointers_to_stack */
            	2784, 0,
            	341, 20,
            0, 8, 1, /* 2784: pointer.ASN1_INTEGER */
            	2789, 0,
            0, 0, 1, /* 2789: ASN1_INTEGER */
            	2794, 0,
            0, 24, 1, /* 2794: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2799: pointer.struct.asn1_type_st */
            	2804, 0,
            0, 16, 1, /* 2804: struct.asn1_type_st */
            	2809, 8,
            0, 8, 20, /* 2809: union.unknown */
            	174, 0,
            	2760, 0,
            	2703, 0,
            	2852, 0,
            	2857, 0,
            	2862, 0,
            	2867, 0,
            	2872, 0,
            	2877, 0,
            	2726, 0,
            	2882, 0,
            	2887, 0,
            	2892, 0,
            	2897, 0,
            	2902, 0,
            	2907, 0,
            	2912, 0,
            	2760, 0,
            	2760, 0,
            	2917, 0,
            1, 8, 1, /* 2852: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2857: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2862: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2867: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2872: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2877: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2882: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2887: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2892: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2897: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2902: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2907: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2912: pointer.struct.asn1_string_st */
            	2731, 0,
            1, 8, 1, /* 2917: pointer.struct.ASN1_VALUE_st */
            	2922, 0,
            0, 0, 0, /* 2922: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2925: pointer.struct.stack_st_ASN1_OBJECT */
            	2930, 0,
            0, 32, 2, /* 2930: struct.stack_st_fake_ASN1_OBJECT */
            	2937, 8,
            	344, 24,
            8884099, 8, 2, /* 2937: pointer_to_array_of_pointers_to_stack */
            	2944, 0,
            	341, 20,
            0, 8, 1, /* 2944: pointer.ASN1_OBJECT */
            	2949, 0,
            0, 0, 1, /* 2949: ASN1_OBJECT */
            	2954, 0,
            0, 40, 3, /* 2954: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2963: pointer.struct.stack_st_X509_POLICY_DATA */
            	2968, 0,
            0, 32, 2, /* 2968: struct.stack_st_fake_X509_POLICY_DATA */
            	2975, 8,
            	344, 24,
            8884099, 8, 2, /* 2975: pointer_to_array_of_pointers_to_stack */
            	2982, 0,
            	341, 20,
            0, 8, 1, /* 2982: pointer.X509_POLICY_DATA */
            	2987, 0,
            0, 0, 1, /* 2987: X509_POLICY_DATA */
            	2992, 0,
            0, 32, 3, /* 2992: struct.X509_POLICY_DATA_st */
            	3001, 8,
            	3015, 16,
            	3039, 24,
            1, 8, 1, /* 3001: pointer.struct.asn1_object_st */
            	3006, 0,
            0, 40, 3, /* 3006: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 3015: pointer.struct.stack_st_POLICYQUALINFO */
            	3020, 0,
            0, 32, 2, /* 3020: struct.stack_st_fake_POLICYQUALINFO */
            	3027, 8,
            	344, 24,
            8884099, 8, 2, /* 3027: pointer_to_array_of_pointers_to_stack */
            	3034, 0,
            	341, 20,
            0, 8, 1, /* 3034: pointer.POLICYQUALINFO */
            	2691, 0,
            1, 8, 1, /* 3039: pointer.struct.stack_st_ASN1_OBJECT */
            	3044, 0,
            0, 32, 2, /* 3044: struct.stack_st_fake_ASN1_OBJECT */
            	3051, 8,
            	344, 24,
            8884099, 8, 2, /* 3051: pointer_to_array_of_pointers_to_stack */
            	3058, 0,
            	341, 20,
            0, 8, 1, /* 3058: pointer.ASN1_OBJECT */
            	2949, 0,
            1, 8, 1, /* 3063: pointer.struct.stack_st_DIST_POINT */
            	3068, 0,
            0, 32, 2, /* 3068: struct.stack_st_fake_DIST_POINT */
            	3075, 8,
            	344, 24,
            8884099, 8, 2, /* 3075: pointer_to_array_of_pointers_to_stack */
            	3082, 0,
            	341, 20,
            0, 8, 1, /* 3082: pointer.DIST_POINT */
            	3087, 0,
            0, 0, 1, /* 3087: DIST_POINT */
            	3092, 0,
            0, 32, 3, /* 3092: struct.DIST_POINT_st */
            	3101, 0,
            	3192, 8,
            	3120, 16,
            1, 8, 1, /* 3101: pointer.struct.DIST_POINT_NAME_st */
            	3106, 0,
            0, 24, 2, /* 3106: struct.DIST_POINT_NAME_st */
            	3113, 8,
            	3168, 16,
            0, 8, 2, /* 3113: union.unknown */
            	3120, 0,
            	3144, 0,
            1, 8, 1, /* 3120: pointer.struct.stack_st_GENERAL_NAME */
            	3125, 0,
            0, 32, 2, /* 3125: struct.stack_st_fake_GENERAL_NAME */
            	3132, 8,
            	344, 24,
            8884099, 8, 2, /* 3132: pointer_to_array_of_pointers_to_stack */
            	3139, 0,
            	341, 20,
            0, 8, 1, /* 3139: pointer.GENERAL_NAME */
            	2352, 0,
            1, 8, 1, /* 3144: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3149, 0,
            0, 32, 2, /* 3149: struct.stack_st_fake_X509_NAME_ENTRY */
            	3156, 8,
            	344, 24,
            8884099, 8, 2, /* 3156: pointer_to_array_of_pointers_to_stack */
            	3163, 0,
            	341, 20,
            0, 8, 1, /* 3163: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 3168: pointer.struct.X509_name_st */
            	3173, 0,
            0, 40, 3, /* 3173: struct.X509_name_st */
            	3144, 0,
            	3182, 16,
            	77, 24,
            1, 8, 1, /* 3182: pointer.struct.buf_mem_st */
            	3187, 0,
            0, 24, 1, /* 3187: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 3192: pointer.struct.asn1_string_st */
            	3197, 0,
            0, 24, 1, /* 3197: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 3202: pointer.struct.stack_st_GENERAL_NAME */
            	3207, 0,
            0, 32, 2, /* 3207: struct.stack_st_fake_GENERAL_NAME */
            	3214, 8,
            	344, 24,
            8884099, 8, 2, /* 3214: pointer_to_array_of_pointers_to_stack */
            	3221, 0,
            	341, 20,
            0, 8, 1, /* 3221: pointer.GENERAL_NAME */
            	2352, 0,
            1, 8, 1, /* 3226: pointer.struct.NAME_CONSTRAINTS_st */
            	3231, 0,
            0, 16, 2, /* 3231: struct.NAME_CONSTRAINTS_st */
            	3238, 0,
            	3238, 8,
            1, 8, 1, /* 3238: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3243, 0,
            0, 32, 2, /* 3243: struct.stack_st_fake_GENERAL_SUBTREE */
            	3250, 8,
            	344, 24,
            8884099, 8, 2, /* 3250: pointer_to_array_of_pointers_to_stack */
            	3257, 0,
            	341, 20,
            0, 8, 1, /* 3257: pointer.GENERAL_SUBTREE */
            	3262, 0,
            0, 0, 1, /* 3262: GENERAL_SUBTREE */
            	3267, 0,
            0, 24, 3, /* 3267: struct.GENERAL_SUBTREE_st */
            	3276, 0,
            	3408, 8,
            	3408, 16,
            1, 8, 1, /* 3276: pointer.struct.GENERAL_NAME_st */
            	3281, 0,
            0, 16, 1, /* 3281: struct.GENERAL_NAME_st */
            	3286, 8,
            0, 8, 15, /* 3286: union.unknown */
            	174, 0,
            	3319, 0,
            	3438, 0,
            	3438, 0,
            	3345, 0,
            	3478, 0,
            	3526, 0,
            	3438, 0,
            	3423, 0,
            	3331, 0,
            	3423, 0,
            	3478, 0,
            	3438, 0,
            	3331, 0,
            	3345, 0,
            1, 8, 1, /* 3319: pointer.struct.otherName_st */
            	3324, 0,
            0, 16, 2, /* 3324: struct.otherName_st */
            	3331, 0,
            	3345, 8,
            1, 8, 1, /* 3331: pointer.struct.asn1_object_st */
            	3336, 0,
            0, 40, 3, /* 3336: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 3345: pointer.struct.asn1_type_st */
            	3350, 0,
            0, 16, 1, /* 3350: struct.asn1_type_st */
            	3355, 8,
            0, 8, 20, /* 3355: union.unknown */
            	174, 0,
            	3398, 0,
            	3331, 0,
            	3408, 0,
            	3413, 0,
            	3418, 0,
            	3423, 0,
            	3428, 0,
            	3433, 0,
            	3438, 0,
            	3443, 0,
            	3448, 0,
            	3453, 0,
            	3458, 0,
            	3463, 0,
            	3468, 0,
            	3473, 0,
            	3398, 0,
            	3398, 0,
            	2917, 0,
            1, 8, 1, /* 3398: pointer.struct.asn1_string_st */
            	3403, 0,
            0, 24, 1, /* 3403: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 3408: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3413: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3418: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3423: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3428: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3433: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3438: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3443: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3448: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3453: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3458: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3463: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3468: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3473: pointer.struct.asn1_string_st */
            	3403, 0,
            1, 8, 1, /* 3478: pointer.struct.X509_name_st */
            	3483, 0,
            0, 40, 3, /* 3483: struct.X509_name_st */
            	3492, 0,
            	3516, 16,
            	77, 24,
            1, 8, 1, /* 3492: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3497, 0,
            0, 32, 2, /* 3497: struct.stack_st_fake_X509_NAME_ENTRY */
            	3504, 8,
            	344, 24,
            8884099, 8, 2, /* 3504: pointer_to_array_of_pointers_to_stack */
            	3511, 0,
            	341, 20,
            0, 8, 1, /* 3511: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 3516: pointer.struct.buf_mem_st */
            	3521, 0,
            0, 24, 1, /* 3521: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 3526: pointer.struct.EDIPartyName_st */
            	3531, 0,
            0, 16, 2, /* 3531: struct.EDIPartyName_st */
            	3398, 0,
            	3398, 8,
            1, 8, 1, /* 3538: pointer.struct.x509_cert_aux_st */
            	3543, 0,
            0, 40, 5, /* 3543: struct.x509_cert_aux_st */
            	3556, 0,
            	3556, 8,
            	3580, 16,
            	2299, 24,
            	3585, 32,
            1, 8, 1, /* 3556: pointer.struct.stack_st_ASN1_OBJECT */
            	3561, 0,
            0, 32, 2, /* 3561: struct.stack_st_fake_ASN1_OBJECT */
            	3568, 8,
            	344, 24,
            8884099, 8, 2, /* 3568: pointer_to_array_of_pointers_to_stack */
            	3575, 0,
            	341, 20,
            0, 8, 1, /* 3575: pointer.ASN1_OBJECT */
            	2949, 0,
            1, 8, 1, /* 3580: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 3585: pointer.struct.stack_st_X509_ALGOR */
            	3590, 0,
            0, 32, 2, /* 3590: struct.stack_st_fake_X509_ALGOR */
            	3597, 8,
            	344, 24,
            8884099, 8, 2, /* 3597: pointer_to_array_of_pointers_to_stack */
            	3604, 0,
            	341, 20,
            0, 8, 1, /* 3604: pointer.X509_ALGOR */
            	3609, 0,
            0, 0, 1, /* 3609: X509_ALGOR */
            	90, 0,
            1, 8, 1, /* 3614: pointer.struct.ISSUING_DIST_POINT_st */
            	3619, 0,
            0, 32, 2, /* 3619: struct.ISSUING_DIST_POINT_st */
            	3101, 0,
            	3192, 16,
            0, 80, 8, /* 3626: struct.X509_crl_info_st */
            	67, 0,
            	85, 8,
            	267, 16,
            	369, 24,
            	369, 32,
            	3645, 40,
            	2212, 48,
            	2272, 56,
            1, 8, 1, /* 3645: pointer.struct.stack_st_X509_REVOKED */
            	3650, 0,
            0, 32, 2, /* 3650: struct.stack_st_fake_X509_REVOKED */
            	3657, 8,
            	344, 24,
            8884099, 8, 2, /* 3657: pointer_to_array_of_pointers_to_stack */
            	3664, 0,
            	341, 20,
            0, 8, 1, /* 3664: pointer.X509_REVOKED */
            	3669, 0,
            0, 0, 1, /* 3669: X509_REVOKED */
            	3674, 0,
            0, 40, 4, /* 3674: struct.x509_revoked_st */
            	3685, 0,
            	3695, 8,
            	3700, 16,
            	3724, 24,
            1, 8, 1, /* 3685: pointer.struct.asn1_string_st */
            	3690, 0,
            0, 24, 1, /* 3690: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 3695: pointer.struct.asn1_string_st */
            	3690, 0,
            1, 8, 1, /* 3700: pointer.struct.stack_st_X509_EXTENSION */
            	3705, 0,
            0, 32, 2, /* 3705: struct.stack_st_fake_X509_EXTENSION */
            	3712, 8,
            	344, 24,
            8884099, 8, 2, /* 3712: pointer_to_array_of_pointers_to_stack */
            	3719, 0,
            	341, 20,
            0, 8, 1, /* 3719: pointer.X509_EXTENSION */
            	2236, 0,
            1, 8, 1, /* 3724: pointer.struct.stack_st_GENERAL_NAME */
            	3729, 0,
            0, 32, 2, /* 3729: struct.stack_st_fake_GENERAL_NAME */
            	3736, 8,
            	344, 24,
            8884099, 8, 2, /* 3736: pointer_to_array_of_pointers_to_stack */
            	3743, 0,
            	341, 20,
            0, 8, 1, /* 3743: pointer.GENERAL_NAME */
            	2352, 0,
            0, 120, 10, /* 3748: struct.X509_crl_st */
            	3771, 0,
            	85, 8,
            	2207, 16,
            	2304, 32,
            	3614, 40,
            	67, 56,
            	67, 64,
            	3776, 96,
            	3817, 104,
            	1079, 112,
            1, 8, 1, /* 3771: pointer.struct.X509_crl_info_st */
            	3626, 0,
            1, 8, 1, /* 3776: pointer.struct.stack_st_GENERAL_NAMES */
            	3781, 0,
            0, 32, 2, /* 3781: struct.stack_st_fake_GENERAL_NAMES */
            	3788, 8,
            	344, 24,
            8884099, 8, 2, /* 3788: pointer_to_array_of_pointers_to_stack */
            	3795, 0,
            	341, 20,
            0, 8, 1, /* 3795: pointer.GENERAL_NAMES */
            	3800, 0,
            0, 0, 1, /* 3800: GENERAL_NAMES */
            	3805, 0,
            0, 32, 1, /* 3805: struct.stack_st_GENERAL_NAME */
            	3810, 0,
            0, 32, 2, /* 3810: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 3817: pointer.struct.x509_crl_method_st */
            	3822, 0,
            0, 40, 4, /* 3822: struct.x509_crl_method_st */
            	3833, 8,
            	3833, 16,
            	3836, 24,
            	3839, 32,
            8884097, 8, 0, /* 3833: pointer.func */
            8884097, 8, 0, /* 3836: pointer.func */
            8884097, 8, 0, /* 3839: pointer.func */
            1, 8, 1, /* 3842: pointer.struct.X509_crl_st */
            	3748, 0,
            1, 8, 1, /* 3847: pointer.struct.stack_st_X509_POLICY_DATA */
            	3852, 0,
            0, 32, 2, /* 3852: struct.stack_st_fake_X509_POLICY_DATA */
            	3859, 8,
            	344, 24,
            8884099, 8, 2, /* 3859: pointer_to_array_of_pointers_to_stack */
            	3866, 0,
            	341, 20,
            0, 8, 1, /* 3866: pointer.X509_POLICY_DATA */
            	2987, 0,
            1, 8, 1, /* 3871: pointer.struct.asn1_object_st */
            	3876, 0,
            0, 40, 3, /* 3876: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            0, 24, 2, /* 3885: struct.X509_POLICY_NODE_st */
            	3892, 0,
            	3954, 8,
            1, 8, 1, /* 3892: pointer.struct.X509_POLICY_DATA_st */
            	3897, 0,
            0, 32, 3, /* 3897: struct.X509_POLICY_DATA_st */
            	3871, 8,
            	3906, 16,
            	3930, 24,
            1, 8, 1, /* 3906: pointer.struct.stack_st_POLICYQUALINFO */
            	3911, 0,
            0, 32, 2, /* 3911: struct.stack_st_fake_POLICYQUALINFO */
            	3918, 8,
            	344, 24,
            8884099, 8, 2, /* 3918: pointer_to_array_of_pointers_to_stack */
            	3925, 0,
            	341, 20,
            0, 8, 1, /* 3925: pointer.POLICYQUALINFO */
            	2691, 0,
            1, 8, 1, /* 3930: pointer.struct.stack_st_ASN1_OBJECT */
            	3935, 0,
            0, 32, 2, /* 3935: struct.stack_st_fake_ASN1_OBJECT */
            	3942, 8,
            	344, 24,
            8884099, 8, 2, /* 3942: pointer_to_array_of_pointers_to_stack */
            	3949, 0,
            	341, 20,
            0, 8, 1, /* 3949: pointer.ASN1_OBJECT */
            	2949, 0,
            1, 8, 1, /* 3954: pointer.struct.X509_POLICY_NODE_st */
            	3885, 0,
            0, 0, 1, /* 3959: X509_POLICY_NODE */
            	3964, 0,
            0, 24, 2, /* 3964: struct.X509_POLICY_NODE_st */
            	3971, 0,
            	3976, 8,
            1, 8, 1, /* 3971: pointer.struct.X509_POLICY_DATA_st */
            	2992, 0,
            1, 8, 1, /* 3976: pointer.struct.X509_POLICY_NODE_st */
            	3964, 0,
            1, 8, 1, /* 3981: pointer.struct.asn1_string_st */
            	3986, 0,
            0, 24, 1, /* 3986: struct.asn1_string_st */
            	77, 8,
            0, 40, 5, /* 3991: struct.x509_cert_aux_st */
            	3930, 0,
            	3930, 8,
            	3981, 16,
            	4004, 24,
            	4009, 32,
            1, 8, 1, /* 4004: pointer.struct.asn1_string_st */
            	3986, 0,
            1, 8, 1, /* 4009: pointer.struct.stack_st_X509_ALGOR */
            	4014, 0,
            0, 32, 2, /* 4014: struct.stack_st_fake_X509_ALGOR */
            	4021, 8,
            	344, 24,
            8884099, 8, 2, /* 4021: pointer_to_array_of_pointers_to_stack */
            	4028, 0,
            	341, 20,
            0, 8, 1, /* 4028: pointer.X509_ALGOR */
            	3609, 0,
            1, 8, 1, /* 4033: pointer.struct.x509_cert_aux_st */
            	3991, 0,
            1, 8, 1, /* 4038: pointer.struct.stack_st_GENERAL_NAME */
            	4043, 0,
            0, 32, 2, /* 4043: struct.stack_st_fake_GENERAL_NAME */
            	4050, 8,
            	344, 24,
            8884099, 8, 2, /* 4050: pointer_to_array_of_pointers_to_stack */
            	4057, 0,
            	341, 20,
            0, 8, 1, /* 4057: pointer.GENERAL_NAME */
            	2352, 0,
            1, 8, 1, /* 4062: pointer.struct.stack_st_DIST_POINT */
            	4067, 0,
            0, 32, 2, /* 4067: struct.stack_st_fake_DIST_POINT */
            	4074, 8,
            	344, 24,
            8884099, 8, 2, /* 4074: pointer_to_array_of_pointers_to_stack */
            	4081, 0,
            	341, 20,
            0, 8, 1, /* 4081: pointer.DIST_POINT */
            	3087, 0,
            1, 8, 1, /* 4086: pointer.struct.stack_st_X509_EXTENSION */
            	4091, 0,
            0, 32, 2, /* 4091: struct.stack_st_fake_X509_EXTENSION */
            	4098, 8,
            	344, 24,
            8884099, 8, 2, /* 4098: pointer_to_array_of_pointers_to_stack */
            	4105, 0,
            	341, 20,
            0, 8, 1, /* 4105: pointer.X509_EXTENSION */
            	2236, 0,
            1, 8, 1, /* 4110: pointer.struct.X509_pubkey_st */
            	379, 0,
            1, 8, 1, /* 4115: pointer.struct.X509_val_st */
            	4120, 0,
            0, 16, 2, /* 4120: struct.X509_val_st */
            	4127, 0,
            	4127, 8,
            1, 8, 1, /* 4127: pointer.struct.asn1_string_st */
            	3986, 0,
            1, 8, 1, /* 4132: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4137, 0,
            0, 32, 2, /* 4137: struct.stack_st_fake_X509_NAME_ENTRY */
            	4144, 8,
            	344, 24,
            8884099, 8, 2, /* 4144: pointer_to_array_of_pointers_to_stack */
            	4151, 0,
            	341, 20,
            0, 8, 1, /* 4151: pointer.X509_NAME_ENTRY */
            	305, 0,
            0, 184, 12, /* 4156: struct.x509_st */
            	4183, 0,
            	4218, 8,
            	4247, 16,
            	174, 32,
            	4257, 40,
            	4004, 104,
            	4279, 112,
            	4284, 120,
            	4062, 128,
            	4038, 136,
            	4289, 144,
            	4033, 176,
            1, 8, 1, /* 4183: pointer.struct.x509_cinf_st */
            	4188, 0,
            0, 104, 11, /* 4188: struct.x509_cinf_st */
            	4213, 0,
            	4213, 8,
            	4218, 16,
            	4223, 24,
            	4115, 32,
            	4223, 40,
            	4110, 48,
            	4247, 56,
            	4247, 64,
            	4086, 72,
            	4252, 80,
            1, 8, 1, /* 4213: pointer.struct.asn1_string_st */
            	3986, 0,
            1, 8, 1, /* 4218: pointer.struct.X509_algor_st */
            	90, 0,
            1, 8, 1, /* 4223: pointer.struct.X509_name_st */
            	4228, 0,
            0, 40, 3, /* 4228: struct.X509_name_st */
            	4132, 0,
            	4237, 16,
            	77, 24,
            1, 8, 1, /* 4237: pointer.struct.buf_mem_st */
            	4242, 0,
            0, 24, 1, /* 4242: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 4247: pointer.struct.asn1_string_st */
            	3986, 0,
            0, 24, 1, /* 4252: struct.ASN1_ENCODING_st */
            	77, 0,
            0, 16, 1, /* 4257: struct.crypto_ex_data_st */
            	4262, 0,
            1, 8, 1, /* 4262: pointer.struct.stack_st_void */
            	4267, 0,
            0, 32, 1, /* 4267: struct.stack_st_void */
            	4272, 0,
            0, 32, 2, /* 4272: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 4279: pointer.struct.AUTHORITY_KEYID_st */
            	2309, 0,
            1, 8, 1, /* 4284: pointer.struct.X509_POLICY_CACHE_st */
            	2632, 0,
            1, 8, 1, /* 4289: pointer.struct.NAME_CONSTRAINTS_st */
            	3231, 0,
            1, 8, 1, /* 4294: pointer.struct.x509_st */
            	4156, 0,
            0, 32, 3, /* 4299: struct.X509_POLICY_LEVEL_st */
            	4294, 0,
            	4308, 8,
            	3954, 16,
            1, 8, 1, /* 4308: pointer.struct.stack_st_X509_POLICY_NODE */
            	4313, 0,
            0, 32, 2, /* 4313: struct.stack_st_fake_X509_POLICY_NODE */
            	4320, 8,
            	344, 24,
            8884099, 8, 2, /* 4320: pointer_to_array_of_pointers_to_stack */
            	4327, 0,
            	341, 20,
            0, 8, 1, /* 4327: pointer.X509_POLICY_NODE */
            	3959, 0,
            1, 8, 1, /* 4332: pointer.struct.X509_POLICY_LEVEL_st */
            	4299, 0,
            0, 48, 4, /* 4337: struct.X509_POLICY_TREE_st */
            	4332, 0,
            	3847, 16,
            	4308, 24,
            	4308, 32,
            0, 24, 1, /* 4348: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 4353: pointer.struct.buf_mem_st */
            	4358, 0,
            0, 24, 1, /* 4358: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 4363: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4368, 0,
            0, 32, 2, /* 4368: struct.stack_st_fake_X509_NAME_ENTRY */
            	4375, 8,
            	344, 24,
            8884099, 8, 2, /* 4375: pointer_to_array_of_pointers_to_stack */
            	4382, 0,
            	341, 20,
            0, 8, 1, /* 4382: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 4387: pointer.struct.X509_crl_info_st */
            	4392, 0,
            0, 80, 8, /* 4392: struct.X509_crl_info_st */
            	4411, 0,
            	4416, 8,
            	4421, 16,
            	4435, 24,
            	4435, 32,
            	4440, 40,
            	4464, 48,
            	4348, 56,
            1, 8, 1, /* 4411: pointer.struct.asn1_string_st */
            	2794, 0,
            1, 8, 1, /* 4416: pointer.struct.X509_algor_st */
            	90, 0,
            1, 8, 1, /* 4421: pointer.struct.X509_name_st */
            	4426, 0,
            0, 40, 3, /* 4426: struct.X509_name_st */
            	4363, 0,
            	4353, 16,
            	77, 24,
            1, 8, 1, /* 4435: pointer.struct.asn1_string_st */
            	2794, 0,
            1, 8, 1, /* 4440: pointer.struct.stack_st_X509_REVOKED */
            	4445, 0,
            0, 32, 2, /* 4445: struct.stack_st_fake_X509_REVOKED */
            	4452, 8,
            	344, 24,
            8884099, 8, 2, /* 4452: pointer_to_array_of_pointers_to_stack */
            	4459, 0,
            	341, 20,
            0, 8, 1, /* 4459: pointer.X509_REVOKED */
            	3669, 0,
            1, 8, 1, /* 4464: pointer.struct.stack_st_X509_EXTENSION */
            	4469, 0,
            0, 32, 2, /* 4469: struct.stack_st_fake_X509_EXTENSION */
            	4476, 8,
            	344, 24,
            8884099, 8, 2, /* 4476: pointer_to_array_of_pointers_to_stack */
            	4483, 0,
            	341, 20,
            0, 8, 1, /* 4483: pointer.X509_EXTENSION */
            	2236, 0,
            0, 120, 10, /* 4488: struct.X509_crl_st */
            	4387, 0,
            	4416, 8,
            	4511, 16,
            	4516, 32,
            	4521, 40,
            	4411, 56,
            	4411, 64,
            	3776, 96,
            	3817, 104,
            	1079, 112,
            1, 8, 1, /* 4511: pointer.struct.asn1_string_st */
            	2794, 0,
            1, 8, 1, /* 4516: pointer.struct.AUTHORITY_KEYID_st */
            	2309, 0,
            1, 8, 1, /* 4521: pointer.struct.ISSUING_DIST_POINT_st */
            	3619, 0,
            0, 0, 1, /* 4526: X509_CRL */
            	4488, 0,
            1, 8, 1, /* 4531: pointer.struct.asn1_string_st */
            	4536, 0,
            0, 24, 1, /* 4536: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 4541: pointer.struct.stack_st_ASN1_OBJECT */
            	4546, 0,
            0, 32, 2, /* 4546: struct.stack_st_fake_ASN1_OBJECT */
            	4553, 8,
            	344, 24,
            8884099, 8, 2, /* 4553: pointer_to_array_of_pointers_to_stack */
            	4560, 0,
            	341, 20,
            0, 8, 1, /* 4560: pointer.ASN1_OBJECT */
            	2949, 0,
            1, 8, 1, /* 4565: pointer.struct.x509_cert_aux_st */
            	4570, 0,
            0, 40, 5, /* 4570: struct.x509_cert_aux_st */
            	4541, 0,
            	4541, 8,
            	4531, 16,
            	4583, 24,
            	4588, 32,
            1, 8, 1, /* 4583: pointer.struct.asn1_string_st */
            	4536, 0,
            1, 8, 1, /* 4588: pointer.struct.stack_st_X509_ALGOR */
            	4593, 0,
            0, 32, 2, /* 4593: struct.stack_st_fake_X509_ALGOR */
            	4600, 8,
            	344, 24,
            8884099, 8, 2, /* 4600: pointer_to_array_of_pointers_to_stack */
            	4607, 0,
            	341, 20,
            0, 8, 1, /* 4607: pointer.X509_ALGOR */
            	3609, 0,
            1, 8, 1, /* 4612: pointer.struct.stack_st_DIST_POINT */
            	4617, 0,
            0, 32, 2, /* 4617: struct.stack_st_fake_DIST_POINT */
            	4624, 8,
            	344, 24,
            8884099, 8, 2, /* 4624: pointer_to_array_of_pointers_to_stack */
            	4631, 0,
            	341, 20,
            0, 8, 1, /* 4631: pointer.DIST_POINT */
            	3087, 0,
            1, 8, 1, /* 4636: pointer.struct.AUTHORITY_KEYID_st */
            	2309, 0,
            1, 8, 1, /* 4641: pointer.struct.stack_st_X509_EXTENSION */
            	4646, 0,
            0, 32, 2, /* 4646: struct.stack_st_fake_X509_EXTENSION */
            	4653, 8,
            	344, 24,
            8884099, 8, 2, /* 4653: pointer_to_array_of_pointers_to_stack */
            	4660, 0,
            	341, 20,
            0, 8, 1, /* 4660: pointer.X509_EXTENSION */
            	2236, 0,
            1, 8, 1, /* 4665: pointer.struct.asn1_string_st */
            	4536, 0,
            1, 8, 1, /* 4670: pointer.struct.X509_val_st */
            	4675, 0,
            0, 16, 2, /* 4675: struct.X509_val_st */
            	4665, 0,
            	4665, 8,
            1, 8, 1, /* 4682: pointer.struct.X509_algor_st */
            	90, 0,
            1, 8, 1, /* 4687: pointer.struct.x509_cinf_st */
            	4692, 0,
            0, 104, 11, /* 4692: struct.x509_cinf_st */
            	4717, 0,
            	4717, 8,
            	4682, 16,
            	4722, 24,
            	4670, 32,
            	4722, 40,
            	4770, 48,
            	4775, 56,
            	4775, 64,
            	4641, 72,
            	4780, 80,
            1, 8, 1, /* 4717: pointer.struct.asn1_string_st */
            	4536, 0,
            1, 8, 1, /* 4722: pointer.struct.X509_name_st */
            	4727, 0,
            0, 40, 3, /* 4727: struct.X509_name_st */
            	4736, 0,
            	4760, 16,
            	77, 24,
            1, 8, 1, /* 4736: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4741, 0,
            0, 32, 2, /* 4741: struct.stack_st_fake_X509_NAME_ENTRY */
            	4748, 8,
            	344, 24,
            8884099, 8, 2, /* 4748: pointer_to_array_of_pointers_to_stack */
            	4755, 0,
            	341, 20,
            0, 8, 1, /* 4755: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 4760: pointer.struct.buf_mem_st */
            	4765, 0,
            0, 24, 1, /* 4765: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 4770: pointer.struct.X509_pubkey_st */
            	379, 0,
            1, 8, 1, /* 4775: pointer.struct.asn1_string_st */
            	4536, 0,
            0, 24, 1, /* 4780: struct.ASN1_ENCODING_st */
            	77, 0,
            0, 184, 12, /* 4785: struct.x509_st */
            	4687, 0,
            	4682, 8,
            	4775, 16,
            	174, 32,
            	1153, 40,
            	4583, 104,
            	4636, 112,
            	4812, 120,
            	4612, 128,
            	3724, 136,
            	4817, 144,
            	4565, 176,
            1, 8, 1, /* 4812: pointer.struct.X509_POLICY_CACHE_st */
            	2632, 0,
            1, 8, 1, /* 4817: pointer.struct.NAME_CONSTRAINTS_st */
            	3231, 0,
            0, 0, 1, /* 4822: X509 */
            	4785, 0,
            1, 8, 1, /* 4827: pointer.struct.stack_st_X509 */
            	4832, 0,
            0, 32, 2, /* 4832: struct.stack_st_fake_X509 */
            	4839, 8,
            	344, 24,
            8884099, 8, 2, /* 4839: pointer_to_array_of_pointers_to_stack */
            	4846, 0,
            	341, 20,
            0, 8, 1, /* 4846: pointer.X509 */
            	4822, 0,
            8884097, 8, 0, /* 4851: pointer.func */
            8884097, 8, 0, /* 4854: pointer.func */
            8884097, 8, 0, /* 4857: pointer.func */
            8884097, 8, 0, /* 4860: pointer.func */
            8884097, 8, 0, /* 4863: pointer.func */
            8884097, 8, 0, /* 4866: pointer.func */
            8884097, 8, 0, /* 4869: pointer.func */
            8884097, 8, 0, /* 4872: pointer.func */
            8884097, 8, 0, /* 4875: pointer.func */
            8884097, 8, 0, /* 4878: pointer.func */
            8884097, 8, 0, /* 4881: pointer.func */
            8884097, 8, 0, /* 4884: pointer.func */
            8884097, 8, 0, /* 4887: pointer.func */
            1, 8, 1, /* 4890: pointer.struct.stack_st_X509_LOOKUP */
            	4895, 0,
            0, 32, 2, /* 4895: struct.stack_st_fake_X509_LOOKUP */
            	4902, 8,
            	344, 24,
            8884099, 8, 2, /* 4902: pointer_to_array_of_pointers_to_stack */
            	4909, 0,
            	341, 20,
            0, 8, 1, /* 4909: pointer.X509_LOOKUP */
            	4914, 0,
            0, 0, 1, /* 4914: X509_LOOKUP */
            	4919, 0,
            0, 32, 3, /* 4919: struct.x509_lookup_st */
            	4928, 8,
            	174, 16,
            	4977, 24,
            1, 8, 1, /* 4928: pointer.struct.x509_lookup_method_st */
            	4933, 0,
            0, 80, 10, /* 4933: struct.x509_lookup_method_st */
            	111, 0,
            	4956, 8,
            	4959, 16,
            	4956, 24,
            	4956, 32,
            	4962, 40,
            	4965, 48,
            	4968, 56,
            	4971, 64,
            	4974, 72,
            8884097, 8, 0, /* 4956: pointer.func */
            8884097, 8, 0, /* 4959: pointer.func */
            8884097, 8, 0, /* 4962: pointer.func */
            8884097, 8, 0, /* 4965: pointer.func */
            8884097, 8, 0, /* 4968: pointer.func */
            8884097, 8, 0, /* 4971: pointer.func */
            8884097, 8, 0, /* 4974: pointer.func */
            1, 8, 1, /* 4977: pointer.struct.x509_store_st */
            	4982, 0,
            0, 144, 15, /* 4982: struct.x509_store_st */
            	5015, 8,
            	4890, 16,
            	5546, 24,
            	4887, 32,
            	5558, 40,
            	5561, 48,
            	4884, 56,
            	4887, 64,
            	5564, 72,
            	4881, 80,
            	5567, 88,
            	4878, 96,
            	4875, 104,
            	4887, 112,
            	5241, 120,
            1, 8, 1, /* 5015: pointer.struct.stack_st_X509_OBJECT */
            	5020, 0,
            0, 32, 2, /* 5020: struct.stack_st_fake_X509_OBJECT */
            	5027, 8,
            	344, 24,
            8884099, 8, 2, /* 5027: pointer_to_array_of_pointers_to_stack */
            	5034, 0,
            	341, 20,
            0, 8, 1, /* 5034: pointer.X509_OBJECT */
            	5039, 0,
            0, 0, 1, /* 5039: X509_OBJECT */
            	5044, 0,
            0, 16, 1, /* 5044: struct.x509_object_st */
            	5049, 8,
            0, 8, 4, /* 5049: union.unknown */
            	174, 0,
            	5060, 0,
            	5392, 0,
            	5468, 0,
            1, 8, 1, /* 5060: pointer.struct.x509_st */
            	5065, 0,
            0, 184, 12, /* 5065: struct.x509_st */
            	5092, 0,
            	5132, 8,
            	5207, 16,
            	174, 32,
            	5241, 40,
            	5263, 104,
            	4516, 112,
            	2627, 120,
            	5268, 128,
            	5292, 136,
            	5316, 144,
            	5321, 176,
            1, 8, 1, /* 5092: pointer.struct.x509_cinf_st */
            	5097, 0,
            0, 104, 11, /* 5097: struct.x509_cinf_st */
            	5122, 0,
            	5122, 8,
            	5132, 16,
            	5137, 24,
            	5185, 32,
            	5137, 40,
            	5202, 48,
            	5207, 56,
            	5207, 64,
            	5212, 72,
            	5236, 80,
            1, 8, 1, /* 5122: pointer.struct.asn1_string_st */
            	5127, 0,
            0, 24, 1, /* 5127: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 5132: pointer.struct.X509_algor_st */
            	90, 0,
            1, 8, 1, /* 5137: pointer.struct.X509_name_st */
            	5142, 0,
            0, 40, 3, /* 5142: struct.X509_name_st */
            	5151, 0,
            	5175, 16,
            	77, 24,
            1, 8, 1, /* 5151: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5156, 0,
            0, 32, 2, /* 5156: struct.stack_st_fake_X509_NAME_ENTRY */
            	5163, 8,
            	344, 24,
            8884099, 8, 2, /* 5163: pointer_to_array_of_pointers_to_stack */
            	5170, 0,
            	341, 20,
            0, 8, 1, /* 5170: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 5175: pointer.struct.buf_mem_st */
            	5180, 0,
            0, 24, 1, /* 5180: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 5185: pointer.struct.X509_val_st */
            	5190, 0,
            0, 16, 2, /* 5190: struct.X509_val_st */
            	5197, 0,
            	5197, 8,
            1, 8, 1, /* 5197: pointer.struct.asn1_string_st */
            	5127, 0,
            1, 8, 1, /* 5202: pointer.struct.X509_pubkey_st */
            	379, 0,
            1, 8, 1, /* 5207: pointer.struct.asn1_string_st */
            	5127, 0,
            1, 8, 1, /* 5212: pointer.struct.stack_st_X509_EXTENSION */
            	5217, 0,
            0, 32, 2, /* 5217: struct.stack_st_fake_X509_EXTENSION */
            	5224, 8,
            	344, 24,
            8884099, 8, 2, /* 5224: pointer_to_array_of_pointers_to_stack */
            	5231, 0,
            	341, 20,
            0, 8, 1, /* 5231: pointer.X509_EXTENSION */
            	2236, 0,
            0, 24, 1, /* 5236: struct.ASN1_ENCODING_st */
            	77, 0,
            0, 16, 1, /* 5241: struct.crypto_ex_data_st */
            	5246, 0,
            1, 8, 1, /* 5246: pointer.struct.stack_st_void */
            	5251, 0,
            0, 32, 1, /* 5251: struct.stack_st_void */
            	5256, 0,
            0, 32, 2, /* 5256: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 5263: pointer.struct.asn1_string_st */
            	5127, 0,
            1, 8, 1, /* 5268: pointer.struct.stack_st_DIST_POINT */
            	5273, 0,
            0, 32, 2, /* 5273: struct.stack_st_fake_DIST_POINT */
            	5280, 8,
            	344, 24,
            8884099, 8, 2, /* 5280: pointer_to_array_of_pointers_to_stack */
            	5287, 0,
            	341, 20,
            0, 8, 1, /* 5287: pointer.DIST_POINT */
            	3087, 0,
            1, 8, 1, /* 5292: pointer.struct.stack_st_GENERAL_NAME */
            	5297, 0,
            0, 32, 2, /* 5297: struct.stack_st_fake_GENERAL_NAME */
            	5304, 8,
            	344, 24,
            8884099, 8, 2, /* 5304: pointer_to_array_of_pointers_to_stack */
            	5311, 0,
            	341, 20,
            0, 8, 1, /* 5311: pointer.GENERAL_NAME */
            	2352, 0,
            1, 8, 1, /* 5316: pointer.struct.NAME_CONSTRAINTS_st */
            	3231, 0,
            1, 8, 1, /* 5321: pointer.struct.x509_cert_aux_st */
            	5326, 0,
            0, 40, 5, /* 5326: struct.x509_cert_aux_st */
            	5339, 0,
            	5339, 8,
            	5363, 16,
            	5263, 24,
            	5368, 32,
            1, 8, 1, /* 5339: pointer.struct.stack_st_ASN1_OBJECT */
            	5344, 0,
            0, 32, 2, /* 5344: struct.stack_st_fake_ASN1_OBJECT */
            	5351, 8,
            	344, 24,
            8884099, 8, 2, /* 5351: pointer_to_array_of_pointers_to_stack */
            	5358, 0,
            	341, 20,
            0, 8, 1, /* 5358: pointer.ASN1_OBJECT */
            	2949, 0,
            1, 8, 1, /* 5363: pointer.struct.asn1_string_st */
            	5127, 0,
            1, 8, 1, /* 5368: pointer.struct.stack_st_X509_ALGOR */
            	5373, 0,
            0, 32, 2, /* 5373: struct.stack_st_fake_X509_ALGOR */
            	5380, 8,
            	344, 24,
            8884099, 8, 2, /* 5380: pointer_to_array_of_pointers_to_stack */
            	5387, 0,
            	341, 20,
            0, 8, 1, /* 5387: pointer.X509_ALGOR */
            	3609, 0,
            1, 8, 1, /* 5392: pointer.struct.X509_crl_st */
            	5397, 0,
            0, 120, 10, /* 5397: struct.X509_crl_st */
            	5420, 0,
            	5132, 8,
            	5207, 16,
            	4516, 32,
            	4521, 40,
            	5122, 56,
            	5122, 64,
            	3776, 96,
            	3817, 104,
            	1079, 112,
            1, 8, 1, /* 5420: pointer.struct.X509_crl_info_st */
            	5425, 0,
            0, 80, 8, /* 5425: struct.X509_crl_info_st */
            	5122, 0,
            	5132, 8,
            	5137, 16,
            	5197, 24,
            	5197, 32,
            	5444, 40,
            	5212, 48,
            	5236, 56,
            1, 8, 1, /* 5444: pointer.struct.stack_st_X509_REVOKED */
            	5449, 0,
            0, 32, 2, /* 5449: struct.stack_st_fake_X509_REVOKED */
            	5456, 8,
            	344, 24,
            8884099, 8, 2, /* 5456: pointer_to_array_of_pointers_to_stack */
            	5463, 0,
            	341, 20,
            0, 8, 1, /* 5463: pointer.X509_REVOKED */
            	3669, 0,
            1, 8, 1, /* 5468: pointer.struct.evp_pkey_st */
            	5473, 0,
            0, 56, 4, /* 5473: struct.evp_pkey_st */
            	5484, 16,
            	983, 24,
            	5489, 32,
            	5522, 48,
            1, 8, 1, /* 5484: pointer.struct.evp_pkey_asn1_method_st */
            	424, 0,
            0, 8, 5, /* 5489: union.unknown */
            	174, 0,
            	5502, 0,
            	5507, 0,
            	5512, 0,
            	5517, 0,
            1, 8, 1, /* 5502: pointer.struct.rsa_st */
            	891, 0,
            1, 8, 1, /* 5507: pointer.struct.dsa_st */
            	1104, 0,
            1, 8, 1, /* 5512: pointer.struct.dh_st */
            	1231, 0,
            1, 8, 1, /* 5517: pointer.struct.ec_key_st */
            	1345, 0,
            1, 8, 1, /* 5522: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5527, 0,
            0, 32, 2, /* 5527: struct.stack_st_fake_X509_ATTRIBUTE */
            	5534, 8,
            	344, 24,
            8884099, 8, 2, /* 5534: pointer_to_array_of_pointers_to_stack */
            	5541, 0,
            	341, 20,
            0, 8, 1, /* 5541: pointer.X509_ATTRIBUTE */
            	1852, 0,
            1, 8, 1, /* 5546: pointer.struct.X509_VERIFY_PARAM_st */
            	5551, 0,
            0, 56, 2, /* 5551: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	5339, 48,
            8884097, 8, 0, /* 5558: pointer.func */
            8884097, 8, 0, /* 5561: pointer.func */
            8884097, 8, 0, /* 5564: pointer.func */
            8884097, 8, 0, /* 5567: pointer.func */
            1, 8, 1, /* 5570: pointer.struct.stack_st_X509_LOOKUP */
            	5575, 0,
            0, 32, 2, /* 5575: struct.stack_st_fake_X509_LOOKUP */
            	5582, 8,
            	344, 24,
            8884099, 8, 2, /* 5582: pointer_to_array_of_pointers_to_stack */
            	5589, 0,
            	341, 20,
            0, 8, 1, /* 5589: pointer.X509_LOOKUP */
            	4914, 0,
            0, 248, 25, /* 5594: struct.x509_store_ctx_st */
            	5647, 0,
            	5, 16,
            	4827, 24,
            	5724, 32,
            	5709, 40,
            	1079, 48,
            	4872, 56,
            	4869, 64,
            	4866, 72,
            	4863, 80,
            	4872, 88,
            	5721, 96,
            	4860, 104,
            	4857, 112,
            	4872, 120,
            	4854, 128,
            	4851, 136,
            	4872, 144,
            	4827, 160,
            	5748, 168,
            	5, 192,
            	5, 200,
            	3842, 208,
            	5753, 224,
            	2277, 232,
            1, 8, 1, /* 5647: pointer.struct.x509_store_st */
            	5652, 0,
            0, 144, 15, /* 5652: struct.x509_store_st */
            	5685, 8,
            	5570, 16,
            	5709, 24,
            	4872, 32,
            	4869, 40,
            	4866, 48,
            	4863, 56,
            	4872, 64,
            	5721, 72,
            	4860, 80,
            	4857, 88,
            	4854, 96,
            	4851, 104,
            	4872, 112,
            	2277, 120,
            1, 8, 1, /* 5685: pointer.struct.stack_st_X509_OBJECT */
            	5690, 0,
            0, 32, 2, /* 5690: struct.stack_st_fake_X509_OBJECT */
            	5697, 8,
            	344, 24,
            8884099, 8, 2, /* 5697: pointer_to_array_of_pointers_to_stack */
            	5704, 0,
            	341, 20,
            0, 8, 1, /* 5704: pointer.X509_OBJECT */
            	5039, 0,
            1, 8, 1, /* 5709: pointer.struct.X509_VERIFY_PARAM_st */
            	5714, 0,
            0, 56, 2, /* 5714: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	3556, 48,
            8884097, 8, 0, /* 5721: pointer.func */
            1, 8, 1, /* 5724: pointer.struct.stack_st_X509_CRL */
            	5729, 0,
            0, 32, 2, /* 5729: struct.stack_st_fake_X509_CRL */
            	5736, 8,
            	344, 24,
            8884099, 8, 2, /* 5736: pointer_to_array_of_pointers_to_stack */
            	5743, 0,
            	341, 20,
            0, 8, 1, /* 5743: pointer.X509_CRL */
            	4526, 0,
            1, 8, 1, /* 5748: pointer.struct.X509_POLICY_TREE_st */
            	4337, 0,
            1, 8, 1, /* 5753: pointer.struct.x509_store_ctx_st */
            	5594, 0,
            0, 1, 0, /* 5758: char */
        },
        .arg_entity_index = { 0, 5753, 5, },
        .ret_entity_index = 341,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 ** new_arg_a = *((X509 ** *)new_args->args[0]);

    X509_STORE_CTX * new_arg_b = *((X509_STORE_CTX * *)new_args->args[1]);

    X509 * new_arg_c = *((X509 * *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_STORE_CTX_get1_issuer)(X509 **,X509_STORE_CTX *,X509 *);
    orig_X509_STORE_CTX_get1_issuer = dlsym(RTLD_NEXT, "X509_STORE_CTX_get1_issuer");
    *new_ret_ptr = (*orig_X509_STORE_CTX_get1_issuer)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

