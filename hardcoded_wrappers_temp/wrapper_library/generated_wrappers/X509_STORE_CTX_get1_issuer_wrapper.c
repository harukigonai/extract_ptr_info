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
            	2253, 16,
            	174, 32,
            	2323, 40,
            	2345, 104,
            	2350, 112,
            	2673, 120,
            	3104, 128,
            	3243, 136,
            	3267, 144,
            	3579, 176,
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
            	2253, 56,
            	2253, 64,
            	2258, 72,
            	2318, 80,
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
            	1882, 48,
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
            	1108, 0,
            	1247, 0,
            	1373, 0,
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
            	1008, 96,
            	1030, 120,
            	1030, 128,
            	1030, 136,
            	174, 144,
            	1044, 152,
            	1044, 160,
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
            8884099, 8, 2, /* 998: pointer_to_array_of_pointers_to_stack */
            	1005, 0,
            	341, 12,
            0, 4, 0, /* 1005: unsigned int */
            0, 16, 1, /* 1008: struct.crypto_ex_data_st */
            	1013, 0,
            1, 8, 1, /* 1013: pointer.struct.stack_st_void */
            	1018, 0,
            0, 32, 1, /* 1018: struct.stack_st_void */
            	1023, 0,
            0, 32, 2, /* 1023: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 1030: pointer.struct.bn_mont_ctx_st */
            	1035, 0,
            0, 96, 3, /* 1035: struct.bn_mont_ctx_st */
            	993, 8,
            	993, 32,
            	993, 56,
            1, 8, 1, /* 1044: pointer.struct.bn_blinding_st */
            	1049, 0,
            0, 88, 7, /* 1049: struct.bn_blinding_st */
            	1066, 0,
            	1066, 8,
            	1066, 16,
            	1066, 24,
            	1083, 40,
            	1091, 72,
            	1105, 80,
            1, 8, 1, /* 1066: pointer.struct.bignum_st */
            	1071, 0,
            0, 24, 1, /* 1071: struct.bignum_st */
            	1076, 0,
            8884099, 8, 2, /* 1076: pointer_to_array_of_pointers_to_stack */
            	1005, 0,
            	341, 12,
            0, 16, 1, /* 1083: struct.crypto_threadid_st */
            	1088, 0,
            0, 8, 0, /* 1088: pointer.void */
            1, 8, 1, /* 1091: pointer.struct.bn_mont_ctx_st */
            	1096, 0,
            0, 96, 3, /* 1096: struct.bn_mont_ctx_st */
            	1071, 8,
            	1071, 32,
            	1071, 56,
            8884097, 8, 0, /* 1105: pointer.func */
            1, 8, 1, /* 1108: pointer.struct.dsa_st */
            	1113, 0,
            0, 136, 11, /* 1113: struct.dsa_st */
            	1138, 24,
            	1138, 32,
            	1138, 40,
            	1138, 48,
            	1138, 56,
            	1138, 64,
            	1138, 72,
            	1155, 88,
            	1169, 104,
            	1191, 120,
            	1242, 128,
            1, 8, 1, /* 1138: pointer.struct.bignum_st */
            	1143, 0,
            0, 24, 1, /* 1143: struct.bignum_st */
            	1148, 0,
            8884099, 8, 2, /* 1148: pointer_to_array_of_pointers_to_stack */
            	1005, 0,
            	341, 12,
            1, 8, 1, /* 1155: pointer.struct.bn_mont_ctx_st */
            	1160, 0,
            0, 96, 3, /* 1160: struct.bn_mont_ctx_st */
            	1143, 8,
            	1143, 32,
            	1143, 56,
            0, 16, 1, /* 1169: struct.crypto_ex_data_st */
            	1174, 0,
            1, 8, 1, /* 1174: pointer.struct.stack_st_void */
            	1179, 0,
            0, 32, 1, /* 1179: struct.stack_st_void */
            	1184, 0,
            0, 32, 2, /* 1184: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 1191: pointer.struct.dsa_method */
            	1196, 0,
            0, 96, 11, /* 1196: struct.dsa_method */
            	111, 0,
            	1221, 8,
            	1224, 16,
            	1227, 24,
            	1230, 32,
            	1233, 40,
            	1236, 48,
            	1236, 56,
            	174, 72,
            	1239, 80,
            	1236, 88,
            8884097, 8, 0, /* 1221: pointer.func */
            8884097, 8, 0, /* 1224: pointer.func */
            8884097, 8, 0, /* 1227: pointer.func */
            8884097, 8, 0, /* 1230: pointer.func */
            8884097, 8, 0, /* 1233: pointer.func */
            8884097, 8, 0, /* 1236: pointer.func */
            8884097, 8, 0, /* 1239: pointer.func */
            1, 8, 1, /* 1242: pointer.struct.engine_st */
            	525, 0,
            1, 8, 1, /* 1247: pointer.struct.dh_st */
            	1252, 0,
            0, 144, 12, /* 1252: struct.dh_st */
            	1279, 8,
            	1279, 16,
            	1279, 32,
            	1279, 40,
            	1296, 56,
            	1279, 64,
            	1279, 72,
            	77, 80,
            	1279, 96,
            	1310, 112,
            	1332, 128,
            	1368, 136,
            1, 8, 1, /* 1279: pointer.struct.bignum_st */
            	1284, 0,
            0, 24, 1, /* 1284: struct.bignum_st */
            	1289, 0,
            8884099, 8, 2, /* 1289: pointer_to_array_of_pointers_to_stack */
            	1005, 0,
            	341, 12,
            1, 8, 1, /* 1296: pointer.struct.bn_mont_ctx_st */
            	1301, 0,
            0, 96, 3, /* 1301: struct.bn_mont_ctx_st */
            	1284, 8,
            	1284, 32,
            	1284, 56,
            0, 16, 1, /* 1310: struct.crypto_ex_data_st */
            	1315, 0,
            1, 8, 1, /* 1315: pointer.struct.stack_st_void */
            	1320, 0,
            0, 32, 1, /* 1320: struct.stack_st_void */
            	1325, 0,
            0, 32, 2, /* 1325: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 1332: pointer.struct.dh_method */
            	1337, 0,
            0, 72, 8, /* 1337: struct.dh_method */
            	111, 0,
            	1356, 8,
            	1359, 16,
            	1362, 24,
            	1356, 32,
            	1356, 40,
            	174, 56,
            	1365, 64,
            8884097, 8, 0, /* 1356: pointer.func */
            8884097, 8, 0, /* 1359: pointer.func */
            8884097, 8, 0, /* 1362: pointer.func */
            8884097, 8, 0, /* 1365: pointer.func */
            1, 8, 1, /* 1368: pointer.struct.engine_st */
            	525, 0,
            1, 8, 1, /* 1373: pointer.struct.ec_key_st */
            	1378, 0,
            0, 56, 4, /* 1378: struct.ec_key_st */
            	1389, 8,
            	1837, 16,
            	1842, 24,
            	1859, 48,
            1, 8, 1, /* 1389: pointer.struct.ec_group_st */
            	1394, 0,
            0, 232, 12, /* 1394: struct.ec_group_st */
            	1421, 0,
            	1593, 8,
            	1793, 16,
            	1793, 40,
            	77, 80,
            	1805, 96,
            	1793, 104,
            	1793, 152,
            	1793, 176,
            	1088, 208,
            	1088, 216,
            	1834, 224,
            1, 8, 1, /* 1421: pointer.struct.ec_method_st */
            	1426, 0,
            0, 304, 37, /* 1426: struct.ec_method_st */
            	1503, 8,
            	1506, 16,
            	1506, 24,
            	1509, 32,
            	1512, 40,
            	1515, 48,
            	1518, 56,
            	1521, 64,
            	1524, 72,
            	1527, 80,
            	1527, 88,
            	1530, 96,
            	1533, 104,
            	1536, 112,
            	1539, 120,
            	1542, 128,
            	1545, 136,
            	1548, 144,
            	1551, 152,
            	1554, 160,
            	1557, 168,
            	1560, 176,
            	1563, 184,
            	1566, 192,
            	1569, 200,
            	1572, 208,
            	1563, 216,
            	1575, 224,
            	1578, 232,
            	1581, 240,
            	1518, 248,
            	1584, 256,
            	1587, 264,
            	1584, 272,
            	1587, 280,
            	1587, 288,
            	1590, 296,
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
            8884097, 8, 0, /* 1560: pointer.func */
            8884097, 8, 0, /* 1563: pointer.func */
            8884097, 8, 0, /* 1566: pointer.func */
            8884097, 8, 0, /* 1569: pointer.func */
            8884097, 8, 0, /* 1572: pointer.func */
            8884097, 8, 0, /* 1575: pointer.func */
            8884097, 8, 0, /* 1578: pointer.func */
            8884097, 8, 0, /* 1581: pointer.func */
            8884097, 8, 0, /* 1584: pointer.func */
            8884097, 8, 0, /* 1587: pointer.func */
            8884097, 8, 0, /* 1590: pointer.func */
            1, 8, 1, /* 1593: pointer.struct.ec_point_st */
            	1598, 0,
            0, 88, 4, /* 1598: struct.ec_point_st */
            	1609, 0,
            	1781, 8,
            	1781, 32,
            	1781, 56,
            1, 8, 1, /* 1609: pointer.struct.ec_method_st */
            	1614, 0,
            0, 304, 37, /* 1614: struct.ec_method_st */
            	1691, 8,
            	1694, 16,
            	1694, 24,
            	1697, 32,
            	1700, 40,
            	1703, 48,
            	1706, 56,
            	1709, 64,
            	1712, 72,
            	1715, 80,
            	1715, 88,
            	1718, 96,
            	1721, 104,
            	1724, 112,
            	1727, 120,
            	1730, 128,
            	1733, 136,
            	1736, 144,
            	1739, 152,
            	1742, 160,
            	1745, 168,
            	1748, 176,
            	1751, 184,
            	1754, 192,
            	1757, 200,
            	1760, 208,
            	1751, 216,
            	1763, 224,
            	1766, 232,
            	1769, 240,
            	1706, 248,
            	1772, 256,
            	1775, 264,
            	1772, 272,
            	1775, 280,
            	1775, 288,
            	1778, 296,
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
            8884097, 8, 0, /* 1748: pointer.func */
            8884097, 8, 0, /* 1751: pointer.func */
            8884097, 8, 0, /* 1754: pointer.func */
            8884097, 8, 0, /* 1757: pointer.func */
            8884097, 8, 0, /* 1760: pointer.func */
            8884097, 8, 0, /* 1763: pointer.func */
            8884097, 8, 0, /* 1766: pointer.func */
            8884097, 8, 0, /* 1769: pointer.func */
            8884097, 8, 0, /* 1772: pointer.func */
            8884097, 8, 0, /* 1775: pointer.func */
            8884097, 8, 0, /* 1778: pointer.func */
            0, 24, 1, /* 1781: struct.bignum_st */
            	1786, 0,
            8884099, 8, 2, /* 1786: pointer_to_array_of_pointers_to_stack */
            	1005, 0,
            	341, 12,
            0, 24, 1, /* 1793: struct.bignum_st */
            	1798, 0,
            8884099, 8, 2, /* 1798: pointer_to_array_of_pointers_to_stack */
            	1005, 0,
            	341, 12,
            1, 8, 1, /* 1805: pointer.struct.ec_extra_data_st */
            	1810, 0,
            0, 40, 5, /* 1810: struct.ec_extra_data_st */
            	1823, 0,
            	1088, 8,
            	1828, 16,
            	1831, 24,
            	1831, 32,
            1, 8, 1, /* 1823: pointer.struct.ec_extra_data_st */
            	1810, 0,
            8884097, 8, 0, /* 1828: pointer.func */
            8884097, 8, 0, /* 1831: pointer.func */
            8884097, 8, 0, /* 1834: pointer.func */
            1, 8, 1, /* 1837: pointer.struct.ec_point_st */
            	1598, 0,
            1, 8, 1, /* 1842: pointer.struct.bignum_st */
            	1847, 0,
            0, 24, 1, /* 1847: struct.bignum_st */
            	1852, 0,
            8884099, 8, 2, /* 1852: pointer_to_array_of_pointers_to_stack */
            	1005, 0,
            	341, 12,
            1, 8, 1, /* 1859: pointer.struct.ec_extra_data_st */
            	1864, 0,
            0, 40, 5, /* 1864: struct.ec_extra_data_st */
            	1877, 0,
            	1088, 8,
            	1828, 16,
            	1831, 24,
            	1831, 32,
            1, 8, 1, /* 1877: pointer.struct.ec_extra_data_st */
            	1864, 0,
            1, 8, 1, /* 1882: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1887, 0,
            0, 32, 2, /* 1887: struct.stack_st_fake_X509_ATTRIBUTE */
            	1894, 8,
            	344, 24,
            8884099, 8, 2, /* 1894: pointer_to_array_of_pointers_to_stack */
            	1901, 0,
            	341, 20,
            0, 8, 1, /* 1901: pointer.X509_ATTRIBUTE */
            	1906, 0,
            0, 0, 1, /* 1906: X509_ATTRIBUTE */
            	1911, 0,
            0, 24, 2, /* 1911: struct.x509_attributes_st */
            	1918, 0,
            	1932, 16,
            1, 8, 1, /* 1918: pointer.struct.asn1_object_st */
            	1923, 0,
            0, 40, 3, /* 1923: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            0, 8, 3, /* 1932: union.unknown */
            	174, 0,
            	1941, 0,
            	2120, 0,
            1, 8, 1, /* 1941: pointer.struct.stack_st_ASN1_TYPE */
            	1946, 0,
            0, 32, 2, /* 1946: struct.stack_st_fake_ASN1_TYPE */
            	1953, 8,
            	344, 24,
            8884099, 8, 2, /* 1953: pointer_to_array_of_pointers_to_stack */
            	1960, 0,
            	341, 20,
            0, 8, 1, /* 1960: pointer.ASN1_TYPE */
            	1965, 0,
            0, 0, 1, /* 1965: ASN1_TYPE */
            	1970, 0,
            0, 16, 1, /* 1970: struct.asn1_type_st */
            	1975, 8,
            0, 8, 20, /* 1975: union.unknown */
            	174, 0,
            	2018, 0,
            	2028, 0,
            	2042, 0,
            	2047, 0,
            	2052, 0,
            	2057, 0,
            	2062, 0,
            	2067, 0,
            	2072, 0,
            	2077, 0,
            	2082, 0,
            	2087, 0,
            	2092, 0,
            	2097, 0,
            	2102, 0,
            	2107, 0,
            	2018, 0,
            	2018, 0,
            	2112, 0,
            1, 8, 1, /* 2018: pointer.struct.asn1_string_st */
            	2023, 0,
            0, 24, 1, /* 2023: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2028: pointer.struct.asn1_object_st */
            	2033, 0,
            0, 40, 3, /* 2033: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2042: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2047: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2052: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2057: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2062: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2067: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2072: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2077: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2082: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2087: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2092: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2097: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2102: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2107: pointer.struct.asn1_string_st */
            	2023, 0,
            1, 8, 1, /* 2112: pointer.struct.ASN1_VALUE_st */
            	2117, 0,
            0, 0, 0, /* 2117: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2120: pointer.struct.asn1_type_st */
            	2125, 0,
            0, 16, 1, /* 2125: struct.asn1_type_st */
            	2130, 8,
            0, 8, 20, /* 2130: union.unknown */
            	174, 0,
            	2173, 0,
            	1918, 0,
            	2183, 0,
            	2188, 0,
            	2193, 0,
            	2198, 0,
            	2203, 0,
            	2208, 0,
            	2213, 0,
            	2218, 0,
            	2223, 0,
            	2228, 0,
            	2233, 0,
            	2238, 0,
            	2243, 0,
            	2248, 0,
            	2173, 0,
            	2173, 0,
            	259, 0,
            1, 8, 1, /* 2173: pointer.struct.asn1_string_st */
            	2178, 0,
            0, 24, 1, /* 2178: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2183: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2188: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2193: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2198: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2203: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2208: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2213: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2218: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2223: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2228: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2233: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2238: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2243: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2248: pointer.struct.asn1_string_st */
            	2178, 0,
            1, 8, 1, /* 2253: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 2258: pointer.struct.stack_st_X509_EXTENSION */
            	2263, 0,
            0, 32, 2, /* 2263: struct.stack_st_fake_X509_EXTENSION */
            	2270, 8,
            	344, 24,
            8884099, 8, 2, /* 2270: pointer_to_array_of_pointers_to_stack */
            	2277, 0,
            	341, 20,
            0, 8, 1, /* 2277: pointer.X509_EXTENSION */
            	2282, 0,
            0, 0, 1, /* 2282: X509_EXTENSION */
            	2287, 0,
            0, 24, 2, /* 2287: struct.X509_extension_st */
            	2294, 0,
            	2308, 16,
            1, 8, 1, /* 2294: pointer.struct.asn1_object_st */
            	2299, 0,
            0, 40, 3, /* 2299: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2308: pointer.struct.asn1_string_st */
            	2313, 0,
            0, 24, 1, /* 2313: struct.asn1_string_st */
            	77, 8,
            0, 24, 1, /* 2318: struct.ASN1_ENCODING_st */
            	77, 0,
            0, 16, 1, /* 2323: struct.crypto_ex_data_st */
            	2328, 0,
            1, 8, 1, /* 2328: pointer.struct.stack_st_void */
            	2333, 0,
            0, 32, 1, /* 2333: struct.stack_st_void */
            	2338, 0,
            0, 32, 2, /* 2338: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 2345: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 2350: pointer.struct.AUTHORITY_KEYID_st */
            	2355, 0,
            0, 24, 3, /* 2355: struct.AUTHORITY_KEYID_st */
            	2364, 0,
            	2374, 8,
            	2668, 16,
            1, 8, 1, /* 2364: pointer.struct.asn1_string_st */
            	2369, 0,
            0, 24, 1, /* 2369: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2374: pointer.struct.stack_st_GENERAL_NAME */
            	2379, 0,
            0, 32, 2, /* 2379: struct.stack_st_fake_GENERAL_NAME */
            	2386, 8,
            	344, 24,
            8884099, 8, 2, /* 2386: pointer_to_array_of_pointers_to_stack */
            	2393, 0,
            	341, 20,
            0, 8, 1, /* 2393: pointer.GENERAL_NAME */
            	2398, 0,
            0, 0, 1, /* 2398: GENERAL_NAME */
            	2403, 0,
            0, 16, 1, /* 2403: struct.GENERAL_NAME_st */
            	2408, 8,
            0, 8, 15, /* 2408: union.unknown */
            	174, 0,
            	2441, 0,
            	2560, 0,
            	2560, 0,
            	2467, 0,
            	2608, 0,
            	2656, 0,
            	2560, 0,
            	2545, 0,
            	2453, 0,
            	2545, 0,
            	2608, 0,
            	2560, 0,
            	2453, 0,
            	2467, 0,
            1, 8, 1, /* 2441: pointer.struct.otherName_st */
            	2446, 0,
            0, 16, 2, /* 2446: struct.otherName_st */
            	2453, 0,
            	2467, 8,
            1, 8, 1, /* 2453: pointer.struct.asn1_object_st */
            	2458, 0,
            0, 40, 3, /* 2458: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2467: pointer.struct.asn1_type_st */
            	2472, 0,
            0, 16, 1, /* 2472: struct.asn1_type_st */
            	2477, 8,
            0, 8, 20, /* 2477: union.unknown */
            	174, 0,
            	2520, 0,
            	2453, 0,
            	2530, 0,
            	2535, 0,
            	2540, 0,
            	2545, 0,
            	2550, 0,
            	2555, 0,
            	2560, 0,
            	2565, 0,
            	2570, 0,
            	2575, 0,
            	2580, 0,
            	2585, 0,
            	2590, 0,
            	2595, 0,
            	2520, 0,
            	2520, 0,
            	2600, 0,
            1, 8, 1, /* 2520: pointer.struct.asn1_string_st */
            	2525, 0,
            0, 24, 1, /* 2525: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2530: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2535: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2540: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2545: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2550: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2555: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2560: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2565: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2570: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2575: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2580: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2585: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2590: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2595: pointer.struct.asn1_string_st */
            	2525, 0,
            1, 8, 1, /* 2600: pointer.struct.ASN1_VALUE_st */
            	2605, 0,
            0, 0, 0, /* 2605: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2608: pointer.struct.X509_name_st */
            	2613, 0,
            0, 40, 3, /* 2613: struct.X509_name_st */
            	2622, 0,
            	2646, 16,
            	77, 24,
            1, 8, 1, /* 2622: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2627, 0,
            0, 32, 2, /* 2627: struct.stack_st_fake_X509_NAME_ENTRY */
            	2634, 8,
            	344, 24,
            8884099, 8, 2, /* 2634: pointer_to_array_of_pointers_to_stack */
            	2641, 0,
            	341, 20,
            0, 8, 1, /* 2641: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 2646: pointer.struct.buf_mem_st */
            	2651, 0,
            0, 24, 1, /* 2651: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 2656: pointer.struct.EDIPartyName_st */
            	2661, 0,
            0, 16, 2, /* 2661: struct.EDIPartyName_st */
            	2520, 0,
            	2520, 8,
            1, 8, 1, /* 2668: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2673: pointer.struct.X509_POLICY_CACHE_st */
            	2678, 0,
            0, 40, 2, /* 2678: struct.X509_POLICY_CACHE_st */
            	2685, 0,
            	3004, 8,
            1, 8, 1, /* 2685: pointer.struct.X509_POLICY_DATA_st */
            	2690, 0,
            0, 32, 3, /* 2690: struct.X509_POLICY_DATA_st */
            	2699, 8,
            	2713, 16,
            	2966, 24,
            1, 8, 1, /* 2699: pointer.struct.asn1_object_st */
            	2704, 0,
            0, 40, 3, /* 2704: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2713: pointer.struct.stack_st_POLICYQUALINFO */
            	2718, 0,
            0, 32, 2, /* 2718: struct.stack_st_fake_POLICYQUALINFO */
            	2725, 8,
            	344, 24,
            8884099, 8, 2, /* 2725: pointer_to_array_of_pointers_to_stack */
            	2732, 0,
            	341, 20,
            0, 8, 1, /* 2732: pointer.POLICYQUALINFO */
            	2737, 0,
            0, 0, 1, /* 2737: POLICYQUALINFO */
            	2742, 0,
            0, 16, 2, /* 2742: struct.POLICYQUALINFO_st */
            	2749, 0,
            	2763, 8,
            1, 8, 1, /* 2749: pointer.struct.asn1_object_st */
            	2754, 0,
            0, 40, 3, /* 2754: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            0, 8, 3, /* 2763: union.unknown */
            	2772, 0,
            	2782, 0,
            	2840, 0,
            1, 8, 1, /* 2772: pointer.struct.asn1_string_st */
            	2777, 0,
            0, 24, 1, /* 2777: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2782: pointer.struct.USERNOTICE_st */
            	2787, 0,
            0, 16, 2, /* 2787: struct.USERNOTICE_st */
            	2794, 0,
            	2806, 8,
            1, 8, 1, /* 2794: pointer.struct.NOTICEREF_st */
            	2799, 0,
            0, 16, 2, /* 2799: struct.NOTICEREF_st */
            	2806, 0,
            	2811, 8,
            1, 8, 1, /* 2806: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2811: pointer.struct.stack_st_ASN1_INTEGER */
            	2816, 0,
            0, 32, 2, /* 2816: struct.stack_st_fake_ASN1_INTEGER */
            	2823, 8,
            	344, 24,
            8884099, 8, 2, /* 2823: pointer_to_array_of_pointers_to_stack */
            	2830, 0,
            	341, 20,
            0, 8, 1, /* 2830: pointer.ASN1_INTEGER */
            	2835, 0,
            0, 0, 1, /* 2835: ASN1_INTEGER */
            	184, 0,
            1, 8, 1, /* 2840: pointer.struct.asn1_type_st */
            	2845, 0,
            0, 16, 1, /* 2845: struct.asn1_type_st */
            	2850, 8,
            0, 8, 20, /* 2850: union.unknown */
            	174, 0,
            	2806, 0,
            	2749, 0,
            	2893, 0,
            	2898, 0,
            	2903, 0,
            	2908, 0,
            	2913, 0,
            	2918, 0,
            	2772, 0,
            	2923, 0,
            	2928, 0,
            	2933, 0,
            	2938, 0,
            	2943, 0,
            	2948, 0,
            	2953, 0,
            	2806, 0,
            	2806, 0,
            	2958, 0,
            1, 8, 1, /* 2893: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2898: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2903: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2908: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2913: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2918: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2923: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2928: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2933: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2938: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2943: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2948: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2953: pointer.struct.asn1_string_st */
            	2777, 0,
            1, 8, 1, /* 2958: pointer.struct.ASN1_VALUE_st */
            	2963, 0,
            0, 0, 0, /* 2963: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2966: pointer.struct.stack_st_ASN1_OBJECT */
            	2971, 0,
            0, 32, 2, /* 2971: struct.stack_st_fake_ASN1_OBJECT */
            	2978, 8,
            	344, 24,
            8884099, 8, 2, /* 2978: pointer_to_array_of_pointers_to_stack */
            	2985, 0,
            	341, 20,
            0, 8, 1, /* 2985: pointer.ASN1_OBJECT */
            	2990, 0,
            0, 0, 1, /* 2990: ASN1_OBJECT */
            	2995, 0,
            0, 40, 3, /* 2995: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 3004: pointer.struct.stack_st_X509_POLICY_DATA */
            	3009, 0,
            0, 32, 2, /* 3009: struct.stack_st_fake_X509_POLICY_DATA */
            	3016, 8,
            	344, 24,
            8884099, 8, 2, /* 3016: pointer_to_array_of_pointers_to_stack */
            	3023, 0,
            	341, 20,
            0, 8, 1, /* 3023: pointer.X509_POLICY_DATA */
            	3028, 0,
            0, 0, 1, /* 3028: X509_POLICY_DATA */
            	3033, 0,
            0, 32, 3, /* 3033: struct.X509_POLICY_DATA_st */
            	3042, 8,
            	3056, 16,
            	3080, 24,
            1, 8, 1, /* 3042: pointer.struct.asn1_object_st */
            	3047, 0,
            0, 40, 3, /* 3047: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 3056: pointer.struct.stack_st_POLICYQUALINFO */
            	3061, 0,
            0, 32, 2, /* 3061: struct.stack_st_fake_POLICYQUALINFO */
            	3068, 8,
            	344, 24,
            8884099, 8, 2, /* 3068: pointer_to_array_of_pointers_to_stack */
            	3075, 0,
            	341, 20,
            0, 8, 1, /* 3075: pointer.POLICYQUALINFO */
            	2737, 0,
            1, 8, 1, /* 3080: pointer.struct.stack_st_ASN1_OBJECT */
            	3085, 0,
            0, 32, 2, /* 3085: struct.stack_st_fake_ASN1_OBJECT */
            	3092, 8,
            	344, 24,
            8884099, 8, 2, /* 3092: pointer_to_array_of_pointers_to_stack */
            	3099, 0,
            	341, 20,
            0, 8, 1, /* 3099: pointer.ASN1_OBJECT */
            	2990, 0,
            1, 8, 1, /* 3104: pointer.struct.stack_st_DIST_POINT */
            	3109, 0,
            0, 32, 2, /* 3109: struct.stack_st_fake_DIST_POINT */
            	3116, 8,
            	344, 24,
            8884099, 8, 2, /* 3116: pointer_to_array_of_pointers_to_stack */
            	3123, 0,
            	341, 20,
            0, 8, 1, /* 3123: pointer.DIST_POINT */
            	3128, 0,
            0, 0, 1, /* 3128: DIST_POINT */
            	3133, 0,
            0, 32, 3, /* 3133: struct.DIST_POINT_st */
            	3142, 0,
            	3233, 8,
            	3161, 16,
            1, 8, 1, /* 3142: pointer.struct.DIST_POINT_NAME_st */
            	3147, 0,
            0, 24, 2, /* 3147: struct.DIST_POINT_NAME_st */
            	3154, 8,
            	3209, 16,
            0, 8, 2, /* 3154: union.unknown */
            	3161, 0,
            	3185, 0,
            1, 8, 1, /* 3161: pointer.struct.stack_st_GENERAL_NAME */
            	3166, 0,
            0, 32, 2, /* 3166: struct.stack_st_fake_GENERAL_NAME */
            	3173, 8,
            	344, 24,
            8884099, 8, 2, /* 3173: pointer_to_array_of_pointers_to_stack */
            	3180, 0,
            	341, 20,
            0, 8, 1, /* 3180: pointer.GENERAL_NAME */
            	2398, 0,
            1, 8, 1, /* 3185: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3190, 0,
            0, 32, 2, /* 3190: struct.stack_st_fake_X509_NAME_ENTRY */
            	3197, 8,
            	344, 24,
            8884099, 8, 2, /* 3197: pointer_to_array_of_pointers_to_stack */
            	3204, 0,
            	341, 20,
            0, 8, 1, /* 3204: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 3209: pointer.struct.X509_name_st */
            	3214, 0,
            0, 40, 3, /* 3214: struct.X509_name_st */
            	3185, 0,
            	3223, 16,
            	77, 24,
            1, 8, 1, /* 3223: pointer.struct.buf_mem_st */
            	3228, 0,
            0, 24, 1, /* 3228: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 3233: pointer.struct.asn1_string_st */
            	3238, 0,
            0, 24, 1, /* 3238: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 3243: pointer.struct.stack_st_GENERAL_NAME */
            	3248, 0,
            0, 32, 2, /* 3248: struct.stack_st_fake_GENERAL_NAME */
            	3255, 8,
            	344, 24,
            8884099, 8, 2, /* 3255: pointer_to_array_of_pointers_to_stack */
            	3262, 0,
            	341, 20,
            0, 8, 1, /* 3262: pointer.GENERAL_NAME */
            	2398, 0,
            1, 8, 1, /* 3267: pointer.struct.NAME_CONSTRAINTS_st */
            	3272, 0,
            0, 16, 2, /* 3272: struct.NAME_CONSTRAINTS_st */
            	3279, 0,
            	3279, 8,
            1, 8, 1, /* 3279: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3284, 0,
            0, 32, 2, /* 3284: struct.stack_st_fake_GENERAL_SUBTREE */
            	3291, 8,
            	344, 24,
            8884099, 8, 2, /* 3291: pointer_to_array_of_pointers_to_stack */
            	3298, 0,
            	341, 20,
            0, 8, 1, /* 3298: pointer.GENERAL_SUBTREE */
            	3303, 0,
            0, 0, 1, /* 3303: GENERAL_SUBTREE */
            	3308, 0,
            0, 24, 3, /* 3308: struct.GENERAL_SUBTREE_st */
            	3317, 0,
            	3449, 8,
            	3449, 16,
            1, 8, 1, /* 3317: pointer.struct.GENERAL_NAME_st */
            	3322, 0,
            0, 16, 1, /* 3322: struct.GENERAL_NAME_st */
            	3327, 8,
            0, 8, 15, /* 3327: union.unknown */
            	174, 0,
            	3360, 0,
            	3479, 0,
            	3479, 0,
            	3386, 0,
            	3519, 0,
            	3567, 0,
            	3479, 0,
            	3464, 0,
            	3372, 0,
            	3464, 0,
            	3519, 0,
            	3479, 0,
            	3372, 0,
            	3386, 0,
            1, 8, 1, /* 3360: pointer.struct.otherName_st */
            	3365, 0,
            0, 16, 2, /* 3365: struct.otherName_st */
            	3372, 0,
            	3386, 8,
            1, 8, 1, /* 3372: pointer.struct.asn1_object_st */
            	3377, 0,
            0, 40, 3, /* 3377: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 3386: pointer.struct.asn1_type_st */
            	3391, 0,
            0, 16, 1, /* 3391: struct.asn1_type_st */
            	3396, 8,
            0, 8, 20, /* 3396: union.unknown */
            	174, 0,
            	3439, 0,
            	3372, 0,
            	3449, 0,
            	3454, 0,
            	3459, 0,
            	3464, 0,
            	3469, 0,
            	3474, 0,
            	3479, 0,
            	3484, 0,
            	3489, 0,
            	3494, 0,
            	3499, 0,
            	3504, 0,
            	3509, 0,
            	3514, 0,
            	3439, 0,
            	3439, 0,
            	2958, 0,
            1, 8, 1, /* 3439: pointer.struct.asn1_string_st */
            	3444, 0,
            0, 24, 1, /* 3444: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 3449: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3454: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3459: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3464: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3469: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3474: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3479: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3484: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3489: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3494: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3499: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3504: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3509: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3514: pointer.struct.asn1_string_st */
            	3444, 0,
            1, 8, 1, /* 3519: pointer.struct.X509_name_st */
            	3524, 0,
            0, 40, 3, /* 3524: struct.X509_name_st */
            	3533, 0,
            	3557, 16,
            	77, 24,
            1, 8, 1, /* 3533: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3538, 0,
            0, 32, 2, /* 3538: struct.stack_st_fake_X509_NAME_ENTRY */
            	3545, 8,
            	344, 24,
            8884099, 8, 2, /* 3545: pointer_to_array_of_pointers_to_stack */
            	3552, 0,
            	341, 20,
            0, 8, 1, /* 3552: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 3557: pointer.struct.buf_mem_st */
            	3562, 0,
            0, 24, 1, /* 3562: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 3567: pointer.struct.EDIPartyName_st */
            	3572, 0,
            0, 16, 2, /* 3572: struct.EDIPartyName_st */
            	3439, 0,
            	3439, 8,
            1, 8, 1, /* 3579: pointer.struct.x509_cert_aux_st */
            	3584, 0,
            0, 40, 5, /* 3584: struct.x509_cert_aux_st */
            	3597, 0,
            	3597, 8,
            	3621, 16,
            	2345, 24,
            	3626, 32,
            1, 8, 1, /* 3597: pointer.struct.stack_st_ASN1_OBJECT */
            	3602, 0,
            0, 32, 2, /* 3602: struct.stack_st_fake_ASN1_OBJECT */
            	3609, 8,
            	344, 24,
            8884099, 8, 2, /* 3609: pointer_to_array_of_pointers_to_stack */
            	3616, 0,
            	341, 20,
            0, 8, 1, /* 3616: pointer.ASN1_OBJECT */
            	2990, 0,
            1, 8, 1, /* 3621: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 3626: pointer.struct.stack_st_X509_ALGOR */
            	3631, 0,
            0, 32, 2, /* 3631: struct.stack_st_fake_X509_ALGOR */
            	3638, 8,
            	344, 24,
            8884099, 8, 2, /* 3638: pointer_to_array_of_pointers_to_stack */
            	3645, 0,
            	341, 20,
            0, 8, 1, /* 3645: pointer.X509_ALGOR */
            	3650, 0,
            0, 0, 1, /* 3650: X509_ALGOR */
            	90, 0,
            1, 8, 1, /* 3655: pointer.struct.stack_st_X509_REVOKED */
            	3660, 0,
            0, 32, 2, /* 3660: struct.stack_st_fake_X509_REVOKED */
            	3667, 8,
            	344, 24,
            8884099, 8, 2, /* 3667: pointer_to_array_of_pointers_to_stack */
            	3674, 0,
            	341, 20,
            0, 8, 1, /* 3674: pointer.X509_REVOKED */
            	3679, 0,
            0, 0, 1, /* 3679: X509_REVOKED */
            	3684, 0,
            0, 40, 4, /* 3684: struct.x509_revoked_st */
            	3695, 0,
            	3705, 8,
            	3710, 16,
            	3734, 24,
            1, 8, 1, /* 3695: pointer.struct.asn1_string_st */
            	3700, 0,
            0, 24, 1, /* 3700: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 3705: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3710: pointer.struct.stack_st_X509_EXTENSION */
            	3715, 0,
            0, 32, 2, /* 3715: struct.stack_st_fake_X509_EXTENSION */
            	3722, 8,
            	344, 24,
            8884099, 8, 2, /* 3722: pointer_to_array_of_pointers_to_stack */
            	3729, 0,
            	341, 20,
            0, 8, 1, /* 3729: pointer.X509_EXTENSION */
            	2282, 0,
            1, 8, 1, /* 3734: pointer.struct.stack_st_GENERAL_NAME */
            	3739, 0,
            0, 32, 2, /* 3739: struct.stack_st_fake_GENERAL_NAME */
            	3746, 8,
            	344, 24,
            8884099, 8, 2, /* 3746: pointer_to_array_of_pointers_to_stack */
            	3753, 0,
            	341, 20,
            0, 8, 1, /* 3753: pointer.GENERAL_NAME */
            	2398, 0,
            0, 120, 10, /* 3758: struct.X509_crl_st */
            	3781, 0,
            	85, 8,
            	2253, 16,
            	2350, 32,
            	3805, 40,
            	67, 56,
            	67, 64,
            	3918, 96,
            	3959, 104,
            	1088, 112,
            1, 8, 1, /* 3781: pointer.struct.X509_crl_info_st */
            	3786, 0,
            0, 80, 8, /* 3786: struct.X509_crl_info_st */
            	67, 0,
            	85, 8,
            	267, 16,
            	369, 24,
            	369, 32,
            	3655, 40,
            	2258, 48,
            	2318, 56,
            1, 8, 1, /* 3805: pointer.struct.ISSUING_DIST_POINT_st */
            	3810, 0,
            0, 32, 2, /* 3810: struct.ISSUING_DIST_POINT_st */
            	3817, 0,
            	3908, 16,
            1, 8, 1, /* 3817: pointer.struct.DIST_POINT_NAME_st */
            	3822, 0,
            0, 24, 2, /* 3822: struct.DIST_POINT_NAME_st */
            	3829, 8,
            	3884, 16,
            0, 8, 2, /* 3829: union.unknown */
            	3836, 0,
            	3860, 0,
            1, 8, 1, /* 3836: pointer.struct.stack_st_GENERAL_NAME */
            	3841, 0,
            0, 32, 2, /* 3841: struct.stack_st_fake_GENERAL_NAME */
            	3848, 8,
            	344, 24,
            8884099, 8, 2, /* 3848: pointer_to_array_of_pointers_to_stack */
            	3855, 0,
            	341, 20,
            0, 8, 1, /* 3855: pointer.GENERAL_NAME */
            	2398, 0,
            1, 8, 1, /* 3860: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3865, 0,
            0, 32, 2, /* 3865: struct.stack_st_fake_X509_NAME_ENTRY */
            	3872, 8,
            	344, 24,
            8884099, 8, 2, /* 3872: pointer_to_array_of_pointers_to_stack */
            	3879, 0,
            	341, 20,
            0, 8, 1, /* 3879: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 3884: pointer.struct.X509_name_st */
            	3889, 0,
            0, 40, 3, /* 3889: struct.X509_name_st */
            	3860, 0,
            	3898, 16,
            	77, 24,
            1, 8, 1, /* 3898: pointer.struct.buf_mem_st */
            	3903, 0,
            0, 24, 1, /* 3903: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 3908: pointer.struct.asn1_string_st */
            	3913, 0,
            0, 24, 1, /* 3913: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 3918: pointer.struct.stack_st_GENERAL_NAMES */
            	3923, 0,
            0, 32, 2, /* 3923: struct.stack_st_fake_GENERAL_NAMES */
            	3930, 8,
            	344, 24,
            8884099, 8, 2, /* 3930: pointer_to_array_of_pointers_to_stack */
            	3937, 0,
            	341, 20,
            0, 8, 1, /* 3937: pointer.GENERAL_NAMES */
            	3942, 0,
            0, 0, 1, /* 3942: GENERAL_NAMES */
            	3947, 0,
            0, 32, 1, /* 3947: struct.stack_st_GENERAL_NAME */
            	3952, 0,
            0, 32, 2, /* 3952: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 3959: pointer.struct.x509_crl_method_st */
            	3964, 0,
            0, 40, 4, /* 3964: struct.x509_crl_method_st */
            	3975, 8,
            	3975, 16,
            	3978, 24,
            	3981, 32,
            8884097, 8, 0, /* 3975: pointer.func */
            8884097, 8, 0, /* 3978: pointer.func */
            8884097, 8, 0, /* 3981: pointer.func */
            1, 8, 1, /* 3984: pointer.struct.X509_POLICY_DATA_st */
            	2690, 0,
            0, 24, 2, /* 3989: struct.X509_POLICY_NODE_st */
            	3984, 0,
            	3996, 8,
            1, 8, 1, /* 3996: pointer.struct.X509_POLICY_NODE_st */
            	3989, 0,
            1, 8, 1, /* 4001: pointer.struct.X509_POLICY_NODE_st */
            	4006, 0,
            0, 24, 2, /* 4006: struct.X509_POLICY_NODE_st */
            	4013, 0,
            	4001, 8,
            1, 8, 1, /* 4013: pointer.struct.X509_POLICY_DATA_st */
            	3033, 0,
            0, 0, 1, /* 4018: X509_POLICY_NODE */
            	4006, 0,
            0, 40, 5, /* 4023: struct.x509_cert_aux_st */
            	2966, 0,
            	2966, 8,
            	4036, 16,
            	4046, 24,
            	4051, 32,
            1, 8, 1, /* 4036: pointer.struct.asn1_string_st */
            	4041, 0,
            0, 24, 1, /* 4041: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 4046: pointer.struct.asn1_string_st */
            	4041, 0,
            1, 8, 1, /* 4051: pointer.struct.stack_st_X509_ALGOR */
            	4056, 0,
            0, 32, 2, /* 4056: struct.stack_st_fake_X509_ALGOR */
            	4063, 8,
            	344, 24,
            8884099, 8, 2, /* 4063: pointer_to_array_of_pointers_to_stack */
            	4070, 0,
            	341, 20,
            0, 8, 1, /* 4070: pointer.X509_ALGOR */
            	3650, 0,
            1, 8, 1, /* 4075: pointer.struct.x509_cert_aux_st */
            	4023, 0,
            1, 8, 1, /* 4080: pointer.struct.NAME_CONSTRAINTS_st */
            	3272, 0,
            1, 8, 1, /* 4085: pointer.struct.AUTHORITY_KEYID_st */
            	2355, 0,
            0, 32, 2, /* 4090: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 4097: pointer.struct.stack_st_void */
            	4102, 0,
            0, 32, 1, /* 4102: struct.stack_st_void */
            	4090, 0,
            0, 16, 1, /* 4107: struct.crypto_ex_data_st */
            	4097, 0,
            1, 8, 1, /* 4112: pointer.struct.stack_st_X509_EXTENSION */
            	4117, 0,
            0, 32, 2, /* 4117: struct.stack_st_fake_X509_EXTENSION */
            	4124, 8,
            	344, 24,
            8884099, 8, 2, /* 4124: pointer_to_array_of_pointers_to_stack */
            	4131, 0,
            	341, 20,
            0, 8, 1, /* 4131: pointer.X509_EXTENSION */
            	2282, 0,
            1, 8, 1, /* 4136: pointer.struct.asn1_string_st */
            	4041, 0,
            1, 8, 1, /* 4141: pointer.struct.X509_pubkey_st */
            	379, 0,
            1, 8, 1, /* 4146: pointer.struct.asn1_string_st */
            	4041, 0,
            0, 16, 2, /* 4151: struct.X509_val_st */
            	4146, 0,
            	4146, 8,
            1, 8, 1, /* 4158: pointer.struct.X509_val_st */
            	4151, 0,
            1, 8, 1, /* 4163: pointer.struct.X509_name_st */
            	4168, 0,
            0, 40, 3, /* 4168: struct.X509_name_st */
            	4177, 0,
            	4201, 16,
            	77, 24,
            1, 8, 1, /* 4177: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4182, 0,
            0, 32, 2, /* 4182: struct.stack_st_fake_X509_NAME_ENTRY */
            	4189, 8,
            	344, 24,
            8884099, 8, 2, /* 4189: pointer_to_array_of_pointers_to_stack */
            	4196, 0,
            	341, 20,
            0, 8, 1, /* 4196: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 4201: pointer.struct.buf_mem_st */
            	4206, 0,
            0, 24, 1, /* 4206: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 4211: pointer.struct.x509_cinf_st */
            	4216, 0,
            0, 104, 11, /* 4216: struct.x509_cinf_st */
            	4241, 0,
            	4241, 8,
            	4246, 16,
            	4163, 24,
            	4158, 32,
            	4163, 40,
            	4141, 48,
            	4136, 56,
            	4136, 64,
            	4112, 72,
            	4251, 80,
            1, 8, 1, /* 4241: pointer.struct.asn1_string_st */
            	4041, 0,
            1, 8, 1, /* 4246: pointer.struct.X509_algor_st */
            	90, 0,
            0, 24, 1, /* 4251: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 4256: pointer.struct.x509_st */
            	4261, 0,
            0, 184, 12, /* 4261: struct.x509_st */
            	4211, 0,
            	4246, 8,
            	4136, 16,
            	174, 32,
            	4107, 40,
            	4046, 104,
            	4085, 112,
            	4288, 120,
            	4293, 128,
            	4317, 136,
            	4080, 144,
            	4075, 176,
            1, 8, 1, /* 4288: pointer.struct.X509_POLICY_CACHE_st */
            	2678, 0,
            1, 8, 1, /* 4293: pointer.struct.stack_st_DIST_POINT */
            	4298, 0,
            0, 32, 2, /* 4298: struct.stack_st_fake_DIST_POINT */
            	4305, 8,
            	344, 24,
            8884099, 8, 2, /* 4305: pointer_to_array_of_pointers_to_stack */
            	4312, 0,
            	341, 20,
            0, 8, 1, /* 4312: pointer.DIST_POINT */
            	3128, 0,
            1, 8, 1, /* 4317: pointer.struct.stack_st_GENERAL_NAME */
            	4322, 0,
            0, 32, 2, /* 4322: struct.stack_st_fake_GENERAL_NAME */
            	4329, 8,
            	344, 24,
            8884099, 8, 2, /* 4329: pointer_to_array_of_pointers_to_stack */
            	4336, 0,
            	341, 20,
            0, 8, 1, /* 4336: pointer.GENERAL_NAME */
            	2398, 0,
            0, 32, 3, /* 4341: struct.X509_POLICY_LEVEL_st */
            	4256, 0,
            	4350, 8,
            	3996, 16,
            1, 8, 1, /* 4350: pointer.struct.stack_st_X509_POLICY_NODE */
            	4355, 0,
            0, 32, 2, /* 4355: struct.stack_st_fake_X509_POLICY_NODE */
            	4362, 8,
            	344, 24,
            8884099, 8, 2, /* 4362: pointer_to_array_of_pointers_to_stack */
            	4369, 0,
            	341, 20,
            0, 8, 1, /* 4369: pointer.X509_POLICY_NODE */
            	4018, 0,
            0, 48, 4, /* 4374: struct.X509_POLICY_TREE_st */
            	4385, 0,
            	3004, 16,
            	4350, 24,
            	4350, 32,
            1, 8, 1, /* 4385: pointer.struct.X509_POLICY_LEVEL_st */
            	4341, 0,
            1, 8, 1, /* 4390: pointer.struct.X509_POLICY_TREE_st */
            	4374, 0,
            1, 8, 1, /* 4395: pointer.struct.x509_crl_method_st */
            	3964, 0,
            1, 8, 1, /* 4400: pointer.struct.ISSUING_DIST_POINT_st */
            	3810, 0,
            1, 8, 1, /* 4405: pointer.struct.AUTHORITY_KEYID_st */
            	2355, 0,
            0, 24, 1, /* 4410: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 4415: pointer.struct.stack_st_X509_EXTENSION */
            	4420, 0,
            0, 32, 2, /* 4420: struct.stack_st_fake_X509_EXTENSION */
            	4427, 8,
            	344, 24,
            8884099, 8, 2, /* 4427: pointer_to_array_of_pointers_to_stack */
            	4434, 0,
            	341, 20,
            0, 8, 1, /* 4434: pointer.X509_EXTENSION */
            	2282, 0,
            1, 8, 1, /* 4439: pointer.struct.asn1_string_st */
            	4444, 0,
            0, 24, 1, /* 4444: struct.asn1_string_st */
            	77, 8,
            0, 24, 1, /* 4449: struct.buf_mem_st */
            	174, 8,
            0, 40, 3, /* 4454: struct.X509_name_st */
            	4463, 0,
            	4487, 16,
            	77, 24,
            1, 8, 1, /* 4463: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4468, 0,
            0, 32, 2, /* 4468: struct.stack_st_fake_X509_NAME_ENTRY */
            	4475, 8,
            	344, 24,
            8884099, 8, 2, /* 4475: pointer_to_array_of_pointers_to_stack */
            	4482, 0,
            	341, 20,
            0, 8, 1, /* 4482: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 4487: pointer.struct.buf_mem_st */
            	4449, 0,
            1, 8, 1, /* 4492: pointer.struct.X509_name_st */
            	4454, 0,
            1, 8, 1, /* 4497: pointer.struct.asn1_string_st */
            	4444, 0,
            1, 8, 1, /* 4502: pointer.struct.X509_crl_info_st */
            	4507, 0,
            0, 80, 8, /* 4507: struct.X509_crl_info_st */
            	4497, 0,
            	4526, 8,
            	4492, 16,
            	4439, 24,
            	4439, 32,
            	4531, 40,
            	4415, 48,
            	4410, 56,
            1, 8, 1, /* 4526: pointer.struct.X509_algor_st */
            	90, 0,
            1, 8, 1, /* 4531: pointer.struct.stack_st_X509_REVOKED */
            	4536, 0,
            0, 32, 2, /* 4536: struct.stack_st_fake_X509_REVOKED */
            	4543, 8,
            	344, 24,
            8884099, 8, 2, /* 4543: pointer_to_array_of_pointers_to_stack */
            	4550, 0,
            	341, 20,
            0, 8, 1, /* 4550: pointer.X509_REVOKED */
            	3679, 0,
            1, 8, 1, /* 4555: pointer.struct.stack_st_X509_ALGOR */
            	4560, 0,
            0, 32, 2, /* 4560: struct.stack_st_fake_X509_ALGOR */
            	4567, 8,
            	344, 24,
            8884099, 8, 2, /* 4567: pointer_to_array_of_pointers_to_stack */
            	4574, 0,
            	341, 20,
            0, 8, 1, /* 4574: pointer.X509_ALGOR */
            	3650, 0,
            1, 8, 1, /* 4579: pointer.struct.stack_st_ASN1_OBJECT */
            	4584, 0,
            0, 32, 2, /* 4584: struct.stack_st_fake_ASN1_OBJECT */
            	4591, 8,
            	344, 24,
            8884099, 8, 2, /* 4591: pointer_to_array_of_pointers_to_stack */
            	4598, 0,
            	341, 20,
            0, 8, 1, /* 4598: pointer.ASN1_OBJECT */
            	2990, 0,
            0, 40, 5, /* 4603: struct.x509_cert_aux_st */
            	4579, 0,
            	4579, 8,
            	4616, 16,
            	4626, 24,
            	4555, 32,
            1, 8, 1, /* 4616: pointer.struct.asn1_string_st */
            	4621, 0,
            0, 24, 1, /* 4621: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 4626: pointer.struct.asn1_string_st */
            	4621, 0,
            1, 8, 1, /* 4631: pointer.struct.x509_cert_aux_st */
            	4603, 0,
            1, 8, 1, /* 4636: pointer.struct.NAME_CONSTRAINTS_st */
            	3272, 0,
            1, 8, 1, /* 4641: pointer.struct.stack_st_GENERAL_NAME */
            	4646, 0,
            0, 32, 2, /* 4646: struct.stack_st_fake_GENERAL_NAME */
            	4653, 8,
            	344, 24,
            8884099, 8, 2, /* 4653: pointer_to_array_of_pointers_to_stack */
            	4660, 0,
            	341, 20,
            0, 8, 1, /* 4660: pointer.GENERAL_NAME */
            	2398, 0,
            1, 8, 1, /* 4665: pointer.struct.X509_POLICY_CACHE_st */
            	2678, 0,
            1, 8, 1, /* 4670: pointer.struct.asn1_string_st */
            	4444, 0,
            1, 8, 1, /* 4675: pointer.struct.AUTHORITY_KEYID_st */
            	2355, 0,
            1, 8, 1, /* 4680: pointer.struct.X509_crl_st */
            	3758, 0,
            0, 32, 2, /* 4685: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 4692: pointer.struct.stack_st_X509_EXTENSION */
            	4697, 0,
            0, 32, 2, /* 4697: struct.stack_st_fake_X509_EXTENSION */
            	4704, 8,
            	344, 24,
            8884099, 8, 2, /* 4704: pointer_to_array_of_pointers_to_stack */
            	4711, 0,
            	341, 20,
            0, 8, 1, /* 4711: pointer.X509_EXTENSION */
            	2282, 0,
            1, 8, 1, /* 4716: pointer.struct.asn1_string_st */
            	4621, 0,
            1, 8, 1, /* 4721: pointer.struct.asn1_string_st */
            	4621, 0,
            0, 24, 1, /* 4726: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 4731: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4736, 0,
            0, 32, 2, /* 4736: struct.stack_st_fake_X509_NAME_ENTRY */
            	4743, 8,
            	344, 24,
            8884099, 8, 2, /* 4743: pointer_to_array_of_pointers_to_stack */
            	4750, 0,
            	341, 20,
            0, 8, 1, /* 4750: pointer.X509_NAME_ENTRY */
            	305, 0,
            0, 40, 3, /* 4755: struct.X509_name_st */
            	4731, 0,
            	4764, 16,
            	77, 24,
            1, 8, 1, /* 4764: pointer.struct.buf_mem_st */
            	4726, 0,
            1, 8, 1, /* 4769: pointer.struct.X509_name_st */
            	4755, 0,
            1, 8, 1, /* 4774: pointer.struct.asn1_string_st */
            	4621, 0,
            0, 104, 11, /* 4779: struct.x509_cinf_st */
            	4774, 0,
            	4774, 8,
            	4804, 16,
            	4769, 24,
            	4809, 32,
            	4769, 40,
            	4821, 48,
            	4716, 56,
            	4716, 64,
            	4692, 72,
            	4826, 80,
            1, 8, 1, /* 4804: pointer.struct.X509_algor_st */
            	90, 0,
            1, 8, 1, /* 4809: pointer.struct.X509_val_st */
            	4814, 0,
            0, 16, 2, /* 4814: struct.X509_val_st */
            	4721, 0,
            	4721, 8,
            1, 8, 1, /* 4821: pointer.struct.X509_pubkey_st */
            	379, 0,
            0, 24, 1, /* 4826: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 4831: pointer.struct.x509_cinf_st */
            	4779, 0,
            1, 8, 1, /* 4836: pointer.struct.stack_st_X509 */
            	4841, 0,
            0, 32, 2, /* 4841: struct.stack_st_fake_X509 */
            	4848, 8,
            	344, 24,
            8884099, 8, 2, /* 4848: pointer_to_array_of_pointers_to_stack */
            	4855, 0,
            	341, 20,
            0, 8, 1, /* 4855: pointer.X509 */
            	4860, 0,
            0, 0, 1, /* 4860: X509 */
            	4865, 0,
            0, 184, 12, /* 4865: struct.x509_st */
            	4831, 0,
            	4804, 8,
            	4716, 16,
            	174, 32,
            	4892, 40,
            	4626, 104,
            	4675, 112,
            	4665, 120,
            	4907, 128,
            	4641, 136,
            	4636, 144,
            	4631, 176,
            0, 16, 1, /* 4892: struct.crypto_ex_data_st */
            	4897, 0,
            1, 8, 1, /* 4897: pointer.struct.stack_st_void */
            	4902, 0,
            0, 32, 1, /* 4902: struct.stack_st_void */
            	4685, 0,
            1, 8, 1, /* 4907: pointer.struct.stack_st_DIST_POINT */
            	4912, 0,
            0, 32, 2, /* 4912: struct.stack_st_fake_DIST_POINT */
            	4919, 8,
            	344, 24,
            8884099, 8, 2, /* 4919: pointer_to_array_of_pointers_to_stack */
            	4926, 0,
            	341, 20,
            0, 8, 1, /* 4926: pointer.DIST_POINT */
            	3128, 0,
            8884097, 8, 0, /* 4931: pointer.func */
            8884097, 8, 0, /* 4934: pointer.func */
            8884097, 8, 0, /* 4937: pointer.func */
            8884097, 8, 0, /* 4940: pointer.func */
            8884097, 8, 0, /* 4943: pointer.func */
            8884097, 8, 0, /* 4946: pointer.func */
            8884097, 8, 0, /* 4949: pointer.func */
            8884097, 8, 0, /* 4952: pointer.func */
            1, 8, 1, /* 4955: pointer.struct.stack_st_X509_LOOKUP */
            	4960, 0,
            0, 32, 2, /* 4960: struct.stack_st_fake_X509_LOOKUP */
            	4967, 8,
            	344, 24,
            8884099, 8, 2, /* 4967: pointer_to_array_of_pointers_to_stack */
            	4974, 0,
            	341, 20,
            0, 8, 1, /* 4974: pointer.X509_LOOKUP */
            	4979, 0,
            0, 0, 1, /* 4979: X509_LOOKUP */
            	4984, 0,
            0, 32, 3, /* 4984: struct.x509_lookup_st */
            	4993, 8,
            	174, 16,
            	5042, 24,
            1, 8, 1, /* 4993: pointer.struct.x509_lookup_method_st */
            	4998, 0,
            0, 80, 10, /* 4998: struct.x509_lookup_method_st */
            	111, 0,
            	5021, 8,
            	5024, 16,
            	5021, 24,
            	5021, 32,
            	5027, 40,
            	5030, 48,
            	5033, 56,
            	5036, 64,
            	5039, 72,
            8884097, 8, 0, /* 5021: pointer.func */
            8884097, 8, 0, /* 5024: pointer.func */
            8884097, 8, 0, /* 5027: pointer.func */
            8884097, 8, 0, /* 5030: pointer.func */
            8884097, 8, 0, /* 5033: pointer.func */
            8884097, 8, 0, /* 5036: pointer.func */
            8884097, 8, 0, /* 5039: pointer.func */
            1, 8, 1, /* 5042: pointer.struct.x509_store_st */
            	5047, 0,
            0, 144, 15, /* 5047: struct.x509_store_st */
            	5080, 8,
            	4955, 16,
            	5626, 24,
            	4952, 32,
            	4949, 40,
            	5638, 48,
            	5641, 56,
            	4952, 64,
            	5644, 72,
            	5647, 80,
            	5650, 88,
            	4946, 96,
            	5653, 104,
            	4952, 112,
            	5306, 120,
            1, 8, 1, /* 5080: pointer.struct.stack_st_X509_OBJECT */
            	5085, 0,
            0, 32, 2, /* 5085: struct.stack_st_fake_X509_OBJECT */
            	5092, 8,
            	344, 24,
            8884099, 8, 2, /* 5092: pointer_to_array_of_pointers_to_stack */
            	5099, 0,
            	341, 20,
            0, 8, 1, /* 5099: pointer.X509_OBJECT */
            	5104, 0,
            0, 0, 1, /* 5104: X509_OBJECT */
            	5109, 0,
            0, 16, 1, /* 5109: struct.x509_object_st */
            	5114, 8,
            0, 8, 4, /* 5114: union.unknown */
            	174, 0,
            	5125, 0,
            	5462, 0,
            	5543, 0,
            1, 8, 1, /* 5125: pointer.struct.x509_st */
            	5130, 0,
            0, 184, 12, /* 5130: struct.x509_st */
            	5157, 0,
            	5197, 8,
            	5272, 16,
            	174, 32,
            	5306, 40,
            	5328, 104,
            	5333, 112,
            	2673, 120,
            	5338, 128,
            	5362, 136,
            	5386, 144,
            	5391, 176,
            1, 8, 1, /* 5157: pointer.struct.x509_cinf_st */
            	5162, 0,
            0, 104, 11, /* 5162: struct.x509_cinf_st */
            	5187, 0,
            	5187, 8,
            	5197, 16,
            	5202, 24,
            	5250, 32,
            	5202, 40,
            	5267, 48,
            	5272, 56,
            	5272, 64,
            	5277, 72,
            	5301, 80,
            1, 8, 1, /* 5187: pointer.struct.asn1_string_st */
            	5192, 0,
            0, 24, 1, /* 5192: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 5197: pointer.struct.X509_algor_st */
            	90, 0,
            1, 8, 1, /* 5202: pointer.struct.X509_name_st */
            	5207, 0,
            0, 40, 3, /* 5207: struct.X509_name_st */
            	5216, 0,
            	5240, 16,
            	77, 24,
            1, 8, 1, /* 5216: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5221, 0,
            0, 32, 2, /* 5221: struct.stack_st_fake_X509_NAME_ENTRY */
            	5228, 8,
            	344, 24,
            8884099, 8, 2, /* 5228: pointer_to_array_of_pointers_to_stack */
            	5235, 0,
            	341, 20,
            0, 8, 1, /* 5235: pointer.X509_NAME_ENTRY */
            	305, 0,
            1, 8, 1, /* 5240: pointer.struct.buf_mem_st */
            	5245, 0,
            0, 24, 1, /* 5245: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 5250: pointer.struct.X509_val_st */
            	5255, 0,
            0, 16, 2, /* 5255: struct.X509_val_st */
            	5262, 0,
            	5262, 8,
            1, 8, 1, /* 5262: pointer.struct.asn1_string_st */
            	5192, 0,
            1, 8, 1, /* 5267: pointer.struct.X509_pubkey_st */
            	379, 0,
            1, 8, 1, /* 5272: pointer.struct.asn1_string_st */
            	5192, 0,
            1, 8, 1, /* 5277: pointer.struct.stack_st_X509_EXTENSION */
            	5282, 0,
            0, 32, 2, /* 5282: struct.stack_st_fake_X509_EXTENSION */
            	5289, 8,
            	344, 24,
            8884099, 8, 2, /* 5289: pointer_to_array_of_pointers_to_stack */
            	5296, 0,
            	341, 20,
            0, 8, 1, /* 5296: pointer.X509_EXTENSION */
            	2282, 0,
            0, 24, 1, /* 5301: struct.ASN1_ENCODING_st */
            	77, 0,
            0, 16, 1, /* 5306: struct.crypto_ex_data_st */
            	5311, 0,
            1, 8, 1, /* 5311: pointer.struct.stack_st_void */
            	5316, 0,
            0, 32, 1, /* 5316: struct.stack_st_void */
            	5321, 0,
            0, 32, 2, /* 5321: struct.stack_st */
            	863, 8,
            	344, 24,
            1, 8, 1, /* 5328: pointer.struct.asn1_string_st */
            	5192, 0,
            1, 8, 1, /* 5333: pointer.struct.AUTHORITY_KEYID_st */
            	2355, 0,
            1, 8, 1, /* 5338: pointer.struct.stack_st_DIST_POINT */
            	5343, 0,
            0, 32, 2, /* 5343: struct.stack_st_fake_DIST_POINT */
            	5350, 8,
            	344, 24,
            8884099, 8, 2, /* 5350: pointer_to_array_of_pointers_to_stack */
            	5357, 0,
            	341, 20,
            0, 8, 1, /* 5357: pointer.DIST_POINT */
            	3128, 0,
            1, 8, 1, /* 5362: pointer.struct.stack_st_GENERAL_NAME */
            	5367, 0,
            0, 32, 2, /* 5367: struct.stack_st_fake_GENERAL_NAME */
            	5374, 8,
            	344, 24,
            8884099, 8, 2, /* 5374: pointer_to_array_of_pointers_to_stack */
            	5381, 0,
            	341, 20,
            0, 8, 1, /* 5381: pointer.GENERAL_NAME */
            	2398, 0,
            1, 8, 1, /* 5386: pointer.struct.NAME_CONSTRAINTS_st */
            	3272, 0,
            1, 8, 1, /* 5391: pointer.struct.x509_cert_aux_st */
            	5396, 0,
            0, 40, 5, /* 5396: struct.x509_cert_aux_st */
            	5409, 0,
            	5409, 8,
            	5433, 16,
            	5328, 24,
            	5438, 32,
            1, 8, 1, /* 5409: pointer.struct.stack_st_ASN1_OBJECT */
            	5414, 0,
            0, 32, 2, /* 5414: struct.stack_st_fake_ASN1_OBJECT */
            	5421, 8,
            	344, 24,
            8884099, 8, 2, /* 5421: pointer_to_array_of_pointers_to_stack */
            	5428, 0,
            	341, 20,
            0, 8, 1, /* 5428: pointer.ASN1_OBJECT */
            	2990, 0,
            1, 8, 1, /* 5433: pointer.struct.asn1_string_st */
            	5192, 0,
            1, 8, 1, /* 5438: pointer.struct.stack_st_X509_ALGOR */
            	5443, 0,
            0, 32, 2, /* 5443: struct.stack_st_fake_X509_ALGOR */
            	5450, 8,
            	344, 24,
            8884099, 8, 2, /* 5450: pointer_to_array_of_pointers_to_stack */
            	5457, 0,
            	341, 20,
            0, 8, 1, /* 5457: pointer.X509_ALGOR */
            	3650, 0,
            1, 8, 1, /* 5462: pointer.struct.X509_crl_st */
            	5467, 0,
            0, 120, 10, /* 5467: struct.X509_crl_st */
            	5490, 0,
            	5197, 8,
            	5272, 16,
            	5333, 32,
            	5538, 40,
            	5187, 56,
            	5187, 64,
            	3918, 96,
            	3959, 104,
            	1088, 112,
            1, 8, 1, /* 5490: pointer.struct.X509_crl_info_st */
            	5495, 0,
            0, 80, 8, /* 5495: struct.X509_crl_info_st */
            	5187, 0,
            	5197, 8,
            	5202, 16,
            	5262, 24,
            	5262, 32,
            	5514, 40,
            	5277, 48,
            	5301, 56,
            1, 8, 1, /* 5514: pointer.struct.stack_st_X509_REVOKED */
            	5519, 0,
            0, 32, 2, /* 5519: struct.stack_st_fake_X509_REVOKED */
            	5526, 8,
            	344, 24,
            8884099, 8, 2, /* 5526: pointer_to_array_of_pointers_to_stack */
            	5533, 0,
            	341, 20,
            0, 8, 1, /* 5533: pointer.X509_REVOKED */
            	3679, 0,
            1, 8, 1, /* 5538: pointer.struct.ISSUING_DIST_POINT_st */
            	3810, 0,
            1, 8, 1, /* 5543: pointer.struct.evp_pkey_st */
            	5548, 0,
            0, 56, 4, /* 5548: struct.evp_pkey_st */
            	5559, 16,
            	5564, 24,
            	5569, 32,
            	5602, 48,
            1, 8, 1, /* 5559: pointer.struct.evp_pkey_asn1_method_st */
            	424, 0,
            1, 8, 1, /* 5564: pointer.struct.engine_st */
            	525, 0,
            0, 8, 5, /* 5569: union.unknown */
            	174, 0,
            	5582, 0,
            	5587, 0,
            	5592, 0,
            	5597, 0,
            1, 8, 1, /* 5582: pointer.struct.rsa_st */
            	891, 0,
            1, 8, 1, /* 5587: pointer.struct.dsa_st */
            	1113, 0,
            1, 8, 1, /* 5592: pointer.struct.dh_st */
            	1252, 0,
            1, 8, 1, /* 5597: pointer.struct.ec_key_st */
            	1378, 0,
            1, 8, 1, /* 5602: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5607, 0,
            0, 32, 2, /* 5607: struct.stack_st_fake_X509_ATTRIBUTE */
            	5614, 8,
            	344, 24,
            8884099, 8, 2, /* 5614: pointer_to_array_of_pointers_to_stack */
            	5621, 0,
            	341, 20,
            0, 8, 1, /* 5621: pointer.X509_ATTRIBUTE */
            	1906, 0,
            1, 8, 1, /* 5626: pointer.struct.X509_VERIFY_PARAM_st */
            	5631, 0,
            0, 56, 2, /* 5631: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	5409, 48,
            8884097, 8, 0, /* 5638: pointer.func */
            8884097, 8, 0, /* 5641: pointer.func */
            8884097, 8, 0, /* 5644: pointer.func */
            8884097, 8, 0, /* 5647: pointer.func */
            8884097, 8, 0, /* 5650: pointer.func */
            8884097, 8, 0, /* 5653: pointer.func */
            1, 8, 1, /* 5656: pointer.struct.stack_st_X509_LOOKUP */
            	5661, 0,
            0, 32, 2, /* 5661: struct.stack_st_fake_X509_LOOKUP */
            	5668, 8,
            	344, 24,
            8884099, 8, 2, /* 5668: pointer_to_array_of_pointers_to_stack */
            	5675, 0,
            	341, 20,
            0, 8, 1, /* 5675: pointer.X509_LOOKUP */
            	4979, 0,
            8884097, 8, 0, /* 5680: pointer.func */
            8884097, 8, 0, /* 5683: pointer.func */
            1, 8, 1, /* 5686: pointer.struct.X509_VERIFY_PARAM_st */
            	5691, 0,
            0, 56, 2, /* 5691: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	3597, 48,
            1, 8, 1, /* 5698: pointer.struct.stack_st_X509_OBJECT */
            	5703, 0,
            0, 32, 2, /* 5703: struct.stack_st_fake_X509_OBJECT */
            	5710, 8,
            	344, 24,
            8884099, 8, 2, /* 5710: pointer_to_array_of_pointers_to_stack */
            	5717, 0,
            	341, 20,
            0, 8, 1, /* 5717: pointer.X509_OBJECT */
            	5104, 0,
            1, 8, 1, /* 5722: pointer.struct.stack_st_GENERAL_NAMES */
            	5727, 0,
            0, 32, 2, /* 5727: struct.stack_st_fake_GENERAL_NAMES */
            	5734, 8,
            	344, 24,
            8884099, 8, 2, /* 5734: pointer_to_array_of_pointers_to_stack */
            	5741, 0,
            	341, 20,
            0, 8, 1, /* 5741: pointer.GENERAL_NAMES */
            	3942, 0,
            0, 144, 15, /* 5746: struct.x509_store_st */
            	5698, 8,
            	5656, 16,
            	5686, 24,
            	4943, 32,
            	4940, 40,
            	4937, 48,
            	5683, 56,
            	4943, 64,
            	5779, 72,
            	5782, 80,
            	4934, 88,
            	4931, 96,
            	5680, 104,
            	4943, 112,
            	2323, 120,
            8884097, 8, 0, /* 5779: pointer.func */
            8884097, 8, 0, /* 5782: pointer.func */
            0, 1, 0, /* 5785: char */
            0, 120, 10, /* 5788: struct.X509_crl_st */
            	4502, 0,
            	4526, 8,
            	4670, 16,
            	4405, 32,
            	4400, 40,
            	4497, 56,
            	4497, 64,
            	5722, 96,
            	4395, 104,
            	1088, 112,
            0, 0, 1, /* 5811: X509_CRL */
            	5788, 0,
            1, 8, 1, /* 5816: pointer.struct.x509_store_ctx_st */
            	5821, 0,
            0, 248, 25, /* 5821: struct.x509_store_ctx_st */
            	5874, 0,
            	5, 16,
            	4836, 24,
            	5879, 32,
            	5686, 40,
            	1088, 48,
            	4943, 56,
            	4940, 64,
            	4937, 72,
            	5683, 80,
            	4943, 88,
            	5779, 96,
            	5782, 104,
            	4934, 112,
            	4943, 120,
            	4931, 128,
            	5680, 136,
            	4943, 144,
            	4836, 160,
            	4390, 168,
            	5, 192,
            	5, 200,
            	4680, 208,
            	5816, 224,
            	2323, 232,
            1, 8, 1, /* 5874: pointer.struct.x509_store_st */
            	5746, 0,
            1, 8, 1, /* 5879: pointer.struct.stack_st_X509_CRL */
            	5884, 0,
            0, 32, 2, /* 5884: struct.stack_st_fake_X509_CRL */
            	5891, 8,
            	344, 24,
            8884099, 8, 2, /* 5891: pointer_to_array_of_pointers_to_stack */
            	5898, 0,
            	341, 20,
            0, 8, 1, /* 5898: pointer.X509_CRL */
            	5811, 0,
        },
        .arg_entity_index = { 0, 5816, 5, },
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

