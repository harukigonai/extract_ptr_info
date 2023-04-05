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
            	189, 16,
            	174, 32,
            	538, 40,
            	194, 104,
            	1180, 112,
            	1488, 120,
            	1496, 128,
            	1635, 136,
            	1659, 144,
            	1971, 176,
            1, 8, 1, /* 37: pointer.struct.x509_cinf_st */
            	42, 0,
            0, 104, 11, /* 42: struct.x509_cinf_st */
            	67, 0,
            	67, 8,
            	85, 16,
            	257, 24,
            	347, 32,
            	257, 40,
            	364, 48,
            	189, 56,
            	189, 64,
            	1115, 72,
            	1175, 80,
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
            	64096, 0,
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
            	67, 0,
            	184, 0,
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
            	179, 0,
            	179, 0,
            	249, 0,
            1, 8, 1, /* 174: pointer.char */
            	64096, 0,
            1, 8, 1, /* 179: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 184: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 189: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 194: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 199: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 204: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 209: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 214: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 219: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 224: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 229: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 234: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 239: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 244: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 249: pointer.struct.ASN1_VALUE_st */
            	254, 0,
            0, 0, 0, /* 254: struct.ASN1_VALUE_st */
            1, 8, 1, /* 257: pointer.struct.X509_name_st */
            	262, 0,
            0, 40, 3, /* 262: struct.X509_name_st */
            	271, 0,
            	337, 16,
            	77, 24,
            1, 8, 1, /* 271: pointer.struct.stack_st_X509_NAME_ENTRY */
            	276, 0,
            0, 32, 2, /* 276: struct.stack_st_fake_X509_NAME_ENTRY */
            	283, 8,
            	334, 24,
            64099, 8, 2, /* 283: pointer_to_array_of_pointers_to_stack */
            	290, 0,
            	331, 20,
            0, 8, 1, /* 290: pointer.X509_NAME_ENTRY */
            	295, 0,
            0, 0, 1, /* 295: X509_NAME_ENTRY */
            	300, 0,
            0, 24, 2, /* 300: struct.X509_name_entry_st */
            	307, 0,
            	321, 8,
            1, 8, 1, /* 307: pointer.struct.asn1_object_st */
            	312, 0,
            0, 40, 3, /* 312: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 321: pointer.struct.asn1_string_st */
            	326, 0,
            0, 24, 1, /* 326: struct.asn1_string_st */
            	77, 8,
            0, 4, 0, /* 331: int */
            64097, 8, 0, /* 334: pointer.func */
            1, 8, 1, /* 337: pointer.struct.buf_mem_st */
            	342, 0,
            0, 24, 1, /* 342: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 347: pointer.struct.X509_val_st */
            	352, 0,
            0, 16, 2, /* 352: struct.X509_val_st */
            	359, 0,
            	359, 8,
            1, 8, 1, /* 359: pointer.struct.asn1_string_st */
            	72, 0,
            1, 8, 1, /* 364: pointer.struct.X509_pubkey_st */
            	369, 0,
            0, 24, 3, /* 369: struct.X509_pubkey_st */
            	85, 0,
            	189, 8,
            	378, 16,
            1, 8, 1, /* 378: pointer.struct.evp_pkey_st */
            	383, 0,
            0, 56, 4, /* 383: struct.evp_pkey_st */
            	394, 16,
            	402, 24,
            	410, 32,
            	744, 48,
            1, 8, 1, /* 394: pointer.struct.evp_pkey_asn1_method_st */
            	399, 0,
            0, 0, 0, /* 399: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 402: pointer.struct.engine_st */
            	407, 0,
            0, 0, 0, /* 407: struct.engine_st */
            0, 8, 5, /* 410: union.unknown */
            	174, 0,
            	423, 0,
            	587, 0,
            	668, 0,
            	736, 0,
            1, 8, 1, /* 423: pointer.struct.rsa_st */
            	428, 0,
            0, 168, 17, /* 428: struct.rsa_st */
            	465, 16,
            	402, 24,
            	520, 32,
            	520, 40,
            	520, 48,
            	520, 56,
            	520, 64,
            	520, 72,
            	520, 80,
            	520, 88,
            	538, 96,
            	565, 120,
            	565, 128,
            	565, 136,
            	174, 144,
            	579, 152,
            	579, 160,
            1, 8, 1, /* 465: pointer.struct.rsa_meth_st */
            	470, 0,
            0, 112, 13, /* 470: struct.rsa_meth_st */
            	111, 0,
            	499, 8,
            	499, 16,
            	499, 24,
            	499, 32,
            	502, 40,
            	505, 48,
            	508, 56,
            	508, 64,
            	174, 80,
            	511, 88,
            	514, 96,
            	517, 104,
            64097, 8, 0, /* 499: pointer.func */
            64097, 8, 0, /* 502: pointer.func */
            64097, 8, 0, /* 505: pointer.func */
            64097, 8, 0, /* 508: pointer.func */
            64097, 8, 0, /* 511: pointer.func */
            64097, 8, 0, /* 514: pointer.func */
            64097, 8, 0, /* 517: pointer.func */
            1, 8, 1, /* 520: pointer.struct.bignum_st */
            	525, 0,
            0, 24, 1, /* 525: struct.bignum_st */
            	530, 0,
            1, 8, 1, /* 530: pointer.unsigned int */
            	535, 0,
            0, 4, 0, /* 535: unsigned int */
            0, 16, 1, /* 538: struct.crypto_ex_data_st */
            	543, 0,
            1, 8, 1, /* 543: pointer.struct.stack_st_void */
            	548, 0,
            0, 32, 1, /* 548: struct.stack_st_void */
            	553, 0,
            0, 32, 2, /* 553: struct.stack_st */
            	560, 8,
            	334, 24,
            1, 8, 1, /* 560: pointer.pointer.char */
            	174, 0,
            1, 8, 1, /* 565: pointer.struct.bn_mont_ctx_st */
            	570, 0,
            0, 96, 3, /* 570: struct.bn_mont_ctx_st */
            	525, 8,
            	525, 32,
            	525, 56,
            1, 8, 1, /* 579: pointer.struct.bn_blinding_st */
            	584, 0,
            0, 0, 0, /* 584: struct.bn_blinding_st */
            1, 8, 1, /* 587: pointer.struct.dsa_st */
            	592, 0,
            0, 136, 11, /* 592: struct.dsa_st */
            	520, 24,
            	520, 32,
            	520, 40,
            	520, 48,
            	520, 56,
            	520, 64,
            	520, 72,
            	565, 88,
            	538, 104,
            	617, 120,
            	402, 128,
            1, 8, 1, /* 617: pointer.struct.dsa_method */
            	622, 0,
            0, 96, 11, /* 622: struct.dsa_method */
            	111, 0,
            	647, 8,
            	650, 16,
            	653, 24,
            	656, 32,
            	659, 40,
            	662, 48,
            	662, 56,
            	174, 72,
            	665, 80,
            	662, 88,
            64097, 8, 0, /* 647: pointer.func */
            64097, 8, 0, /* 650: pointer.func */
            64097, 8, 0, /* 653: pointer.func */
            64097, 8, 0, /* 656: pointer.func */
            64097, 8, 0, /* 659: pointer.func */
            64097, 8, 0, /* 662: pointer.func */
            64097, 8, 0, /* 665: pointer.func */
            1, 8, 1, /* 668: pointer.struct.dh_st */
            	673, 0,
            0, 144, 12, /* 673: struct.dh_st */
            	520, 8,
            	520, 16,
            	520, 32,
            	520, 40,
            	565, 56,
            	520, 64,
            	520, 72,
            	77, 80,
            	520, 96,
            	538, 112,
            	700, 128,
            	402, 136,
            1, 8, 1, /* 700: pointer.struct.dh_method */
            	705, 0,
            0, 72, 8, /* 705: struct.dh_method */
            	111, 0,
            	724, 8,
            	727, 16,
            	730, 24,
            	724, 32,
            	724, 40,
            	174, 56,
            	733, 64,
            64097, 8, 0, /* 724: pointer.func */
            64097, 8, 0, /* 727: pointer.func */
            64097, 8, 0, /* 730: pointer.func */
            64097, 8, 0, /* 733: pointer.func */
            1, 8, 1, /* 736: pointer.struct.ec_key_st */
            	741, 0,
            0, 0, 0, /* 741: struct.ec_key_st */
            1, 8, 1, /* 744: pointer.struct.stack_st_X509_ATTRIBUTE */
            	749, 0,
            0, 32, 2, /* 749: struct.stack_st_fake_X509_ATTRIBUTE */
            	756, 8,
            	334, 24,
            64099, 8, 2, /* 756: pointer_to_array_of_pointers_to_stack */
            	763, 0,
            	331, 20,
            0, 8, 1, /* 763: pointer.X509_ATTRIBUTE */
            	768, 0,
            0, 0, 1, /* 768: X509_ATTRIBUTE */
            	773, 0,
            0, 24, 2, /* 773: struct.x509_attributes_st */
            	780, 0,
            	794, 16,
            1, 8, 1, /* 780: pointer.struct.asn1_object_st */
            	785, 0,
            0, 40, 3, /* 785: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            0, 8, 3, /* 794: union.unknown */
            	174, 0,
            	803, 0,
            	982, 0,
            1, 8, 1, /* 803: pointer.struct.stack_st_ASN1_TYPE */
            	808, 0,
            0, 32, 2, /* 808: struct.stack_st_fake_ASN1_TYPE */
            	815, 8,
            	334, 24,
            64099, 8, 2, /* 815: pointer_to_array_of_pointers_to_stack */
            	822, 0,
            	331, 20,
            0, 8, 1, /* 822: pointer.ASN1_TYPE */
            	827, 0,
            0, 0, 1, /* 827: ASN1_TYPE */
            	832, 0,
            0, 16, 1, /* 832: struct.asn1_type_st */
            	837, 8,
            0, 8, 20, /* 837: union.unknown */
            	174, 0,
            	880, 0,
            	890, 0,
            	904, 0,
            	909, 0,
            	914, 0,
            	919, 0,
            	924, 0,
            	929, 0,
            	934, 0,
            	939, 0,
            	944, 0,
            	949, 0,
            	954, 0,
            	959, 0,
            	964, 0,
            	969, 0,
            	880, 0,
            	880, 0,
            	974, 0,
            1, 8, 1, /* 880: pointer.struct.asn1_string_st */
            	885, 0,
            0, 24, 1, /* 885: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 890: pointer.struct.asn1_object_st */
            	895, 0,
            0, 40, 3, /* 895: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 904: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 909: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 914: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 919: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 924: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 929: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 934: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 939: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 944: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 949: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 954: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 959: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 964: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 969: pointer.struct.asn1_string_st */
            	885, 0,
            1, 8, 1, /* 974: pointer.struct.ASN1_VALUE_st */
            	979, 0,
            0, 0, 0, /* 979: struct.ASN1_VALUE_st */
            1, 8, 1, /* 982: pointer.struct.asn1_type_st */
            	987, 0,
            0, 16, 1, /* 987: struct.asn1_type_st */
            	992, 8,
            0, 8, 20, /* 992: union.unknown */
            	174, 0,
            	1035, 0,
            	780, 0,
            	1045, 0,
            	1050, 0,
            	1055, 0,
            	1060, 0,
            	1065, 0,
            	1070, 0,
            	1075, 0,
            	1080, 0,
            	1085, 0,
            	1090, 0,
            	1095, 0,
            	1100, 0,
            	1105, 0,
            	1110, 0,
            	1035, 0,
            	1035, 0,
            	249, 0,
            1, 8, 1, /* 1035: pointer.struct.asn1_string_st */
            	1040, 0,
            0, 24, 1, /* 1040: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 1045: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1050: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1055: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1060: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1065: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1070: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1075: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1080: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1085: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1090: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1095: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1100: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1105: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1110: pointer.struct.asn1_string_st */
            	1040, 0,
            1, 8, 1, /* 1115: pointer.struct.stack_st_X509_EXTENSION */
            	1120, 0,
            0, 32, 2, /* 1120: struct.stack_st_fake_X509_EXTENSION */
            	1127, 8,
            	334, 24,
            64099, 8, 2, /* 1127: pointer_to_array_of_pointers_to_stack */
            	1134, 0,
            	331, 20,
            0, 8, 1, /* 1134: pointer.X509_EXTENSION */
            	1139, 0,
            0, 0, 1, /* 1139: X509_EXTENSION */
            	1144, 0,
            0, 24, 2, /* 1144: struct.X509_extension_st */
            	1151, 0,
            	1165, 16,
            1, 8, 1, /* 1151: pointer.struct.asn1_object_st */
            	1156, 0,
            0, 40, 3, /* 1156: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 1165: pointer.struct.asn1_string_st */
            	1170, 0,
            0, 24, 1, /* 1170: struct.asn1_string_st */
            	77, 8,
            0, 24, 1, /* 1175: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 1180: pointer.struct.AUTHORITY_KEYID_st */
            	1185, 0,
            0, 24, 3, /* 1185: struct.AUTHORITY_KEYID_st */
            	194, 0,
            	1194, 8,
            	67, 16,
            1, 8, 1, /* 1194: pointer.struct.stack_st_GENERAL_NAME */
            	1199, 0,
            0, 32, 2, /* 1199: struct.stack_st_fake_GENERAL_NAME */
            	1206, 8,
            	334, 24,
            64099, 8, 2, /* 1206: pointer_to_array_of_pointers_to_stack */
            	1213, 0,
            	331, 20,
            0, 8, 1, /* 1213: pointer.GENERAL_NAME */
            	1218, 0,
            0, 0, 1, /* 1218: GENERAL_NAME */
            	1223, 0,
            0, 16, 1, /* 1223: struct.GENERAL_NAME_st */
            	1228, 8,
            0, 8, 15, /* 1228: union.unknown */
            	174, 0,
            	1261, 0,
            	1380, 0,
            	1380, 0,
            	1287, 0,
            	1428, 0,
            	1476, 0,
            	1380, 0,
            	1365, 0,
            	1273, 0,
            	1365, 0,
            	1428, 0,
            	1380, 0,
            	1273, 0,
            	1287, 0,
            1, 8, 1, /* 1261: pointer.struct.otherName_st */
            	1266, 0,
            0, 16, 2, /* 1266: struct.otherName_st */
            	1273, 0,
            	1287, 8,
            1, 8, 1, /* 1273: pointer.struct.asn1_object_st */
            	1278, 0,
            0, 40, 3, /* 1278: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 1287: pointer.struct.asn1_type_st */
            	1292, 0,
            0, 16, 1, /* 1292: struct.asn1_type_st */
            	1297, 8,
            0, 8, 20, /* 1297: union.unknown */
            	174, 0,
            	1340, 0,
            	1273, 0,
            	1350, 0,
            	1355, 0,
            	1360, 0,
            	1365, 0,
            	1370, 0,
            	1375, 0,
            	1380, 0,
            	1385, 0,
            	1390, 0,
            	1395, 0,
            	1400, 0,
            	1405, 0,
            	1410, 0,
            	1415, 0,
            	1340, 0,
            	1340, 0,
            	1420, 0,
            1, 8, 1, /* 1340: pointer.struct.asn1_string_st */
            	1345, 0,
            0, 24, 1, /* 1345: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 1350: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1355: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1360: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1365: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1370: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1375: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1380: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1385: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1390: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1395: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1400: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1405: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1410: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1415: pointer.struct.asn1_string_st */
            	1345, 0,
            1, 8, 1, /* 1420: pointer.struct.ASN1_VALUE_st */
            	1425, 0,
            0, 0, 0, /* 1425: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1428: pointer.struct.X509_name_st */
            	1433, 0,
            0, 40, 3, /* 1433: struct.X509_name_st */
            	1442, 0,
            	1466, 16,
            	77, 24,
            1, 8, 1, /* 1442: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1447, 0,
            0, 32, 2, /* 1447: struct.stack_st_fake_X509_NAME_ENTRY */
            	1454, 8,
            	334, 24,
            64099, 8, 2, /* 1454: pointer_to_array_of_pointers_to_stack */
            	1461, 0,
            	331, 20,
            0, 8, 1, /* 1461: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 1466: pointer.struct.buf_mem_st */
            	1471, 0,
            0, 24, 1, /* 1471: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 1476: pointer.struct.EDIPartyName_st */
            	1481, 0,
            0, 16, 2, /* 1481: struct.EDIPartyName_st */
            	1340, 0,
            	1340, 8,
            1, 8, 1, /* 1488: pointer.struct.X509_POLICY_CACHE_st */
            	1493, 0,
            0, 0, 0, /* 1493: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1496: pointer.struct.stack_st_DIST_POINT */
            	1501, 0,
            0, 32, 2, /* 1501: struct.stack_st_fake_DIST_POINT */
            	1508, 8,
            	334, 24,
            64099, 8, 2, /* 1508: pointer_to_array_of_pointers_to_stack */
            	1515, 0,
            	331, 20,
            0, 8, 1, /* 1515: pointer.DIST_POINT */
            	1520, 0,
            0, 0, 1, /* 1520: DIST_POINT */
            	1525, 0,
            0, 32, 3, /* 1525: struct.DIST_POINT_st */
            	1534, 0,
            	1625, 8,
            	1553, 16,
            1, 8, 1, /* 1534: pointer.struct.DIST_POINT_NAME_st */
            	1539, 0,
            0, 24, 2, /* 1539: struct.DIST_POINT_NAME_st */
            	1546, 8,
            	1601, 16,
            0, 8, 2, /* 1546: union.unknown */
            	1553, 0,
            	1577, 0,
            1, 8, 1, /* 1553: pointer.struct.stack_st_GENERAL_NAME */
            	1558, 0,
            0, 32, 2, /* 1558: struct.stack_st_fake_GENERAL_NAME */
            	1565, 8,
            	334, 24,
            64099, 8, 2, /* 1565: pointer_to_array_of_pointers_to_stack */
            	1572, 0,
            	331, 20,
            0, 8, 1, /* 1572: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 1577: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1582, 0,
            0, 32, 2, /* 1582: struct.stack_st_fake_X509_NAME_ENTRY */
            	1589, 8,
            	334, 24,
            64099, 8, 2, /* 1589: pointer_to_array_of_pointers_to_stack */
            	1596, 0,
            	331, 20,
            0, 8, 1, /* 1596: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 1601: pointer.struct.X509_name_st */
            	1606, 0,
            0, 40, 3, /* 1606: struct.X509_name_st */
            	1577, 0,
            	1615, 16,
            	77, 24,
            1, 8, 1, /* 1615: pointer.struct.buf_mem_st */
            	1620, 0,
            0, 24, 1, /* 1620: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 1625: pointer.struct.asn1_string_st */
            	1630, 0,
            0, 24, 1, /* 1630: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 1635: pointer.struct.stack_st_GENERAL_NAME */
            	1640, 0,
            0, 32, 2, /* 1640: struct.stack_st_fake_GENERAL_NAME */
            	1647, 8,
            	334, 24,
            64099, 8, 2, /* 1647: pointer_to_array_of_pointers_to_stack */
            	1654, 0,
            	331, 20,
            0, 8, 1, /* 1654: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 1659: pointer.struct.NAME_CONSTRAINTS_st */
            	1664, 0,
            0, 16, 2, /* 1664: struct.NAME_CONSTRAINTS_st */
            	1671, 0,
            	1671, 8,
            1, 8, 1, /* 1671: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1676, 0,
            0, 32, 2, /* 1676: struct.stack_st_fake_GENERAL_SUBTREE */
            	1683, 8,
            	334, 24,
            64099, 8, 2, /* 1683: pointer_to_array_of_pointers_to_stack */
            	1690, 0,
            	331, 20,
            0, 8, 1, /* 1690: pointer.GENERAL_SUBTREE */
            	1695, 0,
            0, 0, 1, /* 1695: GENERAL_SUBTREE */
            	1700, 0,
            0, 24, 3, /* 1700: struct.GENERAL_SUBTREE_st */
            	1709, 0,
            	1841, 8,
            	1841, 16,
            1, 8, 1, /* 1709: pointer.struct.GENERAL_NAME_st */
            	1714, 0,
            0, 16, 1, /* 1714: struct.GENERAL_NAME_st */
            	1719, 8,
            0, 8, 15, /* 1719: union.unknown */
            	174, 0,
            	1752, 0,
            	1871, 0,
            	1871, 0,
            	1778, 0,
            	1911, 0,
            	1959, 0,
            	1871, 0,
            	1856, 0,
            	1764, 0,
            	1856, 0,
            	1911, 0,
            	1871, 0,
            	1764, 0,
            	1778, 0,
            1, 8, 1, /* 1752: pointer.struct.otherName_st */
            	1757, 0,
            0, 16, 2, /* 1757: struct.otherName_st */
            	1764, 0,
            	1778, 8,
            1, 8, 1, /* 1764: pointer.struct.asn1_object_st */
            	1769, 0,
            0, 40, 3, /* 1769: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 1778: pointer.struct.asn1_type_st */
            	1783, 0,
            0, 16, 1, /* 1783: struct.asn1_type_st */
            	1788, 8,
            0, 8, 20, /* 1788: union.unknown */
            	174, 0,
            	1831, 0,
            	1764, 0,
            	1841, 0,
            	1846, 0,
            	1851, 0,
            	1856, 0,
            	1861, 0,
            	1866, 0,
            	1871, 0,
            	1876, 0,
            	1881, 0,
            	1886, 0,
            	1891, 0,
            	1896, 0,
            	1901, 0,
            	1906, 0,
            	1831, 0,
            	1831, 0,
            	1420, 0,
            1, 8, 1, /* 1831: pointer.struct.asn1_string_st */
            	1836, 0,
            0, 24, 1, /* 1836: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 1841: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1846: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1851: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1856: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1861: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1866: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1871: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1876: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1881: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1886: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1891: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1896: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1901: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1906: pointer.struct.asn1_string_st */
            	1836, 0,
            1, 8, 1, /* 1911: pointer.struct.X509_name_st */
            	1916, 0,
            0, 40, 3, /* 1916: struct.X509_name_st */
            	1925, 0,
            	1949, 16,
            	77, 24,
            1, 8, 1, /* 1925: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1930, 0,
            0, 32, 2, /* 1930: struct.stack_st_fake_X509_NAME_ENTRY */
            	1937, 8,
            	334, 24,
            64099, 8, 2, /* 1937: pointer_to_array_of_pointers_to_stack */
            	1944, 0,
            	331, 20,
            0, 8, 1, /* 1944: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 1949: pointer.struct.buf_mem_st */
            	1954, 0,
            0, 24, 1, /* 1954: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 1959: pointer.struct.EDIPartyName_st */
            	1964, 0,
            0, 16, 2, /* 1964: struct.EDIPartyName_st */
            	1831, 0,
            	1831, 8,
            1, 8, 1, /* 1971: pointer.struct.x509_cert_aux_st */
            	1976, 0,
            0, 40, 5, /* 1976: struct.x509_cert_aux_st */
            	1989, 0,
            	1989, 8,
            	244, 16,
            	194, 24,
            	2027, 32,
            1, 8, 1, /* 1989: pointer.struct.stack_st_ASN1_OBJECT */
            	1994, 0,
            0, 32, 2, /* 1994: struct.stack_st_fake_ASN1_OBJECT */
            	2001, 8,
            	334, 24,
            64099, 8, 2, /* 2001: pointer_to_array_of_pointers_to_stack */
            	2008, 0,
            	331, 20,
            0, 8, 1, /* 2008: pointer.ASN1_OBJECT */
            	2013, 0,
            0, 0, 1, /* 2013: ASN1_OBJECT */
            	2018, 0,
            0, 40, 3, /* 2018: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2027: pointer.struct.stack_st_X509_ALGOR */
            	2032, 0,
            0, 32, 2, /* 2032: struct.stack_st_fake_X509_ALGOR */
            	2039, 8,
            	334, 24,
            64099, 8, 2, /* 2039: pointer_to_array_of_pointers_to_stack */
            	2046, 0,
            	331, 20,
            0, 8, 1, /* 2046: pointer.X509_ALGOR */
            	2051, 0,
            0, 0, 1, /* 2051: X509_ALGOR */
            	2056, 0,
            0, 16, 2, /* 2056: struct.X509_algor_st */
            	2063, 0,
            	2077, 8,
            1, 8, 1, /* 2063: pointer.struct.asn1_object_st */
            	2068, 0,
            0, 40, 3, /* 2068: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2077: pointer.struct.asn1_type_st */
            	2082, 0,
            0, 16, 1, /* 2082: struct.asn1_type_st */
            	2087, 8,
            0, 8, 20, /* 2087: union.unknown */
            	174, 0,
            	2130, 0,
            	2063, 0,
            	2140, 0,
            	2145, 0,
            	2150, 0,
            	2155, 0,
            	2160, 0,
            	2165, 0,
            	2170, 0,
            	2175, 0,
            	2180, 0,
            	2185, 0,
            	2190, 0,
            	2195, 0,
            	2200, 0,
            	2205, 0,
            	2130, 0,
            	2130, 0,
            	249, 0,
            1, 8, 1, /* 2130: pointer.struct.asn1_string_st */
            	2135, 0,
            0, 24, 1, /* 2135: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2140: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2145: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2150: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2155: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2160: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2165: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2170: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2175: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2180: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2185: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2190: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2195: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2200: pointer.struct.asn1_string_st */
            	2135, 0,
            1, 8, 1, /* 2205: pointer.struct.asn1_string_st */
            	2135, 0,
            0, 8, 2, /* 2210: union.unknown */
            	1194, 0,
            	271, 0,
            0, 24, 2, /* 2217: struct.DIST_POINT_NAME_st */
            	2210, 8,
            	257, 16,
            1, 8, 1, /* 2224: pointer.struct.DIST_POINT_NAME_st */
            	2217, 0,
            1, 8, 1, /* 2229: pointer.struct.ISSUING_DIST_POINT_st */
            	2234, 0,
            0, 32, 2, /* 2234: struct.ISSUING_DIST_POINT_st */
            	2224, 0,
            	189, 16,
            0, 80, 8, /* 2241: struct.X509_crl_info_st */
            	67, 0,
            	85, 8,
            	257, 16,
            	359, 24,
            	359, 32,
            	2260, 40,
            	1115, 48,
            	1175, 56,
            1, 8, 1, /* 2260: pointer.struct.stack_st_X509_REVOKED */
            	2265, 0,
            0, 32, 2, /* 2265: struct.stack_st_fake_X509_REVOKED */
            	2272, 8,
            	334, 24,
            64099, 8, 2, /* 2272: pointer_to_array_of_pointers_to_stack */
            	2279, 0,
            	331, 20,
            0, 8, 1, /* 2279: pointer.X509_REVOKED */
            	2284, 0,
            0, 0, 1, /* 2284: X509_REVOKED */
            	2289, 0,
            0, 40, 4, /* 2289: struct.x509_revoked_st */
            	2300, 0,
            	2310, 8,
            	2315, 16,
            	2339, 24,
            1, 8, 1, /* 2300: pointer.struct.asn1_string_st */
            	2305, 0,
            0, 24, 1, /* 2305: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2310: pointer.struct.asn1_string_st */
            	2305, 0,
            1, 8, 1, /* 2315: pointer.struct.stack_st_X509_EXTENSION */
            	2320, 0,
            0, 32, 2, /* 2320: struct.stack_st_fake_X509_EXTENSION */
            	2327, 8,
            	334, 24,
            64099, 8, 2, /* 2327: pointer_to_array_of_pointers_to_stack */
            	2334, 0,
            	331, 20,
            0, 8, 1, /* 2334: pointer.X509_EXTENSION */
            	1139, 0,
            1, 8, 1, /* 2339: pointer.struct.stack_st_GENERAL_NAME */
            	2344, 0,
            0, 32, 2, /* 2344: struct.stack_st_fake_GENERAL_NAME */
            	2351, 8,
            	334, 24,
            64099, 8, 2, /* 2351: pointer_to_array_of_pointers_to_stack */
            	2358, 0,
            	331, 20,
            0, 8, 1, /* 2358: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 2363: pointer.struct.X509_crl_info_st */
            	2241, 0,
            0, 120, 10, /* 2368: struct.X509_crl_st */
            	2363, 0,
            	85, 8,
            	189, 16,
            	1180, 32,
            	2229, 40,
            	67, 56,
            	67, 64,
            	2391, 96,
            	2432, 104,
            	2440, 112,
            1, 8, 1, /* 2391: pointer.struct.stack_st_GENERAL_NAMES */
            	2396, 0,
            0, 32, 2, /* 2396: struct.stack_st_fake_GENERAL_NAMES */
            	2403, 8,
            	334, 24,
            64099, 8, 2, /* 2403: pointer_to_array_of_pointers_to_stack */
            	2410, 0,
            	331, 20,
            0, 8, 1, /* 2410: pointer.GENERAL_NAMES */
            	2415, 0,
            0, 0, 1, /* 2415: GENERAL_NAMES */
            	2420, 0,
            0, 32, 1, /* 2420: struct.stack_st_GENERAL_NAME */
            	2425, 0,
            0, 32, 2, /* 2425: struct.stack_st */
            	560, 8,
            	334, 24,
            1, 8, 1, /* 2432: pointer.struct.x509_crl_method_st */
            	2437, 0,
            0, 0, 0, /* 2437: struct.x509_crl_method_st */
            0, 8, 0, /* 2440: pointer.void */
            1, 8, 1, /* 2443: pointer.struct.X509_crl_st */
            	2368, 0,
            0, 0, 0, /* 2448: struct.X509_POLICY_TREE_st */
            1, 8, 1, /* 2451: pointer.struct.X509_POLICY_TREE_st */
            	2448, 0,
            1, 8, 1, /* 2456: pointer.struct.x509_crl_method_st */
            	2461, 0,
            0, 0, 0, /* 2461: struct.x509_crl_method_st */
            1, 8, 1, /* 2464: pointer.struct.stack_st_GENERAL_NAMES */
            	2469, 0,
            0, 32, 2, /* 2469: struct.stack_st_fake_GENERAL_NAMES */
            	2476, 8,
            	334, 24,
            64099, 8, 2, /* 2476: pointer_to_array_of_pointers_to_stack */
            	2483, 0,
            	331, 20,
            0, 8, 1, /* 2483: pointer.GENERAL_NAMES */
            	2415, 0,
            0, 0, 0, /* 2488: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2491: pointer.struct.ISSUING_DIST_POINT_st */
            	2488, 0,
            0, 0, 0, /* 2496: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 2499: pointer.struct.asn1_string_st */
            	2504, 0,
            0, 24, 1, /* 2504: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2509: pointer.struct.buf_mem_st */
            	2514, 0,
            0, 24, 1, /* 2514: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 2519: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2524, 0,
            0, 32, 2, /* 2524: struct.stack_st_fake_X509_NAME_ENTRY */
            	2531, 8,
            	334, 24,
            64099, 8, 2, /* 2531: pointer_to_array_of_pointers_to_stack */
            	2538, 0,
            	331, 20,
            0, 8, 1, /* 2538: pointer.X509_NAME_ENTRY */
            	295, 0,
            0, 40, 3, /* 2543: struct.X509_name_st */
            	2519, 0,
            	2509, 16,
            	77, 24,
            1, 8, 1, /* 2552: pointer.struct.X509_name_st */
            	2543, 0,
            0, 0, 0, /* 2557: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2560: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2565: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2570: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2575: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2580: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2585: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2590: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2595: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2600: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2605: pointer.struct.asn1_string_st */
            	2504, 0,
            0, 8, 20, /* 2610: union.unknown */
            	174, 0,
            	2605, 0,
            	2653, 0,
            	2667, 0,
            	2600, 0,
            	2595, 0,
            	2590, 0,
            	2672, 0,
            	2677, 0,
            	2682, 0,
            	2585, 0,
            	2580, 0,
            	2575, 0,
            	2570, 0,
            	2565, 0,
            	2687, 0,
            	2560, 0,
            	2605, 0,
            	2605, 0,
            	2692, 0,
            1, 8, 1, /* 2653: pointer.struct.asn1_object_st */
            	2658, 0,
            0, 40, 3, /* 2658: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2667: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2672: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2677: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2682: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2687: pointer.struct.asn1_string_st */
            	2504, 0,
            1, 8, 1, /* 2692: pointer.struct.ASN1_VALUE_st */
            	2557, 0,
            0, 16, 1, /* 2697: struct.asn1_type_st */
            	2610, 8,
            1, 8, 1, /* 2702: pointer.struct.asn1_type_st */
            	2697, 0,
            0, 16, 2, /* 2707: struct.X509_algor_st */
            	2653, 0,
            	2702, 8,
            1, 8, 1, /* 2714: pointer.struct.X509_algor_st */
            	2707, 0,
            0, 80, 8, /* 2719: struct.X509_crl_info_st */
            	2667, 0,
            	2714, 8,
            	2552, 16,
            	2499, 24,
            	2499, 32,
            	2738, 40,
            	2762, 48,
            	2786, 56,
            1, 8, 1, /* 2738: pointer.struct.stack_st_X509_REVOKED */
            	2743, 0,
            0, 32, 2, /* 2743: struct.stack_st_fake_X509_REVOKED */
            	2750, 8,
            	334, 24,
            64099, 8, 2, /* 2750: pointer_to_array_of_pointers_to_stack */
            	2757, 0,
            	331, 20,
            0, 8, 1, /* 2757: pointer.X509_REVOKED */
            	2284, 0,
            1, 8, 1, /* 2762: pointer.struct.stack_st_X509_EXTENSION */
            	2767, 0,
            0, 32, 2, /* 2767: struct.stack_st_fake_X509_EXTENSION */
            	2774, 8,
            	334, 24,
            64099, 8, 2, /* 2774: pointer_to_array_of_pointers_to_stack */
            	2781, 0,
            	331, 20,
            0, 8, 1, /* 2781: pointer.X509_EXTENSION */
            	1139, 0,
            0, 24, 1, /* 2786: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 2791: pointer.struct.X509_crl_info_st */
            	2719, 0,
            0, 120, 10, /* 2796: struct.X509_crl_st */
            	2791, 0,
            	2714, 8,
            	2595, 16,
            	2819, 32,
            	2491, 40,
            	2667, 56,
            	2667, 64,
            	2464, 96,
            	2456, 104,
            	2440, 112,
            1, 8, 1, /* 2819: pointer.struct.AUTHORITY_KEYID_st */
            	2496, 0,
            0, 0, 1, /* 2824: X509_CRL */
            	2796, 0,
            1, 8, 1, /* 2829: pointer.struct.stack_st_X509_CRL */
            	2834, 0,
            0, 32, 2, /* 2834: struct.stack_st_fake_X509_CRL */
            	2841, 8,
            	334, 24,
            64099, 8, 2, /* 2841: pointer_to_array_of_pointers_to_stack */
            	2848, 0,
            	331, 20,
            0, 8, 1, /* 2848: pointer.X509_CRL */
            	2824, 0,
            1, 8, 1, /* 2853: pointer.struct.stack_st_ASN1_OBJECT */
            	2858, 0,
            0, 32, 2, /* 2858: struct.stack_st_fake_ASN1_OBJECT */
            	2865, 8,
            	334, 24,
            64099, 8, 2, /* 2865: pointer_to_array_of_pointers_to_stack */
            	2872, 0,
            	331, 20,
            0, 8, 1, /* 2872: pointer.ASN1_OBJECT */
            	2013, 0,
            0, 40, 5, /* 2877: struct.x509_cert_aux_st */
            	2853, 0,
            	2853, 8,
            	2890, 16,
            	2900, 24,
            	2905, 32,
            1, 8, 1, /* 2890: pointer.struct.asn1_string_st */
            	2895, 0,
            0, 24, 1, /* 2895: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2900: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 2905: pointer.struct.stack_st_X509_ALGOR */
            	2910, 0,
            0, 32, 2, /* 2910: struct.stack_st_fake_X509_ALGOR */
            	2917, 8,
            	334, 24,
            64099, 8, 2, /* 2917: pointer_to_array_of_pointers_to_stack */
            	2924, 0,
            	331, 20,
            0, 8, 1, /* 2924: pointer.X509_ALGOR */
            	2051, 0,
            0, 0, 0, /* 2929: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2932: pointer.struct.NAME_CONSTRAINTS_st */
            	2929, 0,
            0, 24, 1, /* 2937: struct.buf_mem_st */
            	174, 8,
            0, 144, 12, /* 2942: struct.dh_st */
            	2969, 8,
            	2969, 16,
            	2969, 32,
            	2969, 40,
            	2979, 56,
            	2969, 64,
            	2969, 72,
            	77, 80,
            	2969, 96,
            	2993, 112,
            	3015, 128,
            	3051, 136,
            1, 8, 1, /* 2969: pointer.struct.bignum_st */
            	2974, 0,
            0, 24, 1, /* 2974: struct.bignum_st */
            	530, 0,
            1, 8, 1, /* 2979: pointer.struct.bn_mont_ctx_st */
            	2984, 0,
            0, 96, 3, /* 2984: struct.bn_mont_ctx_st */
            	2974, 8,
            	2974, 32,
            	2974, 56,
            0, 16, 1, /* 2993: struct.crypto_ex_data_st */
            	2998, 0,
            1, 8, 1, /* 2998: pointer.struct.stack_st_void */
            	3003, 0,
            0, 32, 1, /* 3003: struct.stack_st_void */
            	3008, 0,
            0, 32, 2, /* 3008: struct.stack_st */
            	560, 8,
            	334, 24,
            1, 8, 1, /* 3015: pointer.struct.dh_method */
            	3020, 0,
            0, 72, 8, /* 3020: struct.dh_method */
            	111, 0,
            	3039, 8,
            	3042, 16,
            	3045, 24,
            	3039, 32,
            	3039, 40,
            	174, 56,
            	3048, 64,
            64097, 8, 0, /* 3039: pointer.func */
            64097, 8, 0, /* 3042: pointer.func */
            64097, 8, 0, /* 3045: pointer.func */
            64097, 8, 0, /* 3048: pointer.func */
            1, 8, 1, /* 3051: pointer.struct.engine_st */
            	3056, 0,
            0, 0, 0, /* 3056: struct.engine_st */
            64097, 8, 0, /* 3059: pointer.func */
            1, 8, 1, /* 3062: pointer.struct.ASN1_VALUE_st */
            	3067, 0,
            0, 0, 0, /* 3067: struct.ASN1_VALUE_st */
            0, 16, 1, /* 3070: struct.crypto_ex_data_st */
            	3075, 0,
            1, 8, 1, /* 3075: pointer.struct.stack_st_void */
            	3080, 0,
            0, 32, 1, /* 3080: struct.stack_st_void */
            	3085, 0,
            0, 32, 2, /* 3085: struct.stack_st */
            	560, 8,
            	334, 24,
            0, 96, 11, /* 3092: struct.dsa_method */
            	111, 0,
            	3117, 8,
            	3120, 16,
            	3123, 24,
            	3126, 32,
            	3129, 40,
            	3132, 48,
            	3132, 56,
            	174, 72,
            	3135, 80,
            	3132, 88,
            64097, 8, 0, /* 3117: pointer.func */
            64097, 8, 0, /* 3120: pointer.func */
            64097, 8, 0, /* 3123: pointer.func */
            64097, 8, 0, /* 3126: pointer.func */
            64097, 8, 0, /* 3129: pointer.func */
            64097, 8, 0, /* 3132: pointer.func */
            64097, 8, 0, /* 3135: pointer.func */
            0, 16, 2, /* 3138: struct.X509_algor_st */
            	3145, 0,
            	3159, 8,
            1, 8, 1, /* 3145: pointer.struct.asn1_object_st */
            	3150, 0,
            0, 40, 3, /* 3150: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 3159: pointer.struct.asn1_type_st */
            	3164, 0,
            0, 16, 1, /* 3164: struct.asn1_type_st */
            	3169, 8,
            0, 8, 20, /* 3169: union.unknown */
            	174, 0,
            	3212, 0,
            	3145, 0,
            	3222, 0,
            	3227, 0,
            	3232, 0,
            	3237, 0,
            	3242, 0,
            	3247, 0,
            	3252, 0,
            	3257, 0,
            	3262, 0,
            	3267, 0,
            	3272, 0,
            	3277, 0,
            	3282, 0,
            	3287, 0,
            	3212, 0,
            	3212, 0,
            	249, 0,
            1, 8, 1, /* 3212: pointer.struct.asn1_string_st */
            	3217, 0,
            0, 24, 1, /* 3217: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 3222: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3227: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3232: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3237: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3242: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3247: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3252: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3257: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3262: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3267: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3272: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3277: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3282: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3287: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3292: pointer.struct.rsa_st */
            	3297, 0,
            0, 168, 17, /* 3297: struct.rsa_st */
            	3334, 16,
            	402, 24,
            	3386, 32,
            	3386, 40,
            	3386, 48,
            	3386, 56,
            	3386, 64,
            	3386, 72,
            	3386, 80,
            	3386, 88,
            	3070, 96,
            	3396, 120,
            	3396, 128,
            	3396, 136,
            	174, 144,
            	579, 152,
            	579, 160,
            1, 8, 1, /* 3334: pointer.struct.rsa_meth_st */
            	3339, 0,
            0, 112, 13, /* 3339: struct.rsa_meth_st */
            	111, 0,
            	3368, 8,
            	3368, 16,
            	3368, 24,
            	3368, 32,
            	3371, 40,
            	3374, 48,
            	3377, 56,
            	3377, 64,
            	174, 80,
            	3059, 88,
            	3380, 96,
            	3383, 104,
            64097, 8, 0, /* 3368: pointer.func */
            64097, 8, 0, /* 3371: pointer.func */
            64097, 8, 0, /* 3374: pointer.func */
            64097, 8, 0, /* 3377: pointer.func */
            64097, 8, 0, /* 3380: pointer.func */
            64097, 8, 0, /* 3383: pointer.func */
            1, 8, 1, /* 3386: pointer.struct.bignum_st */
            	3391, 0,
            0, 24, 1, /* 3391: struct.bignum_st */
            	530, 0,
            1, 8, 1, /* 3396: pointer.struct.bn_mont_ctx_st */
            	3401, 0,
            0, 96, 3, /* 3401: struct.bn_mont_ctx_st */
            	3391, 8,
            	3391, 32,
            	3391, 56,
            0, 136, 11, /* 3410: struct.dsa_st */
            	3386, 24,
            	3386, 32,
            	3386, 40,
            	3386, 48,
            	3386, 56,
            	3386, 64,
            	3386, 72,
            	3396, 88,
            	3070, 104,
            	3435, 120,
            	402, 128,
            1, 8, 1, /* 3435: pointer.struct.dsa_method */
            	3092, 0,
            64097, 8, 0, /* 3440: pointer.func */
            0, 0, 1, /* 3443: X509_LOOKUP */
            	3448, 0,
            0, 32, 3, /* 3448: struct.x509_lookup_st */
            	3457, 8,
            	174, 16,
            	3506, 24,
            1, 8, 1, /* 3457: pointer.struct.x509_lookup_method_st */
            	3462, 0,
            0, 80, 10, /* 3462: struct.x509_lookup_method_st */
            	111, 0,
            	3485, 8,
            	3488, 16,
            	3485, 24,
            	3485, 32,
            	3491, 40,
            	3494, 48,
            	3497, 56,
            	3500, 64,
            	3503, 72,
            64097, 8, 0, /* 3485: pointer.func */
            64097, 8, 0, /* 3488: pointer.func */
            64097, 8, 0, /* 3491: pointer.func */
            64097, 8, 0, /* 3494: pointer.func */
            64097, 8, 0, /* 3497: pointer.func */
            64097, 8, 0, /* 3500: pointer.func */
            64097, 8, 0, /* 3503: pointer.func */
            1, 8, 1, /* 3506: pointer.struct.x509_store_st */
            	3511, 0,
            0, 144, 15, /* 3511: struct.x509_store_st */
            	3544, 8,
            	4099, 16,
            	4123, 24,
            	4135, 32,
            	4138, 40,
            	4141, 48,
            	4144, 56,
            	4135, 64,
            	4147, 72,
            	4150, 80,
            	4153, 88,
            	4156, 96,
            	4159, 104,
            	4135, 112,
            	3070, 120,
            1, 8, 1, /* 3544: pointer.struct.stack_st_X509_OBJECT */
            	3549, 0,
            0, 32, 2, /* 3549: struct.stack_st_fake_X509_OBJECT */
            	3556, 8,
            	334, 24,
            64099, 8, 2, /* 3556: pointer_to_array_of_pointers_to_stack */
            	3563, 0,
            	331, 20,
            0, 8, 1, /* 3563: pointer.X509_OBJECT */
            	3568, 0,
            0, 0, 1, /* 3568: X509_OBJECT */
            	3573, 0,
            0, 16, 1, /* 3573: struct.x509_object_st */
            	3578, 8,
            0, 8, 4, /* 3578: union.unknown */
            	174, 0,
            	3589, 0,
            	4015, 0,
            	3730, 0,
            1, 8, 1, /* 3589: pointer.struct.x509_st */
            	3594, 0,
            0, 184, 12, /* 3594: struct.x509_st */
            	3621, 0,
            	3651, 8,
            	3232, 16,
            	174, 32,
            	3070, 40,
            	3237, 104,
            	3885, 112,
            	1488, 120,
            	3893, 128,
            	3917, 136,
            	3941, 144,
            	3949, 176,
            1, 8, 1, /* 3621: pointer.struct.x509_cinf_st */
            	3626, 0,
            0, 104, 11, /* 3626: struct.x509_cinf_st */
            	3222, 0,
            	3222, 8,
            	3651, 16,
            	3656, 24,
            	3699, 32,
            	3656, 40,
            	3716, 48,
            	3232, 56,
            	3232, 64,
            	3856, 72,
            	3880, 80,
            1, 8, 1, /* 3651: pointer.struct.X509_algor_st */
            	3138, 0,
            1, 8, 1, /* 3656: pointer.struct.X509_name_st */
            	3661, 0,
            0, 40, 3, /* 3661: struct.X509_name_st */
            	3670, 0,
            	3694, 16,
            	77, 24,
            1, 8, 1, /* 3670: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3675, 0,
            0, 32, 2, /* 3675: struct.stack_st_fake_X509_NAME_ENTRY */
            	3682, 8,
            	334, 24,
            64099, 8, 2, /* 3682: pointer_to_array_of_pointers_to_stack */
            	3689, 0,
            	331, 20,
            0, 8, 1, /* 3689: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 3694: pointer.struct.buf_mem_st */
            	2937, 0,
            1, 8, 1, /* 3699: pointer.struct.X509_val_st */
            	3704, 0,
            0, 16, 2, /* 3704: struct.X509_val_st */
            	3711, 0,
            	3711, 8,
            1, 8, 1, /* 3711: pointer.struct.asn1_string_st */
            	3217, 0,
            1, 8, 1, /* 3716: pointer.struct.X509_pubkey_st */
            	3721, 0,
            0, 24, 3, /* 3721: struct.X509_pubkey_st */
            	3651, 0,
            	3232, 8,
            	3730, 16,
            1, 8, 1, /* 3730: pointer.struct.evp_pkey_st */
            	3735, 0,
            0, 56, 4, /* 3735: struct.evp_pkey_st */
            	394, 16,
            	402, 24,
            	3746, 32,
            	3832, 48,
            0, 8, 5, /* 3746: union.unknown */
            	174, 0,
            	3292, 0,
            	3759, 0,
            	3764, 0,
            	736, 0,
            1, 8, 1, /* 3759: pointer.struct.dsa_st */
            	3410, 0,
            1, 8, 1, /* 3764: pointer.struct.dh_st */
            	3769, 0,
            0, 144, 12, /* 3769: struct.dh_st */
            	3386, 8,
            	3386, 16,
            	3386, 32,
            	3386, 40,
            	3396, 56,
            	3386, 64,
            	3386, 72,
            	77, 80,
            	3386, 96,
            	3070, 112,
            	3796, 128,
            	402, 136,
            1, 8, 1, /* 3796: pointer.struct.dh_method */
            	3801, 0,
            0, 72, 8, /* 3801: struct.dh_method */
            	111, 0,
            	3820, 8,
            	3823, 16,
            	3826, 24,
            	3820, 32,
            	3820, 40,
            	174, 56,
            	3829, 64,
            64097, 8, 0, /* 3820: pointer.func */
            64097, 8, 0, /* 3823: pointer.func */
            64097, 8, 0, /* 3826: pointer.func */
            64097, 8, 0, /* 3829: pointer.func */
            1, 8, 1, /* 3832: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3837, 0,
            0, 32, 2, /* 3837: struct.stack_st_fake_X509_ATTRIBUTE */
            	3844, 8,
            	334, 24,
            64099, 8, 2, /* 3844: pointer_to_array_of_pointers_to_stack */
            	3851, 0,
            	331, 20,
            0, 8, 1, /* 3851: pointer.X509_ATTRIBUTE */
            	768, 0,
            1, 8, 1, /* 3856: pointer.struct.stack_st_X509_EXTENSION */
            	3861, 0,
            0, 32, 2, /* 3861: struct.stack_st_fake_X509_EXTENSION */
            	3868, 8,
            	334, 24,
            64099, 8, 2, /* 3868: pointer_to_array_of_pointers_to_stack */
            	3875, 0,
            	331, 20,
            0, 8, 1, /* 3875: pointer.X509_EXTENSION */
            	1139, 0,
            0, 24, 1, /* 3880: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 3885: pointer.struct.AUTHORITY_KEYID_st */
            	3890, 0,
            0, 0, 0, /* 3890: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3893: pointer.struct.stack_st_DIST_POINT */
            	3898, 0,
            0, 32, 2, /* 3898: struct.stack_st_fake_DIST_POINT */
            	3905, 8,
            	334, 24,
            64099, 8, 2, /* 3905: pointer_to_array_of_pointers_to_stack */
            	3912, 0,
            	331, 20,
            0, 8, 1, /* 3912: pointer.DIST_POINT */
            	1520, 0,
            1, 8, 1, /* 3917: pointer.struct.stack_st_GENERAL_NAME */
            	3922, 0,
            0, 32, 2, /* 3922: struct.stack_st_fake_GENERAL_NAME */
            	3929, 8,
            	334, 24,
            64099, 8, 2, /* 3929: pointer_to_array_of_pointers_to_stack */
            	3936, 0,
            	331, 20,
            0, 8, 1, /* 3936: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 3941: pointer.struct.NAME_CONSTRAINTS_st */
            	3946, 0,
            0, 0, 0, /* 3946: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3949: pointer.struct.x509_cert_aux_st */
            	3954, 0,
            0, 40, 5, /* 3954: struct.x509_cert_aux_st */
            	3967, 0,
            	3967, 8,
            	3287, 16,
            	3237, 24,
            	3991, 32,
            1, 8, 1, /* 3967: pointer.struct.stack_st_ASN1_OBJECT */
            	3972, 0,
            0, 32, 2, /* 3972: struct.stack_st_fake_ASN1_OBJECT */
            	3979, 8,
            	334, 24,
            64099, 8, 2, /* 3979: pointer_to_array_of_pointers_to_stack */
            	3986, 0,
            	331, 20,
            0, 8, 1, /* 3986: pointer.ASN1_OBJECT */
            	2013, 0,
            1, 8, 1, /* 3991: pointer.struct.stack_st_X509_ALGOR */
            	3996, 0,
            0, 32, 2, /* 3996: struct.stack_st_fake_X509_ALGOR */
            	4003, 8,
            	334, 24,
            64099, 8, 2, /* 4003: pointer_to_array_of_pointers_to_stack */
            	4010, 0,
            	331, 20,
            0, 8, 1, /* 4010: pointer.X509_ALGOR */
            	2051, 0,
            1, 8, 1, /* 4015: pointer.struct.X509_crl_st */
            	4020, 0,
            0, 120, 10, /* 4020: struct.X509_crl_st */
            	4043, 0,
            	3651, 8,
            	3232, 16,
            	3885, 32,
            	4091, 40,
            	3222, 56,
            	3222, 64,
            	2391, 96,
            	2432, 104,
            	2440, 112,
            1, 8, 1, /* 4043: pointer.struct.X509_crl_info_st */
            	4048, 0,
            0, 80, 8, /* 4048: struct.X509_crl_info_st */
            	3222, 0,
            	3651, 8,
            	3656, 16,
            	3711, 24,
            	3711, 32,
            	4067, 40,
            	3856, 48,
            	3880, 56,
            1, 8, 1, /* 4067: pointer.struct.stack_st_X509_REVOKED */
            	4072, 0,
            0, 32, 2, /* 4072: struct.stack_st_fake_X509_REVOKED */
            	4079, 8,
            	334, 24,
            64099, 8, 2, /* 4079: pointer_to_array_of_pointers_to_stack */
            	4086, 0,
            	331, 20,
            0, 8, 1, /* 4086: pointer.X509_REVOKED */
            	2284, 0,
            1, 8, 1, /* 4091: pointer.struct.ISSUING_DIST_POINT_st */
            	4096, 0,
            0, 0, 0, /* 4096: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 4099: pointer.struct.stack_st_X509_LOOKUP */
            	4104, 0,
            0, 32, 2, /* 4104: struct.stack_st_fake_X509_LOOKUP */
            	4111, 8,
            	334, 24,
            64099, 8, 2, /* 4111: pointer_to_array_of_pointers_to_stack */
            	4118, 0,
            	331, 20,
            0, 8, 1, /* 4118: pointer.X509_LOOKUP */
            	3443, 0,
            1, 8, 1, /* 4123: pointer.struct.X509_VERIFY_PARAM_st */
            	4128, 0,
            0, 56, 2, /* 4128: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	3967, 48,
            64097, 8, 0, /* 4135: pointer.func */
            64097, 8, 0, /* 4138: pointer.func */
            64097, 8, 0, /* 4141: pointer.func */
            64097, 8, 0, /* 4144: pointer.func */
            64097, 8, 0, /* 4147: pointer.func */
            64097, 8, 0, /* 4150: pointer.func */
            64097, 8, 0, /* 4153: pointer.func */
            64097, 8, 0, /* 4156: pointer.func */
            64097, 8, 0, /* 4159: pointer.func */
            64097, 8, 0, /* 4162: pointer.func */
            0, 248, 25, /* 4165: struct.x509_store_ctx_st */
            	4218, 0,
            	5, 16,
            	4340, 24,
            	2829, 32,
            	4304, 40,
            	2440, 48,
            	4316, 56,
            	4319, 64,
            	3440, 72,
            	4322, 80,
            	4316, 88,
            	4325, 96,
            	4328, 104,
            	4331, 112,
            	4316, 120,
            	4334, 128,
            	4337, 136,
            	4316, 144,
            	4340, 160,
            	2451, 168,
            	5, 192,
            	5, 200,
            	2443, 208,
            	5004, 224,
            	538, 232,
            1, 8, 1, /* 4218: pointer.struct.x509_store_st */
            	4223, 0,
            0, 144, 15, /* 4223: struct.x509_store_st */
            	4256, 8,
            	4280, 16,
            	4304, 24,
            	4316, 32,
            	4319, 40,
            	3440, 48,
            	4322, 56,
            	4316, 64,
            	4325, 72,
            	4328, 80,
            	4331, 88,
            	4334, 96,
            	4337, 104,
            	4316, 112,
            	538, 120,
            1, 8, 1, /* 4256: pointer.struct.stack_st_X509_OBJECT */
            	4261, 0,
            0, 32, 2, /* 4261: struct.stack_st_fake_X509_OBJECT */
            	4268, 8,
            	334, 24,
            64099, 8, 2, /* 4268: pointer_to_array_of_pointers_to_stack */
            	4275, 0,
            	331, 20,
            0, 8, 1, /* 4275: pointer.X509_OBJECT */
            	3568, 0,
            1, 8, 1, /* 4280: pointer.struct.stack_st_X509_LOOKUP */
            	4285, 0,
            0, 32, 2, /* 4285: struct.stack_st_fake_X509_LOOKUP */
            	4292, 8,
            	334, 24,
            64099, 8, 2, /* 4292: pointer_to_array_of_pointers_to_stack */
            	4299, 0,
            	331, 20,
            0, 8, 1, /* 4299: pointer.X509_LOOKUP */
            	3443, 0,
            1, 8, 1, /* 4304: pointer.struct.X509_VERIFY_PARAM_st */
            	4309, 0,
            0, 56, 2, /* 4309: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	1989, 48,
            64097, 8, 0, /* 4316: pointer.func */
            64097, 8, 0, /* 4319: pointer.func */
            64097, 8, 0, /* 4322: pointer.func */
            64097, 8, 0, /* 4325: pointer.func */
            64097, 8, 0, /* 4328: pointer.func */
            64097, 8, 0, /* 4331: pointer.func */
            64097, 8, 0, /* 4334: pointer.func */
            64097, 8, 0, /* 4337: pointer.func */
            1, 8, 1, /* 4340: pointer.struct.stack_st_X509 */
            	4345, 0,
            0, 32, 2, /* 4345: struct.stack_st_fake_X509 */
            	4352, 8,
            	334, 24,
            64099, 8, 2, /* 4352: pointer_to_array_of_pointers_to_stack */
            	4359, 0,
            	331, 20,
            0, 8, 1, /* 4359: pointer.X509 */
            	4364, 0,
            0, 0, 1, /* 4364: X509 */
            	4369, 0,
            0, 184, 12, /* 4369: struct.x509_st */
            	4396, 0,
            	4431, 8,
            	4520, 16,
            	174, 32,
            	2993, 40,
            	2900, 104,
            	4935, 112,
            	4943, 120,
            	4951, 128,
            	4975, 136,
            	2932, 144,
            	4999, 176,
            1, 8, 1, /* 4396: pointer.struct.x509_cinf_st */
            	4401, 0,
            0, 104, 11, /* 4401: struct.x509_cinf_st */
            	4426, 0,
            	4426, 8,
            	4431, 16,
            	4570, 24,
            	4618, 32,
            	4570, 40,
            	4635, 48,
            	4520, 56,
            	4520, 64,
            	4906, 72,
            	4930, 80,
            1, 8, 1, /* 4426: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4431: pointer.struct.X509_algor_st */
            	4436, 0,
            0, 16, 2, /* 4436: struct.X509_algor_st */
            	4443, 0,
            	4457, 8,
            1, 8, 1, /* 4443: pointer.struct.asn1_object_st */
            	4448, 0,
            0, 40, 3, /* 4448: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 4457: pointer.struct.asn1_type_st */
            	4462, 0,
            0, 16, 1, /* 4462: struct.asn1_type_st */
            	4467, 8,
            0, 8, 20, /* 4467: union.unknown */
            	174, 0,
            	4510, 0,
            	4443, 0,
            	4426, 0,
            	4515, 0,
            	4520, 0,
            	2900, 0,
            	4525, 0,
            	4530, 0,
            	4535, 0,
            	4540, 0,
            	4545, 0,
            	4550, 0,
            	4555, 0,
            	4560, 0,
            	4565, 0,
            	2890, 0,
            	4510, 0,
            	4510, 0,
            	3062, 0,
            1, 8, 1, /* 4510: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4515: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4520: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4525: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4530: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4535: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4540: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4545: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4550: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4555: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4560: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4565: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4570: pointer.struct.X509_name_st */
            	4575, 0,
            0, 40, 3, /* 4575: struct.X509_name_st */
            	4584, 0,
            	4608, 16,
            	77, 24,
            1, 8, 1, /* 4584: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4589, 0,
            0, 32, 2, /* 4589: struct.stack_st_fake_X509_NAME_ENTRY */
            	4596, 8,
            	334, 24,
            64099, 8, 2, /* 4596: pointer_to_array_of_pointers_to_stack */
            	4603, 0,
            	331, 20,
            0, 8, 1, /* 4603: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 4608: pointer.struct.buf_mem_st */
            	4613, 0,
            0, 24, 1, /* 4613: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 4618: pointer.struct.X509_val_st */
            	4623, 0,
            0, 16, 2, /* 4623: struct.X509_val_st */
            	4630, 0,
            	4630, 8,
            1, 8, 1, /* 4630: pointer.struct.asn1_string_st */
            	2895, 0,
            1, 8, 1, /* 4635: pointer.struct.X509_pubkey_st */
            	4640, 0,
            0, 24, 3, /* 4640: struct.X509_pubkey_st */
            	4431, 0,
            	4520, 8,
            	4649, 16,
            1, 8, 1, /* 4649: pointer.struct.evp_pkey_st */
            	4654, 0,
            0, 56, 4, /* 4654: struct.evp_pkey_st */
            	4665, 16,
            	3051, 24,
            	4673, 32,
            	4882, 48,
            1, 8, 1, /* 4665: pointer.struct.evp_pkey_asn1_method_st */
            	4670, 0,
            0, 0, 0, /* 4670: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 4673: union.unknown */
            	174, 0,
            	4686, 0,
            	4791, 0,
            	4869, 0,
            	4874, 0,
            1, 8, 1, /* 4686: pointer.struct.rsa_st */
            	4691, 0,
            0, 168, 17, /* 4691: struct.rsa_st */
            	4728, 16,
            	3051, 24,
            	2969, 32,
            	2969, 40,
            	2969, 48,
            	2969, 56,
            	2969, 64,
            	2969, 72,
            	2969, 80,
            	2969, 88,
            	2993, 96,
            	2979, 120,
            	2979, 128,
            	2979, 136,
            	174, 144,
            	4783, 152,
            	4783, 160,
            1, 8, 1, /* 4728: pointer.struct.rsa_meth_st */
            	4733, 0,
            0, 112, 13, /* 4733: struct.rsa_meth_st */
            	111, 0,
            	4762, 8,
            	4762, 16,
            	4762, 24,
            	4762, 32,
            	4765, 40,
            	4768, 48,
            	4771, 56,
            	4771, 64,
            	174, 80,
            	4774, 88,
            	4777, 96,
            	4780, 104,
            64097, 8, 0, /* 4762: pointer.func */
            64097, 8, 0, /* 4765: pointer.func */
            64097, 8, 0, /* 4768: pointer.func */
            64097, 8, 0, /* 4771: pointer.func */
            64097, 8, 0, /* 4774: pointer.func */
            64097, 8, 0, /* 4777: pointer.func */
            64097, 8, 0, /* 4780: pointer.func */
            1, 8, 1, /* 4783: pointer.struct.bn_blinding_st */
            	4788, 0,
            0, 0, 0, /* 4788: struct.bn_blinding_st */
            1, 8, 1, /* 4791: pointer.struct.dsa_st */
            	4796, 0,
            0, 136, 11, /* 4796: struct.dsa_st */
            	2969, 24,
            	2969, 32,
            	2969, 40,
            	2969, 48,
            	2969, 56,
            	2969, 64,
            	2969, 72,
            	2979, 88,
            	2993, 104,
            	4821, 120,
            	3051, 128,
            1, 8, 1, /* 4821: pointer.struct.dsa_method */
            	4826, 0,
            0, 96, 11, /* 4826: struct.dsa_method */
            	111, 0,
            	4851, 8,
            	4854, 16,
            	4857, 24,
            	4162, 32,
            	4860, 40,
            	4863, 48,
            	4863, 56,
            	174, 72,
            	4866, 80,
            	4863, 88,
            64097, 8, 0, /* 4851: pointer.func */
            64097, 8, 0, /* 4854: pointer.func */
            64097, 8, 0, /* 4857: pointer.func */
            64097, 8, 0, /* 4860: pointer.func */
            64097, 8, 0, /* 4863: pointer.func */
            64097, 8, 0, /* 4866: pointer.func */
            1, 8, 1, /* 4869: pointer.struct.dh_st */
            	2942, 0,
            1, 8, 1, /* 4874: pointer.struct.ec_key_st */
            	4879, 0,
            0, 0, 0, /* 4879: struct.ec_key_st */
            1, 8, 1, /* 4882: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4887, 0,
            0, 32, 2, /* 4887: struct.stack_st_fake_X509_ATTRIBUTE */
            	4894, 8,
            	334, 24,
            64099, 8, 2, /* 4894: pointer_to_array_of_pointers_to_stack */
            	4901, 0,
            	331, 20,
            0, 8, 1, /* 4901: pointer.X509_ATTRIBUTE */
            	768, 0,
            1, 8, 1, /* 4906: pointer.struct.stack_st_X509_EXTENSION */
            	4911, 0,
            0, 32, 2, /* 4911: struct.stack_st_fake_X509_EXTENSION */
            	4918, 8,
            	334, 24,
            64099, 8, 2, /* 4918: pointer_to_array_of_pointers_to_stack */
            	4925, 0,
            	331, 20,
            0, 8, 1, /* 4925: pointer.X509_EXTENSION */
            	1139, 0,
            0, 24, 1, /* 4930: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 4935: pointer.struct.AUTHORITY_KEYID_st */
            	4940, 0,
            0, 0, 0, /* 4940: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4943: pointer.struct.X509_POLICY_CACHE_st */
            	4948, 0,
            0, 0, 0, /* 4948: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4951: pointer.struct.stack_st_DIST_POINT */
            	4956, 0,
            0, 32, 2, /* 4956: struct.stack_st_fake_DIST_POINT */
            	4963, 8,
            	334, 24,
            64099, 8, 2, /* 4963: pointer_to_array_of_pointers_to_stack */
            	4970, 0,
            	331, 20,
            0, 8, 1, /* 4970: pointer.DIST_POINT */
            	1520, 0,
            1, 8, 1, /* 4975: pointer.struct.stack_st_GENERAL_NAME */
            	4980, 0,
            0, 32, 2, /* 4980: struct.stack_st_fake_GENERAL_NAME */
            	4987, 8,
            	334, 24,
            64099, 8, 2, /* 4987: pointer_to_array_of_pointers_to_stack */
            	4994, 0,
            	331, 20,
            0, 8, 1, /* 4994: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 4999: pointer.struct.x509_cert_aux_st */
            	2877, 0,
            1, 8, 1, /* 5004: pointer.struct.x509_store_ctx_st */
            	4165, 0,
            0, 1, 0, /* 5009: char */
        },
        .arg_entity_index = { 0, 5004, 5, },
        .ret_entity_index = 331,
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

