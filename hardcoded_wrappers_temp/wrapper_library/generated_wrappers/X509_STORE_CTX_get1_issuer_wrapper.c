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
            	8884096, 0,
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
            8884099, 8, 2, /* 283: pointer_to_array_of_pointers_to_stack */
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
            8884097, 8, 0, /* 334: pointer.func */
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
            8884097, 8, 0, /* 499: pointer.func */
            8884097, 8, 0, /* 502: pointer.func */
            8884097, 8, 0, /* 505: pointer.func */
            8884097, 8, 0, /* 508: pointer.func */
            8884097, 8, 0, /* 511: pointer.func */
            8884097, 8, 0, /* 514: pointer.func */
            8884097, 8, 0, /* 517: pointer.func */
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
            8884097, 8, 0, /* 647: pointer.func */
            8884097, 8, 0, /* 650: pointer.func */
            8884097, 8, 0, /* 653: pointer.func */
            8884097, 8, 0, /* 656: pointer.func */
            8884097, 8, 0, /* 659: pointer.func */
            8884097, 8, 0, /* 662: pointer.func */
            8884097, 8, 0, /* 665: pointer.func */
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
            8884097, 8, 0, /* 724: pointer.func */
            8884097, 8, 0, /* 727: pointer.func */
            8884097, 8, 0, /* 730: pointer.func */
            8884097, 8, 0, /* 733: pointer.func */
            1, 8, 1, /* 736: pointer.struct.ec_key_st */
            	741, 0,
            0, 0, 0, /* 741: struct.ec_key_st */
            1, 8, 1, /* 744: pointer.struct.stack_st_X509_ATTRIBUTE */
            	749, 0,
            0, 32, 2, /* 749: struct.stack_st_fake_X509_ATTRIBUTE */
            	756, 8,
            	334, 24,
            8884099, 8, 2, /* 756: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 815: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1127: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1206: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1454: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1508: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1565: pointer_to_array_of_pointers_to_stack */
            	1572, 0,
            	331, 20,
            0, 8, 1, /* 1572: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 1577: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1582, 0,
            0, 32, 2, /* 1582: struct.stack_st_fake_X509_NAME_ENTRY */
            	1589, 8,
            	334, 24,
            8884099, 8, 2, /* 1589: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1647: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1683: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1937: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 2001: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 2039: pointer_to_array_of_pointers_to_stack */
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
            0, 32, 2, /* 2229: struct.ISSUING_DIST_POINT_st */
            	2224, 0,
            	189, 16,
            1, 8, 1, /* 2236: pointer.struct.ISSUING_DIST_POINT_st */
            	2229, 0,
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
            8884099, 8, 2, /* 2272: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 2327: pointer_to_array_of_pointers_to_stack */
            	2334, 0,
            	331, 20,
            0, 8, 1, /* 2334: pointer.X509_EXTENSION */
            	1139, 0,
            1, 8, 1, /* 2339: pointer.struct.stack_st_GENERAL_NAME */
            	2344, 0,
            0, 32, 2, /* 2344: struct.stack_st_fake_GENERAL_NAME */
            	2351, 8,
            	334, 24,
            8884099, 8, 2, /* 2351: pointer_to_array_of_pointers_to_stack */
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
            	2236, 40,
            	67, 56,
            	67, 64,
            	2391, 96,
            	2425, 104,
            	2433, 112,
            1, 8, 1, /* 2391: pointer.struct.stack_st_GENERAL_NAMES */
            	2396, 0,
            0, 32, 2, /* 2396: struct.stack_st_fake_GENERAL_NAMES */
            	2403, 8,
            	334, 24,
            8884099, 8, 2, /* 2403: pointer_to_array_of_pointers_to_stack */
            	2410, 0,
            	331, 20,
            0, 8, 1, /* 2410: pointer.GENERAL_NAMES */
            	2415, 0,
            0, 0, 1, /* 2415: GENERAL_NAMES */
            	2420, 0,
            0, 32, 1, /* 2420: struct.stack_st_GENERAL_NAME */
            	553, 0,
            1, 8, 1, /* 2425: pointer.struct.x509_crl_method_st */
            	2430, 0,
            0, 0, 0, /* 2430: struct.x509_crl_method_st */
            0, 8, 0, /* 2433: pointer.void */
            1, 8, 1, /* 2436: pointer.struct.X509_crl_st */
            	2368, 0,
            0, 0, 0, /* 2441: struct.X509_POLICY_TREE_st */
            1, 8, 1, /* 2444: pointer.struct.X509_POLICY_TREE_st */
            	2441, 0,
            0, 24, 1, /* 2449: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 2454: pointer.struct.stack_st_X509_EXTENSION */
            	2459, 0,
            0, 32, 2, /* 2459: struct.stack_st_fake_X509_EXTENSION */
            	2466, 8,
            	334, 24,
            8884099, 8, 2, /* 2466: pointer_to_array_of_pointers_to_stack */
            	2473, 0,
            	331, 20,
            0, 8, 1, /* 2473: pointer.X509_EXTENSION */
            	1139, 0,
            1, 8, 1, /* 2478: pointer.struct.asn1_string_st */
            	2483, 0,
            0, 24, 1, /* 2483: struct.asn1_string_st */
            	77, 8,
            0, 24, 1, /* 2488: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 2493: pointer.struct.buf_mem_st */
            	2488, 0,
            1, 8, 1, /* 2498: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2503, 0,
            0, 32, 2, /* 2503: struct.stack_st_fake_X509_NAME_ENTRY */
            	2510, 8,
            	334, 24,
            8884099, 8, 2, /* 2510: pointer_to_array_of_pointers_to_stack */
            	2517, 0,
            	331, 20,
            0, 8, 1, /* 2517: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 2522: pointer.struct.X509_name_st */
            	2527, 0,
            0, 40, 3, /* 2527: struct.X509_name_st */
            	2498, 0,
            	2493, 16,
            	77, 24,
            1, 8, 1, /* 2536: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2541: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2546: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2551: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2556: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2561: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2566: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2571: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2576: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2581: pointer.struct.asn1_string_st */
            	2483, 0,
            0, 8, 20, /* 2586: union.unknown */
            	174, 0,
            	2629, 0,
            	2634, 0,
            	2648, 0,
            	2581, 0,
            	2653, 0,
            	2576, 0,
            	2658, 0,
            	2663, 0,
            	2571, 0,
            	2566, 0,
            	2561, 0,
            	2556, 0,
            	2551, 0,
            	2546, 0,
            	2541, 0,
            	2536, 0,
            	2629, 0,
            	2629, 0,
            	249, 0,
            1, 8, 1, /* 2629: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2634: pointer.struct.asn1_object_st */
            	2639, 0,
            0, 40, 3, /* 2639: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2648: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2653: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2658: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2663: pointer.struct.asn1_string_st */
            	2483, 0,
            0, 16, 1, /* 2668: struct.asn1_type_st */
            	2586, 8,
            1, 8, 1, /* 2673: pointer.struct.asn1_type_st */
            	2668, 0,
            0, 16, 2, /* 2678: struct.X509_algor_st */
            	2634, 0,
            	2673, 8,
            1, 8, 1, /* 2685: pointer.struct.X509_crl_info_st */
            	2690, 0,
            0, 80, 8, /* 2690: struct.X509_crl_info_st */
            	2648, 0,
            	2709, 8,
            	2522, 16,
            	2478, 24,
            	2478, 32,
            	2714, 40,
            	2454, 48,
            	2449, 56,
            1, 8, 1, /* 2709: pointer.struct.X509_algor_st */
            	2678, 0,
            1, 8, 1, /* 2714: pointer.struct.stack_st_X509_REVOKED */
            	2719, 0,
            0, 32, 2, /* 2719: struct.stack_st_fake_X509_REVOKED */
            	2726, 8,
            	334, 24,
            8884099, 8, 2, /* 2726: pointer_to_array_of_pointers_to_stack */
            	2733, 0,
            	331, 20,
            0, 8, 1, /* 2733: pointer.X509_REVOKED */
            	2284, 0,
            0, 120, 10, /* 2738: struct.X509_crl_st */
            	2685, 0,
            	2709, 8,
            	2653, 16,
            	2761, 32,
            	2769, 40,
            	2648, 56,
            	2648, 64,
            	2391, 96,
            	2425, 104,
            	2433, 112,
            1, 8, 1, /* 2761: pointer.struct.AUTHORITY_KEYID_st */
            	2766, 0,
            0, 0, 0, /* 2766: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 2769: pointer.struct.ISSUING_DIST_POINT_st */
            	2774, 0,
            0, 0, 0, /* 2774: struct.ISSUING_DIST_POINT_st */
            0, 0, 1, /* 2777: X509_CRL */
            	2738, 0,
            1, 8, 1, /* 2782: pointer.struct.stack_st_X509_CRL */
            	2787, 0,
            0, 32, 2, /* 2787: struct.stack_st_fake_X509_CRL */
            	2794, 8,
            	334, 24,
            8884099, 8, 2, /* 2794: pointer_to_array_of_pointers_to_stack */
            	2801, 0,
            	331, 20,
            0, 8, 1, /* 2801: pointer.X509_CRL */
            	2777, 0,
            1, 8, 1, /* 2806: pointer.struct.stack_st_ASN1_OBJECT */
            	2811, 0,
            0, 32, 2, /* 2811: struct.stack_st_fake_ASN1_OBJECT */
            	2818, 8,
            	334, 24,
            8884099, 8, 2, /* 2818: pointer_to_array_of_pointers_to_stack */
            	2825, 0,
            	331, 20,
            0, 8, 1, /* 2825: pointer.ASN1_OBJECT */
            	2013, 0,
            0, 0, 0, /* 2830: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2833: pointer.struct.NAME_CONSTRAINTS_st */
            	2830, 0,
            0, 24, 1, /* 2838: struct.buf_mem_st */
            	174, 8,
            0, 144, 12, /* 2843: struct.dh_st */
            	2870, 8,
            	2870, 16,
            	2870, 32,
            	2870, 40,
            	2880, 56,
            	2870, 64,
            	2870, 72,
            	77, 80,
            	2870, 96,
            	2894, 112,
            	2916, 128,
            	2952, 136,
            1, 8, 1, /* 2870: pointer.struct.bignum_st */
            	2875, 0,
            0, 24, 1, /* 2875: struct.bignum_st */
            	530, 0,
            1, 8, 1, /* 2880: pointer.struct.bn_mont_ctx_st */
            	2885, 0,
            0, 96, 3, /* 2885: struct.bn_mont_ctx_st */
            	2875, 8,
            	2875, 32,
            	2875, 56,
            0, 16, 1, /* 2894: struct.crypto_ex_data_st */
            	2899, 0,
            1, 8, 1, /* 2899: pointer.struct.stack_st_void */
            	2904, 0,
            0, 32, 1, /* 2904: struct.stack_st_void */
            	2909, 0,
            0, 32, 2, /* 2909: struct.stack_st */
            	560, 8,
            	334, 24,
            1, 8, 1, /* 2916: pointer.struct.dh_method */
            	2921, 0,
            0, 72, 8, /* 2921: struct.dh_method */
            	111, 0,
            	2940, 8,
            	2943, 16,
            	2946, 24,
            	2940, 32,
            	2940, 40,
            	174, 56,
            	2949, 64,
            8884097, 8, 0, /* 2940: pointer.func */
            8884097, 8, 0, /* 2943: pointer.func */
            8884097, 8, 0, /* 2946: pointer.func */
            8884097, 8, 0, /* 2949: pointer.func */
            1, 8, 1, /* 2952: pointer.struct.engine_st */
            	2957, 0,
            0, 0, 0, /* 2957: struct.engine_st */
            8884097, 8, 0, /* 2960: pointer.func */
            1, 8, 1, /* 2963: pointer.struct.ASN1_VALUE_st */
            	2968, 0,
            0, 0, 0, /* 2968: struct.ASN1_VALUE_st */
            0, 16, 1, /* 2971: struct.crypto_ex_data_st */
            	2976, 0,
            1, 8, 1, /* 2976: pointer.struct.stack_st_void */
            	2981, 0,
            0, 32, 1, /* 2981: struct.stack_st_void */
            	2986, 0,
            0, 32, 2, /* 2986: struct.stack_st */
            	560, 8,
            	334, 24,
            1, 8, 1, /* 2993: pointer.struct.X509_crl_info_st */
            	2998, 0,
            0, 80, 8, /* 2998: struct.X509_crl_info_st */
            	3017, 0,
            	3027, 8,
            	3176, 16,
            	3219, 24,
            	3219, 32,
            	3224, 40,
            	3248, 48,
            	3272, 56,
            1, 8, 1, /* 3017: pointer.struct.asn1_string_st */
            	3022, 0,
            0, 24, 1, /* 3022: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 3027: pointer.struct.X509_algor_st */
            	3032, 0,
            0, 16, 2, /* 3032: struct.X509_algor_st */
            	3039, 0,
            	3053, 8,
            1, 8, 1, /* 3039: pointer.struct.asn1_object_st */
            	3044, 0,
            0, 40, 3, /* 3044: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 3053: pointer.struct.asn1_type_st */
            	3058, 0,
            0, 16, 1, /* 3058: struct.asn1_type_st */
            	3063, 8,
            0, 8, 20, /* 3063: union.unknown */
            	174, 0,
            	3106, 0,
            	3039, 0,
            	3017, 0,
            	3111, 0,
            	3116, 0,
            	3121, 0,
            	3126, 0,
            	3131, 0,
            	3136, 0,
            	3141, 0,
            	3146, 0,
            	3151, 0,
            	3156, 0,
            	3161, 0,
            	3166, 0,
            	3171, 0,
            	3106, 0,
            	3106, 0,
            	249, 0,
            1, 8, 1, /* 3106: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3111: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3116: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3121: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3126: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3131: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3136: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3141: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3146: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3151: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3156: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3161: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3166: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3171: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3176: pointer.struct.X509_name_st */
            	3181, 0,
            0, 40, 3, /* 3181: struct.X509_name_st */
            	3190, 0,
            	3214, 16,
            	77, 24,
            1, 8, 1, /* 3190: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3195, 0,
            0, 32, 2, /* 3195: struct.stack_st_fake_X509_NAME_ENTRY */
            	3202, 8,
            	334, 24,
            8884099, 8, 2, /* 3202: pointer_to_array_of_pointers_to_stack */
            	3209, 0,
            	331, 20,
            0, 8, 1, /* 3209: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 3214: pointer.struct.buf_mem_st */
            	2838, 0,
            1, 8, 1, /* 3219: pointer.struct.asn1_string_st */
            	3022, 0,
            1, 8, 1, /* 3224: pointer.struct.stack_st_X509_REVOKED */
            	3229, 0,
            0, 32, 2, /* 3229: struct.stack_st_fake_X509_REVOKED */
            	3236, 8,
            	334, 24,
            8884099, 8, 2, /* 3236: pointer_to_array_of_pointers_to_stack */
            	3243, 0,
            	331, 20,
            0, 8, 1, /* 3243: pointer.X509_REVOKED */
            	2284, 0,
            1, 8, 1, /* 3248: pointer.struct.stack_st_X509_EXTENSION */
            	3253, 0,
            0, 32, 2, /* 3253: struct.stack_st_fake_X509_EXTENSION */
            	3260, 8,
            	334, 24,
            8884099, 8, 2, /* 3260: pointer_to_array_of_pointers_to_stack */
            	3267, 0,
            	331, 20,
            0, 8, 1, /* 3267: pointer.X509_EXTENSION */
            	1139, 0,
            0, 24, 1, /* 3272: struct.ASN1_ENCODING_st */
            	77, 0,
            0, 96, 11, /* 3277: struct.dsa_method */
            	111, 0,
            	3302, 8,
            	3305, 16,
            	3308, 24,
            	3311, 32,
            	3314, 40,
            	3317, 48,
            	3317, 56,
            	174, 72,
            	3320, 80,
            	3317, 88,
            8884097, 8, 0, /* 3302: pointer.func */
            8884097, 8, 0, /* 3305: pointer.func */
            8884097, 8, 0, /* 3308: pointer.func */
            8884097, 8, 0, /* 3311: pointer.func */
            8884097, 8, 0, /* 3314: pointer.func */
            8884097, 8, 0, /* 3317: pointer.func */
            8884097, 8, 0, /* 3320: pointer.func */
            1, 8, 1, /* 3323: pointer.struct.rsa_st */
            	3328, 0,
            0, 168, 17, /* 3328: struct.rsa_st */
            	3365, 16,
            	402, 24,
            	3417, 32,
            	3417, 40,
            	3417, 48,
            	3417, 56,
            	3417, 64,
            	3417, 72,
            	3417, 80,
            	3417, 88,
            	2971, 96,
            	3427, 120,
            	3427, 128,
            	3427, 136,
            	174, 144,
            	579, 152,
            	579, 160,
            1, 8, 1, /* 3365: pointer.struct.rsa_meth_st */
            	3370, 0,
            0, 112, 13, /* 3370: struct.rsa_meth_st */
            	111, 0,
            	3399, 8,
            	3399, 16,
            	3399, 24,
            	3399, 32,
            	3402, 40,
            	3405, 48,
            	3408, 56,
            	3408, 64,
            	174, 80,
            	2960, 88,
            	3411, 96,
            	3414, 104,
            8884097, 8, 0, /* 3399: pointer.func */
            8884097, 8, 0, /* 3402: pointer.func */
            8884097, 8, 0, /* 3405: pointer.func */
            8884097, 8, 0, /* 3408: pointer.func */
            8884097, 8, 0, /* 3411: pointer.func */
            8884097, 8, 0, /* 3414: pointer.func */
            1, 8, 1, /* 3417: pointer.struct.bignum_st */
            	3422, 0,
            0, 24, 1, /* 3422: struct.bignum_st */
            	530, 0,
            1, 8, 1, /* 3427: pointer.struct.bn_mont_ctx_st */
            	3432, 0,
            0, 96, 3, /* 3432: struct.bn_mont_ctx_st */
            	3422, 8,
            	3422, 32,
            	3422, 56,
            0, 136, 11, /* 3441: struct.dsa_st */
            	3417, 24,
            	3417, 32,
            	3417, 40,
            	3417, 48,
            	3417, 56,
            	3417, 64,
            	3417, 72,
            	3427, 88,
            	2971, 104,
            	3466, 120,
            	402, 128,
            1, 8, 1, /* 3466: pointer.struct.dsa_method */
            	3277, 0,
            8884097, 8, 0, /* 3471: pointer.func */
            0, 0, 1, /* 3474: X509_LOOKUP */
            	3479, 0,
            0, 32, 3, /* 3479: struct.x509_lookup_st */
            	3488, 8,
            	174, 16,
            	3537, 24,
            1, 8, 1, /* 3488: pointer.struct.x509_lookup_method_st */
            	3493, 0,
            0, 80, 10, /* 3493: struct.x509_lookup_method_st */
            	111, 0,
            	3516, 8,
            	3519, 16,
            	3516, 24,
            	3516, 32,
            	3522, 40,
            	3525, 48,
            	3528, 56,
            	3531, 64,
            	3534, 72,
            8884097, 8, 0, /* 3516: pointer.func */
            8884097, 8, 0, /* 3519: pointer.func */
            8884097, 8, 0, /* 3522: pointer.func */
            8884097, 8, 0, /* 3525: pointer.func */
            8884097, 8, 0, /* 3528: pointer.func */
            8884097, 8, 0, /* 3531: pointer.func */
            8884097, 8, 0, /* 3534: pointer.func */
            1, 8, 1, /* 3537: pointer.struct.x509_store_st */
            	3542, 0,
            0, 144, 15, /* 3542: struct.x509_store_st */
            	3575, 8,
            	3984, 16,
            	4008, 24,
            	4020, 32,
            	4023, 40,
            	4026, 48,
            	4029, 56,
            	4020, 64,
            	4032, 72,
            	4035, 80,
            	4038, 88,
            	4041, 96,
            	4044, 104,
            	4020, 112,
            	2971, 120,
            1, 8, 1, /* 3575: pointer.struct.stack_st_X509_OBJECT */
            	3580, 0,
            0, 32, 2, /* 3580: struct.stack_st_fake_X509_OBJECT */
            	3587, 8,
            	334, 24,
            8884099, 8, 2, /* 3587: pointer_to_array_of_pointers_to_stack */
            	3594, 0,
            	331, 20,
            0, 8, 1, /* 3594: pointer.X509_OBJECT */
            	3599, 0,
            0, 0, 1, /* 3599: X509_OBJECT */
            	3604, 0,
            0, 16, 1, /* 3604: struct.x509_object_st */
            	3609, 8,
            0, 8, 4, /* 3609: union.unknown */
            	174, 0,
            	3620, 0,
            	3956, 0,
            	3708, 0,
            1, 8, 1, /* 3620: pointer.struct.x509_st */
            	3625, 0,
            0, 184, 12, /* 3625: struct.x509_st */
            	3652, 0,
            	3027, 8,
            	3116, 16,
            	174, 32,
            	2971, 40,
            	3121, 104,
            	2761, 112,
            	1488, 120,
            	3834, 128,
            	3858, 136,
            	3882, 144,
            	3890, 176,
            1, 8, 1, /* 3652: pointer.struct.x509_cinf_st */
            	3657, 0,
            0, 104, 11, /* 3657: struct.x509_cinf_st */
            	3017, 0,
            	3017, 8,
            	3027, 16,
            	3176, 24,
            	3682, 32,
            	3176, 40,
            	3694, 48,
            	3116, 56,
            	3116, 64,
            	3248, 72,
            	3272, 80,
            1, 8, 1, /* 3682: pointer.struct.X509_val_st */
            	3687, 0,
            0, 16, 2, /* 3687: struct.X509_val_st */
            	3219, 0,
            	3219, 8,
            1, 8, 1, /* 3694: pointer.struct.X509_pubkey_st */
            	3699, 0,
            0, 24, 3, /* 3699: struct.X509_pubkey_st */
            	3027, 0,
            	3116, 8,
            	3708, 16,
            1, 8, 1, /* 3708: pointer.struct.evp_pkey_st */
            	3713, 0,
            0, 56, 4, /* 3713: struct.evp_pkey_st */
            	394, 16,
            	402, 24,
            	3724, 32,
            	3810, 48,
            0, 8, 5, /* 3724: union.unknown */
            	174, 0,
            	3323, 0,
            	3737, 0,
            	3742, 0,
            	736, 0,
            1, 8, 1, /* 3737: pointer.struct.dsa_st */
            	3441, 0,
            1, 8, 1, /* 3742: pointer.struct.dh_st */
            	3747, 0,
            0, 144, 12, /* 3747: struct.dh_st */
            	3417, 8,
            	3417, 16,
            	3417, 32,
            	3417, 40,
            	3427, 56,
            	3417, 64,
            	3417, 72,
            	77, 80,
            	3417, 96,
            	2971, 112,
            	3774, 128,
            	402, 136,
            1, 8, 1, /* 3774: pointer.struct.dh_method */
            	3779, 0,
            0, 72, 8, /* 3779: struct.dh_method */
            	111, 0,
            	3798, 8,
            	3801, 16,
            	3804, 24,
            	3798, 32,
            	3798, 40,
            	174, 56,
            	3807, 64,
            8884097, 8, 0, /* 3798: pointer.func */
            8884097, 8, 0, /* 3801: pointer.func */
            8884097, 8, 0, /* 3804: pointer.func */
            8884097, 8, 0, /* 3807: pointer.func */
            1, 8, 1, /* 3810: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3815, 0,
            0, 32, 2, /* 3815: struct.stack_st_fake_X509_ATTRIBUTE */
            	3822, 8,
            	334, 24,
            8884099, 8, 2, /* 3822: pointer_to_array_of_pointers_to_stack */
            	3829, 0,
            	331, 20,
            0, 8, 1, /* 3829: pointer.X509_ATTRIBUTE */
            	768, 0,
            1, 8, 1, /* 3834: pointer.struct.stack_st_DIST_POINT */
            	3839, 0,
            0, 32, 2, /* 3839: struct.stack_st_fake_DIST_POINT */
            	3846, 8,
            	334, 24,
            8884099, 8, 2, /* 3846: pointer_to_array_of_pointers_to_stack */
            	3853, 0,
            	331, 20,
            0, 8, 1, /* 3853: pointer.DIST_POINT */
            	1520, 0,
            1, 8, 1, /* 3858: pointer.struct.stack_st_GENERAL_NAME */
            	3863, 0,
            0, 32, 2, /* 3863: struct.stack_st_fake_GENERAL_NAME */
            	3870, 8,
            	334, 24,
            8884099, 8, 2, /* 3870: pointer_to_array_of_pointers_to_stack */
            	3877, 0,
            	331, 20,
            0, 8, 1, /* 3877: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 3882: pointer.struct.NAME_CONSTRAINTS_st */
            	3887, 0,
            0, 0, 0, /* 3887: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3890: pointer.struct.x509_cert_aux_st */
            	3895, 0,
            0, 40, 5, /* 3895: struct.x509_cert_aux_st */
            	3908, 0,
            	3908, 8,
            	3171, 16,
            	3121, 24,
            	3932, 32,
            1, 8, 1, /* 3908: pointer.struct.stack_st_ASN1_OBJECT */
            	3913, 0,
            0, 32, 2, /* 3913: struct.stack_st_fake_ASN1_OBJECT */
            	3920, 8,
            	334, 24,
            8884099, 8, 2, /* 3920: pointer_to_array_of_pointers_to_stack */
            	3927, 0,
            	331, 20,
            0, 8, 1, /* 3927: pointer.ASN1_OBJECT */
            	2013, 0,
            1, 8, 1, /* 3932: pointer.struct.stack_st_X509_ALGOR */
            	3937, 0,
            0, 32, 2, /* 3937: struct.stack_st_fake_X509_ALGOR */
            	3944, 8,
            	334, 24,
            8884099, 8, 2, /* 3944: pointer_to_array_of_pointers_to_stack */
            	3951, 0,
            	331, 20,
            0, 8, 1, /* 3951: pointer.X509_ALGOR */
            	2051, 0,
            1, 8, 1, /* 3956: pointer.struct.X509_crl_st */
            	3961, 0,
            0, 120, 10, /* 3961: struct.X509_crl_st */
            	2993, 0,
            	3027, 8,
            	3116, 16,
            	2761, 32,
            	2769, 40,
            	3017, 56,
            	3017, 64,
            	2391, 96,
            	2425, 104,
            	2433, 112,
            1, 8, 1, /* 3984: pointer.struct.stack_st_X509_LOOKUP */
            	3989, 0,
            0, 32, 2, /* 3989: struct.stack_st_fake_X509_LOOKUP */
            	3996, 8,
            	334, 24,
            8884099, 8, 2, /* 3996: pointer_to_array_of_pointers_to_stack */
            	4003, 0,
            	331, 20,
            0, 8, 1, /* 4003: pointer.X509_LOOKUP */
            	3474, 0,
            1, 8, 1, /* 4008: pointer.struct.X509_VERIFY_PARAM_st */
            	4013, 0,
            0, 56, 2, /* 4013: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	3908, 48,
            8884097, 8, 0, /* 4020: pointer.func */
            8884097, 8, 0, /* 4023: pointer.func */
            8884097, 8, 0, /* 4026: pointer.func */
            8884097, 8, 0, /* 4029: pointer.func */
            8884097, 8, 0, /* 4032: pointer.func */
            8884097, 8, 0, /* 4035: pointer.func */
            8884097, 8, 0, /* 4038: pointer.func */
            8884097, 8, 0, /* 4041: pointer.func */
            8884097, 8, 0, /* 4044: pointer.func */
            0, 40, 5, /* 4047: struct.x509_cert_aux_st */
            	2806, 0,
            	2806, 8,
            	4060, 16,
            	4070, 24,
            	4075, 32,
            1, 8, 1, /* 4060: pointer.struct.asn1_string_st */
            	4065, 0,
            0, 24, 1, /* 4065: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 4070: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4075: pointer.struct.stack_st_X509_ALGOR */
            	4080, 0,
            0, 32, 2, /* 4080: struct.stack_st_fake_X509_ALGOR */
            	4087, 8,
            	334, 24,
            8884099, 8, 2, /* 4087: pointer_to_array_of_pointers_to_stack */
            	4094, 0,
            	331, 20,
            0, 8, 1, /* 4094: pointer.X509_ALGOR */
            	2051, 0,
            8884097, 8, 0, /* 4099: pointer.func */
            0, 104, 11, /* 4102: struct.x509_cinf_st */
            	4127, 0,
            	4127, 8,
            	4132, 16,
            	4271, 24,
            	4319, 32,
            	4271, 40,
            	4336, 48,
            	4221, 56,
            	4221, 64,
            	4607, 72,
            	4631, 80,
            1, 8, 1, /* 4127: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4132: pointer.struct.X509_algor_st */
            	4137, 0,
            0, 16, 2, /* 4137: struct.X509_algor_st */
            	4144, 0,
            	4158, 8,
            1, 8, 1, /* 4144: pointer.struct.asn1_object_st */
            	4149, 0,
            0, 40, 3, /* 4149: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 4158: pointer.struct.asn1_type_st */
            	4163, 0,
            0, 16, 1, /* 4163: struct.asn1_type_st */
            	4168, 8,
            0, 8, 20, /* 4168: union.unknown */
            	174, 0,
            	4211, 0,
            	4144, 0,
            	4127, 0,
            	4216, 0,
            	4221, 0,
            	4070, 0,
            	4226, 0,
            	4231, 0,
            	4236, 0,
            	4241, 0,
            	4246, 0,
            	4251, 0,
            	4256, 0,
            	4261, 0,
            	4266, 0,
            	4060, 0,
            	4211, 0,
            	4211, 0,
            	2963, 0,
            1, 8, 1, /* 4211: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4216: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4221: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4226: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4231: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4236: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4241: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4246: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4251: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4256: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4261: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4266: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4271: pointer.struct.X509_name_st */
            	4276, 0,
            0, 40, 3, /* 4276: struct.X509_name_st */
            	4285, 0,
            	4309, 16,
            	77, 24,
            1, 8, 1, /* 4285: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4290, 0,
            0, 32, 2, /* 4290: struct.stack_st_fake_X509_NAME_ENTRY */
            	4297, 8,
            	334, 24,
            8884099, 8, 2, /* 4297: pointer_to_array_of_pointers_to_stack */
            	4304, 0,
            	331, 20,
            0, 8, 1, /* 4304: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 4309: pointer.struct.buf_mem_st */
            	4314, 0,
            0, 24, 1, /* 4314: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 4319: pointer.struct.X509_val_st */
            	4324, 0,
            0, 16, 2, /* 4324: struct.X509_val_st */
            	4331, 0,
            	4331, 8,
            1, 8, 1, /* 4331: pointer.struct.asn1_string_st */
            	4065, 0,
            1, 8, 1, /* 4336: pointer.struct.X509_pubkey_st */
            	4341, 0,
            0, 24, 3, /* 4341: struct.X509_pubkey_st */
            	4132, 0,
            	4221, 8,
            	4350, 16,
            1, 8, 1, /* 4350: pointer.struct.evp_pkey_st */
            	4355, 0,
            0, 56, 4, /* 4355: struct.evp_pkey_st */
            	4366, 16,
            	2952, 24,
            	4374, 32,
            	4583, 48,
            1, 8, 1, /* 4366: pointer.struct.evp_pkey_asn1_method_st */
            	4371, 0,
            0, 0, 0, /* 4371: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 4374: union.unknown */
            	174, 0,
            	4387, 0,
            	4492, 0,
            	4570, 0,
            	4575, 0,
            1, 8, 1, /* 4387: pointer.struct.rsa_st */
            	4392, 0,
            0, 168, 17, /* 4392: struct.rsa_st */
            	4429, 16,
            	2952, 24,
            	2870, 32,
            	2870, 40,
            	2870, 48,
            	2870, 56,
            	2870, 64,
            	2870, 72,
            	2870, 80,
            	2870, 88,
            	2894, 96,
            	2880, 120,
            	2880, 128,
            	2880, 136,
            	174, 144,
            	4484, 152,
            	4484, 160,
            1, 8, 1, /* 4429: pointer.struct.rsa_meth_st */
            	4434, 0,
            0, 112, 13, /* 4434: struct.rsa_meth_st */
            	111, 0,
            	4463, 8,
            	4463, 16,
            	4463, 24,
            	4463, 32,
            	4466, 40,
            	4469, 48,
            	4472, 56,
            	4472, 64,
            	174, 80,
            	4475, 88,
            	4478, 96,
            	4481, 104,
            8884097, 8, 0, /* 4463: pointer.func */
            8884097, 8, 0, /* 4466: pointer.func */
            8884097, 8, 0, /* 4469: pointer.func */
            8884097, 8, 0, /* 4472: pointer.func */
            8884097, 8, 0, /* 4475: pointer.func */
            8884097, 8, 0, /* 4478: pointer.func */
            8884097, 8, 0, /* 4481: pointer.func */
            1, 8, 1, /* 4484: pointer.struct.bn_blinding_st */
            	4489, 0,
            0, 0, 0, /* 4489: struct.bn_blinding_st */
            1, 8, 1, /* 4492: pointer.struct.dsa_st */
            	4497, 0,
            0, 136, 11, /* 4497: struct.dsa_st */
            	2870, 24,
            	2870, 32,
            	2870, 40,
            	2870, 48,
            	2870, 56,
            	2870, 64,
            	2870, 72,
            	2880, 88,
            	2894, 104,
            	4522, 120,
            	2952, 128,
            1, 8, 1, /* 4522: pointer.struct.dsa_method */
            	4527, 0,
            0, 96, 11, /* 4527: struct.dsa_method */
            	111, 0,
            	4552, 8,
            	4555, 16,
            	4558, 24,
            	4099, 32,
            	4561, 40,
            	4564, 48,
            	4564, 56,
            	174, 72,
            	4567, 80,
            	4564, 88,
            8884097, 8, 0, /* 4552: pointer.func */
            8884097, 8, 0, /* 4555: pointer.func */
            8884097, 8, 0, /* 4558: pointer.func */
            8884097, 8, 0, /* 4561: pointer.func */
            8884097, 8, 0, /* 4564: pointer.func */
            8884097, 8, 0, /* 4567: pointer.func */
            1, 8, 1, /* 4570: pointer.struct.dh_st */
            	2843, 0,
            1, 8, 1, /* 4575: pointer.struct.ec_key_st */
            	4580, 0,
            0, 0, 0, /* 4580: struct.ec_key_st */
            1, 8, 1, /* 4583: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4588, 0,
            0, 32, 2, /* 4588: struct.stack_st_fake_X509_ATTRIBUTE */
            	4595, 8,
            	334, 24,
            8884099, 8, 2, /* 4595: pointer_to_array_of_pointers_to_stack */
            	4602, 0,
            	331, 20,
            0, 8, 1, /* 4602: pointer.X509_ATTRIBUTE */
            	768, 0,
            1, 8, 1, /* 4607: pointer.struct.stack_st_X509_EXTENSION */
            	4612, 0,
            0, 32, 2, /* 4612: struct.stack_st_fake_X509_EXTENSION */
            	4619, 8,
            	334, 24,
            8884099, 8, 2, /* 4619: pointer_to_array_of_pointers_to_stack */
            	4626, 0,
            	331, 20,
            0, 8, 1, /* 4626: pointer.X509_EXTENSION */
            	1139, 0,
            0, 24, 1, /* 4631: struct.ASN1_ENCODING_st */
            	77, 0,
            0, 0, 0, /* 4636: struct.X509_POLICY_CACHE_st */
            0, 248, 25, /* 4639: struct.x509_store_ctx_st */
            	4692, 0,
            	5, 16,
            	4814, 24,
            	2782, 32,
            	4778, 40,
            	2433, 48,
            	4790, 56,
            	4793, 64,
            	3471, 72,
            	4796, 80,
            	4790, 88,
            	4799, 96,
            	4802, 104,
            	4805, 112,
            	4790, 120,
            	4808, 128,
            	4811, 136,
            	4790, 144,
            	4814, 160,
            	2444, 168,
            	5, 192,
            	5, 200,
            	2436, 208,
            	4941, 224,
            	538, 232,
            1, 8, 1, /* 4692: pointer.struct.x509_store_st */
            	4697, 0,
            0, 144, 15, /* 4697: struct.x509_store_st */
            	4730, 8,
            	4754, 16,
            	4778, 24,
            	4790, 32,
            	4793, 40,
            	3471, 48,
            	4796, 56,
            	4790, 64,
            	4799, 72,
            	4802, 80,
            	4805, 88,
            	4808, 96,
            	4811, 104,
            	4790, 112,
            	538, 120,
            1, 8, 1, /* 4730: pointer.struct.stack_st_X509_OBJECT */
            	4735, 0,
            0, 32, 2, /* 4735: struct.stack_st_fake_X509_OBJECT */
            	4742, 8,
            	334, 24,
            8884099, 8, 2, /* 4742: pointer_to_array_of_pointers_to_stack */
            	4749, 0,
            	331, 20,
            0, 8, 1, /* 4749: pointer.X509_OBJECT */
            	3599, 0,
            1, 8, 1, /* 4754: pointer.struct.stack_st_X509_LOOKUP */
            	4759, 0,
            0, 32, 2, /* 4759: struct.stack_st_fake_X509_LOOKUP */
            	4766, 8,
            	334, 24,
            8884099, 8, 2, /* 4766: pointer_to_array_of_pointers_to_stack */
            	4773, 0,
            	331, 20,
            0, 8, 1, /* 4773: pointer.X509_LOOKUP */
            	3474, 0,
            1, 8, 1, /* 4778: pointer.struct.X509_VERIFY_PARAM_st */
            	4783, 0,
            0, 56, 2, /* 4783: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	1989, 48,
            8884097, 8, 0, /* 4790: pointer.func */
            8884097, 8, 0, /* 4793: pointer.func */
            8884097, 8, 0, /* 4796: pointer.func */
            8884097, 8, 0, /* 4799: pointer.func */
            8884097, 8, 0, /* 4802: pointer.func */
            8884097, 8, 0, /* 4805: pointer.func */
            8884097, 8, 0, /* 4808: pointer.func */
            8884097, 8, 0, /* 4811: pointer.func */
            1, 8, 1, /* 4814: pointer.struct.stack_st_X509 */
            	4819, 0,
            0, 32, 2, /* 4819: struct.stack_st_fake_X509 */
            	4826, 8,
            	334, 24,
            8884099, 8, 2, /* 4826: pointer_to_array_of_pointers_to_stack */
            	4833, 0,
            	331, 20,
            0, 8, 1, /* 4833: pointer.X509 */
            	4838, 0,
            0, 0, 1, /* 4838: X509 */
            	4843, 0,
            0, 184, 12, /* 4843: struct.x509_st */
            	4870, 0,
            	4132, 8,
            	4221, 16,
            	174, 32,
            	2894, 40,
            	4070, 104,
            	4875, 112,
            	4883, 120,
            	4888, 128,
            	4912, 136,
            	2833, 144,
            	4936, 176,
            1, 8, 1, /* 4870: pointer.struct.x509_cinf_st */
            	4102, 0,
            1, 8, 1, /* 4875: pointer.struct.AUTHORITY_KEYID_st */
            	4880, 0,
            0, 0, 0, /* 4880: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4883: pointer.struct.X509_POLICY_CACHE_st */
            	4636, 0,
            1, 8, 1, /* 4888: pointer.struct.stack_st_DIST_POINT */
            	4893, 0,
            0, 32, 2, /* 4893: struct.stack_st_fake_DIST_POINT */
            	4900, 8,
            	334, 24,
            8884099, 8, 2, /* 4900: pointer_to_array_of_pointers_to_stack */
            	4907, 0,
            	331, 20,
            0, 8, 1, /* 4907: pointer.DIST_POINT */
            	1520, 0,
            1, 8, 1, /* 4912: pointer.struct.stack_st_GENERAL_NAME */
            	4917, 0,
            0, 32, 2, /* 4917: struct.stack_st_fake_GENERAL_NAME */
            	4924, 8,
            	334, 24,
            8884099, 8, 2, /* 4924: pointer_to_array_of_pointers_to_stack */
            	4931, 0,
            	331, 20,
            0, 8, 1, /* 4931: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 4936: pointer.struct.x509_cert_aux_st */
            	4047, 0,
            1, 8, 1, /* 4941: pointer.struct.x509_store_ctx_st */
            	4639, 0,
            0, 1, 0, /* 4946: char */
        },
        .arg_entity_index = { 0, 4941, 5, },
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

