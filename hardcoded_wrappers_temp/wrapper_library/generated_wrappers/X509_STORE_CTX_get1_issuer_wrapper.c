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
            	1714, 176,
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
            	1350, 8,
            	1350, 16,
            1, 8, 1, /* 1709: pointer.struct.GENERAL_NAME_st */
            	1223, 0,
            1, 8, 1, /* 1714: pointer.struct.x509_cert_aux_st */
            	1719, 0,
            0, 40, 5, /* 1719: struct.x509_cert_aux_st */
            	1732, 0,
            	1732, 8,
            	244, 16,
            	194, 24,
            	1761, 32,
            1, 8, 1, /* 1732: pointer.struct.stack_st_ASN1_OBJECT */
            	1737, 0,
            0, 32, 2, /* 1737: struct.stack_st_fake_ASN1_OBJECT */
            	1744, 8,
            	334, 24,
            8884099, 8, 2, /* 1744: pointer_to_array_of_pointers_to_stack */
            	1751, 0,
            	331, 20,
            0, 8, 1, /* 1751: pointer.ASN1_OBJECT */
            	1756, 0,
            0, 0, 1, /* 1756: ASN1_OBJECT */
            	895, 0,
            1, 8, 1, /* 1761: pointer.struct.stack_st_X509_ALGOR */
            	1766, 0,
            0, 32, 2, /* 1766: struct.stack_st_fake_X509_ALGOR */
            	1773, 8,
            	334, 24,
            8884099, 8, 2, /* 1773: pointer_to_array_of_pointers_to_stack */
            	1780, 0,
            	331, 20,
            0, 8, 1, /* 1780: pointer.X509_ALGOR */
            	1785, 0,
            0, 0, 1, /* 1785: X509_ALGOR */
            	1790, 0,
            0, 16, 2, /* 1790: struct.X509_algor_st */
            	1797, 0,
            	1811, 8,
            1, 8, 1, /* 1797: pointer.struct.asn1_object_st */
            	1802, 0,
            0, 40, 3, /* 1802: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 1811: pointer.struct.asn1_type_st */
            	1816, 0,
            0, 16, 1, /* 1816: struct.asn1_type_st */
            	1821, 8,
            0, 8, 20, /* 1821: union.unknown */
            	174, 0,
            	1864, 0,
            	1797, 0,
            	1874, 0,
            	1879, 0,
            	1884, 0,
            	1889, 0,
            	1894, 0,
            	1899, 0,
            	1904, 0,
            	1909, 0,
            	1914, 0,
            	1919, 0,
            	1924, 0,
            	1929, 0,
            	1934, 0,
            	1939, 0,
            	1864, 0,
            	1864, 0,
            	249, 0,
            1, 8, 1, /* 1864: pointer.struct.asn1_string_st */
            	1869, 0,
            0, 24, 1, /* 1869: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 1874: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1879: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1884: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1889: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1894: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1899: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1904: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1909: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1914: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1919: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1924: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1929: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1934: pointer.struct.asn1_string_st */
            	1869, 0,
            1, 8, 1, /* 1939: pointer.struct.asn1_string_st */
            	1869, 0,
            0, 8, 2, /* 1944: union.unknown */
            	1194, 0,
            	271, 0,
            0, 24, 2, /* 1951: struct.DIST_POINT_NAME_st */
            	1944, 8,
            	257, 16,
            1, 8, 1, /* 1958: pointer.struct.DIST_POINT_NAME_st */
            	1951, 0,
            0, 32, 2, /* 1963: struct.ISSUING_DIST_POINT_st */
            	1958, 0,
            	189, 16,
            1, 8, 1, /* 1970: pointer.struct.ISSUING_DIST_POINT_st */
            	1963, 0,
            0, 80, 8, /* 1975: struct.X509_crl_info_st */
            	67, 0,
            	85, 8,
            	257, 16,
            	359, 24,
            	359, 32,
            	1994, 40,
            	1115, 48,
            	1175, 56,
            1, 8, 1, /* 1994: pointer.struct.stack_st_X509_REVOKED */
            	1999, 0,
            0, 32, 2, /* 1999: struct.stack_st_fake_X509_REVOKED */
            	2006, 8,
            	334, 24,
            8884099, 8, 2, /* 2006: pointer_to_array_of_pointers_to_stack */
            	2013, 0,
            	331, 20,
            0, 8, 1, /* 2013: pointer.X509_REVOKED */
            	2018, 0,
            0, 0, 1, /* 2018: X509_REVOKED */
            	2023, 0,
            0, 40, 4, /* 2023: struct.x509_revoked_st */
            	2034, 0,
            	2044, 8,
            	2049, 16,
            	2073, 24,
            1, 8, 1, /* 2034: pointer.struct.asn1_string_st */
            	2039, 0,
            0, 24, 1, /* 2039: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2044: pointer.struct.asn1_string_st */
            	2039, 0,
            1, 8, 1, /* 2049: pointer.struct.stack_st_X509_EXTENSION */
            	2054, 0,
            0, 32, 2, /* 2054: struct.stack_st_fake_X509_EXTENSION */
            	2061, 8,
            	334, 24,
            8884099, 8, 2, /* 2061: pointer_to_array_of_pointers_to_stack */
            	2068, 0,
            	331, 20,
            0, 8, 1, /* 2068: pointer.X509_EXTENSION */
            	1139, 0,
            1, 8, 1, /* 2073: pointer.struct.stack_st_GENERAL_NAME */
            	2078, 0,
            0, 32, 2, /* 2078: struct.stack_st_fake_GENERAL_NAME */
            	2085, 8,
            	334, 24,
            8884099, 8, 2, /* 2085: pointer_to_array_of_pointers_to_stack */
            	2092, 0,
            	331, 20,
            0, 8, 1, /* 2092: pointer.GENERAL_NAME */
            	1218, 0,
            0, 120, 10, /* 2097: struct.X509_crl_st */
            	2120, 0,
            	85, 8,
            	189, 16,
            	1180, 32,
            	1970, 40,
            	67, 56,
            	67, 64,
            	2125, 96,
            	2159, 104,
            	2167, 112,
            1, 8, 1, /* 2120: pointer.struct.X509_crl_info_st */
            	1975, 0,
            1, 8, 1, /* 2125: pointer.struct.stack_st_GENERAL_NAMES */
            	2130, 0,
            0, 32, 2, /* 2130: struct.stack_st_fake_GENERAL_NAMES */
            	2137, 8,
            	334, 24,
            8884099, 8, 2, /* 2137: pointer_to_array_of_pointers_to_stack */
            	2144, 0,
            	331, 20,
            0, 8, 1, /* 2144: pointer.GENERAL_NAMES */
            	2149, 0,
            0, 0, 1, /* 2149: GENERAL_NAMES */
            	2154, 0,
            0, 32, 1, /* 2154: struct.stack_st_GENERAL_NAME */
            	553, 0,
            1, 8, 1, /* 2159: pointer.struct.x509_crl_method_st */
            	2164, 0,
            0, 0, 0, /* 2164: struct.x509_crl_method_st */
            0, 8, 0, /* 2167: pointer.void */
            1, 8, 1, /* 2170: pointer.struct.X509_crl_st */
            	2097, 0,
            0, 0, 0, /* 2175: struct.X509_POLICY_TREE_st */
            1, 8, 1, /* 2178: pointer.struct.X509_POLICY_TREE_st */
            	2175, 0,
            0, 24, 1, /* 2183: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 2188: pointer.struct.stack_st_X509_EXTENSION */
            	2193, 0,
            0, 32, 2, /* 2193: struct.stack_st_fake_X509_EXTENSION */
            	2200, 8,
            	334, 24,
            8884099, 8, 2, /* 2200: pointer_to_array_of_pointers_to_stack */
            	2207, 0,
            	331, 20,
            0, 8, 1, /* 2207: pointer.X509_EXTENSION */
            	1139, 0,
            1, 8, 1, /* 2212: pointer.struct.asn1_string_st */
            	2217, 0,
            0, 24, 1, /* 2217: struct.asn1_string_st */
            	77, 8,
            0, 24, 1, /* 2222: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 2227: pointer.struct.buf_mem_st */
            	2222, 0,
            1, 8, 1, /* 2232: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2237, 0,
            0, 32, 2, /* 2237: struct.stack_st_fake_X509_NAME_ENTRY */
            	2244, 8,
            	334, 24,
            8884099, 8, 2, /* 2244: pointer_to_array_of_pointers_to_stack */
            	2251, 0,
            	331, 20,
            0, 8, 1, /* 2251: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 2256: pointer.struct.X509_name_st */
            	2261, 0,
            0, 40, 3, /* 2261: struct.X509_name_st */
            	2232, 0,
            	2227, 16,
            	77, 24,
            1, 8, 1, /* 2270: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 2275: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 2280: pointer.struct.x509_store_st */
            	2285, 0,
            0, 144, 15, /* 2285: struct.x509_store_st */
            	2318, 8,
            	3251, 16,
            	3463, 24,
            	3475, 32,
            	3478, 40,
            	3481, 48,
            	3484, 56,
            	3475, 64,
            	3487, 72,
            	3490, 80,
            	3493, 88,
            	3496, 96,
            	3499, 104,
            	3475, 112,
            	538, 120,
            1, 8, 1, /* 2318: pointer.struct.stack_st_X509_OBJECT */
            	2323, 0,
            0, 32, 2, /* 2323: struct.stack_st_fake_X509_OBJECT */
            	2330, 8,
            	334, 24,
            8884099, 8, 2, /* 2330: pointer_to_array_of_pointers_to_stack */
            	2337, 0,
            	331, 20,
            0, 8, 1, /* 2337: pointer.X509_OBJECT */
            	2342, 0,
            0, 0, 1, /* 2342: X509_OBJECT */
            	2347, 0,
            0, 16, 1, /* 2347: struct.x509_object_st */
            	2352, 8,
            0, 8, 4, /* 2352: union.unknown */
            	174, 0,
            	2363, 0,
            	3167, 0,
            	2663, 0,
            1, 8, 1, /* 2363: pointer.struct.x509_st */
            	2368, 0,
            0, 184, 12, /* 2368: struct.x509_st */
            	2395, 0,
            	2435, 8,
            	2524, 16,
            	174, 32,
            	2799, 40,
            	2529, 104,
            	3037, 112,
            	1488, 120,
            	3045, 128,
            	3069, 136,
            	3093, 144,
            	3101, 176,
            1, 8, 1, /* 2395: pointer.struct.x509_cinf_st */
            	2400, 0,
            0, 104, 11, /* 2400: struct.x509_cinf_st */
            	2425, 0,
            	2425, 8,
            	2435, 16,
            	2584, 24,
            	2632, 32,
            	2584, 40,
            	2649, 48,
            	2524, 56,
            	2524, 64,
            	3008, 72,
            	3032, 80,
            1, 8, 1, /* 2425: pointer.struct.asn1_string_st */
            	2430, 0,
            0, 24, 1, /* 2430: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2435: pointer.struct.X509_algor_st */
            	2440, 0,
            0, 16, 2, /* 2440: struct.X509_algor_st */
            	2447, 0,
            	2461, 8,
            1, 8, 1, /* 2447: pointer.struct.asn1_object_st */
            	2452, 0,
            0, 40, 3, /* 2452: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2461: pointer.struct.asn1_type_st */
            	2466, 0,
            0, 16, 1, /* 2466: struct.asn1_type_st */
            	2471, 8,
            0, 8, 20, /* 2471: union.unknown */
            	174, 0,
            	2514, 0,
            	2447, 0,
            	2425, 0,
            	2519, 0,
            	2524, 0,
            	2529, 0,
            	2534, 0,
            	2539, 0,
            	2544, 0,
            	2549, 0,
            	2554, 0,
            	2559, 0,
            	2564, 0,
            	2569, 0,
            	2574, 0,
            	2579, 0,
            	2514, 0,
            	2514, 0,
            	249, 0,
            1, 8, 1, /* 2514: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2519: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2524: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2529: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2534: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2539: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2544: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2549: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2554: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2559: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2564: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2569: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2574: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2579: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2584: pointer.struct.X509_name_st */
            	2589, 0,
            0, 40, 3, /* 2589: struct.X509_name_st */
            	2598, 0,
            	2622, 16,
            	77, 24,
            1, 8, 1, /* 2598: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2603, 0,
            0, 32, 2, /* 2603: struct.stack_st_fake_X509_NAME_ENTRY */
            	2610, 8,
            	334, 24,
            8884099, 8, 2, /* 2610: pointer_to_array_of_pointers_to_stack */
            	2617, 0,
            	331, 20,
            0, 8, 1, /* 2617: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 2622: pointer.struct.buf_mem_st */
            	2627, 0,
            0, 24, 1, /* 2627: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 2632: pointer.struct.X509_val_st */
            	2637, 0,
            0, 16, 2, /* 2637: struct.X509_val_st */
            	2644, 0,
            	2644, 8,
            1, 8, 1, /* 2644: pointer.struct.asn1_string_st */
            	2430, 0,
            1, 8, 1, /* 2649: pointer.struct.X509_pubkey_st */
            	2654, 0,
            0, 24, 3, /* 2654: struct.X509_pubkey_st */
            	2435, 0,
            	2524, 8,
            	2663, 16,
            1, 8, 1, /* 2663: pointer.struct.evp_pkey_st */
            	2668, 0,
            0, 56, 4, /* 2668: struct.evp_pkey_st */
            	394, 16,
            	402, 24,
            	2679, 32,
            	2984, 48,
            0, 8, 5, /* 2679: union.unknown */
            	174, 0,
            	2692, 0,
            	2835, 0,
            	2916, 0,
            	736, 0,
            1, 8, 1, /* 2692: pointer.struct.rsa_st */
            	2697, 0,
            0, 168, 17, /* 2697: struct.rsa_st */
            	2734, 16,
            	402, 24,
            	2789, 32,
            	2789, 40,
            	2789, 48,
            	2789, 56,
            	2789, 64,
            	2789, 72,
            	2789, 80,
            	2789, 88,
            	2799, 96,
            	2821, 120,
            	2821, 128,
            	2821, 136,
            	174, 144,
            	579, 152,
            	579, 160,
            1, 8, 1, /* 2734: pointer.struct.rsa_meth_st */
            	2739, 0,
            0, 112, 13, /* 2739: struct.rsa_meth_st */
            	111, 0,
            	2768, 8,
            	2768, 16,
            	2768, 24,
            	2768, 32,
            	2771, 40,
            	2774, 48,
            	2777, 56,
            	2777, 64,
            	174, 80,
            	2780, 88,
            	2783, 96,
            	2786, 104,
            8884097, 8, 0, /* 2768: pointer.func */
            8884097, 8, 0, /* 2771: pointer.func */
            8884097, 8, 0, /* 2774: pointer.func */
            8884097, 8, 0, /* 2777: pointer.func */
            8884097, 8, 0, /* 2780: pointer.func */
            8884097, 8, 0, /* 2783: pointer.func */
            8884097, 8, 0, /* 2786: pointer.func */
            1, 8, 1, /* 2789: pointer.struct.bignum_st */
            	2794, 0,
            0, 24, 1, /* 2794: struct.bignum_st */
            	530, 0,
            0, 16, 1, /* 2799: struct.crypto_ex_data_st */
            	2804, 0,
            1, 8, 1, /* 2804: pointer.struct.stack_st_void */
            	2809, 0,
            0, 32, 1, /* 2809: struct.stack_st_void */
            	2814, 0,
            0, 32, 2, /* 2814: struct.stack_st */
            	560, 8,
            	334, 24,
            1, 8, 1, /* 2821: pointer.struct.bn_mont_ctx_st */
            	2826, 0,
            0, 96, 3, /* 2826: struct.bn_mont_ctx_st */
            	2794, 8,
            	2794, 32,
            	2794, 56,
            1, 8, 1, /* 2835: pointer.struct.dsa_st */
            	2840, 0,
            0, 136, 11, /* 2840: struct.dsa_st */
            	2789, 24,
            	2789, 32,
            	2789, 40,
            	2789, 48,
            	2789, 56,
            	2789, 64,
            	2789, 72,
            	2821, 88,
            	2799, 104,
            	2865, 120,
            	402, 128,
            1, 8, 1, /* 2865: pointer.struct.dsa_method */
            	2870, 0,
            0, 96, 11, /* 2870: struct.dsa_method */
            	111, 0,
            	2895, 8,
            	2898, 16,
            	2901, 24,
            	2904, 32,
            	2907, 40,
            	2910, 48,
            	2910, 56,
            	174, 72,
            	2913, 80,
            	2910, 88,
            8884097, 8, 0, /* 2895: pointer.func */
            8884097, 8, 0, /* 2898: pointer.func */
            8884097, 8, 0, /* 2901: pointer.func */
            8884097, 8, 0, /* 2904: pointer.func */
            8884097, 8, 0, /* 2907: pointer.func */
            8884097, 8, 0, /* 2910: pointer.func */
            8884097, 8, 0, /* 2913: pointer.func */
            1, 8, 1, /* 2916: pointer.struct.dh_st */
            	2921, 0,
            0, 144, 12, /* 2921: struct.dh_st */
            	2789, 8,
            	2789, 16,
            	2789, 32,
            	2789, 40,
            	2821, 56,
            	2789, 64,
            	2789, 72,
            	77, 80,
            	2789, 96,
            	2799, 112,
            	2948, 128,
            	402, 136,
            1, 8, 1, /* 2948: pointer.struct.dh_method */
            	2953, 0,
            0, 72, 8, /* 2953: struct.dh_method */
            	111, 0,
            	2972, 8,
            	2975, 16,
            	2978, 24,
            	2972, 32,
            	2972, 40,
            	174, 56,
            	2981, 64,
            8884097, 8, 0, /* 2972: pointer.func */
            8884097, 8, 0, /* 2975: pointer.func */
            8884097, 8, 0, /* 2978: pointer.func */
            8884097, 8, 0, /* 2981: pointer.func */
            1, 8, 1, /* 2984: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2989, 0,
            0, 32, 2, /* 2989: struct.stack_st_fake_X509_ATTRIBUTE */
            	2996, 8,
            	334, 24,
            8884099, 8, 2, /* 2996: pointer_to_array_of_pointers_to_stack */
            	3003, 0,
            	331, 20,
            0, 8, 1, /* 3003: pointer.X509_ATTRIBUTE */
            	768, 0,
            1, 8, 1, /* 3008: pointer.struct.stack_st_X509_EXTENSION */
            	3013, 0,
            0, 32, 2, /* 3013: struct.stack_st_fake_X509_EXTENSION */
            	3020, 8,
            	334, 24,
            8884099, 8, 2, /* 3020: pointer_to_array_of_pointers_to_stack */
            	3027, 0,
            	331, 20,
            0, 8, 1, /* 3027: pointer.X509_EXTENSION */
            	1139, 0,
            0, 24, 1, /* 3032: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 3037: pointer.struct.AUTHORITY_KEYID_st */
            	3042, 0,
            0, 0, 0, /* 3042: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3045: pointer.struct.stack_st_DIST_POINT */
            	3050, 0,
            0, 32, 2, /* 3050: struct.stack_st_fake_DIST_POINT */
            	3057, 8,
            	334, 24,
            8884099, 8, 2, /* 3057: pointer_to_array_of_pointers_to_stack */
            	3064, 0,
            	331, 20,
            0, 8, 1, /* 3064: pointer.DIST_POINT */
            	1520, 0,
            1, 8, 1, /* 3069: pointer.struct.stack_st_GENERAL_NAME */
            	3074, 0,
            0, 32, 2, /* 3074: struct.stack_st_fake_GENERAL_NAME */
            	3081, 8,
            	334, 24,
            8884099, 8, 2, /* 3081: pointer_to_array_of_pointers_to_stack */
            	3088, 0,
            	331, 20,
            0, 8, 1, /* 3088: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 3093: pointer.struct.NAME_CONSTRAINTS_st */
            	3098, 0,
            0, 0, 0, /* 3098: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3101: pointer.struct.x509_cert_aux_st */
            	3106, 0,
            0, 40, 5, /* 3106: struct.x509_cert_aux_st */
            	3119, 0,
            	3119, 8,
            	2579, 16,
            	2529, 24,
            	3143, 32,
            1, 8, 1, /* 3119: pointer.struct.stack_st_ASN1_OBJECT */
            	3124, 0,
            0, 32, 2, /* 3124: struct.stack_st_fake_ASN1_OBJECT */
            	3131, 8,
            	334, 24,
            8884099, 8, 2, /* 3131: pointer_to_array_of_pointers_to_stack */
            	3138, 0,
            	331, 20,
            0, 8, 1, /* 3138: pointer.ASN1_OBJECT */
            	1756, 0,
            1, 8, 1, /* 3143: pointer.struct.stack_st_X509_ALGOR */
            	3148, 0,
            0, 32, 2, /* 3148: struct.stack_st_fake_X509_ALGOR */
            	3155, 8,
            	334, 24,
            8884099, 8, 2, /* 3155: pointer_to_array_of_pointers_to_stack */
            	3162, 0,
            	331, 20,
            0, 8, 1, /* 3162: pointer.X509_ALGOR */
            	1785, 0,
            1, 8, 1, /* 3167: pointer.struct.X509_crl_st */
            	3172, 0,
            0, 120, 10, /* 3172: struct.X509_crl_st */
            	3195, 0,
            	2435, 8,
            	2524, 16,
            	3037, 32,
            	3243, 40,
            	2425, 56,
            	2425, 64,
            	2125, 96,
            	2159, 104,
            	2167, 112,
            1, 8, 1, /* 3195: pointer.struct.X509_crl_info_st */
            	3200, 0,
            0, 80, 8, /* 3200: struct.X509_crl_info_st */
            	2425, 0,
            	2435, 8,
            	2584, 16,
            	2644, 24,
            	2644, 32,
            	3219, 40,
            	3008, 48,
            	3032, 56,
            1, 8, 1, /* 3219: pointer.struct.stack_st_X509_REVOKED */
            	3224, 0,
            0, 32, 2, /* 3224: struct.stack_st_fake_X509_REVOKED */
            	3231, 8,
            	334, 24,
            8884099, 8, 2, /* 3231: pointer_to_array_of_pointers_to_stack */
            	3238, 0,
            	331, 20,
            0, 8, 1, /* 3238: pointer.X509_REVOKED */
            	2018, 0,
            1, 8, 1, /* 3243: pointer.struct.ISSUING_DIST_POINT_st */
            	3248, 0,
            0, 0, 0, /* 3248: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3251: pointer.struct.stack_st_X509_LOOKUP */
            	3256, 0,
            0, 32, 2, /* 3256: struct.stack_st_fake_X509_LOOKUP */
            	3263, 8,
            	334, 24,
            8884099, 8, 2, /* 3263: pointer_to_array_of_pointers_to_stack */
            	3270, 0,
            	331, 20,
            0, 8, 1, /* 3270: pointer.X509_LOOKUP */
            	3275, 0,
            0, 0, 1, /* 3275: X509_LOOKUP */
            	3280, 0,
            0, 32, 3, /* 3280: struct.x509_lookup_st */
            	3289, 8,
            	174, 16,
            	3338, 24,
            1, 8, 1, /* 3289: pointer.struct.x509_lookup_method_st */
            	3294, 0,
            0, 80, 10, /* 3294: struct.x509_lookup_method_st */
            	111, 0,
            	3317, 8,
            	3320, 16,
            	3317, 24,
            	3317, 32,
            	3323, 40,
            	3326, 48,
            	3329, 56,
            	3332, 64,
            	3335, 72,
            8884097, 8, 0, /* 3317: pointer.func */
            8884097, 8, 0, /* 3320: pointer.func */
            8884097, 8, 0, /* 3323: pointer.func */
            8884097, 8, 0, /* 3326: pointer.func */
            8884097, 8, 0, /* 3329: pointer.func */
            8884097, 8, 0, /* 3332: pointer.func */
            8884097, 8, 0, /* 3335: pointer.func */
            1, 8, 1, /* 3338: pointer.struct.x509_store_st */
            	3343, 0,
            0, 144, 15, /* 3343: struct.x509_store_st */
            	3376, 8,
            	3400, 16,
            	3424, 24,
            	3436, 32,
            	3439, 40,
            	3442, 48,
            	3445, 56,
            	3436, 64,
            	3448, 72,
            	3451, 80,
            	3454, 88,
            	3457, 96,
            	3460, 104,
            	3436, 112,
            	2799, 120,
            1, 8, 1, /* 3376: pointer.struct.stack_st_X509_OBJECT */
            	3381, 0,
            0, 32, 2, /* 3381: struct.stack_st_fake_X509_OBJECT */
            	3388, 8,
            	334, 24,
            8884099, 8, 2, /* 3388: pointer_to_array_of_pointers_to_stack */
            	3395, 0,
            	331, 20,
            0, 8, 1, /* 3395: pointer.X509_OBJECT */
            	2342, 0,
            1, 8, 1, /* 3400: pointer.struct.stack_st_X509_LOOKUP */
            	3405, 0,
            0, 32, 2, /* 3405: struct.stack_st_fake_X509_LOOKUP */
            	3412, 8,
            	334, 24,
            8884099, 8, 2, /* 3412: pointer_to_array_of_pointers_to_stack */
            	3419, 0,
            	331, 20,
            0, 8, 1, /* 3419: pointer.X509_LOOKUP */
            	3275, 0,
            1, 8, 1, /* 3424: pointer.struct.X509_VERIFY_PARAM_st */
            	3429, 0,
            0, 56, 2, /* 3429: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	3119, 48,
            8884097, 8, 0, /* 3436: pointer.func */
            8884097, 8, 0, /* 3439: pointer.func */
            8884097, 8, 0, /* 3442: pointer.func */
            8884097, 8, 0, /* 3445: pointer.func */
            8884097, 8, 0, /* 3448: pointer.func */
            8884097, 8, 0, /* 3451: pointer.func */
            8884097, 8, 0, /* 3454: pointer.func */
            8884097, 8, 0, /* 3457: pointer.func */
            8884097, 8, 0, /* 3460: pointer.func */
            1, 8, 1, /* 3463: pointer.struct.X509_VERIFY_PARAM_st */
            	3468, 0,
            0, 56, 2, /* 3468: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	1732, 48,
            8884097, 8, 0, /* 3475: pointer.func */
            8884097, 8, 0, /* 3478: pointer.func */
            8884097, 8, 0, /* 3481: pointer.func */
            8884097, 8, 0, /* 3484: pointer.func */
            8884097, 8, 0, /* 3487: pointer.func */
            8884097, 8, 0, /* 3490: pointer.func */
            8884097, 8, 0, /* 3493: pointer.func */
            8884097, 8, 0, /* 3496: pointer.func */
            8884097, 8, 0, /* 3499: pointer.func */
            0, 56, 4, /* 3502: struct.evp_pkey_st */
            	3513, 16,
            	3521, 24,
            	3529, 32,
            	3850, 48,
            1, 8, 1, /* 3513: pointer.struct.evp_pkey_asn1_method_st */
            	3518, 0,
            0, 0, 0, /* 3518: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3521: pointer.struct.engine_st */
            	3526, 0,
            0, 0, 0, /* 3526: struct.engine_st */
            0, 8, 5, /* 3529: union.unknown */
            	174, 0,
            	3542, 0,
            	3693, 0,
            	3774, 0,
            	3842, 0,
            1, 8, 1, /* 3542: pointer.struct.rsa_st */
            	3547, 0,
            0, 168, 17, /* 3547: struct.rsa_st */
            	3584, 16,
            	3521, 24,
            	3639, 32,
            	3639, 40,
            	3639, 48,
            	3639, 56,
            	3639, 64,
            	3639, 72,
            	3639, 80,
            	3639, 88,
            	3649, 96,
            	3671, 120,
            	3671, 128,
            	3671, 136,
            	174, 144,
            	3685, 152,
            	3685, 160,
            1, 8, 1, /* 3584: pointer.struct.rsa_meth_st */
            	3589, 0,
            0, 112, 13, /* 3589: struct.rsa_meth_st */
            	111, 0,
            	3618, 8,
            	3618, 16,
            	3618, 24,
            	3618, 32,
            	3621, 40,
            	3624, 48,
            	3627, 56,
            	3627, 64,
            	174, 80,
            	3630, 88,
            	3633, 96,
            	3636, 104,
            8884097, 8, 0, /* 3618: pointer.func */
            8884097, 8, 0, /* 3621: pointer.func */
            8884097, 8, 0, /* 3624: pointer.func */
            8884097, 8, 0, /* 3627: pointer.func */
            8884097, 8, 0, /* 3630: pointer.func */
            8884097, 8, 0, /* 3633: pointer.func */
            8884097, 8, 0, /* 3636: pointer.func */
            1, 8, 1, /* 3639: pointer.struct.bignum_st */
            	3644, 0,
            0, 24, 1, /* 3644: struct.bignum_st */
            	530, 0,
            0, 16, 1, /* 3649: struct.crypto_ex_data_st */
            	3654, 0,
            1, 8, 1, /* 3654: pointer.struct.stack_st_void */
            	3659, 0,
            0, 32, 1, /* 3659: struct.stack_st_void */
            	3664, 0,
            0, 32, 2, /* 3664: struct.stack_st */
            	560, 8,
            	334, 24,
            1, 8, 1, /* 3671: pointer.struct.bn_mont_ctx_st */
            	3676, 0,
            0, 96, 3, /* 3676: struct.bn_mont_ctx_st */
            	3644, 8,
            	3644, 32,
            	3644, 56,
            1, 8, 1, /* 3685: pointer.struct.bn_blinding_st */
            	3690, 0,
            0, 0, 0, /* 3690: struct.bn_blinding_st */
            1, 8, 1, /* 3693: pointer.struct.dsa_st */
            	3698, 0,
            0, 136, 11, /* 3698: struct.dsa_st */
            	3639, 24,
            	3639, 32,
            	3639, 40,
            	3639, 48,
            	3639, 56,
            	3639, 64,
            	3639, 72,
            	3671, 88,
            	3649, 104,
            	3723, 120,
            	3521, 128,
            1, 8, 1, /* 3723: pointer.struct.dsa_method */
            	3728, 0,
            0, 96, 11, /* 3728: struct.dsa_method */
            	111, 0,
            	3753, 8,
            	3756, 16,
            	3759, 24,
            	3762, 32,
            	3765, 40,
            	3768, 48,
            	3768, 56,
            	174, 72,
            	3771, 80,
            	3768, 88,
            8884097, 8, 0, /* 3753: pointer.func */
            8884097, 8, 0, /* 3756: pointer.func */
            8884097, 8, 0, /* 3759: pointer.func */
            8884097, 8, 0, /* 3762: pointer.func */
            8884097, 8, 0, /* 3765: pointer.func */
            8884097, 8, 0, /* 3768: pointer.func */
            8884097, 8, 0, /* 3771: pointer.func */
            1, 8, 1, /* 3774: pointer.struct.dh_st */
            	3779, 0,
            0, 144, 12, /* 3779: struct.dh_st */
            	3639, 8,
            	3639, 16,
            	3639, 32,
            	3639, 40,
            	3671, 56,
            	3639, 64,
            	3639, 72,
            	77, 80,
            	3639, 96,
            	3649, 112,
            	3806, 128,
            	3521, 136,
            1, 8, 1, /* 3806: pointer.struct.dh_method */
            	3811, 0,
            0, 72, 8, /* 3811: struct.dh_method */
            	111, 0,
            	3830, 8,
            	3833, 16,
            	3836, 24,
            	3830, 32,
            	3830, 40,
            	174, 56,
            	3839, 64,
            8884097, 8, 0, /* 3830: pointer.func */
            8884097, 8, 0, /* 3833: pointer.func */
            8884097, 8, 0, /* 3836: pointer.func */
            8884097, 8, 0, /* 3839: pointer.func */
            1, 8, 1, /* 3842: pointer.struct.ec_key_st */
            	3847, 0,
            0, 0, 0, /* 3847: struct.ec_key_st */
            1, 8, 1, /* 3850: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3855, 0,
            0, 32, 2, /* 3855: struct.stack_st_fake_X509_ATTRIBUTE */
            	3862, 8,
            	334, 24,
            8884099, 8, 2, /* 3862: pointer_to_array_of_pointers_to_stack */
            	3869, 0,
            	331, 20,
            0, 8, 1, /* 3869: pointer.X509_ATTRIBUTE */
            	768, 0,
            0, 248, 25, /* 3874: struct.x509_store_ctx_st */
            	2280, 0,
            	5, 16,
            	3927, 24,
            	4431, 32,
            	3463, 40,
            	2167, 48,
            	3475, 56,
            	3478, 64,
            	3481, 72,
            	3484, 80,
            	3475, 88,
            	3487, 96,
            	3490, 104,
            	3493, 112,
            	3475, 120,
            	3496, 128,
            	3499, 136,
            	3475, 144,
            	3927, 160,
            	2178, 168,
            	5, 192,
            	5, 200,
            	2170, 208,
            	4675, 224,
            	538, 232,
            1, 8, 1, /* 3927: pointer.struct.stack_st_X509 */
            	3932, 0,
            0, 32, 2, /* 3932: struct.stack_st_fake_X509 */
            	3939, 8,
            	334, 24,
            8884099, 8, 2, /* 3939: pointer_to_array_of_pointers_to_stack */
            	3946, 0,
            	331, 20,
            0, 8, 1, /* 3946: pointer.X509 */
            	3951, 0,
            0, 0, 1, /* 3951: X509 */
            	3956, 0,
            0, 184, 12, /* 3956: struct.x509_st */
            	3983, 0,
            	4023, 8,
            	4112, 16,
            	174, 32,
            	3649, 40,
            	4117, 104,
            	4293, 112,
            	4301, 120,
            	4309, 128,
            	4333, 136,
            	4357, 144,
            	4365, 176,
            1, 8, 1, /* 3983: pointer.struct.x509_cinf_st */
            	3988, 0,
            0, 104, 11, /* 3988: struct.x509_cinf_st */
            	4013, 0,
            	4013, 8,
            	4023, 16,
            	4180, 24,
            	4228, 32,
            	4180, 40,
            	4245, 48,
            	4112, 56,
            	4112, 64,
            	4264, 72,
            	4288, 80,
            1, 8, 1, /* 4013: pointer.struct.asn1_string_st */
            	4018, 0,
            0, 24, 1, /* 4018: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 4023: pointer.struct.X509_algor_st */
            	4028, 0,
            0, 16, 2, /* 4028: struct.X509_algor_st */
            	4035, 0,
            	4049, 8,
            1, 8, 1, /* 4035: pointer.struct.asn1_object_st */
            	4040, 0,
            0, 40, 3, /* 4040: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 4049: pointer.struct.asn1_type_st */
            	4054, 0,
            0, 16, 1, /* 4054: struct.asn1_type_st */
            	4059, 8,
            0, 8, 20, /* 4059: union.unknown */
            	174, 0,
            	4102, 0,
            	4035, 0,
            	4013, 0,
            	4107, 0,
            	4112, 0,
            	4117, 0,
            	4122, 0,
            	4127, 0,
            	4132, 0,
            	4137, 0,
            	4142, 0,
            	4147, 0,
            	4152, 0,
            	4157, 0,
            	4162, 0,
            	4167, 0,
            	4102, 0,
            	4102, 0,
            	4172, 0,
            1, 8, 1, /* 4102: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4107: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4112: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4117: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4122: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4127: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4132: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4137: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4142: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4147: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4152: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4157: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4162: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4167: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4172: pointer.struct.ASN1_VALUE_st */
            	4177, 0,
            0, 0, 0, /* 4177: struct.ASN1_VALUE_st */
            1, 8, 1, /* 4180: pointer.struct.X509_name_st */
            	4185, 0,
            0, 40, 3, /* 4185: struct.X509_name_st */
            	4194, 0,
            	4218, 16,
            	77, 24,
            1, 8, 1, /* 4194: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4199, 0,
            0, 32, 2, /* 4199: struct.stack_st_fake_X509_NAME_ENTRY */
            	4206, 8,
            	334, 24,
            8884099, 8, 2, /* 4206: pointer_to_array_of_pointers_to_stack */
            	4213, 0,
            	331, 20,
            0, 8, 1, /* 4213: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 4218: pointer.struct.buf_mem_st */
            	4223, 0,
            0, 24, 1, /* 4223: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 4228: pointer.struct.X509_val_st */
            	4233, 0,
            0, 16, 2, /* 4233: struct.X509_val_st */
            	4240, 0,
            	4240, 8,
            1, 8, 1, /* 4240: pointer.struct.asn1_string_st */
            	4018, 0,
            1, 8, 1, /* 4245: pointer.struct.X509_pubkey_st */
            	4250, 0,
            0, 24, 3, /* 4250: struct.X509_pubkey_st */
            	4023, 0,
            	4112, 8,
            	4259, 16,
            1, 8, 1, /* 4259: pointer.struct.evp_pkey_st */
            	3502, 0,
            1, 8, 1, /* 4264: pointer.struct.stack_st_X509_EXTENSION */
            	4269, 0,
            0, 32, 2, /* 4269: struct.stack_st_fake_X509_EXTENSION */
            	4276, 8,
            	334, 24,
            8884099, 8, 2, /* 4276: pointer_to_array_of_pointers_to_stack */
            	4283, 0,
            	331, 20,
            0, 8, 1, /* 4283: pointer.X509_EXTENSION */
            	1139, 0,
            0, 24, 1, /* 4288: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 4293: pointer.struct.AUTHORITY_KEYID_st */
            	4298, 0,
            0, 0, 0, /* 4298: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4301: pointer.struct.X509_POLICY_CACHE_st */
            	4306, 0,
            0, 0, 0, /* 4306: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4309: pointer.struct.stack_st_DIST_POINT */
            	4314, 0,
            0, 32, 2, /* 4314: struct.stack_st_fake_DIST_POINT */
            	4321, 8,
            	334, 24,
            8884099, 8, 2, /* 4321: pointer_to_array_of_pointers_to_stack */
            	4328, 0,
            	331, 20,
            0, 8, 1, /* 4328: pointer.DIST_POINT */
            	1520, 0,
            1, 8, 1, /* 4333: pointer.struct.stack_st_GENERAL_NAME */
            	4338, 0,
            0, 32, 2, /* 4338: struct.stack_st_fake_GENERAL_NAME */
            	4345, 8,
            	334, 24,
            8884099, 8, 2, /* 4345: pointer_to_array_of_pointers_to_stack */
            	4352, 0,
            	331, 20,
            0, 8, 1, /* 4352: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 4357: pointer.struct.NAME_CONSTRAINTS_st */
            	4362, 0,
            0, 0, 0, /* 4362: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4365: pointer.struct.x509_cert_aux_st */
            	4370, 0,
            0, 40, 5, /* 4370: struct.x509_cert_aux_st */
            	4383, 0,
            	4383, 8,
            	4167, 16,
            	4117, 24,
            	4407, 32,
            1, 8, 1, /* 4383: pointer.struct.stack_st_ASN1_OBJECT */
            	4388, 0,
            0, 32, 2, /* 4388: struct.stack_st_fake_ASN1_OBJECT */
            	4395, 8,
            	334, 24,
            8884099, 8, 2, /* 4395: pointer_to_array_of_pointers_to_stack */
            	4402, 0,
            	331, 20,
            0, 8, 1, /* 4402: pointer.ASN1_OBJECT */
            	1756, 0,
            1, 8, 1, /* 4407: pointer.struct.stack_st_X509_ALGOR */
            	4412, 0,
            0, 32, 2, /* 4412: struct.stack_st_fake_X509_ALGOR */
            	4419, 8,
            	334, 24,
            8884099, 8, 2, /* 4419: pointer_to_array_of_pointers_to_stack */
            	4426, 0,
            	331, 20,
            0, 8, 1, /* 4426: pointer.X509_ALGOR */
            	1785, 0,
            1, 8, 1, /* 4431: pointer.struct.stack_st_X509_CRL */
            	4436, 0,
            0, 32, 2, /* 4436: struct.stack_st_fake_X509_CRL */
            	4443, 8,
            	334, 24,
            8884099, 8, 2, /* 4443: pointer_to_array_of_pointers_to_stack */
            	4450, 0,
            	331, 20,
            0, 8, 1, /* 4450: pointer.X509_CRL */
            	4455, 0,
            0, 0, 1, /* 4455: X509_CRL */
            	4460, 0,
            0, 120, 10, /* 4460: struct.X509_crl_st */
            	4483, 0,
            	4512, 8,
            	4601, 16,
            	3037, 32,
            	3243, 40,
            	4507, 56,
            	4507, 64,
            	2125, 96,
            	2159, 104,
            	2167, 112,
            1, 8, 1, /* 4483: pointer.struct.X509_crl_info_st */
            	4488, 0,
            0, 80, 8, /* 4488: struct.X509_crl_info_st */
            	4507, 0,
            	4512, 8,
            	2256, 16,
            	2212, 24,
            	2212, 32,
            	4651, 40,
            	2188, 48,
            	2183, 56,
            1, 8, 1, /* 4507: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4512: pointer.struct.X509_algor_st */
            	4517, 0,
            0, 16, 2, /* 4517: struct.X509_algor_st */
            	4524, 0,
            	4538, 8,
            1, 8, 1, /* 4524: pointer.struct.asn1_object_st */
            	4529, 0,
            0, 40, 3, /* 4529: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 4538: pointer.struct.asn1_type_st */
            	4543, 0,
            0, 16, 1, /* 4543: struct.asn1_type_st */
            	4548, 8,
            0, 8, 20, /* 4548: union.unknown */
            	174, 0,
            	4591, 0,
            	4524, 0,
            	4507, 0,
            	4596, 0,
            	4601, 0,
            	4606, 0,
            	4611, 0,
            	4616, 0,
            	4621, 0,
            	4626, 0,
            	4631, 0,
            	4636, 0,
            	4641, 0,
            	4646, 0,
            	2275, 0,
            	2270, 0,
            	4591, 0,
            	4591, 0,
            	249, 0,
            1, 8, 1, /* 4591: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4596: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4601: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4606: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4611: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4616: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4621: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4626: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4631: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4636: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4641: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4646: pointer.struct.asn1_string_st */
            	2217, 0,
            1, 8, 1, /* 4651: pointer.struct.stack_st_X509_REVOKED */
            	4656, 0,
            0, 32, 2, /* 4656: struct.stack_st_fake_X509_REVOKED */
            	4663, 8,
            	334, 24,
            8884099, 8, 2, /* 4663: pointer_to_array_of_pointers_to_stack */
            	4670, 0,
            	331, 20,
            0, 8, 1, /* 4670: pointer.X509_REVOKED */
            	2018, 0,
            1, 8, 1, /* 4675: pointer.struct.x509_store_ctx_st */
            	3874, 0,
            0, 1, 0, /* 4680: char */
        },
        .arg_entity_index = { 0, 4675, 5, },
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

