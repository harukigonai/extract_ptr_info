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
            	1979, 176,
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
            	1919, 0,
            	1967, 0,
            	1871, 0,
            	1856, 0,
            	1764, 0,
            	1856, 0,
            	1919, 0,
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
            	1911, 0,
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
            1, 8, 1, /* 1911: pointer.struct.ASN1_VALUE_st */
            	1916, 0,
            0, 0, 0, /* 1916: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1919: pointer.struct.X509_name_st */
            	1924, 0,
            0, 40, 3, /* 1924: struct.X509_name_st */
            	1933, 0,
            	1957, 16,
            	77, 24,
            1, 8, 1, /* 1933: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1938, 0,
            0, 32, 2, /* 1938: struct.stack_st_fake_X509_NAME_ENTRY */
            	1945, 8,
            	334, 24,
            8884099, 8, 2, /* 1945: pointer_to_array_of_pointers_to_stack */
            	1952, 0,
            	331, 20,
            0, 8, 1, /* 1952: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 1957: pointer.struct.buf_mem_st */
            	1962, 0,
            0, 24, 1, /* 1962: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 1967: pointer.struct.EDIPartyName_st */
            	1972, 0,
            0, 16, 2, /* 1972: struct.EDIPartyName_st */
            	1831, 0,
            	1831, 8,
            1, 8, 1, /* 1979: pointer.struct.x509_cert_aux_st */
            	1984, 0,
            0, 40, 5, /* 1984: struct.x509_cert_aux_st */
            	1997, 0,
            	1997, 8,
            	244, 16,
            	194, 24,
            	2035, 32,
            1, 8, 1, /* 1997: pointer.struct.stack_st_ASN1_OBJECT */
            	2002, 0,
            0, 32, 2, /* 2002: struct.stack_st_fake_ASN1_OBJECT */
            	2009, 8,
            	334, 24,
            8884099, 8, 2, /* 2009: pointer_to_array_of_pointers_to_stack */
            	2016, 0,
            	331, 20,
            0, 8, 1, /* 2016: pointer.ASN1_OBJECT */
            	2021, 0,
            0, 0, 1, /* 2021: ASN1_OBJECT */
            	2026, 0,
            0, 40, 3, /* 2026: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2035: pointer.struct.stack_st_X509_ALGOR */
            	2040, 0,
            0, 32, 2, /* 2040: struct.stack_st_fake_X509_ALGOR */
            	2047, 8,
            	334, 24,
            8884099, 8, 2, /* 2047: pointer_to_array_of_pointers_to_stack */
            	2054, 0,
            	331, 20,
            0, 8, 1, /* 2054: pointer.X509_ALGOR */
            	2059, 0,
            0, 0, 1, /* 2059: X509_ALGOR */
            	2064, 0,
            0, 16, 2, /* 2064: struct.X509_algor_st */
            	890, 0,
            	2071, 8,
            1, 8, 1, /* 2071: pointer.struct.asn1_type_st */
            	832, 0,
            0, 8, 2, /* 2076: union.unknown */
            	1194, 0,
            	271, 0,
            0, 24, 2, /* 2083: struct.DIST_POINT_NAME_st */
            	2076, 8,
            	257, 16,
            1, 8, 1, /* 2090: pointer.struct.DIST_POINT_NAME_st */
            	2083, 0,
            0, 32, 2, /* 2095: struct.ISSUING_DIST_POINT_st */
            	2090, 0,
            	189, 16,
            1, 8, 1, /* 2102: pointer.struct.ISSUING_DIST_POINT_st */
            	2095, 0,
            0, 80, 8, /* 2107: struct.X509_crl_info_st */
            	67, 0,
            	85, 8,
            	257, 16,
            	359, 24,
            	359, 32,
            	2126, 40,
            	1115, 48,
            	1175, 56,
            1, 8, 1, /* 2126: pointer.struct.stack_st_X509_REVOKED */
            	2131, 0,
            0, 32, 2, /* 2131: struct.stack_st_fake_X509_REVOKED */
            	2138, 8,
            	334, 24,
            8884099, 8, 2, /* 2138: pointer_to_array_of_pointers_to_stack */
            	2145, 0,
            	331, 20,
            0, 8, 1, /* 2145: pointer.X509_REVOKED */
            	2150, 0,
            0, 0, 1, /* 2150: X509_REVOKED */
            	2155, 0,
            0, 40, 4, /* 2155: struct.x509_revoked_st */
            	2166, 0,
            	2176, 8,
            	2181, 16,
            	2205, 24,
            1, 8, 1, /* 2166: pointer.struct.asn1_string_st */
            	2171, 0,
            0, 24, 1, /* 2171: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2176: pointer.struct.asn1_string_st */
            	2171, 0,
            1, 8, 1, /* 2181: pointer.struct.stack_st_X509_EXTENSION */
            	2186, 0,
            0, 32, 2, /* 2186: struct.stack_st_fake_X509_EXTENSION */
            	2193, 8,
            	334, 24,
            8884099, 8, 2, /* 2193: pointer_to_array_of_pointers_to_stack */
            	2200, 0,
            	331, 20,
            0, 8, 1, /* 2200: pointer.X509_EXTENSION */
            	1139, 0,
            1, 8, 1, /* 2205: pointer.struct.stack_st_GENERAL_NAME */
            	2210, 0,
            0, 32, 2, /* 2210: struct.stack_st_fake_GENERAL_NAME */
            	2217, 8,
            	334, 24,
            8884099, 8, 2, /* 2217: pointer_to_array_of_pointers_to_stack */
            	2224, 0,
            	331, 20,
            0, 8, 1, /* 2224: pointer.GENERAL_NAME */
            	1218, 0,
            0, 120, 10, /* 2229: struct.X509_crl_st */
            	2252, 0,
            	85, 8,
            	189, 16,
            	1180, 32,
            	2102, 40,
            	67, 56,
            	67, 64,
            	2257, 96,
            	2298, 104,
            	2306, 112,
            1, 8, 1, /* 2252: pointer.struct.X509_crl_info_st */
            	2107, 0,
            1, 8, 1, /* 2257: pointer.struct.stack_st_GENERAL_NAMES */
            	2262, 0,
            0, 32, 2, /* 2262: struct.stack_st_fake_GENERAL_NAMES */
            	2269, 8,
            	334, 24,
            8884099, 8, 2, /* 2269: pointer_to_array_of_pointers_to_stack */
            	2276, 0,
            	331, 20,
            0, 8, 1, /* 2276: pointer.GENERAL_NAMES */
            	2281, 0,
            0, 0, 1, /* 2281: GENERAL_NAMES */
            	2286, 0,
            0, 32, 1, /* 2286: struct.stack_st_GENERAL_NAME */
            	2291, 0,
            0, 32, 2, /* 2291: struct.stack_st */
            	560, 8,
            	334, 24,
            1, 8, 1, /* 2298: pointer.struct.x509_crl_method_st */
            	2303, 0,
            0, 0, 0, /* 2303: struct.x509_crl_method_st */
            0, 8, 0, /* 2306: pointer.void */
            1, 8, 1, /* 2309: pointer.struct.X509_crl_st */
            	2229, 0,
            0, 0, 0, /* 2314: struct.X509_POLICY_TREE_st */
            1, 8, 1, /* 2317: pointer.struct.X509_POLICY_TREE_st */
            	2314, 0,
            0, 24, 1, /* 2322: struct.ASN1_ENCODING_st */
            	77, 0,
            1, 8, 1, /* 2327: pointer.struct.stack_st_X509_EXTENSION */
            	2332, 0,
            0, 32, 2, /* 2332: struct.stack_st_fake_X509_EXTENSION */
            	2339, 8,
            	334, 24,
            8884099, 8, 2, /* 2339: pointer_to_array_of_pointers_to_stack */
            	2346, 0,
            	331, 20,
            0, 8, 1, /* 2346: pointer.X509_EXTENSION */
            	1139, 0,
            1, 8, 1, /* 2351: pointer.struct.buf_mem_st */
            	2356, 0,
            0, 24, 1, /* 2356: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 2361: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2366, 0,
            0, 32, 2, /* 2366: struct.stack_st_fake_X509_NAME_ENTRY */
            	2373, 8,
            	334, 24,
            8884099, 8, 2, /* 2373: pointer_to_array_of_pointers_to_stack */
            	2380, 0,
            	331, 20,
            0, 8, 1, /* 2380: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 2385: pointer.struct.X509_name_st */
            	2390, 0,
            0, 40, 3, /* 2390: struct.X509_name_st */
            	2361, 0,
            	2351, 16,
            	77, 24,
            1, 8, 1, /* 2399: pointer.struct.asn1_string_st */
            	2404, 0,
            0, 24, 1, /* 2404: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2409: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2414: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2419: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2424: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2429: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2434: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2439: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2444: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2449: pointer.struct.asn1_string_st */
            	2404, 0,
            0, 8, 20, /* 2454: union.unknown */
            	174, 0,
            	2497, 0,
            	2502, 0,
            	2516, 0,
            	2449, 0,
            	2521, 0,
            	2444, 0,
            	2526, 0,
            	2531, 0,
            	2439, 0,
            	2434, 0,
            	2429, 0,
            	2424, 0,
            	2419, 0,
            	2414, 0,
            	2409, 0,
            	2399, 0,
            	2497, 0,
            	2497, 0,
            	249, 0,
            1, 8, 1, /* 2497: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2502: pointer.struct.asn1_object_st */
            	2507, 0,
            0, 40, 3, /* 2507: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2516: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2521: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2526: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 2531: pointer.struct.asn1_string_st */
            	2404, 0,
            0, 16, 1, /* 2536: struct.asn1_type_st */
            	2454, 8,
            1, 8, 1, /* 2541: pointer.struct.asn1_type_st */
            	2536, 0,
            0, 24, 1, /* 2546: struct.buf_mem_st */
            	174, 8,
            0, 16, 2, /* 2551: struct.X509_algor_st */
            	2558, 0,
            	2572, 8,
            1, 8, 1, /* 2558: pointer.struct.asn1_object_st */
            	2563, 0,
            0, 40, 3, /* 2563: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 2572: pointer.struct.asn1_type_st */
            	2577, 0,
            0, 16, 1, /* 2577: struct.asn1_type_st */
            	2582, 8,
            0, 8, 20, /* 2582: union.unknown */
            	174, 0,
            	2625, 0,
            	2558, 0,
            	2635, 0,
            	2640, 0,
            	2645, 0,
            	2650, 0,
            	2655, 0,
            	2660, 0,
            	2665, 0,
            	2670, 0,
            	2675, 0,
            	2680, 0,
            	2685, 0,
            	2690, 0,
            	2695, 0,
            	2700, 0,
            	2625, 0,
            	2625, 0,
            	249, 0,
            1, 8, 1, /* 2625: pointer.struct.asn1_string_st */
            	2630, 0,
            0, 24, 1, /* 2630: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 2635: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2640: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2645: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2650: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2655: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2660: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2665: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2670: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2675: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2680: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2685: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2690: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2695: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2700: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2705: pointer.struct.rsa_st */
            	2710, 0,
            0, 168, 17, /* 2710: struct.rsa_st */
            	2747, 16,
            	402, 24,
            	2802, 32,
            	2802, 40,
            	2802, 48,
            	2802, 56,
            	2802, 64,
            	2802, 72,
            	2802, 80,
            	2802, 88,
            	2812, 96,
            	2834, 120,
            	2834, 128,
            	2834, 136,
            	174, 144,
            	579, 152,
            	579, 160,
            1, 8, 1, /* 2747: pointer.struct.rsa_meth_st */
            	2752, 0,
            0, 112, 13, /* 2752: struct.rsa_meth_st */
            	111, 0,
            	2781, 8,
            	2781, 16,
            	2781, 24,
            	2781, 32,
            	2784, 40,
            	2787, 48,
            	2790, 56,
            	2790, 64,
            	174, 80,
            	2793, 88,
            	2796, 96,
            	2799, 104,
            8884097, 8, 0, /* 2781: pointer.func */
            8884097, 8, 0, /* 2784: pointer.func */
            8884097, 8, 0, /* 2787: pointer.func */
            8884097, 8, 0, /* 2790: pointer.func */
            8884097, 8, 0, /* 2793: pointer.func */
            8884097, 8, 0, /* 2796: pointer.func */
            8884097, 8, 0, /* 2799: pointer.func */
            1, 8, 1, /* 2802: pointer.struct.bignum_st */
            	2807, 0,
            0, 24, 1, /* 2807: struct.bignum_st */
            	530, 0,
            0, 16, 1, /* 2812: struct.crypto_ex_data_st */
            	2817, 0,
            1, 8, 1, /* 2817: pointer.struct.stack_st_void */
            	2822, 0,
            0, 32, 1, /* 2822: struct.stack_st_void */
            	2827, 0,
            0, 32, 2, /* 2827: struct.stack_st */
            	560, 8,
            	334, 24,
            1, 8, 1, /* 2834: pointer.struct.bn_mont_ctx_st */
            	2839, 0,
            0, 96, 3, /* 2839: struct.bn_mont_ctx_st */
            	2807, 8,
            	2807, 32,
            	2807, 56,
            1, 8, 1, /* 2848: pointer.struct.ASN1_VALUE_st */
            	2853, 0,
            0, 0, 0, /* 2853: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2856: pointer.struct.stack_st_ASN1_OBJECT */
            	2861, 0,
            0, 32, 2, /* 2861: struct.stack_st_fake_ASN1_OBJECT */
            	2868, 8,
            	334, 24,
            8884099, 8, 2, /* 2868: pointer_to_array_of_pointers_to_stack */
            	2875, 0,
            	331, 20,
            0, 8, 1, /* 2875: pointer.ASN1_OBJECT */
            	2021, 0,
            1, 8, 1, /* 2880: pointer.struct.X509_crl_info_st */
            	2885, 0,
            0, 80, 8, /* 2885: struct.X509_crl_info_st */
            	2635, 0,
            	2904, 8,
            	2909, 16,
            	2952, 24,
            	2952, 32,
            	2957, 40,
            	2981, 48,
            	3005, 56,
            1, 8, 1, /* 2904: pointer.struct.X509_algor_st */
            	2551, 0,
            1, 8, 1, /* 2909: pointer.struct.X509_name_st */
            	2914, 0,
            0, 40, 3, /* 2914: struct.X509_name_st */
            	2923, 0,
            	2947, 16,
            	77, 24,
            1, 8, 1, /* 2923: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2928, 0,
            0, 32, 2, /* 2928: struct.stack_st_fake_X509_NAME_ENTRY */
            	2935, 8,
            	334, 24,
            8884099, 8, 2, /* 2935: pointer_to_array_of_pointers_to_stack */
            	2942, 0,
            	331, 20,
            0, 8, 1, /* 2942: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 2947: pointer.struct.buf_mem_st */
            	2546, 0,
            1, 8, 1, /* 2952: pointer.struct.asn1_string_st */
            	2630, 0,
            1, 8, 1, /* 2957: pointer.struct.stack_st_X509_REVOKED */
            	2962, 0,
            0, 32, 2, /* 2962: struct.stack_st_fake_X509_REVOKED */
            	2969, 8,
            	334, 24,
            8884099, 8, 2, /* 2969: pointer_to_array_of_pointers_to_stack */
            	2976, 0,
            	331, 20,
            0, 8, 1, /* 2976: pointer.X509_REVOKED */
            	2150, 0,
            1, 8, 1, /* 2981: pointer.struct.stack_st_X509_EXTENSION */
            	2986, 0,
            0, 32, 2, /* 2986: struct.stack_st_fake_X509_EXTENSION */
            	2993, 8,
            	334, 24,
            8884099, 8, 2, /* 2993: pointer_to_array_of_pointers_to_stack */
            	3000, 0,
            	331, 20,
            0, 8, 1, /* 3000: pointer.X509_EXTENSION */
            	1139, 0,
            0, 24, 1, /* 3005: struct.ASN1_ENCODING_st */
            	77, 0,
            8884097, 8, 0, /* 3010: pointer.func */
            8884097, 8, 0, /* 3013: pointer.func */
            1, 8, 1, /* 3016: pointer.struct.X509_crl_info_st */
            	3021, 0,
            0, 80, 8, /* 3021: struct.X509_crl_info_st */
            	2516, 0,
            	3040, 8,
            	2385, 16,
            	3052, 24,
            	3052, 32,
            	3057, 40,
            	2327, 48,
            	2322, 56,
            1, 8, 1, /* 3040: pointer.struct.X509_algor_st */
            	3045, 0,
            0, 16, 2, /* 3045: struct.X509_algor_st */
            	2502, 0,
            	2541, 8,
            1, 8, 1, /* 3052: pointer.struct.asn1_string_st */
            	2404, 0,
            1, 8, 1, /* 3057: pointer.struct.stack_st_X509_REVOKED */
            	3062, 0,
            0, 32, 2, /* 3062: struct.stack_st_fake_X509_REVOKED */
            	3069, 8,
            	334, 24,
            8884099, 8, 2, /* 3069: pointer_to_array_of_pointers_to_stack */
            	3076, 0,
            	331, 20,
            0, 8, 1, /* 3076: pointer.X509_REVOKED */
            	2150, 0,
            0, 0, 1, /* 3081: X509_CRL */
            	3086, 0,
            0, 120, 10, /* 3086: struct.X509_crl_st */
            	3016, 0,
            	3040, 8,
            	2521, 16,
            	3109, 32,
            	3117, 40,
            	2516, 56,
            	2516, 64,
            	2257, 96,
            	2298, 104,
            	2306, 112,
            1, 8, 1, /* 3109: pointer.struct.AUTHORITY_KEYID_st */
            	3114, 0,
            0, 0, 0, /* 3114: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3117: pointer.struct.ISSUING_DIST_POINT_st */
            	3122, 0,
            0, 0, 0, /* 3122: struct.ISSUING_DIST_POINT_st */
            0, 144, 12, /* 3125: struct.dh_st */
            	3152, 8,
            	3152, 16,
            	3152, 32,
            	3152, 40,
            	3162, 56,
            	3152, 64,
            	3152, 72,
            	77, 80,
            	3152, 96,
            	3176, 112,
            	3198, 128,
            	3234, 136,
            1, 8, 1, /* 3152: pointer.struct.bignum_st */
            	3157, 0,
            0, 24, 1, /* 3157: struct.bignum_st */
            	530, 0,
            1, 8, 1, /* 3162: pointer.struct.bn_mont_ctx_st */
            	3167, 0,
            0, 96, 3, /* 3167: struct.bn_mont_ctx_st */
            	3157, 8,
            	3157, 32,
            	3157, 56,
            0, 16, 1, /* 3176: struct.crypto_ex_data_st */
            	3181, 0,
            1, 8, 1, /* 3181: pointer.struct.stack_st_void */
            	3186, 0,
            0, 32, 1, /* 3186: struct.stack_st_void */
            	3191, 0,
            0, 32, 2, /* 3191: struct.stack_st */
            	560, 8,
            	334, 24,
            1, 8, 1, /* 3198: pointer.struct.dh_method */
            	3203, 0,
            0, 72, 8, /* 3203: struct.dh_method */
            	111, 0,
            	3222, 8,
            	3225, 16,
            	3228, 24,
            	3222, 32,
            	3222, 40,
            	174, 56,
            	3231, 64,
            8884097, 8, 0, /* 3222: pointer.func */
            8884097, 8, 0, /* 3225: pointer.func */
            8884097, 8, 0, /* 3228: pointer.func */
            8884097, 8, 0, /* 3231: pointer.func */
            1, 8, 1, /* 3234: pointer.struct.engine_st */
            	3239, 0,
            0, 0, 0, /* 3239: struct.engine_st */
            0, 1, 0, /* 3242: char */
            0, 72, 8, /* 3245: struct.dh_method */
            	111, 0,
            	3264, 8,
            	3267, 16,
            	3270, 24,
            	3264, 32,
            	3264, 40,
            	174, 56,
            	3273, 64,
            8884097, 8, 0, /* 3264: pointer.func */
            8884097, 8, 0, /* 3267: pointer.func */
            8884097, 8, 0, /* 3270: pointer.func */
            8884097, 8, 0, /* 3273: pointer.func */
            8884097, 8, 0, /* 3276: pointer.func */
            8884097, 8, 0, /* 3279: pointer.func */
            0, 104, 11, /* 3282: struct.x509_cinf_st */
            	3307, 0,
            	3307, 8,
            	3317, 16,
            	3466, 24,
            	3514, 32,
            	3466, 40,
            	3531, 48,
            	3406, 56,
            	3406, 64,
            	3799, 72,
            	3823, 80,
            1, 8, 1, /* 3307: pointer.struct.asn1_string_st */
            	3312, 0,
            0, 24, 1, /* 3312: struct.asn1_string_st */
            	77, 8,
            1, 8, 1, /* 3317: pointer.struct.X509_algor_st */
            	3322, 0,
            0, 16, 2, /* 3322: struct.X509_algor_st */
            	3329, 0,
            	3343, 8,
            1, 8, 1, /* 3329: pointer.struct.asn1_object_st */
            	3334, 0,
            0, 40, 3, /* 3334: struct.asn1_object_st */
            	111, 0,
            	111, 8,
            	116, 24,
            1, 8, 1, /* 3343: pointer.struct.asn1_type_st */
            	3348, 0,
            0, 16, 1, /* 3348: struct.asn1_type_st */
            	3353, 8,
            0, 8, 20, /* 3353: union.unknown */
            	174, 0,
            	3396, 0,
            	3329, 0,
            	3307, 0,
            	3401, 0,
            	3406, 0,
            	3411, 0,
            	3416, 0,
            	3421, 0,
            	3426, 0,
            	3431, 0,
            	3436, 0,
            	3441, 0,
            	3446, 0,
            	3451, 0,
            	3456, 0,
            	3461, 0,
            	3396, 0,
            	3396, 0,
            	2848, 0,
            1, 8, 1, /* 3396: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3401: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3406: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3411: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3416: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3421: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3426: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3431: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3436: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3441: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3446: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3451: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3456: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3461: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3466: pointer.struct.X509_name_st */
            	3471, 0,
            0, 40, 3, /* 3471: struct.X509_name_st */
            	3480, 0,
            	3504, 16,
            	77, 24,
            1, 8, 1, /* 3480: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3485, 0,
            0, 32, 2, /* 3485: struct.stack_st_fake_X509_NAME_ENTRY */
            	3492, 8,
            	334, 24,
            8884099, 8, 2, /* 3492: pointer_to_array_of_pointers_to_stack */
            	3499, 0,
            	331, 20,
            0, 8, 1, /* 3499: pointer.X509_NAME_ENTRY */
            	295, 0,
            1, 8, 1, /* 3504: pointer.struct.buf_mem_st */
            	3509, 0,
            0, 24, 1, /* 3509: struct.buf_mem_st */
            	174, 8,
            1, 8, 1, /* 3514: pointer.struct.X509_val_st */
            	3519, 0,
            0, 16, 2, /* 3519: struct.X509_val_st */
            	3526, 0,
            	3526, 8,
            1, 8, 1, /* 3526: pointer.struct.asn1_string_st */
            	3312, 0,
            1, 8, 1, /* 3531: pointer.struct.X509_pubkey_st */
            	3536, 0,
            0, 24, 3, /* 3536: struct.X509_pubkey_st */
            	3317, 0,
            	3406, 8,
            	3545, 16,
            1, 8, 1, /* 3545: pointer.struct.evp_pkey_st */
            	3550, 0,
            0, 56, 4, /* 3550: struct.evp_pkey_st */
            	3561, 16,
            	3234, 24,
            	3569, 32,
            	3775, 48,
            1, 8, 1, /* 3561: pointer.struct.evp_pkey_asn1_method_st */
            	3566, 0,
            0, 0, 0, /* 3566: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3569: union.unknown */
            	174, 0,
            	3582, 0,
            	3684, 0,
            	3762, 0,
            	3767, 0,
            1, 8, 1, /* 3582: pointer.struct.rsa_st */
            	3587, 0,
            0, 168, 17, /* 3587: struct.rsa_st */
            	3624, 16,
            	3234, 24,
            	3152, 32,
            	3152, 40,
            	3152, 48,
            	3152, 56,
            	3152, 64,
            	3152, 72,
            	3152, 80,
            	3152, 88,
            	3176, 96,
            	3162, 120,
            	3162, 128,
            	3162, 136,
            	174, 144,
            	3676, 152,
            	3676, 160,
            1, 8, 1, /* 3624: pointer.struct.rsa_meth_st */
            	3629, 0,
            0, 112, 13, /* 3629: struct.rsa_meth_st */
            	111, 0,
            	3658, 8,
            	3658, 16,
            	3658, 24,
            	3658, 32,
            	3013, 40,
            	3661, 48,
            	3664, 56,
            	3664, 64,
            	174, 80,
            	3667, 88,
            	3670, 96,
            	3673, 104,
            8884097, 8, 0, /* 3658: pointer.func */
            8884097, 8, 0, /* 3661: pointer.func */
            8884097, 8, 0, /* 3664: pointer.func */
            8884097, 8, 0, /* 3667: pointer.func */
            8884097, 8, 0, /* 3670: pointer.func */
            8884097, 8, 0, /* 3673: pointer.func */
            1, 8, 1, /* 3676: pointer.struct.bn_blinding_st */
            	3681, 0,
            0, 0, 0, /* 3681: struct.bn_blinding_st */
            1, 8, 1, /* 3684: pointer.struct.dsa_st */
            	3689, 0,
            0, 136, 11, /* 3689: struct.dsa_st */
            	3152, 24,
            	3152, 32,
            	3152, 40,
            	3152, 48,
            	3152, 56,
            	3152, 64,
            	3152, 72,
            	3162, 88,
            	3176, 104,
            	3714, 120,
            	3234, 128,
            1, 8, 1, /* 3714: pointer.struct.dsa_method */
            	3719, 0,
            0, 96, 11, /* 3719: struct.dsa_method */
            	111, 0,
            	3744, 8,
            	3747, 16,
            	3750, 24,
            	3279, 32,
            	3753, 40,
            	3756, 48,
            	3756, 56,
            	174, 72,
            	3759, 80,
            	3756, 88,
            8884097, 8, 0, /* 3744: pointer.func */
            8884097, 8, 0, /* 3747: pointer.func */
            8884097, 8, 0, /* 3750: pointer.func */
            8884097, 8, 0, /* 3753: pointer.func */
            8884097, 8, 0, /* 3756: pointer.func */
            8884097, 8, 0, /* 3759: pointer.func */
            1, 8, 1, /* 3762: pointer.struct.dh_st */
            	3125, 0,
            1, 8, 1, /* 3767: pointer.struct.ec_key_st */
            	3772, 0,
            0, 0, 0, /* 3772: struct.ec_key_st */
            1, 8, 1, /* 3775: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3780, 0,
            0, 32, 2, /* 3780: struct.stack_st_fake_X509_ATTRIBUTE */
            	3787, 8,
            	334, 24,
            8884099, 8, 2, /* 3787: pointer_to_array_of_pointers_to_stack */
            	3794, 0,
            	331, 20,
            0, 8, 1, /* 3794: pointer.X509_ATTRIBUTE */
            	768, 0,
            1, 8, 1, /* 3799: pointer.struct.stack_st_X509_EXTENSION */
            	3804, 0,
            0, 32, 2, /* 3804: struct.stack_st_fake_X509_EXTENSION */
            	3811, 8,
            	334, 24,
            8884099, 8, 2, /* 3811: pointer_to_array_of_pointers_to_stack */
            	3818, 0,
            	331, 20,
            0, 8, 1, /* 3818: pointer.X509_EXTENSION */
            	1139, 0,
            0, 24, 1, /* 3823: struct.ASN1_ENCODING_st */
            	77, 0,
            0, 248, 25, /* 3828: struct.x509_store_ctx_st */
            	3881, 0,
            	5, 16,
            	4618, 24,
            	4793, 32,
            	4579, 40,
            	2306, 48,
            	4591, 56,
            	4594, 64,
            	4597, 72,
            	4600, 80,
            	4591, 88,
            	4603, 96,
            	4606, 104,
            	4609, 112,
            	4591, 120,
            	4612, 128,
            	4615, 136,
            	4591, 144,
            	4618, 160,
            	2317, 168,
            	5, 192,
            	5, 200,
            	2309, 208,
            	4817, 224,
            	538, 232,
            1, 8, 1, /* 3881: pointer.struct.x509_store_st */
            	3886, 0,
            0, 144, 15, /* 3886: struct.x509_store_st */
            	3919, 8,
            	4373, 16,
            	4579, 24,
            	4591, 32,
            	4594, 40,
            	4597, 48,
            	4600, 56,
            	4591, 64,
            	4603, 72,
            	4606, 80,
            	4609, 88,
            	4612, 96,
            	4615, 104,
            	4591, 112,
            	538, 120,
            1, 8, 1, /* 3919: pointer.struct.stack_st_X509_OBJECT */
            	3924, 0,
            0, 32, 2, /* 3924: struct.stack_st_fake_X509_OBJECT */
            	3931, 8,
            	334, 24,
            8884099, 8, 2, /* 3931: pointer_to_array_of_pointers_to_stack */
            	3938, 0,
            	331, 20,
            0, 8, 1, /* 3938: pointer.X509_OBJECT */
            	3943, 0,
            0, 0, 1, /* 3943: X509_OBJECT */
            	3948, 0,
            0, 16, 1, /* 3948: struct.x509_object_st */
            	3953, 8,
            0, 8, 4, /* 3953: union.unknown */
            	174, 0,
            	3964, 0,
            	4345, 0,
            	4052, 0,
            1, 8, 1, /* 3964: pointer.struct.x509_st */
            	3969, 0,
            0, 184, 12, /* 3969: struct.x509_st */
            	3996, 0,
            	2904, 8,
            	2645, 16,
            	174, 32,
            	2812, 40,
            	2650, 104,
            	3109, 112,
            	1488, 120,
            	4223, 128,
            	4247, 136,
            	4271, 144,
            	4279, 176,
            1, 8, 1, /* 3996: pointer.struct.x509_cinf_st */
            	4001, 0,
            0, 104, 11, /* 4001: struct.x509_cinf_st */
            	2635, 0,
            	2635, 8,
            	2904, 16,
            	2909, 24,
            	4026, 32,
            	2909, 40,
            	4038, 48,
            	2645, 56,
            	2645, 64,
            	2981, 72,
            	3005, 80,
            1, 8, 1, /* 4026: pointer.struct.X509_val_st */
            	4031, 0,
            0, 16, 2, /* 4031: struct.X509_val_st */
            	2952, 0,
            	2952, 8,
            1, 8, 1, /* 4038: pointer.struct.X509_pubkey_st */
            	4043, 0,
            0, 24, 3, /* 4043: struct.X509_pubkey_st */
            	2904, 0,
            	2645, 8,
            	4052, 16,
            1, 8, 1, /* 4052: pointer.struct.evp_pkey_st */
            	4057, 0,
            0, 56, 4, /* 4057: struct.evp_pkey_st */
            	394, 16,
            	402, 24,
            	4068, 32,
            	4199, 48,
            0, 8, 5, /* 4068: union.unknown */
            	174, 0,
            	2705, 0,
            	4081, 0,
            	4162, 0,
            	736, 0,
            1, 8, 1, /* 4081: pointer.struct.dsa_st */
            	4086, 0,
            0, 136, 11, /* 4086: struct.dsa_st */
            	2802, 24,
            	2802, 32,
            	2802, 40,
            	2802, 48,
            	2802, 56,
            	2802, 64,
            	2802, 72,
            	2834, 88,
            	2812, 104,
            	4111, 120,
            	402, 128,
            1, 8, 1, /* 4111: pointer.struct.dsa_method */
            	4116, 0,
            0, 96, 11, /* 4116: struct.dsa_method */
            	111, 0,
            	4141, 8,
            	4144, 16,
            	4147, 24,
            	4150, 32,
            	4153, 40,
            	4156, 48,
            	4156, 56,
            	174, 72,
            	4159, 80,
            	4156, 88,
            8884097, 8, 0, /* 4141: pointer.func */
            8884097, 8, 0, /* 4144: pointer.func */
            8884097, 8, 0, /* 4147: pointer.func */
            8884097, 8, 0, /* 4150: pointer.func */
            8884097, 8, 0, /* 4153: pointer.func */
            8884097, 8, 0, /* 4156: pointer.func */
            8884097, 8, 0, /* 4159: pointer.func */
            1, 8, 1, /* 4162: pointer.struct.dh_st */
            	4167, 0,
            0, 144, 12, /* 4167: struct.dh_st */
            	2802, 8,
            	2802, 16,
            	2802, 32,
            	2802, 40,
            	2834, 56,
            	2802, 64,
            	2802, 72,
            	77, 80,
            	2802, 96,
            	2812, 112,
            	4194, 128,
            	402, 136,
            1, 8, 1, /* 4194: pointer.struct.dh_method */
            	3245, 0,
            1, 8, 1, /* 4199: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4204, 0,
            0, 32, 2, /* 4204: struct.stack_st_fake_X509_ATTRIBUTE */
            	4211, 8,
            	334, 24,
            8884099, 8, 2, /* 4211: pointer_to_array_of_pointers_to_stack */
            	4218, 0,
            	331, 20,
            0, 8, 1, /* 4218: pointer.X509_ATTRIBUTE */
            	768, 0,
            1, 8, 1, /* 4223: pointer.struct.stack_st_DIST_POINT */
            	4228, 0,
            0, 32, 2, /* 4228: struct.stack_st_fake_DIST_POINT */
            	4235, 8,
            	334, 24,
            8884099, 8, 2, /* 4235: pointer_to_array_of_pointers_to_stack */
            	4242, 0,
            	331, 20,
            0, 8, 1, /* 4242: pointer.DIST_POINT */
            	1520, 0,
            1, 8, 1, /* 4247: pointer.struct.stack_st_GENERAL_NAME */
            	4252, 0,
            0, 32, 2, /* 4252: struct.stack_st_fake_GENERAL_NAME */
            	4259, 8,
            	334, 24,
            8884099, 8, 2, /* 4259: pointer_to_array_of_pointers_to_stack */
            	4266, 0,
            	331, 20,
            0, 8, 1, /* 4266: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 4271: pointer.struct.NAME_CONSTRAINTS_st */
            	4276, 0,
            0, 0, 0, /* 4276: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4279: pointer.struct.x509_cert_aux_st */
            	4284, 0,
            0, 40, 5, /* 4284: struct.x509_cert_aux_st */
            	4297, 0,
            	4297, 8,
            	2700, 16,
            	2650, 24,
            	4321, 32,
            1, 8, 1, /* 4297: pointer.struct.stack_st_ASN1_OBJECT */
            	4302, 0,
            0, 32, 2, /* 4302: struct.stack_st_fake_ASN1_OBJECT */
            	4309, 8,
            	334, 24,
            8884099, 8, 2, /* 4309: pointer_to_array_of_pointers_to_stack */
            	4316, 0,
            	331, 20,
            0, 8, 1, /* 4316: pointer.ASN1_OBJECT */
            	2021, 0,
            1, 8, 1, /* 4321: pointer.struct.stack_st_X509_ALGOR */
            	4326, 0,
            0, 32, 2, /* 4326: struct.stack_st_fake_X509_ALGOR */
            	4333, 8,
            	334, 24,
            8884099, 8, 2, /* 4333: pointer_to_array_of_pointers_to_stack */
            	4340, 0,
            	331, 20,
            0, 8, 1, /* 4340: pointer.X509_ALGOR */
            	2059, 0,
            1, 8, 1, /* 4345: pointer.struct.X509_crl_st */
            	4350, 0,
            0, 120, 10, /* 4350: struct.X509_crl_st */
            	2880, 0,
            	2904, 8,
            	2645, 16,
            	3109, 32,
            	3117, 40,
            	2635, 56,
            	2635, 64,
            	2257, 96,
            	2298, 104,
            	2306, 112,
            1, 8, 1, /* 4373: pointer.struct.stack_st_X509_LOOKUP */
            	4378, 0,
            0, 32, 2, /* 4378: struct.stack_st_fake_X509_LOOKUP */
            	4385, 8,
            	334, 24,
            8884099, 8, 2, /* 4385: pointer_to_array_of_pointers_to_stack */
            	4392, 0,
            	331, 20,
            0, 8, 1, /* 4392: pointer.X509_LOOKUP */
            	4397, 0,
            0, 0, 1, /* 4397: X509_LOOKUP */
            	4402, 0,
            0, 32, 3, /* 4402: struct.x509_lookup_st */
            	4411, 8,
            	174, 16,
            	4460, 24,
            1, 8, 1, /* 4411: pointer.struct.x509_lookup_method_st */
            	4416, 0,
            0, 80, 10, /* 4416: struct.x509_lookup_method_st */
            	111, 0,
            	4439, 8,
            	4442, 16,
            	4439, 24,
            	4439, 32,
            	4445, 40,
            	4448, 48,
            	4451, 56,
            	4454, 64,
            	4457, 72,
            8884097, 8, 0, /* 4439: pointer.func */
            8884097, 8, 0, /* 4442: pointer.func */
            8884097, 8, 0, /* 4445: pointer.func */
            8884097, 8, 0, /* 4448: pointer.func */
            8884097, 8, 0, /* 4451: pointer.func */
            8884097, 8, 0, /* 4454: pointer.func */
            8884097, 8, 0, /* 4457: pointer.func */
            1, 8, 1, /* 4460: pointer.struct.x509_store_st */
            	4465, 0,
            0, 144, 15, /* 4465: struct.x509_store_st */
            	4498, 8,
            	4522, 16,
            	4546, 24,
            	4558, 32,
            	4561, 40,
            	4564, 48,
            	3276, 56,
            	4558, 64,
            	4567, 72,
            	4570, 80,
            	4573, 88,
            	3010, 96,
            	4576, 104,
            	4558, 112,
            	2812, 120,
            1, 8, 1, /* 4498: pointer.struct.stack_st_X509_OBJECT */
            	4503, 0,
            0, 32, 2, /* 4503: struct.stack_st_fake_X509_OBJECT */
            	4510, 8,
            	334, 24,
            8884099, 8, 2, /* 4510: pointer_to_array_of_pointers_to_stack */
            	4517, 0,
            	331, 20,
            0, 8, 1, /* 4517: pointer.X509_OBJECT */
            	3943, 0,
            1, 8, 1, /* 4522: pointer.struct.stack_st_X509_LOOKUP */
            	4527, 0,
            0, 32, 2, /* 4527: struct.stack_st_fake_X509_LOOKUP */
            	4534, 8,
            	334, 24,
            8884099, 8, 2, /* 4534: pointer_to_array_of_pointers_to_stack */
            	4541, 0,
            	331, 20,
            0, 8, 1, /* 4541: pointer.X509_LOOKUP */
            	4397, 0,
            1, 8, 1, /* 4546: pointer.struct.X509_VERIFY_PARAM_st */
            	4551, 0,
            0, 56, 2, /* 4551: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	4297, 48,
            8884097, 8, 0, /* 4558: pointer.func */
            8884097, 8, 0, /* 4561: pointer.func */
            8884097, 8, 0, /* 4564: pointer.func */
            8884097, 8, 0, /* 4567: pointer.func */
            8884097, 8, 0, /* 4570: pointer.func */
            8884097, 8, 0, /* 4573: pointer.func */
            8884097, 8, 0, /* 4576: pointer.func */
            1, 8, 1, /* 4579: pointer.struct.X509_VERIFY_PARAM_st */
            	4584, 0,
            0, 56, 2, /* 4584: struct.X509_VERIFY_PARAM_st */
            	174, 0,
            	1997, 48,
            8884097, 8, 0, /* 4591: pointer.func */
            8884097, 8, 0, /* 4594: pointer.func */
            8884097, 8, 0, /* 4597: pointer.func */
            8884097, 8, 0, /* 4600: pointer.func */
            8884097, 8, 0, /* 4603: pointer.func */
            8884097, 8, 0, /* 4606: pointer.func */
            8884097, 8, 0, /* 4609: pointer.func */
            8884097, 8, 0, /* 4612: pointer.func */
            8884097, 8, 0, /* 4615: pointer.func */
            1, 8, 1, /* 4618: pointer.struct.stack_st_X509 */
            	4623, 0,
            0, 32, 2, /* 4623: struct.stack_st_fake_X509 */
            	4630, 8,
            	334, 24,
            8884099, 8, 2, /* 4630: pointer_to_array_of_pointers_to_stack */
            	4637, 0,
            	331, 20,
            0, 8, 1, /* 4637: pointer.X509 */
            	4642, 0,
            0, 0, 1, /* 4642: X509 */
            	4647, 0,
            0, 184, 12, /* 4647: struct.x509_st */
            	4674, 0,
            	3317, 8,
            	3406, 16,
            	174, 32,
            	3176, 40,
            	3411, 104,
            	4679, 112,
            	4687, 120,
            	4695, 128,
            	4719, 136,
            	4743, 144,
            	4751, 176,
            1, 8, 1, /* 4674: pointer.struct.x509_cinf_st */
            	3282, 0,
            1, 8, 1, /* 4679: pointer.struct.AUTHORITY_KEYID_st */
            	4684, 0,
            0, 0, 0, /* 4684: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4687: pointer.struct.X509_POLICY_CACHE_st */
            	4692, 0,
            0, 0, 0, /* 4692: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4695: pointer.struct.stack_st_DIST_POINT */
            	4700, 0,
            0, 32, 2, /* 4700: struct.stack_st_fake_DIST_POINT */
            	4707, 8,
            	334, 24,
            8884099, 8, 2, /* 4707: pointer_to_array_of_pointers_to_stack */
            	4714, 0,
            	331, 20,
            0, 8, 1, /* 4714: pointer.DIST_POINT */
            	1520, 0,
            1, 8, 1, /* 4719: pointer.struct.stack_st_GENERAL_NAME */
            	4724, 0,
            0, 32, 2, /* 4724: struct.stack_st_fake_GENERAL_NAME */
            	4731, 8,
            	334, 24,
            8884099, 8, 2, /* 4731: pointer_to_array_of_pointers_to_stack */
            	4738, 0,
            	331, 20,
            0, 8, 1, /* 4738: pointer.GENERAL_NAME */
            	1218, 0,
            1, 8, 1, /* 4743: pointer.struct.NAME_CONSTRAINTS_st */
            	4748, 0,
            0, 0, 0, /* 4748: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4751: pointer.struct.x509_cert_aux_st */
            	4756, 0,
            0, 40, 5, /* 4756: struct.x509_cert_aux_st */
            	2856, 0,
            	2856, 8,
            	3461, 16,
            	3411, 24,
            	4769, 32,
            1, 8, 1, /* 4769: pointer.struct.stack_st_X509_ALGOR */
            	4774, 0,
            0, 32, 2, /* 4774: struct.stack_st_fake_X509_ALGOR */
            	4781, 8,
            	334, 24,
            8884099, 8, 2, /* 4781: pointer_to_array_of_pointers_to_stack */
            	4788, 0,
            	331, 20,
            0, 8, 1, /* 4788: pointer.X509_ALGOR */
            	2059, 0,
            1, 8, 1, /* 4793: pointer.struct.stack_st_X509_CRL */
            	4798, 0,
            0, 32, 2, /* 4798: struct.stack_st_fake_X509_CRL */
            	4805, 8,
            	334, 24,
            8884099, 8, 2, /* 4805: pointer_to_array_of_pointers_to_stack */
            	4812, 0,
            	331, 20,
            0, 8, 1, /* 4812: pointer.X509_CRL */
            	3081, 0,
            1, 8, 1, /* 4817: pointer.struct.x509_store_ctx_st */
            	3828, 0,
        },
        .arg_entity_index = { 0, 4817, 5, },
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

