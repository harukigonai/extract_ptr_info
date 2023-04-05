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

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d);

void * X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_ext_d2i called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    else {
        void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
        orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
        return orig_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    }
}

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    void * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.asn1_string_st */
            	5, 0,
            0, 24, 1, /* 5: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 10: pointer.unsigned char */
            	15, 0,
            0, 1, 0, /* 15: unsigned char */
            1, 8, 1, /* 18: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 23: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 28: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 33: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 38: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 43: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 48: pointer.struct.asn1_string_st */
            	5, 0,
            0, 8, 20, /* 53: union.unknown */
            	96, 0,
            	48, 0,
            	101, 0,
            	43, 0,
            	125, 0,
            	130, 0,
            	38, 0,
            	135, 0,
            	33, 0,
            	28, 0,
            	23, 0,
            	140, 0,
            	145, 0,
            	18, 0,
            	0, 0,
            	150, 0,
            	155, 0,
            	48, 0,
            	48, 0,
            	160, 0,
            1, 8, 1, /* 96: pointer.char */
            	64096, 0,
            1, 8, 1, /* 101: pointer.struct.asn1_object_st */
            	106, 0,
            0, 40, 3, /* 106: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 115: pointer.char */
            	64096, 0,
            1, 8, 1, /* 120: pointer.unsigned char */
            	15, 0,
            1, 8, 1, /* 125: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 130: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 135: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 140: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 145: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 150: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 155: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 160: pointer.struct.ASN1_VALUE_st */
            	165, 0,
            0, 0, 0, /* 165: struct.ASN1_VALUE_st */
            0, 16, 2, /* 168: struct.X509_algor_st */
            	101, 0,
            	175, 8,
            1, 8, 1, /* 175: pointer.struct.asn1_type_st */
            	180, 0,
            0, 16, 1, /* 180: struct.asn1_type_st */
            	53, 8,
            0, 0, 1, /* 185: X509_ALGOR */
            	168, 0,
            1, 8, 1, /* 190: pointer.struct.stack_st_X509_ALGOR */
            	195, 0,
            0, 32, 2, /* 195: struct.stack_st_fake_X509_ALGOR */
            	202, 8,
            	217, 24,
            64099, 8, 2, /* 202: pointer_to_array_of_pointers_to_stack */
            	209, 0,
            	214, 20,
            0, 8, 1, /* 209: pointer.X509_ALGOR */
            	185, 0,
            0, 4, 0, /* 214: int */
            64097, 8, 0, /* 217: pointer.func */
            0, 40, 3, /* 220: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            0, 0, 1, /* 229: ASN1_OBJECT */
            	220, 0,
            1, 8, 1, /* 234: pointer.struct.stack_st_ASN1_OBJECT */
            	239, 0,
            0, 32, 2, /* 239: struct.stack_st_fake_ASN1_OBJECT */
            	246, 8,
            	217, 24,
            64099, 8, 2, /* 246: pointer_to_array_of_pointers_to_stack */
            	253, 0,
            	214, 20,
            0, 8, 1, /* 253: pointer.ASN1_OBJECT */
            	229, 0,
            1, 8, 1, /* 258: pointer.struct.x509_cert_aux_st */
            	263, 0,
            0, 40, 5, /* 263: struct.x509_cert_aux_st */
            	234, 0,
            	234, 8,
            	276, 16,
            	286, 24,
            	190, 32,
            1, 8, 1, /* 276: pointer.struct.asn1_string_st */
            	281, 0,
            0, 24, 1, /* 281: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 286: pointer.struct.asn1_string_st */
            	281, 0,
            0, 16, 2, /* 291: struct.EDIPartyName_st */
            	298, 0,
            	298, 8,
            1, 8, 1, /* 298: pointer.struct.asn1_string_st */
            	303, 0,
            0, 24, 1, /* 303: struct.asn1_string_st */
            	10, 8,
            0, 24, 1, /* 308: struct.buf_mem_st */
            	96, 8,
            1, 8, 1, /* 313: pointer.struct.asn1_string_st */
            	318, 0,
            0, 24, 1, /* 318: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 323: pointer.struct.asn1_string_st */
            	318, 0,
            0, 40, 3, /* 328: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            0, 40, 3, /* 337: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 346: pointer.struct.asn1_string_st */
            	351, 0,
            0, 24, 1, /* 351: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 356: pointer.struct.asn1_string_st */
            	361, 0,
            0, 24, 1, /* 361: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 366: pointer.struct.asn1_string_st */
            	303, 0,
            0, 0, 1, /* 371: X509_ATTRIBUTE */
            	376, 0,
            0, 24, 2, /* 376: struct.x509_attributes_st */
            	383, 0,
            	388, 16,
            1, 8, 1, /* 383: pointer.struct.asn1_object_st */
            	337, 0,
            0, 8, 3, /* 388: union.unknown */
            	96, 0,
            	397, 0,
            	552, 0,
            1, 8, 1, /* 397: pointer.struct.stack_st_ASN1_TYPE */
            	402, 0,
            0, 32, 2, /* 402: struct.stack_st_fake_ASN1_TYPE */
            	409, 8,
            	217, 24,
            64099, 8, 2, /* 409: pointer_to_array_of_pointers_to_stack */
            	416, 0,
            	214, 20,
            0, 8, 1, /* 416: pointer.ASN1_TYPE */
            	421, 0,
            0, 0, 1, /* 421: ASN1_TYPE */
            	426, 0,
            0, 16, 1, /* 426: struct.asn1_type_st */
            	431, 8,
            0, 8, 20, /* 431: union.unknown */
            	96, 0,
            	474, 0,
            	479, 0,
            	323, 0,
            	484, 0,
            	313, 0,
            	489, 0,
            	494, 0,
            	499, 0,
            	504, 0,
            	509, 0,
            	514, 0,
            	519, 0,
            	524, 0,
            	529, 0,
            	534, 0,
            	539, 0,
            	474, 0,
            	474, 0,
            	544, 0,
            1, 8, 1, /* 474: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 479: pointer.struct.asn1_object_st */
            	328, 0,
            1, 8, 1, /* 484: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 489: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 494: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 499: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 504: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 509: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 514: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 519: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 524: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 529: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 534: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 539: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 544: pointer.struct.ASN1_VALUE_st */
            	549, 0,
            0, 0, 0, /* 549: struct.ASN1_VALUE_st */
            1, 8, 1, /* 552: pointer.struct.asn1_type_st */
            	557, 0,
            0, 16, 1, /* 557: struct.asn1_type_st */
            	562, 8,
            0, 8, 20, /* 562: union.unknown */
            	96, 0,
            	605, 0,
            	383, 0,
            	615, 0,
            	620, 0,
            	625, 0,
            	630, 0,
            	635, 0,
            	640, 0,
            	645, 0,
            	650, 0,
            	655, 0,
            	660, 0,
            	665, 0,
            	670, 0,
            	675, 0,
            	680, 0,
            	605, 0,
            	605, 0,
            	160, 0,
            1, 8, 1, /* 605: pointer.struct.asn1_string_st */
            	610, 0,
            0, 24, 1, /* 610: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 615: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 620: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 625: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 630: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 635: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 640: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 645: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 650: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 655: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 660: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 665: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 670: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 675: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 680: pointer.struct.asn1_string_st */
            	610, 0,
            1, 8, 1, /* 685: pointer.struct.stack_st_X509_ATTRIBUTE */
            	690, 0,
            0, 32, 2, /* 690: struct.stack_st_fake_X509_ATTRIBUTE */
            	697, 8,
            	217, 24,
            64099, 8, 2, /* 697: pointer_to_array_of_pointers_to_stack */
            	704, 0,
            	214, 20,
            0, 8, 1, /* 704: pointer.X509_ATTRIBUTE */
            	371, 0,
            1, 8, 1, /* 709: pointer.struct.ec_key_st */
            	714, 0,
            0, 0, 0, /* 714: struct.ec_key_st */
            64097, 8, 0, /* 717: pointer.func */
            1, 8, 1, /* 720: pointer.struct.asn1_object_st */
            	725, 0,
            0, 40, 3, /* 725: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            0, 40, 3, /* 734: struct.X509_name_st */
            	743, 0,
            	803, 16,
            	10, 24,
            1, 8, 1, /* 743: pointer.struct.stack_st_X509_NAME_ENTRY */
            	748, 0,
            0, 32, 2, /* 748: struct.stack_st_fake_X509_NAME_ENTRY */
            	755, 8,
            	217, 24,
            64099, 8, 2, /* 755: pointer_to_array_of_pointers_to_stack */
            	762, 0,
            	214, 20,
            0, 8, 1, /* 762: pointer.X509_NAME_ENTRY */
            	767, 0,
            0, 0, 1, /* 767: X509_NAME_ENTRY */
            	772, 0,
            0, 24, 2, /* 772: struct.X509_name_entry_st */
            	779, 0,
            	793, 8,
            1, 8, 1, /* 779: pointer.struct.asn1_object_st */
            	784, 0,
            0, 40, 3, /* 784: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 793: pointer.struct.asn1_string_st */
            	798, 0,
            0, 24, 1, /* 798: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 803: pointer.struct.buf_mem_st */
            	808, 0,
            0, 24, 1, /* 808: struct.buf_mem_st */
            	96, 8,
            64097, 8, 0, /* 813: pointer.func */
            0, 96, 11, /* 816: struct.dsa_method */
            	115, 0,
            	841, 8,
            	844, 16,
            	813, 24,
            	847, 32,
            	717, 40,
            	850, 48,
            	850, 56,
            	96, 72,
            	853, 80,
            	850, 88,
            64097, 8, 0, /* 841: pointer.func */
            64097, 8, 0, /* 844: pointer.func */
            64097, 8, 0, /* 847: pointer.func */
            64097, 8, 0, /* 850: pointer.func */
            64097, 8, 0, /* 853: pointer.func */
            1, 8, 1, /* 856: pointer.struct.stack_st_void */
            	861, 0,
            0, 32, 1, /* 861: struct.stack_st_void */
            	866, 0,
            0, 32, 2, /* 866: struct.stack_st */
            	873, 8,
            	217, 24,
            1, 8, 1, /* 873: pointer.pointer.char */
            	96, 0,
            1, 8, 1, /* 878: pointer.struct.dsa_method */
            	816, 0,
            1, 8, 1, /* 883: pointer.struct.EDIPartyName_st */
            	291, 0,
            1, 8, 1, /* 888: pointer.struct.dsa_st */
            	893, 0,
            0, 136, 11, /* 893: struct.dsa_st */
            	918, 24,
            	918, 32,
            	918, 40,
            	918, 48,
            	918, 56,
            	918, 64,
            	918, 72,
            	936, 88,
            	950, 104,
            	878, 120,
            	955, 128,
            1, 8, 1, /* 918: pointer.struct.bignum_st */
            	923, 0,
            0, 24, 1, /* 923: struct.bignum_st */
            	928, 0,
            1, 8, 1, /* 928: pointer.unsigned int */
            	933, 0,
            0, 4, 0, /* 933: unsigned int */
            1, 8, 1, /* 936: pointer.struct.bn_mont_ctx_st */
            	941, 0,
            0, 96, 3, /* 941: struct.bn_mont_ctx_st */
            	923, 8,
            	923, 32,
            	923, 56,
            0, 16, 1, /* 950: struct.crypto_ex_data_st */
            	856, 0,
            1, 8, 1, /* 955: pointer.struct.engine_st */
            	960, 0,
            0, 0, 0, /* 960: struct.engine_st */
            1, 8, 1, /* 963: pointer.struct.bn_blinding_st */
            	968, 0,
            0, 0, 0, /* 968: struct.bn_blinding_st */
            0, 104, 11, /* 971: struct.x509_cinf_st */
            	996, 0,
            	996, 8,
            	1001, 16,
            	1126, 24,
            	1174, 32,
            	1126, 40,
            	1191, 48,
            	1076, 56,
            	1076, 64,
            	1407, 72,
            	1457, 80,
            1, 8, 1, /* 996: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1001: pointer.struct.X509_algor_st */
            	1006, 0,
            0, 16, 2, /* 1006: struct.X509_algor_st */
            	720, 0,
            	1013, 8,
            1, 8, 1, /* 1013: pointer.struct.asn1_type_st */
            	1018, 0,
            0, 16, 1, /* 1018: struct.asn1_type_st */
            	1023, 8,
            0, 8, 20, /* 1023: union.unknown */
            	96, 0,
            	1066, 0,
            	720, 0,
            	996, 0,
            	1071, 0,
            	1076, 0,
            	286, 0,
            	1081, 0,
            	1086, 0,
            	1091, 0,
            	1096, 0,
            	1101, 0,
            	1106, 0,
            	1111, 0,
            	1116, 0,
            	1121, 0,
            	276, 0,
            	1066, 0,
            	1066, 0,
            	160, 0,
            1, 8, 1, /* 1066: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1071: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1076: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1081: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1086: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1091: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1096: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1101: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1106: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1111: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1116: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1121: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1126: pointer.struct.X509_name_st */
            	1131, 0,
            0, 40, 3, /* 1131: struct.X509_name_st */
            	1140, 0,
            	1164, 16,
            	10, 24,
            1, 8, 1, /* 1140: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1145, 0,
            0, 32, 2, /* 1145: struct.stack_st_fake_X509_NAME_ENTRY */
            	1152, 8,
            	217, 24,
            64099, 8, 2, /* 1152: pointer_to_array_of_pointers_to_stack */
            	1159, 0,
            	214, 20,
            0, 8, 1, /* 1159: pointer.X509_NAME_ENTRY */
            	767, 0,
            1, 8, 1, /* 1164: pointer.struct.buf_mem_st */
            	1169, 0,
            0, 24, 1, /* 1169: struct.buf_mem_st */
            	96, 8,
            1, 8, 1, /* 1174: pointer.struct.X509_val_st */
            	1179, 0,
            0, 16, 2, /* 1179: struct.X509_val_st */
            	1186, 0,
            	1186, 8,
            1, 8, 1, /* 1186: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1191: pointer.struct.X509_pubkey_st */
            	1196, 0,
            0, 24, 3, /* 1196: struct.X509_pubkey_st */
            	1001, 0,
            	1076, 8,
            	1205, 16,
            1, 8, 1, /* 1205: pointer.struct.evp_pkey_st */
            	1210, 0,
            0, 56, 4, /* 1210: struct.evp_pkey_st */
            	1221, 16,
            	955, 24,
            	1229, 32,
            	685, 48,
            1, 8, 1, /* 1221: pointer.struct.evp_pkey_asn1_method_st */
            	1226, 0,
            0, 0, 0, /* 1226: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1229: union.unknown */
            	96, 0,
            	1242, 0,
            	888, 0,
            	1339, 0,
            	709, 0,
            1, 8, 1, /* 1242: pointer.struct.rsa_st */
            	1247, 0,
            0, 168, 17, /* 1247: struct.rsa_st */
            	1284, 16,
            	955, 24,
            	918, 32,
            	918, 40,
            	918, 48,
            	918, 56,
            	918, 64,
            	918, 72,
            	918, 80,
            	918, 88,
            	950, 96,
            	936, 120,
            	936, 128,
            	936, 136,
            	96, 144,
            	963, 152,
            	963, 160,
            1, 8, 1, /* 1284: pointer.struct.rsa_meth_st */
            	1289, 0,
            0, 112, 13, /* 1289: struct.rsa_meth_st */
            	115, 0,
            	1318, 8,
            	1318, 16,
            	1318, 24,
            	1318, 32,
            	1321, 40,
            	1324, 48,
            	1327, 56,
            	1327, 64,
            	96, 80,
            	1330, 88,
            	1333, 96,
            	1336, 104,
            64097, 8, 0, /* 1318: pointer.func */
            64097, 8, 0, /* 1321: pointer.func */
            64097, 8, 0, /* 1324: pointer.func */
            64097, 8, 0, /* 1327: pointer.func */
            64097, 8, 0, /* 1330: pointer.func */
            64097, 8, 0, /* 1333: pointer.func */
            64097, 8, 0, /* 1336: pointer.func */
            1, 8, 1, /* 1339: pointer.struct.dh_st */
            	1344, 0,
            0, 144, 12, /* 1344: struct.dh_st */
            	918, 8,
            	918, 16,
            	918, 32,
            	918, 40,
            	936, 56,
            	918, 64,
            	918, 72,
            	10, 80,
            	918, 96,
            	950, 112,
            	1371, 128,
            	955, 136,
            1, 8, 1, /* 1371: pointer.struct.dh_method */
            	1376, 0,
            0, 72, 8, /* 1376: struct.dh_method */
            	115, 0,
            	1395, 8,
            	1398, 16,
            	1401, 24,
            	1395, 32,
            	1395, 40,
            	96, 56,
            	1404, 64,
            64097, 8, 0, /* 1395: pointer.func */
            64097, 8, 0, /* 1398: pointer.func */
            64097, 8, 0, /* 1401: pointer.func */
            64097, 8, 0, /* 1404: pointer.func */
            1, 8, 1, /* 1407: pointer.struct.stack_st_X509_EXTENSION */
            	1412, 0,
            0, 32, 2, /* 1412: struct.stack_st_fake_X509_EXTENSION */
            	1419, 8,
            	217, 24,
            64099, 8, 2, /* 1419: pointer_to_array_of_pointers_to_stack */
            	1426, 0,
            	214, 20,
            0, 8, 1, /* 1426: pointer.X509_EXTENSION */
            	1431, 0,
            0, 0, 1, /* 1431: X509_EXTENSION */
            	1436, 0,
            0, 24, 2, /* 1436: struct.X509_extension_st */
            	1443, 0,
            	346, 16,
            1, 8, 1, /* 1443: pointer.struct.asn1_object_st */
            	1448, 0,
            0, 40, 3, /* 1448: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            0, 24, 1, /* 1457: struct.ASN1_ENCODING_st */
            	10, 0,
            1, 8, 1, /* 1462: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1467: pointer.struct.x509_st */
            	1472, 0,
            0, 184, 12, /* 1472: struct.x509_st */
            	1499, 0,
            	1001, 8,
            	1076, 16,
            	96, 32,
            	950, 40,
            	286, 104,
            	1504, 112,
            	1759, 120,
            	1767, 128,
            	1906, 136,
            	1930, 144,
            	258, 176,
            1, 8, 1, /* 1499: pointer.struct.x509_cinf_st */
            	971, 0,
            1, 8, 1, /* 1504: pointer.struct.AUTHORITY_KEYID_st */
            	1509, 0,
            0, 24, 3, /* 1509: struct.AUTHORITY_KEYID_st */
            	286, 0,
            	1518, 8,
            	996, 16,
            1, 8, 1, /* 1518: pointer.struct.stack_st_GENERAL_NAME */
            	1523, 0,
            0, 32, 2, /* 1523: struct.stack_st_fake_GENERAL_NAME */
            	1530, 8,
            	217, 24,
            64099, 8, 2, /* 1530: pointer_to_array_of_pointers_to_stack */
            	1537, 0,
            	214, 20,
            0, 8, 1, /* 1537: pointer.GENERAL_NAME */
            	1542, 0,
            0, 0, 1, /* 1542: GENERAL_NAME */
            	1547, 0,
            0, 16, 1, /* 1547: struct.GENERAL_NAME_st */
            	1552, 8,
            0, 8, 15, /* 1552: union.unknown */
            	96, 0,
            	1585, 0,
            	1694, 0,
            	1694, 0,
            	1611, 0,
            	1742, 0,
            	1747, 0,
            	1694, 0,
            	356, 0,
            	1597, 0,
            	356, 0,
            	1742, 0,
            	1694, 0,
            	1597, 0,
            	1611, 0,
            1, 8, 1, /* 1585: pointer.struct.otherName_st */
            	1590, 0,
            0, 16, 2, /* 1590: struct.otherName_st */
            	1597, 0,
            	1611, 8,
            1, 8, 1, /* 1597: pointer.struct.asn1_object_st */
            	1602, 0,
            0, 40, 3, /* 1602: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 1611: pointer.struct.asn1_type_st */
            	1616, 0,
            0, 16, 1, /* 1616: struct.asn1_type_st */
            	1621, 8,
            0, 8, 20, /* 1621: union.unknown */
            	96, 0,
            	1664, 0,
            	1597, 0,
            	1669, 0,
            	1674, 0,
            	1679, 0,
            	356, 0,
            	1684, 0,
            	1689, 0,
            	1694, 0,
            	1699, 0,
            	1704, 0,
            	1709, 0,
            	1714, 0,
            	1719, 0,
            	1724, 0,
            	1729, 0,
            	1664, 0,
            	1664, 0,
            	1734, 0,
            1, 8, 1, /* 1664: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1669: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1674: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1679: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1684: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1689: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1694: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1699: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1704: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1709: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1714: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1719: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1724: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1729: pointer.struct.asn1_string_st */
            	361, 0,
            1, 8, 1, /* 1734: pointer.struct.ASN1_VALUE_st */
            	1739, 0,
            0, 0, 0, /* 1739: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1742: pointer.struct.X509_name_st */
            	734, 0,
            1, 8, 1, /* 1747: pointer.struct.EDIPartyName_st */
            	1752, 0,
            0, 16, 2, /* 1752: struct.EDIPartyName_st */
            	1664, 0,
            	1664, 8,
            1, 8, 1, /* 1759: pointer.struct.X509_POLICY_CACHE_st */
            	1764, 0,
            0, 0, 0, /* 1764: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1767: pointer.struct.stack_st_DIST_POINT */
            	1772, 0,
            0, 32, 2, /* 1772: struct.stack_st_fake_DIST_POINT */
            	1779, 8,
            	217, 24,
            64099, 8, 2, /* 1779: pointer_to_array_of_pointers_to_stack */
            	1786, 0,
            	214, 20,
            0, 8, 1, /* 1786: pointer.DIST_POINT */
            	1791, 0,
            0, 0, 1, /* 1791: DIST_POINT */
            	1796, 0,
            0, 32, 3, /* 1796: struct.DIST_POINT_st */
            	1805, 0,
            	1896, 8,
            	1824, 16,
            1, 8, 1, /* 1805: pointer.struct.DIST_POINT_NAME_st */
            	1810, 0,
            0, 24, 2, /* 1810: struct.DIST_POINT_NAME_st */
            	1817, 8,
            	1872, 16,
            0, 8, 2, /* 1817: union.unknown */
            	1824, 0,
            	1848, 0,
            1, 8, 1, /* 1824: pointer.struct.stack_st_GENERAL_NAME */
            	1829, 0,
            0, 32, 2, /* 1829: struct.stack_st_fake_GENERAL_NAME */
            	1836, 8,
            	217, 24,
            64099, 8, 2, /* 1836: pointer_to_array_of_pointers_to_stack */
            	1843, 0,
            	214, 20,
            0, 8, 1, /* 1843: pointer.GENERAL_NAME */
            	1542, 0,
            1, 8, 1, /* 1848: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1853, 0,
            0, 32, 2, /* 1853: struct.stack_st_fake_X509_NAME_ENTRY */
            	1860, 8,
            	217, 24,
            64099, 8, 2, /* 1860: pointer_to_array_of_pointers_to_stack */
            	1867, 0,
            	214, 20,
            0, 8, 1, /* 1867: pointer.X509_NAME_ENTRY */
            	767, 0,
            1, 8, 1, /* 1872: pointer.struct.X509_name_st */
            	1877, 0,
            0, 40, 3, /* 1877: struct.X509_name_st */
            	1848, 0,
            	1886, 16,
            	10, 24,
            1, 8, 1, /* 1886: pointer.struct.buf_mem_st */
            	1891, 0,
            0, 24, 1, /* 1891: struct.buf_mem_st */
            	96, 8,
            1, 8, 1, /* 1896: pointer.struct.asn1_string_st */
            	1901, 0,
            0, 24, 1, /* 1901: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 1906: pointer.struct.stack_st_GENERAL_NAME */
            	1911, 0,
            0, 32, 2, /* 1911: struct.stack_st_fake_GENERAL_NAME */
            	1918, 8,
            	217, 24,
            64099, 8, 2, /* 1918: pointer_to_array_of_pointers_to_stack */
            	1925, 0,
            	214, 20,
            0, 8, 1, /* 1925: pointer.GENERAL_NAME */
            	1542, 0,
            1, 8, 1, /* 1930: pointer.struct.NAME_CONSTRAINTS_st */
            	1935, 0,
            0, 16, 2, /* 1935: struct.NAME_CONSTRAINTS_st */
            	1942, 0,
            	1942, 8,
            1, 8, 1, /* 1942: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1947, 0,
            0, 32, 2, /* 1947: struct.stack_st_fake_GENERAL_SUBTREE */
            	1954, 8,
            	217, 24,
            64099, 8, 2, /* 1954: pointer_to_array_of_pointers_to_stack */
            	1961, 0,
            	214, 20,
            0, 8, 1, /* 1961: pointer.GENERAL_SUBTREE */
            	1966, 0,
            0, 0, 1, /* 1966: GENERAL_SUBTREE */
            	1971, 0,
            0, 24, 3, /* 1971: struct.GENERAL_SUBTREE_st */
            	1980, 0,
            	2102, 8,
            	2102, 16,
            1, 8, 1, /* 1980: pointer.struct.GENERAL_NAME_st */
            	1985, 0,
            0, 16, 1, /* 1985: struct.GENERAL_NAME_st */
            	1990, 8,
            0, 8, 15, /* 1990: union.unknown */
            	96, 0,
            	2023, 0,
            	2127, 0,
            	2127, 0,
            	2049, 0,
            	2162, 0,
            	883, 0,
            	2127, 0,
            	366, 0,
            	2035, 0,
            	366, 0,
            	2162, 0,
            	2127, 0,
            	2035, 0,
            	2049, 0,
            1, 8, 1, /* 2023: pointer.struct.otherName_st */
            	2028, 0,
            0, 16, 2, /* 2028: struct.otherName_st */
            	2035, 0,
            	2049, 8,
            1, 8, 1, /* 2035: pointer.struct.asn1_object_st */
            	2040, 0,
            0, 40, 3, /* 2040: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 2049: pointer.struct.asn1_type_st */
            	2054, 0,
            0, 16, 1, /* 2054: struct.asn1_type_st */
            	2059, 8,
            0, 8, 20, /* 2059: union.unknown */
            	96, 0,
            	298, 0,
            	2035, 0,
            	2102, 0,
            	2107, 0,
            	2112, 0,
            	366, 0,
            	2117, 0,
            	2122, 0,
            	2127, 0,
            	2132, 0,
            	2137, 0,
            	2142, 0,
            	2147, 0,
            	1462, 0,
            	2152, 0,
            	2157, 0,
            	298, 0,
            	298, 0,
            	1734, 0,
            1, 8, 1, /* 2102: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2107: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2112: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2117: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2122: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2127: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2132: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2137: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2142: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2147: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2152: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2157: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2162: pointer.struct.X509_name_st */
            	2167, 0,
            0, 40, 3, /* 2167: struct.X509_name_st */
            	2176, 0,
            	2200, 16,
            	10, 24,
            1, 8, 1, /* 2176: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2181, 0,
            0, 32, 2, /* 2181: struct.stack_st_fake_X509_NAME_ENTRY */
            	2188, 8,
            	217, 24,
            64099, 8, 2, /* 2188: pointer_to_array_of_pointers_to_stack */
            	2195, 0,
            	214, 20,
            0, 8, 1, /* 2195: pointer.X509_NAME_ENTRY */
            	767, 0,
            1, 8, 1, /* 2200: pointer.struct.buf_mem_st */
            	308, 0,
            0, 1, 0, /* 2205: char */
            0, 8, 0, /* 2208: pointer.void */
            1, 8, 1, /* 2211: pointer.int */
            	214, 0,
        },
        .arg_entity_index = { 1467, 214, 2211, 2211, },
        .ret_entity_index = 2208,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int * new_arg_c = *((int * *)new_args->args[2]);

    int * new_arg_d = *((int * *)new_args->args[3]);

    void * *new_ret_ptr = (void * *)new_args->ret;

    void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
    orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
    *new_ret_ptr = (*orig_X509_get_ext_d2i)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

