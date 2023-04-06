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

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d);

EVP_PKEY * PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("PEM_read_bio_PrivateKey called %lu\n", in_lib);
    if (!in_lib)
        return bb_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    else {
        EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
        orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
        return orig_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    }
}

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    EVP_PKEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            8884097, 8, 0, /* 0: pointer.func */
            0, 32, 2, /* 3: struct.stack_st */
            	10, 8,
            	20, 24,
            1, 8, 1, /* 10: pointer.pointer.char */
            	15, 0,
            1, 8, 1, /* 15: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 20: pointer.func */
            0, 32, 1, /* 23: struct.stack_st_void */
            	3, 0,
            1, 8, 1, /* 28: pointer.struct.stack_st_void */
            	23, 0,
            0, 16, 1, /* 33: struct.crypto_ex_data_st */
            	28, 0,
            8884097, 8, 0, /* 38: pointer.func */
            8884097, 8, 0, /* 41: pointer.func */
            8884097, 8, 0, /* 44: pointer.func */
            8884097, 8, 0, /* 47: pointer.func */
            8884097, 8, 0, /* 50: pointer.func */
            8884097, 8, 0, /* 53: pointer.func */
            1, 8, 1, /* 56: pointer.struct.bio_method_st */
            	61, 0,
            0, 80, 9, /* 61: struct.bio_method_st */
            	82, 8,
            	53, 16,
            	50, 24,
            	47, 32,
            	50, 40,
            	87, 48,
            	44, 56,
            	44, 64,
            	41, 72,
            1, 8, 1, /* 82: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 87: pointer.func */
            0, 112, 7, /* 90: struct.bio_st */
            	56, 0,
            	38, 8,
            	15, 16,
            	107, 48,
            	110, 56,
            	110, 64,
            	33, 96,
            0, 8, 0, /* 107: pointer.void */
            1, 8, 1, /* 110: pointer.struct.bio_st */
            	90, 0,
            1, 8, 1, /* 115: pointer.struct.bio_st */
            	90, 0,
            1, 8, 1, /* 120: pointer.struct.ASN1_VALUE_st */
            	125, 0,
            0, 0, 0, /* 125: struct.ASN1_VALUE_st */
            1, 8, 1, /* 128: pointer.struct.asn1_string_st */
            	133, 0,
            0, 24, 1, /* 133: struct.asn1_string_st */
            	138, 8,
            1, 8, 1, /* 138: pointer.unsigned char */
            	143, 0,
            0, 1, 0, /* 143: unsigned char */
            1, 8, 1, /* 146: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 151: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 156: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 161: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 166: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 171: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 176: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 181: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 186: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 191: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 196: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 201: pointer.struct.asn1_string_st */
            	133, 0,
            0, 16, 1, /* 206: struct.asn1_type_st */
            	211, 8,
            0, 8, 20, /* 211: union.unknown */
            	15, 0,
            	201, 0,
            	254, 0,
            	273, 0,
            	196, 0,
            	191, 0,
            	186, 0,
            	181, 0,
            	176, 0,
            	171, 0,
            	166, 0,
            	161, 0,
            	156, 0,
            	151, 0,
            	146, 0,
            	278, 0,
            	128, 0,
            	201, 0,
            	201, 0,
            	120, 0,
            1, 8, 1, /* 254: pointer.struct.asn1_object_st */
            	259, 0,
            0, 40, 3, /* 259: struct.asn1_object_st */
            	82, 0,
            	82, 8,
            	268, 24,
            1, 8, 1, /* 268: pointer.unsigned char */
            	143, 0,
            1, 8, 1, /* 273: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 278: pointer.struct.asn1_string_st */
            	133, 0,
            1, 8, 1, /* 283: pointer.struct.asn1_string_st */
            	288, 0,
            0, 24, 1, /* 288: struct.asn1_string_st */
            	138, 8,
            1, 8, 1, /* 293: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 298: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 303: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 308: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 313: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 318: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 323: pointer.struct.dsa_method */
            	328, 0,
            0, 96, 11, /* 328: struct.dsa_method */
            	82, 0,
            	353, 8,
            	356, 16,
            	359, 24,
            	362, 32,
            	365, 40,
            	368, 48,
            	368, 56,
            	15, 72,
            	371, 80,
            	368, 88,
            8884097, 8, 0, /* 353: pointer.func */
            8884097, 8, 0, /* 356: pointer.func */
            8884097, 8, 0, /* 359: pointer.func */
            8884097, 8, 0, /* 362: pointer.func */
            8884097, 8, 0, /* 365: pointer.func */
            8884097, 8, 0, /* 368: pointer.func */
            8884097, 8, 0, /* 371: pointer.func */
            1, 8, 1, /* 374: pointer.struct.stack_st_void */
            	379, 0,
            0, 32, 1, /* 379: struct.stack_st_void */
            	384, 0,
            0, 32, 2, /* 384: struct.stack_st */
            	10, 8,
            	20, 24,
            0, 24, 1, /* 391: struct.bignum_st */
            	396, 0,
            1, 8, 1, /* 396: pointer.unsigned int */
            	401, 0,
            0, 4, 0, /* 401: unsigned int */
            1, 8, 1, /* 404: pointer.struct.bn_mont_ctx_st */
            	409, 0,
            0, 96, 3, /* 409: struct.bn_mont_ctx_st */
            	418, 8,
            	418, 32,
            	418, 56,
            0, 24, 1, /* 418: struct.bignum_st */
            	396, 0,
            1, 8, 1, /* 423: pointer.struct.engine_st */
            	428, 0,
            0, 216, 24, /* 428: struct.engine_st */
            	82, 0,
            	82, 8,
            	479, 16,
            	534, 24,
            	585, 32,
            	621, 40,
            	638, 48,
            	665, 56,
            	700, 64,
            	708, 72,
            	711, 80,
            	714, 88,
            	717, 96,
            	720, 104,
            	720, 112,
            	720, 120,
            	723, 128,
            	726, 136,
            	726, 144,
            	729, 152,
            	732, 160,
            	744, 184,
            	766, 200,
            	766, 208,
            1, 8, 1, /* 479: pointer.struct.rsa_meth_st */
            	484, 0,
            0, 112, 13, /* 484: struct.rsa_meth_st */
            	82, 0,
            	513, 8,
            	513, 16,
            	513, 24,
            	513, 32,
            	516, 40,
            	519, 48,
            	522, 56,
            	522, 64,
            	15, 80,
            	525, 88,
            	528, 96,
            	531, 104,
            8884097, 8, 0, /* 513: pointer.func */
            8884097, 8, 0, /* 516: pointer.func */
            8884097, 8, 0, /* 519: pointer.func */
            8884097, 8, 0, /* 522: pointer.func */
            8884097, 8, 0, /* 525: pointer.func */
            8884097, 8, 0, /* 528: pointer.func */
            8884097, 8, 0, /* 531: pointer.func */
            1, 8, 1, /* 534: pointer.struct.dsa_method */
            	539, 0,
            0, 96, 11, /* 539: struct.dsa_method */
            	82, 0,
            	564, 8,
            	567, 16,
            	570, 24,
            	573, 32,
            	576, 40,
            	579, 48,
            	579, 56,
            	15, 72,
            	582, 80,
            	579, 88,
            8884097, 8, 0, /* 564: pointer.func */
            8884097, 8, 0, /* 567: pointer.func */
            8884097, 8, 0, /* 570: pointer.func */
            8884097, 8, 0, /* 573: pointer.func */
            8884097, 8, 0, /* 576: pointer.func */
            8884097, 8, 0, /* 579: pointer.func */
            8884097, 8, 0, /* 582: pointer.func */
            1, 8, 1, /* 585: pointer.struct.dh_method */
            	590, 0,
            0, 72, 8, /* 590: struct.dh_method */
            	82, 0,
            	609, 8,
            	612, 16,
            	615, 24,
            	609, 32,
            	609, 40,
            	15, 56,
            	618, 64,
            8884097, 8, 0, /* 609: pointer.func */
            8884097, 8, 0, /* 612: pointer.func */
            8884097, 8, 0, /* 615: pointer.func */
            8884097, 8, 0, /* 618: pointer.func */
            1, 8, 1, /* 621: pointer.struct.ecdh_method */
            	626, 0,
            0, 32, 3, /* 626: struct.ecdh_method */
            	82, 0,
            	635, 8,
            	15, 24,
            8884097, 8, 0, /* 635: pointer.func */
            1, 8, 1, /* 638: pointer.struct.ecdsa_method */
            	643, 0,
            0, 48, 5, /* 643: struct.ecdsa_method */
            	82, 0,
            	656, 8,
            	659, 16,
            	662, 24,
            	15, 40,
            8884097, 8, 0, /* 656: pointer.func */
            8884097, 8, 0, /* 659: pointer.func */
            8884097, 8, 0, /* 662: pointer.func */
            1, 8, 1, /* 665: pointer.struct.rand_meth_st */
            	670, 0,
            0, 48, 6, /* 670: struct.rand_meth_st */
            	685, 0,
            	688, 8,
            	691, 16,
            	694, 24,
            	688, 32,
            	697, 40,
            8884097, 8, 0, /* 685: pointer.func */
            8884097, 8, 0, /* 688: pointer.func */
            8884097, 8, 0, /* 691: pointer.func */
            8884097, 8, 0, /* 694: pointer.func */
            8884097, 8, 0, /* 697: pointer.func */
            1, 8, 1, /* 700: pointer.struct.store_method_st */
            	705, 0,
            0, 0, 0, /* 705: struct.store_method_st */
            8884097, 8, 0, /* 708: pointer.func */
            8884097, 8, 0, /* 711: pointer.func */
            8884097, 8, 0, /* 714: pointer.func */
            8884097, 8, 0, /* 717: pointer.func */
            8884097, 8, 0, /* 720: pointer.func */
            8884097, 8, 0, /* 723: pointer.func */
            8884097, 8, 0, /* 726: pointer.func */
            8884097, 8, 0, /* 729: pointer.func */
            1, 8, 1, /* 732: pointer.struct.ENGINE_CMD_DEFN_st */
            	737, 0,
            0, 32, 2, /* 737: struct.ENGINE_CMD_DEFN_st */
            	82, 8,
            	82, 16,
            0, 16, 1, /* 744: struct.crypto_ex_data_st */
            	749, 0,
            1, 8, 1, /* 749: pointer.struct.stack_st_void */
            	754, 0,
            0, 32, 1, /* 754: struct.stack_st_void */
            	759, 0,
            0, 32, 2, /* 759: struct.stack_st */
            	10, 8,
            	20, 24,
            1, 8, 1, /* 766: pointer.struct.engine_st */
            	428, 0,
            1, 8, 1, /* 771: pointer.struct.dsa_st */
            	776, 0,
            0, 136, 11, /* 776: struct.dsa_st */
            	801, 24,
            	801, 32,
            	801, 40,
            	801, 48,
            	801, 56,
            	801, 64,
            	801, 72,
            	404, 88,
            	806, 104,
            	323, 120,
            	811, 128,
            1, 8, 1, /* 801: pointer.struct.bignum_st */
            	418, 0,
            0, 16, 1, /* 806: struct.crypto_ex_data_st */
            	374, 0,
            1, 8, 1, /* 811: pointer.struct.engine_st */
            	428, 0,
            0, 88, 7, /* 816: struct.bn_blinding_st */
            	833, 0,
            	833, 8,
            	833, 16,
            	833, 24,
            	843, 40,
            	848, 72,
            	862, 80,
            1, 8, 1, /* 833: pointer.struct.bignum_st */
            	838, 0,
            0, 24, 1, /* 838: struct.bignum_st */
            	396, 0,
            0, 16, 1, /* 843: struct.crypto_threadid_st */
            	107, 0,
            1, 8, 1, /* 848: pointer.struct.bn_mont_ctx_st */
            	853, 0,
            0, 96, 3, /* 853: struct.bn_mont_ctx_st */
            	838, 8,
            	838, 32,
            	838, 56,
            8884097, 8, 0, /* 862: pointer.func */
            1, 8, 1, /* 865: pointer.struct.bn_blinding_st */
            	816, 0,
            1, 8, 1, /* 870: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 875: pointer.struct.bn_mont_ctx_st */
            	880, 0,
            0, 96, 3, /* 880: struct.bn_mont_ctx_st */
            	391, 8,
            	391, 32,
            	391, 56,
            1, 8, 1, /* 889: pointer.struct.stack_st_X509_ATTRIBUTE */
            	894, 0,
            0, 32, 2, /* 894: struct.stack_st_fake_X509_ATTRIBUTE */
            	901, 8,
            	20, 24,
            8884099, 8, 2, /* 901: pointer_to_array_of_pointers_to_stack */
            	908, 0,
            	1068, 20,
            0, 8, 1, /* 908: pointer.X509_ATTRIBUTE */
            	913, 0,
            0, 0, 1, /* 913: X509_ATTRIBUTE */
            	918, 0,
            0, 24, 2, /* 918: struct.x509_attributes_st */
            	254, 0,
            	925, 16,
            0, 8, 3, /* 925: union.unknown */
            	15, 0,
            	934, 0,
            	1071, 0,
            1, 8, 1, /* 934: pointer.struct.stack_st_ASN1_TYPE */
            	939, 0,
            0, 32, 2, /* 939: struct.stack_st_fake_ASN1_TYPE */
            	946, 8,
            	20, 24,
            8884099, 8, 2, /* 946: pointer_to_array_of_pointers_to_stack */
            	953, 0,
            	1068, 20,
            0, 8, 1, /* 953: pointer.ASN1_TYPE */
            	958, 0,
            0, 0, 1, /* 958: ASN1_TYPE */
            	963, 0,
            0, 16, 1, /* 963: struct.asn1_type_st */
            	968, 8,
            0, 8, 20, /* 968: union.unknown */
            	15, 0,
            	1011, 0,
            	1016, 0,
            	1030, 0,
            	1035, 0,
            	1040, 0,
            	318, 0,
            	1045, 0,
            	1050, 0,
            	313, 0,
            	308, 0,
            	870, 0,
            	303, 0,
            	298, 0,
            	293, 0,
            	1055, 0,
            	283, 0,
            	1011, 0,
            	1011, 0,
            	1060, 0,
            1, 8, 1, /* 1011: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 1016: pointer.struct.asn1_object_st */
            	1021, 0,
            0, 40, 3, /* 1021: struct.asn1_object_st */
            	82, 0,
            	82, 8,
            	268, 24,
            1, 8, 1, /* 1030: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 1035: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 1040: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 1045: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 1050: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 1055: pointer.struct.asn1_string_st */
            	288, 0,
            1, 8, 1, /* 1060: pointer.struct.ASN1_VALUE_st */
            	1065, 0,
            0, 0, 0, /* 1065: struct.ASN1_VALUE_st */
            0, 4, 0, /* 1068: int */
            1, 8, 1, /* 1071: pointer.struct.asn1_type_st */
            	206, 0,
            0, 96, 3, /* 1076: struct.bn_mont_ctx_st */
            	1085, 8,
            	1085, 32,
            	1085, 56,
            0, 24, 1, /* 1085: struct.bignum_st */
            	396, 0,
            1, 8, 1, /* 1090: pointer.struct.bn_mont_ctx_st */
            	1076, 0,
            0, 32, 1, /* 1095: struct.stack_st_void */
            	1100, 0,
            0, 32, 2, /* 1100: struct.stack_st */
            	10, 8,
            	20, 24,
            8884097, 8, 0, /* 1107: pointer.func */
            0, 16, 1, /* 1110: struct.crypto_ex_data_st */
            	1115, 0,
            1, 8, 1, /* 1115: pointer.struct.stack_st_void */
            	1095, 0,
            8884097, 8, 0, /* 1120: pointer.func */
            0, 112, 13, /* 1123: struct.rsa_meth_st */
            	82, 0,
            	1152, 8,
            	1152, 16,
            	1152, 24,
            	1152, 32,
            	1155, 40,
            	1158, 48,
            	1107, 56,
            	1107, 64,
            	15, 80,
            	1161, 88,
            	1164, 96,
            	1167, 104,
            8884097, 8, 0, /* 1152: pointer.func */
            8884097, 8, 0, /* 1155: pointer.func */
            8884097, 8, 0, /* 1158: pointer.func */
            8884097, 8, 0, /* 1161: pointer.func */
            8884097, 8, 0, /* 1164: pointer.func */
            8884097, 8, 0, /* 1167: pointer.func */
            1, 8, 1, /* 1170: pointer.struct.ec_key_st */
            	1175, 0,
            0, 56, 4, /* 1175: struct.ec_key_st */
            	1186, 8,
            	1620, 16,
            	1625, 24,
            	1635, 48,
            1, 8, 1, /* 1186: pointer.struct.ec_group_st */
            	1191, 0,
            0, 232, 12, /* 1191: struct.ec_group_st */
            	1218, 0,
            	1390, 8,
            	1583, 16,
            	1583, 40,
            	138, 80,
            	1588, 96,
            	1583, 104,
            	1583, 152,
            	1583, 176,
            	107, 208,
            	107, 216,
            	1617, 224,
            1, 8, 1, /* 1218: pointer.struct.ec_method_st */
            	1223, 0,
            0, 304, 37, /* 1223: struct.ec_method_st */
            	1300, 8,
            	1303, 16,
            	1303, 24,
            	1306, 32,
            	1309, 40,
            	1312, 48,
            	1315, 56,
            	1318, 64,
            	1321, 72,
            	1324, 80,
            	1324, 88,
            	1327, 96,
            	1330, 104,
            	1333, 112,
            	1336, 120,
            	1339, 128,
            	1342, 136,
            	1345, 144,
            	1348, 152,
            	1351, 160,
            	1354, 168,
            	1357, 176,
            	1360, 184,
            	1363, 192,
            	1366, 200,
            	1369, 208,
            	1360, 216,
            	1372, 224,
            	1375, 232,
            	1378, 240,
            	1315, 248,
            	1381, 256,
            	1384, 264,
            	1381, 272,
            	1384, 280,
            	1384, 288,
            	1387, 296,
            8884097, 8, 0, /* 1300: pointer.func */
            8884097, 8, 0, /* 1303: pointer.func */
            8884097, 8, 0, /* 1306: pointer.func */
            8884097, 8, 0, /* 1309: pointer.func */
            8884097, 8, 0, /* 1312: pointer.func */
            8884097, 8, 0, /* 1315: pointer.func */
            8884097, 8, 0, /* 1318: pointer.func */
            8884097, 8, 0, /* 1321: pointer.func */
            8884097, 8, 0, /* 1324: pointer.func */
            8884097, 8, 0, /* 1327: pointer.func */
            8884097, 8, 0, /* 1330: pointer.func */
            8884097, 8, 0, /* 1333: pointer.func */
            8884097, 8, 0, /* 1336: pointer.func */
            8884097, 8, 0, /* 1339: pointer.func */
            8884097, 8, 0, /* 1342: pointer.func */
            8884097, 8, 0, /* 1345: pointer.func */
            8884097, 8, 0, /* 1348: pointer.func */
            8884097, 8, 0, /* 1351: pointer.func */
            8884097, 8, 0, /* 1354: pointer.func */
            8884097, 8, 0, /* 1357: pointer.func */
            8884097, 8, 0, /* 1360: pointer.func */
            8884097, 8, 0, /* 1363: pointer.func */
            8884097, 8, 0, /* 1366: pointer.func */
            8884097, 8, 0, /* 1369: pointer.func */
            8884097, 8, 0, /* 1372: pointer.func */
            8884097, 8, 0, /* 1375: pointer.func */
            8884097, 8, 0, /* 1378: pointer.func */
            8884097, 8, 0, /* 1381: pointer.func */
            8884097, 8, 0, /* 1384: pointer.func */
            8884097, 8, 0, /* 1387: pointer.func */
            1, 8, 1, /* 1390: pointer.struct.ec_point_st */
            	1395, 0,
            0, 88, 4, /* 1395: struct.ec_point_st */
            	1406, 0,
            	1578, 8,
            	1578, 32,
            	1578, 56,
            1, 8, 1, /* 1406: pointer.struct.ec_method_st */
            	1411, 0,
            0, 304, 37, /* 1411: struct.ec_method_st */
            	1488, 8,
            	1491, 16,
            	1491, 24,
            	1494, 32,
            	1497, 40,
            	1500, 48,
            	1503, 56,
            	1506, 64,
            	1509, 72,
            	1512, 80,
            	1512, 88,
            	1515, 96,
            	1518, 104,
            	1521, 112,
            	1524, 120,
            	1527, 128,
            	1530, 136,
            	1533, 144,
            	1536, 152,
            	1539, 160,
            	1542, 168,
            	1545, 176,
            	1548, 184,
            	1551, 192,
            	1554, 200,
            	1557, 208,
            	1548, 216,
            	1560, 224,
            	1563, 232,
            	1566, 240,
            	1503, 248,
            	1569, 256,
            	1572, 264,
            	1569, 272,
            	1572, 280,
            	1572, 288,
            	1575, 296,
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
            8884097, 8, 0, /* 1560: pointer.func */
            8884097, 8, 0, /* 1563: pointer.func */
            8884097, 8, 0, /* 1566: pointer.func */
            8884097, 8, 0, /* 1569: pointer.func */
            8884097, 8, 0, /* 1572: pointer.func */
            8884097, 8, 0, /* 1575: pointer.func */
            0, 24, 1, /* 1578: struct.bignum_st */
            	396, 0,
            0, 24, 1, /* 1583: struct.bignum_st */
            	396, 0,
            1, 8, 1, /* 1588: pointer.struct.ec_extra_data_st */
            	1593, 0,
            0, 40, 5, /* 1593: struct.ec_extra_data_st */
            	1606, 0,
            	107, 8,
            	1611, 16,
            	1614, 24,
            	1614, 32,
            1, 8, 1, /* 1606: pointer.struct.ec_extra_data_st */
            	1593, 0,
            8884097, 8, 0, /* 1611: pointer.func */
            8884097, 8, 0, /* 1614: pointer.func */
            8884097, 8, 0, /* 1617: pointer.func */
            1, 8, 1, /* 1620: pointer.struct.ec_point_st */
            	1395, 0,
            1, 8, 1, /* 1625: pointer.struct.bignum_st */
            	1630, 0,
            0, 24, 1, /* 1630: struct.bignum_st */
            	396, 0,
            1, 8, 1, /* 1635: pointer.struct.ec_extra_data_st */
            	1640, 0,
            0, 40, 5, /* 1640: struct.ec_extra_data_st */
            	1653, 0,
            	107, 8,
            	1611, 16,
            	1614, 24,
            	1614, 32,
            1, 8, 1, /* 1653: pointer.struct.ec_extra_data_st */
            	1640, 0,
            0, 168, 17, /* 1658: struct.rsa_st */
            	1695, 16,
            	1700, 24,
            	1705, 32,
            	1705, 40,
            	1705, 48,
            	1705, 56,
            	1705, 64,
            	1705, 72,
            	1705, 80,
            	1705, 88,
            	1110, 96,
            	1090, 120,
            	1090, 128,
            	1090, 136,
            	15, 144,
            	865, 152,
            	865, 160,
            1, 8, 1, /* 1695: pointer.struct.rsa_meth_st */
            	1123, 0,
            1, 8, 1, /* 1700: pointer.struct.engine_st */
            	428, 0,
            1, 8, 1, /* 1705: pointer.struct.bignum_st */
            	1085, 0,
            0, 8, 5, /* 1710: union.unknown */
            	15, 0,
            	1723, 0,
            	771, 0,
            	1728, 0,
            	1170, 0,
            1, 8, 1, /* 1723: pointer.struct.rsa_st */
            	1658, 0,
            1, 8, 1, /* 1728: pointer.struct.dh_st */
            	1733, 0,
            0, 144, 12, /* 1733: struct.dh_st */
            	1760, 8,
            	1760, 16,
            	1760, 32,
            	1760, 40,
            	875, 56,
            	1760, 64,
            	1760, 72,
            	138, 80,
            	1760, 96,
            	1765, 112,
            	1787, 128,
            	1700, 136,
            1, 8, 1, /* 1760: pointer.struct.bignum_st */
            	391, 0,
            0, 16, 1, /* 1765: struct.crypto_ex_data_st */
            	1770, 0,
            1, 8, 1, /* 1770: pointer.struct.stack_st_void */
            	1775, 0,
            0, 32, 1, /* 1775: struct.stack_st_void */
            	1780, 0,
            0, 32, 2, /* 1780: struct.stack_st */
            	10, 8,
            	20, 24,
            1, 8, 1, /* 1787: pointer.struct.dh_method */
            	1792, 0,
            0, 72, 8, /* 1792: struct.dh_method */
            	82, 0,
            	1811, 8,
            	1814, 16,
            	1817, 24,
            	1811, 32,
            	1811, 40,
            	15, 56,
            	1820, 64,
            8884097, 8, 0, /* 1811: pointer.func */
            8884097, 8, 0, /* 1814: pointer.func */
            8884097, 8, 0, /* 1817: pointer.func */
            8884097, 8, 0, /* 1820: pointer.func */
            1, 8, 1, /* 1823: pointer.struct.evp_pkey_st */
            	1828, 0,
            0, 56, 4, /* 1828: struct.evp_pkey_st */
            	1839, 16,
            	423, 24,
            	1710, 32,
            	889, 48,
            1, 8, 1, /* 1839: pointer.struct.evp_pkey_asn1_method_st */
            	1844, 0,
            0, 208, 24, /* 1844: struct.evp_pkey_asn1_method_st */
            	15, 16,
            	15, 24,
            	1895, 32,
            	1898, 40,
            	1901, 48,
            	1904, 56,
            	1907, 64,
            	1910, 72,
            	1904, 80,
            	1913, 88,
            	1913, 96,
            	1916, 104,
            	1919, 112,
            	1913, 120,
            	1922, 128,
            	1901, 136,
            	1904, 144,
            	1120, 152,
            	1925, 160,
            	1928, 168,
            	1916, 176,
            	1919, 184,
            	1931, 192,
            	1934, 200,
            8884097, 8, 0, /* 1895: pointer.func */
            8884097, 8, 0, /* 1898: pointer.func */
            8884097, 8, 0, /* 1901: pointer.func */
            8884097, 8, 0, /* 1904: pointer.func */
            8884097, 8, 0, /* 1907: pointer.func */
            8884097, 8, 0, /* 1910: pointer.func */
            8884097, 8, 0, /* 1913: pointer.func */
            8884097, 8, 0, /* 1916: pointer.func */
            8884097, 8, 0, /* 1919: pointer.func */
            8884097, 8, 0, /* 1922: pointer.func */
            8884097, 8, 0, /* 1925: pointer.func */
            8884097, 8, 0, /* 1928: pointer.func */
            8884097, 8, 0, /* 1931: pointer.func */
            8884097, 8, 0, /* 1934: pointer.func */
            1, 8, 1, /* 1937: pointer.pointer.struct.evp_pkey_st */
            	1823, 0,
            0, 1, 0, /* 1942: char */
        },
        .arg_entity_index = { 115, 1937, 0, 107, },
        .ret_entity_index = 1823,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    EVP_PKEY ** new_arg_b = *((EVP_PKEY ** *)new_args->args[1]);

    pem_password_cb * new_arg_c = *((pem_password_cb * *)new_args->args[2]);

    void * new_arg_d = *((void * *)new_args->args[3]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
    orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
    *new_ret_ptr = (*orig_PEM_read_bio_PrivateKey)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

