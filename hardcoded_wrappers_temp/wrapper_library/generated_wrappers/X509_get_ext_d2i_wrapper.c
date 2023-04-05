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
            	135, 0,
            	38, 0,
            	140, 0,
            	145, 0,
            	33, 0,
            	28, 0,
            	150, 0,
            	23, 0,
            	18, 0,
            	155, 0,
            	0, 0,
            	48, 0,
            	48, 0,
            	160, 0,
            1, 8, 1, /* 96: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 101: pointer.struct.asn1_object_st */
            	106, 0,
            0, 40, 3, /* 106: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 115: pointer.char */
            	8884096, 0,
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
            1, 8, 1, /* 168: pointer.struct.asn1_type_st */
            	173, 0,
            0, 16, 1, /* 173: struct.asn1_type_st */
            	53, 8,
            0, 0, 1, /* 178: X509_ALGOR */
            	183, 0,
            0, 16, 2, /* 183: struct.X509_algor_st */
            	101, 0,
            	168, 8,
            1, 8, 1, /* 190: pointer.struct.stack_st_X509_ALGOR */
            	195, 0,
            0, 32, 2, /* 195: struct.stack_st_fake_X509_ALGOR */
            	202, 8,
            	217, 24,
            8884099, 8, 2, /* 202: pointer_to_array_of_pointers_to_stack */
            	209, 0,
            	214, 20,
            0, 8, 1, /* 209: pointer.X509_ALGOR */
            	178, 0,
            0, 4, 0, /* 214: int */
            8884097, 8, 0, /* 217: pointer.func */
            0, 0, 1, /* 220: ASN1_OBJECT */
            	225, 0,
            0, 40, 3, /* 225: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 234: pointer.struct.stack_st_ASN1_OBJECT */
            	239, 0,
            0, 32, 2, /* 239: struct.stack_st_fake_ASN1_OBJECT */
            	246, 8,
            	217, 24,
            8884099, 8, 2, /* 246: pointer_to_array_of_pointers_to_stack */
            	253, 0,
            	214, 20,
            0, 8, 1, /* 253: pointer.ASN1_OBJECT */
            	220, 0,
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
            0, 16, 1, /* 323: struct.asn1_type_st */
            	328, 8,
            0, 8, 20, /* 328: union.unknown */
            	96, 0,
            	371, 0,
            	376, 0,
            	390, 0,
            	313, 0,
            	395, 0,
            	400, 0,
            	405, 0,
            	410, 0,
            	415, 0,
            	420, 0,
            	425, 0,
            	430, 0,
            	435, 0,
            	440, 0,
            	445, 0,
            	450, 0,
            	371, 0,
            	371, 0,
            	455, 0,
            1, 8, 1, /* 371: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 376: pointer.struct.asn1_object_st */
            	381, 0,
            0, 40, 3, /* 381: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 390: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 395: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 400: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 405: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 410: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 415: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 420: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 425: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 430: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 435: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 440: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 445: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 450: pointer.struct.asn1_string_st */
            	318, 0,
            1, 8, 1, /* 455: pointer.struct.ASN1_VALUE_st */
            	460, 0,
            0, 0, 0, /* 460: struct.ASN1_VALUE_st */
            0, 0, 1, /* 463: ASN1_TYPE */
            	323, 0,
            0, 40, 3, /* 468: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            0, 40, 3, /* 477: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 486: pointer.struct.asn1_string_st */
            	491, 0,
            0, 24, 1, /* 491: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 496: pointer.struct.asn1_string_st */
            	501, 0,
            0, 24, 1, /* 501: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 506: pointer.struct.asn1_string_st */
            	303, 0,
            0, 24, 2, /* 511: struct.x509_attributes_st */
            	518, 0,
            	523, 16,
            1, 8, 1, /* 518: pointer.struct.asn1_object_st */
            	477, 0,
            0, 8, 3, /* 523: union.unknown */
            	96, 0,
            	532, 0,
            	556, 0,
            1, 8, 1, /* 532: pointer.struct.stack_st_ASN1_TYPE */
            	537, 0,
            0, 32, 2, /* 537: struct.stack_st_fake_ASN1_TYPE */
            	544, 8,
            	217, 24,
            8884099, 8, 2, /* 544: pointer_to_array_of_pointers_to_stack */
            	551, 0,
            	214, 20,
            0, 8, 1, /* 551: pointer.ASN1_TYPE */
            	463, 0,
            1, 8, 1, /* 556: pointer.struct.asn1_type_st */
            	561, 0,
            0, 16, 1, /* 561: struct.asn1_type_st */
            	566, 8,
            0, 8, 20, /* 566: union.unknown */
            	96, 0,
            	609, 0,
            	518, 0,
            	619, 0,
            	624, 0,
            	629, 0,
            	634, 0,
            	639, 0,
            	644, 0,
            	649, 0,
            	654, 0,
            	659, 0,
            	664, 0,
            	669, 0,
            	674, 0,
            	679, 0,
            	684, 0,
            	609, 0,
            	609, 0,
            	160, 0,
            1, 8, 1, /* 609: pointer.struct.asn1_string_st */
            	614, 0,
            0, 24, 1, /* 614: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 619: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 624: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 629: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 634: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 639: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 644: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 649: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 654: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 659: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 664: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 669: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 674: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 679: pointer.struct.asn1_string_st */
            	614, 0,
            1, 8, 1, /* 684: pointer.struct.asn1_string_st */
            	614, 0,
            0, 0, 1, /* 689: X509_ATTRIBUTE */
            	511, 0,
            1, 8, 1, /* 694: pointer.struct.stack_st_X509_ATTRIBUTE */
            	699, 0,
            0, 32, 2, /* 699: struct.stack_st_fake_X509_ATTRIBUTE */
            	706, 8,
            	217, 24,
            8884099, 8, 2, /* 706: pointer_to_array_of_pointers_to_stack */
            	713, 0,
            	214, 20,
            0, 8, 1, /* 713: pointer.X509_ATTRIBUTE */
            	689, 0,
            1, 8, 1, /* 718: pointer.struct.ec_key_st */
            	723, 0,
            0, 0, 0, /* 723: struct.ec_key_st */
            8884097, 8, 0, /* 726: pointer.func */
            0, 40, 3, /* 729: struct.X509_name_st */
            	738, 0,
            	789, 16,
            	10, 24,
            1, 8, 1, /* 738: pointer.struct.stack_st_X509_NAME_ENTRY */
            	743, 0,
            0, 32, 2, /* 743: struct.stack_st_fake_X509_NAME_ENTRY */
            	750, 8,
            	217, 24,
            8884099, 8, 2, /* 750: pointer_to_array_of_pointers_to_stack */
            	757, 0,
            	214, 20,
            0, 8, 1, /* 757: pointer.X509_NAME_ENTRY */
            	762, 0,
            0, 0, 1, /* 762: X509_NAME_ENTRY */
            	767, 0,
            0, 24, 2, /* 767: struct.X509_name_entry_st */
            	774, 0,
            	779, 8,
            1, 8, 1, /* 774: pointer.struct.asn1_object_st */
            	468, 0,
            1, 8, 1, /* 779: pointer.struct.asn1_string_st */
            	784, 0,
            0, 24, 1, /* 784: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 789: pointer.struct.buf_mem_st */
            	794, 0,
            0, 24, 1, /* 794: struct.buf_mem_st */
            	96, 8,
            8884097, 8, 0, /* 799: pointer.func */
            0, 96, 11, /* 802: struct.dsa_method */
            	115, 0,
            	827, 8,
            	830, 16,
            	799, 24,
            	833, 32,
            	726, 40,
            	836, 48,
            	836, 56,
            	96, 72,
            	839, 80,
            	836, 88,
            8884097, 8, 0, /* 827: pointer.func */
            8884097, 8, 0, /* 830: pointer.func */
            8884097, 8, 0, /* 833: pointer.func */
            8884097, 8, 0, /* 836: pointer.func */
            8884097, 8, 0, /* 839: pointer.func */
            1, 8, 1, /* 842: pointer.struct.stack_st_void */
            	847, 0,
            0, 32, 1, /* 847: struct.stack_st_void */
            	852, 0,
            0, 32, 2, /* 852: struct.stack_st */
            	859, 8,
            	217, 24,
            1, 8, 1, /* 859: pointer.pointer.char */
            	96, 0,
            1, 8, 1, /* 864: pointer.struct.dsa_method */
            	802, 0,
            1, 8, 1, /* 869: pointer.struct.EDIPartyName_st */
            	291, 0,
            1, 8, 1, /* 874: pointer.struct.dsa_st */
            	879, 0,
            0, 136, 11, /* 879: struct.dsa_st */
            	904, 24,
            	904, 32,
            	904, 40,
            	904, 48,
            	904, 56,
            	904, 64,
            	904, 72,
            	922, 88,
            	936, 104,
            	864, 120,
            	941, 128,
            1, 8, 1, /* 904: pointer.struct.bignum_st */
            	909, 0,
            0, 24, 1, /* 909: struct.bignum_st */
            	914, 0,
            1, 8, 1, /* 914: pointer.unsigned int */
            	919, 0,
            0, 4, 0, /* 919: unsigned int */
            1, 8, 1, /* 922: pointer.struct.bn_mont_ctx_st */
            	927, 0,
            0, 96, 3, /* 927: struct.bn_mont_ctx_st */
            	909, 8,
            	909, 32,
            	909, 56,
            0, 16, 1, /* 936: struct.crypto_ex_data_st */
            	842, 0,
            1, 8, 1, /* 941: pointer.struct.engine_st */
            	946, 0,
            0, 0, 0, /* 946: struct.engine_st */
            0, 168, 17, /* 949: struct.rsa_st */
            	986, 16,
            	941, 24,
            	904, 32,
            	904, 40,
            	904, 48,
            	904, 56,
            	904, 64,
            	904, 72,
            	904, 80,
            	904, 88,
            	936, 96,
            	922, 120,
            	922, 128,
            	922, 136,
            	96, 144,
            	1041, 152,
            	1041, 160,
            1, 8, 1, /* 986: pointer.struct.rsa_meth_st */
            	991, 0,
            0, 112, 13, /* 991: struct.rsa_meth_st */
            	115, 0,
            	1020, 8,
            	1020, 16,
            	1020, 24,
            	1020, 32,
            	1023, 40,
            	1026, 48,
            	1029, 56,
            	1029, 64,
            	96, 80,
            	1032, 88,
            	1035, 96,
            	1038, 104,
            8884097, 8, 0, /* 1020: pointer.func */
            8884097, 8, 0, /* 1023: pointer.func */
            8884097, 8, 0, /* 1026: pointer.func */
            8884097, 8, 0, /* 1029: pointer.func */
            8884097, 8, 0, /* 1032: pointer.func */
            8884097, 8, 0, /* 1035: pointer.func */
            8884097, 8, 0, /* 1038: pointer.func */
            1, 8, 1, /* 1041: pointer.struct.bn_blinding_st */
            	1046, 0,
            0, 0, 0, /* 1046: struct.bn_blinding_st */
            0, 104, 11, /* 1049: struct.x509_cinf_st */
            	1074, 0,
            	1074, 8,
            	1079, 16,
            	1218, 24,
            	1266, 32,
            	1218, 40,
            	1283, 48,
            	1168, 56,
            	1168, 64,
            	1407, 72,
            	1457, 80,
            1, 8, 1, /* 1074: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1079: pointer.struct.X509_algor_st */
            	1084, 0,
            0, 16, 2, /* 1084: struct.X509_algor_st */
            	1091, 0,
            	1105, 8,
            1, 8, 1, /* 1091: pointer.struct.asn1_object_st */
            	1096, 0,
            0, 40, 3, /* 1096: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 1105: pointer.struct.asn1_type_st */
            	1110, 0,
            0, 16, 1, /* 1110: struct.asn1_type_st */
            	1115, 8,
            0, 8, 20, /* 1115: union.unknown */
            	96, 0,
            	1158, 0,
            	1091, 0,
            	1074, 0,
            	1163, 0,
            	1168, 0,
            	286, 0,
            	1173, 0,
            	1178, 0,
            	1183, 0,
            	1188, 0,
            	1193, 0,
            	1198, 0,
            	1203, 0,
            	1208, 0,
            	1213, 0,
            	276, 0,
            	1158, 0,
            	1158, 0,
            	160, 0,
            1, 8, 1, /* 1158: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1163: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1168: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1173: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1178: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1183: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1188: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1193: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1198: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1203: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1208: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1213: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1218: pointer.struct.X509_name_st */
            	1223, 0,
            0, 40, 3, /* 1223: struct.X509_name_st */
            	1232, 0,
            	1256, 16,
            	10, 24,
            1, 8, 1, /* 1232: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1237, 0,
            0, 32, 2, /* 1237: struct.stack_st_fake_X509_NAME_ENTRY */
            	1244, 8,
            	217, 24,
            8884099, 8, 2, /* 1244: pointer_to_array_of_pointers_to_stack */
            	1251, 0,
            	214, 20,
            0, 8, 1, /* 1251: pointer.X509_NAME_ENTRY */
            	762, 0,
            1, 8, 1, /* 1256: pointer.struct.buf_mem_st */
            	1261, 0,
            0, 24, 1, /* 1261: struct.buf_mem_st */
            	96, 8,
            1, 8, 1, /* 1266: pointer.struct.X509_val_st */
            	1271, 0,
            0, 16, 2, /* 1271: struct.X509_val_st */
            	1278, 0,
            	1278, 8,
            1, 8, 1, /* 1278: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1283: pointer.struct.X509_pubkey_st */
            	1288, 0,
            0, 24, 3, /* 1288: struct.X509_pubkey_st */
            	1079, 0,
            	1168, 8,
            	1297, 16,
            1, 8, 1, /* 1297: pointer.struct.evp_pkey_st */
            	1302, 0,
            0, 56, 4, /* 1302: struct.evp_pkey_st */
            	1313, 16,
            	941, 24,
            	1321, 32,
            	694, 48,
            1, 8, 1, /* 1313: pointer.struct.evp_pkey_asn1_method_st */
            	1318, 0,
            0, 0, 0, /* 1318: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1321: union.unknown */
            	96, 0,
            	1334, 0,
            	874, 0,
            	1339, 0,
            	718, 0,
            1, 8, 1, /* 1334: pointer.struct.rsa_st */
            	949, 0,
            1, 8, 1, /* 1339: pointer.struct.dh_st */
            	1344, 0,
            0, 144, 12, /* 1344: struct.dh_st */
            	904, 8,
            	904, 16,
            	904, 32,
            	904, 40,
            	922, 56,
            	904, 64,
            	904, 72,
            	10, 80,
            	904, 96,
            	936, 112,
            	1371, 128,
            	941, 136,
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
            8884097, 8, 0, /* 1395: pointer.func */
            8884097, 8, 0, /* 1398: pointer.func */
            8884097, 8, 0, /* 1401: pointer.func */
            8884097, 8, 0, /* 1404: pointer.func */
            1, 8, 1, /* 1407: pointer.struct.stack_st_X509_EXTENSION */
            	1412, 0,
            0, 32, 2, /* 1412: struct.stack_st_fake_X509_EXTENSION */
            	1419, 8,
            	217, 24,
            8884099, 8, 2, /* 1419: pointer_to_array_of_pointers_to_stack */
            	1426, 0,
            	214, 20,
            0, 8, 1, /* 1426: pointer.X509_EXTENSION */
            	1431, 0,
            0, 0, 1, /* 1431: X509_EXTENSION */
            	1436, 0,
            0, 24, 2, /* 1436: struct.X509_extension_st */
            	1443, 0,
            	486, 16,
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
            0, 8, 0, /* 1467: pointer.void */
            1, 8, 1, /* 1470: pointer.struct.x509_st */
            	1475, 0,
            0, 184, 12, /* 1475: struct.x509_st */
            	1502, 0,
            	1079, 8,
            	1168, 16,
            	96, 32,
            	936, 40,
            	286, 104,
            	1507, 112,
            	1762, 120,
            	1770, 128,
            	1909, 136,
            	1933, 144,
            	258, 176,
            1, 8, 1, /* 1502: pointer.struct.x509_cinf_st */
            	1049, 0,
            1, 8, 1, /* 1507: pointer.struct.AUTHORITY_KEYID_st */
            	1512, 0,
            0, 24, 3, /* 1512: struct.AUTHORITY_KEYID_st */
            	286, 0,
            	1521, 8,
            	1074, 16,
            1, 8, 1, /* 1521: pointer.struct.stack_st_GENERAL_NAME */
            	1526, 0,
            0, 32, 2, /* 1526: struct.stack_st_fake_GENERAL_NAME */
            	1533, 8,
            	217, 24,
            8884099, 8, 2, /* 1533: pointer_to_array_of_pointers_to_stack */
            	1540, 0,
            	214, 20,
            0, 8, 1, /* 1540: pointer.GENERAL_NAME */
            	1545, 0,
            0, 0, 1, /* 1545: GENERAL_NAME */
            	1550, 0,
            0, 16, 1, /* 1550: struct.GENERAL_NAME_st */
            	1555, 8,
            0, 8, 15, /* 1555: union.unknown */
            	96, 0,
            	1588, 0,
            	1697, 0,
            	1697, 0,
            	1614, 0,
            	1745, 0,
            	1750, 0,
            	1697, 0,
            	496, 0,
            	1600, 0,
            	496, 0,
            	1745, 0,
            	1697, 0,
            	1600, 0,
            	1614, 0,
            1, 8, 1, /* 1588: pointer.struct.otherName_st */
            	1593, 0,
            0, 16, 2, /* 1593: struct.otherName_st */
            	1600, 0,
            	1614, 8,
            1, 8, 1, /* 1600: pointer.struct.asn1_object_st */
            	1605, 0,
            0, 40, 3, /* 1605: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 1614: pointer.struct.asn1_type_st */
            	1619, 0,
            0, 16, 1, /* 1619: struct.asn1_type_st */
            	1624, 8,
            0, 8, 20, /* 1624: union.unknown */
            	96, 0,
            	1667, 0,
            	1600, 0,
            	1672, 0,
            	1677, 0,
            	1682, 0,
            	496, 0,
            	1687, 0,
            	1692, 0,
            	1697, 0,
            	1702, 0,
            	1707, 0,
            	1712, 0,
            	1717, 0,
            	1722, 0,
            	1727, 0,
            	1732, 0,
            	1667, 0,
            	1667, 0,
            	1737, 0,
            1, 8, 1, /* 1667: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1672: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1677: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1682: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1687: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1692: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1697: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1702: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1707: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1712: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1717: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1722: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1727: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1732: pointer.struct.asn1_string_st */
            	501, 0,
            1, 8, 1, /* 1737: pointer.struct.ASN1_VALUE_st */
            	1742, 0,
            0, 0, 0, /* 1742: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1745: pointer.struct.X509_name_st */
            	729, 0,
            1, 8, 1, /* 1750: pointer.struct.EDIPartyName_st */
            	1755, 0,
            0, 16, 2, /* 1755: struct.EDIPartyName_st */
            	1667, 0,
            	1667, 8,
            1, 8, 1, /* 1762: pointer.struct.X509_POLICY_CACHE_st */
            	1767, 0,
            0, 0, 0, /* 1767: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1770: pointer.struct.stack_st_DIST_POINT */
            	1775, 0,
            0, 32, 2, /* 1775: struct.stack_st_fake_DIST_POINT */
            	1782, 8,
            	217, 24,
            8884099, 8, 2, /* 1782: pointer_to_array_of_pointers_to_stack */
            	1789, 0,
            	214, 20,
            0, 8, 1, /* 1789: pointer.DIST_POINT */
            	1794, 0,
            0, 0, 1, /* 1794: DIST_POINT */
            	1799, 0,
            0, 32, 3, /* 1799: struct.DIST_POINT_st */
            	1808, 0,
            	1899, 8,
            	1827, 16,
            1, 8, 1, /* 1808: pointer.struct.DIST_POINT_NAME_st */
            	1813, 0,
            0, 24, 2, /* 1813: struct.DIST_POINT_NAME_st */
            	1820, 8,
            	1875, 16,
            0, 8, 2, /* 1820: union.unknown */
            	1827, 0,
            	1851, 0,
            1, 8, 1, /* 1827: pointer.struct.stack_st_GENERAL_NAME */
            	1832, 0,
            0, 32, 2, /* 1832: struct.stack_st_fake_GENERAL_NAME */
            	1839, 8,
            	217, 24,
            8884099, 8, 2, /* 1839: pointer_to_array_of_pointers_to_stack */
            	1846, 0,
            	214, 20,
            0, 8, 1, /* 1846: pointer.GENERAL_NAME */
            	1545, 0,
            1, 8, 1, /* 1851: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1856, 0,
            0, 32, 2, /* 1856: struct.stack_st_fake_X509_NAME_ENTRY */
            	1863, 8,
            	217, 24,
            8884099, 8, 2, /* 1863: pointer_to_array_of_pointers_to_stack */
            	1870, 0,
            	214, 20,
            0, 8, 1, /* 1870: pointer.X509_NAME_ENTRY */
            	762, 0,
            1, 8, 1, /* 1875: pointer.struct.X509_name_st */
            	1880, 0,
            0, 40, 3, /* 1880: struct.X509_name_st */
            	1851, 0,
            	1889, 16,
            	10, 24,
            1, 8, 1, /* 1889: pointer.struct.buf_mem_st */
            	1894, 0,
            0, 24, 1, /* 1894: struct.buf_mem_st */
            	96, 8,
            1, 8, 1, /* 1899: pointer.struct.asn1_string_st */
            	1904, 0,
            0, 24, 1, /* 1904: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 1909: pointer.struct.stack_st_GENERAL_NAME */
            	1914, 0,
            0, 32, 2, /* 1914: struct.stack_st_fake_GENERAL_NAME */
            	1921, 8,
            	217, 24,
            8884099, 8, 2, /* 1921: pointer_to_array_of_pointers_to_stack */
            	1928, 0,
            	214, 20,
            0, 8, 1, /* 1928: pointer.GENERAL_NAME */
            	1545, 0,
            1, 8, 1, /* 1933: pointer.struct.NAME_CONSTRAINTS_st */
            	1938, 0,
            0, 16, 2, /* 1938: struct.NAME_CONSTRAINTS_st */
            	1945, 0,
            	1945, 8,
            1, 8, 1, /* 1945: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1950, 0,
            0, 32, 2, /* 1950: struct.stack_st_fake_GENERAL_SUBTREE */
            	1957, 8,
            	217, 24,
            8884099, 8, 2, /* 1957: pointer_to_array_of_pointers_to_stack */
            	1964, 0,
            	214, 20,
            0, 8, 1, /* 1964: pointer.GENERAL_SUBTREE */
            	1969, 0,
            0, 0, 1, /* 1969: GENERAL_SUBTREE */
            	1974, 0,
            0, 24, 3, /* 1974: struct.GENERAL_SUBTREE_st */
            	1983, 0,
            	2105, 8,
            	2105, 16,
            1, 8, 1, /* 1983: pointer.struct.GENERAL_NAME_st */
            	1988, 0,
            0, 16, 1, /* 1988: struct.GENERAL_NAME_st */
            	1993, 8,
            0, 8, 15, /* 1993: union.unknown */
            	96, 0,
            	2026, 0,
            	2130, 0,
            	2130, 0,
            	2052, 0,
            	2165, 0,
            	869, 0,
            	2130, 0,
            	506, 0,
            	2038, 0,
            	506, 0,
            	2165, 0,
            	2130, 0,
            	2038, 0,
            	2052, 0,
            1, 8, 1, /* 2026: pointer.struct.otherName_st */
            	2031, 0,
            0, 16, 2, /* 2031: struct.otherName_st */
            	2038, 0,
            	2052, 8,
            1, 8, 1, /* 2038: pointer.struct.asn1_object_st */
            	2043, 0,
            0, 40, 3, /* 2043: struct.asn1_object_st */
            	115, 0,
            	115, 8,
            	120, 24,
            1, 8, 1, /* 2052: pointer.struct.asn1_type_st */
            	2057, 0,
            0, 16, 1, /* 2057: struct.asn1_type_st */
            	2062, 8,
            0, 8, 20, /* 2062: union.unknown */
            	96, 0,
            	298, 0,
            	2038, 0,
            	2105, 0,
            	2110, 0,
            	2115, 0,
            	506, 0,
            	2120, 0,
            	2125, 0,
            	2130, 0,
            	2135, 0,
            	2140, 0,
            	2145, 0,
            	2150, 0,
            	1462, 0,
            	2155, 0,
            	2160, 0,
            	298, 0,
            	298, 0,
            	1737, 0,
            1, 8, 1, /* 2105: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2110: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2115: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2120: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2125: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2130: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2135: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2140: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2145: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2150: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2155: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2160: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2165: pointer.struct.X509_name_st */
            	2170, 0,
            0, 40, 3, /* 2170: struct.X509_name_st */
            	2179, 0,
            	2203, 16,
            	10, 24,
            1, 8, 1, /* 2179: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2184, 0,
            0, 32, 2, /* 2184: struct.stack_st_fake_X509_NAME_ENTRY */
            	2191, 8,
            	217, 24,
            8884099, 8, 2, /* 2191: pointer_to_array_of_pointers_to_stack */
            	2198, 0,
            	214, 20,
            0, 8, 1, /* 2198: pointer.X509_NAME_ENTRY */
            	762, 0,
            1, 8, 1, /* 2203: pointer.struct.buf_mem_st */
            	308, 0,
            0, 1, 0, /* 2208: char */
            1, 8, 1, /* 2211: pointer.int */
            	214, 0,
        },
        .arg_entity_index = { 1470, 214, 2211, 2211, },
        .ret_entity_index = 1467,
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

