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

X509_NAME * bb_X509_get_subject_name(X509 * arg_a);

X509_NAME * X509_get_subject_name(X509 * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_subject_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_subject_name(arg_a);
    else {
        X509_NAME * (*orig_X509_get_subject_name)(X509 *);
        orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
        return orig_X509_get_subject_name(arg_a);
    }
}

X509_NAME * bb_X509_get_subject_name(X509 * arg_a) 
{
    X509_NAME * ret;

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
            1, 8, 1, /* 53: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 58: pointer.struct.asn1_string_st */
            	5, 0,
            0, 8, 20, /* 63: union.unknown */
            	106, 0,
            	58, 0,
            	111, 0,
            	53, 0,
            	135, 0,
            	48, 0,
            	140, 0,
            	43, 0,
            	38, 0,
            	33, 0,
            	145, 0,
            	28, 0,
            	150, 0,
            	23, 0,
            	18, 0,
            	155, 0,
            	0, 0,
            	58, 0,
            	58, 0,
            	160, 0,
            1, 8, 1, /* 106: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 111: pointer.struct.asn1_object_st */
            	116, 0,
            0, 40, 3, /* 116: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 125: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 130: pointer.unsigned char */
            	15, 0,
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
            	63, 8,
            0, 0, 1, /* 178: X509_ALGOR */
            	183, 0,
            0, 16, 2, /* 183: struct.X509_algor_st */
            	111, 0,
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
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 234: pointer.struct.x509_cert_aux_st */
            	239, 0,
            0, 40, 5, /* 239: struct.x509_cert_aux_st */
            	252, 0,
            	252, 8,
            	276, 16,
            	286, 24,
            	190, 32,
            1, 8, 1, /* 252: pointer.struct.stack_st_ASN1_OBJECT */
            	257, 0,
            0, 32, 2, /* 257: struct.stack_st_fake_ASN1_OBJECT */
            	264, 8,
            	217, 24,
            8884099, 8, 2, /* 264: pointer_to_array_of_pointers_to_stack */
            	271, 0,
            	214, 20,
            0, 8, 1, /* 271: pointer.ASN1_OBJECT */
            	220, 0,
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
            1, 8, 1, /* 308: pointer.struct.asn1_string_st */
            	313, 0,
            0, 24, 1, /* 313: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 318: pointer.struct.asn1_object_st */
            	323, 0,
            0, 40, 3, /* 323: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 332: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 337: pointer.struct.dh_st */
            	342, 0,
            0, 144, 12, /* 342: struct.dh_st */
            	369, 8,
            	369, 16,
            	369, 32,
            	369, 40,
            	387, 56,
            	369, 64,
            	369, 72,
            	10, 80,
            	369, 96,
            	401, 112,
            	428, 128,
            	464, 136,
            1, 8, 1, /* 369: pointer.struct.bignum_st */
            	374, 0,
            0, 24, 1, /* 374: struct.bignum_st */
            	379, 0,
            1, 8, 1, /* 379: pointer.unsigned int */
            	384, 0,
            0, 4, 0, /* 384: unsigned int */
            1, 8, 1, /* 387: pointer.struct.bn_mont_ctx_st */
            	392, 0,
            0, 96, 3, /* 392: struct.bn_mont_ctx_st */
            	374, 8,
            	374, 32,
            	374, 56,
            0, 16, 1, /* 401: struct.crypto_ex_data_st */
            	406, 0,
            1, 8, 1, /* 406: pointer.struct.stack_st_void */
            	411, 0,
            0, 32, 1, /* 411: struct.stack_st_void */
            	416, 0,
            0, 32, 2, /* 416: struct.stack_st */
            	423, 8,
            	217, 24,
            1, 8, 1, /* 423: pointer.pointer.char */
            	106, 0,
            1, 8, 1, /* 428: pointer.struct.dh_method */
            	433, 0,
            0, 72, 8, /* 433: struct.dh_method */
            	125, 0,
            	452, 8,
            	455, 16,
            	458, 24,
            	452, 32,
            	452, 40,
            	106, 56,
            	461, 64,
            8884097, 8, 0, /* 452: pointer.func */
            8884097, 8, 0, /* 455: pointer.func */
            8884097, 8, 0, /* 458: pointer.func */
            8884097, 8, 0, /* 461: pointer.func */
            1, 8, 1, /* 464: pointer.struct.engine_st */
            	469, 0,
            0, 0, 0, /* 469: struct.engine_st */
            1, 8, 1, /* 472: pointer.struct.asn1_string_st */
            	313, 0,
            0, 16, 1, /* 477: struct.asn1_type_st */
            	482, 8,
            0, 8, 20, /* 482: union.unknown */
            	106, 0,
            	472, 0,
            	525, 0,
            	539, 0,
            	332, 0,
            	544, 0,
            	308, 0,
            	549, 0,
            	554, 0,
            	559, 0,
            	564, 0,
            	569, 0,
            	574, 0,
            	579, 0,
            	584, 0,
            	589, 0,
            	594, 0,
            	472, 0,
            	472, 0,
            	599, 0,
            1, 8, 1, /* 525: pointer.struct.asn1_object_st */
            	530, 0,
            0, 40, 3, /* 530: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 539: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 544: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 549: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 554: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 559: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 564: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 569: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 574: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 579: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 584: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 589: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 594: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 599: pointer.struct.ASN1_VALUE_st */
            	604, 0,
            0, 0, 0, /* 604: struct.ASN1_VALUE_st */
            0, 0, 1, /* 607: ASN1_TYPE */
            	477, 0,
            0, 40, 3, /* 612: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            0, 40, 3, /* 621: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            0, 24, 2, /* 630: struct.x509_attributes_st */
            	637, 0,
            	642, 16,
            1, 8, 1, /* 637: pointer.struct.asn1_object_st */
            	621, 0,
            0, 8, 3, /* 642: union.unknown */
            	106, 0,
            	651, 0,
            	675, 0,
            1, 8, 1, /* 651: pointer.struct.stack_st_ASN1_TYPE */
            	656, 0,
            0, 32, 2, /* 656: struct.stack_st_fake_ASN1_TYPE */
            	663, 8,
            	217, 24,
            8884099, 8, 2, /* 663: pointer_to_array_of_pointers_to_stack */
            	670, 0,
            	214, 20,
            0, 8, 1, /* 670: pointer.ASN1_TYPE */
            	607, 0,
            1, 8, 1, /* 675: pointer.struct.asn1_type_st */
            	680, 0,
            0, 16, 1, /* 680: struct.asn1_type_st */
            	685, 8,
            0, 8, 20, /* 685: union.unknown */
            	106, 0,
            	728, 0,
            	637, 0,
            	738, 0,
            	743, 0,
            	748, 0,
            	753, 0,
            	758, 0,
            	763, 0,
            	768, 0,
            	773, 0,
            	778, 0,
            	783, 0,
            	788, 0,
            	793, 0,
            	798, 0,
            	803, 0,
            	728, 0,
            	728, 0,
            	160, 0,
            1, 8, 1, /* 728: pointer.struct.asn1_string_st */
            	733, 0,
            0, 24, 1, /* 733: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 738: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 743: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 748: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 753: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 758: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 763: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 768: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 773: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 778: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 783: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 788: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 793: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 798: pointer.struct.asn1_string_st */
            	733, 0,
            1, 8, 1, /* 803: pointer.struct.asn1_string_st */
            	733, 0,
            8884097, 8, 0, /* 808: pointer.func */
            1, 8, 1, /* 811: pointer.struct.ec_key_st */
            	816, 0,
            0, 0, 0, /* 816: struct.ec_key_st */
            1, 8, 1, /* 819: pointer.struct.asn1_type_st */
            	824, 0,
            0, 16, 1, /* 824: struct.asn1_type_st */
            	829, 8,
            0, 8, 20, /* 829: union.unknown */
            	106, 0,
            	872, 0,
            	877, 0,
            	891, 0,
            	896, 0,
            	901, 0,
            	286, 0,
            	906, 0,
            	911, 0,
            	916, 0,
            	921, 0,
            	926, 0,
            	931, 0,
            	936, 0,
            	941, 0,
            	946, 0,
            	276, 0,
            	872, 0,
            	872, 0,
            	160, 0,
            1, 8, 1, /* 872: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 877: pointer.struct.asn1_object_st */
            	882, 0,
            0, 40, 3, /* 882: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 891: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 896: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 901: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 906: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 911: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 916: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 921: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 926: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 931: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 936: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 941: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 946: pointer.struct.asn1_string_st */
            	281, 0,
            8884097, 8, 0, /* 951: pointer.func */
            8884097, 8, 0, /* 954: pointer.func */
            0, 0, 0, /* 957: struct.evp_pkey_asn1_method_st */
            0, 8, 15, /* 960: union.unknown */
            	106, 0,
            	993, 0,
            	1102, 0,
            	1102, 0,
            	1019, 0,
            	1150, 0,
            	1225, 0,
            	1102, 0,
            	1087, 0,
            	1005, 0,
            	1087, 0,
            	1150, 0,
            	1102, 0,
            	1005, 0,
            	1019, 0,
            1, 8, 1, /* 993: pointer.struct.otherName_st */
            	998, 0,
            0, 16, 2, /* 998: struct.otherName_st */
            	1005, 0,
            	1019, 8,
            1, 8, 1, /* 1005: pointer.struct.asn1_object_st */
            	1010, 0,
            0, 40, 3, /* 1010: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 1019: pointer.struct.asn1_type_st */
            	1024, 0,
            0, 16, 1, /* 1024: struct.asn1_type_st */
            	1029, 8,
            0, 8, 20, /* 1029: union.unknown */
            	106, 0,
            	298, 0,
            	1005, 0,
            	1072, 0,
            	1077, 0,
            	1082, 0,
            	1087, 0,
            	1092, 0,
            	1097, 0,
            	1102, 0,
            	1107, 0,
            	1112, 0,
            	1117, 0,
            	1122, 0,
            	1127, 0,
            	1132, 0,
            	1137, 0,
            	298, 0,
            	298, 0,
            	1142, 0,
            1, 8, 1, /* 1072: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1077: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1082: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1087: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1092: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1097: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1102: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1107: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1112: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1117: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1122: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1127: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1132: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1137: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1142: pointer.struct.ASN1_VALUE_st */
            	1147, 0,
            0, 0, 0, /* 1147: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1150: pointer.struct.X509_name_st */
            	1155, 0,
            0, 40, 3, /* 1155: struct.X509_name_st */
            	1164, 0,
            	1215, 16,
            	10, 24,
            1, 8, 1, /* 1164: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1169, 0,
            0, 32, 2, /* 1169: struct.stack_st_fake_X509_NAME_ENTRY */
            	1176, 8,
            	217, 24,
            8884099, 8, 2, /* 1176: pointer_to_array_of_pointers_to_stack */
            	1183, 0,
            	214, 20,
            0, 8, 1, /* 1183: pointer.X509_NAME_ENTRY */
            	1188, 0,
            0, 0, 1, /* 1188: X509_NAME_ENTRY */
            	1193, 0,
            0, 24, 2, /* 1193: struct.X509_name_entry_st */
            	1200, 0,
            	1205, 8,
            1, 8, 1, /* 1200: pointer.struct.asn1_object_st */
            	612, 0,
            1, 8, 1, /* 1205: pointer.struct.asn1_string_st */
            	1210, 0,
            0, 24, 1, /* 1210: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 1215: pointer.struct.buf_mem_st */
            	1220, 0,
            0, 24, 1, /* 1220: struct.buf_mem_st */
            	106, 8,
            1, 8, 1, /* 1225: pointer.struct.EDIPartyName_st */
            	291, 0,
            1, 8, 1, /* 1230: pointer.struct.dsa_method */
            	1235, 0,
            0, 96, 11, /* 1235: struct.dsa_method */
            	125, 0,
            	954, 8,
            	1260, 16,
            	1263, 24,
            	951, 32,
            	1266, 40,
            	1269, 48,
            	1269, 56,
            	106, 72,
            	1272, 80,
            	1269, 88,
            8884097, 8, 0, /* 1260: pointer.func */
            8884097, 8, 0, /* 1263: pointer.func */
            8884097, 8, 0, /* 1266: pointer.func */
            8884097, 8, 0, /* 1269: pointer.func */
            8884097, 8, 0, /* 1272: pointer.func */
            0, 24, 3, /* 1275: struct.AUTHORITY_KEYID_st */
            	286, 0,
            	1284, 8,
            	891, 16,
            1, 8, 1, /* 1284: pointer.struct.stack_st_GENERAL_NAME */
            	1289, 0,
            0, 32, 2, /* 1289: struct.stack_st_fake_GENERAL_NAME */
            	1296, 8,
            	217, 24,
            8884099, 8, 2, /* 1296: pointer_to_array_of_pointers_to_stack */
            	1303, 0,
            	214, 20,
            0, 8, 1, /* 1303: pointer.GENERAL_NAME */
            	1308, 0,
            0, 0, 1, /* 1308: GENERAL_NAME */
            	1313, 0,
            0, 16, 1, /* 1313: struct.GENERAL_NAME_st */
            	1318, 8,
            0, 8, 15, /* 1318: union.unknown */
            	106, 0,
            	1351, 0,
            	1470, 0,
            	1470, 0,
            	1377, 0,
            	1510, 0,
            	1558, 0,
            	1470, 0,
            	1455, 0,
            	1363, 0,
            	1455, 0,
            	1510, 0,
            	1470, 0,
            	1363, 0,
            	1377, 0,
            1, 8, 1, /* 1351: pointer.struct.otherName_st */
            	1356, 0,
            0, 16, 2, /* 1356: struct.otherName_st */
            	1363, 0,
            	1377, 8,
            1, 8, 1, /* 1363: pointer.struct.asn1_object_st */
            	1368, 0,
            0, 40, 3, /* 1368: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 1377: pointer.struct.asn1_type_st */
            	1382, 0,
            0, 16, 1, /* 1382: struct.asn1_type_st */
            	1387, 8,
            0, 8, 20, /* 1387: union.unknown */
            	106, 0,
            	1430, 0,
            	1363, 0,
            	1440, 0,
            	1445, 0,
            	1450, 0,
            	1455, 0,
            	1460, 0,
            	1465, 0,
            	1470, 0,
            	1475, 0,
            	1480, 0,
            	1485, 0,
            	1490, 0,
            	1495, 0,
            	1500, 0,
            	1505, 0,
            	1430, 0,
            	1430, 0,
            	1142, 0,
            1, 8, 1, /* 1430: pointer.struct.asn1_string_st */
            	1435, 0,
            0, 24, 1, /* 1435: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 1440: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1445: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1450: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1455: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1460: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1465: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1470: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1475: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1480: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1485: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1490: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1495: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1500: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1505: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1510: pointer.struct.X509_name_st */
            	1515, 0,
            0, 40, 3, /* 1515: struct.X509_name_st */
            	1524, 0,
            	1548, 16,
            	10, 24,
            1, 8, 1, /* 1524: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1529, 0,
            0, 32, 2, /* 1529: struct.stack_st_fake_X509_NAME_ENTRY */
            	1536, 8,
            	217, 24,
            8884099, 8, 2, /* 1536: pointer_to_array_of_pointers_to_stack */
            	1543, 0,
            	214, 20,
            0, 8, 1, /* 1543: pointer.X509_NAME_ENTRY */
            	1188, 0,
            1, 8, 1, /* 1548: pointer.struct.buf_mem_st */
            	1553, 0,
            0, 24, 1, /* 1553: struct.buf_mem_st */
            	106, 8,
            1, 8, 1, /* 1558: pointer.struct.EDIPartyName_st */
            	1563, 0,
            0, 16, 2, /* 1563: struct.EDIPartyName_st */
            	1430, 0,
            	1430, 8,
            0, 0, 0, /* 1570: struct.bn_blinding_st */
            1, 8, 1, /* 1573: pointer.struct.dsa_st */
            	1578, 0,
            0, 136, 11, /* 1578: struct.dsa_st */
            	369, 24,
            	369, 32,
            	369, 40,
            	369, 48,
            	369, 56,
            	369, 64,
            	369, 72,
            	387, 88,
            	401, 104,
            	1230, 120,
            	464, 128,
            0, 16, 2, /* 1603: struct.NAME_CONSTRAINTS_st */
            	1610, 0,
            	1610, 8,
            1, 8, 1, /* 1610: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1615, 0,
            0, 32, 2, /* 1615: struct.stack_st_fake_GENERAL_SUBTREE */
            	1622, 8,
            	217, 24,
            8884099, 8, 2, /* 1622: pointer_to_array_of_pointers_to_stack */
            	1629, 0,
            	214, 20,
            0, 8, 1, /* 1629: pointer.GENERAL_SUBTREE */
            	1634, 0,
            0, 0, 1, /* 1634: GENERAL_SUBTREE */
            	1639, 0,
            0, 24, 3, /* 1639: struct.GENERAL_SUBTREE_st */
            	1648, 0,
            	1072, 8,
            	1072, 16,
            1, 8, 1, /* 1648: pointer.struct.GENERAL_NAME_st */
            	1653, 0,
            0, 16, 1, /* 1653: struct.GENERAL_NAME_st */
            	960, 8,
            0, 24, 3, /* 1658: struct.X509_pubkey_st */
            	1667, 0,
            	901, 8,
            	1679, 16,
            1, 8, 1, /* 1667: pointer.struct.X509_algor_st */
            	1672, 0,
            0, 16, 2, /* 1672: struct.X509_algor_st */
            	877, 0,
            	819, 8,
            1, 8, 1, /* 1679: pointer.struct.evp_pkey_st */
            	1684, 0,
            0, 56, 4, /* 1684: struct.evp_pkey_st */
            	1695, 16,
            	464, 24,
            	1700, 32,
            	1812, 48,
            1, 8, 1, /* 1695: pointer.struct.evp_pkey_asn1_method_st */
            	957, 0,
            0, 8, 5, /* 1700: union.unknown */
            	106, 0,
            	1713, 0,
            	1573, 0,
            	337, 0,
            	811, 0,
            1, 8, 1, /* 1713: pointer.struct.rsa_st */
            	1718, 0,
            0, 168, 17, /* 1718: struct.rsa_st */
            	1755, 16,
            	464, 24,
            	369, 32,
            	369, 40,
            	369, 48,
            	369, 56,
            	369, 64,
            	369, 72,
            	369, 80,
            	369, 88,
            	401, 96,
            	387, 120,
            	387, 128,
            	387, 136,
            	106, 144,
            	1807, 152,
            	1807, 160,
            1, 8, 1, /* 1755: pointer.struct.rsa_meth_st */
            	1760, 0,
            0, 112, 13, /* 1760: struct.rsa_meth_st */
            	125, 0,
            	808, 8,
            	808, 16,
            	808, 24,
            	808, 32,
            	1789, 40,
            	1792, 48,
            	1795, 56,
            	1795, 64,
            	106, 80,
            	1798, 88,
            	1801, 96,
            	1804, 104,
            8884097, 8, 0, /* 1789: pointer.func */
            8884097, 8, 0, /* 1792: pointer.func */
            8884097, 8, 0, /* 1795: pointer.func */
            8884097, 8, 0, /* 1798: pointer.func */
            8884097, 8, 0, /* 1801: pointer.func */
            8884097, 8, 0, /* 1804: pointer.func */
            1, 8, 1, /* 1807: pointer.struct.bn_blinding_st */
            	1570, 0,
            1, 8, 1, /* 1812: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1817, 0,
            0, 32, 2, /* 1817: struct.stack_st_fake_X509_ATTRIBUTE */
            	1824, 8,
            	217, 24,
            8884099, 8, 2, /* 1824: pointer_to_array_of_pointers_to_stack */
            	1831, 0,
            	214, 20,
            0, 8, 1, /* 1831: pointer.X509_ATTRIBUTE */
            	1836, 0,
            0, 0, 1, /* 1836: X509_ATTRIBUTE */
            	630, 0,
            1, 8, 1, /* 1841: pointer.struct.DIST_POINT_NAME_st */
            	1846, 0,
            0, 24, 2, /* 1846: struct.DIST_POINT_NAME_st */
            	1853, 8,
            	1908, 16,
            0, 8, 2, /* 1853: union.unknown */
            	1860, 0,
            	1884, 0,
            1, 8, 1, /* 1860: pointer.struct.stack_st_GENERAL_NAME */
            	1865, 0,
            0, 32, 2, /* 1865: struct.stack_st_fake_GENERAL_NAME */
            	1872, 8,
            	217, 24,
            8884099, 8, 2, /* 1872: pointer_to_array_of_pointers_to_stack */
            	1879, 0,
            	214, 20,
            0, 8, 1, /* 1879: pointer.GENERAL_NAME */
            	1308, 0,
            1, 8, 1, /* 1884: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1889, 0,
            0, 32, 2, /* 1889: struct.stack_st_fake_X509_NAME_ENTRY */
            	1896, 8,
            	217, 24,
            8884099, 8, 2, /* 1896: pointer_to_array_of_pointers_to_stack */
            	1903, 0,
            	214, 20,
            0, 8, 1, /* 1903: pointer.X509_NAME_ENTRY */
            	1188, 0,
            1, 8, 1, /* 1908: pointer.struct.X509_name_st */
            	1913, 0,
            0, 40, 3, /* 1913: struct.X509_name_st */
            	1884, 0,
            	1922, 16,
            	10, 24,
            1, 8, 1, /* 1922: pointer.struct.buf_mem_st */
            	1927, 0,
            0, 24, 1, /* 1927: struct.buf_mem_st */
            	106, 8,
            1, 8, 1, /* 1932: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1937, 0,
            0, 32, 2, /* 1937: struct.stack_st_fake_X509_NAME_ENTRY */
            	1944, 8,
            	217, 24,
            8884099, 8, 2, /* 1944: pointer_to_array_of_pointers_to_stack */
            	1951, 0,
            	214, 20,
            0, 8, 1, /* 1951: pointer.X509_NAME_ENTRY */
            	1188, 0,
            0, 16, 2, /* 1956: struct.X509_val_st */
            	1963, 0,
            	1963, 8,
            1, 8, 1, /* 1963: pointer.struct.asn1_string_st */
            	281, 0,
            0, 104, 11, /* 1968: struct.x509_cinf_st */
            	891, 0,
            	891, 8,
            	1667, 16,
            	1993, 24,
            	2017, 32,
            	1993, 40,
            	2022, 48,
            	901, 56,
            	901, 64,
            	2027, 72,
            	2073, 80,
            1, 8, 1, /* 1993: pointer.struct.X509_name_st */
            	1998, 0,
            0, 40, 3, /* 1998: struct.X509_name_st */
            	1932, 0,
            	2007, 16,
            	10, 24,
            1, 8, 1, /* 2007: pointer.struct.buf_mem_st */
            	2012, 0,
            0, 24, 1, /* 2012: struct.buf_mem_st */
            	106, 8,
            1, 8, 1, /* 2017: pointer.struct.X509_val_st */
            	1956, 0,
            1, 8, 1, /* 2022: pointer.struct.X509_pubkey_st */
            	1658, 0,
            1, 8, 1, /* 2027: pointer.struct.stack_st_X509_EXTENSION */
            	2032, 0,
            0, 32, 2, /* 2032: struct.stack_st_fake_X509_EXTENSION */
            	2039, 8,
            	217, 24,
            8884099, 8, 2, /* 2039: pointer_to_array_of_pointers_to_stack */
            	2046, 0,
            	214, 20,
            0, 8, 1, /* 2046: pointer.X509_EXTENSION */
            	2051, 0,
            0, 0, 1, /* 2051: X509_EXTENSION */
            	2056, 0,
            0, 24, 2, /* 2056: struct.X509_extension_st */
            	318, 0,
            	2063, 16,
            1, 8, 1, /* 2063: pointer.struct.asn1_string_st */
            	2068, 0,
            0, 24, 1, /* 2068: struct.asn1_string_st */
            	10, 8,
            0, 24, 1, /* 2073: struct.ASN1_ENCODING_st */
            	10, 0,
            0, 1, 0, /* 2078: char */
            0, 184, 12, /* 2081: struct.x509_st */
            	2108, 0,
            	1667, 8,
            	901, 16,
            	106, 32,
            	401, 40,
            	286, 104,
            	2113, 112,
            	2118, 120,
            	2126, 128,
            	2174, 136,
            	2198, 144,
            	234, 176,
            1, 8, 1, /* 2108: pointer.struct.x509_cinf_st */
            	1968, 0,
            1, 8, 1, /* 2113: pointer.struct.AUTHORITY_KEYID_st */
            	1275, 0,
            1, 8, 1, /* 2118: pointer.struct.X509_POLICY_CACHE_st */
            	2123, 0,
            0, 0, 0, /* 2123: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2126: pointer.struct.stack_st_DIST_POINT */
            	2131, 0,
            0, 32, 2, /* 2131: struct.stack_st_fake_DIST_POINT */
            	2138, 8,
            	217, 24,
            8884099, 8, 2, /* 2138: pointer_to_array_of_pointers_to_stack */
            	2145, 0,
            	214, 20,
            0, 8, 1, /* 2145: pointer.DIST_POINT */
            	2150, 0,
            0, 0, 1, /* 2150: DIST_POINT */
            	2155, 0,
            0, 32, 3, /* 2155: struct.DIST_POINT_st */
            	1841, 0,
            	2164, 8,
            	1860, 16,
            1, 8, 1, /* 2164: pointer.struct.asn1_string_st */
            	2169, 0,
            0, 24, 1, /* 2169: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 2174: pointer.struct.stack_st_GENERAL_NAME */
            	2179, 0,
            0, 32, 2, /* 2179: struct.stack_st_fake_GENERAL_NAME */
            	2186, 8,
            	217, 24,
            8884099, 8, 2, /* 2186: pointer_to_array_of_pointers_to_stack */
            	2193, 0,
            	214, 20,
            0, 8, 1, /* 2193: pointer.GENERAL_NAME */
            	1308, 0,
            1, 8, 1, /* 2198: pointer.struct.NAME_CONSTRAINTS_st */
            	1603, 0,
            1, 8, 1, /* 2203: pointer.struct.x509_st */
            	2081, 0,
        },
        .arg_entity_index = { 2203, },
        .ret_entity_index = 1993,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    X509_NAME * *new_ret_ptr = (X509_NAME * *)new_args->ret;

    X509_NAME * (*orig_X509_get_subject_name)(X509 *);
    orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
    *new_ret_ptr = (*orig_X509_get_subject_name)(new_arg_a);

    syscall(889);

    return ret;
}

