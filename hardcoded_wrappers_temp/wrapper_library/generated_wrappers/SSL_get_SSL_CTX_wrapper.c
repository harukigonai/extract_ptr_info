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

SSL_CTX * bb_SSL_get_SSL_CTX(const SSL * arg_a);

SSL_CTX * SSL_get_SSL_CTX(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_SSL_CTX called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_SSL_CTX(arg_a);
    else {
        SSL_CTX * (*orig_SSL_get_SSL_CTX)(const SSL *);
        orig_SSL_get_SSL_CTX = dlsym(RTLD_NEXT, "SSL_get_SSL_CTX");
        return orig_SSL_get_SSL_CTX(arg_a);
    }
}

SSL_CTX * bb_SSL_get_SSL_CTX(const SSL * arg_a) 
{
    SSL_CTX * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.tls_session_ticket_ext_st */
            	5, 8,
            0, 8, 0, /* 5: pointer.void */
            0, 24, 1, /* 8: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 13: pointer.unsigned char */
            	18, 0,
            0, 1, 0, /* 18: unsigned char */
            0, 24, 1, /* 21: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 26: pointer.char */
            	8884096, 0,
            0, 8, 2, /* 31: union.unknown */
            	38, 0,
            	133, 0,
            1, 8, 1, /* 38: pointer.struct.X509_name_st */
            	43, 0,
            0, 40, 3, /* 43: struct.X509_name_st */
            	52, 0,
            	128, 16,
            	13, 24,
            1, 8, 1, /* 52: pointer.struct.stack_st_X509_NAME_ENTRY */
            	57, 0,
            0, 32, 2, /* 57: struct.stack_st_fake_X509_NAME_ENTRY */
            	64, 8,
            	125, 24,
            8884099, 8, 2, /* 64: pointer_to_array_of_pointers_to_stack */
            	71, 0,
            	122, 20,
            0, 8, 1, /* 71: pointer.X509_NAME_ENTRY */
            	76, 0,
            0, 0, 1, /* 76: X509_NAME_ENTRY */
            	81, 0,
            0, 24, 2, /* 81: struct.X509_name_entry_st */
            	88, 0,
            	112, 8,
            1, 8, 1, /* 88: pointer.struct.asn1_object_st */
            	93, 0,
            0, 40, 3, /* 93: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 102: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 107: pointer.unsigned char */
            	18, 0,
            1, 8, 1, /* 112: pointer.struct.asn1_string_st */
            	117, 0,
            0, 24, 1, /* 117: struct.asn1_string_st */
            	13, 8,
            0, 4, 0, /* 122: int */
            8884097, 8, 0, /* 125: pointer.func */
            1, 8, 1, /* 128: pointer.struct.buf_mem_st */
            	21, 0,
            1, 8, 1, /* 133: pointer.struct.asn1_string_st */
            	8, 0,
            0, 0, 1, /* 138: OCSP_RESPID */
            	143, 0,
            0, 16, 1, /* 143: struct.ocsp_responder_id_st */
            	31, 8,
            8884097, 8, 0, /* 148: pointer.func */
            8884097, 8, 0, /* 151: pointer.func */
            1, 8, 1, /* 154: pointer.struct.bignum_st */
            	159, 0,
            0, 24, 1, /* 159: struct.bignum_st */
            	164, 0,
            1, 8, 1, /* 164: pointer.unsigned int */
            	169, 0,
            0, 4, 0, /* 169: unsigned int */
            1, 8, 1, /* 172: pointer.struct.ssl3_buf_freelist_st */
            	177, 0,
            0, 24, 1, /* 177: struct.ssl3_buf_freelist_st */
            	182, 16,
            1, 8, 1, /* 182: pointer.struct.ssl3_buf_freelist_entry_st */
            	187, 0,
            0, 8, 1, /* 187: struct.ssl3_buf_freelist_entry_st */
            	182, 0,
            8884097, 8, 0, /* 192: pointer.func */
            1, 8, 1, /* 195: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	200, 0,
            0, 32, 2, /* 200: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	207, 8,
            	125, 24,
            8884099, 8, 2, /* 207: pointer_to_array_of_pointers_to_stack */
            	214, 0,
            	122, 20,
            0, 8, 1, /* 214: pointer.SRTP_PROTECTION_PROFILE */
            	219, 0,
            0, 0, 1, /* 219: SRTP_PROTECTION_PROFILE */
            	224, 0,
            0, 16, 1, /* 224: struct.srtp_protection_profile_st */
            	102, 0,
            1, 8, 1, /* 229: pointer.struct.stack_st_SSL_COMP */
            	234, 0,
            0, 32, 2, /* 234: struct.stack_st_fake_SSL_COMP */
            	241, 8,
            	125, 24,
            8884099, 8, 2, /* 241: pointer_to_array_of_pointers_to_stack */
            	248, 0,
            	122, 20,
            0, 8, 1, /* 248: pointer.SSL_COMP */
            	253, 0,
            0, 0, 1, /* 253: SSL_COMP */
            	258, 0,
            0, 24, 2, /* 258: struct.ssl_comp_st */
            	102, 8,
            	265, 16,
            1, 8, 1, /* 265: pointer.struct.comp_method_st */
            	270, 0,
            0, 64, 7, /* 270: struct.comp_method_st */
            	102, 8,
            	287, 16,
            	290, 24,
            	293, 32,
            	293, 40,
            	296, 48,
            	296, 56,
            8884097, 8, 0, /* 287: pointer.func */
            8884097, 8, 0, /* 290: pointer.func */
            8884097, 8, 0, /* 293: pointer.func */
            8884097, 8, 0, /* 296: pointer.func */
            8884097, 8, 0, /* 299: pointer.func */
            8884097, 8, 0, /* 302: pointer.func */
            8884097, 8, 0, /* 305: pointer.func */
            8884097, 8, 0, /* 308: pointer.func */
            8884097, 8, 0, /* 311: pointer.func */
            8884097, 8, 0, /* 314: pointer.func */
            8884097, 8, 0, /* 317: pointer.func */
            1, 8, 1, /* 320: pointer.struct.stack_st_X509_LOOKUP */
            	325, 0,
            0, 32, 2, /* 325: struct.stack_st_fake_X509_LOOKUP */
            	332, 8,
            	125, 24,
            8884099, 8, 2, /* 332: pointer_to_array_of_pointers_to_stack */
            	339, 0,
            	122, 20,
            0, 8, 1, /* 339: pointer.X509_LOOKUP */
            	344, 0,
            0, 0, 1, /* 344: X509_LOOKUP */
            	349, 0,
            0, 32, 3, /* 349: struct.x509_lookup_st */
            	358, 8,
            	26, 16,
            	407, 24,
            1, 8, 1, /* 358: pointer.struct.x509_lookup_method_st */
            	363, 0,
            0, 80, 10, /* 363: struct.x509_lookup_method_st */
            	102, 0,
            	386, 8,
            	389, 16,
            	386, 24,
            	386, 32,
            	392, 40,
            	395, 48,
            	398, 56,
            	401, 64,
            	404, 72,
            8884097, 8, 0, /* 386: pointer.func */
            8884097, 8, 0, /* 389: pointer.func */
            8884097, 8, 0, /* 392: pointer.func */
            8884097, 8, 0, /* 395: pointer.func */
            8884097, 8, 0, /* 398: pointer.func */
            8884097, 8, 0, /* 401: pointer.func */
            8884097, 8, 0, /* 404: pointer.func */
            1, 8, 1, /* 407: pointer.struct.x509_store_st */
            	412, 0,
            0, 144, 15, /* 412: struct.x509_store_st */
            	445, 8,
            	4334, 16,
            	4358, 24,
            	4370, 32,
            	4373, 40,
            	4376, 48,
            	4379, 56,
            	4370, 64,
            	4382, 72,
            	4385, 80,
            	4388, 88,
            	4391, 96,
            	4394, 104,
            	4370, 112,
            	2686, 120,
            1, 8, 1, /* 445: pointer.struct.stack_st_X509_OBJECT */
            	450, 0,
            0, 32, 2, /* 450: struct.stack_st_fake_X509_OBJECT */
            	457, 8,
            	125, 24,
            8884099, 8, 2, /* 457: pointer_to_array_of_pointers_to_stack */
            	464, 0,
            	122, 20,
            0, 8, 1, /* 464: pointer.X509_OBJECT */
            	469, 0,
            0, 0, 1, /* 469: X509_OBJECT */
            	474, 0,
            0, 16, 1, /* 474: struct.x509_object_st */
            	479, 8,
            0, 8, 4, /* 479: union.unknown */
            	26, 0,
            	490, 0,
            	4023, 0,
            	4256, 0,
            1, 8, 1, /* 490: pointer.struct.x509_st */
            	495, 0,
            0, 184, 12, /* 495: struct.x509_st */
            	522, 0,
            	562, 8,
            	2616, 16,
            	26, 32,
            	2686, 40,
            	2708, 104,
            	2713, 112,
            	3036, 120,
            	3472, 128,
            	3611, 136,
            	3635, 144,
            	3947, 176,
            1, 8, 1, /* 522: pointer.struct.x509_cinf_st */
            	527, 0,
            0, 104, 11, /* 527: struct.x509_cinf_st */
            	552, 0,
            	552, 8,
            	562, 16,
            	729, 24,
            	777, 32,
            	729, 40,
            	794, 48,
            	2616, 56,
            	2616, 64,
            	2621, 72,
            	2681, 80,
            1, 8, 1, /* 552: pointer.struct.asn1_string_st */
            	557, 0,
            0, 24, 1, /* 557: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 562: pointer.struct.X509_algor_st */
            	567, 0,
            0, 16, 2, /* 567: struct.X509_algor_st */
            	574, 0,
            	588, 8,
            1, 8, 1, /* 574: pointer.struct.asn1_object_st */
            	579, 0,
            0, 40, 3, /* 579: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 588: pointer.struct.asn1_type_st */
            	593, 0,
            0, 16, 1, /* 593: struct.asn1_type_st */
            	598, 8,
            0, 8, 20, /* 598: union.unknown */
            	26, 0,
            	641, 0,
            	574, 0,
            	651, 0,
            	656, 0,
            	661, 0,
            	666, 0,
            	671, 0,
            	676, 0,
            	681, 0,
            	686, 0,
            	691, 0,
            	696, 0,
            	701, 0,
            	706, 0,
            	711, 0,
            	716, 0,
            	641, 0,
            	641, 0,
            	721, 0,
            1, 8, 1, /* 641: pointer.struct.asn1_string_st */
            	646, 0,
            0, 24, 1, /* 646: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 651: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 656: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 661: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 666: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 671: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 676: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 681: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 686: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 691: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 696: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 701: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 706: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 711: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 716: pointer.struct.asn1_string_st */
            	646, 0,
            1, 8, 1, /* 721: pointer.struct.ASN1_VALUE_st */
            	726, 0,
            0, 0, 0, /* 726: struct.ASN1_VALUE_st */
            1, 8, 1, /* 729: pointer.struct.X509_name_st */
            	734, 0,
            0, 40, 3, /* 734: struct.X509_name_st */
            	743, 0,
            	767, 16,
            	13, 24,
            1, 8, 1, /* 743: pointer.struct.stack_st_X509_NAME_ENTRY */
            	748, 0,
            0, 32, 2, /* 748: struct.stack_st_fake_X509_NAME_ENTRY */
            	755, 8,
            	125, 24,
            8884099, 8, 2, /* 755: pointer_to_array_of_pointers_to_stack */
            	762, 0,
            	122, 20,
            0, 8, 1, /* 762: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 767: pointer.struct.buf_mem_st */
            	772, 0,
            0, 24, 1, /* 772: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 777: pointer.struct.X509_val_st */
            	782, 0,
            0, 16, 2, /* 782: struct.X509_val_st */
            	789, 0,
            	789, 8,
            1, 8, 1, /* 789: pointer.struct.asn1_string_st */
            	557, 0,
            1, 8, 1, /* 794: pointer.struct.X509_pubkey_st */
            	799, 0,
            0, 24, 3, /* 799: struct.X509_pubkey_st */
            	808, 0,
            	813, 8,
            	823, 16,
            1, 8, 1, /* 808: pointer.struct.X509_algor_st */
            	567, 0,
            1, 8, 1, /* 813: pointer.struct.asn1_string_st */
            	818, 0,
            0, 24, 1, /* 818: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 823: pointer.struct.evp_pkey_st */
            	828, 0,
            0, 56, 4, /* 828: struct.evp_pkey_st */
            	839, 16,
            	940, 24,
            	1293, 32,
            	2237, 48,
            1, 8, 1, /* 839: pointer.struct.evp_pkey_asn1_method_st */
            	844, 0,
            0, 208, 24, /* 844: struct.evp_pkey_asn1_method_st */
            	26, 16,
            	26, 24,
            	895, 32,
            	898, 40,
            	901, 48,
            	904, 56,
            	907, 64,
            	910, 72,
            	904, 80,
            	913, 88,
            	913, 96,
            	916, 104,
            	919, 112,
            	913, 120,
            	922, 128,
            	901, 136,
            	904, 144,
            	925, 152,
            	928, 160,
            	931, 168,
            	916, 176,
            	919, 184,
            	934, 192,
            	937, 200,
            8884097, 8, 0, /* 895: pointer.func */
            8884097, 8, 0, /* 898: pointer.func */
            8884097, 8, 0, /* 901: pointer.func */
            8884097, 8, 0, /* 904: pointer.func */
            8884097, 8, 0, /* 907: pointer.func */
            8884097, 8, 0, /* 910: pointer.func */
            8884097, 8, 0, /* 913: pointer.func */
            8884097, 8, 0, /* 916: pointer.func */
            8884097, 8, 0, /* 919: pointer.func */
            8884097, 8, 0, /* 922: pointer.func */
            8884097, 8, 0, /* 925: pointer.func */
            8884097, 8, 0, /* 928: pointer.func */
            8884097, 8, 0, /* 931: pointer.func */
            8884097, 8, 0, /* 934: pointer.func */
            8884097, 8, 0, /* 937: pointer.func */
            1, 8, 1, /* 940: pointer.struct.engine_st */
            	945, 0,
            0, 216, 24, /* 945: struct.engine_st */
            	102, 0,
            	102, 8,
            	996, 16,
            	1051, 24,
            	1102, 32,
            	1138, 40,
            	1155, 48,
            	1182, 56,
            	1217, 64,
            	1225, 72,
            	1228, 80,
            	1231, 88,
            	1234, 96,
            	1237, 104,
            	1237, 112,
            	1237, 120,
            	1240, 128,
            	1243, 136,
            	1243, 144,
            	1246, 152,
            	1249, 160,
            	1261, 184,
            	1288, 200,
            	1288, 208,
            1, 8, 1, /* 996: pointer.struct.rsa_meth_st */
            	1001, 0,
            0, 112, 13, /* 1001: struct.rsa_meth_st */
            	102, 0,
            	1030, 8,
            	1030, 16,
            	1030, 24,
            	1030, 32,
            	1033, 40,
            	1036, 48,
            	1039, 56,
            	1039, 64,
            	26, 80,
            	1042, 88,
            	1045, 96,
            	1048, 104,
            8884097, 8, 0, /* 1030: pointer.func */
            8884097, 8, 0, /* 1033: pointer.func */
            8884097, 8, 0, /* 1036: pointer.func */
            8884097, 8, 0, /* 1039: pointer.func */
            8884097, 8, 0, /* 1042: pointer.func */
            8884097, 8, 0, /* 1045: pointer.func */
            8884097, 8, 0, /* 1048: pointer.func */
            1, 8, 1, /* 1051: pointer.struct.dsa_method */
            	1056, 0,
            0, 96, 11, /* 1056: struct.dsa_method */
            	102, 0,
            	1081, 8,
            	1084, 16,
            	1087, 24,
            	1090, 32,
            	1093, 40,
            	1096, 48,
            	1096, 56,
            	26, 72,
            	1099, 80,
            	1096, 88,
            8884097, 8, 0, /* 1081: pointer.func */
            8884097, 8, 0, /* 1084: pointer.func */
            8884097, 8, 0, /* 1087: pointer.func */
            8884097, 8, 0, /* 1090: pointer.func */
            8884097, 8, 0, /* 1093: pointer.func */
            8884097, 8, 0, /* 1096: pointer.func */
            8884097, 8, 0, /* 1099: pointer.func */
            1, 8, 1, /* 1102: pointer.struct.dh_method */
            	1107, 0,
            0, 72, 8, /* 1107: struct.dh_method */
            	102, 0,
            	1126, 8,
            	1129, 16,
            	1132, 24,
            	1126, 32,
            	1126, 40,
            	26, 56,
            	1135, 64,
            8884097, 8, 0, /* 1126: pointer.func */
            8884097, 8, 0, /* 1129: pointer.func */
            8884097, 8, 0, /* 1132: pointer.func */
            8884097, 8, 0, /* 1135: pointer.func */
            1, 8, 1, /* 1138: pointer.struct.ecdh_method */
            	1143, 0,
            0, 32, 3, /* 1143: struct.ecdh_method */
            	102, 0,
            	1152, 8,
            	26, 24,
            8884097, 8, 0, /* 1152: pointer.func */
            1, 8, 1, /* 1155: pointer.struct.ecdsa_method */
            	1160, 0,
            0, 48, 5, /* 1160: struct.ecdsa_method */
            	102, 0,
            	1173, 8,
            	1176, 16,
            	1179, 24,
            	26, 40,
            8884097, 8, 0, /* 1173: pointer.func */
            8884097, 8, 0, /* 1176: pointer.func */
            8884097, 8, 0, /* 1179: pointer.func */
            1, 8, 1, /* 1182: pointer.struct.rand_meth_st */
            	1187, 0,
            0, 48, 6, /* 1187: struct.rand_meth_st */
            	1202, 0,
            	1205, 8,
            	1208, 16,
            	1211, 24,
            	1205, 32,
            	1214, 40,
            8884097, 8, 0, /* 1202: pointer.func */
            8884097, 8, 0, /* 1205: pointer.func */
            8884097, 8, 0, /* 1208: pointer.func */
            8884097, 8, 0, /* 1211: pointer.func */
            8884097, 8, 0, /* 1214: pointer.func */
            1, 8, 1, /* 1217: pointer.struct.store_method_st */
            	1222, 0,
            0, 0, 0, /* 1222: struct.store_method_st */
            8884097, 8, 0, /* 1225: pointer.func */
            8884097, 8, 0, /* 1228: pointer.func */
            8884097, 8, 0, /* 1231: pointer.func */
            8884097, 8, 0, /* 1234: pointer.func */
            8884097, 8, 0, /* 1237: pointer.func */
            8884097, 8, 0, /* 1240: pointer.func */
            8884097, 8, 0, /* 1243: pointer.func */
            8884097, 8, 0, /* 1246: pointer.func */
            1, 8, 1, /* 1249: pointer.struct.ENGINE_CMD_DEFN_st */
            	1254, 0,
            0, 32, 2, /* 1254: struct.ENGINE_CMD_DEFN_st */
            	102, 8,
            	102, 16,
            0, 16, 1, /* 1261: struct.crypto_ex_data_st */
            	1266, 0,
            1, 8, 1, /* 1266: pointer.struct.stack_st_void */
            	1271, 0,
            0, 32, 1, /* 1271: struct.stack_st_void */
            	1276, 0,
            0, 32, 2, /* 1276: struct.stack_st */
            	1283, 8,
            	125, 24,
            1, 8, 1, /* 1283: pointer.pointer.char */
            	26, 0,
            1, 8, 1, /* 1288: pointer.struct.engine_st */
            	945, 0,
            0, 8, 5, /* 1293: union.unknown */
            	26, 0,
            	1306, 0,
            	1508, 0,
            	1635, 0,
            	1749, 0,
            1, 8, 1, /* 1306: pointer.struct.rsa_st */
            	1311, 0,
            0, 168, 17, /* 1311: struct.rsa_st */
            	1348, 16,
            	1403, 24,
            	1408, 32,
            	1408, 40,
            	1408, 48,
            	1408, 56,
            	1408, 64,
            	1408, 72,
            	1408, 80,
            	1408, 88,
            	1418, 96,
            	1440, 120,
            	1440, 128,
            	1440, 136,
            	26, 144,
            	1454, 152,
            	1454, 160,
            1, 8, 1, /* 1348: pointer.struct.rsa_meth_st */
            	1353, 0,
            0, 112, 13, /* 1353: struct.rsa_meth_st */
            	102, 0,
            	1382, 8,
            	1382, 16,
            	1382, 24,
            	1382, 32,
            	1385, 40,
            	1388, 48,
            	1391, 56,
            	1391, 64,
            	26, 80,
            	1394, 88,
            	1397, 96,
            	1400, 104,
            8884097, 8, 0, /* 1382: pointer.func */
            8884097, 8, 0, /* 1385: pointer.func */
            8884097, 8, 0, /* 1388: pointer.func */
            8884097, 8, 0, /* 1391: pointer.func */
            8884097, 8, 0, /* 1394: pointer.func */
            8884097, 8, 0, /* 1397: pointer.func */
            8884097, 8, 0, /* 1400: pointer.func */
            1, 8, 1, /* 1403: pointer.struct.engine_st */
            	945, 0,
            1, 8, 1, /* 1408: pointer.struct.bignum_st */
            	1413, 0,
            0, 24, 1, /* 1413: struct.bignum_st */
            	164, 0,
            0, 16, 1, /* 1418: struct.crypto_ex_data_st */
            	1423, 0,
            1, 8, 1, /* 1423: pointer.struct.stack_st_void */
            	1428, 0,
            0, 32, 1, /* 1428: struct.stack_st_void */
            	1433, 0,
            0, 32, 2, /* 1433: struct.stack_st */
            	1283, 8,
            	125, 24,
            1, 8, 1, /* 1440: pointer.struct.bn_mont_ctx_st */
            	1445, 0,
            0, 96, 3, /* 1445: struct.bn_mont_ctx_st */
            	1413, 8,
            	1413, 32,
            	1413, 56,
            1, 8, 1, /* 1454: pointer.struct.bn_blinding_st */
            	1459, 0,
            0, 88, 7, /* 1459: struct.bn_blinding_st */
            	1476, 0,
            	1476, 8,
            	1476, 16,
            	1476, 24,
            	1486, 40,
            	1491, 72,
            	1505, 80,
            1, 8, 1, /* 1476: pointer.struct.bignum_st */
            	1481, 0,
            0, 24, 1, /* 1481: struct.bignum_st */
            	164, 0,
            0, 16, 1, /* 1486: struct.crypto_threadid_st */
            	5, 0,
            1, 8, 1, /* 1491: pointer.struct.bn_mont_ctx_st */
            	1496, 0,
            0, 96, 3, /* 1496: struct.bn_mont_ctx_st */
            	1481, 8,
            	1481, 32,
            	1481, 56,
            8884097, 8, 0, /* 1505: pointer.func */
            1, 8, 1, /* 1508: pointer.struct.dsa_st */
            	1513, 0,
            0, 136, 11, /* 1513: struct.dsa_st */
            	1538, 24,
            	1538, 32,
            	1538, 40,
            	1538, 48,
            	1538, 56,
            	1538, 64,
            	1538, 72,
            	1548, 88,
            	1562, 104,
            	1584, 120,
            	940, 128,
            1, 8, 1, /* 1538: pointer.struct.bignum_st */
            	1543, 0,
            0, 24, 1, /* 1543: struct.bignum_st */
            	164, 0,
            1, 8, 1, /* 1548: pointer.struct.bn_mont_ctx_st */
            	1553, 0,
            0, 96, 3, /* 1553: struct.bn_mont_ctx_st */
            	1543, 8,
            	1543, 32,
            	1543, 56,
            0, 16, 1, /* 1562: struct.crypto_ex_data_st */
            	1567, 0,
            1, 8, 1, /* 1567: pointer.struct.stack_st_void */
            	1572, 0,
            0, 32, 1, /* 1572: struct.stack_st_void */
            	1577, 0,
            0, 32, 2, /* 1577: struct.stack_st */
            	1283, 8,
            	125, 24,
            1, 8, 1, /* 1584: pointer.struct.dsa_method */
            	1589, 0,
            0, 96, 11, /* 1589: struct.dsa_method */
            	102, 0,
            	1614, 8,
            	1617, 16,
            	1620, 24,
            	1623, 32,
            	1626, 40,
            	1629, 48,
            	1629, 56,
            	26, 72,
            	1632, 80,
            	1629, 88,
            8884097, 8, 0, /* 1614: pointer.func */
            8884097, 8, 0, /* 1617: pointer.func */
            8884097, 8, 0, /* 1620: pointer.func */
            8884097, 8, 0, /* 1623: pointer.func */
            8884097, 8, 0, /* 1626: pointer.func */
            8884097, 8, 0, /* 1629: pointer.func */
            8884097, 8, 0, /* 1632: pointer.func */
            1, 8, 1, /* 1635: pointer.struct.dh_st */
            	1640, 0,
            0, 144, 12, /* 1640: struct.dh_st */
            	1667, 8,
            	1667, 16,
            	1667, 32,
            	1667, 40,
            	1677, 56,
            	1667, 64,
            	1667, 72,
            	13, 80,
            	1667, 96,
            	1691, 112,
            	1713, 128,
            	1403, 136,
            1, 8, 1, /* 1667: pointer.struct.bignum_st */
            	1672, 0,
            0, 24, 1, /* 1672: struct.bignum_st */
            	164, 0,
            1, 8, 1, /* 1677: pointer.struct.bn_mont_ctx_st */
            	1682, 0,
            0, 96, 3, /* 1682: struct.bn_mont_ctx_st */
            	1672, 8,
            	1672, 32,
            	1672, 56,
            0, 16, 1, /* 1691: struct.crypto_ex_data_st */
            	1696, 0,
            1, 8, 1, /* 1696: pointer.struct.stack_st_void */
            	1701, 0,
            0, 32, 1, /* 1701: struct.stack_st_void */
            	1706, 0,
            0, 32, 2, /* 1706: struct.stack_st */
            	1283, 8,
            	125, 24,
            1, 8, 1, /* 1713: pointer.struct.dh_method */
            	1718, 0,
            0, 72, 8, /* 1718: struct.dh_method */
            	102, 0,
            	1737, 8,
            	1740, 16,
            	1743, 24,
            	1737, 32,
            	1737, 40,
            	26, 56,
            	1746, 64,
            8884097, 8, 0, /* 1737: pointer.func */
            8884097, 8, 0, /* 1740: pointer.func */
            8884097, 8, 0, /* 1743: pointer.func */
            8884097, 8, 0, /* 1746: pointer.func */
            1, 8, 1, /* 1749: pointer.struct.ec_key_st */
            	1754, 0,
            0, 56, 4, /* 1754: struct.ec_key_st */
            	1765, 8,
            	2199, 16,
            	2204, 24,
            	2214, 48,
            1, 8, 1, /* 1765: pointer.struct.ec_group_st */
            	1770, 0,
            0, 232, 12, /* 1770: struct.ec_group_st */
            	1797, 0,
            	1969, 8,
            	2162, 16,
            	2162, 40,
            	13, 80,
            	2167, 96,
            	2162, 104,
            	2162, 152,
            	2162, 176,
            	5, 208,
            	5, 216,
            	2196, 224,
            1, 8, 1, /* 1797: pointer.struct.ec_method_st */
            	1802, 0,
            0, 304, 37, /* 1802: struct.ec_method_st */
            	1879, 8,
            	1882, 16,
            	1882, 24,
            	1885, 32,
            	1888, 40,
            	1891, 48,
            	1894, 56,
            	1897, 64,
            	1900, 72,
            	1903, 80,
            	1903, 88,
            	1906, 96,
            	1909, 104,
            	1912, 112,
            	1915, 120,
            	1918, 128,
            	1921, 136,
            	1924, 144,
            	1927, 152,
            	1930, 160,
            	1933, 168,
            	1936, 176,
            	1939, 184,
            	1942, 192,
            	1945, 200,
            	1948, 208,
            	1939, 216,
            	1951, 224,
            	1954, 232,
            	1957, 240,
            	1894, 248,
            	1960, 256,
            	1963, 264,
            	1960, 272,
            	1963, 280,
            	1963, 288,
            	1966, 296,
            8884097, 8, 0, /* 1879: pointer.func */
            8884097, 8, 0, /* 1882: pointer.func */
            8884097, 8, 0, /* 1885: pointer.func */
            8884097, 8, 0, /* 1888: pointer.func */
            8884097, 8, 0, /* 1891: pointer.func */
            8884097, 8, 0, /* 1894: pointer.func */
            8884097, 8, 0, /* 1897: pointer.func */
            8884097, 8, 0, /* 1900: pointer.func */
            8884097, 8, 0, /* 1903: pointer.func */
            8884097, 8, 0, /* 1906: pointer.func */
            8884097, 8, 0, /* 1909: pointer.func */
            8884097, 8, 0, /* 1912: pointer.func */
            8884097, 8, 0, /* 1915: pointer.func */
            8884097, 8, 0, /* 1918: pointer.func */
            8884097, 8, 0, /* 1921: pointer.func */
            8884097, 8, 0, /* 1924: pointer.func */
            8884097, 8, 0, /* 1927: pointer.func */
            8884097, 8, 0, /* 1930: pointer.func */
            8884097, 8, 0, /* 1933: pointer.func */
            8884097, 8, 0, /* 1936: pointer.func */
            8884097, 8, 0, /* 1939: pointer.func */
            8884097, 8, 0, /* 1942: pointer.func */
            8884097, 8, 0, /* 1945: pointer.func */
            8884097, 8, 0, /* 1948: pointer.func */
            8884097, 8, 0, /* 1951: pointer.func */
            8884097, 8, 0, /* 1954: pointer.func */
            8884097, 8, 0, /* 1957: pointer.func */
            8884097, 8, 0, /* 1960: pointer.func */
            8884097, 8, 0, /* 1963: pointer.func */
            8884097, 8, 0, /* 1966: pointer.func */
            1, 8, 1, /* 1969: pointer.struct.ec_point_st */
            	1974, 0,
            0, 88, 4, /* 1974: struct.ec_point_st */
            	1985, 0,
            	2157, 8,
            	2157, 32,
            	2157, 56,
            1, 8, 1, /* 1985: pointer.struct.ec_method_st */
            	1990, 0,
            0, 304, 37, /* 1990: struct.ec_method_st */
            	2067, 8,
            	2070, 16,
            	2070, 24,
            	2073, 32,
            	2076, 40,
            	2079, 48,
            	2082, 56,
            	2085, 64,
            	2088, 72,
            	2091, 80,
            	2091, 88,
            	2094, 96,
            	2097, 104,
            	2100, 112,
            	2103, 120,
            	2106, 128,
            	2109, 136,
            	2112, 144,
            	2115, 152,
            	2118, 160,
            	2121, 168,
            	2124, 176,
            	2127, 184,
            	2130, 192,
            	2133, 200,
            	2136, 208,
            	2127, 216,
            	2139, 224,
            	2142, 232,
            	2145, 240,
            	2082, 248,
            	2148, 256,
            	2151, 264,
            	2148, 272,
            	2151, 280,
            	2151, 288,
            	2154, 296,
            8884097, 8, 0, /* 2067: pointer.func */
            8884097, 8, 0, /* 2070: pointer.func */
            8884097, 8, 0, /* 2073: pointer.func */
            8884097, 8, 0, /* 2076: pointer.func */
            8884097, 8, 0, /* 2079: pointer.func */
            8884097, 8, 0, /* 2082: pointer.func */
            8884097, 8, 0, /* 2085: pointer.func */
            8884097, 8, 0, /* 2088: pointer.func */
            8884097, 8, 0, /* 2091: pointer.func */
            8884097, 8, 0, /* 2094: pointer.func */
            8884097, 8, 0, /* 2097: pointer.func */
            8884097, 8, 0, /* 2100: pointer.func */
            8884097, 8, 0, /* 2103: pointer.func */
            8884097, 8, 0, /* 2106: pointer.func */
            8884097, 8, 0, /* 2109: pointer.func */
            8884097, 8, 0, /* 2112: pointer.func */
            8884097, 8, 0, /* 2115: pointer.func */
            8884097, 8, 0, /* 2118: pointer.func */
            8884097, 8, 0, /* 2121: pointer.func */
            8884097, 8, 0, /* 2124: pointer.func */
            8884097, 8, 0, /* 2127: pointer.func */
            8884097, 8, 0, /* 2130: pointer.func */
            8884097, 8, 0, /* 2133: pointer.func */
            8884097, 8, 0, /* 2136: pointer.func */
            8884097, 8, 0, /* 2139: pointer.func */
            8884097, 8, 0, /* 2142: pointer.func */
            8884097, 8, 0, /* 2145: pointer.func */
            8884097, 8, 0, /* 2148: pointer.func */
            8884097, 8, 0, /* 2151: pointer.func */
            8884097, 8, 0, /* 2154: pointer.func */
            0, 24, 1, /* 2157: struct.bignum_st */
            	164, 0,
            0, 24, 1, /* 2162: struct.bignum_st */
            	164, 0,
            1, 8, 1, /* 2167: pointer.struct.ec_extra_data_st */
            	2172, 0,
            0, 40, 5, /* 2172: struct.ec_extra_data_st */
            	2185, 0,
            	5, 8,
            	2190, 16,
            	2193, 24,
            	2193, 32,
            1, 8, 1, /* 2185: pointer.struct.ec_extra_data_st */
            	2172, 0,
            8884097, 8, 0, /* 2190: pointer.func */
            8884097, 8, 0, /* 2193: pointer.func */
            8884097, 8, 0, /* 2196: pointer.func */
            1, 8, 1, /* 2199: pointer.struct.ec_point_st */
            	1974, 0,
            1, 8, 1, /* 2204: pointer.struct.bignum_st */
            	2209, 0,
            0, 24, 1, /* 2209: struct.bignum_st */
            	164, 0,
            1, 8, 1, /* 2214: pointer.struct.ec_extra_data_st */
            	2219, 0,
            0, 40, 5, /* 2219: struct.ec_extra_data_st */
            	2232, 0,
            	5, 8,
            	2190, 16,
            	2193, 24,
            	2193, 32,
            1, 8, 1, /* 2232: pointer.struct.ec_extra_data_st */
            	2219, 0,
            1, 8, 1, /* 2237: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2242, 0,
            0, 32, 2, /* 2242: struct.stack_st_fake_X509_ATTRIBUTE */
            	2249, 8,
            	125, 24,
            8884099, 8, 2, /* 2249: pointer_to_array_of_pointers_to_stack */
            	2256, 0,
            	122, 20,
            0, 8, 1, /* 2256: pointer.X509_ATTRIBUTE */
            	2261, 0,
            0, 0, 1, /* 2261: X509_ATTRIBUTE */
            	2266, 0,
            0, 24, 2, /* 2266: struct.x509_attributes_st */
            	2273, 0,
            	2287, 16,
            1, 8, 1, /* 2273: pointer.struct.asn1_object_st */
            	2278, 0,
            0, 40, 3, /* 2278: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            0, 8, 3, /* 2287: union.unknown */
            	26, 0,
            	2296, 0,
            	2475, 0,
            1, 8, 1, /* 2296: pointer.struct.stack_st_ASN1_TYPE */
            	2301, 0,
            0, 32, 2, /* 2301: struct.stack_st_fake_ASN1_TYPE */
            	2308, 8,
            	125, 24,
            8884099, 8, 2, /* 2308: pointer_to_array_of_pointers_to_stack */
            	2315, 0,
            	122, 20,
            0, 8, 1, /* 2315: pointer.ASN1_TYPE */
            	2320, 0,
            0, 0, 1, /* 2320: ASN1_TYPE */
            	2325, 0,
            0, 16, 1, /* 2325: struct.asn1_type_st */
            	2330, 8,
            0, 8, 20, /* 2330: union.unknown */
            	26, 0,
            	2373, 0,
            	2383, 0,
            	2397, 0,
            	2402, 0,
            	2407, 0,
            	2412, 0,
            	2417, 0,
            	2422, 0,
            	2427, 0,
            	2432, 0,
            	2437, 0,
            	2442, 0,
            	2447, 0,
            	2452, 0,
            	2457, 0,
            	2462, 0,
            	2373, 0,
            	2373, 0,
            	2467, 0,
            1, 8, 1, /* 2373: pointer.struct.asn1_string_st */
            	2378, 0,
            0, 24, 1, /* 2378: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 2383: pointer.struct.asn1_object_st */
            	2388, 0,
            0, 40, 3, /* 2388: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 2397: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2402: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2407: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2412: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2417: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2422: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2427: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2432: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2437: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2442: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2447: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2452: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2457: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2462: pointer.struct.asn1_string_st */
            	2378, 0,
            1, 8, 1, /* 2467: pointer.struct.ASN1_VALUE_st */
            	2472, 0,
            0, 0, 0, /* 2472: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2475: pointer.struct.asn1_type_st */
            	2480, 0,
            0, 16, 1, /* 2480: struct.asn1_type_st */
            	2485, 8,
            0, 8, 20, /* 2485: union.unknown */
            	26, 0,
            	2528, 0,
            	2273, 0,
            	2538, 0,
            	2543, 0,
            	2548, 0,
            	2553, 0,
            	2558, 0,
            	2563, 0,
            	2568, 0,
            	2573, 0,
            	2578, 0,
            	2583, 0,
            	2588, 0,
            	2593, 0,
            	2598, 0,
            	2603, 0,
            	2528, 0,
            	2528, 0,
            	2608, 0,
            1, 8, 1, /* 2528: pointer.struct.asn1_string_st */
            	2533, 0,
            0, 24, 1, /* 2533: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 2538: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2543: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2548: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2553: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2558: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2563: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2568: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2573: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2578: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2583: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2588: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2593: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2598: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2603: pointer.struct.asn1_string_st */
            	2533, 0,
            1, 8, 1, /* 2608: pointer.struct.ASN1_VALUE_st */
            	2613, 0,
            0, 0, 0, /* 2613: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2616: pointer.struct.asn1_string_st */
            	557, 0,
            1, 8, 1, /* 2621: pointer.struct.stack_st_X509_EXTENSION */
            	2626, 0,
            0, 32, 2, /* 2626: struct.stack_st_fake_X509_EXTENSION */
            	2633, 8,
            	125, 24,
            8884099, 8, 2, /* 2633: pointer_to_array_of_pointers_to_stack */
            	2640, 0,
            	122, 20,
            0, 8, 1, /* 2640: pointer.X509_EXTENSION */
            	2645, 0,
            0, 0, 1, /* 2645: X509_EXTENSION */
            	2650, 0,
            0, 24, 2, /* 2650: struct.X509_extension_st */
            	2657, 0,
            	2671, 16,
            1, 8, 1, /* 2657: pointer.struct.asn1_object_st */
            	2662, 0,
            0, 40, 3, /* 2662: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 2671: pointer.struct.asn1_string_st */
            	2676, 0,
            0, 24, 1, /* 2676: struct.asn1_string_st */
            	13, 8,
            0, 24, 1, /* 2681: struct.ASN1_ENCODING_st */
            	13, 0,
            0, 16, 1, /* 2686: struct.crypto_ex_data_st */
            	2691, 0,
            1, 8, 1, /* 2691: pointer.struct.stack_st_void */
            	2696, 0,
            0, 32, 1, /* 2696: struct.stack_st_void */
            	2701, 0,
            0, 32, 2, /* 2701: struct.stack_st */
            	1283, 8,
            	125, 24,
            1, 8, 1, /* 2708: pointer.struct.asn1_string_st */
            	557, 0,
            1, 8, 1, /* 2713: pointer.struct.AUTHORITY_KEYID_st */
            	2718, 0,
            0, 24, 3, /* 2718: struct.AUTHORITY_KEYID_st */
            	2727, 0,
            	2737, 8,
            	3031, 16,
            1, 8, 1, /* 2727: pointer.struct.asn1_string_st */
            	2732, 0,
            0, 24, 1, /* 2732: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 2737: pointer.struct.stack_st_GENERAL_NAME */
            	2742, 0,
            0, 32, 2, /* 2742: struct.stack_st_fake_GENERAL_NAME */
            	2749, 8,
            	125, 24,
            8884099, 8, 2, /* 2749: pointer_to_array_of_pointers_to_stack */
            	2756, 0,
            	122, 20,
            0, 8, 1, /* 2756: pointer.GENERAL_NAME */
            	2761, 0,
            0, 0, 1, /* 2761: GENERAL_NAME */
            	2766, 0,
            0, 16, 1, /* 2766: struct.GENERAL_NAME_st */
            	2771, 8,
            0, 8, 15, /* 2771: union.unknown */
            	26, 0,
            	2804, 0,
            	2923, 0,
            	2923, 0,
            	2830, 0,
            	2971, 0,
            	3019, 0,
            	2923, 0,
            	2908, 0,
            	2816, 0,
            	2908, 0,
            	2971, 0,
            	2923, 0,
            	2816, 0,
            	2830, 0,
            1, 8, 1, /* 2804: pointer.struct.otherName_st */
            	2809, 0,
            0, 16, 2, /* 2809: struct.otherName_st */
            	2816, 0,
            	2830, 8,
            1, 8, 1, /* 2816: pointer.struct.asn1_object_st */
            	2821, 0,
            0, 40, 3, /* 2821: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 2830: pointer.struct.asn1_type_st */
            	2835, 0,
            0, 16, 1, /* 2835: struct.asn1_type_st */
            	2840, 8,
            0, 8, 20, /* 2840: union.unknown */
            	26, 0,
            	2883, 0,
            	2816, 0,
            	2893, 0,
            	2898, 0,
            	2903, 0,
            	2908, 0,
            	2913, 0,
            	2918, 0,
            	2923, 0,
            	2928, 0,
            	2933, 0,
            	2938, 0,
            	2943, 0,
            	2948, 0,
            	2953, 0,
            	2958, 0,
            	2883, 0,
            	2883, 0,
            	2963, 0,
            1, 8, 1, /* 2883: pointer.struct.asn1_string_st */
            	2888, 0,
            0, 24, 1, /* 2888: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 2893: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2898: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2903: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2908: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2913: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2918: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2923: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2928: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2933: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2938: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2943: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2948: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2953: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2958: pointer.struct.asn1_string_st */
            	2888, 0,
            1, 8, 1, /* 2963: pointer.struct.ASN1_VALUE_st */
            	2968, 0,
            0, 0, 0, /* 2968: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2971: pointer.struct.X509_name_st */
            	2976, 0,
            0, 40, 3, /* 2976: struct.X509_name_st */
            	2985, 0,
            	3009, 16,
            	13, 24,
            1, 8, 1, /* 2985: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2990, 0,
            0, 32, 2, /* 2990: struct.stack_st_fake_X509_NAME_ENTRY */
            	2997, 8,
            	125, 24,
            8884099, 8, 2, /* 2997: pointer_to_array_of_pointers_to_stack */
            	3004, 0,
            	122, 20,
            0, 8, 1, /* 3004: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 3009: pointer.struct.buf_mem_st */
            	3014, 0,
            0, 24, 1, /* 3014: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 3019: pointer.struct.EDIPartyName_st */
            	3024, 0,
            0, 16, 2, /* 3024: struct.EDIPartyName_st */
            	2883, 0,
            	2883, 8,
            1, 8, 1, /* 3031: pointer.struct.asn1_string_st */
            	2732, 0,
            1, 8, 1, /* 3036: pointer.struct.X509_POLICY_CACHE_st */
            	3041, 0,
            0, 40, 2, /* 3041: struct.X509_POLICY_CACHE_st */
            	3048, 0,
            	3372, 8,
            1, 8, 1, /* 3048: pointer.struct.X509_POLICY_DATA_st */
            	3053, 0,
            0, 32, 3, /* 3053: struct.X509_POLICY_DATA_st */
            	3062, 8,
            	3076, 16,
            	3334, 24,
            1, 8, 1, /* 3062: pointer.struct.asn1_object_st */
            	3067, 0,
            0, 40, 3, /* 3067: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 3076: pointer.struct.stack_st_POLICYQUALINFO */
            	3081, 0,
            0, 32, 2, /* 3081: struct.stack_st_fake_POLICYQUALINFO */
            	3088, 8,
            	125, 24,
            8884099, 8, 2, /* 3088: pointer_to_array_of_pointers_to_stack */
            	3095, 0,
            	122, 20,
            0, 8, 1, /* 3095: pointer.POLICYQUALINFO */
            	3100, 0,
            0, 0, 1, /* 3100: POLICYQUALINFO */
            	3105, 0,
            0, 16, 2, /* 3105: struct.POLICYQUALINFO_st */
            	3112, 0,
            	3126, 8,
            1, 8, 1, /* 3112: pointer.struct.asn1_object_st */
            	3117, 0,
            0, 40, 3, /* 3117: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            0, 8, 3, /* 3126: union.unknown */
            	3135, 0,
            	3145, 0,
            	3208, 0,
            1, 8, 1, /* 3135: pointer.struct.asn1_string_st */
            	3140, 0,
            0, 24, 1, /* 3140: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 3145: pointer.struct.USERNOTICE_st */
            	3150, 0,
            0, 16, 2, /* 3150: struct.USERNOTICE_st */
            	3157, 0,
            	3169, 8,
            1, 8, 1, /* 3157: pointer.struct.NOTICEREF_st */
            	3162, 0,
            0, 16, 2, /* 3162: struct.NOTICEREF_st */
            	3169, 0,
            	3174, 8,
            1, 8, 1, /* 3169: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3174: pointer.struct.stack_st_ASN1_INTEGER */
            	3179, 0,
            0, 32, 2, /* 3179: struct.stack_st_fake_ASN1_INTEGER */
            	3186, 8,
            	125, 24,
            8884099, 8, 2, /* 3186: pointer_to_array_of_pointers_to_stack */
            	3193, 0,
            	122, 20,
            0, 8, 1, /* 3193: pointer.ASN1_INTEGER */
            	3198, 0,
            0, 0, 1, /* 3198: ASN1_INTEGER */
            	3203, 0,
            0, 24, 1, /* 3203: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 3208: pointer.struct.asn1_type_st */
            	3213, 0,
            0, 16, 1, /* 3213: struct.asn1_type_st */
            	3218, 8,
            0, 8, 20, /* 3218: union.unknown */
            	26, 0,
            	3169, 0,
            	3112, 0,
            	3261, 0,
            	3266, 0,
            	3271, 0,
            	3276, 0,
            	3281, 0,
            	3286, 0,
            	3135, 0,
            	3291, 0,
            	3296, 0,
            	3301, 0,
            	3306, 0,
            	3311, 0,
            	3316, 0,
            	3321, 0,
            	3169, 0,
            	3169, 0,
            	3326, 0,
            1, 8, 1, /* 3261: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3266: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3271: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3276: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3281: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3286: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3291: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3296: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3301: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3306: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3311: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3316: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3321: pointer.struct.asn1_string_st */
            	3140, 0,
            1, 8, 1, /* 3326: pointer.struct.ASN1_VALUE_st */
            	3331, 0,
            0, 0, 0, /* 3331: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3334: pointer.struct.stack_st_ASN1_OBJECT */
            	3339, 0,
            0, 32, 2, /* 3339: struct.stack_st_fake_ASN1_OBJECT */
            	3346, 8,
            	125, 24,
            8884099, 8, 2, /* 3346: pointer_to_array_of_pointers_to_stack */
            	3353, 0,
            	122, 20,
            0, 8, 1, /* 3353: pointer.ASN1_OBJECT */
            	3358, 0,
            0, 0, 1, /* 3358: ASN1_OBJECT */
            	3363, 0,
            0, 40, 3, /* 3363: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 3372: pointer.struct.stack_st_X509_POLICY_DATA */
            	3377, 0,
            0, 32, 2, /* 3377: struct.stack_st_fake_X509_POLICY_DATA */
            	3384, 8,
            	125, 24,
            8884099, 8, 2, /* 3384: pointer_to_array_of_pointers_to_stack */
            	3391, 0,
            	122, 20,
            0, 8, 1, /* 3391: pointer.X509_POLICY_DATA */
            	3396, 0,
            0, 0, 1, /* 3396: X509_POLICY_DATA */
            	3401, 0,
            0, 32, 3, /* 3401: struct.X509_POLICY_DATA_st */
            	3410, 8,
            	3424, 16,
            	3448, 24,
            1, 8, 1, /* 3410: pointer.struct.asn1_object_st */
            	3415, 0,
            0, 40, 3, /* 3415: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 3424: pointer.struct.stack_st_POLICYQUALINFO */
            	3429, 0,
            0, 32, 2, /* 3429: struct.stack_st_fake_POLICYQUALINFO */
            	3436, 8,
            	125, 24,
            8884099, 8, 2, /* 3436: pointer_to_array_of_pointers_to_stack */
            	3443, 0,
            	122, 20,
            0, 8, 1, /* 3443: pointer.POLICYQUALINFO */
            	3100, 0,
            1, 8, 1, /* 3448: pointer.struct.stack_st_ASN1_OBJECT */
            	3453, 0,
            0, 32, 2, /* 3453: struct.stack_st_fake_ASN1_OBJECT */
            	3460, 8,
            	125, 24,
            8884099, 8, 2, /* 3460: pointer_to_array_of_pointers_to_stack */
            	3467, 0,
            	122, 20,
            0, 8, 1, /* 3467: pointer.ASN1_OBJECT */
            	3358, 0,
            1, 8, 1, /* 3472: pointer.struct.stack_st_DIST_POINT */
            	3477, 0,
            0, 32, 2, /* 3477: struct.stack_st_fake_DIST_POINT */
            	3484, 8,
            	125, 24,
            8884099, 8, 2, /* 3484: pointer_to_array_of_pointers_to_stack */
            	3491, 0,
            	122, 20,
            0, 8, 1, /* 3491: pointer.DIST_POINT */
            	3496, 0,
            0, 0, 1, /* 3496: DIST_POINT */
            	3501, 0,
            0, 32, 3, /* 3501: struct.DIST_POINT_st */
            	3510, 0,
            	3601, 8,
            	3529, 16,
            1, 8, 1, /* 3510: pointer.struct.DIST_POINT_NAME_st */
            	3515, 0,
            0, 24, 2, /* 3515: struct.DIST_POINT_NAME_st */
            	3522, 8,
            	3577, 16,
            0, 8, 2, /* 3522: union.unknown */
            	3529, 0,
            	3553, 0,
            1, 8, 1, /* 3529: pointer.struct.stack_st_GENERAL_NAME */
            	3534, 0,
            0, 32, 2, /* 3534: struct.stack_st_fake_GENERAL_NAME */
            	3541, 8,
            	125, 24,
            8884099, 8, 2, /* 3541: pointer_to_array_of_pointers_to_stack */
            	3548, 0,
            	122, 20,
            0, 8, 1, /* 3548: pointer.GENERAL_NAME */
            	2761, 0,
            1, 8, 1, /* 3553: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3558, 0,
            0, 32, 2, /* 3558: struct.stack_st_fake_X509_NAME_ENTRY */
            	3565, 8,
            	125, 24,
            8884099, 8, 2, /* 3565: pointer_to_array_of_pointers_to_stack */
            	3572, 0,
            	122, 20,
            0, 8, 1, /* 3572: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 3577: pointer.struct.X509_name_st */
            	3582, 0,
            0, 40, 3, /* 3582: struct.X509_name_st */
            	3553, 0,
            	3591, 16,
            	13, 24,
            1, 8, 1, /* 3591: pointer.struct.buf_mem_st */
            	3596, 0,
            0, 24, 1, /* 3596: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 3601: pointer.struct.asn1_string_st */
            	3606, 0,
            0, 24, 1, /* 3606: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 3611: pointer.struct.stack_st_GENERAL_NAME */
            	3616, 0,
            0, 32, 2, /* 3616: struct.stack_st_fake_GENERAL_NAME */
            	3623, 8,
            	125, 24,
            8884099, 8, 2, /* 3623: pointer_to_array_of_pointers_to_stack */
            	3630, 0,
            	122, 20,
            0, 8, 1, /* 3630: pointer.GENERAL_NAME */
            	2761, 0,
            1, 8, 1, /* 3635: pointer.struct.NAME_CONSTRAINTS_st */
            	3640, 0,
            0, 16, 2, /* 3640: struct.NAME_CONSTRAINTS_st */
            	3647, 0,
            	3647, 8,
            1, 8, 1, /* 3647: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3652, 0,
            0, 32, 2, /* 3652: struct.stack_st_fake_GENERAL_SUBTREE */
            	3659, 8,
            	125, 24,
            8884099, 8, 2, /* 3659: pointer_to_array_of_pointers_to_stack */
            	3666, 0,
            	122, 20,
            0, 8, 1, /* 3666: pointer.GENERAL_SUBTREE */
            	3671, 0,
            0, 0, 1, /* 3671: GENERAL_SUBTREE */
            	3676, 0,
            0, 24, 3, /* 3676: struct.GENERAL_SUBTREE_st */
            	3685, 0,
            	3817, 8,
            	3817, 16,
            1, 8, 1, /* 3685: pointer.struct.GENERAL_NAME_st */
            	3690, 0,
            0, 16, 1, /* 3690: struct.GENERAL_NAME_st */
            	3695, 8,
            0, 8, 15, /* 3695: union.unknown */
            	26, 0,
            	3728, 0,
            	3847, 0,
            	3847, 0,
            	3754, 0,
            	3887, 0,
            	3935, 0,
            	3847, 0,
            	3832, 0,
            	3740, 0,
            	3832, 0,
            	3887, 0,
            	3847, 0,
            	3740, 0,
            	3754, 0,
            1, 8, 1, /* 3728: pointer.struct.otherName_st */
            	3733, 0,
            0, 16, 2, /* 3733: struct.otherName_st */
            	3740, 0,
            	3754, 8,
            1, 8, 1, /* 3740: pointer.struct.asn1_object_st */
            	3745, 0,
            0, 40, 3, /* 3745: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 3754: pointer.struct.asn1_type_st */
            	3759, 0,
            0, 16, 1, /* 3759: struct.asn1_type_st */
            	3764, 8,
            0, 8, 20, /* 3764: union.unknown */
            	26, 0,
            	3807, 0,
            	3740, 0,
            	3817, 0,
            	3822, 0,
            	3827, 0,
            	3832, 0,
            	3837, 0,
            	3842, 0,
            	3847, 0,
            	3852, 0,
            	3857, 0,
            	3862, 0,
            	3867, 0,
            	3872, 0,
            	3877, 0,
            	3882, 0,
            	3807, 0,
            	3807, 0,
            	3326, 0,
            1, 8, 1, /* 3807: pointer.struct.asn1_string_st */
            	3812, 0,
            0, 24, 1, /* 3812: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 3817: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3822: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3827: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3832: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3837: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3842: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3847: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3852: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3857: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3862: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3867: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3872: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3877: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3882: pointer.struct.asn1_string_st */
            	3812, 0,
            1, 8, 1, /* 3887: pointer.struct.X509_name_st */
            	3892, 0,
            0, 40, 3, /* 3892: struct.X509_name_st */
            	3901, 0,
            	3925, 16,
            	13, 24,
            1, 8, 1, /* 3901: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3906, 0,
            0, 32, 2, /* 3906: struct.stack_st_fake_X509_NAME_ENTRY */
            	3913, 8,
            	125, 24,
            8884099, 8, 2, /* 3913: pointer_to_array_of_pointers_to_stack */
            	3920, 0,
            	122, 20,
            0, 8, 1, /* 3920: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 3925: pointer.struct.buf_mem_st */
            	3930, 0,
            0, 24, 1, /* 3930: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 3935: pointer.struct.EDIPartyName_st */
            	3940, 0,
            0, 16, 2, /* 3940: struct.EDIPartyName_st */
            	3807, 0,
            	3807, 8,
            1, 8, 1, /* 3947: pointer.struct.x509_cert_aux_st */
            	3952, 0,
            0, 40, 5, /* 3952: struct.x509_cert_aux_st */
            	3965, 0,
            	3965, 8,
            	3989, 16,
            	2708, 24,
            	3994, 32,
            1, 8, 1, /* 3965: pointer.struct.stack_st_ASN1_OBJECT */
            	3970, 0,
            0, 32, 2, /* 3970: struct.stack_st_fake_ASN1_OBJECT */
            	3977, 8,
            	125, 24,
            8884099, 8, 2, /* 3977: pointer_to_array_of_pointers_to_stack */
            	3984, 0,
            	122, 20,
            0, 8, 1, /* 3984: pointer.ASN1_OBJECT */
            	3358, 0,
            1, 8, 1, /* 3989: pointer.struct.asn1_string_st */
            	557, 0,
            1, 8, 1, /* 3994: pointer.struct.stack_st_X509_ALGOR */
            	3999, 0,
            0, 32, 2, /* 3999: struct.stack_st_fake_X509_ALGOR */
            	4006, 8,
            	125, 24,
            8884099, 8, 2, /* 4006: pointer_to_array_of_pointers_to_stack */
            	4013, 0,
            	122, 20,
            0, 8, 1, /* 4013: pointer.X509_ALGOR */
            	4018, 0,
            0, 0, 1, /* 4018: X509_ALGOR */
            	567, 0,
            1, 8, 1, /* 4023: pointer.struct.X509_crl_st */
            	4028, 0,
            0, 120, 10, /* 4028: struct.X509_crl_st */
            	4051, 0,
            	562, 8,
            	2616, 16,
            	2713, 32,
            	4178, 40,
            	552, 56,
            	552, 64,
            	4190, 96,
            	4231, 104,
            	5, 112,
            1, 8, 1, /* 4051: pointer.struct.X509_crl_info_st */
            	4056, 0,
            0, 80, 8, /* 4056: struct.X509_crl_info_st */
            	552, 0,
            	562, 8,
            	729, 16,
            	789, 24,
            	789, 32,
            	4075, 40,
            	2621, 48,
            	2681, 56,
            1, 8, 1, /* 4075: pointer.struct.stack_st_X509_REVOKED */
            	4080, 0,
            0, 32, 2, /* 4080: struct.stack_st_fake_X509_REVOKED */
            	4087, 8,
            	125, 24,
            8884099, 8, 2, /* 4087: pointer_to_array_of_pointers_to_stack */
            	4094, 0,
            	122, 20,
            0, 8, 1, /* 4094: pointer.X509_REVOKED */
            	4099, 0,
            0, 0, 1, /* 4099: X509_REVOKED */
            	4104, 0,
            0, 40, 4, /* 4104: struct.x509_revoked_st */
            	4115, 0,
            	4125, 8,
            	4130, 16,
            	4154, 24,
            1, 8, 1, /* 4115: pointer.struct.asn1_string_st */
            	4120, 0,
            0, 24, 1, /* 4120: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 4125: pointer.struct.asn1_string_st */
            	4120, 0,
            1, 8, 1, /* 4130: pointer.struct.stack_st_X509_EXTENSION */
            	4135, 0,
            0, 32, 2, /* 4135: struct.stack_st_fake_X509_EXTENSION */
            	4142, 8,
            	125, 24,
            8884099, 8, 2, /* 4142: pointer_to_array_of_pointers_to_stack */
            	4149, 0,
            	122, 20,
            0, 8, 1, /* 4149: pointer.X509_EXTENSION */
            	2645, 0,
            1, 8, 1, /* 4154: pointer.struct.stack_st_GENERAL_NAME */
            	4159, 0,
            0, 32, 2, /* 4159: struct.stack_st_fake_GENERAL_NAME */
            	4166, 8,
            	125, 24,
            8884099, 8, 2, /* 4166: pointer_to_array_of_pointers_to_stack */
            	4173, 0,
            	122, 20,
            0, 8, 1, /* 4173: pointer.GENERAL_NAME */
            	2761, 0,
            1, 8, 1, /* 4178: pointer.struct.ISSUING_DIST_POINT_st */
            	4183, 0,
            0, 32, 2, /* 4183: struct.ISSUING_DIST_POINT_st */
            	3510, 0,
            	3601, 16,
            1, 8, 1, /* 4190: pointer.struct.stack_st_GENERAL_NAMES */
            	4195, 0,
            0, 32, 2, /* 4195: struct.stack_st_fake_GENERAL_NAMES */
            	4202, 8,
            	125, 24,
            8884099, 8, 2, /* 4202: pointer_to_array_of_pointers_to_stack */
            	4209, 0,
            	122, 20,
            0, 8, 1, /* 4209: pointer.GENERAL_NAMES */
            	4214, 0,
            0, 0, 1, /* 4214: GENERAL_NAMES */
            	4219, 0,
            0, 32, 1, /* 4219: struct.stack_st_GENERAL_NAME */
            	4224, 0,
            0, 32, 2, /* 4224: struct.stack_st */
            	1283, 8,
            	125, 24,
            1, 8, 1, /* 4231: pointer.struct.x509_crl_method_st */
            	4236, 0,
            0, 40, 4, /* 4236: struct.x509_crl_method_st */
            	4247, 8,
            	4247, 16,
            	4250, 24,
            	4253, 32,
            8884097, 8, 0, /* 4247: pointer.func */
            8884097, 8, 0, /* 4250: pointer.func */
            8884097, 8, 0, /* 4253: pointer.func */
            1, 8, 1, /* 4256: pointer.struct.evp_pkey_st */
            	4261, 0,
            0, 56, 4, /* 4261: struct.evp_pkey_st */
            	4272, 16,
            	1403, 24,
            	4277, 32,
            	4310, 48,
            1, 8, 1, /* 4272: pointer.struct.evp_pkey_asn1_method_st */
            	844, 0,
            0, 8, 5, /* 4277: union.unknown */
            	26, 0,
            	4290, 0,
            	4295, 0,
            	4300, 0,
            	4305, 0,
            1, 8, 1, /* 4290: pointer.struct.rsa_st */
            	1311, 0,
            1, 8, 1, /* 4295: pointer.struct.dsa_st */
            	1513, 0,
            1, 8, 1, /* 4300: pointer.struct.dh_st */
            	1640, 0,
            1, 8, 1, /* 4305: pointer.struct.ec_key_st */
            	1754, 0,
            1, 8, 1, /* 4310: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4315, 0,
            0, 32, 2, /* 4315: struct.stack_st_fake_X509_ATTRIBUTE */
            	4322, 8,
            	125, 24,
            8884099, 8, 2, /* 4322: pointer_to_array_of_pointers_to_stack */
            	4329, 0,
            	122, 20,
            0, 8, 1, /* 4329: pointer.X509_ATTRIBUTE */
            	2261, 0,
            1, 8, 1, /* 4334: pointer.struct.stack_st_X509_LOOKUP */
            	4339, 0,
            0, 32, 2, /* 4339: struct.stack_st_fake_X509_LOOKUP */
            	4346, 8,
            	125, 24,
            8884099, 8, 2, /* 4346: pointer_to_array_of_pointers_to_stack */
            	4353, 0,
            	122, 20,
            0, 8, 1, /* 4353: pointer.X509_LOOKUP */
            	344, 0,
            1, 8, 1, /* 4358: pointer.struct.X509_VERIFY_PARAM_st */
            	4363, 0,
            0, 56, 2, /* 4363: struct.X509_VERIFY_PARAM_st */
            	26, 0,
            	3965, 48,
            8884097, 8, 0, /* 4370: pointer.func */
            8884097, 8, 0, /* 4373: pointer.func */
            8884097, 8, 0, /* 4376: pointer.func */
            8884097, 8, 0, /* 4379: pointer.func */
            8884097, 8, 0, /* 4382: pointer.func */
            8884097, 8, 0, /* 4385: pointer.func */
            8884097, 8, 0, /* 4388: pointer.func */
            8884097, 8, 0, /* 4391: pointer.func */
            8884097, 8, 0, /* 4394: pointer.func */
            8884097, 8, 0, /* 4397: pointer.func */
            1, 8, 1, /* 4400: pointer.struct.x509_store_st */
            	4405, 0,
            0, 144, 15, /* 4405: struct.x509_store_st */
            	4438, 8,
            	320, 16,
            	4462, 24,
            	317, 32,
            	4498, 40,
            	4501, 48,
            	4504, 56,
            	317, 64,
            	4507, 72,
            	4397, 80,
            	4510, 88,
            	314, 96,
            	311, 104,
            	317, 112,
            	4513, 120,
            1, 8, 1, /* 4438: pointer.struct.stack_st_X509_OBJECT */
            	4443, 0,
            0, 32, 2, /* 4443: struct.stack_st_fake_X509_OBJECT */
            	4450, 8,
            	125, 24,
            8884099, 8, 2, /* 4450: pointer_to_array_of_pointers_to_stack */
            	4457, 0,
            	122, 20,
            0, 8, 1, /* 4457: pointer.X509_OBJECT */
            	469, 0,
            1, 8, 1, /* 4462: pointer.struct.X509_VERIFY_PARAM_st */
            	4467, 0,
            0, 56, 2, /* 4467: struct.X509_VERIFY_PARAM_st */
            	26, 0,
            	4474, 48,
            1, 8, 1, /* 4474: pointer.struct.stack_st_ASN1_OBJECT */
            	4479, 0,
            0, 32, 2, /* 4479: struct.stack_st_fake_ASN1_OBJECT */
            	4486, 8,
            	125, 24,
            8884099, 8, 2, /* 4486: pointer_to_array_of_pointers_to_stack */
            	4493, 0,
            	122, 20,
            0, 8, 1, /* 4493: pointer.ASN1_OBJECT */
            	3358, 0,
            8884097, 8, 0, /* 4498: pointer.func */
            8884097, 8, 0, /* 4501: pointer.func */
            8884097, 8, 0, /* 4504: pointer.func */
            8884097, 8, 0, /* 4507: pointer.func */
            8884097, 8, 0, /* 4510: pointer.func */
            0, 16, 1, /* 4513: struct.crypto_ex_data_st */
            	4518, 0,
            1, 8, 1, /* 4518: pointer.struct.stack_st_void */
            	4523, 0,
            0, 32, 1, /* 4523: struct.stack_st_void */
            	4528, 0,
            0, 32, 2, /* 4528: struct.stack_st */
            	1283, 8,
            	125, 24,
            0, 736, 50, /* 4535: struct.ssl_ctx_st */
            	4638, 0,
            	4804, 8,
            	4804, 16,
            	4400, 24,
            	4838, 32,
            	4874, 48,
            	4874, 56,
            	5990, 80,
            	308, 88,
            	5993, 96,
            	305, 152,
            	5, 160,
            	5996, 168,
            	5, 176,
            	5999, 184,
            	302, 192,
            	299, 200,
            	4513, 208,
            	6002, 224,
            	6002, 232,
            	6002, 240,
            	6041, 248,
            	229, 256,
            	6065, 264,
            	6068, 272,
            	6097, 304,
            	6538, 320,
            	5, 328,
            	4498, 376,
            	6541, 384,
            	4462, 392,
            	5625, 408,
            	192, 416,
            	5, 424,
            	6544, 480,
            	6547, 488,
            	5, 496,
            	6550, 504,
            	5, 512,
            	26, 520,
            	6553, 528,
            	6556, 536,
            	172, 552,
            	172, 560,
            	6559, 568,
            	151, 696,
            	5, 704,
            	148, 712,
            	5, 720,
            	195, 728,
            1, 8, 1, /* 4638: pointer.struct.ssl_method_st */
            	4643, 0,
            0, 232, 28, /* 4643: struct.ssl_method_st */
            	4702, 8,
            	4705, 16,
            	4705, 24,
            	4702, 32,
            	4702, 40,
            	4708, 48,
            	4708, 56,
            	4711, 64,
            	4702, 72,
            	4702, 80,
            	4702, 88,
            	4714, 96,
            	4717, 104,
            	4720, 112,
            	4702, 120,
            	4723, 128,
            	4726, 136,
            	4729, 144,
            	4732, 152,
            	4735, 160,
            	1214, 168,
            	4738, 176,
            	4741, 184,
            	296, 192,
            	4744, 200,
            	1214, 208,
            	4798, 216,
            	4801, 224,
            8884097, 8, 0, /* 4702: pointer.func */
            8884097, 8, 0, /* 4705: pointer.func */
            8884097, 8, 0, /* 4708: pointer.func */
            8884097, 8, 0, /* 4711: pointer.func */
            8884097, 8, 0, /* 4714: pointer.func */
            8884097, 8, 0, /* 4717: pointer.func */
            8884097, 8, 0, /* 4720: pointer.func */
            8884097, 8, 0, /* 4723: pointer.func */
            8884097, 8, 0, /* 4726: pointer.func */
            8884097, 8, 0, /* 4729: pointer.func */
            8884097, 8, 0, /* 4732: pointer.func */
            8884097, 8, 0, /* 4735: pointer.func */
            8884097, 8, 0, /* 4738: pointer.func */
            8884097, 8, 0, /* 4741: pointer.func */
            1, 8, 1, /* 4744: pointer.struct.ssl3_enc_method */
            	4749, 0,
            0, 112, 11, /* 4749: struct.ssl3_enc_method */
            	4774, 0,
            	4777, 8,
            	4780, 16,
            	4783, 24,
            	4774, 32,
            	4786, 40,
            	4789, 56,
            	102, 64,
            	102, 80,
            	4792, 96,
            	4795, 104,
            8884097, 8, 0, /* 4774: pointer.func */
            8884097, 8, 0, /* 4777: pointer.func */
            8884097, 8, 0, /* 4780: pointer.func */
            8884097, 8, 0, /* 4783: pointer.func */
            8884097, 8, 0, /* 4786: pointer.func */
            8884097, 8, 0, /* 4789: pointer.func */
            8884097, 8, 0, /* 4792: pointer.func */
            8884097, 8, 0, /* 4795: pointer.func */
            8884097, 8, 0, /* 4798: pointer.func */
            8884097, 8, 0, /* 4801: pointer.func */
            1, 8, 1, /* 4804: pointer.struct.stack_st_SSL_CIPHER */
            	4809, 0,
            0, 32, 2, /* 4809: struct.stack_st_fake_SSL_CIPHER */
            	4816, 8,
            	125, 24,
            8884099, 8, 2, /* 4816: pointer_to_array_of_pointers_to_stack */
            	4823, 0,
            	122, 20,
            0, 8, 1, /* 4823: pointer.SSL_CIPHER */
            	4828, 0,
            0, 0, 1, /* 4828: SSL_CIPHER */
            	4833, 0,
            0, 88, 1, /* 4833: struct.ssl_cipher_st */
            	102, 8,
            1, 8, 1, /* 4838: pointer.struct.lhash_st */
            	4843, 0,
            0, 176, 3, /* 4843: struct.lhash_st */
            	4852, 0,
            	125, 8,
            	4871, 16,
            8884099, 8, 2, /* 4852: pointer_to_array_of_pointers_to_stack */
            	4859, 0,
            	169, 28,
            1, 8, 1, /* 4859: pointer.struct.lhash_node_st */
            	4864, 0,
            0, 24, 2, /* 4864: struct.lhash_node_st */
            	5, 0,
            	4859, 8,
            8884097, 8, 0, /* 4871: pointer.func */
            1, 8, 1, /* 4874: pointer.struct.ssl_session_st */
            	4879, 0,
            0, 352, 14, /* 4879: struct.ssl_session_st */
            	26, 144,
            	26, 152,
            	4910, 168,
            	5747, 176,
            	5980, 224,
            	4804, 240,
            	4513, 248,
            	4874, 264,
            	4874, 272,
            	26, 280,
            	13, 296,
            	13, 312,
            	13, 320,
            	26, 344,
            1, 8, 1, /* 4910: pointer.struct.sess_cert_st */
            	4915, 0,
            0, 248, 5, /* 4915: struct.sess_cert_st */
            	4928, 0,
            	5248, 16,
            	5732, 216,
            	5737, 224,
            	5742, 232,
            1, 8, 1, /* 4928: pointer.struct.stack_st_X509 */
            	4933, 0,
            0, 32, 2, /* 4933: struct.stack_st_fake_X509 */
            	4940, 8,
            	125, 24,
            8884099, 8, 2, /* 4940: pointer_to_array_of_pointers_to_stack */
            	4947, 0,
            	122, 20,
            0, 8, 1, /* 4947: pointer.X509 */
            	4952, 0,
            0, 0, 1, /* 4952: X509 */
            	4957, 0,
            0, 184, 12, /* 4957: struct.x509_st */
            	4984, 0,
            	5024, 8,
            	5099, 16,
            	26, 32,
            	1562, 40,
            	5133, 104,
            	5138, 112,
            	5143, 120,
            	5148, 128,
            	4154, 136,
            	5172, 144,
            	5177, 176,
            1, 8, 1, /* 4984: pointer.struct.x509_cinf_st */
            	4989, 0,
            0, 104, 11, /* 4989: struct.x509_cinf_st */
            	5014, 0,
            	5014, 8,
            	5024, 16,
            	5029, 24,
            	5077, 32,
            	5029, 40,
            	5094, 48,
            	5099, 56,
            	5099, 64,
            	5104, 72,
            	5128, 80,
            1, 8, 1, /* 5014: pointer.struct.asn1_string_st */
            	5019, 0,
            0, 24, 1, /* 5019: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 5024: pointer.struct.X509_algor_st */
            	567, 0,
            1, 8, 1, /* 5029: pointer.struct.X509_name_st */
            	5034, 0,
            0, 40, 3, /* 5034: struct.X509_name_st */
            	5043, 0,
            	5067, 16,
            	13, 24,
            1, 8, 1, /* 5043: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5048, 0,
            0, 32, 2, /* 5048: struct.stack_st_fake_X509_NAME_ENTRY */
            	5055, 8,
            	125, 24,
            8884099, 8, 2, /* 5055: pointer_to_array_of_pointers_to_stack */
            	5062, 0,
            	122, 20,
            0, 8, 1, /* 5062: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 5067: pointer.struct.buf_mem_st */
            	5072, 0,
            0, 24, 1, /* 5072: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 5077: pointer.struct.X509_val_st */
            	5082, 0,
            0, 16, 2, /* 5082: struct.X509_val_st */
            	5089, 0,
            	5089, 8,
            1, 8, 1, /* 5089: pointer.struct.asn1_string_st */
            	5019, 0,
            1, 8, 1, /* 5094: pointer.struct.X509_pubkey_st */
            	799, 0,
            1, 8, 1, /* 5099: pointer.struct.asn1_string_st */
            	5019, 0,
            1, 8, 1, /* 5104: pointer.struct.stack_st_X509_EXTENSION */
            	5109, 0,
            0, 32, 2, /* 5109: struct.stack_st_fake_X509_EXTENSION */
            	5116, 8,
            	125, 24,
            8884099, 8, 2, /* 5116: pointer_to_array_of_pointers_to_stack */
            	5123, 0,
            	122, 20,
            0, 8, 1, /* 5123: pointer.X509_EXTENSION */
            	2645, 0,
            0, 24, 1, /* 5128: struct.ASN1_ENCODING_st */
            	13, 0,
            1, 8, 1, /* 5133: pointer.struct.asn1_string_st */
            	5019, 0,
            1, 8, 1, /* 5138: pointer.struct.AUTHORITY_KEYID_st */
            	2718, 0,
            1, 8, 1, /* 5143: pointer.struct.X509_POLICY_CACHE_st */
            	3041, 0,
            1, 8, 1, /* 5148: pointer.struct.stack_st_DIST_POINT */
            	5153, 0,
            0, 32, 2, /* 5153: struct.stack_st_fake_DIST_POINT */
            	5160, 8,
            	125, 24,
            8884099, 8, 2, /* 5160: pointer_to_array_of_pointers_to_stack */
            	5167, 0,
            	122, 20,
            0, 8, 1, /* 5167: pointer.DIST_POINT */
            	3496, 0,
            1, 8, 1, /* 5172: pointer.struct.NAME_CONSTRAINTS_st */
            	3640, 0,
            1, 8, 1, /* 5177: pointer.struct.x509_cert_aux_st */
            	5182, 0,
            0, 40, 5, /* 5182: struct.x509_cert_aux_st */
            	5195, 0,
            	5195, 8,
            	5219, 16,
            	5133, 24,
            	5224, 32,
            1, 8, 1, /* 5195: pointer.struct.stack_st_ASN1_OBJECT */
            	5200, 0,
            0, 32, 2, /* 5200: struct.stack_st_fake_ASN1_OBJECT */
            	5207, 8,
            	125, 24,
            8884099, 8, 2, /* 5207: pointer_to_array_of_pointers_to_stack */
            	5214, 0,
            	122, 20,
            0, 8, 1, /* 5214: pointer.ASN1_OBJECT */
            	3358, 0,
            1, 8, 1, /* 5219: pointer.struct.asn1_string_st */
            	5019, 0,
            1, 8, 1, /* 5224: pointer.struct.stack_st_X509_ALGOR */
            	5229, 0,
            0, 32, 2, /* 5229: struct.stack_st_fake_X509_ALGOR */
            	5236, 8,
            	125, 24,
            8884099, 8, 2, /* 5236: pointer_to_array_of_pointers_to_stack */
            	5243, 0,
            	122, 20,
            0, 8, 1, /* 5243: pointer.X509_ALGOR */
            	4018, 0,
            1, 8, 1, /* 5248: pointer.struct.cert_pkey_st */
            	5253, 0,
            0, 24, 3, /* 5253: struct.cert_pkey_st */
            	5262, 0,
            	5604, 8,
            	5687, 16,
            1, 8, 1, /* 5262: pointer.struct.x509_st */
            	5267, 0,
            0, 184, 12, /* 5267: struct.x509_st */
            	5294, 0,
            	5334, 8,
            	5409, 16,
            	26, 32,
            	5443, 40,
            	5465, 104,
            	5470, 112,
            	5475, 120,
            	5480, 128,
            	5504, 136,
            	5528, 144,
            	5533, 176,
            1, 8, 1, /* 5294: pointer.struct.x509_cinf_st */
            	5299, 0,
            0, 104, 11, /* 5299: struct.x509_cinf_st */
            	5324, 0,
            	5324, 8,
            	5334, 16,
            	5339, 24,
            	5387, 32,
            	5339, 40,
            	5404, 48,
            	5409, 56,
            	5409, 64,
            	5414, 72,
            	5438, 80,
            1, 8, 1, /* 5324: pointer.struct.asn1_string_st */
            	5329, 0,
            0, 24, 1, /* 5329: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 5334: pointer.struct.X509_algor_st */
            	567, 0,
            1, 8, 1, /* 5339: pointer.struct.X509_name_st */
            	5344, 0,
            0, 40, 3, /* 5344: struct.X509_name_st */
            	5353, 0,
            	5377, 16,
            	13, 24,
            1, 8, 1, /* 5353: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5358, 0,
            0, 32, 2, /* 5358: struct.stack_st_fake_X509_NAME_ENTRY */
            	5365, 8,
            	125, 24,
            8884099, 8, 2, /* 5365: pointer_to_array_of_pointers_to_stack */
            	5372, 0,
            	122, 20,
            0, 8, 1, /* 5372: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 5377: pointer.struct.buf_mem_st */
            	5382, 0,
            0, 24, 1, /* 5382: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 5387: pointer.struct.X509_val_st */
            	5392, 0,
            0, 16, 2, /* 5392: struct.X509_val_st */
            	5399, 0,
            	5399, 8,
            1, 8, 1, /* 5399: pointer.struct.asn1_string_st */
            	5329, 0,
            1, 8, 1, /* 5404: pointer.struct.X509_pubkey_st */
            	799, 0,
            1, 8, 1, /* 5409: pointer.struct.asn1_string_st */
            	5329, 0,
            1, 8, 1, /* 5414: pointer.struct.stack_st_X509_EXTENSION */
            	5419, 0,
            0, 32, 2, /* 5419: struct.stack_st_fake_X509_EXTENSION */
            	5426, 8,
            	125, 24,
            8884099, 8, 2, /* 5426: pointer_to_array_of_pointers_to_stack */
            	5433, 0,
            	122, 20,
            0, 8, 1, /* 5433: pointer.X509_EXTENSION */
            	2645, 0,
            0, 24, 1, /* 5438: struct.ASN1_ENCODING_st */
            	13, 0,
            0, 16, 1, /* 5443: struct.crypto_ex_data_st */
            	5448, 0,
            1, 8, 1, /* 5448: pointer.struct.stack_st_void */
            	5453, 0,
            0, 32, 1, /* 5453: struct.stack_st_void */
            	5458, 0,
            0, 32, 2, /* 5458: struct.stack_st */
            	1283, 8,
            	125, 24,
            1, 8, 1, /* 5465: pointer.struct.asn1_string_st */
            	5329, 0,
            1, 8, 1, /* 5470: pointer.struct.AUTHORITY_KEYID_st */
            	2718, 0,
            1, 8, 1, /* 5475: pointer.struct.X509_POLICY_CACHE_st */
            	3041, 0,
            1, 8, 1, /* 5480: pointer.struct.stack_st_DIST_POINT */
            	5485, 0,
            0, 32, 2, /* 5485: struct.stack_st_fake_DIST_POINT */
            	5492, 8,
            	125, 24,
            8884099, 8, 2, /* 5492: pointer_to_array_of_pointers_to_stack */
            	5499, 0,
            	122, 20,
            0, 8, 1, /* 5499: pointer.DIST_POINT */
            	3496, 0,
            1, 8, 1, /* 5504: pointer.struct.stack_st_GENERAL_NAME */
            	5509, 0,
            0, 32, 2, /* 5509: struct.stack_st_fake_GENERAL_NAME */
            	5516, 8,
            	125, 24,
            8884099, 8, 2, /* 5516: pointer_to_array_of_pointers_to_stack */
            	5523, 0,
            	122, 20,
            0, 8, 1, /* 5523: pointer.GENERAL_NAME */
            	2761, 0,
            1, 8, 1, /* 5528: pointer.struct.NAME_CONSTRAINTS_st */
            	3640, 0,
            1, 8, 1, /* 5533: pointer.struct.x509_cert_aux_st */
            	5538, 0,
            0, 40, 5, /* 5538: struct.x509_cert_aux_st */
            	5551, 0,
            	5551, 8,
            	5575, 16,
            	5465, 24,
            	5580, 32,
            1, 8, 1, /* 5551: pointer.struct.stack_st_ASN1_OBJECT */
            	5556, 0,
            0, 32, 2, /* 5556: struct.stack_st_fake_ASN1_OBJECT */
            	5563, 8,
            	125, 24,
            8884099, 8, 2, /* 5563: pointer_to_array_of_pointers_to_stack */
            	5570, 0,
            	122, 20,
            0, 8, 1, /* 5570: pointer.ASN1_OBJECT */
            	3358, 0,
            1, 8, 1, /* 5575: pointer.struct.asn1_string_st */
            	5329, 0,
            1, 8, 1, /* 5580: pointer.struct.stack_st_X509_ALGOR */
            	5585, 0,
            0, 32, 2, /* 5585: struct.stack_st_fake_X509_ALGOR */
            	5592, 8,
            	125, 24,
            8884099, 8, 2, /* 5592: pointer_to_array_of_pointers_to_stack */
            	5599, 0,
            	122, 20,
            0, 8, 1, /* 5599: pointer.X509_ALGOR */
            	4018, 0,
            1, 8, 1, /* 5604: pointer.struct.evp_pkey_st */
            	5609, 0,
            0, 56, 4, /* 5609: struct.evp_pkey_st */
            	5620, 16,
            	5625, 24,
            	5630, 32,
            	5663, 48,
            1, 8, 1, /* 5620: pointer.struct.evp_pkey_asn1_method_st */
            	844, 0,
            1, 8, 1, /* 5625: pointer.struct.engine_st */
            	945, 0,
            0, 8, 5, /* 5630: union.unknown */
            	26, 0,
            	5643, 0,
            	5648, 0,
            	5653, 0,
            	5658, 0,
            1, 8, 1, /* 5643: pointer.struct.rsa_st */
            	1311, 0,
            1, 8, 1, /* 5648: pointer.struct.dsa_st */
            	1513, 0,
            1, 8, 1, /* 5653: pointer.struct.dh_st */
            	1640, 0,
            1, 8, 1, /* 5658: pointer.struct.ec_key_st */
            	1754, 0,
            1, 8, 1, /* 5663: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5668, 0,
            0, 32, 2, /* 5668: struct.stack_st_fake_X509_ATTRIBUTE */
            	5675, 8,
            	125, 24,
            8884099, 8, 2, /* 5675: pointer_to_array_of_pointers_to_stack */
            	5682, 0,
            	122, 20,
            0, 8, 1, /* 5682: pointer.X509_ATTRIBUTE */
            	2261, 0,
            1, 8, 1, /* 5687: pointer.struct.env_md_st */
            	5692, 0,
            0, 120, 8, /* 5692: struct.env_md_st */
            	5711, 24,
            	5714, 32,
            	5717, 40,
            	5720, 48,
            	5711, 56,
            	5723, 64,
            	5726, 72,
            	5729, 112,
            8884097, 8, 0, /* 5711: pointer.func */
            8884097, 8, 0, /* 5714: pointer.func */
            8884097, 8, 0, /* 5717: pointer.func */
            8884097, 8, 0, /* 5720: pointer.func */
            8884097, 8, 0, /* 5723: pointer.func */
            8884097, 8, 0, /* 5726: pointer.func */
            8884097, 8, 0, /* 5729: pointer.func */
            1, 8, 1, /* 5732: pointer.struct.rsa_st */
            	1311, 0,
            1, 8, 1, /* 5737: pointer.struct.dh_st */
            	1640, 0,
            1, 8, 1, /* 5742: pointer.struct.ec_key_st */
            	1754, 0,
            1, 8, 1, /* 5747: pointer.struct.x509_st */
            	5752, 0,
            0, 184, 12, /* 5752: struct.x509_st */
            	5779, 0,
            	5819, 8,
            	5894, 16,
            	26, 32,
            	4513, 40,
            	5928, 104,
            	5470, 112,
            	5475, 120,
            	5480, 128,
            	5504, 136,
            	5528, 144,
            	5933, 176,
            1, 8, 1, /* 5779: pointer.struct.x509_cinf_st */
            	5784, 0,
            0, 104, 11, /* 5784: struct.x509_cinf_st */
            	5809, 0,
            	5809, 8,
            	5819, 16,
            	5824, 24,
            	5872, 32,
            	5824, 40,
            	5889, 48,
            	5894, 56,
            	5894, 64,
            	5899, 72,
            	5923, 80,
            1, 8, 1, /* 5809: pointer.struct.asn1_string_st */
            	5814, 0,
            0, 24, 1, /* 5814: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 5819: pointer.struct.X509_algor_st */
            	567, 0,
            1, 8, 1, /* 5824: pointer.struct.X509_name_st */
            	5829, 0,
            0, 40, 3, /* 5829: struct.X509_name_st */
            	5838, 0,
            	5862, 16,
            	13, 24,
            1, 8, 1, /* 5838: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5843, 0,
            0, 32, 2, /* 5843: struct.stack_st_fake_X509_NAME_ENTRY */
            	5850, 8,
            	125, 24,
            8884099, 8, 2, /* 5850: pointer_to_array_of_pointers_to_stack */
            	5857, 0,
            	122, 20,
            0, 8, 1, /* 5857: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 5862: pointer.struct.buf_mem_st */
            	5867, 0,
            0, 24, 1, /* 5867: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 5872: pointer.struct.X509_val_st */
            	5877, 0,
            0, 16, 2, /* 5877: struct.X509_val_st */
            	5884, 0,
            	5884, 8,
            1, 8, 1, /* 5884: pointer.struct.asn1_string_st */
            	5814, 0,
            1, 8, 1, /* 5889: pointer.struct.X509_pubkey_st */
            	799, 0,
            1, 8, 1, /* 5894: pointer.struct.asn1_string_st */
            	5814, 0,
            1, 8, 1, /* 5899: pointer.struct.stack_st_X509_EXTENSION */
            	5904, 0,
            0, 32, 2, /* 5904: struct.stack_st_fake_X509_EXTENSION */
            	5911, 8,
            	125, 24,
            8884099, 8, 2, /* 5911: pointer_to_array_of_pointers_to_stack */
            	5918, 0,
            	122, 20,
            0, 8, 1, /* 5918: pointer.X509_EXTENSION */
            	2645, 0,
            0, 24, 1, /* 5923: struct.ASN1_ENCODING_st */
            	13, 0,
            1, 8, 1, /* 5928: pointer.struct.asn1_string_st */
            	5814, 0,
            1, 8, 1, /* 5933: pointer.struct.x509_cert_aux_st */
            	5938, 0,
            0, 40, 5, /* 5938: struct.x509_cert_aux_st */
            	4474, 0,
            	4474, 8,
            	5951, 16,
            	5928, 24,
            	5956, 32,
            1, 8, 1, /* 5951: pointer.struct.asn1_string_st */
            	5814, 0,
            1, 8, 1, /* 5956: pointer.struct.stack_st_X509_ALGOR */
            	5961, 0,
            0, 32, 2, /* 5961: struct.stack_st_fake_X509_ALGOR */
            	5968, 8,
            	125, 24,
            8884099, 8, 2, /* 5968: pointer_to_array_of_pointers_to_stack */
            	5975, 0,
            	122, 20,
            0, 8, 1, /* 5975: pointer.X509_ALGOR */
            	4018, 0,
            1, 8, 1, /* 5980: pointer.struct.ssl_cipher_st */
            	5985, 0,
            0, 88, 1, /* 5985: struct.ssl_cipher_st */
            	102, 8,
            8884097, 8, 0, /* 5990: pointer.func */
            8884097, 8, 0, /* 5993: pointer.func */
            8884097, 8, 0, /* 5996: pointer.func */
            8884097, 8, 0, /* 5999: pointer.func */
            1, 8, 1, /* 6002: pointer.struct.env_md_st */
            	6007, 0,
            0, 120, 8, /* 6007: struct.env_md_st */
            	6026, 24,
            	6029, 32,
            	6032, 40,
            	6035, 48,
            	6026, 56,
            	5723, 64,
            	5726, 72,
            	6038, 112,
            8884097, 8, 0, /* 6026: pointer.func */
            8884097, 8, 0, /* 6029: pointer.func */
            8884097, 8, 0, /* 6032: pointer.func */
            8884097, 8, 0, /* 6035: pointer.func */
            8884097, 8, 0, /* 6038: pointer.func */
            1, 8, 1, /* 6041: pointer.struct.stack_st_X509 */
            	6046, 0,
            0, 32, 2, /* 6046: struct.stack_st_fake_X509 */
            	6053, 8,
            	125, 24,
            8884099, 8, 2, /* 6053: pointer_to_array_of_pointers_to_stack */
            	6060, 0,
            	122, 20,
            0, 8, 1, /* 6060: pointer.X509 */
            	4952, 0,
            8884097, 8, 0, /* 6065: pointer.func */
            1, 8, 1, /* 6068: pointer.struct.stack_st_X509_NAME */
            	6073, 0,
            0, 32, 2, /* 6073: struct.stack_st_fake_X509_NAME */
            	6080, 8,
            	125, 24,
            8884099, 8, 2, /* 6080: pointer_to_array_of_pointers_to_stack */
            	6087, 0,
            	122, 20,
            0, 8, 1, /* 6087: pointer.X509_NAME */
            	6092, 0,
            0, 0, 1, /* 6092: X509_NAME */
            	5034, 0,
            1, 8, 1, /* 6097: pointer.struct.cert_st */
            	6102, 0,
            0, 296, 7, /* 6102: struct.cert_st */
            	6119, 0,
            	6519, 48,
            	6524, 56,
            	6527, 64,
            	6532, 72,
            	5742, 80,
            	6535, 88,
            1, 8, 1, /* 6119: pointer.struct.cert_pkey_st */
            	6124, 0,
            0, 24, 3, /* 6124: struct.cert_pkey_st */
            	6133, 0,
            	6412, 8,
            	6480, 16,
            1, 8, 1, /* 6133: pointer.struct.x509_st */
            	6138, 0,
            0, 184, 12, /* 6138: struct.x509_st */
            	6165, 0,
            	6205, 8,
            	6280, 16,
            	26, 32,
            	6314, 40,
            	6336, 104,
            	5470, 112,
            	5475, 120,
            	5480, 128,
            	5504, 136,
            	5528, 144,
            	6341, 176,
            1, 8, 1, /* 6165: pointer.struct.x509_cinf_st */
            	6170, 0,
            0, 104, 11, /* 6170: struct.x509_cinf_st */
            	6195, 0,
            	6195, 8,
            	6205, 16,
            	6210, 24,
            	6258, 32,
            	6210, 40,
            	6275, 48,
            	6280, 56,
            	6280, 64,
            	6285, 72,
            	6309, 80,
            1, 8, 1, /* 6195: pointer.struct.asn1_string_st */
            	6200, 0,
            0, 24, 1, /* 6200: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 6205: pointer.struct.X509_algor_st */
            	567, 0,
            1, 8, 1, /* 6210: pointer.struct.X509_name_st */
            	6215, 0,
            0, 40, 3, /* 6215: struct.X509_name_st */
            	6224, 0,
            	6248, 16,
            	13, 24,
            1, 8, 1, /* 6224: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6229, 0,
            0, 32, 2, /* 6229: struct.stack_st_fake_X509_NAME_ENTRY */
            	6236, 8,
            	125, 24,
            8884099, 8, 2, /* 6236: pointer_to_array_of_pointers_to_stack */
            	6243, 0,
            	122, 20,
            0, 8, 1, /* 6243: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 6248: pointer.struct.buf_mem_st */
            	6253, 0,
            0, 24, 1, /* 6253: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 6258: pointer.struct.X509_val_st */
            	6263, 0,
            0, 16, 2, /* 6263: struct.X509_val_st */
            	6270, 0,
            	6270, 8,
            1, 8, 1, /* 6270: pointer.struct.asn1_string_st */
            	6200, 0,
            1, 8, 1, /* 6275: pointer.struct.X509_pubkey_st */
            	799, 0,
            1, 8, 1, /* 6280: pointer.struct.asn1_string_st */
            	6200, 0,
            1, 8, 1, /* 6285: pointer.struct.stack_st_X509_EXTENSION */
            	6290, 0,
            0, 32, 2, /* 6290: struct.stack_st_fake_X509_EXTENSION */
            	6297, 8,
            	125, 24,
            8884099, 8, 2, /* 6297: pointer_to_array_of_pointers_to_stack */
            	6304, 0,
            	122, 20,
            0, 8, 1, /* 6304: pointer.X509_EXTENSION */
            	2645, 0,
            0, 24, 1, /* 6309: struct.ASN1_ENCODING_st */
            	13, 0,
            0, 16, 1, /* 6314: struct.crypto_ex_data_st */
            	6319, 0,
            1, 8, 1, /* 6319: pointer.struct.stack_st_void */
            	6324, 0,
            0, 32, 1, /* 6324: struct.stack_st_void */
            	6329, 0,
            0, 32, 2, /* 6329: struct.stack_st */
            	1283, 8,
            	125, 24,
            1, 8, 1, /* 6336: pointer.struct.asn1_string_st */
            	6200, 0,
            1, 8, 1, /* 6341: pointer.struct.x509_cert_aux_st */
            	6346, 0,
            0, 40, 5, /* 6346: struct.x509_cert_aux_st */
            	6359, 0,
            	6359, 8,
            	6383, 16,
            	6336, 24,
            	6388, 32,
            1, 8, 1, /* 6359: pointer.struct.stack_st_ASN1_OBJECT */
            	6364, 0,
            0, 32, 2, /* 6364: struct.stack_st_fake_ASN1_OBJECT */
            	6371, 8,
            	125, 24,
            8884099, 8, 2, /* 6371: pointer_to_array_of_pointers_to_stack */
            	6378, 0,
            	122, 20,
            0, 8, 1, /* 6378: pointer.ASN1_OBJECT */
            	3358, 0,
            1, 8, 1, /* 6383: pointer.struct.asn1_string_st */
            	6200, 0,
            1, 8, 1, /* 6388: pointer.struct.stack_st_X509_ALGOR */
            	6393, 0,
            0, 32, 2, /* 6393: struct.stack_st_fake_X509_ALGOR */
            	6400, 8,
            	125, 24,
            8884099, 8, 2, /* 6400: pointer_to_array_of_pointers_to_stack */
            	6407, 0,
            	122, 20,
            0, 8, 1, /* 6407: pointer.X509_ALGOR */
            	4018, 0,
            1, 8, 1, /* 6412: pointer.struct.evp_pkey_st */
            	6417, 0,
            0, 56, 4, /* 6417: struct.evp_pkey_st */
            	5620, 16,
            	5625, 24,
            	6428, 32,
            	6456, 48,
            0, 8, 5, /* 6428: union.unknown */
            	26, 0,
            	6441, 0,
            	6446, 0,
            	6451, 0,
            	5658, 0,
            1, 8, 1, /* 6441: pointer.struct.rsa_st */
            	1311, 0,
            1, 8, 1, /* 6446: pointer.struct.dsa_st */
            	1513, 0,
            1, 8, 1, /* 6451: pointer.struct.dh_st */
            	1640, 0,
            1, 8, 1, /* 6456: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6461, 0,
            0, 32, 2, /* 6461: struct.stack_st_fake_X509_ATTRIBUTE */
            	6468, 8,
            	125, 24,
            8884099, 8, 2, /* 6468: pointer_to_array_of_pointers_to_stack */
            	6475, 0,
            	122, 20,
            0, 8, 1, /* 6475: pointer.X509_ATTRIBUTE */
            	2261, 0,
            1, 8, 1, /* 6480: pointer.struct.env_md_st */
            	6485, 0,
            0, 120, 8, /* 6485: struct.env_md_st */
            	6504, 24,
            	6507, 32,
            	6510, 40,
            	6513, 48,
            	6504, 56,
            	5723, 64,
            	5726, 72,
            	6516, 112,
            8884097, 8, 0, /* 6504: pointer.func */
            8884097, 8, 0, /* 6507: pointer.func */
            8884097, 8, 0, /* 6510: pointer.func */
            8884097, 8, 0, /* 6513: pointer.func */
            8884097, 8, 0, /* 6516: pointer.func */
            1, 8, 1, /* 6519: pointer.struct.rsa_st */
            	1311, 0,
            8884097, 8, 0, /* 6524: pointer.func */
            1, 8, 1, /* 6527: pointer.struct.dh_st */
            	1640, 0,
            8884097, 8, 0, /* 6532: pointer.func */
            8884097, 8, 0, /* 6535: pointer.func */
            8884097, 8, 0, /* 6538: pointer.func */
            8884097, 8, 0, /* 6541: pointer.func */
            8884097, 8, 0, /* 6544: pointer.func */
            8884097, 8, 0, /* 6547: pointer.func */
            8884097, 8, 0, /* 6550: pointer.func */
            8884097, 8, 0, /* 6553: pointer.func */
            8884097, 8, 0, /* 6556: pointer.func */
            0, 128, 14, /* 6559: struct.srp_ctx_st */
            	5, 0,
            	192, 8,
            	6547, 16,
            	6590, 24,
            	26, 32,
            	154, 40,
            	154, 48,
            	154, 56,
            	154, 64,
            	154, 72,
            	154, 80,
            	154, 88,
            	154, 96,
            	26, 104,
            8884097, 8, 0, /* 6590: pointer.func */
            1, 8, 1, /* 6593: pointer.struct.ssl_ctx_st */
            	4535, 0,
            0, 88, 1, /* 6598: struct.hm_header_st */
            	6603, 48,
            0, 40, 4, /* 6603: struct.dtls1_retransmit_state */
            	6614, 0,
            	6667, 8,
            	6894, 16,
            	6937, 24,
            1, 8, 1, /* 6614: pointer.struct.evp_cipher_ctx_st */
            	6619, 0,
            0, 168, 4, /* 6619: struct.evp_cipher_ctx_st */
            	6630, 0,
            	5625, 8,
            	5, 96,
            	5, 120,
            1, 8, 1, /* 6630: pointer.struct.evp_cipher_st */
            	6635, 0,
            0, 88, 7, /* 6635: struct.evp_cipher_st */
            	6652, 24,
            	6655, 32,
            	6658, 40,
            	6661, 56,
            	6661, 64,
            	6664, 72,
            	5, 80,
            8884097, 8, 0, /* 6652: pointer.func */
            8884097, 8, 0, /* 6655: pointer.func */
            8884097, 8, 0, /* 6658: pointer.func */
            8884097, 8, 0, /* 6661: pointer.func */
            8884097, 8, 0, /* 6664: pointer.func */
            1, 8, 1, /* 6667: pointer.struct.env_md_ctx_st */
            	6672, 0,
            0, 48, 5, /* 6672: struct.env_md_ctx_st */
            	6002, 0,
            	5625, 8,
            	5, 24,
            	6685, 32,
            	6029, 40,
            1, 8, 1, /* 6685: pointer.struct.evp_pkey_ctx_st */
            	6690, 0,
            0, 80, 8, /* 6690: struct.evp_pkey_ctx_st */
            	6709, 0,
            	6803, 8,
            	6808, 16,
            	6808, 24,
            	5, 40,
            	5, 48,
            	6886, 56,
            	6889, 64,
            1, 8, 1, /* 6709: pointer.struct.evp_pkey_method_st */
            	6714, 0,
            0, 208, 25, /* 6714: struct.evp_pkey_method_st */
            	6767, 8,
            	6770, 16,
            	6773, 24,
            	6767, 32,
            	6776, 40,
            	6767, 48,
            	6776, 56,
            	6767, 64,
            	6779, 72,
            	6767, 80,
            	6782, 88,
            	6767, 96,
            	6779, 104,
            	6785, 112,
            	6788, 120,
            	6785, 128,
            	6791, 136,
            	6767, 144,
            	6779, 152,
            	6767, 160,
            	6779, 168,
            	6767, 176,
            	6794, 184,
            	6797, 192,
            	6800, 200,
            8884097, 8, 0, /* 6767: pointer.func */
            8884097, 8, 0, /* 6770: pointer.func */
            8884097, 8, 0, /* 6773: pointer.func */
            8884097, 8, 0, /* 6776: pointer.func */
            8884097, 8, 0, /* 6779: pointer.func */
            8884097, 8, 0, /* 6782: pointer.func */
            8884097, 8, 0, /* 6785: pointer.func */
            8884097, 8, 0, /* 6788: pointer.func */
            8884097, 8, 0, /* 6791: pointer.func */
            8884097, 8, 0, /* 6794: pointer.func */
            8884097, 8, 0, /* 6797: pointer.func */
            8884097, 8, 0, /* 6800: pointer.func */
            1, 8, 1, /* 6803: pointer.struct.engine_st */
            	945, 0,
            1, 8, 1, /* 6808: pointer.struct.evp_pkey_st */
            	6813, 0,
            0, 56, 4, /* 6813: struct.evp_pkey_st */
            	6824, 16,
            	6803, 24,
            	6829, 32,
            	6862, 48,
            1, 8, 1, /* 6824: pointer.struct.evp_pkey_asn1_method_st */
            	844, 0,
            0, 8, 5, /* 6829: union.unknown */
            	26, 0,
            	6842, 0,
            	6847, 0,
            	6852, 0,
            	6857, 0,
            1, 8, 1, /* 6842: pointer.struct.rsa_st */
            	1311, 0,
            1, 8, 1, /* 6847: pointer.struct.dsa_st */
            	1513, 0,
            1, 8, 1, /* 6852: pointer.struct.dh_st */
            	1640, 0,
            1, 8, 1, /* 6857: pointer.struct.ec_key_st */
            	1754, 0,
            1, 8, 1, /* 6862: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6867, 0,
            0, 32, 2, /* 6867: struct.stack_st_fake_X509_ATTRIBUTE */
            	6874, 8,
            	125, 24,
            8884099, 8, 2, /* 6874: pointer_to_array_of_pointers_to_stack */
            	6881, 0,
            	122, 20,
            0, 8, 1, /* 6881: pointer.X509_ATTRIBUTE */
            	2261, 0,
            8884097, 8, 0, /* 6886: pointer.func */
            1, 8, 1, /* 6889: pointer.int */
            	122, 0,
            1, 8, 1, /* 6894: pointer.struct.comp_ctx_st */
            	6899, 0,
            0, 56, 2, /* 6899: struct.comp_ctx_st */
            	6906, 0,
            	4513, 40,
            1, 8, 1, /* 6906: pointer.struct.comp_method_st */
            	6911, 0,
            0, 64, 7, /* 6911: struct.comp_method_st */
            	102, 8,
            	6928, 16,
            	6931, 24,
            	6934, 32,
            	6934, 40,
            	296, 48,
            	296, 56,
            8884097, 8, 0, /* 6928: pointer.func */
            8884097, 8, 0, /* 6931: pointer.func */
            8884097, 8, 0, /* 6934: pointer.func */
            1, 8, 1, /* 6937: pointer.struct.ssl_session_st */
            	4879, 0,
            1, 8, 1, /* 6942: pointer.struct._pqueue */
            	6947, 0,
            0, 16, 1, /* 6947: struct._pqueue */
            	6952, 0,
            1, 8, 1, /* 6952: pointer.struct._pitem */
            	6957, 0,
            0, 24, 2, /* 6957: struct._pitem */
            	5, 8,
            	6964, 16,
            1, 8, 1, /* 6964: pointer.struct._pitem */
            	6957, 0,
            1, 8, 1, /* 6969: pointer.struct.dtls1_state_st */
            	6974, 0,
            0, 888, 7, /* 6974: struct.dtls1_state_st */
            	6991, 576,
            	6991, 592,
            	6942, 608,
            	6942, 616,
            	6991, 624,
            	6598, 648,
            	6598, 736,
            0, 16, 1, /* 6991: struct.record_pqueue_st */
            	6942, 8,
            1, 8, 1, /* 6996: pointer.struct.ssl_comp_st */
            	7001, 0,
            0, 24, 2, /* 7001: struct.ssl_comp_st */
            	102, 8,
            	6906, 16,
            0, 528, 8, /* 7008: struct.unknown */
            	5980, 408,
            	7027, 416,
            	5742, 424,
            	6068, 464,
            	13, 480,
            	6630, 488,
            	6002, 496,
            	6996, 512,
            1, 8, 1, /* 7027: pointer.struct.dh_st */
            	1640, 0,
            0, 56, 3, /* 7032: struct.ssl3_record_st */
            	13, 16,
            	13, 24,
            	13, 32,
            0, 344, 9, /* 7041: struct.ssl2_state_st */
            	107, 24,
            	13, 56,
            	13, 64,
            	13, 72,
            	13, 104,
            	13, 112,
            	13, 120,
            	13, 128,
            	13, 136,
            8884097, 8, 0, /* 7062: pointer.func */
            8884097, 8, 0, /* 7065: pointer.func */
            0, 80, 9, /* 7068: struct.bio_method_st */
            	102, 8,
            	7089, 16,
            	7092, 24,
            	7065, 32,
            	7092, 40,
            	7095, 48,
            	7062, 56,
            	7062, 64,
            	7098, 72,
            8884097, 8, 0, /* 7089: pointer.func */
            8884097, 8, 0, /* 7092: pointer.func */
            8884097, 8, 0, /* 7095: pointer.func */
            8884097, 8, 0, /* 7098: pointer.func */
            1, 8, 1, /* 7101: pointer.struct.bio_method_st */
            	7068, 0,
            0, 112, 7, /* 7106: struct.bio_st */
            	7101, 0,
            	7123, 8,
            	26, 16,
            	5, 48,
            	7126, 56,
            	7126, 64,
            	4513, 96,
            8884097, 8, 0, /* 7123: pointer.func */
            1, 8, 1, /* 7126: pointer.struct.bio_st */
            	7106, 0,
            1, 8, 1, /* 7131: pointer.struct.bio_st */
            	7106, 0,
            0, 808, 51, /* 7136: struct.ssl_st */
            	4638, 8,
            	7131, 16,
            	7131, 24,
            	7131, 32,
            	4702, 48,
            	5862, 80,
            	5, 88,
            	13, 104,
            	7241, 120,
            	7246, 128,
            	6969, 136,
            	6538, 152,
            	5, 160,
            	4462, 176,
            	4804, 184,
            	4804, 192,
            	6614, 208,
            	6667, 216,
            	6894, 224,
            	6614, 232,
            	6667, 240,
            	6894, 248,
            	6097, 256,
            	6937, 304,
            	6541, 312,
            	4498, 328,
            	6065, 336,
            	6553, 352,
            	6556, 360,
            	6593, 368,
            	4513, 392,
            	6068, 408,
            	7284, 464,
            	5, 472,
            	26, 480,
            	7287, 504,
            	7311, 512,
            	13, 520,
            	13, 544,
            	13, 560,
            	5, 568,
            	7335, 584,
            	7340, 592,
            	5, 600,
            	7343, 608,
            	5, 616,
            	6593, 624,
            	13, 632,
            	195, 648,
            	7346, 656,
            	6559, 680,
            1, 8, 1, /* 7241: pointer.struct.ssl2_state_st */
            	7041, 0,
            1, 8, 1, /* 7246: pointer.struct.ssl3_state_st */
            	7251, 0,
            0, 1200, 10, /* 7251: struct.ssl3_state_st */
            	7274, 240,
            	7274, 264,
            	7032, 288,
            	7032, 344,
            	107, 432,
            	7131, 440,
            	7279, 448,
            	5, 496,
            	5, 512,
            	7008, 528,
            0, 24, 1, /* 7274: struct.ssl3_buffer_st */
            	13, 0,
            1, 8, 1, /* 7279: pointer.pointer.struct.env_md_ctx_st */
            	6667, 0,
            8884097, 8, 0, /* 7284: pointer.func */
            1, 8, 1, /* 7287: pointer.struct.stack_st_OCSP_RESPID */
            	7292, 0,
            0, 32, 2, /* 7292: struct.stack_st_fake_OCSP_RESPID */
            	7299, 8,
            	125, 24,
            8884099, 8, 2, /* 7299: pointer_to_array_of_pointers_to_stack */
            	7306, 0,
            	122, 20,
            0, 8, 1, /* 7306: pointer.OCSP_RESPID */
            	138, 0,
            1, 8, 1, /* 7311: pointer.struct.stack_st_X509_EXTENSION */
            	7316, 0,
            0, 32, 2, /* 7316: struct.stack_st_fake_X509_EXTENSION */
            	7323, 8,
            	125, 24,
            8884099, 8, 2, /* 7323: pointer_to_array_of_pointers_to_stack */
            	7330, 0,
            	122, 20,
            0, 8, 1, /* 7330: pointer.X509_EXTENSION */
            	2645, 0,
            1, 8, 1, /* 7335: pointer.struct.tls_session_ticket_ext_st */
            	0, 0,
            8884097, 8, 0, /* 7340: pointer.func */
            8884097, 8, 0, /* 7343: pointer.func */
            1, 8, 1, /* 7346: pointer.struct.srtp_protection_profile_st */
            	7351, 0,
            0, 16, 1, /* 7351: struct.srtp_protection_profile_st */
            	102, 0,
            0, 128, 14, /* 7356: struct.srp_ctx_st */
            	5, 0,
            	7387, 8,
            	7390, 16,
            	7393, 24,
            	26, 32,
            	7396, 40,
            	7396, 48,
            	7396, 56,
            	7396, 64,
            	7396, 72,
            	7396, 80,
            	7396, 88,
            	7396, 96,
            	26, 104,
            8884097, 8, 0, /* 7387: pointer.func */
            8884097, 8, 0, /* 7390: pointer.func */
            8884097, 8, 0, /* 7393: pointer.func */
            1, 8, 1, /* 7396: pointer.struct.bignum_st */
            	7401, 0,
            0, 24, 1, /* 7401: struct.bignum_st */
            	164, 0,
            8884097, 8, 0, /* 7406: pointer.func */
            8884097, 8, 0, /* 7409: pointer.func */
            8884097, 8, 0, /* 7412: pointer.func */
            1, 8, 1, /* 7415: pointer.struct.cert_st */
            	6102, 0,
            1, 8, 1, /* 7420: pointer.struct.stack_st_X509_NAME */
            	7425, 0,
            0, 32, 2, /* 7425: struct.stack_st_fake_X509_NAME */
            	7432, 8,
            	125, 24,
            8884099, 8, 2, /* 7432: pointer_to_array_of_pointers_to_stack */
            	7439, 0,
            	122, 20,
            0, 8, 1, /* 7439: pointer.X509_NAME */
            	6092, 0,
            8884097, 8, 0, /* 7444: pointer.func */
            1, 8, 1, /* 7447: pointer.struct.stack_st_SSL_COMP */
            	7452, 0,
            0, 32, 2, /* 7452: struct.stack_st_fake_SSL_COMP */
            	7459, 8,
            	125, 24,
            8884099, 8, 2, /* 7459: pointer_to_array_of_pointers_to_stack */
            	7466, 0,
            	122, 20,
            0, 8, 1, /* 7466: pointer.SSL_COMP */
            	253, 0,
            1, 8, 1, /* 7471: pointer.struct.stack_st_X509 */
            	7476, 0,
            0, 32, 2, /* 7476: struct.stack_st_fake_X509 */
            	7483, 8,
            	125, 24,
            8884099, 8, 2, /* 7483: pointer_to_array_of_pointers_to_stack */
            	7490, 0,
            	122, 20,
            0, 8, 1, /* 7490: pointer.X509 */
            	4952, 0,
            8884097, 8, 0, /* 7495: pointer.func */
            8884097, 8, 0, /* 7498: pointer.func */
            8884097, 8, 0, /* 7501: pointer.func */
            8884097, 8, 0, /* 7504: pointer.func */
            8884097, 8, 0, /* 7507: pointer.func */
            0, 88, 1, /* 7510: struct.ssl_cipher_st */
            	102, 8,
            0, 40, 5, /* 7515: struct.x509_cert_aux_st */
            	7528, 0,
            	7528, 8,
            	7552, 16,
            	7562, 24,
            	7567, 32,
            1, 8, 1, /* 7528: pointer.struct.stack_st_ASN1_OBJECT */
            	7533, 0,
            0, 32, 2, /* 7533: struct.stack_st_fake_ASN1_OBJECT */
            	7540, 8,
            	125, 24,
            8884099, 8, 2, /* 7540: pointer_to_array_of_pointers_to_stack */
            	7547, 0,
            	122, 20,
            0, 8, 1, /* 7547: pointer.ASN1_OBJECT */
            	3358, 0,
            1, 8, 1, /* 7552: pointer.struct.asn1_string_st */
            	7557, 0,
            0, 24, 1, /* 7557: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 7562: pointer.struct.asn1_string_st */
            	7557, 0,
            1, 8, 1, /* 7567: pointer.struct.stack_st_X509_ALGOR */
            	7572, 0,
            0, 32, 2, /* 7572: struct.stack_st_fake_X509_ALGOR */
            	7579, 8,
            	125, 24,
            8884099, 8, 2, /* 7579: pointer_to_array_of_pointers_to_stack */
            	7586, 0,
            	122, 20,
            0, 8, 1, /* 7586: pointer.X509_ALGOR */
            	4018, 0,
            1, 8, 1, /* 7591: pointer.struct.x509_cert_aux_st */
            	7515, 0,
            1, 8, 1, /* 7596: pointer.struct.stack_st_GENERAL_NAME */
            	7601, 0,
            0, 32, 2, /* 7601: struct.stack_st_fake_GENERAL_NAME */
            	7608, 8,
            	125, 24,
            8884099, 8, 2, /* 7608: pointer_to_array_of_pointers_to_stack */
            	7615, 0,
            	122, 20,
            0, 8, 1, /* 7615: pointer.GENERAL_NAME */
            	2761, 0,
            1, 8, 1, /* 7620: pointer.struct.stack_st_DIST_POINT */
            	7625, 0,
            0, 32, 2, /* 7625: struct.stack_st_fake_DIST_POINT */
            	7632, 8,
            	125, 24,
            8884099, 8, 2, /* 7632: pointer_to_array_of_pointers_to_stack */
            	7639, 0,
            	122, 20,
            0, 8, 1, /* 7639: pointer.DIST_POINT */
            	3496, 0,
            0, 24, 1, /* 7644: struct.ASN1_ENCODING_st */
            	13, 0,
            1, 8, 1, /* 7649: pointer.struct.stack_st_X509_EXTENSION */
            	7654, 0,
            0, 32, 2, /* 7654: struct.stack_st_fake_X509_EXTENSION */
            	7661, 8,
            	125, 24,
            8884099, 8, 2, /* 7661: pointer_to_array_of_pointers_to_stack */
            	7668, 0,
            	122, 20,
            0, 8, 1, /* 7668: pointer.X509_EXTENSION */
            	2645, 0,
            1, 8, 1, /* 7673: pointer.struct.X509_pubkey_st */
            	799, 0,
            0, 16, 2, /* 7678: struct.X509_val_st */
            	7685, 0,
            	7685, 8,
            1, 8, 1, /* 7685: pointer.struct.asn1_string_st */
            	7557, 0,
            1, 8, 1, /* 7690: pointer.struct.buf_mem_st */
            	7695, 0,
            0, 24, 1, /* 7695: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 7700: pointer.struct.stack_st_X509_NAME_ENTRY */
            	7705, 0,
            0, 32, 2, /* 7705: struct.stack_st_fake_X509_NAME_ENTRY */
            	7712, 8,
            	125, 24,
            8884099, 8, 2, /* 7712: pointer_to_array_of_pointers_to_stack */
            	7719, 0,
            	122, 20,
            0, 8, 1, /* 7719: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 7724: pointer.struct.X509_name_st */
            	7729, 0,
            0, 40, 3, /* 7729: struct.X509_name_st */
            	7700, 0,
            	7690, 16,
            	13, 24,
            1, 8, 1, /* 7738: pointer.struct.X509_algor_st */
            	567, 0,
            1, 8, 1, /* 7743: pointer.struct.asn1_string_st */
            	7557, 0,
            1, 8, 1, /* 7748: pointer.struct.NAME_CONSTRAINTS_st */
            	3640, 0,
            8884097, 8, 0, /* 7753: pointer.func */
            0, 352, 14, /* 7756: struct.ssl_session_st */
            	26, 144,
            	26, 152,
            	7787, 168,
            	7792, 176,
            	7891, 224,
            	7896, 240,
            	7864, 248,
            	7920, 264,
            	7920, 272,
            	26, 280,
            	13, 296,
            	13, 312,
            	13, 320,
            	26, 344,
            1, 8, 1, /* 7787: pointer.struct.sess_cert_st */
            	4915, 0,
            1, 8, 1, /* 7792: pointer.struct.x509_st */
            	7797, 0,
            0, 184, 12, /* 7797: struct.x509_st */
            	7824, 0,
            	7738, 8,
            	7859, 16,
            	26, 32,
            	7864, 40,
            	7562, 104,
            	7886, 112,
            	5475, 120,
            	7620, 128,
            	7596, 136,
            	7748, 144,
            	7591, 176,
            1, 8, 1, /* 7824: pointer.struct.x509_cinf_st */
            	7829, 0,
            0, 104, 11, /* 7829: struct.x509_cinf_st */
            	7743, 0,
            	7743, 8,
            	7738, 16,
            	7724, 24,
            	7854, 32,
            	7724, 40,
            	7673, 48,
            	7859, 56,
            	7859, 64,
            	7649, 72,
            	7644, 80,
            1, 8, 1, /* 7854: pointer.struct.X509_val_st */
            	7678, 0,
            1, 8, 1, /* 7859: pointer.struct.asn1_string_st */
            	7557, 0,
            0, 16, 1, /* 7864: struct.crypto_ex_data_st */
            	7869, 0,
            1, 8, 1, /* 7869: pointer.struct.stack_st_void */
            	7874, 0,
            0, 32, 1, /* 7874: struct.stack_st_void */
            	7879, 0,
            0, 32, 2, /* 7879: struct.stack_st */
            	1283, 8,
            	125, 24,
            1, 8, 1, /* 7886: pointer.struct.AUTHORITY_KEYID_st */
            	2718, 0,
            1, 8, 1, /* 7891: pointer.struct.ssl_cipher_st */
            	7510, 0,
            1, 8, 1, /* 7896: pointer.struct.stack_st_SSL_CIPHER */
            	7901, 0,
            0, 32, 2, /* 7901: struct.stack_st_fake_SSL_CIPHER */
            	7908, 8,
            	125, 24,
            8884099, 8, 2, /* 7908: pointer_to_array_of_pointers_to_stack */
            	7915, 0,
            	122, 20,
            0, 8, 1, /* 7915: pointer.SSL_CIPHER */
            	4828, 0,
            1, 8, 1, /* 7920: pointer.struct.ssl_session_st */
            	7756, 0,
            8884097, 8, 0, /* 7925: pointer.func */
            8884097, 8, 0, /* 7928: pointer.func */
            1, 8, 1, /* 7931: pointer.struct.stack_st_X509_LOOKUP */
            	7936, 0,
            0, 32, 2, /* 7936: struct.stack_st_fake_X509_LOOKUP */
            	7943, 8,
            	125, 24,
            8884099, 8, 2, /* 7943: pointer_to_array_of_pointers_to_stack */
            	7950, 0,
            	122, 20,
            0, 8, 1, /* 7950: pointer.X509_LOOKUP */
            	344, 0,
            8884097, 8, 0, /* 7955: pointer.func */
            1, 8, 1, /* 7958: pointer.struct.ssl3_buf_freelist_st */
            	177, 0,
            8884097, 8, 0, /* 7963: pointer.func */
            8884097, 8, 0, /* 7966: pointer.func */
            0, 120, 8, /* 7969: struct.env_md_st */
            	7988, 24,
            	7991, 32,
            	7498, 40,
            	7495, 48,
            	7988, 56,
            	5723, 64,
            	5726, 72,
            	7994, 112,
            8884097, 8, 0, /* 7988: pointer.func */
            8884097, 8, 0, /* 7991: pointer.func */
            8884097, 8, 0, /* 7994: pointer.func */
            8884097, 8, 0, /* 7997: pointer.func */
            8884097, 8, 0, /* 8000: pointer.func */
            8884097, 8, 0, /* 8003: pointer.func */
            0, 56, 2, /* 8006: struct.X509_VERIFY_PARAM_st */
            	26, 0,
            	7528, 48,
            1, 8, 1, /* 8013: pointer.struct.ssl3_enc_method */
            	4749, 0,
            1, 8, 1, /* 8018: pointer.struct.stack_st_X509_OBJECT */
            	8023, 0,
            0, 32, 2, /* 8023: struct.stack_st_fake_X509_OBJECT */
            	8030, 8,
            	125, 24,
            8884099, 8, 2, /* 8030: pointer_to_array_of_pointers_to_stack */
            	8037, 0,
            	122, 20,
            0, 8, 1, /* 8037: pointer.X509_OBJECT */
            	469, 0,
            8884097, 8, 0, /* 8042: pointer.func */
            1, 8, 1, /* 8045: pointer.struct.ssl_ctx_st */
            	8050, 0,
            0, 736, 50, /* 8050: struct.ssl_ctx_st */
            	8153, 0,
            	7896, 8,
            	7896, 16,
            	8259, 24,
            	4838, 32,
            	7920, 48,
            	7920, 56,
            	7928, 80,
            	7753, 88,
            	7507, 96,
            	7955, 152,
            	5, 160,
            	5996, 168,
            	5, 176,
            	8317, 184,
            	7504, 192,
            	7501, 200,
            	7864, 208,
            	8320, 224,
            	8320, 232,
            	8320, 240,
            	7471, 248,
            	7447, 256,
            	7444, 264,
            	7420, 272,
            	7415, 304,
            	8325, 320,
            	5, 328,
            	8302, 376,
            	8328, 384,
            	8297, 392,
            	5625, 408,
            	7387, 416,
            	5, 424,
            	7406, 480,
            	7390, 488,
            	5, 496,
            	7409, 504,
            	5, 512,
            	26, 520,
            	7412, 528,
            	7966, 536,
            	7958, 552,
            	7958, 560,
            	7356, 568,
            	8331, 696,
            	5, 704,
            	8334, 712,
            	5, 720,
            	8337, 728,
            1, 8, 1, /* 8153: pointer.struct.ssl_method_st */
            	8158, 0,
            0, 232, 28, /* 8158: struct.ssl_method_st */
            	8217, 8,
            	8220, 16,
            	8220, 24,
            	8217, 32,
            	8217, 40,
            	8223, 48,
            	8223, 56,
            	8226, 64,
            	8217, 72,
            	8217, 80,
            	8217, 88,
            	8229, 96,
            	8232, 104,
            	8235, 112,
            	8217, 120,
            	8238, 128,
            	8241, 136,
            	8244, 144,
            	8247, 152,
            	8250, 160,
            	1214, 168,
            	8253, 176,
            	8000, 184,
            	296, 192,
            	8013, 200,
            	1214, 208,
            	8042, 216,
            	8256, 224,
            8884097, 8, 0, /* 8217: pointer.func */
            8884097, 8, 0, /* 8220: pointer.func */
            8884097, 8, 0, /* 8223: pointer.func */
            8884097, 8, 0, /* 8226: pointer.func */
            8884097, 8, 0, /* 8229: pointer.func */
            8884097, 8, 0, /* 8232: pointer.func */
            8884097, 8, 0, /* 8235: pointer.func */
            8884097, 8, 0, /* 8238: pointer.func */
            8884097, 8, 0, /* 8241: pointer.func */
            8884097, 8, 0, /* 8244: pointer.func */
            8884097, 8, 0, /* 8247: pointer.func */
            8884097, 8, 0, /* 8250: pointer.func */
            8884097, 8, 0, /* 8253: pointer.func */
            8884097, 8, 0, /* 8256: pointer.func */
            1, 8, 1, /* 8259: pointer.struct.x509_store_st */
            	8264, 0,
            0, 144, 15, /* 8264: struct.x509_store_st */
            	8018, 8,
            	7931, 16,
            	8297, 24,
            	7925, 32,
            	8302, 40,
            	7997, 48,
            	8305, 56,
            	7925, 64,
            	7963, 72,
            	8003, 80,
            	8308, 88,
            	8311, 96,
            	8314, 104,
            	7925, 112,
            	7864, 120,
            1, 8, 1, /* 8297: pointer.struct.X509_VERIFY_PARAM_st */
            	8006, 0,
            8884097, 8, 0, /* 8302: pointer.func */
            8884097, 8, 0, /* 8305: pointer.func */
            8884097, 8, 0, /* 8308: pointer.func */
            8884097, 8, 0, /* 8311: pointer.func */
            8884097, 8, 0, /* 8314: pointer.func */
            8884097, 8, 0, /* 8317: pointer.func */
            1, 8, 1, /* 8320: pointer.struct.env_md_st */
            	7969, 0,
            8884097, 8, 0, /* 8325: pointer.func */
            8884097, 8, 0, /* 8328: pointer.func */
            8884097, 8, 0, /* 8331: pointer.func */
            8884097, 8, 0, /* 8334: pointer.func */
            1, 8, 1, /* 8337: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	8342, 0,
            0, 32, 2, /* 8342: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	8349, 8,
            	125, 24,
            8884099, 8, 2, /* 8349: pointer_to_array_of_pointers_to_stack */
            	8356, 0,
            	122, 20,
            0, 8, 1, /* 8356: pointer.SRTP_PROTECTION_PROFILE */
            	219, 0,
            0, 1, 0, /* 8361: char */
            1, 8, 1, /* 8364: pointer.struct.ssl_st */
            	7136, 0,
        },
        .arg_entity_index = { 8364, },
        .ret_entity_index = 8045,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    SSL_CTX * *new_ret_ptr = (SSL_CTX * *)new_args->ret;

    SSL_CTX * (*orig_SSL_get_SSL_CTX)(const SSL *);
    orig_SSL_get_SSL_CTX = dlsym(RTLD_NEXT, "SSL_get_SSL_CTX");
    *new_ret_ptr = (*orig_SSL_get_SSL_CTX)(new_arg_a);

    syscall(889);

    return ret;
}

