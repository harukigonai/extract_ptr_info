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

int bb_SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c);

int SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_use_PrivateKey_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_use_PrivateKey_file(arg_a,arg_b,arg_c);
    else {
        int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *,const char *,int);
        orig_SSL_CTX_use_PrivateKey_file = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey_file");
        return orig_SSL_CTX_use_PrivateKey_file(arg_a,arg_b,arg_c);
    }
}

int bb_SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            0, 0, 1, /* 10: SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 15: pointer.func */
            0, 8, 1, /* 18: struct.ssl3_buf_freelist_entry_st */
            	23, 0,
            1, 8, 1, /* 23: pointer.struct.ssl3_buf_freelist_entry_st */
            	18, 0,
            0, 24, 1, /* 28: struct.ssl3_buf_freelist_st */
            	23, 16,
            8884097, 8, 0, /* 33: pointer.func */
            8884097, 8, 0, /* 36: pointer.func */
            8884097, 8, 0, /* 39: pointer.func */
            8884097, 8, 0, /* 42: pointer.func */
            8884097, 8, 0, /* 45: pointer.func */
            8884097, 8, 0, /* 48: pointer.func */
            0, 296, 7, /* 51: struct.cert_st */
            	68, 0,
            	1859, 48,
            	1864, 56,
            	1867, 64,
            	48, 72,
            	1872, 80,
            	45, 88,
            1, 8, 1, /* 68: pointer.struct.cert_pkey_st */
            	73, 0,
            0, 24, 3, /* 73: struct.cert_pkey_st */
            	82, 0,
            	450, 8,
            	1814, 16,
            1, 8, 1, /* 82: pointer.struct.x509_st */
            	87, 0,
            0, 184, 12, /* 87: struct.x509_st */
            	114, 0,
            	162, 8,
            	261, 16,
            	246, 32,
            	610, 40,
            	266, 104,
            	1260, 112,
            	1268, 120,
            	1276, 128,
            	1685, 136,
            	1709, 144,
            	1717, 176,
            1, 8, 1, /* 114: pointer.struct.x509_cinf_st */
            	119, 0,
            0, 104, 11, /* 119: struct.x509_cinf_st */
            	144, 0,
            	144, 8,
            	162, 16,
            	329, 24,
            	419, 32,
            	329, 40,
            	436, 48,
            	261, 56,
            	261, 64,
            	1195, 72,
            	1255, 80,
            1, 8, 1, /* 144: pointer.struct.asn1_string_st */
            	149, 0,
            0, 24, 1, /* 149: struct.asn1_string_st */
            	154, 8,
            1, 8, 1, /* 154: pointer.unsigned char */
            	159, 0,
            0, 1, 0, /* 159: unsigned char */
            1, 8, 1, /* 162: pointer.struct.X509_algor_st */
            	167, 0,
            0, 16, 2, /* 167: struct.X509_algor_st */
            	174, 0,
            	193, 8,
            1, 8, 1, /* 174: pointer.struct.asn1_object_st */
            	179, 0,
            0, 40, 3, /* 179: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	188, 24,
            1, 8, 1, /* 188: pointer.unsigned char */
            	159, 0,
            1, 8, 1, /* 193: pointer.struct.asn1_type_st */
            	198, 0,
            0, 16, 1, /* 198: struct.asn1_type_st */
            	203, 8,
            0, 8, 20, /* 203: union.unknown */
            	246, 0,
            	251, 0,
            	174, 0,
            	144, 0,
            	256, 0,
            	261, 0,
            	266, 0,
            	271, 0,
            	276, 0,
            	281, 0,
            	286, 0,
            	291, 0,
            	296, 0,
            	301, 0,
            	306, 0,
            	311, 0,
            	316, 0,
            	251, 0,
            	251, 0,
            	321, 0,
            1, 8, 1, /* 246: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 251: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 256: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 261: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 266: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 271: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 276: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 281: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 286: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 291: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 296: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 301: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 306: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 311: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 316: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 321: pointer.struct.ASN1_VALUE_st */
            	326, 0,
            0, 0, 0, /* 326: struct.ASN1_VALUE_st */
            1, 8, 1, /* 329: pointer.struct.X509_name_st */
            	334, 0,
            0, 40, 3, /* 334: struct.X509_name_st */
            	343, 0,
            	409, 16,
            	154, 24,
            1, 8, 1, /* 343: pointer.struct.stack_st_X509_NAME_ENTRY */
            	348, 0,
            0, 32, 2, /* 348: struct.stack_st_fake_X509_NAME_ENTRY */
            	355, 8,
            	406, 24,
            8884099, 8, 2, /* 355: pointer_to_array_of_pointers_to_stack */
            	362, 0,
            	403, 20,
            0, 8, 1, /* 362: pointer.X509_NAME_ENTRY */
            	367, 0,
            0, 0, 1, /* 367: X509_NAME_ENTRY */
            	372, 0,
            0, 24, 2, /* 372: struct.X509_name_entry_st */
            	379, 0,
            	393, 8,
            1, 8, 1, /* 379: pointer.struct.asn1_object_st */
            	384, 0,
            0, 40, 3, /* 384: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	188, 24,
            1, 8, 1, /* 393: pointer.struct.asn1_string_st */
            	398, 0,
            0, 24, 1, /* 398: struct.asn1_string_st */
            	154, 8,
            0, 4, 0, /* 403: int */
            8884097, 8, 0, /* 406: pointer.func */
            1, 8, 1, /* 409: pointer.struct.buf_mem_st */
            	414, 0,
            0, 24, 1, /* 414: struct.buf_mem_st */
            	246, 8,
            1, 8, 1, /* 419: pointer.struct.X509_val_st */
            	424, 0,
            0, 16, 2, /* 424: struct.X509_val_st */
            	431, 0,
            	431, 8,
            1, 8, 1, /* 431: pointer.struct.asn1_string_st */
            	149, 0,
            1, 8, 1, /* 436: pointer.struct.X509_pubkey_st */
            	441, 0,
            0, 24, 3, /* 441: struct.X509_pubkey_st */
            	162, 0,
            	261, 8,
            	450, 16,
            1, 8, 1, /* 450: pointer.struct.evp_pkey_st */
            	455, 0,
            0, 56, 4, /* 455: struct.evp_pkey_st */
            	466, 16,
            	474, 24,
            	482, 32,
            	816, 48,
            1, 8, 1, /* 466: pointer.struct.evp_pkey_asn1_method_st */
            	471, 0,
            0, 0, 0, /* 471: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 474: pointer.struct.engine_st */
            	479, 0,
            0, 0, 0, /* 479: struct.engine_st */
            0, 8, 5, /* 482: union.unknown */
            	246, 0,
            	495, 0,
            	659, 0,
            	740, 0,
            	808, 0,
            1, 8, 1, /* 495: pointer.struct.rsa_st */
            	500, 0,
            0, 168, 17, /* 500: struct.rsa_st */
            	537, 16,
            	474, 24,
            	592, 32,
            	592, 40,
            	592, 48,
            	592, 56,
            	592, 64,
            	592, 72,
            	592, 80,
            	592, 88,
            	610, 96,
            	637, 120,
            	637, 128,
            	637, 136,
            	246, 144,
            	651, 152,
            	651, 160,
            1, 8, 1, /* 537: pointer.struct.rsa_meth_st */
            	542, 0,
            0, 112, 13, /* 542: struct.rsa_meth_st */
            	5, 0,
            	571, 8,
            	571, 16,
            	571, 24,
            	571, 32,
            	574, 40,
            	577, 48,
            	580, 56,
            	580, 64,
            	246, 80,
            	583, 88,
            	586, 96,
            	589, 104,
            8884097, 8, 0, /* 571: pointer.func */
            8884097, 8, 0, /* 574: pointer.func */
            8884097, 8, 0, /* 577: pointer.func */
            8884097, 8, 0, /* 580: pointer.func */
            8884097, 8, 0, /* 583: pointer.func */
            8884097, 8, 0, /* 586: pointer.func */
            8884097, 8, 0, /* 589: pointer.func */
            1, 8, 1, /* 592: pointer.struct.bignum_st */
            	597, 0,
            0, 24, 1, /* 597: struct.bignum_st */
            	602, 0,
            1, 8, 1, /* 602: pointer.unsigned int */
            	607, 0,
            0, 4, 0, /* 607: unsigned int */
            0, 16, 1, /* 610: struct.crypto_ex_data_st */
            	615, 0,
            1, 8, 1, /* 615: pointer.struct.stack_st_void */
            	620, 0,
            0, 32, 1, /* 620: struct.stack_st_void */
            	625, 0,
            0, 32, 2, /* 625: struct.stack_st */
            	632, 8,
            	406, 24,
            1, 8, 1, /* 632: pointer.pointer.char */
            	246, 0,
            1, 8, 1, /* 637: pointer.struct.bn_mont_ctx_st */
            	642, 0,
            0, 96, 3, /* 642: struct.bn_mont_ctx_st */
            	597, 8,
            	597, 32,
            	597, 56,
            1, 8, 1, /* 651: pointer.struct.bn_blinding_st */
            	656, 0,
            0, 0, 0, /* 656: struct.bn_blinding_st */
            1, 8, 1, /* 659: pointer.struct.dsa_st */
            	664, 0,
            0, 136, 11, /* 664: struct.dsa_st */
            	592, 24,
            	592, 32,
            	592, 40,
            	592, 48,
            	592, 56,
            	592, 64,
            	592, 72,
            	637, 88,
            	610, 104,
            	689, 120,
            	474, 128,
            1, 8, 1, /* 689: pointer.struct.dsa_method */
            	694, 0,
            0, 96, 11, /* 694: struct.dsa_method */
            	5, 0,
            	719, 8,
            	722, 16,
            	725, 24,
            	728, 32,
            	731, 40,
            	734, 48,
            	734, 56,
            	246, 72,
            	737, 80,
            	734, 88,
            8884097, 8, 0, /* 719: pointer.func */
            8884097, 8, 0, /* 722: pointer.func */
            8884097, 8, 0, /* 725: pointer.func */
            8884097, 8, 0, /* 728: pointer.func */
            8884097, 8, 0, /* 731: pointer.func */
            8884097, 8, 0, /* 734: pointer.func */
            8884097, 8, 0, /* 737: pointer.func */
            1, 8, 1, /* 740: pointer.struct.dh_st */
            	745, 0,
            0, 144, 12, /* 745: struct.dh_st */
            	592, 8,
            	592, 16,
            	592, 32,
            	592, 40,
            	637, 56,
            	592, 64,
            	592, 72,
            	154, 80,
            	592, 96,
            	610, 112,
            	772, 128,
            	474, 136,
            1, 8, 1, /* 772: pointer.struct.dh_method */
            	777, 0,
            0, 72, 8, /* 777: struct.dh_method */
            	5, 0,
            	796, 8,
            	799, 16,
            	802, 24,
            	796, 32,
            	796, 40,
            	246, 56,
            	805, 64,
            8884097, 8, 0, /* 796: pointer.func */
            8884097, 8, 0, /* 799: pointer.func */
            8884097, 8, 0, /* 802: pointer.func */
            8884097, 8, 0, /* 805: pointer.func */
            1, 8, 1, /* 808: pointer.struct.ec_key_st */
            	813, 0,
            0, 0, 0, /* 813: struct.ec_key_st */
            1, 8, 1, /* 816: pointer.struct.stack_st_X509_ATTRIBUTE */
            	821, 0,
            0, 32, 2, /* 821: struct.stack_st_fake_X509_ATTRIBUTE */
            	828, 8,
            	406, 24,
            8884099, 8, 2, /* 828: pointer_to_array_of_pointers_to_stack */
            	835, 0,
            	403, 20,
            0, 8, 1, /* 835: pointer.X509_ATTRIBUTE */
            	840, 0,
            0, 0, 1, /* 840: X509_ATTRIBUTE */
            	845, 0,
            0, 24, 2, /* 845: struct.x509_attributes_st */
            	852, 0,
            	866, 16,
            1, 8, 1, /* 852: pointer.struct.asn1_object_st */
            	857, 0,
            0, 40, 3, /* 857: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	188, 24,
            0, 8, 3, /* 866: union.unknown */
            	246, 0,
            	875, 0,
            	1054, 0,
            1, 8, 1, /* 875: pointer.struct.stack_st_ASN1_TYPE */
            	880, 0,
            0, 32, 2, /* 880: struct.stack_st_fake_ASN1_TYPE */
            	887, 8,
            	406, 24,
            8884099, 8, 2, /* 887: pointer_to_array_of_pointers_to_stack */
            	894, 0,
            	403, 20,
            0, 8, 1, /* 894: pointer.ASN1_TYPE */
            	899, 0,
            0, 0, 1, /* 899: ASN1_TYPE */
            	904, 0,
            0, 16, 1, /* 904: struct.asn1_type_st */
            	909, 8,
            0, 8, 20, /* 909: union.unknown */
            	246, 0,
            	952, 0,
            	962, 0,
            	976, 0,
            	981, 0,
            	986, 0,
            	991, 0,
            	996, 0,
            	1001, 0,
            	1006, 0,
            	1011, 0,
            	1016, 0,
            	1021, 0,
            	1026, 0,
            	1031, 0,
            	1036, 0,
            	1041, 0,
            	952, 0,
            	952, 0,
            	1046, 0,
            1, 8, 1, /* 952: pointer.struct.asn1_string_st */
            	957, 0,
            0, 24, 1, /* 957: struct.asn1_string_st */
            	154, 8,
            1, 8, 1, /* 962: pointer.struct.asn1_object_st */
            	967, 0,
            0, 40, 3, /* 967: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	188, 24,
            1, 8, 1, /* 976: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 981: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 986: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 991: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 996: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 1001: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 1006: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 1011: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 1016: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 1021: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 1026: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 1031: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 1036: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 1041: pointer.struct.asn1_string_st */
            	957, 0,
            1, 8, 1, /* 1046: pointer.struct.ASN1_VALUE_st */
            	1051, 0,
            0, 0, 0, /* 1051: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1054: pointer.struct.asn1_type_st */
            	1059, 0,
            0, 16, 1, /* 1059: struct.asn1_type_st */
            	1064, 8,
            0, 8, 20, /* 1064: union.unknown */
            	246, 0,
            	1107, 0,
            	852, 0,
            	1117, 0,
            	1122, 0,
            	1127, 0,
            	1132, 0,
            	1137, 0,
            	1142, 0,
            	1147, 0,
            	1152, 0,
            	1157, 0,
            	1162, 0,
            	1167, 0,
            	1172, 0,
            	1177, 0,
            	1182, 0,
            	1107, 0,
            	1107, 0,
            	1187, 0,
            1, 8, 1, /* 1107: pointer.struct.asn1_string_st */
            	1112, 0,
            0, 24, 1, /* 1112: struct.asn1_string_st */
            	154, 8,
            1, 8, 1, /* 1117: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1122: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1127: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1132: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1137: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1142: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1147: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1152: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1157: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1162: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1167: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1172: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1177: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1182: pointer.struct.asn1_string_st */
            	1112, 0,
            1, 8, 1, /* 1187: pointer.struct.ASN1_VALUE_st */
            	1192, 0,
            0, 0, 0, /* 1192: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1195: pointer.struct.stack_st_X509_EXTENSION */
            	1200, 0,
            0, 32, 2, /* 1200: struct.stack_st_fake_X509_EXTENSION */
            	1207, 8,
            	406, 24,
            8884099, 8, 2, /* 1207: pointer_to_array_of_pointers_to_stack */
            	1214, 0,
            	403, 20,
            0, 8, 1, /* 1214: pointer.X509_EXTENSION */
            	1219, 0,
            0, 0, 1, /* 1219: X509_EXTENSION */
            	1224, 0,
            0, 24, 2, /* 1224: struct.X509_extension_st */
            	1231, 0,
            	1245, 16,
            1, 8, 1, /* 1231: pointer.struct.asn1_object_st */
            	1236, 0,
            0, 40, 3, /* 1236: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	188, 24,
            1, 8, 1, /* 1245: pointer.struct.asn1_string_st */
            	1250, 0,
            0, 24, 1, /* 1250: struct.asn1_string_st */
            	154, 8,
            0, 24, 1, /* 1255: struct.ASN1_ENCODING_st */
            	154, 0,
            1, 8, 1, /* 1260: pointer.struct.AUTHORITY_KEYID_st */
            	1265, 0,
            0, 0, 0, /* 1265: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1268: pointer.struct.X509_POLICY_CACHE_st */
            	1273, 0,
            0, 0, 0, /* 1273: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1276: pointer.struct.stack_st_DIST_POINT */
            	1281, 0,
            0, 32, 2, /* 1281: struct.stack_st_fake_DIST_POINT */
            	1288, 8,
            	406, 24,
            8884099, 8, 2, /* 1288: pointer_to_array_of_pointers_to_stack */
            	1295, 0,
            	403, 20,
            0, 8, 1, /* 1295: pointer.DIST_POINT */
            	1300, 0,
            0, 0, 1, /* 1300: DIST_POINT */
            	1305, 0,
            0, 32, 3, /* 1305: struct.DIST_POINT_st */
            	1314, 0,
            	1675, 8,
            	1333, 16,
            1, 8, 1, /* 1314: pointer.struct.DIST_POINT_NAME_st */
            	1319, 0,
            0, 24, 2, /* 1319: struct.DIST_POINT_NAME_st */
            	1326, 8,
            	1651, 16,
            0, 8, 2, /* 1326: union.unknown */
            	1333, 0,
            	1627, 0,
            1, 8, 1, /* 1333: pointer.struct.stack_st_GENERAL_NAME */
            	1338, 0,
            0, 32, 2, /* 1338: struct.stack_st_fake_GENERAL_NAME */
            	1345, 8,
            	406, 24,
            8884099, 8, 2, /* 1345: pointer_to_array_of_pointers_to_stack */
            	1352, 0,
            	403, 20,
            0, 8, 1, /* 1352: pointer.GENERAL_NAME */
            	1357, 0,
            0, 0, 1, /* 1357: GENERAL_NAME */
            	1362, 0,
            0, 16, 1, /* 1362: struct.GENERAL_NAME_st */
            	1367, 8,
            0, 8, 15, /* 1367: union.unknown */
            	246, 0,
            	1400, 0,
            	1519, 0,
            	1519, 0,
            	1426, 0,
            	1567, 0,
            	1615, 0,
            	1519, 0,
            	1504, 0,
            	1412, 0,
            	1504, 0,
            	1567, 0,
            	1519, 0,
            	1412, 0,
            	1426, 0,
            1, 8, 1, /* 1400: pointer.struct.otherName_st */
            	1405, 0,
            0, 16, 2, /* 1405: struct.otherName_st */
            	1412, 0,
            	1426, 8,
            1, 8, 1, /* 1412: pointer.struct.asn1_object_st */
            	1417, 0,
            0, 40, 3, /* 1417: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	188, 24,
            1, 8, 1, /* 1426: pointer.struct.asn1_type_st */
            	1431, 0,
            0, 16, 1, /* 1431: struct.asn1_type_st */
            	1436, 8,
            0, 8, 20, /* 1436: union.unknown */
            	246, 0,
            	1479, 0,
            	1412, 0,
            	1489, 0,
            	1494, 0,
            	1499, 0,
            	1504, 0,
            	1509, 0,
            	1514, 0,
            	1519, 0,
            	1524, 0,
            	1529, 0,
            	1534, 0,
            	1539, 0,
            	1544, 0,
            	1549, 0,
            	1554, 0,
            	1479, 0,
            	1479, 0,
            	1559, 0,
            1, 8, 1, /* 1479: pointer.struct.asn1_string_st */
            	1484, 0,
            0, 24, 1, /* 1484: struct.asn1_string_st */
            	154, 8,
            1, 8, 1, /* 1489: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1494: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1499: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1504: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1509: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1514: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1519: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1524: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1529: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1534: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1539: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1544: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1549: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1554: pointer.struct.asn1_string_st */
            	1484, 0,
            1, 8, 1, /* 1559: pointer.struct.ASN1_VALUE_st */
            	1564, 0,
            0, 0, 0, /* 1564: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1567: pointer.struct.X509_name_st */
            	1572, 0,
            0, 40, 3, /* 1572: struct.X509_name_st */
            	1581, 0,
            	1605, 16,
            	154, 24,
            1, 8, 1, /* 1581: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1586, 0,
            0, 32, 2, /* 1586: struct.stack_st_fake_X509_NAME_ENTRY */
            	1593, 8,
            	406, 24,
            8884099, 8, 2, /* 1593: pointer_to_array_of_pointers_to_stack */
            	1600, 0,
            	403, 20,
            0, 8, 1, /* 1600: pointer.X509_NAME_ENTRY */
            	367, 0,
            1, 8, 1, /* 1605: pointer.struct.buf_mem_st */
            	1610, 0,
            0, 24, 1, /* 1610: struct.buf_mem_st */
            	246, 8,
            1, 8, 1, /* 1615: pointer.struct.EDIPartyName_st */
            	1620, 0,
            0, 16, 2, /* 1620: struct.EDIPartyName_st */
            	1479, 0,
            	1479, 8,
            1, 8, 1, /* 1627: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1632, 0,
            0, 32, 2, /* 1632: struct.stack_st_fake_X509_NAME_ENTRY */
            	1639, 8,
            	406, 24,
            8884099, 8, 2, /* 1639: pointer_to_array_of_pointers_to_stack */
            	1646, 0,
            	403, 20,
            0, 8, 1, /* 1646: pointer.X509_NAME_ENTRY */
            	367, 0,
            1, 8, 1, /* 1651: pointer.struct.X509_name_st */
            	1656, 0,
            0, 40, 3, /* 1656: struct.X509_name_st */
            	1627, 0,
            	1665, 16,
            	154, 24,
            1, 8, 1, /* 1665: pointer.struct.buf_mem_st */
            	1670, 0,
            0, 24, 1, /* 1670: struct.buf_mem_st */
            	246, 8,
            1, 8, 1, /* 1675: pointer.struct.asn1_string_st */
            	1680, 0,
            0, 24, 1, /* 1680: struct.asn1_string_st */
            	154, 8,
            1, 8, 1, /* 1685: pointer.struct.stack_st_GENERAL_NAME */
            	1690, 0,
            0, 32, 2, /* 1690: struct.stack_st_fake_GENERAL_NAME */
            	1697, 8,
            	406, 24,
            8884099, 8, 2, /* 1697: pointer_to_array_of_pointers_to_stack */
            	1704, 0,
            	403, 20,
            0, 8, 1, /* 1704: pointer.GENERAL_NAME */
            	1357, 0,
            1, 8, 1, /* 1709: pointer.struct.NAME_CONSTRAINTS_st */
            	1714, 0,
            0, 0, 0, /* 1714: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 1717: pointer.struct.x509_cert_aux_st */
            	1722, 0,
            0, 40, 5, /* 1722: struct.x509_cert_aux_st */
            	1735, 0,
            	1735, 8,
            	316, 16,
            	266, 24,
            	1773, 32,
            1, 8, 1, /* 1735: pointer.struct.stack_st_ASN1_OBJECT */
            	1740, 0,
            0, 32, 2, /* 1740: struct.stack_st_fake_ASN1_OBJECT */
            	1747, 8,
            	406, 24,
            8884099, 8, 2, /* 1747: pointer_to_array_of_pointers_to_stack */
            	1754, 0,
            	403, 20,
            0, 8, 1, /* 1754: pointer.ASN1_OBJECT */
            	1759, 0,
            0, 0, 1, /* 1759: ASN1_OBJECT */
            	1764, 0,
            0, 40, 3, /* 1764: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	188, 24,
            1, 8, 1, /* 1773: pointer.struct.stack_st_X509_ALGOR */
            	1778, 0,
            0, 32, 2, /* 1778: struct.stack_st_fake_X509_ALGOR */
            	1785, 8,
            	406, 24,
            8884099, 8, 2, /* 1785: pointer_to_array_of_pointers_to_stack */
            	1792, 0,
            	403, 20,
            0, 8, 1, /* 1792: pointer.X509_ALGOR */
            	1797, 0,
            0, 0, 1, /* 1797: X509_ALGOR */
            	1802, 0,
            0, 16, 2, /* 1802: struct.X509_algor_st */
            	962, 0,
            	1809, 8,
            1, 8, 1, /* 1809: pointer.struct.asn1_type_st */
            	904, 0,
            1, 8, 1, /* 1814: pointer.struct.env_md_st */
            	1819, 0,
            0, 120, 8, /* 1819: struct.env_md_st */
            	1838, 24,
            	1841, 32,
            	1844, 40,
            	1847, 48,
            	1838, 56,
            	1850, 64,
            	1853, 72,
            	1856, 112,
            8884097, 8, 0, /* 1838: pointer.func */
            8884097, 8, 0, /* 1841: pointer.func */
            8884097, 8, 0, /* 1844: pointer.func */
            8884097, 8, 0, /* 1847: pointer.func */
            8884097, 8, 0, /* 1850: pointer.func */
            8884097, 8, 0, /* 1853: pointer.func */
            8884097, 8, 0, /* 1856: pointer.func */
            1, 8, 1, /* 1859: pointer.struct.rsa_st */
            	500, 0,
            8884097, 8, 0, /* 1864: pointer.func */
            1, 8, 1, /* 1867: pointer.struct.dh_st */
            	745, 0,
            1, 8, 1, /* 1872: pointer.struct.ec_key_st */
            	813, 0,
            1, 8, 1, /* 1877: pointer.struct.cert_st */
            	51, 0,
            8884097, 8, 0, /* 1882: pointer.func */
            0, 0, 1, /* 1885: X509_NAME */
            	1890, 0,
            0, 40, 3, /* 1890: struct.X509_name_st */
            	1899, 0,
            	1923, 16,
            	154, 24,
            1, 8, 1, /* 1899: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1904, 0,
            0, 32, 2, /* 1904: struct.stack_st_fake_X509_NAME_ENTRY */
            	1911, 8,
            	406, 24,
            8884099, 8, 2, /* 1911: pointer_to_array_of_pointers_to_stack */
            	1918, 0,
            	403, 20,
            0, 8, 1, /* 1918: pointer.X509_NAME_ENTRY */
            	367, 0,
            1, 8, 1, /* 1923: pointer.struct.buf_mem_st */
            	1928, 0,
            0, 24, 1, /* 1928: struct.buf_mem_st */
            	246, 8,
            8884097, 8, 0, /* 1933: pointer.func */
            8884097, 8, 0, /* 1936: pointer.func */
            0, 64, 7, /* 1939: struct.comp_method_st */
            	5, 8,
            	1956, 16,
            	1936, 24,
            	1933, 32,
            	1933, 40,
            	1959, 48,
            	1959, 56,
            8884097, 8, 0, /* 1956: pointer.func */
            8884097, 8, 0, /* 1959: pointer.func */
            1, 8, 1, /* 1962: pointer.struct.comp_method_st */
            	1939, 0,
            1, 8, 1, /* 1967: pointer.struct.stack_st_SSL_COMP */
            	1972, 0,
            0, 32, 2, /* 1972: struct.stack_st_fake_SSL_COMP */
            	1979, 8,
            	406, 24,
            8884099, 8, 2, /* 1979: pointer_to_array_of_pointers_to_stack */
            	1986, 0,
            	403, 20,
            0, 8, 1, /* 1986: pointer.SSL_COMP */
            	1991, 0,
            0, 0, 1, /* 1991: SSL_COMP */
            	1996, 0,
            0, 24, 2, /* 1996: struct.ssl_comp_st */
            	5, 8,
            	1962, 16,
            8884097, 8, 0, /* 2003: pointer.func */
            8884097, 8, 0, /* 2006: pointer.func */
            8884097, 8, 0, /* 2009: pointer.func */
            8884097, 8, 0, /* 2012: pointer.func */
            8884097, 8, 0, /* 2015: pointer.func */
            8884097, 8, 0, /* 2018: pointer.func */
            8884097, 8, 0, /* 2021: pointer.func */
            8884097, 8, 0, /* 2024: pointer.func */
            1, 8, 1, /* 2027: pointer.struct.ssl_cipher_st */
            	2032, 0,
            0, 88, 1, /* 2032: struct.ssl_cipher_st */
            	5, 8,
            0, 16, 1, /* 2037: struct.crypto_ex_data_st */
            	2042, 0,
            1, 8, 1, /* 2042: pointer.struct.stack_st_void */
            	2047, 0,
            0, 32, 1, /* 2047: struct.stack_st_void */
            	2052, 0,
            0, 32, 2, /* 2052: struct.stack_st */
            	632, 8,
            	406, 24,
            8884097, 8, 0, /* 2059: pointer.func */
            0, 168, 17, /* 2062: struct.rsa_st */
            	2099, 16,
            	2151, 24,
            	2159, 32,
            	2159, 40,
            	2159, 48,
            	2159, 56,
            	2159, 64,
            	2159, 72,
            	2159, 80,
            	2159, 88,
            	2169, 96,
            	2191, 120,
            	2191, 128,
            	2191, 136,
            	246, 144,
            	2205, 152,
            	2205, 160,
            1, 8, 1, /* 2099: pointer.struct.rsa_meth_st */
            	2104, 0,
            0, 112, 13, /* 2104: struct.rsa_meth_st */
            	5, 0,
            	2133, 8,
            	2133, 16,
            	2133, 24,
            	2133, 32,
            	2059, 40,
            	2136, 48,
            	2139, 56,
            	2139, 64,
            	246, 80,
            	2142, 88,
            	2145, 96,
            	2148, 104,
            8884097, 8, 0, /* 2133: pointer.func */
            8884097, 8, 0, /* 2136: pointer.func */
            8884097, 8, 0, /* 2139: pointer.func */
            8884097, 8, 0, /* 2142: pointer.func */
            8884097, 8, 0, /* 2145: pointer.func */
            8884097, 8, 0, /* 2148: pointer.func */
            1, 8, 1, /* 2151: pointer.struct.engine_st */
            	2156, 0,
            0, 0, 0, /* 2156: struct.engine_st */
            1, 8, 1, /* 2159: pointer.struct.bignum_st */
            	2164, 0,
            0, 24, 1, /* 2164: struct.bignum_st */
            	602, 0,
            0, 16, 1, /* 2169: struct.crypto_ex_data_st */
            	2174, 0,
            1, 8, 1, /* 2174: pointer.struct.stack_st_void */
            	2179, 0,
            0, 32, 1, /* 2179: struct.stack_st_void */
            	2184, 0,
            0, 32, 2, /* 2184: struct.stack_st */
            	632, 8,
            	406, 24,
            1, 8, 1, /* 2191: pointer.struct.bn_mont_ctx_st */
            	2196, 0,
            0, 96, 3, /* 2196: struct.bn_mont_ctx_st */
            	2164, 8,
            	2164, 32,
            	2164, 56,
            1, 8, 1, /* 2205: pointer.struct.bn_blinding_st */
            	2210, 0,
            0, 0, 0, /* 2210: struct.bn_blinding_st */
            0, 1, 0, /* 2213: char */
            1, 8, 1, /* 2216: pointer.struct.asn1_string_st */
            	2221, 0,
            0, 24, 1, /* 2221: struct.asn1_string_st */
            	154, 8,
            8884097, 8, 0, /* 2226: pointer.func */
            1, 8, 1, /* 2229: pointer.struct.X509_crl_info_st */
            	2234, 0,
            0, 80, 8, /* 2234: struct.X509_crl_info_st */
            	2253, 0,
            	2258, 8,
            	2402, 16,
            	2450, 24,
            	2450, 32,
            	2455, 40,
            	2558, 48,
            	2582, 56,
            1, 8, 1, /* 2253: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2258: pointer.struct.X509_algor_st */
            	2263, 0,
            0, 16, 2, /* 2263: struct.X509_algor_st */
            	2270, 0,
            	2284, 8,
            1, 8, 1, /* 2270: pointer.struct.asn1_object_st */
            	2275, 0,
            0, 40, 3, /* 2275: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	188, 24,
            1, 8, 1, /* 2284: pointer.struct.asn1_type_st */
            	2289, 0,
            0, 16, 1, /* 2289: struct.asn1_type_st */
            	2294, 8,
            0, 8, 20, /* 2294: union.unknown */
            	246, 0,
            	2337, 0,
            	2270, 0,
            	2253, 0,
            	2342, 0,
            	2347, 0,
            	2352, 0,
            	2357, 0,
            	2362, 0,
            	2367, 0,
            	2372, 0,
            	2377, 0,
            	2382, 0,
            	2216, 0,
            	2387, 0,
            	2392, 0,
            	2397, 0,
            	2337, 0,
            	2337, 0,
            	1187, 0,
            1, 8, 1, /* 2337: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2342: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2347: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2352: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2357: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2362: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2367: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2372: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2377: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2382: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2387: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2392: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2397: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2402: pointer.struct.X509_name_st */
            	2407, 0,
            0, 40, 3, /* 2407: struct.X509_name_st */
            	2416, 0,
            	2440, 16,
            	154, 24,
            1, 8, 1, /* 2416: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2421, 0,
            0, 32, 2, /* 2421: struct.stack_st_fake_X509_NAME_ENTRY */
            	2428, 8,
            	406, 24,
            8884099, 8, 2, /* 2428: pointer_to_array_of_pointers_to_stack */
            	2435, 0,
            	403, 20,
            0, 8, 1, /* 2435: pointer.X509_NAME_ENTRY */
            	367, 0,
            1, 8, 1, /* 2440: pointer.struct.buf_mem_st */
            	2445, 0,
            0, 24, 1, /* 2445: struct.buf_mem_st */
            	246, 8,
            1, 8, 1, /* 2450: pointer.struct.asn1_string_st */
            	2221, 0,
            1, 8, 1, /* 2455: pointer.struct.stack_st_X509_REVOKED */
            	2460, 0,
            0, 32, 2, /* 2460: struct.stack_st_fake_X509_REVOKED */
            	2467, 8,
            	406, 24,
            8884099, 8, 2, /* 2467: pointer_to_array_of_pointers_to_stack */
            	2474, 0,
            	403, 20,
            0, 8, 1, /* 2474: pointer.X509_REVOKED */
            	2479, 0,
            0, 0, 1, /* 2479: X509_REVOKED */
            	2484, 0,
            0, 40, 4, /* 2484: struct.x509_revoked_st */
            	2495, 0,
            	2505, 8,
            	2510, 16,
            	2534, 24,
            1, 8, 1, /* 2495: pointer.struct.asn1_string_st */
            	2500, 0,
            0, 24, 1, /* 2500: struct.asn1_string_st */
            	154, 8,
            1, 8, 1, /* 2505: pointer.struct.asn1_string_st */
            	2500, 0,
            1, 8, 1, /* 2510: pointer.struct.stack_st_X509_EXTENSION */
            	2515, 0,
            0, 32, 2, /* 2515: struct.stack_st_fake_X509_EXTENSION */
            	2522, 8,
            	406, 24,
            8884099, 8, 2, /* 2522: pointer_to_array_of_pointers_to_stack */
            	2529, 0,
            	403, 20,
            0, 8, 1, /* 2529: pointer.X509_EXTENSION */
            	1219, 0,
            1, 8, 1, /* 2534: pointer.struct.stack_st_GENERAL_NAME */
            	2539, 0,
            0, 32, 2, /* 2539: struct.stack_st_fake_GENERAL_NAME */
            	2546, 8,
            	406, 24,
            8884099, 8, 2, /* 2546: pointer_to_array_of_pointers_to_stack */
            	2553, 0,
            	403, 20,
            0, 8, 1, /* 2553: pointer.GENERAL_NAME */
            	1357, 0,
            1, 8, 1, /* 2558: pointer.struct.stack_st_X509_EXTENSION */
            	2563, 0,
            0, 32, 2, /* 2563: struct.stack_st_fake_X509_EXTENSION */
            	2570, 8,
            	406, 24,
            8884099, 8, 2, /* 2570: pointer_to_array_of_pointers_to_stack */
            	2577, 0,
            	403, 20,
            0, 8, 1, /* 2577: pointer.X509_EXTENSION */
            	1219, 0,
            0, 24, 1, /* 2582: struct.ASN1_ENCODING_st */
            	154, 0,
            8884097, 8, 0, /* 2587: pointer.func */
            1, 8, 1, /* 2590: pointer.struct.X509_POLICY_CACHE_st */
            	2595, 0,
            0, 0, 0, /* 2595: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2598: struct.AUTHORITY_KEYID_st */
            0, 0, 0, /* 2601: struct.ec_key_st */
            1, 8, 1, /* 2604: pointer.struct.AUTHORITY_KEYID_st */
            	2598, 0,
            8884097, 8, 0, /* 2609: pointer.func */
            8884097, 8, 0, /* 2612: pointer.func */
            0, 104, 11, /* 2615: struct.x509_cinf_st */
            	2640, 0,
            	2640, 8,
            	2650, 16,
            	2807, 24,
            	2812, 32,
            	2807, 40,
            	2829, 48,
            	2739, 56,
            	2739, 64,
            	3063, 72,
            	3087, 80,
            1, 8, 1, /* 2640: pointer.struct.asn1_string_st */
            	2645, 0,
            0, 24, 1, /* 2645: struct.asn1_string_st */
            	154, 8,
            1, 8, 1, /* 2650: pointer.struct.X509_algor_st */
            	2655, 0,
            0, 16, 2, /* 2655: struct.X509_algor_st */
            	2662, 0,
            	2676, 8,
            1, 8, 1, /* 2662: pointer.struct.asn1_object_st */
            	2667, 0,
            0, 40, 3, /* 2667: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	188, 24,
            1, 8, 1, /* 2676: pointer.struct.asn1_type_st */
            	2681, 0,
            0, 16, 1, /* 2681: struct.asn1_type_st */
            	2686, 8,
            0, 8, 20, /* 2686: union.unknown */
            	246, 0,
            	2729, 0,
            	2662, 0,
            	2640, 0,
            	2734, 0,
            	2739, 0,
            	2744, 0,
            	2749, 0,
            	2754, 0,
            	2759, 0,
            	2764, 0,
            	2769, 0,
            	2774, 0,
            	2779, 0,
            	2784, 0,
            	2789, 0,
            	2794, 0,
            	2729, 0,
            	2729, 0,
            	2799, 0,
            1, 8, 1, /* 2729: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2734: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2739: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2744: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2749: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2754: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2759: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2764: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2769: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2774: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2779: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2784: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2789: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2794: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2799: pointer.struct.ASN1_VALUE_st */
            	2804, 0,
            0, 0, 0, /* 2804: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2807: pointer.struct.X509_name_st */
            	1890, 0,
            1, 8, 1, /* 2812: pointer.struct.X509_val_st */
            	2817, 0,
            0, 16, 2, /* 2817: struct.X509_val_st */
            	2824, 0,
            	2824, 8,
            1, 8, 1, /* 2824: pointer.struct.asn1_string_st */
            	2645, 0,
            1, 8, 1, /* 2829: pointer.struct.X509_pubkey_st */
            	2834, 0,
            0, 24, 3, /* 2834: struct.X509_pubkey_st */
            	2650, 0,
            	2739, 8,
            	2843, 16,
            1, 8, 1, /* 2843: pointer.struct.evp_pkey_st */
            	2848, 0,
            0, 56, 4, /* 2848: struct.evp_pkey_st */
            	2859, 16,
            	2151, 24,
            	2867, 32,
            	3039, 48,
            1, 8, 1, /* 2859: pointer.struct.evp_pkey_asn1_method_st */
            	2864, 0,
            0, 0, 0, /* 2864: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 2867: union.unknown */
            	246, 0,
            	2880, 0,
            	2885, 0,
            	2963, 0,
            	3031, 0,
            1, 8, 1, /* 2880: pointer.struct.rsa_st */
            	2062, 0,
            1, 8, 1, /* 2885: pointer.struct.dsa_st */
            	2890, 0,
            0, 136, 11, /* 2890: struct.dsa_st */
            	2159, 24,
            	2159, 32,
            	2159, 40,
            	2159, 48,
            	2159, 56,
            	2159, 64,
            	2159, 72,
            	2191, 88,
            	2169, 104,
            	2915, 120,
            	2151, 128,
            1, 8, 1, /* 2915: pointer.struct.dsa_method */
            	2920, 0,
            0, 96, 11, /* 2920: struct.dsa_method */
            	5, 0,
            	2945, 8,
            	2948, 16,
            	2951, 24,
            	2612, 32,
            	2954, 40,
            	2957, 48,
            	2957, 56,
            	246, 72,
            	2960, 80,
            	2957, 88,
            8884097, 8, 0, /* 2945: pointer.func */
            8884097, 8, 0, /* 2948: pointer.func */
            8884097, 8, 0, /* 2951: pointer.func */
            8884097, 8, 0, /* 2954: pointer.func */
            8884097, 8, 0, /* 2957: pointer.func */
            8884097, 8, 0, /* 2960: pointer.func */
            1, 8, 1, /* 2963: pointer.struct.dh_st */
            	2968, 0,
            0, 144, 12, /* 2968: struct.dh_st */
            	2159, 8,
            	2159, 16,
            	2159, 32,
            	2159, 40,
            	2191, 56,
            	2159, 64,
            	2159, 72,
            	154, 80,
            	2159, 96,
            	2169, 112,
            	2995, 128,
            	2151, 136,
            1, 8, 1, /* 2995: pointer.struct.dh_method */
            	3000, 0,
            0, 72, 8, /* 3000: struct.dh_method */
            	5, 0,
            	3019, 8,
            	3022, 16,
            	3025, 24,
            	3019, 32,
            	3019, 40,
            	246, 56,
            	3028, 64,
            8884097, 8, 0, /* 3019: pointer.func */
            8884097, 8, 0, /* 3022: pointer.func */
            8884097, 8, 0, /* 3025: pointer.func */
            8884097, 8, 0, /* 3028: pointer.func */
            1, 8, 1, /* 3031: pointer.struct.ec_key_st */
            	3036, 0,
            0, 0, 0, /* 3036: struct.ec_key_st */
            1, 8, 1, /* 3039: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3044, 0,
            0, 32, 2, /* 3044: struct.stack_st_fake_X509_ATTRIBUTE */
            	3051, 8,
            	406, 24,
            8884099, 8, 2, /* 3051: pointer_to_array_of_pointers_to_stack */
            	3058, 0,
            	403, 20,
            0, 8, 1, /* 3058: pointer.X509_ATTRIBUTE */
            	840, 0,
            1, 8, 1, /* 3063: pointer.struct.stack_st_X509_EXTENSION */
            	3068, 0,
            0, 32, 2, /* 3068: struct.stack_st_fake_X509_EXTENSION */
            	3075, 8,
            	406, 24,
            8884099, 8, 2, /* 3075: pointer_to_array_of_pointers_to_stack */
            	3082, 0,
            	403, 20,
            0, 8, 1, /* 3082: pointer.X509_EXTENSION */
            	1219, 0,
            0, 24, 1, /* 3087: struct.ASN1_ENCODING_st */
            	154, 0,
            8884097, 8, 0, /* 3092: pointer.func */
            8884097, 8, 0, /* 3095: pointer.func */
            0, 128, 14, /* 3098: struct.srp_ctx_st */
            	3129, 0,
            	3132, 8,
            	2587, 16,
            	15, 24,
            	246, 32,
            	592, 40,
            	592, 48,
            	592, 56,
            	592, 64,
            	592, 72,
            	592, 80,
            	592, 88,
            	592, 96,
            	246, 104,
            0, 8, 0, /* 3129: pointer.void */
            8884097, 8, 0, /* 3132: pointer.func */
            1, 8, 1, /* 3135: pointer.struct.rsa_meth_st */
            	3140, 0,
            0, 112, 13, /* 3140: struct.rsa_meth_st */
            	5, 0,
            	3169, 8,
            	3169, 16,
            	3169, 24,
            	3169, 32,
            	3172, 40,
            	3175, 48,
            	3178, 56,
            	3178, 64,
            	246, 80,
            	3181, 88,
            	3184, 96,
            	3187, 104,
            8884097, 8, 0, /* 3169: pointer.func */
            8884097, 8, 0, /* 3172: pointer.func */
            8884097, 8, 0, /* 3175: pointer.func */
            8884097, 8, 0, /* 3178: pointer.func */
            8884097, 8, 0, /* 3181: pointer.func */
            8884097, 8, 0, /* 3184: pointer.func */
            8884097, 8, 0, /* 3187: pointer.func */
            1, 8, 1, /* 3190: pointer.struct.ec_key_st */
            	2601, 0,
            8884097, 8, 0, /* 3195: pointer.func */
            8884097, 8, 0, /* 3198: pointer.func */
            8884097, 8, 0, /* 3201: pointer.func */
            0, 0, 0, /* 3204: struct.NAME_CONSTRAINTS_st */
            8884097, 8, 0, /* 3207: pointer.func */
            0, 136, 11, /* 3210: struct.dsa_st */
            	3235, 24,
            	3235, 32,
            	3235, 40,
            	3235, 48,
            	3235, 56,
            	3235, 64,
            	3235, 72,
            	3245, 88,
            	2037, 104,
            	3259, 120,
            	3304, 128,
            1, 8, 1, /* 3235: pointer.struct.bignum_st */
            	3240, 0,
            0, 24, 1, /* 3240: struct.bignum_st */
            	602, 0,
            1, 8, 1, /* 3245: pointer.struct.bn_mont_ctx_st */
            	3250, 0,
            0, 96, 3, /* 3250: struct.bn_mont_ctx_st */
            	3240, 8,
            	3240, 32,
            	3240, 56,
            1, 8, 1, /* 3259: pointer.struct.dsa_method */
            	3264, 0,
            0, 96, 11, /* 3264: struct.dsa_method */
            	5, 0,
            	3289, 8,
            	3292, 16,
            	3207, 24,
            	3295, 32,
            	3201, 40,
            	3298, 48,
            	3298, 56,
            	246, 72,
            	3301, 80,
            	3298, 88,
            8884097, 8, 0, /* 3289: pointer.func */
            8884097, 8, 0, /* 3292: pointer.func */
            8884097, 8, 0, /* 3295: pointer.func */
            8884097, 8, 0, /* 3298: pointer.func */
            8884097, 8, 0, /* 3301: pointer.func */
            1, 8, 1, /* 3304: pointer.struct.engine_st */
            	3309, 0,
            0, 0, 0, /* 3309: struct.engine_st */
            1, 8, 1, /* 3312: pointer.struct.evp_pkey_asn1_method_st */
            	3317, 0,
            0, 0, 0, /* 3317: struct.evp_pkey_asn1_method_st */
            0, 144, 12, /* 3320: struct.dh_st */
            	3235, 8,
            	3235, 16,
            	3235, 32,
            	3235, 40,
            	3245, 56,
            	3235, 64,
            	3235, 72,
            	154, 80,
            	3235, 96,
            	2037, 112,
            	3347, 128,
            	3304, 136,
            1, 8, 1, /* 3347: pointer.struct.dh_method */
            	3352, 0,
            0, 72, 8, /* 3352: struct.dh_method */
            	5, 0,
            	3371, 8,
            	3374, 16,
            	3195, 24,
            	3371, 32,
            	3371, 40,
            	246, 56,
            	3377, 64,
            8884097, 8, 0, /* 3371: pointer.func */
            8884097, 8, 0, /* 3374: pointer.func */
            8884097, 8, 0, /* 3377: pointer.func */
            1, 8, 1, /* 3380: pointer.struct.x509_st */
            	3385, 0,
            0, 184, 12, /* 3385: struct.x509_st */
            	3412, 0,
            	2258, 8,
            	2347, 16,
            	246, 32,
            	2037, 40,
            	2352, 104,
            	2604, 112,
            	2590, 120,
            	3581, 128,
            	3605, 136,
            	3629, 144,
            	3637, 176,
            1, 8, 1, /* 3412: pointer.struct.x509_cinf_st */
            	3417, 0,
            0, 104, 11, /* 3417: struct.x509_cinf_st */
            	2253, 0,
            	2253, 8,
            	2258, 16,
            	2402, 24,
            	3442, 32,
            	2402, 40,
            	3454, 48,
            	2347, 56,
            	2347, 64,
            	2558, 72,
            	2582, 80,
            1, 8, 1, /* 3442: pointer.struct.X509_val_st */
            	3447, 0,
            0, 16, 2, /* 3447: struct.X509_val_st */
            	2450, 0,
            	2450, 8,
            1, 8, 1, /* 3454: pointer.struct.X509_pubkey_st */
            	3459, 0,
            0, 24, 3, /* 3459: struct.X509_pubkey_st */
            	2258, 0,
            	2347, 8,
            	3468, 16,
            1, 8, 1, /* 3468: pointer.struct.evp_pkey_st */
            	3473, 0,
            0, 56, 4, /* 3473: struct.evp_pkey_st */
            	3312, 16,
            	3304, 24,
            	3484, 32,
            	3557, 48,
            0, 8, 5, /* 3484: union.unknown */
            	246, 0,
            	3497, 0,
            	3547, 0,
            	3552, 0,
            	3190, 0,
            1, 8, 1, /* 3497: pointer.struct.rsa_st */
            	3502, 0,
            0, 168, 17, /* 3502: struct.rsa_st */
            	3135, 16,
            	3304, 24,
            	3235, 32,
            	3235, 40,
            	3235, 48,
            	3235, 56,
            	3235, 64,
            	3235, 72,
            	3235, 80,
            	3235, 88,
            	2037, 96,
            	3245, 120,
            	3245, 128,
            	3245, 136,
            	246, 144,
            	3539, 152,
            	3539, 160,
            1, 8, 1, /* 3539: pointer.struct.bn_blinding_st */
            	3544, 0,
            0, 0, 0, /* 3544: struct.bn_blinding_st */
            1, 8, 1, /* 3547: pointer.struct.dsa_st */
            	3210, 0,
            1, 8, 1, /* 3552: pointer.struct.dh_st */
            	3320, 0,
            1, 8, 1, /* 3557: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3562, 0,
            0, 32, 2, /* 3562: struct.stack_st_fake_X509_ATTRIBUTE */
            	3569, 8,
            	406, 24,
            8884099, 8, 2, /* 3569: pointer_to_array_of_pointers_to_stack */
            	3576, 0,
            	403, 20,
            0, 8, 1, /* 3576: pointer.X509_ATTRIBUTE */
            	840, 0,
            1, 8, 1, /* 3581: pointer.struct.stack_st_DIST_POINT */
            	3586, 0,
            0, 32, 2, /* 3586: struct.stack_st_fake_DIST_POINT */
            	3593, 8,
            	406, 24,
            8884099, 8, 2, /* 3593: pointer_to_array_of_pointers_to_stack */
            	3600, 0,
            	403, 20,
            0, 8, 1, /* 3600: pointer.DIST_POINT */
            	1300, 0,
            1, 8, 1, /* 3605: pointer.struct.stack_st_GENERAL_NAME */
            	3610, 0,
            0, 32, 2, /* 3610: struct.stack_st_fake_GENERAL_NAME */
            	3617, 8,
            	406, 24,
            8884099, 8, 2, /* 3617: pointer_to_array_of_pointers_to_stack */
            	3624, 0,
            	403, 20,
            0, 8, 1, /* 3624: pointer.GENERAL_NAME */
            	1357, 0,
            1, 8, 1, /* 3629: pointer.struct.NAME_CONSTRAINTS_st */
            	3634, 0,
            0, 0, 0, /* 3634: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3637: pointer.struct.x509_cert_aux_st */
            	3642, 0,
            0, 40, 5, /* 3642: struct.x509_cert_aux_st */
            	3655, 0,
            	3655, 8,
            	2397, 16,
            	2352, 24,
            	3679, 32,
            1, 8, 1, /* 3655: pointer.struct.stack_st_ASN1_OBJECT */
            	3660, 0,
            0, 32, 2, /* 3660: struct.stack_st_fake_ASN1_OBJECT */
            	3667, 8,
            	406, 24,
            8884099, 8, 2, /* 3667: pointer_to_array_of_pointers_to_stack */
            	3674, 0,
            	403, 20,
            0, 8, 1, /* 3674: pointer.ASN1_OBJECT */
            	1759, 0,
            1, 8, 1, /* 3679: pointer.struct.stack_st_X509_ALGOR */
            	3684, 0,
            0, 32, 2, /* 3684: struct.stack_st_fake_X509_ALGOR */
            	3691, 8,
            	406, 24,
            8884099, 8, 2, /* 3691: pointer_to_array_of_pointers_to_stack */
            	3698, 0,
            	403, 20,
            0, 8, 1, /* 3698: pointer.X509_ALGOR */
            	1797, 0,
            0, 0, 1, /* 3703: SSL_CIPHER */
            	3708, 0,
            0, 88, 1, /* 3708: struct.ssl_cipher_st */
            	5, 8,
            8884097, 8, 0, /* 3713: pointer.func */
            8884097, 8, 0, /* 3716: pointer.func */
            1, 8, 1, /* 3719: pointer.struct.ssl3_buf_freelist_st */
            	28, 0,
            8884097, 8, 0, /* 3724: pointer.func */
            8884097, 8, 0, /* 3727: pointer.func */
            1, 8, 1, /* 3730: pointer.struct.stack_st_X509 */
            	3735, 0,
            0, 32, 2, /* 3735: struct.stack_st_fake_X509 */
            	3742, 8,
            	406, 24,
            8884099, 8, 2, /* 3742: pointer_to_array_of_pointers_to_stack */
            	3749, 0,
            	403, 20,
            0, 8, 1, /* 3749: pointer.X509 */
            	3754, 0,
            0, 0, 1, /* 3754: X509 */
            	3759, 0,
            0, 184, 12, /* 3759: struct.x509_st */
            	3786, 0,
            	2650, 8,
            	2739, 16,
            	246, 32,
            	2169, 40,
            	2744, 104,
            	3791, 112,
            	3799, 120,
            	3807, 128,
            	3831, 136,
            	3855, 144,
            	3860, 176,
            1, 8, 1, /* 3786: pointer.struct.x509_cinf_st */
            	2615, 0,
            1, 8, 1, /* 3791: pointer.struct.AUTHORITY_KEYID_st */
            	3796, 0,
            0, 0, 0, /* 3796: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3799: pointer.struct.X509_POLICY_CACHE_st */
            	3804, 0,
            0, 0, 0, /* 3804: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3807: pointer.struct.stack_st_DIST_POINT */
            	3812, 0,
            0, 32, 2, /* 3812: struct.stack_st_fake_DIST_POINT */
            	3819, 8,
            	406, 24,
            8884099, 8, 2, /* 3819: pointer_to_array_of_pointers_to_stack */
            	3826, 0,
            	403, 20,
            0, 8, 1, /* 3826: pointer.DIST_POINT */
            	1300, 0,
            1, 8, 1, /* 3831: pointer.struct.stack_st_GENERAL_NAME */
            	3836, 0,
            0, 32, 2, /* 3836: struct.stack_st_fake_GENERAL_NAME */
            	3843, 8,
            	406, 24,
            8884099, 8, 2, /* 3843: pointer_to_array_of_pointers_to_stack */
            	3850, 0,
            	403, 20,
            0, 8, 1, /* 3850: pointer.GENERAL_NAME */
            	1357, 0,
            1, 8, 1, /* 3855: pointer.struct.NAME_CONSTRAINTS_st */
            	3204, 0,
            1, 8, 1, /* 3860: pointer.struct.x509_cert_aux_st */
            	3865, 0,
            0, 40, 5, /* 3865: struct.x509_cert_aux_st */
            	3878, 0,
            	3878, 8,
            	2794, 16,
            	2744, 24,
            	3902, 32,
            1, 8, 1, /* 3878: pointer.struct.stack_st_ASN1_OBJECT */
            	3883, 0,
            0, 32, 2, /* 3883: struct.stack_st_fake_ASN1_OBJECT */
            	3890, 8,
            	406, 24,
            8884099, 8, 2, /* 3890: pointer_to_array_of_pointers_to_stack */
            	3897, 0,
            	403, 20,
            0, 8, 1, /* 3897: pointer.ASN1_OBJECT */
            	1759, 0,
            1, 8, 1, /* 3902: pointer.struct.stack_st_X509_ALGOR */
            	3907, 0,
            0, 32, 2, /* 3907: struct.stack_st_fake_X509_ALGOR */
            	3914, 8,
            	406, 24,
            8884099, 8, 2, /* 3914: pointer_to_array_of_pointers_to_stack */
            	3921, 0,
            	403, 20,
            0, 8, 1, /* 3921: pointer.X509_ALGOR */
            	1797, 0,
            0, 8, 1, /* 3926: pointer.SRTP_PROTECTION_PROFILE */
            	10, 0,
            0, 32, 1, /* 3931: struct.stack_st_GENERAL_NAME */
            	3936, 0,
            0, 32, 2, /* 3936: struct.stack_st */
            	632, 8,
            	406, 24,
            0, 0, 0, /* 3943: struct.ISSUING_DIST_POINT_st */
            8884097, 8, 0, /* 3946: pointer.func */
            1, 8, 1, /* 3949: pointer.struct.ssl_method_st */
            	3954, 0,
            0, 232, 28, /* 3954: struct.ssl_method_st */
            	3727, 8,
            	4013, 16,
            	4013, 24,
            	3727, 32,
            	3727, 40,
            	4016, 48,
            	4016, 56,
            	4019, 64,
            	3727, 72,
            	3727, 80,
            	3727, 88,
            	4022, 96,
            	3946, 104,
            	4025, 112,
            	3727, 120,
            	4028, 128,
            	4031, 136,
            	4034, 144,
            	4037, 152,
            	4040, 160,
            	4043, 168,
            	4046, 176,
            	4049, 184,
            	1959, 192,
            	4052, 200,
            	4043, 208,
            	4100, 216,
            	4103, 224,
            8884097, 8, 0, /* 4013: pointer.func */
            8884097, 8, 0, /* 4016: pointer.func */
            8884097, 8, 0, /* 4019: pointer.func */
            8884097, 8, 0, /* 4022: pointer.func */
            8884097, 8, 0, /* 4025: pointer.func */
            8884097, 8, 0, /* 4028: pointer.func */
            8884097, 8, 0, /* 4031: pointer.func */
            8884097, 8, 0, /* 4034: pointer.func */
            8884097, 8, 0, /* 4037: pointer.func */
            8884097, 8, 0, /* 4040: pointer.func */
            8884097, 8, 0, /* 4043: pointer.func */
            8884097, 8, 0, /* 4046: pointer.func */
            8884097, 8, 0, /* 4049: pointer.func */
            1, 8, 1, /* 4052: pointer.struct.ssl3_enc_method */
            	4057, 0,
            0, 112, 11, /* 4057: struct.ssl3_enc_method */
            	4082, 0,
            	4085, 8,
            	3727, 16,
            	4088, 24,
            	4082, 32,
            	3716, 40,
            	4091, 56,
            	5, 64,
            	5, 80,
            	4094, 96,
            	4097, 104,
            8884097, 8, 0, /* 4082: pointer.func */
            8884097, 8, 0, /* 4085: pointer.func */
            8884097, 8, 0, /* 4088: pointer.func */
            8884097, 8, 0, /* 4091: pointer.func */
            8884097, 8, 0, /* 4094: pointer.func */
            8884097, 8, 0, /* 4097: pointer.func */
            8884097, 8, 0, /* 4100: pointer.func */
            8884097, 8, 0, /* 4103: pointer.func */
            1, 8, 1, /* 4106: pointer.struct.stack_st_SSL_CIPHER */
            	4111, 0,
            0, 32, 2, /* 4111: struct.stack_st_fake_SSL_CIPHER */
            	4118, 8,
            	406, 24,
            8884099, 8, 2, /* 4118: pointer_to_array_of_pointers_to_stack */
            	4125, 0,
            	403, 20,
            0, 8, 1, /* 4125: pointer.SSL_CIPHER */
            	3703, 0,
            1, 8, 1, /* 4130: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4135, 0,
            0, 32, 2, /* 4135: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4142, 8,
            	406, 24,
            8884099, 8, 2, /* 4142: pointer_to_array_of_pointers_to_stack */
            	3926, 0,
            	403, 20,
            1, 8, 1, /* 4149: pointer.struct.ISSUING_DIST_POINT_st */
            	3943, 0,
            0, 736, 50, /* 4154: struct.ssl_ctx_st */
            	3949, 0,
            	4106, 8,
            	4106, 16,
            	4257, 24,
            	4638, 32,
            	4674, 48,
            	4674, 56,
            	2024, 80,
            	2018, 88,
            	2015, 96,
            	2012, 152,
            	3129, 160,
            	4728, 168,
            	3129, 176,
            	2009, 184,
            	2006, 192,
            	2003, 200,
            	610, 208,
            	1814, 224,
            	1814, 232,
            	1814, 240,
            	3730, 248,
            	1967, 256,
            	1882, 264,
            	4731, 272,
            	1877, 304,
            	42, 320,
            	3129, 328,
            	4614, 376,
            	36, 384,
            	4599, 392,
            	474, 408,
            	3132, 416,
            	3129, 424,
            	33, 480,
            	2587, 488,
            	3129, 496,
            	4755, 504,
            	3129, 512,
            	246, 520,
            	2021, 528,
            	4758, 536,
            	3719, 552,
            	3719, 560,
            	3098, 568,
            	4761, 696,
            	3129, 704,
            	39, 712,
            	3129, 720,
            	4130, 728,
            1, 8, 1, /* 4257: pointer.struct.x509_store_st */
            	4262, 0,
            0, 144, 15, /* 4262: struct.x509_store_st */
            	4295, 8,
            	4405, 16,
            	4599, 24,
            	4611, 32,
            	4614, 40,
            	4617, 48,
            	4620, 56,
            	4611, 64,
            	4623, 72,
            	4626, 80,
            	4629, 88,
            	4632, 96,
            	4635, 104,
            	4611, 112,
            	610, 120,
            1, 8, 1, /* 4295: pointer.struct.stack_st_X509_OBJECT */
            	4300, 0,
            0, 32, 2, /* 4300: struct.stack_st_fake_X509_OBJECT */
            	4307, 8,
            	406, 24,
            8884099, 8, 2, /* 4307: pointer_to_array_of_pointers_to_stack */
            	4314, 0,
            	403, 20,
            0, 8, 1, /* 4314: pointer.X509_OBJECT */
            	4319, 0,
            0, 0, 1, /* 4319: X509_OBJECT */
            	4324, 0,
            0, 16, 1, /* 4324: struct.x509_object_st */
            	4329, 8,
            0, 8, 4, /* 4329: union.unknown */
            	246, 0,
            	3380, 0,
            	4340, 0,
            	3468, 0,
            1, 8, 1, /* 4340: pointer.struct.X509_crl_st */
            	4345, 0,
            0, 120, 10, /* 4345: struct.X509_crl_st */
            	2229, 0,
            	2258, 8,
            	2347, 16,
            	2604, 32,
            	4149, 40,
            	2253, 56,
            	2253, 64,
            	4368, 96,
            	4397, 104,
            	3129, 112,
            1, 8, 1, /* 4368: pointer.struct.stack_st_GENERAL_NAMES */
            	4373, 0,
            0, 32, 2, /* 4373: struct.stack_st_fake_GENERAL_NAMES */
            	4380, 8,
            	406, 24,
            8884099, 8, 2, /* 4380: pointer_to_array_of_pointers_to_stack */
            	4387, 0,
            	403, 20,
            0, 8, 1, /* 4387: pointer.GENERAL_NAMES */
            	4392, 0,
            0, 0, 1, /* 4392: GENERAL_NAMES */
            	3931, 0,
            1, 8, 1, /* 4397: pointer.struct.x509_crl_method_st */
            	4402, 0,
            0, 0, 0, /* 4402: struct.x509_crl_method_st */
            1, 8, 1, /* 4405: pointer.struct.stack_st_X509_LOOKUP */
            	4410, 0,
            0, 32, 2, /* 4410: struct.stack_st_fake_X509_LOOKUP */
            	4417, 8,
            	406, 24,
            8884099, 8, 2, /* 4417: pointer_to_array_of_pointers_to_stack */
            	4424, 0,
            	403, 20,
            0, 8, 1, /* 4424: pointer.X509_LOOKUP */
            	4429, 0,
            0, 0, 1, /* 4429: X509_LOOKUP */
            	4434, 0,
            0, 32, 3, /* 4434: struct.x509_lookup_st */
            	4443, 8,
            	246, 16,
            	4486, 24,
            1, 8, 1, /* 4443: pointer.struct.x509_lookup_method_st */
            	4448, 0,
            0, 80, 10, /* 4448: struct.x509_lookup_method_st */
            	5, 0,
            	4471, 8,
            	2609, 16,
            	4471, 24,
            	4471, 32,
            	4474, 40,
            	4477, 48,
            	3724, 56,
            	4480, 64,
            	4483, 72,
            8884097, 8, 0, /* 4471: pointer.func */
            8884097, 8, 0, /* 4474: pointer.func */
            8884097, 8, 0, /* 4477: pointer.func */
            8884097, 8, 0, /* 4480: pointer.func */
            8884097, 8, 0, /* 4483: pointer.func */
            1, 8, 1, /* 4486: pointer.struct.x509_store_st */
            	4491, 0,
            0, 144, 15, /* 4491: struct.x509_store_st */
            	4524, 8,
            	4548, 16,
            	4572, 24,
            	4584, 32,
            	4587, 40,
            	3713, 48,
            	2226, 56,
            	4584, 64,
            	4590, 72,
            	4593, 80,
            	4596, 88,
            	3198, 96,
            	3095, 104,
            	4584, 112,
            	2037, 120,
            1, 8, 1, /* 4524: pointer.struct.stack_st_X509_OBJECT */
            	4529, 0,
            0, 32, 2, /* 4529: struct.stack_st_fake_X509_OBJECT */
            	4536, 8,
            	406, 24,
            8884099, 8, 2, /* 4536: pointer_to_array_of_pointers_to_stack */
            	4543, 0,
            	403, 20,
            0, 8, 1, /* 4543: pointer.X509_OBJECT */
            	4319, 0,
            1, 8, 1, /* 4548: pointer.struct.stack_st_X509_LOOKUP */
            	4553, 0,
            0, 32, 2, /* 4553: struct.stack_st_fake_X509_LOOKUP */
            	4560, 8,
            	406, 24,
            8884099, 8, 2, /* 4560: pointer_to_array_of_pointers_to_stack */
            	4567, 0,
            	403, 20,
            0, 8, 1, /* 4567: pointer.X509_LOOKUP */
            	4429, 0,
            1, 8, 1, /* 4572: pointer.struct.X509_VERIFY_PARAM_st */
            	4577, 0,
            0, 56, 2, /* 4577: struct.X509_VERIFY_PARAM_st */
            	246, 0,
            	3655, 48,
            8884097, 8, 0, /* 4584: pointer.func */
            8884097, 8, 0, /* 4587: pointer.func */
            8884097, 8, 0, /* 4590: pointer.func */
            8884097, 8, 0, /* 4593: pointer.func */
            8884097, 8, 0, /* 4596: pointer.func */
            1, 8, 1, /* 4599: pointer.struct.X509_VERIFY_PARAM_st */
            	4604, 0,
            0, 56, 2, /* 4604: struct.X509_VERIFY_PARAM_st */
            	246, 0,
            	1735, 48,
            8884097, 8, 0, /* 4611: pointer.func */
            8884097, 8, 0, /* 4614: pointer.func */
            8884097, 8, 0, /* 4617: pointer.func */
            8884097, 8, 0, /* 4620: pointer.func */
            8884097, 8, 0, /* 4623: pointer.func */
            8884097, 8, 0, /* 4626: pointer.func */
            8884097, 8, 0, /* 4629: pointer.func */
            8884097, 8, 0, /* 4632: pointer.func */
            8884097, 8, 0, /* 4635: pointer.func */
            1, 8, 1, /* 4638: pointer.struct.lhash_st */
            	4643, 0,
            0, 176, 3, /* 4643: struct.lhash_st */
            	4652, 0,
            	406, 8,
            	3092, 16,
            1, 8, 1, /* 4652: pointer.pointer.struct.lhash_node_st */
            	4657, 0,
            1, 8, 1, /* 4657: pointer.struct.lhash_node_st */
            	4662, 0,
            0, 24, 2, /* 4662: struct.lhash_node_st */
            	3129, 0,
            	4669, 8,
            1, 8, 1, /* 4669: pointer.struct.lhash_node_st */
            	4662, 0,
            1, 8, 1, /* 4674: pointer.struct.ssl_session_st */
            	4679, 0,
            0, 352, 14, /* 4679: struct.ssl_session_st */
            	246, 144,
            	246, 152,
            	4710, 168,
            	82, 176,
            	2027, 224,
            	4106, 240,
            	610, 248,
            	4674, 264,
            	4674, 272,
            	246, 280,
            	154, 296,
            	154, 312,
            	154, 320,
            	246, 344,
            1, 8, 1, /* 4710: pointer.struct.sess_cert_st */
            	4715, 0,
            0, 248, 5, /* 4715: struct.sess_cert_st */
            	3730, 0,
            	68, 16,
            	1859, 216,
            	1867, 224,
            	1872, 232,
            8884097, 8, 0, /* 4728: pointer.func */
            1, 8, 1, /* 4731: pointer.struct.stack_st_X509_NAME */
            	4736, 0,
            0, 32, 2, /* 4736: struct.stack_st_fake_X509_NAME */
            	4743, 8,
            	406, 24,
            8884099, 8, 2, /* 4743: pointer_to_array_of_pointers_to_stack */
            	4750, 0,
            	403, 20,
            0, 8, 1, /* 4750: pointer.X509_NAME */
            	1885, 0,
            8884097, 8, 0, /* 4755: pointer.func */
            8884097, 8, 0, /* 4758: pointer.func */
            8884097, 8, 0, /* 4761: pointer.func */
            1, 8, 1, /* 4764: pointer.struct.ssl_ctx_st */
            	4154, 0,
        },
        .arg_entity_index = { 4764, 5, 403, },
        .ret_entity_index = 403,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *,const char *,int);
    orig_SSL_CTX_use_PrivateKey_file = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey_file");
    *new_ret_ptr = (*orig_SSL_CTX_use_PrivateKey_file)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

