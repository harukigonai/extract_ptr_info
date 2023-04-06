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

SSL * bb_SSL_new(SSL_CTX * arg_a);

SSL * SSL_new(SSL_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_new called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_new(arg_a);
    else {
        SSL * (*orig_SSL_new)(SSL_CTX *);
        orig_SSL_new = dlsym(RTLD_NEXT, "SSL_new");
        return orig_SSL_new(arg_a);
    }
}

SSL * bb_SSL_new(SSL_CTX * arg_a) 
{
    SSL * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            8884097, 8, 0, /* 0: pointer.func */
            0, 24, 1, /* 3: struct.bignum_st */
            	8, 0,
            8884099, 8, 2, /* 8: pointer_to_array_of_pointers_to_stack */
            	15, 0,
            	18, 12,
            0, 4, 0, /* 15: unsigned int */
            0, 4, 0, /* 18: int */
            1, 8, 1, /* 21: pointer.struct.bignum_st */
            	3, 0,
            0, 128, 14, /* 26: struct.srp_ctx_st */
            	57, 0,
            	60, 8,
            	63, 16,
            	66, 24,
            	69, 32,
            	21, 40,
            	21, 48,
            	21, 56,
            	21, 64,
            	21, 72,
            	21, 80,
            	21, 88,
            	21, 96,
            	69, 104,
            0, 8, 0, /* 57: pointer.void */
            8884097, 8, 0, /* 60: pointer.func */
            8884097, 8, 0, /* 63: pointer.func */
            8884097, 8, 0, /* 66: pointer.func */
            1, 8, 1, /* 69: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 74: pointer.func */
            1, 8, 1, /* 77: pointer.struct.cert_st */
            	82, 0,
            0, 296, 7, /* 82: struct.cert_st */
            	99, 0,
            	3877, 48,
            	3882, 56,
            	3885, 64,
            	3890, 72,
            	3893, 80,
            	3898, 88,
            1, 8, 1, /* 99: pointer.struct.cert_pkey_st */
            	104, 0,
            0, 24, 3, /* 104: struct.cert_pkey_st */
            	113, 0,
            	3749, 8,
            	3832, 16,
            1, 8, 1, /* 113: pointer.struct.x509_st */
            	118, 0,
            0, 184, 12, /* 118: struct.x509_st */
            	145, 0,
            	193, 8,
            	2347, 16,
            	69, 32,
            	2417, 40,
            	2439, 104,
            	2444, 112,
            	2767, 120,
            	3198, 128,
            	3337, 136,
            	3361, 144,
            	3673, 176,
            1, 8, 1, /* 145: pointer.struct.x509_cinf_st */
            	150, 0,
            0, 104, 11, /* 150: struct.x509_cinf_st */
            	175, 0,
            	175, 8,
            	193, 16,
            	370, 24,
            	457, 32,
            	370, 40,
            	474, 48,
            	2347, 56,
            	2347, 64,
            	2352, 72,
            	2412, 80,
            1, 8, 1, /* 175: pointer.struct.asn1_string_st */
            	180, 0,
            0, 24, 1, /* 180: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 185: pointer.unsigned char */
            	190, 0,
            0, 1, 0, /* 190: unsigned char */
            1, 8, 1, /* 193: pointer.struct.X509_algor_st */
            	198, 0,
            0, 16, 2, /* 198: struct.X509_algor_st */
            	205, 0,
            	229, 8,
            1, 8, 1, /* 205: pointer.struct.asn1_object_st */
            	210, 0,
            0, 40, 3, /* 210: struct.asn1_object_st */
            	219, 0,
            	219, 8,
            	224, 24,
            1, 8, 1, /* 219: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 224: pointer.unsigned char */
            	190, 0,
            1, 8, 1, /* 229: pointer.struct.asn1_type_st */
            	234, 0,
            0, 16, 1, /* 234: struct.asn1_type_st */
            	239, 8,
            0, 8, 20, /* 239: union.unknown */
            	69, 0,
            	282, 0,
            	205, 0,
            	292, 0,
            	297, 0,
            	302, 0,
            	307, 0,
            	312, 0,
            	317, 0,
            	322, 0,
            	327, 0,
            	332, 0,
            	337, 0,
            	342, 0,
            	347, 0,
            	352, 0,
            	357, 0,
            	282, 0,
            	282, 0,
            	362, 0,
            1, 8, 1, /* 282: pointer.struct.asn1_string_st */
            	287, 0,
            0, 24, 1, /* 287: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 292: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 297: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 302: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 307: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 312: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 317: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 322: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 327: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 332: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 337: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 342: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 347: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 352: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 357: pointer.struct.asn1_string_st */
            	287, 0,
            1, 8, 1, /* 362: pointer.struct.ASN1_VALUE_st */
            	367, 0,
            0, 0, 0, /* 367: struct.ASN1_VALUE_st */
            1, 8, 1, /* 370: pointer.struct.X509_name_st */
            	375, 0,
            0, 40, 3, /* 375: struct.X509_name_st */
            	384, 0,
            	447, 16,
            	185, 24,
            1, 8, 1, /* 384: pointer.struct.stack_st_X509_NAME_ENTRY */
            	389, 0,
            0, 32, 2, /* 389: struct.stack_st_fake_X509_NAME_ENTRY */
            	396, 8,
            	444, 24,
            8884099, 8, 2, /* 396: pointer_to_array_of_pointers_to_stack */
            	403, 0,
            	18, 20,
            0, 8, 1, /* 403: pointer.X509_NAME_ENTRY */
            	408, 0,
            0, 0, 1, /* 408: X509_NAME_ENTRY */
            	413, 0,
            0, 24, 2, /* 413: struct.X509_name_entry_st */
            	420, 0,
            	434, 8,
            1, 8, 1, /* 420: pointer.struct.asn1_object_st */
            	425, 0,
            0, 40, 3, /* 425: struct.asn1_object_st */
            	219, 0,
            	219, 8,
            	224, 24,
            1, 8, 1, /* 434: pointer.struct.asn1_string_st */
            	439, 0,
            0, 24, 1, /* 439: struct.asn1_string_st */
            	185, 8,
            8884097, 8, 0, /* 444: pointer.func */
            1, 8, 1, /* 447: pointer.struct.buf_mem_st */
            	452, 0,
            0, 24, 1, /* 452: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 457: pointer.struct.X509_val_st */
            	462, 0,
            0, 16, 2, /* 462: struct.X509_val_st */
            	469, 0,
            	469, 8,
            1, 8, 1, /* 469: pointer.struct.asn1_string_st */
            	180, 0,
            1, 8, 1, /* 474: pointer.struct.X509_pubkey_st */
            	479, 0,
            0, 24, 3, /* 479: struct.X509_pubkey_st */
            	488, 0,
            	493, 8,
            	503, 16,
            1, 8, 1, /* 488: pointer.struct.X509_algor_st */
            	198, 0,
            1, 8, 1, /* 493: pointer.struct.asn1_string_st */
            	498, 0,
            0, 24, 1, /* 498: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 503: pointer.struct.evp_pkey_st */
            	508, 0,
            0, 56, 4, /* 508: struct.evp_pkey_st */
            	519, 16,
            	620, 24,
            	973, 32,
            	1976, 48,
            1, 8, 1, /* 519: pointer.struct.evp_pkey_asn1_method_st */
            	524, 0,
            0, 208, 24, /* 524: struct.evp_pkey_asn1_method_st */
            	69, 16,
            	69, 24,
            	575, 32,
            	578, 40,
            	581, 48,
            	584, 56,
            	587, 64,
            	590, 72,
            	584, 80,
            	593, 88,
            	593, 96,
            	596, 104,
            	599, 112,
            	593, 120,
            	602, 128,
            	581, 136,
            	584, 144,
            	605, 152,
            	608, 160,
            	611, 168,
            	596, 176,
            	599, 184,
            	614, 192,
            	617, 200,
            8884097, 8, 0, /* 575: pointer.func */
            8884097, 8, 0, /* 578: pointer.func */
            8884097, 8, 0, /* 581: pointer.func */
            8884097, 8, 0, /* 584: pointer.func */
            8884097, 8, 0, /* 587: pointer.func */
            8884097, 8, 0, /* 590: pointer.func */
            8884097, 8, 0, /* 593: pointer.func */
            8884097, 8, 0, /* 596: pointer.func */
            8884097, 8, 0, /* 599: pointer.func */
            8884097, 8, 0, /* 602: pointer.func */
            8884097, 8, 0, /* 605: pointer.func */
            8884097, 8, 0, /* 608: pointer.func */
            8884097, 8, 0, /* 611: pointer.func */
            8884097, 8, 0, /* 614: pointer.func */
            8884097, 8, 0, /* 617: pointer.func */
            1, 8, 1, /* 620: pointer.struct.engine_st */
            	625, 0,
            0, 216, 24, /* 625: struct.engine_st */
            	219, 0,
            	219, 8,
            	676, 16,
            	731, 24,
            	782, 32,
            	818, 40,
            	835, 48,
            	862, 56,
            	897, 64,
            	905, 72,
            	908, 80,
            	911, 88,
            	914, 96,
            	917, 104,
            	917, 112,
            	917, 120,
            	920, 128,
            	923, 136,
            	923, 144,
            	926, 152,
            	929, 160,
            	941, 184,
            	968, 200,
            	968, 208,
            1, 8, 1, /* 676: pointer.struct.rsa_meth_st */
            	681, 0,
            0, 112, 13, /* 681: struct.rsa_meth_st */
            	219, 0,
            	710, 8,
            	710, 16,
            	710, 24,
            	710, 32,
            	713, 40,
            	716, 48,
            	719, 56,
            	719, 64,
            	69, 80,
            	722, 88,
            	725, 96,
            	728, 104,
            8884097, 8, 0, /* 710: pointer.func */
            8884097, 8, 0, /* 713: pointer.func */
            8884097, 8, 0, /* 716: pointer.func */
            8884097, 8, 0, /* 719: pointer.func */
            8884097, 8, 0, /* 722: pointer.func */
            8884097, 8, 0, /* 725: pointer.func */
            8884097, 8, 0, /* 728: pointer.func */
            1, 8, 1, /* 731: pointer.struct.dsa_method */
            	736, 0,
            0, 96, 11, /* 736: struct.dsa_method */
            	219, 0,
            	761, 8,
            	764, 16,
            	767, 24,
            	770, 32,
            	773, 40,
            	776, 48,
            	776, 56,
            	69, 72,
            	779, 80,
            	776, 88,
            8884097, 8, 0, /* 761: pointer.func */
            8884097, 8, 0, /* 764: pointer.func */
            8884097, 8, 0, /* 767: pointer.func */
            8884097, 8, 0, /* 770: pointer.func */
            8884097, 8, 0, /* 773: pointer.func */
            8884097, 8, 0, /* 776: pointer.func */
            8884097, 8, 0, /* 779: pointer.func */
            1, 8, 1, /* 782: pointer.struct.dh_method */
            	787, 0,
            0, 72, 8, /* 787: struct.dh_method */
            	219, 0,
            	806, 8,
            	809, 16,
            	812, 24,
            	806, 32,
            	806, 40,
            	69, 56,
            	815, 64,
            8884097, 8, 0, /* 806: pointer.func */
            8884097, 8, 0, /* 809: pointer.func */
            8884097, 8, 0, /* 812: pointer.func */
            8884097, 8, 0, /* 815: pointer.func */
            1, 8, 1, /* 818: pointer.struct.ecdh_method */
            	823, 0,
            0, 32, 3, /* 823: struct.ecdh_method */
            	219, 0,
            	832, 8,
            	69, 24,
            8884097, 8, 0, /* 832: pointer.func */
            1, 8, 1, /* 835: pointer.struct.ecdsa_method */
            	840, 0,
            0, 48, 5, /* 840: struct.ecdsa_method */
            	219, 0,
            	853, 8,
            	856, 16,
            	859, 24,
            	69, 40,
            8884097, 8, 0, /* 853: pointer.func */
            8884097, 8, 0, /* 856: pointer.func */
            8884097, 8, 0, /* 859: pointer.func */
            1, 8, 1, /* 862: pointer.struct.rand_meth_st */
            	867, 0,
            0, 48, 6, /* 867: struct.rand_meth_st */
            	882, 0,
            	885, 8,
            	888, 16,
            	891, 24,
            	885, 32,
            	894, 40,
            8884097, 8, 0, /* 882: pointer.func */
            8884097, 8, 0, /* 885: pointer.func */
            8884097, 8, 0, /* 888: pointer.func */
            8884097, 8, 0, /* 891: pointer.func */
            8884097, 8, 0, /* 894: pointer.func */
            1, 8, 1, /* 897: pointer.struct.store_method_st */
            	902, 0,
            0, 0, 0, /* 902: struct.store_method_st */
            8884097, 8, 0, /* 905: pointer.func */
            8884097, 8, 0, /* 908: pointer.func */
            8884097, 8, 0, /* 911: pointer.func */
            8884097, 8, 0, /* 914: pointer.func */
            8884097, 8, 0, /* 917: pointer.func */
            8884097, 8, 0, /* 920: pointer.func */
            8884097, 8, 0, /* 923: pointer.func */
            8884097, 8, 0, /* 926: pointer.func */
            1, 8, 1, /* 929: pointer.struct.ENGINE_CMD_DEFN_st */
            	934, 0,
            0, 32, 2, /* 934: struct.ENGINE_CMD_DEFN_st */
            	219, 8,
            	219, 16,
            0, 16, 1, /* 941: struct.crypto_ex_data_st */
            	946, 0,
            1, 8, 1, /* 946: pointer.struct.stack_st_void */
            	951, 0,
            0, 32, 1, /* 951: struct.stack_st_void */
            	956, 0,
            0, 32, 2, /* 956: struct.stack_st */
            	963, 8,
            	444, 24,
            1, 8, 1, /* 963: pointer.pointer.char */
            	69, 0,
            1, 8, 1, /* 968: pointer.struct.engine_st */
            	625, 0,
            0, 8, 5, /* 973: union.unknown */
            	69, 0,
            	986, 0,
            	1202, 0,
            	1341, 0,
            	1467, 0,
            1, 8, 1, /* 986: pointer.struct.rsa_st */
            	991, 0,
            0, 168, 17, /* 991: struct.rsa_st */
            	1028, 16,
            	1083, 24,
            	1088, 32,
            	1088, 40,
            	1088, 48,
            	1088, 56,
            	1088, 64,
            	1088, 72,
            	1088, 80,
            	1088, 88,
            	1105, 96,
            	1127, 120,
            	1127, 128,
            	1127, 136,
            	69, 144,
            	1141, 152,
            	1141, 160,
            1, 8, 1, /* 1028: pointer.struct.rsa_meth_st */
            	1033, 0,
            0, 112, 13, /* 1033: struct.rsa_meth_st */
            	219, 0,
            	1062, 8,
            	1062, 16,
            	1062, 24,
            	1062, 32,
            	1065, 40,
            	1068, 48,
            	1071, 56,
            	1071, 64,
            	69, 80,
            	1074, 88,
            	1077, 96,
            	1080, 104,
            8884097, 8, 0, /* 1062: pointer.func */
            8884097, 8, 0, /* 1065: pointer.func */
            8884097, 8, 0, /* 1068: pointer.func */
            8884097, 8, 0, /* 1071: pointer.func */
            8884097, 8, 0, /* 1074: pointer.func */
            8884097, 8, 0, /* 1077: pointer.func */
            8884097, 8, 0, /* 1080: pointer.func */
            1, 8, 1, /* 1083: pointer.struct.engine_st */
            	625, 0,
            1, 8, 1, /* 1088: pointer.struct.bignum_st */
            	1093, 0,
            0, 24, 1, /* 1093: struct.bignum_st */
            	1098, 0,
            8884099, 8, 2, /* 1098: pointer_to_array_of_pointers_to_stack */
            	15, 0,
            	18, 12,
            0, 16, 1, /* 1105: struct.crypto_ex_data_st */
            	1110, 0,
            1, 8, 1, /* 1110: pointer.struct.stack_st_void */
            	1115, 0,
            0, 32, 1, /* 1115: struct.stack_st_void */
            	1120, 0,
            0, 32, 2, /* 1120: struct.stack_st */
            	963, 8,
            	444, 24,
            1, 8, 1, /* 1127: pointer.struct.bn_mont_ctx_st */
            	1132, 0,
            0, 96, 3, /* 1132: struct.bn_mont_ctx_st */
            	1093, 8,
            	1093, 32,
            	1093, 56,
            1, 8, 1, /* 1141: pointer.struct.bn_blinding_st */
            	1146, 0,
            0, 88, 7, /* 1146: struct.bn_blinding_st */
            	1163, 0,
            	1163, 8,
            	1163, 16,
            	1163, 24,
            	1180, 40,
            	1185, 72,
            	1199, 80,
            1, 8, 1, /* 1163: pointer.struct.bignum_st */
            	1168, 0,
            0, 24, 1, /* 1168: struct.bignum_st */
            	1173, 0,
            8884099, 8, 2, /* 1173: pointer_to_array_of_pointers_to_stack */
            	15, 0,
            	18, 12,
            0, 16, 1, /* 1180: struct.crypto_threadid_st */
            	57, 0,
            1, 8, 1, /* 1185: pointer.struct.bn_mont_ctx_st */
            	1190, 0,
            0, 96, 3, /* 1190: struct.bn_mont_ctx_st */
            	1168, 8,
            	1168, 32,
            	1168, 56,
            8884097, 8, 0, /* 1199: pointer.func */
            1, 8, 1, /* 1202: pointer.struct.dsa_st */
            	1207, 0,
            0, 136, 11, /* 1207: struct.dsa_st */
            	1232, 24,
            	1232, 32,
            	1232, 40,
            	1232, 48,
            	1232, 56,
            	1232, 64,
            	1232, 72,
            	1249, 88,
            	1263, 104,
            	1285, 120,
            	1336, 128,
            1, 8, 1, /* 1232: pointer.struct.bignum_st */
            	1237, 0,
            0, 24, 1, /* 1237: struct.bignum_st */
            	1242, 0,
            8884099, 8, 2, /* 1242: pointer_to_array_of_pointers_to_stack */
            	15, 0,
            	18, 12,
            1, 8, 1, /* 1249: pointer.struct.bn_mont_ctx_st */
            	1254, 0,
            0, 96, 3, /* 1254: struct.bn_mont_ctx_st */
            	1237, 8,
            	1237, 32,
            	1237, 56,
            0, 16, 1, /* 1263: struct.crypto_ex_data_st */
            	1268, 0,
            1, 8, 1, /* 1268: pointer.struct.stack_st_void */
            	1273, 0,
            0, 32, 1, /* 1273: struct.stack_st_void */
            	1278, 0,
            0, 32, 2, /* 1278: struct.stack_st */
            	963, 8,
            	444, 24,
            1, 8, 1, /* 1285: pointer.struct.dsa_method */
            	1290, 0,
            0, 96, 11, /* 1290: struct.dsa_method */
            	219, 0,
            	1315, 8,
            	1318, 16,
            	1321, 24,
            	1324, 32,
            	1327, 40,
            	1330, 48,
            	1330, 56,
            	69, 72,
            	1333, 80,
            	1330, 88,
            8884097, 8, 0, /* 1315: pointer.func */
            8884097, 8, 0, /* 1318: pointer.func */
            8884097, 8, 0, /* 1321: pointer.func */
            8884097, 8, 0, /* 1324: pointer.func */
            8884097, 8, 0, /* 1327: pointer.func */
            8884097, 8, 0, /* 1330: pointer.func */
            8884097, 8, 0, /* 1333: pointer.func */
            1, 8, 1, /* 1336: pointer.struct.engine_st */
            	625, 0,
            1, 8, 1, /* 1341: pointer.struct.dh_st */
            	1346, 0,
            0, 144, 12, /* 1346: struct.dh_st */
            	1373, 8,
            	1373, 16,
            	1373, 32,
            	1373, 40,
            	1390, 56,
            	1373, 64,
            	1373, 72,
            	185, 80,
            	1373, 96,
            	1404, 112,
            	1426, 128,
            	1462, 136,
            1, 8, 1, /* 1373: pointer.struct.bignum_st */
            	1378, 0,
            0, 24, 1, /* 1378: struct.bignum_st */
            	1383, 0,
            8884099, 8, 2, /* 1383: pointer_to_array_of_pointers_to_stack */
            	15, 0,
            	18, 12,
            1, 8, 1, /* 1390: pointer.struct.bn_mont_ctx_st */
            	1395, 0,
            0, 96, 3, /* 1395: struct.bn_mont_ctx_st */
            	1378, 8,
            	1378, 32,
            	1378, 56,
            0, 16, 1, /* 1404: struct.crypto_ex_data_st */
            	1409, 0,
            1, 8, 1, /* 1409: pointer.struct.stack_st_void */
            	1414, 0,
            0, 32, 1, /* 1414: struct.stack_st_void */
            	1419, 0,
            0, 32, 2, /* 1419: struct.stack_st */
            	963, 8,
            	444, 24,
            1, 8, 1, /* 1426: pointer.struct.dh_method */
            	1431, 0,
            0, 72, 8, /* 1431: struct.dh_method */
            	219, 0,
            	1450, 8,
            	1453, 16,
            	1456, 24,
            	1450, 32,
            	1450, 40,
            	69, 56,
            	1459, 64,
            8884097, 8, 0, /* 1450: pointer.func */
            8884097, 8, 0, /* 1453: pointer.func */
            8884097, 8, 0, /* 1456: pointer.func */
            8884097, 8, 0, /* 1459: pointer.func */
            1, 8, 1, /* 1462: pointer.struct.engine_st */
            	625, 0,
            1, 8, 1, /* 1467: pointer.struct.ec_key_st */
            	1472, 0,
            0, 56, 4, /* 1472: struct.ec_key_st */
            	1483, 8,
            	1931, 16,
            	1936, 24,
            	1953, 48,
            1, 8, 1, /* 1483: pointer.struct.ec_group_st */
            	1488, 0,
            0, 232, 12, /* 1488: struct.ec_group_st */
            	1515, 0,
            	1687, 8,
            	1887, 16,
            	1887, 40,
            	185, 80,
            	1899, 96,
            	1887, 104,
            	1887, 152,
            	1887, 176,
            	57, 208,
            	57, 216,
            	1928, 224,
            1, 8, 1, /* 1515: pointer.struct.ec_method_st */
            	1520, 0,
            0, 304, 37, /* 1520: struct.ec_method_st */
            	1597, 8,
            	1600, 16,
            	1600, 24,
            	1603, 32,
            	1606, 40,
            	1609, 48,
            	1612, 56,
            	1615, 64,
            	1618, 72,
            	1621, 80,
            	1621, 88,
            	1624, 96,
            	1627, 104,
            	1630, 112,
            	1633, 120,
            	1636, 128,
            	1639, 136,
            	1642, 144,
            	1645, 152,
            	1648, 160,
            	1651, 168,
            	1654, 176,
            	1657, 184,
            	1660, 192,
            	1663, 200,
            	1666, 208,
            	1657, 216,
            	1669, 224,
            	1672, 232,
            	1675, 240,
            	1612, 248,
            	1678, 256,
            	1681, 264,
            	1678, 272,
            	1681, 280,
            	1681, 288,
            	1684, 296,
            8884097, 8, 0, /* 1597: pointer.func */
            8884097, 8, 0, /* 1600: pointer.func */
            8884097, 8, 0, /* 1603: pointer.func */
            8884097, 8, 0, /* 1606: pointer.func */
            8884097, 8, 0, /* 1609: pointer.func */
            8884097, 8, 0, /* 1612: pointer.func */
            8884097, 8, 0, /* 1615: pointer.func */
            8884097, 8, 0, /* 1618: pointer.func */
            8884097, 8, 0, /* 1621: pointer.func */
            8884097, 8, 0, /* 1624: pointer.func */
            8884097, 8, 0, /* 1627: pointer.func */
            8884097, 8, 0, /* 1630: pointer.func */
            8884097, 8, 0, /* 1633: pointer.func */
            8884097, 8, 0, /* 1636: pointer.func */
            8884097, 8, 0, /* 1639: pointer.func */
            8884097, 8, 0, /* 1642: pointer.func */
            8884097, 8, 0, /* 1645: pointer.func */
            8884097, 8, 0, /* 1648: pointer.func */
            8884097, 8, 0, /* 1651: pointer.func */
            8884097, 8, 0, /* 1654: pointer.func */
            8884097, 8, 0, /* 1657: pointer.func */
            8884097, 8, 0, /* 1660: pointer.func */
            8884097, 8, 0, /* 1663: pointer.func */
            8884097, 8, 0, /* 1666: pointer.func */
            8884097, 8, 0, /* 1669: pointer.func */
            8884097, 8, 0, /* 1672: pointer.func */
            8884097, 8, 0, /* 1675: pointer.func */
            8884097, 8, 0, /* 1678: pointer.func */
            8884097, 8, 0, /* 1681: pointer.func */
            8884097, 8, 0, /* 1684: pointer.func */
            1, 8, 1, /* 1687: pointer.struct.ec_point_st */
            	1692, 0,
            0, 88, 4, /* 1692: struct.ec_point_st */
            	1703, 0,
            	1875, 8,
            	1875, 32,
            	1875, 56,
            1, 8, 1, /* 1703: pointer.struct.ec_method_st */
            	1708, 0,
            0, 304, 37, /* 1708: struct.ec_method_st */
            	1785, 8,
            	1788, 16,
            	1788, 24,
            	1791, 32,
            	1794, 40,
            	1797, 48,
            	1800, 56,
            	1803, 64,
            	1806, 72,
            	1809, 80,
            	1809, 88,
            	1812, 96,
            	1815, 104,
            	1818, 112,
            	1821, 120,
            	1824, 128,
            	1827, 136,
            	1830, 144,
            	1833, 152,
            	1836, 160,
            	1839, 168,
            	1842, 176,
            	1845, 184,
            	1848, 192,
            	1851, 200,
            	1854, 208,
            	1845, 216,
            	1857, 224,
            	1860, 232,
            	1863, 240,
            	1800, 248,
            	1866, 256,
            	1869, 264,
            	1866, 272,
            	1869, 280,
            	1869, 288,
            	1872, 296,
            8884097, 8, 0, /* 1785: pointer.func */
            8884097, 8, 0, /* 1788: pointer.func */
            8884097, 8, 0, /* 1791: pointer.func */
            8884097, 8, 0, /* 1794: pointer.func */
            8884097, 8, 0, /* 1797: pointer.func */
            8884097, 8, 0, /* 1800: pointer.func */
            8884097, 8, 0, /* 1803: pointer.func */
            8884097, 8, 0, /* 1806: pointer.func */
            8884097, 8, 0, /* 1809: pointer.func */
            8884097, 8, 0, /* 1812: pointer.func */
            8884097, 8, 0, /* 1815: pointer.func */
            8884097, 8, 0, /* 1818: pointer.func */
            8884097, 8, 0, /* 1821: pointer.func */
            8884097, 8, 0, /* 1824: pointer.func */
            8884097, 8, 0, /* 1827: pointer.func */
            8884097, 8, 0, /* 1830: pointer.func */
            8884097, 8, 0, /* 1833: pointer.func */
            8884097, 8, 0, /* 1836: pointer.func */
            8884097, 8, 0, /* 1839: pointer.func */
            8884097, 8, 0, /* 1842: pointer.func */
            8884097, 8, 0, /* 1845: pointer.func */
            8884097, 8, 0, /* 1848: pointer.func */
            8884097, 8, 0, /* 1851: pointer.func */
            8884097, 8, 0, /* 1854: pointer.func */
            8884097, 8, 0, /* 1857: pointer.func */
            8884097, 8, 0, /* 1860: pointer.func */
            8884097, 8, 0, /* 1863: pointer.func */
            8884097, 8, 0, /* 1866: pointer.func */
            8884097, 8, 0, /* 1869: pointer.func */
            8884097, 8, 0, /* 1872: pointer.func */
            0, 24, 1, /* 1875: struct.bignum_st */
            	1880, 0,
            8884099, 8, 2, /* 1880: pointer_to_array_of_pointers_to_stack */
            	15, 0,
            	18, 12,
            0, 24, 1, /* 1887: struct.bignum_st */
            	1892, 0,
            8884099, 8, 2, /* 1892: pointer_to_array_of_pointers_to_stack */
            	15, 0,
            	18, 12,
            1, 8, 1, /* 1899: pointer.struct.ec_extra_data_st */
            	1904, 0,
            0, 40, 5, /* 1904: struct.ec_extra_data_st */
            	1917, 0,
            	57, 8,
            	1922, 16,
            	1925, 24,
            	1925, 32,
            1, 8, 1, /* 1917: pointer.struct.ec_extra_data_st */
            	1904, 0,
            8884097, 8, 0, /* 1922: pointer.func */
            8884097, 8, 0, /* 1925: pointer.func */
            8884097, 8, 0, /* 1928: pointer.func */
            1, 8, 1, /* 1931: pointer.struct.ec_point_st */
            	1692, 0,
            1, 8, 1, /* 1936: pointer.struct.bignum_st */
            	1941, 0,
            0, 24, 1, /* 1941: struct.bignum_st */
            	1946, 0,
            8884099, 8, 2, /* 1946: pointer_to_array_of_pointers_to_stack */
            	15, 0,
            	18, 12,
            1, 8, 1, /* 1953: pointer.struct.ec_extra_data_st */
            	1958, 0,
            0, 40, 5, /* 1958: struct.ec_extra_data_st */
            	1971, 0,
            	57, 8,
            	1922, 16,
            	1925, 24,
            	1925, 32,
            1, 8, 1, /* 1971: pointer.struct.ec_extra_data_st */
            	1958, 0,
            1, 8, 1, /* 1976: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1981, 0,
            0, 32, 2, /* 1981: struct.stack_st_fake_X509_ATTRIBUTE */
            	1988, 8,
            	444, 24,
            8884099, 8, 2, /* 1988: pointer_to_array_of_pointers_to_stack */
            	1995, 0,
            	18, 20,
            0, 8, 1, /* 1995: pointer.X509_ATTRIBUTE */
            	2000, 0,
            0, 0, 1, /* 2000: X509_ATTRIBUTE */
            	2005, 0,
            0, 24, 2, /* 2005: struct.x509_attributes_st */
            	2012, 0,
            	2026, 16,
            1, 8, 1, /* 2012: pointer.struct.asn1_object_st */
            	2017, 0,
            0, 40, 3, /* 2017: struct.asn1_object_st */
            	219, 0,
            	219, 8,
            	224, 24,
            0, 8, 3, /* 2026: union.unknown */
            	69, 0,
            	2035, 0,
            	2214, 0,
            1, 8, 1, /* 2035: pointer.struct.stack_st_ASN1_TYPE */
            	2040, 0,
            0, 32, 2, /* 2040: struct.stack_st_fake_ASN1_TYPE */
            	2047, 8,
            	444, 24,
            8884099, 8, 2, /* 2047: pointer_to_array_of_pointers_to_stack */
            	2054, 0,
            	18, 20,
            0, 8, 1, /* 2054: pointer.ASN1_TYPE */
            	2059, 0,
            0, 0, 1, /* 2059: ASN1_TYPE */
            	2064, 0,
            0, 16, 1, /* 2064: struct.asn1_type_st */
            	2069, 8,
            0, 8, 20, /* 2069: union.unknown */
            	69, 0,
            	2112, 0,
            	2122, 0,
            	2136, 0,
            	2141, 0,
            	2146, 0,
            	2151, 0,
            	2156, 0,
            	2161, 0,
            	2166, 0,
            	2171, 0,
            	2176, 0,
            	2181, 0,
            	2186, 0,
            	2191, 0,
            	2196, 0,
            	2201, 0,
            	2112, 0,
            	2112, 0,
            	2206, 0,
            1, 8, 1, /* 2112: pointer.struct.asn1_string_st */
            	2117, 0,
            0, 24, 1, /* 2117: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 2122: pointer.struct.asn1_object_st */
            	2127, 0,
            0, 40, 3, /* 2127: struct.asn1_object_st */
            	219, 0,
            	219, 8,
            	224, 24,
            1, 8, 1, /* 2136: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2141: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2146: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2151: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2156: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2161: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2166: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2171: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2176: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2181: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2186: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2191: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2196: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2201: pointer.struct.asn1_string_st */
            	2117, 0,
            1, 8, 1, /* 2206: pointer.struct.ASN1_VALUE_st */
            	2211, 0,
            0, 0, 0, /* 2211: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2214: pointer.struct.asn1_type_st */
            	2219, 0,
            0, 16, 1, /* 2219: struct.asn1_type_st */
            	2224, 8,
            0, 8, 20, /* 2224: union.unknown */
            	69, 0,
            	2267, 0,
            	2012, 0,
            	2277, 0,
            	2282, 0,
            	2287, 0,
            	2292, 0,
            	2297, 0,
            	2302, 0,
            	2307, 0,
            	2312, 0,
            	2317, 0,
            	2322, 0,
            	2327, 0,
            	2332, 0,
            	2337, 0,
            	2342, 0,
            	2267, 0,
            	2267, 0,
            	362, 0,
            1, 8, 1, /* 2267: pointer.struct.asn1_string_st */
            	2272, 0,
            0, 24, 1, /* 2272: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 2277: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2282: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2287: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2292: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2297: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2302: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2307: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2312: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2317: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2322: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2327: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2332: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2337: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2342: pointer.struct.asn1_string_st */
            	2272, 0,
            1, 8, 1, /* 2347: pointer.struct.asn1_string_st */
            	180, 0,
            1, 8, 1, /* 2352: pointer.struct.stack_st_X509_EXTENSION */
            	2357, 0,
            0, 32, 2, /* 2357: struct.stack_st_fake_X509_EXTENSION */
            	2364, 8,
            	444, 24,
            8884099, 8, 2, /* 2364: pointer_to_array_of_pointers_to_stack */
            	2371, 0,
            	18, 20,
            0, 8, 1, /* 2371: pointer.X509_EXTENSION */
            	2376, 0,
            0, 0, 1, /* 2376: X509_EXTENSION */
            	2381, 0,
            0, 24, 2, /* 2381: struct.X509_extension_st */
            	2388, 0,
            	2402, 16,
            1, 8, 1, /* 2388: pointer.struct.asn1_object_st */
            	2393, 0,
            0, 40, 3, /* 2393: struct.asn1_object_st */
            	219, 0,
            	219, 8,
            	224, 24,
            1, 8, 1, /* 2402: pointer.struct.asn1_string_st */
            	2407, 0,
            0, 24, 1, /* 2407: struct.asn1_string_st */
            	185, 8,
            0, 24, 1, /* 2412: struct.ASN1_ENCODING_st */
            	185, 0,
            0, 16, 1, /* 2417: struct.crypto_ex_data_st */
            	2422, 0,
            1, 8, 1, /* 2422: pointer.struct.stack_st_void */
            	2427, 0,
            0, 32, 1, /* 2427: struct.stack_st_void */
            	2432, 0,
            0, 32, 2, /* 2432: struct.stack_st */
            	963, 8,
            	444, 24,
            1, 8, 1, /* 2439: pointer.struct.asn1_string_st */
            	180, 0,
            1, 8, 1, /* 2444: pointer.struct.AUTHORITY_KEYID_st */
            	2449, 0,
            0, 24, 3, /* 2449: struct.AUTHORITY_KEYID_st */
            	2458, 0,
            	2468, 8,
            	2762, 16,
            1, 8, 1, /* 2458: pointer.struct.asn1_string_st */
            	2463, 0,
            0, 24, 1, /* 2463: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 2468: pointer.struct.stack_st_GENERAL_NAME */
            	2473, 0,
            0, 32, 2, /* 2473: struct.stack_st_fake_GENERAL_NAME */
            	2480, 8,
            	444, 24,
            8884099, 8, 2, /* 2480: pointer_to_array_of_pointers_to_stack */
            	2487, 0,
            	18, 20,
            0, 8, 1, /* 2487: pointer.GENERAL_NAME */
            	2492, 0,
            0, 0, 1, /* 2492: GENERAL_NAME */
            	2497, 0,
            0, 16, 1, /* 2497: struct.GENERAL_NAME_st */
            	2502, 8,
            0, 8, 15, /* 2502: union.unknown */
            	69, 0,
            	2535, 0,
            	2654, 0,
            	2654, 0,
            	2561, 0,
            	2702, 0,
            	2750, 0,
            	2654, 0,
            	2639, 0,
            	2547, 0,
            	2639, 0,
            	2702, 0,
            	2654, 0,
            	2547, 0,
            	2561, 0,
            1, 8, 1, /* 2535: pointer.struct.otherName_st */
            	2540, 0,
            0, 16, 2, /* 2540: struct.otherName_st */
            	2547, 0,
            	2561, 8,
            1, 8, 1, /* 2547: pointer.struct.asn1_object_st */
            	2552, 0,
            0, 40, 3, /* 2552: struct.asn1_object_st */
            	219, 0,
            	219, 8,
            	224, 24,
            1, 8, 1, /* 2561: pointer.struct.asn1_type_st */
            	2566, 0,
            0, 16, 1, /* 2566: struct.asn1_type_st */
            	2571, 8,
            0, 8, 20, /* 2571: union.unknown */
            	69, 0,
            	2614, 0,
            	2547, 0,
            	2624, 0,
            	2629, 0,
            	2634, 0,
            	2639, 0,
            	2644, 0,
            	2649, 0,
            	2654, 0,
            	2659, 0,
            	2664, 0,
            	2669, 0,
            	2674, 0,
            	2679, 0,
            	2684, 0,
            	2689, 0,
            	2614, 0,
            	2614, 0,
            	2694, 0,
            1, 8, 1, /* 2614: pointer.struct.asn1_string_st */
            	2619, 0,
            0, 24, 1, /* 2619: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 2624: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2629: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2634: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2639: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2644: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2649: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2654: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2659: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2664: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2669: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2674: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2679: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2684: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2689: pointer.struct.asn1_string_st */
            	2619, 0,
            1, 8, 1, /* 2694: pointer.struct.ASN1_VALUE_st */
            	2699, 0,
            0, 0, 0, /* 2699: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2702: pointer.struct.X509_name_st */
            	2707, 0,
            0, 40, 3, /* 2707: struct.X509_name_st */
            	2716, 0,
            	2740, 16,
            	185, 24,
            1, 8, 1, /* 2716: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2721, 0,
            0, 32, 2, /* 2721: struct.stack_st_fake_X509_NAME_ENTRY */
            	2728, 8,
            	444, 24,
            8884099, 8, 2, /* 2728: pointer_to_array_of_pointers_to_stack */
            	2735, 0,
            	18, 20,
            0, 8, 1, /* 2735: pointer.X509_NAME_ENTRY */
            	408, 0,
            1, 8, 1, /* 2740: pointer.struct.buf_mem_st */
            	2745, 0,
            0, 24, 1, /* 2745: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 2750: pointer.struct.EDIPartyName_st */
            	2755, 0,
            0, 16, 2, /* 2755: struct.EDIPartyName_st */
            	2614, 0,
            	2614, 8,
            1, 8, 1, /* 2762: pointer.struct.asn1_string_st */
            	2463, 0,
            1, 8, 1, /* 2767: pointer.struct.X509_POLICY_CACHE_st */
            	2772, 0,
            0, 40, 2, /* 2772: struct.X509_POLICY_CACHE_st */
            	2779, 0,
            	3098, 8,
            1, 8, 1, /* 2779: pointer.struct.X509_POLICY_DATA_st */
            	2784, 0,
            0, 32, 3, /* 2784: struct.X509_POLICY_DATA_st */
            	2793, 8,
            	2807, 16,
            	3060, 24,
            1, 8, 1, /* 2793: pointer.struct.asn1_object_st */
            	2798, 0,
            0, 40, 3, /* 2798: struct.asn1_object_st */
            	219, 0,
            	219, 8,
            	224, 24,
            1, 8, 1, /* 2807: pointer.struct.stack_st_POLICYQUALINFO */
            	2812, 0,
            0, 32, 2, /* 2812: struct.stack_st_fake_POLICYQUALINFO */
            	2819, 8,
            	444, 24,
            8884099, 8, 2, /* 2819: pointer_to_array_of_pointers_to_stack */
            	2826, 0,
            	18, 20,
            0, 8, 1, /* 2826: pointer.POLICYQUALINFO */
            	2831, 0,
            0, 0, 1, /* 2831: POLICYQUALINFO */
            	2836, 0,
            0, 16, 2, /* 2836: struct.POLICYQUALINFO_st */
            	2843, 0,
            	2857, 8,
            1, 8, 1, /* 2843: pointer.struct.asn1_object_st */
            	2848, 0,
            0, 40, 3, /* 2848: struct.asn1_object_st */
            	219, 0,
            	219, 8,
            	224, 24,
            0, 8, 3, /* 2857: union.unknown */
            	2866, 0,
            	2876, 0,
            	2934, 0,
            1, 8, 1, /* 2866: pointer.struct.asn1_string_st */
            	2871, 0,
            0, 24, 1, /* 2871: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 2876: pointer.struct.USERNOTICE_st */
            	2881, 0,
            0, 16, 2, /* 2881: struct.USERNOTICE_st */
            	2888, 0,
            	2900, 8,
            1, 8, 1, /* 2888: pointer.struct.NOTICEREF_st */
            	2893, 0,
            0, 16, 2, /* 2893: struct.NOTICEREF_st */
            	2900, 0,
            	2905, 8,
            1, 8, 1, /* 2900: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 2905: pointer.struct.stack_st_ASN1_INTEGER */
            	2910, 0,
            0, 32, 2, /* 2910: struct.stack_st_fake_ASN1_INTEGER */
            	2917, 8,
            	444, 24,
            8884099, 8, 2, /* 2917: pointer_to_array_of_pointers_to_stack */
            	2924, 0,
            	18, 20,
            0, 8, 1, /* 2924: pointer.ASN1_INTEGER */
            	2929, 0,
            0, 0, 1, /* 2929: ASN1_INTEGER */
            	287, 0,
            1, 8, 1, /* 2934: pointer.struct.asn1_type_st */
            	2939, 0,
            0, 16, 1, /* 2939: struct.asn1_type_st */
            	2944, 8,
            0, 8, 20, /* 2944: union.unknown */
            	69, 0,
            	2900, 0,
            	2843, 0,
            	2987, 0,
            	2992, 0,
            	2997, 0,
            	3002, 0,
            	3007, 0,
            	3012, 0,
            	2866, 0,
            	3017, 0,
            	3022, 0,
            	3027, 0,
            	3032, 0,
            	3037, 0,
            	3042, 0,
            	3047, 0,
            	2900, 0,
            	2900, 0,
            	3052, 0,
            1, 8, 1, /* 2987: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 2992: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 2997: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 3002: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 3007: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 3012: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 3017: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 3022: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 3027: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 3032: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 3037: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 3042: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 3047: pointer.struct.asn1_string_st */
            	2871, 0,
            1, 8, 1, /* 3052: pointer.struct.ASN1_VALUE_st */
            	3057, 0,
            0, 0, 0, /* 3057: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3060: pointer.struct.stack_st_ASN1_OBJECT */
            	3065, 0,
            0, 32, 2, /* 3065: struct.stack_st_fake_ASN1_OBJECT */
            	3072, 8,
            	444, 24,
            8884099, 8, 2, /* 3072: pointer_to_array_of_pointers_to_stack */
            	3079, 0,
            	18, 20,
            0, 8, 1, /* 3079: pointer.ASN1_OBJECT */
            	3084, 0,
            0, 0, 1, /* 3084: ASN1_OBJECT */
            	3089, 0,
            0, 40, 3, /* 3089: struct.asn1_object_st */
            	219, 0,
            	219, 8,
            	224, 24,
            1, 8, 1, /* 3098: pointer.struct.stack_st_X509_POLICY_DATA */
            	3103, 0,
            0, 32, 2, /* 3103: struct.stack_st_fake_X509_POLICY_DATA */
            	3110, 8,
            	444, 24,
            8884099, 8, 2, /* 3110: pointer_to_array_of_pointers_to_stack */
            	3117, 0,
            	18, 20,
            0, 8, 1, /* 3117: pointer.X509_POLICY_DATA */
            	3122, 0,
            0, 0, 1, /* 3122: X509_POLICY_DATA */
            	3127, 0,
            0, 32, 3, /* 3127: struct.X509_POLICY_DATA_st */
            	3136, 8,
            	3150, 16,
            	3174, 24,
            1, 8, 1, /* 3136: pointer.struct.asn1_object_st */
            	3141, 0,
            0, 40, 3, /* 3141: struct.asn1_object_st */
            	219, 0,
            	219, 8,
            	224, 24,
            1, 8, 1, /* 3150: pointer.struct.stack_st_POLICYQUALINFO */
            	3155, 0,
            0, 32, 2, /* 3155: struct.stack_st_fake_POLICYQUALINFO */
            	3162, 8,
            	444, 24,
            8884099, 8, 2, /* 3162: pointer_to_array_of_pointers_to_stack */
            	3169, 0,
            	18, 20,
            0, 8, 1, /* 3169: pointer.POLICYQUALINFO */
            	2831, 0,
            1, 8, 1, /* 3174: pointer.struct.stack_st_ASN1_OBJECT */
            	3179, 0,
            0, 32, 2, /* 3179: struct.stack_st_fake_ASN1_OBJECT */
            	3186, 8,
            	444, 24,
            8884099, 8, 2, /* 3186: pointer_to_array_of_pointers_to_stack */
            	3193, 0,
            	18, 20,
            0, 8, 1, /* 3193: pointer.ASN1_OBJECT */
            	3084, 0,
            1, 8, 1, /* 3198: pointer.struct.stack_st_DIST_POINT */
            	3203, 0,
            0, 32, 2, /* 3203: struct.stack_st_fake_DIST_POINT */
            	3210, 8,
            	444, 24,
            8884099, 8, 2, /* 3210: pointer_to_array_of_pointers_to_stack */
            	3217, 0,
            	18, 20,
            0, 8, 1, /* 3217: pointer.DIST_POINT */
            	3222, 0,
            0, 0, 1, /* 3222: DIST_POINT */
            	3227, 0,
            0, 32, 3, /* 3227: struct.DIST_POINT_st */
            	3236, 0,
            	3327, 8,
            	3255, 16,
            1, 8, 1, /* 3236: pointer.struct.DIST_POINT_NAME_st */
            	3241, 0,
            0, 24, 2, /* 3241: struct.DIST_POINT_NAME_st */
            	3248, 8,
            	3303, 16,
            0, 8, 2, /* 3248: union.unknown */
            	3255, 0,
            	3279, 0,
            1, 8, 1, /* 3255: pointer.struct.stack_st_GENERAL_NAME */
            	3260, 0,
            0, 32, 2, /* 3260: struct.stack_st_fake_GENERAL_NAME */
            	3267, 8,
            	444, 24,
            8884099, 8, 2, /* 3267: pointer_to_array_of_pointers_to_stack */
            	3274, 0,
            	18, 20,
            0, 8, 1, /* 3274: pointer.GENERAL_NAME */
            	2492, 0,
            1, 8, 1, /* 3279: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3284, 0,
            0, 32, 2, /* 3284: struct.stack_st_fake_X509_NAME_ENTRY */
            	3291, 8,
            	444, 24,
            8884099, 8, 2, /* 3291: pointer_to_array_of_pointers_to_stack */
            	3298, 0,
            	18, 20,
            0, 8, 1, /* 3298: pointer.X509_NAME_ENTRY */
            	408, 0,
            1, 8, 1, /* 3303: pointer.struct.X509_name_st */
            	3308, 0,
            0, 40, 3, /* 3308: struct.X509_name_st */
            	3279, 0,
            	3317, 16,
            	185, 24,
            1, 8, 1, /* 3317: pointer.struct.buf_mem_st */
            	3322, 0,
            0, 24, 1, /* 3322: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 3327: pointer.struct.asn1_string_st */
            	3332, 0,
            0, 24, 1, /* 3332: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 3337: pointer.struct.stack_st_GENERAL_NAME */
            	3342, 0,
            0, 32, 2, /* 3342: struct.stack_st_fake_GENERAL_NAME */
            	3349, 8,
            	444, 24,
            8884099, 8, 2, /* 3349: pointer_to_array_of_pointers_to_stack */
            	3356, 0,
            	18, 20,
            0, 8, 1, /* 3356: pointer.GENERAL_NAME */
            	2492, 0,
            1, 8, 1, /* 3361: pointer.struct.NAME_CONSTRAINTS_st */
            	3366, 0,
            0, 16, 2, /* 3366: struct.NAME_CONSTRAINTS_st */
            	3373, 0,
            	3373, 8,
            1, 8, 1, /* 3373: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3378, 0,
            0, 32, 2, /* 3378: struct.stack_st_fake_GENERAL_SUBTREE */
            	3385, 8,
            	444, 24,
            8884099, 8, 2, /* 3385: pointer_to_array_of_pointers_to_stack */
            	3392, 0,
            	18, 20,
            0, 8, 1, /* 3392: pointer.GENERAL_SUBTREE */
            	3397, 0,
            0, 0, 1, /* 3397: GENERAL_SUBTREE */
            	3402, 0,
            0, 24, 3, /* 3402: struct.GENERAL_SUBTREE_st */
            	3411, 0,
            	3543, 8,
            	3543, 16,
            1, 8, 1, /* 3411: pointer.struct.GENERAL_NAME_st */
            	3416, 0,
            0, 16, 1, /* 3416: struct.GENERAL_NAME_st */
            	3421, 8,
            0, 8, 15, /* 3421: union.unknown */
            	69, 0,
            	3454, 0,
            	3573, 0,
            	3573, 0,
            	3480, 0,
            	3613, 0,
            	3661, 0,
            	3573, 0,
            	3558, 0,
            	3466, 0,
            	3558, 0,
            	3613, 0,
            	3573, 0,
            	3466, 0,
            	3480, 0,
            1, 8, 1, /* 3454: pointer.struct.otherName_st */
            	3459, 0,
            0, 16, 2, /* 3459: struct.otherName_st */
            	3466, 0,
            	3480, 8,
            1, 8, 1, /* 3466: pointer.struct.asn1_object_st */
            	3471, 0,
            0, 40, 3, /* 3471: struct.asn1_object_st */
            	219, 0,
            	219, 8,
            	224, 24,
            1, 8, 1, /* 3480: pointer.struct.asn1_type_st */
            	3485, 0,
            0, 16, 1, /* 3485: struct.asn1_type_st */
            	3490, 8,
            0, 8, 20, /* 3490: union.unknown */
            	69, 0,
            	3533, 0,
            	3466, 0,
            	3543, 0,
            	3548, 0,
            	3553, 0,
            	3558, 0,
            	3563, 0,
            	3568, 0,
            	3573, 0,
            	3578, 0,
            	3583, 0,
            	3588, 0,
            	3593, 0,
            	3598, 0,
            	3603, 0,
            	3608, 0,
            	3533, 0,
            	3533, 0,
            	3052, 0,
            1, 8, 1, /* 3533: pointer.struct.asn1_string_st */
            	3538, 0,
            0, 24, 1, /* 3538: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 3543: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3548: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3553: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3558: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3563: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3568: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3573: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3578: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3583: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3588: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3593: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3598: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3603: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3608: pointer.struct.asn1_string_st */
            	3538, 0,
            1, 8, 1, /* 3613: pointer.struct.X509_name_st */
            	3618, 0,
            0, 40, 3, /* 3618: struct.X509_name_st */
            	3627, 0,
            	3651, 16,
            	185, 24,
            1, 8, 1, /* 3627: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3632, 0,
            0, 32, 2, /* 3632: struct.stack_st_fake_X509_NAME_ENTRY */
            	3639, 8,
            	444, 24,
            8884099, 8, 2, /* 3639: pointer_to_array_of_pointers_to_stack */
            	3646, 0,
            	18, 20,
            0, 8, 1, /* 3646: pointer.X509_NAME_ENTRY */
            	408, 0,
            1, 8, 1, /* 3651: pointer.struct.buf_mem_st */
            	3656, 0,
            0, 24, 1, /* 3656: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 3661: pointer.struct.EDIPartyName_st */
            	3666, 0,
            0, 16, 2, /* 3666: struct.EDIPartyName_st */
            	3533, 0,
            	3533, 8,
            1, 8, 1, /* 3673: pointer.struct.x509_cert_aux_st */
            	3678, 0,
            0, 40, 5, /* 3678: struct.x509_cert_aux_st */
            	3691, 0,
            	3691, 8,
            	3715, 16,
            	2439, 24,
            	3720, 32,
            1, 8, 1, /* 3691: pointer.struct.stack_st_ASN1_OBJECT */
            	3696, 0,
            0, 32, 2, /* 3696: struct.stack_st_fake_ASN1_OBJECT */
            	3703, 8,
            	444, 24,
            8884099, 8, 2, /* 3703: pointer_to_array_of_pointers_to_stack */
            	3710, 0,
            	18, 20,
            0, 8, 1, /* 3710: pointer.ASN1_OBJECT */
            	3084, 0,
            1, 8, 1, /* 3715: pointer.struct.asn1_string_st */
            	180, 0,
            1, 8, 1, /* 3720: pointer.struct.stack_st_X509_ALGOR */
            	3725, 0,
            0, 32, 2, /* 3725: struct.stack_st_fake_X509_ALGOR */
            	3732, 8,
            	444, 24,
            8884099, 8, 2, /* 3732: pointer_to_array_of_pointers_to_stack */
            	3739, 0,
            	18, 20,
            0, 8, 1, /* 3739: pointer.X509_ALGOR */
            	3744, 0,
            0, 0, 1, /* 3744: X509_ALGOR */
            	198, 0,
            1, 8, 1, /* 3749: pointer.struct.evp_pkey_st */
            	3754, 0,
            0, 56, 4, /* 3754: struct.evp_pkey_st */
            	3765, 16,
            	3770, 24,
            	3775, 32,
            	3808, 48,
            1, 8, 1, /* 3765: pointer.struct.evp_pkey_asn1_method_st */
            	524, 0,
            1, 8, 1, /* 3770: pointer.struct.engine_st */
            	625, 0,
            0, 8, 5, /* 3775: union.unknown */
            	69, 0,
            	3788, 0,
            	3793, 0,
            	3798, 0,
            	3803, 0,
            1, 8, 1, /* 3788: pointer.struct.rsa_st */
            	991, 0,
            1, 8, 1, /* 3793: pointer.struct.dsa_st */
            	1207, 0,
            1, 8, 1, /* 3798: pointer.struct.dh_st */
            	1346, 0,
            1, 8, 1, /* 3803: pointer.struct.ec_key_st */
            	1472, 0,
            1, 8, 1, /* 3808: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3813, 0,
            0, 32, 2, /* 3813: struct.stack_st_fake_X509_ATTRIBUTE */
            	3820, 8,
            	444, 24,
            8884099, 8, 2, /* 3820: pointer_to_array_of_pointers_to_stack */
            	3827, 0,
            	18, 20,
            0, 8, 1, /* 3827: pointer.X509_ATTRIBUTE */
            	2000, 0,
            1, 8, 1, /* 3832: pointer.struct.env_md_st */
            	3837, 0,
            0, 120, 8, /* 3837: struct.env_md_st */
            	3856, 24,
            	3859, 32,
            	3862, 40,
            	3865, 48,
            	3856, 56,
            	3868, 64,
            	3871, 72,
            	3874, 112,
            8884097, 8, 0, /* 3856: pointer.func */
            8884097, 8, 0, /* 3859: pointer.func */
            8884097, 8, 0, /* 3862: pointer.func */
            8884097, 8, 0, /* 3865: pointer.func */
            8884097, 8, 0, /* 3868: pointer.func */
            8884097, 8, 0, /* 3871: pointer.func */
            8884097, 8, 0, /* 3874: pointer.func */
            1, 8, 1, /* 3877: pointer.struct.rsa_st */
            	991, 0,
            8884097, 8, 0, /* 3882: pointer.func */
            1, 8, 1, /* 3885: pointer.struct.dh_st */
            	1346, 0,
            8884097, 8, 0, /* 3890: pointer.func */
            1, 8, 1, /* 3893: pointer.struct.ec_key_st */
            	1472, 0,
            8884097, 8, 0, /* 3898: pointer.func */
            1, 8, 1, /* 3901: pointer.struct.stack_st_X509_NAME */
            	3906, 0,
            0, 32, 2, /* 3906: struct.stack_st_fake_X509_NAME */
            	3913, 8,
            	444, 24,
            8884099, 8, 2, /* 3913: pointer_to_array_of_pointers_to_stack */
            	3920, 0,
            	18, 20,
            0, 8, 1, /* 3920: pointer.X509_NAME */
            	3925, 0,
            0, 0, 1, /* 3925: X509_NAME */
            	3930, 0,
            0, 40, 3, /* 3930: struct.X509_name_st */
            	3939, 0,
            	3963, 16,
            	185, 24,
            1, 8, 1, /* 3939: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3944, 0,
            0, 32, 2, /* 3944: struct.stack_st_fake_X509_NAME_ENTRY */
            	3951, 8,
            	444, 24,
            8884099, 8, 2, /* 3951: pointer_to_array_of_pointers_to_stack */
            	3958, 0,
            	18, 20,
            0, 8, 1, /* 3958: pointer.X509_NAME_ENTRY */
            	408, 0,
            1, 8, 1, /* 3963: pointer.struct.buf_mem_st */
            	3968, 0,
            0, 24, 1, /* 3968: struct.buf_mem_st */
            	69, 8,
            8884097, 8, 0, /* 3973: pointer.func */
            1, 8, 1, /* 3976: pointer.struct.stack_st_X509 */
            	3981, 0,
            0, 32, 2, /* 3981: struct.stack_st_fake_X509 */
            	3988, 8,
            	444, 24,
            8884099, 8, 2, /* 3988: pointer_to_array_of_pointers_to_stack */
            	3995, 0,
            	18, 20,
            0, 8, 1, /* 3995: pointer.X509 */
            	4000, 0,
            0, 0, 1, /* 4000: X509 */
            	4005, 0,
            0, 184, 12, /* 4005: struct.x509_st */
            	4032, 0,
            	4072, 8,
            	4147, 16,
            	69, 32,
            	4181, 40,
            	4203, 104,
            	4208, 112,
            	4213, 120,
            	4218, 128,
            	4242, 136,
            	4266, 144,
            	4271, 176,
            1, 8, 1, /* 4032: pointer.struct.x509_cinf_st */
            	4037, 0,
            0, 104, 11, /* 4037: struct.x509_cinf_st */
            	4062, 0,
            	4062, 8,
            	4072, 16,
            	4077, 24,
            	4125, 32,
            	4077, 40,
            	4142, 48,
            	4147, 56,
            	4147, 64,
            	4152, 72,
            	4176, 80,
            1, 8, 1, /* 4062: pointer.struct.asn1_string_st */
            	4067, 0,
            0, 24, 1, /* 4067: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 4072: pointer.struct.X509_algor_st */
            	198, 0,
            1, 8, 1, /* 4077: pointer.struct.X509_name_st */
            	4082, 0,
            0, 40, 3, /* 4082: struct.X509_name_st */
            	4091, 0,
            	4115, 16,
            	185, 24,
            1, 8, 1, /* 4091: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4096, 0,
            0, 32, 2, /* 4096: struct.stack_st_fake_X509_NAME_ENTRY */
            	4103, 8,
            	444, 24,
            8884099, 8, 2, /* 4103: pointer_to_array_of_pointers_to_stack */
            	4110, 0,
            	18, 20,
            0, 8, 1, /* 4110: pointer.X509_NAME_ENTRY */
            	408, 0,
            1, 8, 1, /* 4115: pointer.struct.buf_mem_st */
            	4120, 0,
            0, 24, 1, /* 4120: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 4125: pointer.struct.X509_val_st */
            	4130, 0,
            0, 16, 2, /* 4130: struct.X509_val_st */
            	4137, 0,
            	4137, 8,
            1, 8, 1, /* 4137: pointer.struct.asn1_string_st */
            	4067, 0,
            1, 8, 1, /* 4142: pointer.struct.X509_pubkey_st */
            	479, 0,
            1, 8, 1, /* 4147: pointer.struct.asn1_string_st */
            	4067, 0,
            1, 8, 1, /* 4152: pointer.struct.stack_st_X509_EXTENSION */
            	4157, 0,
            0, 32, 2, /* 4157: struct.stack_st_fake_X509_EXTENSION */
            	4164, 8,
            	444, 24,
            8884099, 8, 2, /* 4164: pointer_to_array_of_pointers_to_stack */
            	4171, 0,
            	18, 20,
            0, 8, 1, /* 4171: pointer.X509_EXTENSION */
            	2376, 0,
            0, 24, 1, /* 4176: struct.ASN1_ENCODING_st */
            	185, 0,
            0, 16, 1, /* 4181: struct.crypto_ex_data_st */
            	4186, 0,
            1, 8, 1, /* 4186: pointer.struct.stack_st_void */
            	4191, 0,
            0, 32, 1, /* 4191: struct.stack_st_void */
            	4196, 0,
            0, 32, 2, /* 4196: struct.stack_st */
            	963, 8,
            	444, 24,
            1, 8, 1, /* 4203: pointer.struct.asn1_string_st */
            	4067, 0,
            1, 8, 1, /* 4208: pointer.struct.AUTHORITY_KEYID_st */
            	2449, 0,
            1, 8, 1, /* 4213: pointer.struct.X509_POLICY_CACHE_st */
            	2772, 0,
            1, 8, 1, /* 4218: pointer.struct.stack_st_DIST_POINT */
            	4223, 0,
            0, 32, 2, /* 4223: struct.stack_st_fake_DIST_POINT */
            	4230, 8,
            	444, 24,
            8884099, 8, 2, /* 4230: pointer_to_array_of_pointers_to_stack */
            	4237, 0,
            	18, 20,
            0, 8, 1, /* 4237: pointer.DIST_POINT */
            	3222, 0,
            1, 8, 1, /* 4242: pointer.struct.stack_st_GENERAL_NAME */
            	4247, 0,
            0, 32, 2, /* 4247: struct.stack_st_fake_GENERAL_NAME */
            	4254, 8,
            	444, 24,
            8884099, 8, 2, /* 4254: pointer_to_array_of_pointers_to_stack */
            	4261, 0,
            	18, 20,
            0, 8, 1, /* 4261: pointer.GENERAL_NAME */
            	2492, 0,
            1, 8, 1, /* 4266: pointer.struct.NAME_CONSTRAINTS_st */
            	3366, 0,
            1, 8, 1, /* 4271: pointer.struct.x509_cert_aux_st */
            	4276, 0,
            0, 40, 5, /* 4276: struct.x509_cert_aux_st */
            	4289, 0,
            	4289, 8,
            	4313, 16,
            	4203, 24,
            	4318, 32,
            1, 8, 1, /* 4289: pointer.struct.stack_st_ASN1_OBJECT */
            	4294, 0,
            0, 32, 2, /* 4294: struct.stack_st_fake_ASN1_OBJECT */
            	4301, 8,
            	444, 24,
            8884099, 8, 2, /* 4301: pointer_to_array_of_pointers_to_stack */
            	4308, 0,
            	18, 20,
            0, 8, 1, /* 4308: pointer.ASN1_OBJECT */
            	3084, 0,
            1, 8, 1, /* 4313: pointer.struct.asn1_string_st */
            	4067, 0,
            1, 8, 1, /* 4318: pointer.struct.stack_st_X509_ALGOR */
            	4323, 0,
            0, 32, 2, /* 4323: struct.stack_st_fake_X509_ALGOR */
            	4330, 8,
            	444, 24,
            8884099, 8, 2, /* 4330: pointer_to_array_of_pointers_to_stack */
            	4337, 0,
            	18, 20,
            0, 8, 1, /* 4337: pointer.X509_ALGOR */
            	3744, 0,
            8884097, 8, 0, /* 4342: pointer.func */
            8884097, 8, 0, /* 4345: pointer.func */
            0, 120, 8, /* 4348: struct.env_md_st */
            	4345, 24,
            	4367, 32,
            	4342, 40,
            	4370, 48,
            	4345, 56,
            	3868, 64,
            	3871, 72,
            	4373, 112,
            8884097, 8, 0, /* 4367: pointer.func */
            8884097, 8, 0, /* 4370: pointer.func */
            8884097, 8, 0, /* 4373: pointer.func */
            8884097, 8, 0, /* 4376: pointer.func */
            8884097, 8, 0, /* 4379: pointer.func */
            0, 88, 1, /* 4382: struct.ssl_cipher_st */
            	219, 8,
            0, 40, 5, /* 4387: struct.x509_cert_aux_st */
            	4400, 0,
            	4400, 8,
            	4424, 16,
            	4434, 24,
            	4439, 32,
            1, 8, 1, /* 4400: pointer.struct.stack_st_ASN1_OBJECT */
            	4405, 0,
            0, 32, 2, /* 4405: struct.stack_st_fake_ASN1_OBJECT */
            	4412, 8,
            	444, 24,
            8884099, 8, 2, /* 4412: pointer_to_array_of_pointers_to_stack */
            	4419, 0,
            	18, 20,
            0, 8, 1, /* 4419: pointer.ASN1_OBJECT */
            	3084, 0,
            1, 8, 1, /* 4424: pointer.struct.asn1_string_st */
            	4429, 0,
            0, 24, 1, /* 4429: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 4434: pointer.struct.asn1_string_st */
            	4429, 0,
            1, 8, 1, /* 4439: pointer.struct.stack_st_X509_ALGOR */
            	4444, 0,
            0, 32, 2, /* 4444: struct.stack_st_fake_X509_ALGOR */
            	4451, 8,
            	444, 24,
            8884099, 8, 2, /* 4451: pointer_to_array_of_pointers_to_stack */
            	4458, 0,
            	18, 20,
            0, 8, 1, /* 4458: pointer.X509_ALGOR */
            	3744, 0,
            1, 8, 1, /* 4463: pointer.struct.stack_st_DIST_POINT */
            	4468, 0,
            0, 32, 2, /* 4468: struct.stack_st_fake_DIST_POINT */
            	4475, 8,
            	444, 24,
            8884099, 8, 2, /* 4475: pointer_to_array_of_pointers_to_stack */
            	4482, 0,
            	18, 20,
            0, 8, 1, /* 4482: pointer.DIST_POINT */
            	3222, 0,
            0, 24, 1, /* 4487: struct.ASN1_ENCODING_st */
            	185, 0,
            1, 8, 1, /* 4492: pointer.struct.stack_st_X509_EXTENSION */
            	4497, 0,
            0, 32, 2, /* 4497: struct.stack_st_fake_X509_EXTENSION */
            	4504, 8,
            	444, 24,
            8884099, 8, 2, /* 4504: pointer_to_array_of_pointers_to_stack */
            	4511, 0,
            	18, 20,
            0, 8, 1, /* 4511: pointer.X509_EXTENSION */
            	2376, 0,
            1, 8, 1, /* 4516: pointer.struct.X509_pubkey_st */
            	479, 0,
            1, 8, 1, /* 4521: pointer.struct.asn1_string_st */
            	4429, 0,
            0, 16, 2, /* 4526: struct.X509_val_st */
            	4521, 0,
            	4521, 8,
            1, 8, 1, /* 4533: pointer.struct.X509_algor_st */
            	198, 0,
            1, 8, 1, /* 4538: pointer.struct.asn1_string_st */
            	4429, 0,
            0, 32, 1, /* 4543: struct.stack_st_void */
            	4548, 0,
            0, 32, 2, /* 4548: struct.stack_st */
            	963, 8,
            	444, 24,
            0, 16, 1, /* 4555: struct.crypto_ex_data_st */
            	4560, 0,
            1, 8, 1, /* 4560: pointer.struct.stack_st_void */
            	4543, 0,
            8884097, 8, 0, /* 4565: pointer.func */
            1, 8, 1, /* 4568: pointer.struct.sess_cert_st */
            	4573, 0,
            0, 248, 5, /* 4573: struct.sess_cert_st */
            	4586, 0,
            	4610, 16,
            	5010, 216,
            	5015, 224,
            	3893, 232,
            1, 8, 1, /* 4586: pointer.struct.stack_st_X509 */
            	4591, 0,
            0, 32, 2, /* 4591: struct.stack_st_fake_X509 */
            	4598, 8,
            	444, 24,
            8884099, 8, 2, /* 4598: pointer_to_array_of_pointers_to_stack */
            	4605, 0,
            	18, 20,
            0, 8, 1, /* 4605: pointer.X509 */
            	4000, 0,
            1, 8, 1, /* 4610: pointer.struct.cert_pkey_st */
            	4615, 0,
            0, 24, 3, /* 4615: struct.cert_pkey_st */
            	4624, 0,
            	4903, 8,
            	4971, 16,
            1, 8, 1, /* 4624: pointer.struct.x509_st */
            	4629, 0,
            0, 184, 12, /* 4629: struct.x509_st */
            	4656, 0,
            	4696, 8,
            	4771, 16,
            	69, 32,
            	4805, 40,
            	4827, 104,
            	2444, 112,
            	2767, 120,
            	3198, 128,
            	3337, 136,
            	3361, 144,
            	4832, 176,
            1, 8, 1, /* 4656: pointer.struct.x509_cinf_st */
            	4661, 0,
            0, 104, 11, /* 4661: struct.x509_cinf_st */
            	4686, 0,
            	4686, 8,
            	4696, 16,
            	4701, 24,
            	4749, 32,
            	4701, 40,
            	4766, 48,
            	4771, 56,
            	4771, 64,
            	4776, 72,
            	4800, 80,
            1, 8, 1, /* 4686: pointer.struct.asn1_string_st */
            	4691, 0,
            0, 24, 1, /* 4691: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 4696: pointer.struct.X509_algor_st */
            	198, 0,
            1, 8, 1, /* 4701: pointer.struct.X509_name_st */
            	4706, 0,
            0, 40, 3, /* 4706: struct.X509_name_st */
            	4715, 0,
            	4739, 16,
            	185, 24,
            1, 8, 1, /* 4715: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4720, 0,
            0, 32, 2, /* 4720: struct.stack_st_fake_X509_NAME_ENTRY */
            	4727, 8,
            	444, 24,
            8884099, 8, 2, /* 4727: pointer_to_array_of_pointers_to_stack */
            	4734, 0,
            	18, 20,
            0, 8, 1, /* 4734: pointer.X509_NAME_ENTRY */
            	408, 0,
            1, 8, 1, /* 4739: pointer.struct.buf_mem_st */
            	4744, 0,
            0, 24, 1, /* 4744: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 4749: pointer.struct.X509_val_st */
            	4754, 0,
            0, 16, 2, /* 4754: struct.X509_val_st */
            	4761, 0,
            	4761, 8,
            1, 8, 1, /* 4761: pointer.struct.asn1_string_st */
            	4691, 0,
            1, 8, 1, /* 4766: pointer.struct.X509_pubkey_st */
            	479, 0,
            1, 8, 1, /* 4771: pointer.struct.asn1_string_st */
            	4691, 0,
            1, 8, 1, /* 4776: pointer.struct.stack_st_X509_EXTENSION */
            	4781, 0,
            0, 32, 2, /* 4781: struct.stack_st_fake_X509_EXTENSION */
            	4788, 8,
            	444, 24,
            8884099, 8, 2, /* 4788: pointer_to_array_of_pointers_to_stack */
            	4795, 0,
            	18, 20,
            0, 8, 1, /* 4795: pointer.X509_EXTENSION */
            	2376, 0,
            0, 24, 1, /* 4800: struct.ASN1_ENCODING_st */
            	185, 0,
            0, 16, 1, /* 4805: struct.crypto_ex_data_st */
            	4810, 0,
            1, 8, 1, /* 4810: pointer.struct.stack_st_void */
            	4815, 0,
            0, 32, 1, /* 4815: struct.stack_st_void */
            	4820, 0,
            0, 32, 2, /* 4820: struct.stack_st */
            	963, 8,
            	444, 24,
            1, 8, 1, /* 4827: pointer.struct.asn1_string_st */
            	4691, 0,
            1, 8, 1, /* 4832: pointer.struct.x509_cert_aux_st */
            	4837, 0,
            0, 40, 5, /* 4837: struct.x509_cert_aux_st */
            	4850, 0,
            	4850, 8,
            	4874, 16,
            	4827, 24,
            	4879, 32,
            1, 8, 1, /* 4850: pointer.struct.stack_st_ASN1_OBJECT */
            	4855, 0,
            0, 32, 2, /* 4855: struct.stack_st_fake_ASN1_OBJECT */
            	4862, 8,
            	444, 24,
            8884099, 8, 2, /* 4862: pointer_to_array_of_pointers_to_stack */
            	4869, 0,
            	18, 20,
            0, 8, 1, /* 4869: pointer.ASN1_OBJECT */
            	3084, 0,
            1, 8, 1, /* 4874: pointer.struct.asn1_string_st */
            	4691, 0,
            1, 8, 1, /* 4879: pointer.struct.stack_st_X509_ALGOR */
            	4884, 0,
            0, 32, 2, /* 4884: struct.stack_st_fake_X509_ALGOR */
            	4891, 8,
            	444, 24,
            8884099, 8, 2, /* 4891: pointer_to_array_of_pointers_to_stack */
            	4898, 0,
            	18, 20,
            0, 8, 1, /* 4898: pointer.X509_ALGOR */
            	3744, 0,
            1, 8, 1, /* 4903: pointer.struct.evp_pkey_st */
            	4908, 0,
            0, 56, 4, /* 4908: struct.evp_pkey_st */
            	3765, 16,
            	3770, 24,
            	4919, 32,
            	4947, 48,
            0, 8, 5, /* 4919: union.unknown */
            	69, 0,
            	4932, 0,
            	4937, 0,
            	4942, 0,
            	3803, 0,
            1, 8, 1, /* 4932: pointer.struct.rsa_st */
            	991, 0,
            1, 8, 1, /* 4937: pointer.struct.dsa_st */
            	1207, 0,
            1, 8, 1, /* 4942: pointer.struct.dh_st */
            	1346, 0,
            1, 8, 1, /* 4947: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4952, 0,
            0, 32, 2, /* 4952: struct.stack_st_fake_X509_ATTRIBUTE */
            	4959, 8,
            	444, 24,
            8884099, 8, 2, /* 4959: pointer_to_array_of_pointers_to_stack */
            	4966, 0,
            	18, 20,
            0, 8, 1, /* 4966: pointer.X509_ATTRIBUTE */
            	2000, 0,
            1, 8, 1, /* 4971: pointer.struct.env_md_st */
            	4976, 0,
            0, 120, 8, /* 4976: struct.env_md_st */
            	4995, 24,
            	4998, 32,
            	5001, 40,
            	5004, 48,
            	4995, 56,
            	3868, 64,
            	3871, 72,
            	5007, 112,
            8884097, 8, 0, /* 4995: pointer.func */
            8884097, 8, 0, /* 4998: pointer.func */
            8884097, 8, 0, /* 5001: pointer.func */
            8884097, 8, 0, /* 5004: pointer.func */
            8884097, 8, 0, /* 5007: pointer.func */
            1, 8, 1, /* 5010: pointer.struct.rsa_st */
            	991, 0,
            1, 8, 1, /* 5015: pointer.struct.dh_st */
            	1346, 0,
            8884097, 8, 0, /* 5020: pointer.func */
            8884097, 8, 0, /* 5023: pointer.func */
            0, 56, 2, /* 5026: struct.X509_VERIFY_PARAM_st */
            	69, 0,
            	4400, 48,
            1, 8, 1, /* 5033: pointer.struct.stack_st_X509_LOOKUP */
            	5038, 0,
            0, 32, 2, /* 5038: struct.stack_st_fake_X509_LOOKUP */
            	5045, 8,
            	444, 24,
            8884099, 8, 2, /* 5045: pointer_to_array_of_pointers_to_stack */
            	5052, 0,
            	18, 20,
            0, 8, 1, /* 5052: pointer.X509_LOOKUP */
            	5057, 0,
            0, 0, 1, /* 5057: X509_LOOKUP */
            	5062, 0,
            0, 32, 3, /* 5062: struct.x509_lookup_st */
            	5071, 8,
            	69, 16,
            	5120, 24,
            1, 8, 1, /* 5071: pointer.struct.x509_lookup_method_st */
            	5076, 0,
            0, 80, 10, /* 5076: struct.x509_lookup_method_st */
            	219, 0,
            	5099, 8,
            	5102, 16,
            	5099, 24,
            	5099, 32,
            	5105, 40,
            	5108, 48,
            	5111, 56,
            	5114, 64,
            	5117, 72,
            8884097, 8, 0, /* 5099: pointer.func */
            8884097, 8, 0, /* 5102: pointer.func */
            8884097, 8, 0, /* 5105: pointer.func */
            8884097, 8, 0, /* 5108: pointer.func */
            8884097, 8, 0, /* 5111: pointer.func */
            8884097, 8, 0, /* 5114: pointer.func */
            8884097, 8, 0, /* 5117: pointer.func */
            1, 8, 1, /* 5120: pointer.struct.x509_store_st */
            	5125, 0,
            0, 144, 15, /* 5125: struct.x509_store_st */
            	5158, 8,
            	5962, 16,
            	5986, 24,
            	5998, 32,
            	6001, 40,
            	6004, 48,
            	6007, 56,
            	5998, 64,
            	6010, 72,
            	6013, 80,
            	6016, 88,
            	6019, 96,
            	6022, 104,
            	5998, 112,
            	5384, 120,
            1, 8, 1, /* 5158: pointer.struct.stack_st_X509_OBJECT */
            	5163, 0,
            0, 32, 2, /* 5163: struct.stack_st_fake_X509_OBJECT */
            	5170, 8,
            	444, 24,
            8884099, 8, 2, /* 5170: pointer_to_array_of_pointers_to_stack */
            	5177, 0,
            	18, 20,
            0, 8, 1, /* 5177: pointer.X509_OBJECT */
            	5182, 0,
            0, 0, 1, /* 5182: X509_OBJECT */
            	5187, 0,
            0, 16, 1, /* 5187: struct.x509_object_st */
            	5192, 8,
            0, 8, 4, /* 5192: union.unknown */
            	69, 0,
            	5203, 0,
            	5545, 0,
            	5879, 0,
            1, 8, 1, /* 5203: pointer.struct.x509_st */
            	5208, 0,
            0, 184, 12, /* 5208: struct.x509_st */
            	5235, 0,
            	5275, 8,
            	5350, 16,
            	69, 32,
            	5384, 40,
            	5406, 104,
            	5411, 112,
            	5416, 120,
            	5421, 128,
            	5445, 136,
            	5469, 144,
            	5474, 176,
            1, 8, 1, /* 5235: pointer.struct.x509_cinf_st */
            	5240, 0,
            0, 104, 11, /* 5240: struct.x509_cinf_st */
            	5265, 0,
            	5265, 8,
            	5275, 16,
            	5280, 24,
            	5328, 32,
            	5280, 40,
            	5345, 48,
            	5350, 56,
            	5350, 64,
            	5355, 72,
            	5379, 80,
            1, 8, 1, /* 5265: pointer.struct.asn1_string_st */
            	5270, 0,
            0, 24, 1, /* 5270: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 5275: pointer.struct.X509_algor_st */
            	198, 0,
            1, 8, 1, /* 5280: pointer.struct.X509_name_st */
            	5285, 0,
            0, 40, 3, /* 5285: struct.X509_name_st */
            	5294, 0,
            	5318, 16,
            	185, 24,
            1, 8, 1, /* 5294: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5299, 0,
            0, 32, 2, /* 5299: struct.stack_st_fake_X509_NAME_ENTRY */
            	5306, 8,
            	444, 24,
            8884099, 8, 2, /* 5306: pointer_to_array_of_pointers_to_stack */
            	5313, 0,
            	18, 20,
            0, 8, 1, /* 5313: pointer.X509_NAME_ENTRY */
            	408, 0,
            1, 8, 1, /* 5318: pointer.struct.buf_mem_st */
            	5323, 0,
            0, 24, 1, /* 5323: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 5328: pointer.struct.X509_val_st */
            	5333, 0,
            0, 16, 2, /* 5333: struct.X509_val_st */
            	5340, 0,
            	5340, 8,
            1, 8, 1, /* 5340: pointer.struct.asn1_string_st */
            	5270, 0,
            1, 8, 1, /* 5345: pointer.struct.X509_pubkey_st */
            	479, 0,
            1, 8, 1, /* 5350: pointer.struct.asn1_string_st */
            	5270, 0,
            1, 8, 1, /* 5355: pointer.struct.stack_st_X509_EXTENSION */
            	5360, 0,
            0, 32, 2, /* 5360: struct.stack_st_fake_X509_EXTENSION */
            	5367, 8,
            	444, 24,
            8884099, 8, 2, /* 5367: pointer_to_array_of_pointers_to_stack */
            	5374, 0,
            	18, 20,
            0, 8, 1, /* 5374: pointer.X509_EXTENSION */
            	2376, 0,
            0, 24, 1, /* 5379: struct.ASN1_ENCODING_st */
            	185, 0,
            0, 16, 1, /* 5384: struct.crypto_ex_data_st */
            	5389, 0,
            1, 8, 1, /* 5389: pointer.struct.stack_st_void */
            	5394, 0,
            0, 32, 1, /* 5394: struct.stack_st_void */
            	5399, 0,
            0, 32, 2, /* 5399: struct.stack_st */
            	963, 8,
            	444, 24,
            1, 8, 1, /* 5406: pointer.struct.asn1_string_st */
            	5270, 0,
            1, 8, 1, /* 5411: pointer.struct.AUTHORITY_KEYID_st */
            	2449, 0,
            1, 8, 1, /* 5416: pointer.struct.X509_POLICY_CACHE_st */
            	2772, 0,
            1, 8, 1, /* 5421: pointer.struct.stack_st_DIST_POINT */
            	5426, 0,
            0, 32, 2, /* 5426: struct.stack_st_fake_DIST_POINT */
            	5433, 8,
            	444, 24,
            8884099, 8, 2, /* 5433: pointer_to_array_of_pointers_to_stack */
            	5440, 0,
            	18, 20,
            0, 8, 1, /* 5440: pointer.DIST_POINT */
            	3222, 0,
            1, 8, 1, /* 5445: pointer.struct.stack_st_GENERAL_NAME */
            	5450, 0,
            0, 32, 2, /* 5450: struct.stack_st_fake_GENERAL_NAME */
            	5457, 8,
            	444, 24,
            8884099, 8, 2, /* 5457: pointer_to_array_of_pointers_to_stack */
            	5464, 0,
            	18, 20,
            0, 8, 1, /* 5464: pointer.GENERAL_NAME */
            	2492, 0,
            1, 8, 1, /* 5469: pointer.struct.NAME_CONSTRAINTS_st */
            	3366, 0,
            1, 8, 1, /* 5474: pointer.struct.x509_cert_aux_st */
            	5479, 0,
            0, 40, 5, /* 5479: struct.x509_cert_aux_st */
            	5492, 0,
            	5492, 8,
            	5516, 16,
            	5406, 24,
            	5521, 32,
            1, 8, 1, /* 5492: pointer.struct.stack_st_ASN1_OBJECT */
            	5497, 0,
            0, 32, 2, /* 5497: struct.stack_st_fake_ASN1_OBJECT */
            	5504, 8,
            	444, 24,
            8884099, 8, 2, /* 5504: pointer_to_array_of_pointers_to_stack */
            	5511, 0,
            	18, 20,
            0, 8, 1, /* 5511: pointer.ASN1_OBJECT */
            	3084, 0,
            1, 8, 1, /* 5516: pointer.struct.asn1_string_st */
            	5270, 0,
            1, 8, 1, /* 5521: pointer.struct.stack_st_X509_ALGOR */
            	5526, 0,
            0, 32, 2, /* 5526: struct.stack_st_fake_X509_ALGOR */
            	5533, 8,
            	444, 24,
            8884099, 8, 2, /* 5533: pointer_to_array_of_pointers_to_stack */
            	5540, 0,
            	18, 20,
            0, 8, 1, /* 5540: pointer.X509_ALGOR */
            	3744, 0,
            1, 8, 1, /* 5545: pointer.struct.X509_crl_st */
            	5550, 0,
            0, 120, 10, /* 5550: struct.X509_crl_st */
            	5573, 0,
            	5275, 8,
            	5350, 16,
            	5411, 32,
            	5700, 40,
            	5265, 56,
            	5265, 64,
            	5813, 96,
            	5854, 104,
            	57, 112,
            1, 8, 1, /* 5573: pointer.struct.X509_crl_info_st */
            	5578, 0,
            0, 80, 8, /* 5578: struct.X509_crl_info_st */
            	5265, 0,
            	5275, 8,
            	5280, 16,
            	5340, 24,
            	5340, 32,
            	5597, 40,
            	5355, 48,
            	5379, 56,
            1, 8, 1, /* 5597: pointer.struct.stack_st_X509_REVOKED */
            	5602, 0,
            0, 32, 2, /* 5602: struct.stack_st_fake_X509_REVOKED */
            	5609, 8,
            	444, 24,
            8884099, 8, 2, /* 5609: pointer_to_array_of_pointers_to_stack */
            	5616, 0,
            	18, 20,
            0, 8, 1, /* 5616: pointer.X509_REVOKED */
            	5621, 0,
            0, 0, 1, /* 5621: X509_REVOKED */
            	5626, 0,
            0, 40, 4, /* 5626: struct.x509_revoked_st */
            	5637, 0,
            	5647, 8,
            	5652, 16,
            	5676, 24,
            1, 8, 1, /* 5637: pointer.struct.asn1_string_st */
            	5642, 0,
            0, 24, 1, /* 5642: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 5647: pointer.struct.asn1_string_st */
            	5642, 0,
            1, 8, 1, /* 5652: pointer.struct.stack_st_X509_EXTENSION */
            	5657, 0,
            0, 32, 2, /* 5657: struct.stack_st_fake_X509_EXTENSION */
            	5664, 8,
            	444, 24,
            8884099, 8, 2, /* 5664: pointer_to_array_of_pointers_to_stack */
            	5671, 0,
            	18, 20,
            0, 8, 1, /* 5671: pointer.X509_EXTENSION */
            	2376, 0,
            1, 8, 1, /* 5676: pointer.struct.stack_st_GENERAL_NAME */
            	5681, 0,
            0, 32, 2, /* 5681: struct.stack_st_fake_GENERAL_NAME */
            	5688, 8,
            	444, 24,
            8884099, 8, 2, /* 5688: pointer_to_array_of_pointers_to_stack */
            	5695, 0,
            	18, 20,
            0, 8, 1, /* 5695: pointer.GENERAL_NAME */
            	2492, 0,
            1, 8, 1, /* 5700: pointer.struct.ISSUING_DIST_POINT_st */
            	5705, 0,
            0, 32, 2, /* 5705: struct.ISSUING_DIST_POINT_st */
            	5712, 0,
            	5803, 16,
            1, 8, 1, /* 5712: pointer.struct.DIST_POINT_NAME_st */
            	5717, 0,
            0, 24, 2, /* 5717: struct.DIST_POINT_NAME_st */
            	5724, 8,
            	5779, 16,
            0, 8, 2, /* 5724: union.unknown */
            	5731, 0,
            	5755, 0,
            1, 8, 1, /* 5731: pointer.struct.stack_st_GENERAL_NAME */
            	5736, 0,
            0, 32, 2, /* 5736: struct.stack_st_fake_GENERAL_NAME */
            	5743, 8,
            	444, 24,
            8884099, 8, 2, /* 5743: pointer_to_array_of_pointers_to_stack */
            	5750, 0,
            	18, 20,
            0, 8, 1, /* 5750: pointer.GENERAL_NAME */
            	2492, 0,
            1, 8, 1, /* 5755: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5760, 0,
            0, 32, 2, /* 5760: struct.stack_st_fake_X509_NAME_ENTRY */
            	5767, 8,
            	444, 24,
            8884099, 8, 2, /* 5767: pointer_to_array_of_pointers_to_stack */
            	5774, 0,
            	18, 20,
            0, 8, 1, /* 5774: pointer.X509_NAME_ENTRY */
            	408, 0,
            1, 8, 1, /* 5779: pointer.struct.X509_name_st */
            	5784, 0,
            0, 40, 3, /* 5784: struct.X509_name_st */
            	5755, 0,
            	5793, 16,
            	185, 24,
            1, 8, 1, /* 5793: pointer.struct.buf_mem_st */
            	5798, 0,
            0, 24, 1, /* 5798: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 5803: pointer.struct.asn1_string_st */
            	5808, 0,
            0, 24, 1, /* 5808: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 5813: pointer.struct.stack_st_GENERAL_NAMES */
            	5818, 0,
            0, 32, 2, /* 5818: struct.stack_st_fake_GENERAL_NAMES */
            	5825, 8,
            	444, 24,
            8884099, 8, 2, /* 5825: pointer_to_array_of_pointers_to_stack */
            	5832, 0,
            	18, 20,
            0, 8, 1, /* 5832: pointer.GENERAL_NAMES */
            	5837, 0,
            0, 0, 1, /* 5837: GENERAL_NAMES */
            	5842, 0,
            0, 32, 1, /* 5842: struct.stack_st_GENERAL_NAME */
            	5847, 0,
            0, 32, 2, /* 5847: struct.stack_st */
            	963, 8,
            	444, 24,
            1, 8, 1, /* 5854: pointer.struct.x509_crl_method_st */
            	5859, 0,
            0, 40, 4, /* 5859: struct.x509_crl_method_st */
            	5870, 8,
            	5870, 16,
            	5873, 24,
            	5876, 32,
            8884097, 8, 0, /* 5870: pointer.func */
            8884097, 8, 0, /* 5873: pointer.func */
            8884097, 8, 0, /* 5876: pointer.func */
            1, 8, 1, /* 5879: pointer.struct.evp_pkey_st */
            	5884, 0,
            0, 56, 4, /* 5884: struct.evp_pkey_st */
            	5895, 16,
            	5900, 24,
            	5905, 32,
            	5938, 48,
            1, 8, 1, /* 5895: pointer.struct.evp_pkey_asn1_method_st */
            	524, 0,
            1, 8, 1, /* 5900: pointer.struct.engine_st */
            	625, 0,
            0, 8, 5, /* 5905: union.unknown */
            	69, 0,
            	5918, 0,
            	5923, 0,
            	5928, 0,
            	5933, 0,
            1, 8, 1, /* 5918: pointer.struct.rsa_st */
            	991, 0,
            1, 8, 1, /* 5923: pointer.struct.dsa_st */
            	1207, 0,
            1, 8, 1, /* 5928: pointer.struct.dh_st */
            	1346, 0,
            1, 8, 1, /* 5933: pointer.struct.ec_key_st */
            	1472, 0,
            1, 8, 1, /* 5938: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5943, 0,
            0, 32, 2, /* 5943: struct.stack_st_fake_X509_ATTRIBUTE */
            	5950, 8,
            	444, 24,
            8884099, 8, 2, /* 5950: pointer_to_array_of_pointers_to_stack */
            	5957, 0,
            	18, 20,
            0, 8, 1, /* 5957: pointer.X509_ATTRIBUTE */
            	2000, 0,
            1, 8, 1, /* 5962: pointer.struct.stack_st_X509_LOOKUP */
            	5967, 0,
            0, 32, 2, /* 5967: struct.stack_st_fake_X509_LOOKUP */
            	5974, 8,
            	444, 24,
            8884099, 8, 2, /* 5974: pointer_to_array_of_pointers_to_stack */
            	5981, 0,
            	18, 20,
            0, 8, 1, /* 5981: pointer.X509_LOOKUP */
            	5057, 0,
            1, 8, 1, /* 5986: pointer.struct.X509_VERIFY_PARAM_st */
            	5991, 0,
            0, 56, 2, /* 5991: struct.X509_VERIFY_PARAM_st */
            	69, 0,
            	5492, 48,
            8884097, 8, 0, /* 5998: pointer.func */
            8884097, 8, 0, /* 6001: pointer.func */
            8884097, 8, 0, /* 6004: pointer.func */
            8884097, 8, 0, /* 6007: pointer.func */
            8884097, 8, 0, /* 6010: pointer.func */
            8884097, 8, 0, /* 6013: pointer.func */
            8884097, 8, 0, /* 6016: pointer.func */
            8884097, 8, 0, /* 6019: pointer.func */
            8884097, 8, 0, /* 6022: pointer.func */
            1, 8, 1, /* 6025: pointer.struct.x509_store_st */
            	6030, 0,
            0, 144, 15, /* 6030: struct.x509_store_st */
            	6063, 8,
            	5033, 16,
            	6087, 24,
            	5023, 32,
            	6092, 40,
            	6095, 48,
            	6098, 56,
            	5023, 64,
            	5020, 72,
            	4565, 80,
            	6101, 88,
            	6104, 96,
            	6107, 104,
            	5023, 112,
            	4555, 120,
            1, 8, 1, /* 6063: pointer.struct.stack_st_X509_OBJECT */
            	6068, 0,
            0, 32, 2, /* 6068: struct.stack_st_fake_X509_OBJECT */
            	6075, 8,
            	444, 24,
            8884099, 8, 2, /* 6075: pointer_to_array_of_pointers_to_stack */
            	6082, 0,
            	18, 20,
            0, 8, 1, /* 6082: pointer.X509_OBJECT */
            	5182, 0,
            1, 8, 1, /* 6087: pointer.struct.X509_VERIFY_PARAM_st */
            	5026, 0,
            8884097, 8, 0, /* 6092: pointer.func */
            8884097, 8, 0, /* 6095: pointer.func */
            8884097, 8, 0, /* 6098: pointer.func */
            8884097, 8, 0, /* 6101: pointer.func */
            8884097, 8, 0, /* 6104: pointer.func */
            8884097, 8, 0, /* 6107: pointer.func */
            1, 8, 1, /* 6110: pointer.struct.stack_st_SSL_CIPHER */
            	6115, 0,
            0, 32, 2, /* 6115: struct.stack_st_fake_SSL_CIPHER */
            	6122, 8,
            	444, 24,
            8884099, 8, 2, /* 6122: pointer_to_array_of_pointers_to_stack */
            	6129, 0,
            	18, 20,
            0, 8, 1, /* 6129: pointer.SSL_CIPHER */
            	6134, 0,
            0, 0, 1, /* 6134: SSL_CIPHER */
            	6139, 0,
            0, 88, 1, /* 6139: struct.ssl_cipher_st */
            	219, 8,
            8884097, 8, 0, /* 6144: pointer.func */
            1, 8, 1, /* 6147: pointer.struct.ssl3_enc_method */
            	6152, 0,
            0, 112, 11, /* 6152: struct.ssl3_enc_method */
            	6177, 0,
            	6180, 8,
            	6183, 16,
            	6186, 24,
            	6177, 32,
            	6189, 40,
            	6192, 56,
            	219, 64,
            	219, 80,
            	6195, 96,
            	6198, 104,
            8884097, 8, 0, /* 6177: pointer.func */
            8884097, 8, 0, /* 6180: pointer.func */
            8884097, 8, 0, /* 6183: pointer.func */
            8884097, 8, 0, /* 6186: pointer.func */
            8884097, 8, 0, /* 6189: pointer.func */
            8884097, 8, 0, /* 6192: pointer.func */
            8884097, 8, 0, /* 6195: pointer.func */
            8884097, 8, 0, /* 6198: pointer.func */
            8884097, 8, 0, /* 6201: pointer.func */
            8884097, 8, 0, /* 6204: pointer.func */
            8884097, 8, 0, /* 6207: pointer.func */
            8884097, 8, 0, /* 6210: pointer.func */
            8884097, 8, 0, /* 6213: pointer.func */
            8884097, 8, 0, /* 6216: pointer.func */
            8884097, 8, 0, /* 6219: pointer.func */
            0, 232, 28, /* 6222: struct.ssl_method_st */
            	6219, 8,
            	6281, 16,
            	6281, 24,
            	6219, 32,
            	6219, 40,
            	6284, 48,
            	6284, 56,
            	6216, 64,
            	6219, 72,
            	6219, 80,
            	6219, 88,
            	6213, 96,
            	6210, 104,
            	6287, 112,
            	6219, 120,
            	6290, 128,
            	6293, 136,
            	6296, 144,
            	6207, 152,
            	6204, 160,
            	894, 168,
            	6299, 176,
            	6201, 184,
            	6302, 192,
            	6147, 200,
            	894, 208,
            	6144, 216,
            	6305, 224,
            8884097, 8, 0, /* 6281: pointer.func */
            8884097, 8, 0, /* 6284: pointer.func */
            8884097, 8, 0, /* 6287: pointer.func */
            8884097, 8, 0, /* 6290: pointer.func */
            8884097, 8, 0, /* 6293: pointer.func */
            8884097, 8, 0, /* 6296: pointer.func */
            8884097, 8, 0, /* 6299: pointer.func */
            8884097, 8, 0, /* 6302: pointer.func */
            8884097, 8, 0, /* 6305: pointer.func */
            0, 736, 50, /* 6308: struct.ssl_ctx_st */
            	6411, 0,
            	6110, 8,
            	6110, 16,
            	6025, 24,
            	6416, 32,
            	6452, 48,
            	6452, 56,
            	6652, 80,
            	6655, 88,
            	4379, 96,
            	6658, 152,
            	57, 160,
            	6661, 168,
            	57, 176,
            	6664, 184,
            	4376, 192,
            	6667, 200,
            	4555, 208,
            	6670, 224,
            	6670, 232,
            	6670, 240,
            	3976, 248,
            	6675, 256,
            	3973, 264,
            	3901, 272,
            	77, 304,
            	6742, 320,
            	57, 328,
            	6092, 376,
            	6745, 384,
            	6087, 392,
            	3770, 408,
            	60, 416,
            	57, 424,
            	74, 480,
            	63, 488,
            	57, 496,
            	6748, 504,
            	57, 512,
            	69, 520,
            	6751, 528,
            	6754, 536,
            	6757, 552,
            	6757, 560,
            	26, 568,
            	0, 696,
            	57, 704,
            	6777, 712,
            	57, 720,
            	6780, 728,
            1, 8, 1, /* 6411: pointer.struct.ssl_method_st */
            	6222, 0,
            1, 8, 1, /* 6416: pointer.struct.lhash_st */
            	6421, 0,
            0, 176, 3, /* 6421: struct.lhash_st */
            	6430, 0,
            	444, 8,
            	6449, 16,
            8884099, 8, 2, /* 6430: pointer_to_array_of_pointers_to_stack */
            	6437, 0,
            	15, 28,
            1, 8, 1, /* 6437: pointer.struct.lhash_node_st */
            	6442, 0,
            0, 24, 2, /* 6442: struct.lhash_node_st */
            	57, 0,
            	6437, 8,
            8884097, 8, 0, /* 6449: pointer.func */
            1, 8, 1, /* 6452: pointer.struct.ssl_session_st */
            	6457, 0,
            0, 352, 14, /* 6457: struct.ssl_session_st */
            	69, 144,
            	69, 152,
            	4568, 168,
            	6488, 176,
            	6647, 224,
            	6110, 240,
            	4555, 248,
            	6452, 264,
            	6452, 272,
            	69, 280,
            	185, 296,
            	185, 312,
            	185, 320,
            	69, 344,
            1, 8, 1, /* 6488: pointer.struct.x509_st */
            	6493, 0,
            0, 184, 12, /* 6493: struct.x509_st */
            	6520, 0,
            	4533, 8,
            	6603, 16,
            	69, 32,
            	4555, 40,
            	4434, 104,
            	6608, 112,
            	2767, 120,
            	4463, 128,
            	6613, 136,
            	6637, 144,
            	6642, 176,
            1, 8, 1, /* 6520: pointer.struct.x509_cinf_st */
            	6525, 0,
            0, 104, 11, /* 6525: struct.x509_cinf_st */
            	4538, 0,
            	4538, 8,
            	4533, 16,
            	6550, 24,
            	6598, 32,
            	6550, 40,
            	4516, 48,
            	6603, 56,
            	6603, 64,
            	4492, 72,
            	4487, 80,
            1, 8, 1, /* 6550: pointer.struct.X509_name_st */
            	6555, 0,
            0, 40, 3, /* 6555: struct.X509_name_st */
            	6564, 0,
            	6588, 16,
            	185, 24,
            1, 8, 1, /* 6564: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6569, 0,
            0, 32, 2, /* 6569: struct.stack_st_fake_X509_NAME_ENTRY */
            	6576, 8,
            	444, 24,
            8884099, 8, 2, /* 6576: pointer_to_array_of_pointers_to_stack */
            	6583, 0,
            	18, 20,
            0, 8, 1, /* 6583: pointer.X509_NAME_ENTRY */
            	408, 0,
            1, 8, 1, /* 6588: pointer.struct.buf_mem_st */
            	6593, 0,
            0, 24, 1, /* 6593: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 6598: pointer.struct.X509_val_st */
            	4526, 0,
            1, 8, 1, /* 6603: pointer.struct.asn1_string_st */
            	4429, 0,
            1, 8, 1, /* 6608: pointer.struct.AUTHORITY_KEYID_st */
            	2449, 0,
            1, 8, 1, /* 6613: pointer.struct.stack_st_GENERAL_NAME */
            	6618, 0,
            0, 32, 2, /* 6618: struct.stack_st_fake_GENERAL_NAME */
            	6625, 8,
            	444, 24,
            8884099, 8, 2, /* 6625: pointer_to_array_of_pointers_to_stack */
            	6632, 0,
            	18, 20,
            0, 8, 1, /* 6632: pointer.GENERAL_NAME */
            	2492, 0,
            1, 8, 1, /* 6637: pointer.struct.NAME_CONSTRAINTS_st */
            	3366, 0,
            1, 8, 1, /* 6642: pointer.struct.x509_cert_aux_st */
            	4387, 0,
            1, 8, 1, /* 6647: pointer.struct.ssl_cipher_st */
            	4382, 0,
            8884097, 8, 0, /* 6652: pointer.func */
            8884097, 8, 0, /* 6655: pointer.func */
            8884097, 8, 0, /* 6658: pointer.func */
            8884097, 8, 0, /* 6661: pointer.func */
            8884097, 8, 0, /* 6664: pointer.func */
            8884097, 8, 0, /* 6667: pointer.func */
            1, 8, 1, /* 6670: pointer.struct.env_md_st */
            	4348, 0,
            1, 8, 1, /* 6675: pointer.struct.stack_st_SSL_COMP */
            	6680, 0,
            0, 32, 2, /* 6680: struct.stack_st_fake_SSL_COMP */
            	6687, 8,
            	444, 24,
            8884099, 8, 2, /* 6687: pointer_to_array_of_pointers_to_stack */
            	6694, 0,
            	18, 20,
            0, 8, 1, /* 6694: pointer.SSL_COMP */
            	6699, 0,
            0, 0, 1, /* 6699: SSL_COMP */
            	6704, 0,
            0, 24, 2, /* 6704: struct.ssl_comp_st */
            	219, 8,
            	6711, 16,
            1, 8, 1, /* 6711: pointer.struct.comp_method_st */
            	6716, 0,
            0, 64, 7, /* 6716: struct.comp_method_st */
            	219, 8,
            	6733, 16,
            	6736, 24,
            	6739, 32,
            	6739, 40,
            	6302, 48,
            	6302, 56,
            8884097, 8, 0, /* 6733: pointer.func */
            8884097, 8, 0, /* 6736: pointer.func */
            8884097, 8, 0, /* 6739: pointer.func */
            8884097, 8, 0, /* 6742: pointer.func */
            8884097, 8, 0, /* 6745: pointer.func */
            8884097, 8, 0, /* 6748: pointer.func */
            8884097, 8, 0, /* 6751: pointer.func */
            8884097, 8, 0, /* 6754: pointer.func */
            1, 8, 1, /* 6757: pointer.struct.ssl3_buf_freelist_st */
            	6762, 0,
            0, 24, 1, /* 6762: struct.ssl3_buf_freelist_st */
            	6767, 16,
            1, 8, 1, /* 6767: pointer.struct.ssl3_buf_freelist_entry_st */
            	6772, 0,
            0, 8, 1, /* 6772: struct.ssl3_buf_freelist_entry_st */
            	6767, 0,
            8884097, 8, 0, /* 6777: pointer.func */
            1, 8, 1, /* 6780: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6785, 0,
            0, 32, 2, /* 6785: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6792, 8,
            	444, 24,
            8884099, 8, 2, /* 6792: pointer_to_array_of_pointers_to_stack */
            	6799, 0,
            	18, 20,
            0, 8, 1, /* 6799: pointer.SRTP_PROTECTION_PROFILE */
            	6804, 0,
            0, 0, 1, /* 6804: SRTP_PROTECTION_PROFILE */
            	6809, 0,
            0, 16, 1, /* 6809: struct.srtp_protection_profile_st */
            	219, 0,
            1, 8, 1, /* 6814: pointer.struct.ssl_ctx_st */
            	6308, 0,
            0, 16, 1, /* 6819: struct.srtp_protection_profile_st */
            	219, 0,
            0, 16, 1, /* 6824: struct.tls_session_ticket_ext_st */
            	57, 8,
            0, 0, 1, /* 6829: OCSP_RESPID */
            	6834, 0,
            0, 16, 1, /* 6834: struct.ocsp_responder_id_st */
            	6839, 8,
            0, 8, 2, /* 6839: union.unknown */
            	2702, 0,
            	2639, 0,
            8884097, 8, 0, /* 6846: pointer.func */
            0, 24, 1, /* 6849: struct.bignum_st */
            	6854, 0,
            8884099, 8, 2, /* 6854: pointer_to_array_of_pointers_to_stack */
            	15, 0,
            	18, 12,
            1, 8, 1, /* 6861: pointer.struct.bignum_st */
            	6849, 0,
            1, 8, 1, /* 6866: pointer.struct.ssl3_buf_freelist_st */
            	6762, 0,
            8884097, 8, 0, /* 6871: pointer.func */
            8884097, 8, 0, /* 6874: pointer.func */
            8884097, 8, 0, /* 6877: pointer.func */
            8884097, 8, 0, /* 6880: pointer.func */
            8884097, 8, 0, /* 6883: pointer.func */
            8884097, 8, 0, /* 6886: pointer.func */
            8884097, 8, 0, /* 6889: pointer.func */
            8884097, 8, 0, /* 6892: pointer.func */
            8884097, 8, 0, /* 6895: pointer.func */
            1, 8, 1, /* 6898: pointer.struct.stack_st_X509_LOOKUP */
            	6903, 0,
            0, 32, 2, /* 6903: struct.stack_st_fake_X509_LOOKUP */
            	6910, 8,
            	444, 24,
            8884099, 8, 2, /* 6910: pointer_to_array_of_pointers_to_stack */
            	6917, 0,
            	18, 20,
            0, 8, 1, /* 6917: pointer.X509_LOOKUP */
            	5057, 0,
            1, 8, 1, /* 6922: pointer.struct.stack_st_X509_OBJECT */
            	6927, 0,
            0, 32, 2, /* 6927: struct.stack_st_fake_X509_OBJECT */
            	6934, 8,
            	444, 24,
            8884099, 8, 2, /* 6934: pointer_to_array_of_pointers_to_stack */
            	6941, 0,
            	18, 20,
            0, 8, 1, /* 6941: pointer.X509_OBJECT */
            	5182, 0,
            1, 8, 1, /* 6946: pointer.struct.ssl_ctx_st */
            	6951, 0,
            0, 736, 50, /* 6951: struct.ssl_ctx_st */
            	7054, 0,
            	7171, 8,
            	7171, 16,
            	7195, 24,
            	6416, 32,
            	7303, 48,
            	7303, 56,
            	6880, 80,
            	7587, 88,
            	7590, 96,
            	6877, 152,
            	57, 160,
            	6661, 168,
            	57, 176,
            	6874, 184,
            	7593, 192,
            	7596, 200,
            	7281, 208,
            	7599, 224,
            	7599, 232,
            	7599, 240,
            	7638, 248,
            	7662, 256,
            	7686, 264,
            	7689, 272,
            	7713, 304,
            	7718, 320,
            	57, 328,
            	7272, 376,
            	7721, 384,
            	7233, 392,
            	3770, 408,
            	7724, 416,
            	57, 424,
            	7727, 480,
            	7730, 488,
            	57, 496,
            	6871, 504,
            	57, 512,
            	69, 520,
            	7733, 528,
            	7736, 536,
            	6866, 552,
            	6866, 560,
            	7739, 568,
            	7773, 696,
            	57, 704,
            	6846, 712,
            	57, 720,
            	7776, 728,
            1, 8, 1, /* 7054: pointer.struct.ssl_method_st */
            	7059, 0,
            0, 232, 28, /* 7059: struct.ssl_method_st */
            	7118, 8,
            	7121, 16,
            	7121, 24,
            	7118, 32,
            	7118, 40,
            	7124, 48,
            	7124, 56,
            	7127, 64,
            	7118, 72,
            	7118, 80,
            	7118, 88,
            	7130, 96,
            	7133, 104,
            	7136, 112,
            	7118, 120,
            	7139, 128,
            	7142, 136,
            	7145, 144,
            	7148, 152,
            	7151, 160,
            	894, 168,
            	7154, 176,
            	7157, 184,
            	6302, 192,
            	7160, 200,
            	894, 208,
            	7165, 216,
            	7168, 224,
            8884097, 8, 0, /* 7118: pointer.func */
            8884097, 8, 0, /* 7121: pointer.func */
            8884097, 8, 0, /* 7124: pointer.func */
            8884097, 8, 0, /* 7127: pointer.func */
            8884097, 8, 0, /* 7130: pointer.func */
            8884097, 8, 0, /* 7133: pointer.func */
            8884097, 8, 0, /* 7136: pointer.func */
            8884097, 8, 0, /* 7139: pointer.func */
            8884097, 8, 0, /* 7142: pointer.func */
            8884097, 8, 0, /* 7145: pointer.func */
            8884097, 8, 0, /* 7148: pointer.func */
            8884097, 8, 0, /* 7151: pointer.func */
            8884097, 8, 0, /* 7154: pointer.func */
            8884097, 8, 0, /* 7157: pointer.func */
            1, 8, 1, /* 7160: pointer.struct.ssl3_enc_method */
            	6152, 0,
            8884097, 8, 0, /* 7165: pointer.func */
            8884097, 8, 0, /* 7168: pointer.func */
            1, 8, 1, /* 7171: pointer.struct.stack_st_SSL_CIPHER */
            	7176, 0,
            0, 32, 2, /* 7176: struct.stack_st_fake_SSL_CIPHER */
            	7183, 8,
            	444, 24,
            8884099, 8, 2, /* 7183: pointer_to_array_of_pointers_to_stack */
            	7190, 0,
            	18, 20,
            0, 8, 1, /* 7190: pointer.SSL_CIPHER */
            	6134, 0,
            1, 8, 1, /* 7195: pointer.struct.x509_store_st */
            	7200, 0,
            0, 144, 15, /* 7200: struct.x509_store_st */
            	6922, 8,
            	6898, 16,
            	7233, 24,
            	7269, 32,
            	7272, 40,
            	7275, 48,
            	6895, 56,
            	7269, 64,
            	6892, 72,
            	6889, 80,
            	6886, 88,
            	6883, 96,
            	7278, 104,
            	7269, 112,
            	7281, 120,
            1, 8, 1, /* 7233: pointer.struct.X509_VERIFY_PARAM_st */
            	7238, 0,
            0, 56, 2, /* 7238: struct.X509_VERIFY_PARAM_st */
            	69, 0,
            	7245, 48,
            1, 8, 1, /* 7245: pointer.struct.stack_st_ASN1_OBJECT */
            	7250, 0,
            0, 32, 2, /* 7250: struct.stack_st_fake_ASN1_OBJECT */
            	7257, 8,
            	444, 24,
            8884099, 8, 2, /* 7257: pointer_to_array_of_pointers_to_stack */
            	7264, 0,
            	18, 20,
            0, 8, 1, /* 7264: pointer.ASN1_OBJECT */
            	3084, 0,
            8884097, 8, 0, /* 7269: pointer.func */
            8884097, 8, 0, /* 7272: pointer.func */
            8884097, 8, 0, /* 7275: pointer.func */
            8884097, 8, 0, /* 7278: pointer.func */
            0, 16, 1, /* 7281: struct.crypto_ex_data_st */
            	7286, 0,
            1, 8, 1, /* 7286: pointer.struct.stack_st_void */
            	7291, 0,
            0, 32, 1, /* 7291: struct.stack_st_void */
            	7296, 0,
            0, 32, 2, /* 7296: struct.stack_st */
            	963, 8,
            	444, 24,
            1, 8, 1, /* 7303: pointer.struct.ssl_session_st */
            	7308, 0,
            0, 352, 14, /* 7308: struct.ssl_session_st */
            	69, 144,
            	69, 152,
            	7339, 168,
            	7344, 176,
            	7577, 224,
            	7171, 240,
            	7281, 248,
            	7303, 264,
            	7303, 272,
            	69, 280,
            	185, 296,
            	185, 312,
            	185, 320,
            	69, 344,
            1, 8, 1, /* 7339: pointer.struct.sess_cert_st */
            	4573, 0,
            1, 8, 1, /* 7344: pointer.struct.x509_st */
            	7349, 0,
            0, 184, 12, /* 7349: struct.x509_st */
            	7376, 0,
            	7416, 8,
            	7491, 16,
            	69, 32,
            	7281, 40,
            	7525, 104,
            	2444, 112,
            	2767, 120,
            	3198, 128,
            	3337, 136,
            	3361, 144,
            	7530, 176,
            1, 8, 1, /* 7376: pointer.struct.x509_cinf_st */
            	7381, 0,
            0, 104, 11, /* 7381: struct.x509_cinf_st */
            	7406, 0,
            	7406, 8,
            	7416, 16,
            	7421, 24,
            	7469, 32,
            	7421, 40,
            	7486, 48,
            	7491, 56,
            	7491, 64,
            	7496, 72,
            	7520, 80,
            1, 8, 1, /* 7406: pointer.struct.asn1_string_st */
            	7411, 0,
            0, 24, 1, /* 7411: struct.asn1_string_st */
            	185, 8,
            1, 8, 1, /* 7416: pointer.struct.X509_algor_st */
            	198, 0,
            1, 8, 1, /* 7421: pointer.struct.X509_name_st */
            	7426, 0,
            0, 40, 3, /* 7426: struct.X509_name_st */
            	7435, 0,
            	7459, 16,
            	185, 24,
            1, 8, 1, /* 7435: pointer.struct.stack_st_X509_NAME_ENTRY */
            	7440, 0,
            0, 32, 2, /* 7440: struct.stack_st_fake_X509_NAME_ENTRY */
            	7447, 8,
            	444, 24,
            8884099, 8, 2, /* 7447: pointer_to_array_of_pointers_to_stack */
            	7454, 0,
            	18, 20,
            0, 8, 1, /* 7454: pointer.X509_NAME_ENTRY */
            	408, 0,
            1, 8, 1, /* 7459: pointer.struct.buf_mem_st */
            	7464, 0,
            0, 24, 1, /* 7464: struct.buf_mem_st */
            	69, 8,
            1, 8, 1, /* 7469: pointer.struct.X509_val_st */
            	7474, 0,
            0, 16, 2, /* 7474: struct.X509_val_st */
            	7481, 0,
            	7481, 8,
            1, 8, 1, /* 7481: pointer.struct.asn1_string_st */
            	7411, 0,
            1, 8, 1, /* 7486: pointer.struct.X509_pubkey_st */
            	479, 0,
            1, 8, 1, /* 7491: pointer.struct.asn1_string_st */
            	7411, 0,
            1, 8, 1, /* 7496: pointer.struct.stack_st_X509_EXTENSION */
            	7501, 0,
            0, 32, 2, /* 7501: struct.stack_st_fake_X509_EXTENSION */
            	7508, 8,
            	444, 24,
            8884099, 8, 2, /* 7508: pointer_to_array_of_pointers_to_stack */
            	7515, 0,
            	18, 20,
            0, 8, 1, /* 7515: pointer.X509_EXTENSION */
            	2376, 0,
            0, 24, 1, /* 7520: struct.ASN1_ENCODING_st */
            	185, 0,
            1, 8, 1, /* 7525: pointer.struct.asn1_string_st */
            	7411, 0,
            1, 8, 1, /* 7530: pointer.struct.x509_cert_aux_st */
            	7535, 0,
            0, 40, 5, /* 7535: struct.x509_cert_aux_st */
            	7245, 0,
            	7245, 8,
            	7548, 16,
            	7525, 24,
            	7553, 32,
            1, 8, 1, /* 7548: pointer.struct.asn1_string_st */
            	7411, 0,
            1, 8, 1, /* 7553: pointer.struct.stack_st_X509_ALGOR */
            	7558, 0,
            0, 32, 2, /* 7558: struct.stack_st_fake_X509_ALGOR */
            	7565, 8,
            	444, 24,
            8884099, 8, 2, /* 7565: pointer_to_array_of_pointers_to_stack */
            	7572, 0,
            	18, 20,
            0, 8, 1, /* 7572: pointer.X509_ALGOR */
            	3744, 0,
            1, 8, 1, /* 7577: pointer.struct.ssl_cipher_st */
            	7582, 0,
            0, 88, 1, /* 7582: struct.ssl_cipher_st */
            	219, 8,
            8884097, 8, 0, /* 7587: pointer.func */
            8884097, 8, 0, /* 7590: pointer.func */
            8884097, 8, 0, /* 7593: pointer.func */
            8884097, 8, 0, /* 7596: pointer.func */
            1, 8, 1, /* 7599: pointer.struct.env_md_st */
            	7604, 0,
            0, 120, 8, /* 7604: struct.env_md_st */
            	7623, 24,
            	7626, 32,
            	7629, 40,
            	7632, 48,
            	7623, 56,
            	3868, 64,
            	3871, 72,
            	7635, 112,
            8884097, 8, 0, /* 7623: pointer.func */
            8884097, 8, 0, /* 7626: pointer.func */
            8884097, 8, 0, /* 7629: pointer.func */
            8884097, 8, 0, /* 7632: pointer.func */
            8884097, 8, 0, /* 7635: pointer.func */
            1, 8, 1, /* 7638: pointer.struct.stack_st_X509 */
            	7643, 0,
            0, 32, 2, /* 7643: struct.stack_st_fake_X509 */
            	7650, 8,
            	444, 24,
            8884099, 8, 2, /* 7650: pointer_to_array_of_pointers_to_stack */
            	7657, 0,
            	18, 20,
            0, 8, 1, /* 7657: pointer.X509 */
            	4000, 0,
            1, 8, 1, /* 7662: pointer.struct.stack_st_SSL_COMP */
            	7667, 0,
            0, 32, 2, /* 7667: struct.stack_st_fake_SSL_COMP */
            	7674, 8,
            	444, 24,
            8884099, 8, 2, /* 7674: pointer_to_array_of_pointers_to_stack */
            	7681, 0,
            	18, 20,
            0, 8, 1, /* 7681: pointer.SSL_COMP */
            	6699, 0,
            8884097, 8, 0, /* 7686: pointer.func */
            1, 8, 1, /* 7689: pointer.struct.stack_st_X509_NAME */
            	7694, 0,
            0, 32, 2, /* 7694: struct.stack_st_fake_X509_NAME */
            	7701, 8,
            	444, 24,
            8884099, 8, 2, /* 7701: pointer_to_array_of_pointers_to_stack */
            	7708, 0,
            	18, 20,
            0, 8, 1, /* 7708: pointer.X509_NAME */
            	3925, 0,
            1, 8, 1, /* 7713: pointer.struct.cert_st */
            	82, 0,
            8884097, 8, 0, /* 7718: pointer.func */
            8884097, 8, 0, /* 7721: pointer.func */
            8884097, 8, 0, /* 7724: pointer.func */
            8884097, 8, 0, /* 7727: pointer.func */
            8884097, 8, 0, /* 7730: pointer.func */
            8884097, 8, 0, /* 7733: pointer.func */
            8884097, 8, 0, /* 7736: pointer.func */
            0, 128, 14, /* 7739: struct.srp_ctx_st */
            	57, 0,
            	7724, 8,
            	7730, 16,
            	7770, 24,
            	69, 32,
            	6861, 40,
            	6861, 48,
            	6861, 56,
            	6861, 64,
            	6861, 72,
            	6861, 80,
            	6861, 88,
            	6861, 96,
            	69, 104,
            8884097, 8, 0, /* 7770: pointer.func */
            8884097, 8, 0, /* 7773: pointer.func */
            1, 8, 1, /* 7776: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	7781, 0,
            0, 32, 2, /* 7781: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	7788, 8,
            	444, 24,
            8884099, 8, 2, /* 7788: pointer_to_array_of_pointers_to_stack */
            	7795, 0,
            	18, 20,
            0, 8, 1, /* 7795: pointer.SRTP_PROTECTION_PROFILE */
            	6804, 0,
            1, 8, 1, /* 7800: pointer.struct.tls_session_ticket_ext_st */
            	6824, 0,
            1, 8, 1, /* 7805: pointer.struct.srtp_protection_profile_st */
            	6819, 0,
            1, 8, 1, /* 7810: pointer.struct.stack_st_X509_ATTRIBUTE */
            	7815, 0,
            0, 32, 2, /* 7815: struct.stack_st_fake_X509_ATTRIBUTE */
            	7822, 8,
            	444, 24,
            8884099, 8, 2, /* 7822: pointer_to_array_of_pointers_to_stack */
            	7829, 0,
            	18, 20,
            0, 8, 1, /* 7829: pointer.X509_ATTRIBUTE */
            	2000, 0,
            8884097, 8, 0, /* 7834: pointer.func */
            8884097, 8, 0, /* 7837: pointer.func */
            1, 8, 1, /* 7840: pointer.struct.dh_st */
            	1346, 0,
            1, 8, 1, /* 7845: pointer.struct.ec_key_st */
            	1472, 0,
            1, 8, 1, /* 7850: pointer.struct.stack_st_X509_EXTENSION */
            	7855, 0,
            0, 32, 2, /* 7855: struct.stack_st_fake_X509_EXTENSION */
            	7862, 8,
            	444, 24,
            8884099, 8, 2, /* 7862: pointer_to_array_of_pointers_to_stack */
            	7869, 0,
            	18, 20,
            0, 8, 1, /* 7869: pointer.X509_EXTENSION */
            	2376, 0,
            8884097, 8, 0, /* 7874: pointer.func */
            1, 8, 1, /* 7877: pointer.struct.stack_st_OCSP_RESPID */
            	7882, 0,
            0, 32, 2, /* 7882: struct.stack_st_fake_OCSP_RESPID */
            	7889, 8,
            	444, 24,
            8884099, 8, 2, /* 7889: pointer_to_array_of_pointers_to_stack */
            	7896, 0,
            	18, 20,
            0, 8, 1, /* 7896: pointer.OCSP_RESPID */
            	6829, 0,
            1, 8, 1, /* 7901: pointer.struct.rsa_st */
            	991, 0,
            0, 16, 1, /* 7906: struct.record_pqueue_st */
            	7911, 8,
            1, 8, 1, /* 7911: pointer.struct._pqueue */
            	7916, 0,
            0, 16, 1, /* 7916: struct._pqueue */
            	7921, 0,
            1, 8, 1, /* 7921: pointer.struct._pitem */
            	7926, 0,
            0, 24, 2, /* 7926: struct._pitem */
            	57, 8,
            	7933, 16,
            1, 8, 1, /* 7933: pointer.struct._pitem */
            	7926, 0,
            1, 8, 1, /* 7938: pointer.struct.evp_pkey_asn1_method_st */
            	524, 0,
            1, 8, 1, /* 7943: pointer.struct.evp_pkey_st */
            	7948, 0,
            0, 56, 4, /* 7948: struct.evp_pkey_st */
            	7938, 16,
            	1462, 24,
            	7959, 32,
            	7810, 48,
            0, 8, 5, /* 7959: union.unknown */
            	69, 0,
            	7901, 0,
            	7972, 0,
            	7840, 0,
            	7845, 0,
            1, 8, 1, /* 7972: pointer.struct.dsa_st */
            	1207, 0,
            8884097, 8, 0, /* 7977: pointer.func */
            8884097, 8, 0, /* 7980: pointer.func */
            8884097, 8, 0, /* 7983: pointer.func */
            0, 80, 8, /* 7986: struct.evp_pkey_ctx_st */
            	8005, 0,
            	1462, 8,
            	7943, 16,
            	7943, 24,
            	57, 40,
            	57, 48,
            	8090, 56,
            	8093, 64,
            1, 8, 1, /* 8005: pointer.struct.evp_pkey_method_st */
            	8010, 0,
            0, 208, 25, /* 8010: struct.evp_pkey_method_st */
            	8063, 8,
            	8066, 16,
            	8069, 24,
            	8063, 32,
            	8072, 40,
            	8063, 48,
            	8072, 56,
            	8063, 64,
            	7983, 72,
            	8063, 80,
            	8075, 88,
            	8063, 96,
            	7983, 104,
            	7980, 112,
            	7977, 120,
            	7980, 128,
            	8078, 136,
            	8063, 144,
            	7983, 152,
            	8063, 160,
            	7983, 168,
            	8063, 176,
            	8081, 184,
            	8084, 192,
            	8087, 200,
            8884097, 8, 0, /* 8063: pointer.func */
            8884097, 8, 0, /* 8066: pointer.func */
            8884097, 8, 0, /* 8069: pointer.func */
            8884097, 8, 0, /* 8072: pointer.func */
            8884097, 8, 0, /* 8075: pointer.func */
            8884097, 8, 0, /* 8078: pointer.func */
            8884097, 8, 0, /* 8081: pointer.func */
            8884097, 8, 0, /* 8084: pointer.func */
            8884097, 8, 0, /* 8087: pointer.func */
            8884097, 8, 0, /* 8090: pointer.func */
            1, 8, 1, /* 8093: pointer.int */
            	18, 0,
            8884097, 8, 0, /* 8098: pointer.func */
            1, 8, 1, /* 8101: pointer.struct.bio_st */
            	8106, 0,
            0, 112, 7, /* 8106: struct.bio_st */
            	8123, 0,
            	8164, 8,
            	69, 16,
            	57, 48,
            	8101, 56,
            	8101, 64,
            	7281, 96,
            1, 8, 1, /* 8123: pointer.struct.bio_method_st */
            	8128, 0,
            0, 80, 9, /* 8128: struct.bio_method_st */
            	219, 8,
            	8149, 16,
            	8152, 24,
            	8155, 32,
            	8152, 40,
            	7837, 48,
            	8158, 56,
            	8158, 64,
            	8161, 72,
            8884097, 8, 0, /* 8149: pointer.func */
            8884097, 8, 0, /* 8152: pointer.func */
            8884097, 8, 0, /* 8155: pointer.func */
            8884097, 8, 0, /* 8158: pointer.func */
            8884097, 8, 0, /* 8161: pointer.func */
            8884097, 8, 0, /* 8164: pointer.func */
            1, 8, 1, /* 8167: pointer.struct.dh_st */
            	1346, 0,
            0, 1200, 10, /* 8172: struct.ssl3_state_st */
            	8195, 240,
            	8195, 264,
            	8200, 288,
            	8200, 344,
            	224, 432,
            	8209, 440,
            	8214, 448,
            	57, 496,
            	57, 512,
            	8242, 528,
            0, 24, 1, /* 8195: struct.ssl3_buffer_st */
            	185, 0,
            0, 56, 3, /* 8200: struct.ssl3_record_st */
            	185, 16,
            	185, 24,
            	185, 32,
            1, 8, 1, /* 8209: pointer.struct.bio_st */
            	8106, 0,
            1, 8, 1, /* 8214: pointer.pointer.struct.env_md_ctx_st */
            	8219, 0,
            1, 8, 1, /* 8219: pointer.struct.env_md_ctx_st */
            	8224, 0,
            0, 48, 5, /* 8224: struct.env_md_ctx_st */
            	7599, 0,
            	3770, 8,
            	57, 24,
            	8237, 32,
            	7626, 40,
            1, 8, 1, /* 8237: pointer.struct.evp_pkey_ctx_st */
            	7986, 0,
            0, 528, 8, /* 8242: struct.unknown */
            	7577, 408,
            	8167, 416,
            	3893, 424,
            	7689, 464,
            	185, 480,
            	8261, 488,
            	7599, 496,
            	8295, 512,
            1, 8, 1, /* 8261: pointer.struct.evp_cipher_st */
            	8266, 0,
            0, 88, 7, /* 8266: struct.evp_cipher_st */
            	8283, 24,
            	8286, 32,
            	7874, 40,
            	8289, 56,
            	8289, 64,
            	8292, 72,
            	57, 80,
            8884097, 8, 0, /* 8283: pointer.func */
            8884097, 8, 0, /* 8286: pointer.func */
            8884097, 8, 0, /* 8289: pointer.func */
            8884097, 8, 0, /* 8292: pointer.func */
            1, 8, 1, /* 8295: pointer.struct.ssl_comp_st */
            	8300, 0,
            0, 24, 2, /* 8300: struct.ssl_comp_st */
            	219, 8,
            	8307, 16,
            1, 8, 1, /* 8307: pointer.struct.comp_method_st */
            	8312, 0,
            0, 64, 7, /* 8312: struct.comp_method_st */
            	219, 8,
            	8098, 16,
            	8329, 24,
            	7834, 32,
            	7834, 40,
            	6302, 48,
            	6302, 56,
            8884097, 8, 0, /* 8329: pointer.func */
            0, 1, 0, /* 8332: char */
            1, 8, 1, /* 8335: pointer.struct.ssl3_state_st */
            	8172, 0,
            0, 808, 51, /* 8340: struct.ssl_st */
            	7054, 8,
            	8209, 16,
            	8209, 24,
            	8209, 32,
            	7118, 48,
            	7459, 80,
            	57, 88,
            	185, 104,
            	8445, 120,
            	8335, 128,
            	8471, 136,
            	7718, 152,
            	57, 160,
            	7233, 176,
            	7171, 184,
            	7171, 192,
            	8509, 208,
            	8219, 216,
            	8525, 224,
            	8509, 232,
            	8219, 240,
            	8525, 248,
            	7713, 256,
            	8537, 304,
            	7721, 312,
            	7272, 328,
            	7686, 336,
            	7733, 352,
            	7736, 360,
            	6946, 368,
            	7281, 392,
            	7689, 408,
            	8542, 464,
            	57, 472,
            	69, 480,
            	7877, 504,
            	7850, 512,
            	185, 520,
            	185, 544,
            	185, 560,
            	57, 568,
            	7800, 584,
            	8545, 592,
            	57, 600,
            	8548, 608,
            	57, 616,
            	6946, 624,
            	185, 632,
            	7776, 648,
            	7805, 656,
            	7739, 680,
            1, 8, 1, /* 8445: pointer.struct.ssl2_state_st */
            	8450, 0,
            0, 344, 9, /* 8450: struct.ssl2_state_st */
            	224, 24,
            	185, 56,
            	185, 64,
            	185, 72,
            	185, 104,
            	185, 112,
            	185, 120,
            	185, 128,
            	185, 136,
            1, 8, 1, /* 8471: pointer.struct.dtls1_state_st */
            	8476, 0,
            0, 888, 7, /* 8476: struct.dtls1_state_st */
            	7906, 576,
            	7906, 592,
            	7911, 608,
            	7911, 616,
            	7906, 624,
            	8493, 648,
            	8493, 736,
            0, 88, 1, /* 8493: struct.hm_header_st */
            	8498, 48,
            0, 40, 4, /* 8498: struct.dtls1_retransmit_state */
            	8509, 0,
            	8219, 8,
            	8525, 16,
            	8537, 24,
            1, 8, 1, /* 8509: pointer.struct.evp_cipher_ctx_st */
            	8514, 0,
            0, 168, 4, /* 8514: struct.evp_cipher_ctx_st */
            	8261, 0,
            	3770, 8,
            	57, 96,
            	57, 120,
            1, 8, 1, /* 8525: pointer.struct.comp_ctx_st */
            	8530, 0,
            0, 56, 2, /* 8530: struct.comp_ctx_st */
            	8307, 0,
            	7281, 40,
            1, 8, 1, /* 8537: pointer.struct.ssl_session_st */
            	7308, 0,
            8884097, 8, 0, /* 8542: pointer.func */
            8884097, 8, 0, /* 8545: pointer.func */
            8884097, 8, 0, /* 8548: pointer.func */
            1, 8, 1, /* 8551: pointer.struct.ssl_st */
            	8340, 0,
        },
        .arg_entity_index = { 6814, },
        .ret_entity_index = 8551,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    SSL * *new_ret_ptr = (SSL * *)new_args->ret;

    SSL * (*orig_SSL_new)(SSL_CTX *);
    orig_SSL_new = dlsym(RTLD_NEXT, "SSL_new");
    *new_ret_ptr = (*orig_SSL_new)(new_arg_a);

    syscall(889);

    return ret;
}

