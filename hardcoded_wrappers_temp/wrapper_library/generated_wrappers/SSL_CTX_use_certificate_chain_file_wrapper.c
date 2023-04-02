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

int bb_SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b);

int SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_use_certificate_chain_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_use_certificate_chain_file(arg_a,arg_b);
    else {
        int (*orig_SSL_CTX_use_certificate_chain_file)(SSL_CTX *,const char *);
        orig_SSL_CTX_use_certificate_chain_file = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate_chain_file");
        return orig_SSL_CTX_use_certificate_chain_file(arg_a,arg_b);
    }
}

int bb_SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            4097, 8, 0, /* 3: pointer.func */
            0, 0, 0, /* 6: func */
            0, 0, 0, /* 9: func */
            4097, 8, 0, /* 12: pointer.func */
            0, 128, 14, /* 15: struct.srp_ctx_st */
            	46, 0,
            	49, 8,
            	52, 16,
            	12, 24,
            	55, 32,
            	60, 40,
            	60, 48,
            	60, 56,
            	60, 64,
            	60, 72,
            	60, 80,
            	60, 88,
            	60, 96,
            	55, 104,
            0, 8, 0, /* 46: pointer.void */
            4097, 8, 0, /* 49: pointer.func */
            4097, 8, 0, /* 52: pointer.func */
            1, 8, 1, /* 55: pointer.char */
            	4096, 0,
            1, 8, 1, /* 60: pointer.struct.bignum_st */
            	65, 0,
            0, 24, 1, /* 65: struct.bignum_st */
            	70, 0,
            1, 8, 1, /* 70: pointer.int */
            	75, 0,
            0, 4, 0, /* 75: int */
            0, 0, 0, /* 78: func */
            4097, 8, 0, /* 81: pointer.func */
            0, 0, 0, /* 84: func */
            4097, 8, 0, /* 87: pointer.func */
            0, 0, 0, /* 90: func */
            4097, 8, 0, /* 93: pointer.func */
            0, 16, 0, /* 96: array[16].char */
            0, 0, 0, /* 99: func */
            0, 0, 0, /* 102: func */
            0, 0, 0, /* 105: func */
            4097, 8, 0, /* 108: pointer.func */
            1, 8, 1, /* 111: pointer.struct.cert_st */
            	116, 0,
            0, 296, 8, /* 116: struct.cert_st */
            	135, 0,
            	902, 48,
            	985, 56,
            	988, 64,
            	1020, 72,
            	1023, 80,
            	108, 88,
            	1259, 96,
            1, 8, 1, /* 135: pointer.struct.cert_pkey_st */
            	140, 0,
            0, 24, 3, /* 140: struct.cert_pkey_st */
            	149, 0,
            	337, 8,
            	857, 16,
            1, 8, 1, /* 149: pointer.struct.x509_st */
            	154, 0,
            0, 184, 12, /* 154: struct.x509_st */
            	181, 0,
            	221, 8,
            	211, 16,
            	55, 32,
            	777, 40,
            	211, 104,
            	787, 112,
            	801, 120,
            	276, 128,
            	276, 136,
            	827, 144,
            	839, 176,
            1, 8, 1, /* 181: pointer.struct.x509_cinf_st */
            	186, 0,
            0, 104, 11, /* 186: struct.x509_cinf_st */
            	211, 0,
            	211, 8,
            	221, 16,
            	262, 24,
            	311, 32,
            	262, 40,
            	323, 48,
            	211, 56,
            	211, 64,
            	276, 72,
            	782, 80,
            1, 8, 1, /* 211: pointer.struct.asn1_string_st */
            	216, 0,
            0, 24, 1, /* 216: struct.asn1_string_st */
            	55, 8,
            1, 8, 1, /* 221: pointer.struct.X509_algor_st */
            	226, 0,
            0, 16, 2, /* 226: struct.X509_algor_st */
            	233, 0,
            	247, 8,
            1, 8, 1, /* 233: pointer.struct.asn1_object_st */
            	238, 0,
            0, 40, 3, /* 238: struct.asn1_object_st */
            	55, 0,
            	55, 8,
            	55, 24,
            1, 8, 1, /* 247: pointer.struct.asn1_type_st */
            	252, 0,
            0, 16, 1, /* 252: struct.asn1_type_st */
            	257, 8,
            0, 8, 1, /* 257: struct.fnames */
            	55, 0,
            1, 8, 1, /* 262: pointer.struct.X509_name_st */
            	267, 0,
            0, 40, 3, /* 267: struct.X509_name_st */
            	276, 0,
            	301, 16,
            	55, 24,
            1, 8, 1, /* 276: pointer.struct.stack_st_OPENSSL_STRING */
            	281, 0,
            0, 32, 1, /* 281: struct.stack_st_OPENSSL_STRING */
            	286, 0,
            0, 32, 2, /* 286: struct.stack_st */
            	293, 8,
            	298, 24,
            1, 8, 1, /* 293: pointer.pointer.char */
            	55, 0,
            4097, 8, 0, /* 298: pointer.func */
            1, 8, 1, /* 301: pointer.struct.buf_mem_st */
            	306, 0,
            0, 24, 1, /* 306: struct.buf_mem_st */
            	55, 8,
            1, 8, 1, /* 311: pointer.struct.X509_val_st */
            	316, 0,
            0, 16, 2, /* 316: struct.X509_val_st */
            	211, 0,
            	211, 8,
            1, 8, 1, /* 323: pointer.struct.X509_pubkey_st */
            	328, 0,
            0, 24, 3, /* 328: struct.X509_pubkey_st */
            	221, 0,
            	211, 8,
            	337, 16,
            1, 8, 1, /* 337: pointer.struct.evp_pkey_st */
            	342, 0,
            0, 56, 4, /* 342: struct.evp_pkey_st */
            	353, 16,
            	456, 24,
            	257, 32,
            	276, 48,
            1, 8, 1, /* 353: pointer.struct.evp_pkey_asn1_method_st */
            	358, 0,
            0, 208, 24, /* 358: struct.evp_pkey_asn1_method_st */
            	55, 16,
            	55, 24,
            	409, 32,
            	417, 40,
            	420, 48,
            	423, 56,
            	426, 64,
            	429, 72,
            	423, 80,
            	432, 88,
            	432, 96,
            	435, 104,
            	438, 112,
            	432, 120,
            	420, 128,
            	420, 136,
            	423, 144,
            	441, 152,
            	444, 160,
            	447, 168,
            	435, 176,
            	438, 184,
            	450, 192,
            	453, 200,
            1, 8, 1, /* 409: pointer.struct.unnamed */
            	414, 0,
            0, 0, 0, /* 414: struct.unnamed */
            4097, 8, 0, /* 417: pointer.func */
            4097, 8, 0, /* 420: pointer.func */
            4097, 8, 0, /* 423: pointer.func */
            4097, 8, 0, /* 426: pointer.func */
            4097, 8, 0, /* 429: pointer.func */
            4097, 8, 0, /* 432: pointer.func */
            4097, 8, 0, /* 435: pointer.func */
            4097, 8, 0, /* 438: pointer.func */
            4097, 8, 0, /* 441: pointer.func */
            4097, 8, 0, /* 444: pointer.func */
            4097, 8, 0, /* 447: pointer.func */
            4097, 8, 0, /* 450: pointer.func */
            4097, 8, 0, /* 453: pointer.func */
            1, 8, 1, /* 456: pointer.struct.engine_st */
            	461, 0,
            0, 216, 24, /* 461: struct.engine_st */
            	55, 0,
            	55, 8,
            	512, 16,
            	567, 24,
            	618, 32,
            	654, 40,
            	671, 48,
            	698, 56,
            	733, 64,
            	741, 72,
            	744, 80,
            	747, 88,
            	750, 96,
            	753, 104,
            	753, 112,
            	753, 120,
            	756, 128,
            	759, 136,
            	759, 144,
            	762, 152,
            	765, 160,
            	777, 184,
            	456, 200,
            	456, 208,
            1, 8, 1, /* 512: pointer.struct.rsa_meth_st */
            	517, 0,
            0, 112, 13, /* 517: struct.rsa_meth_st */
            	55, 0,
            	546, 8,
            	546, 16,
            	546, 24,
            	546, 32,
            	549, 40,
            	552, 48,
            	555, 56,
            	555, 64,
            	55, 80,
            	558, 88,
            	561, 96,
            	564, 104,
            4097, 8, 0, /* 546: pointer.func */
            4097, 8, 0, /* 549: pointer.func */
            4097, 8, 0, /* 552: pointer.func */
            4097, 8, 0, /* 555: pointer.func */
            4097, 8, 0, /* 558: pointer.func */
            4097, 8, 0, /* 561: pointer.func */
            4097, 8, 0, /* 564: pointer.func */
            1, 8, 1, /* 567: pointer.struct.dsa_method */
            	572, 0,
            0, 96, 11, /* 572: struct.dsa_method */
            	55, 0,
            	597, 8,
            	600, 16,
            	603, 24,
            	606, 32,
            	609, 40,
            	612, 48,
            	612, 56,
            	55, 72,
            	615, 80,
            	612, 88,
            4097, 8, 0, /* 597: pointer.func */
            4097, 8, 0, /* 600: pointer.func */
            4097, 8, 0, /* 603: pointer.func */
            4097, 8, 0, /* 606: pointer.func */
            4097, 8, 0, /* 609: pointer.func */
            4097, 8, 0, /* 612: pointer.func */
            4097, 8, 0, /* 615: pointer.func */
            1, 8, 1, /* 618: pointer.struct.dh_method */
            	623, 0,
            0, 72, 8, /* 623: struct.dh_method */
            	55, 0,
            	642, 8,
            	645, 16,
            	648, 24,
            	642, 32,
            	642, 40,
            	55, 56,
            	651, 64,
            4097, 8, 0, /* 642: pointer.func */
            4097, 8, 0, /* 645: pointer.func */
            4097, 8, 0, /* 648: pointer.func */
            4097, 8, 0, /* 651: pointer.func */
            1, 8, 1, /* 654: pointer.struct.ecdh_method */
            	659, 0,
            0, 32, 3, /* 659: struct.ecdh_method */
            	55, 0,
            	668, 8,
            	55, 24,
            4097, 8, 0, /* 668: pointer.func */
            1, 8, 1, /* 671: pointer.struct.ecdsa_method */
            	676, 0,
            0, 48, 5, /* 676: struct.ecdsa_method */
            	55, 0,
            	689, 8,
            	692, 16,
            	695, 24,
            	55, 40,
            4097, 8, 0, /* 689: pointer.func */
            4097, 8, 0, /* 692: pointer.func */
            4097, 8, 0, /* 695: pointer.func */
            1, 8, 1, /* 698: pointer.struct.rand_meth_st */
            	703, 0,
            0, 48, 6, /* 703: struct.rand_meth_st */
            	718, 0,
            	721, 8,
            	724, 16,
            	727, 24,
            	721, 32,
            	730, 40,
            4097, 8, 0, /* 718: pointer.func */
            4097, 8, 0, /* 721: pointer.func */
            4097, 8, 0, /* 724: pointer.func */
            4097, 8, 0, /* 727: pointer.func */
            4097, 8, 0, /* 730: pointer.func */
            1, 8, 1, /* 733: pointer.struct.store_method_st */
            	738, 0,
            0, 0, 0, /* 738: struct.store_method_st */
            4097, 8, 0, /* 741: pointer.func */
            4097, 8, 0, /* 744: pointer.func */
            4097, 8, 0, /* 747: pointer.func */
            4097, 8, 0, /* 750: pointer.func */
            4097, 8, 0, /* 753: pointer.func */
            4097, 8, 0, /* 756: pointer.func */
            4097, 8, 0, /* 759: pointer.func */
            4097, 8, 0, /* 762: pointer.func */
            1, 8, 1, /* 765: pointer.struct.ENGINE_CMD_DEFN_st */
            	770, 0,
            0, 32, 2, /* 770: struct.ENGINE_CMD_DEFN_st */
            	55, 8,
            	55, 16,
            0, 16, 1, /* 777: struct.crypto_ex_data_st */
            	276, 0,
            0, 24, 1, /* 782: struct.ASN1_ENCODING_st */
            	55, 0,
            1, 8, 1, /* 787: pointer.struct.AUTHORITY_KEYID_st */
            	792, 0,
            0, 24, 3, /* 792: struct.AUTHORITY_KEYID_st */
            	211, 0,
            	276, 8,
            	211, 16,
            1, 8, 1, /* 801: pointer.struct.X509_POLICY_CACHE_st */
            	806, 0,
            0, 40, 2, /* 806: struct.X509_POLICY_CACHE_st */
            	813, 0,
            	276, 8,
            1, 8, 1, /* 813: pointer.struct.X509_POLICY_DATA_st */
            	818, 0,
            0, 32, 3, /* 818: struct.X509_POLICY_DATA_st */
            	233, 8,
            	276, 16,
            	276, 24,
            1, 8, 1, /* 827: pointer.struct.NAME_CONSTRAINTS_st */
            	832, 0,
            0, 16, 2, /* 832: struct.NAME_CONSTRAINTS_st */
            	276, 0,
            	276, 8,
            1, 8, 1, /* 839: pointer.struct.x509_cert_aux_st */
            	844, 0,
            0, 40, 5, /* 844: struct.x509_cert_aux_st */
            	276, 0,
            	276, 8,
            	211, 16,
            	211, 24,
            	276, 32,
            1, 8, 1, /* 857: pointer.struct.env_md_st */
            	862, 0,
            0, 120, 8, /* 862: struct.env_md_st */
            	881, 24,
            	884, 32,
            	887, 40,
            	890, 48,
            	881, 56,
            	893, 64,
            	896, 72,
            	899, 112,
            4097, 8, 0, /* 881: pointer.func */
            4097, 8, 0, /* 884: pointer.func */
            4097, 8, 0, /* 887: pointer.func */
            4097, 8, 0, /* 890: pointer.func */
            4097, 8, 0, /* 893: pointer.func */
            4097, 8, 0, /* 896: pointer.func */
            4097, 8, 0, /* 899: pointer.func */
            1, 8, 1, /* 902: pointer.struct.rsa_st */
            	907, 0,
            0, 168, 17, /* 907: struct.rsa_st */
            	512, 16,
            	456, 24,
            	60, 32,
            	60, 40,
            	60, 48,
            	60, 56,
            	60, 64,
            	60, 72,
            	60, 80,
            	60, 88,
            	777, 96,
            	944, 120,
            	944, 128,
            	944, 136,
            	55, 144,
            	958, 152,
            	958, 160,
            1, 8, 1, /* 944: pointer.struct.bn_mont_ctx_st */
            	949, 0,
            0, 96, 3, /* 949: struct.bn_mont_ctx_st */
            	65, 8,
            	65, 32,
            	65, 56,
            1, 8, 1, /* 958: pointer.struct.bn_blinding_st */
            	963, 0,
            0, 88, 7, /* 963: struct.bn_blinding_st */
            	60, 0,
            	60, 8,
            	60, 16,
            	60, 24,
            	980, 40,
            	944, 72,
            	552, 80,
            0, 16, 1, /* 980: struct.iovec */
            	55, 0,
            4097, 8, 0, /* 985: pointer.func */
            1, 8, 1, /* 988: pointer.struct.dh_st */
            	993, 0,
            0, 144, 12, /* 993: struct.dh_st */
            	60, 8,
            	60, 16,
            	60, 32,
            	60, 40,
            	944, 56,
            	60, 64,
            	60, 72,
            	55, 80,
            	60, 96,
            	777, 112,
            	618, 128,
            	456, 136,
            4097, 8, 0, /* 1020: pointer.func */
            1, 8, 1, /* 1023: pointer.struct.ec_key_st */
            	1028, 0,
            0, 56, 4, /* 1028: struct.ec_key_st */
            	1039, 8,
            	1216, 16,
            	60, 24,
            	1232, 48,
            1, 8, 1, /* 1039: pointer.struct.ec_group_st */
            	1044, 0,
            0, 232, 12, /* 1044: struct.ec_group_st */
            	1071, 0,
            	1216, 8,
            	65, 16,
            	65, 40,
            	55, 80,
            	1232, 96,
            	65, 104,
            	65, 152,
            	65, 176,
            	55, 208,
            	55, 216,
            	1256, 224,
            1, 8, 1, /* 1071: pointer.struct.ec_method_st */
            	1076, 0,
            0, 304, 37, /* 1076: struct.ec_method_st */
            	1153, 8,
            	1156, 16,
            	1156, 24,
            	1159, 32,
            	1162, 40,
            	1162, 48,
            	1153, 56,
            	1165, 64,
            	1168, 72,
            	1171, 80,
            	1171, 88,
            	1174, 96,
            	1177, 104,
            	1180, 112,
            	1180, 120,
            	1183, 128,
            	1183, 136,
            	1186, 144,
            	1189, 152,
            	1192, 160,
            	1195, 168,
            	1198, 176,
            	1201, 184,
            	1177, 192,
            	1201, 200,
            	1198, 208,
            	1201, 216,
            	1204, 224,
            	1207, 232,
            	1165, 240,
            	1153, 248,
            	1162, 256,
            	1210, 264,
            	1162, 272,
            	1210, 280,
            	1210, 288,
            	1213, 296,
            4097, 8, 0, /* 1153: pointer.func */
            4097, 8, 0, /* 1156: pointer.func */
            4097, 8, 0, /* 1159: pointer.func */
            4097, 8, 0, /* 1162: pointer.func */
            4097, 8, 0, /* 1165: pointer.func */
            4097, 8, 0, /* 1168: pointer.func */
            4097, 8, 0, /* 1171: pointer.func */
            4097, 8, 0, /* 1174: pointer.func */
            4097, 8, 0, /* 1177: pointer.func */
            4097, 8, 0, /* 1180: pointer.func */
            4097, 8, 0, /* 1183: pointer.func */
            4097, 8, 0, /* 1186: pointer.func */
            4097, 8, 0, /* 1189: pointer.func */
            4097, 8, 0, /* 1192: pointer.func */
            4097, 8, 0, /* 1195: pointer.func */
            4097, 8, 0, /* 1198: pointer.func */
            4097, 8, 0, /* 1201: pointer.func */
            4097, 8, 0, /* 1204: pointer.func */
            4097, 8, 0, /* 1207: pointer.func */
            4097, 8, 0, /* 1210: pointer.func */
            4097, 8, 0, /* 1213: pointer.func */
            1, 8, 1, /* 1216: pointer.struct.ec_point_st */
            	1221, 0,
            0, 88, 4, /* 1221: struct.ec_point_st */
            	1071, 0,
            	65, 8,
            	65, 32,
            	65, 56,
            1, 8, 1, /* 1232: pointer.struct.ec_extra_data_st */
            	1237, 0,
            0, 40, 5, /* 1237: struct.ec_extra_data_st */
            	1232, 0,
            	55, 8,
            	1250, 16,
            	1253, 24,
            	1253, 32,
            4097, 8, 0, /* 1250: pointer.func */
            4097, 8, 0, /* 1253: pointer.func */
            4097, 8, 0, /* 1256: pointer.func */
            0, 192, 8, /* 1259: array[8].struct.cert_pkey_st */
            	140, 0,
            	140, 24,
            	140, 48,
            	140, 72,
            	140, 96,
            	140, 120,
            	140, 144,
            	140, 168,
            4097, 8, 0, /* 1278: pointer.func */
            0, 0, 0, /* 1281: func */
            4097, 8, 0, /* 1284: pointer.func */
            4097, 8, 0, /* 1287: pointer.func */
            0, 44, 0, /* 1290: struct.apr_time_exp_t */
            0, 0, 0, /* 1293: func */
            4097, 8, 0, /* 1296: pointer.func */
            0, 88, 1, /* 1299: struct.ssl_cipher_st */
            	55, 8,
            1, 8, 1, /* 1304: pointer.struct.ssl_cipher_st */
            	1299, 0,
            0, 0, 0, /* 1309: func */
            0, 24, 0, /* 1312: array[6].int */
            4097, 8, 0, /* 1315: pointer.func */
            0, 0, 0, /* 1318: func */
            0, 0, 0, /* 1321: func */
            0, 0, 0, /* 1324: func */
            0, 0, 0, /* 1327: func */
            0, 0, 0, /* 1330: func */
            0, 0, 0, /* 1333: func */
            0, 0, 0, /* 1336: func */
            0, 0, 0, /* 1339: func */
            0, 0, 0, /* 1342: func */
            0, 0, 0, /* 1345: func */
            0, 0, 0, /* 1348: func */
            0, 0, 0, /* 1351: func */
            0, 24, 1, /* 1354: struct.ssl3_buf_freelist_st */
            	1359, 16,
            1, 8, 1, /* 1359: pointer.struct.ssl3_buf_freelist_entry_st */
            	1364, 0,
            0, 8, 1, /* 1364: struct.ssl3_buf_freelist_entry_st */
            	1359, 0,
            0, 0, 0, /* 1369: func */
            0, 0, 0, /* 1372: func */
            0, 0, 0, /* 1375: func */
            0, 0, 0, /* 1378: func */
            1, 8, 1, /* 1381: pointer.struct.ssl3_buf_freelist_st */
            	1354, 0,
            0, 8, 0, /* 1386: array[2].int */
            0, 0, 0, /* 1389: func */
            0, 20, 0, /* 1392: array[5].int */
            4097, 8, 0, /* 1395: pointer.func */
            0, 0, 0, /* 1398: func */
            0, 0, 0, /* 1401: func */
            0, 0, 0, /* 1404: func */
            0, 0, 0, /* 1407: func */
            1, 8, 1, /* 1410: pointer.struct.sess_cert_st */
            	1415, 0,
            0, 248, 6, /* 1415: struct.sess_cert_st */
            	276, 0,
            	135, 16,
            	1259, 24,
            	902, 216,
            	988, 224,
            	1023, 232,
            0, 0, 0, /* 1430: func */
            4097, 8, 0, /* 1433: pointer.func */
            0, 0, 0, /* 1436: func */
            0, 0, 0, /* 1439: func */
            0, 0, 0, /* 1442: func */
            0, 0, 0, /* 1445: func */
            0, 0, 0, /* 1448: func */
            0, 48, 0, /* 1451: array[48].char */
            0, 352, 14, /* 1454: struct.ssl_session_st */
            	55, 144,
            	55, 152,
            	1410, 168,
            	149, 176,
            	1304, 224,
            	276, 240,
            	777, 248,
            	1485, 264,
            	1485, 272,
            	55, 280,
            	55, 296,
            	55, 312,
            	55, 320,
            	55, 344,
            1, 8, 1, /* 1485: pointer.struct.ssl_session_st */
            	1454, 0,
            0, 4, 0, /* 1490: struct.in_addr */
            0, 0, 0, /* 1493: func */
            0, 0, 0, /* 1496: func */
            4097, 8, 0, /* 1499: pointer.func */
            0, 0, 0, /* 1502: func */
            0, 0, 0, /* 1505: func */
            0, 0, 0, /* 1508: func */
            4097, 8, 0, /* 1511: pointer.func */
            4097, 8, 0, /* 1514: pointer.func */
            0, 0, 0, /* 1517: func */
            1, 8, 1, /* 1520: pointer.struct.X509_VERIFY_PARAM_st */
            	1525, 0,
            0, 56, 2, /* 1525: struct.X509_VERIFY_PARAM_st */
            	55, 0,
            	276, 48,
            0, 0, 0, /* 1532: func */
            1, 8, 1, /* 1535: pointer.struct.in_addr */
            	1490, 0,
            0, 0, 0, /* 1540: func */
            0, 0, 0, /* 1543: func */
            0, 144, 15, /* 1546: struct.x509_store_st */
            	276, 8,
            	276, 16,
            	1520, 24,
            	1579, 32,
            	1582, 40,
            	1585, 48,
            	1511, 56,
            	1579, 64,
            	1588, 72,
            	1591, 80,
            	1499, 88,
            	1594, 96,
            	1594, 104,
            	1579, 112,
            	777, 120,
            4097, 8, 0, /* 1579: pointer.func */
            4097, 8, 0, /* 1582: pointer.func */
            4097, 8, 0, /* 1585: pointer.func */
            4097, 8, 0, /* 1588: pointer.func */
            4097, 8, 0, /* 1591: pointer.func */
            4097, 8, 0, /* 1594: pointer.func */
            0, 0, 0, /* 1597: func */
            1, 8, 1, /* 1600: pointer.struct.x509_store_st */
            	1546, 0,
            0, 0, 0, /* 1605: func */
            0, 0, 0, /* 1608: func */
            0, 0, 0, /* 1611: func */
            4097, 8, 0, /* 1614: pointer.func */
            0, 0, 0, /* 1617: func */
            4097, 8, 0, /* 1620: pointer.func */
            0, 0, 0, /* 1623: func */
            4097, 8, 0, /* 1626: pointer.func */
            0, 0, 0, /* 1629: func */
            0, 0, 0, /* 1632: func */
            0, 0, 0, /* 1635: func */
            0, 232, 28, /* 1638: struct.ssl_method_st */
            	1514, 8,
            	1697, 16,
            	1697, 24,
            	1514, 32,
            	1514, 40,
            	1700, 48,
            	1700, 56,
            	1700, 64,
            	1514, 72,
            	1514, 80,
            	1514, 88,
            	1703, 96,
            	1706, 104,
            	1709, 112,
            	1514, 120,
            	1712, 128,
            	1715, 136,
            	1620, 144,
            	1614, 152,
            	1514, 160,
            	730, 168,
            	1626, 176,
            	1718, 184,
            	1721, 192,
            	1724, 200,
            	730, 208,
            	1433, 216,
            	1772, 224,
            4097, 8, 0, /* 1697: pointer.func */
            4097, 8, 0, /* 1700: pointer.func */
            4097, 8, 0, /* 1703: pointer.func */
            4097, 8, 0, /* 1706: pointer.func */
            4097, 8, 0, /* 1709: pointer.func */
            4097, 8, 0, /* 1712: pointer.func */
            4097, 8, 0, /* 1715: pointer.func */
            4097, 8, 0, /* 1718: pointer.func */
            4097, 8, 0, /* 1721: pointer.func */
            1, 8, 1, /* 1724: pointer.struct.ssl3_enc_method */
            	1729, 0,
            0, 112, 11, /* 1729: struct.ssl3_enc_method */
            	1754, 0,
            	1700, 8,
            	1514, 16,
            	1757, 24,
            	1754, 32,
            	1760, 40,
            	1763, 56,
            	55, 64,
            	55, 80,
            	1766, 96,
            	1769, 104,
            4097, 8, 0, /* 1754: pointer.func */
            4097, 8, 0, /* 1757: pointer.func */
            4097, 8, 0, /* 1760: pointer.func */
            4097, 8, 0, /* 1763: pointer.func */
            4097, 8, 0, /* 1766: pointer.func */
            4097, 8, 0, /* 1769: pointer.func */
            4097, 8, 0, /* 1772: pointer.func */
            0, 0, 0, /* 1775: func */
            4097, 8, 0, /* 1778: pointer.func */
            0, 0, 0, /* 1781: func */
            4097, 8, 0, /* 1784: pointer.func */
            0, 0, 0, /* 1787: func */
            0, 0, 0, /* 1790: func */
            1, 8, 1, /* 1793: pointer.struct.ssl_method_st */
            	1638, 0,
            0, 0, 0, /* 1798: func */
            0, 0, 0, /* 1801: func */
            0, 0, 0, /* 1804: func */
            0, 0, 0, /* 1807: func */
            0, 0, 0, /* 1810: func */
            0, 0, 0, /* 1813: func */
            0, 0, 0, /* 1816: func */
            0, 0, 0, /* 1819: func */
            0, 0, 0, /* 1822: func */
            0, 736, 50, /* 1825: struct.ssl_ctx_st */
            	1793, 0,
            	276, 8,
            	276, 16,
            	1600, 24,
            	1535, 32,
            	1485, 48,
            	1485, 56,
            	1928, 80,
            	1296, 88,
            	1778, 96,
            	1287, 152,
            	46, 160,
            	1284, 168,
            	46, 176,
            	1784, 184,
            	1395, 192,
            	1700, 200,
            	777, 208,
            	857, 224,
            	857, 232,
            	857, 240,
            	276, 248,
            	276, 256,
            	1278, 264,
            	276, 272,
            	111, 304,
            	1315, 320,
            	46, 328,
            	1582, 376,
            	1395, 384,
            	1520, 392,
            	456, 408,
            	49, 416,
            	46, 424,
            	93, 480,
            	52, 488,
            	46, 496,
            	87, 504,
            	46, 512,
            	55, 520,
            	81, 528,
            	1757, 536,
            	1381, 552,
            	1381, 560,
            	15, 568,
            	1931, 696,
            	46, 704,
            	3, 712,
            	46, 720,
            	276, 728,
            4097, 8, 0, /* 1928: pointer.func */
            4097, 8, 0, /* 1931: pointer.func */
            0, 0, 0, /* 1934: func */
            0, 0, 0, /* 1937: func */
            0, 0, 0, /* 1940: func */
            0, 0, 0, /* 1943: func */
            0, 8, 0, /* 1946: array[8].char */
            0, 0, 0, /* 1949: func */
            0, 0, 0, /* 1952: func */
            0, 0, 0, /* 1955: func */
            0, 0, 0, /* 1958: func */
            0, 0, 0, /* 1961: func */
            0, 0, 0, /* 1964: func */
            0, 0, 0, /* 1967: func */
            0, 0, 0, /* 1970: func */
            0, 0, 0, /* 1973: func */
            0, 0, 0, /* 1976: func */
            1, 8, 1, /* 1979: pointer.struct.ssl_ctx_st */
            	1825, 0,
            0, 0, 0, /* 1984: func */
            0, 1, 0, /* 1987: char */
            0, 0, 0, /* 1990: func */
            0, 0, 0, /* 1993: func */
            0, 0, 0, /* 1996: func */
            0, 0, 0, /* 1999: func */
            0, 0, 0, /* 2002: func */
            0, 0, 0, /* 2005: func */
            0, 0, 0, /* 2008: func */
            0, 0, 0, /* 2011: func */
            0, 0, 0, /* 2014: func */
            0, 0, 0, /* 2017: func */
            0, 8, 0, /* 2020: long */
            0, 0, 0, /* 2023: func */
            0, 0, 0, /* 2026: func */
            0, 0, 0, /* 2029: func */
            0, 0, 0, /* 2032: func */
            0, 0, 0, /* 2035: func */
            0, 0, 0, /* 2038: func */
            0, 0, 0, /* 2041: func */
            0, 0, 0, /* 2044: func */
            0, 0, 0, /* 2047: func */
            0, 0, 0, /* 2050: func */
            0, 0, 0, /* 2053: func */
            0, 0, 0, /* 2056: func */
            0, 0, 0, /* 2059: func */
            0, 0, 0, /* 2062: func */
            0, 0, 0, /* 2065: func */
            0, 0, 0, /* 2068: func */
            0, 0, 0, /* 2071: func */
            0, 0, 0, /* 2074: func */
            0, 0, 0, /* 2077: func */
            0, 0, 0, /* 2080: func */
            0, 0, 0, /* 2083: func */
            0, 0, 0, /* 2086: func */
            0, 0, 0, /* 2089: func */
            0, 0, 0, /* 2092: func */
            0, 0, 0, /* 2095: func */
            0, 0, 0, /* 2098: func */
            0, 0, 0, /* 2101: func */
            0, 20, 0, /* 2104: array[20].char */
            0, 32, 0, /* 2107: array[32].char */
            0, 0, 0, /* 2110: func */
            0, 0, 0, /* 2113: func */
            0, 0, 0, /* 2116: func */
            0, 0, 0, /* 2119: func */
            0, 0, 0, /* 2122: func */
            0, 0, 0, /* 2125: func */
            0, 0, 0, /* 2128: func */
        },
        .arg_entity_index = { 1979, 55, },
        .ret_entity_index = 75,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_use_certificate_chain_file)(SSL_CTX *,const char *);
    orig_SSL_CTX_use_certificate_chain_file = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate_chain_file");
    *new_ret_ptr = (*orig_SSL_CTX_use_certificate_chain_file)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

