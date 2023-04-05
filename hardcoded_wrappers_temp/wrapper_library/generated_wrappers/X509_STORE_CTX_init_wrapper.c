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

int bb_X509_STORE_CTX_init(X509_STORE_CTX * arg_a,X509_STORE * arg_b,X509 * arg_c,STACK_OF(X509) * arg_d);

int X509_STORE_CTX_init(X509_STORE_CTX * arg_a,X509_STORE * arg_b,X509 * arg_c,STACK_OF(X509) * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_STORE_CTX_init called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_STORE_CTX_init(arg_a,arg_b,arg_c,arg_d);
    else {
        int (*orig_X509_STORE_CTX_init)(X509_STORE_CTX *,X509_STORE *,X509 *,STACK_OF(X509) *);
        orig_X509_STORE_CTX_init = dlsym(RTLD_NEXT, "X509_STORE_CTX_init");
        return orig_X509_STORE_CTX_init(arg_a,arg_b,arg_c,arg_d);
    }
}

int bb_X509_STORE_CTX_init(X509_STORE_CTX * arg_a,X509_STORE * arg_b,X509 * arg_c,STACK_OF(X509) * arg_d) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.x509_crl_method_st */
            	5, 0,
            0, 0, 0, /* 5: struct.x509_crl_method_st */
            1, 8, 1, /* 8: pointer.struct.stack_st_GENERAL_NAMES */
            	13, 0,
            0, 0, 0, /* 13: struct.stack_st_GENERAL_NAMES */
            0, 8, 2, /* 16: union.unknown */
            	23, 0,
            	53, 0,
            1, 8, 1, /* 23: pointer.struct.stack_st_GENERAL_NAME */
            	28, 0,
            0, 32, 1, /* 28: struct.stack_st_GENERAL_NAME */
            	33, 0,
            0, 32, 2, /* 33: struct.stack_st */
            	40, 8,
            	50, 24,
            1, 8, 1, /* 40: pointer.pointer.char */
            	45, 0,
            1, 8, 1, /* 45: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 50: pointer.func */
            1, 8, 1, /* 53: pointer.struct.stack_st_X509_NAME_ENTRY */
            	58, 0,
            0, 32, 1, /* 58: struct.stack_st_X509_NAME_ENTRY */
            	33, 0,
            0, 24, 2, /* 63: struct.DIST_POINT_NAME_st */
            	16, 8,
            	70, 16,
            1, 8, 1, /* 70: pointer.struct.X509_name_st */
            	75, 0,
            0, 40, 3, /* 75: struct.X509_name_st */
            	53, 0,
            	84, 16,
            	94, 24,
            1, 8, 1, /* 84: pointer.struct.buf_mem_st */
            	89, 0,
            0, 24, 1, /* 89: struct.buf_mem_st */
            	45, 8,
            1, 8, 1, /* 94: pointer.unsigned char */
            	99, 0,
            0, 1, 0, /* 99: unsigned char */
            1, 8, 1, /* 102: pointer.struct.DIST_POINT_NAME_st */
            	63, 0,
            0, 32, 2, /* 107: struct.ISSUING_DIST_POINT_st */
            	102, 0,
            	114, 16,
            1, 8, 1, /* 114: pointer.struct.asn1_string_st */
            	119, 0,
            0, 24, 1, /* 119: struct.asn1_string_st */
            	94, 8,
            0, 32, 1, /* 124: struct.stack_st_X509_REVOKED */
            	33, 0,
            1, 8, 1, /* 129: pointer.struct.stack_st_X509_REVOKED */
            	124, 0,
            0, 80, 8, /* 134: struct.X509_crl_info_st */
            	153, 0,
            	158, 8,
            	70, 16,
            	320, 24,
            	320, 32,
            	129, 40,
            	325, 48,
            	335, 56,
            1, 8, 1, /* 153: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 158: pointer.struct.X509_algor_st */
            	163, 0,
            0, 16, 2, /* 163: struct.X509_algor_st */
            	170, 0,
            	194, 8,
            1, 8, 1, /* 170: pointer.struct.asn1_object_st */
            	175, 0,
            0, 40, 3, /* 175: struct.asn1_object_st */
            	184, 0,
            	184, 8,
            	189, 24,
            1, 8, 1, /* 184: pointer.char */
            	4096, 0,
            1, 8, 1, /* 189: pointer.unsigned char */
            	99, 0,
            1, 8, 1, /* 194: pointer.struct.asn1_type_st */
            	199, 0,
            0, 16, 1, /* 199: struct.asn1_type_st */
            	204, 8,
            0, 8, 20, /* 204: union.unknown */
            	45, 0,
            	247, 0,
            	170, 0,
            	153, 0,
            	252, 0,
            	114, 0,
            	257, 0,
            	262, 0,
            	267, 0,
            	272, 0,
            	277, 0,
            	282, 0,
            	287, 0,
            	292, 0,
            	297, 0,
            	302, 0,
            	307, 0,
            	247, 0,
            	247, 0,
            	312, 0,
            1, 8, 1, /* 247: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 252: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 257: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 262: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 267: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 272: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 277: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 282: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 287: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 292: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 297: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 302: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 307: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 312: pointer.struct.ASN1_VALUE_st */
            	317, 0,
            0, 0, 0, /* 317: struct.ASN1_VALUE_st */
            1, 8, 1, /* 320: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 325: pointer.struct.stack_st_X509_EXTENSION */
            	330, 0,
            0, 32, 1, /* 330: struct.stack_st_X509_EXTENSION */
            	33, 0,
            0, 24, 1, /* 335: struct.ASN1_ENCODING_st */
            	94, 0,
            1, 8, 1, /* 340: pointer.struct.X509_crl_st */
            	345, 0,
            0, 120, 10, /* 345: struct.X509_crl_st */
            	368, 0,
            	158, 8,
            	114, 16,
            	373, 32,
            	387, 40,
            	153, 56,
            	153, 64,
            	8, 96,
            	0, 104,
            	392, 112,
            1, 8, 1, /* 368: pointer.struct.X509_crl_info_st */
            	134, 0,
            1, 8, 1, /* 373: pointer.struct.AUTHORITY_KEYID_st */
            	378, 0,
            0, 24, 3, /* 378: struct.AUTHORITY_KEYID_st */
            	257, 0,
            	23, 8,
            	153, 16,
            1, 8, 1, /* 387: pointer.struct.ISSUING_DIST_POINT_st */
            	107, 0,
            0, 8, 0, /* 392: pointer.void */
            0, 0, 0, /* 395: struct.X509_POLICY_TREE_st */
            1, 8, 1, /* 398: pointer.struct.X509_POLICY_TREE_st */
            	395, 0,
            0, 32, 1, /* 403: struct.stack_st_X509_CRL */
            	33, 0,
            1, 8, 1, /* 408: pointer.struct.stack_st_X509_CRL */
            	403, 0,
            4097, 8, 0, /* 413: pointer.func */
            4097, 8, 0, /* 416: pointer.func */
            4097, 8, 0, /* 419: pointer.func */
            4097, 8, 0, /* 422: pointer.func */
            4097, 8, 0, /* 425: pointer.func */
            1, 8, 1, /* 428: pointer.struct.X509_VERIFY_PARAM_st */
            	433, 0,
            0, 56, 2, /* 433: struct.X509_VERIFY_PARAM_st */
            	45, 0,
            	440, 48,
            1, 8, 1, /* 440: pointer.struct.stack_st_ASN1_OBJECT */
            	445, 0,
            0, 32, 1, /* 445: struct.stack_st_ASN1_OBJECT */
            	33, 0,
            0, 32, 1, /* 450: struct.stack_st_X509_LOOKUP */
            	33, 0,
            0, 32, 1, /* 455: struct.stack_st_X509_OBJECT */
            	33, 0,
            4097, 8, 0, /* 460: pointer.func */
            1, 8, 1, /* 463: pointer.struct.stack_st_X509_OBJECT */
            	455, 0,
            1, 8, 1, /* 468: pointer.struct.x509_store_st */
            	473, 0,
            0, 144, 15, /* 473: struct.x509_store_st */
            	463, 8,
            	506, 16,
            	428, 24,
            	425, 32,
            	511, 40,
            	460, 48,
            	422, 56,
            	425, 64,
            	419, 72,
            	416, 80,
            	413, 88,
            	514, 96,
            	517, 104,
            	425, 112,
            	520, 120,
            1, 8, 1, /* 506: pointer.struct.stack_st_X509_LOOKUP */
            	450, 0,
            4097, 8, 0, /* 511: pointer.func */
            4097, 8, 0, /* 514: pointer.func */
            4097, 8, 0, /* 517: pointer.func */
            0, 16, 1, /* 520: struct.crypto_ex_data_st */
            	525, 0,
            1, 8, 1, /* 525: pointer.struct.stack_st_void */
            	530, 0,
            0, 32, 1, /* 530: struct.stack_st_void */
            	33, 0,
            0, 248, 25, /* 535: struct.x509_store_ctx_st */
            	468, 0,
            	588, 16,
            	1098, 24,
            	408, 32,
            	428, 40,
            	392, 48,
            	425, 56,
            	511, 64,
            	460, 72,
            	422, 80,
            	425, 88,
            	419, 96,
            	416, 104,
            	413, 112,
            	425, 120,
            	514, 128,
            	517, 136,
            	425, 144,
            	1098, 160,
            	398, 168,
            	588, 192,
            	588, 200,
            	340, 208,
            	1108, 224,
            	520, 232,
            1, 8, 1, /* 588: pointer.struct.x509_st */
            	593, 0,
            0, 184, 12, /* 593: struct.x509_st */
            	620, 0,
            	158, 8,
            	114, 16,
            	45, 32,
            	520, 40,
            	257, 104,
            	373, 112,
            	1025, 120,
            	1033, 128,
            	1043, 136,
            	1048, 144,
            	1070, 176,
            1, 8, 1, /* 620: pointer.struct.x509_cinf_st */
            	625, 0,
            0, 104, 11, /* 625: struct.x509_cinf_st */
            	153, 0,
            	153, 8,
            	158, 16,
            	70, 24,
            	650, 32,
            	70, 40,
            	662, 48,
            	114, 56,
            	114, 64,
            	325, 72,
            	335, 80,
            1, 8, 1, /* 650: pointer.struct.X509_val_st */
            	655, 0,
            0, 16, 2, /* 655: struct.X509_val_st */
            	320, 0,
            	320, 8,
            1, 8, 1, /* 662: pointer.struct.X509_pubkey_st */
            	667, 0,
            0, 24, 3, /* 667: struct.X509_pubkey_st */
            	158, 0,
            	114, 8,
            	676, 16,
            1, 8, 1, /* 676: pointer.struct.evp_pkey_st */
            	681, 0,
            0, 56, 4, /* 681: struct.evp_pkey_st */
            	692, 16,
            	700, 24,
            	708, 32,
            	1015, 48,
            1, 8, 1, /* 692: pointer.struct.evp_pkey_asn1_method_st */
            	697, 0,
            0, 0, 0, /* 697: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 700: pointer.struct.engine_st */
            	705, 0,
            0, 0, 0, /* 705: struct.engine_st */
            0, 8, 5, /* 708: union.unknown */
            	45, 0,
            	721, 0,
            	858, 0,
            	939, 0,
            	1007, 0,
            1, 8, 1, /* 721: pointer.struct.rsa_st */
            	726, 0,
            0, 168, 17, /* 726: struct.rsa_st */
            	763, 16,
            	700, 24,
            	818, 32,
            	818, 40,
            	818, 48,
            	818, 56,
            	818, 64,
            	818, 72,
            	818, 80,
            	818, 88,
            	520, 96,
            	836, 120,
            	836, 128,
            	836, 136,
            	45, 144,
            	850, 152,
            	850, 160,
            1, 8, 1, /* 763: pointer.struct.rsa_meth_st */
            	768, 0,
            0, 112, 13, /* 768: struct.rsa_meth_st */
            	184, 0,
            	797, 8,
            	797, 16,
            	797, 24,
            	797, 32,
            	800, 40,
            	803, 48,
            	806, 56,
            	806, 64,
            	45, 80,
            	809, 88,
            	812, 96,
            	815, 104,
            4097, 8, 0, /* 797: pointer.func */
            4097, 8, 0, /* 800: pointer.func */
            4097, 8, 0, /* 803: pointer.func */
            4097, 8, 0, /* 806: pointer.func */
            4097, 8, 0, /* 809: pointer.func */
            4097, 8, 0, /* 812: pointer.func */
            4097, 8, 0, /* 815: pointer.func */
            1, 8, 1, /* 818: pointer.struct.bignum_st */
            	823, 0,
            0, 24, 1, /* 823: struct.bignum_st */
            	828, 0,
            1, 8, 1, /* 828: pointer.unsigned int */
            	833, 0,
            0, 4, 0, /* 833: unsigned int */
            1, 8, 1, /* 836: pointer.struct.bn_mont_ctx_st */
            	841, 0,
            0, 96, 3, /* 841: struct.bn_mont_ctx_st */
            	823, 8,
            	823, 32,
            	823, 56,
            1, 8, 1, /* 850: pointer.struct.bn_blinding_st */
            	855, 0,
            0, 0, 0, /* 855: struct.bn_blinding_st */
            1, 8, 1, /* 858: pointer.struct.dsa_st */
            	863, 0,
            0, 136, 11, /* 863: struct.dsa_st */
            	818, 24,
            	818, 32,
            	818, 40,
            	818, 48,
            	818, 56,
            	818, 64,
            	818, 72,
            	836, 88,
            	520, 104,
            	888, 120,
            	700, 128,
            1, 8, 1, /* 888: pointer.struct.dsa_method */
            	893, 0,
            0, 96, 11, /* 893: struct.dsa_method */
            	184, 0,
            	918, 8,
            	921, 16,
            	924, 24,
            	927, 32,
            	930, 40,
            	933, 48,
            	933, 56,
            	45, 72,
            	936, 80,
            	933, 88,
            4097, 8, 0, /* 918: pointer.func */
            4097, 8, 0, /* 921: pointer.func */
            4097, 8, 0, /* 924: pointer.func */
            4097, 8, 0, /* 927: pointer.func */
            4097, 8, 0, /* 930: pointer.func */
            4097, 8, 0, /* 933: pointer.func */
            4097, 8, 0, /* 936: pointer.func */
            1, 8, 1, /* 939: pointer.struct.dh_st */
            	944, 0,
            0, 144, 12, /* 944: struct.dh_st */
            	818, 8,
            	818, 16,
            	818, 32,
            	818, 40,
            	836, 56,
            	818, 64,
            	818, 72,
            	94, 80,
            	818, 96,
            	520, 112,
            	971, 128,
            	700, 136,
            1, 8, 1, /* 971: pointer.struct.dh_method */
            	976, 0,
            0, 72, 8, /* 976: struct.dh_method */
            	184, 0,
            	995, 8,
            	998, 16,
            	1001, 24,
            	995, 32,
            	995, 40,
            	45, 56,
            	1004, 64,
            4097, 8, 0, /* 995: pointer.func */
            4097, 8, 0, /* 998: pointer.func */
            4097, 8, 0, /* 1001: pointer.func */
            4097, 8, 0, /* 1004: pointer.func */
            1, 8, 1, /* 1007: pointer.struct.ec_key_st */
            	1012, 0,
            0, 0, 0, /* 1012: struct.ec_key_st */
            1, 8, 1, /* 1015: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1020, 0,
            0, 32, 1, /* 1020: struct.stack_st_X509_ATTRIBUTE */
            	33, 0,
            1, 8, 1, /* 1025: pointer.struct.X509_POLICY_CACHE_st */
            	1030, 0,
            0, 0, 0, /* 1030: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1033: pointer.struct.stack_st_DIST_POINT */
            	1038, 0,
            0, 32, 1, /* 1038: struct.stack_st_DIST_POINT */
            	33, 0,
            1, 8, 1, /* 1043: pointer.struct.stack_st_GENERAL_NAME */
            	28, 0,
            1, 8, 1, /* 1048: pointer.struct.NAME_CONSTRAINTS_st */
            	1053, 0,
            0, 16, 2, /* 1053: struct.NAME_CONSTRAINTS_st */
            	1060, 0,
            	1060, 8,
            1, 8, 1, /* 1060: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1065, 0,
            0, 32, 1, /* 1065: struct.stack_st_GENERAL_SUBTREE */
            	33, 0,
            1, 8, 1, /* 1070: pointer.struct.x509_cert_aux_st */
            	1075, 0,
            0, 40, 5, /* 1075: struct.x509_cert_aux_st */
            	440, 0,
            	440, 8,
            	307, 16,
            	257, 24,
            	1088, 32,
            1, 8, 1, /* 1088: pointer.struct.stack_st_X509_ALGOR */
            	1093, 0,
            0, 32, 1, /* 1093: struct.stack_st_X509_ALGOR */
            	33, 0,
            1, 8, 1, /* 1098: pointer.struct.stack_st_X509 */
            	1103, 0,
            0, 32, 1, /* 1103: struct.stack_st_X509 */
            	33, 0,
            1, 8, 1, /* 1108: pointer.struct.x509_store_ctx_st */
            	535, 0,
            0, 4, 0, /* 1113: int */
            0, 1, 0, /* 1116: char */
        },
        .arg_entity_index = { 1108, 468, 588, 1098, },
        .ret_entity_index = 1113,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_STORE_CTX * new_arg_a = *((X509_STORE_CTX * *)new_args->args[0]);

    X509_STORE * new_arg_b = *((X509_STORE * *)new_args->args[1]);

    X509 * new_arg_c = *((X509 * *)new_args->args[2]);

    STACK_OF(X509) * new_arg_d = *((STACK_OF(X509) * *)new_args->args[3]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_STORE_CTX_init)(X509_STORE_CTX *,X509_STORE *,X509 *,STACK_OF(X509) *);
    orig_X509_STORE_CTX_init = dlsym(RTLD_NEXT, "X509_STORE_CTX_init");
    *new_ret_ptr = (*orig_X509_STORE_CTX_init)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

