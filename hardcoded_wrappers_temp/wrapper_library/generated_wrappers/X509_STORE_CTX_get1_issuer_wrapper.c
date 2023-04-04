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
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            4097, 8, 0, /* 6: pointer.func */
            0, 40, 4, /* 9: struct.x509_crl_method_st */
            	6, 8,
            	6, 16,
            	3, 24,
            	0, 32,
            0, 8, 1, /* 20: union.anon.1.3127 */
            	25, 0,
            1, 8, 1, /* 25: pointer.struct.stack_st_OPENSSL_STRING */
            	30, 0,
            0, 32, 1, /* 30: struct.stack_st_OPENSSL_STRING */
            	35, 0,
            0, 32, 2, /* 35: struct.stack_st */
            	42, 8,
            	52, 24,
            1, 8, 1, /* 42: pointer.pointer.char */
            	47, 0,
            1, 8, 1, /* 47: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 52: pointer.func */
            1, 8, 1, /* 55: pointer.struct.DIST_POINT_NAME_st */
            	60, 0,
            0, 24, 2, /* 60: struct.DIST_POINT_NAME_st */
            	20, 8,
            	67, 16,
            1, 8, 1, /* 67: pointer.struct.X509_name_st */
            	72, 0,
            0, 40, 3, /* 72: struct.X509_name_st */
            	25, 0,
            	81, 16,
            	47, 24,
            1, 8, 1, /* 81: pointer.struct.buf_mem_st */
            	86, 0,
            0, 24, 1, /* 86: struct.buf_mem_st */
            	47, 8,
            0, 32, 2, /* 91: struct.ISSUING_DIST_POINT_st */
            	55, 0,
            	98, 16,
            1, 8, 1, /* 98: pointer.struct.asn1_string_st */
            	103, 0,
            0, 24, 1, /* 103: struct.asn1_string_st */
            	47, 8,
            1, 8, 1, /* 108: pointer.struct.X509_crl_info_st */
            	113, 0,
            0, 80, 8, /* 113: struct.X509_crl_info_st */
            	98, 0,
            	132, 8,
            	67, 16,
            	98, 24,
            	98, 32,
            	25, 40,
            	25, 48,
            	173, 56,
            1, 8, 1, /* 132: pointer.struct.X509_algor_st */
            	137, 0,
            0, 16, 2, /* 137: struct.X509_algor_st */
            	144, 0,
            	158, 8,
            1, 8, 1, /* 144: pointer.struct.asn1_object_st */
            	149, 0,
            0, 40, 3, /* 149: struct.asn1_object_st */
            	47, 0,
            	47, 8,
            	47, 24,
            1, 8, 1, /* 158: pointer.struct.asn1_type_st */
            	163, 0,
            0, 16, 1, /* 163: struct.asn1_type_st */
            	168, 8,
            0, 8, 1, /* 168: struct.fnames */
            	47, 0,
            0, 24, 1, /* 173: struct.ASN1_ENCODING_st */
            	47, 0,
            0, 24, 2, /* 178: struct.X509_POLICY_NODE_st */
            	185, 0,
            	199, 8,
            1, 8, 1, /* 185: pointer.struct.X509_POLICY_DATA_st */
            	190, 0,
            0, 32, 3, /* 190: struct.X509_POLICY_DATA_st */
            	144, 8,
            	25, 16,
            	25, 24,
            1, 8, 1, /* 199: pointer.struct.X509_POLICY_NODE_st */
            	178, 0,
            1, 8, 1, /* 204: pointer.struct.ISSUING_DIST_POINT_st */
            	91, 0,
            1, 8, 1, /* 209: pointer.struct.X509_crl_st */
            	214, 0,
            0, 120, 10, /* 214: struct.X509_crl_st */
            	108, 0,
            	132, 8,
            	98, 16,
            	237, 32,
            	204, 40,
            	98, 56,
            	98, 64,
            	25, 96,
            	251, 104,
            	256, 112,
            1, 8, 1, /* 237: pointer.struct.AUTHORITY_KEYID_st */
            	242, 0,
            0, 24, 3, /* 242: struct.AUTHORITY_KEYID_st */
            	98, 0,
            	25, 8,
            	98, 16,
            1, 8, 1, /* 251: pointer.struct.x509_crl_method_st */
            	9, 0,
            0, 8, 0, /* 256: pointer.void */
            0, 32, 3, /* 259: struct.X509_POLICY_LEVEL_st */
            	268, 0,
            	25, 8,
            	199, 16,
            1, 8, 1, /* 268: pointer.struct.x509_st */
            	273, 0,
            0, 184, 12, /* 273: struct.x509_st */
            	300, 0,
            	132, 8,
            	98, 16,
            	47, 32,
            	796, 40,
            	98, 104,
            	237, 112,
            	801, 120,
            	25, 128,
            	25, 136,
            	813, 144,
            	825, 176,
            1, 8, 1, /* 300: pointer.struct.x509_cinf_st */
            	305, 0,
            0, 104, 11, /* 305: struct.x509_cinf_st */
            	98, 0,
            	98, 8,
            	132, 16,
            	67, 24,
            	330, 32,
            	67, 40,
            	342, 48,
            	98, 56,
            	98, 64,
            	25, 72,
            	173, 80,
            1, 8, 1, /* 330: pointer.struct.X509_val_st */
            	335, 0,
            0, 16, 2, /* 335: struct.X509_val_st */
            	98, 0,
            	98, 8,
            1, 8, 1, /* 342: pointer.struct.X509_pubkey_st */
            	347, 0,
            0, 24, 3, /* 347: struct.X509_pubkey_st */
            	132, 0,
            	98, 8,
            	356, 16,
            1, 8, 1, /* 356: pointer.struct.evp_pkey_st */
            	361, 0,
            0, 56, 4, /* 361: struct.evp_pkey_st */
            	372, 16,
            	475, 24,
            	168, 32,
            	25, 48,
            1, 8, 1, /* 372: pointer.struct.evp_pkey_asn1_method_st */
            	377, 0,
            0, 208, 24, /* 377: struct.evp_pkey_asn1_method_st */
            	47, 16,
            	47, 24,
            	428, 32,
            	436, 40,
            	439, 48,
            	442, 56,
            	445, 64,
            	448, 72,
            	442, 80,
            	451, 88,
            	451, 96,
            	454, 104,
            	457, 112,
            	451, 120,
            	439, 128,
            	439, 136,
            	442, 144,
            	460, 152,
            	463, 160,
            	466, 168,
            	454, 176,
            	457, 184,
            	469, 192,
            	472, 200,
            1, 8, 1, /* 428: pointer.struct.unnamed */
            	433, 0,
            0, 0, 0, /* 433: struct.unnamed */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            4097, 8, 0, /* 442: pointer.func */
            4097, 8, 0, /* 445: pointer.func */
            4097, 8, 0, /* 448: pointer.func */
            4097, 8, 0, /* 451: pointer.func */
            4097, 8, 0, /* 454: pointer.func */
            4097, 8, 0, /* 457: pointer.func */
            4097, 8, 0, /* 460: pointer.func */
            4097, 8, 0, /* 463: pointer.func */
            4097, 8, 0, /* 466: pointer.func */
            4097, 8, 0, /* 469: pointer.func */
            4097, 8, 0, /* 472: pointer.func */
            1, 8, 1, /* 475: pointer.struct.engine_st */
            	480, 0,
            0, 216, 24, /* 480: struct.engine_st */
            	47, 0,
            	47, 8,
            	531, 16,
            	586, 24,
            	637, 32,
            	673, 40,
            	690, 48,
            	717, 56,
            	752, 64,
            	760, 72,
            	763, 80,
            	766, 88,
            	769, 96,
            	772, 104,
            	772, 112,
            	772, 120,
            	775, 128,
            	778, 136,
            	778, 144,
            	781, 152,
            	784, 160,
            	796, 184,
            	475, 200,
            	475, 208,
            1, 8, 1, /* 531: pointer.struct.rsa_meth_st */
            	536, 0,
            0, 112, 13, /* 536: struct.rsa_meth_st */
            	47, 0,
            	565, 8,
            	565, 16,
            	565, 24,
            	565, 32,
            	568, 40,
            	571, 48,
            	574, 56,
            	574, 64,
            	47, 80,
            	577, 88,
            	580, 96,
            	583, 104,
            4097, 8, 0, /* 565: pointer.func */
            4097, 8, 0, /* 568: pointer.func */
            4097, 8, 0, /* 571: pointer.func */
            4097, 8, 0, /* 574: pointer.func */
            4097, 8, 0, /* 577: pointer.func */
            4097, 8, 0, /* 580: pointer.func */
            4097, 8, 0, /* 583: pointer.func */
            1, 8, 1, /* 586: pointer.struct.dsa_method */
            	591, 0,
            0, 96, 11, /* 591: struct.dsa_method */
            	47, 0,
            	616, 8,
            	619, 16,
            	622, 24,
            	625, 32,
            	628, 40,
            	631, 48,
            	631, 56,
            	47, 72,
            	634, 80,
            	631, 88,
            4097, 8, 0, /* 616: pointer.func */
            4097, 8, 0, /* 619: pointer.func */
            4097, 8, 0, /* 622: pointer.func */
            4097, 8, 0, /* 625: pointer.func */
            4097, 8, 0, /* 628: pointer.func */
            4097, 8, 0, /* 631: pointer.func */
            4097, 8, 0, /* 634: pointer.func */
            1, 8, 1, /* 637: pointer.struct.dh_method */
            	642, 0,
            0, 72, 8, /* 642: struct.dh_method */
            	47, 0,
            	661, 8,
            	664, 16,
            	667, 24,
            	661, 32,
            	661, 40,
            	47, 56,
            	670, 64,
            4097, 8, 0, /* 661: pointer.func */
            4097, 8, 0, /* 664: pointer.func */
            4097, 8, 0, /* 667: pointer.func */
            4097, 8, 0, /* 670: pointer.func */
            1, 8, 1, /* 673: pointer.struct.ecdh_method */
            	678, 0,
            0, 32, 3, /* 678: struct.ecdh_method */
            	47, 0,
            	687, 8,
            	47, 24,
            4097, 8, 0, /* 687: pointer.func */
            1, 8, 1, /* 690: pointer.struct.ecdsa_method */
            	695, 0,
            0, 48, 5, /* 695: struct.ecdsa_method */
            	47, 0,
            	708, 8,
            	711, 16,
            	714, 24,
            	47, 40,
            4097, 8, 0, /* 708: pointer.func */
            4097, 8, 0, /* 711: pointer.func */
            4097, 8, 0, /* 714: pointer.func */
            1, 8, 1, /* 717: pointer.struct.rand_meth_st */
            	722, 0,
            0, 48, 6, /* 722: struct.rand_meth_st */
            	737, 0,
            	740, 8,
            	743, 16,
            	746, 24,
            	740, 32,
            	749, 40,
            4097, 8, 0, /* 737: pointer.func */
            4097, 8, 0, /* 740: pointer.func */
            4097, 8, 0, /* 743: pointer.func */
            4097, 8, 0, /* 746: pointer.func */
            4097, 8, 0, /* 749: pointer.func */
            1, 8, 1, /* 752: pointer.struct.store_method_st */
            	757, 0,
            0, 0, 0, /* 757: struct.store_method_st */
            4097, 8, 0, /* 760: pointer.func */
            4097, 8, 0, /* 763: pointer.func */
            4097, 8, 0, /* 766: pointer.func */
            4097, 8, 0, /* 769: pointer.func */
            4097, 8, 0, /* 772: pointer.func */
            4097, 8, 0, /* 775: pointer.func */
            4097, 8, 0, /* 778: pointer.func */
            4097, 8, 0, /* 781: pointer.func */
            1, 8, 1, /* 784: pointer.struct.ENGINE_CMD_DEFN_st */
            	789, 0,
            0, 32, 2, /* 789: struct.ENGINE_CMD_DEFN_st */
            	47, 8,
            	47, 16,
            0, 16, 1, /* 796: struct.crypto_ex_data_st */
            	25, 0,
            1, 8, 1, /* 801: pointer.struct.X509_POLICY_CACHE_st */
            	806, 0,
            0, 40, 2, /* 806: struct.X509_POLICY_CACHE_st */
            	185, 0,
            	25, 8,
            1, 8, 1, /* 813: pointer.struct.NAME_CONSTRAINTS_st */
            	818, 0,
            0, 16, 2, /* 818: struct.NAME_CONSTRAINTS_st */
            	25, 0,
            	25, 8,
            1, 8, 1, /* 825: pointer.struct.x509_cert_aux_st */
            	830, 0,
            0, 40, 5, /* 830: struct.x509_cert_aux_st */
            	25, 0,
            	25, 8,
            	98, 16,
            	98, 24,
            	25, 32,
            1, 8, 1, /* 843: pointer.struct.X509_POLICY_LEVEL_st */
            	259, 0,
            1, 8, 1, /* 848: pointer.struct.X509_POLICY_TREE_st */
            	853, 0,
            0, 48, 4, /* 853: struct.X509_POLICY_TREE_st */
            	843, 0,
            	25, 16,
            	25, 24,
            	25, 32,
            4097, 8, 0, /* 864: pointer.func */
            0, 1, 0, /* 867: char */
            1, 8, 1, /* 870: pointer.pointer.struct.x509_st */
            	268, 0,
            4097, 8, 0, /* 875: pointer.func */
            4097, 8, 0, /* 878: pointer.func */
            0, 4, 0, /* 881: int */
            4097, 8, 0, /* 884: pointer.func */
            0, 56, 2, /* 887: struct.X509_VERIFY_PARAM_st */
            	47, 0,
            	25, 48,
            4097, 8, 0, /* 894: pointer.func */
            4097, 8, 0, /* 897: pointer.func */
            0, 248, 25, /* 900: struct.x509_store_ctx_st */
            	953, 0,
            	268, 16,
            	25, 24,
            	25, 32,
            	991, 40,
            	47, 48,
            	428, 56,
            	878, 64,
            	996, 72,
            	884, 80,
            	428, 88,
            	897, 96,
            	999, 104,
            	875, 112,
            	428, 120,
            	864, 128,
            	864, 136,
            	428, 144,
            	25, 160,
            	848, 168,
            	268, 192,
            	268, 200,
            	209, 208,
            	1002, 224,
            	796, 232,
            1, 8, 1, /* 953: pointer.struct.x509_store_st */
            	958, 0,
            0, 144, 15, /* 958: struct.x509_store_st */
            	25, 8,
            	25, 16,
            	991, 24,
            	894, 32,
            	878, 40,
            	996, 48,
            	884, 56,
            	894, 64,
            	897, 72,
            	999, 80,
            	875, 88,
            	864, 96,
            	864, 104,
            	894, 112,
            	796, 120,
            1, 8, 1, /* 991: pointer.struct.X509_VERIFY_PARAM_st */
            	887, 0,
            4097, 8, 0, /* 996: pointer.func */
            4097, 8, 0, /* 999: pointer.func */
            1, 8, 1, /* 1002: pointer.struct.x509_store_ctx_st */
            	900, 0,
        },
        .arg_entity_index = { 870, 1002, 268, },
        .ret_entity_index = 881,
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

