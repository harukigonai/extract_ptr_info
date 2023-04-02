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

EVP_PKEY * bb_X509_get_pubkey(X509 * arg_a);

EVP_PKEY * X509_get_pubkey(X509 * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_pubkey called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_pubkey(arg_a);
    else {
        EVP_PKEY * (*orig_X509_get_pubkey)(X509 *);
        orig_X509_get_pubkey = dlsym(RTLD_NEXT, "X509_get_pubkey");
        return orig_X509_get_pubkey(arg_a);
    }
}

EVP_PKEY * bb_X509_get_pubkey(X509 * arg_a) 
{
    EVP_PKEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 20, 0, /* 0: array[20].char */
            0, 32, 3, /* 3: struct.X509_POLICY_DATA_st */
            	12, 8,
            	31, 16,
            	31, 24,
            0, 8, 1, /* 12: pointer.struct.asn1_object_st */
            	17, 0,
            0, 40, 3, /* 17: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	26, 24,
            0, 8, 1, /* 26: pointer.char */
            	4096, 0,
            0, 8, 1, /* 31: pointer.struct.stack_st_OPENSSL_STRING */
            	36, 0,
            0, 32, 1, /* 36: struct.stack_st_OPENSSL_STRING */
            	41, 0,
            0, 32, 2, /* 41: struct.stack_st */
            	48, 8,
            	53, 24,
            0, 8, 1, /* 48: pointer.pointer.char */
            	26, 0,
            4097, 8, 0, /* 53: pointer.func */
            0, 24, 3, /* 56: struct.AUTHORITY_KEYID_st */
            	65, 0,
            	31, 8,
            	65, 16,
            0, 8, 1, /* 65: pointer.struct.asn1_string_st */
            	70, 0,
            0, 24, 1, /* 70: struct.asn1_string_st */
            	26, 8,
            0, 8, 1, /* 75: pointer.struct.AUTHORITY_KEYID_st */
            	56, 0,
            0, 24, 1, /* 80: struct.ASN1_ENCODING_st */
            	26, 0,
            0, 8, 1, /* 85: pointer.struct.X509_pubkey_st */
            	90, 0,
            0, 24, 3, /* 90: struct.X509_pubkey_st */
            	99, 0,
            	65, 8,
            	126, 16,
            0, 8, 1, /* 99: pointer.struct.X509_algor_st */
            	104, 0,
            0, 16, 2, /* 104: struct.X509_algor_st */
            	12, 0,
            	111, 8,
            0, 8, 1, /* 111: pointer.struct.asn1_type_st */
            	116, 0,
            0, 16, 1, /* 116: struct.asn1_type_st */
            	121, 8,
            0, 8, 1, /* 121: struct.fnames */
            	26, 0,
            0, 8, 1, /* 126: pointer.struct.evp_pkey_st */
            	131, 0,
            0, 56, 4, /* 131: struct.evp_pkey_st */
            	142, 16,
            	240, 24,
            	121, 32,
            	31, 48,
            0, 8, 1, /* 142: pointer.struct.evp_pkey_asn1_method_st */
            	147, 0,
            0, 208, 24, /* 147: struct.evp_pkey_asn1_method_st */
            	26, 16,
            	26, 24,
            	198, 32,
            	201, 40,
            	204, 48,
            	207, 56,
            	210, 64,
            	213, 72,
            	207, 80,
            	216, 88,
            	216, 96,
            	219, 104,
            	222, 112,
            	216, 120,
            	204, 128,
            	204, 136,
            	207, 144,
            	225, 152,
            	228, 160,
            	231, 168,
            	219, 176,
            	222, 184,
            	234, 192,
            	237, 200,
            4097, 8, 0, /* 198: pointer.func */
            4097, 8, 0, /* 201: pointer.func */
            4097, 8, 0, /* 204: pointer.func */
            4097, 8, 0, /* 207: pointer.func */
            4097, 8, 0, /* 210: pointer.func */
            4097, 8, 0, /* 213: pointer.func */
            4097, 8, 0, /* 216: pointer.func */
            4097, 8, 0, /* 219: pointer.func */
            4097, 8, 0, /* 222: pointer.func */
            4097, 8, 0, /* 225: pointer.func */
            4097, 8, 0, /* 228: pointer.func */
            4097, 8, 0, /* 231: pointer.func */
            4097, 8, 0, /* 234: pointer.func */
            4097, 8, 0, /* 237: pointer.func */
            0, 8, 1, /* 240: pointer.struct.engine_st */
            	245, 0,
            0, 216, 24, /* 245: struct.engine_st */
            	26, 0,
            	26, 8,
            	296, 16,
            	351, 24,
            	402, 32,
            	438, 40,
            	455, 48,
            	482, 56,
            	517, 64,
            	525, 72,
            	528, 80,
            	531, 88,
            	534, 96,
            	537, 104,
            	537, 112,
            	537, 120,
            	540, 128,
            	543, 136,
            	543, 144,
            	546, 152,
            	549, 160,
            	561, 184,
            	240, 200,
            	240, 208,
            0, 8, 1, /* 296: pointer.struct.rsa_meth_st */
            	301, 0,
            0, 112, 13, /* 301: struct.rsa_meth_st */
            	26, 0,
            	330, 8,
            	330, 16,
            	330, 24,
            	330, 32,
            	333, 40,
            	336, 48,
            	339, 56,
            	339, 64,
            	26, 80,
            	342, 88,
            	345, 96,
            	348, 104,
            4097, 8, 0, /* 330: pointer.func */
            4097, 8, 0, /* 333: pointer.func */
            4097, 8, 0, /* 336: pointer.func */
            4097, 8, 0, /* 339: pointer.func */
            4097, 8, 0, /* 342: pointer.func */
            4097, 8, 0, /* 345: pointer.func */
            4097, 8, 0, /* 348: pointer.func */
            0, 8, 1, /* 351: pointer.struct.dsa_method */
            	356, 0,
            0, 96, 11, /* 356: struct.dsa_method */
            	26, 0,
            	381, 8,
            	384, 16,
            	387, 24,
            	390, 32,
            	393, 40,
            	396, 48,
            	396, 56,
            	26, 72,
            	399, 80,
            	396, 88,
            4097, 8, 0, /* 381: pointer.func */
            4097, 8, 0, /* 384: pointer.func */
            4097, 8, 0, /* 387: pointer.func */
            4097, 8, 0, /* 390: pointer.func */
            4097, 8, 0, /* 393: pointer.func */
            4097, 8, 0, /* 396: pointer.func */
            4097, 8, 0, /* 399: pointer.func */
            0, 8, 1, /* 402: pointer.struct.dh_method */
            	407, 0,
            0, 72, 8, /* 407: struct.dh_method */
            	26, 0,
            	426, 8,
            	429, 16,
            	432, 24,
            	426, 32,
            	426, 40,
            	26, 56,
            	435, 64,
            4097, 8, 0, /* 426: pointer.func */
            4097, 8, 0, /* 429: pointer.func */
            4097, 8, 0, /* 432: pointer.func */
            4097, 8, 0, /* 435: pointer.func */
            0, 8, 1, /* 438: pointer.struct.ecdh_method */
            	443, 0,
            0, 32, 3, /* 443: struct.ecdh_method */
            	26, 0,
            	452, 8,
            	26, 24,
            4097, 8, 0, /* 452: pointer.func */
            0, 8, 1, /* 455: pointer.struct.ecdsa_method */
            	460, 0,
            0, 48, 5, /* 460: struct.ecdsa_method */
            	26, 0,
            	473, 8,
            	476, 16,
            	479, 24,
            	26, 40,
            4097, 8, 0, /* 473: pointer.func */
            4097, 8, 0, /* 476: pointer.func */
            4097, 8, 0, /* 479: pointer.func */
            0, 8, 1, /* 482: pointer.struct.rand_meth_st */
            	487, 0,
            0, 48, 6, /* 487: struct.rand_meth_st */
            	502, 0,
            	505, 8,
            	508, 16,
            	511, 24,
            	505, 32,
            	514, 40,
            4097, 8, 0, /* 502: pointer.func */
            4097, 8, 0, /* 505: pointer.func */
            4097, 8, 0, /* 508: pointer.func */
            4097, 8, 0, /* 511: pointer.func */
            4097, 8, 0, /* 514: pointer.func */
            0, 8, 1, /* 517: pointer.struct.store_method_st */
            	522, 0,
            0, 0, 0, /* 522: struct.store_method_st */
            4097, 8, 0, /* 525: pointer.func */
            4097, 8, 0, /* 528: pointer.func */
            4097, 8, 0, /* 531: pointer.func */
            4097, 8, 0, /* 534: pointer.func */
            4097, 8, 0, /* 537: pointer.func */
            4097, 8, 0, /* 540: pointer.func */
            4097, 8, 0, /* 543: pointer.func */
            4097, 8, 0, /* 546: pointer.func */
            0, 8, 1, /* 549: pointer.struct.ENGINE_CMD_DEFN_st */
            	554, 0,
            0, 32, 2, /* 554: struct.ENGINE_CMD_DEFN_st */
            	26, 8,
            	26, 16,
            0, 16, 1, /* 561: struct.crypto_ex_data_st */
            	31, 0,
            0, 8, 1, /* 566: pointer.struct.X509_val_st */
            	571, 0,
            0, 16, 2, /* 571: struct.X509_val_st */
            	65, 0,
            	65, 8,
            0, 24, 1, /* 578: struct.buf_mem_st */
            	26, 8,
            0, 8, 1, /* 583: pointer.struct.buf_mem_st */
            	578, 0,
            0, 40, 3, /* 588: struct.X509_name_st */
            	31, 0,
            	583, 16,
            	26, 24,
            0, 8, 1, /* 597: pointer.struct.X509_name_st */
            	588, 0,
            0, 8, 1, /* 602: pointer.struct.x509_cinf_st */
            	607, 0,
            0, 104, 11, /* 607: struct.x509_cinf_st */
            	65, 0,
            	65, 8,
            	99, 16,
            	597, 24,
            	566, 32,
            	597, 40,
            	85, 48,
            	65, 56,
            	65, 64,
            	31, 72,
            	80, 80,
            0, 0, 0, /* 632: func */
            0, 0, 0, /* 635: func */
            0, 0, 0, /* 638: func */
            0, 0, 0, /* 641: func */
            0, 0, 0, /* 644: func */
            0, 0, 0, /* 647: func */
            0, 0, 0, /* 650: func */
            0, 0, 0, /* 653: func */
            0, 0, 0, /* 656: func */
            0, 0, 0, /* 659: func */
            0, 1, 0, /* 662: char */
            0, 0, 0, /* 665: func */
            0, 0, 0, /* 668: func */
            0, 0, 0, /* 671: func */
            0, 0, 0, /* 674: func */
            0, 0, 0, /* 677: func */
            0, 0, 0, /* 680: func */
            0, 0, 0, /* 683: func */
            0, 0, 0, /* 686: func */
            0, 0, 0, /* 689: func */
            0, 0, 0, /* 692: func */
            0, 0, 0, /* 695: func */
            0, 8, 1, /* 698: pointer.struct.x509_st */
            	703, 0,
            0, 184, 12, /* 703: struct.x509_st */
            	602, 0,
            	99, 8,
            	65, 16,
            	26, 32,
            	561, 40,
            	65, 104,
            	75, 112,
            	730, 120,
            	31, 128,
            	31, 136,
            	747, 144,
            	759, 176,
            0, 8, 1, /* 730: pointer.struct.X509_POLICY_CACHE_st */
            	735, 0,
            0, 40, 2, /* 735: struct.X509_POLICY_CACHE_st */
            	742, 0,
            	31, 8,
            0, 8, 1, /* 742: pointer.struct.X509_POLICY_DATA_st */
            	3, 0,
            0, 8, 1, /* 747: pointer.struct.NAME_CONSTRAINTS_st */
            	752, 0,
            0, 16, 2, /* 752: struct.NAME_CONSTRAINTS_st */
            	31, 0,
            	31, 8,
            0, 8, 1, /* 759: pointer.struct.x509_cert_aux_st */
            	764, 0,
            0, 40, 5, /* 764: struct.x509_cert_aux_st */
            	31, 0,
            	31, 8,
            	65, 16,
            	65, 24,
            	31, 32,
            0, 0, 0, /* 777: func */
            0, 0, 0, /* 780: func */
            0, 8, 0, /* 783: long */
            0, 0, 0, /* 786: func */
            0, 0, 0, /* 789: func */
            0, 0, 0, /* 792: func */
            0, 0, 0, /* 795: func */
            0, 0, 0, /* 798: func */
            0, 0, 0, /* 801: func */
            0, 0, 0, /* 804: func */
            0, 4, 0, /* 807: int */
            0, 0, 0, /* 810: func */
            0, 0, 0, /* 813: func */
            0, 0, 0, /* 816: func */
            0, 0, 0, /* 819: func */
            0, 8, 0, /* 822: pointer.void */
            0, 0, 0, /* 825: func */
            0, 0, 0, /* 828: func */
            0, 0, 0, /* 831: func */
            0, 0, 0, /* 834: func */
            0, 0, 0, /* 837: func */
            0, 0, 0, /* 840: func */
            0, 0, 0, /* 843: func */
            0, 0, 0, /* 846: func */
            0, 0, 0, /* 849: func */
            0, 0, 0, /* 852: func */
            0, 0, 0, /* 855: func */
            0, 0, 0, /* 858: func */
            0, 0, 0, /* 861: func */
            0, 0, 0, /* 864: func */
            0, 0, 0, /* 867: func */
            0, 0, 0, /* 870: func */
        },
        .arg_entity_index = { 698, },
        .ret_entity_index = 126,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_X509_get_pubkey)(X509 *);
    orig_X509_get_pubkey = dlsym(RTLD_NEXT, "X509_get_pubkey");
    *new_ret_ptr = (*orig_X509_get_pubkey)(new_arg_a);

    syscall(889);

    return ret;
}

