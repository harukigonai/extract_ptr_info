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
            0, 8, 0, /* 0: pointer.void */
            0, 20, 0, /* 3: array[20].char */
            0, 32, 3, /* 6: struct.X509_POLICY_DATA_st */
            	15, 8,
            	34, 16,
            	34, 24,
            1, 8, 1, /* 15: pointer.struct.asn1_object_st */
            	20, 0,
            0, 40, 3, /* 20: struct.asn1_object_st */
            	29, 0,
            	29, 8,
            	29, 24,
            1, 8, 1, /* 29: pointer.char */
            	4096, 0,
            1, 8, 1, /* 34: pointer.struct.stack_st_OPENSSL_STRING */
            	39, 0,
            0, 32, 1, /* 39: struct.stack_st_OPENSSL_STRING */
            	44, 0,
            0, 32, 2, /* 44: struct.stack_st */
            	51, 8,
            	56, 24,
            1, 8, 1, /* 51: pointer.pointer.char */
            	29, 0,
            4097, 8, 0, /* 56: pointer.func */
            0, 24, 3, /* 59: struct.AUTHORITY_KEYID_st */
            	68, 0,
            	34, 8,
            	68, 16,
            1, 8, 1, /* 68: pointer.struct.asn1_string_st */
            	73, 0,
            0, 24, 1, /* 73: struct.asn1_string_st */
            	29, 8,
            1, 8, 1, /* 78: pointer.struct.AUTHORITY_KEYID_st */
            	59, 0,
            0, 24, 1, /* 83: struct.ASN1_ENCODING_st */
            	29, 0,
            1, 8, 1, /* 88: pointer.struct.X509_pubkey_st */
            	93, 0,
            0, 24, 3, /* 93: struct.X509_pubkey_st */
            	102, 0,
            	68, 8,
            	129, 16,
            1, 8, 1, /* 102: pointer.struct.X509_algor_st */
            	107, 0,
            0, 16, 2, /* 107: struct.X509_algor_st */
            	15, 0,
            	114, 8,
            1, 8, 1, /* 114: pointer.struct.asn1_type_st */
            	119, 0,
            0, 16, 1, /* 119: struct.asn1_type_st */
            	124, 8,
            0, 8, 1, /* 124: struct.fnames */
            	29, 0,
            1, 8, 1, /* 129: pointer.struct.evp_pkey_st */
            	134, 0,
            0, 56, 4, /* 134: struct.evp_pkey_st */
            	145, 16,
            	243, 24,
            	124, 32,
            	34, 48,
            1, 8, 1, /* 145: pointer.struct.evp_pkey_asn1_method_st */
            	150, 0,
            0, 208, 24, /* 150: struct.evp_pkey_asn1_method_st */
            	29, 16,
            	29, 24,
            	201, 32,
            	204, 40,
            	207, 48,
            	210, 56,
            	213, 64,
            	216, 72,
            	210, 80,
            	219, 88,
            	219, 96,
            	222, 104,
            	225, 112,
            	219, 120,
            	207, 128,
            	207, 136,
            	210, 144,
            	228, 152,
            	231, 160,
            	234, 168,
            	222, 176,
            	225, 184,
            	237, 192,
            	240, 200,
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
            4097, 8, 0, /* 240: pointer.func */
            1, 8, 1, /* 243: pointer.struct.engine_st */
            	248, 0,
            0, 216, 24, /* 248: struct.engine_st */
            	29, 0,
            	29, 8,
            	299, 16,
            	354, 24,
            	405, 32,
            	441, 40,
            	458, 48,
            	485, 56,
            	520, 64,
            	528, 72,
            	531, 80,
            	534, 88,
            	537, 96,
            	540, 104,
            	540, 112,
            	540, 120,
            	543, 128,
            	546, 136,
            	546, 144,
            	549, 152,
            	552, 160,
            	564, 184,
            	243, 200,
            	243, 208,
            1, 8, 1, /* 299: pointer.struct.rsa_meth_st */
            	304, 0,
            0, 112, 13, /* 304: struct.rsa_meth_st */
            	29, 0,
            	333, 8,
            	333, 16,
            	333, 24,
            	333, 32,
            	336, 40,
            	339, 48,
            	342, 56,
            	342, 64,
            	29, 80,
            	345, 88,
            	348, 96,
            	351, 104,
            4097, 8, 0, /* 333: pointer.func */
            4097, 8, 0, /* 336: pointer.func */
            4097, 8, 0, /* 339: pointer.func */
            4097, 8, 0, /* 342: pointer.func */
            4097, 8, 0, /* 345: pointer.func */
            4097, 8, 0, /* 348: pointer.func */
            4097, 8, 0, /* 351: pointer.func */
            1, 8, 1, /* 354: pointer.struct.dsa_method */
            	359, 0,
            0, 96, 11, /* 359: struct.dsa_method */
            	29, 0,
            	384, 8,
            	387, 16,
            	390, 24,
            	393, 32,
            	396, 40,
            	399, 48,
            	399, 56,
            	29, 72,
            	402, 80,
            	399, 88,
            4097, 8, 0, /* 384: pointer.func */
            4097, 8, 0, /* 387: pointer.func */
            4097, 8, 0, /* 390: pointer.func */
            4097, 8, 0, /* 393: pointer.func */
            4097, 8, 0, /* 396: pointer.func */
            4097, 8, 0, /* 399: pointer.func */
            4097, 8, 0, /* 402: pointer.func */
            1, 8, 1, /* 405: pointer.struct.dh_method */
            	410, 0,
            0, 72, 8, /* 410: struct.dh_method */
            	29, 0,
            	429, 8,
            	432, 16,
            	435, 24,
            	429, 32,
            	429, 40,
            	29, 56,
            	438, 64,
            4097, 8, 0, /* 429: pointer.func */
            4097, 8, 0, /* 432: pointer.func */
            4097, 8, 0, /* 435: pointer.func */
            4097, 8, 0, /* 438: pointer.func */
            1, 8, 1, /* 441: pointer.struct.ecdh_method */
            	446, 0,
            0, 32, 3, /* 446: struct.ecdh_method */
            	29, 0,
            	455, 8,
            	29, 24,
            4097, 8, 0, /* 455: pointer.func */
            1, 8, 1, /* 458: pointer.struct.ecdsa_method */
            	463, 0,
            0, 48, 5, /* 463: struct.ecdsa_method */
            	29, 0,
            	476, 8,
            	479, 16,
            	482, 24,
            	29, 40,
            4097, 8, 0, /* 476: pointer.func */
            4097, 8, 0, /* 479: pointer.func */
            4097, 8, 0, /* 482: pointer.func */
            1, 8, 1, /* 485: pointer.struct.rand_meth_st */
            	490, 0,
            0, 48, 6, /* 490: struct.rand_meth_st */
            	505, 0,
            	508, 8,
            	511, 16,
            	514, 24,
            	508, 32,
            	517, 40,
            4097, 8, 0, /* 505: pointer.func */
            4097, 8, 0, /* 508: pointer.func */
            4097, 8, 0, /* 511: pointer.func */
            4097, 8, 0, /* 514: pointer.func */
            4097, 8, 0, /* 517: pointer.func */
            1, 8, 1, /* 520: pointer.struct.store_method_st */
            	525, 0,
            0, 0, 0, /* 525: struct.store_method_st */
            4097, 8, 0, /* 528: pointer.func */
            4097, 8, 0, /* 531: pointer.func */
            4097, 8, 0, /* 534: pointer.func */
            4097, 8, 0, /* 537: pointer.func */
            4097, 8, 0, /* 540: pointer.func */
            4097, 8, 0, /* 543: pointer.func */
            4097, 8, 0, /* 546: pointer.func */
            4097, 8, 0, /* 549: pointer.func */
            1, 8, 1, /* 552: pointer.struct.ENGINE_CMD_DEFN_st */
            	557, 0,
            0, 32, 2, /* 557: struct.ENGINE_CMD_DEFN_st */
            	29, 8,
            	29, 16,
            0, 16, 1, /* 564: struct.crypto_ex_data_st */
            	34, 0,
            1, 8, 1, /* 569: pointer.struct.X509_val_st */
            	574, 0,
            0, 16, 2, /* 574: struct.X509_val_st */
            	68, 0,
            	68, 8,
            0, 24, 1, /* 581: struct.buf_mem_st */
            	29, 8,
            1, 8, 1, /* 586: pointer.struct.buf_mem_st */
            	581, 0,
            0, 40, 3, /* 591: struct.X509_name_st */
            	34, 0,
            	586, 16,
            	29, 24,
            1, 8, 1, /* 600: pointer.struct.X509_name_st */
            	591, 0,
            1, 8, 1, /* 605: pointer.struct.x509_cinf_st */
            	610, 0,
            0, 104, 11, /* 610: struct.x509_cinf_st */
            	68, 0,
            	68, 8,
            	102, 16,
            	600, 24,
            	569, 32,
            	600, 40,
            	88, 48,
            	68, 56,
            	68, 64,
            	34, 72,
            	83, 80,
            0, 0, 0, /* 635: func */
            0, 0, 0, /* 638: func */
            0, 0, 0, /* 641: func */
            0, 0, 0, /* 644: func */
            0, 0, 0, /* 647: func */
            0, 0, 0, /* 650: func */
            0, 0, 0, /* 653: func */
            0, 0, 0, /* 656: func */
            0, 0, 0, /* 659: func */
            0, 0, 0, /* 662: func */
            0, 1, 0, /* 665: char */
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
            0, 0, 0, /* 698: func */
            1, 8, 1, /* 701: pointer.struct.x509_st */
            	706, 0,
            0, 184, 12, /* 706: struct.x509_st */
            	605, 0,
            	102, 8,
            	68, 16,
            	29, 32,
            	564, 40,
            	68, 104,
            	78, 112,
            	733, 120,
            	34, 128,
            	34, 136,
            	750, 144,
            	762, 176,
            1, 8, 1, /* 733: pointer.struct.X509_POLICY_CACHE_st */
            	738, 0,
            0, 40, 2, /* 738: struct.X509_POLICY_CACHE_st */
            	745, 0,
            	34, 8,
            1, 8, 1, /* 745: pointer.struct.X509_POLICY_DATA_st */
            	6, 0,
            1, 8, 1, /* 750: pointer.struct.NAME_CONSTRAINTS_st */
            	755, 0,
            0, 16, 2, /* 755: struct.NAME_CONSTRAINTS_st */
            	34, 0,
            	34, 8,
            1, 8, 1, /* 762: pointer.struct.x509_cert_aux_st */
            	767, 0,
            0, 40, 5, /* 767: struct.x509_cert_aux_st */
            	34, 0,
            	34, 8,
            	68, 16,
            	68, 24,
            	34, 32,
            0, 0, 0, /* 780: func */
            0, 0, 0, /* 783: func */
            0, 8, 0, /* 786: long */
            0, 0, 0, /* 789: func */
            0, 0, 0, /* 792: func */
            0, 0, 0, /* 795: func */
            0, 0, 0, /* 798: func */
            0, 0, 0, /* 801: func */
            0, 0, 0, /* 804: func */
            0, 0, 0, /* 807: func */
            0, 4, 0, /* 810: int */
            0, 0, 0, /* 813: func */
            0, 0, 0, /* 816: func */
            0, 0, 0, /* 819: func */
            0, 0, 0, /* 822: func */
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
        .arg_entity_index = { 701, },
        .ret_entity_index = 129,
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

