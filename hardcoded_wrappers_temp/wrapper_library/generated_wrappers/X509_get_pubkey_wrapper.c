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
            1, 8, 1, /* 0: pointer.struct.NAME_CONSTRAINTS_st */
            	5, 0,
            0, 16, 2, /* 5: struct.NAME_CONSTRAINTS_st */
            	12, 0,
            	12, 8,
            1, 8, 1, /* 12: pointer.struct.stack_st_OPENSSL_STRING */
            	17, 0,
            0, 32, 1, /* 17: struct.stack_st_OPENSSL_STRING */
            	22, 0,
            0, 32, 2, /* 22: struct.stack_st */
            	29, 8,
            	39, 24,
            1, 8, 1, /* 29: pointer.pointer.char */
            	34, 0,
            1, 8, 1, /* 34: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 39: pointer.func */
            0, 32, 3, /* 42: struct.X509_POLICY_DATA_st */
            	51, 8,
            	12, 16,
            	12, 24,
            1, 8, 1, /* 51: pointer.struct.asn1_object_st */
            	56, 0,
            0, 40, 3, /* 56: struct.asn1_object_st */
            	34, 0,
            	34, 8,
            	34, 24,
            1, 8, 1, /* 65: pointer.struct.X509_POLICY_DATA_st */
            	42, 0,
            0, 24, 3, /* 70: struct.AUTHORITY_KEYID_st */
            	79, 0,
            	12, 8,
            	79, 16,
            1, 8, 1, /* 79: pointer.struct.asn1_string_st */
            	84, 0,
            0, 24, 1, /* 84: struct.asn1_string_st */
            	34, 8,
            1, 8, 1, /* 89: pointer.struct.AUTHORITY_KEYID_st */
            	70, 0,
            0, 24, 1, /* 94: struct.ASN1_ENCODING_st */
            	34, 0,
            0, 24, 3, /* 99: struct.X509_pubkey_st */
            	108, 0,
            	79, 8,
            	135, 16,
            1, 8, 1, /* 108: pointer.struct.X509_algor_st */
            	113, 0,
            0, 16, 2, /* 113: struct.X509_algor_st */
            	51, 0,
            	120, 8,
            1, 8, 1, /* 120: pointer.struct.asn1_type_st */
            	125, 0,
            0, 16, 1, /* 125: struct.asn1_type_st */
            	130, 8,
            0, 8, 1, /* 130: struct.fnames */
            	34, 0,
            1, 8, 1, /* 135: pointer.struct.evp_pkey_st */
            	140, 0,
            0, 56, 4, /* 140: struct.evp_pkey_st */
            	151, 16,
            	249, 24,
            	130, 32,
            	12, 48,
            1, 8, 1, /* 151: pointer.struct.evp_pkey_asn1_method_st */
            	156, 0,
            0, 208, 24, /* 156: struct.evp_pkey_asn1_method_st */
            	34, 16,
            	34, 24,
            	207, 32,
            	210, 40,
            	213, 48,
            	216, 56,
            	219, 64,
            	222, 72,
            	216, 80,
            	225, 88,
            	225, 96,
            	228, 104,
            	231, 112,
            	225, 120,
            	213, 128,
            	213, 136,
            	216, 144,
            	234, 152,
            	237, 160,
            	240, 168,
            	228, 176,
            	231, 184,
            	243, 192,
            	246, 200,
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
            4097, 8, 0, /* 243: pointer.func */
            4097, 8, 0, /* 246: pointer.func */
            1, 8, 1, /* 249: pointer.struct.engine_st */
            	254, 0,
            0, 216, 24, /* 254: struct.engine_st */
            	34, 0,
            	34, 8,
            	305, 16,
            	360, 24,
            	411, 32,
            	447, 40,
            	464, 48,
            	491, 56,
            	526, 64,
            	534, 72,
            	537, 80,
            	540, 88,
            	543, 96,
            	546, 104,
            	546, 112,
            	546, 120,
            	549, 128,
            	552, 136,
            	552, 144,
            	555, 152,
            	558, 160,
            	570, 184,
            	249, 200,
            	249, 208,
            1, 8, 1, /* 305: pointer.struct.rsa_meth_st */
            	310, 0,
            0, 112, 13, /* 310: struct.rsa_meth_st */
            	34, 0,
            	339, 8,
            	339, 16,
            	339, 24,
            	339, 32,
            	342, 40,
            	345, 48,
            	348, 56,
            	348, 64,
            	34, 80,
            	351, 88,
            	354, 96,
            	357, 104,
            4097, 8, 0, /* 339: pointer.func */
            4097, 8, 0, /* 342: pointer.func */
            4097, 8, 0, /* 345: pointer.func */
            4097, 8, 0, /* 348: pointer.func */
            4097, 8, 0, /* 351: pointer.func */
            4097, 8, 0, /* 354: pointer.func */
            4097, 8, 0, /* 357: pointer.func */
            1, 8, 1, /* 360: pointer.struct.dsa_method */
            	365, 0,
            0, 96, 11, /* 365: struct.dsa_method */
            	34, 0,
            	390, 8,
            	393, 16,
            	396, 24,
            	399, 32,
            	402, 40,
            	405, 48,
            	405, 56,
            	34, 72,
            	408, 80,
            	405, 88,
            4097, 8, 0, /* 390: pointer.func */
            4097, 8, 0, /* 393: pointer.func */
            4097, 8, 0, /* 396: pointer.func */
            4097, 8, 0, /* 399: pointer.func */
            4097, 8, 0, /* 402: pointer.func */
            4097, 8, 0, /* 405: pointer.func */
            4097, 8, 0, /* 408: pointer.func */
            1, 8, 1, /* 411: pointer.struct.dh_method */
            	416, 0,
            0, 72, 8, /* 416: struct.dh_method */
            	34, 0,
            	435, 8,
            	438, 16,
            	441, 24,
            	435, 32,
            	435, 40,
            	34, 56,
            	444, 64,
            4097, 8, 0, /* 435: pointer.func */
            4097, 8, 0, /* 438: pointer.func */
            4097, 8, 0, /* 441: pointer.func */
            4097, 8, 0, /* 444: pointer.func */
            1, 8, 1, /* 447: pointer.struct.ecdh_method */
            	452, 0,
            0, 32, 3, /* 452: struct.ecdh_method */
            	34, 0,
            	461, 8,
            	34, 24,
            4097, 8, 0, /* 461: pointer.func */
            1, 8, 1, /* 464: pointer.struct.ecdsa_method */
            	469, 0,
            0, 48, 5, /* 469: struct.ecdsa_method */
            	34, 0,
            	482, 8,
            	485, 16,
            	488, 24,
            	34, 40,
            4097, 8, 0, /* 482: pointer.func */
            4097, 8, 0, /* 485: pointer.func */
            4097, 8, 0, /* 488: pointer.func */
            1, 8, 1, /* 491: pointer.struct.rand_meth_st */
            	496, 0,
            0, 48, 6, /* 496: struct.rand_meth_st */
            	511, 0,
            	514, 8,
            	517, 16,
            	520, 24,
            	514, 32,
            	523, 40,
            4097, 8, 0, /* 511: pointer.func */
            4097, 8, 0, /* 514: pointer.func */
            4097, 8, 0, /* 517: pointer.func */
            4097, 8, 0, /* 520: pointer.func */
            4097, 8, 0, /* 523: pointer.func */
            1, 8, 1, /* 526: pointer.struct.store_method_st */
            	531, 0,
            0, 0, 0, /* 531: struct.store_method_st */
            4097, 8, 0, /* 534: pointer.func */
            4097, 8, 0, /* 537: pointer.func */
            4097, 8, 0, /* 540: pointer.func */
            4097, 8, 0, /* 543: pointer.func */
            4097, 8, 0, /* 546: pointer.func */
            4097, 8, 0, /* 549: pointer.func */
            4097, 8, 0, /* 552: pointer.func */
            4097, 8, 0, /* 555: pointer.func */
            1, 8, 1, /* 558: pointer.struct.ENGINE_CMD_DEFN_st */
            	563, 0,
            0, 32, 2, /* 563: struct.ENGINE_CMD_DEFN_st */
            	34, 8,
            	34, 16,
            0, 16, 1, /* 570: struct.crypto_ex_data_st */
            	12, 0,
            1, 8, 1, /* 575: pointer.struct.X509_pubkey_st */
            	99, 0,
            0, 16, 2, /* 580: struct.X509_val_st */
            	79, 0,
            	79, 8,
            0, 24, 1, /* 587: struct.buf_mem_st */
            	34, 8,
            0, 104, 11, /* 592: struct.x509_cinf_st */
            	79, 0,
            	79, 8,
            	108, 16,
            	617, 24,
            	636, 32,
            	617, 40,
            	575, 48,
            	79, 56,
            	79, 64,
            	12, 72,
            	94, 80,
            1, 8, 1, /* 617: pointer.struct.X509_name_st */
            	622, 0,
            0, 40, 3, /* 622: struct.X509_name_st */
            	12, 0,
            	631, 16,
            	34, 24,
            1, 8, 1, /* 631: pointer.struct.buf_mem_st */
            	587, 0,
            1, 8, 1, /* 636: pointer.struct.X509_val_st */
            	580, 0,
            0, 184, 12, /* 641: struct.x509_st */
            	668, 0,
            	108, 8,
            	79, 16,
            	34, 32,
            	570, 40,
            	79, 104,
            	89, 112,
            	673, 120,
            	12, 128,
            	12, 136,
            	0, 144,
            	685, 176,
            1, 8, 1, /* 668: pointer.struct.x509_cinf_st */
            	592, 0,
            1, 8, 1, /* 673: pointer.struct.X509_POLICY_CACHE_st */
            	678, 0,
            0, 40, 2, /* 678: struct.X509_POLICY_CACHE_st */
            	65, 0,
            	12, 8,
            1, 8, 1, /* 685: pointer.struct.x509_cert_aux_st */
            	690, 0,
            0, 40, 5, /* 690: struct.x509_cert_aux_st */
            	12, 0,
            	12, 8,
            	79, 16,
            	79, 24,
            	12, 32,
            0, 1, 0, /* 703: char */
            0, 8, 0, /* 706: pointer.void */
            1, 8, 1, /* 709: pointer.struct.x509_st */
            	641, 0,
        },
        .arg_entity_index = { 709, },
        .ret_entity_index = 135,
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

