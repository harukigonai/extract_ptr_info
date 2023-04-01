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

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b);

int X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_check_private_key called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_check_private_key(arg_a,arg_b);
    else {
        int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
        orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
        return orig_X509_check_private_key(arg_a,arg_b);
    }
}

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.x509_cert_aux_st */
            	5, 0,
            0, 40, 5, /* 5: struct.x509_cert_aux_st */
            	18, 0,
            	18, 8,
            	43, 16,
            	43, 24,
            	18, 32,
            1, 8, 1, /* 18: pointer.struct.stack_st_OPENSSL_STRING */
            	23, 0,
            0, 32, 1, /* 23: struct.stack_st_OPENSSL_STRING */
            	28, 0,
            0, 32, 1, /* 28: struct.stack_st */
            	33, 8,
            1, 8, 1, /* 33: pointer.pointer.char */
            	38, 0,
            1, 8, 1, /* 38: pointer.char */
            	4096, 0,
            1, 8, 1, /* 43: pointer.struct.asn1_string_st */
            	48, 0,
            0, 24, 1, /* 48: struct.asn1_string_st */
            	38, 8,
            0, 20, 0, /* 53: array[20].char */
            1, 8, 1, /* 56: pointer.struct.NAME_CONSTRAINTS_st */
            	61, 0,
            0, 16, 2, /* 61: struct.NAME_CONSTRAINTS_st */
            	18, 0,
            	18, 8,
            1, 8, 1, /* 68: pointer.struct.X509_POLICY_CACHE_st */
            	73, 0,
            0, 40, 2, /* 73: struct.X509_POLICY_CACHE_st */
            	80, 0,
            	18, 8,
            1, 8, 1, /* 80: pointer.struct.X509_POLICY_DATA_st */
            	85, 0,
            0, 32, 3, /* 85: struct.X509_POLICY_DATA_st */
            	94, 8,
            	18, 16,
            	18, 24,
            1, 8, 1, /* 94: pointer.struct.asn1_object_st */
            	99, 0,
            0, 40, 3, /* 99: struct.asn1_object_st */
            	38, 0,
            	38, 8,
            	38, 24,
            0, 24, 1, /* 108: struct.ASN1_ENCODING_st */
            	38, 0,
            0, 32, 2, /* 113: struct.ENGINE_CMD_DEFN_st */
            	38, 8,
            	38, 16,
            1, 8, 1, /* 120: pointer.struct.ENGINE_CMD_DEFN_st */
            	113, 0,
            0, 0, 0, /* 125: func */
            4097, 8, 0, /* 128: pointer.func */
            0, 0, 0, /* 131: func */
            0, 0, 0, /* 134: func */
            0, 0, 0, /* 137: func */
            0, 16, 1, /* 140: struct.crypto_ex_data_st */
            	18, 0,
            0, 0, 0, /* 145: func */
            0, 0, 0, /* 148: func */
            4097, 8, 0, /* 151: pointer.func */
            0, 0, 0, /* 154: struct.store_method_st */
            1, 8, 1, /* 157: pointer.struct.store_method_st */
            	154, 0,
            0, 0, 0, /* 162: func */
            4097, 8, 0, /* 165: pointer.func */
            4097, 8, 0, /* 168: pointer.func */
            0, 0, 0, /* 171: func */
            4097, 8, 0, /* 174: pointer.func */
            4097, 8, 0, /* 177: pointer.func */
            0, 0, 0, /* 180: func */
            0, 0, 0, /* 183: func */
            0, 0, 0, /* 186: func */
            0, 96, 2, /* 189: struct.dsa_method.1040 */
            	38, 0,
            	38, 72,
            4097, 8, 0, /* 196: pointer.func */
            0, 0, 0, /* 199: func */
            0, 0, 0, /* 202: func */
            4097, 8, 0, /* 205: pointer.func */
            4097, 8, 0, /* 208: pointer.func */
            4097, 8, 0, /* 211: pointer.func */
            0, 0, 0, /* 214: func */
            0, 0, 0, /* 217: func */
            4097, 8, 0, /* 220: pointer.func */
            0, 0, 0, /* 223: func */
            4097, 8, 0, /* 226: pointer.func */
            4097, 8, 0, /* 229: pointer.func */
            0, 0, 0, /* 232: func */
            0, 24, 3, /* 235: struct.X509_pubkey_st.2915 */
            	244, 0,
            	43, 8,
            	271, 16,
            1, 8, 1, /* 244: pointer.struct.X509_algor_st */
            	249, 0,
            0, 16, 2, /* 249: struct.X509_algor_st */
            	94, 0,
            	256, 8,
            1, 8, 1, /* 256: pointer.struct.asn1_type_st */
            	261, 0,
            0, 16, 1, /* 261: struct.asn1_type_st */
            	266, 8,
            0, 8, 1, /* 266: struct.fnames */
            	38, 0,
            1, 8, 1, /* 271: pointer.struct.evp_pkey_st.2930 */
            	276, 0,
            0, 56, 4, /* 276: struct.evp_pkey_st.2930 */
            	287, 16,
            	299, 24,
            	266, 32,
            	18, 48,
            1, 8, 1, /* 287: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	292, 0,
            0, 208, 2, /* 292: struct.evp_pkey_asn1_method_st.2928 */
            	38, 16,
            	38, 24,
            1, 8, 1, /* 299: pointer.struct.engine_st */
            	304, 0,
            0, 216, 13, /* 304: struct.engine_st */
            	38, 0,
            	38, 8,
            	333, 16,
            	345, 24,
            	350, 32,
            	362, 40,
            	374, 48,
            	386, 56,
            	157, 64,
            	120, 160,
            	140, 184,
            	299, 200,
            	299, 208,
            1, 8, 1, /* 333: pointer.struct.rsa_meth_st */
            	338, 0,
            0, 112, 2, /* 338: struct.rsa_meth_st */
            	38, 0,
            	38, 80,
            1, 8, 1, /* 345: pointer.struct.dsa_method.1040 */
            	189, 0,
            1, 8, 1, /* 350: pointer.struct.dh_method */
            	355, 0,
            0, 72, 2, /* 355: struct.dh_method */
            	38, 0,
            	38, 56,
            1, 8, 1, /* 362: pointer.struct.ecdh_method */
            	367, 0,
            0, 32, 2, /* 367: struct.ecdh_method */
            	38, 0,
            	38, 24,
            1, 8, 1, /* 374: pointer.struct.ecdsa_method */
            	379, 0,
            0, 48, 2, /* 379: struct.ecdsa_method */
            	38, 0,
            	38, 40,
            1, 8, 1, /* 386: pointer.struct.rand_meth_st */
            	391, 0,
            0, 48, 0, /* 391: struct.rand_meth_st */
            0, 0, 0, /* 394: func */
            0, 0, 0, /* 397: func */
            0, 8, 0, /* 400: long */
            1, 8, 1, /* 403: pointer.struct.X509_val_st */
            	408, 0,
            0, 16, 2, /* 408: struct.X509_val_st */
            	43, 0,
            	43, 8,
            4097, 8, 0, /* 415: pointer.func */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            0, 0, 0, /* 427: func */
            0, 4, 0, /* 430: int */
            1, 8, 1, /* 433: pointer.struct.x509_cinf_st.3159 */
            	438, 0,
            0, 104, 11, /* 438: struct.x509_cinf_st.3159 */
            	43, 0,
            	43, 8,
            	244, 16,
            	463, 24,
            	403, 32,
            	463, 40,
            	487, 48,
            	43, 56,
            	43, 64,
            	18, 72,
            	108, 80,
            1, 8, 1, /* 463: pointer.struct.X509_name_st */
            	468, 0,
            0, 40, 3, /* 468: struct.X509_name_st */
            	18, 0,
            	477, 16,
            	38, 24,
            1, 8, 1, /* 477: pointer.struct.buf_mem_st */
            	482, 0,
            0, 24, 1, /* 482: struct.buf_mem_st */
            	38, 8,
            1, 8, 1, /* 487: pointer.struct.X509_pubkey_st.2915 */
            	235, 0,
            4097, 8, 0, /* 492: pointer.func */
            0, 0, 0, /* 495: func */
            4097, 8, 0, /* 498: pointer.func */
            0, 0, 0, /* 501: func */
            0, 0, 0, /* 504: func */
            0, 0, 0, /* 507: func */
            1, 8, 1, /* 510: pointer.struct.x509_st.3164 */
            	515, 0,
            0, 184, 12, /* 515: struct.x509_st.3164 */
            	433, 0,
            	244, 8,
            	43, 16,
            	38, 32,
            	140, 40,
            	43, 104,
            	542, 112,
            	68, 120,
            	18, 128,
            	18, 136,
            	56, 144,
            	0, 176,
            1, 8, 1, /* 542: pointer.struct.AUTHORITY_KEYID_st */
            	547, 0,
            0, 24, 3, /* 547: struct.AUTHORITY_KEYID_st */
            	43, 0,
            	18, 8,
            	43, 16,
            4097, 8, 0, /* 556: pointer.func */
            4097, 8, 0, /* 559: pointer.func */
            4097, 8, 0, /* 562: pointer.func */
            0, 0, 0, /* 565: func */
            4097, 8, 0, /* 568: pointer.func */
            4097, 8, 0, /* 571: pointer.func */
            0, 0, 0, /* 574: func */
            0, 0, 0, /* 577: func */
            0, 0, 0, /* 580: func */
            4097, 8, 0, /* 583: pointer.func */
            4097, 8, 0, /* 586: pointer.func */
            0, 0, 0, /* 589: func */
            4097, 8, 0, /* 592: pointer.func */
            0, 0, 0, /* 595: func */
            0, 0, 0, /* 598: func */
            0, 0, 0, /* 601: func */
            4097, 8, 0, /* 604: pointer.func */
            4097, 8, 0, /* 607: pointer.func */
            4097, 8, 0, /* 610: pointer.func */
            0, 0, 0, /* 613: func */
            0, 0, 0, /* 616: func */
            4097, 8, 0, /* 619: pointer.func */
            4097, 8, 0, /* 622: pointer.func */
            0, 0, 0, /* 625: func */
            4097, 8, 0, /* 628: pointer.func */
            0, 0, 0, /* 631: func */
            0, 0, 0, /* 634: func */
            0, 0, 0, /* 637: func */
            4097, 8, 0, /* 640: pointer.func */
            4097, 8, 0, /* 643: pointer.func */
            4097, 8, 0, /* 646: pointer.func */
            0, 0, 0, /* 649: func */
            4097, 8, 0, /* 652: pointer.func */
            4097, 8, 0, /* 655: pointer.func */
            4097, 8, 0, /* 658: pointer.func */
            0, 0, 0, /* 661: func */
            4097, 8, 0, /* 664: pointer.func */
            0, 0, 0, /* 667: func */
            4097, 8, 0, /* 670: pointer.func */
            4097, 8, 0, /* 673: pointer.func */
            4097, 8, 0, /* 676: pointer.func */
            0, 0, 0, /* 679: func */
            0, 0, 0, /* 682: func */
            0, 0, 0, /* 685: func */
            4097, 8, 0, /* 688: pointer.func */
            4097, 8, 0, /* 691: pointer.func */
            0, 0, 0, /* 694: func */
            0, 1, 0, /* 697: char */
            0, 0, 0, /* 700: func */
            4097, 8, 0, /* 703: pointer.func */
            0, 0, 0, /* 706: func */
            4097, 8, 0, /* 709: pointer.func */
            4097, 8, 0, /* 712: pointer.func */
            0, 0, 0, /* 715: func */
            4097, 8, 0, /* 718: pointer.func */
            4097, 8, 0, /* 721: pointer.func */
            0, 0, 0, /* 724: func */
            0, 0, 0, /* 727: func */
        },
        .arg_entity_index = { 510, 271, },
        .ret_entity_index = 430,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * new_arg_b = *((EVP_PKEY * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
    orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
    *new_ret_ptr = (*orig_X509_check_private_key)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

