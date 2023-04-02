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
            0, 8, 1, /* 85: pointer.struct.ENGINE_CMD_DEFN_st */
            	90, 0,
            0, 32, 2, /* 90: struct.ENGINE_CMD_DEFN_st */
            	26, 8,
            	26, 16,
            0, 8, 1, /* 97: pointer.struct.NAME_CONSTRAINTS_st */
            	102, 0,
            0, 16, 2, /* 102: struct.NAME_CONSTRAINTS_st */
            	31, 0,
            	31, 8,
            4097, 8, 0, /* 109: pointer.func */
            4097, 8, 0, /* 112: pointer.func */
            0, 0, 0, /* 115: func */
            4097, 8, 0, /* 118: pointer.func */
            0, 0, 0, /* 121: func */
            0, 0, 0, /* 124: func */
            4097, 8, 0, /* 127: pointer.func */
            4097, 8, 0, /* 130: pointer.func */
            0, 0, 0, /* 133: func */
            4097, 8, 0, /* 136: pointer.func */
            0, 0, 0, /* 139: struct.store_method_st */
            0, 8, 1, /* 142: pointer.struct.store_method_st */
            	139, 0,
            0, 0, 0, /* 147: func */
            4097, 8, 0, /* 150: pointer.func */
            0, 0, 0, /* 153: func */
            4097, 8, 0, /* 156: pointer.func */
            4097, 8, 0, /* 159: pointer.func */
            0, 0, 0, /* 162: func */
            0, 40, 2, /* 165: struct.X509_POLICY_CACHE_st */
            	172, 0,
            	31, 8,
            0, 8, 1, /* 172: pointer.struct.X509_POLICY_DATA_st */
            	3, 0,
            0, 0, 0, /* 177: func */
            0, 8, 1, /* 180: pointer.struct.X509_POLICY_CACHE_st */
            	165, 0,
            4097, 8, 0, /* 185: pointer.func */
            0, 0, 0, /* 188: func */
            0, 8, 1, /* 191: pointer.struct.evp_pkey_asn1_method_st */
            	196, 0,
            0, 208, 24, /* 196: struct.evp_pkey_asn1_method_st */
            	26, 16,
            	26, 24,
            	247, 32,
            	250, 40,
            	253, 48,
            	256, 56,
            	259, 64,
            	262, 72,
            	256, 80,
            	265, 88,
            	265, 96,
            	268, 104,
            	271, 112,
            	265, 120,
            	253, 128,
            	253, 136,
            	256, 144,
            	185, 152,
            	159, 160,
            	274, 168,
            	268, 176,
            	271, 184,
            	277, 192,
            	280, 200,
            4097, 8, 0, /* 247: pointer.func */
            4097, 8, 0, /* 250: pointer.func */
            4097, 8, 0, /* 253: pointer.func */
            4097, 8, 0, /* 256: pointer.func */
            4097, 8, 0, /* 259: pointer.func */
            4097, 8, 0, /* 262: pointer.func */
            4097, 8, 0, /* 265: pointer.func */
            4097, 8, 0, /* 268: pointer.func */
            4097, 8, 0, /* 271: pointer.func */
            4097, 8, 0, /* 274: pointer.func */
            4097, 8, 0, /* 277: pointer.func */
            4097, 8, 0, /* 280: pointer.func */
            0, 16, 1, /* 283: struct.crypto_ex_data_st */
            	31, 0,
            0, 0, 0, /* 288: func */
            0, 0, 0, /* 291: func */
            0, 0, 0, /* 294: func */
            0, 0, 0, /* 297: func */
            4097, 8, 0, /* 300: pointer.func */
            0, 0, 0, /* 303: func */
            0, 8, 1, /* 306: pointer.struct.evp_pkey_st */
            	311, 0,
            0, 56, 4, /* 311: struct.evp_pkey_st */
            	191, 16,
            	322, 24,
            	596, 32,
            	31, 48,
            0, 8, 1, /* 322: pointer.struct.engine_st */
            	327, 0,
            0, 216, 24, /* 327: struct.engine_st */
            	26, 0,
            	26, 8,
            	378, 16,
            	433, 24,
            	484, 32,
            	520, 40,
            	537, 48,
            	564, 56,
            	142, 64,
            	136, 72,
            	130, 80,
            	590, 88,
            	127, 96,
            	593, 104,
            	593, 112,
            	593, 120,
            	118, 128,
            	112, 136,
            	112, 144,
            	109, 152,
            	85, 160,
            	283, 184,
            	322, 200,
            	322, 208,
            0, 8, 1, /* 378: pointer.struct.rsa_meth_st */
            	383, 0,
            0, 112, 13, /* 383: struct.rsa_meth_st */
            	26, 0,
            	412, 8,
            	412, 16,
            	412, 24,
            	412, 32,
            	415, 40,
            	418, 48,
            	421, 56,
            	421, 64,
            	26, 80,
            	424, 88,
            	427, 96,
            	430, 104,
            4097, 8, 0, /* 412: pointer.func */
            4097, 8, 0, /* 415: pointer.func */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            4097, 8, 0, /* 430: pointer.func */
            0, 8, 1, /* 433: pointer.struct.dsa_method */
            	438, 0,
            0, 96, 11, /* 438: struct.dsa_method */
            	26, 0,
            	463, 8,
            	466, 16,
            	469, 24,
            	472, 32,
            	475, 40,
            	478, 48,
            	478, 56,
            	26, 72,
            	481, 80,
            	478, 88,
            4097, 8, 0, /* 463: pointer.func */
            4097, 8, 0, /* 466: pointer.func */
            4097, 8, 0, /* 469: pointer.func */
            4097, 8, 0, /* 472: pointer.func */
            4097, 8, 0, /* 475: pointer.func */
            4097, 8, 0, /* 478: pointer.func */
            4097, 8, 0, /* 481: pointer.func */
            0, 8, 1, /* 484: pointer.struct.dh_method */
            	489, 0,
            0, 72, 8, /* 489: struct.dh_method */
            	26, 0,
            	508, 8,
            	511, 16,
            	514, 24,
            	508, 32,
            	508, 40,
            	26, 56,
            	517, 64,
            4097, 8, 0, /* 508: pointer.func */
            4097, 8, 0, /* 511: pointer.func */
            4097, 8, 0, /* 514: pointer.func */
            4097, 8, 0, /* 517: pointer.func */
            0, 8, 1, /* 520: pointer.struct.ecdh_method */
            	525, 0,
            0, 32, 3, /* 525: struct.ecdh_method */
            	26, 0,
            	534, 8,
            	26, 24,
            4097, 8, 0, /* 534: pointer.func */
            0, 8, 1, /* 537: pointer.struct.ecdsa_method */
            	542, 0,
            0, 48, 5, /* 542: struct.ecdsa_method */
            	26, 0,
            	555, 8,
            	558, 16,
            	561, 24,
            	26, 40,
            4097, 8, 0, /* 555: pointer.func */
            4097, 8, 0, /* 558: pointer.func */
            4097, 8, 0, /* 561: pointer.func */
            0, 8, 1, /* 564: pointer.struct.rand_meth_st */
            	569, 0,
            0, 48, 6, /* 569: struct.rand_meth_st */
            	584, 0,
            	587, 8,
            	300, 16,
            	156, 24,
            	587, 32,
            	150, 40,
            4097, 8, 0, /* 584: pointer.func */
            4097, 8, 0, /* 587: pointer.func */
            4097, 8, 0, /* 590: pointer.func */
            4097, 8, 0, /* 593: pointer.func */
            0, 8, 1, /* 596: struct.fnames */
            	26, 0,
            0, 0, 0, /* 601: func */
            0, 8, 1, /* 604: pointer.struct.X509_pubkey_st */
            	609, 0,
            0, 24, 3, /* 609: struct.X509_pubkey_st */
            	618, 0,
            	65, 8,
            	306, 16,
            0, 8, 1, /* 618: pointer.struct.X509_algor_st */
            	623, 0,
            0, 16, 2, /* 623: struct.X509_algor_st */
            	12, 0,
            	630, 8,
            0, 8, 1, /* 630: pointer.struct.asn1_type_st */
            	635, 0,
            0, 16, 1, /* 635: struct.asn1_type_st */
            	596, 8,
            0, 0, 0, /* 640: func */
            0, 8, 0, /* 643: long */
            0, 8, 1, /* 646: pointer.struct.x509_st */
            	651, 0,
            0, 184, 12, /* 651: struct.x509_st */
            	678, 0,
            	618, 8,
            	65, 16,
            	26, 32,
            	283, 40,
            	65, 104,
            	75, 112,
            	180, 120,
            	31, 128,
            	31, 136,
            	97, 144,
            	744, 176,
            0, 8, 1, /* 678: pointer.struct.x509_cinf_st */
            	683, 0,
            0, 104, 11, /* 683: struct.x509_cinf_st */
            	65, 0,
            	65, 8,
            	618, 16,
            	708, 24,
            	732, 32,
            	708, 40,
            	604, 48,
            	65, 56,
            	65, 64,
            	31, 72,
            	80, 80,
            0, 8, 1, /* 708: pointer.struct.X509_name_st */
            	713, 0,
            0, 40, 3, /* 713: struct.X509_name_st */
            	31, 0,
            	722, 16,
            	26, 24,
            0, 8, 1, /* 722: pointer.struct.buf_mem_st */
            	727, 0,
            0, 24, 1, /* 727: struct.buf_mem_st */
            	26, 8,
            0, 8, 1, /* 732: pointer.struct.X509_val_st */
            	737, 0,
            0, 16, 2, /* 737: struct.X509_val_st */
            	65, 0,
            	65, 8,
            0, 8, 1, /* 744: pointer.struct.x509_cert_aux_st */
            	749, 0,
            0, 40, 5, /* 749: struct.x509_cert_aux_st */
            	31, 0,
            	31, 8,
            	65, 16,
            	65, 24,
            	31, 32,
            0, 1, 0, /* 762: char */
            0, 0, 0, /* 765: func */
            0, 0, 0, /* 768: func */
            0, 0, 0, /* 771: func */
            0, 0, 0, /* 774: func */
            0, 0, 0, /* 777: func */
            0, 4, 0, /* 780: int */
            0, 0, 0, /* 783: func */
            0, 0, 0, /* 786: func */
            0, 0, 0, /* 789: func */
            0, 0, 0, /* 792: func */
            0, 0, 0, /* 795: func */
            0, 0, 0, /* 798: func */
            0, 0, 0, /* 801: func */
            0, 0, 0, /* 804: func */
            0, 0, 0, /* 807: func */
            0, 0, 0, /* 810: func */
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
            0, 8, 0, /* 846: pointer.void */
            0, 0, 0, /* 849: func */
            0, 0, 0, /* 852: func */
            0, 0, 0, /* 855: func */
            0, 0, 0, /* 858: func */
            0, 0, 0, /* 861: func */
            0, 0, 0, /* 864: func */
            0, 0, 0, /* 867: func */
            0, 0, 0, /* 870: func */
        },
        .arg_entity_index = { 646, 306, },
        .ret_entity_index = 780,
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

