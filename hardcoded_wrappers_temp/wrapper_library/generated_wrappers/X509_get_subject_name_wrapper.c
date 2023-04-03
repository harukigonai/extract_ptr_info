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

X509_NAME * bb_X509_get_subject_name(X509 * arg_a);

X509_NAME * X509_get_subject_name(X509 * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_subject_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_subject_name(arg_a);
    else {
        X509_NAME * (*orig_X509_get_subject_name)(X509 *);
        orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
        return orig_X509_get_subject_name(arg_a);
    }
}

X509_NAME * bb_X509_get_subject_name(X509 * arg_a) 
{
    X509_NAME * ret;

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
            1, 8, 1, /* 88: pointer.struct.ENGINE_CMD_DEFN_st */
            	93, 0,
            0, 32, 2, /* 93: struct.ENGINE_CMD_DEFN_st */
            	29, 8,
            	29, 16,
            1, 8, 1, /* 100: pointer.struct.NAME_CONSTRAINTS_st */
            	105, 0,
            0, 16, 2, /* 105: struct.NAME_CONSTRAINTS_st */
            	34, 0,
            	34, 8,
            4097, 8, 0, /* 112: pointer.func */
            4097, 8, 0, /* 115: pointer.func */
            0, 0, 0, /* 118: func */
            4097, 8, 0, /* 121: pointer.func */
            0, 0, 0, /* 124: func */
            0, 0, 0, /* 127: func */
            4097, 8, 0, /* 130: pointer.func */
            4097, 8, 0, /* 133: pointer.func */
            0, 0, 0, /* 136: func */
            4097, 8, 0, /* 139: pointer.func */
            0, 0, 0, /* 142: struct.store_method_st */
            1, 8, 1, /* 145: pointer.struct.store_method_st */
            	142, 0,
            0, 0, 0, /* 150: func */
            4097, 8, 0, /* 153: pointer.func */
            0, 0, 0, /* 156: func */
            4097, 8, 0, /* 159: pointer.func */
            4097, 8, 0, /* 162: pointer.func */
            0, 0, 0, /* 165: func */
            0, 40, 2, /* 168: struct.X509_POLICY_CACHE_st */
            	175, 0,
            	34, 8,
            1, 8, 1, /* 175: pointer.struct.X509_POLICY_DATA_st */
            	6, 0,
            0, 0, 0, /* 180: func */
            1, 8, 1, /* 183: pointer.struct.X509_POLICY_CACHE_st */
            	168, 0,
            4097, 8, 0, /* 188: pointer.func */
            0, 0, 0, /* 191: func */
            1, 8, 1, /* 194: pointer.struct.evp_pkey_asn1_method_st */
            	199, 0,
            0, 208, 24, /* 199: struct.evp_pkey_asn1_method_st */
            	29, 16,
            	29, 24,
            	250, 32,
            	253, 40,
            	256, 48,
            	259, 56,
            	262, 64,
            	265, 72,
            	259, 80,
            	268, 88,
            	268, 96,
            	271, 104,
            	274, 112,
            	268, 120,
            	256, 128,
            	256, 136,
            	259, 144,
            	188, 152,
            	162, 160,
            	277, 168,
            	271, 176,
            	274, 184,
            	280, 192,
            	283, 200,
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
            4097, 8, 0, /* 283: pointer.func */
            0, 16, 1, /* 286: struct.crypto_ex_data_st */
            	34, 0,
            0, 0, 0, /* 291: func */
            0, 0, 0, /* 294: func */
            0, 0, 0, /* 297: func */
            0, 0, 0, /* 300: func */
            4097, 8, 0, /* 303: pointer.func */
            0, 0, 0, /* 306: func */
            1, 8, 1, /* 309: pointer.struct.evp_pkey_st */
            	314, 0,
            0, 56, 4, /* 314: struct.evp_pkey_st */
            	194, 16,
            	325, 24,
            	599, 32,
            	34, 48,
            1, 8, 1, /* 325: pointer.struct.engine_st */
            	330, 0,
            0, 216, 24, /* 330: struct.engine_st */
            	29, 0,
            	29, 8,
            	381, 16,
            	436, 24,
            	487, 32,
            	523, 40,
            	540, 48,
            	567, 56,
            	145, 64,
            	139, 72,
            	133, 80,
            	593, 88,
            	130, 96,
            	596, 104,
            	596, 112,
            	596, 120,
            	121, 128,
            	115, 136,
            	115, 144,
            	112, 152,
            	88, 160,
            	286, 184,
            	325, 200,
            	325, 208,
            1, 8, 1, /* 381: pointer.struct.rsa_meth_st */
            	386, 0,
            0, 112, 13, /* 386: struct.rsa_meth_st */
            	29, 0,
            	415, 8,
            	415, 16,
            	415, 24,
            	415, 32,
            	418, 40,
            	421, 48,
            	424, 56,
            	424, 64,
            	29, 80,
            	427, 88,
            	430, 96,
            	433, 104,
            4097, 8, 0, /* 415: pointer.func */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            4097, 8, 0, /* 430: pointer.func */
            4097, 8, 0, /* 433: pointer.func */
            1, 8, 1, /* 436: pointer.struct.dsa_method */
            	441, 0,
            0, 96, 11, /* 441: struct.dsa_method */
            	29, 0,
            	466, 8,
            	469, 16,
            	472, 24,
            	475, 32,
            	478, 40,
            	481, 48,
            	481, 56,
            	29, 72,
            	484, 80,
            	481, 88,
            4097, 8, 0, /* 466: pointer.func */
            4097, 8, 0, /* 469: pointer.func */
            4097, 8, 0, /* 472: pointer.func */
            4097, 8, 0, /* 475: pointer.func */
            4097, 8, 0, /* 478: pointer.func */
            4097, 8, 0, /* 481: pointer.func */
            4097, 8, 0, /* 484: pointer.func */
            1, 8, 1, /* 487: pointer.struct.dh_method */
            	492, 0,
            0, 72, 8, /* 492: struct.dh_method */
            	29, 0,
            	511, 8,
            	514, 16,
            	517, 24,
            	511, 32,
            	511, 40,
            	29, 56,
            	520, 64,
            4097, 8, 0, /* 511: pointer.func */
            4097, 8, 0, /* 514: pointer.func */
            4097, 8, 0, /* 517: pointer.func */
            4097, 8, 0, /* 520: pointer.func */
            1, 8, 1, /* 523: pointer.struct.ecdh_method */
            	528, 0,
            0, 32, 3, /* 528: struct.ecdh_method */
            	29, 0,
            	537, 8,
            	29, 24,
            4097, 8, 0, /* 537: pointer.func */
            1, 8, 1, /* 540: pointer.struct.ecdsa_method */
            	545, 0,
            0, 48, 5, /* 545: struct.ecdsa_method */
            	29, 0,
            	558, 8,
            	561, 16,
            	564, 24,
            	29, 40,
            4097, 8, 0, /* 558: pointer.func */
            4097, 8, 0, /* 561: pointer.func */
            4097, 8, 0, /* 564: pointer.func */
            1, 8, 1, /* 567: pointer.struct.rand_meth_st */
            	572, 0,
            0, 48, 6, /* 572: struct.rand_meth_st */
            	587, 0,
            	590, 8,
            	303, 16,
            	159, 24,
            	590, 32,
            	153, 40,
            4097, 8, 0, /* 587: pointer.func */
            4097, 8, 0, /* 590: pointer.func */
            4097, 8, 0, /* 593: pointer.func */
            4097, 8, 0, /* 596: pointer.func */
            0, 8, 1, /* 599: struct.fnames */
            	29, 0,
            0, 0, 0, /* 604: func */
            1, 8, 1, /* 607: pointer.struct.X509_pubkey_st */
            	612, 0,
            0, 24, 3, /* 612: struct.X509_pubkey_st */
            	621, 0,
            	68, 8,
            	309, 16,
            1, 8, 1, /* 621: pointer.struct.X509_algor_st */
            	626, 0,
            0, 16, 2, /* 626: struct.X509_algor_st */
            	15, 0,
            	633, 8,
            1, 8, 1, /* 633: pointer.struct.asn1_type_st */
            	638, 0,
            0, 16, 1, /* 638: struct.asn1_type_st */
            	599, 8,
            0, 24, 1, /* 643: struct.buf_mem_st */
            	29, 8,
            0, 40, 5, /* 648: struct.x509_cert_aux_st */
            	34, 0,
            	34, 8,
            	68, 16,
            	68, 24,
            	34, 32,
            1, 8, 1, /* 661: pointer.struct.X509_val_st */
            	666, 0,
            0, 16, 2, /* 666: struct.X509_val_st */
            	68, 0,
            	68, 8,
            0, 1, 0, /* 673: char */
            0, 0, 0, /* 676: func */
            0, 0, 0, /* 679: func */
            0, 0, 0, /* 682: func */
            0, 0, 0, /* 685: func */
            1, 8, 1, /* 688: pointer.struct.X509_name_st */
            	693, 0,
            0, 40, 3, /* 693: struct.X509_name_st */
            	34, 0,
            	702, 16,
            	29, 24,
            1, 8, 1, /* 702: pointer.struct.buf_mem_st */
            	643, 0,
            0, 0, 0, /* 707: func */
            0, 0, 0, /* 710: func */
            0, 0, 0, /* 713: func */
            0, 4, 0, /* 716: int */
            0, 0, 0, /* 719: func */
            0, 0, 0, /* 722: func */
            0, 0, 0, /* 725: func */
            0, 0, 0, /* 728: func */
            0, 8, 0, /* 731: long */
            1, 8, 1, /* 734: pointer.struct.x509_st */
            	739, 0,
            0, 184, 12, /* 739: struct.x509_st */
            	766, 0,
            	621, 8,
            	68, 16,
            	29, 32,
            	286, 40,
            	68, 104,
            	78, 112,
            	183, 120,
            	34, 128,
            	34, 136,
            	100, 144,
            	796, 176,
            1, 8, 1, /* 766: pointer.struct.x509_cinf_st */
            	771, 0,
            0, 104, 11, /* 771: struct.x509_cinf_st */
            	68, 0,
            	68, 8,
            	621, 16,
            	688, 24,
            	661, 32,
            	688, 40,
            	607, 48,
            	68, 56,
            	68, 64,
            	34, 72,
            	83, 80,
            1, 8, 1, /* 796: pointer.struct.x509_cert_aux_st */
            	648, 0,
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
        .arg_entity_index = { 734, },
        .ret_entity_index = 688,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    X509_NAME * *new_ret_ptr = (X509_NAME * *)new_args->ret;

    X509_NAME * (*orig_X509_get_subject_name)(X509 *);
    orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
    *new_ret_ptr = (*orig_X509_get_subject_name)(new_arg_a);

    syscall(889);

    return ret;
}

