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

void bb_EVP_PKEY_free(EVP_PKEY * arg_a);

void EVP_PKEY_free(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EVP_PKEY_free(arg_a);
    else {
        void (*orig_EVP_PKEY_free)(EVP_PKEY *);
        orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
        orig_EVP_PKEY_free(arg_a);
    }
}

void bb_EVP_PKEY_free(EVP_PKEY * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.ASN1_VALUE_st */
            	5, 0,
            0, 0, 0, /* 5: struct.ASN1_VALUE_st */
            64097, 8, 0, /* 8: pointer.func */
            64097, 8, 0, /* 11: pointer.func */
            1, 8, 1, /* 14: pointer.struct.asn1_string_st */
            	19, 0,
            0, 24, 1, /* 19: struct.asn1_string_st */
            	24, 8,
            1, 8, 1, /* 24: pointer.unsigned char */
            	29, 0,
            0, 1, 0, /* 29: unsigned char */
            1, 8, 1, /* 32: pointer.struct.asn1_string_st */
            	19, 0,
            0, 24, 1, /* 37: struct.asn1_string_st */
            	24, 8,
            0, 24, 1, /* 42: struct.bignum_st */
            	47, 0,
            1, 8, 1, /* 47: pointer.unsigned int */
            	52, 0,
            0, 4, 0, /* 52: unsigned int */
            1, 8, 1, /* 55: pointer.struct.bignum_st */
            	42, 0,
            64097, 8, 0, /* 60: pointer.func */
            1, 8, 1, /* 63: pointer.struct.asn1_string_st */
            	19, 0,
            64097, 8, 0, /* 68: pointer.func */
            0, 8, 20, /* 71: union.unknown */
            	114, 0,
            	119, 0,
            	124, 0,
            	148, 0,
            	153, 0,
            	158, 0,
            	163, 0,
            	168, 0,
            	173, 0,
            	178, 0,
            	14, 0,
            	63, 0,
            	183, 0,
            	32, 0,
            	188, 0,
            	193, 0,
            	198, 0,
            	119, 0,
            	119, 0,
            	203, 0,
            1, 8, 1, /* 114: pointer.char */
            	64096, 0,
            1, 8, 1, /* 119: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 124: pointer.struct.asn1_object_st */
            	129, 0,
            0, 40, 3, /* 129: struct.asn1_object_st */
            	138, 0,
            	138, 8,
            	143, 24,
            1, 8, 1, /* 138: pointer.char */
            	64096, 0,
            1, 8, 1, /* 143: pointer.unsigned char */
            	29, 0,
            1, 8, 1, /* 148: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 153: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 158: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 163: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 168: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 173: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 178: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 183: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 188: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 193: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 198: pointer.struct.asn1_string_st */
            	19, 0,
            1, 8, 1, /* 203: pointer.struct.ASN1_VALUE_st */
            	208, 0,
            0, 0, 0, /* 208: struct.ASN1_VALUE_st */
            1, 8, 1, /* 211: pointer.struct.asn1_string_st */
            	37, 0,
            0, 96, 3, /* 216: struct.bn_mont_ctx_st */
            	42, 8,
            	42, 32,
            	42, 56,
            1, 8, 1, /* 225: pointer.struct.dh_st */
            	230, 0,
            0, 144, 12, /* 230: struct.dh_st */
            	55, 8,
            	55, 16,
            	55, 32,
            	55, 40,
            	257, 56,
            	55, 64,
            	55, 72,
            	24, 80,
            	55, 96,
            	262, 112,
            	292, 128,
            	328, 136,
            1, 8, 1, /* 257: pointer.struct.bn_mont_ctx_st */
            	216, 0,
            0, 16, 1, /* 262: struct.crypto_ex_data_st */
            	267, 0,
            1, 8, 1, /* 267: pointer.struct.stack_st_void */
            	272, 0,
            0, 32, 1, /* 272: struct.stack_st_void */
            	277, 0,
            0, 32, 2, /* 277: struct.stack_st */
            	284, 8,
            	289, 24,
            1, 8, 1, /* 284: pointer.pointer.char */
            	114, 0,
            64097, 8, 0, /* 289: pointer.func */
            1, 8, 1, /* 292: pointer.struct.dh_method */
            	297, 0,
            0, 72, 8, /* 297: struct.dh_method */
            	138, 0,
            	316, 8,
            	319, 16,
            	322, 24,
            	316, 32,
            	316, 40,
            	114, 56,
            	325, 64,
            64097, 8, 0, /* 316: pointer.func */
            64097, 8, 0, /* 319: pointer.func */
            64097, 8, 0, /* 322: pointer.func */
            64097, 8, 0, /* 325: pointer.func */
            1, 8, 1, /* 328: pointer.struct.engine_st */
            	333, 0,
            0, 0, 0, /* 333: struct.engine_st */
            64097, 8, 0, /* 336: pointer.func */
            64097, 8, 0, /* 339: pointer.func */
            64097, 8, 0, /* 342: pointer.func */
            64097, 8, 0, /* 345: pointer.func */
            64097, 8, 0, /* 348: pointer.func */
            1, 8, 1, /* 351: pointer.struct.evp_pkey_asn1_method_st */
            	356, 0,
            0, 208, 24, /* 356: struct.evp_pkey_asn1_method_st */
            	114, 16,
            	114, 24,
            	407, 32,
            	410, 40,
            	413, 48,
            	339, 56,
            	416, 64,
            	345, 72,
            	339, 80,
            	419, 88,
            	419, 96,
            	422, 104,
            	425, 112,
            	419, 120,
            	342, 128,
            	413, 136,
            	339, 144,
            	428, 152,
            	348, 160,
            	431, 168,
            	422, 176,
            	425, 184,
            	434, 192,
            	437, 200,
            64097, 8, 0, /* 407: pointer.func */
            64097, 8, 0, /* 410: pointer.func */
            64097, 8, 0, /* 413: pointer.func */
            64097, 8, 0, /* 416: pointer.func */
            64097, 8, 0, /* 419: pointer.func */
            64097, 8, 0, /* 422: pointer.func */
            64097, 8, 0, /* 425: pointer.func */
            64097, 8, 0, /* 428: pointer.func */
            64097, 8, 0, /* 431: pointer.func */
            64097, 8, 0, /* 434: pointer.func */
            64097, 8, 0, /* 437: pointer.func */
            1, 8, 1, /* 440: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 445: pointer.struct.dsa_st */
            	450, 0,
            0, 136, 11, /* 450: struct.dsa_st */
            	55, 24,
            	55, 32,
            	55, 40,
            	55, 48,
            	55, 56,
            	55, 64,
            	55, 72,
            	257, 88,
            	262, 104,
            	475, 120,
            	328, 128,
            1, 8, 1, /* 475: pointer.struct.dsa_method */
            	480, 0,
            0, 96, 11, /* 480: struct.dsa_method */
            	138, 0,
            	336, 8,
            	505, 16,
            	508, 24,
            	511, 32,
            	8, 40,
            	514, 48,
            	514, 56,
            	114, 72,
            	517, 80,
            	514, 88,
            64097, 8, 0, /* 505: pointer.func */
            64097, 8, 0, /* 508: pointer.func */
            64097, 8, 0, /* 511: pointer.func */
            64097, 8, 0, /* 514: pointer.func */
            64097, 8, 0, /* 517: pointer.func */
            64097, 8, 0, /* 520: pointer.func */
            1, 8, 1, /* 523: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 528: pointer.struct.asn1_string_st */
            	37, 0,
            0, 8, 5, /* 533: union.unknown */
            	114, 0,
            	546, 0,
            	445, 0,
            	225, 0,
            	639, 0,
            1, 8, 1, /* 546: pointer.struct.rsa_st */
            	551, 0,
            0, 168, 17, /* 551: struct.rsa_st */
            	588, 16,
            	328, 24,
            	55, 32,
            	55, 40,
            	55, 48,
            	55, 56,
            	55, 64,
            	55, 72,
            	55, 80,
            	55, 88,
            	262, 96,
            	257, 120,
            	257, 128,
            	257, 136,
            	114, 144,
            	631, 152,
            	631, 160,
            1, 8, 1, /* 588: pointer.struct.rsa_meth_st */
            	593, 0,
            0, 112, 13, /* 593: struct.rsa_meth_st */
            	138, 0,
            	622, 8,
            	622, 16,
            	622, 24,
            	622, 32,
            	625, 40,
            	520, 48,
            	628, 56,
            	628, 64,
            	114, 80,
            	11, 88,
            	68, 96,
            	60, 104,
            64097, 8, 0, /* 622: pointer.func */
            64097, 8, 0, /* 625: pointer.func */
            64097, 8, 0, /* 628: pointer.func */
            1, 8, 1, /* 631: pointer.struct.bn_blinding_st */
            	636, 0,
            0, 0, 0, /* 636: struct.bn_blinding_st */
            1, 8, 1, /* 639: pointer.struct.ec_key_st */
            	644, 0,
            0, 0, 0, /* 644: struct.ec_key_st */
            0, 1, 0, /* 647: char */
            1, 8, 1, /* 650: pointer.struct.asn1_string_st */
            	37, 0,
            0, 4, 0, /* 655: int */
            0, 16, 1, /* 658: struct.asn1_type_st */
            	663, 8,
            0, 8, 20, /* 663: union.unknown */
            	114, 0,
            	706, 0,
            	711, 0,
            	523, 0,
            	725, 0,
            	730, 0,
            	650, 0,
            	211, 0,
            	735, 0,
            	740, 0,
            	745, 0,
            	750, 0,
            	528, 0,
            	755, 0,
            	760, 0,
            	765, 0,
            	440, 0,
            	706, 0,
            	706, 0,
            	0, 0,
            1, 8, 1, /* 706: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 711: pointer.struct.asn1_object_st */
            	716, 0,
            0, 40, 3, /* 716: struct.asn1_object_st */
            	138, 0,
            	138, 8,
            	143, 24,
            1, 8, 1, /* 725: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 730: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 735: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 740: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 745: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 750: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 755: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 760: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 765: pointer.struct.asn1_string_st */
            	37, 0,
            1, 8, 1, /* 770: pointer.struct.evp_pkey_st */
            	775, 0,
            0, 56, 4, /* 775: struct.evp_pkey_st */
            	351, 16,
            	328, 24,
            	533, 32,
            	786, 48,
            1, 8, 1, /* 786: pointer.struct.stack_st_X509_ATTRIBUTE */
            	791, 0,
            0, 32, 2, /* 791: struct.stack_st_fake_X509_ATTRIBUTE */
            	798, 8,
            	289, 24,
            64099, 8, 2, /* 798: pointer_to_array_of_pointers_to_stack */
            	805, 0,
            	655, 20,
            0, 8, 1, /* 805: pointer.X509_ATTRIBUTE */
            	810, 0,
            0, 0, 1, /* 810: X509_ATTRIBUTE */
            	815, 0,
            0, 24, 2, /* 815: struct.x509_attributes_st */
            	711, 0,
            	822, 16,
            0, 8, 3, /* 822: union.unknown */
            	114, 0,
            	831, 0,
            	865, 0,
            1, 8, 1, /* 831: pointer.struct.stack_st_ASN1_TYPE */
            	836, 0,
            0, 32, 2, /* 836: struct.stack_st_fake_ASN1_TYPE */
            	843, 8,
            	289, 24,
            64099, 8, 2, /* 843: pointer_to_array_of_pointers_to_stack */
            	850, 0,
            	655, 20,
            0, 8, 1, /* 850: pointer.ASN1_TYPE */
            	855, 0,
            0, 0, 1, /* 855: ASN1_TYPE */
            	860, 0,
            0, 16, 1, /* 860: struct.asn1_type_st */
            	71, 8,
            1, 8, 1, /* 865: pointer.struct.asn1_type_st */
            	658, 0,
        },
        .arg_entity_index = { 770, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    void (*orig_EVP_PKEY_free)(EVP_PKEY *);
    orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
    (*orig_EVP_PKEY_free)(new_arg_a);

    syscall(889);

}

