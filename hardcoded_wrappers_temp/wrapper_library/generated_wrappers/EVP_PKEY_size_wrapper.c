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

int bb_EVP_PKEY_size(EVP_PKEY * arg_a);

int EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_size called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_PKEY_size(arg_a);
    else {
        int (*orig_EVP_PKEY_size)(EVP_PKEY *);
        orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
        return orig_EVP_PKEY_size(arg_a);
    }
}

int bb_EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.ASN1_VALUE_st */
            	5, 0,
            0, 0, 0, /* 5: struct.ASN1_VALUE_st */
            64097, 8, 0, /* 8: pointer.func */
            1, 8, 1, /* 11: pointer.struct.asn1_string_st */
            	16, 0,
            0, 24, 1, /* 16: struct.asn1_string_st */
            	21, 8,
            1, 8, 1, /* 21: pointer.unsigned char */
            	26, 0,
            0, 1, 0, /* 26: unsigned char */
            1, 8, 1, /* 29: pointer.struct.asn1_string_st */
            	16, 0,
            0, 24, 1, /* 34: struct.asn1_string_st */
            	21, 8,
            0, 24, 1, /* 39: struct.bignum_st */
            	44, 0,
            1, 8, 1, /* 44: pointer.unsigned int */
            	49, 0,
            0, 4, 0, /* 49: unsigned int */
            1, 8, 1, /* 52: pointer.struct.bignum_st */
            	39, 0,
            64097, 8, 0, /* 57: pointer.func */
            1, 8, 1, /* 60: pointer.struct.asn1_string_st */
            	16, 0,
            64097, 8, 0, /* 65: pointer.func */
            0, 8, 20, /* 68: union.unknown */
            	111, 0,
            	116, 0,
            	121, 0,
            	145, 0,
            	150, 0,
            	155, 0,
            	160, 0,
            	165, 0,
            	170, 0,
            	175, 0,
            	11, 0,
            	60, 0,
            	180, 0,
            	29, 0,
            	185, 0,
            	190, 0,
            	195, 0,
            	116, 0,
            	116, 0,
            	200, 0,
            1, 8, 1, /* 111: pointer.char */
            	64096, 0,
            1, 8, 1, /* 116: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 121: pointer.struct.asn1_object_st */
            	126, 0,
            0, 40, 3, /* 126: struct.asn1_object_st */
            	135, 0,
            	135, 8,
            	140, 24,
            1, 8, 1, /* 135: pointer.char */
            	64096, 0,
            1, 8, 1, /* 140: pointer.unsigned char */
            	26, 0,
            1, 8, 1, /* 145: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 150: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 155: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 160: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 165: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 170: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 175: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 180: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 185: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 190: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 195: pointer.struct.asn1_string_st */
            	16, 0,
            1, 8, 1, /* 200: pointer.struct.ASN1_VALUE_st */
            	205, 0,
            0, 0, 0, /* 205: struct.ASN1_VALUE_st */
            1, 8, 1, /* 208: pointer.struct.asn1_string_st */
            	34, 0,
            0, 96, 3, /* 213: struct.bn_mont_ctx_st */
            	39, 8,
            	39, 32,
            	39, 56,
            1, 8, 1, /* 222: pointer.struct.dh_st */
            	227, 0,
            0, 144, 12, /* 227: struct.dh_st */
            	52, 8,
            	52, 16,
            	52, 32,
            	52, 40,
            	254, 56,
            	52, 64,
            	52, 72,
            	21, 80,
            	52, 96,
            	259, 112,
            	289, 128,
            	325, 136,
            1, 8, 1, /* 254: pointer.struct.bn_mont_ctx_st */
            	213, 0,
            0, 16, 1, /* 259: struct.crypto_ex_data_st */
            	264, 0,
            1, 8, 1, /* 264: pointer.struct.stack_st_void */
            	269, 0,
            0, 32, 1, /* 269: struct.stack_st_void */
            	274, 0,
            0, 32, 2, /* 274: struct.stack_st */
            	281, 8,
            	286, 24,
            1, 8, 1, /* 281: pointer.pointer.char */
            	111, 0,
            64097, 8, 0, /* 286: pointer.func */
            1, 8, 1, /* 289: pointer.struct.dh_method */
            	294, 0,
            0, 72, 8, /* 294: struct.dh_method */
            	135, 0,
            	313, 8,
            	316, 16,
            	319, 24,
            	313, 32,
            	313, 40,
            	111, 56,
            	322, 64,
            64097, 8, 0, /* 313: pointer.func */
            64097, 8, 0, /* 316: pointer.func */
            64097, 8, 0, /* 319: pointer.func */
            64097, 8, 0, /* 322: pointer.func */
            1, 8, 1, /* 325: pointer.struct.engine_st */
            	330, 0,
            0, 0, 0, /* 330: struct.engine_st */
            64097, 8, 0, /* 333: pointer.func */
            64097, 8, 0, /* 336: pointer.func */
            64097, 8, 0, /* 339: pointer.func */
            64097, 8, 0, /* 342: pointer.func */
            1, 8, 1, /* 345: pointer.struct.evp_pkey_asn1_method_st */
            	350, 0,
            0, 208, 24, /* 350: struct.evp_pkey_asn1_method_st */
            	111, 16,
            	111, 24,
            	401, 32,
            	404, 40,
            	407, 48,
            	333, 56,
            	410, 64,
            	339, 72,
            	333, 80,
            	413, 88,
            	413, 96,
            	416, 104,
            	419, 112,
            	413, 120,
            	336, 128,
            	407, 136,
            	333, 144,
            	422, 152,
            	342, 160,
            	425, 168,
            	416, 176,
            	419, 184,
            	428, 192,
            	431, 200,
            64097, 8, 0, /* 401: pointer.func */
            64097, 8, 0, /* 404: pointer.func */
            64097, 8, 0, /* 407: pointer.func */
            64097, 8, 0, /* 410: pointer.func */
            64097, 8, 0, /* 413: pointer.func */
            64097, 8, 0, /* 416: pointer.func */
            64097, 8, 0, /* 419: pointer.func */
            64097, 8, 0, /* 422: pointer.func */
            64097, 8, 0, /* 425: pointer.func */
            64097, 8, 0, /* 428: pointer.func */
            64097, 8, 0, /* 431: pointer.func */
            1, 8, 1, /* 434: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 439: pointer.struct.dsa_st */
            	444, 0,
            0, 136, 11, /* 444: struct.dsa_st */
            	52, 24,
            	52, 32,
            	52, 40,
            	52, 48,
            	52, 56,
            	52, 64,
            	52, 72,
            	254, 88,
            	259, 104,
            	469, 120,
            	325, 128,
            1, 8, 1, /* 469: pointer.struct.dsa_method */
            	474, 0,
            0, 96, 11, /* 474: struct.dsa_method */
            	135, 0,
            	499, 8,
            	502, 16,
            	505, 24,
            	508, 32,
            	511, 40,
            	514, 48,
            	514, 56,
            	111, 72,
            	517, 80,
            	514, 88,
            64097, 8, 0, /* 499: pointer.func */
            64097, 8, 0, /* 502: pointer.func */
            64097, 8, 0, /* 505: pointer.func */
            64097, 8, 0, /* 508: pointer.func */
            64097, 8, 0, /* 511: pointer.func */
            64097, 8, 0, /* 514: pointer.func */
            64097, 8, 0, /* 517: pointer.func */
            64097, 8, 0, /* 520: pointer.func */
            1, 8, 1, /* 523: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 528: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 533: pointer.struct.asn1_string_st */
            	34, 0,
            0, 1, 0, /* 538: char */
            0, 4, 0, /* 541: int */
            64097, 8, 0, /* 544: pointer.func */
            1, 8, 1, /* 547: pointer.struct.bn_blinding_st */
            	552, 0,
            0, 0, 0, /* 552: struct.bn_blinding_st */
            0, 8, 5, /* 555: union.unknown */
            	111, 0,
            	568, 0,
            	439, 0,
            	222, 0,
            	650, 0,
            1, 8, 1, /* 568: pointer.struct.rsa_st */
            	573, 0,
            0, 168, 17, /* 573: struct.rsa_st */
            	610, 16,
            	325, 24,
            	52, 32,
            	52, 40,
            	52, 48,
            	52, 56,
            	52, 64,
            	52, 72,
            	52, 80,
            	52, 88,
            	259, 96,
            	254, 120,
            	254, 128,
            	254, 136,
            	111, 144,
            	547, 152,
            	547, 160,
            1, 8, 1, /* 610: pointer.struct.rsa_meth_st */
            	615, 0,
            0, 112, 13, /* 615: struct.rsa_meth_st */
            	135, 0,
            	644, 8,
            	644, 16,
            	644, 24,
            	644, 32,
            	544, 40,
            	520, 48,
            	647, 56,
            	647, 64,
            	111, 80,
            	8, 88,
            	65, 96,
            	57, 104,
            64097, 8, 0, /* 644: pointer.func */
            64097, 8, 0, /* 647: pointer.func */
            1, 8, 1, /* 650: pointer.struct.ec_key_st */
            	655, 0,
            0, 0, 0, /* 655: struct.ec_key_st */
            0, 16, 1, /* 658: struct.asn1_type_st */
            	663, 8,
            0, 8, 20, /* 663: union.unknown */
            	111, 0,
            	706, 0,
            	711, 0,
            	523, 0,
            	725, 0,
            	730, 0,
            	528, 0,
            	208, 0,
            	735, 0,
            	740, 0,
            	745, 0,
            	750, 0,
            	533, 0,
            	755, 0,
            	760, 0,
            	765, 0,
            	434, 0,
            	706, 0,
            	706, 0,
            	0, 0,
            1, 8, 1, /* 706: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 711: pointer.struct.asn1_object_st */
            	716, 0,
            0, 40, 3, /* 716: struct.asn1_object_st */
            	135, 0,
            	135, 8,
            	140, 24,
            1, 8, 1, /* 725: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 730: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 735: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 740: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 745: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 750: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 755: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 760: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 765: pointer.struct.asn1_string_st */
            	34, 0,
            1, 8, 1, /* 770: pointer.struct.evp_pkey_st */
            	775, 0,
            0, 56, 4, /* 775: struct.evp_pkey_st */
            	345, 16,
            	325, 24,
            	555, 32,
            	786, 48,
            1, 8, 1, /* 786: pointer.struct.stack_st_X509_ATTRIBUTE */
            	791, 0,
            0, 32, 2, /* 791: struct.stack_st_fake_X509_ATTRIBUTE */
            	798, 8,
            	286, 24,
            64099, 8, 2, /* 798: pointer_to_array_of_pointers_to_stack */
            	805, 0,
            	541, 20,
            0, 8, 1, /* 805: pointer.X509_ATTRIBUTE */
            	810, 0,
            0, 0, 1, /* 810: X509_ATTRIBUTE */
            	815, 0,
            0, 24, 2, /* 815: struct.x509_attributes_st */
            	711, 0,
            	822, 16,
            0, 8, 3, /* 822: union.unknown */
            	111, 0,
            	831, 0,
            	865, 0,
            1, 8, 1, /* 831: pointer.struct.stack_st_ASN1_TYPE */
            	836, 0,
            0, 32, 2, /* 836: struct.stack_st_fake_ASN1_TYPE */
            	843, 8,
            	286, 24,
            64099, 8, 2, /* 843: pointer_to_array_of_pointers_to_stack */
            	850, 0,
            	541, 20,
            0, 8, 1, /* 850: pointer.ASN1_TYPE */
            	855, 0,
            0, 0, 1, /* 855: ASN1_TYPE */
            	860, 0,
            0, 16, 1, /* 860: struct.asn1_type_st */
            	68, 8,
            1, 8, 1, /* 865: pointer.struct.asn1_type_st */
            	658, 0,
        },
        .arg_entity_index = { 770, },
        .ret_entity_index = 541,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_PKEY_size)(EVP_PKEY *);
    orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
    *new_ret_ptr = (*orig_EVP_PKEY_size)(new_arg_a);

    syscall(889);

    return ret;
}

