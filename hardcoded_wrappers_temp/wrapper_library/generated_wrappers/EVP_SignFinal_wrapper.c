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

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d);

int EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_SignFinal called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    else {
        int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
        orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
        return orig_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    }
}

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: struct.bn_blinding_st */
            1, 8, 1, /* 3: pointer.struct.asn1_string_st */
            	8, 0,
            0, 24, 1, /* 8: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 13: pointer.unsigned char */
            	18, 0,
            0, 1, 0, /* 18: unsigned char */
            0, 96, 3, /* 21: struct.bn_mont_ctx_st */
            	30, 8,
            	30, 32,
            	30, 56,
            0, 24, 1, /* 30: struct.bignum_st */
            	35, 0,
            1, 8, 1, /* 35: pointer.unsigned int */
            	40, 0,
            0, 4, 0, /* 40: unsigned int */
            1, 8, 1, /* 43: pointer.struct.bn_mont_ctx_st */
            	21, 0,
            8884097, 8, 0, /* 48: pointer.func */
            1, 8, 1, /* 51: pointer.struct.dsa_st */
            	56, 0,
            0, 136, 11, /* 56: struct.dsa_st */
            	81, 24,
            	81, 32,
            	81, 40,
            	81, 48,
            	81, 56,
            	81, 64,
            	81, 72,
            	43, 88,
            	86, 104,
            	121, 120,
            	174, 128,
            1, 8, 1, /* 81: pointer.struct.bignum_st */
            	30, 0,
            0, 16, 1, /* 86: struct.crypto_ex_data_st */
            	91, 0,
            1, 8, 1, /* 91: pointer.struct.stack_st_void */
            	96, 0,
            0, 32, 1, /* 96: struct.stack_st_void */
            	101, 0,
            0, 32, 2, /* 101: struct.stack_st */
            	108, 8,
            	118, 24,
            1, 8, 1, /* 108: pointer.pointer.char */
            	113, 0,
            1, 8, 1, /* 113: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 118: pointer.func */
            1, 8, 1, /* 121: pointer.struct.dsa_method */
            	126, 0,
            0, 96, 11, /* 126: struct.dsa_method */
            	151, 0,
            	156, 8,
            	159, 16,
            	162, 24,
            	165, 32,
            	48, 40,
            	168, 48,
            	168, 56,
            	113, 72,
            	171, 80,
            	168, 88,
            1, 8, 1, /* 151: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 156: pointer.func */
            8884097, 8, 0, /* 159: pointer.func */
            8884097, 8, 0, /* 162: pointer.func */
            8884097, 8, 0, /* 165: pointer.func */
            8884097, 8, 0, /* 168: pointer.func */
            8884097, 8, 0, /* 171: pointer.func */
            1, 8, 1, /* 174: pointer.struct.engine_st */
            	179, 0,
            0, 0, 0, /* 179: struct.engine_st */
            1, 8, 1, /* 182: pointer.struct.asn1_type_st */
            	187, 0,
            0, 16, 1, /* 187: struct.asn1_type_st */
            	192, 8,
            0, 8, 20, /* 192: union.unknown */
            	113, 0,
            	235, 0,
            	240, 0,
            	259, 0,
            	264, 0,
            	3, 0,
            	269, 0,
            	274, 0,
            	279, 0,
            	284, 0,
            	289, 0,
            	294, 0,
            	299, 0,
            	304, 0,
            	309, 0,
            	314, 0,
            	319, 0,
            	235, 0,
            	235, 0,
            	324, 0,
            1, 8, 1, /* 235: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 240: pointer.struct.asn1_object_st */
            	245, 0,
            0, 40, 3, /* 245: struct.asn1_object_st */
            	151, 0,
            	151, 8,
            	254, 24,
            1, 8, 1, /* 254: pointer.unsigned char */
            	18, 0,
            1, 8, 1, /* 259: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 264: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 269: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 274: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 279: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 284: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 289: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 294: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 299: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 304: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 309: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 314: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 319: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 324: pointer.struct.ASN1_VALUE_st */
            	329, 0,
            0, 0, 0, /* 329: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 332: pointer.func */
            8884097, 8, 0, /* 335: pointer.func */
            8884097, 8, 0, /* 338: pointer.func */
            8884097, 8, 0, /* 341: pointer.func */
            8884097, 8, 0, /* 344: pointer.func */
            1, 8, 1, /* 347: pointer.struct.rsa_meth_st */
            	352, 0,
            0, 112, 13, /* 352: struct.rsa_meth_st */
            	151, 0,
            	344, 8,
            	344, 16,
            	344, 24,
            	344, 32,
            	381, 40,
            	384, 48,
            	338, 56,
            	338, 64,
            	113, 80,
            	335, 88,
            	332, 96,
            	387, 104,
            8884097, 8, 0, /* 381: pointer.func */
            8884097, 8, 0, /* 384: pointer.func */
            8884097, 8, 0, /* 387: pointer.func */
            8884097, 8, 0, /* 390: pointer.func */
            1, 8, 1, /* 393: pointer.struct.asn1_string_st */
            	398, 0,
            0, 24, 1, /* 398: struct.asn1_string_st */
            	13, 8,
            8884097, 8, 0, /* 403: pointer.func */
            1, 8, 1, /* 406: pointer.struct.env_md_st */
            	411, 0,
            0, 120, 8, /* 411: struct.env_md_st */
            	430, 24,
            	433, 32,
            	436, 40,
            	390, 48,
            	430, 56,
            	439, 64,
            	403, 72,
            	442, 112,
            8884097, 8, 0, /* 430: pointer.func */
            8884097, 8, 0, /* 433: pointer.func */
            8884097, 8, 0, /* 436: pointer.func */
            8884097, 8, 0, /* 439: pointer.func */
            8884097, 8, 0, /* 442: pointer.func */
            1, 8, 1, /* 445: pointer.struct.asn1_string_st */
            	398, 0,
            8884099, 8, 2, /* 450: pointer_to_array_of_pointers_to_stack */
            	457, 0,
            	602, 20,
            0, 8, 1, /* 457: pointer.ASN1_TYPE */
            	462, 0,
            0, 0, 1, /* 462: ASN1_TYPE */
            	467, 0,
            0, 16, 1, /* 467: struct.asn1_type_st */
            	472, 8,
            0, 8, 20, /* 472: union.unknown */
            	113, 0,
            	515, 0,
            	520, 0,
            	534, 0,
            	539, 0,
            	544, 0,
            	549, 0,
            	554, 0,
            	559, 0,
            	393, 0,
            	564, 0,
            	569, 0,
            	574, 0,
            	445, 0,
            	579, 0,
            	584, 0,
            	589, 0,
            	515, 0,
            	515, 0,
            	594, 0,
            1, 8, 1, /* 515: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 520: pointer.struct.asn1_object_st */
            	525, 0,
            0, 40, 3, /* 525: struct.asn1_object_st */
            	151, 0,
            	151, 8,
            	254, 24,
            1, 8, 1, /* 534: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 539: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 544: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 549: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 554: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 559: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 564: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 569: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 574: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 579: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 584: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 589: pointer.struct.asn1_string_st */
            	398, 0,
            1, 8, 1, /* 594: pointer.struct.ASN1_VALUE_st */
            	599, 0,
            0, 0, 0, /* 599: struct.ASN1_VALUE_st */
            0, 4, 0, /* 602: int */
            1, 8, 1, /* 605: pointer.struct.evp_pkey_st */
            	610, 0,
            0, 56, 4, /* 610: struct.evp_pkey_st */
            	621, 16,
            	174, 24,
            	629, 32,
            	762, 48,
            1, 8, 1, /* 621: pointer.struct.evp_pkey_asn1_method_st */
            	626, 0,
            0, 0, 0, /* 626: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 629: union.unknown */
            	113, 0,
            	642, 0,
            	51, 0,
            	689, 0,
            	754, 0,
            1, 8, 1, /* 642: pointer.struct.rsa_st */
            	647, 0,
            0, 168, 17, /* 647: struct.rsa_st */
            	347, 16,
            	174, 24,
            	81, 32,
            	81, 40,
            	81, 48,
            	81, 56,
            	81, 64,
            	81, 72,
            	81, 80,
            	81, 88,
            	86, 96,
            	43, 120,
            	43, 128,
            	43, 136,
            	113, 144,
            	684, 152,
            	684, 160,
            1, 8, 1, /* 684: pointer.struct.bn_blinding_st */
            	0, 0,
            1, 8, 1, /* 689: pointer.struct.dh_st */
            	694, 0,
            0, 144, 12, /* 694: struct.dh_st */
            	81, 8,
            	81, 16,
            	81, 32,
            	81, 40,
            	43, 56,
            	81, 64,
            	81, 72,
            	13, 80,
            	81, 96,
            	86, 112,
            	721, 128,
            	174, 136,
            1, 8, 1, /* 721: pointer.struct.dh_method */
            	726, 0,
            0, 72, 8, /* 726: struct.dh_method */
            	151, 0,
            	745, 8,
            	341, 16,
            	748, 24,
            	745, 32,
            	745, 40,
            	113, 56,
            	751, 64,
            8884097, 8, 0, /* 745: pointer.func */
            8884097, 8, 0, /* 748: pointer.func */
            8884097, 8, 0, /* 751: pointer.func */
            1, 8, 1, /* 754: pointer.struct.ec_key_st */
            	759, 0,
            0, 0, 0, /* 759: struct.ec_key_st */
            1, 8, 1, /* 762: pointer.struct.stack_st_X509_ATTRIBUTE */
            	767, 0,
            0, 32, 2, /* 767: struct.stack_st_fake_X509_ATTRIBUTE */
            	774, 8,
            	118, 24,
            8884099, 8, 2, /* 774: pointer_to_array_of_pointers_to_stack */
            	781, 0,
            	602, 20,
            0, 8, 1, /* 781: pointer.X509_ATTRIBUTE */
            	786, 0,
            0, 0, 1, /* 786: X509_ATTRIBUTE */
            	791, 0,
            0, 24, 2, /* 791: struct.x509_attributes_st */
            	240, 0,
            	798, 16,
            0, 8, 3, /* 798: union.unknown */
            	113, 0,
            	807, 0,
            	182, 0,
            1, 8, 1, /* 807: pointer.struct.stack_st_ASN1_TYPE */
            	812, 0,
            0, 32, 2, /* 812: struct.stack_st_fake_ASN1_TYPE */
            	450, 8,
            	118, 24,
            0, 48, 5, /* 819: struct.env_md_ctx_st */
            	406, 0,
            	174, 8,
            	832, 24,
            	835, 32,
            	433, 40,
            0, 8, 0, /* 832: pointer.void */
            1, 8, 1, /* 835: pointer.struct.evp_pkey_ctx_st */
            	840, 0,
            0, 0, 0, /* 840: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 843: pointer.struct.env_md_ctx_st */
            	819, 0,
            0, 1, 0, /* 848: char */
        },
        .arg_entity_index = { 843, 13, 35, 605, },
        .ret_entity_index = 602,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    unsigned char * new_arg_b = *((unsigned char * *)new_args->args[1]);

    unsigned int * new_arg_c = *((unsigned int * *)new_args->args[2]);

    EVP_PKEY * new_arg_d = *((EVP_PKEY * *)new_args->args[3]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
    orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
    *new_ret_ptr = (*orig_EVP_SignFinal)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

