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
            8884097, 8, 0, /* 0: pointer.func */
            8884097, 8, 0, /* 3: pointer.func */
            1, 8, 1, /* 6: pointer.struct.asn1_string_st */
            	11, 0,
            0, 24, 1, /* 11: struct.asn1_string_st */
            	16, 8,
            1, 8, 1, /* 16: pointer.unsigned char */
            	21, 0,
            0, 1, 0, /* 21: unsigned char */
            0, 16, 1, /* 24: struct.crypto_ex_data_st */
            	29, 0,
            1, 8, 1, /* 29: pointer.struct.stack_st_void */
            	34, 0,
            0, 32, 1, /* 34: struct.stack_st_void */
            	39, 0,
            0, 32, 2, /* 39: struct.stack_st */
            	46, 8,
            	56, 24,
            1, 8, 1, /* 46: pointer.pointer.char */
            	51, 0,
            1, 8, 1, /* 51: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 56: pointer.func */
            0, 24, 1, /* 59: struct.asn1_string_st */
            	16, 8,
            0, 16, 1, /* 64: struct.asn1_type_st */
            	69, 8,
            0, 8, 20, /* 69: union.unknown */
            	51, 0,
            	112, 0,
            	117, 0,
            	141, 0,
            	146, 0,
            	151, 0,
            	156, 0,
            	161, 0,
            	166, 0,
            	171, 0,
            	176, 0,
            	181, 0,
            	186, 0,
            	191, 0,
            	196, 0,
            	201, 0,
            	6, 0,
            	112, 0,
            	112, 0,
            	206, 0,
            1, 8, 1, /* 112: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 117: pointer.struct.asn1_object_st */
            	122, 0,
            0, 40, 3, /* 122: struct.asn1_object_st */
            	131, 0,
            	131, 8,
            	136, 24,
            1, 8, 1, /* 131: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 136: pointer.unsigned char */
            	21, 0,
            1, 8, 1, /* 141: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 146: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 151: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 156: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 161: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 166: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 171: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 176: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 181: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 186: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 191: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 196: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 201: pointer.struct.asn1_string_st */
            	11, 0,
            1, 8, 1, /* 206: pointer.struct.ASN1_VALUE_st */
            	211, 0,
            0, 0, 0, /* 211: struct.ASN1_VALUE_st */
            0, 24, 1, /* 214: struct.bignum_st */
            	219, 0,
            1, 8, 1, /* 219: pointer.unsigned int */
            	224, 0,
            0, 4, 0, /* 224: unsigned int */
            1, 8, 1, /* 227: pointer.struct.bignum_st */
            	214, 0,
            8884097, 8, 0, /* 232: pointer.func */
            8884097, 8, 0, /* 235: pointer.func */
            8884097, 8, 0, /* 238: pointer.func */
            1, 8, 1, /* 241: pointer.struct.asn1_string_st */
            	59, 0,
            0, 96, 3, /* 246: struct.bn_mont_ctx_st */
            	214, 8,
            	214, 32,
            	214, 56,
            1, 8, 1, /* 255: pointer.struct.dh_st */
            	260, 0,
            0, 144, 12, /* 260: struct.dh_st */
            	227, 8,
            	227, 16,
            	227, 32,
            	227, 40,
            	287, 56,
            	227, 64,
            	227, 72,
            	16, 80,
            	227, 96,
            	24, 112,
            	292, 128,
            	325, 136,
            1, 8, 1, /* 287: pointer.struct.bn_mont_ctx_st */
            	246, 0,
            1, 8, 1, /* 292: pointer.struct.dh_method */
            	297, 0,
            0, 72, 8, /* 297: struct.dh_method */
            	131, 0,
            	316, 8,
            	235, 16,
            	319, 24,
            	316, 32,
            	316, 40,
            	51, 56,
            	322, 64,
            8884097, 8, 0, /* 316: pointer.func */
            8884097, 8, 0, /* 319: pointer.func */
            8884097, 8, 0, /* 322: pointer.func */
            1, 8, 1, /* 325: pointer.struct.engine_st */
            	330, 0,
            0, 0, 0, /* 330: struct.engine_st */
            8884097, 8, 0, /* 333: pointer.func */
            8884097, 8, 0, /* 336: pointer.func */
            8884097, 8, 0, /* 339: pointer.func */
            8884097, 8, 0, /* 342: pointer.func */
            0, 56, 4, /* 345: struct.evp_pkey_st */
            	356, 16,
            	325, 24,
            	445, 32,
            	640, 48,
            1, 8, 1, /* 356: pointer.struct.evp_pkey_asn1_method_st */
            	361, 0,
            0, 208, 24, /* 361: struct.evp_pkey_asn1_method_st */
            	51, 16,
            	51, 24,
            	412, 32,
            	415, 40,
            	418, 48,
            	333, 56,
            	421, 64,
            	339, 72,
            	333, 80,
            	424, 88,
            	424, 96,
            	427, 104,
            	430, 112,
            	424, 120,
            	336, 128,
            	418, 136,
            	333, 144,
            	433, 152,
            	342, 160,
            	436, 168,
            	427, 176,
            	430, 184,
            	439, 192,
            	442, 200,
            8884097, 8, 0, /* 412: pointer.func */
            8884097, 8, 0, /* 415: pointer.func */
            8884097, 8, 0, /* 418: pointer.func */
            8884097, 8, 0, /* 421: pointer.func */
            8884097, 8, 0, /* 424: pointer.func */
            8884097, 8, 0, /* 427: pointer.func */
            8884097, 8, 0, /* 430: pointer.func */
            8884097, 8, 0, /* 433: pointer.func */
            8884097, 8, 0, /* 436: pointer.func */
            8884097, 8, 0, /* 439: pointer.func */
            8884097, 8, 0, /* 442: pointer.func */
            0, 8, 5, /* 445: union.unknown */
            	51, 0,
            	458, 0,
            	554, 0,
            	255, 0,
            	632, 0,
            1, 8, 1, /* 458: pointer.struct.rsa_st */
            	463, 0,
            0, 168, 17, /* 463: struct.rsa_st */
            	500, 16,
            	325, 24,
            	227, 32,
            	227, 40,
            	227, 48,
            	227, 56,
            	227, 64,
            	227, 72,
            	227, 80,
            	227, 88,
            	24, 96,
            	287, 120,
            	287, 128,
            	287, 136,
            	51, 144,
            	546, 152,
            	546, 160,
            1, 8, 1, /* 500: pointer.struct.rsa_meth_st */
            	505, 0,
            0, 112, 13, /* 505: struct.rsa_meth_st */
            	131, 0,
            	534, 8,
            	534, 16,
            	534, 24,
            	534, 32,
            	537, 40,
            	540, 48,
            	543, 56,
            	543, 64,
            	51, 80,
            	0, 88,
            	238, 96,
            	232, 104,
            8884097, 8, 0, /* 534: pointer.func */
            8884097, 8, 0, /* 537: pointer.func */
            8884097, 8, 0, /* 540: pointer.func */
            8884097, 8, 0, /* 543: pointer.func */
            1, 8, 1, /* 546: pointer.struct.bn_blinding_st */
            	551, 0,
            0, 0, 0, /* 551: struct.bn_blinding_st */
            1, 8, 1, /* 554: pointer.struct.dsa_st */
            	559, 0,
            0, 136, 11, /* 559: struct.dsa_st */
            	227, 24,
            	227, 32,
            	227, 40,
            	227, 48,
            	227, 56,
            	227, 64,
            	227, 72,
            	287, 88,
            	24, 104,
            	584, 120,
            	325, 128,
            1, 8, 1, /* 584: pointer.struct.dsa_method */
            	589, 0,
            0, 96, 11, /* 589: struct.dsa_method */
            	131, 0,
            	614, 8,
            	617, 16,
            	620, 24,
            	3, 32,
            	623, 40,
            	626, 48,
            	626, 56,
            	51, 72,
            	629, 80,
            	626, 88,
            8884097, 8, 0, /* 614: pointer.func */
            8884097, 8, 0, /* 617: pointer.func */
            8884097, 8, 0, /* 620: pointer.func */
            8884097, 8, 0, /* 623: pointer.func */
            8884097, 8, 0, /* 626: pointer.func */
            8884097, 8, 0, /* 629: pointer.func */
            1, 8, 1, /* 632: pointer.struct.ec_key_st */
            	637, 0,
            0, 0, 0, /* 637: struct.ec_key_st */
            1, 8, 1, /* 640: pointer.struct.stack_st_X509_ATTRIBUTE */
            	645, 0,
            0, 32, 2, /* 645: struct.stack_st_fake_X509_ATTRIBUTE */
            	652, 8,
            	56, 24,
            8884099, 8, 2, /* 652: pointer_to_array_of_pointers_to_stack */
            	659, 0,
            	728, 20,
            0, 8, 1, /* 659: pointer.X509_ATTRIBUTE */
            	664, 0,
            0, 0, 1, /* 664: X509_ATTRIBUTE */
            	669, 0,
            0, 24, 2, /* 669: struct.x509_attributes_st */
            	676, 0,
            	690, 16,
            1, 8, 1, /* 676: pointer.struct.asn1_object_st */
            	681, 0,
            0, 40, 3, /* 681: struct.asn1_object_st */
            	131, 0,
            	131, 8,
            	136, 24,
            0, 8, 3, /* 690: union.unknown */
            	51, 0,
            	699, 0,
            	731, 0,
            1, 8, 1, /* 699: pointer.struct.stack_st_ASN1_TYPE */
            	704, 0,
            0, 32, 2, /* 704: struct.stack_st_fake_ASN1_TYPE */
            	711, 8,
            	56, 24,
            8884099, 8, 2, /* 711: pointer_to_array_of_pointers_to_stack */
            	718, 0,
            	728, 20,
            0, 8, 1, /* 718: pointer.ASN1_TYPE */
            	723, 0,
            0, 0, 1, /* 723: ASN1_TYPE */
            	64, 0,
            0, 4, 0, /* 728: int */
            1, 8, 1, /* 731: pointer.struct.asn1_type_st */
            	736, 0,
            0, 16, 1, /* 736: struct.asn1_type_st */
            	741, 8,
            0, 8, 20, /* 741: union.unknown */
            	51, 0,
            	784, 0,
            	676, 0,
            	789, 0,
            	794, 0,
            	799, 0,
            	804, 0,
            	241, 0,
            	809, 0,
            	814, 0,
            	819, 0,
            	824, 0,
            	829, 0,
            	834, 0,
            	839, 0,
            	844, 0,
            	849, 0,
            	784, 0,
            	784, 0,
            	854, 0,
            1, 8, 1, /* 784: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 789: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 794: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 799: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 804: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 809: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 814: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 819: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 824: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 829: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 834: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 839: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 844: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 849: pointer.struct.asn1_string_st */
            	59, 0,
            1, 8, 1, /* 854: pointer.struct.ASN1_VALUE_st */
            	859, 0,
            0, 0, 0, /* 859: struct.ASN1_VALUE_st */
            1, 8, 1, /* 862: pointer.struct.evp_pkey_st */
            	345, 0,
            0, 1, 0, /* 867: char */
        },
        .arg_entity_index = { 862, },
        .ret_entity_index = 728,
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

