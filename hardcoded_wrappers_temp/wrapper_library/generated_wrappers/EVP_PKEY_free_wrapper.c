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
            8884097, 8, 0, /* 0: pointer.func */
            8884097, 8, 0, /* 3: pointer.func */
            8884097, 8, 0, /* 6: pointer.func */
            1, 8, 1, /* 9: pointer.struct.asn1_string_st */
            	14, 0,
            0, 24, 1, /* 14: struct.asn1_string_st */
            	19, 8,
            1, 8, 1, /* 19: pointer.unsigned char */
            	24, 0,
            0, 1, 0, /* 24: unsigned char */
            0, 16, 1, /* 27: struct.crypto_ex_data_st */
            	32, 0,
            1, 8, 1, /* 32: pointer.struct.stack_st_void */
            	37, 0,
            0, 32, 1, /* 37: struct.stack_st_void */
            	42, 0,
            0, 32, 2, /* 42: struct.stack_st */
            	49, 8,
            	59, 24,
            1, 8, 1, /* 49: pointer.pointer.char */
            	54, 0,
            1, 8, 1, /* 54: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 59: pointer.func */
            0, 24, 1, /* 62: struct.asn1_string_st */
            	19, 8,
            0, 16, 1, /* 67: struct.asn1_type_st */
            	72, 8,
            0, 8, 20, /* 72: union.unknown */
            	54, 0,
            	115, 0,
            	120, 0,
            	144, 0,
            	149, 0,
            	154, 0,
            	159, 0,
            	164, 0,
            	169, 0,
            	174, 0,
            	179, 0,
            	184, 0,
            	189, 0,
            	194, 0,
            	199, 0,
            	204, 0,
            	9, 0,
            	115, 0,
            	115, 0,
            	209, 0,
            1, 8, 1, /* 115: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 120: pointer.struct.asn1_object_st */
            	125, 0,
            0, 40, 3, /* 125: struct.asn1_object_st */
            	134, 0,
            	134, 8,
            	139, 24,
            1, 8, 1, /* 134: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 139: pointer.unsigned char */
            	24, 0,
            1, 8, 1, /* 144: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 149: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 154: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 159: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 164: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 169: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 174: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 179: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 184: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 189: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 194: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 199: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 204: pointer.struct.asn1_string_st */
            	14, 0,
            1, 8, 1, /* 209: pointer.struct.ASN1_VALUE_st */
            	214, 0,
            0, 0, 0, /* 214: struct.ASN1_VALUE_st */
            0, 24, 1, /* 217: struct.bignum_st */
            	222, 0,
            1, 8, 1, /* 222: pointer.unsigned int */
            	227, 0,
            0, 4, 0, /* 227: unsigned int */
            1, 8, 1, /* 230: pointer.struct.bignum_st */
            	217, 0,
            8884097, 8, 0, /* 235: pointer.func */
            8884097, 8, 0, /* 238: pointer.func */
            8884097, 8, 0, /* 241: pointer.func */
            1, 8, 1, /* 244: pointer.struct.asn1_string_st */
            	62, 0,
            0, 96, 3, /* 249: struct.bn_mont_ctx_st */
            	217, 8,
            	217, 32,
            	217, 56,
            1, 8, 1, /* 258: pointer.struct.dh_st */
            	263, 0,
            0, 144, 12, /* 263: struct.dh_st */
            	230, 8,
            	230, 16,
            	230, 32,
            	230, 40,
            	290, 56,
            	230, 64,
            	230, 72,
            	19, 80,
            	230, 96,
            	27, 112,
            	295, 128,
            	328, 136,
            1, 8, 1, /* 290: pointer.struct.bn_mont_ctx_st */
            	249, 0,
            1, 8, 1, /* 295: pointer.struct.dh_method */
            	300, 0,
            0, 72, 8, /* 300: struct.dh_method */
            	134, 0,
            	319, 8,
            	238, 16,
            	322, 24,
            	319, 32,
            	319, 40,
            	54, 56,
            	325, 64,
            8884097, 8, 0, /* 319: pointer.func */
            8884097, 8, 0, /* 322: pointer.func */
            8884097, 8, 0, /* 325: pointer.func */
            1, 8, 1, /* 328: pointer.struct.engine_st */
            	333, 0,
            0, 0, 0, /* 333: struct.engine_st */
            8884097, 8, 0, /* 336: pointer.func */
            8884097, 8, 0, /* 339: pointer.func */
            8884097, 8, 0, /* 342: pointer.func */
            8884097, 8, 0, /* 345: pointer.func */
            8884097, 8, 0, /* 348: pointer.func */
            0, 56, 4, /* 351: struct.evp_pkey_st */
            	362, 16,
            	328, 24,
            	451, 32,
            	640, 48,
            1, 8, 1, /* 362: pointer.struct.evp_pkey_asn1_method_st */
            	367, 0,
            0, 208, 24, /* 367: struct.evp_pkey_asn1_method_st */
            	54, 16,
            	54, 24,
            	418, 32,
            	421, 40,
            	424, 48,
            	339, 56,
            	427, 64,
            	345, 72,
            	339, 80,
            	430, 88,
            	430, 96,
            	433, 104,
            	436, 112,
            	430, 120,
            	342, 128,
            	424, 136,
            	339, 144,
            	439, 152,
            	348, 160,
            	442, 168,
            	433, 176,
            	436, 184,
            	445, 192,
            	448, 200,
            8884097, 8, 0, /* 418: pointer.func */
            8884097, 8, 0, /* 421: pointer.func */
            8884097, 8, 0, /* 424: pointer.func */
            8884097, 8, 0, /* 427: pointer.func */
            8884097, 8, 0, /* 430: pointer.func */
            8884097, 8, 0, /* 433: pointer.func */
            8884097, 8, 0, /* 436: pointer.func */
            8884097, 8, 0, /* 439: pointer.func */
            8884097, 8, 0, /* 442: pointer.func */
            8884097, 8, 0, /* 445: pointer.func */
            8884097, 8, 0, /* 448: pointer.func */
            0, 8, 5, /* 451: union.unknown */
            	54, 0,
            	464, 0,
            	560, 0,
            	258, 0,
            	632, 0,
            1, 8, 1, /* 464: pointer.struct.rsa_st */
            	469, 0,
            0, 168, 17, /* 469: struct.rsa_st */
            	506, 16,
            	328, 24,
            	230, 32,
            	230, 40,
            	230, 48,
            	230, 56,
            	230, 64,
            	230, 72,
            	230, 80,
            	230, 88,
            	27, 96,
            	290, 120,
            	290, 128,
            	290, 136,
            	54, 144,
            	552, 152,
            	552, 160,
            1, 8, 1, /* 506: pointer.struct.rsa_meth_st */
            	511, 0,
            0, 112, 13, /* 511: struct.rsa_meth_st */
            	134, 0,
            	540, 8,
            	540, 16,
            	540, 24,
            	540, 32,
            	543, 40,
            	546, 48,
            	549, 56,
            	549, 64,
            	54, 80,
            	3, 88,
            	241, 96,
            	235, 104,
            8884097, 8, 0, /* 540: pointer.func */
            8884097, 8, 0, /* 543: pointer.func */
            8884097, 8, 0, /* 546: pointer.func */
            8884097, 8, 0, /* 549: pointer.func */
            1, 8, 1, /* 552: pointer.struct.bn_blinding_st */
            	557, 0,
            0, 0, 0, /* 557: struct.bn_blinding_st */
            1, 8, 1, /* 560: pointer.struct.dsa_st */
            	565, 0,
            0, 136, 11, /* 565: struct.dsa_st */
            	230, 24,
            	230, 32,
            	230, 40,
            	230, 48,
            	230, 56,
            	230, 64,
            	230, 72,
            	290, 88,
            	27, 104,
            	590, 120,
            	328, 128,
            1, 8, 1, /* 590: pointer.struct.dsa_method */
            	595, 0,
            0, 96, 11, /* 595: struct.dsa_method */
            	134, 0,
            	336, 8,
            	620, 16,
            	623, 24,
            	6, 32,
            	0, 40,
            	626, 48,
            	626, 56,
            	54, 72,
            	629, 80,
            	626, 88,
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
            	59, 24,
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
            	134, 0,
            	134, 8,
            	139, 24,
            0, 8, 3, /* 690: union.unknown */
            	54, 0,
            	699, 0,
            	731, 0,
            1, 8, 1, /* 699: pointer.struct.stack_st_ASN1_TYPE */
            	704, 0,
            0, 32, 2, /* 704: struct.stack_st_fake_ASN1_TYPE */
            	711, 8,
            	59, 24,
            8884099, 8, 2, /* 711: pointer_to_array_of_pointers_to_stack */
            	718, 0,
            	728, 20,
            0, 8, 1, /* 718: pointer.ASN1_TYPE */
            	723, 0,
            0, 0, 1, /* 723: ASN1_TYPE */
            	67, 0,
            0, 4, 0, /* 728: int */
            1, 8, 1, /* 731: pointer.struct.asn1_type_st */
            	736, 0,
            0, 16, 1, /* 736: struct.asn1_type_st */
            	741, 8,
            0, 8, 20, /* 741: union.unknown */
            	54, 0,
            	784, 0,
            	676, 0,
            	789, 0,
            	794, 0,
            	799, 0,
            	804, 0,
            	244, 0,
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
            	62, 0,
            1, 8, 1, /* 789: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 794: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 799: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 804: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 809: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 814: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 819: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 824: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 829: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 834: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 839: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 844: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 849: pointer.struct.asn1_string_st */
            	62, 0,
            1, 8, 1, /* 854: pointer.struct.ASN1_VALUE_st */
            	859, 0,
            0, 0, 0, /* 859: struct.ASN1_VALUE_st */
            0, 1, 0, /* 862: char */
            1, 8, 1, /* 865: pointer.struct.evp_pkey_st */
            	351, 0,
        },
        .arg_entity_index = { 865, },
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

