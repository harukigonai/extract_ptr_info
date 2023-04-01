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
            0, 24, 3, /* 113: struct.X509_pubkey_st.2915 */
            	122, 0,
            	43, 8,
            	149, 16,
            1, 8, 1, /* 122: pointer.struct.X509_algor_st */
            	127, 0,
            0, 16, 2, /* 127: struct.X509_algor_st */
            	94, 0,
            	134, 8,
            1, 8, 1, /* 134: pointer.struct.asn1_type_st */
            	139, 0,
            0, 16, 1, /* 139: struct.asn1_type_st */
            	144, 8,
            0, 8, 1, /* 144: struct.fnames */
            	38, 0,
            1, 8, 1, /* 149: pointer.struct.evp_pkey_st.2930 */
            	154, 0,
            0, 56, 4, /* 154: struct.evp_pkey_st.2930 */
            	165, 16,
            	177, 24,
            	144, 32,
            	18, 48,
            1, 8, 1, /* 165: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	170, 0,
            0, 208, 2, /* 170: struct.evp_pkey_asn1_method_st.2928 */
            	38, 16,
            	38, 24,
            1, 8, 1, /* 177: pointer.struct.engine_st */
            	182, 0,
            0, 216, 13, /* 182: struct.engine_st */
            	38, 0,
            	38, 8,
            	211, 16,
            	223, 24,
            	235, 32,
            	247, 40,
            	259, 48,
            	271, 56,
            	279, 64,
            	287, 160,
            	299, 184,
            	177, 200,
            	177, 208,
            1, 8, 1, /* 211: pointer.struct.rsa_meth_st */
            	216, 0,
            0, 112, 2, /* 216: struct.rsa_meth_st */
            	38, 0,
            	38, 80,
            1, 8, 1, /* 223: pointer.struct.dsa_method.1040 */
            	228, 0,
            0, 96, 2, /* 228: struct.dsa_method.1040 */
            	38, 0,
            	38, 72,
            1, 8, 1, /* 235: pointer.struct.dh_method */
            	240, 0,
            0, 72, 2, /* 240: struct.dh_method */
            	38, 0,
            	38, 56,
            1, 8, 1, /* 247: pointer.struct.ecdh_method */
            	252, 0,
            0, 32, 2, /* 252: struct.ecdh_method */
            	38, 0,
            	38, 24,
            1, 8, 1, /* 259: pointer.struct.ecdsa_method */
            	264, 0,
            0, 48, 2, /* 264: struct.ecdsa_method */
            	38, 0,
            	38, 40,
            1, 8, 1, /* 271: pointer.struct.rand_meth_st */
            	276, 0,
            0, 48, 0, /* 276: struct.rand_meth_st */
            1, 8, 1, /* 279: pointer.struct.store_method_st */
            	284, 0,
            0, 0, 0, /* 284: struct.store_method_st */
            1, 8, 1, /* 287: pointer.struct.ENGINE_CMD_DEFN_st */
            	292, 0,
            0, 32, 2, /* 292: struct.ENGINE_CMD_DEFN_st */
            	38, 8,
            	38, 16,
            0, 16, 1, /* 299: struct.crypto_ex_data_st */
            	18, 0,
            0, 16, 2, /* 304: struct.X509_val_st */
            	43, 0,
            	43, 8,
            1, 8, 1, /* 311: pointer.struct.X509_val_st */
            	304, 0,
            0, 24, 1, /* 316: struct.buf_mem_st */
            	38, 8,
            1, 8, 1, /* 321: pointer.struct.x509_cinf_st.3159 */
            	326, 0,
            0, 104, 11, /* 326: struct.x509_cinf_st.3159 */
            	43, 0,
            	43, 8,
            	122, 16,
            	351, 24,
            	311, 32,
            	351, 40,
            	370, 48,
            	43, 56,
            	43, 64,
            	18, 72,
            	108, 80,
            1, 8, 1, /* 351: pointer.struct.X509_name_st */
            	356, 0,
            0, 40, 3, /* 356: struct.X509_name_st */
            	18, 0,
            	365, 16,
            	38, 24,
            1, 8, 1, /* 365: pointer.struct.buf_mem_st */
            	316, 0,
            1, 8, 1, /* 370: pointer.struct.X509_pubkey_st.2915 */
            	113, 0,
            1, 8, 1, /* 375: pointer.struct.x509_st.3164 */
            	380, 0,
            0, 184, 12, /* 380: struct.x509_st.3164 */
            	321, 0,
            	122, 8,
            	43, 16,
            	38, 32,
            	299, 40,
            	43, 104,
            	407, 112,
            	68, 120,
            	18, 128,
            	18, 136,
            	56, 144,
            	0, 176,
            1, 8, 1, /* 407: pointer.struct.AUTHORITY_KEYID_st */
            	412, 0,
            0, 24, 3, /* 412: struct.AUTHORITY_KEYID_st */
            	43, 0,
            	18, 8,
            	43, 16,
            4097, 94396196035680, 94396196036960, /* 421: pointer.func */
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94416502956857, 94396195305936,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396195297680,
            	1, 4097,
            	94396196035360, 140425329646816,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396195431840,
            	64, 0,
            	0, 0,
            	4097, 32,
            	94416502956761, 4097,
            	1, 33,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 385,
            	94396194087712, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 97,
            	94396196034624, 4097,
            	1, 65,
            	4097, 94396196034624,
            	1, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	1, 161,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	1, 33,
            	4097, 94396196036160,
            	128, 4097,
            	94416502956281, 94396195473120,
            	4097, 32,
            	94416504656089, 4097,
            	1, 929,
            	4097, 140425329646816,
            	0, 4097,
            	140425329646816, 94396196037216,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396194203760,
            	0, 4097,
            	94396194064448, 94396196035296,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396194257424,
            	0, 4097,
            	94396196034880, 94396196034080,
            	0, 8,
            	0, 4097,
            	64, 32,
            	0, 0,
            	0, 4097,
            	94396194064448, 94396196034624,
            	4097, 32,
            	94416502954585, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 32,
            	94416504678041, 4097,
            	1, 129,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 33,
            	94396196035744, 4097,
            	96, 32,
            	4097, 94396194500976,
            	608, 0,
            	0, 0,
            	4097, 32,
            	94416502959545, 4097,
            	672, 32,
            	0, 0,
            	0, 4097,
            	94396194074704, 94396196035456,
            	0, 0,
            	0, 4097,
            	768, 32,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396194074704,
            	0, 0,
            	0, 0,
            	4097, 32,
            	94416504674489, 4097,
            	0, 74881,
            	0, 0,
            	0, 0,
            	1, 0,
            	0, 0,
            	0, 4097,
            	32, 32,
            	0, 0,
            	0, 4097,
            	94396196036608, 94396196034304,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396194802320,
            	0, 4097,
            	94396196035200, 94396196033216,
            	4097, 0,
            	94416502954745, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396196037408, 140425329646816,
            	0, 0,
            	0, 4097,
            	1, 129,
            	4097, 94396196034304,
            	1, 0,
            	0, 0,
            	4097, 65,
            	94396196034112, 0,
            	0, 0,
            	4097, 94396196034112,
            	224, 0,
            	0, 0,
            	4097, 65,
            	94396196037120, 0,
            	4, 0,
            	0, 0,
            	0, 4097,
            	94416502956633, 94396195008720,
            	0, 0,
            	0, 0,
            	0, 0,
        },
        .arg_entity_index = { 375, },
        .ret_entity_index = 149,
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

