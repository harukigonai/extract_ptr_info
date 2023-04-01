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

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d);

EVP_PKEY * PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("PEM_read_bio_PrivateKey called %lu\n", in_lib);
    if (!in_lib)
        return bb_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    else {
        EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
        orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
        return orig_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    }
}

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    EVP_PKEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            4097, 8, 0, /* 3: pointer.func */
            0, 0, 0, /* 6: func */
            4097, 8, 0, /* 9: pointer.func */
            0, 0, 0, /* 12: func */
            4097, 8, 0, /* 15: pointer.func */
            0, 0, 0, /* 18: func */
            4097, 8, 0, /* 21: pointer.func */
            0, 0, 0, /* 24: func */
            0, 80, 1, /* 27: struct.bio_method_st */
            	32, 8,
            1, 8, 1, /* 32: pointer.char */
            	4096, 0,
            0, 112, 6, /* 37: struct.bio_st */
            	52, 0,
            	32, 16,
            	32, 48,
            	57, 56,
            	57, 64,
            	62, 96,
            1, 8, 1, /* 52: pointer.struct.bio_method_st */
            	27, 0,
            1, 8, 1, /* 57: pointer.struct.bio_st */
            	37, 0,
            0, 16, 1, /* 62: struct.crypto_ex_data_st */
            	67, 0,
            1, 8, 1, /* 67: pointer.struct.stack_st_OPENSSL_STRING */
            	72, 0,
            0, 32, 1, /* 72: struct.stack_st_OPENSSL_STRING */
            	77, 0,
            0, 32, 1, /* 77: struct.stack_st */
            	82, 8,
            1, 8, 1, /* 82: pointer.pointer.char */
            	32, 0,
            0, 8, 1, /* 87: struct.fnames */
            	32, 0,
            0, 0, 0, /* 92: func */
            4097, 8, 0, /* 95: pointer.func */
            0, 0, 0, /* 98: func */
            1, 8, 1, /* 101: pointer.struct.dsa_method.1040 */
            	106, 0,
            0, 96, 2, /* 106: struct.dsa_method.1040 */
            	32, 0,
            	32, 72,
            4097, 8, 0, /* 113: pointer.func */
            0, 0, 0, /* 116: func */
            0, 0, 0, /* 119: func */
            4097, 8, 0, /* 122: pointer.func */
            0, 112, 2, /* 125: struct.rsa_meth_st */
            	32, 0,
            	32, 80,
            4097, 8, 0, /* 132: pointer.func */
            0, 0, 0, /* 135: func */
            0, 0, 0, /* 138: func */
            0, 0, 0, /* 141: func */
            1, 8, 1, /* 144: pointer.struct.ENGINE_CMD_DEFN_st */
            	149, 0,
            0, 32, 2, /* 149: struct.ENGINE_CMD_DEFN_st */
            	32, 8,
            	32, 16,
            4097, 8, 0, /* 156: pointer.func */
            0, 0, 0, /* 159: func */
            0, 0, 0, /* 162: func */
            4097, 8, 0, /* 165: pointer.func */
            0, 0, 0, /* 168: func */
            0, 48, 2, /* 171: struct.ecdsa_method */
            	32, 0,
            	32, 40,
            4097, 8, 0, /* 178: pointer.func */
            4097, 8, 0, /* 181: pointer.func */
            1, 8, 1, /* 184: pointer.struct.engine_st */
            	189, 0,
            0, 216, 13, /* 189: struct.engine_st */
            	32, 0,
            	32, 8,
            	218, 16,
            	101, 24,
            	223, 32,
            	235, 40,
            	247, 48,
            	252, 56,
            	260, 64,
            	144, 160,
            	62, 184,
            	184, 200,
            	184, 208,
            1, 8, 1, /* 218: pointer.struct.rsa_meth_st */
            	125, 0,
            1, 8, 1, /* 223: pointer.struct.dh_method */
            	228, 0,
            0, 72, 2, /* 228: struct.dh_method */
            	32, 0,
            	32, 56,
            1, 8, 1, /* 235: pointer.struct.ecdh_method */
            	240, 0,
            0, 32, 2, /* 240: struct.ecdh_method */
            	32, 0,
            	32, 24,
            1, 8, 1, /* 247: pointer.struct.ecdsa_method */
            	171, 0,
            1, 8, 1, /* 252: pointer.struct.rand_meth_st */
            	257, 0,
            0, 48, 0, /* 257: struct.rand_meth_st */
            1, 8, 1, /* 260: pointer.struct.store_method_st */
            	265, 0,
            0, 0, 0, /* 265: struct.store_method_st */
            0, 0, 0, /* 268: func */
            4097, 8, 0, /* 271: pointer.func */
            0, 0, 0, /* 274: func */
            4097, 8, 0, /* 277: pointer.func */
            4097, 8, 0, /* 280: pointer.func */
            0, 0, 0, /* 283: func */
            4097, 8, 0, /* 286: pointer.func */
            4097, 8, 0, /* 289: pointer.func */
            4097, 8, 0, /* 292: pointer.func */
            4097, 8, 0, /* 295: pointer.func */
            1, 8, 1, /* 298: pointer.struct.evp_pkey_asn1_method_st.2593 */
            	303, 0,
            0, 208, 2, /* 303: struct.evp_pkey_asn1_method_st.2593 */
            	32, 16,
            	32, 24,
            0, 0, 0, /* 310: func */
            4097, 8, 0, /* 313: pointer.func */
            4097, 8, 0, /* 316: pointer.func */
            0, 0, 0, /* 319: func */
            0, 0, 0, /* 322: func */
            4097, 8, 0, /* 325: pointer.func */
            0, 0, 0, /* 328: func */
            4097, 8, 0, /* 331: pointer.func */
            0, 0, 0, /* 334: func */
            4097, 8, 0, /* 337: pointer.func */
            0, 0, 0, /* 340: func */
            4097, 8, 0, /* 343: pointer.func */
            0, 0, 0, /* 346: func */
            0, 0, 0, /* 349: func */
            4097, 8, 0, /* 352: pointer.func */
            4097, 8, 0, /* 355: pointer.func */
            0, 8, 0, /* 358: long */
            4097, 8, 0, /* 361: pointer.func */
            0, 0, 0, /* 364: func */
            0, 56, 4, /* 367: struct.evp_pkey_st.2595 */
            	298, 16,
            	184, 24,
            	87, 32,
            	67, 48,
            1, 8, 1, /* 378: pointer.struct.evp_pkey_st.2595 */
            	367, 0,
            4097, 8, 0, /* 383: pointer.func */
            0, 0, 0, /* 386: func */
            4097, 8, 0, /* 389: pointer.func */
            0, 0, 0, /* 392: func */
            4097, 8, 0, /* 395: pointer.func */
            0, 0, 0, /* 398: func */
            4097, 8, 0, /* 401: pointer.func */
            4097, 8, 0, /* 404: pointer.func */
            4097, 8, 0, /* 407: pointer.func */
            0, 0, 0, /* 410: func */
            4097, 8, 0, /* 413: pointer.func */
            4097, 8, 0, /* 416: pointer.func */
            4097, 8, 0, /* 419: pointer.func */
            0, 0, 0, /* 422: func */
            0, 0, 0, /* 425: func */
            0, 0, 0, /* 428: func */
            4097, 8, 0, /* 431: pointer.func */
            0, 0, 0, /* 434: func */
            1, 8, 1, /* 437: pointer.pointer.struct.evp_pkey_st.2595 */
            	378, 0,
            4097, 8, 0, /* 442: pointer.func */
            0, 0, 0, /* 445: func */
            0, 0, 0, /* 448: func */
            4097, 8, 0, /* 451: pointer.func */
            0, 0, 0, /* 454: func */
            0, 0, 0, /* 457: func */
            0, 0, 0, /* 460: func */
            0, 0, 0, /* 463: func */
            4097, 8, 0, /* 466: pointer.func */
            0, 0, 0, /* 469: func */
            4097, 8, 0, /* 472: pointer.func */
            4097, 8, 0, /* 475: pointer.func */
            0, 0, 0, /* 478: func */
            4097, 8, 0, /* 481: pointer.func */
            4097, 8, 0, /* 484: pointer.func */
            0, 0, 0, /* 487: func */
            0, 1, 0, /* 490: char */
            0, 0, 0, /* 493: func */
            4097, 8, 0, /* 496: pointer.func */
            0, 0, 0, /* 499: func */
            4097, 8, 0, /* 502: pointer.func */
            4097, 8, 0, /* 505: pointer.func */
            0, 0, 0, /* 508: func */
            0, 0, 0, /* 511: func */
            4097, 8, 0, /* 514: pointer.func */
            4097, 8, 0, /* 517: pointer.func */
            4097, 8, 0, /* 520: pointer.func */
            0, 0, 0, /* 523: func */
            0, 0, 0, /* 526: func */
            4097, 8, 0, /* 529: pointer.func */
            0, 0, 0, /* 532: func */
            4097, 8, 0, /* 535: pointer.func */
            0, 0, 0, /* 538: func */
            0, 0, 0, /* 541: func */
            4097, 8, 0, /* 544: pointer.func */
            0, 0, 0, /* 547: func */
            4097, 8, 0, /* 550: pointer.func */
            0, 0, 0, /* 553: func */
            4097, 8, 0, /* 556: pointer.func */
            0, 4, 0, /* 559: int */
            0, 0, 0, /* 562: func */
            4097, 8, 0, /* 565: pointer.func */
            0, 0, 0, /* 568: func */
        },
        .arg_entity_index = { 57, 437, 484, 32, },
        .ret_entity_index = 378,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    EVP_PKEY ** new_arg_b = *((EVP_PKEY ** *)new_args->args[1]);

    pem_password_cb * new_arg_c = *((pem_password_cb * *)new_args->args[2]);

    void * new_arg_d = *((void * *)new_args->args[3]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
    orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
    *new_ret_ptr = (*orig_PEM_read_bio_PrivateKey)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

