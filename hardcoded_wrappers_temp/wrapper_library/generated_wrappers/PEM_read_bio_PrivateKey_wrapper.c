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
    if (syscall(890))
        return bb_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    else {
        EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
        orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
        return orig_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    }
}

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    printf("PEM_read_bio_PrivateKey called\n");
    EVP_PKEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.func */
            	5, 0,
            0, 0, 0, /* 5: func */
            1, 8, 1, /* 8: pointer.pointer.struct.evp_pkey_st.2595 */
            	13, 0,
            1, 8, 1, /* 13: pointer.struct.evp_pkey_st.2595 */
            	18, 0,
            0, 56, 4, /* 18: struct.evp_pkey_st.2595 */
            	29, 16,
            	205, 24,
            	736, 32,
            	706, 48,
            1, 8, 1, /* 29: pointer.struct.evp_pkey_asn1_method_st.2593 */
            	34, 0,
            0, 208, 24, /* 34: struct.evp_pkey_asn1_method_st.2593 */
            	85, 16,
            	85, 24,
            	93, 32,
            	101, 40,
            	109, 48,
            	117, 56,
            	125, 64,
            	133, 72,
            	117, 80,
            	141, 88,
            	141, 96,
            	149, 104,
            	157, 112,
            	141, 120,
            	109, 128,
            	109, 136,
            	117, 144,
            	165, 152,
            	173, 160,
            	181, 168,
            	149, 176,
            	157, 184,
            	189, 192,
            	197, 200,
            1, 8, 1, /* 85: pointer.char */
            	90, 0,
            0, 1, 0, /* 90: char */
            1, 8, 1, /* 93: pointer.func */
            	98, 0,
            0, 0, 0, /* 98: func */
            1, 8, 1, /* 101: pointer.func */
            	106, 0,
            0, 0, 0, /* 106: func */
            1, 8, 1, /* 109: pointer.func */
            	114, 0,
            0, 0, 0, /* 114: func */
            1, 8, 1, /* 117: pointer.func */
            	122, 0,
            0, 0, 0, /* 122: func */
            1, 8, 1, /* 125: pointer.func */
            	130, 0,
            0, 0, 0, /* 130: func */
            1, 8, 1, /* 133: pointer.func */
            	138, 0,
            0, 0, 0, /* 138: func */
            1, 8, 1, /* 141: pointer.func */
            	146, 0,
            0, 0, 0, /* 146: func */
            1, 8, 1, /* 149: pointer.func */
            	154, 0,
            0, 0, 0, /* 154: func */
            1, 8, 1, /* 157: pointer.func */
            	162, 0,
            0, 0, 0, /* 162: func */
            1, 8, 1, /* 165: pointer.func */
            	170, 0,
            0, 0, 0, /* 170: func */
            1, 8, 1, /* 173: pointer.func */
            	178, 0,
            0, 0, 0, /* 178: func */
            1, 8, 1, /* 181: pointer.func */
            	186, 0,
            0, 0, 0, /* 186: func */
            1, 8, 1, /* 189: pointer.func */
            	194, 0,
            0, 0, 0, /* 194: func */
            1, 8, 1, /* 197: pointer.func */
            	202, 0,
            0, 0, 0, /* 202: func */
            1, 8, 1, /* 205: pointer.struct.engine_st */
            	210, 0,
            0, 216, 24, /* 210: struct.engine_st */
            	85, 0,
            	85, 8,
            	261, 16,
            	351, 24,
            	437, 32,
            	493, 40,
            	515, 48,
            	557, 56,
            	617, 64,
            	625, 72,
            	633, 80,
            	641, 88,
            	649, 96,
            	657, 104,
            	657, 112,
            	657, 120,
            	665, 128,
            	673, 136,
            	673, 144,
            	681, 152,
            	689, 160,
            	701, 184,
            	205, 200,
            	205, 208,
            1, 8, 1, /* 261: pointer.struct.rsa_meth_st */
            	266, 0,
            0, 112, 13, /* 266: struct.rsa_meth_st */
            	85, 0,
            	295, 8,
            	295, 16,
            	295, 24,
            	295, 32,
            	303, 40,
            	311, 48,
            	319, 56,
            	319, 64,
            	85, 80,
            	327, 88,
            	335, 96,
            	343, 104,
            1, 8, 1, /* 295: pointer.func */
            	300, 0,
            0, 0, 0, /* 300: func */
            1, 8, 1, /* 303: pointer.func */
            	308, 0,
            0, 0, 0, /* 308: func */
            1, 8, 1, /* 311: pointer.func */
            	316, 0,
            0, 0, 0, /* 316: func */
            1, 8, 1, /* 319: pointer.func */
            	324, 0,
            0, 0, 0, /* 324: func */
            1, 8, 1, /* 327: pointer.func */
            	332, 0,
            0, 0, 0, /* 332: func */
            1, 8, 1, /* 335: pointer.func */
            	340, 0,
            0, 0, 0, /* 340: func */
            1, 8, 1, /* 343: pointer.func */
            	348, 0,
            0, 0, 0, /* 348: func */
            1, 8, 1, /* 351: pointer.struct.dsa_method.1040 */
            	356, 0,
            0, 96, 11, /* 356: struct.dsa_method.1040 */
            	85, 0,
            	381, 8,
            	389, 16,
            	397, 24,
            	405, 32,
            	413, 40,
            	421, 48,
            	421, 56,
            	85, 72,
            	429, 80,
            	421, 88,
            1, 8, 1, /* 381: pointer.func */
            	386, 0,
            0, 0, 0, /* 386: func */
            1, 8, 1, /* 389: pointer.func */
            	394, 0,
            0, 0, 0, /* 394: func */
            1, 8, 1, /* 397: pointer.func */
            	402, 0,
            0, 0, 0, /* 402: func */
            1, 8, 1, /* 405: pointer.func */
            	410, 0,
            0, 0, 0, /* 410: func */
            1, 8, 1, /* 413: pointer.func */
            	418, 0,
            0, 0, 0, /* 418: func */
            1, 8, 1, /* 421: pointer.func */
            	426, 0,
            0, 0, 0, /* 426: func */
            1, 8, 1, /* 429: pointer.func */
            	434, 0,
            0, 0, 0, /* 434: func */
            1, 8, 1, /* 437: pointer.struct.dh_method */
            	442, 0,
            0, 72, 8, /* 442: struct.dh_method */
            	85, 0,
            	461, 8,
            	469, 16,
            	477, 24,
            	461, 32,
            	461, 40,
            	85, 56,
            	485, 64,
            1, 8, 1, /* 461: pointer.func */
            	466, 0,
            0, 0, 0, /* 466: func */
            1, 8, 1, /* 469: pointer.func */
            	474, 0,
            0, 0, 0, /* 474: func */
            1, 8, 1, /* 477: pointer.func */
            	482, 0,
            0, 0, 0, /* 482: func */
            1, 8, 1, /* 485: pointer.func */
            	490, 0,
            0, 0, 0, /* 490: func */
            1, 8, 1, /* 493: pointer.struct.ecdh_method */
            	498, 0,
            0, 32, 3, /* 498: struct.ecdh_method */
            	85, 0,
            	507, 8,
            	85, 24,
            1, 8, 1, /* 507: pointer.func */
            	512, 0,
            0, 0, 0, /* 512: func */
            1, 8, 1, /* 515: pointer.struct.ecdsa_method */
            	520, 0,
            0, 48, 5, /* 520: struct.ecdsa_method */
            	85, 0,
            	533, 8,
            	541, 16,
            	549, 24,
            	85, 40,
            1, 8, 1, /* 533: pointer.func */
            	538, 0,
            0, 0, 0, /* 538: func */
            1, 8, 1, /* 541: pointer.func */
            	546, 0,
            0, 0, 0, /* 546: func */
            1, 8, 1, /* 549: pointer.func */
            	554, 0,
            0, 0, 0, /* 554: func */
            1, 8, 1, /* 557: pointer.struct.rand_meth_st */
            	562, 0,
            0, 48, 6, /* 562: struct.rand_meth_st */
            	577, 0,
            	585, 8,
            	593, 16,
            	601, 24,
            	585, 32,
            	609, 40,
            1, 8, 1, /* 577: pointer.func */
            	582, 0,
            0, 0, 0, /* 582: func */
            1, 8, 1, /* 585: pointer.func */
            	590, 0,
            0, 0, 0, /* 590: func */
            1, 8, 1, /* 593: pointer.func */
            	598, 0,
            0, 0, 0, /* 598: func */
            1, 8, 1, /* 601: pointer.func */
            	606, 0,
            0, 0, 0, /* 606: func */
            1, 8, 1, /* 609: pointer.func */
            	614, 0,
            0, 0, 0, /* 614: func */
            1, 8, 1, /* 617: pointer.struct.store_method_st */
            	622, 0,
            0, 0, 0, /* 622: struct.store_method_st */
            1, 8, 1, /* 625: pointer.func */
            	630, 0,
            0, 0, 0, /* 630: func */
            1, 8, 1, /* 633: pointer.func */
            	638, 0,
            0, 0, 0, /* 638: func */
            1, 8, 1, /* 641: pointer.func */
            	646, 0,
            0, 0, 0, /* 646: func */
            1, 8, 1, /* 649: pointer.func */
            	654, 0,
            0, 0, 0, /* 654: func */
            1, 8, 1, /* 657: pointer.func */
            	662, 0,
            0, 0, 0, /* 662: func */
            1, 8, 1, /* 665: pointer.func */
            	670, 0,
            0, 0, 0, /* 670: func */
            1, 8, 1, /* 673: pointer.func */
            	678, 0,
            0, 0, 0, /* 678: func */
            1, 8, 1, /* 681: pointer.func */
            	686, 0,
            0, 0, 0, /* 686: func */
            1, 8, 1, /* 689: pointer.struct.ENGINE_CMD_DEFN_st */
            	694, 0,
            0, 32, 2, /* 694: struct.ENGINE_CMD_DEFN_st */
            	85, 8,
            	85, 16,
            0, 16, 1, /* 701: struct.crypto_ex_data_st */
            	706, 0,
            1, 8, 1, /* 706: pointer.struct.stack_st_OPENSSL_STRING */
            	711, 0,
            0, 32, 1, /* 711: struct.stack_st_OPENSSL_STRING */
            	716, 0,
            0, 32, 2, /* 716: struct.stack_st */
            	723, 8,
            	728, 24,
            1, 8, 1, /* 723: pointer.pointer.char */
            	85, 0,
            1, 8, 1, /* 728: pointer.func */
            	733, 0,
            0, 0, 0, /* 733: func */
            0, 8, 1, /* 736: struct.fnames */
            	85, 0,
            0, 0, 0, /* 741: func */
            1, 8, 1, /* 744: pointer.func */
            	741, 0,
            0, 0, 0, /* 749: func */
            1, 8, 1, /* 752: pointer.func */
            	749, 0,
            0, 0, 0, /* 757: func */
            1, 8, 1, /* 760: pointer.func */
            	757, 0,
            0, 0, 0, /* 765: func */
            1, 8, 1, /* 768: pointer.func */
            	765, 0,
            1, 8, 1, /* 773: pointer.func */
            	778, 0,
            0, 0, 0, /* 778: func */
            0, 80, 9, /* 781: struct.bio_method_st */
            	85, 8,
            	773, 16,
            	773, 24,
            	768, 32,
            	773, 40,
            	760, 48,
            	752, 56,
            	752, 64,
            	744, 72,
            0, 112, 7, /* 802: struct.bio_st */
            	819, 0,
            	824, 8,
            	85, 16,
            	85, 48,
            	832, 56,
            	832, 64,
            	701, 96,
            1, 8, 1, /* 819: pointer.struct.bio_method_st */
            	781, 0,
            1, 8, 1, /* 824: pointer.func */
            	829, 0,
            0, 0, 0, /* 829: func */
            1, 8, 1, /* 832: pointer.struct.bio_st */
            	802, 0,
            0, 4, 0, /* 837: int */
            0, 8, 0, /* 840: long */
        },
        .arg_entity_index = { 832, 8, 0, 85, },
        .ret_entity_index = 13,
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

