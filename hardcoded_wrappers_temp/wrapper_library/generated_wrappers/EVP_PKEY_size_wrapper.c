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

int EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 8, 1, /* 0: struct.fnames */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	10, 0,
            0, 1, 0, /* 10: char */
            0, 0, 0, /* 13: func */
            1, 8, 1, /* 16: pointer.func */
            	13, 0,
            1, 8, 1, /* 21: pointer.pointer.char */
            	5, 0,
            0, 0, 0, /* 26: func */
            0, 96, 11, /* 29: struct.dsa_method.1040 */
            	5, 0,
            	54, 8,
            	59, 16,
            	67, 24,
            	75, 32,
            	83, 40,
            	91, 48,
            	91, 56,
            	5, 72,
            	99, 80,
            	91, 88,
            1, 8, 1, /* 54: pointer.func */
            	26, 0,
            1, 8, 1, /* 59: pointer.func */
            	64, 0,
            0, 0, 0, /* 64: func */
            1, 8, 1, /* 67: pointer.func */
            	72, 0,
            0, 0, 0, /* 72: func */
            1, 8, 1, /* 75: pointer.func */
            	80, 0,
            0, 0, 0, /* 80: func */
            1, 8, 1, /* 83: pointer.func */
            	88, 0,
            0, 0, 0, /* 88: func */
            1, 8, 1, /* 91: pointer.func */
            	96, 0,
            0, 0, 0, /* 96: func */
            1, 8, 1, /* 99: pointer.func */
            	104, 0,
            0, 0, 0, /* 104: func */
            1, 8, 1, /* 107: pointer.struct.dsa_method.1040 */
            	29, 0,
            1, 8, 1, /* 112: pointer.func */
            	117, 0,
            0, 0, 0, /* 117: func */
            1, 8, 1, /* 120: pointer.func */
            	125, 0,
            0, 0, 0, /* 125: func */
            1, 8, 1, /* 128: pointer.func */
            	133, 0,
            0, 0, 0, /* 133: func */
            1, 8, 1, /* 136: pointer.func */
            	141, 0,
            0, 0, 0, /* 141: func */
            1, 8, 1, /* 144: pointer.func */
            	149, 0,
            0, 0, 0, /* 149: func */
            0, 0, 0, /* 152: func */
            0, 0, 0, /* 155: func */
            0, 208, 24, /* 158: struct.evp_pkey_asn1_method_st.2593 */
            	5, 16,
            	5, 24,
            	209, 32,
            	217, 40,
            	225, 48,
            	233, 56,
            	241, 64,
            	249, 72,
            	233, 80,
            	257, 88,
            	257, 96,
            	265, 104,
            	273, 112,
            	257, 120,
            	225, 128,
            	225, 136,
            	233, 144,
            	281, 152,
            	289, 160,
            	112, 168,
            	265, 176,
            	273, 184,
            	297, 192,
            	305, 200,
            1, 8, 1, /* 209: pointer.func */
            	214, 0,
            0, 0, 0, /* 214: func */
            1, 8, 1, /* 217: pointer.func */
            	222, 0,
            0, 0, 0, /* 222: func */
            1, 8, 1, /* 225: pointer.func */
            	230, 0,
            0, 0, 0, /* 230: func */
            1, 8, 1, /* 233: pointer.func */
            	238, 0,
            0, 0, 0, /* 238: func */
            1, 8, 1, /* 241: pointer.func */
            	246, 0,
            0, 0, 0, /* 246: func */
            1, 8, 1, /* 249: pointer.func */
            	254, 0,
            0, 0, 0, /* 254: func */
            1, 8, 1, /* 257: pointer.func */
            	262, 0,
            0, 0, 0, /* 262: func */
            1, 8, 1, /* 265: pointer.func */
            	270, 0,
            0, 0, 0, /* 270: func */
            1, 8, 1, /* 273: pointer.func */
            	278, 0,
            0, 0, 0, /* 278: func */
            1, 8, 1, /* 281: pointer.func */
            	286, 0,
            0, 0, 0, /* 286: func */
            1, 8, 1, /* 289: pointer.func */
            	294, 0,
            0, 0, 0, /* 294: func */
            1, 8, 1, /* 297: pointer.func */
            	302, 0,
            0, 0, 0, /* 302: func */
            1, 8, 1, /* 305: pointer.func */
            	310, 0,
            0, 0, 0, /* 310: func */
            1, 8, 1, /* 313: pointer.struct.rsa_meth_st */
            	318, 0,
            0, 112, 13, /* 318: struct.rsa_meth_st */
            	5, 0,
            	347, 8,
            	347, 16,
            	347, 24,
            	347, 32,
            	352, 40,
            	360, 48,
            	365, 56,
            	365, 64,
            	5, 80,
            	373, 88,
            	128, 96,
            	120, 104,
            1, 8, 1, /* 347: pointer.func */
            	155, 0,
            1, 8, 1, /* 352: pointer.func */
            	357, 0,
            0, 0, 0, /* 357: func */
            1, 8, 1, /* 360: pointer.func */
            	152, 0,
            1, 8, 1, /* 365: pointer.func */
            	370, 0,
            0, 0, 0, /* 370: func */
            1, 8, 1, /* 373: pointer.func */
            	378, 0,
            0, 0, 0, /* 378: func */
            1, 8, 1, /* 381: pointer.func */
            	386, 0,
            0, 0, 0, /* 386: func */
            1, 8, 1, /* 389: pointer.struct.engine_st */
            	394, 0,
            0, 216, 24, /* 394: struct.engine_st */
            	5, 0,
            	5, 8,
            	313, 16,
            	107, 24,
            	445, 32,
            	493, 40,
            	515, 48,
            	549, 56,
            	609, 64,
            	617, 72,
            	625, 80,
            	633, 88,
            	641, 96,
            	144, 104,
            	144, 112,
            	144, 120,
            	649, 128,
            	657, 136,
            	657, 144,
            	665, 152,
            	673, 160,
            	685, 184,
            	389, 200,
            	389, 208,
            1, 8, 1, /* 445: pointer.struct.dh_method */
            	450, 0,
            0, 72, 8, /* 450: struct.dh_method */
            	5, 0,
            	136, 8,
            	469, 16,
            	477, 24,
            	136, 32,
            	136, 40,
            	5, 56,
            	485, 64,
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
            	5, 0,
            	507, 8,
            	5, 24,
            1, 8, 1, /* 507: pointer.func */
            	512, 0,
            0, 0, 0, /* 512: func */
            1, 8, 1, /* 515: pointer.struct.ecdsa_method */
            	520, 0,
            0, 48, 5, /* 520: struct.ecdsa_method */
            	5, 0,
            	533, 8,
            	381, 16,
            	541, 24,
            	5, 40,
            1, 8, 1, /* 533: pointer.func */
            	538, 0,
            0, 0, 0, /* 538: func */
            1, 8, 1, /* 541: pointer.func */
            	546, 0,
            0, 0, 0, /* 546: func */
            1, 8, 1, /* 549: pointer.struct.rand_meth_st */
            	554, 0,
            0, 48, 6, /* 554: struct.rand_meth_st */
            	569, 0,
            	577, 8,
            	585, 16,
            	593, 24,
            	577, 32,
            	601, 40,
            1, 8, 1, /* 569: pointer.func */
            	574, 0,
            0, 0, 0, /* 574: func */
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
            1, 8, 1, /* 609: pointer.struct.store_method_st */
            	614, 0,
            0, 0, 0, /* 614: struct.store_method_st */
            1, 8, 1, /* 617: pointer.func */
            	622, 0,
            0, 0, 0, /* 622: func */
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
            1, 8, 1, /* 673: pointer.struct.ENGINE_CMD_DEFN_st */
            	678, 0,
            0, 32, 2, /* 678: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 685: struct.crypto_ex_data_st */
            	690, 0,
            1, 8, 1, /* 690: pointer.struct.stack_st_OPENSSL_STRING */
            	695, 0,
            0, 32, 1, /* 695: struct.stack_st_OPENSSL_STRING */
            	700, 0,
            0, 32, 2, /* 700: struct.stack_st */
            	21, 8,
            	16, 24,
            1, 8, 1, /* 707: pointer.struct.evp_pkey_asn1_method_st.2593 */
            	158, 0,
            0, 56, 4, /* 712: struct.evp_pkey_st.2595 */
            	707, 16,
            	389, 24,
            	0, 32,
            	690, 48,
            0, 4, 0, /* 723: int */
            0, 8, 0, /* 726: long */
            1, 8, 1, /* 729: pointer.struct.evp_pkey_st.2595 */
            	712, 0,
        },
        .arg_entity_index = { 729, },
        .ret_entity_index = 723,
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

