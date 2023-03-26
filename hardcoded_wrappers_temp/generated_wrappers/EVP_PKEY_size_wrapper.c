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
            0, 96, 12, /* 29: struct.dsa_method.1040 */
            	5, 0,
            	56, 8,
            	61, 16,
            	69, 24,
            	77, 32,
            	85, 40,
            	93, 48,
            	93, 56,
            	101, 64,
            	5, 72,
            	104, 80,
            	93, 88,
            1, 8, 1, /* 56: pointer.func */
            	26, 0,
            1, 8, 1, /* 61: pointer.func */
            	66, 0,
            0, 0, 0, /* 66: func */
            1, 8, 1, /* 69: pointer.func */
            	74, 0,
            0, 0, 0, /* 74: func */
            1, 8, 1, /* 77: pointer.func */
            	82, 0,
            0, 0, 0, /* 82: func */
            1, 8, 1, /* 85: pointer.func */
            	90, 0,
            0, 0, 0, /* 90: func */
            1, 8, 1, /* 93: pointer.func */
            	98, 0,
            0, 0, 0, /* 98: func */
            0, 4, 0, /* 101: int */
            1, 8, 1, /* 104: pointer.func */
            	109, 0,
            0, 0, 0, /* 109: func */
            1, 8, 1, /* 112: pointer.struct.dsa_method.1040 */
            	29, 0,
            1, 8, 1, /* 117: pointer.func */
            	122, 0,
            0, 0, 0, /* 122: func */
            1, 8, 1, /* 125: pointer.func */
            	130, 0,
            0, 0, 0, /* 130: func */
            1, 8, 1, /* 133: pointer.func */
            	138, 0,
            0, 0, 0, /* 138: func */
            0, 0, 0, /* 141: func */
            0, 0, 0, /* 144: func */
            0, 208, 27, /* 147: struct.evp_pkey_asn1_method_st.2593 */
            	101, 0,
            	101, 4,
            	204, 8,
            	5, 16,
            	5, 24,
            	207, 32,
            	215, 40,
            	223, 48,
            	231, 56,
            	239, 64,
            	247, 72,
            	231, 80,
            	255, 88,
            	255, 96,
            	263, 104,
            	271, 112,
            	255, 120,
            	223, 128,
            	223, 136,
            	231, 144,
            	279, 152,
            	287, 160,
            	117, 168,
            	263, 176,
            	271, 184,
            	295, 192,
            	303, 200,
            0, 8, 0, /* 204: long */
            1, 8, 1, /* 207: pointer.func */
            	212, 0,
            0, 0, 0, /* 212: func */
            1, 8, 1, /* 215: pointer.func */
            	220, 0,
            0, 0, 0, /* 220: func */
            1, 8, 1, /* 223: pointer.func */
            	228, 0,
            0, 0, 0, /* 228: func */
            1, 8, 1, /* 231: pointer.func */
            	236, 0,
            0, 0, 0, /* 236: func */
            1, 8, 1, /* 239: pointer.func */
            	244, 0,
            0, 0, 0, /* 244: func */
            1, 8, 1, /* 247: pointer.func */
            	252, 0,
            0, 0, 0, /* 252: func */
            1, 8, 1, /* 255: pointer.func */
            	260, 0,
            0, 0, 0, /* 260: func */
            1, 8, 1, /* 263: pointer.func */
            	268, 0,
            0, 0, 0, /* 268: func */
            1, 8, 1, /* 271: pointer.func */
            	276, 0,
            0, 0, 0, /* 276: func */
            1, 8, 1, /* 279: pointer.func */
            	284, 0,
            0, 0, 0, /* 284: func */
            1, 8, 1, /* 287: pointer.func */
            	292, 0,
            0, 0, 0, /* 292: func */
            1, 8, 1, /* 295: pointer.func */
            	300, 0,
            0, 0, 0, /* 300: func */
            1, 8, 1, /* 303: pointer.func */
            	308, 0,
            0, 0, 0, /* 308: func */
            1, 8, 1, /* 311: pointer.struct.rsa_meth_st */
            	316, 0,
            0, 112, 14, /* 316: struct.rsa_meth_st */
            	5, 0,
            	347, 8,
            	347, 16,
            	347, 24,
            	347, 32,
            	352, 40,
            	360, 48,
            	365, 56,
            	365, 64,
            	101, 72,
            	5, 80,
            	373, 88,
            	381, 96,
            	125, 104,
            1, 8, 1, /* 347: pointer.func */
            	144, 0,
            1, 8, 1, /* 352: pointer.func */
            	357, 0,
            0, 0, 0, /* 357: func */
            1, 8, 1, /* 360: pointer.func */
            	141, 0,
            1, 8, 1, /* 365: pointer.func */
            	370, 0,
            0, 0, 0, /* 370: func */
            1, 8, 1, /* 373: pointer.func */
            	378, 0,
            0, 0, 0, /* 378: func */
            1, 8, 1, /* 381: pointer.func */
            	386, 0,
            0, 0, 0, /* 386: func */
            1, 8, 1, /* 389: pointer.func */
            	394, 0,
            0, 0, 0, /* 394: func */
            0, 216, 27, /* 397: struct.engine_st */
            	5, 0,
            	5, 8,
            	311, 16,
            	112, 24,
            	454, 32,
            	512, 40,
            	536, 48,
            	572, 56,
            	632, 64,
            	640, 72,
            	648, 80,
            	656, 88,
            	664, 96,
            	133, 104,
            	133, 112,
            	133, 120,
            	672, 128,
            	680, 136,
            	680, 144,
            	688, 152,
            	696, 160,
            	101, 168,
            	101, 172,
            	101, 176,
            	712, 184,
            	742, 200,
            	742, 208,
            1, 8, 1, /* 454: pointer.struct.dh_method */
            	459, 0,
            0, 72, 9, /* 459: struct.dh_method */
            	5, 0,
            	480, 8,
            	488, 16,
            	496, 24,
            	480, 32,
            	480, 40,
            	101, 48,
            	5, 56,
            	504, 64,
            1, 8, 1, /* 480: pointer.func */
            	485, 0,
            0, 0, 0, /* 485: func */
            1, 8, 1, /* 488: pointer.func */
            	493, 0,
            0, 0, 0, /* 493: func */
            1, 8, 1, /* 496: pointer.func */
            	501, 0,
            0, 0, 0, /* 501: func */
            1, 8, 1, /* 504: pointer.func */
            	509, 0,
            0, 0, 0, /* 509: func */
            1, 8, 1, /* 512: pointer.struct.ecdh_method */
            	517, 0,
            0, 32, 4, /* 517: struct.ecdh_method */
            	5, 0,
            	528, 8,
            	101, 16,
            	5, 24,
            1, 8, 1, /* 528: pointer.func */
            	533, 0,
            0, 0, 0, /* 533: func */
            1, 8, 1, /* 536: pointer.struct.ecdsa_method */
            	541, 0,
            0, 48, 6, /* 541: struct.ecdsa_method */
            	5, 0,
            	556, 8,
            	389, 16,
            	564, 24,
            	101, 32,
            	5, 40,
            1, 8, 1, /* 556: pointer.func */
            	561, 0,
            0, 0, 0, /* 561: func */
            1, 8, 1, /* 564: pointer.func */
            	569, 0,
            0, 0, 0, /* 569: func */
            1, 8, 1, /* 572: pointer.struct.rand_meth_st */
            	577, 0,
            0, 48, 6, /* 577: struct.rand_meth_st */
            	592, 0,
            	600, 8,
            	608, 16,
            	616, 24,
            	600, 32,
            	624, 40,
            1, 8, 1, /* 592: pointer.func */
            	597, 0,
            0, 0, 0, /* 597: func */
            1, 8, 1, /* 600: pointer.func */
            	605, 0,
            0, 0, 0, /* 605: func */
            1, 8, 1, /* 608: pointer.func */
            	613, 0,
            0, 0, 0, /* 613: func */
            1, 8, 1, /* 616: pointer.func */
            	621, 0,
            0, 0, 0, /* 621: func */
            1, 8, 1, /* 624: pointer.func */
            	629, 0,
            0, 0, 0, /* 629: func */
            1, 8, 1, /* 632: pointer.struct.store_method_st */
            	637, 0,
            0, 0, 0, /* 637: struct.store_method_st */
            1, 8, 1, /* 640: pointer.func */
            	645, 0,
            0, 0, 0, /* 645: func */
            1, 8, 1, /* 648: pointer.func */
            	653, 0,
            0, 0, 0, /* 653: func */
            1, 8, 1, /* 656: pointer.func */
            	661, 0,
            0, 0, 0, /* 661: func */
            1, 8, 1, /* 664: pointer.func */
            	669, 0,
            0, 0, 0, /* 669: func */
            1, 8, 1, /* 672: pointer.func */
            	677, 0,
            0, 0, 0, /* 677: func */
            1, 8, 1, /* 680: pointer.func */
            	685, 0,
            0, 0, 0, /* 685: func */
            1, 8, 1, /* 688: pointer.func */
            	693, 0,
            0, 0, 0, /* 693: func */
            1, 8, 1, /* 696: pointer.struct.ENGINE_CMD_DEFN_st */
            	701, 0,
            0, 32, 4, /* 701: struct.ENGINE_CMD_DEFN_st */
            	101, 0,
            	5, 8,
            	5, 16,
            	101, 24,
            0, 16, 2, /* 712: struct.crypto_ex_data_st */
            	719, 0,
            	101, 8,
            1, 8, 1, /* 719: pointer.struct.stack_st_OPENSSL_STRING */
            	724, 0,
            0, 32, 1, /* 724: struct.stack_st_OPENSSL_STRING */
            	729, 0,
            0, 32, 5, /* 729: struct.stack_st */
            	101, 0,
            	21, 8,
            	101, 16,
            	101, 20,
            	16, 24,
            1, 8, 1, /* 742: pointer.struct.engine_st */
            	397, 0,
            1, 8, 1, /* 747: pointer.struct.evp_pkey_asn1_method_st.2593 */
            	147, 0,
            0, 56, 8, /* 752: struct.evp_pkey_st.2595 */
            	101, 0,
            	101, 4,
            	101, 8,
            	747, 16,
            	742, 24,
            	0, 32,
            	101, 40,
            	719, 48,
            1, 8, 1, /* 771: pointer.struct.evp_pkey_st.2595 */
            	752, 0,
        },
        .arg_entity_index = { 771, },
        .ret_entity_index = 101,
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

