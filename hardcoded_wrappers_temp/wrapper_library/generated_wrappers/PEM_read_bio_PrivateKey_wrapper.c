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

EVP_PKEY * PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    EVP_PKEY * ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.func */
            	5, 0,
            0, 0, 0, /* 5: func */
            1, 8, 1, /* 8: pointer.pointer.struct.evp_pkey_st.2595 */
            	13, 0,
            1, 8, 1, /* 13: pointer.struct.evp_pkey_st.2595 */
            	18, 0,
            0, 56, 8, /* 18: struct.evp_pkey_st.2595 */
            	37, 0,
            	37, 4,
            	37, 8,
            	40, 16,
            	225, 24,
            	784, 32,
            	37, 40,
            	748, 48,
            0, 4, 0, /* 37: int */
            1, 8, 1, /* 40: pointer.struct.evp_pkey_asn1_method_st.2593 */
            	45, 0,
            0, 208, 27, /* 45: struct.evp_pkey_asn1_method_st.2593 */
            	37, 0,
            	37, 4,
            	102, 8,
            	105, 16,
            	105, 24,
            	113, 32,
            	121, 40,
            	129, 48,
            	137, 56,
            	145, 64,
            	153, 72,
            	137, 80,
            	161, 88,
            	161, 96,
            	169, 104,
            	177, 112,
            	161, 120,
            	129, 128,
            	129, 136,
            	137, 144,
            	185, 152,
            	193, 160,
            	201, 168,
            	169, 176,
            	177, 184,
            	209, 192,
            	217, 200,
            0, 8, 0, /* 102: long */
            1, 8, 1, /* 105: pointer.char */
            	110, 0,
            0, 1, 0, /* 110: char */
            1, 8, 1, /* 113: pointer.func */
            	118, 0,
            0, 0, 0, /* 118: func */
            1, 8, 1, /* 121: pointer.func */
            	126, 0,
            0, 0, 0, /* 126: func */
            1, 8, 1, /* 129: pointer.func */
            	134, 0,
            0, 0, 0, /* 134: func */
            1, 8, 1, /* 137: pointer.func */
            	142, 0,
            0, 0, 0, /* 142: func */
            1, 8, 1, /* 145: pointer.func */
            	150, 0,
            0, 0, 0, /* 150: func */
            1, 8, 1, /* 153: pointer.func */
            	158, 0,
            0, 0, 0, /* 158: func */
            1, 8, 1, /* 161: pointer.func */
            	166, 0,
            0, 0, 0, /* 166: func */
            1, 8, 1, /* 169: pointer.func */
            	174, 0,
            0, 0, 0, /* 174: func */
            1, 8, 1, /* 177: pointer.func */
            	182, 0,
            0, 0, 0, /* 182: func */
            1, 8, 1, /* 185: pointer.func */
            	190, 0,
            0, 0, 0, /* 190: func */
            1, 8, 1, /* 193: pointer.func */
            	198, 0,
            0, 0, 0, /* 198: func */
            1, 8, 1, /* 201: pointer.func */
            	206, 0,
            0, 0, 0, /* 206: func */
            1, 8, 1, /* 209: pointer.func */
            	214, 0,
            0, 0, 0, /* 214: func */
            1, 8, 1, /* 217: pointer.func */
            	222, 0,
            0, 0, 0, /* 222: func */
            1, 8, 1, /* 225: pointer.struct.engine_st */
            	230, 0,
            0, 216, 27, /* 230: struct.engine_st */
            	105, 0,
            	105, 8,
            	287, 16,
            	379, 24,
            	467, 32,
            	525, 40,
            	549, 48,
            	593, 56,
            	653, 64,
            	661, 72,
            	669, 80,
            	677, 88,
            	685, 96,
            	693, 104,
            	693, 112,
            	693, 120,
            	701, 128,
            	709, 136,
            	709, 144,
            	717, 152,
            	725, 160,
            	37, 168,
            	37, 172,
            	37, 176,
            	741, 184,
            	225, 200,
            	225, 208,
            1, 8, 1, /* 287: pointer.struct.rsa_meth_st */
            	292, 0,
            0, 112, 14, /* 292: struct.rsa_meth_st */
            	105, 0,
            	323, 8,
            	323, 16,
            	323, 24,
            	323, 32,
            	331, 40,
            	339, 48,
            	347, 56,
            	347, 64,
            	37, 72,
            	105, 80,
            	355, 88,
            	363, 96,
            	371, 104,
            1, 8, 1, /* 323: pointer.func */
            	328, 0,
            0, 0, 0, /* 328: func */
            1, 8, 1, /* 331: pointer.func */
            	336, 0,
            0, 0, 0, /* 336: func */
            1, 8, 1, /* 339: pointer.func */
            	344, 0,
            0, 0, 0, /* 344: func */
            1, 8, 1, /* 347: pointer.func */
            	352, 0,
            0, 0, 0, /* 352: func */
            1, 8, 1, /* 355: pointer.func */
            	360, 0,
            0, 0, 0, /* 360: func */
            1, 8, 1, /* 363: pointer.func */
            	368, 0,
            0, 0, 0, /* 368: func */
            1, 8, 1, /* 371: pointer.func */
            	376, 0,
            0, 0, 0, /* 376: func */
            1, 8, 1, /* 379: pointer.struct.dsa_method.1040 */
            	384, 0,
            0, 96, 12, /* 384: struct.dsa_method.1040 */
            	105, 0,
            	411, 8,
            	419, 16,
            	427, 24,
            	435, 32,
            	443, 40,
            	451, 48,
            	451, 56,
            	37, 64,
            	105, 72,
            	459, 80,
            	451, 88,
            1, 8, 1, /* 411: pointer.func */
            	416, 0,
            0, 0, 0, /* 416: func */
            1, 8, 1, /* 419: pointer.func */
            	424, 0,
            0, 0, 0, /* 424: func */
            1, 8, 1, /* 427: pointer.func */
            	432, 0,
            0, 0, 0, /* 432: func */
            1, 8, 1, /* 435: pointer.func */
            	440, 0,
            0, 0, 0, /* 440: func */
            1, 8, 1, /* 443: pointer.func */
            	448, 0,
            0, 0, 0, /* 448: func */
            1, 8, 1, /* 451: pointer.func */
            	456, 0,
            0, 0, 0, /* 456: func */
            1, 8, 1, /* 459: pointer.func */
            	464, 0,
            0, 0, 0, /* 464: func */
            1, 8, 1, /* 467: pointer.struct.dh_method */
            	472, 0,
            0, 72, 9, /* 472: struct.dh_method */
            	105, 0,
            	493, 8,
            	501, 16,
            	509, 24,
            	493, 32,
            	493, 40,
            	37, 48,
            	105, 56,
            	517, 64,
            1, 8, 1, /* 493: pointer.func */
            	498, 0,
            0, 0, 0, /* 498: func */
            1, 8, 1, /* 501: pointer.func */
            	506, 0,
            0, 0, 0, /* 506: func */
            1, 8, 1, /* 509: pointer.func */
            	514, 0,
            0, 0, 0, /* 514: func */
            1, 8, 1, /* 517: pointer.func */
            	522, 0,
            0, 0, 0, /* 522: func */
            1, 8, 1, /* 525: pointer.struct.ecdh_method */
            	530, 0,
            0, 32, 4, /* 530: struct.ecdh_method */
            	105, 0,
            	541, 8,
            	37, 16,
            	105, 24,
            1, 8, 1, /* 541: pointer.func */
            	546, 0,
            0, 0, 0, /* 546: func */
            1, 8, 1, /* 549: pointer.struct.ecdsa_method */
            	554, 0,
            0, 48, 6, /* 554: struct.ecdsa_method */
            	105, 0,
            	569, 8,
            	577, 16,
            	585, 24,
            	37, 32,
            	105, 40,
            1, 8, 1, /* 569: pointer.func */
            	574, 0,
            0, 0, 0, /* 574: func */
            1, 8, 1, /* 577: pointer.func */
            	582, 0,
            0, 0, 0, /* 582: func */
            1, 8, 1, /* 585: pointer.func */
            	590, 0,
            0, 0, 0, /* 590: func */
            1, 8, 1, /* 593: pointer.struct.rand_meth_st */
            	598, 0,
            0, 48, 6, /* 598: struct.rand_meth_st */
            	613, 0,
            	621, 8,
            	629, 16,
            	637, 24,
            	621, 32,
            	645, 40,
            1, 8, 1, /* 613: pointer.func */
            	618, 0,
            0, 0, 0, /* 618: func */
            1, 8, 1, /* 621: pointer.func */
            	626, 0,
            0, 0, 0, /* 626: func */
            1, 8, 1, /* 629: pointer.func */
            	634, 0,
            0, 0, 0, /* 634: func */
            1, 8, 1, /* 637: pointer.func */
            	642, 0,
            0, 0, 0, /* 642: func */
            1, 8, 1, /* 645: pointer.func */
            	650, 0,
            0, 0, 0, /* 650: func */
            1, 8, 1, /* 653: pointer.struct.store_method_st */
            	658, 0,
            0, 0, 0, /* 658: struct.store_method_st */
            1, 8, 1, /* 661: pointer.func */
            	666, 0,
            0, 0, 0, /* 666: func */
            1, 8, 1, /* 669: pointer.func */
            	674, 0,
            0, 0, 0, /* 674: func */
            1, 8, 1, /* 677: pointer.func */
            	682, 0,
            0, 0, 0, /* 682: func */
            1, 8, 1, /* 685: pointer.func */
            	690, 0,
            0, 0, 0, /* 690: func */
            1, 8, 1, /* 693: pointer.func */
            	698, 0,
            0, 0, 0, /* 698: func */
            1, 8, 1, /* 701: pointer.func */
            	706, 0,
            0, 0, 0, /* 706: func */
            1, 8, 1, /* 709: pointer.func */
            	714, 0,
            0, 0, 0, /* 714: func */
            1, 8, 1, /* 717: pointer.func */
            	722, 0,
            0, 0, 0, /* 722: func */
            1, 8, 1, /* 725: pointer.struct.ENGINE_CMD_DEFN_st */
            	730, 0,
            0, 32, 4, /* 730: struct.ENGINE_CMD_DEFN_st */
            	37, 0,
            	105, 8,
            	105, 16,
            	37, 24,
            0, 16, 2, /* 741: struct.crypto_ex_data_st */
            	748, 0,
            	37, 8,
            1, 8, 1, /* 748: pointer.struct.stack_st_OPENSSL_STRING */
            	753, 0,
            0, 32, 1, /* 753: struct.stack_st_OPENSSL_STRING */
            	758, 0,
            0, 32, 5, /* 758: struct.stack_st */
            	37, 0,
            	771, 8,
            	37, 16,
            	37, 20,
            	776, 24,
            1, 8, 1, /* 771: pointer.pointer.char */
            	105, 0,
            1, 8, 1, /* 776: pointer.func */
            	781, 0,
            0, 0, 0, /* 781: func */
            0, 8, 1, /* 784: struct.fnames */
            	105, 0,
            0, 0, 0, /* 789: func */
            1, 8, 1, /* 792: pointer.func */
            	789, 0,
            0, 0, 0, /* 797: func */
            1, 8, 1, /* 800: pointer.func */
            	797, 0,
            0, 0, 0, /* 805: func */
            1, 8, 1, /* 808: pointer.func */
            	805, 0,
            0, 0, 0, /* 813: func */
            1, 8, 1, /* 816: pointer.func */
            	813, 0,
            1, 8, 1, /* 821: pointer.func */
            	826, 0,
            0, 0, 0, /* 826: func */
            0, 80, 10, /* 829: struct.bio_method_st */
            	37, 0,
            	105, 8,
            	821, 16,
            	821, 24,
            	816, 32,
            	821, 40,
            	808, 48,
            	800, 56,
            	800, 64,
            	792, 72,
            0, 112, 15, /* 852: struct.bio_st */
            	885, 0,
            	890, 8,
            	105, 16,
            	37, 24,
            	37, 28,
            	37, 32,
            	37, 36,
            	37, 40,
            	105, 48,
            	898, 56,
            	898, 64,
            	37, 72,
            	102, 80,
            	102, 88,
            	741, 96,
            1, 8, 1, /* 885: pointer.struct.bio_method_st */
            	829, 0,
            1, 8, 1, /* 890: pointer.func */
            	895, 0,
            0, 0, 0, /* 895: func */
            1, 8, 1, /* 898: pointer.struct.bio_st */
            	852, 0,
        },
        .arg_entity_index = { 898, 8, 0, 105, },
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

