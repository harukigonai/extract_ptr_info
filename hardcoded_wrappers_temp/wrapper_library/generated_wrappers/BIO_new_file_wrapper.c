#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
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

BIO * bb_BIO_new_file(const char * arg_a,const char * arg_b);

BIO * BIO_new_file(const char * arg_a,const char * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_new_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_new_file(arg_a,arg_b);
    else {
        BIO * (*orig_BIO_new_file)(const char *,const char *);
        orig_BIO_new_file = dlsym(RTLD_NEXT, "BIO_new_file");
        return orig_BIO_new_file(arg_a,arg_b);
    }
}

BIO * bb_BIO_new_file(const char * arg_a,const char * arg_b) 
{
    BIO * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 1; em[4] = 8; em[5] = 1; /* 3: pointer.pointer.char */
    	em[6] = 8; em[7] = 0; 
    em[8] = 1; em[9] = 8; em[10] = 1; /* 8: pointer.char */
    	em[11] = 8884096; em[12] = 0; 
    em[13] = 0; em[14] = 32; em[15] = 1; /* 13: struct.stack_st_void */
    	em[16] = 18; em[17] = 0; 
    em[18] = 0; em[19] = 32; em[20] = 2; /* 18: struct.stack_st */
    	em[21] = 3; em[22] = 8; 
    	em[23] = 0; em[24] = 24; 
    em[25] = 1; em[26] = 8; em[27] = 1; /* 25: pointer.struct.bio_st */
    	em[28] = 30; em[29] = 0; 
    em[30] = 0; em[31] = 112; em[32] = 7; /* 30: struct.bio_st */
    	em[33] = 47; em[34] = 0; 
    	em[35] = 96; em[36] = 8; 
    	em[37] = 8; em[38] = 16; 
    	em[39] = 99; em[40] = 48; 
    	em[41] = 25; em[42] = 56; 
    	em[43] = 25; em[44] = 64; 
    	em[45] = 102; em[46] = 96; 
    em[47] = 1; em[48] = 8; em[49] = 1; /* 47: pointer.struct.bio_method_st */
    	em[50] = 52; em[51] = 0; 
    em[52] = 0; em[53] = 80; em[54] = 9; /* 52: struct.bio_method_st */
    	em[55] = 73; em[56] = 8; 
    	em[57] = 78; em[58] = 16; 
    	em[59] = 81; em[60] = 24; 
    	em[61] = 84; em[62] = 32; 
    	em[63] = 81; em[64] = 40; 
    	em[65] = 87; em[66] = 48; 
    	em[67] = 90; em[68] = 56; 
    	em[69] = 90; em[70] = 64; 
    	em[71] = 93; em[72] = 72; 
    em[73] = 1; em[74] = 8; em[75] = 1; /* 73: pointer.char */
    	em[76] = 8884096; em[77] = 0; 
    em[78] = 8884097; em[79] = 8; em[80] = 0; /* 78: pointer.func */
    em[81] = 8884097; em[82] = 8; em[83] = 0; /* 81: pointer.func */
    em[84] = 8884097; em[85] = 8; em[86] = 0; /* 84: pointer.func */
    em[87] = 8884097; em[88] = 8; em[89] = 0; /* 87: pointer.func */
    em[90] = 8884097; em[91] = 8; em[92] = 0; /* 90: pointer.func */
    em[93] = 8884097; em[94] = 8; em[95] = 0; /* 93: pointer.func */
    em[96] = 8884097; em[97] = 8; em[98] = 0; /* 96: pointer.func */
    em[99] = 0; em[100] = 8; em[101] = 0; /* 99: pointer.void */
    em[102] = 0; em[103] = 16; em[104] = 1; /* 102: struct.crypto_ex_data_st */
    	em[105] = 107; em[106] = 0; 
    em[107] = 1; em[108] = 8; em[109] = 1; /* 107: pointer.struct.stack_st_void */
    	em[110] = 13; em[111] = 0; 
    em[112] = 1; em[113] = 8; em[114] = 1; /* 112: pointer.struct.bio_st */
    	em[115] = 30; em[116] = 0; 
    em[117] = 0; em[118] = 1; em[119] = 0; /* 117: char */
    args_addr->arg_entity_index[0] = 73;
    args_addr->arg_entity_index[1] = 73;
    args_addr->ret_entity_index = 112;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const char * new_arg_a = *((const char * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    BIO * *new_ret_ptr = (BIO * *)new_args->ret;

    BIO * (*orig_BIO_new_file)(const char *,const char *);
    orig_BIO_new_file = dlsym(RTLD_NEXT, "BIO_new_file");
    *new_ret_ptr = (*orig_BIO_new_file)(new_arg_a,new_arg_b);

    syscall(889);

    free(args_addr);

    return ret;
}

