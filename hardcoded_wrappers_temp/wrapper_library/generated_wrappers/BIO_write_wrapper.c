#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
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

int bb_BIO_write(BIO * arg_a,const void * arg_b,int arg_c);

int BIO_write(BIO * arg_a,const void * arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_write called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_write(arg_a,arg_b,arg_c);
    else {
        int (*orig_BIO_write)(BIO *,const void *,int);
        orig_BIO_write = dlsym(RTLD_NEXT, "BIO_write");
        return orig_BIO_write(arg_a,arg_b,arg_c);
    }
}

int bb_BIO_write(BIO * arg_a,const void * arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
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
    em[25] = 0; em[26] = 16; em[27] = 1; /* 25: struct.crypto_ex_data_st */
    	em[28] = 30; em[29] = 0; 
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.struct.stack_st_void */
    	em[33] = 13; em[34] = 0; 
    em[35] = 1; em[36] = 8; em[37] = 1; /* 35: pointer.struct.bio_st */
    	em[38] = 40; em[39] = 0; 
    em[40] = 0; em[41] = 112; em[42] = 7; /* 40: struct.bio_st */
    	em[43] = 57; em[44] = 0; 
    	em[45] = 106; em[46] = 8; 
    	em[47] = 8; em[48] = 16; 
    	em[49] = 109; em[50] = 48; 
    	em[51] = 35; em[52] = 56; 
    	em[53] = 35; em[54] = 64; 
    	em[55] = 25; em[56] = 96; 
    em[57] = 1; em[58] = 8; em[59] = 1; /* 57: pointer.struct.bio_method_st */
    	em[60] = 62; em[61] = 0; 
    em[62] = 0; em[63] = 80; em[64] = 9; /* 62: struct.bio_method_st */
    	em[65] = 83; em[66] = 8; 
    	em[67] = 88; em[68] = 16; 
    	em[69] = 91; em[70] = 24; 
    	em[71] = 94; em[72] = 32; 
    	em[73] = 91; em[74] = 40; 
    	em[75] = 97; em[76] = 48; 
    	em[77] = 100; em[78] = 56; 
    	em[79] = 100; em[80] = 64; 
    	em[81] = 103; em[82] = 72; 
    em[83] = 1; em[84] = 8; em[85] = 1; /* 83: pointer.char */
    	em[86] = 8884096; em[87] = 0; 
    em[88] = 8884097; em[89] = 8; em[90] = 0; /* 88: pointer.func */
    em[91] = 8884097; em[92] = 8; em[93] = 0; /* 91: pointer.func */
    em[94] = 8884097; em[95] = 8; em[96] = 0; /* 94: pointer.func */
    em[97] = 8884097; em[98] = 8; em[99] = 0; /* 97: pointer.func */
    em[100] = 8884097; em[101] = 8; em[102] = 0; /* 100: pointer.func */
    em[103] = 8884097; em[104] = 8; em[105] = 0; /* 103: pointer.func */
    em[106] = 8884097; em[107] = 8; em[108] = 0; /* 106: pointer.func */
    em[109] = 0; em[110] = 8; em[111] = 0; /* 109: pointer.void */
    em[112] = 0; em[113] = 1; em[114] = 0; /* 112: char */
    em[115] = 1; em[116] = 8; em[117] = 1; /* 115: pointer.struct.bio_st */
    	em[118] = 40; em[119] = 0; 
    em[120] = 0; em[121] = 4; em[122] = 0; /* 120: int */
    args_addr->arg_entity_index[0] = 115;
    args_addr->arg_entity_index[1] = 109;
    args_addr->arg_entity_index[2] = 120;
    args_addr->ret_entity_index = 120;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    const void * new_arg_b = *((const void * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_BIO_write)(BIO *,const void *,int);
    orig_BIO_write = dlsym(RTLD_NEXT, "BIO_write");
    *new_ret_ptr = (*orig_BIO_write)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    free(args_addr);

    return ret;
}

