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

int bb_X509_NAME_get_index_by_NID(X509_NAME * arg_a,int arg_b,int arg_c);

int X509_NAME_get_index_by_NID(X509_NAME * arg_a,int arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_NAME_get_index_by_NID called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_NAME_get_index_by_NID(arg_a,arg_b,arg_c);
    else {
        int (*orig_X509_NAME_get_index_by_NID)(X509_NAME *,int,int);
        orig_X509_NAME_get_index_by_NID = dlsym(RTLD_NEXT, "X509_NAME_get_index_by_NID");
        return orig_X509_NAME_get_index_by_NID(arg_a,arg_b,arg_c);
    }
}

int bb_X509_NAME_get_index_by_NID(X509_NAME * arg_a,int arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.char */
    	em[3] = 8884096; em[4] = 0; 
    em[5] = 0; em[6] = 24; em[7] = 1; /* 5: struct.buf_mem_st */
    	em[8] = 0; em[9] = 8; 
    em[10] = 1; em[11] = 8; em[12] = 1; /* 10: pointer.struct.buf_mem_st */
    	em[13] = 5; em[14] = 0; 
    em[15] = 0; em[16] = 1; em[17] = 0; /* 15: unsigned char */
    em[18] = 1; em[19] = 8; em[20] = 1; /* 18: pointer.struct.asn1_string_st */
    	em[21] = 23; em[22] = 0; 
    em[23] = 0; em[24] = 24; em[25] = 1; /* 23: struct.asn1_string_st */
    	em[26] = 28; em[27] = 8; 
    em[28] = 1; em[29] = 8; em[30] = 1; /* 28: pointer.unsigned char */
    	em[31] = 15; em[32] = 0; 
    em[33] = 1; em[34] = 8; em[35] = 1; /* 33: pointer.unsigned char */
    	em[36] = 15; em[37] = 0; 
    em[38] = 0; em[39] = 8; em[40] = 1; /* 38: pointer.X509_NAME_ENTRY */
    	em[41] = 43; em[42] = 0; 
    em[43] = 0; em[44] = 0; em[45] = 1; /* 43: X509_NAME_ENTRY */
    	em[46] = 48; em[47] = 0; 
    em[48] = 0; em[49] = 24; em[50] = 2; /* 48: struct.X509_name_entry_st */
    	em[51] = 55; em[52] = 0; 
    	em[53] = 18; em[54] = 8; 
    em[55] = 1; em[56] = 8; em[57] = 1; /* 55: pointer.struct.asn1_object_st */
    	em[58] = 60; em[59] = 0; 
    em[60] = 0; em[61] = 40; em[62] = 3; /* 60: struct.asn1_object_st */
    	em[63] = 69; em[64] = 0; 
    	em[65] = 69; em[66] = 8; 
    	em[67] = 33; em[68] = 24; 
    em[69] = 1; em[70] = 8; em[71] = 1; /* 69: pointer.char */
    	em[72] = 8884096; em[73] = 0; 
    em[74] = 0; em[75] = 1; em[76] = 0; /* 74: char */
    em[77] = 8884097; em[78] = 8; em[79] = 0; /* 77: pointer.func */
    em[80] = 1; em[81] = 8; em[82] = 1; /* 80: pointer.struct.X509_name_st */
    	em[83] = 85; em[84] = 0; 
    em[85] = 0; em[86] = 40; em[87] = 3; /* 85: struct.X509_name_st */
    	em[88] = 94; em[89] = 0; 
    	em[90] = 10; em[91] = 16; 
    	em[92] = 28; em[93] = 24; 
    em[94] = 1; em[95] = 8; em[96] = 1; /* 94: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[97] = 99; em[98] = 0; 
    em[99] = 0; em[100] = 32; em[101] = 2; /* 99: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[102] = 106; em[103] = 8; 
    	em[104] = 77; em[105] = 24; 
    em[106] = 8884099; em[107] = 8; em[108] = 2; /* 106: pointer_to_array_of_pointers_to_stack */
    	em[109] = 38; em[110] = 0; 
    	em[111] = 113; em[112] = 20; 
    em[113] = 0; em[114] = 4; em[115] = 0; /* 113: int */
    args_addr->arg_entity_index[0] = 80;
    args_addr->arg_entity_index[1] = 113;
    args_addr->arg_entity_index[2] = 113;
    args_addr->ret_entity_index = 113;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_NAME * new_arg_a = *((X509_NAME * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_NAME_get_index_by_NID)(X509_NAME *,int,int);
    orig_X509_NAME_get_index_by_NID = dlsym(RTLD_NEXT, "X509_NAME_get_index_by_NID");
    *new_ret_ptr = (*orig_X509_NAME_get_index_by_NID)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    free(args_addr);

    return ret;
}

