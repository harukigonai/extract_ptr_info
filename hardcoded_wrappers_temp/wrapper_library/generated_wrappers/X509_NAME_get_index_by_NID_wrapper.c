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
    em[15] = 1; em[16] = 8; em[17] = 1; /* 15: pointer.struct.asn1_string_st */
    	em[18] = 20; em[19] = 0; 
    em[20] = 0; em[21] = 24; em[22] = 1; /* 20: struct.asn1_string_st */
    	em[23] = 25; em[24] = 8; 
    em[25] = 1; em[26] = 8; em[27] = 1; /* 25: pointer.unsigned char */
    	em[28] = 30; em[29] = 0; 
    em[30] = 0; em[31] = 1; em[32] = 0; /* 30: unsigned char */
    em[33] = 1; em[34] = 8; em[35] = 1; /* 33: pointer.unsigned char */
    	em[36] = 30; em[37] = 0; 
    em[38] = 0; em[39] = 1; em[40] = 0; /* 38: char */
    em[41] = 8884097; em[42] = 8; em[43] = 0; /* 41: pointer.func */
    em[44] = 1; em[45] = 8; em[46] = 1; /* 44: pointer.struct.X509_name_st */
    	em[47] = 49; em[48] = 0; 
    em[49] = 0; em[50] = 40; em[51] = 3; /* 49: struct.X509_name_st */
    	em[52] = 58; em[53] = 0; 
    	em[54] = 10; em[55] = 16; 
    	em[56] = 25; em[57] = 24; 
    em[58] = 1; em[59] = 8; em[60] = 1; /* 58: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[61] = 63; em[62] = 0; 
    em[63] = 0; em[64] = 32; em[65] = 2; /* 63: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[66] = 70; em[67] = 8; 
    	em[68] = 41; em[69] = 24; 
    em[70] = 8884099; em[71] = 8; em[72] = 2; /* 70: pointer_to_array_of_pointers_to_stack */
    	em[73] = 77; em[74] = 0; 
    	em[75] = 113; em[76] = 20; 
    em[77] = 0; em[78] = 8; em[79] = 1; /* 77: pointer.X509_NAME_ENTRY */
    	em[80] = 82; em[81] = 0; 
    em[82] = 0; em[83] = 0; em[84] = 1; /* 82: X509_NAME_ENTRY */
    	em[85] = 87; em[86] = 0; 
    em[87] = 0; em[88] = 24; em[89] = 2; /* 87: struct.X509_name_entry_st */
    	em[90] = 94; em[91] = 0; 
    	em[92] = 15; em[93] = 8; 
    em[94] = 1; em[95] = 8; em[96] = 1; /* 94: pointer.struct.asn1_object_st */
    	em[97] = 99; em[98] = 0; 
    em[99] = 0; em[100] = 40; em[101] = 3; /* 99: struct.asn1_object_st */
    	em[102] = 108; em[103] = 0; 
    	em[104] = 108; em[105] = 8; 
    	em[106] = 33; em[107] = 24; 
    em[108] = 1; em[109] = 8; em[110] = 1; /* 108: pointer.char */
    	em[111] = 8884096; em[112] = 0; 
    em[113] = 0; em[114] = 4; em[115] = 0; /* 113: int */
    args_addr->arg_entity_index[0] = 44;
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

