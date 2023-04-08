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

EC_KEY * bb_EC_KEY_new_by_curve_name(int arg_a);

EC_KEY * EC_KEY_new_by_curve_name(int arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_KEY_new_by_curve_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_KEY_new_by_curve_name(arg_a);
    else {
        EC_KEY * (*orig_EC_KEY_new_by_curve_name)(int);
        orig_EC_KEY_new_by_curve_name = dlsym(RTLD_NEXT, "EC_KEY_new_by_curve_name");
        return orig_EC_KEY_new_by_curve_name(arg_a);
    }
}

EC_KEY * bb_EC_KEY_new_by_curve_name(int arg_a) 
{
    EC_KEY * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.ec_extra_data_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 40; em[7] = 5; /* 5: struct.ec_extra_data_st */
    	em[8] = 18; em[9] = 0; 
    	em[10] = 23; em[11] = 8; 
    	em[12] = 26; em[13] = 16; 
    	em[14] = 29; em[15] = 24; 
    	em[16] = 29; em[17] = 32; 
    em[18] = 1; em[19] = 8; em[20] = 1; /* 18: pointer.struct.ec_extra_data_st */
    	em[21] = 5; em[22] = 0; 
    em[23] = 0; em[24] = 8; em[25] = 0; /* 23: pointer.void */
    em[26] = 8884097; em[27] = 8; em[28] = 0; /* 26: pointer.func */
    em[29] = 8884097; em[30] = 8; em[31] = 0; /* 29: pointer.func */
    em[32] = 1; em[33] = 8; em[34] = 1; /* 32: pointer.struct.ec_point_st */
    	em[35] = 37; em[36] = 0; 
    em[37] = 0; em[38] = 88; em[39] = 4; /* 37: struct.ec_point_st */
    	em[40] = 48; em[41] = 0; 
    	em[42] = 220; em[43] = 8; 
    	em[44] = 220; em[45] = 32; 
    	em[46] = 220; em[47] = 56; 
    em[48] = 1; em[49] = 8; em[50] = 1; /* 48: pointer.struct.ec_method_st */
    	em[51] = 53; em[52] = 0; 
    em[53] = 0; em[54] = 304; em[55] = 37; /* 53: struct.ec_method_st */
    	em[56] = 130; em[57] = 8; 
    	em[58] = 133; em[59] = 16; 
    	em[60] = 133; em[61] = 24; 
    	em[62] = 136; em[63] = 32; 
    	em[64] = 139; em[65] = 40; 
    	em[66] = 142; em[67] = 48; 
    	em[68] = 145; em[69] = 56; 
    	em[70] = 148; em[71] = 64; 
    	em[72] = 151; em[73] = 72; 
    	em[74] = 154; em[75] = 80; 
    	em[76] = 154; em[77] = 88; 
    	em[78] = 157; em[79] = 96; 
    	em[80] = 160; em[81] = 104; 
    	em[82] = 163; em[83] = 112; 
    	em[84] = 166; em[85] = 120; 
    	em[86] = 169; em[87] = 128; 
    	em[88] = 172; em[89] = 136; 
    	em[90] = 175; em[91] = 144; 
    	em[92] = 178; em[93] = 152; 
    	em[94] = 181; em[95] = 160; 
    	em[96] = 184; em[97] = 168; 
    	em[98] = 187; em[99] = 176; 
    	em[100] = 190; em[101] = 184; 
    	em[102] = 193; em[103] = 192; 
    	em[104] = 196; em[105] = 200; 
    	em[106] = 199; em[107] = 208; 
    	em[108] = 190; em[109] = 216; 
    	em[110] = 202; em[111] = 224; 
    	em[112] = 205; em[113] = 232; 
    	em[114] = 208; em[115] = 240; 
    	em[116] = 145; em[117] = 248; 
    	em[118] = 211; em[119] = 256; 
    	em[120] = 214; em[121] = 264; 
    	em[122] = 211; em[123] = 272; 
    	em[124] = 214; em[125] = 280; 
    	em[126] = 214; em[127] = 288; 
    	em[128] = 217; em[129] = 296; 
    em[130] = 8884097; em[131] = 8; em[132] = 0; /* 130: pointer.func */
    em[133] = 8884097; em[134] = 8; em[135] = 0; /* 133: pointer.func */
    em[136] = 8884097; em[137] = 8; em[138] = 0; /* 136: pointer.func */
    em[139] = 8884097; em[140] = 8; em[141] = 0; /* 139: pointer.func */
    em[142] = 8884097; em[143] = 8; em[144] = 0; /* 142: pointer.func */
    em[145] = 8884097; em[146] = 8; em[147] = 0; /* 145: pointer.func */
    em[148] = 8884097; em[149] = 8; em[150] = 0; /* 148: pointer.func */
    em[151] = 8884097; em[152] = 8; em[153] = 0; /* 151: pointer.func */
    em[154] = 8884097; em[155] = 8; em[156] = 0; /* 154: pointer.func */
    em[157] = 8884097; em[158] = 8; em[159] = 0; /* 157: pointer.func */
    em[160] = 8884097; em[161] = 8; em[162] = 0; /* 160: pointer.func */
    em[163] = 8884097; em[164] = 8; em[165] = 0; /* 163: pointer.func */
    em[166] = 8884097; em[167] = 8; em[168] = 0; /* 166: pointer.func */
    em[169] = 8884097; em[170] = 8; em[171] = 0; /* 169: pointer.func */
    em[172] = 8884097; em[173] = 8; em[174] = 0; /* 172: pointer.func */
    em[175] = 8884097; em[176] = 8; em[177] = 0; /* 175: pointer.func */
    em[178] = 8884097; em[179] = 8; em[180] = 0; /* 178: pointer.func */
    em[181] = 8884097; em[182] = 8; em[183] = 0; /* 181: pointer.func */
    em[184] = 8884097; em[185] = 8; em[186] = 0; /* 184: pointer.func */
    em[187] = 8884097; em[188] = 8; em[189] = 0; /* 187: pointer.func */
    em[190] = 8884097; em[191] = 8; em[192] = 0; /* 190: pointer.func */
    em[193] = 8884097; em[194] = 8; em[195] = 0; /* 193: pointer.func */
    em[196] = 8884097; em[197] = 8; em[198] = 0; /* 196: pointer.func */
    em[199] = 8884097; em[200] = 8; em[201] = 0; /* 199: pointer.func */
    em[202] = 8884097; em[203] = 8; em[204] = 0; /* 202: pointer.func */
    em[205] = 8884097; em[206] = 8; em[207] = 0; /* 205: pointer.func */
    em[208] = 8884097; em[209] = 8; em[210] = 0; /* 208: pointer.func */
    em[211] = 8884097; em[212] = 8; em[213] = 0; /* 211: pointer.func */
    em[214] = 8884097; em[215] = 8; em[216] = 0; /* 214: pointer.func */
    em[217] = 8884097; em[218] = 8; em[219] = 0; /* 217: pointer.func */
    em[220] = 0; em[221] = 24; em[222] = 1; /* 220: struct.bignum_st */
    	em[223] = 225; em[224] = 0; 
    em[225] = 8884099; em[226] = 8; em[227] = 2; /* 225: pointer_to_array_of_pointers_to_stack */
    	em[228] = 232; em[229] = 0; 
    	em[230] = 235; em[231] = 12; 
    em[232] = 0; em[233] = 8; em[234] = 0; /* 232: long unsigned int */
    em[235] = 0; em[236] = 4; em[237] = 0; /* 235: int */
    em[238] = 1; em[239] = 8; em[240] = 1; /* 238: pointer.struct.ec_extra_data_st */
    	em[241] = 243; em[242] = 0; 
    em[243] = 0; em[244] = 40; em[245] = 5; /* 243: struct.ec_extra_data_st */
    	em[246] = 256; em[247] = 0; 
    	em[248] = 23; em[249] = 8; 
    	em[250] = 26; em[251] = 16; 
    	em[252] = 29; em[253] = 24; 
    	em[254] = 29; em[255] = 32; 
    em[256] = 1; em[257] = 8; em[258] = 1; /* 256: pointer.struct.ec_extra_data_st */
    	em[259] = 243; em[260] = 0; 
    em[261] = 1; em[262] = 8; em[263] = 1; /* 261: pointer.unsigned char */
    	em[264] = 266; em[265] = 0; 
    em[266] = 0; em[267] = 1; em[268] = 0; /* 266: unsigned char */
    em[269] = 8884099; em[270] = 8; em[271] = 2; /* 269: pointer_to_array_of_pointers_to_stack */
    	em[272] = 232; em[273] = 0; 
    	em[274] = 235; em[275] = 12; 
    em[276] = 1; em[277] = 8; em[278] = 1; /* 276: pointer.struct.ec_group_st */
    	em[279] = 281; em[280] = 0; 
    em[281] = 0; em[282] = 232; em[283] = 12; /* 281: struct.ec_group_st */
    	em[284] = 48; em[285] = 0; 
    	em[286] = 308; em[287] = 8; 
    	em[288] = 220; em[289] = 16; 
    	em[290] = 220; em[291] = 40; 
    	em[292] = 261; em[293] = 80; 
    	em[294] = 238; em[295] = 96; 
    	em[296] = 220; em[297] = 104; 
    	em[298] = 220; em[299] = 152; 
    	em[300] = 220; em[301] = 176; 
    	em[302] = 23; em[303] = 208; 
    	em[304] = 23; em[305] = 216; 
    	em[306] = 313; em[307] = 224; 
    em[308] = 1; em[309] = 8; em[310] = 1; /* 308: pointer.struct.ec_point_st */
    	em[311] = 37; em[312] = 0; 
    em[313] = 8884097; em[314] = 8; em[315] = 0; /* 313: pointer.func */
    em[316] = 1; em[317] = 8; em[318] = 1; /* 316: pointer.struct.bignum_st */
    	em[319] = 321; em[320] = 0; 
    em[321] = 0; em[322] = 24; em[323] = 1; /* 321: struct.bignum_st */
    	em[324] = 269; em[325] = 0; 
    em[326] = 1; em[327] = 8; em[328] = 1; /* 326: pointer.struct.ec_key_st */
    	em[329] = 331; em[330] = 0; 
    em[331] = 0; em[332] = 56; em[333] = 4; /* 331: struct.ec_key_st */
    	em[334] = 276; em[335] = 8; 
    	em[336] = 32; em[337] = 16; 
    	em[338] = 316; em[339] = 24; 
    	em[340] = 0; em[341] = 48; 
    args_addr->arg_entity_index[0] = 235;
    args_addr->ret_entity_index = 326;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    int new_arg_a = *((int *)new_args->args[0]);

    EC_KEY * *new_ret_ptr = (EC_KEY * *)new_args->ret;

    EC_KEY * (*orig_EC_KEY_new_by_curve_name)(int);
    orig_EC_KEY_new_by_curve_name = dlsym(RTLD_NEXT, "EC_KEY_new_by_curve_name");
    *new_ret_ptr = (*orig_EC_KEY_new_by_curve_name)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

