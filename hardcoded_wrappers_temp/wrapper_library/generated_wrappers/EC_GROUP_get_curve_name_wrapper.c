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

int bb_EC_GROUP_get_curve_name(const EC_GROUP * arg_a);

int EC_GROUP_get_curve_name(const EC_GROUP * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_GROUP_get_curve_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_GROUP_get_curve_name(arg_a);
    else {
        int (*orig_EC_GROUP_get_curve_name)(const EC_GROUP *);
        orig_EC_GROUP_get_curve_name = dlsym(RTLD_NEXT, "EC_GROUP_get_curve_name");
        return orig_EC_GROUP_get_curve_name(arg_a);
    }
}

int bb_EC_GROUP_get_curve_name(const EC_GROUP * arg_a) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 0; em[4] = 8; em[5] = 0; /* 3: pointer.void */
    em[6] = 1; em[7] = 8; em[8] = 1; /* 6: pointer.struct.ec_extra_data_st */
    	em[9] = 11; em[10] = 0; 
    em[11] = 0; em[12] = 40; em[13] = 5; /* 11: struct.ec_extra_data_st */
    	em[14] = 6; em[15] = 0; 
    	em[16] = 3; em[17] = 8; 
    	em[18] = 24; em[19] = 16; 
    	em[20] = 27; em[21] = 24; 
    	em[22] = 27; em[23] = 32; 
    em[24] = 8884097; em[25] = 8; em[26] = 0; /* 24: pointer.func */
    em[27] = 8884097; em[28] = 8; em[29] = 0; /* 27: pointer.func */
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.unsigned char */
    	em[33] = 35; em[34] = 0; 
    em[35] = 0; em[36] = 1; em[37] = 0; /* 35: unsigned char */
    em[38] = 0; em[39] = 24; em[40] = 1; /* 38: struct.bignum_st */
    	em[41] = 43; em[42] = 0; 
    em[43] = 8884099; em[44] = 8; em[45] = 2; /* 43: pointer_to_array_of_pointers_to_stack */
    	em[46] = 50; em[47] = 0; 
    	em[48] = 53; em[49] = 12; 
    em[50] = 0; em[51] = 8; em[52] = 0; /* 50: long unsigned int */
    em[53] = 0; em[54] = 4; em[55] = 0; /* 53: int */
    em[56] = 8884097; em[57] = 8; em[58] = 0; /* 56: pointer.func */
    em[59] = 8884097; em[60] = 8; em[61] = 0; /* 59: pointer.func */
    em[62] = 8884097; em[63] = 8; em[64] = 0; /* 62: pointer.func */
    em[65] = 8884097; em[66] = 8; em[67] = 0; /* 65: pointer.func */
    em[68] = 8884097; em[69] = 8; em[70] = 0; /* 68: pointer.func */
    em[71] = 8884097; em[72] = 8; em[73] = 0; /* 71: pointer.func */
    em[74] = 0; em[75] = 304; em[76] = 37; /* 74: struct.ec_method_st */
    	em[77] = 151; em[78] = 8; 
    	em[79] = 154; em[80] = 16; 
    	em[81] = 154; em[82] = 24; 
    	em[83] = 157; em[84] = 32; 
    	em[85] = 160; em[86] = 40; 
    	em[87] = 163; em[88] = 48; 
    	em[89] = 166; em[90] = 56; 
    	em[91] = 169; em[92] = 64; 
    	em[93] = 172; em[94] = 72; 
    	em[95] = 175; em[96] = 80; 
    	em[97] = 175; em[98] = 88; 
    	em[99] = 178; em[100] = 96; 
    	em[101] = 181; em[102] = 104; 
    	em[103] = 184; em[104] = 112; 
    	em[105] = 187; em[106] = 120; 
    	em[107] = 190; em[108] = 128; 
    	em[109] = 193; em[110] = 136; 
    	em[111] = 196; em[112] = 144; 
    	em[113] = 199; em[114] = 152; 
    	em[115] = 202; em[116] = 160; 
    	em[117] = 205; em[118] = 168; 
    	em[119] = 208; em[120] = 176; 
    	em[121] = 211; em[122] = 184; 
    	em[123] = 71; em[124] = 192; 
    	em[125] = 214; em[126] = 200; 
    	em[127] = 217; em[128] = 208; 
    	em[129] = 211; em[130] = 216; 
    	em[131] = 220; em[132] = 224; 
    	em[133] = 223; em[134] = 232; 
    	em[135] = 226; em[136] = 240; 
    	em[137] = 166; em[138] = 248; 
    	em[139] = 229; em[140] = 256; 
    	em[141] = 232; em[142] = 264; 
    	em[143] = 229; em[144] = 272; 
    	em[145] = 232; em[146] = 280; 
    	em[147] = 232; em[148] = 288; 
    	em[149] = 235; em[150] = 296; 
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
    em[220] = 8884097; em[221] = 8; em[222] = 0; /* 220: pointer.func */
    em[223] = 8884097; em[224] = 8; em[225] = 0; /* 223: pointer.func */
    em[226] = 8884097; em[227] = 8; em[228] = 0; /* 226: pointer.func */
    em[229] = 8884097; em[230] = 8; em[231] = 0; /* 229: pointer.func */
    em[232] = 8884097; em[233] = 8; em[234] = 0; /* 232: pointer.func */
    em[235] = 8884097; em[236] = 8; em[237] = 0; /* 235: pointer.func */
    em[238] = 8884097; em[239] = 8; em[240] = 0; /* 238: pointer.func */
    em[241] = 1; em[242] = 8; em[243] = 1; /* 241: pointer.struct.ec_method_st */
    	em[244] = 74; em[245] = 0; 
    em[246] = 8884097; em[247] = 8; em[248] = 0; /* 246: pointer.func */
    em[249] = 8884097; em[250] = 8; em[251] = 0; /* 249: pointer.func */
    em[252] = 1; em[253] = 8; em[254] = 1; /* 252: pointer.struct.ec_extra_data_st */
    	em[255] = 11; em[256] = 0; 
    em[257] = 8884097; em[258] = 8; em[259] = 0; /* 257: pointer.func */
    em[260] = 8884097; em[261] = 8; em[262] = 0; /* 260: pointer.func */
    em[263] = 1; em[264] = 8; em[265] = 1; /* 263: pointer.struct.ec_group_st */
    	em[266] = 268; em[267] = 0; 
    em[268] = 0; em[269] = 232; em[270] = 12; /* 268: struct.ec_group_st */
    	em[271] = 241; em[272] = 0; 
    	em[273] = 295; em[274] = 8; 
    	em[275] = 38; em[276] = 16; 
    	em[277] = 38; em[278] = 40; 
    	em[279] = 30; em[280] = 80; 
    	em[281] = 252; em[282] = 96; 
    	em[283] = 38; em[284] = 104; 
    	em[285] = 38; em[286] = 152; 
    	em[287] = 38; em[288] = 176; 
    	em[289] = 3; em[290] = 208; 
    	em[291] = 3; em[292] = 216; 
    	em[293] = 0; em[294] = 224; 
    em[295] = 1; em[296] = 8; em[297] = 1; /* 295: pointer.struct.ec_point_st */
    	em[298] = 300; em[299] = 0; 
    em[300] = 0; em[301] = 88; em[302] = 4; /* 300: struct.ec_point_st */
    	em[303] = 311; em[304] = 0; 
    	em[305] = 453; em[306] = 8; 
    	em[307] = 453; em[308] = 32; 
    	em[309] = 453; em[310] = 56; 
    em[311] = 1; em[312] = 8; em[313] = 1; /* 311: pointer.struct.ec_method_st */
    	em[314] = 316; em[315] = 0; 
    em[316] = 0; em[317] = 304; em[318] = 37; /* 316: struct.ec_method_st */
    	em[319] = 393; em[320] = 8; 
    	em[321] = 396; em[322] = 16; 
    	em[323] = 396; em[324] = 24; 
    	em[325] = 399; em[326] = 32; 
    	em[327] = 402; em[328] = 40; 
    	em[329] = 405; em[330] = 48; 
    	em[331] = 408; em[332] = 56; 
    	em[333] = 411; em[334] = 64; 
    	em[335] = 414; em[336] = 72; 
    	em[337] = 417; em[338] = 80; 
    	em[339] = 417; em[340] = 88; 
    	em[341] = 420; em[342] = 96; 
    	em[343] = 423; em[344] = 104; 
    	em[345] = 426; em[346] = 112; 
    	em[347] = 429; em[348] = 120; 
    	em[349] = 246; em[350] = 128; 
    	em[351] = 432; em[352] = 136; 
    	em[353] = 435; em[354] = 144; 
    	em[355] = 257; em[356] = 152; 
    	em[357] = 438; em[358] = 160; 
    	em[359] = 441; em[360] = 168; 
    	em[361] = 444; em[362] = 176; 
    	em[363] = 447; em[364] = 184; 
    	em[365] = 260; em[366] = 192; 
    	em[367] = 68; em[368] = 200; 
    	em[369] = 249; em[370] = 208; 
    	em[371] = 447; em[372] = 216; 
    	em[373] = 65; em[374] = 224; 
    	em[375] = 62; em[376] = 232; 
    	em[377] = 238; em[378] = 240; 
    	em[379] = 408; em[380] = 248; 
    	em[381] = 59; em[382] = 256; 
    	em[383] = 450; em[384] = 264; 
    	em[385] = 59; em[386] = 272; 
    	em[387] = 450; em[388] = 280; 
    	em[389] = 450; em[390] = 288; 
    	em[391] = 56; em[392] = 296; 
    em[393] = 8884097; em[394] = 8; em[395] = 0; /* 393: pointer.func */
    em[396] = 8884097; em[397] = 8; em[398] = 0; /* 396: pointer.func */
    em[399] = 8884097; em[400] = 8; em[401] = 0; /* 399: pointer.func */
    em[402] = 8884097; em[403] = 8; em[404] = 0; /* 402: pointer.func */
    em[405] = 8884097; em[406] = 8; em[407] = 0; /* 405: pointer.func */
    em[408] = 8884097; em[409] = 8; em[410] = 0; /* 408: pointer.func */
    em[411] = 8884097; em[412] = 8; em[413] = 0; /* 411: pointer.func */
    em[414] = 8884097; em[415] = 8; em[416] = 0; /* 414: pointer.func */
    em[417] = 8884097; em[418] = 8; em[419] = 0; /* 417: pointer.func */
    em[420] = 8884097; em[421] = 8; em[422] = 0; /* 420: pointer.func */
    em[423] = 8884097; em[424] = 8; em[425] = 0; /* 423: pointer.func */
    em[426] = 8884097; em[427] = 8; em[428] = 0; /* 426: pointer.func */
    em[429] = 8884097; em[430] = 8; em[431] = 0; /* 429: pointer.func */
    em[432] = 8884097; em[433] = 8; em[434] = 0; /* 432: pointer.func */
    em[435] = 8884097; em[436] = 8; em[437] = 0; /* 435: pointer.func */
    em[438] = 8884097; em[439] = 8; em[440] = 0; /* 438: pointer.func */
    em[441] = 8884097; em[442] = 8; em[443] = 0; /* 441: pointer.func */
    em[444] = 8884097; em[445] = 8; em[446] = 0; /* 444: pointer.func */
    em[447] = 8884097; em[448] = 8; em[449] = 0; /* 447: pointer.func */
    em[450] = 8884097; em[451] = 8; em[452] = 0; /* 450: pointer.func */
    em[453] = 0; em[454] = 24; em[455] = 1; /* 453: struct.bignum_st */
    	em[456] = 458; em[457] = 0; 
    em[458] = 8884099; em[459] = 8; em[460] = 2; /* 458: pointer_to_array_of_pointers_to_stack */
    	em[461] = 50; em[462] = 0; 
    	em[463] = 53; em[464] = 12; 
    args_addr->arg_entity_index[0] = 263;
    args_addr->ret_entity_index = 53;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EC_GROUP * new_arg_a = *((const EC_GROUP * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EC_GROUP_get_curve_name)(const EC_GROUP *);
    orig_EC_GROUP_get_curve_name = dlsym(RTLD_NEXT, "EC_GROUP_get_curve_name");
    *new_ret_ptr = (*orig_EC_GROUP_get_curve_name)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

