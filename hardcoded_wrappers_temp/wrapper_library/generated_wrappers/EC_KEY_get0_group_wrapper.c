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

const EC_GROUP * bb_EC_KEY_get0_group(const EC_KEY * arg_a);

const EC_GROUP * EC_KEY_get0_group(const EC_KEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_KEY_get0_group called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_KEY_get0_group(arg_a);
    else {
        const EC_GROUP * (*orig_EC_KEY_get0_group)(const EC_KEY *);
        orig_EC_KEY_get0_group = dlsym(RTLD_NEXT, "EC_KEY_get0_group");
        return orig_EC_KEY_get0_group(arg_a);
    }
}

const EC_GROUP * bb_EC_KEY_get0_group(const EC_KEY * arg_a) 
{
    const EC_GROUP * ret;

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
    em[32] = 0; em[33] = 24; em[34] = 1; /* 32: struct.bignum_st */
    	em[35] = 37; em[36] = 0; 
    em[37] = 8884099; em[38] = 8; em[39] = 2; /* 37: pointer_to_array_of_pointers_to_stack */
    	em[40] = 44; em[41] = 0; 
    	em[42] = 47; em[43] = 12; 
    em[44] = 0; em[45] = 8; em[46] = 0; /* 44: long unsigned int */
    em[47] = 0; em[48] = 4; em[49] = 0; /* 47: int */
    em[50] = 1; em[51] = 8; em[52] = 1; /* 50: pointer.struct.bignum_st */
    	em[53] = 32; em[54] = 0; 
    em[55] = 1; em[56] = 8; em[57] = 1; /* 55: pointer.struct.ec_group_st */
    	em[58] = 60; em[59] = 0; 
    em[60] = 0; em[61] = 232; em[62] = 12; /* 60: struct.ec_group_st */
    	em[63] = 87; em[64] = 0; 
    	em[65] = 259; em[66] = 8; 
    	em[67] = 459; em[68] = 16; 
    	em[69] = 459; em[70] = 40; 
    	em[71] = 471; em[72] = 80; 
    	em[73] = 479; em[74] = 96; 
    	em[75] = 459; em[76] = 104; 
    	em[77] = 459; em[78] = 152; 
    	em[79] = 459; em[80] = 176; 
    	em[81] = 23; em[82] = 208; 
    	em[83] = 23; em[84] = 216; 
    	em[85] = 502; em[86] = 224; 
    em[87] = 1; em[88] = 8; em[89] = 1; /* 87: pointer.struct.ec_method_st */
    	em[90] = 92; em[91] = 0; 
    em[92] = 0; em[93] = 304; em[94] = 37; /* 92: struct.ec_method_st */
    	em[95] = 169; em[96] = 8; 
    	em[97] = 172; em[98] = 16; 
    	em[99] = 172; em[100] = 24; 
    	em[101] = 175; em[102] = 32; 
    	em[103] = 178; em[104] = 40; 
    	em[105] = 181; em[106] = 48; 
    	em[107] = 184; em[108] = 56; 
    	em[109] = 187; em[110] = 64; 
    	em[111] = 190; em[112] = 72; 
    	em[113] = 193; em[114] = 80; 
    	em[115] = 193; em[116] = 88; 
    	em[117] = 196; em[118] = 96; 
    	em[119] = 199; em[120] = 104; 
    	em[121] = 202; em[122] = 112; 
    	em[123] = 205; em[124] = 120; 
    	em[125] = 208; em[126] = 128; 
    	em[127] = 211; em[128] = 136; 
    	em[129] = 214; em[130] = 144; 
    	em[131] = 217; em[132] = 152; 
    	em[133] = 220; em[134] = 160; 
    	em[135] = 223; em[136] = 168; 
    	em[137] = 226; em[138] = 176; 
    	em[139] = 229; em[140] = 184; 
    	em[141] = 232; em[142] = 192; 
    	em[143] = 235; em[144] = 200; 
    	em[145] = 238; em[146] = 208; 
    	em[147] = 229; em[148] = 216; 
    	em[149] = 241; em[150] = 224; 
    	em[151] = 244; em[152] = 232; 
    	em[153] = 247; em[154] = 240; 
    	em[155] = 184; em[156] = 248; 
    	em[157] = 250; em[158] = 256; 
    	em[159] = 253; em[160] = 264; 
    	em[161] = 250; em[162] = 272; 
    	em[163] = 253; em[164] = 280; 
    	em[165] = 253; em[166] = 288; 
    	em[167] = 256; em[168] = 296; 
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
    em[241] = 8884097; em[242] = 8; em[243] = 0; /* 241: pointer.func */
    em[244] = 8884097; em[245] = 8; em[246] = 0; /* 244: pointer.func */
    em[247] = 8884097; em[248] = 8; em[249] = 0; /* 247: pointer.func */
    em[250] = 8884097; em[251] = 8; em[252] = 0; /* 250: pointer.func */
    em[253] = 8884097; em[254] = 8; em[255] = 0; /* 253: pointer.func */
    em[256] = 8884097; em[257] = 8; em[258] = 0; /* 256: pointer.func */
    em[259] = 1; em[260] = 8; em[261] = 1; /* 259: pointer.struct.ec_point_st */
    	em[262] = 264; em[263] = 0; 
    em[264] = 0; em[265] = 88; em[266] = 4; /* 264: struct.ec_point_st */
    	em[267] = 275; em[268] = 0; 
    	em[269] = 447; em[270] = 8; 
    	em[271] = 447; em[272] = 32; 
    	em[273] = 447; em[274] = 56; 
    em[275] = 1; em[276] = 8; em[277] = 1; /* 275: pointer.struct.ec_method_st */
    	em[278] = 280; em[279] = 0; 
    em[280] = 0; em[281] = 304; em[282] = 37; /* 280: struct.ec_method_st */
    	em[283] = 357; em[284] = 8; 
    	em[285] = 360; em[286] = 16; 
    	em[287] = 360; em[288] = 24; 
    	em[289] = 363; em[290] = 32; 
    	em[291] = 366; em[292] = 40; 
    	em[293] = 369; em[294] = 48; 
    	em[295] = 372; em[296] = 56; 
    	em[297] = 375; em[298] = 64; 
    	em[299] = 378; em[300] = 72; 
    	em[301] = 381; em[302] = 80; 
    	em[303] = 381; em[304] = 88; 
    	em[305] = 384; em[306] = 96; 
    	em[307] = 387; em[308] = 104; 
    	em[309] = 390; em[310] = 112; 
    	em[311] = 393; em[312] = 120; 
    	em[313] = 396; em[314] = 128; 
    	em[315] = 399; em[316] = 136; 
    	em[317] = 402; em[318] = 144; 
    	em[319] = 405; em[320] = 152; 
    	em[321] = 408; em[322] = 160; 
    	em[323] = 411; em[324] = 168; 
    	em[325] = 414; em[326] = 176; 
    	em[327] = 417; em[328] = 184; 
    	em[329] = 420; em[330] = 192; 
    	em[331] = 423; em[332] = 200; 
    	em[333] = 426; em[334] = 208; 
    	em[335] = 417; em[336] = 216; 
    	em[337] = 429; em[338] = 224; 
    	em[339] = 432; em[340] = 232; 
    	em[341] = 435; em[342] = 240; 
    	em[343] = 372; em[344] = 248; 
    	em[345] = 438; em[346] = 256; 
    	em[347] = 441; em[348] = 264; 
    	em[349] = 438; em[350] = 272; 
    	em[351] = 441; em[352] = 280; 
    	em[353] = 441; em[354] = 288; 
    	em[355] = 444; em[356] = 296; 
    em[357] = 8884097; em[358] = 8; em[359] = 0; /* 357: pointer.func */
    em[360] = 8884097; em[361] = 8; em[362] = 0; /* 360: pointer.func */
    em[363] = 8884097; em[364] = 8; em[365] = 0; /* 363: pointer.func */
    em[366] = 8884097; em[367] = 8; em[368] = 0; /* 366: pointer.func */
    em[369] = 8884097; em[370] = 8; em[371] = 0; /* 369: pointer.func */
    em[372] = 8884097; em[373] = 8; em[374] = 0; /* 372: pointer.func */
    em[375] = 8884097; em[376] = 8; em[377] = 0; /* 375: pointer.func */
    em[378] = 8884097; em[379] = 8; em[380] = 0; /* 378: pointer.func */
    em[381] = 8884097; em[382] = 8; em[383] = 0; /* 381: pointer.func */
    em[384] = 8884097; em[385] = 8; em[386] = 0; /* 384: pointer.func */
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 8884097; em[391] = 8; em[392] = 0; /* 390: pointer.func */
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
    em[447] = 0; em[448] = 24; em[449] = 1; /* 447: struct.bignum_st */
    	em[450] = 452; em[451] = 0; 
    em[452] = 8884099; em[453] = 8; em[454] = 2; /* 452: pointer_to_array_of_pointers_to_stack */
    	em[455] = 44; em[456] = 0; 
    	em[457] = 47; em[458] = 12; 
    em[459] = 0; em[460] = 24; em[461] = 1; /* 459: struct.bignum_st */
    	em[462] = 464; em[463] = 0; 
    em[464] = 8884099; em[465] = 8; em[466] = 2; /* 464: pointer_to_array_of_pointers_to_stack */
    	em[467] = 44; em[468] = 0; 
    	em[469] = 47; em[470] = 12; 
    em[471] = 1; em[472] = 8; em[473] = 1; /* 471: pointer.unsigned char */
    	em[474] = 476; em[475] = 0; 
    em[476] = 0; em[477] = 1; em[478] = 0; /* 476: unsigned char */
    em[479] = 1; em[480] = 8; em[481] = 1; /* 479: pointer.struct.ec_extra_data_st */
    	em[482] = 484; em[483] = 0; 
    em[484] = 0; em[485] = 40; em[486] = 5; /* 484: struct.ec_extra_data_st */
    	em[487] = 497; em[488] = 0; 
    	em[489] = 23; em[490] = 8; 
    	em[491] = 26; em[492] = 16; 
    	em[493] = 29; em[494] = 24; 
    	em[495] = 29; em[496] = 32; 
    em[497] = 1; em[498] = 8; em[499] = 1; /* 497: pointer.struct.ec_extra_data_st */
    	em[500] = 484; em[501] = 0; 
    em[502] = 8884097; em[503] = 8; em[504] = 0; /* 502: pointer.func */
    em[505] = 1; em[506] = 8; em[507] = 1; /* 505: pointer.struct.ec_key_st */
    	em[508] = 510; em[509] = 0; 
    em[510] = 0; em[511] = 56; em[512] = 4; /* 510: struct.ec_key_st */
    	em[513] = 55; em[514] = 8; 
    	em[515] = 521; em[516] = 16; 
    	em[517] = 50; em[518] = 24; 
    	em[519] = 0; em[520] = 48; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_point_st */
    	em[524] = 264; em[525] = 0; 
    em[526] = 1; em[527] = 8; em[528] = 1; /* 526: pointer.struct.ec_group_st */
    	em[529] = 60; em[530] = 0; 
    args_addr->arg_entity_index[0] = 505;
    args_addr->ret_entity_index = 526;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EC_KEY * new_arg_a = *((const EC_KEY * *)new_args->args[0]);

    const EC_GROUP * *new_ret_ptr = (const EC_GROUP * *)new_args->ret;

    const EC_GROUP * (*orig_EC_KEY_get0_group)(const EC_KEY *);
    orig_EC_KEY_get0_group = dlsym(RTLD_NEXT, "EC_KEY_get0_group");
    *new_ret_ptr = (*orig_EC_KEY_get0_group)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

