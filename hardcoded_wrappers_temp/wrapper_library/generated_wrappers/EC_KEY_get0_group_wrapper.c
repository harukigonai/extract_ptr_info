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
    em[0] = 0; em[1] = 40; em[2] = 5; /* 0: struct.ec_extra_data_st */
    	em[3] = 13; em[4] = 0; 
    	em[5] = 18; em[6] = 8; 
    	em[7] = 21; em[8] = 16; 
    	em[9] = 24; em[10] = 24; 
    	em[11] = 24; em[12] = 32; 
    em[13] = 1; em[14] = 8; em[15] = 1; /* 13: pointer.struct.ec_extra_data_st */
    	em[16] = 0; em[17] = 0; 
    em[18] = 0; em[19] = 8; em[20] = 0; /* 18: pointer.void */
    em[21] = 8884097; em[22] = 8; em[23] = 0; /* 21: pointer.func */
    em[24] = 8884097; em[25] = 8; em[26] = 0; /* 24: pointer.func */
    em[27] = 1; em[28] = 8; em[29] = 1; /* 27: pointer.struct.ec_key_st */
    	em[30] = 32; em[31] = 0; 
    em[32] = 0; em[33] = 56; em[34] = 4; /* 32: struct.ec_key_st */
    	em[35] = 43; em[36] = 8; 
    	em[37] = 499; em[38] = 16; 
    	em[39] = 504; em[40] = 24; 
    	em[41] = 521; em[42] = 48; 
    em[43] = 1; em[44] = 8; em[45] = 1; /* 43: pointer.struct.ec_group_st */
    	em[46] = 48; em[47] = 0; 
    em[48] = 0; em[49] = 232; em[50] = 12; /* 48: struct.ec_group_st */
    	em[51] = 75; em[52] = 0; 
    	em[53] = 247; em[54] = 8; 
    	em[55] = 453; em[56] = 16; 
    	em[57] = 453; em[58] = 40; 
    	em[59] = 465; em[60] = 80; 
    	em[61] = 473; em[62] = 96; 
    	em[63] = 453; em[64] = 104; 
    	em[65] = 453; em[66] = 152; 
    	em[67] = 453; em[68] = 176; 
    	em[69] = 18; em[70] = 208; 
    	em[71] = 18; em[72] = 216; 
    	em[73] = 496; em[74] = 224; 
    em[75] = 1; em[76] = 8; em[77] = 1; /* 75: pointer.struct.ec_method_st */
    	em[78] = 80; em[79] = 0; 
    em[80] = 0; em[81] = 304; em[82] = 37; /* 80: struct.ec_method_st */
    	em[83] = 157; em[84] = 8; 
    	em[85] = 160; em[86] = 16; 
    	em[87] = 160; em[88] = 24; 
    	em[89] = 163; em[90] = 32; 
    	em[91] = 166; em[92] = 40; 
    	em[93] = 169; em[94] = 48; 
    	em[95] = 172; em[96] = 56; 
    	em[97] = 175; em[98] = 64; 
    	em[99] = 178; em[100] = 72; 
    	em[101] = 181; em[102] = 80; 
    	em[103] = 181; em[104] = 88; 
    	em[105] = 184; em[106] = 96; 
    	em[107] = 187; em[108] = 104; 
    	em[109] = 190; em[110] = 112; 
    	em[111] = 193; em[112] = 120; 
    	em[113] = 196; em[114] = 128; 
    	em[115] = 199; em[116] = 136; 
    	em[117] = 202; em[118] = 144; 
    	em[119] = 205; em[120] = 152; 
    	em[121] = 208; em[122] = 160; 
    	em[123] = 211; em[124] = 168; 
    	em[125] = 214; em[126] = 176; 
    	em[127] = 217; em[128] = 184; 
    	em[129] = 220; em[130] = 192; 
    	em[131] = 223; em[132] = 200; 
    	em[133] = 226; em[134] = 208; 
    	em[135] = 217; em[136] = 216; 
    	em[137] = 229; em[138] = 224; 
    	em[139] = 232; em[140] = 232; 
    	em[141] = 235; em[142] = 240; 
    	em[143] = 172; em[144] = 248; 
    	em[145] = 238; em[146] = 256; 
    	em[147] = 241; em[148] = 264; 
    	em[149] = 238; em[150] = 272; 
    	em[151] = 241; em[152] = 280; 
    	em[153] = 241; em[154] = 288; 
    	em[155] = 244; em[156] = 296; 
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
    em[241] = 8884097; em[242] = 8; em[243] = 0; /* 241: pointer.func */
    em[244] = 8884097; em[245] = 8; em[246] = 0; /* 244: pointer.func */
    em[247] = 1; em[248] = 8; em[249] = 1; /* 247: pointer.struct.ec_point_st */
    	em[250] = 252; em[251] = 0; 
    em[252] = 0; em[253] = 88; em[254] = 4; /* 252: struct.ec_point_st */
    	em[255] = 263; em[256] = 0; 
    	em[257] = 435; em[258] = 8; 
    	em[259] = 435; em[260] = 32; 
    	em[261] = 435; em[262] = 56; 
    em[263] = 1; em[264] = 8; em[265] = 1; /* 263: pointer.struct.ec_method_st */
    	em[266] = 268; em[267] = 0; 
    em[268] = 0; em[269] = 304; em[270] = 37; /* 268: struct.ec_method_st */
    	em[271] = 345; em[272] = 8; 
    	em[273] = 348; em[274] = 16; 
    	em[275] = 348; em[276] = 24; 
    	em[277] = 351; em[278] = 32; 
    	em[279] = 354; em[280] = 40; 
    	em[281] = 357; em[282] = 48; 
    	em[283] = 360; em[284] = 56; 
    	em[285] = 363; em[286] = 64; 
    	em[287] = 366; em[288] = 72; 
    	em[289] = 369; em[290] = 80; 
    	em[291] = 369; em[292] = 88; 
    	em[293] = 372; em[294] = 96; 
    	em[295] = 375; em[296] = 104; 
    	em[297] = 378; em[298] = 112; 
    	em[299] = 381; em[300] = 120; 
    	em[301] = 384; em[302] = 128; 
    	em[303] = 387; em[304] = 136; 
    	em[305] = 390; em[306] = 144; 
    	em[307] = 393; em[308] = 152; 
    	em[309] = 396; em[310] = 160; 
    	em[311] = 399; em[312] = 168; 
    	em[313] = 402; em[314] = 176; 
    	em[315] = 405; em[316] = 184; 
    	em[317] = 408; em[318] = 192; 
    	em[319] = 411; em[320] = 200; 
    	em[321] = 414; em[322] = 208; 
    	em[323] = 405; em[324] = 216; 
    	em[325] = 417; em[326] = 224; 
    	em[327] = 420; em[328] = 232; 
    	em[329] = 423; em[330] = 240; 
    	em[331] = 360; em[332] = 248; 
    	em[333] = 426; em[334] = 256; 
    	em[335] = 429; em[336] = 264; 
    	em[337] = 426; em[338] = 272; 
    	em[339] = 429; em[340] = 280; 
    	em[341] = 429; em[342] = 288; 
    	em[343] = 432; em[344] = 296; 
    em[345] = 8884097; em[346] = 8; em[347] = 0; /* 345: pointer.func */
    em[348] = 8884097; em[349] = 8; em[350] = 0; /* 348: pointer.func */
    em[351] = 8884097; em[352] = 8; em[353] = 0; /* 351: pointer.func */
    em[354] = 8884097; em[355] = 8; em[356] = 0; /* 354: pointer.func */
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
    em[435] = 0; em[436] = 24; em[437] = 1; /* 435: struct.bignum_st */
    	em[438] = 440; em[439] = 0; 
    em[440] = 8884099; em[441] = 8; em[442] = 2; /* 440: pointer_to_array_of_pointers_to_stack */
    	em[443] = 447; em[444] = 0; 
    	em[445] = 450; em[446] = 12; 
    em[447] = 0; em[448] = 8; em[449] = 0; /* 447: long unsigned int */
    em[450] = 0; em[451] = 4; em[452] = 0; /* 450: int */
    em[453] = 0; em[454] = 24; em[455] = 1; /* 453: struct.bignum_st */
    	em[456] = 458; em[457] = 0; 
    em[458] = 8884099; em[459] = 8; em[460] = 2; /* 458: pointer_to_array_of_pointers_to_stack */
    	em[461] = 447; em[462] = 0; 
    	em[463] = 450; em[464] = 12; 
    em[465] = 1; em[466] = 8; em[467] = 1; /* 465: pointer.unsigned char */
    	em[468] = 470; em[469] = 0; 
    em[470] = 0; em[471] = 1; em[472] = 0; /* 470: unsigned char */
    em[473] = 1; em[474] = 8; em[475] = 1; /* 473: pointer.struct.ec_extra_data_st */
    	em[476] = 478; em[477] = 0; 
    em[478] = 0; em[479] = 40; em[480] = 5; /* 478: struct.ec_extra_data_st */
    	em[481] = 491; em[482] = 0; 
    	em[483] = 18; em[484] = 8; 
    	em[485] = 21; em[486] = 16; 
    	em[487] = 24; em[488] = 24; 
    	em[489] = 24; em[490] = 32; 
    em[491] = 1; em[492] = 8; em[493] = 1; /* 491: pointer.struct.ec_extra_data_st */
    	em[494] = 478; em[495] = 0; 
    em[496] = 8884097; em[497] = 8; em[498] = 0; /* 496: pointer.func */
    em[499] = 1; em[500] = 8; em[501] = 1; /* 499: pointer.struct.ec_point_st */
    	em[502] = 252; em[503] = 0; 
    em[504] = 1; em[505] = 8; em[506] = 1; /* 504: pointer.struct.bignum_st */
    	em[507] = 509; em[508] = 0; 
    em[509] = 0; em[510] = 24; em[511] = 1; /* 509: struct.bignum_st */
    	em[512] = 514; em[513] = 0; 
    em[514] = 8884099; em[515] = 8; em[516] = 2; /* 514: pointer_to_array_of_pointers_to_stack */
    	em[517] = 447; em[518] = 0; 
    	em[519] = 450; em[520] = 12; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_extra_data_st */
    	em[524] = 0; em[525] = 0; 
    em[526] = 1; em[527] = 8; em[528] = 1; /* 526: pointer.struct.ec_group_st */
    	em[529] = 48; em[530] = 0; 
    args_addr->arg_entity_index[0] = 27;
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

