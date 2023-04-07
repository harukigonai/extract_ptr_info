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
    	em[8] = 0; em[9] = 0; 
    	em[10] = 18; em[11] = 8; 
    	em[12] = 21; em[13] = 16; 
    	em[14] = 24; em[15] = 24; 
    	em[16] = 24; em[17] = 32; 
    em[18] = 0; em[19] = 8; em[20] = 0; /* 18: pointer.void */
    em[21] = 8884097; em[22] = 8; em[23] = 0; /* 21: pointer.func */
    em[24] = 8884097; em[25] = 8; em[26] = 0; /* 24: pointer.func */
    em[27] = 1; em[28] = 8; em[29] = 1; /* 27: pointer.struct.ec_group_st */
    	em[30] = 32; em[31] = 0; 
    em[32] = 0; em[33] = 232; em[34] = 12; /* 32: struct.ec_group_st */
    	em[35] = 59; em[36] = 0; 
    	em[37] = 231; em[38] = 8; 
    	em[39] = 437; em[40] = 16; 
    	em[41] = 437; em[42] = 40; 
    	em[43] = 449; em[44] = 80; 
    	em[45] = 457; em[46] = 96; 
    	em[47] = 437; em[48] = 104; 
    	em[49] = 437; em[50] = 152; 
    	em[51] = 437; em[52] = 176; 
    	em[53] = 18; em[54] = 208; 
    	em[55] = 18; em[56] = 216; 
    	em[57] = 480; em[58] = 224; 
    em[59] = 1; em[60] = 8; em[61] = 1; /* 59: pointer.struct.ec_method_st */
    	em[62] = 64; em[63] = 0; 
    em[64] = 0; em[65] = 304; em[66] = 37; /* 64: struct.ec_method_st */
    	em[67] = 141; em[68] = 8; 
    	em[69] = 144; em[70] = 16; 
    	em[71] = 144; em[72] = 24; 
    	em[73] = 147; em[74] = 32; 
    	em[75] = 150; em[76] = 40; 
    	em[77] = 153; em[78] = 48; 
    	em[79] = 156; em[80] = 56; 
    	em[81] = 159; em[82] = 64; 
    	em[83] = 162; em[84] = 72; 
    	em[85] = 165; em[86] = 80; 
    	em[87] = 165; em[88] = 88; 
    	em[89] = 168; em[90] = 96; 
    	em[91] = 171; em[92] = 104; 
    	em[93] = 174; em[94] = 112; 
    	em[95] = 177; em[96] = 120; 
    	em[97] = 180; em[98] = 128; 
    	em[99] = 183; em[100] = 136; 
    	em[101] = 186; em[102] = 144; 
    	em[103] = 189; em[104] = 152; 
    	em[105] = 192; em[106] = 160; 
    	em[107] = 195; em[108] = 168; 
    	em[109] = 198; em[110] = 176; 
    	em[111] = 201; em[112] = 184; 
    	em[113] = 204; em[114] = 192; 
    	em[115] = 207; em[116] = 200; 
    	em[117] = 210; em[118] = 208; 
    	em[119] = 201; em[120] = 216; 
    	em[121] = 213; em[122] = 224; 
    	em[123] = 216; em[124] = 232; 
    	em[125] = 219; em[126] = 240; 
    	em[127] = 156; em[128] = 248; 
    	em[129] = 222; em[130] = 256; 
    	em[131] = 225; em[132] = 264; 
    	em[133] = 222; em[134] = 272; 
    	em[135] = 225; em[136] = 280; 
    	em[137] = 225; em[138] = 288; 
    	em[139] = 228; em[140] = 296; 
    em[141] = 8884097; em[142] = 8; em[143] = 0; /* 141: pointer.func */
    em[144] = 8884097; em[145] = 8; em[146] = 0; /* 144: pointer.func */
    em[147] = 8884097; em[148] = 8; em[149] = 0; /* 147: pointer.func */
    em[150] = 8884097; em[151] = 8; em[152] = 0; /* 150: pointer.func */
    em[153] = 8884097; em[154] = 8; em[155] = 0; /* 153: pointer.func */
    em[156] = 8884097; em[157] = 8; em[158] = 0; /* 156: pointer.func */
    em[159] = 8884097; em[160] = 8; em[161] = 0; /* 159: pointer.func */
    em[162] = 8884097; em[163] = 8; em[164] = 0; /* 162: pointer.func */
    em[165] = 8884097; em[166] = 8; em[167] = 0; /* 165: pointer.func */
    em[168] = 8884097; em[169] = 8; em[170] = 0; /* 168: pointer.func */
    em[171] = 8884097; em[172] = 8; em[173] = 0; /* 171: pointer.func */
    em[174] = 8884097; em[175] = 8; em[176] = 0; /* 174: pointer.func */
    em[177] = 8884097; em[178] = 8; em[179] = 0; /* 177: pointer.func */
    em[180] = 8884097; em[181] = 8; em[182] = 0; /* 180: pointer.func */
    em[183] = 8884097; em[184] = 8; em[185] = 0; /* 183: pointer.func */
    em[186] = 8884097; em[187] = 8; em[188] = 0; /* 186: pointer.func */
    em[189] = 8884097; em[190] = 8; em[191] = 0; /* 189: pointer.func */
    em[192] = 8884097; em[193] = 8; em[194] = 0; /* 192: pointer.func */
    em[195] = 8884097; em[196] = 8; em[197] = 0; /* 195: pointer.func */
    em[198] = 8884097; em[199] = 8; em[200] = 0; /* 198: pointer.func */
    em[201] = 8884097; em[202] = 8; em[203] = 0; /* 201: pointer.func */
    em[204] = 8884097; em[205] = 8; em[206] = 0; /* 204: pointer.func */
    em[207] = 8884097; em[208] = 8; em[209] = 0; /* 207: pointer.func */
    em[210] = 8884097; em[211] = 8; em[212] = 0; /* 210: pointer.func */
    em[213] = 8884097; em[214] = 8; em[215] = 0; /* 213: pointer.func */
    em[216] = 8884097; em[217] = 8; em[218] = 0; /* 216: pointer.func */
    em[219] = 8884097; em[220] = 8; em[221] = 0; /* 219: pointer.func */
    em[222] = 8884097; em[223] = 8; em[224] = 0; /* 222: pointer.func */
    em[225] = 8884097; em[226] = 8; em[227] = 0; /* 225: pointer.func */
    em[228] = 8884097; em[229] = 8; em[230] = 0; /* 228: pointer.func */
    em[231] = 1; em[232] = 8; em[233] = 1; /* 231: pointer.struct.ec_point_st */
    	em[234] = 236; em[235] = 0; 
    em[236] = 0; em[237] = 88; em[238] = 4; /* 236: struct.ec_point_st */
    	em[239] = 247; em[240] = 0; 
    	em[241] = 419; em[242] = 8; 
    	em[243] = 419; em[244] = 32; 
    	em[245] = 419; em[246] = 56; 
    em[247] = 1; em[248] = 8; em[249] = 1; /* 247: pointer.struct.ec_method_st */
    	em[250] = 252; em[251] = 0; 
    em[252] = 0; em[253] = 304; em[254] = 37; /* 252: struct.ec_method_st */
    	em[255] = 329; em[256] = 8; 
    	em[257] = 332; em[258] = 16; 
    	em[259] = 332; em[260] = 24; 
    	em[261] = 335; em[262] = 32; 
    	em[263] = 338; em[264] = 40; 
    	em[265] = 341; em[266] = 48; 
    	em[267] = 344; em[268] = 56; 
    	em[269] = 347; em[270] = 64; 
    	em[271] = 350; em[272] = 72; 
    	em[273] = 353; em[274] = 80; 
    	em[275] = 353; em[276] = 88; 
    	em[277] = 356; em[278] = 96; 
    	em[279] = 359; em[280] = 104; 
    	em[281] = 362; em[282] = 112; 
    	em[283] = 365; em[284] = 120; 
    	em[285] = 368; em[286] = 128; 
    	em[287] = 371; em[288] = 136; 
    	em[289] = 374; em[290] = 144; 
    	em[291] = 377; em[292] = 152; 
    	em[293] = 380; em[294] = 160; 
    	em[295] = 383; em[296] = 168; 
    	em[297] = 386; em[298] = 176; 
    	em[299] = 389; em[300] = 184; 
    	em[301] = 392; em[302] = 192; 
    	em[303] = 395; em[304] = 200; 
    	em[305] = 398; em[306] = 208; 
    	em[307] = 389; em[308] = 216; 
    	em[309] = 401; em[310] = 224; 
    	em[311] = 404; em[312] = 232; 
    	em[313] = 407; em[314] = 240; 
    	em[315] = 344; em[316] = 248; 
    	em[317] = 410; em[318] = 256; 
    	em[319] = 413; em[320] = 264; 
    	em[321] = 410; em[322] = 272; 
    	em[323] = 413; em[324] = 280; 
    	em[325] = 413; em[326] = 288; 
    	em[327] = 416; em[328] = 296; 
    em[329] = 8884097; em[330] = 8; em[331] = 0; /* 329: pointer.func */
    em[332] = 8884097; em[333] = 8; em[334] = 0; /* 332: pointer.func */
    em[335] = 8884097; em[336] = 8; em[337] = 0; /* 335: pointer.func */
    em[338] = 8884097; em[339] = 8; em[340] = 0; /* 338: pointer.func */
    em[341] = 8884097; em[342] = 8; em[343] = 0; /* 341: pointer.func */
    em[344] = 8884097; em[345] = 8; em[346] = 0; /* 344: pointer.func */
    em[347] = 8884097; em[348] = 8; em[349] = 0; /* 347: pointer.func */
    em[350] = 8884097; em[351] = 8; em[352] = 0; /* 350: pointer.func */
    em[353] = 8884097; em[354] = 8; em[355] = 0; /* 353: pointer.func */
    em[356] = 8884097; em[357] = 8; em[358] = 0; /* 356: pointer.func */
    em[359] = 8884097; em[360] = 8; em[361] = 0; /* 359: pointer.func */
    em[362] = 8884097; em[363] = 8; em[364] = 0; /* 362: pointer.func */
    em[365] = 8884097; em[366] = 8; em[367] = 0; /* 365: pointer.func */
    em[368] = 8884097; em[369] = 8; em[370] = 0; /* 368: pointer.func */
    em[371] = 8884097; em[372] = 8; em[373] = 0; /* 371: pointer.func */
    em[374] = 8884097; em[375] = 8; em[376] = 0; /* 374: pointer.func */
    em[377] = 8884097; em[378] = 8; em[379] = 0; /* 377: pointer.func */
    em[380] = 8884097; em[381] = 8; em[382] = 0; /* 380: pointer.func */
    em[383] = 8884097; em[384] = 8; em[385] = 0; /* 383: pointer.func */
    em[386] = 8884097; em[387] = 8; em[388] = 0; /* 386: pointer.func */
    em[389] = 8884097; em[390] = 8; em[391] = 0; /* 389: pointer.func */
    em[392] = 8884097; em[393] = 8; em[394] = 0; /* 392: pointer.func */
    em[395] = 8884097; em[396] = 8; em[397] = 0; /* 395: pointer.func */
    em[398] = 8884097; em[399] = 8; em[400] = 0; /* 398: pointer.func */
    em[401] = 8884097; em[402] = 8; em[403] = 0; /* 401: pointer.func */
    em[404] = 8884097; em[405] = 8; em[406] = 0; /* 404: pointer.func */
    em[407] = 8884097; em[408] = 8; em[409] = 0; /* 407: pointer.func */
    em[410] = 8884097; em[411] = 8; em[412] = 0; /* 410: pointer.func */
    em[413] = 8884097; em[414] = 8; em[415] = 0; /* 413: pointer.func */
    em[416] = 8884097; em[417] = 8; em[418] = 0; /* 416: pointer.func */
    em[419] = 0; em[420] = 24; em[421] = 1; /* 419: struct.bignum_st */
    	em[422] = 424; em[423] = 0; 
    em[424] = 8884099; em[425] = 8; em[426] = 2; /* 424: pointer_to_array_of_pointers_to_stack */
    	em[427] = 431; em[428] = 0; 
    	em[429] = 434; em[430] = 12; 
    em[431] = 0; em[432] = 4; em[433] = 0; /* 431: unsigned int */
    em[434] = 0; em[435] = 4; em[436] = 0; /* 434: int */
    em[437] = 0; em[438] = 24; em[439] = 1; /* 437: struct.bignum_st */
    	em[440] = 442; em[441] = 0; 
    em[442] = 8884099; em[443] = 8; em[444] = 2; /* 442: pointer_to_array_of_pointers_to_stack */
    	em[445] = 431; em[446] = 0; 
    	em[447] = 434; em[448] = 12; 
    em[449] = 1; em[450] = 8; em[451] = 1; /* 449: pointer.unsigned char */
    	em[452] = 454; em[453] = 0; 
    em[454] = 0; em[455] = 1; em[456] = 0; /* 454: unsigned char */
    em[457] = 1; em[458] = 8; em[459] = 1; /* 457: pointer.struct.ec_extra_data_st */
    	em[460] = 462; em[461] = 0; 
    em[462] = 0; em[463] = 40; em[464] = 5; /* 462: struct.ec_extra_data_st */
    	em[465] = 475; em[466] = 0; 
    	em[467] = 18; em[468] = 8; 
    	em[469] = 21; em[470] = 16; 
    	em[471] = 24; em[472] = 24; 
    	em[473] = 24; em[474] = 32; 
    em[475] = 1; em[476] = 8; em[477] = 1; /* 475: pointer.struct.ec_extra_data_st */
    	em[478] = 462; em[479] = 0; 
    em[480] = 8884097; em[481] = 8; em[482] = 0; /* 480: pointer.func */
    em[483] = 0; em[484] = 56; em[485] = 4; /* 483: struct.ec_key_st */
    	em[486] = 27; em[487] = 8; 
    	em[488] = 494; em[489] = 16; 
    	em[490] = 499; em[491] = 24; 
    	em[492] = 516; em[493] = 48; 
    em[494] = 1; em[495] = 8; em[496] = 1; /* 494: pointer.struct.ec_point_st */
    	em[497] = 236; em[498] = 0; 
    em[499] = 1; em[500] = 8; em[501] = 1; /* 499: pointer.struct.bignum_st */
    	em[502] = 504; em[503] = 0; 
    em[504] = 0; em[505] = 24; em[506] = 1; /* 504: struct.bignum_st */
    	em[507] = 509; em[508] = 0; 
    em[509] = 8884099; em[510] = 8; em[511] = 2; /* 509: pointer_to_array_of_pointers_to_stack */
    	em[512] = 431; em[513] = 0; 
    	em[514] = 434; em[515] = 12; 
    em[516] = 1; em[517] = 8; em[518] = 1; /* 516: pointer.struct.ec_extra_data_st */
    	em[519] = 5; em[520] = 0; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_key_st */
    	em[524] = 483; em[525] = 0; 
    em[526] = 1; em[527] = 8; em[528] = 1; /* 526: pointer.struct.ec_group_st */
    	em[529] = 32; em[530] = 0; 
    args_addr->arg_entity_index[0] = 521;
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

