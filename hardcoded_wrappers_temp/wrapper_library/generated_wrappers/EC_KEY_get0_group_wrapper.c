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
    em[0] = 0; em[1] = 24; em[2] = 1; /* 0: struct.bignum_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 8884099; em[6] = 8; em[7] = 2; /* 5: pointer_to_array_of_pointers_to_stack */
    	em[8] = 12; em[9] = 0; 
    	em[10] = 15; em[11] = 12; 
    em[12] = 0; em[13] = 8; em[14] = 0; /* 12: long unsigned int */
    em[15] = 0; em[16] = 4; em[17] = 0; /* 15: int */
    em[18] = 1; em[19] = 8; em[20] = 1; /* 18: pointer.struct.ec_extra_data_st */
    	em[21] = 23; em[22] = 0; 
    em[23] = 0; em[24] = 40; em[25] = 5; /* 23: struct.ec_extra_data_st */
    	em[26] = 18; em[27] = 0; 
    	em[28] = 36; em[29] = 8; 
    	em[30] = 39; em[31] = 16; 
    	em[32] = 42; em[33] = 24; 
    	em[34] = 42; em[35] = 32; 
    em[36] = 0; em[37] = 8; em[38] = 0; /* 36: pointer.void */
    em[39] = 8884097; em[40] = 8; em[41] = 0; /* 39: pointer.func */
    em[42] = 8884097; em[43] = 8; em[44] = 0; /* 42: pointer.func */
    em[45] = 1; em[46] = 8; em[47] = 1; /* 45: pointer.struct.ec_group_st */
    	em[48] = 50; em[49] = 0; 
    em[50] = 0; em[51] = 232; em[52] = 12; /* 50: struct.ec_group_st */
    	em[53] = 77; em[54] = 0; 
    	em[55] = 249; em[56] = 8; 
    	em[57] = 449; em[58] = 16; 
    	em[59] = 449; em[60] = 40; 
    	em[61] = 461; em[62] = 80; 
    	em[63] = 469; em[64] = 96; 
    	em[65] = 449; em[66] = 104; 
    	em[67] = 449; em[68] = 152; 
    	em[69] = 449; em[70] = 176; 
    	em[71] = 36; em[72] = 208; 
    	em[73] = 36; em[74] = 216; 
    	em[75] = 492; em[76] = 224; 
    em[77] = 1; em[78] = 8; em[79] = 1; /* 77: pointer.struct.ec_method_st */
    	em[80] = 82; em[81] = 0; 
    em[82] = 0; em[83] = 304; em[84] = 37; /* 82: struct.ec_method_st */
    	em[85] = 159; em[86] = 8; 
    	em[87] = 162; em[88] = 16; 
    	em[89] = 162; em[90] = 24; 
    	em[91] = 165; em[92] = 32; 
    	em[93] = 168; em[94] = 40; 
    	em[95] = 171; em[96] = 48; 
    	em[97] = 174; em[98] = 56; 
    	em[99] = 177; em[100] = 64; 
    	em[101] = 180; em[102] = 72; 
    	em[103] = 183; em[104] = 80; 
    	em[105] = 183; em[106] = 88; 
    	em[107] = 186; em[108] = 96; 
    	em[109] = 189; em[110] = 104; 
    	em[111] = 192; em[112] = 112; 
    	em[113] = 195; em[114] = 120; 
    	em[115] = 198; em[116] = 128; 
    	em[117] = 201; em[118] = 136; 
    	em[119] = 204; em[120] = 144; 
    	em[121] = 207; em[122] = 152; 
    	em[123] = 210; em[124] = 160; 
    	em[125] = 213; em[126] = 168; 
    	em[127] = 216; em[128] = 176; 
    	em[129] = 219; em[130] = 184; 
    	em[131] = 222; em[132] = 192; 
    	em[133] = 225; em[134] = 200; 
    	em[135] = 228; em[136] = 208; 
    	em[137] = 219; em[138] = 216; 
    	em[139] = 231; em[140] = 224; 
    	em[141] = 234; em[142] = 232; 
    	em[143] = 237; em[144] = 240; 
    	em[145] = 174; em[146] = 248; 
    	em[147] = 240; em[148] = 256; 
    	em[149] = 243; em[150] = 264; 
    	em[151] = 240; em[152] = 272; 
    	em[153] = 243; em[154] = 280; 
    	em[155] = 243; em[156] = 288; 
    	em[157] = 246; em[158] = 296; 
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
    em[231] = 8884097; em[232] = 8; em[233] = 0; /* 231: pointer.func */
    em[234] = 8884097; em[235] = 8; em[236] = 0; /* 234: pointer.func */
    em[237] = 8884097; em[238] = 8; em[239] = 0; /* 237: pointer.func */
    em[240] = 8884097; em[241] = 8; em[242] = 0; /* 240: pointer.func */
    em[243] = 8884097; em[244] = 8; em[245] = 0; /* 243: pointer.func */
    em[246] = 8884097; em[247] = 8; em[248] = 0; /* 246: pointer.func */
    em[249] = 1; em[250] = 8; em[251] = 1; /* 249: pointer.struct.ec_point_st */
    	em[252] = 254; em[253] = 0; 
    em[254] = 0; em[255] = 88; em[256] = 4; /* 254: struct.ec_point_st */
    	em[257] = 265; em[258] = 0; 
    	em[259] = 437; em[260] = 8; 
    	em[261] = 437; em[262] = 32; 
    	em[263] = 437; em[264] = 56; 
    em[265] = 1; em[266] = 8; em[267] = 1; /* 265: pointer.struct.ec_method_st */
    	em[268] = 270; em[269] = 0; 
    em[270] = 0; em[271] = 304; em[272] = 37; /* 270: struct.ec_method_st */
    	em[273] = 347; em[274] = 8; 
    	em[275] = 350; em[276] = 16; 
    	em[277] = 350; em[278] = 24; 
    	em[279] = 353; em[280] = 32; 
    	em[281] = 356; em[282] = 40; 
    	em[283] = 359; em[284] = 48; 
    	em[285] = 362; em[286] = 56; 
    	em[287] = 365; em[288] = 64; 
    	em[289] = 368; em[290] = 72; 
    	em[291] = 371; em[292] = 80; 
    	em[293] = 371; em[294] = 88; 
    	em[295] = 374; em[296] = 96; 
    	em[297] = 377; em[298] = 104; 
    	em[299] = 380; em[300] = 112; 
    	em[301] = 383; em[302] = 120; 
    	em[303] = 386; em[304] = 128; 
    	em[305] = 389; em[306] = 136; 
    	em[307] = 392; em[308] = 144; 
    	em[309] = 395; em[310] = 152; 
    	em[311] = 398; em[312] = 160; 
    	em[313] = 401; em[314] = 168; 
    	em[315] = 404; em[316] = 176; 
    	em[317] = 407; em[318] = 184; 
    	em[319] = 410; em[320] = 192; 
    	em[321] = 413; em[322] = 200; 
    	em[323] = 416; em[324] = 208; 
    	em[325] = 407; em[326] = 216; 
    	em[327] = 419; em[328] = 224; 
    	em[329] = 422; em[330] = 232; 
    	em[331] = 425; em[332] = 240; 
    	em[333] = 362; em[334] = 248; 
    	em[335] = 428; em[336] = 256; 
    	em[337] = 431; em[338] = 264; 
    	em[339] = 428; em[340] = 272; 
    	em[341] = 431; em[342] = 280; 
    	em[343] = 431; em[344] = 288; 
    	em[345] = 434; em[346] = 296; 
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
    em[419] = 8884097; em[420] = 8; em[421] = 0; /* 419: pointer.func */
    em[422] = 8884097; em[423] = 8; em[424] = 0; /* 422: pointer.func */
    em[425] = 8884097; em[426] = 8; em[427] = 0; /* 425: pointer.func */
    em[428] = 8884097; em[429] = 8; em[430] = 0; /* 428: pointer.func */
    em[431] = 8884097; em[432] = 8; em[433] = 0; /* 431: pointer.func */
    em[434] = 8884097; em[435] = 8; em[436] = 0; /* 434: pointer.func */
    em[437] = 0; em[438] = 24; em[439] = 1; /* 437: struct.bignum_st */
    	em[440] = 442; em[441] = 0; 
    em[442] = 8884099; em[443] = 8; em[444] = 2; /* 442: pointer_to_array_of_pointers_to_stack */
    	em[445] = 12; em[446] = 0; 
    	em[447] = 15; em[448] = 12; 
    em[449] = 0; em[450] = 24; em[451] = 1; /* 449: struct.bignum_st */
    	em[452] = 454; em[453] = 0; 
    em[454] = 8884099; em[455] = 8; em[456] = 2; /* 454: pointer_to_array_of_pointers_to_stack */
    	em[457] = 12; em[458] = 0; 
    	em[459] = 15; em[460] = 12; 
    em[461] = 1; em[462] = 8; em[463] = 1; /* 461: pointer.unsigned char */
    	em[464] = 466; em[465] = 0; 
    em[466] = 0; em[467] = 1; em[468] = 0; /* 466: unsigned char */
    em[469] = 1; em[470] = 8; em[471] = 1; /* 469: pointer.struct.ec_extra_data_st */
    	em[472] = 474; em[473] = 0; 
    em[474] = 0; em[475] = 40; em[476] = 5; /* 474: struct.ec_extra_data_st */
    	em[477] = 487; em[478] = 0; 
    	em[479] = 36; em[480] = 8; 
    	em[481] = 39; em[482] = 16; 
    	em[483] = 42; em[484] = 24; 
    	em[485] = 42; em[486] = 32; 
    em[487] = 1; em[488] = 8; em[489] = 1; /* 487: pointer.struct.ec_extra_data_st */
    	em[490] = 474; em[491] = 0; 
    em[492] = 8884097; em[493] = 8; em[494] = 0; /* 492: pointer.func */
    em[495] = 0; em[496] = 56; em[497] = 4; /* 495: struct.ec_key_st */
    	em[498] = 45; em[499] = 8; 
    	em[500] = 506; em[501] = 16; 
    	em[502] = 511; em[503] = 24; 
    	em[504] = 516; em[505] = 48; 
    em[506] = 1; em[507] = 8; em[508] = 1; /* 506: pointer.struct.ec_point_st */
    	em[509] = 254; em[510] = 0; 
    em[511] = 1; em[512] = 8; em[513] = 1; /* 511: pointer.struct.bignum_st */
    	em[514] = 0; em[515] = 0; 
    em[516] = 1; em[517] = 8; em[518] = 1; /* 516: pointer.struct.ec_extra_data_st */
    	em[519] = 23; em[520] = 0; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_key_st */
    	em[524] = 495; em[525] = 0; 
    em[526] = 1; em[527] = 8; em[528] = 1; /* 526: pointer.struct.ec_group_st */
    	em[529] = 50; em[530] = 0; 
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

