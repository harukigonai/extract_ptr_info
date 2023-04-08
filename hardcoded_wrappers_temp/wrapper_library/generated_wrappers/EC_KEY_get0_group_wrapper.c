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
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.bignum_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 24; em[7] = 1; /* 5: struct.bignum_st */
    	em[8] = 10; em[9] = 0; 
    em[10] = 8884099; em[11] = 8; em[12] = 2; /* 10: pointer_to_array_of_pointers_to_stack */
    	em[13] = 17; em[14] = 0; 
    	em[15] = 20; em[16] = 12; 
    em[17] = 0; em[18] = 8; em[19] = 0; /* 17: long unsigned int */
    em[20] = 0; em[21] = 4; em[22] = 0; /* 20: int */
    em[23] = 1; em[24] = 8; em[25] = 1; /* 23: pointer.struct.ec_point_st */
    	em[26] = 28; em[27] = 0; 
    em[28] = 0; em[29] = 88; em[30] = 4; /* 28: struct.ec_point_st */
    	em[31] = 39; em[32] = 0; 
    	em[33] = 211; em[34] = 8; 
    	em[35] = 211; em[36] = 32; 
    	em[37] = 211; em[38] = 56; 
    em[39] = 1; em[40] = 8; em[41] = 1; /* 39: pointer.struct.ec_method_st */
    	em[42] = 44; em[43] = 0; 
    em[44] = 0; em[45] = 304; em[46] = 37; /* 44: struct.ec_method_st */
    	em[47] = 121; em[48] = 8; 
    	em[49] = 124; em[50] = 16; 
    	em[51] = 124; em[52] = 24; 
    	em[53] = 127; em[54] = 32; 
    	em[55] = 130; em[56] = 40; 
    	em[57] = 133; em[58] = 48; 
    	em[59] = 136; em[60] = 56; 
    	em[61] = 139; em[62] = 64; 
    	em[63] = 142; em[64] = 72; 
    	em[65] = 145; em[66] = 80; 
    	em[67] = 145; em[68] = 88; 
    	em[69] = 148; em[70] = 96; 
    	em[71] = 151; em[72] = 104; 
    	em[73] = 154; em[74] = 112; 
    	em[75] = 157; em[76] = 120; 
    	em[77] = 160; em[78] = 128; 
    	em[79] = 163; em[80] = 136; 
    	em[81] = 166; em[82] = 144; 
    	em[83] = 169; em[84] = 152; 
    	em[85] = 172; em[86] = 160; 
    	em[87] = 175; em[88] = 168; 
    	em[89] = 178; em[90] = 176; 
    	em[91] = 181; em[92] = 184; 
    	em[93] = 184; em[94] = 192; 
    	em[95] = 187; em[96] = 200; 
    	em[97] = 190; em[98] = 208; 
    	em[99] = 181; em[100] = 216; 
    	em[101] = 193; em[102] = 224; 
    	em[103] = 196; em[104] = 232; 
    	em[105] = 199; em[106] = 240; 
    	em[107] = 136; em[108] = 248; 
    	em[109] = 202; em[110] = 256; 
    	em[111] = 205; em[112] = 264; 
    	em[113] = 202; em[114] = 272; 
    	em[115] = 205; em[116] = 280; 
    	em[117] = 205; em[118] = 288; 
    	em[119] = 208; em[120] = 296; 
    em[121] = 8884097; em[122] = 8; em[123] = 0; /* 121: pointer.func */
    em[124] = 8884097; em[125] = 8; em[126] = 0; /* 124: pointer.func */
    em[127] = 8884097; em[128] = 8; em[129] = 0; /* 127: pointer.func */
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
    em[211] = 0; em[212] = 24; em[213] = 1; /* 211: struct.bignum_st */
    	em[214] = 216; em[215] = 0; 
    em[216] = 8884099; em[217] = 8; em[218] = 2; /* 216: pointer_to_array_of_pointers_to_stack */
    	em[219] = 17; em[220] = 0; 
    	em[221] = 20; em[222] = 12; 
    em[223] = 1; em[224] = 8; em[225] = 1; /* 223: pointer.struct.ec_extra_data_st */
    	em[226] = 228; em[227] = 0; 
    em[228] = 0; em[229] = 40; em[230] = 5; /* 228: struct.ec_extra_data_st */
    	em[231] = 223; em[232] = 0; 
    	em[233] = 241; em[234] = 8; 
    	em[235] = 244; em[236] = 16; 
    	em[237] = 247; em[238] = 24; 
    	em[239] = 247; em[240] = 32; 
    em[241] = 0; em[242] = 8; em[243] = 0; /* 241: pointer.void */
    em[244] = 8884097; em[245] = 8; em[246] = 0; /* 244: pointer.func */
    em[247] = 8884097; em[248] = 8; em[249] = 0; /* 247: pointer.func */
    em[250] = 1; em[251] = 8; em[252] = 1; /* 250: pointer.struct.ec_group_st */
    	em[253] = 255; em[254] = 0; 
    em[255] = 0; em[256] = 232; em[257] = 12; /* 255: struct.ec_group_st */
    	em[258] = 282; em[259] = 0; 
    	em[260] = 454; em[261] = 8; 
    	em[262] = 459; em[263] = 16; 
    	em[264] = 459; em[265] = 40; 
    	em[266] = 471; em[267] = 80; 
    	em[268] = 479; em[269] = 96; 
    	em[270] = 459; em[271] = 104; 
    	em[272] = 459; em[273] = 152; 
    	em[274] = 459; em[275] = 176; 
    	em[276] = 241; em[277] = 208; 
    	em[278] = 241; em[279] = 216; 
    	em[280] = 502; em[281] = 224; 
    em[282] = 1; em[283] = 8; em[284] = 1; /* 282: pointer.struct.ec_method_st */
    	em[285] = 287; em[286] = 0; 
    em[287] = 0; em[288] = 304; em[289] = 37; /* 287: struct.ec_method_st */
    	em[290] = 364; em[291] = 8; 
    	em[292] = 367; em[293] = 16; 
    	em[294] = 367; em[295] = 24; 
    	em[296] = 370; em[297] = 32; 
    	em[298] = 373; em[299] = 40; 
    	em[300] = 376; em[301] = 48; 
    	em[302] = 379; em[303] = 56; 
    	em[304] = 382; em[305] = 64; 
    	em[306] = 385; em[307] = 72; 
    	em[308] = 388; em[309] = 80; 
    	em[310] = 388; em[311] = 88; 
    	em[312] = 391; em[313] = 96; 
    	em[314] = 394; em[315] = 104; 
    	em[316] = 397; em[317] = 112; 
    	em[318] = 400; em[319] = 120; 
    	em[320] = 403; em[321] = 128; 
    	em[322] = 406; em[323] = 136; 
    	em[324] = 409; em[325] = 144; 
    	em[326] = 412; em[327] = 152; 
    	em[328] = 415; em[329] = 160; 
    	em[330] = 418; em[331] = 168; 
    	em[332] = 421; em[333] = 176; 
    	em[334] = 424; em[335] = 184; 
    	em[336] = 427; em[337] = 192; 
    	em[338] = 430; em[339] = 200; 
    	em[340] = 433; em[341] = 208; 
    	em[342] = 424; em[343] = 216; 
    	em[344] = 436; em[345] = 224; 
    	em[346] = 439; em[347] = 232; 
    	em[348] = 442; em[349] = 240; 
    	em[350] = 379; em[351] = 248; 
    	em[352] = 445; em[353] = 256; 
    	em[354] = 448; em[355] = 264; 
    	em[356] = 445; em[357] = 272; 
    	em[358] = 448; em[359] = 280; 
    	em[360] = 448; em[361] = 288; 
    	em[362] = 451; em[363] = 296; 
    em[364] = 8884097; em[365] = 8; em[366] = 0; /* 364: pointer.func */
    em[367] = 8884097; em[368] = 8; em[369] = 0; /* 367: pointer.func */
    em[370] = 8884097; em[371] = 8; em[372] = 0; /* 370: pointer.func */
    em[373] = 8884097; em[374] = 8; em[375] = 0; /* 373: pointer.func */
    em[376] = 8884097; em[377] = 8; em[378] = 0; /* 376: pointer.func */
    em[379] = 8884097; em[380] = 8; em[381] = 0; /* 379: pointer.func */
    em[382] = 8884097; em[383] = 8; em[384] = 0; /* 382: pointer.func */
    em[385] = 8884097; em[386] = 8; em[387] = 0; /* 385: pointer.func */
    em[388] = 8884097; em[389] = 8; em[390] = 0; /* 388: pointer.func */
    em[391] = 8884097; em[392] = 8; em[393] = 0; /* 391: pointer.func */
    em[394] = 8884097; em[395] = 8; em[396] = 0; /* 394: pointer.func */
    em[397] = 8884097; em[398] = 8; em[399] = 0; /* 397: pointer.func */
    em[400] = 8884097; em[401] = 8; em[402] = 0; /* 400: pointer.func */
    em[403] = 8884097; em[404] = 8; em[405] = 0; /* 403: pointer.func */
    em[406] = 8884097; em[407] = 8; em[408] = 0; /* 406: pointer.func */
    em[409] = 8884097; em[410] = 8; em[411] = 0; /* 409: pointer.func */
    em[412] = 8884097; em[413] = 8; em[414] = 0; /* 412: pointer.func */
    em[415] = 8884097; em[416] = 8; em[417] = 0; /* 415: pointer.func */
    em[418] = 8884097; em[419] = 8; em[420] = 0; /* 418: pointer.func */
    em[421] = 8884097; em[422] = 8; em[423] = 0; /* 421: pointer.func */
    em[424] = 8884097; em[425] = 8; em[426] = 0; /* 424: pointer.func */
    em[427] = 8884097; em[428] = 8; em[429] = 0; /* 427: pointer.func */
    em[430] = 8884097; em[431] = 8; em[432] = 0; /* 430: pointer.func */
    em[433] = 8884097; em[434] = 8; em[435] = 0; /* 433: pointer.func */
    em[436] = 8884097; em[437] = 8; em[438] = 0; /* 436: pointer.func */
    em[439] = 8884097; em[440] = 8; em[441] = 0; /* 439: pointer.func */
    em[442] = 8884097; em[443] = 8; em[444] = 0; /* 442: pointer.func */
    em[445] = 8884097; em[446] = 8; em[447] = 0; /* 445: pointer.func */
    em[448] = 8884097; em[449] = 8; em[450] = 0; /* 448: pointer.func */
    em[451] = 8884097; em[452] = 8; em[453] = 0; /* 451: pointer.func */
    em[454] = 1; em[455] = 8; em[456] = 1; /* 454: pointer.struct.ec_point_st */
    	em[457] = 28; em[458] = 0; 
    em[459] = 0; em[460] = 24; em[461] = 1; /* 459: struct.bignum_st */
    	em[462] = 464; em[463] = 0; 
    em[464] = 8884099; em[465] = 8; em[466] = 2; /* 464: pointer_to_array_of_pointers_to_stack */
    	em[467] = 17; em[468] = 0; 
    	em[469] = 20; em[470] = 12; 
    em[471] = 1; em[472] = 8; em[473] = 1; /* 471: pointer.unsigned char */
    	em[474] = 476; em[475] = 0; 
    em[476] = 0; em[477] = 1; em[478] = 0; /* 476: unsigned char */
    em[479] = 1; em[480] = 8; em[481] = 1; /* 479: pointer.struct.ec_extra_data_st */
    	em[482] = 484; em[483] = 0; 
    em[484] = 0; em[485] = 40; em[486] = 5; /* 484: struct.ec_extra_data_st */
    	em[487] = 497; em[488] = 0; 
    	em[489] = 241; em[490] = 8; 
    	em[491] = 244; em[492] = 16; 
    	em[493] = 247; em[494] = 24; 
    	em[495] = 247; em[496] = 32; 
    em[497] = 1; em[498] = 8; em[499] = 1; /* 497: pointer.struct.ec_extra_data_st */
    	em[500] = 484; em[501] = 0; 
    em[502] = 8884097; em[503] = 8; em[504] = 0; /* 502: pointer.func */
    em[505] = 0; em[506] = 56; em[507] = 4; /* 505: struct.ec_key_st */
    	em[508] = 250; em[509] = 8; 
    	em[510] = 23; em[511] = 16; 
    	em[512] = 0; em[513] = 24; 
    	em[514] = 516; em[515] = 48; 
    em[516] = 1; em[517] = 8; em[518] = 1; /* 516: pointer.struct.ec_extra_data_st */
    	em[519] = 228; em[520] = 0; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_key_st */
    	em[524] = 505; em[525] = 0; 
    em[526] = 1; em[527] = 8; em[528] = 1; /* 526: pointer.struct.ec_group_st */
    	em[529] = 255; em[530] = 0; 
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

