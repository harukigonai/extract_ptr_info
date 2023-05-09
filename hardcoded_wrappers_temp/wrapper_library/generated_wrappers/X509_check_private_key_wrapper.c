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

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b);

int X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_check_private_key called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_check_private_key(arg_a,arg_b);
    else {
        int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
        orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
        return orig_X509_check_private_key(arg_a,arg_b);
    }
}

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.dh_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 144; em[7] = 12; /* 5: struct.dh_st */
    	em[8] = 32; em[9] = 8; 
    	em[10] = 32; em[11] = 16; 
    	em[12] = 32; em[13] = 32; 
    	em[14] = 32; em[15] = 40; 
    	em[16] = 55; em[17] = 56; 
    	em[18] = 32; em[19] = 64; 
    	em[20] = 32; em[21] = 72; 
    	em[22] = 69; em[23] = 80; 
    	em[24] = 32; em[25] = 96; 
    	em[26] = 77; em[27] = 112; 
    	em[28] = 97; em[29] = 128; 
    	em[30] = 143; em[31] = 136; 
    em[32] = 1; em[33] = 8; em[34] = 1; /* 32: pointer.struct.bignum_st */
    	em[35] = 37; em[36] = 0; 
    em[37] = 0; em[38] = 24; em[39] = 1; /* 37: struct.bignum_st */
    	em[40] = 42; em[41] = 0; 
    em[42] = 8884099; em[43] = 8; em[44] = 2; /* 42: pointer_to_array_of_pointers_to_stack */
    	em[45] = 49; em[46] = 0; 
    	em[47] = 52; em[48] = 12; 
    em[49] = 0; em[50] = 8; em[51] = 0; /* 49: long unsigned int */
    em[52] = 0; em[53] = 4; em[54] = 0; /* 52: int */
    em[55] = 1; em[56] = 8; em[57] = 1; /* 55: pointer.struct.bn_mont_ctx_st */
    	em[58] = 60; em[59] = 0; 
    em[60] = 0; em[61] = 96; em[62] = 3; /* 60: struct.bn_mont_ctx_st */
    	em[63] = 37; em[64] = 8; 
    	em[65] = 37; em[66] = 32; 
    	em[67] = 37; em[68] = 56; 
    em[69] = 1; em[70] = 8; em[71] = 1; /* 69: pointer.unsigned char */
    	em[72] = 74; em[73] = 0; 
    em[74] = 0; em[75] = 1; em[76] = 0; /* 74: unsigned char */
    em[77] = 0; em[78] = 32; em[79] = 2; /* 77: struct.crypto_ex_data_st_fake */
    	em[80] = 84; em[81] = 8; 
    	em[82] = 94; em[83] = 24; 
    em[84] = 8884099; em[85] = 8; em[86] = 2; /* 84: pointer_to_array_of_pointers_to_stack */
    	em[87] = 91; em[88] = 0; 
    	em[89] = 52; em[90] = 20; 
    em[91] = 0; em[92] = 8; em[93] = 0; /* 91: pointer.void */
    em[94] = 8884097; em[95] = 8; em[96] = 0; /* 94: pointer.func */
    em[97] = 1; em[98] = 8; em[99] = 1; /* 97: pointer.struct.dh_method */
    	em[100] = 102; em[101] = 0; 
    em[102] = 0; em[103] = 72; em[104] = 8; /* 102: struct.dh_method */
    	em[105] = 121; em[106] = 0; 
    	em[107] = 126; em[108] = 8; 
    	em[109] = 129; em[110] = 16; 
    	em[111] = 132; em[112] = 24; 
    	em[113] = 126; em[114] = 32; 
    	em[115] = 126; em[116] = 40; 
    	em[117] = 135; em[118] = 56; 
    	em[119] = 140; em[120] = 64; 
    em[121] = 1; em[122] = 8; em[123] = 1; /* 121: pointer.char */
    	em[124] = 8884096; em[125] = 0; 
    em[126] = 8884097; em[127] = 8; em[128] = 0; /* 126: pointer.func */
    em[129] = 8884097; em[130] = 8; em[131] = 0; /* 129: pointer.func */
    em[132] = 8884097; em[133] = 8; em[134] = 0; /* 132: pointer.func */
    em[135] = 1; em[136] = 8; em[137] = 1; /* 135: pointer.char */
    	em[138] = 8884096; em[139] = 0; 
    em[140] = 8884097; em[141] = 8; em[142] = 0; /* 140: pointer.func */
    em[143] = 1; em[144] = 8; em[145] = 1; /* 143: pointer.struct.engine_st */
    	em[146] = 148; em[147] = 0; 
    em[148] = 0; em[149] = 216; em[150] = 24; /* 148: struct.engine_st */
    	em[151] = 121; em[152] = 0; 
    	em[153] = 121; em[154] = 8; 
    	em[155] = 199; em[156] = 16; 
    	em[157] = 254; em[158] = 24; 
    	em[159] = 305; em[160] = 32; 
    	em[161] = 341; em[162] = 40; 
    	em[163] = 358; em[164] = 48; 
    	em[165] = 385; em[166] = 56; 
    	em[167] = 420; em[168] = 64; 
    	em[169] = 428; em[170] = 72; 
    	em[171] = 431; em[172] = 80; 
    	em[173] = 434; em[174] = 88; 
    	em[175] = 437; em[176] = 96; 
    	em[177] = 440; em[178] = 104; 
    	em[179] = 440; em[180] = 112; 
    	em[181] = 440; em[182] = 120; 
    	em[183] = 443; em[184] = 128; 
    	em[185] = 446; em[186] = 136; 
    	em[187] = 446; em[188] = 144; 
    	em[189] = 449; em[190] = 152; 
    	em[191] = 452; em[192] = 160; 
    	em[193] = 464; em[194] = 184; 
    	em[195] = 478; em[196] = 200; 
    	em[197] = 478; em[198] = 208; 
    em[199] = 1; em[200] = 8; em[201] = 1; /* 199: pointer.struct.rsa_meth_st */
    	em[202] = 204; em[203] = 0; 
    em[204] = 0; em[205] = 112; em[206] = 13; /* 204: struct.rsa_meth_st */
    	em[207] = 121; em[208] = 0; 
    	em[209] = 233; em[210] = 8; 
    	em[211] = 233; em[212] = 16; 
    	em[213] = 233; em[214] = 24; 
    	em[215] = 233; em[216] = 32; 
    	em[217] = 236; em[218] = 40; 
    	em[219] = 239; em[220] = 48; 
    	em[221] = 242; em[222] = 56; 
    	em[223] = 242; em[224] = 64; 
    	em[225] = 135; em[226] = 80; 
    	em[227] = 245; em[228] = 88; 
    	em[229] = 248; em[230] = 96; 
    	em[231] = 251; em[232] = 104; 
    em[233] = 8884097; em[234] = 8; em[235] = 0; /* 233: pointer.func */
    em[236] = 8884097; em[237] = 8; em[238] = 0; /* 236: pointer.func */
    em[239] = 8884097; em[240] = 8; em[241] = 0; /* 239: pointer.func */
    em[242] = 8884097; em[243] = 8; em[244] = 0; /* 242: pointer.func */
    em[245] = 8884097; em[246] = 8; em[247] = 0; /* 245: pointer.func */
    em[248] = 8884097; em[249] = 8; em[250] = 0; /* 248: pointer.func */
    em[251] = 8884097; em[252] = 8; em[253] = 0; /* 251: pointer.func */
    em[254] = 1; em[255] = 8; em[256] = 1; /* 254: pointer.struct.dsa_method */
    	em[257] = 259; em[258] = 0; 
    em[259] = 0; em[260] = 96; em[261] = 11; /* 259: struct.dsa_method */
    	em[262] = 121; em[263] = 0; 
    	em[264] = 284; em[265] = 8; 
    	em[266] = 287; em[267] = 16; 
    	em[268] = 290; em[269] = 24; 
    	em[270] = 293; em[271] = 32; 
    	em[272] = 296; em[273] = 40; 
    	em[274] = 299; em[275] = 48; 
    	em[276] = 299; em[277] = 56; 
    	em[278] = 135; em[279] = 72; 
    	em[280] = 302; em[281] = 80; 
    	em[282] = 299; em[283] = 88; 
    em[284] = 8884097; em[285] = 8; em[286] = 0; /* 284: pointer.func */
    em[287] = 8884097; em[288] = 8; em[289] = 0; /* 287: pointer.func */
    em[290] = 8884097; em[291] = 8; em[292] = 0; /* 290: pointer.func */
    em[293] = 8884097; em[294] = 8; em[295] = 0; /* 293: pointer.func */
    em[296] = 8884097; em[297] = 8; em[298] = 0; /* 296: pointer.func */
    em[299] = 8884097; em[300] = 8; em[301] = 0; /* 299: pointer.func */
    em[302] = 8884097; em[303] = 8; em[304] = 0; /* 302: pointer.func */
    em[305] = 1; em[306] = 8; em[307] = 1; /* 305: pointer.struct.dh_method */
    	em[308] = 310; em[309] = 0; 
    em[310] = 0; em[311] = 72; em[312] = 8; /* 310: struct.dh_method */
    	em[313] = 121; em[314] = 0; 
    	em[315] = 329; em[316] = 8; 
    	em[317] = 332; em[318] = 16; 
    	em[319] = 335; em[320] = 24; 
    	em[321] = 329; em[322] = 32; 
    	em[323] = 329; em[324] = 40; 
    	em[325] = 135; em[326] = 56; 
    	em[327] = 338; em[328] = 64; 
    em[329] = 8884097; em[330] = 8; em[331] = 0; /* 329: pointer.func */
    em[332] = 8884097; em[333] = 8; em[334] = 0; /* 332: pointer.func */
    em[335] = 8884097; em[336] = 8; em[337] = 0; /* 335: pointer.func */
    em[338] = 8884097; em[339] = 8; em[340] = 0; /* 338: pointer.func */
    em[341] = 1; em[342] = 8; em[343] = 1; /* 341: pointer.struct.ecdh_method */
    	em[344] = 346; em[345] = 0; 
    em[346] = 0; em[347] = 32; em[348] = 3; /* 346: struct.ecdh_method */
    	em[349] = 121; em[350] = 0; 
    	em[351] = 355; em[352] = 8; 
    	em[353] = 135; em[354] = 24; 
    em[355] = 8884097; em[356] = 8; em[357] = 0; /* 355: pointer.func */
    em[358] = 1; em[359] = 8; em[360] = 1; /* 358: pointer.struct.ecdsa_method */
    	em[361] = 363; em[362] = 0; 
    em[363] = 0; em[364] = 48; em[365] = 5; /* 363: struct.ecdsa_method */
    	em[366] = 121; em[367] = 0; 
    	em[368] = 376; em[369] = 8; 
    	em[370] = 379; em[371] = 16; 
    	em[372] = 382; em[373] = 24; 
    	em[374] = 135; em[375] = 40; 
    em[376] = 8884097; em[377] = 8; em[378] = 0; /* 376: pointer.func */
    em[379] = 8884097; em[380] = 8; em[381] = 0; /* 379: pointer.func */
    em[382] = 8884097; em[383] = 8; em[384] = 0; /* 382: pointer.func */
    em[385] = 1; em[386] = 8; em[387] = 1; /* 385: pointer.struct.rand_meth_st */
    	em[388] = 390; em[389] = 0; 
    em[390] = 0; em[391] = 48; em[392] = 6; /* 390: struct.rand_meth_st */
    	em[393] = 405; em[394] = 0; 
    	em[395] = 408; em[396] = 8; 
    	em[397] = 411; em[398] = 16; 
    	em[399] = 414; em[400] = 24; 
    	em[401] = 408; em[402] = 32; 
    	em[403] = 417; em[404] = 40; 
    em[405] = 8884097; em[406] = 8; em[407] = 0; /* 405: pointer.func */
    em[408] = 8884097; em[409] = 8; em[410] = 0; /* 408: pointer.func */
    em[411] = 8884097; em[412] = 8; em[413] = 0; /* 411: pointer.func */
    em[414] = 8884097; em[415] = 8; em[416] = 0; /* 414: pointer.func */
    em[417] = 8884097; em[418] = 8; em[419] = 0; /* 417: pointer.func */
    em[420] = 1; em[421] = 8; em[422] = 1; /* 420: pointer.struct.store_method_st */
    	em[423] = 425; em[424] = 0; 
    em[425] = 0; em[426] = 0; em[427] = 0; /* 425: struct.store_method_st */
    em[428] = 8884097; em[429] = 8; em[430] = 0; /* 428: pointer.func */
    em[431] = 8884097; em[432] = 8; em[433] = 0; /* 431: pointer.func */
    em[434] = 8884097; em[435] = 8; em[436] = 0; /* 434: pointer.func */
    em[437] = 8884097; em[438] = 8; em[439] = 0; /* 437: pointer.func */
    em[440] = 8884097; em[441] = 8; em[442] = 0; /* 440: pointer.func */
    em[443] = 8884097; em[444] = 8; em[445] = 0; /* 443: pointer.func */
    em[446] = 8884097; em[447] = 8; em[448] = 0; /* 446: pointer.func */
    em[449] = 8884097; em[450] = 8; em[451] = 0; /* 449: pointer.func */
    em[452] = 1; em[453] = 8; em[454] = 1; /* 452: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[455] = 457; em[456] = 0; 
    em[457] = 0; em[458] = 32; em[459] = 2; /* 457: struct.ENGINE_CMD_DEFN_st */
    	em[460] = 121; em[461] = 8; 
    	em[462] = 121; em[463] = 16; 
    em[464] = 0; em[465] = 32; em[466] = 2; /* 464: struct.crypto_ex_data_st_fake */
    	em[467] = 471; em[468] = 8; 
    	em[469] = 94; em[470] = 24; 
    em[471] = 8884099; em[472] = 8; em[473] = 2; /* 471: pointer_to_array_of_pointers_to_stack */
    	em[474] = 91; em[475] = 0; 
    	em[476] = 52; em[477] = 20; 
    em[478] = 1; em[479] = 8; em[480] = 1; /* 478: pointer.struct.engine_st */
    	em[481] = 148; em[482] = 0; 
    em[483] = 1; em[484] = 8; em[485] = 1; /* 483: pointer.struct.dsa_st */
    	em[486] = 488; em[487] = 0; 
    em[488] = 0; em[489] = 136; em[490] = 11; /* 488: struct.dsa_st */
    	em[491] = 513; em[492] = 24; 
    	em[493] = 513; em[494] = 32; 
    	em[495] = 513; em[496] = 40; 
    	em[497] = 513; em[498] = 48; 
    	em[499] = 513; em[500] = 56; 
    	em[501] = 513; em[502] = 64; 
    	em[503] = 513; em[504] = 72; 
    	em[505] = 530; em[506] = 88; 
    	em[507] = 544; em[508] = 104; 
    	em[509] = 558; em[510] = 120; 
    	em[511] = 609; em[512] = 128; 
    em[513] = 1; em[514] = 8; em[515] = 1; /* 513: pointer.struct.bignum_st */
    	em[516] = 518; em[517] = 0; 
    em[518] = 0; em[519] = 24; em[520] = 1; /* 518: struct.bignum_st */
    	em[521] = 523; em[522] = 0; 
    em[523] = 8884099; em[524] = 8; em[525] = 2; /* 523: pointer_to_array_of_pointers_to_stack */
    	em[526] = 49; em[527] = 0; 
    	em[528] = 52; em[529] = 12; 
    em[530] = 1; em[531] = 8; em[532] = 1; /* 530: pointer.struct.bn_mont_ctx_st */
    	em[533] = 535; em[534] = 0; 
    em[535] = 0; em[536] = 96; em[537] = 3; /* 535: struct.bn_mont_ctx_st */
    	em[538] = 518; em[539] = 8; 
    	em[540] = 518; em[541] = 32; 
    	em[542] = 518; em[543] = 56; 
    em[544] = 0; em[545] = 32; em[546] = 2; /* 544: struct.crypto_ex_data_st_fake */
    	em[547] = 551; em[548] = 8; 
    	em[549] = 94; em[550] = 24; 
    em[551] = 8884099; em[552] = 8; em[553] = 2; /* 551: pointer_to_array_of_pointers_to_stack */
    	em[554] = 91; em[555] = 0; 
    	em[556] = 52; em[557] = 20; 
    em[558] = 1; em[559] = 8; em[560] = 1; /* 558: pointer.struct.dsa_method */
    	em[561] = 563; em[562] = 0; 
    em[563] = 0; em[564] = 96; em[565] = 11; /* 563: struct.dsa_method */
    	em[566] = 121; em[567] = 0; 
    	em[568] = 588; em[569] = 8; 
    	em[570] = 591; em[571] = 16; 
    	em[572] = 594; em[573] = 24; 
    	em[574] = 597; em[575] = 32; 
    	em[576] = 600; em[577] = 40; 
    	em[578] = 603; em[579] = 48; 
    	em[580] = 603; em[581] = 56; 
    	em[582] = 135; em[583] = 72; 
    	em[584] = 606; em[585] = 80; 
    	em[586] = 603; em[587] = 88; 
    em[588] = 8884097; em[589] = 8; em[590] = 0; /* 588: pointer.func */
    em[591] = 8884097; em[592] = 8; em[593] = 0; /* 591: pointer.func */
    em[594] = 8884097; em[595] = 8; em[596] = 0; /* 594: pointer.func */
    em[597] = 8884097; em[598] = 8; em[599] = 0; /* 597: pointer.func */
    em[600] = 8884097; em[601] = 8; em[602] = 0; /* 600: pointer.func */
    em[603] = 8884097; em[604] = 8; em[605] = 0; /* 603: pointer.func */
    em[606] = 8884097; em[607] = 8; em[608] = 0; /* 606: pointer.func */
    em[609] = 1; em[610] = 8; em[611] = 1; /* 609: pointer.struct.engine_st */
    	em[612] = 148; em[613] = 0; 
    em[614] = 1; em[615] = 8; em[616] = 1; /* 614: pointer.struct.rsa_st */
    	em[617] = 619; em[618] = 0; 
    em[619] = 0; em[620] = 168; em[621] = 17; /* 619: struct.rsa_st */
    	em[622] = 656; em[623] = 16; 
    	em[624] = 711; em[625] = 24; 
    	em[626] = 716; em[627] = 32; 
    	em[628] = 716; em[629] = 40; 
    	em[630] = 716; em[631] = 48; 
    	em[632] = 716; em[633] = 56; 
    	em[634] = 716; em[635] = 64; 
    	em[636] = 716; em[637] = 72; 
    	em[638] = 716; em[639] = 80; 
    	em[640] = 716; em[641] = 88; 
    	em[642] = 733; em[643] = 96; 
    	em[644] = 747; em[645] = 120; 
    	em[646] = 747; em[647] = 128; 
    	em[648] = 747; em[649] = 136; 
    	em[650] = 135; em[651] = 144; 
    	em[652] = 761; em[653] = 152; 
    	em[654] = 761; em[655] = 160; 
    em[656] = 1; em[657] = 8; em[658] = 1; /* 656: pointer.struct.rsa_meth_st */
    	em[659] = 661; em[660] = 0; 
    em[661] = 0; em[662] = 112; em[663] = 13; /* 661: struct.rsa_meth_st */
    	em[664] = 121; em[665] = 0; 
    	em[666] = 690; em[667] = 8; 
    	em[668] = 690; em[669] = 16; 
    	em[670] = 690; em[671] = 24; 
    	em[672] = 690; em[673] = 32; 
    	em[674] = 693; em[675] = 40; 
    	em[676] = 696; em[677] = 48; 
    	em[678] = 699; em[679] = 56; 
    	em[680] = 699; em[681] = 64; 
    	em[682] = 135; em[683] = 80; 
    	em[684] = 702; em[685] = 88; 
    	em[686] = 705; em[687] = 96; 
    	em[688] = 708; em[689] = 104; 
    em[690] = 8884097; em[691] = 8; em[692] = 0; /* 690: pointer.func */
    em[693] = 8884097; em[694] = 8; em[695] = 0; /* 693: pointer.func */
    em[696] = 8884097; em[697] = 8; em[698] = 0; /* 696: pointer.func */
    em[699] = 8884097; em[700] = 8; em[701] = 0; /* 699: pointer.func */
    em[702] = 8884097; em[703] = 8; em[704] = 0; /* 702: pointer.func */
    em[705] = 8884097; em[706] = 8; em[707] = 0; /* 705: pointer.func */
    em[708] = 8884097; em[709] = 8; em[710] = 0; /* 708: pointer.func */
    em[711] = 1; em[712] = 8; em[713] = 1; /* 711: pointer.struct.engine_st */
    	em[714] = 148; em[715] = 0; 
    em[716] = 1; em[717] = 8; em[718] = 1; /* 716: pointer.struct.bignum_st */
    	em[719] = 721; em[720] = 0; 
    em[721] = 0; em[722] = 24; em[723] = 1; /* 721: struct.bignum_st */
    	em[724] = 726; em[725] = 0; 
    em[726] = 8884099; em[727] = 8; em[728] = 2; /* 726: pointer_to_array_of_pointers_to_stack */
    	em[729] = 49; em[730] = 0; 
    	em[731] = 52; em[732] = 12; 
    em[733] = 0; em[734] = 32; em[735] = 2; /* 733: struct.crypto_ex_data_st_fake */
    	em[736] = 740; em[737] = 8; 
    	em[738] = 94; em[739] = 24; 
    em[740] = 8884099; em[741] = 8; em[742] = 2; /* 740: pointer_to_array_of_pointers_to_stack */
    	em[743] = 91; em[744] = 0; 
    	em[745] = 52; em[746] = 20; 
    em[747] = 1; em[748] = 8; em[749] = 1; /* 747: pointer.struct.bn_mont_ctx_st */
    	em[750] = 752; em[751] = 0; 
    em[752] = 0; em[753] = 96; em[754] = 3; /* 752: struct.bn_mont_ctx_st */
    	em[755] = 721; em[756] = 8; 
    	em[757] = 721; em[758] = 32; 
    	em[759] = 721; em[760] = 56; 
    em[761] = 1; em[762] = 8; em[763] = 1; /* 761: pointer.struct.bn_blinding_st */
    	em[764] = 766; em[765] = 0; 
    em[766] = 0; em[767] = 88; em[768] = 7; /* 766: struct.bn_blinding_st */
    	em[769] = 783; em[770] = 0; 
    	em[771] = 783; em[772] = 8; 
    	em[773] = 783; em[774] = 16; 
    	em[775] = 783; em[776] = 24; 
    	em[777] = 800; em[778] = 40; 
    	em[779] = 805; em[780] = 72; 
    	em[781] = 819; em[782] = 80; 
    em[783] = 1; em[784] = 8; em[785] = 1; /* 783: pointer.struct.bignum_st */
    	em[786] = 788; em[787] = 0; 
    em[788] = 0; em[789] = 24; em[790] = 1; /* 788: struct.bignum_st */
    	em[791] = 793; em[792] = 0; 
    em[793] = 8884099; em[794] = 8; em[795] = 2; /* 793: pointer_to_array_of_pointers_to_stack */
    	em[796] = 49; em[797] = 0; 
    	em[798] = 52; em[799] = 12; 
    em[800] = 0; em[801] = 16; em[802] = 1; /* 800: struct.crypto_threadid_st */
    	em[803] = 91; em[804] = 0; 
    em[805] = 1; em[806] = 8; em[807] = 1; /* 805: pointer.struct.bn_mont_ctx_st */
    	em[808] = 810; em[809] = 0; 
    em[810] = 0; em[811] = 96; em[812] = 3; /* 810: struct.bn_mont_ctx_st */
    	em[813] = 788; em[814] = 8; 
    	em[815] = 788; em[816] = 32; 
    	em[817] = 788; em[818] = 56; 
    em[819] = 8884097; em[820] = 8; em[821] = 0; /* 819: pointer.func */
    em[822] = 0; em[823] = 56; em[824] = 4; /* 822: struct.evp_pkey_st */
    	em[825] = 833; em[826] = 16; 
    	em[827] = 934; em[828] = 24; 
    	em[829] = 939; em[830] = 32; 
    	em[831] = 1463; em[832] = 48; 
    em[833] = 1; em[834] = 8; em[835] = 1; /* 833: pointer.struct.evp_pkey_asn1_method_st */
    	em[836] = 838; em[837] = 0; 
    em[838] = 0; em[839] = 208; em[840] = 24; /* 838: struct.evp_pkey_asn1_method_st */
    	em[841] = 135; em[842] = 16; 
    	em[843] = 135; em[844] = 24; 
    	em[845] = 889; em[846] = 32; 
    	em[847] = 892; em[848] = 40; 
    	em[849] = 895; em[850] = 48; 
    	em[851] = 898; em[852] = 56; 
    	em[853] = 901; em[854] = 64; 
    	em[855] = 904; em[856] = 72; 
    	em[857] = 898; em[858] = 80; 
    	em[859] = 907; em[860] = 88; 
    	em[861] = 907; em[862] = 96; 
    	em[863] = 910; em[864] = 104; 
    	em[865] = 913; em[866] = 112; 
    	em[867] = 907; em[868] = 120; 
    	em[869] = 916; em[870] = 128; 
    	em[871] = 895; em[872] = 136; 
    	em[873] = 898; em[874] = 144; 
    	em[875] = 919; em[876] = 152; 
    	em[877] = 922; em[878] = 160; 
    	em[879] = 925; em[880] = 168; 
    	em[881] = 910; em[882] = 176; 
    	em[883] = 913; em[884] = 184; 
    	em[885] = 928; em[886] = 192; 
    	em[887] = 931; em[888] = 200; 
    em[889] = 8884097; em[890] = 8; em[891] = 0; /* 889: pointer.func */
    em[892] = 8884097; em[893] = 8; em[894] = 0; /* 892: pointer.func */
    em[895] = 8884097; em[896] = 8; em[897] = 0; /* 895: pointer.func */
    em[898] = 8884097; em[899] = 8; em[900] = 0; /* 898: pointer.func */
    em[901] = 8884097; em[902] = 8; em[903] = 0; /* 901: pointer.func */
    em[904] = 8884097; em[905] = 8; em[906] = 0; /* 904: pointer.func */
    em[907] = 8884097; em[908] = 8; em[909] = 0; /* 907: pointer.func */
    em[910] = 8884097; em[911] = 8; em[912] = 0; /* 910: pointer.func */
    em[913] = 8884097; em[914] = 8; em[915] = 0; /* 913: pointer.func */
    em[916] = 8884097; em[917] = 8; em[918] = 0; /* 916: pointer.func */
    em[919] = 8884097; em[920] = 8; em[921] = 0; /* 919: pointer.func */
    em[922] = 8884097; em[923] = 8; em[924] = 0; /* 922: pointer.func */
    em[925] = 8884097; em[926] = 8; em[927] = 0; /* 925: pointer.func */
    em[928] = 8884097; em[929] = 8; em[930] = 0; /* 928: pointer.func */
    em[931] = 8884097; em[932] = 8; em[933] = 0; /* 931: pointer.func */
    em[934] = 1; em[935] = 8; em[936] = 1; /* 934: pointer.struct.engine_st */
    	em[937] = 148; em[938] = 0; 
    em[939] = 8884101; em[940] = 8; em[941] = 6; /* 939: union.union_of_evp_pkey_st */
    	em[942] = 91; em[943] = 0; 
    	em[944] = 614; em[945] = 6; 
    	em[946] = 483; em[947] = 116; 
    	em[948] = 0; em[949] = 28; 
    	em[950] = 954; em[951] = 408; 
    	em[952] = 52; em[953] = 0; 
    em[954] = 1; em[955] = 8; em[956] = 1; /* 954: pointer.struct.ec_key_st */
    	em[957] = 959; em[958] = 0; 
    em[959] = 0; em[960] = 56; em[961] = 4; /* 959: struct.ec_key_st */
    	em[962] = 970; em[963] = 8; 
    	em[964] = 1418; em[965] = 16; 
    	em[966] = 1423; em[967] = 24; 
    	em[968] = 1440; em[969] = 48; 
    em[970] = 1; em[971] = 8; em[972] = 1; /* 970: pointer.struct.ec_group_st */
    	em[973] = 975; em[974] = 0; 
    em[975] = 0; em[976] = 232; em[977] = 12; /* 975: struct.ec_group_st */
    	em[978] = 1002; em[979] = 0; 
    	em[980] = 1174; em[981] = 8; 
    	em[982] = 1374; em[983] = 16; 
    	em[984] = 1374; em[985] = 40; 
    	em[986] = 69; em[987] = 80; 
    	em[988] = 1386; em[989] = 96; 
    	em[990] = 1374; em[991] = 104; 
    	em[992] = 1374; em[993] = 152; 
    	em[994] = 1374; em[995] = 176; 
    	em[996] = 91; em[997] = 208; 
    	em[998] = 91; em[999] = 216; 
    	em[1000] = 1415; em[1001] = 224; 
    em[1002] = 1; em[1003] = 8; em[1004] = 1; /* 1002: pointer.struct.ec_method_st */
    	em[1005] = 1007; em[1006] = 0; 
    em[1007] = 0; em[1008] = 304; em[1009] = 37; /* 1007: struct.ec_method_st */
    	em[1010] = 1084; em[1011] = 8; 
    	em[1012] = 1087; em[1013] = 16; 
    	em[1014] = 1087; em[1015] = 24; 
    	em[1016] = 1090; em[1017] = 32; 
    	em[1018] = 1093; em[1019] = 40; 
    	em[1020] = 1096; em[1021] = 48; 
    	em[1022] = 1099; em[1023] = 56; 
    	em[1024] = 1102; em[1025] = 64; 
    	em[1026] = 1105; em[1027] = 72; 
    	em[1028] = 1108; em[1029] = 80; 
    	em[1030] = 1108; em[1031] = 88; 
    	em[1032] = 1111; em[1033] = 96; 
    	em[1034] = 1114; em[1035] = 104; 
    	em[1036] = 1117; em[1037] = 112; 
    	em[1038] = 1120; em[1039] = 120; 
    	em[1040] = 1123; em[1041] = 128; 
    	em[1042] = 1126; em[1043] = 136; 
    	em[1044] = 1129; em[1045] = 144; 
    	em[1046] = 1132; em[1047] = 152; 
    	em[1048] = 1135; em[1049] = 160; 
    	em[1050] = 1138; em[1051] = 168; 
    	em[1052] = 1141; em[1053] = 176; 
    	em[1054] = 1144; em[1055] = 184; 
    	em[1056] = 1147; em[1057] = 192; 
    	em[1058] = 1150; em[1059] = 200; 
    	em[1060] = 1153; em[1061] = 208; 
    	em[1062] = 1144; em[1063] = 216; 
    	em[1064] = 1156; em[1065] = 224; 
    	em[1066] = 1159; em[1067] = 232; 
    	em[1068] = 1162; em[1069] = 240; 
    	em[1070] = 1099; em[1071] = 248; 
    	em[1072] = 1165; em[1073] = 256; 
    	em[1074] = 1168; em[1075] = 264; 
    	em[1076] = 1165; em[1077] = 272; 
    	em[1078] = 1168; em[1079] = 280; 
    	em[1080] = 1168; em[1081] = 288; 
    	em[1082] = 1171; em[1083] = 296; 
    em[1084] = 8884097; em[1085] = 8; em[1086] = 0; /* 1084: pointer.func */
    em[1087] = 8884097; em[1088] = 8; em[1089] = 0; /* 1087: pointer.func */
    em[1090] = 8884097; em[1091] = 8; em[1092] = 0; /* 1090: pointer.func */
    em[1093] = 8884097; em[1094] = 8; em[1095] = 0; /* 1093: pointer.func */
    em[1096] = 8884097; em[1097] = 8; em[1098] = 0; /* 1096: pointer.func */
    em[1099] = 8884097; em[1100] = 8; em[1101] = 0; /* 1099: pointer.func */
    em[1102] = 8884097; em[1103] = 8; em[1104] = 0; /* 1102: pointer.func */
    em[1105] = 8884097; em[1106] = 8; em[1107] = 0; /* 1105: pointer.func */
    em[1108] = 8884097; em[1109] = 8; em[1110] = 0; /* 1108: pointer.func */
    em[1111] = 8884097; em[1112] = 8; em[1113] = 0; /* 1111: pointer.func */
    em[1114] = 8884097; em[1115] = 8; em[1116] = 0; /* 1114: pointer.func */
    em[1117] = 8884097; em[1118] = 8; em[1119] = 0; /* 1117: pointer.func */
    em[1120] = 8884097; em[1121] = 8; em[1122] = 0; /* 1120: pointer.func */
    em[1123] = 8884097; em[1124] = 8; em[1125] = 0; /* 1123: pointer.func */
    em[1126] = 8884097; em[1127] = 8; em[1128] = 0; /* 1126: pointer.func */
    em[1129] = 8884097; em[1130] = 8; em[1131] = 0; /* 1129: pointer.func */
    em[1132] = 8884097; em[1133] = 8; em[1134] = 0; /* 1132: pointer.func */
    em[1135] = 8884097; em[1136] = 8; em[1137] = 0; /* 1135: pointer.func */
    em[1138] = 8884097; em[1139] = 8; em[1140] = 0; /* 1138: pointer.func */
    em[1141] = 8884097; em[1142] = 8; em[1143] = 0; /* 1141: pointer.func */
    em[1144] = 8884097; em[1145] = 8; em[1146] = 0; /* 1144: pointer.func */
    em[1147] = 8884097; em[1148] = 8; em[1149] = 0; /* 1147: pointer.func */
    em[1150] = 8884097; em[1151] = 8; em[1152] = 0; /* 1150: pointer.func */
    em[1153] = 8884097; em[1154] = 8; em[1155] = 0; /* 1153: pointer.func */
    em[1156] = 8884097; em[1157] = 8; em[1158] = 0; /* 1156: pointer.func */
    em[1159] = 8884097; em[1160] = 8; em[1161] = 0; /* 1159: pointer.func */
    em[1162] = 8884097; em[1163] = 8; em[1164] = 0; /* 1162: pointer.func */
    em[1165] = 8884097; em[1166] = 8; em[1167] = 0; /* 1165: pointer.func */
    em[1168] = 8884097; em[1169] = 8; em[1170] = 0; /* 1168: pointer.func */
    em[1171] = 8884097; em[1172] = 8; em[1173] = 0; /* 1171: pointer.func */
    em[1174] = 1; em[1175] = 8; em[1176] = 1; /* 1174: pointer.struct.ec_point_st */
    	em[1177] = 1179; em[1178] = 0; 
    em[1179] = 0; em[1180] = 88; em[1181] = 4; /* 1179: struct.ec_point_st */
    	em[1182] = 1190; em[1183] = 0; 
    	em[1184] = 1362; em[1185] = 8; 
    	em[1186] = 1362; em[1187] = 32; 
    	em[1188] = 1362; em[1189] = 56; 
    em[1190] = 1; em[1191] = 8; em[1192] = 1; /* 1190: pointer.struct.ec_method_st */
    	em[1193] = 1195; em[1194] = 0; 
    em[1195] = 0; em[1196] = 304; em[1197] = 37; /* 1195: struct.ec_method_st */
    	em[1198] = 1272; em[1199] = 8; 
    	em[1200] = 1275; em[1201] = 16; 
    	em[1202] = 1275; em[1203] = 24; 
    	em[1204] = 1278; em[1205] = 32; 
    	em[1206] = 1281; em[1207] = 40; 
    	em[1208] = 1284; em[1209] = 48; 
    	em[1210] = 1287; em[1211] = 56; 
    	em[1212] = 1290; em[1213] = 64; 
    	em[1214] = 1293; em[1215] = 72; 
    	em[1216] = 1296; em[1217] = 80; 
    	em[1218] = 1296; em[1219] = 88; 
    	em[1220] = 1299; em[1221] = 96; 
    	em[1222] = 1302; em[1223] = 104; 
    	em[1224] = 1305; em[1225] = 112; 
    	em[1226] = 1308; em[1227] = 120; 
    	em[1228] = 1311; em[1229] = 128; 
    	em[1230] = 1314; em[1231] = 136; 
    	em[1232] = 1317; em[1233] = 144; 
    	em[1234] = 1320; em[1235] = 152; 
    	em[1236] = 1323; em[1237] = 160; 
    	em[1238] = 1326; em[1239] = 168; 
    	em[1240] = 1329; em[1241] = 176; 
    	em[1242] = 1332; em[1243] = 184; 
    	em[1244] = 1335; em[1245] = 192; 
    	em[1246] = 1338; em[1247] = 200; 
    	em[1248] = 1341; em[1249] = 208; 
    	em[1250] = 1332; em[1251] = 216; 
    	em[1252] = 1344; em[1253] = 224; 
    	em[1254] = 1347; em[1255] = 232; 
    	em[1256] = 1350; em[1257] = 240; 
    	em[1258] = 1287; em[1259] = 248; 
    	em[1260] = 1353; em[1261] = 256; 
    	em[1262] = 1356; em[1263] = 264; 
    	em[1264] = 1353; em[1265] = 272; 
    	em[1266] = 1356; em[1267] = 280; 
    	em[1268] = 1356; em[1269] = 288; 
    	em[1270] = 1359; em[1271] = 296; 
    em[1272] = 8884097; em[1273] = 8; em[1274] = 0; /* 1272: pointer.func */
    em[1275] = 8884097; em[1276] = 8; em[1277] = 0; /* 1275: pointer.func */
    em[1278] = 8884097; em[1279] = 8; em[1280] = 0; /* 1278: pointer.func */
    em[1281] = 8884097; em[1282] = 8; em[1283] = 0; /* 1281: pointer.func */
    em[1284] = 8884097; em[1285] = 8; em[1286] = 0; /* 1284: pointer.func */
    em[1287] = 8884097; em[1288] = 8; em[1289] = 0; /* 1287: pointer.func */
    em[1290] = 8884097; em[1291] = 8; em[1292] = 0; /* 1290: pointer.func */
    em[1293] = 8884097; em[1294] = 8; em[1295] = 0; /* 1293: pointer.func */
    em[1296] = 8884097; em[1297] = 8; em[1298] = 0; /* 1296: pointer.func */
    em[1299] = 8884097; em[1300] = 8; em[1301] = 0; /* 1299: pointer.func */
    em[1302] = 8884097; em[1303] = 8; em[1304] = 0; /* 1302: pointer.func */
    em[1305] = 8884097; em[1306] = 8; em[1307] = 0; /* 1305: pointer.func */
    em[1308] = 8884097; em[1309] = 8; em[1310] = 0; /* 1308: pointer.func */
    em[1311] = 8884097; em[1312] = 8; em[1313] = 0; /* 1311: pointer.func */
    em[1314] = 8884097; em[1315] = 8; em[1316] = 0; /* 1314: pointer.func */
    em[1317] = 8884097; em[1318] = 8; em[1319] = 0; /* 1317: pointer.func */
    em[1320] = 8884097; em[1321] = 8; em[1322] = 0; /* 1320: pointer.func */
    em[1323] = 8884097; em[1324] = 8; em[1325] = 0; /* 1323: pointer.func */
    em[1326] = 8884097; em[1327] = 8; em[1328] = 0; /* 1326: pointer.func */
    em[1329] = 8884097; em[1330] = 8; em[1331] = 0; /* 1329: pointer.func */
    em[1332] = 8884097; em[1333] = 8; em[1334] = 0; /* 1332: pointer.func */
    em[1335] = 8884097; em[1336] = 8; em[1337] = 0; /* 1335: pointer.func */
    em[1338] = 8884097; em[1339] = 8; em[1340] = 0; /* 1338: pointer.func */
    em[1341] = 8884097; em[1342] = 8; em[1343] = 0; /* 1341: pointer.func */
    em[1344] = 8884097; em[1345] = 8; em[1346] = 0; /* 1344: pointer.func */
    em[1347] = 8884097; em[1348] = 8; em[1349] = 0; /* 1347: pointer.func */
    em[1350] = 8884097; em[1351] = 8; em[1352] = 0; /* 1350: pointer.func */
    em[1353] = 8884097; em[1354] = 8; em[1355] = 0; /* 1353: pointer.func */
    em[1356] = 8884097; em[1357] = 8; em[1358] = 0; /* 1356: pointer.func */
    em[1359] = 8884097; em[1360] = 8; em[1361] = 0; /* 1359: pointer.func */
    em[1362] = 0; em[1363] = 24; em[1364] = 1; /* 1362: struct.bignum_st */
    	em[1365] = 1367; em[1366] = 0; 
    em[1367] = 8884099; em[1368] = 8; em[1369] = 2; /* 1367: pointer_to_array_of_pointers_to_stack */
    	em[1370] = 49; em[1371] = 0; 
    	em[1372] = 52; em[1373] = 12; 
    em[1374] = 0; em[1375] = 24; em[1376] = 1; /* 1374: struct.bignum_st */
    	em[1377] = 1379; em[1378] = 0; 
    em[1379] = 8884099; em[1380] = 8; em[1381] = 2; /* 1379: pointer_to_array_of_pointers_to_stack */
    	em[1382] = 49; em[1383] = 0; 
    	em[1384] = 52; em[1385] = 12; 
    em[1386] = 1; em[1387] = 8; em[1388] = 1; /* 1386: pointer.struct.ec_extra_data_st */
    	em[1389] = 1391; em[1390] = 0; 
    em[1391] = 0; em[1392] = 40; em[1393] = 5; /* 1391: struct.ec_extra_data_st */
    	em[1394] = 1404; em[1395] = 0; 
    	em[1396] = 91; em[1397] = 8; 
    	em[1398] = 1409; em[1399] = 16; 
    	em[1400] = 1412; em[1401] = 24; 
    	em[1402] = 1412; em[1403] = 32; 
    em[1404] = 1; em[1405] = 8; em[1406] = 1; /* 1404: pointer.struct.ec_extra_data_st */
    	em[1407] = 1391; em[1408] = 0; 
    em[1409] = 8884097; em[1410] = 8; em[1411] = 0; /* 1409: pointer.func */
    em[1412] = 8884097; em[1413] = 8; em[1414] = 0; /* 1412: pointer.func */
    em[1415] = 8884097; em[1416] = 8; em[1417] = 0; /* 1415: pointer.func */
    em[1418] = 1; em[1419] = 8; em[1420] = 1; /* 1418: pointer.struct.ec_point_st */
    	em[1421] = 1179; em[1422] = 0; 
    em[1423] = 1; em[1424] = 8; em[1425] = 1; /* 1423: pointer.struct.bignum_st */
    	em[1426] = 1428; em[1427] = 0; 
    em[1428] = 0; em[1429] = 24; em[1430] = 1; /* 1428: struct.bignum_st */
    	em[1431] = 1433; em[1432] = 0; 
    em[1433] = 8884099; em[1434] = 8; em[1435] = 2; /* 1433: pointer_to_array_of_pointers_to_stack */
    	em[1436] = 49; em[1437] = 0; 
    	em[1438] = 52; em[1439] = 12; 
    em[1440] = 1; em[1441] = 8; em[1442] = 1; /* 1440: pointer.struct.ec_extra_data_st */
    	em[1443] = 1445; em[1444] = 0; 
    em[1445] = 0; em[1446] = 40; em[1447] = 5; /* 1445: struct.ec_extra_data_st */
    	em[1448] = 1458; em[1449] = 0; 
    	em[1450] = 91; em[1451] = 8; 
    	em[1452] = 1409; em[1453] = 16; 
    	em[1454] = 1412; em[1455] = 24; 
    	em[1456] = 1412; em[1457] = 32; 
    em[1458] = 1; em[1459] = 8; em[1460] = 1; /* 1458: pointer.struct.ec_extra_data_st */
    	em[1461] = 1445; em[1462] = 0; 
    em[1463] = 1; em[1464] = 8; em[1465] = 1; /* 1463: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1466] = 1468; em[1467] = 0; 
    em[1468] = 0; em[1469] = 32; em[1470] = 2; /* 1468: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1471] = 1475; em[1472] = 8; 
    	em[1473] = 94; em[1474] = 24; 
    em[1475] = 8884099; em[1476] = 8; em[1477] = 2; /* 1475: pointer_to_array_of_pointers_to_stack */
    	em[1478] = 1482; em[1479] = 0; 
    	em[1480] = 52; em[1481] = 20; 
    em[1482] = 0; em[1483] = 8; em[1484] = 1; /* 1482: pointer.X509_ATTRIBUTE */
    	em[1485] = 1487; em[1486] = 0; 
    em[1487] = 0; em[1488] = 0; em[1489] = 1; /* 1487: X509_ATTRIBUTE */
    	em[1490] = 1492; em[1491] = 0; 
    em[1492] = 0; em[1493] = 24; em[1494] = 2; /* 1492: struct.x509_attributes_st */
    	em[1495] = 1499; em[1496] = 0; 
    	em[1497] = 1518; em[1498] = 16; 
    em[1499] = 1; em[1500] = 8; em[1501] = 1; /* 1499: pointer.struct.asn1_object_st */
    	em[1502] = 1504; em[1503] = 0; 
    em[1504] = 0; em[1505] = 40; em[1506] = 3; /* 1504: struct.asn1_object_st */
    	em[1507] = 121; em[1508] = 0; 
    	em[1509] = 121; em[1510] = 8; 
    	em[1511] = 1513; em[1512] = 24; 
    em[1513] = 1; em[1514] = 8; em[1515] = 1; /* 1513: pointer.unsigned char */
    	em[1516] = 74; em[1517] = 0; 
    em[1518] = 0; em[1519] = 8; em[1520] = 3; /* 1518: union.unknown */
    	em[1521] = 135; em[1522] = 0; 
    	em[1523] = 1527; em[1524] = 0; 
    	em[1525] = 1706; em[1526] = 0; 
    em[1527] = 1; em[1528] = 8; em[1529] = 1; /* 1527: pointer.struct.stack_st_ASN1_TYPE */
    	em[1530] = 1532; em[1531] = 0; 
    em[1532] = 0; em[1533] = 32; em[1534] = 2; /* 1532: struct.stack_st_fake_ASN1_TYPE */
    	em[1535] = 1539; em[1536] = 8; 
    	em[1537] = 94; em[1538] = 24; 
    em[1539] = 8884099; em[1540] = 8; em[1541] = 2; /* 1539: pointer_to_array_of_pointers_to_stack */
    	em[1542] = 1546; em[1543] = 0; 
    	em[1544] = 52; em[1545] = 20; 
    em[1546] = 0; em[1547] = 8; em[1548] = 1; /* 1546: pointer.ASN1_TYPE */
    	em[1549] = 1551; em[1550] = 0; 
    em[1551] = 0; em[1552] = 0; em[1553] = 1; /* 1551: ASN1_TYPE */
    	em[1554] = 1556; em[1555] = 0; 
    em[1556] = 0; em[1557] = 16; em[1558] = 1; /* 1556: struct.asn1_type_st */
    	em[1559] = 1561; em[1560] = 8; 
    em[1561] = 0; em[1562] = 8; em[1563] = 20; /* 1561: union.unknown */
    	em[1564] = 135; em[1565] = 0; 
    	em[1566] = 1604; em[1567] = 0; 
    	em[1568] = 1614; em[1569] = 0; 
    	em[1570] = 1628; em[1571] = 0; 
    	em[1572] = 1633; em[1573] = 0; 
    	em[1574] = 1638; em[1575] = 0; 
    	em[1576] = 1643; em[1577] = 0; 
    	em[1578] = 1648; em[1579] = 0; 
    	em[1580] = 1653; em[1581] = 0; 
    	em[1582] = 1658; em[1583] = 0; 
    	em[1584] = 1663; em[1585] = 0; 
    	em[1586] = 1668; em[1587] = 0; 
    	em[1588] = 1673; em[1589] = 0; 
    	em[1590] = 1678; em[1591] = 0; 
    	em[1592] = 1683; em[1593] = 0; 
    	em[1594] = 1688; em[1595] = 0; 
    	em[1596] = 1693; em[1597] = 0; 
    	em[1598] = 1604; em[1599] = 0; 
    	em[1600] = 1604; em[1601] = 0; 
    	em[1602] = 1698; em[1603] = 0; 
    em[1604] = 1; em[1605] = 8; em[1606] = 1; /* 1604: pointer.struct.asn1_string_st */
    	em[1607] = 1609; em[1608] = 0; 
    em[1609] = 0; em[1610] = 24; em[1611] = 1; /* 1609: struct.asn1_string_st */
    	em[1612] = 69; em[1613] = 8; 
    em[1614] = 1; em[1615] = 8; em[1616] = 1; /* 1614: pointer.struct.asn1_object_st */
    	em[1617] = 1619; em[1618] = 0; 
    em[1619] = 0; em[1620] = 40; em[1621] = 3; /* 1619: struct.asn1_object_st */
    	em[1622] = 121; em[1623] = 0; 
    	em[1624] = 121; em[1625] = 8; 
    	em[1626] = 1513; em[1627] = 24; 
    em[1628] = 1; em[1629] = 8; em[1630] = 1; /* 1628: pointer.struct.asn1_string_st */
    	em[1631] = 1609; em[1632] = 0; 
    em[1633] = 1; em[1634] = 8; em[1635] = 1; /* 1633: pointer.struct.asn1_string_st */
    	em[1636] = 1609; em[1637] = 0; 
    em[1638] = 1; em[1639] = 8; em[1640] = 1; /* 1638: pointer.struct.asn1_string_st */
    	em[1641] = 1609; em[1642] = 0; 
    em[1643] = 1; em[1644] = 8; em[1645] = 1; /* 1643: pointer.struct.asn1_string_st */
    	em[1646] = 1609; em[1647] = 0; 
    em[1648] = 1; em[1649] = 8; em[1650] = 1; /* 1648: pointer.struct.asn1_string_st */
    	em[1651] = 1609; em[1652] = 0; 
    em[1653] = 1; em[1654] = 8; em[1655] = 1; /* 1653: pointer.struct.asn1_string_st */
    	em[1656] = 1609; em[1657] = 0; 
    em[1658] = 1; em[1659] = 8; em[1660] = 1; /* 1658: pointer.struct.asn1_string_st */
    	em[1661] = 1609; em[1662] = 0; 
    em[1663] = 1; em[1664] = 8; em[1665] = 1; /* 1663: pointer.struct.asn1_string_st */
    	em[1666] = 1609; em[1667] = 0; 
    em[1668] = 1; em[1669] = 8; em[1670] = 1; /* 1668: pointer.struct.asn1_string_st */
    	em[1671] = 1609; em[1672] = 0; 
    em[1673] = 1; em[1674] = 8; em[1675] = 1; /* 1673: pointer.struct.asn1_string_st */
    	em[1676] = 1609; em[1677] = 0; 
    em[1678] = 1; em[1679] = 8; em[1680] = 1; /* 1678: pointer.struct.asn1_string_st */
    	em[1681] = 1609; em[1682] = 0; 
    em[1683] = 1; em[1684] = 8; em[1685] = 1; /* 1683: pointer.struct.asn1_string_st */
    	em[1686] = 1609; em[1687] = 0; 
    em[1688] = 1; em[1689] = 8; em[1690] = 1; /* 1688: pointer.struct.asn1_string_st */
    	em[1691] = 1609; em[1692] = 0; 
    em[1693] = 1; em[1694] = 8; em[1695] = 1; /* 1693: pointer.struct.asn1_string_st */
    	em[1696] = 1609; em[1697] = 0; 
    em[1698] = 1; em[1699] = 8; em[1700] = 1; /* 1698: pointer.struct.ASN1_VALUE_st */
    	em[1701] = 1703; em[1702] = 0; 
    em[1703] = 0; em[1704] = 0; em[1705] = 0; /* 1703: struct.ASN1_VALUE_st */
    em[1706] = 1; em[1707] = 8; em[1708] = 1; /* 1706: pointer.struct.asn1_type_st */
    	em[1709] = 1711; em[1710] = 0; 
    em[1711] = 0; em[1712] = 16; em[1713] = 1; /* 1711: struct.asn1_type_st */
    	em[1714] = 1716; em[1715] = 8; 
    em[1716] = 0; em[1717] = 8; em[1718] = 20; /* 1716: union.unknown */
    	em[1719] = 135; em[1720] = 0; 
    	em[1721] = 1759; em[1722] = 0; 
    	em[1723] = 1499; em[1724] = 0; 
    	em[1725] = 1769; em[1726] = 0; 
    	em[1727] = 1774; em[1728] = 0; 
    	em[1729] = 1779; em[1730] = 0; 
    	em[1731] = 1784; em[1732] = 0; 
    	em[1733] = 1789; em[1734] = 0; 
    	em[1735] = 1794; em[1736] = 0; 
    	em[1737] = 1799; em[1738] = 0; 
    	em[1739] = 1804; em[1740] = 0; 
    	em[1741] = 1809; em[1742] = 0; 
    	em[1743] = 1814; em[1744] = 0; 
    	em[1745] = 1819; em[1746] = 0; 
    	em[1747] = 1824; em[1748] = 0; 
    	em[1749] = 1829; em[1750] = 0; 
    	em[1751] = 1834; em[1752] = 0; 
    	em[1753] = 1759; em[1754] = 0; 
    	em[1755] = 1759; em[1756] = 0; 
    	em[1757] = 1839; em[1758] = 0; 
    em[1759] = 1; em[1760] = 8; em[1761] = 1; /* 1759: pointer.struct.asn1_string_st */
    	em[1762] = 1764; em[1763] = 0; 
    em[1764] = 0; em[1765] = 24; em[1766] = 1; /* 1764: struct.asn1_string_st */
    	em[1767] = 69; em[1768] = 8; 
    em[1769] = 1; em[1770] = 8; em[1771] = 1; /* 1769: pointer.struct.asn1_string_st */
    	em[1772] = 1764; em[1773] = 0; 
    em[1774] = 1; em[1775] = 8; em[1776] = 1; /* 1774: pointer.struct.asn1_string_st */
    	em[1777] = 1764; em[1778] = 0; 
    em[1779] = 1; em[1780] = 8; em[1781] = 1; /* 1779: pointer.struct.asn1_string_st */
    	em[1782] = 1764; em[1783] = 0; 
    em[1784] = 1; em[1785] = 8; em[1786] = 1; /* 1784: pointer.struct.asn1_string_st */
    	em[1787] = 1764; em[1788] = 0; 
    em[1789] = 1; em[1790] = 8; em[1791] = 1; /* 1789: pointer.struct.asn1_string_st */
    	em[1792] = 1764; em[1793] = 0; 
    em[1794] = 1; em[1795] = 8; em[1796] = 1; /* 1794: pointer.struct.asn1_string_st */
    	em[1797] = 1764; em[1798] = 0; 
    em[1799] = 1; em[1800] = 8; em[1801] = 1; /* 1799: pointer.struct.asn1_string_st */
    	em[1802] = 1764; em[1803] = 0; 
    em[1804] = 1; em[1805] = 8; em[1806] = 1; /* 1804: pointer.struct.asn1_string_st */
    	em[1807] = 1764; em[1808] = 0; 
    em[1809] = 1; em[1810] = 8; em[1811] = 1; /* 1809: pointer.struct.asn1_string_st */
    	em[1812] = 1764; em[1813] = 0; 
    em[1814] = 1; em[1815] = 8; em[1816] = 1; /* 1814: pointer.struct.asn1_string_st */
    	em[1817] = 1764; em[1818] = 0; 
    em[1819] = 1; em[1820] = 8; em[1821] = 1; /* 1819: pointer.struct.asn1_string_st */
    	em[1822] = 1764; em[1823] = 0; 
    em[1824] = 1; em[1825] = 8; em[1826] = 1; /* 1824: pointer.struct.asn1_string_st */
    	em[1827] = 1764; em[1828] = 0; 
    em[1829] = 1; em[1830] = 8; em[1831] = 1; /* 1829: pointer.struct.asn1_string_st */
    	em[1832] = 1764; em[1833] = 0; 
    em[1834] = 1; em[1835] = 8; em[1836] = 1; /* 1834: pointer.struct.asn1_string_st */
    	em[1837] = 1764; em[1838] = 0; 
    em[1839] = 1; em[1840] = 8; em[1841] = 1; /* 1839: pointer.struct.ASN1_VALUE_st */
    	em[1842] = 1844; em[1843] = 0; 
    em[1844] = 0; em[1845] = 0; em[1846] = 0; /* 1844: struct.ASN1_VALUE_st */
    em[1847] = 1; em[1848] = 8; em[1849] = 1; /* 1847: pointer.struct.evp_pkey_st */
    	em[1850] = 822; em[1851] = 0; 
    em[1852] = 0; em[1853] = 0; em[1854] = 1; /* 1852: X509_ALGOR */
    	em[1855] = 1857; em[1856] = 0; 
    em[1857] = 0; em[1858] = 16; em[1859] = 2; /* 1857: struct.X509_algor_st */
    	em[1860] = 1864; em[1861] = 0; 
    	em[1862] = 1878; em[1863] = 8; 
    em[1864] = 1; em[1865] = 8; em[1866] = 1; /* 1864: pointer.struct.asn1_object_st */
    	em[1867] = 1869; em[1868] = 0; 
    em[1869] = 0; em[1870] = 40; em[1871] = 3; /* 1869: struct.asn1_object_st */
    	em[1872] = 121; em[1873] = 0; 
    	em[1874] = 121; em[1875] = 8; 
    	em[1876] = 1513; em[1877] = 24; 
    em[1878] = 1; em[1879] = 8; em[1880] = 1; /* 1878: pointer.struct.asn1_type_st */
    	em[1881] = 1883; em[1882] = 0; 
    em[1883] = 0; em[1884] = 16; em[1885] = 1; /* 1883: struct.asn1_type_st */
    	em[1886] = 1888; em[1887] = 8; 
    em[1888] = 0; em[1889] = 8; em[1890] = 20; /* 1888: union.unknown */
    	em[1891] = 135; em[1892] = 0; 
    	em[1893] = 1931; em[1894] = 0; 
    	em[1895] = 1864; em[1896] = 0; 
    	em[1897] = 1941; em[1898] = 0; 
    	em[1899] = 1946; em[1900] = 0; 
    	em[1901] = 1951; em[1902] = 0; 
    	em[1903] = 1956; em[1904] = 0; 
    	em[1905] = 1961; em[1906] = 0; 
    	em[1907] = 1966; em[1908] = 0; 
    	em[1909] = 1971; em[1910] = 0; 
    	em[1911] = 1976; em[1912] = 0; 
    	em[1913] = 1981; em[1914] = 0; 
    	em[1915] = 1986; em[1916] = 0; 
    	em[1917] = 1991; em[1918] = 0; 
    	em[1919] = 1996; em[1920] = 0; 
    	em[1921] = 2001; em[1922] = 0; 
    	em[1923] = 2006; em[1924] = 0; 
    	em[1925] = 1931; em[1926] = 0; 
    	em[1927] = 1931; em[1928] = 0; 
    	em[1929] = 1839; em[1930] = 0; 
    em[1931] = 1; em[1932] = 8; em[1933] = 1; /* 1931: pointer.struct.asn1_string_st */
    	em[1934] = 1936; em[1935] = 0; 
    em[1936] = 0; em[1937] = 24; em[1938] = 1; /* 1936: struct.asn1_string_st */
    	em[1939] = 69; em[1940] = 8; 
    em[1941] = 1; em[1942] = 8; em[1943] = 1; /* 1941: pointer.struct.asn1_string_st */
    	em[1944] = 1936; em[1945] = 0; 
    em[1946] = 1; em[1947] = 8; em[1948] = 1; /* 1946: pointer.struct.asn1_string_st */
    	em[1949] = 1936; em[1950] = 0; 
    em[1951] = 1; em[1952] = 8; em[1953] = 1; /* 1951: pointer.struct.asn1_string_st */
    	em[1954] = 1936; em[1955] = 0; 
    em[1956] = 1; em[1957] = 8; em[1958] = 1; /* 1956: pointer.struct.asn1_string_st */
    	em[1959] = 1936; em[1960] = 0; 
    em[1961] = 1; em[1962] = 8; em[1963] = 1; /* 1961: pointer.struct.asn1_string_st */
    	em[1964] = 1936; em[1965] = 0; 
    em[1966] = 1; em[1967] = 8; em[1968] = 1; /* 1966: pointer.struct.asn1_string_st */
    	em[1969] = 1936; em[1970] = 0; 
    em[1971] = 1; em[1972] = 8; em[1973] = 1; /* 1971: pointer.struct.asn1_string_st */
    	em[1974] = 1936; em[1975] = 0; 
    em[1976] = 1; em[1977] = 8; em[1978] = 1; /* 1976: pointer.struct.asn1_string_st */
    	em[1979] = 1936; em[1980] = 0; 
    em[1981] = 1; em[1982] = 8; em[1983] = 1; /* 1981: pointer.struct.asn1_string_st */
    	em[1984] = 1936; em[1985] = 0; 
    em[1986] = 1; em[1987] = 8; em[1988] = 1; /* 1986: pointer.struct.asn1_string_st */
    	em[1989] = 1936; em[1990] = 0; 
    em[1991] = 1; em[1992] = 8; em[1993] = 1; /* 1991: pointer.struct.asn1_string_st */
    	em[1994] = 1936; em[1995] = 0; 
    em[1996] = 1; em[1997] = 8; em[1998] = 1; /* 1996: pointer.struct.asn1_string_st */
    	em[1999] = 1936; em[2000] = 0; 
    em[2001] = 1; em[2002] = 8; em[2003] = 1; /* 2001: pointer.struct.asn1_string_st */
    	em[2004] = 1936; em[2005] = 0; 
    em[2006] = 1; em[2007] = 8; em[2008] = 1; /* 2006: pointer.struct.asn1_string_st */
    	em[2009] = 1936; em[2010] = 0; 
    em[2011] = 1; em[2012] = 8; em[2013] = 1; /* 2011: pointer.struct.asn1_string_st */
    	em[2014] = 2016; em[2015] = 0; 
    em[2016] = 0; em[2017] = 24; em[2018] = 1; /* 2016: struct.asn1_string_st */
    	em[2019] = 69; em[2020] = 8; 
    em[2021] = 0; em[2022] = 40; em[2023] = 5; /* 2021: struct.x509_cert_aux_st */
    	em[2024] = 2034; em[2025] = 0; 
    	em[2026] = 2034; em[2027] = 8; 
    	em[2028] = 2011; em[2029] = 16; 
    	em[2030] = 2072; em[2031] = 24; 
    	em[2032] = 2077; em[2033] = 32; 
    em[2034] = 1; em[2035] = 8; em[2036] = 1; /* 2034: pointer.struct.stack_st_ASN1_OBJECT */
    	em[2037] = 2039; em[2038] = 0; 
    em[2039] = 0; em[2040] = 32; em[2041] = 2; /* 2039: struct.stack_st_fake_ASN1_OBJECT */
    	em[2042] = 2046; em[2043] = 8; 
    	em[2044] = 94; em[2045] = 24; 
    em[2046] = 8884099; em[2047] = 8; em[2048] = 2; /* 2046: pointer_to_array_of_pointers_to_stack */
    	em[2049] = 2053; em[2050] = 0; 
    	em[2051] = 52; em[2052] = 20; 
    em[2053] = 0; em[2054] = 8; em[2055] = 1; /* 2053: pointer.ASN1_OBJECT */
    	em[2056] = 2058; em[2057] = 0; 
    em[2058] = 0; em[2059] = 0; em[2060] = 1; /* 2058: ASN1_OBJECT */
    	em[2061] = 2063; em[2062] = 0; 
    em[2063] = 0; em[2064] = 40; em[2065] = 3; /* 2063: struct.asn1_object_st */
    	em[2066] = 121; em[2067] = 0; 
    	em[2068] = 121; em[2069] = 8; 
    	em[2070] = 1513; em[2071] = 24; 
    em[2072] = 1; em[2073] = 8; em[2074] = 1; /* 2072: pointer.struct.asn1_string_st */
    	em[2075] = 2016; em[2076] = 0; 
    em[2077] = 1; em[2078] = 8; em[2079] = 1; /* 2077: pointer.struct.stack_st_X509_ALGOR */
    	em[2080] = 2082; em[2081] = 0; 
    em[2082] = 0; em[2083] = 32; em[2084] = 2; /* 2082: struct.stack_st_fake_X509_ALGOR */
    	em[2085] = 2089; em[2086] = 8; 
    	em[2087] = 94; em[2088] = 24; 
    em[2089] = 8884099; em[2090] = 8; em[2091] = 2; /* 2089: pointer_to_array_of_pointers_to_stack */
    	em[2092] = 2096; em[2093] = 0; 
    	em[2094] = 52; em[2095] = 20; 
    em[2096] = 0; em[2097] = 8; em[2098] = 1; /* 2096: pointer.X509_ALGOR */
    	em[2099] = 1852; em[2100] = 0; 
    em[2101] = 1; em[2102] = 8; em[2103] = 1; /* 2101: pointer.struct.x509_cert_aux_st */
    	em[2104] = 2021; em[2105] = 0; 
    em[2106] = 0; em[2107] = 16; em[2108] = 2; /* 2106: struct.EDIPartyName_st */
    	em[2109] = 2113; em[2110] = 0; 
    	em[2111] = 2113; em[2112] = 8; 
    em[2113] = 1; em[2114] = 8; em[2115] = 1; /* 2113: pointer.struct.asn1_string_st */
    	em[2116] = 2118; em[2117] = 0; 
    em[2118] = 0; em[2119] = 24; em[2120] = 1; /* 2118: struct.asn1_string_st */
    	em[2121] = 69; em[2122] = 8; 
    em[2123] = 1; em[2124] = 8; em[2125] = 1; /* 2123: pointer.struct.EDIPartyName_st */
    	em[2126] = 2106; em[2127] = 0; 
    em[2128] = 1; em[2129] = 8; em[2130] = 1; /* 2128: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2131] = 2133; em[2132] = 0; 
    em[2133] = 0; em[2134] = 32; em[2135] = 2; /* 2133: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2136] = 2140; em[2137] = 8; 
    	em[2138] = 94; em[2139] = 24; 
    em[2140] = 8884099; em[2141] = 8; em[2142] = 2; /* 2140: pointer_to_array_of_pointers_to_stack */
    	em[2143] = 2147; em[2144] = 0; 
    	em[2145] = 52; em[2146] = 20; 
    em[2147] = 0; em[2148] = 8; em[2149] = 1; /* 2147: pointer.X509_NAME_ENTRY */
    	em[2150] = 2152; em[2151] = 0; 
    em[2152] = 0; em[2153] = 0; em[2154] = 1; /* 2152: X509_NAME_ENTRY */
    	em[2155] = 2157; em[2156] = 0; 
    em[2157] = 0; em[2158] = 24; em[2159] = 2; /* 2157: struct.X509_name_entry_st */
    	em[2160] = 2164; em[2161] = 0; 
    	em[2162] = 2178; em[2163] = 8; 
    em[2164] = 1; em[2165] = 8; em[2166] = 1; /* 2164: pointer.struct.asn1_object_st */
    	em[2167] = 2169; em[2168] = 0; 
    em[2169] = 0; em[2170] = 40; em[2171] = 3; /* 2169: struct.asn1_object_st */
    	em[2172] = 121; em[2173] = 0; 
    	em[2174] = 121; em[2175] = 8; 
    	em[2176] = 1513; em[2177] = 24; 
    em[2178] = 1; em[2179] = 8; em[2180] = 1; /* 2178: pointer.struct.asn1_string_st */
    	em[2181] = 2183; em[2182] = 0; 
    em[2183] = 0; em[2184] = 24; em[2185] = 1; /* 2183: struct.asn1_string_st */
    	em[2186] = 69; em[2187] = 8; 
    em[2188] = 0; em[2189] = 40; em[2190] = 3; /* 2188: struct.X509_name_st */
    	em[2191] = 2128; em[2192] = 0; 
    	em[2193] = 2197; em[2194] = 16; 
    	em[2195] = 69; em[2196] = 24; 
    em[2197] = 1; em[2198] = 8; em[2199] = 1; /* 2197: pointer.struct.buf_mem_st */
    	em[2200] = 2202; em[2201] = 0; 
    em[2202] = 0; em[2203] = 24; em[2204] = 1; /* 2202: struct.buf_mem_st */
    	em[2205] = 135; em[2206] = 8; 
    em[2207] = 1; em[2208] = 8; em[2209] = 1; /* 2207: pointer.struct.asn1_string_st */
    	em[2210] = 2118; em[2211] = 0; 
    em[2212] = 1; em[2213] = 8; em[2214] = 1; /* 2212: pointer.struct.asn1_string_st */
    	em[2215] = 2118; em[2216] = 0; 
    em[2217] = 1; em[2218] = 8; em[2219] = 1; /* 2217: pointer.struct.asn1_string_st */
    	em[2220] = 2118; em[2221] = 0; 
    em[2222] = 1; em[2223] = 8; em[2224] = 1; /* 2222: pointer.struct.asn1_string_st */
    	em[2225] = 2118; em[2226] = 0; 
    em[2227] = 1; em[2228] = 8; em[2229] = 1; /* 2227: pointer.struct.asn1_string_st */
    	em[2230] = 2118; em[2231] = 0; 
    em[2232] = 1; em[2233] = 8; em[2234] = 1; /* 2232: pointer.struct.asn1_string_st */
    	em[2235] = 2118; em[2236] = 0; 
    em[2237] = 1; em[2238] = 8; em[2239] = 1; /* 2237: pointer.struct.asn1_string_st */
    	em[2240] = 2118; em[2241] = 0; 
    em[2242] = 0; em[2243] = 8; em[2244] = 20; /* 2242: union.unknown */
    	em[2245] = 135; em[2246] = 0; 
    	em[2247] = 2113; em[2248] = 0; 
    	em[2249] = 2285; em[2250] = 0; 
    	em[2251] = 2299; em[2252] = 0; 
    	em[2253] = 2304; em[2254] = 0; 
    	em[2255] = 2309; em[2256] = 0; 
    	em[2257] = 2237; em[2258] = 0; 
    	em[2259] = 2232; em[2260] = 0; 
    	em[2261] = 2227; em[2262] = 0; 
    	em[2263] = 2314; em[2264] = 0; 
    	em[2265] = 2222; em[2266] = 0; 
    	em[2267] = 2217; em[2268] = 0; 
    	em[2269] = 2319; em[2270] = 0; 
    	em[2271] = 2212; em[2272] = 0; 
    	em[2273] = 2207; em[2274] = 0; 
    	em[2275] = 2324; em[2276] = 0; 
    	em[2277] = 2329; em[2278] = 0; 
    	em[2279] = 2113; em[2280] = 0; 
    	em[2281] = 2113; em[2282] = 0; 
    	em[2283] = 2334; em[2284] = 0; 
    em[2285] = 1; em[2286] = 8; em[2287] = 1; /* 2285: pointer.struct.asn1_object_st */
    	em[2288] = 2290; em[2289] = 0; 
    em[2290] = 0; em[2291] = 40; em[2292] = 3; /* 2290: struct.asn1_object_st */
    	em[2293] = 121; em[2294] = 0; 
    	em[2295] = 121; em[2296] = 8; 
    	em[2297] = 1513; em[2298] = 24; 
    em[2299] = 1; em[2300] = 8; em[2301] = 1; /* 2299: pointer.struct.asn1_string_st */
    	em[2302] = 2118; em[2303] = 0; 
    em[2304] = 1; em[2305] = 8; em[2306] = 1; /* 2304: pointer.struct.asn1_string_st */
    	em[2307] = 2118; em[2308] = 0; 
    em[2309] = 1; em[2310] = 8; em[2311] = 1; /* 2309: pointer.struct.asn1_string_st */
    	em[2312] = 2118; em[2313] = 0; 
    em[2314] = 1; em[2315] = 8; em[2316] = 1; /* 2314: pointer.struct.asn1_string_st */
    	em[2317] = 2118; em[2318] = 0; 
    em[2319] = 1; em[2320] = 8; em[2321] = 1; /* 2319: pointer.struct.asn1_string_st */
    	em[2322] = 2118; em[2323] = 0; 
    em[2324] = 1; em[2325] = 8; em[2326] = 1; /* 2324: pointer.struct.asn1_string_st */
    	em[2327] = 2118; em[2328] = 0; 
    em[2329] = 1; em[2330] = 8; em[2331] = 1; /* 2329: pointer.struct.asn1_string_st */
    	em[2332] = 2118; em[2333] = 0; 
    em[2334] = 1; em[2335] = 8; em[2336] = 1; /* 2334: pointer.struct.ASN1_VALUE_st */
    	em[2337] = 2339; em[2338] = 0; 
    em[2339] = 0; em[2340] = 0; em[2341] = 0; /* 2339: struct.ASN1_VALUE_st */
    em[2342] = 1; em[2343] = 8; em[2344] = 1; /* 2342: pointer.struct.otherName_st */
    	em[2345] = 2347; em[2346] = 0; 
    em[2347] = 0; em[2348] = 16; em[2349] = 2; /* 2347: struct.otherName_st */
    	em[2350] = 2285; em[2351] = 0; 
    	em[2352] = 2354; em[2353] = 8; 
    em[2354] = 1; em[2355] = 8; em[2356] = 1; /* 2354: pointer.struct.asn1_type_st */
    	em[2357] = 2359; em[2358] = 0; 
    em[2359] = 0; em[2360] = 16; em[2361] = 1; /* 2359: struct.asn1_type_st */
    	em[2362] = 2242; em[2363] = 8; 
    em[2364] = 0; em[2365] = 16; em[2366] = 1; /* 2364: struct.GENERAL_NAME_st */
    	em[2367] = 2369; em[2368] = 8; 
    em[2369] = 0; em[2370] = 8; em[2371] = 15; /* 2369: union.unknown */
    	em[2372] = 135; em[2373] = 0; 
    	em[2374] = 2342; em[2375] = 0; 
    	em[2376] = 2314; em[2377] = 0; 
    	em[2378] = 2314; em[2379] = 0; 
    	em[2380] = 2354; em[2381] = 0; 
    	em[2382] = 2402; em[2383] = 0; 
    	em[2384] = 2123; em[2385] = 0; 
    	em[2386] = 2314; em[2387] = 0; 
    	em[2388] = 2237; em[2389] = 0; 
    	em[2390] = 2285; em[2391] = 0; 
    	em[2392] = 2237; em[2393] = 0; 
    	em[2394] = 2402; em[2395] = 0; 
    	em[2396] = 2314; em[2397] = 0; 
    	em[2398] = 2285; em[2399] = 0; 
    	em[2400] = 2354; em[2401] = 0; 
    em[2402] = 1; em[2403] = 8; em[2404] = 1; /* 2402: pointer.struct.X509_name_st */
    	em[2405] = 2188; em[2406] = 0; 
    em[2407] = 1; em[2408] = 8; em[2409] = 1; /* 2407: pointer.struct.GENERAL_NAME_st */
    	em[2410] = 2364; em[2411] = 0; 
    em[2412] = 0; em[2413] = 24; em[2414] = 3; /* 2412: struct.GENERAL_SUBTREE_st */
    	em[2415] = 2407; em[2416] = 0; 
    	em[2417] = 2299; em[2418] = 8; 
    	em[2419] = 2299; em[2420] = 16; 
    em[2421] = 1; em[2422] = 8; em[2423] = 1; /* 2421: pointer.struct.NAME_CONSTRAINTS_st */
    	em[2424] = 2426; em[2425] = 0; 
    em[2426] = 0; em[2427] = 16; em[2428] = 2; /* 2426: struct.NAME_CONSTRAINTS_st */
    	em[2429] = 2433; em[2430] = 0; 
    	em[2431] = 2433; em[2432] = 8; 
    em[2433] = 1; em[2434] = 8; em[2435] = 1; /* 2433: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[2436] = 2438; em[2437] = 0; 
    em[2438] = 0; em[2439] = 32; em[2440] = 2; /* 2438: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[2441] = 2445; em[2442] = 8; 
    	em[2443] = 94; em[2444] = 24; 
    em[2445] = 8884099; em[2446] = 8; em[2447] = 2; /* 2445: pointer_to_array_of_pointers_to_stack */
    	em[2448] = 2452; em[2449] = 0; 
    	em[2450] = 52; em[2451] = 20; 
    em[2452] = 0; em[2453] = 8; em[2454] = 1; /* 2452: pointer.GENERAL_SUBTREE */
    	em[2455] = 2457; em[2456] = 0; 
    em[2457] = 0; em[2458] = 0; em[2459] = 1; /* 2457: GENERAL_SUBTREE */
    	em[2460] = 2412; em[2461] = 0; 
    em[2462] = 1; em[2463] = 8; em[2464] = 1; /* 2462: pointer.struct.stack_st_GENERAL_NAME */
    	em[2465] = 2467; em[2466] = 0; 
    em[2467] = 0; em[2468] = 32; em[2469] = 2; /* 2467: struct.stack_st_fake_GENERAL_NAME */
    	em[2470] = 2474; em[2471] = 8; 
    	em[2472] = 94; em[2473] = 24; 
    em[2474] = 8884099; em[2475] = 8; em[2476] = 2; /* 2474: pointer_to_array_of_pointers_to_stack */
    	em[2477] = 2481; em[2478] = 0; 
    	em[2479] = 52; em[2480] = 20; 
    em[2481] = 0; em[2482] = 8; em[2483] = 1; /* 2481: pointer.GENERAL_NAME */
    	em[2484] = 2486; em[2485] = 0; 
    em[2486] = 0; em[2487] = 0; em[2488] = 1; /* 2486: GENERAL_NAME */
    	em[2489] = 2491; em[2490] = 0; 
    em[2491] = 0; em[2492] = 16; em[2493] = 1; /* 2491: struct.GENERAL_NAME_st */
    	em[2494] = 2496; em[2495] = 8; 
    em[2496] = 0; em[2497] = 8; em[2498] = 15; /* 2496: union.unknown */
    	em[2499] = 135; em[2500] = 0; 
    	em[2501] = 2529; em[2502] = 0; 
    	em[2503] = 2648; em[2504] = 0; 
    	em[2505] = 2648; em[2506] = 0; 
    	em[2507] = 2555; em[2508] = 0; 
    	em[2509] = 2688; em[2510] = 0; 
    	em[2511] = 2736; em[2512] = 0; 
    	em[2513] = 2648; em[2514] = 0; 
    	em[2515] = 2633; em[2516] = 0; 
    	em[2517] = 2541; em[2518] = 0; 
    	em[2519] = 2633; em[2520] = 0; 
    	em[2521] = 2688; em[2522] = 0; 
    	em[2523] = 2648; em[2524] = 0; 
    	em[2525] = 2541; em[2526] = 0; 
    	em[2527] = 2555; em[2528] = 0; 
    em[2529] = 1; em[2530] = 8; em[2531] = 1; /* 2529: pointer.struct.otherName_st */
    	em[2532] = 2534; em[2533] = 0; 
    em[2534] = 0; em[2535] = 16; em[2536] = 2; /* 2534: struct.otherName_st */
    	em[2537] = 2541; em[2538] = 0; 
    	em[2539] = 2555; em[2540] = 8; 
    em[2541] = 1; em[2542] = 8; em[2543] = 1; /* 2541: pointer.struct.asn1_object_st */
    	em[2544] = 2546; em[2545] = 0; 
    em[2546] = 0; em[2547] = 40; em[2548] = 3; /* 2546: struct.asn1_object_st */
    	em[2549] = 121; em[2550] = 0; 
    	em[2551] = 121; em[2552] = 8; 
    	em[2553] = 1513; em[2554] = 24; 
    em[2555] = 1; em[2556] = 8; em[2557] = 1; /* 2555: pointer.struct.asn1_type_st */
    	em[2558] = 2560; em[2559] = 0; 
    em[2560] = 0; em[2561] = 16; em[2562] = 1; /* 2560: struct.asn1_type_st */
    	em[2563] = 2565; em[2564] = 8; 
    em[2565] = 0; em[2566] = 8; em[2567] = 20; /* 2565: union.unknown */
    	em[2568] = 135; em[2569] = 0; 
    	em[2570] = 2608; em[2571] = 0; 
    	em[2572] = 2541; em[2573] = 0; 
    	em[2574] = 2618; em[2575] = 0; 
    	em[2576] = 2623; em[2577] = 0; 
    	em[2578] = 2628; em[2579] = 0; 
    	em[2580] = 2633; em[2581] = 0; 
    	em[2582] = 2638; em[2583] = 0; 
    	em[2584] = 2643; em[2585] = 0; 
    	em[2586] = 2648; em[2587] = 0; 
    	em[2588] = 2653; em[2589] = 0; 
    	em[2590] = 2658; em[2591] = 0; 
    	em[2592] = 2663; em[2593] = 0; 
    	em[2594] = 2668; em[2595] = 0; 
    	em[2596] = 2673; em[2597] = 0; 
    	em[2598] = 2678; em[2599] = 0; 
    	em[2600] = 2683; em[2601] = 0; 
    	em[2602] = 2608; em[2603] = 0; 
    	em[2604] = 2608; em[2605] = 0; 
    	em[2606] = 2334; em[2607] = 0; 
    em[2608] = 1; em[2609] = 8; em[2610] = 1; /* 2608: pointer.struct.asn1_string_st */
    	em[2611] = 2613; em[2612] = 0; 
    em[2613] = 0; em[2614] = 24; em[2615] = 1; /* 2613: struct.asn1_string_st */
    	em[2616] = 69; em[2617] = 8; 
    em[2618] = 1; em[2619] = 8; em[2620] = 1; /* 2618: pointer.struct.asn1_string_st */
    	em[2621] = 2613; em[2622] = 0; 
    em[2623] = 1; em[2624] = 8; em[2625] = 1; /* 2623: pointer.struct.asn1_string_st */
    	em[2626] = 2613; em[2627] = 0; 
    em[2628] = 1; em[2629] = 8; em[2630] = 1; /* 2628: pointer.struct.asn1_string_st */
    	em[2631] = 2613; em[2632] = 0; 
    em[2633] = 1; em[2634] = 8; em[2635] = 1; /* 2633: pointer.struct.asn1_string_st */
    	em[2636] = 2613; em[2637] = 0; 
    em[2638] = 1; em[2639] = 8; em[2640] = 1; /* 2638: pointer.struct.asn1_string_st */
    	em[2641] = 2613; em[2642] = 0; 
    em[2643] = 1; em[2644] = 8; em[2645] = 1; /* 2643: pointer.struct.asn1_string_st */
    	em[2646] = 2613; em[2647] = 0; 
    em[2648] = 1; em[2649] = 8; em[2650] = 1; /* 2648: pointer.struct.asn1_string_st */
    	em[2651] = 2613; em[2652] = 0; 
    em[2653] = 1; em[2654] = 8; em[2655] = 1; /* 2653: pointer.struct.asn1_string_st */
    	em[2656] = 2613; em[2657] = 0; 
    em[2658] = 1; em[2659] = 8; em[2660] = 1; /* 2658: pointer.struct.asn1_string_st */
    	em[2661] = 2613; em[2662] = 0; 
    em[2663] = 1; em[2664] = 8; em[2665] = 1; /* 2663: pointer.struct.asn1_string_st */
    	em[2666] = 2613; em[2667] = 0; 
    em[2668] = 1; em[2669] = 8; em[2670] = 1; /* 2668: pointer.struct.asn1_string_st */
    	em[2671] = 2613; em[2672] = 0; 
    em[2673] = 1; em[2674] = 8; em[2675] = 1; /* 2673: pointer.struct.asn1_string_st */
    	em[2676] = 2613; em[2677] = 0; 
    em[2678] = 1; em[2679] = 8; em[2680] = 1; /* 2678: pointer.struct.asn1_string_st */
    	em[2681] = 2613; em[2682] = 0; 
    em[2683] = 1; em[2684] = 8; em[2685] = 1; /* 2683: pointer.struct.asn1_string_st */
    	em[2686] = 2613; em[2687] = 0; 
    em[2688] = 1; em[2689] = 8; em[2690] = 1; /* 2688: pointer.struct.X509_name_st */
    	em[2691] = 2693; em[2692] = 0; 
    em[2693] = 0; em[2694] = 40; em[2695] = 3; /* 2693: struct.X509_name_st */
    	em[2696] = 2702; em[2697] = 0; 
    	em[2698] = 2726; em[2699] = 16; 
    	em[2700] = 69; em[2701] = 24; 
    em[2702] = 1; em[2703] = 8; em[2704] = 1; /* 2702: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2705] = 2707; em[2706] = 0; 
    em[2707] = 0; em[2708] = 32; em[2709] = 2; /* 2707: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2710] = 2714; em[2711] = 8; 
    	em[2712] = 94; em[2713] = 24; 
    em[2714] = 8884099; em[2715] = 8; em[2716] = 2; /* 2714: pointer_to_array_of_pointers_to_stack */
    	em[2717] = 2721; em[2718] = 0; 
    	em[2719] = 52; em[2720] = 20; 
    em[2721] = 0; em[2722] = 8; em[2723] = 1; /* 2721: pointer.X509_NAME_ENTRY */
    	em[2724] = 2152; em[2725] = 0; 
    em[2726] = 1; em[2727] = 8; em[2728] = 1; /* 2726: pointer.struct.buf_mem_st */
    	em[2729] = 2731; em[2730] = 0; 
    em[2731] = 0; em[2732] = 24; em[2733] = 1; /* 2731: struct.buf_mem_st */
    	em[2734] = 135; em[2735] = 8; 
    em[2736] = 1; em[2737] = 8; em[2738] = 1; /* 2736: pointer.struct.EDIPartyName_st */
    	em[2739] = 2741; em[2740] = 0; 
    em[2741] = 0; em[2742] = 16; em[2743] = 2; /* 2741: struct.EDIPartyName_st */
    	em[2744] = 2608; em[2745] = 0; 
    	em[2746] = 2608; em[2747] = 8; 
    em[2748] = 0; em[2749] = 24; em[2750] = 1; /* 2748: struct.asn1_string_st */
    	em[2751] = 69; em[2752] = 8; 
    em[2753] = 1; em[2754] = 8; em[2755] = 1; /* 2753: pointer.struct.buf_mem_st */
    	em[2756] = 2758; em[2757] = 0; 
    em[2758] = 0; em[2759] = 24; em[2760] = 1; /* 2758: struct.buf_mem_st */
    	em[2761] = 135; em[2762] = 8; 
    em[2763] = 1; em[2764] = 8; em[2765] = 1; /* 2763: pointer.struct.stack_st_GENERAL_NAME */
    	em[2766] = 2768; em[2767] = 0; 
    em[2768] = 0; em[2769] = 32; em[2770] = 2; /* 2768: struct.stack_st_fake_GENERAL_NAME */
    	em[2771] = 2775; em[2772] = 8; 
    	em[2773] = 94; em[2774] = 24; 
    em[2775] = 8884099; em[2776] = 8; em[2777] = 2; /* 2775: pointer_to_array_of_pointers_to_stack */
    	em[2778] = 2782; em[2779] = 0; 
    	em[2780] = 52; em[2781] = 20; 
    em[2782] = 0; em[2783] = 8; em[2784] = 1; /* 2782: pointer.GENERAL_NAME */
    	em[2785] = 2486; em[2786] = 0; 
    em[2787] = 0; em[2788] = 8; em[2789] = 2; /* 2787: union.unknown */
    	em[2790] = 2763; em[2791] = 0; 
    	em[2792] = 2794; em[2793] = 0; 
    em[2794] = 1; em[2795] = 8; em[2796] = 1; /* 2794: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2797] = 2799; em[2798] = 0; 
    em[2799] = 0; em[2800] = 32; em[2801] = 2; /* 2799: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2802] = 2806; em[2803] = 8; 
    	em[2804] = 94; em[2805] = 24; 
    em[2806] = 8884099; em[2807] = 8; em[2808] = 2; /* 2806: pointer_to_array_of_pointers_to_stack */
    	em[2809] = 2813; em[2810] = 0; 
    	em[2811] = 52; em[2812] = 20; 
    em[2813] = 0; em[2814] = 8; em[2815] = 1; /* 2813: pointer.X509_NAME_ENTRY */
    	em[2816] = 2152; em[2817] = 0; 
    em[2818] = 0; em[2819] = 24; em[2820] = 2; /* 2818: struct.DIST_POINT_NAME_st */
    	em[2821] = 2787; em[2822] = 8; 
    	em[2823] = 2825; em[2824] = 16; 
    em[2825] = 1; em[2826] = 8; em[2827] = 1; /* 2825: pointer.struct.X509_name_st */
    	em[2828] = 2830; em[2829] = 0; 
    em[2830] = 0; em[2831] = 40; em[2832] = 3; /* 2830: struct.X509_name_st */
    	em[2833] = 2794; em[2834] = 0; 
    	em[2835] = 2753; em[2836] = 16; 
    	em[2837] = 69; em[2838] = 24; 
    em[2839] = 1; em[2840] = 8; em[2841] = 1; /* 2839: pointer.struct.DIST_POINT_NAME_st */
    	em[2842] = 2818; em[2843] = 0; 
    em[2844] = 0; em[2845] = 0; em[2846] = 1; /* 2844: DIST_POINT */
    	em[2847] = 2849; em[2848] = 0; 
    em[2849] = 0; em[2850] = 32; em[2851] = 3; /* 2849: struct.DIST_POINT_st */
    	em[2852] = 2839; em[2853] = 0; 
    	em[2854] = 2858; em[2855] = 8; 
    	em[2856] = 2763; em[2857] = 16; 
    em[2858] = 1; em[2859] = 8; em[2860] = 1; /* 2858: pointer.struct.asn1_string_st */
    	em[2861] = 2748; em[2862] = 0; 
    em[2863] = 1; em[2864] = 8; em[2865] = 1; /* 2863: pointer.struct.stack_st_DIST_POINT */
    	em[2866] = 2868; em[2867] = 0; 
    em[2868] = 0; em[2869] = 32; em[2870] = 2; /* 2868: struct.stack_st_fake_DIST_POINT */
    	em[2871] = 2875; em[2872] = 8; 
    	em[2873] = 94; em[2874] = 24; 
    em[2875] = 8884099; em[2876] = 8; em[2877] = 2; /* 2875: pointer_to_array_of_pointers_to_stack */
    	em[2878] = 2882; em[2879] = 0; 
    	em[2880] = 52; em[2881] = 20; 
    em[2882] = 0; em[2883] = 8; em[2884] = 1; /* 2882: pointer.DIST_POINT */
    	em[2885] = 2844; em[2886] = 0; 
    em[2887] = 1; em[2888] = 8; em[2889] = 1; /* 2887: pointer.struct.stack_st_ASN1_OBJECT */
    	em[2890] = 2892; em[2891] = 0; 
    em[2892] = 0; em[2893] = 32; em[2894] = 2; /* 2892: struct.stack_st_fake_ASN1_OBJECT */
    	em[2895] = 2899; em[2896] = 8; 
    	em[2897] = 94; em[2898] = 24; 
    em[2899] = 8884099; em[2900] = 8; em[2901] = 2; /* 2899: pointer_to_array_of_pointers_to_stack */
    	em[2902] = 2906; em[2903] = 0; 
    	em[2904] = 52; em[2905] = 20; 
    em[2906] = 0; em[2907] = 8; em[2908] = 1; /* 2906: pointer.ASN1_OBJECT */
    	em[2909] = 2058; em[2910] = 0; 
    em[2911] = 1; em[2912] = 8; em[2913] = 1; /* 2911: pointer.struct.stack_st_POLICYQUALINFO */
    	em[2914] = 2916; em[2915] = 0; 
    em[2916] = 0; em[2917] = 32; em[2918] = 2; /* 2916: struct.stack_st_fake_POLICYQUALINFO */
    	em[2919] = 2923; em[2920] = 8; 
    	em[2921] = 94; em[2922] = 24; 
    em[2923] = 8884099; em[2924] = 8; em[2925] = 2; /* 2923: pointer_to_array_of_pointers_to_stack */
    	em[2926] = 2930; em[2927] = 0; 
    	em[2928] = 52; em[2929] = 20; 
    em[2930] = 0; em[2931] = 8; em[2932] = 1; /* 2930: pointer.POLICYQUALINFO */
    	em[2933] = 2935; em[2934] = 0; 
    em[2935] = 0; em[2936] = 0; em[2937] = 1; /* 2935: POLICYQUALINFO */
    	em[2938] = 2940; em[2939] = 0; 
    em[2940] = 0; em[2941] = 16; em[2942] = 2; /* 2940: struct.POLICYQUALINFO_st */
    	em[2943] = 2947; em[2944] = 0; 
    	em[2945] = 2961; em[2946] = 8; 
    em[2947] = 1; em[2948] = 8; em[2949] = 1; /* 2947: pointer.struct.asn1_object_st */
    	em[2950] = 2952; em[2951] = 0; 
    em[2952] = 0; em[2953] = 40; em[2954] = 3; /* 2952: struct.asn1_object_st */
    	em[2955] = 121; em[2956] = 0; 
    	em[2957] = 121; em[2958] = 8; 
    	em[2959] = 1513; em[2960] = 24; 
    em[2961] = 0; em[2962] = 8; em[2963] = 3; /* 2961: union.unknown */
    	em[2964] = 2970; em[2965] = 0; 
    	em[2966] = 2980; em[2967] = 0; 
    	em[2968] = 3038; em[2969] = 0; 
    em[2970] = 1; em[2971] = 8; em[2972] = 1; /* 2970: pointer.struct.asn1_string_st */
    	em[2973] = 2975; em[2974] = 0; 
    em[2975] = 0; em[2976] = 24; em[2977] = 1; /* 2975: struct.asn1_string_st */
    	em[2978] = 69; em[2979] = 8; 
    em[2980] = 1; em[2981] = 8; em[2982] = 1; /* 2980: pointer.struct.USERNOTICE_st */
    	em[2983] = 2985; em[2984] = 0; 
    em[2985] = 0; em[2986] = 16; em[2987] = 2; /* 2985: struct.USERNOTICE_st */
    	em[2988] = 2992; em[2989] = 0; 
    	em[2990] = 3004; em[2991] = 8; 
    em[2992] = 1; em[2993] = 8; em[2994] = 1; /* 2992: pointer.struct.NOTICEREF_st */
    	em[2995] = 2997; em[2996] = 0; 
    em[2997] = 0; em[2998] = 16; em[2999] = 2; /* 2997: struct.NOTICEREF_st */
    	em[3000] = 3004; em[3001] = 0; 
    	em[3002] = 3009; em[3003] = 8; 
    em[3004] = 1; em[3005] = 8; em[3006] = 1; /* 3004: pointer.struct.asn1_string_st */
    	em[3007] = 2975; em[3008] = 0; 
    em[3009] = 1; em[3010] = 8; em[3011] = 1; /* 3009: pointer.struct.stack_st_ASN1_INTEGER */
    	em[3012] = 3014; em[3013] = 0; 
    em[3014] = 0; em[3015] = 32; em[3016] = 2; /* 3014: struct.stack_st_fake_ASN1_INTEGER */
    	em[3017] = 3021; em[3018] = 8; 
    	em[3019] = 94; em[3020] = 24; 
    em[3021] = 8884099; em[3022] = 8; em[3023] = 2; /* 3021: pointer_to_array_of_pointers_to_stack */
    	em[3024] = 3028; em[3025] = 0; 
    	em[3026] = 52; em[3027] = 20; 
    em[3028] = 0; em[3029] = 8; em[3030] = 1; /* 3028: pointer.ASN1_INTEGER */
    	em[3031] = 3033; em[3032] = 0; 
    em[3033] = 0; em[3034] = 0; em[3035] = 1; /* 3033: ASN1_INTEGER */
    	em[3036] = 1936; em[3037] = 0; 
    em[3038] = 1; em[3039] = 8; em[3040] = 1; /* 3038: pointer.struct.asn1_type_st */
    	em[3041] = 3043; em[3042] = 0; 
    em[3043] = 0; em[3044] = 16; em[3045] = 1; /* 3043: struct.asn1_type_st */
    	em[3046] = 3048; em[3047] = 8; 
    em[3048] = 0; em[3049] = 8; em[3050] = 20; /* 3048: union.unknown */
    	em[3051] = 135; em[3052] = 0; 
    	em[3053] = 3004; em[3054] = 0; 
    	em[3055] = 2947; em[3056] = 0; 
    	em[3057] = 3091; em[3058] = 0; 
    	em[3059] = 3096; em[3060] = 0; 
    	em[3061] = 3101; em[3062] = 0; 
    	em[3063] = 3106; em[3064] = 0; 
    	em[3065] = 3111; em[3066] = 0; 
    	em[3067] = 3116; em[3068] = 0; 
    	em[3069] = 2970; em[3070] = 0; 
    	em[3071] = 3121; em[3072] = 0; 
    	em[3073] = 3126; em[3074] = 0; 
    	em[3075] = 3131; em[3076] = 0; 
    	em[3077] = 3136; em[3078] = 0; 
    	em[3079] = 3141; em[3080] = 0; 
    	em[3081] = 3146; em[3082] = 0; 
    	em[3083] = 3151; em[3084] = 0; 
    	em[3085] = 3004; em[3086] = 0; 
    	em[3087] = 3004; em[3088] = 0; 
    	em[3089] = 2334; em[3090] = 0; 
    em[3091] = 1; em[3092] = 8; em[3093] = 1; /* 3091: pointer.struct.asn1_string_st */
    	em[3094] = 2975; em[3095] = 0; 
    em[3096] = 1; em[3097] = 8; em[3098] = 1; /* 3096: pointer.struct.asn1_string_st */
    	em[3099] = 2975; em[3100] = 0; 
    em[3101] = 1; em[3102] = 8; em[3103] = 1; /* 3101: pointer.struct.asn1_string_st */
    	em[3104] = 2975; em[3105] = 0; 
    em[3106] = 1; em[3107] = 8; em[3108] = 1; /* 3106: pointer.struct.asn1_string_st */
    	em[3109] = 2975; em[3110] = 0; 
    em[3111] = 1; em[3112] = 8; em[3113] = 1; /* 3111: pointer.struct.asn1_string_st */
    	em[3114] = 2975; em[3115] = 0; 
    em[3116] = 1; em[3117] = 8; em[3118] = 1; /* 3116: pointer.struct.asn1_string_st */
    	em[3119] = 2975; em[3120] = 0; 
    em[3121] = 1; em[3122] = 8; em[3123] = 1; /* 3121: pointer.struct.asn1_string_st */
    	em[3124] = 2975; em[3125] = 0; 
    em[3126] = 1; em[3127] = 8; em[3128] = 1; /* 3126: pointer.struct.asn1_string_st */
    	em[3129] = 2975; em[3130] = 0; 
    em[3131] = 1; em[3132] = 8; em[3133] = 1; /* 3131: pointer.struct.asn1_string_st */
    	em[3134] = 2975; em[3135] = 0; 
    em[3136] = 1; em[3137] = 8; em[3138] = 1; /* 3136: pointer.struct.asn1_string_st */
    	em[3139] = 2975; em[3140] = 0; 
    em[3141] = 1; em[3142] = 8; em[3143] = 1; /* 3141: pointer.struct.asn1_string_st */
    	em[3144] = 2975; em[3145] = 0; 
    em[3146] = 1; em[3147] = 8; em[3148] = 1; /* 3146: pointer.struct.asn1_string_st */
    	em[3149] = 2975; em[3150] = 0; 
    em[3151] = 1; em[3152] = 8; em[3153] = 1; /* 3151: pointer.struct.asn1_string_st */
    	em[3154] = 2975; em[3155] = 0; 
    em[3156] = 1; em[3157] = 8; em[3158] = 1; /* 3156: pointer.struct.asn1_object_st */
    	em[3159] = 3161; em[3160] = 0; 
    em[3161] = 0; em[3162] = 40; em[3163] = 3; /* 3161: struct.asn1_object_st */
    	em[3164] = 121; em[3165] = 0; 
    	em[3166] = 121; em[3167] = 8; 
    	em[3168] = 1513; em[3169] = 24; 
    em[3170] = 0; em[3171] = 32; em[3172] = 3; /* 3170: struct.X509_POLICY_DATA_st */
    	em[3173] = 3156; em[3174] = 8; 
    	em[3175] = 2911; em[3176] = 16; 
    	em[3177] = 2887; em[3178] = 24; 
    em[3179] = 1; em[3180] = 8; em[3181] = 1; /* 3179: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[3182] = 3184; em[3183] = 0; 
    em[3184] = 0; em[3185] = 32; em[3186] = 2; /* 3184: struct.stack_st_fake_X509_POLICY_DATA */
    	em[3187] = 3191; em[3188] = 8; 
    	em[3189] = 94; em[3190] = 24; 
    em[3191] = 8884099; em[3192] = 8; em[3193] = 2; /* 3191: pointer_to_array_of_pointers_to_stack */
    	em[3194] = 3198; em[3195] = 0; 
    	em[3196] = 52; em[3197] = 20; 
    em[3198] = 0; em[3199] = 8; em[3200] = 1; /* 3198: pointer.X509_POLICY_DATA */
    	em[3201] = 3203; em[3202] = 0; 
    em[3203] = 0; em[3204] = 0; em[3205] = 1; /* 3203: X509_POLICY_DATA */
    	em[3206] = 3170; em[3207] = 0; 
    em[3208] = 1; em[3209] = 8; em[3210] = 1; /* 3208: pointer.struct.stack_st_ASN1_OBJECT */
    	em[3211] = 3213; em[3212] = 0; 
    em[3213] = 0; em[3214] = 32; em[3215] = 2; /* 3213: struct.stack_st_fake_ASN1_OBJECT */
    	em[3216] = 3220; em[3217] = 8; 
    	em[3218] = 94; em[3219] = 24; 
    em[3220] = 8884099; em[3221] = 8; em[3222] = 2; /* 3220: pointer_to_array_of_pointers_to_stack */
    	em[3223] = 3227; em[3224] = 0; 
    	em[3225] = 52; em[3226] = 20; 
    em[3227] = 0; em[3228] = 8; em[3229] = 1; /* 3227: pointer.ASN1_OBJECT */
    	em[3230] = 2058; em[3231] = 0; 
    em[3232] = 1; em[3233] = 8; em[3234] = 1; /* 3232: pointer.struct.stack_st_POLICYQUALINFO */
    	em[3235] = 3237; em[3236] = 0; 
    em[3237] = 0; em[3238] = 32; em[3239] = 2; /* 3237: struct.stack_st_fake_POLICYQUALINFO */
    	em[3240] = 3244; em[3241] = 8; 
    	em[3242] = 94; em[3243] = 24; 
    em[3244] = 8884099; em[3245] = 8; em[3246] = 2; /* 3244: pointer_to_array_of_pointers_to_stack */
    	em[3247] = 3251; em[3248] = 0; 
    	em[3249] = 52; em[3250] = 20; 
    em[3251] = 0; em[3252] = 8; em[3253] = 1; /* 3251: pointer.POLICYQUALINFO */
    	em[3254] = 2935; em[3255] = 0; 
    em[3256] = 0; em[3257] = 40; em[3258] = 3; /* 3256: struct.asn1_object_st */
    	em[3259] = 121; em[3260] = 0; 
    	em[3261] = 121; em[3262] = 8; 
    	em[3263] = 1513; em[3264] = 24; 
    em[3265] = 0; em[3266] = 32; em[3267] = 3; /* 3265: struct.X509_POLICY_DATA_st */
    	em[3268] = 3274; em[3269] = 8; 
    	em[3270] = 3232; em[3271] = 16; 
    	em[3272] = 3208; em[3273] = 24; 
    em[3274] = 1; em[3275] = 8; em[3276] = 1; /* 3274: pointer.struct.asn1_object_st */
    	em[3277] = 3256; em[3278] = 0; 
    em[3279] = 1; em[3280] = 8; em[3281] = 1; /* 3279: pointer.struct.X509_POLICY_DATA_st */
    	em[3282] = 3265; em[3283] = 0; 
    em[3284] = 0; em[3285] = 40; em[3286] = 2; /* 3284: struct.X509_POLICY_CACHE_st */
    	em[3287] = 3279; em[3288] = 0; 
    	em[3289] = 3179; em[3290] = 8; 
    em[3291] = 1; em[3292] = 8; em[3293] = 1; /* 3291: pointer.struct.asn1_string_st */
    	em[3294] = 3296; em[3295] = 0; 
    em[3296] = 0; em[3297] = 24; em[3298] = 1; /* 3296: struct.asn1_string_st */
    	em[3299] = 69; em[3300] = 8; 
    em[3301] = 1; em[3302] = 8; em[3303] = 1; /* 3301: pointer.struct.stack_st_GENERAL_NAME */
    	em[3304] = 3306; em[3305] = 0; 
    em[3306] = 0; em[3307] = 32; em[3308] = 2; /* 3306: struct.stack_st_fake_GENERAL_NAME */
    	em[3309] = 3313; em[3310] = 8; 
    	em[3311] = 94; em[3312] = 24; 
    em[3313] = 8884099; em[3314] = 8; em[3315] = 2; /* 3313: pointer_to_array_of_pointers_to_stack */
    	em[3316] = 3320; em[3317] = 0; 
    	em[3318] = 52; em[3319] = 20; 
    em[3320] = 0; em[3321] = 8; em[3322] = 1; /* 3320: pointer.GENERAL_NAME */
    	em[3323] = 2486; em[3324] = 0; 
    em[3325] = 1; em[3326] = 8; em[3327] = 1; /* 3325: pointer.struct.AUTHORITY_KEYID_st */
    	em[3328] = 3330; em[3329] = 0; 
    em[3330] = 0; em[3331] = 24; em[3332] = 3; /* 3330: struct.AUTHORITY_KEYID_st */
    	em[3333] = 3339; em[3334] = 0; 
    	em[3335] = 3301; em[3336] = 8; 
    	em[3337] = 3291; em[3338] = 16; 
    em[3339] = 1; em[3340] = 8; em[3341] = 1; /* 3339: pointer.struct.asn1_string_st */
    	em[3342] = 3296; em[3343] = 0; 
    em[3344] = 0; em[3345] = 24; em[3346] = 1; /* 3344: struct.asn1_string_st */
    	em[3347] = 69; em[3348] = 8; 
    em[3349] = 1; em[3350] = 8; em[3351] = 1; /* 3349: pointer.struct.asn1_string_st */
    	em[3352] = 3344; em[3353] = 0; 
    em[3354] = 1; em[3355] = 8; em[3356] = 1; /* 3354: pointer.struct.stack_st_X509_EXTENSION */
    	em[3357] = 3359; em[3358] = 0; 
    em[3359] = 0; em[3360] = 32; em[3361] = 2; /* 3359: struct.stack_st_fake_X509_EXTENSION */
    	em[3362] = 3366; em[3363] = 8; 
    	em[3364] = 94; em[3365] = 24; 
    em[3366] = 8884099; em[3367] = 8; em[3368] = 2; /* 3366: pointer_to_array_of_pointers_to_stack */
    	em[3369] = 3373; em[3370] = 0; 
    	em[3371] = 52; em[3372] = 20; 
    em[3373] = 0; em[3374] = 8; em[3375] = 1; /* 3373: pointer.X509_EXTENSION */
    	em[3376] = 3378; em[3377] = 0; 
    em[3378] = 0; em[3379] = 0; em[3380] = 1; /* 3378: X509_EXTENSION */
    	em[3381] = 3383; em[3382] = 0; 
    em[3383] = 0; em[3384] = 24; em[3385] = 2; /* 3383: struct.X509_extension_st */
    	em[3386] = 3390; em[3387] = 0; 
    	em[3388] = 3349; em[3389] = 16; 
    em[3390] = 1; em[3391] = 8; em[3392] = 1; /* 3390: pointer.struct.asn1_object_st */
    	em[3393] = 3395; em[3394] = 0; 
    em[3395] = 0; em[3396] = 40; em[3397] = 3; /* 3395: struct.asn1_object_st */
    	em[3398] = 121; em[3399] = 0; 
    	em[3400] = 121; em[3401] = 8; 
    	em[3402] = 1513; em[3403] = 24; 
    em[3404] = 1; em[3405] = 8; em[3406] = 1; /* 3404: pointer.struct.asn1_string_st */
    	em[3407] = 2016; em[3408] = 0; 
    em[3409] = 0; em[3410] = 24; em[3411] = 1; /* 3409: struct.ASN1_ENCODING_st */
    	em[3412] = 69; em[3413] = 0; 
    em[3414] = 1; em[3415] = 8; em[3416] = 1; /* 3414: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3417] = 3419; em[3418] = 0; 
    em[3419] = 0; em[3420] = 32; em[3421] = 2; /* 3419: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[3422] = 3426; em[3423] = 8; 
    	em[3424] = 94; em[3425] = 24; 
    em[3426] = 8884099; em[3427] = 8; em[3428] = 2; /* 3426: pointer_to_array_of_pointers_to_stack */
    	em[3429] = 3433; em[3430] = 0; 
    	em[3431] = 52; em[3432] = 20; 
    em[3433] = 0; em[3434] = 8; em[3435] = 1; /* 3433: pointer.X509_ATTRIBUTE */
    	em[3436] = 1487; em[3437] = 0; 
    em[3438] = 1; em[3439] = 8; em[3440] = 1; /* 3438: pointer.struct.evp_pkey_asn1_method_st */
    	em[3441] = 838; em[3442] = 0; 
    em[3443] = 0; em[3444] = 56; em[3445] = 4; /* 3443: struct.evp_pkey_st */
    	em[3446] = 3438; em[3447] = 16; 
    	em[3448] = 3454; em[3449] = 24; 
    	em[3450] = 3459; em[3451] = 32; 
    	em[3452] = 3414; em[3453] = 48; 
    em[3454] = 1; em[3455] = 8; em[3456] = 1; /* 3454: pointer.struct.engine_st */
    	em[3457] = 148; em[3458] = 0; 
    em[3459] = 8884101; em[3460] = 8; em[3461] = 6; /* 3459: union.union_of_evp_pkey_st */
    	em[3462] = 91; em[3463] = 0; 
    	em[3464] = 3474; em[3465] = 6; 
    	em[3466] = 3479; em[3467] = 116; 
    	em[3468] = 3484; em[3469] = 28; 
    	em[3470] = 3489; em[3471] = 408; 
    	em[3472] = 52; em[3473] = 0; 
    em[3474] = 1; em[3475] = 8; em[3476] = 1; /* 3474: pointer.struct.rsa_st */
    	em[3477] = 619; em[3478] = 0; 
    em[3479] = 1; em[3480] = 8; em[3481] = 1; /* 3479: pointer.struct.dsa_st */
    	em[3482] = 488; em[3483] = 0; 
    em[3484] = 1; em[3485] = 8; em[3486] = 1; /* 3484: pointer.struct.dh_st */
    	em[3487] = 5; em[3488] = 0; 
    em[3489] = 1; em[3490] = 8; em[3491] = 1; /* 3489: pointer.struct.ec_key_st */
    	em[3492] = 959; em[3493] = 0; 
    em[3494] = 1; em[3495] = 8; em[3496] = 1; /* 3494: pointer.struct.evp_pkey_st */
    	em[3497] = 3443; em[3498] = 0; 
    em[3499] = 0; em[3500] = 24; em[3501] = 1; /* 3499: struct.asn1_string_st */
    	em[3502] = 69; em[3503] = 8; 
    em[3504] = 0; em[3505] = 1; em[3506] = 0; /* 3504: char */
    em[3507] = 1; em[3508] = 8; em[3509] = 1; /* 3507: pointer.struct.buf_mem_st */
    	em[3510] = 3512; em[3511] = 0; 
    em[3512] = 0; em[3513] = 24; em[3514] = 1; /* 3512: struct.buf_mem_st */
    	em[3515] = 135; em[3516] = 8; 
    em[3517] = 1; em[3518] = 8; em[3519] = 1; /* 3517: pointer.struct.asn1_string_st */
    	em[3520] = 2016; em[3521] = 0; 
    em[3522] = 0; em[3523] = 184; em[3524] = 12; /* 3522: struct.x509_st */
    	em[3525] = 3549; em[3526] = 0; 
    	em[3527] = 3584; em[3528] = 8; 
    	em[3529] = 3404; em[3530] = 16; 
    	em[3531] = 135; em[3532] = 32; 
    	em[3533] = 3663; em[3534] = 40; 
    	em[3535] = 2072; em[3536] = 104; 
    	em[3537] = 3325; em[3538] = 112; 
    	em[3539] = 3677; em[3540] = 120; 
    	em[3541] = 2863; em[3542] = 128; 
    	em[3543] = 2462; em[3544] = 136; 
    	em[3545] = 2421; em[3546] = 144; 
    	em[3547] = 2101; em[3548] = 176; 
    em[3549] = 1; em[3550] = 8; em[3551] = 1; /* 3549: pointer.struct.x509_cinf_st */
    	em[3552] = 3554; em[3553] = 0; 
    em[3554] = 0; em[3555] = 104; em[3556] = 11; /* 3554: struct.x509_cinf_st */
    	em[3557] = 3579; em[3558] = 0; 
    	em[3559] = 3579; em[3560] = 8; 
    	em[3561] = 3584; em[3562] = 16; 
    	em[3563] = 3589; em[3564] = 24; 
    	em[3565] = 3627; em[3566] = 32; 
    	em[3567] = 3589; em[3568] = 40; 
    	em[3569] = 3639; em[3570] = 48; 
    	em[3571] = 3404; em[3572] = 56; 
    	em[3573] = 3404; em[3574] = 64; 
    	em[3575] = 3354; em[3576] = 72; 
    	em[3577] = 3409; em[3578] = 80; 
    em[3579] = 1; em[3580] = 8; em[3581] = 1; /* 3579: pointer.struct.asn1_string_st */
    	em[3582] = 2016; em[3583] = 0; 
    em[3584] = 1; em[3585] = 8; em[3586] = 1; /* 3584: pointer.struct.X509_algor_st */
    	em[3587] = 1857; em[3588] = 0; 
    em[3589] = 1; em[3590] = 8; em[3591] = 1; /* 3589: pointer.struct.X509_name_st */
    	em[3592] = 3594; em[3593] = 0; 
    em[3594] = 0; em[3595] = 40; em[3596] = 3; /* 3594: struct.X509_name_st */
    	em[3597] = 3603; em[3598] = 0; 
    	em[3599] = 3507; em[3600] = 16; 
    	em[3601] = 69; em[3602] = 24; 
    em[3603] = 1; em[3604] = 8; em[3605] = 1; /* 3603: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3606] = 3608; em[3607] = 0; 
    em[3608] = 0; em[3609] = 32; em[3610] = 2; /* 3608: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3611] = 3615; em[3612] = 8; 
    	em[3613] = 94; em[3614] = 24; 
    em[3615] = 8884099; em[3616] = 8; em[3617] = 2; /* 3615: pointer_to_array_of_pointers_to_stack */
    	em[3618] = 3622; em[3619] = 0; 
    	em[3620] = 52; em[3621] = 20; 
    em[3622] = 0; em[3623] = 8; em[3624] = 1; /* 3622: pointer.X509_NAME_ENTRY */
    	em[3625] = 2152; em[3626] = 0; 
    em[3627] = 1; em[3628] = 8; em[3629] = 1; /* 3627: pointer.struct.X509_val_st */
    	em[3630] = 3632; em[3631] = 0; 
    em[3632] = 0; em[3633] = 16; em[3634] = 2; /* 3632: struct.X509_val_st */
    	em[3635] = 3517; em[3636] = 0; 
    	em[3637] = 3517; em[3638] = 8; 
    em[3639] = 1; em[3640] = 8; em[3641] = 1; /* 3639: pointer.struct.X509_pubkey_st */
    	em[3642] = 3644; em[3643] = 0; 
    em[3644] = 0; em[3645] = 24; em[3646] = 3; /* 3644: struct.X509_pubkey_st */
    	em[3647] = 3653; em[3648] = 0; 
    	em[3649] = 3658; em[3650] = 8; 
    	em[3651] = 3494; em[3652] = 16; 
    em[3653] = 1; em[3654] = 8; em[3655] = 1; /* 3653: pointer.struct.X509_algor_st */
    	em[3656] = 1857; em[3657] = 0; 
    em[3658] = 1; em[3659] = 8; em[3660] = 1; /* 3658: pointer.struct.asn1_string_st */
    	em[3661] = 3499; em[3662] = 0; 
    em[3663] = 0; em[3664] = 32; em[3665] = 2; /* 3663: struct.crypto_ex_data_st_fake */
    	em[3666] = 3670; em[3667] = 8; 
    	em[3668] = 94; em[3669] = 24; 
    em[3670] = 8884099; em[3671] = 8; em[3672] = 2; /* 3670: pointer_to_array_of_pointers_to_stack */
    	em[3673] = 91; em[3674] = 0; 
    	em[3675] = 52; em[3676] = 20; 
    em[3677] = 1; em[3678] = 8; em[3679] = 1; /* 3677: pointer.struct.X509_POLICY_CACHE_st */
    	em[3680] = 3284; em[3681] = 0; 
    em[3682] = 1; em[3683] = 8; em[3684] = 1; /* 3682: pointer.struct.x509_st */
    	em[3685] = 3522; em[3686] = 0; 
    args_addr->arg_entity_index[0] = 3682;
    args_addr->arg_entity_index[1] = 1847;
    args_addr->ret_entity_index = 52;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * new_arg_b = *((EVP_PKEY * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
    orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
    *new_ret_ptr = (*orig_X509_check_private_key)(new_arg_a,new_arg_b);

    syscall(889);

    free(args_addr);

    return ret;
}

