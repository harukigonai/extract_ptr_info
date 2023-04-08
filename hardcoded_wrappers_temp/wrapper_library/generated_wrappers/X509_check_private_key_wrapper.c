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
    	em[831] = 1461; em[832] = 48; 
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
    em[939] = 0; em[940] = 8; em[941] = 5; /* 939: union.unknown */
    	em[942] = 135; em[943] = 0; 
    	em[944] = 614; em[945] = 0; 
    	em[946] = 483; em[947] = 0; 
    	em[948] = 0; em[949] = 0; 
    	em[950] = 952; em[951] = 0; 
    em[952] = 1; em[953] = 8; em[954] = 1; /* 952: pointer.struct.ec_key_st */
    	em[955] = 957; em[956] = 0; 
    em[957] = 0; em[958] = 56; em[959] = 4; /* 957: struct.ec_key_st */
    	em[960] = 968; em[961] = 8; 
    	em[962] = 1416; em[963] = 16; 
    	em[964] = 1421; em[965] = 24; 
    	em[966] = 1438; em[967] = 48; 
    em[968] = 1; em[969] = 8; em[970] = 1; /* 968: pointer.struct.ec_group_st */
    	em[971] = 973; em[972] = 0; 
    em[973] = 0; em[974] = 232; em[975] = 12; /* 973: struct.ec_group_st */
    	em[976] = 1000; em[977] = 0; 
    	em[978] = 1172; em[979] = 8; 
    	em[980] = 1372; em[981] = 16; 
    	em[982] = 1372; em[983] = 40; 
    	em[984] = 69; em[985] = 80; 
    	em[986] = 1384; em[987] = 96; 
    	em[988] = 1372; em[989] = 104; 
    	em[990] = 1372; em[991] = 152; 
    	em[992] = 1372; em[993] = 176; 
    	em[994] = 91; em[995] = 208; 
    	em[996] = 91; em[997] = 216; 
    	em[998] = 1413; em[999] = 224; 
    em[1000] = 1; em[1001] = 8; em[1002] = 1; /* 1000: pointer.struct.ec_method_st */
    	em[1003] = 1005; em[1004] = 0; 
    em[1005] = 0; em[1006] = 304; em[1007] = 37; /* 1005: struct.ec_method_st */
    	em[1008] = 1082; em[1009] = 8; 
    	em[1010] = 1085; em[1011] = 16; 
    	em[1012] = 1085; em[1013] = 24; 
    	em[1014] = 1088; em[1015] = 32; 
    	em[1016] = 1091; em[1017] = 40; 
    	em[1018] = 1094; em[1019] = 48; 
    	em[1020] = 1097; em[1021] = 56; 
    	em[1022] = 1100; em[1023] = 64; 
    	em[1024] = 1103; em[1025] = 72; 
    	em[1026] = 1106; em[1027] = 80; 
    	em[1028] = 1106; em[1029] = 88; 
    	em[1030] = 1109; em[1031] = 96; 
    	em[1032] = 1112; em[1033] = 104; 
    	em[1034] = 1115; em[1035] = 112; 
    	em[1036] = 1118; em[1037] = 120; 
    	em[1038] = 1121; em[1039] = 128; 
    	em[1040] = 1124; em[1041] = 136; 
    	em[1042] = 1127; em[1043] = 144; 
    	em[1044] = 1130; em[1045] = 152; 
    	em[1046] = 1133; em[1047] = 160; 
    	em[1048] = 1136; em[1049] = 168; 
    	em[1050] = 1139; em[1051] = 176; 
    	em[1052] = 1142; em[1053] = 184; 
    	em[1054] = 1145; em[1055] = 192; 
    	em[1056] = 1148; em[1057] = 200; 
    	em[1058] = 1151; em[1059] = 208; 
    	em[1060] = 1142; em[1061] = 216; 
    	em[1062] = 1154; em[1063] = 224; 
    	em[1064] = 1157; em[1065] = 232; 
    	em[1066] = 1160; em[1067] = 240; 
    	em[1068] = 1097; em[1069] = 248; 
    	em[1070] = 1163; em[1071] = 256; 
    	em[1072] = 1166; em[1073] = 264; 
    	em[1074] = 1163; em[1075] = 272; 
    	em[1076] = 1166; em[1077] = 280; 
    	em[1078] = 1166; em[1079] = 288; 
    	em[1080] = 1169; em[1081] = 296; 
    em[1082] = 8884097; em[1083] = 8; em[1084] = 0; /* 1082: pointer.func */
    em[1085] = 8884097; em[1086] = 8; em[1087] = 0; /* 1085: pointer.func */
    em[1088] = 8884097; em[1089] = 8; em[1090] = 0; /* 1088: pointer.func */
    em[1091] = 8884097; em[1092] = 8; em[1093] = 0; /* 1091: pointer.func */
    em[1094] = 8884097; em[1095] = 8; em[1096] = 0; /* 1094: pointer.func */
    em[1097] = 8884097; em[1098] = 8; em[1099] = 0; /* 1097: pointer.func */
    em[1100] = 8884097; em[1101] = 8; em[1102] = 0; /* 1100: pointer.func */
    em[1103] = 8884097; em[1104] = 8; em[1105] = 0; /* 1103: pointer.func */
    em[1106] = 8884097; em[1107] = 8; em[1108] = 0; /* 1106: pointer.func */
    em[1109] = 8884097; em[1110] = 8; em[1111] = 0; /* 1109: pointer.func */
    em[1112] = 8884097; em[1113] = 8; em[1114] = 0; /* 1112: pointer.func */
    em[1115] = 8884097; em[1116] = 8; em[1117] = 0; /* 1115: pointer.func */
    em[1118] = 8884097; em[1119] = 8; em[1120] = 0; /* 1118: pointer.func */
    em[1121] = 8884097; em[1122] = 8; em[1123] = 0; /* 1121: pointer.func */
    em[1124] = 8884097; em[1125] = 8; em[1126] = 0; /* 1124: pointer.func */
    em[1127] = 8884097; em[1128] = 8; em[1129] = 0; /* 1127: pointer.func */
    em[1130] = 8884097; em[1131] = 8; em[1132] = 0; /* 1130: pointer.func */
    em[1133] = 8884097; em[1134] = 8; em[1135] = 0; /* 1133: pointer.func */
    em[1136] = 8884097; em[1137] = 8; em[1138] = 0; /* 1136: pointer.func */
    em[1139] = 8884097; em[1140] = 8; em[1141] = 0; /* 1139: pointer.func */
    em[1142] = 8884097; em[1143] = 8; em[1144] = 0; /* 1142: pointer.func */
    em[1145] = 8884097; em[1146] = 8; em[1147] = 0; /* 1145: pointer.func */
    em[1148] = 8884097; em[1149] = 8; em[1150] = 0; /* 1148: pointer.func */
    em[1151] = 8884097; em[1152] = 8; em[1153] = 0; /* 1151: pointer.func */
    em[1154] = 8884097; em[1155] = 8; em[1156] = 0; /* 1154: pointer.func */
    em[1157] = 8884097; em[1158] = 8; em[1159] = 0; /* 1157: pointer.func */
    em[1160] = 8884097; em[1161] = 8; em[1162] = 0; /* 1160: pointer.func */
    em[1163] = 8884097; em[1164] = 8; em[1165] = 0; /* 1163: pointer.func */
    em[1166] = 8884097; em[1167] = 8; em[1168] = 0; /* 1166: pointer.func */
    em[1169] = 8884097; em[1170] = 8; em[1171] = 0; /* 1169: pointer.func */
    em[1172] = 1; em[1173] = 8; em[1174] = 1; /* 1172: pointer.struct.ec_point_st */
    	em[1175] = 1177; em[1176] = 0; 
    em[1177] = 0; em[1178] = 88; em[1179] = 4; /* 1177: struct.ec_point_st */
    	em[1180] = 1188; em[1181] = 0; 
    	em[1182] = 1360; em[1183] = 8; 
    	em[1184] = 1360; em[1185] = 32; 
    	em[1186] = 1360; em[1187] = 56; 
    em[1188] = 1; em[1189] = 8; em[1190] = 1; /* 1188: pointer.struct.ec_method_st */
    	em[1191] = 1193; em[1192] = 0; 
    em[1193] = 0; em[1194] = 304; em[1195] = 37; /* 1193: struct.ec_method_st */
    	em[1196] = 1270; em[1197] = 8; 
    	em[1198] = 1273; em[1199] = 16; 
    	em[1200] = 1273; em[1201] = 24; 
    	em[1202] = 1276; em[1203] = 32; 
    	em[1204] = 1279; em[1205] = 40; 
    	em[1206] = 1282; em[1207] = 48; 
    	em[1208] = 1285; em[1209] = 56; 
    	em[1210] = 1288; em[1211] = 64; 
    	em[1212] = 1291; em[1213] = 72; 
    	em[1214] = 1294; em[1215] = 80; 
    	em[1216] = 1294; em[1217] = 88; 
    	em[1218] = 1297; em[1219] = 96; 
    	em[1220] = 1300; em[1221] = 104; 
    	em[1222] = 1303; em[1223] = 112; 
    	em[1224] = 1306; em[1225] = 120; 
    	em[1226] = 1309; em[1227] = 128; 
    	em[1228] = 1312; em[1229] = 136; 
    	em[1230] = 1315; em[1231] = 144; 
    	em[1232] = 1318; em[1233] = 152; 
    	em[1234] = 1321; em[1235] = 160; 
    	em[1236] = 1324; em[1237] = 168; 
    	em[1238] = 1327; em[1239] = 176; 
    	em[1240] = 1330; em[1241] = 184; 
    	em[1242] = 1333; em[1243] = 192; 
    	em[1244] = 1336; em[1245] = 200; 
    	em[1246] = 1339; em[1247] = 208; 
    	em[1248] = 1330; em[1249] = 216; 
    	em[1250] = 1342; em[1251] = 224; 
    	em[1252] = 1345; em[1253] = 232; 
    	em[1254] = 1348; em[1255] = 240; 
    	em[1256] = 1285; em[1257] = 248; 
    	em[1258] = 1351; em[1259] = 256; 
    	em[1260] = 1354; em[1261] = 264; 
    	em[1262] = 1351; em[1263] = 272; 
    	em[1264] = 1354; em[1265] = 280; 
    	em[1266] = 1354; em[1267] = 288; 
    	em[1268] = 1357; em[1269] = 296; 
    em[1270] = 8884097; em[1271] = 8; em[1272] = 0; /* 1270: pointer.func */
    em[1273] = 8884097; em[1274] = 8; em[1275] = 0; /* 1273: pointer.func */
    em[1276] = 8884097; em[1277] = 8; em[1278] = 0; /* 1276: pointer.func */
    em[1279] = 8884097; em[1280] = 8; em[1281] = 0; /* 1279: pointer.func */
    em[1282] = 8884097; em[1283] = 8; em[1284] = 0; /* 1282: pointer.func */
    em[1285] = 8884097; em[1286] = 8; em[1287] = 0; /* 1285: pointer.func */
    em[1288] = 8884097; em[1289] = 8; em[1290] = 0; /* 1288: pointer.func */
    em[1291] = 8884097; em[1292] = 8; em[1293] = 0; /* 1291: pointer.func */
    em[1294] = 8884097; em[1295] = 8; em[1296] = 0; /* 1294: pointer.func */
    em[1297] = 8884097; em[1298] = 8; em[1299] = 0; /* 1297: pointer.func */
    em[1300] = 8884097; em[1301] = 8; em[1302] = 0; /* 1300: pointer.func */
    em[1303] = 8884097; em[1304] = 8; em[1305] = 0; /* 1303: pointer.func */
    em[1306] = 8884097; em[1307] = 8; em[1308] = 0; /* 1306: pointer.func */
    em[1309] = 8884097; em[1310] = 8; em[1311] = 0; /* 1309: pointer.func */
    em[1312] = 8884097; em[1313] = 8; em[1314] = 0; /* 1312: pointer.func */
    em[1315] = 8884097; em[1316] = 8; em[1317] = 0; /* 1315: pointer.func */
    em[1318] = 8884097; em[1319] = 8; em[1320] = 0; /* 1318: pointer.func */
    em[1321] = 8884097; em[1322] = 8; em[1323] = 0; /* 1321: pointer.func */
    em[1324] = 8884097; em[1325] = 8; em[1326] = 0; /* 1324: pointer.func */
    em[1327] = 8884097; em[1328] = 8; em[1329] = 0; /* 1327: pointer.func */
    em[1330] = 8884097; em[1331] = 8; em[1332] = 0; /* 1330: pointer.func */
    em[1333] = 8884097; em[1334] = 8; em[1335] = 0; /* 1333: pointer.func */
    em[1336] = 8884097; em[1337] = 8; em[1338] = 0; /* 1336: pointer.func */
    em[1339] = 8884097; em[1340] = 8; em[1341] = 0; /* 1339: pointer.func */
    em[1342] = 8884097; em[1343] = 8; em[1344] = 0; /* 1342: pointer.func */
    em[1345] = 8884097; em[1346] = 8; em[1347] = 0; /* 1345: pointer.func */
    em[1348] = 8884097; em[1349] = 8; em[1350] = 0; /* 1348: pointer.func */
    em[1351] = 8884097; em[1352] = 8; em[1353] = 0; /* 1351: pointer.func */
    em[1354] = 8884097; em[1355] = 8; em[1356] = 0; /* 1354: pointer.func */
    em[1357] = 8884097; em[1358] = 8; em[1359] = 0; /* 1357: pointer.func */
    em[1360] = 0; em[1361] = 24; em[1362] = 1; /* 1360: struct.bignum_st */
    	em[1363] = 1365; em[1364] = 0; 
    em[1365] = 8884099; em[1366] = 8; em[1367] = 2; /* 1365: pointer_to_array_of_pointers_to_stack */
    	em[1368] = 49; em[1369] = 0; 
    	em[1370] = 52; em[1371] = 12; 
    em[1372] = 0; em[1373] = 24; em[1374] = 1; /* 1372: struct.bignum_st */
    	em[1375] = 1377; em[1376] = 0; 
    em[1377] = 8884099; em[1378] = 8; em[1379] = 2; /* 1377: pointer_to_array_of_pointers_to_stack */
    	em[1380] = 49; em[1381] = 0; 
    	em[1382] = 52; em[1383] = 12; 
    em[1384] = 1; em[1385] = 8; em[1386] = 1; /* 1384: pointer.struct.ec_extra_data_st */
    	em[1387] = 1389; em[1388] = 0; 
    em[1389] = 0; em[1390] = 40; em[1391] = 5; /* 1389: struct.ec_extra_data_st */
    	em[1392] = 1402; em[1393] = 0; 
    	em[1394] = 91; em[1395] = 8; 
    	em[1396] = 1407; em[1397] = 16; 
    	em[1398] = 1410; em[1399] = 24; 
    	em[1400] = 1410; em[1401] = 32; 
    em[1402] = 1; em[1403] = 8; em[1404] = 1; /* 1402: pointer.struct.ec_extra_data_st */
    	em[1405] = 1389; em[1406] = 0; 
    em[1407] = 8884097; em[1408] = 8; em[1409] = 0; /* 1407: pointer.func */
    em[1410] = 8884097; em[1411] = 8; em[1412] = 0; /* 1410: pointer.func */
    em[1413] = 8884097; em[1414] = 8; em[1415] = 0; /* 1413: pointer.func */
    em[1416] = 1; em[1417] = 8; em[1418] = 1; /* 1416: pointer.struct.ec_point_st */
    	em[1419] = 1177; em[1420] = 0; 
    em[1421] = 1; em[1422] = 8; em[1423] = 1; /* 1421: pointer.struct.bignum_st */
    	em[1424] = 1426; em[1425] = 0; 
    em[1426] = 0; em[1427] = 24; em[1428] = 1; /* 1426: struct.bignum_st */
    	em[1429] = 1431; em[1430] = 0; 
    em[1431] = 8884099; em[1432] = 8; em[1433] = 2; /* 1431: pointer_to_array_of_pointers_to_stack */
    	em[1434] = 49; em[1435] = 0; 
    	em[1436] = 52; em[1437] = 12; 
    em[1438] = 1; em[1439] = 8; em[1440] = 1; /* 1438: pointer.struct.ec_extra_data_st */
    	em[1441] = 1443; em[1442] = 0; 
    em[1443] = 0; em[1444] = 40; em[1445] = 5; /* 1443: struct.ec_extra_data_st */
    	em[1446] = 1456; em[1447] = 0; 
    	em[1448] = 91; em[1449] = 8; 
    	em[1450] = 1407; em[1451] = 16; 
    	em[1452] = 1410; em[1453] = 24; 
    	em[1454] = 1410; em[1455] = 32; 
    em[1456] = 1; em[1457] = 8; em[1458] = 1; /* 1456: pointer.struct.ec_extra_data_st */
    	em[1459] = 1443; em[1460] = 0; 
    em[1461] = 1; em[1462] = 8; em[1463] = 1; /* 1461: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1464] = 1466; em[1465] = 0; 
    em[1466] = 0; em[1467] = 32; em[1468] = 2; /* 1466: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1469] = 1473; em[1470] = 8; 
    	em[1471] = 94; em[1472] = 24; 
    em[1473] = 8884099; em[1474] = 8; em[1475] = 2; /* 1473: pointer_to_array_of_pointers_to_stack */
    	em[1476] = 1480; em[1477] = 0; 
    	em[1478] = 52; em[1479] = 20; 
    em[1480] = 0; em[1481] = 8; em[1482] = 1; /* 1480: pointer.X509_ATTRIBUTE */
    	em[1483] = 1485; em[1484] = 0; 
    em[1485] = 0; em[1486] = 0; em[1487] = 1; /* 1485: X509_ATTRIBUTE */
    	em[1488] = 1490; em[1489] = 0; 
    em[1490] = 0; em[1491] = 24; em[1492] = 2; /* 1490: struct.x509_attributes_st */
    	em[1493] = 1497; em[1494] = 0; 
    	em[1495] = 1516; em[1496] = 16; 
    em[1497] = 1; em[1498] = 8; em[1499] = 1; /* 1497: pointer.struct.asn1_object_st */
    	em[1500] = 1502; em[1501] = 0; 
    em[1502] = 0; em[1503] = 40; em[1504] = 3; /* 1502: struct.asn1_object_st */
    	em[1505] = 121; em[1506] = 0; 
    	em[1507] = 121; em[1508] = 8; 
    	em[1509] = 1511; em[1510] = 24; 
    em[1511] = 1; em[1512] = 8; em[1513] = 1; /* 1511: pointer.unsigned char */
    	em[1514] = 74; em[1515] = 0; 
    em[1516] = 0; em[1517] = 8; em[1518] = 3; /* 1516: union.unknown */
    	em[1519] = 135; em[1520] = 0; 
    	em[1521] = 1525; em[1522] = 0; 
    	em[1523] = 1704; em[1524] = 0; 
    em[1525] = 1; em[1526] = 8; em[1527] = 1; /* 1525: pointer.struct.stack_st_ASN1_TYPE */
    	em[1528] = 1530; em[1529] = 0; 
    em[1530] = 0; em[1531] = 32; em[1532] = 2; /* 1530: struct.stack_st_fake_ASN1_TYPE */
    	em[1533] = 1537; em[1534] = 8; 
    	em[1535] = 94; em[1536] = 24; 
    em[1537] = 8884099; em[1538] = 8; em[1539] = 2; /* 1537: pointer_to_array_of_pointers_to_stack */
    	em[1540] = 1544; em[1541] = 0; 
    	em[1542] = 52; em[1543] = 20; 
    em[1544] = 0; em[1545] = 8; em[1546] = 1; /* 1544: pointer.ASN1_TYPE */
    	em[1547] = 1549; em[1548] = 0; 
    em[1549] = 0; em[1550] = 0; em[1551] = 1; /* 1549: ASN1_TYPE */
    	em[1552] = 1554; em[1553] = 0; 
    em[1554] = 0; em[1555] = 16; em[1556] = 1; /* 1554: struct.asn1_type_st */
    	em[1557] = 1559; em[1558] = 8; 
    em[1559] = 0; em[1560] = 8; em[1561] = 20; /* 1559: union.unknown */
    	em[1562] = 135; em[1563] = 0; 
    	em[1564] = 1602; em[1565] = 0; 
    	em[1566] = 1612; em[1567] = 0; 
    	em[1568] = 1626; em[1569] = 0; 
    	em[1570] = 1631; em[1571] = 0; 
    	em[1572] = 1636; em[1573] = 0; 
    	em[1574] = 1641; em[1575] = 0; 
    	em[1576] = 1646; em[1577] = 0; 
    	em[1578] = 1651; em[1579] = 0; 
    	em[1580] = 1656; em[1581] = 0; 
    	em[1582] = 1661; em[1583] = 0; 
    	em[1584] = 1666; em[1585] = 0; 
    	em[1586] = 1671; em[1587] = 0; 
    	em[1588] = 1676; em[1589] = 0; 
    	em[1590] = 1681; em[1591] = 0; 
    	em[1592] = 1686; em[1593] = 0; 
    	em[1594] = 1691; em[1595] = 0; 
    	em[1596] = 1602; em[1597] = 0; 
    	em[1598] = 1602; em[1599] = 0; 
    	em[1600] = 1696; em[1601] = 0; 
    em[1602] = 1; em[1603] = 8; em[1604] = 1; /* 1602: pointer.struct.asn1_string_st */
    	em[1605] = 1607; em[1606] = 0; 
    em[1607] = 0; em[1608] = 24; em[1609] = 1; /* 1607: struct.asn1_string_st */
    	em[1610] = 69; em[1611] = 8; 
    em[1612] = 1; em[1613] = 8; em[1614] = 1; /* 1612: pointer.struct.asn1_object_st */
    	em[1615] = 1617; em[1616] = 0; 
    em[1617] = 0; em[1618] = 40; em[1619] = 3; /* 1617: struct.asn1_object_st */
    	em[1620] = 121; em[1621] = 0; 
    	em[1622] = 121; em[1623] = 8; 
    	em[1624] = 1511; em[1625] = 24; 
    em[1626] = 1; em[1627] = 8; em[1628] = 1; /* 1626: pointer.struct.asn1_string_st */
    	em[1629] = 1607; em[1630] = 0; 
    em[1631] = 1; em[1632] = 8; em[1633] = 1; /* 1631: pointer.struct.asn1_string_st */
    	em[1634] = 1607; em[1635] = 0; 
    em[1636] = 1; em[1637] = 8; em[1638] = 1; /* 1636: pointer.struct.asn1_string_st */
    	em[1639] = 1607; em[1640] = 0; 
    em[1641] = 1; em[1642] = 8; em[1643] = 1; /* 1641: pointer.struct.asn1_string_st */
    	em[1644] = 1607; em[1645] = 0; 
    em[1646] = 1; em[1647] = 8; em[1648] = 1; /* 1646: pointer.struct.asn1_string_st */
    	em[1649] = 1607; em[1650] = 0; 
    em[1651] = 1; em[1652] = 8; em[1653] = 1; /* 1651: pointer.struct.asn1_string_st */
    	em[1654] = 1607; em[1655] = 0; 
    em[1656] = 1; em[1657] = 8; em[1658] = 1; /* 1656: pointer.struct.asn1_string_st */
    	em[1659] = 1607; em[1660] = 0; 
    em[1661] = 1; em[1662] = 8; em[1663] = 1; /* 1661: pointer.struct.asn1_string_st */
    	em[1664] = 1607; em[1665] = 0; 
    em[1666] = 1; em[1667] = 8; em[1668] = 1; /* 1666: pointer.struct.asn1_string_st */
    	em[1669] = 1607; em[1670] = 0; 
    em[1671] = 1; em[1672] = 8; em[1673] = 1; /* 1671: pointer.struct.asn1_string_st */
    	em[1674] = 1607; em[1675] = 0; 
    em[1676] = 1; em[1677] = 8; em[1678] = 1; /* 1676: pointer.struct.asn1_string_st */
    	em[1679] = 1607; em[1680] = 0; 
    em[1681] = 1; em[1682] = 8; em[1683] = 1; /* 1681: pointer.struct.asn1_string_st */
    	em[1684] = 1607; em[1685] = 0; 
    em[1686] = 1; em[1687] = 8; em[1688] = 1; /* 1686: pointer.struct.asn1_string_st */
    	em[1689] = 1607; em[1690] = 0; 
    em[1691] = 1; em[1692] = 8; em[1693] = 1; /* 1691: pointer.struct.asn1_string_st */
    	em[1694] = 1607; em[1695] = 0; 
    em[1696] = 1; em[1697] = 8; em[1698] = 1; /* 1696: pointer.struct.ASN1_VALUE_st */
    	em[1699] = 1701; em[1700] = 0; 
    em[1701] = 0; em[1702] = 0; em[1703] = 0; /* 1701: struct.ASN1_VALUE_st */
    em[1704] = 1; em[1705] = 8; em[1706] = 1; /* 1704: pointer.struct.asn1_type_st */
    	em[1707] = 1709; em[1708] = 0; 
    em[1709] = 0; em[1710] = 16; em[1711] = 1; /* 1709: struct.asn1_type_st */
    	em[1712] = 1714; em[1713] = 8; 
    em[1714] = 0; em[1715] = 8; em[1716] = 20; /* 1714: union.unknown */
    	em[1717] = 135; em[1718] = 0; 
    	em[1719] = 1757; em[1720] = 0; 
    	em[1721] = 1497; em[1722] = 0; 
    	em[1723] = 1767; em[1724] = 0; 
    	em[1725] = 1772; em[1726] = 0; 
    	em[1727] = 1777; em[1728] = 0; 
    	em[1729] = 1782; em[1730] = 0; 
    	em[1731] = 1787; em[1732] = 0; 
    	em[1733] = 1792; em[1734] = 0; 
    	em[1735] = 1797; em[1736] = 0; 
    	em[1737] = 1802; em[1738] = 0; 
    	em[1739] = 1807; em[1740] = 0; 
    	em[1741] = 1812; em[1742] = 0; 
    	em[1743] = 1817; em[1744] = 0; 
    	em[1745] = 1822; em[1746] = 0; 
    	em[1747] = 1827; em[1748] = 0; 
    	em[1749] = 1832; em[1750] = 0; 
    	em[1751] = 1757; em[1752] = 0; 
    	em[1753] = 1757; em[1754] = 0; 
    	em[1755] = 1837; em[1756] = 0; 
    em[1757] = 1; em[1758] = 8; em[1759] = 1; /* 1757: pointer.struct.asn1_string_st */
    	em[1760] = 1762; em[1761] = 0; 
    em[1762] = 0; em[1763] = 24; em[1764] = 1; /* 1762: struct.asn1_string_st */
    	em[1765] = 69; em[1766] = 8; 
    em[1767] = 1; em[1768] = 8; em[1769] = 1; /* 1767: pointer.struct.asn1_string_st */
    	em[1770] = 1762; em[1771] = 0; 
    em[1772] = 1; em[1773] = 8; em[1774] = 1; /* 1772: pointer.struct.asn1_string_st */
    	em[1775] = 1762; em[1776] = 0; 
    em[1777] = 1; em[1778] = 8; em[1779] = 1; /* 1777: pointer.struct.asn1_string_st */
    	em[1780] = 1762; em[1781] = 0; 
    em[1782] = 1; em[1783] = 8; em[1784] = 1; /* 1782: pointer.struct.asn1_string_st */
    	em[1785] = 1762; em[1786] = 0; 
    em[1787] = 1; em[1788] = 8; em[1789] = 1; /* 1787: pointer.struct.asn1_string_st */
    	em[1790] = 1762; em[1791] = 0; 
    em[1792] = 1; em[1793] = 8; em[1794] = 1; /* 1792: pointer.struct.asn1_string_st */
    	em[1795] = 1762; em[1796] = 0; 
    em[1797] = 1; em[1798] = 8; em[1799] = 1; /* 1797: pointer.struct.asn1_string_st */
    	em[1800] = 1762; em[1801] = 0; 
    em[1802] = 1; em[1803] = 8; em[1804] = 1; /* 1802: pointer.struct.asn1_string_st */
    	em[1805] = 1762; em[1806] = 0; 
    em[1807] = 1; em[1808] = 8; em[1809] = 1; /* 1807: pointer.struct.asn1_string_st */
    	em[1810] = 1762; em[1811] = 0; 
    em[1812] = 1; em[1813] = 8; em[1814] = 1; /* 1812: pointer.struct.asn1_string_st */
    	em[1815] = 1762; em[1816] = 0; 
    em[1817] = 1; em[1818] = 8; em[1819] = 1; /* 1817: pointer.struct.asn1_string_st */
    	em[1820] = 1762; em[1821] = 0; 
    em[1822] = 1; em[1823] = 8; em[1824] = 1; /* 1822: pointer.struct.asn1_string_st */
    	em[1825] = 1762; em[1826] = 0; 
    em[1827] = 1; em[1828] = 8; em[1829] = 1; /* 1827: pointer.struct.asn1_string_st */
    	em[1830] = 1762; em[1831] = 0; 
    em[1832] = 1; em[1833] = 8; em[1834] = 1; /* 1832: pointer.struct.asn1_string_st */
    	em[1835] = 1762; em[1836] = 0; 
    em[1837] = 1; em[1838] = 8; em[1839] = 1; /* 1837: pointer.struct.ASN1_VALUE_st */
    	em[1840] = 1842; em[1841] = 0; 
    em[1842] = 0; em[1843] = 0; em[1844] = 0; /* 1842: struct.ASN1_VALUE_st */
    em[1845] = 1; em[1846] = 8; em[1847] = 1; /* 1845: pointer.struct.evp_pkey_st */
    	em[1848] = 822; em[1849] = 0; 
    em[1850] = 0; em[1851] = 0; em[1852] = 1; /* 1850: X509_ALGOR */
    	em[1853] = 1855; em[1854] = 0; 
    em[1855] = 0; em[1856] = 16; em[1857] = 2; /* 1855: struct.X509_algor_st */
    	em[1858] = 1862; em[1859] = 0; 
    	em[1860] = 1876; em[1861] = 8; 
    em[1862] = 1; em[1863] = 8; em[1864] = 1; /* 1862: pointer.struct.asn1_object_st */
    	em[1865] = 1867; em[1866] = 0; 
    em[1867] = 0; em[1868] = 40; em[1869] = 3; /* 1867: struct.asn1_object_st */
    	em[1870] = 121; em[1871] = 0; 
    	em[1872] = 121; em[1873] = 8; 
    	em[1874] = 1511; em[1875] = 24; 
    em[1876] = 1; em[1877] = 8; em[1878] = 1; /* 1876: pointer.struct.asn1_type_st */
    	em[1879] = 1881; em[1880] = 0; 
    em[1881] = 0; em[1882] = 16; em[1883] = 1; /* 1881: struct.asn1_type_st */
    	em[1884] = 1886; em[1885] = 8; 
    em[1886] = 0; em[1887] = 8; em[1888] = 20; /* 1886: union.unknown */
    	em[1889] = 135; em[1890] = 0; 
    	em[1891] = 1929; em[1892] = 0; 
    	em[1893] = 1862; em[1894] = 0; 
    	em[1895] = 1939; em[1896] = 0; 
    	em[1897] = 1944; em[1898] = 0; 
    	em[1899] = 1949; em[1900] = 0; 
    	em[1901] = 1954; em[1902] = 0; 
    	em[1903] = 1959; em[1904] = 0; 
    	em[1905] = 1964; em[1906] = 0; 
    	em[1907] = 1969; em[1908] = 0; 
    	em[1909] = 1974; em[1910] = 0; 
    	em[1911] = 1979; em[1912] = 0; 
    	em[1913] = 1984; em[1914] = 0; 
    	em[1915] = 1989; em[1916] = 0; 
    	em[1917] = 1994; em[1918] = 0; 
    	em[1919] = 1999; em[1920] = 0; 
    	em[1921] = 2004; em[1922] = 0; 
    	em[1923] = 1929; em[1924] = 0; 
    	em[1925] = 1929; em[1926] = 0; 
    	em[1927] = 1837; em[1928] = 0; 
    em[1929] = 1; em[1930] = 8; em[1931] = 1; /* 1929: pointer.struct.asn1_string_st */
    	em[1932] = 1934; em[1933] = 0; 
    em[1934] = 0; em[1935] = 24; em[1936] = 1; /* 1934: struct.asn1_string_st */
    	em[1937] = 69; em[1938] = 8; 
    em[1939] = 1; em[1940] = 8; em[1941] = 1; /* 1939: pointer.struct.asn1_string_st */
    	em[1942] = 1934; em[1943] = 0; 
    em[1944] = 1; em[1945] = 8; em[1946] = 1; /* 1944: pointer.struct.asn1_string_st */
    	em[1947] = 1934; em[1948] = 0; 
    em[1949] = 1; em[1950] = 8; em[1951] = 1; /* 1949: pointer.struct.asn1_string_st */
    	em[1952] = 1934; em[1953] = 0; 
    em[1954] = 1; em[1955] = 8; em[1956] = 1; /* 1954: pointer.struct.asn1_string_st */
    	em[1957] = 1934; em[1958] = 0; 
    em[1959] = 1; em[1960] = 8; em[1961] = 1; /* 1959: pointer.struct.asn1_string_st */
    	em[1962] = 1934; em[1963] = 0; 
    em[1964] = 1; em[1965] = 8; em[1966] = 1; /* 1964: pointer.struct.asn1_string_st */
    	em[1967] = 1934; em[1968] = 0; 
    em[1969] = 1; em[1970] = 8; em[1971] = 1; /* 1969: pointer.struct.asn1_string_st */
    	em[1972] = 1934; em[1973] = 0; 
    em[1974] = 1; em[1975] = 8; em[1976] = 1; /* 1974: pointer.struct.asn1_string_st */
    	em[1977] = 1934; em[1978] = 0; 
    em[1979] = 1; em[1980] = 8; em[1981] = 1; /* 1979: pointer.struct.asn1_string_st */
    	em[1982] = 1934; em[1983] = 0; 
    em[1984] = 1; em[1985] = 8; em[1986] = 1; /* 1984: pointer.struct.asn1_string_st */
    	em[1987] = 1934; em[1988] = 0; 
    em[1989] = 1; em[1990] = 8; em[1991] = 1; /* 1989: pointer.struct.asn1_string_st */
    	em[1992] = 1934; em[1993] = 0; 
    em[1994] = 1; em[1995] = 8; em[1996] = 1; /* 1994: pointer.struct.asn1_string_st */
    	em[1997] = 1934; em[1998] = 0; 
    em[1999] = 1; em[2000] = 8; em[2001] = 1; /* 1999: pointer.struct.asn1_string_st */
    	em[2002] = 1934; em[2003] = 0; 
    em[2004] = 1; em[2005] = 8; em[2006] = 1; /* 2004: pointer.struct.asn1_string_st */
    	em[2007] = 1934; em[2008] = 0; 
    em[2009] = 1; em[2010] = 8; em[2011] = 1; /* 2009: pointer.struct.asn1_string_st */
    	em[2012] = 2014; em[2013] = 0; 
    em[2014] = 0; em[2015] = 24; em[2016] = 1; /* 2014: struct.asn1_string_st */
    	em[2017] = 69; em[2018] = 8; 
    em[2019] = 0; em[2020] = 40; em[2021] = 5; /* 2019: struct.x509_cert_aux_st */
    	em[2022] = 2032; em[2023] = 0; 
    	em[2024] = 2032; em[2025] = 8; 
    	em[2026] = 2009; em[2027] = 16; 
    	em[2028] = 2070; em[2029] = 24; 
    	em[2030] = 2075; em[2031] = 32; 
    em[2032] = 1; em[2033] = 8; em[2034] = 1; /* 2032: pointer.struct.stack_st_ASN1_OBJECT */
    	em[2035] = 2037; em[2036] = 0; 
    em[2037] = 0; em[2038] = 32; em[2039] = 2; /* 2037: struct.stack_st_fake_ASN1_OBJECT */
    	em[2040] = 2044; em[2041] = 8; 
    	em[2042] = 94; em[2043] = 24; 
    em[2044] = 8884099; em[2045] = 8; em[2046] = 2; /* 2044: pointer_to_array_of_pointers_to_stack */
    	em[2047] = 2051; em[2048] = 0; 
    	em[2049] = 52; em[2050] = 20; 
    em[2051] = 0; em[2052] = 8; em[2053] = 1; /* 2051: pointer.ASN1_OBJECT */
    	em[2054] = 2056; em[2055] = 0; 
    em[2056] = 0; em[2057] = 0; em[2058] = 1; /* 2056: ASN1_OBJECT */
    	em[2059] = 2061; em[2060] = 0; 
    em[2061] = 0; em[2062] = 40; em[2063] = 3; /* 2061: struct.asn1_object_st */
    	em[2064] = 121; em[2065] = 0; 
    	em[2066] = 121; em[2067] = 8; 
    	em[2068] = 1511; em[2069] = 24; 
    em[2070] = 1; em[2071] = 8; em[2072] = 1; /* 2070: pointer.struct.asn1_string_st */
    	em[2073] = 2014; em[2074] = 0; 
    em[2075] = 1; em[2076] = 8; em[2077] = 1; /* 2075: pointer.struct.stack_st_X509_ALGOR */
    	em[2078] = 2080; em[2079] = 0; 
    em[2080] = 0; em[2081] = 32; em[2082] = 2; /* 2080: struct.stack_st_fake_X509_ALGOR */
    	em[2083] = 2087; em[2084] = 8; 
    	em[2085] = 94; em[2086] = 24; 
    em[2087] = 8884099; em[2088] = 8; em[2089] = 2; /* 2087: pointer_to_array_of_pointers_to_stack */
    	em[2090] = 2094; em[2091] = 0; 
    	em[2092] = 52; em[2093] = 20; 
    em[2094] = 0; em[2095] = 8; em[2096] = 1; /* 2094: pointer.X509_ALGOR */
    	em[2097] = 1850; em[2098] = 0; 
    em[2099] = 1; em[2100] = 8; em[2101] = 1; /* 2099: pointer.struct.x509_cert_aux_st */
    	em[2102] = 2019; em[2103] = 0; 
    em[2104] = 0; em[2105] = 16; em[2106] = 2; /* 2104: struct.EDIPartyName_st */
    	em[2107] = 2111; em[2108] = 0; 
    	em[2109] = 2111; em[2110] = 8; 
    em[2111] = 1; em[2112] = 8; em[2113] = 1; /* 2111: pointer.struct.asn1_string_st */
    	em[2114] = 2116; em[2115] = 0; 
    em[2116] = 0; em[2117] = 24; em[2118] = 1; /* 2116: struct.asn1_string_st */
    	em[2119] = 69; em[2120] = 8; 
    em[2121] = 1; em[2122] = 8; em[2123] = 1; /* 2121: pointer.struct.EDIPartyName_st */
    	em[2124] = 2104; em[2125] = 0; 
    em[2126] = 1; em[2127] = 8; em[2128] = 1; /* 2126: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2129] = 2131; em[2130] = 0; 
    em[2131] = 0; em[2132] = 32; em[2133] = 2; /* 2131: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2134] = 2138; em[2135] = 8; 
    	em[2136] = 94; em[2137] = 24; 
    em[2138] = 8884099; em[2139] = 8; em[2140] = 2; /* 2138: pointer_to_array_of_pointers_to_stack */
    	em[2141] = 2145; em[2142] = 0; 
    	em[2143] = 52; em[2144] = 20; 
    em[2145] = 0; em[2146] = 8; em[2147] = 1; /* 2145: pointer.X509_NAME_ENTRY */
    	em[2148] = 2150; em[2149] = 0; 
    em[2150] = 0; em[2151] = 0; em[2152] = 1; /* 2150: X509_NAME_ENTRY */
    	em[2153] = 2155; em[2154] = 0; 
    em[2155] = 0; em[2156] = 24; em[2157] = 2; /* 2155: struct.X509_name_entry_st */
    	em[2158] = 2162; em[2159] = 0; 
    	em[2160] = 2176; em[2161] = 8; 
    em[2162] = 1; em[2163] = 8; em[2164] = 1; /* 2162: pointer.struct.asn1_object_st */
    	em[2165] = 2167; em[2166] = 0; 
    em[2167] = 0; em[2168] = 40; em[2169] = 3; /* 2167: struct.asn1_object_st */
    	em[2170] = 121; em[2171] = 0; 
    	em[2172] = 121; em[2173] = 8; 
    	em[2174] = 1511; em[2175] = 24; 
    em[2176] = 1; em[2177] = 8; em[2178] = 1; /* 2176: pointer.struct.asn1_string_st */
    	em[2179] = 2181; em[2180] = 0; 
    em[2181] = 0; em[2182] = 24; em[2183] = 1; /* 2181: struct.asn1_string_st */
    	em[2184] = 69; em[2185] = 8; 
    em[2186] = 0; em[2187] = 40; em[2188] = 3; /* 2186: struct.X509_name_st */
    	em[2189] = 2126; em[2190] = 0; 
    	em[2191] = 2195; em[2192] = 16; 
    	em[2193] = 69; em[2194] = 24; 
    em[2195] = 1; em[2196] = 8; em[2197] = 1; /* 2195: pointer.struct.buf_mem_st */
    	em[2198] = 2200; em[2199] = 0; 
    em[2200] = 0; em[2201] = 24; em[2202] = 1; /* 2200: struct.buf_mem_st */
    	em[2203] = 135; em[2204] = 8; 
    em[2205] = 1; em[2206] = 8; em[2207] = 1; /* 2205: pointer.struct.asn1_string_st */
    	em[2208] = 2116; em[2209] = 0; 
    em[2210] = 1; em[2211] = 8; em[2212] = 1; /* 2210: pointer.struct.asn1_string_st */
    	em[2213] = 2116; em[2214] = 0; 
    em[2215] = 1; em[2216] = 8; em[2217] = 1; /* 2215: pointer.struct.asn1_string_st */
    	em[2218] = 2116; em[2219] = 0; 
    em[2220] = 1; em[2221] = 8; em[2222] = 1; /* 2220: pointer.struct.asn1_string_st */
    	em[2223] = 2116; em[2224] = 0; 
    em[2225] = 1; em[2226] = 8; em[2227] = 1; /* 2225: pointer.struct.asn1_string_st */
    	em[2228] = 2116; em[2229] = 0; 
    em[2230] = 1; em[2231] = 8; em[2232] = 1; /* 2230: pointer.struct.asn1_string_st */
    	em[2233] = 2116; em[2234] = 0; 
    em[2235] = 1; em[2236] = 8; em[2237] = 1; /* 2235: pointer.struct.asn1_string_st */
    	em[2238] = 2116; em[2239] = 0; 
    em[2240] = 0; em[2241] = 8; em[2242] = 20; /* 2240: union.unknown */
    	em[2243] = 135; em[2244] = 0; 
    	em[2245] = 2111; em[2246] = 0; 
    	em[2247] = 2283; em[2248] = 0; 
    	em[2249] = 2297; em[2250] = 0; 
    	em[2251] = 2302; em[2252] = 0; 
    	em[2253] = 2307; em[2254] = 0; 
    	em[2255] = 2235; em[2256] = 0; 
    	em[2257] = 2230; em[2258] = 0; 
    	em[2259] = 2225; em[2260] = 0; 
    	em[2261] = 2312; em[2262] = 0; 
    	em[2263] = 2220; em[2264] = 0; 
    	em[2265] = 2215; em[2266] = 0; 
    	em[2267] = 2317; em[2268] = 0; 
    	em[2269] = 2210; em[2270] = 0; 
    	em[2271] = 2205; em[2272] = 0; 
    	em[2273] = 2322; em[2274] = 0; 
    	em[2275] = 2327; em[2276] = 0; 
    	em[2277] = 2111; em[2278] = 0; 
    	em[2279] = 2111; em[2280] = 0; 
    	em[2281] = 2332; em[2282] = 0; 
    em[2283] = 1; em[2284] = 8; em[2285] = 1; /* 2283: pointer.struct.asn1_object_st */
    	em[2286] = 2288; em[2287] = 0; 
    em[2288] = 0; em[2289] = 40; em[2290] = 3; /* 2288: struct.asn1_object_st */
    	em[2291] = 121; em[2292] = 0; 
    	em[2293] = 121; em[2294] = 8; 
    	em[2295] = 1511; em[2296] = 24; 
    em[2297] = 1; em[2298] = 8; em[2299] = 1; /* 2297: pointer.struct.asn1_string_st */
    	em[2300] = 2116; em[2301] = 0; 
    em[2302] = 1; em[2303] = 8; em[2304] = 1; /* 2302: pointer.struct.asn1_string_st */
    	em[2305] = 2116; em[2306] = 0; 
    em[2307] = 1; em[2308] = 8; em[2309] = 1; /* 2307: pointer.struct.asn1_string_st */
    	em[2310] = 2116; em[2311] = 0; 
    em[2312] = 1; em[2313] = 8; em[2314] = 1; /* 2312: pointer.struct.asn1_string_st */
    	em[2315] = 2116; em[2316] = 0; 
    em[2317] = 1; em[2318] = 8; em[2319] = 1; /* 2317: pointer.struct.asn1_string_st */
    	em[2320] = 2116; em[2321] = 0; 
    em[2322] = 1; em[2323] = 8; em[2324] = 1; /* 2322: pointer.struct.asn1_string_st */
    	em[2325] = 2116; em[2326] = 0; 
    em[2327] = 1; em[2328] = 8; em[2329] = 1; /* 2327: pointer.struct.asn1_string_st */
    	em[2330] = 2116; em[2331] = 0; 
    em[2332] = 1; em[2333] = 8; em[2334] = 1; /* 2332: pointer.struct.ASN1_VALUE_st */
    	em[2335] = 2337; em[2336] = 0; 
    em[2337] = 0; em[2338] = 0; em[2339] = 0; /* 2337: struct.ASN1_VALUE_st */
    em[2340] = 1; em[2341] = 8; em[2342] = 1; /* 2340: pointer.struct.otherName_st */
    	em[2343] = 2345; em[2344] = 0; 
    em[2345] = 0; em[2346] = 16; em[2347] = 2; /* 2345: struct.otherName_st */
    	em[2348] = 2283; em[2349] = 0; 
    	em[2350] = 2352; em[2351] = 8; 
    em[2352] = 1; em[2353] = 8; em[2354] = 1; /* 2352: pointer.struct.asn1_type_st */
    	em[2355] = 2357; em[2356] = 0; 
    em[2357] = 0; em[2358] = 16; em[2359] = 1; /* 2357: struct.asn1_type_st */
    	em[2360] = 2240; em[2361] = 8; 
    em[2362] = 0; em[2363] = 16; em[2364] = 1; /* 2362: struct.GENERAL_NAME_st */
    	em[2365] = 2367; em[2366] = 8; 
    em[2367] = 0; em[2368] = 8; em[2369] = 15; /* 2367: union.unknown */
    	em[2370] = 135; em[2371] = 0; 
    	em[2372] = 2340; em[2373] = 0; 
    	em[2374] = 2312; em[2375] = 0; 
    	em[2376] = 2312; em[2377] = 0; 
    	em[2378] = 2352; em[2379] = 0; 
    	em[2380] = 2400; em[2381] = 0; 
    	em[2382] = 2121; em[2383] = 0; 
    	em[2384] = 2312; em[2385] = 0; 
    	em[2386] = 2235; em[2387] = 0; 
    	em[2388] = 2283; em[2389] = 0; 
    	em[2390] = 2235; em[2391] = 0; 
    	em[2392] = 2400; em[2393] = 0; 
    	em[2394] = 2312; em[2395] = 0; 
    	em[2396] = 2283; em[2397] = 0; 
    	em[2398] = 2352; em[2399] = 0; 
    em[2400] = 1; em[2401] = 8; em[2402] = 1; /* 2400: pointer.struct.X509_name_st */
    	em[2403] = 2186; em[2404] = 0; 
    em[2405] = 1; em[2406] = 8; em[2407] = 1; /* 2405: pointer.struct.GENERAL_NAME_st */
    	em[2408] = 2362; em[2409] = 0; 
    em[2410] = 0; em[2411] = 24; em[2412] = 3; /* 2410: struct.GENERAL_SUBTREE_st */
    	em[2413] = 2405; em[2414] = 0; 
    	em[2415] = 2297; em[2416] = 8; 
    	em[2417] = 2297; em[2418] = 16; 
    em[2419] = 1; em[2420] = 8; em[2421] = 1; /* 2419: pointer.struct.NAME_CONSTRAINTS_st */
    	em[2422] = 2424; em[2423] = 0; 
    em[2424] = 0; em[2425] = 16; em[2426] = 2; /* 2424: struct.NAME_CONSTRAINTS_st */
    	em[2427] = 2431; em[2428] = 0; 
    	em[2429] = 2431; em[2430] = 8; 
    em[2431] = 1; em[2432] = 8; em[2433] = 1; /* 2431: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[2434] = 2436; em[2435] = 0; 
    em[2436] = 0; em[2437] = 32; em[2438] = 2; /* 2436: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[2439] = 2443; em[2440] = 8; 
    	em[2441] = 94; em[2442] = 24; 
    em[2443] = 8884099; em[2444] = 8; em[2445] = 2; /* 2443: pointer_to_array_of_pointers_to_stack */
    	em[2446] = 2450; em[2447] = 0; 
    	em[2448] = 52; em[2449] = 20; 
    em[2450] = 0; em[2451] = 8; em[2452] = 1; /* 2450: pointer.GENERAL_SUBTREE */
    	em[2453] = 2455; em[2454] = 0; 
    em[2455] = 0; em[2456] = 0; em[2457] = 1; /* 2455: GENERAL_SUBTREE */
    	em[2458] = 2410; em[2459] = 0; 
    em[2460] = 1; em[2461] = 8; em[2462] = 1; /* 2460: pointer.struct.stack_st_GENERAL_NAME */
    	em[2463] = 2465; em[2464] = 0; 
    em[2465] = 0; em[2466] = 32; em[2467] = 2; /* 2465: struct.stack_st_fake_GENERAL_NAME */
    	em[2468] = 2472; em[2469] = 8; 
    	em[2470] = 94; em[2471] = 24; 
    em[2472] = 8884099; em[2473] = 8; em[2474] = 2; /* 2472: pointer_to_array_of_pointers_to_stack */
    	em[2475] = 2479; em[2476] = 0; 
    	em[2477] = 52; em[2478] = 20; 
    em[2479] = 0; em[2480] = 8; em[2481] = 1; /* 2479: pointer.GENERAL_NAME */
    	em[2482] = 2484; em[2483] = 0; 
    em[2484] = 0; em[2485] = 0; em[2486] = 1; /* 2484: GENERAL_NAME */
    	em[2487] = 2489; em[2488] = 0; 
    em[2489] = 0; em[2490] = 16; em[2491] = 1; /* 2489: struct.GENERAL_NAME_st */
    	em[2492] = 2494; em[2493] = 8; 
    em[2494] = 0; em[2495] = 8; em[2496] = 15; /* 2494: union.unknown */
    	em[2497] = 135; em[2498] = 0; 
    	em[2499] = 2527; em[2500] = 0; 
    	em[2501] = 2646; em[2502] = 0; 
    	em[2503] = 2646; em[2504] = 0; 
    	em[2505] = 2553; em[2506] = 0; 
    	em[2507] = 2686; em[2508] = 0; 
    	em[2509] = 2734; em[2510] = 0; 
    	em[2511] = 2646; em[2512] = 0; 
    	em[2513] = 2631; em[2514] = 0; 
    	em[2515] = 2539; em[2516] = 0; 
    	em[2517] = 2631; em[2518] = 0; 
    	em[2519] = 2686; em[2520] = 0; 
    	em[2521] = 2646; em[2522] = 0; 
    	em[2523] = 2539; em[2524] = 0; 
    	em[2525] = 2553; em[2526] = 0; 
    em[2527] = 1; em[2528] = 8; em[2529] = 1; /* 2527: pointer.struct.otherName_st */
    	em[2530] = 2532; em[2531] = 0; 
    em[2532] = 0; em[2533] = 16; em[2534] = 2; /* 2532: struct.otherName_st */
    	em[2535] = 2539; em[2536] = 0; 
    	em[2537] = 2553; em[2538] = 8; 
    em[2539] = 1; em[2540] = 8; em[2541] = 1; /* 2539: pointer.struct.asn1_object_st */
    	em[2542] = 2544; em[2543] = 0; 
    em[2544] = 0; em[2545] = 40; em[2546] = 3; /* 2544: struct.asn1_object_st */
    	em[2547] = 121; em[2548] = 0; 
    	em[2549] = 121; em[2550] = 8; 
    	em[2551] = 1511; em[2552] = 24; 
    em[2553] = 1; em[2554] = 8; em[2555] = 1; /* 2553: pointer.struct.asn1_type_st */
    	em[2556] = 2558; em[2557] = 0; 
    em[2558] = 0; em[2559] = 16; em[2560] = 1; /* 2558: struct.asn1_type_st */
    	em[2561] = 2563; em[2562] = 8; 
    em[2563] = 0; em[2564] = 8; em[2565] = 20; /* 2563: union.unknown */
    	em[2566] = 135; em[2567] = 0; 
    	em[2568] = 2606; em[2569] = 0; 
    	em[2570] = 2539; em[2571] = 0; 
    	em[2572] = 2616; em[2573] = 0; 
    	em[2574] = 2621; em[2575] = 0; 
    	em[2576] = 2626; em[2577] = 0; 
    	em[2578] = 2631; em[2579] = 0; 
    	em[2580] = 2636; em[2581] = 0; 
    	em[2582] = 2641; em[2583] = 0; 
    	em[2584] = 2646; em[2585] = 0; 
    	em[2586] = 2651; em[2587] = 0; 
    	em[2588] = 2656; em[2589] = 0; 
    	em[2590] = 2661; em[2591] = 0; 
    	em[2592] = 2666; em[2593] = 0; 
    	em[2594] = 2671; em[2595] = 0; 
    	em[2596] = 2676; em[2597] = 0; 
    	em[2598] = 2681; em[2599] = 0; 
    	em[2600] = 2606; em[2601] = 0; 
    	em[2602] = 2606; em[2603] = 0; 
    	em[2604] = 2332; em[2605] = 0; 
    em[2606] = 1; em[2607] = 8; em[2608] = 1; /* 2606: pointer.struct.asn1_string_st */
    	em[2609] = 2611; em[2610] = 0; 
    em[2611] = 0; em[2612] = 24; em[2613] = 1; /* 2611: struct.asn1_string_st */
    	em[2614] = 69; em[2615] = 8; 
    em[2616] = 1; em[2617] = 8; em[2618] = 1; /* 2616: pointer.struct.asn1_string_st */
    	em[2619] = 2611; em[2620] = 0; 
    em[2621] = 1; em[2622] = 8; em[2623] = 1; /* 2621: pointer.struct.asn1_string_st */
    	em[2624] = 2611; em[2625] = 0; 
    em[2626] = 1; em[2627] = 8; em[2628] = 1; /* 2626: pointer.struct.asn1_string_st */
    	em[2629] = 2611; em[2630] = 0; 
    em[2631] = 1; em[2632] = 8; em[2633] = 1; /* 2631: pointer.struct.asn1_string_st */
    	em[2634] = 2611; em[2635] = 0; 
    em[2636] = 1; em[2637] = 8; em[2638] = 1; /* 2636: pointer.struct.asn1_string_st */
    	em[2639] = 2611; em[2640] = 0; 
    em[2641] = 1; em[2642] = 8; em[2643] = 1; /* 2641: pointer.struct.asn1_string_st */
    	em[2644] = 2611; em[2645] = 0; 
    em[2646] = 1; em[2647] = 8; em[2648] = 1; /* 2646: pointer.struct.asn1_string_st */
    	em[2649] = 2611; em[2650] = 0; 
    em[2651] = 1; em[2652] = 8; em[2653] = 1; /* 2651: pointer.struct.asn1_string_st */
    	em[2654] = 2611; em[2655] = 0; 
    em[2656] = 1; em[2657] = 8; em[2658] = 1; /* 2656: pointer.struct.asn1_string_st */
    	em[2659] = 2611; em[2660] = 0; 
    em[2661] = 1; em[2662] = 8; em[2663] = 1; /* 2661: pointer.struct.asn1_string_st */
    	em[2664] = 2611; em[2665] = 0; 
    em[2666] = 1; em[2667] = 8; em[2668] = 1; /* 2666: pointer.struct.asn1_string_st */
    	em[2669] = 2611; em[2670] = 0; 
    em[2671] = 1; em[2672] = 8; em[2673] = 1; /* 2671: pointer.struct.asn1_string_st */
    	em[2674] = 2611; em[2675] = 0; 
    em[2676] = 1; em[2677] = 8; em[2678] = 1; /* 2676: pointer.struct.asn1_string_st */
    	em[2679] = 2611; em[2680] = 0; 
    em[2681] = 1; em[2682] = 8; em[2683] = 1; /* 2681: pointer.struct.asn1_string_st */
    	em[2684] = 2611; em[2685] = 0; 
    em[2686] = 1; em[2687] = 8; em[2688] = 1; /* 2686: pointer.struct.X509_name_st */
    	em[2689] = 2691; em[2690] = 0; 
    em[2691] = 0; em[2692] = 40; em[2693] = 3; /* 2691: struct.X509_name_st */
    	em[2694] = 2700; em[2695] = 0; 
    	em[2696] = 2724; em[2697] = 16; 
    	em[2698] = 69; em[2699] = 24; 
    em[2700] = 1; em[2701] = 8; em[2702] = 1; /* 2700: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2703] = 2705; em[2704] = 0; 
    em[2705] = 0; em[2706] = 32; em[2707] = 2; /* 2705: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2708] = 2712; em[2709] = 8; 
    	em[2710] = 94; em[2711] = 24; 
    em[2712] = 8884099; em[2713] = 8; em[2714] = 2; /* 2712: pointer_to_array_of_pointers_to_stack */
    	em[2715] = 2719; em[2716] = 0; 
    	em[2717] = 52; em[2718] = 20; 
    em[2719] = 0; em[2720] = 8; em[2721] = 1; /* 2719: pointer.X509_NAME_ENTRY */
    	em[2722] = 2150; em[2723] = 0; 
    em[2724] = 1; em[2725] = 8; em[2726] = 1; /* 2724: pointer.struct.buf_mem_st */
    	em[2727] = 2729; em[2728] = 0; 
    em[2729] = 0; em[2730] = 24; em[2731] = 1; /* 2729: struct.buf_mem_st */
    	em[2732] = 135; em[2733] = 8; 
    em[2734] = 1; em[2735] = 8; em[2736] = 1; /* 2734: pointer.struct.EDIPartyName_st */
    	em[2737] = 2739; em[2738] = 0; 
    em[2739] = 0; em[2740] = 16; em[2741] = 2; /* 2739: struct.EDIPartyName_st */
    	em[2742] = 2606; em[2743] = 0; 
    	em[2744] = 2606; em[2745] = 8; 
    em[2746] = 0; em[2747] = 24; em[2748] = 1; /* 2746: struct.asn1_string_st */
    	em[2749] = 69; em[2750] = 8; 
    em[2751] = 1; em[2752] = 8; em[2753] = 1; /* 2751: pointer.struct.buf_mem_st */
    	em[2754] = 2756; em[2755] = 0; 
    em[2756] = 0; em[2757] = 24; em[2758] = 1; /* 2756: struct.buf_mem_st */
    	em[2759] = 135; em[2760] = 8; 
    em[2761] = 1; em[2762] = 8; em[2763] = 1; /* 2761: pointer.struct.stack_st_GENERAL_NAME */
    	em[2764] = 2766; em[2765] = 0; 
    em[2766] = 0; em[2767] = 32; em[2768] = 2; /* 2766: struct.stack_st_fake_GENERAL_NAME */
    	em[2769] = 2773; em[2770] = 8; 
    	em[2771] = 94; em[2772] = 24; 
    em[2773] = 8884099; em[2774] = 8; em[2775] = 2; /* 2773: pointer_to_array_of_pointers_to_stack */
    	em[2776] = 2780; em[2777] = 0; 
    	em[2778] = 52; em[2779] = 20; 
    em[2780] = 0; em[2781] = 8; em[2782] = 1; /* 2780: pointer.GENERAL_NAME */
    	em[2783] = 2484; em[2784] = 0; 
    em[2785] = 0; em[2786] = 8; em[2787] = 2; /* 2785: union.unknown */
    	em[2788] = 2761; em[2789] = 0; 
    	em[2790] = 2792; em[2791] = 0; 
    em[2792] = 1; em[2793] = 8; em[2794] = 1; /* 2792: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2795] = 2797; em[2796] = 0; 
    em[2797] = 0; em[2798] = 32; em[2799] = 2; /* 2797: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2800] = 2804; em[2801] = 8; 
    	em[2802] = 94; em[2803] = 24; 
    em[2804] = 8884099; em[2805] = 8; em[2806] = 2; /* 2804: pointer_to_array_of_pointers_to_stack */
    	em[2807] = 2811; em[2808] = 0; 
    	em[2809] = 52; em[2810] = 20; 
    em[2811] = 0; em[2812] = 8; em[2813] = 1; /* 2811: pointer.X509_NAME_ENTRY */
    	em[2814] = 2150; em[2815] = 0; 
    em[2816] = 0; em[2817] = 24; em[2818] = 2; /* 2816: struct.DIST_POINT_NAME_st */
    	em[2819] = 2785; em[2820] = 8; 
    	em[2821] = 2823; em[2822] = 16; 
    em[2823] = 1; em[2824] = 8; em[2825] = 1; /* 2823: pointer.struct.X509_name_st */
    	em[2826] = 2828; em[2827] = 0; 
    em[2828] = 0; em[2829] = 40; em[2830] = 3; /* 2828: struct.X509_name_st */
    	em[2831] = 2792; em[2832] = 0; 
    	em[2833] = 2751; em[2834] = 16; 
    	em[2835] = 69; em[2836] = 24; 
    em[2837] = 1; em[2838] = 8; em[2839] = 1; /* 2837: pointer.struct.DIST_POINT_NAME_st */
    	em[2840] = 2816; em[2841] = 0; 
    em[2842] = 0; em[2843] = 0; em[2844] = 1; /* 2842: DIST_POINT */
    	em[2845] = 2847; em[2846] = 0; 
    em[2847] = 0; em[2848] = 32; em[2849] = 3; /* 2847: struct.DIST_POINT_st */
    	em[2850] = 2837; em[2851] = 0; 
    	em[2852] = 2856; em[2853] = 8; 
    	em[2854] = 2761; em[2855] = 16; 
    em[2856] = 1; em[2857] = 8; em[2858] = 1; /* 2856: pointer.struct.asn1_string_st */
    	em[2859] = 2746; em[2860] = 0; 
    em[2861] = 1; em[2862] = 8; em[2863] = 1; /* 2861: pointer.struct.stack_st_DIST_POINT */
    	em[2864] = 2866; em[2865] = 0; 
    em[2866] = 0; em[2867] = 32; em[2868] = 2; /* 2866: struct.stack_st_fake_DIST_POINT */
    	em[2869] = 2873; em[2870] = 8; 
    	em[2871] = 94; em[2872] = 24; 
    em[2873] = 8884099; em[2874] = 8; em[2875] = 2; /* 2873: pointer_to_array_of_pointers_to_stack */
    	em[2876] = 2880; em[2877] = 0; 
    	em[2878] = 52; em[2879] = 20; 
    em[2880] = 0; em[2881] = 8; em[2882] = 1; /* 2880: pointer.DIST_POINT */
    	em[2883] = 2842; em[2884] = 0; 
    em[2885] = 1; em[2886] = 8; em[2887] = 1; /* 2885: pointer.struct.stack_st_ASN1_OBJECT */
    	em[2888] = 2890; em[2889] = 0; 
    em[2890] = 0; em[2891] = 32; em[2892] = 2; /* 2890: struct.stack_st_fake_ASN1_OBJECT */
    	em[2893] = 2897; em[2894] = 8; 
    	em[2895] = 94; em[2896] = 24; 
    em[2897] = 8884099; em[2898] = 8; em[2899] = 2; /* 2897: pointer_to_array_of_pointers_to_stack */
    	em[2900] = 2904; em[2901] = 0; 
    	em[2902] = 52; em[2903] = 20; 
    em[2904] = 0; em[2905] = 8; em[2906] = 1; /* 2904: pointer.ASN1_OBJECT */
    	em[2907] = 2056; em[2908] = 0; 
    em[2909] = 1; em[2910] = 8; em[2911] = 1; /* 2909: pointer.struct.stack_st_POLICYQUALINFO */
    	em[2912] = 2914; em[2913] = 0; 
    em[2914] = 0; em[2915] = 32; em[2916] = 2; /* 2914: struct.stack_st_fake_POLICYQUALINFO */
    	em[2917] = 2921; em[2918] = 8; 
    	em[2919] = 94; em[2920] = 24; 
    em[2921] = 8884099; em[2922] = 8; em[2923] = 2; /* 2921: pointer_to_array_of_pointers_to_stack */
    	em[2924] = 2928; em[2925] = 0; 
    	em[2926] = 52; em[2927] = 20; 
    em[2928] = 0; em[2929] = 8; em[2930] = 1; /* 2928: pointer.POLICYQUALINFO */
    	em[2931] = 2933; em[2932] = 0; 
    em[2933] = 0; em[2934] = 0; em[2935] = 1; /* 2933: POLICYQUALINFO */
    	em[2936] = 2938; em[2937] = 0; 
    em[2938] = 0; em[2939] = 16; em[2940] = 2; /* 2938: struct.POLICYQUALINFO_st */
    	em[2941] = 2945; em[2942] = 0; 
    	em[2943] = 2959; em[2944] = 8; 
    em[2945] = 1; em[2946] = 8; em[2947] = 1; /* 2945: pointer.struct.asn1_object_st */
    	em[2948] = 2950; em[2949] = 0; 
    em[2950] = 0; em[2951] = 40; em[2952] = 3; /* 2950: struct.asn1_object_st */
    	em[2953] = 121; em[2954] = 0; 
    	em[2955] = 121; em[2956] = 8; 
    	em[2957] = 1511; em[2958] = 24; 
    em[2959] = 0; em[2960] = 8; em[2961] = 3; /* 2959: union.unknown */
    	em[2962] = 2968; em[2963] = 0; 
    	em[2964] = 2978; em[2965] = 0; 
    	em[2966] = 3036; em[2967] = 0; 
    em[2968] = 1; em[2969] = 8; em[2970] = 1; /* 2968: pointer.struct.asn1_string_st */
    	em[2971] = 2973; em[2972] = 0; 
    em[2973] = 0; em[2974] = 24; em[2975] = 1; /* 2973: struct.asn1_string_st */
    	em[2976] = 69; em[2977] = 8; 
    em[2978] = 1; em[2979] = 8; em[2980] = 1; /* 2978: pointer.struct.USERNOTICE_st */
    	em[2981] = 2983; em[2982] = 0; 
    em[2983] = 0; em[2984] = 16; em[2985] = 2; /* 2983: struct.USERNOTICE_st */
    	em[2986] = 2990; em[2987] = 0; 
    	em[2988] = 3002; em[2989] = 8; 
    em[2990] = 1; em[2991] = 8; em[2992] = 1; /* 2990: pointer.struct.NOTICEREF_st */
    	em[2993] = 2995; em[2994] = 0; 
    em[2995] = 0; em[2996] = 16; em[2997] = 2; /* 2995: struct.NOTICEREF_st */
    	em[2998] = 3002; em[2999] = 0; 
    	em[3000] = 3007; em[3001] = 8; 
    em[3002] = 1; em[3003] = 8; em[3004] = 1; /* 3002: pointer.struct.asn1_string_st */
    	em[3005] = 2973; em[3006] = 0; 
    em[3007] = 1; em[3008] = 8; em[3009] = 1; /* 3007: pointer.struct.stack_st_ASN1_INTEGER */
    	em[3010] = 3012; em[3011] = 0; 
    em[3012] = 0; em[3013] = 32; em[3014] = 2; /* 3012: struct.stack_st_fake_ASN1_INTEGER */
    	em[3015] = 3019; em[3016] = 8; 
    	em[3017] = 94; em[3018] = 24; 
    em[3019] = 8884099; em[3020] = 8; em[3021] = 2; /* 3019: pointer_to_array_of_pointers_to_stack */
    	em[3022] = 3026; em[3023] = 0; 
    	em[3024] = 52; em[3025] = 20; 
    em[3026] = 0; em[3027] = 8; em[3028] = 1; /* 3026: pointer.ASN1_INTEGER */
    	em[3029] = 3031; em[3030] = 0; 
    em[3031] = 0; em[3032] = 0; em[3033] = 1; /* 3031: ASN1_INTEGER */
    	em[3034] = 1934; em[3035] = 0; 
    em[3036] = 1; em[3037] = 8; em[3038] = 1; /* 3036: pointer.struct.asn1_type_st */
    	em[3039] = 3041; em[3040] = 0; 
    em[3041] = 0; em[3042] = 16; em[3043] = 1; /* 3041: struct.asn1_type_st */
    	em[3044] = 3046; em[3045] = 8; 
    em[3046] = 0; em[3047] = 8; em[3048] = 20; /* 3046: union.unknown */
    	em[3049] = 135; em[3050] = 0; 
    	em[3051] = 3002; em[3052] = 0; 
    	em[3053] = 2945; em[3054] = 0; 
    	em[3055] = 3089; em[3056] = 0; 
    	em[3057] = 3094; em[3058] = 0; 
    	em[3059] = 3099; em[3060] = 0; 
    	em[3061] = 3104; em[3062] = 0; 
    	em[3063] = 3109; em[3064] = 0; 
    	em[3065] = 3114; em[3066] = 0; 
    	em[3067] = 2968; em[3068] = 0; 
    	em[3069] = 3119; em[3070] = 0; 
    	em[3071] = 3124; em[3072] = 0; 
    	em[3073] = 3129; em[3074] = 0; 
    	em[3075] = 3134; em[3076] = 0; 
    	em[3077] = 3139; em[3078] = 0; 
    	em[3079] = 3144; em[3080] = 0; 
    	em[3081] = 3149; em[3082] = 0; 
    	em[3083] = 3002; em[3084] = 0; 
    	em[3085] = 3002; em[3086] = 0; 
    	em[3087] = 2332; em[3088] = 0; 
    em[3089] = 1; em[3090] = 8; em[3091] = 1; /* 3089: pointer.struct.asn1_string_st */
    	em[3092] = 2973; em[3093] = 0; 
    em[3094] = 1; em[3095] = 8; em[3096] = 1; /* 3094: pointer.struct.asn1_string_st */
    	em[3097] = 2973; em[3098] = 0; 
    em[3099] = 1; em[3100] = 8; em[3101] = 1; /* 3099: pointer.struct.asn1_string_st */
    	em[3102] = 2973; em[3103] = 0; 
    em[3104] = 1; em[3105] = 8; em[3106] = 1; /* 3104: pointer.struct.asn1_string_st */
    	em[3107] = 2973; em[3108] = 0; 
    em[3109] = 1; em[3110] = 8; em[3111] = 1; /* 3109: pointer.struct.asn1_string_st */
    	em[3112] = 2973; em[3113] = 0; 
    em[3114] = 1; em[3115] = 8; em[3116] = 1; /* 3114: pointer.struct.asn1_string_st */
    	em[3117] = 2973; em[3118] = 0; 
    em[3119] = 1; em[3120] = 8; em[3121] = 1; /* 3119: pointer.struct.asn1_string_st */
    	em[3122] = 2973; em[3123] = 0; 
    em[3124] = 1; em[3125] = 8; em[3126] = 1; /* 3124: pointer.struct.asn1_string_st */
    	em[3127] = 2973; em[3128] = 0; 
    em[3129] = 1; em[3130] = 8; em[3131] = 1; /* 3129: pointer.struct.asn1_string_st */
    	em[3132] = 2973; em[3133] = 0; 
    em[3134] = 1; em[3135] = 8; em[3136] = 1; /* 3134: pointer.struct.asn1_string_st */
    	em[3137] = 2973; em[3138] = 0; 
    em[3139] = 1; em[3140] = 8; em[3141] = 1; /* 3139: pointer.struct.asn1_string_st */
    	em[3142] = 2973; em[3143] = 0; 
    em[3144] = 1; em[3145] = 8; em[3146] = 1; /* 3144: pointer.struct.asn1_string_st */
    	em[3147] = 2973; em[3148] = 0; 
    em[3149] = 1; em[3150] = 8; em[3151] = 1; /* 3149: pointer.struct.asn1_string_st */
    	em[3152] = 2973; em[3153] = 0; 
    em[3154] = 0; em[3155] = 32; em[3156] = 3; /* 3154: struct.X509_POLICY_DATA_st */
    	em[3157] = 3163; em[3158] = 8; 
    	em[3159] = 2909; em[3160] = 16; 
    	em[3161] = 2885; em[3162] = 24; 
    em[3163] = 1; em[3164] = 8; em[3165] = 1; /* 3163: pointer.struct.asn1_object_st */
    	em[3166] = 3168; em[3167] = 0; 
    em[3168] = 0; em[3169] = 40; em[3170] = 3; /* 3168: struct.asn1_object_st */
    	em[3171] = 121; em[3172] = 0; 
    	em[3173] = 121; em[3174] = 8; 
    	em[3175] = 1511; em[3176] = 24; 
    em[3177] = 1; em[3178] = 8; em[3179] = 1; /* 3177: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[3180] = 3182; em[3181] = 0; 
    em[3182] = 0; em[3183] = 32; em[3184] = 2; /* 3182: struct.stack_st_fake_X509_POLICY_DATA */
    	em[3185] = 3189; em[3186] = 8; 
    	em[3187] = 94; em[3188] = 24; 
    em[3189] = 8884099; em[3190] = 8; em[3191] = 2; /* 3189: pointer_to_array_of_pointers_to_stack */
    	em[3192] = 3196; em[3193] = 0; 
    	em[3194] = 52; em[3195] = 20; 
    em[3196] = 0; em[3197] = 8; em[3198] = 1; /* 3196: pointer.X509_POLICY_DATA */
    	em[3199] = 3201; em[3200] = 0; 
    em[3201] = 0; em[3202] = 0; em[3203] = 1; /* 3201: X509_POLICY_DATA */
    	em[3204] = 3154; em[3205] = 0; 
    em[3206] = 1; em[3207] = 8; em[3208] = 1; /* 3206: pointer.struct.stack_st_ASN1_OBJECT */
    	em[3209] = 3211; em[3210] = 0; 
    em[3211] = 0; em[3212] = 32; em[3213] = 2; /* 3211: struct.stack_st_fake_ASN1_OBJECT */
    	em[3214] = 3218; em[3215] = 8; 
    	em[3216] = 94; em[3217] = 24; 
    em[3218] = 8884099; em[3219] = 8; em[3220] = 2; /* 3218: pointer_to_array_of_pointers_to_stack */
    	em[3221] = 3225; em[3222] = 0; 
    	em[3223] = 52; em[3224] = 20; 
    em[3225] = 0; em[3226] = 8; em[3227] = 1; /* 3225: pointer.ASN1_OBJECT */
    	em[3228] = 2056; em[3229] = 0; 
    em[3230] = 1; em[3231] = 8; em[3232] = 1; /* 3230: pointer.struct.stack_st_POLICYQUALINFO */
    	em[3233] = 3235; em[3234] = 0; 
    em[3235] = 0; em[3236] = 32; em[3237] = 2; /* 3235: struct.stack_st_fake_POLICYQUALINFO */
    	em[3238] = 3242; em[3239] = 8; 
    	em[3240] = 94; em[3241] = 24; 
    em[3242] = 8884099; em[3243] = 8; em[3244] = 2; /* 3242: pointer_to_array_of_pointers_to_stack */
    	em[3245] = 3249; em[3246] = 0; 
    	em[3247] = 52; em[3248] = 20; 
    em[3249] = 0; em[3250] = 8; em[3251] = 1; /* 3249: pointer.POLICYQUALINFO */
    	em[3252] = 2933; em[3253] = 0; 
    em[3254] = 0; em[3255] = 40; em[3256] = 3; /* 3254: struct.asn1_object_st */
    	em[3257] = 121; em[3258] = 0; 
    	em[3259] = 121; em[3260] = 8; 
    	em[3261] = 1511; em[3262] = 24; 
    em[3263] = 0; em[3264] = 32; em[3265] = 3; /* 3263: struct.X509_POLICY_DATA_st */
    	em[3266] = 3272; em[3267] = 8; 
    	em[3268] = 3230; em[3269] = 16; 
    	em[3270] = 3206; em[3271] = 24; 
    em[3272] = 1; em[3273] = 8; em[3274] = 1; /* 3272: pointer.struct.asn1_object_st */
    	em[3275] = 3254; em[3276] = 0; 
    em[3277] = 1; em[3278] = 8; em[3279] = 1; /* 3277: pointer.struct.X509_POLICY_DATA_st */
    	em[3280] = 3263; em[3281] = 0; 
    em[3282] = 0; em[3283] = 40; em[3284] = 2; /* 3282: struct.X509_POLICY_CACHE_st */
    	em[3285] = 3277; em[3286] = 0; 
    	em[3287] = 3177; em[3288] = 8; 
    em[3289] = 1; em[3290] = 8; em[3291] = 1; /* 3289: pointer.struct.asn1_string_st */
    	em[3292] = 3294; em[3293] = 0; 
    em[3294] = 0; em[3295] = 24; em[3296] = 1; /* 3294: struct.asn1_string_st */
    	em[3297] = 69; em[3298] = 8; 
    em[3299] = 1; em[3300] = 8; em[3301] = 1; /* 3299: pointer.struct.stack_st_GENERAL_NAME */
    	em[3302] = 3304; em[3303] = 0; 
    em[3304] = 0; em[3305] = 32; em[3306] = 2; /* 3304: struct.stack_st_fake_GENERAL_NAME */
    	em[3307] = 3311; em[3308] = 8; 
    	em[3309] = 94; em[3310] = 24; 
    em[3311] = 8884099; em[3312] = 8; em[3313] = 2; /* 3311: pointer_to_array_of_pointers_to_stack */
    	em[3314] = 3318; em[3315] = 0; 
    	em[3316] = 52; em[3317] = 20; 
    em[3318] = 0; em[3319] = 8; em[3320] = 1; /* 3318: pointer.GENERAL_NAME */
    	em[3321] = 2484; em[3322] = 0; 
    em[3323] = 1; em[3324] = 8; em[3325] = 1; /* 3323: pointer.struct.AUTHORITY_KEYID_st */
    	em[3326] = 3328; em[3327] = 0; 
    em[3328] = 0; em[3329] = 24; em[3330] = 3; /* 3328: struct.AUTHORITY_KEYID_st */
    	em[3331] = 3337; em[3332] = 0; 
    	em[3333] = 3299; em[3334] = 8; 
    	em[3335] = 3289; em[3336] = 16; 
    em[3337] = 1; em[3338] = 8; em[3339] = 1; /* 3337: pointer.struct.asn1_string_st */
    	em[3340] = 3294; em[3341] = 0; 
    em[3342] = 0; em[3343] = 24; em[3344] = 1; /* 3342: struct.asn1_string_st */
    	em[3345] = 69; em[3346] = 8; 
    em[3347] = 1; em[3348] = 8; em[3349] = 1; /* 3347: pointer.struct.asn1_string_st */
    	em[3350] = 3342; em[3351] = 0; 
    em[3352] = 1; em[3353] = 8; em[3354] = 1; /* 3352: pointer.struct.stack_st_X509_EXTENSION */
    	em[3355] = 3357; em[3356] = 0; 
    em[3357] = 0; em[3358] = 32; em[3359] = 2; /* 3357: struct.stack_st_fake_X509_EXTENSION */
    	em[3360] = 3364; em[3361] = 8; 
    	em[3362] = 94; em[3363] = 24; 
    em[3364] = 8884099; em[3365] = 8; em[3366] = 2; /* 3364: pointer_to_array_of_pointers_to_stack */
    	em[3367] = 3371; em[3368] = 0; 
    	em[3369] = 52; em[3370] = 20; 
    em[3371] = 0; em[3372] = 8; em[3373] = 1; /* 3371: pointer.X509_EXTENSION */
    	em[3374] = 3376; em[3375] = 0; 
    em[3376] = 0; em[3377] = 0; em[3378] = 1; /* 3376: X509_EXTENSION */
    	em[3379] = 3381; em[3380] = 0; 
    em[3381] = 0; em[3382] = 24; em[3383] = 2; /* 3381: struct.X509_extension_st */
    	em[3384] = 3388; em[3385] = 0; 
    	em[3386] = 3347; em[3387] = 16; 
    em[3388] = 1; em[3389] = 8; em[3390] = 1; /* 3388: pointer.struct.asn1_object_st */
    	em[3391] = 3393; em[3392] = 0; 
    em[3393] = 0; em[3394] = 40; em[3395] = 3; /* 3393: struct.asn1_object_st */
    	em[3396] = 121; em[3397] = 0; 
    	em[3398] = 121; em[3399] = 8; 
    	em[3400] = 1511; em[3401] = 24; 
    em[3402] = 1; em[3403] = 8; em[3404] = 1; /* 3402: pointer.struct.asn1_string_st */
    	em[3405] = 2014; em[3406] = 0; 
    em[3407] = 0; em[3408] = 24; em[3409] = 1; /* 3407: struct.ASN1_ENCODING_st */
    	em[3410] = 69; em[3411] = 0; 
    em[3412] = 1; em[3413] = 8; em[3414] = 1; /* 3412: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3415] = 3417; em[3416] = 0; 
    em[3417] = 0; em[3418] = 32; em[3419] = 2; /* 3417: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[3420] = 3424; em[3421] = 8; 
    	em[3422] = 94; em[3423] = 24; 
    em[3424] = 8884099; em[3425] = 8; em[3426] = 2; /* 3424: pointer_to_array_of_pointers_to_stack */
    	em[3427] = 3431; em[3428] = 0; 
    	em[3429] = 52; em[3430] = 20; 
    em[3431] = 0; em[3432] = 8; em[3433] = 1; /* 3431: pointer.X509_ATTRIBUTE */
    	em[3434] = 1485; em[3435] = 0; 
    em[3436] = 1; em[3437] = 8; em[3438] = 1; /* 3436: pointer.struct.evp_pkey_asn1_method_st */
    	em[3439] = 838; em[3440] = 0; 
    em[3441] = 0; em[3442] = 56; em[3443] = 4; /* 3441: struct.evp_pkey_st */
    	em[3444] = 3436; em[3445] = 16; 
    	em[3446] = 3452; em[3447] = 24; 
    	em[3448] = 3457; em[3449] = 32; 
    	em[3450] = 3412; em[3451] = 48; 
    em[3452] = 1; em[3453] = 8; em[3454] = 1; /* 3452: pointer.struct.engine_st */
    	em[3455] = 148; em[3456] = 0; 
    em[3457] = 0; em[3458] = 8; em[3459] = 5; /* 3457: union.unknown */
    	em[3460] = 135; em[3461] = 0; 
    	em[3462] = 3470; em[3463] = 0; 
    	em[3464] = 3475; em[3465] = 0; 
    	em[3466] = 3480; em[3467] = 0; 
    	em[3468] = 3485; em[3469] = 0; 
    em[3470] = 1; em[3471] = 8; em[3472] = 1; /* 3470: pointer.struct.rsa_st */
    	em[3473] = 619; em[3474] = 0; 
    em[3475] = 1; em[3476] = 8; em[3477] = 1; /* 3475: pointer.struct.dsa_st */
    	em[3478] = 488; em[3479] = 0; 
    em[3480] = 1; em[3481] = 8; em[3482] = 1; /* 3480: pointer.struct.dh_st */
    	em[3483] = 5; em[3484] = 0; 
    em[3485] = 1; em[3486] = 8; em[3487] = 1; /* 3485: pointer.struct.ec_key_st */
    	em[3488] = 957; em[3489] = 0; 
    em[3490] = 1; em[3491] = 8; em[3492] = 1; /* 3490: pointer.struct.evp_pkey_st */
    	em[3493] = 3441; em[3494] = 0; 
    em[3495] = 0; em[3496] = 24; em[3497] = 1; /* 3495: struct.asn1_string_st */
    	em[3498] = 69; em[3499] = 8; 
    em[3500] = 0; em[3501] = 1; em[3502] = 0; /* 3500: char */
    em[3503] = 1; em[3504] = 8; em[3505] = 1; /* 3503: pointer.struct.buf_mem_st */
    	em[3506] = 3508; em[3507] = 0; 
    em[3508] = 0; em[3509] = 24; em[3510] = 1; /* 3508: struct.buf_mem_st */
    	em[3511] = 135; em[3512] = 8; 
    em[3513] = 1; em[3514] = 8; em[3515] = 1; /* 3513: pointer.struct.asn1_string_st */
    	em[3516] = 2014; em[3517] = 0; 
    em[3518] = 0; em[3519] = 184; em[3520] = 12; /* 3518: struct.x509_st */
    	em[3521] = 3545; em[3522] = 0; 
    	em[3523] = 3580; em[3524] = 8; 
    	em[3525] = 3402; em[3526] = 16; 
    	em[3527] = 135; em[3528] = 32; 
    	em[3529] = 3659; em[3530] = 40; 
    	em[3531] = 2070; em[3532] = 104; 
    	em[3533] = 3323; em[3534] = 112; 
    	em[3535] = 3673; em[3536] = 120; 
    	em[3537] = 2861; em[3538] = 128; 
    	em[3539] = 2460; em[3540] = 136; 
    	em[3541] = 2419; em[3542] = 144; 
    	em[3543] = 2099; em[3544] = 176; 
    em[3545] = 1; em[3546] = 8; em[3547] = 1; /* 3545: pointer.struct.x509_cinf_st */
    	em[3548] = 3550; em[3549] = 0; 
    em[3550] = 0; em[3551] = 104; em[3552] = 11; /* 3550: struct.x509_cinf_st */
    	em[3553] = 3575; em[3554] = 0; 
    	em[3555] = 3575; em[3556] = 8; 
    	em[3557] = 3580; em[3558] = 16; 
    	em[3559] = 3585; em[3560] = 24; 
    	em[3561] = 3623; em[3562] = 32; 
    	em[3563] = 3585; em[3564] = 40; 
    	em[3565] = 3635; em[3566] = 48; 
    	em[3567] = 3402; em[3568] = 56; 
    	em[3569] = 3402; em[3570] = 64; 
    	em[3571] = 3352; em[3572] = 72; 
    	em[3573] = 3407; em[3574] = 80; 
    em[3575] = 1; em[3576] = 8; em[3577] = 1; /* 3575: pointer.struct.asn1_string_st */
    	em[3578] = 2014; em[3579] = 0; 
    em[3580] = 1; em[3581] = 8; em[3582] = 1; /* 3580: pointer.struct.X509_algor_st */
    	em[3583] = 1855; em[3584] = 0; 
    em[3585] = 1; em[3586] = 8; em[3587] = 1; /* 3585: pointer.struct.X509_name_st */
    	em[3588] = 3590; em[3589] = 0; 
    em[3590] = 0; em[3591] = 40; em[3592] = 3; /* 3590: struct.X509_name_st */
    	em[3593] = 3599; em[3594] = 0; 
    	em[3595] = 3503; em[3596] = 16; 
    	em[3597] = 69; em[3598] = 24; 
    em[3599] = 1; em[3600] = 8; em[3601] = 1; /* 3599: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3602] = 3604; em[3603] = 0; 
    em[3604] = 0; em[3605] = 32; em[3606] = 2; /* 3604: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3607] = 3611; em[3608] = 8; 
    	em[3609] = 94; em[3610] = 24; 
    em[3611] = 8884099; em[3612] = 8; em[3613] = 2; /* 3611: pointer_to_array_of_pointers_to_stack */
    	em[3614] = 3618; em[3615] = 0; 
    	em[3616] = 52; em[3617] = 20; 
    em[3618] = 0; em[3619] = 8; em[3620] = 1; /* 3618: pointer.X509_NAME_ENTRY */
    	em[3621] = 2150; em[3622] = 0; 
    em[3623] = 1; em[3624] = 8; em[3625] = 1; /* 3623: pointer.struct.X509_val_st */
    	em[3626] = 3628; em[3627] = 0; 
    em[3628] = 0; em[3629] = 16; em[3630] = 2; /* 3628: struct.X509_val_st */
    	em[3631] = 3513; em[3632] = 0; 
    	em[3633] = 3513; em[3634] = 8; 
    em[3635] = 1; em[3636] = 8; em[3637] = 1; /* 3635: pointer.struct.X509_pubkey_st */
    	em[3638] = 3640; em[3639] = 0; 
    em[3640] = 0; em[3641] = 24; em[3642] = 3; /* 3640: struct.X509_pubkey_st */
    	em[3643] = 3649; em[3644] = 0; 
    	em[3645] = 3654; em[3646] = 8; 
    	em[3647] = 3490; em[3648] = 16; 
    em[3649] = 1; em[3650] = 8; em[3651] = 1; /* 3649: pointer.struct.X509_algor_st */
    	em[3652] = 1855; em[3653] = 0; 
    em[3654] = 1; em[3655] = 8; em[3656] = 1; /* 3654: pointer.struct.asn1_string_st */
    	em[3657] = 3495; em[3658] = 0; 
    em[3659] = 0; em[3660] = 32; em[3661] = 2; /* 3659: struct.crypto_ex_data_st_fake */
    	em[3662] = 3666; em[3663] = 8; 
    	em[3664] = 94; em[3665] = 24; 
    em[3666] = 8884099; em[3667] = 8; em[3668] = 2; /* 3666: pointer_to_array_of_pointers_to_stack */
    	em[3669] = 91; em[3670] = 0; 
    	em[3671] = 52; em[3672] = 20; 
    em[3673] = 1; em[3674] = 8; em[3675] = 1; /* 3673: pointer.struct.X509_POLICY_CACHE_st */
    	em[3676] = 3282; em[3677] = 0; 
    em[3678] = 1; em[3679] = 8; em[3680] = 1; /* 3678: pointer.struct.x509_st */
    	em[3681] = 3518; em[3682] = 0; 
    args_addr->arg_entity_index[0] = 3678;
    args_addr->arg_entity_index[1] = 1845;
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

