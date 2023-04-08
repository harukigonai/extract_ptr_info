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

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d);

int EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_SignFinal called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    else {
        int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
        orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
        return orig_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    }
}

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
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
    em[939] = 0; em[940] = 8; em[941] = 6; /* 939: union.union_of_evp_pkey_st */
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
    em[1852] = 8884097; em[1853] = 8; em[1854] = 0; /* 1852: pointer.func */
    em[1855] = 1; em[1856] = 8; em[1857] = 1; /* 1855: pointer.struct.rsa_st */
    	em[1858] = 619; em[1859] = 0; 
    em[1860] = 8884097; em[1861] = 8; em[1862] = 0; /* 1860: pointer.func */
    em[1863] = 8884097; em[1864] = 8; em[1865] = 0; /* 1863: pointer.func */
    em[1866] = 8884097; em[1867] = 8; em[1868] = 0; /* 1866: pointer.func */
    em[1869] = 0; em[1870] = 208; em[1871] = 25; /* 1869: struct.evp_pkey_method_st */
    	em[1872] = 1866; em[1873] = 8; 
    	em[1874] = 1922; em[1875] = 16; 
    	em[1876] = 1925; em[1877] = 24; 
    	em[1878] = 1866; em[1879] = 32; 
    	em[1880] = 1928; em[1881] = 40; 
    	em[1882] = 1866; em[1883] = 48; 
    	em[1884] = 1928; em[1885] = 56; 
    	em[1886] = 1866; em[1887] = 64; 
    	em[1888] = 1931; em[1889] = 72; 
    	em[1890] = 1866; em[1891] = 80; 
    	em[1892] = 1934; em[1893] = 88; 
    	em[1894] = 1866; em[1895] = 96; 
    	em[1896] = 1931; em[1897] = 104; 
    	em[1898] = 1937; em[1899] = 112; 
    	em[1900] = 1863; em[1901] = 120; 
    	em[1902] = 1937; em[1903] = 128; 
    	em[1904] = 1860; em[1905] = 136; 
    	em[1906] = 1866; em[1907] = 144; 
    	em[1908] = 1931; em[1909] = 152; 
    	em[1910] = 1866; em[1911] = 160; 
    	em[1912] = 1931; em[1913] = 168; 
    	em[1914] = 1866; em[1915] = 176; 
    	em[1916] = 1940; em[1917] = 184; 
    	em[1918] = 1943; em[1919] = 192; 
    	em[1920] = 1946; em[1921] = 200; 
    em[1922] = 8884097; em[1923] = 8; em[1924] = 0; /* 1922: pointer.func */
    em[1925] = 8884097; em[1926] = 8; em[1927] = 0; /* 1925: pointer.func */
    em[1928] = 8884097; em[1929] = 8; em[1930] = 0; /* 1928: pointer.func */
    em[1931] = 8884097; em[1932] = 8; em[1933] = 0; /* 1931: pointer.func */
    em[1934] = 8884097; em[1935] = 8; em[1936] = 0; /* 1934: pointer.func */
    em[1937] = 8884097; em[1938] = 8; em[1939] = 0; /* 1937: pointer.func */
    em[1940] = 8884097; em[1941] = 8; em[1942] = 0; /* 1940: pointer.func */
    em[1943] = 8884097; em[1944] = 8; em[1945] = 0; /* 1943: pointer.func */
    em[1946] = 8884097; em[1947] = 8; em[1948] = 0; /* 1946: pointer.func */
    em[1949] = 1; em[1950] = 8; em[1951] = 1; /* 1949: pointer.struct.evp_pkey_ctx_st */
    	em[1952] = 1954; em[1953] = 0; 
    em[1954] = 0; em[1955] = 80; em[1956] = 8; /* 1954: struct.evp_pkey_ctx_st */
    	em[1957] = 1973; em[1958] = 0; 
    	em[1959] = 934; em[1960] = 8; 
    	em[1961] = 1978; em[1962] = 16; 
    	em[1963] = 1978; em[1964] = 24; 
    	em[1965] = 91; em[1966] = 40; 
    	em[1967] = 91; em[1968] = 48; 
    	em[1969] = 2043; em[1970] = 56; 
    	em[1971] = 2046; em[1972] = 64; 
    em[1973] = 1; em[1974] = 8; em[1975] = 1; /* 1973: pointer.struct.evp_pkey_method_st */
    	em[1976] = 1869; em[1977] = 0; 
    em[1978] = 1; em[1979] = 8; em[1980] = 1; /* 1978: pointer.struct.evp_pkey_st */
    	em[1981] = 1983; em[1982] = 0; 
    em[1983] = 0; em[1984] = 56; em[1985] = 4; /* 1983: struct.evp_pkey_st */
    	em[1986] = 833; em[1987] = 16; 
    	em[1988] = 934; em[1989] = 24; 
    	em[1990] = 1994; em[1991] = 32; 
    	em[1992] = 2019; em[1993] = 48; 
    em[1994] = 0; em[1995] = 8; em[1996] = 6; /* 1994: union.union_of_evp_pkey_st */
    	em[1997] = 91; em[1998] = 0; 
    	em[1999] = 1855; em[2000] = 6; 
    	em[2001] = 2009; em[2002] = 116; 
    	em[2003] = 2014; em[2004] = 28; 
    	em[2005] = 954; em[2006] = 408; 
    	em[2007] = 52; em[2008] = 0; 
    em[2009] = 1; em[2010] = 8; em[2011] = 1; /* 2009: pointer.struct.dsa_st */
    	em[2012] = 488; em[2013] = 0; 
    em[2014] = 1; em[2015] = 8; em[2016] = 1; /* 2014: pointer.struct.dh_st */
    	em[2017] = 5; em[2018] = 0; 
    em[2019] = 1; em[2020] = 8; em[2021] = 1; /* 2019: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[2022] = 2024; em[2023] = 0; 
    em[2024] = 0; em[2025] = 32; em[2026] = 2; /* 2024: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[2027] = 2031; em[2028] = 8; 
    	em[2029] = 94; em[2030] = 24; 
    em[2031] = 8884099; em[2032] = 8; em[2033] = 2; /* 2031: pointer_to_array_of_pointers_to_stack */
    	em[2034] = 2038; em[2035] = 0; 
    	em[2036] = 52; em[2037] = 20; 
    em[2038] = 0; em[2039] = 8; em[2040] = 1; /* 2038: pointer.X509_ATTRIBUTE */
    	em[2041] = 1487; em[2042] = 0; 
    em[2043] = 8884097; em[2044] = 8; em[2045] = 0; /* 2043: pointer.func */
    em[2046] = 1; em[2047] = 8; em[2048] = 1; /* 2046: pointer.int */
    	em[2049] = 52; em[2050] = 0; 
    em[2051] = 8884097; em[2052] = 8; em[2053] = 0; /* 2051: pointer.func */
    em[2054] = 0; em[2055] = 1; em[2056] = 0; /* 2054: char */
    em[2057] = 8884097; em[2058] = 8; em[2059] = 0; /* 2057: pointer.func */
    em[2060] = 8884097; em[2061] = 8; em[2062] = 0; /* 2060: pointer.func */
    em[2063] = 8884097; em[2064] = 8; em[2065] = 0; /* 2063: pointer.func */
    em[2066] = 1; em[2067] = 8; em[2068] = 1; /* 2066: pointer.struct.env_md_st */
    	em[2069] = 2071; em[2070] = 0; 
    em[2071] = 0; em[2072] = 120; em[2073] = 8; /* 2071: struct.env_md_st */
    	em[2074] = 2051; em[2075] = 24; 
    	em[2076] = 2063; em[2077] = 32; 
    	em[2078] = 2090; em[2079] = 40; 
    	em[2080] = 2093; em[2081] = 48; 
    	em[2082] = 2051; em[2083] = 56; 
    	em[2084] = 2060; em[2085] = 64; 
    	em[2086] = 1852; em[2087] = 72; 
    	em[2088] = 2057; em[2089] = 112; 
    em[2090] = 8884097; em[2091] = 8; em[2092] = 0; /* 2090: pointer.func */
    em[2093] = 8884097; em[2094] = 8; em[2095] = 0; /* 2093: pointer.func */
    em[2096] = 0; em[2097] = 48; em[2098] = 5; /* 2096: struct.env_md_ctx_st */
    	em[2099] = 2066; em[2100] = 0; 
    	em[2101] = 934; em[2102] = 8; 
    	em[2103] = 91; em[2104] = 24; 
    	em[2105] = 1949; em[2106] = 32; 
    	em[2107] = 2063; em[2108] = 40; 
    em[2109] = 1; em[2110] = 8; em[2111] = 1; /* 2109: pointer.unsigned int */
    	em[2112] = 2114; em[2113] = 0; 
    em[2114] = 0; em[2115] = 4; em[2116] = 0; /* 2114: unsigned int */
    em[2117] = 1; em[2118] = 8; em[2119] = 1; /* 2117: pointer.struct.env_md_ctx_st */
    	em[2120] = 2096; em[2121] = 0; 
    args_addr->arg_entity_index[0] = 2117;
    args_addr->arg_entity_index[1] = 69;
    args_addr->arg_entity_index[2] = 2109;
    args_addr->arg_entity_index[3] = 1847;
    args_addr->ret_entity_index = 52;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    unsigned char * new_arg_b = *((unsigned char * *)new_args->args[1]);

    unsigned int * new_arg_c = *((unsigned int * *)new_args->args[2]);

    EVP_PKEY * new_arg_d = *((EVP_PKEY * *)new_args->args[3]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
    orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
    *new_ret_ptr = (*orig_EVP_SignFinal)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    free(args_addr);

    return ret;
}

