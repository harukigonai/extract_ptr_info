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
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.dsa_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 136; em[7] = 11; /* 5: struct.dsa_st */
    	em[8] = 30; em[9] = 24; 
    	em[10] = 30; em[11] = 32; 
    	em[12] = 30; em[13] = 40; 
    	em[14] = 30; em[15] = 48; 
    	em[16] = 30; em[17] = 56; 
    	em[18] = 30; em[19] = 64; 
    	em[20] = 30; em[21] = 72; 
    	em[22] = 53; em[23] = 88; 
    	em[24] = 67; em[25] = 104; 
    	em[26] = 87; em[27] = 120; 
    	em[28] = 148; em[29] = 128; 
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.struct.bignum_st */
    	em[33] = 35; em[34] = 0; 
    em[35] = 0; em[36] = 24; em[37] = 1; /* 35: struct.bignum_st */
    	em[38] = 40; em[39] = 0; 
    em[40] = 8884099; em[41] = 8; em[42] = 2; /* 40: pointer_to_array_of_pointers_to_stack */
    	em[43] = 47; em[44] = 0; 
    	em[45] = 50; em[46] = 12; 
    em[47] = 0; em[48] = 8; em[49] = 0; /* 47: long unsigned int */
    em[50] = 0; em[51] = 4; em[52] = 0; /* 50: int */
    em[53] = 1; em[54] = 8; em[55] = 1; /* 53: pointer.struct.bn_mont_ctx_st */
    	em[56] = 58; em[57] = 0; 
    em[58] = 0; em[59] = 96; em[60] = 3; /* 58: struct.bn_mont_ctx_st */
    	em[61] = 35; em[62] = 8; 
    	em[63] = 35; em[64] = 32; 
    	em[65] = 35; em[66] = 56; 
    em[67] = 0; em[68] = 32; em[69] = 2; /* 67: struct.crypto_ex_data_st_fake */
    	em[70] = 74; em[71] = 8; 
    	em[72] = 84; em[73] = 24; 
    em[74] = 8884099; em[75] = 8; em[76] = 2; /* 74: pointer_to_array_of_pointers_to_stack */
    	em[77] = 81; em[78] = 0; 
    	em[79] = 50; em[80] = 20; 
    em[81] = 0; em[82] = 8; em[83] = 0; /* 81: pointer.void */
    em[84] = 8884097; em[85] = 8; em[86] = 0; /* 84: pointer.func */
    em[87] = 1; em[88] = 8; em[89] = 1; /* 87: pointer.struct.dsa_method */
    	em[90] = 92; em[91] = 0; 
    em[92] = 0; em[93] = 96; em[94] = 11; /* 92: struct.dsa_method */
    	em[95] = 117; em[96] = 0; 
    	em[97] = 122; em[98] = 8; 
    	em[99] = 125; em[100] = 16; 
    	em[101] = 128; em[102] = 24; 
    	em[103] = 131; em[104] = 32; 
    	em[105] = 134; em[106] = 40; 
    	em[107] = 137; em[108] = 48; 
    	em[109] = 137; em[110] = 56; 
    	em[111] = 140; em[112] = 72; 
    	em[113] = 145; em[114] = 80; 
    	em[115] = 137; em[116] = 88; 
    em[117] = 1; em[118] = 8; em[119] = 1; /* 117: pointer.char */
    	em[120] = 8884096; em[121] = 0; 
    em[122] = 8884097; em[123] = 8; em[124] = 0; /* 122: pointer.func */
    em[125] = 8884097; em[126] = 8; em[127] = 0; /* 125: pointer.func */
    em[128] = 8884097; em[129] = 8; em[130] = 0; /* 128: pointer.func */
    em[131] = 8884097; em[132] = 8; em[133] = 0; /* 131: pointer.func */
    em[134] = 8884097; em[135] = 8; em[136] = 0; /* 134: pointer.func */
    em[137] = 8884097; em[138] = 8; em[139] = 0; /* 137: pointer.func */
    em[140] = 1; em[141] = 8; em[142] = 1; /* 140: pointer.char */
    	em[143] = 8884096; em[144] = 0; 
    em[145] = 8884097; em[146] = 8; em[147] = 0; /* 145: pointer.func */
    em[148] = 1; em[149] = 8; em[150] = 1; /* 148: pointer.struct.engine_st */
    	em[151] = 153; em[152] = 0; 
    em[153] = 0; em[154] = 216; em[155] = 24; /* 153: struct.engine_st */
    	em[156] = 117; em[157] = 0; 
    	em[158] = 117; em[159] = 8; 
    	em[160] = 204; em[161] = 16; 
    	em[162] = 259; em[163] = 24; 
    	em[164] = 310; em[165] = 32; 
    	em[166] = 346; em[167] = 40; 
    	em[168] = 363; em[169] = 48; 
    	em[170] = 390; em[171] = 56; 
    	em[172] = 425; em[173] = 64; 
    	em[174] = 433; em[175] = 72; 
    	em[176] = 436; em[177] = 80; 
    	em[178] = 439; em[179] = 88; 
    	em[180] = 442; em[181] = 96; 
    	em[182] = 445; em[183] = 104; 
    	em[184] = 445; em[185] = 112; 
    	em[186] = 445; em[187] = 120; 
    	em[188] = 448; em[189] = 128; 
    	em[190] = 451; em[191] = 136; 
    	em[192] = 451; em[193] = 144; 
    	em[194] = 454; em[195] = 152; 
    	em[196] = 457; em[197] = 160; 
    	em[198] = 469; em[199] = 184; 
    	em[200] = 483; em[201] = 200; 
    	em[202] = 483; em[203] = 208; 
    em[204] = 1; em[205] = 8; em[206] = 1; /* 204: pointer.struct.rsa_meth_st */
    	em[207] = 209; em[208] = 0; 
    em[209] = 0; em[210] = 112; em[211] = 13; /* 209: struct.rsa_meth_st */
    	em[212] = 117; em[213] = 0; 
    	em[214] = 238; em[215] = 8; 
    	em[216] = 238; em[217] = 16; 
    	em[218] = 238; em[219] = 24; 
    	em[220] = 238; em[221] = 32; 
    	em[222] = 241; em[223] = 40; 
    	em[224] = 244; em[225] = 48; 
    	em[226] = 247; em[227] = 56; 
    	em[228] = 247; em[229] = 64; 
    	em[230] = 140; em[231] = 80; 
    	em[232] = 250; em[233] = 88; 
    	em[234] = 253; em[235] = 96; 
    	em[236] = 256; em[237] = 104; 
    em[238] = 8884097; em[239] = 8; em[240] = 0; /* 238: pointer.func */
    em[241] = 8884097; em[242] = 8; em[243] = 0; /* 241: pointer.func */
    em[244] = 8884097; em[245] = 8; em[246] = 0; /* 244: pointer.func */
    em[247] = 8884097; em[248] = 8; em[249] = 0; /* 247: pointer.func */
    em[250] = 8884097; em[251] = 8; em[252] = 0; /* 250: pointer.func */
    em[253] = 8884097; em[254] = 8; em[255] = 0; /* 253: pointer.func */
    em[256] = 8884097; em[257] = 8; em[258] = 0; /* 256: pointer.func */
    em[259] = 1; em[260] = 8; em[261] = 1; /* 259: pointer.struct.dsa_method */
    	em[262] = 264; em[263] = 0; 
    em[264] = 0; em[265] = 96; em[266] = 11; /* 264: struct.dsa_method */
    	em[267] = 117; em[268] = 0; 
    	em[269] = 289; em[270] = 8; 
    	em[271] = 292; em[272] = 16; 
    	em[273] = 295; em[274] = 24; 
    	em[275] = 298; em[276] = 32; 
    	em[277] = 301; em[278] = 40; 
    	em[279] = 304; em[280] = 48; 
    	em[281] = 304; em[282] = 56; 
    	em[283] = 140; em[284] = 72; 
    	em[285] = 307; em[286] = 80; 
    	em[287] = 304; em[288] = 88; 
    em[289] = 8884097; em[290] = 8; em[291] = 0; /* 289: pointer.func */
    em[292] = 8884097; em[293] = 8; em[294] = 0; /* 292: pointer.func */
    em[295] = 8884097; em[296] = 8; em[297] = 0; /* 295: pointer.func */
    em[298] = 8884097; em[299] = 8; em[300] = 0; /* 298: pointer.func */
    em[301] = 8884097; em[302] = 8; em[303] = 0; /* 301: pointer.func */
    em[304] = 8884097; em[305] = 8; em[306] = 0; /* 304: pointer.func */
    em[307] = 8884097; em[308] = 8; em[309] = 0; /* 307: pointer.func */
    em[310] = 1; em[311] = 8; em[312] = 1; /* 310: pointer.struct.dh_method */
    	em[313] = 315; em[314] = 0; 
    em[315] = 0; em[316] = 72; em[317] = 8; /* 315: struct.dh_method */
    	em[318] = 117; em[319] = 0; 
    	em[320] = 334; em[321] = 8; 
    	em[322] = 337; em[323] = 16; 
    	em[324] = 340; em[325] = 24; 
    	em[326] = 334; em[327] = 32; 
    	em[328] = 334; em[329] = 40; 
    	em[330] = 140; em[331] = 56; 
    	em[332] = 343; em[333] = 64; 
    em[334] = 8884097; em[335] = 8; em[336] = 0; /* 334: pointer.func */
    em[337] = 8884097; em[338] = 8; em[339] = 0; /* 337: pointer.func */
    em[340] = 8884097; em[341] = 8; em[342] = 0; /* 340: pointer.func */
    em[343] = 8884097; em[344] = 8; em[345] = 0; /* 343: pointer.func */
    em[346] = 1; em[347] = 8; em[348] = 1; /* 346: pointer.struct.ecdh_method */
    	em[349] = 351; em[350] = 0; 
    em[351] = 0; em[352] = 32; em[353] = 3; /* 351: struct.ecdh_method */
    	em[354] = 117; em[355] = 0; 
    	em[356] = 360; em[357] = 8; 
    	em[358] = 140; em[359] = 24; 
    em[360] = 8884097; em[361] = 8; em[362] = 0; /* 360: pointer.func */
    em[363] = 1; em[364] = 8; em[365] = 1; /* 363: pointer.struct.ecdsa_method */
    	em[366] = 368; em[367] = 0; 
    em[368] = 0; em[369] = 48; em[370] = 5; /* 368: struct.ecdsa_method */
    	em[371] = 117; em[372] = 0; 
    	em[373] = 381; em[374] = 8; 
    	em[375] = 384; em[376] = 16; 
    	em[377] = 387; em[378] = 24; 
    	em[379] = 140; em[380] = 40; 
    em[381] = 8884097; em[382] = 8; em[383] = 0; /* 381: pointer.func */
    em[384] = 8884097; em[385] = 8; em[386] = 0; /* 384: pointer.func */
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 1; em[391] = 8; em[392] = 1; /* 390: pointer.struct.rand_meth_st */
    	em[393] = 395; em[394] = 0; 
    em[395] = 0; em[396] = 48; em[397] = 6; /* 395: struct.rand_meth_st */
    	em[398] = 410; em[399] = 0; 
    	em[400] = 413; em[401] = 8; 
    	em[402] = 416; em[403] = 16; 
    	em[404] = 419; em[405] = 24; 
    	em[406] = 413; em[407] = 32; 
    	em[408] = 422; em[409] = 40; 
    em[410] = 8884097; em[411] = 8; em[412] = 0; /* 410: pointer.func */
    em[413] = 8884097; em[414] = 8; em[415] = 0; /* 413: pointer.func */
    em[416] = 8884097; em[417] = 8; em[418] = 0; /* 416: pointer.func */
    em[419] = 8884097; em[420] = 8; em[421] = 0; /* 419: pointer.func */
    em[422] = 8884097; em[423] = 8; em[424] = 0; /* 422: pointer.func */
    em[425] = 1; em[426] = 8; em[427] = 1; /* 425: pointer.struct.store_method_st */
    	em[428] = 430; em[429] = 0; 
    em[430] = 0; em[431] = 0; em[432] = 0; /* 430: struct.store_method_st */
    em[433] = 8884097; em[434] = 8; em[435] = 0; /* 433: pointer.func */
    em[436] = 8884097; em[437] = 8; em[438] = 0; /* 436: pointer.func */
    em[439] = 8884097; em[440] = 8; em[441] = 0; /* 439: pointer.func */
    em[442] = 8884097; em[443] = 8; em[444] = 0; /* 442: pointer.func */
    em[445] = 8884097; em[446] = 8; em[447] = 0; /* 445: pointer.func */
    em[448] = 8884097; em[449] = 8; em[450] = 0; /* 448: pointer.func */
    em[451] = 8884097; em[452] = 8; em[453] = 0; /* 451: pointer.func */
    em[454] = 8884097; em[455] = 8; em[456] = 0; /* 454: pointer.func */
    em[457] = 1; em[458] = 8; em[459] = 1; /* 457: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[460] = 462; em[461] = 0; 
    em[462] = 0; em[463] = 32; em[464] = 2; /* 462: struct.ENGINE_CMD_DEFN_st */
    	em[465] = 117; em[466] = 8; 
    	em[467] = 117; em[468] = 16; 
    em[469] = 0; em[470] = 32; em[471] = 2; /* 469: struct.crypto_ex_data_st_fake */
    	em[472] = 476; em[473] = 8; 
    	em[474] = 84; em[475] = 24; 
    em[476] = 8884099; em[477] = 8; em[478] = 2; /* 476: pointer_to_array_of_pointers_to_stack */
    	em[479] = 81; em[480] = 0; 
    	em[481] = 50; em[482] = 20; 
    em[483] = 1; em[484] = 8; em[485] = 1; /* 483: pointer.struct.engine_st */
    	em[486] = 153; em[487] = 0; 
    em[488] = 1; em[489] = 8; em[490] = 1; /* 488: pointer.struct.rsa_st */
    	em[491] = 493; em[492] = 0; 
    em[493] = 0; em[494] = 168; em[495] = 17; /* 493: struct.rsa_st */
    	em[496] = 530; em[497] = 16; 
    	em[498] = 585; em[499] = 24; 
    	em[500] = 590; em[501] = 32; 
    	em[502] = 590; em[503] = 40; 
    	em[504] = 590; em[505] = 48; 
    	em[506] = 590; em[507] = 56; 
    	em[508] = 590; em[509] = 64; 
    	em[510] = 590; em[511] = 72; 
    	em[512] = 590; em[513] = 80; 
    	em[514] = 590; em[515] = 88; 
    	em[516] = 607; em[517] = 96; 
    	em[518] = 621; em[519] = 120; 
    	em[520] = 621; em[521] = 128; 
    	em[522] = 621; em[523] = 136; 
    	em[524] = 140; em[525] = 144; 
    	em[526] = 635; em[527] = 152; 
    	em[528] = 635; em[529] = 160; 
    em[530] = 1; em[531] = 8; em[532] = 1; /* 530: pointer.struct.rsa_meth_st */
    	em[533] = 535; em[534] = 0; 
    em[535] = 0; em[536] = 112; em[537] = 13; /* 535: struct.rsa_meth_st */
    	em[538] = 117; em[539] = 0; 
    	em[540] = 564; em[541] = 8; 
    	em[542] = 564; em[543] = 16; 
    	em[544] = 564; em[545] = 24; 
    	em[546] = 564; em[547] = 32; 
    	em[548] = 567; em[549] = 40; 
    	em[550] = 570; em[551] = 48; 
    	em[552] = 573; em[553] = 56; 
    	em[554] = 573; em[555] = 64; 
    	em[556] = 140; em[557] = 80; 
    	em[558] = 576; em[559] = 88; 
    	em[560] = 579; em[561] = 96; 
    	em[562] = 582; em[563] = 104; 
    em[564] = 8884097; em[565] = 8; em[566] = 0; /* 564: pointer.func */
    em[567] = 8884097; em[568] = 8; em[569] = 0; /* 567: pointer.func */
    em[570] = 8884097; em[571] = 8; em[572] = 0; /* 570: pointer.func */
    em[573] = 8884097; em[574] = 8; em[575] = 0; /* 573: pointer.func */
    em[576] = 8884097; em[577] = 8; em[578] = 0; /* 576: pointer.func */
    em[579] = 8884097; em[580] = 8; em[581] = 0; /* 579: pointer.func */
    em[582] = 8884097; em[583] = 8; em[584] = 0; /* 582: pointer.func */
    em[585] = 1; em[586] = 8; em[587] = 1; /* 585: pointer.struct.engine_st */
    	em[588] = 153; em[589] = 0; 
    em[590] = 1; em[591] = 8; em[592] = 1; /* 590: pointer.struct.bignum_st */
    	em[593] = 595; em[594] = 0; 
    em[595] = 0; em[596] = 24; em[597] = 1; /* 595: struct.bignum_st */
    	em[598] = 600; em[599] = 0; 
    em[600] = 8884099; em[601] = 8; em[602] = 2; /* 600: pointer_to_array_of_pointers_to_stack */
    	em[603] = 47; em[604] = 0; 
    	em[605] = 50; em[606] = 12; 
    em[607] = 0; em[608] = 32; em[609] = 2; /* 607: struct.crypto_ex_data_st_fake */
    	em[610] = 614; em[611] = 8; 
    	em[612] = 84; em[613] = 24; 
    em[614] = 8884099; em[615] = 8; em[616] = 2; /* 614: pointer_to_array_of_pointers_to_stack */
    	em[617] = 81; em[618] = 0; 
    	em[619] = 50; em[620] = 20; 
    em[621] = 1; em[622] = 8; em[623] = 1; /* 621: pointer.struct.bn_mont_ctx_st */
    	em[624] = 626; em[625] = 0; 
    em[626] = 0; em[627] = 96; em[628] = 3; /* 626: struct.bn_mont_ctx_st */
    	em[629] = 595; em[630] = 8; 
    	em[631] = 595; em[632] = 32; 
    	em[633] = 595; em[634] = 56; 
    em[635] = 1; em[636] = 8; em[637] = 1; /* 635: pointer.struct.bn_blinding_st */
    	em[638] = 640; em[639] = 0; 
    em[640] = 0; em[641] = 88; em[642] = 7; /* 640: struct.bn_blinding_st */
    	em[643] = 657; em[644] = 0; 
    	em[645] = 657; em[646] = 8; 
    	em[647] = 657; em[648] = 16; 
    	em[649] = 657; em[650] = 24; 
    	em[651] = 674; em[652] = 40; 
    	em[653] = 679; em[654] = 72; 
    	em[655] = 693; em[656] = 80; 
    em[657] = 1; em[658] = 8; em[659] = 1; /* 657: pointer.struct.bignum_st */
    	em[660] = 662; em[661] = 0; 
    em[662] = 0; em[663] = 24; em[664] = 1; /* 662: struct.bignum_st */
    	em[665] = 667; em[666] = 0; 
    em[667] = 8884099; em[668] = 8; em[669] = 2; /* 667: pointer_to_array_of_pointers_to_stack */
    	em[670] = 47; em[671] = 0; 
    	em[672] = 50; em[673] = 12; 
    em[674] = 0; em[675] = 16; em[676] = 1; /* 674: struct.crypto_threadid_st */
    	em[677] = 81; em[678] = 0; 
    em[679] = 1; em[680] = 8; em[681] = 1; /* 679: pointer.struct.bn_mont_ctx_st */
    	em[682] = 684; em[683] = 0; 
    em[684] = 0; em[685] = 96; em[686] = 3; /* 684: struct.bn_mont_ctx_st */
    	em[687] = 662; em[688] = 8; 
    	em[689] = 662; em[690] = 32; 
    	em[691] = 662; em[692] = 56; 
    em[693] = 8884097; em[694] = 8; em[695] = 0; /* 693: pointer.func */
    em[696] = 8884097; em[697] = 8; em[698] = 0; /* 696: pointer.func */
    em[699] = 1; em[700] = 8; em[701] = 1; /* 699: pointer.struct.ASN1_VALUE_st */
    	em[702] = 704; em[703] = 0; 
    em[704] = 0; em[705] = 0; em[706] = 0; /* 704: struct.ASN1_VALUE_st */
    em[707] = 1; em[708] = 8; em[709] = 1; /* 707: pointer.struct.asn1_string_st */
    	em[710] = 712; em[711] = 0; 
    em[712] = 0; em[713] = 24; em[714] = 1; /* 712: struct.asn1_string_st */
    	em[715] = 717; em[716] = 8; 
    em[717] = 1; em[718] = 8; em[719] = 1; /* 717: pointer.unsigned char */
    	em[720] = 722; em[721] = 0; 
    em[722] = 0; em[723] = 1; em[724] = 0; /* 722: unsigned char */
    em[725] = 1; em[726] = 8; em[727] = 1; /* 725: pointer.struct.asn1_string_st */
    	em[728] = 712; em[729] = 0; 
    em[730] = 1; em[731] = 8; em[732] = 1; /* 730: pointer.struct.asn1_string_st */
    	em[733] = 712; em[734] = 0; 
    em[735] = 1; em[736] = 8; em[737] = 1; /* 735: pointer.struct.asn1_string_st */
    	em[738] = 712; em[739] = 0; 
    em[740] = 1; em[741] = 8; em[742] = 1; /* 740: pointer.struct.asn1_string_st */
    	em[743] = 712; em[744] = 0; 
    em[745] = 1; em[746] = 8; em[747] = 1; /* 745: pointer.struct.asn1_string_st */
    	em[748] = 712; em[749] = 0; 
    em[750] = 1; em[751] = 8; em[752] = 1; /* 750: pointer.struct.asn1_string_st */
    	em[753] = 712; em[754] = 0; 
    em[755] = 1; em[756] = 8; em[757] = 1; /* 755: pointer.struct.asn1_string_st */
    	em[758] = 712; em[759] = 0; 
    em[760] = 1; em[761] = 8; em[762] = 1; /* 760: pointer.struct.asn1_string_st */
    	em[763] = 712; em[764] = 0; 
    em[765] = 1; em[766] = 8; em[767] = 1; /* 765: pointer.struct.asn1_string_st */
    	em[768] = 712; em[769] = 0; 
    em[770] = 0; em[771] = 16; em[772] = 1; /* 770: struct.asn1_type_st */
    	em[773] = 775; em[774] = 8; 
    em[775] = 0; em[776] = 8; em[777] = 20; /* 775: union.unknown */
    	em[778] = 140; em[779] = 0; 
    	em[780] = 765; em[781] = 0; 
    	em[782] = 818; em[783] = 0; 
    	em[784] = 837; em[785] = 0; 
    	em[786] = 760; em[787] = 0; 
    	em[788] = 842; em[789] = 0; 
    	em[790] = 755; em[791] = 0; 
    	em[792] = 847; em[793] = 0; 
    	em[794] = 750; em[795] = 0; 
    	em[796] = 745; em[797] = 0; 
    	em[798] = 740; em[799] = 0; 
    	em[800] = 735; em[801] = 0; 
    	em[802] = 852; em[803] = 0; 
    	em[804] = 730; em[805] = 0; 
    	em[806] = 725; em[807] = 0; 
    	em[808] = 857; em[809] = 0; 
    	em[810] = 707; em[811] = 0; 
    	em[812] = 765; em[813] = 0; 
    	em[814] = 765; em[815] = 0; 
    	em[816] = 699; em[817] = 0; 
    em[818] = 1; em[819] = 8; em[820] = 1; /* 818: pointer.struct.asn1_object_st */
    	em[821] = 823; em[822] = 0; 
    em[823] = 0; em[824] = 40; em[825] = 3; /* 823: struct.asn1_object_st */
    	em[826] = 117; em[827] = 0; 
    	em[828] = 117; em[829] = 8; 
    	em[830] = 832; em[831] = 24; 
    em[832] = 1; em[833] = 8; em[834] = 1; /* 832: pointer.unsigned char */
    	em[835] = 722; em[836] = 0; 
    em[837] = 1; em[838] = 8; em[839] = 1; /* 837: pointer.struct.asn1_string_st */
    	em[840] = 712; em[841] = 0; 
    em[842] = 1; em[843] = 8; em[844] = 1; /* 842: pointer.struct.asn1_string_st */
    	em[845] = 712; em[846] = 0; 
    em[847] = 1; em[848] = 8; em[849] = 1; /* 847: pointer.struct.asn1_string_st */
    	em[850] = 712; em[851] = 0; 
    em[852] = 1; em[853] = 8; em[854] = 1; /* 852: pointer.struct.asn1_string_st */
    	em[855] = 712; em[856] = 0; 
    em[857] = 1; em[858] = 8; em[859] = 1; /* 857: pointer.struct.asn1_string_st */
    	em[860] = 712; em[861] = 0; 
    em[862] = 0; em[863] = 0; em[864] = 0; /* 862: struct.ASN1_VALUE_st */
    em[865] = 1; em[866] = 8; em[867] = 1; /* 865: pointer.struct.ASN1_VALUE_st */
    	em[868] = 862; em[869] = 0; 
    em[870] = 1; em[871] = 8; em[872] = 1; /* 870: pointer.struct.asn1_string_st */
    	em[873] = 875; em[874] = 0; 
    em[875] = 0; em[876] = 24; em[877] = 1; /* 875: struct.asn1_string_st */
    	em[878] = 717; em[879] = 8; 
    em[880] = 1; em[881] = 8; em[882] = 1; /* 880: pointer.struct.asn1_string_st */
    	em[883] = 875; em[884] = 0; 
    em[885] = 1; em[886] = 8; em[887] = 1; /* 885: pointer.struct.asn1_string_st */
    	em[888] = 875; em[889] = 0; 
    em[890] = 1; em[891] = 8; em[892] = 1; /* 890: pointer.struct.asn1_string_st */
    	em[893] = 875; em[894] = 0; 
    em[895] = 1; em[896] = 8; em[897] = 1; /* 895: pointer.struct.asn1_string_st */
    	em[898] = 875; em[899] = 0; 
    em[900] = 1; em[901] = 8; em[902] = 1; /* 900: pointer.struct.asn1_string_st */
    	em[903] = 875; em[904] = 0; 
    em[905] = 1; em[906] = 8; em[907] = 1; /* 905: pointer.struct.asn1_string_st */
    	em[908] = 875; em[909] = 0; 
    em[910] = 1; em[911] = 8; em[912] = 1; /* 910: pointer.struct.asn1_string_st */
    	em[913] = 875; em[914] = 0; 
    em[915] = 0; em[916] = 40; em[917] = 3; /* 915: struct.asn1_object_st */
    	em[918] = 117; em[919] = 0; 
    	em[920] = 117; em[921] = 8; 
    	em[922] = 832; em[923] = 24; 
    em[924] = 1; em[925] = 8; em[926] = 1; /* 924: pointer.struct.asn1_string_st */
    	em[927] = 875; em[928] = 0; 
    em[929] = 0; em[930] = 0; em[931] = 1; /* 929: ASN1_TYPE */
    	em[932] = 934; em[933] = 0; 
    em[934] = 0; em[935] = 16; em[936] = 1; /* 934: struct.asn1_type_st */
    	em[937] = 939; em[938] = 8; 
    em[939] = 0; em[940] = 8; em[941] = 20; /* 939: union.unknown */
    	em[942] = 140; em[943] = 0; 
    	em[944] = 924; em[945] = 0; 
    	em[946] = 982; em[947] = 0; 
    	em[948] = 910; em[949] = 0; 
    	em[950] = 905; em[951] = 0; 
    	em[952] = 900; em[953] = 0; 
    	em[954] = 895; em[955] = 0; 
    	em[956] = 987; em[957] = 0; 
    	em[958] = 992; em[959] = 0; 
    	em[960] = 890; em[961] = 0; 
    	em[962] = 885; em[963] = 0; 
    	em[964] = 997; em[965] = 0; 
    	em[966] = 1002; em[967] = 0; 
    	em[968] = 1007; em[969] = 0; 
    	em[970] = 880; em[971] = 0; 
    	em[972] = 1012; em[973] = 0; 
    	em[974] = 870; em[975] = 0; 
    	em[976] = 924; em[977] = 0; 
    	em[978] = 924; em[979] = 0; 
    	em[980] = 865; em[981] = 0; 
    em[982] = 1; em[983] = 8; em[984] = 1; /* 982: pointer.struct.asn1_object_st */
    	em[985] = 915; em[986] = 0; 
    em[987] = 1; em[988] = 8; em[989] = 1; /* 987: pointer.struct.asn1_string_st */
    	em[990] = 875; em[991] = 0; 
    em[992] = 1; em[993] = 8; em[994] = 1; /* 992: pointer.struct.asn1_string_st */
    	em[995] = 875; em[996] = 0; 
    em[997] = 1; em[998] = 8; em[999] = 1; /* 997: pointer.struct.asn1_string_st */
    	em[1000] = 875; em[1001] = 0; 
    em[1002] = 1; em[1003] = 8; em[1004] = 1; /* 1002: pointer.struct.asn1_string_st */
    	em[1005] = 875; em[1006] = 0; 
    em[1007] = 1; em[1008] = 8; em[1009] = 1; /* 1007: pointer.struct.asn1_string_st */
    	em[1010] = 875; em[1011] = 0; 
    em[1012] = 1; em[1013] = 8; em[1014] = 1; /* 1012: pointer.struct.asn1_string_st */
    	em[1015] = 875; em[1016] = 0; 
    em[1017] = 1; em[1018] = 8; em[1019] = 1; /* 1017: pointer.struct.stack_st_ASN1_TYPE */
    	em[1020] = 1022; em[1021] = 0; 
    em[1022] = 0; em[1023] = 32; em[1024] = 2; /* 1022: struct.stack_st_fake_ASN1_TYPE */
    	em[1025] = 1029; em[1026] = 8; 
    	em[1027] = 84; em[1028] = 24; 
    em[1029] = 8884099; em[1030] = 8; em[1031] = 2; /* 1029: pointer_to_array_of_pointers_to_stack */
    	em[1032] = 1036; em[1033] = 0; 
    	em[1034] = 50; em[1035] = 20; 
    em[1036] = 0; em[1037] = 8; em[1038] = 1; /* 1036: pointer.ASN1_TYPE */
    	em[1039] = 929; em[1040] = 0; 
    em[1041] = 0; em[1042] = 8; em[1043] = 3; /* 1041: union.unknown */
    	em[1044] = 140; em[1045] = 0; 
    	em[1046] = 1017; em[1047] = 0; 
    	em[1048] = 1050; em[1049] = 0; 
    em[1050] = 1; em[1051] = 8; em[1052] = 1; /* 1050: pointer.struct.asn1_type_st */
    	em[1053] = 770; em[1054] = 0; 
    em[1055] = 8884097; em[1056] = 8; em[1057] = 0; /* 1055: pointer.func */
    em[1058] = 0; em[1059] = 208; em[1060] = 24; /* 1058: struct.evp_pkey_asn1_method_st */
    	em[1061] = 140; em[1062] = 16; 
    	em[1063] = 140; em[1064] = 24; 
    	em[1065] = 1109; em[1066] = 32; 
    	em[1067] = 1112; em[1068] = 40; 
    	em[1069] = 1115; em[1070] = 48; 
    	em[1071] = 1118; em[1072] = 56; 
    	em[1073] = 1121; em[1074] = 64; 
    	em[1075] = 1124; em[1076] = 72; 
    	em[1077] = 1118; em[1078] = 80; 
    	em[1079] = 1127; em[1080] = 88; 
    	em[1081] = 1127; em[1082] = 96; 
    	em[1083] = 1130; em[1084] = 104; 
    	em[1085] = 1133; em[1086] = 112; 
    	em[1087] = 1127; em[1088] = 120; 
    	em[1089] = 1055; em[1090] = 128; 
    	em[1091] = 1115; em[1092] = 136; 
    	em[1093] = 1118; em[1094] = 144; 
    	em[1095] = 1136; em[1096] = 152; 
    	em[1097] = 1139; em[1098] = 160; 
    	em[1099] = 1142; em[1100] = 168; 
    	em[1101] = 1130; em[1102] = 176; 
    	em[1103] = 1133; em[1104] = 184; 
    	em[1105] = 1145; em[1106] = 192; 
    	em[1107] = 1148; em[1108] = 200; 
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
    em[1157] = 1; em[1158] = 8; em[1159] = 1; /* 1157: pointer.struct.bn_mont_ctx_st */
    	em[1160] = 1162; em[1161] = 0; 
    em[1162] = 0; em[1163] = 96; em[1164] = 3; /* 1162: struct.bn_mont_ctx_st */
    	em[1165] = 1171; em[1166] = 8; 
    	em[1167] = 1171; em[1168] = 32; 
    	em[1169] = 1171; em[1170] = 56; 
    em[1171] = 0; em[1172] = 24; em[1173] = 1; /* 1171: struct.bignum_st */
    	em[1174] = 1176; em[1175] = 0; 
    em[1176] = 8884099; em[1177] = 8; em[1178] = 2; /* 1176: pointer_to_array_of_pointers_to_stack */
    	em[1179] = 47; em[1180] = 0; 
    	em[1181] = 50; em[1182] = 12; 
    em[1183] = 8884097; em[1184] = 8; em[1185] = 0; /* 1183: pointer.func */
    em[1186] = 1; em[1187] = 8; em[1188] = 1; /* 1186: pointer.struct.dh_method */
    	em[1189] = 1191; em[1190] = 0; 
    em[1191] = 0; em[1192] = 72; em[1193] = 8; /* 1191: struct.dh_method */
    	em[1194] = 117; em[1195] = 0; 
    	em[1196] = 1210; em[1197] = 8; 
    	em[1198] = 1213; em[1199] = 16; 
    	em[1200] = 1216; em[1201] = 24; 
    	em[1202] = 1210; em[1203] = 32; 
    	em[1204] = 1210; em[1205] = 40; 
    	em[1206] = 140; em[1207] = 56; 
    	em[1208] = 1219; em[1209] = 64; 
    em[1210] = 8884097; em[1211] = 8; em[1212] = 0; /* 1210: pointer.func */
    em[1213] = 8884097; em[1214] = 8; em[1215] = 0; /* 1213: pointer.func */
    em[1216] = 8884097; em[1217] = 8; em[1218] = 0; /* 1216: pointer.func */
    em[1219] = 8884097; em[1220] = 8; em[1221] = 0; /* 1219: pointer.func */
    em[1222] = 1; em[1223] = 8; em[1224] = 1; /* 1222: pointer.struct.evp_pkey_asn1_method_st */
    	em[1225] = 1058; em[1226] = 0; 
    em[1227] = 0; em[1228] = 56; em[1229] = 4; /* 1227: struct.evp_pkey_st */
    	em[1230] = 1222; em[1231] = 16; 
    	em[1232] = 1238; em[1233] = 24; 
    	em[1234] = 1243; em[1235] = 32; 
    	em[1236] = 1822; em[1237] = 48; 
    em[1238] = 1; em[1239] = 8; em[1240] = 1; /* 1238: pointer.struct.engine_st */
    	em[1241] = 153; em[1242] = 0; 
    em[1243] = 8884101; em[1244] = 8; em[1245] = 6; /* 1243: union.union_of_evp_pkey_st */
    	em[1246] = 81; em[1247] = 0; 
    	em[1248] = 1258; em[1249] = 6; 
    	em[1250] = 1263; em[1251] = 116; 
    	em[1252] = 1268; em[1253] = 28; 
    	em[1254] = 1319; em[1255] = 408; 
    	em[1256] = 50; em[1257] = 0; 
    em[1258] = 1; em[1259] = 8; em[1260] = 1; /* 1258: pointer.struct.rsa_st */
    	em[1261] = 493; em[1262] = 0; 
    em[1263] = 1; em[1264] = 8; em[1265] = 1; /* 1263: pointer.struct.dsa_st */
    	em[1266] = 5; em[1267] = 0; 
    em[1268] = 1; em[1269] = 8; em[1270] = 1; /* 1268: pointer.struct.dh_st */
    	em[1271] = 1273; em[1272] = 0; 
    em[1273] = 0; em[1274] = 144; em[1275] = 12; /* 1273: struct.dh_st */
    	em[1276] = 1300; em[1277] = 8; 
    	em[1278] = 1300; em[1279] = 16; 
    	em[1280] = 1300; em[1281] = 32; 
    	em[1282] = 1300; em[1283] = 40; 
    	em[1284] = 1157; em[1285] = 56; 
    	em[1286] = 1300; em[1287] = 64; 
    	em[1288] = 1300; em[1289] = 72; 
    	em[1290] = 717; em[1291] = 80; 
    	em[1292] = 1300; em[1293] = 96; 
    	em[1294] = 1305; em[1295] = 112; 
    	em[1296] = 1186; em[1297] = 128; 
    	em[1298] = 1238; em[1299] = 136; 
    em[1300] = 1; em[1301] = 8; em[1302] = 1; /* 1300: pointer.struct.bignum_st */
    	em[1303] = 1171; em[1304] = 0; 
    em[1305] = 0; em[1306] = 32; em[1307] = 2; /* 1305: struct.crypto_ex_data_st_fake */
    	em[1308] = 1312; em[1309] = 8; 
    	em[1310] = 84; em[1311] = 24; 
    em[1312] = 8884099; em[1313] = 8; em[1314] = 2; /* 1312: pointer_to_array_of_pointers_to_stack */
    	em[1315] = 81; em[1316] = 0; 
    	em[1317] = 50; em[1318] = 20; 
    em[1319] = 1; em[1320] = 8; em[1321] = 1; /* 1319: pointer.struct.ec_key_st */
    	em[1322] = 1324; em[1323] = 0; 
    em[1324] = 0; em[1325] = 56; em[1326] = 4; /* 1324: struct.ec_key_st */
    	em[1327] = 1335; em[1328] = 8; 
    	em[1329] = 1777; em[1330] = 16; 
    	em[1331] = 1782; em[1332] = 24; 
    	em[1333] = 1799; em[1334] = 48; 
    em[1335] = 1; em[1336] = 8; em[1337] = 1; /* 1335: pointer.struct.ec_group_st */
    	em[1338] = 1340; em[1339] = 0; 
    em[1340] = 0; em[1341] = 232; em[1342] = 12; /* 1340: struct.ec_group_st */
    	em[1343] = 1367; em[1344] = 0; 
    	em[1345] = 1536; em[1346] = 8; 
    	em[1347] = 1733; em[1348] = 16; 
    	em[1349] = 1733; em[1350] = 40; 
    	em[1351] = 717; em[1352] = 80; 
    	em[1353] = 1745; em[1354] = 96; 
    	em[1355] = 1733; em[1356] = 104; 
    	em[1357] = 1733; em[1358] = 152; 
    	em[1359] = 1733; em[1360] = 176; 
    	em[1361] = 81; em[1362] = 208; 
    	em[1363] = 81; em[1364] = 216; 
    	em[1365] = 1774; em[1366] = 224; 
    em[1367] = 1; em[1368] = 8; em[1369] = 1; /* 1367: pointer.struct.ec_method_st */
    	em[1370] = 1372; em[1371] = 0; 
    em[1372] = 0; em[1373] = 304; em[1374] = 37; /* 1372: struct.ec_method_st */
    	em[1375] = 1449; em[1376] = 8; 
    	em[1377] = 1452; em[1378] = 16; 
    	em[1379] = 1452; em[1380] = 24; 
    	em[1381] = 1455; em[1382] = 32; 
    	em[1383] = 1458; em[1384] = 40; 
    	em[1385] = 1461; em[1386] = 48; 
    	em[1387] = 1464; em[1388] = 56; 
    	em[1389] = 1467; em[1390] = 64; 
    	em[1391] = 1470; em[1392] = 72; 
    	em[1393] = 1154; em[1394] = 80; 
    	em[1395] = 1154; em[1396] = 88; 
    	em[1397] = 1473; em[1398] = 96; 
    	em[1399] = 1476; em[1400] = 104; 
    	em[1401] = 1479; em[1402] = 112; 
    	em[1403] = 1482; em[1404] = 120; 
    	em[1405] = 1485; em[1406] = 128; 
    	em[1407] = 1488; em[1408] = 136; 
    	em[1409] = 1491; em[1410] = 144; 
    	em[1411] = 1494; em[1412] = 152; 
    	em[1413] = 1497; em[1414] = 160; 
    	em[1415] = 1500; em[1416] = 168; 
    	em[1417] = 1503; em[1418] = 176; 
    	em[1419] = 1506; em[1420] = 184; 
    	em[1421] = 1509; em[1422] = 192; 
    	em[1423] = 1512; em[1424] = 200; 
    	em[1425] = 1515; em[1426] = 208; 
    	em[1427] = 1506; em[1428] = 216; 
    	em[1429] = 1518; em[1430] = 224; 
    	em[1431] = 1521; em[1432] = 232; 
    	em[1433] = 1524; em[1434] = 240; 
    	em[1435] = 1464; em[1436] = 248; 
    	em[1437] = 1527; em[1438] = 256; 
    	em[1439] = 1530; em[1440] = 264; 
    	em[1441] = 1527; em[1442] = 272; 
    	em[1443] = 1530; em[1444] = 280; 
    	em[1445] = 1530; em[1446] = 288; 
    	em[1447] = 1533; em[1448] = 296; 
    em[1449] = 8884097; em[1450] = 8; em[1451] = 0; /* 1449: pointer.func */
    em[1452] = 8884097; em[1453] = 8; em[1454] = 0; /* 1452: pointer.func */
    em[1455] = 8884097; em[1456] = 8; em[1457] = 0; /* 1455: pointer.func */
    em[1458] = 8884097; em[1459] = 8; em[1460] = 0; /* 1458: pointer.func */
    em[1461] = 8884097; em[1462] = 8; em[1463] = 0; /* 1461: pointer.func */
    em[1464] = 8884097; em[1465] = 8; em[1466] = 0; /* 1464: pointer.func */
    em[1467] = 8884097; em[1468] = 8; em[1469] = 0; /* 1467: pointer.func */
    em[1470] = 8884097; em[1471] = 8; em[1472] = 0; /* 1470: pointer.func */
    em[1473] = 8884097; em[1474] = 8; em[1475] = 0; /* 1473: pointer.func */
    em[1476] = 8884097; em[1477] = 8; em[1478] = 0; /* 1476: pointer.func */
    em[1479] = 8884097; em[1480] = 8; em[1481] = 0; /* 1479: pointer.func */
    em[1482] = 8884097; em[1483] = 8; em[1484] = 0; /* 1482: pointer.func */
    em[1485] = 8884097; em[1486] = 8; em[1487] = 0; /* 1485: pointer.func */
    em[1488] = 8884097; em[1489] = 8; em[1490] = 0; /* 1488: pointer.func */
    em[1491] = 8884097; em[1492] = 8; em[1493] = 0; /* 1491: pointer.func */
    em[1494] = 8884097; em[1495] = 8; em[1496] = 0; /* 1494: pointer.func */
    em[1497] = 8884097; em[1498] = 8; em[1499] = 0; /* 1497: pointer.func */
    em[1500] = 8884097; em[1501] = 8; em[1502] = 0; /* 1500: pointer.func */
    em[1503] = 8884097; em[1504] = 8; em[1505] = 0; /* 1503: pointer.func */
    em[1506] = 8884097; em[1507] = 8; em[1508] = 0; /* 1506: pointer.func */
    em[1509] = 8884097; em[1510] = 8; em[1511] = 0; /* 1509: pointer.func */
    em[1512] = 8884097; em[1513] = 8; em[1514] = 0; /* 1512: pointer.func */
    em[1515] = 8884097; em[1516] = 8; em[1517] = 0; /* 1515: pointer.func */
    em[1518] = 8884097; em[1519] = 8; em[1520] = 0; /* 1518: pointer.func */
    em[1521] = 8884097; em[1522] = 8; em[1523] = 0; /* 1521: pointer.func */
    em[1524] = 8884097; em[1525] = 8; em[1526] = 0; /* 1524: pointer.func */
    em[1527] = 8884097; em[1528] = 8; em[1529] = 0; /* 1527: pointer.func */
    em[1530] = 8884097; em[1531] = 8; em[1532] = 0; /* 1530: pointer.func */
    em[1533] = 8884097; em[1534] = 8; em[1535] = 0; /* 1533: pointer.func */
    em[1536] = 1; em[1537] = 8; em[1538] = 1; /* 1536: pointer.struct.ec_point_st */
    	em[1539] = 1541; em[1540] = 0; 
    em[1541] = 0; em[1542] = 88; em[1543] = 4; /* 1541: struct.ec_point_st */
    	em[1544] = 1552; em[1545] = 0; 
    	em[1546] = 1721; em[1547] = 8; 
    	em[1548] = 1721; em[1549] = 32; 
    	em[1550] = 1721; em[1551] = 56; 
    em[1552] = 1; em[1553] = 8; em[1554] = 1; /* 1552: pointer.struct.ec_method_st */
    	em[1555] = 1557; em[1556] = 0; 
    em[1557] = 0; em[1558] = 304; em[1559] = 37; /* 1557: struct.ec_method_st */
    	em[1560] = 1634; em[1561] = 8; 
    	em[1562] = 1637; em[1563] = 16; 
    	em[1564] = 1637; em[1565] = 24; 
    	em[1566] = 1640; em[1567] = 32; 
    	em[1568] = 1643; em[1569] = 40; 
    	em[1570] = 1646; em[1571] = 48; 
    	em[1572] = 1649; em[1573] = 56; 
    	em[1574] = 1652; em[1575] = 64; 
    	em[1576] = 1655; em[1577] = 72; 
    	em[1578] = 1658; em[1579] = 80; 
    	em[1580] = 1658; em[1581] = 88; 
    	em[1582] = 1661; em[1583] = 96; 
    	em[1584] = 1664; em[1585] = 104; 
    	em[1586] = 1667; em[1587] = 112; 
    	em[1588] = 1670; em[1589] = 120; 
    	em[1590] = 1673; em[1591] = 128; 
    	em[1592] = 1676; em[1593] = 136; 
    	em[1594] = 1679; em[1595] = 144; 
    	em[1596] = 1682; em[1597] = 152; 
    	em[1598] = 1151; em[1599] = 160; 
    	em[1600] = 1685; em[1601] = 168; 
    	em[1602] = 1688; em[1603] = 176; 
    	em[1604] = 1691; em[1605] = 184; 
    	em[1606] = 1694; em[1607] = 192; 
    	em[1608] = 1697; em[1609] = 200; 
    	em[1610] = 1700; em[1611] = 208; 
    	em[1612] = 1691; em[1613] = 216; 
    	em[1614] = 1703; em[1615] = 224; 
    	em[1616] = 1706; em[1617] = 232; 
    	em[1618] = 1709; em[1619] = 240; 
    	em[1620] = 1649; em[1621] = 248; 
    	em[1622] = 1712; em[1623] = 256; 
    	em[1624] = 1715; em[1625] = 264; 
    	em[1626] = 1712; em[1627] = 272; 
    	em[1628] = 1715; em[1629] = 280; 
    	em[1630] = 1715; em[1631] = 288; 
    	em[1632] = 1718; em[1633] = 296; 
    em[1634] = 8884097; em[1635] = 8; em[1636] = 0; /* 1634: pointer.func */
    em[1637] = 8884097; em[1638] = 8; em[1639] = 0; /* 1637: pointer.func */
    em[1640] = 8884097; em[1641] = 8; em[1642] = 0; /* 1640: pointer.func */
    em[1643] = 8884097; em[1644] = 8; em[1645] = 0; /* 1643: pointer.func */
    em[1646] = 8884097; em[1647] = 8; em[1648] = 0; /* 1646: pointer.func */
    em[1649] = 8884097; em[1650] = 8; em[1651] = 0; /* 1649: pointer.func */
    em[1652] = 8884097; em[1653] = 8; em[1654] = 0; /* 1652: pointer.func */
    em[1655] = 8884097; em[1656] = 8; em[1657] = 0; /* 1655: pointer.func */
    em[1658] = 8884097; em[1659] = 8; em[1660] = 0; /* 1658: pointer.func */
    em[1661] = 8884097; em[1662] = 8; em[1663] = 0; /* 1661: pointer.func */
    em[1664] = 8884097; em[1665] = 8; em[1666] = 0; /* 1664: pointer.func */
    em[1667] = 8884097; em[1668] = 8; em[1669] = 0; /* 1667: pointer.func */
    em[1670] = 8884097; em[1671] = 8; em[1672] = 0; /* 1670: pointer.func */
    em[1673] = 8884097; em[1674] = 8; em[1675] = 0; /* 1673: pointer.func */
    em[1676] = 8884097; em[1677] = 8; em[1678] = 0; /* 1676: pointer.func */
    em[1679] = 8884097; em[1680] = 8; em[1681] = 0; /* 1679: pointer.func */
    em[1682] = 8884097; em[1683] = 8; em[1684] = 0; /* 1682: pointer.func */
    em[1685] = 8884097; em[1686] = 8; em[1687] = 0; /* 1685: pointer.func */
    em[1688] = 8884097; em[1689] = 8; em[1690] = 0; /* 1688: pointer.func */
    em[1691] = 8884097; em[1692] = 8; em[1693] = 0; /* 1691: pointer.func */
    em[1694] = 8884097; em[1695] = 8; em[1696] = 0; /* 1694: pointer.func */
    em[1697] = 8884097; em[1698] = 8; em[1699] = 0; /* 1697: pointer.func */
    em[1700] = 8884097; em[1701] = 8; em[1702] = 0; /* 1700: pointer.func */
    em[1703] = 8884097; em[1704] = 8; em[1705] = 0; /* 1703: pointer.func */
    em[1706] = 8884097; em[1707] = 8; em[1708] = 0; /* 1706: pointer.func */
    em[1709] = 8884097; em[1710] = 8; em[1711] = 0; /* 1709: pointer.func */
    em[1712] = 8884097; em[1713] = 8; em[1714] = 0; /* 1712: pointer.func */
    em[1715] = 8884097; em[1716] = 8; em[1717] = 0; /* 1715: pointer.func */
    em[1718] = 8884097; em[1719] = 8; em[1720] = 0; /* 1718: pointer.func */
    em[1721] = 0; em[1722] = 24; em[1723] = 1; /* 1721: struct.bignum_st */
    	em[1724] = 1726; em[1725] = 0; 
    em[1726] = 8884099; em[1727] = 8; em[1728] = 2; /* 1726: pointer_to_array_of_pointers_to_stack */
    	em[1729] = 47; em[1730] = 0; 
    	em[1731] = 50; em[1732] = 12; 
    em[1733] = 0; em[1734] = 24; em[1735] = 1; /* 1733: struct.bignum_st */
    	em[1736] = 1738; em[1737] = 0; 
    em[1738] = 8884099; em[1739] = 8; em[1740] = 2; /* 1738: pointer_to_array_of_pointers_to_stack */
    	em[1741] = 47; em[1742] = 0; 
    	em[1743] = 50; em[1744] = 12; 
    em[1745] = 1; em[1746] = 8; em[1747] = 1; /* 1745: pointer.struct.ec_extra_data_st */
    	em[1748] = 1750; em[1749] = 0; 
    em[1750] = 0; em[1751] = 40; em[1752] = 5; /* 1750: struct.ec_extra_data_st */
    	em[1753] = 1763; em[1754] = 0; 
    	em[1755] = 81; em[1756] = 8; 
    	em[1757] = 1768; em[1758] = 16; 
    	em[1759] = 1771; em[1760] = 24; 
    	em[1761] = 1771; em[1762] = 32; 
    em[1763] = 1; em[1764] = 8; em[1765] = 1; /* 1763: pointer.struct.ec_extra_data_st */
    	em[1766] = 1750; em[1767] = 0; 
    em[1768] = 8884097; em[1769] = 8; em[1770] = 0; /* 1768: pointer.func */
    em[1771] = 8884097; em[1772] = 8; em[1773] = 0; /* 1771: pointer.func */
    em[1774] = 8884097; em[1775] = 8; em[1776] = 0; /* 1774: pointer.func */
    em[1777] = 1; em[1778] = 8; em[1779] = 1; /* 1777: pointer.struct.ec_point_st */
    	em[1780] = 1541; em[1781] = 0; 
    em[1782] = 1; em[1783] = 8; em[1784] = 1; /* 1782: pointer.struct.bignum_st */
    	em[1785] = 1787; em[1786] = 0; 
    em[1787] = 0; em[1788] = 24; em[1789] = 1; /* 1787: struct.bignum_st */
    	em[1790] = 1792; em[1791] = 0; 
    em[1792] = 8884099; em[1793] = 8; em[1794] = 2; /* 1792: pointer_to_array_of_pointers_to_stack */
    	em[1795] = 47; em[1796] = 0; 
    	em[1797] = 50; em[1798] = 12; 
    em[1799] = 1; em[1800] = 8; em[1801] = 1; /* 1799: pointer.struct.ec_extra_data_st */
    	em[1802] = 1804; em[1803] = 0; 
    em[1804] = 0; em[1805] = 40; em[1806] = 5; /* 1804: struct.ec_extra_data_st */
    	em[1807] = 1817; em[1808] = 0; 
    	em[1809] = 81; em[1810] = 8; 
    	em[1811] = 1768; em[1812] = 16; 
    	em[1813] = 1771; em[1814] = 24; 
    	em[1815] = 1771; em[1816] = 32; 
    em[1817] = 1; em[1818] = 8; em[1819] = 1; /* 1817: pointer.struct.ec_extra_data_st */
    	em[1820] = 1804; em[1821] = 0; 
    em[1822] = 1; em[1823] = 8; em[1824] = 1; /* 1822: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1825] = 1827; em[1826] = 0; 
    em[1827] = 0; em[1828] = 32; em[1829] = 2; /* 1827: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1830] = 1834; em[1831] = 8; 
    	em[1832] = 84; em[1833] = 24; 
    em[1834] = 8884099; em[1835] = 8; em[1836] = 2; /* 1834: pointer_to_array_of_pointers_to_stack */
    	em[1837] = 1841; em[1838] = 0; 
    	em[1839] = 50; em[1840] = 20; 
    em[1841] = 0; em[1842] = 8; em[1843] = 1; /* 1841: pointer.X509_ATTRIBUTE */
    	em[1844] = 1846; em[1845] = 0; 
    em[1846] = 0; em[1847] = 0; em[1848] = 1; /* 1846: X509_ATTRIBUTE */
    	em[1849] = 1851; em[1850] = 0; 
    em[1851] = 0; em[1852] = 24; em[1853] = 2; /* 1851: struct.x509_attributes_st */
    	em[1854] = 818; em[1855] = 0; 
    	em[1856] = 1041; em[1857] = 16; 
    em[1858] = 8884101; em[1859] = 8; em[1860] = 6; /* 1858: union.union_of_evp_pkey_st */
    	em[1861] = 81; em[1862] = 0; 
    	em[1863] = 488; em[1864] = 6; 
    	em[1865] = 0; em[1866] = 116; 
    	em[1867] = 1873; em[1868] = 28; 
    	em[1869] = 1319; em[1870] = 408; 
    	em[1871] = 50; em[1872] = 0; 
    em[1873] = 1; em[1874] = 8; em[1875] = 1; /* 1873: pointer.struct.dh_st */
    	em[1876] = 1273; em[1877] = 0; 
    em[1878] = 8884097; em[1879] = 8; em[1880] = 0; /* 1878: pointer.func */
    em[1881] = 8884097; em[1882] = 8; em[1883] = 0; /* 1881: pointer.func */
    em[1884] = 8884097; em[1885] = 8; em[1886] = 0; /* 1884: pointer.func */
    em[1887] = 0; em[1888] = 1; em[1889] = 0; /* 1887: char */
    em[1890] = 1; em[1891] = 8; em[1892] = 1; /* 1890: pointer.struct.evp_pkey_st */
    	em[1893] = 1895; em[1894] = 0; 
    em[1895] = 0; em[1896] = 56; em[1897] = 4; /* 1895: struct.evp_pkey_st */
    	em[1898] = 1222; em[1899] = 16; 
    	em[1900] = 1238; em[1901] = 24; 
    	em[1902] = 1858; em[1903] = 32; 
    	em[1904] = 1906; em[1905] = 48; 
    em[1906] = 1; em[1907] = 8; em[1908] = 1; /* 1906: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1909] = 1911; em[1910] = 0; 
    em[1911] = 0; em[1912] = 32; em[1913] = 2; /* 1911: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1914] = 1918; em[1915] = 8; 
    	em[1916] = 84; em[1917] = 24; 
    em[1918] = 8884099; em[1919] = 8; em[1920] = 2; /* 1918: pointer_to_array_of_pointers_to_stack */
    	em[1921] = 1925; em[1922] = 0; 
    	em[1923] = 50; em[1924] = 20; 
    em[1925] = 0; em[1926] = 8; em[1927] = 1; /* 1925: pointer.X509_ATTRIBUTE */
    	em[1928] = 1846; em[1929] = 0; 
    em[1930] = 8884097; em[1931] = 8; em[1932] = 0; /* 1930: pointer.func */
    em[1933] = 8884097; em[1934] = 8; em[1935] = 0; /* 1933: pointer.func */
    em[1936] = 1; em[1937] = 8; em[1938] = 1; /* 1936: pointer.struct.evp_pkey_method_st */
    	em[1939] = 1941; em[1940] = 0; 
    em[1941] = 0; em[1942] = 208; em[1943] = 25; /* 1941: struct.evp_pkey_method_st */
    	em[1944] = 1994; em[1945] = 8; 
    	em[1946] = 1997; em[1947] = 16; 
    	em[1948] = 2000; em[1949] = 24; 
    	em[1950] = 1994; em[1951] = 32; 
    	em[1952] = 2003; em[1953] = 40; 
    	em[1954] = 1994; em[1955] = 48; 
    	em[1956] = 2003; em[1957] = 56; 
    	em[1958] = 1994; em[1959] = 64; 
    	em[1960] = 2006; em[1961] = 72; 
    	em[1962] = 1994; em[1963] = 80; 
    	em[1964] = 2009; em[1965] = 88; 
    	em[1966] = 1994; em[1967] = 96; 
    	em[1968] = 2006; em[1969] = 104; 
    	em[1970] = 2012; em[1971] = 112; 
    	em[1972] = 1878; em[1973] = 120; 
    	em[1974] = 2012; em[1975] = 128; 
    	em[1976] = 2015; em[1977] = 136; 
    	em[1978] = 1994; em[1979] = 144; 
    	em[1980] = 2006; em[1981] = 152; 
    	em[1982] = 1994; em[1983] = 160; 
    	em[1984] = 2006; em[1985] = 168; 
    	em[1986] = 1994; em[1987] = 176; 
    	em[1988] = 1930; em[1989] = 184; 
    	em[1990] = 1884; em[1991] = 192; 
    	em[1992] = 1881; em[1993] = 200; 
    em[1994] = 8884097; em[1995] = 8; em[1996] = 0; /* 1994: pointer.func */
    em[1997] = 8884097; em[1998] = 8; em[1999] = 0; /* 1997: pointer.func */
    em[2000] = 8884097; em[2001] = 8; em[2002] = 0; /* 2000: pointer.func */
    em[2003] = 8884097; em[2004] = 8; em[2005] = 0; /* 2003: pointer.func */
    em[2006] = 8884097; em[2007] = 8; em[2008] = 0; /* 2006: pointer.func */
    em[2009] = 8884097; em[2010] = 8; em[2011] = 0; /* 2009: pointer.func */
    em[2012] = 8884097; em[2013] = 8; em[2014] = 0; /* 2012: pointer.func */
    em[2015] = 8884097; em[2016] = 8; em[2017] = 0; /* 2015: pointer.func */
    em[2018] = 8884097; em[2019] = 8; em[2020] = 0; /* 2018: pointer.func */
    em[2021] = 0; em[2022] = 48; em[2023] = 5; /* 2021: struct.env_md_ctx_st */
    	em[2024] = 2034; em[2025] = 0; 
    	em[2026] = 1238; em[2027] = 8; 
    	em[2028] = 81; em[2029] = 24; 
    	em[2030] = 2070; em[2031] = 32; 
    	em[2032] = 2061; em[2033] = 40; 
    em[2034] = 1; em[2035] = 8; em[2036] = 1; /* 2034: pointer.struct.env_md_st */
    	em[2037] = 2039; em[2038] = 0; 
    em[2039] = 0; em[2040] = 120; em[2041] = 8; /* 2039: struct.env_md_st */
    	em[2042] = 2058; em[2043] = 24; 
    	em[2044] = 2061; em[2045] = 32; 
    	em[2046] = 1933; em[2047] = 40; 
    	em[2048] = 2018; em[2049] = 48; 
    	em[2050] = 2058; em[2051] = 56; 
    	em[2052] = 2064; em[2053] = 64; 
    	em[2054] = 1183; em[2055] = 72; 
    	em[2056] = 2067; em[2057] = 112; 
    em[2058] = 8884097; em[2059] = 8; em[2060] = 0; /* 2058: pointer.func */
    em[2061] = 8884097; em[2062] = 8; em[2063] = 0; /* 2061: pointer.func */
    em[2064] = 8884097; em[2065] = 8; em[2066] = 0; /* 2064: pointer.func */
    em[2067] = 8884097; em[2068] = 8; em[2069] = 0; /* 2067: pointer.func */
    em[2070] = 1; em[2071] = 8; em[2072] = 1; /* 2070: pointer.struct.evp_pkey_ctx_st */
    	em[2073] = 2075; em[2074] = 0; 
    em[2075] = 0; em[2076] = 80; em[2077] = 8; /* 2075: struct.evp_pkey_ctx_st */
    	em[2078] = 1936; em[2079] = 0; 
    	em[2080] = 1238; em[2081] = 8; 
    	em[2082] = 2094; em[2083] = 16; 
    	em[2084] = 2094; em[2085] = 24; 
    	em[2086] = 81; em[2087] = 40; 
    	em[2088] = 81; em[2089] = 48; 
    	em[2090] = 696; em[2091] = 56; 
    	em[2092] = 2099; em[2093] = 64; 
    em[2094] = 1; em[2095] = 8; em[2096] = 1; /* 2094: pointer.struct.evp_pkey_st */
    	em[2097] = 1227; em[2098] = 0; 
    em[2099] = 1; em[2100] = 8; em[2101] = 1; /* 2099: pointer.int */
    	em[2102] = 50; em[2103] = 0; 
    em[2104] = 1; em[2105] = 8; em[2106] = 1; /* 2104: pointer.struct.env_md_ctx_st */
    	em[2107] = 2021; em[2108] = 0; 
    em[2109] = 1; em[2110] = 8; em[2111] = 1; /* 2109: pointer.unsigned int */
    	em[2112] = 2114; em[2113] = 0; 
    em[2114] = 0; em[2115] = 4; em[2116] = 0; /* 2114: unsigned int */
    args_addr->arg_entity_index[0] = 2104;
    args_addr->arg_entity_index[1] = 717;
    args_addr->arg_entity_index[2] = 2109;
    args_addr->arg_entity_index[3] = 1890;
    args_addr->ret_entity_index = 50;
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

