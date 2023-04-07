#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
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
    	em[26] = 102; em[27] = 120; 
    	em[28] = 158; em[29] = 128; 
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.struct.bignum_st */
    	em[33] = 35; em[34] = 0; 
    em[35] = 0; em[36] = 24; em[37] = 1; /* 35: struct.bignum_st */
    	em[38] = 40; em[39] = 0; 
    em[40] = 8884099; em[41] = 8; em[42] = 2; /* 40: pointer_to_array_of_pointers_to_stack */
    	em[43] = 47; em[44] = 0; 
    	em[45] = 50; em[46] = 12; 
    em[47] = 0; em[48] = 4; em[49] = 0; /* 47: unsigned int */
    em[50] = 0; em[51] = 4; em[52] = 0; /* 50: int */
    em[53] = 1; em[54] = 8; em[55] = 1; /* 53: pointer.struct.bn_mont_ctx_st */
    	em[56] = 58; em[57] = 0; 
    em[58] = 0; em[59] = 96; em[60] = 3; /* 58: struct.bn_mont_ctx_st */
    	em[61] = 35; em[62] = 8; 
    	em[63] = 35; em[64] = 32; 
    	em[65] = 35; em[66] = 56; 
    em[67] = 0; em[68] = 16; em[69] = 1; /* 67: struct.crypto_ex_data_st */
    	em[70] = 72; em[71] = 0; 
    em[72] = 1; em[73] = 8; em[74] = 1; /* 72: pointer.struct.stack_st_void */
    	em[75] = 77; em[76] = 0; 
    em[77] = 0; em[78] = 32; em[79] = 1; /* 77: struct.stack_st_void */
    	em[80] = 82; em[81] = 0; 
    em[82] = 0; em[83] = 32; em[84] = 2; /* 82: struct.stack_st */
    	em[85] = 89; em[86] = 8; 
    	em[87] = 99; em[88] = 24; 
    em[89] = 1; em[90] = 8; em[91] = 1; /* 89: pointer.pointer.char */
    	em[92] = 94; em[93] = 0; 
    em[94] = 1; em[95] = 8; em[96] = 1; /* 94: pointer.char */
    	em[97] = 8884096; em[98] = 0; 
    em[99] = 8884097; em[100] = 8; em[101] = 0; /* 99: pointer.func */
    em[102] = 1; em[103] = 8; em[104] = 1; /* 102: pointer.struct.dsa_method */
    	em[105] = 107; em[106] = 0; 
    em[107] = 0; em[108] = 96; em[109] = 11; /* 107: struct.dsa_method */
    	em[110] = 132; em[111] = 0; 
    	em[112] = 137; em[113] = 8; 
    	em[114] = 140; em[115] = 16; 
    	em[116] = 143; em[117] = 24; 
    	em[118] = 146; em[119] = 32; 
    	em[120] = 149; em[121] = 40; 
    	em[122] = 152; em[123] = 48; 
    	em[124] = 152; em[125] = 56; 
    	em[126] = 94; em[127] = 72; 
    	em[128] = 155; em[129] = 80; 
    	em[130] = 152; em[131] = 88; 
    em[132] = 1; em[133] = 8; em[134] = 1; /* 132: pointer.char */
    	em[135] = 8884096; em[136] = 0; 
    em[137] = 8884097; em[138] = 8; em[139] = 0; /* 137: pointer.func */
    em[140] = 8884097; em[141] = 8; em[142] = 0; /* 140: pointer.func */
    em[143] = 8884097; em[144] = 8; em[145] = 0; /* 143: pointer.func */
    em[146] = 8884097; em[147] = 8; em[148] = 0; /* 146: pointer.func */
    em[149] = 8884097; em[150] = 8; em[151] = 0; /* 149: pointer.func */
    em[152] = 8884097; em[153] = 8; em[154] = 0; /* 152: pointer.func */
    em[155] = 8884097; em[156] = 8; em[157] = 0; /* 155: pointer.func */
    em[158] = 1; em[159] = 8; em[160] = 1; /* 158: pointer.struct.engine_st */
    	em[161] = 163; em[162] = 0; 
    em[163] = 0; em[164] = 216; em[165] = 24; /* 163: struct.engine_st */
    	em[166] = 132; em[167] = 0; 
    	em[168] = 132; em[169] = 8; 
    	em[170] = 214; em[171] = 16; 
    	em[172] = 269; em[173] = 24; 
    	em[174] = 320; em[175] = 32; 
    	em[176] = 356; em[177] = 40; 
    	em[178] = 373; em[179] = 48; 
    	em[180] = 400; em[181] = 56; 
    	em[182] = 435; em[183] = 64; 
    	em[184] = 443; em[185] = 72; 
    	em[186] = 446; em[187] = 80; 
    	em[188] = 449; em[189] = 88; 
    	em[190] = 452; em[191] = 96; 
    	em[192] = 455; em[193] = 104; 
    	em[194] = 455; em[195] = 112; 
    	em[196] = 455; em[197] = 120; 
    	em[198] = 458; em[199] = 128; 
    	em[200] = 461; em[201] = 136; 
    	em[202] = 461; em[203] = 144; 
    	em[204] = 464; em[205] = 152; 
    	em[206] = 467; em[207] = 160; 
    	em[208] = 479; em[209] = 184; 
    	em[210] = 501; em[211] = 200; 
    	em[212] = 501; em[213] = 208; 
    em[214] = 1; em[215] = 8; em[216] = 1; /* 214: pointer.struct.rsa_meth_st */
    	em[217] = 219; em[218] = 0; 
    em[219] = 0; em[220] = 112; em[221] = 13; /* 219: struct.rsa_meth_st */
    	em[222] = 132; em[223] = 0; 
    	em[224] = 248; em[225] = 8; 
    	em[226] = 248; em[227] = 16; 
    	em[228] = 248; em[229] = 24; 
    	em[230] = 248; em[231] = 32; 
    	em[232] = 251; em[233] = 40; 
    	em[234] = 254; em[235] = 48; 
    	em[236] = 257; em[237] = 56; 
    	em[238] = 257; em[239] = 64; 
    	em[240] = 94; em[241] = 80; 
    	em[242] = 260; em[243] = 88; 
    	em[244] = 263; em[245] = 96; 
    	em[246] = 266; em[247] = 104; 
    em[248] = 8884097; em[249] = 8; em[250] = 0; /* 248: pointer.func */
    em[251] = 8884097; em[252] = 8; em[253] = 0; /* 251: pointer.func */
    em[254] = 8884097; em[255] = 8; em[256] = 0; /* 254: pointer.func */
    em[257] = 8884097; em[258] = 8; em[259] = 0; /* 257: pointer.func */
    em[260] = 8884097; em[261] = 8; em[262] = 0; /* 260: pointer.func */
    em[263] = 8884097; em[264] = 8; em[265] = 0; /* 263: pointer.func */
    em[266] = 8884097; em[267] = 8; em[268] = 0; /* 266: pointer.func */
    em[269] = 1; em[270] = 8; em[271] = 1; /* 269: pointer.struct.dsa_method */
    	em[272] = 274; em[273] = 0; 
    em[274] = 0; em[275] = 96; em[276] = 11; /* 274: struct.dsa_method */
    	em[277] = 132; em[278] = 0; 
    	em[279] = 299; em[280] = 8; 
    	em[281] = 302; em[282] = 16; 
    	em[283] = 305; em[284] = 24; 
    	em[285] = 308; em[286] = 32; 
    	em[287] = 311; em[288] = 40; 
    	em[289] = 314; em[290] = 48; 
    	em[291] = 314; em[292] = 56; 
    	em[293] = 94; em[294] = 72; 
    	em[295] = 317; em[296] = 80; 
    	em[297] = 314; em[298] = 88; 
    em[299] = 8884097; em[300] = 8; em[301] = 0; /* 299: pointer.func */
    em[302] = 8884097; em[303] = 8; em[304] = 0; /* 302: pointer.func */
    em[305] = 8884097; em[306] = 8; em[307] = 0; /* 305: pointer.func */
    em[308] = 8884097; em[309] = 8; em[310] = 0; /* 308: pointer.func */
    em[311] = 8884097; em[312] = 8; em[313] = 0; /* 311: pointer.func */
    em[314] = 8884097; em[315] = 8; em[316] = 0; /* 314: pointer.func */
    em[317] = 8884097; em[318] = 8; em[319] = 0; /* 317: pointer.func */
    em[320] = 1; em[321] = 8; em[322] = 1; /* 320: pointer.struct.dh_method */
    	em[323] = 325; em[324] = 0; 
    em[325] = 0; em[326] = 72; em[327] = 8; /* 325: struct.dh_method */
    	em[328] = 132; em[329] = 0; 
    	em[330] = 344; em[331] = 8; 
    	em[332] = 347; em[333] = 16; 
    	em[334] = 350; em[335] = 24; 
    	em[336] = 344; em[337] = 32; 
    	em[338] = 344; em[339] = 40; 
    	em[340] = 94; em[341] = 56; 
    	em[342] = 353; em[343] = 64; 
    em[344] = 8884097; em[345] = 8; em[346] = 0; /* 344: pointer.func */
    em[347] = 8884097; em[348] = 8; em[349] = 0; /* 347: pointer.func */
    em[350] = 8884097; em[351] = 8; em[352] = 0; /* 350: pointer.func */
    em[353] = 8884097; em[354] = 8; em[355] = 0; /* 353: pointer.func */
    em[356] = 1; em[357] = 8; em[358] = 1; /* 356: pointer.struct.ecdh_method */
    	em[359] = 361; em[360] = 0; 
    em[361] = 0; em[362] = 32; em[363] = 3; /* 361: struct.ecdh_method */
    	em[364] = 132; em[365] = 0; 
    	em[366] = 370; em[367] = 8; 
    	em[368] = 94; em[369] = 24; 
    em[370] = 8884097; em[371] = 8; em[372] = 0; /* 370: pointer.func */
    em[373] = 1; em[374] = 8; em[375] = 1; /* 373: pointer.struct.ecdsa_method */
    	em[376] = 378; em[377] = 0; 
    em[378] = 0; em[379] = 48; em[380] = 5; /* 378: struct.ecdsa_method */
    	em[381] = 132; em[382] = 0; 
    	em[383] = 391; em[384] = 8; 
    	em[385] = 394; em[386] = 16; 
    	em[387] = 397; em[388] = 24; 
    	em[389] = 94; em[390] = 40; 
    em[391] = 8884097; em[392] = 8; em[393] = 0; /* 391: pointer.func */
    em[394] = 8884097; em[395] = 8; em[396] = 0; /* 394: pointer.func */
    em[397] = 8884097; em[398] = 8; em[399] = 0; /* 397: pointer.func */
    em[400] = 1; em[401] = 8; em[402] = 1; /* 400: pointer.struct.rand_meth_st */
    	em[403] = 405; em[404] = 0; 
    em[405] = 0; em[406] = 48; em[407] = 6; /* 405: struct.rand_meth_st */
    	em[408] = 420; em[409] = 0; 
    	em[410] = 423; em[411] = 8; 
    	em[412] = 426; em[413] = 16; 
    	em[414] = 429; em[415] = 24; 
    	em[416] = 423; em[417] = 32; 
    	em[418] = 432; em[419] = 40; 
    em[420] = 8884097; em[421] = 8; em[422] = 0; /* 420: pointer.func */
    em[423] = 8884097; em[424] = 8; em[425] = 0; /* 423: pointer.func */
    em[426] = 8884097; em[427] = 8; em[428] = 0; /* 426: pointer.func */
    em[429] = 8884097; em[430] = 8; em[431] = 0; /* 429: pointer.func */
    em[432] = 8884097; em[433] = 8; em[434] = 0; /* 432: pointer.func */
    em[435] = 1; em[436] = 8; em[437] = 1; /* 435: pointer.struct.store_method_st */
    	em[438] = 440; em[439] = 0; 
    em[440] = 0; em[441] = 0; em[442] = 0; /* 440: struct.store_method_st */
    em[443] = 8884097; em[444] = 8; em[445] = 0; /* 443: pointer.func */
    em[446] = 8884097; em[447] = 8; em[448] = 0; /* 446: pointer.func */
    em[449] = 8884097; em[450] = 8; em[451] = 0; /* 449: pointer.func */
    em[452] = 8884097; em[453] = 8; em[454] = 0; /* 452: pointer.func */
    em[455] = 8884097; em[456] = 8; em[457] = 0; /* 455: pointer.func */
    em[458] = 8884097; em[459] = 8; em[460] = 0; /* 458: pointer.func */
    em[461] = 8884097; em[462] = 8; em[463] = 0; /* 461: pointer.func */
    em[464] = 8884097; em[465] = 8; em[466] = 0; /* 464: pointer.func */
    em[467] = 1; em[468] = 8; em[469] = 1; /* 467: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[470] = 472; em[471] = 0; 
    em[472] = 0; em[473] = 32; em[474] = 2; /* 472: struct.ENGINE_CMD_DEFN_st */
    	em[475] = 132; em[476] = 8; 
    	em[477] = 132; em[478] = 16; 
    em[479] = 0; em[480] = 16; em[481] = 1; /* 479: struct.crypto_ex_data_st */
    	em[482] = 484; em[483] = 0; 
    em[484] = 1; em[485] = 8; em[486] = 1; /* 484: pointer.struct.stack_st_void */
    	em[487] = 489; em[488] = 0; 
    em[489] = 0; em[490] = 32; em[491] = 1; /* 489: struct.stack_st_void */
    	em[492] = 494; em[493] = 0; 
    em[494] = 0; em[495] = 32; em[496] = 2; /* 494: struct.stack_st */
    	em[497] = 89; em[498] = 8; 
    	em[499] = 99; em[500] = 24; 
    em[501] = 1; em[502] = 8; em[503] = 1; /* 501: pointer.struct.engine_st */
    	em[504] = 163; em[505] = 0; 
    em[506] = 1; em[507] = 8; em[508] = 1; /* 506: pointer.struct.rsa_st */
    	em[509] = 511; em[510] = 0; 
    em[511] = 0; em[512] = 168; em[513] = 17; /* 511: struct.rsa_st */
    	em[514] = 548; em[515] = 16; 
    	em[516] = 603; em[517] = 24; 
    	em[518] = 608; em[519] = 32; 
    	em[520] = 608; em[521] = 40; 
    	em[522] = 608; em[523] = 48; 
    	em[524] = 608; em[525] = 56; 
    	em[526] = 608; em[527] = 64; 
    	em[528] = 608; em[529] = 72; 
    	em[530] = 608; em[531] = 80; 
    	em[532] = 608; em[533] = 88; 
    	em[534] = 625; em[535] = 96; 
    	em[536] = 647; em[537] = 120; 
    	em[538] = 647; em[539] = 128; 
    	em[540] = 647; em[541] = 136; 
    	em[542] = 94; em[543] = 144; 
    	em[544] = 661; em[545] = 152; 
    	em[546] = 661; em[547] = 160; 
    em[548] = 1; em[549] = 8; em[550] = 1; /* 548: pointer.struct.rsa_meth_st */
    	em[551] = 553; em[552] = 0; 
    em[553] = 0; em[554] = 112; em[555] = 13; /* 553: struct.rsa_meth_st */
    	em[556] = 132; em[557] = 0; 
    	em[558] = 582; em[559] = 8; 
    	em[560] = 582; em[561] = 16; 
    	em[562] = 582; em[563] = 24; 
    	em[564] = 582; em[565] = 32; 
    	em[566] = 585; em[567] = 40; 
    	em[568] = 588; em[569] = 48; 
    	em[570] = 591; em[571] = 56; 
    	em[572] = 591; em[573] = 64; 
    	em[574] = 94; em[575] = 80; 
    	em[576] = 594; em[577] = 88; 
    	em[578] = 597; em[579] = 96; 
    	em[580] = 600; em[581] = 104; 
    em[582] = 8884097; em[583] = 8; em[584] = 0; /* 582: pointer.func */
    em[585] = 8884097; em[586] = 8; em[587] = 0; /* 585: pointer.func */
    em[588] = 8884097; em[589] = 8; em[590] = 0; /* 588: pointer.func */
    em[591] = 8884097; em[592] = 8; em[593] = 0; /* 591: pointer.func */
    em[594] = 8884097; em[595] = 8; em[596] = 0; /* 594: pointer.func */
    em[597] = 8884097; em[598] = 8; em[599] = 0; /* 597: pointer.func */
    em[600] = 8884097; em[601] = 8; em[602] = 0; /* 600: pointer.func */
    em[603] = 1; em[604] = 8; em[605] = 1; /* 603: pointer.struct.engine_st */
    	em[606] = 163; em[607] = 0; 
    em[608] = 1; em[609] = 8; em[610] = 1; /* 608: pointer.struct.bignum_st */
    	em[611] = 613; em[612] = 0; 
    em[613] = 0; em[614] = 24; em[615] = 1; /* 613: struct.bignum_st */
    	em[616] = 618; em[617] = 0; 
    em[618] = 8884099; em[619] = 8; em[620] = 2; /* 618: pointer_to_array_of_pointers_to_stack */
    	em[621] = 47; em[622] = 0; 
    	em[623] = 50; em[624] = 12; 
    em[625] = 0; em[626] = 16; em[627] = 1; /* 625: struct.crypto_ex_data_st */
    	em[628] = 630; em[629] = 0; 
    em[630] = 1; em[631] = 8; em[632] = 1; /* 630: pointer.struct.stack_st_void */
    	em[633] = 635; em[634] = 0; 
    em[635] = 0; em[636] = 32; em[637] = 1; /* 635: struct.stack_st_void */
    	em[638] = 640; em[639] = 0; 
    em[640] = 0; em[641] = 32; em[642] = 2; /* 640: struct.stack_st */
    	em[643] = 89; em[644] = 8; 
    	em[645] = 99; em[646] = 24; 
    em[647] = 1; em[648] = 8; em[649] = 1; /* 647: pointer.struct.bn_mont_ctx_st */
    	em[650] = 652; em[651] = 0; 
    em[652] = 0; em[653] = 96; em[654] = 3; /* 652: struct.bn_mont_ctx_st */
    	em[655] = 613; em[656] = 8; 
    	em[657] = 613; em[658] = 32; 
    	em[659] = 613; em[660] = 56; 
    em[661] = 1; em[662] = 8; em[663] = 1; /* 661: pointer.struct.bn_blinding_st */
    	em[664] = 666; em[665] = 0; 
    em[666] = 0; em[667] = 88; em[668] = 7; /* 666: struct.bn_blinding_st */
    	em[669] = 683; em[670] = 0; 
    	em[671] = 683; em[672] = 8; 
    	em[673] = 683; em[674] = 16; 
    	em[675] = 683; em[676] = 24; 
    	em[677] = 700; em[678] = 40; 
    	em[679] = 708; em[680] = 72; 
    	em[681] = 722; em[682] = 80; 
    em[683] = 1; em[684] = 8; em[685] = 1; /* 683: pointer.struct.bignum_st */
    	em[686] = 688; em[687] = 0; 
    em[688] = 0; em[689] = 24; em[690] = 1; /* 688: struct.bignum_st */
    	em[691] = 693; em[692] = 0; 
    em[693] = 8884099; em[694] = 8; em[695] = 2; /* 693: pointer_to_array_of_pointers_to_stack */
    	em[696] = 47; em[697] = 0; 
    	em[698] = 50; em[699] = 12; 
    em[700] = 0; em[701] = 16; em[702] = 1; /* 700: struct.crypto_threadid_st */
    	em[703] = 705; em[704] = 0; 
    em[705] = 0; em[706] = 8; em[707] = 0; /* 705: pointer.void */
    em[708] = 1; em[709] = 8; em[710] = 1; /* 708: pointer.struct.bn_mont_ctx_st */
    	em[711] = 713; em[712] = 0; 
    em[713] = 0; em[714] = 96; em[715] = 3; /* 713: struct.bn_mont_ctx_st */
    	em[716] = 688; em[717] = 8; 
    	em[718] = 688; em[719] = 32; 
    	em[720] = 688; em[721] = 56; 
    em[722] = 8884097; em[723] = 8; em[724] = 0; /* 722: pointer.func */
    em[725] = 0; em[726] = 8; em[727] = 5; /* 725: union.unknown */
    	em[728] = 94; em[729] = 0; 
    	em[730] = 506; em[731] = 0; 
    	em[732] = 0; em[733] = 0; 
    	em[734] = 738; em[735] = 0; 
    	em[736] = 872; em[737] = 0; 
    em[738] = 1; em[739] = 8; em[740] = 1; /* 738: pointer.struct.dh_st */
    	em[741] = 743; em[742] = 0; 
    em[743] = 0; em[744] = 144; em[745] = 12; /* 743: struct.dh_st */
    	em[746] = 770; em[747] = 8; 
    	em[748] = 770; em[749] = 16; 
    	em[750] = 770; em[751] = 32; 
    	em[752] = 770; em[753] = 40; 
    	em[754] = 787; em[755] = 56; 
    	em[756] = 770; em[757] = 64; 
    	em[758] = 770; em[759] = 72; 
    	em[760] = 801; em[761] = 80; 
    	em[762] = 770; em[763] = 96; 
    	em[764] = 809; em[765] = 112; 
    	em[766] = 831; em[767] = 128; 
    	em[768] = 867; em[769] = 136; 
    em[770] = 1; em[771] = 8; em[772] = 1; /* 770: pointer.struct.bignum_st */
    	em[773] = 775; em[774] = 0; 
    em[775] = 0; em[776] = 24; em[777] = 1; /* 775: struct.bignum_st */
    	em[778] = 780; em[779] = 0; 
    em[780] = 8884099; em[781] = 8; em[782] = 2; /* 780: pointer_to_array_of_pointers_to_stack */
    	em[783] = 47; em[784] = 0; 
    	em[785] = 50; em[786] = 12; 
    em[787] = 1; em[788] = 8; em[789] = 1; /* 787: pointer.struct.bn_mont_ctx_st */
    	em[790] = 792; em[791] = 0; 
    em[792] = 0; em[793] = 96; em[794] = 3; /* 792: struct.bn_mont_ctx_st */
    	em[795] = 775; em[796] = 8; 
    	em[797] = 775; em[798] = 32; 
    	em[799] = 775; em[800] = 56; 
    em[801] = 1; em[802] = 8; em[803] = 1; /* 801: pointer.unsigned char */
    	em[804] = 806; em[805] = 0; 
    em[806] = 0; em[807] = 1; em[808] = 0; /* 806: unsigned char */
    em[809] = 0; em[810] = 16; em[811] = 1; /* 809: struct.crypto_ex_data_st */
    	em[812] = 814; em[813] = 0; 
    em[814] = 1; em[815] = 8; em[816] = 1; /* 814: pointer.struct.stack_st_void */
    	em[817] = 819; em[818] = 0; 
    em[819] = 0; em[820] = 32; em[821] = 1; /* 819: struct.stack_st_void */
    	em[822] = 824; em[823] = 0; 
    em[824] = 0; em[825] = 32; em[826] = 2; /* 824: struct.stack_st */
    	em[827] = 89; em[828] = 8; 
    	em[829] = 99; em[830] = 24; 
    em[831] = 1; em[832] = 8; em[833] = 1; /* 831: pointer.struct.dh_method */
    	em[834] = 836; em[835] = 0; 
    em[836] = 0; em[837] = 72; em[838] = 8; /* 836: struct.dh_method */
    	em[839] = 132; em[840] = 0; 
    	em[841] = 855; em[842] = 8; 
    	em[843] = 858; em[844] = 16; 
    	em[845] = 861; em[846] = 24; 
    	em[847] = 855; em[848] = 32; 
    	em[849] = 855; em[850] = 40; 
    	em[851] = 94; em[852] = 56; 
    	em[853] = 864; em[854] = 64; 
    em[855] = 8884097; em[856] = 8; em[857] = 0; /* 855: pointer.func */
    em[858] = 8884097; em[859] = 8; em[860] = 0; /* 858: pointer.func */
    em[861] = 8884097; em[862] = 8; em[863] = 0; /* 861: pointer.func */
    em[864] = 8884097; em[865] = 8; em[866] = 0; /* 864: pointer.func */
    em[867] = 1; em[868] = 8; em[869] = 1; /* 867: pointer.struct.engine_st */
    	em[870] = 163; em[871] = 0; 
    em[872] = 1; em[873] = 8; em[874] = 1; /* 872: pointer.struct.ec_key_st */
    	em[875] = 877; em[876] = 0; 
    em[877] = 0; em[878] = 56; em[879] = 4; /* 877: struct.ec_key_st */
    	em[880] = 888; em[881] = 8; 
    	em[882] = 1336; em[883] = 16; 
    	em[884] = 1341; em[885] = 24; 
    	em[886] = 1358; em[887] = 48; 
    em[888] = 1; em[889] = 8; em[890] = 1; /* 888: pointer.struct.ec_group_st */
    	em[891] = 893; em[892] = 0; 
    em[893] = 0; em[894] = 232; em[895] = 12; /* 893: struct.ec_group_st */
    	em[896] = 920; em[897] = 0; 
    	em[898] = 1092; em[899] = 8; 
    	em[900] = 1292; em[901] = 16; 
    	em[902] = 1292; em[903] = 40; 
    	em[904] = 801; em[905] = 80; 
    	em[906] = 1304; em[907] = 96; 
    	em[908] = 1292; em[909] = 104; 
    	em[910] = 1292; em[911] = 152; 
    	em[912] = 1292; em[913] = 176; 
    	em[914] = 705; em[915] = 208; 
    	em[916] = 705; em[917] = 216; 
    	em[918] = 1333; em[919] = 224; 
    em[920] = 1; em[921] = 8; em[922] = 1; /* 920: pointer.struct.ec_method_st */
    	em[923] = 925; em[924] = 0; 
    em[925] = 0; em[926] = 304; em[927] = 37; /* 925: struct.ec_method_st */
    	em[928] = 1002; em[929] = 8; 
    	em[930] = 1005; em[931] = 16; 
    	em[932] = 1005; em[933] = 24; 
    	em[934] = 1008; em[935] = 32; 
    	em[936] = 1011; em[937] = 40; 
    	em[938] = 1014; em[939] = 48; 
    	em[940] = 1017; em[941] = 56; 
    	em[942] = 1020; em[943] = 64; 
    	em[944] = 1023; em[945] = 72; 
    	em[946] = 1026; em[947] = 80; 
    	em[948] = 1026; em[949] = 88; 
    	em[950] = 1029; em[951] = 96; 
    	em[952] = 1032; em[953] = 104; 
    	em[954] = 1035; em[955] = 112; 
    	em[956] = 1038; em[957] = 120; 
    	em[958] = 1041; em[959] = 128; 
    	em[960] = 1044; em[961] = 136; 
    	em[962] = 1047; em[963] = 144; 
    	em[964] = 1050; em[965] = 152; 
    	em[966] = 1053; em[967] = 160; 
    	em[968] = 1056; em[969] = 168; 
    	em[970] = 1059; em[971] = 176; 
    	em[972] = 1062; em[973] = 184; 
    	em[974] = 1065; em[975] = 192; 
    	em[976] = 1068; em[977] = 200; 
    	em[978] = 1071; em[979] = 208; 
    	em[980] = 1062; em[981] = 216; 
    	em[982] = 1074; em[983] = 224; 
    	em[984] = 1077; em[985] = 232; 
    	em[986] = 1080; em[987] = 240; 
    	em[988] = 1017; em[989] = 248; 
    	em[990] = 1083; em[991] = 256; 
    	em[992] = 1086; em[993] = 264; 
    	em[994] = 1083; em[995] = 272; 
    	em[996] = 1086; em[997] = 280; 
    	em[998] = 1086; em[999] = 288; 
    	em[1000] = 1089; em[1001] = 296; 
    em[1002] = 8884097; em[1003] = 8; em[1004] = 0; /* 1002: pointer.func */
    em[1005] = 8884097; em[1006] = 8; em[1007] = 0; /* 1005: pointer.func */
    em[1008] = 8884097; em[1009] = 8; em[1010] = 0; /* 1008: pointer.func */
    em[1011] = 8884097; em[1012] = 8; em[1013] = 0; /* 1011: pointer.func */
    em[1014] = 8884097; em[1015] = 8; em[1016] = 0; /* 1014: pointer.func */
    em[1017] = 8884097; em[1018] = 8; em[1019] = 0; /* 1017: pointer.func */
    em[1020] = 8884097; em[1021] = 8; em[1022] = 0; /* 1020: pointer.func */
    em[1023] = 8884097; em[1024] = 8; em[1025] = 0; /* 1023: pointer.func */
    em[1026] = 8884097; em[1027] = 8; em[1028] = 0; /* 1026: pointer.func */
    em[1029] = 8884097; em[1030] = 8; em[1031] = 0; /* 1029: pointer.func */
    em[1032] = 8884097; em[1033] = 8; em[1034] = 0; /* 1032: pointer.func */
    em[1035] = 8884097; em[1036] = 8; em[1037] = 0; /* 1035: pointer.func */
    em[1038] = 8884097; em[1039] = 8; em[1040] = 0; /* 1038: pointer.func */
    em[1041] = 8884097; em[1042] = 8; em[1043] = 0; /* 1041: pointer.func */
    em[1044] = 8884097; em[1045] = 8; em[1046] = 0; /* 1044: pointer.func */
    em[1047] = 8884097; em[1048] = 8; em[1049] = 0; /* 1047: pointer.func */
    em[1050] = 8884097; em[1051] = 8; em[1052] = 0; /* 1050: pointer.func */
    em[1053] = 8884097; em[1054] = 8; em[1055] = 0; /* 1053: pointer.func */
    em[1056] = 8884097; em[1057] = 8; em[1058] = 0; /* 1056: pointer.func */
    em[1059] = 8884097; em[1060] = 8; em[1061] = 0; /* 1059: pointer.func */
    em[1062] = 8884097; em[1063] = 8; em[1064] = 0; /* 1062: pointer.func */
    em[1065] = 8884097; em[1066] = 8; em[1067] = 0; /* 1065: pointer.func */
    em[1068] = 8884097; em[1069] = 8; em[1070] = 0; /* 1068: pointer.func */
    em[1071] = 8884097; em[1072] = 8; em[1073] = 0; /* 1071: pointer.func */
    em[1074] = 8884097; em[1075] = 8; em[1076] = 0; /* 1074: pointer.func */
    em[1077] = 8884097; em[1078] = 8; em[1079] = 0; /* 1077: pointer.func */
    em[1080] = 8884097; em[1081] = 8; em[1082] = 0; /* 1080: pointer.func */
    em[1083] = 8884097; em[1084] = 8; em[1085] = 0; /* 1083: pointer.func */
    em[1086] = 8884097; em[1087] = 8; em[1088] = 0; /* 1086: pointer.func */
    em[1089] = 8884097; em[1090] = 8; em[1091] = 0; /* 1089: pointer.func */
    em[1092] = 1; em[1093] = 8; em[1094] = 1; /* 1092: pointer.struct.ec_point_st */
    	em[1095] = 1097; em[1096] = 0; 
    em[1097] = 0; em[1098] = 88; em[1099] = 4; /* 1097: struct.ec_point_st */
    	em[1100] = 1108; em[1101] = 0; 
    	em[1102] = 1280; em[1103] = 8; 
    	em[1104] = 1280; em[1105] = 32; 
    	em[1106] = 1280; em[1107] = 56; 
    em[1108] = 1; em[1109] = 8; em[1110] = 1; /* 1108: pointer.struct.ec_method_st */
    	em[1111] = 1113; em[1112] = 0; 
    em[1113] = 0; em[1114] = 304; em[1115] = 37; /* 1113: struct.ec_method_st */
    	em[1116] = 1190; em[1117] = 8; 
    	em[1118] = 1193; em[1119] = 16; 
    	em[1120] = 1193; em[1121] = 24; 
    	em[1122] = 1196; em[1123] = 32; 
    	em[1124] = 1199; em[1125] = 40; 
    	em[1126] = 1202; em[1127] = 48; 
    	em[1128] = 1205; em[1129] = 56; 
    	em[1130] = 1208; em[1131] = 64; 
    	em[1132] = 1211; em[1133] = 72; 
    	em[1134] = 1214; em[1135] = 80; 
    	em[1136] = 1214; em[1137] = 88; 
    	em[1138] = 1217; em[1139] = 96; 
    	em[1140] = 1220; em[1141] = 104; 
    	em[1142] = 1223; em[1143] = 112; 
    	em[1144] = 1226; em[1145] = 120; 
    	em[1146] = 1229; em[1147] = 128; 
    	em[1148] = 1232; em[1149] = 136; 
    	em[1150] = 1235; em[1151] = 144; 
    	em[1152] = 1238; em[1153] = 152; 
    	em[1154] = 1241; em[1155] = 160; 
    	em[1156] = 1244; em[1157] = 168; 
    	em[1158] = 1247; em[1159] = 176; 
    	em[1160] = 1250; em[1161] = 184; 
    	em[1162] = 1253; em[1163] = 192; 
    	em[1164] = 1256; em[1165] = 200; 
    	em[1166] = 1259; em[1167] = 208; 
    	em[1168] = 1250; em[1169] = 216; 
    	em[1170] = 1262; em[1171] = 224; 
    	em[1172] = 1265; em[1173] = 232; 
    	em[1174] = 1268; em[1175] = 240; 
    	em[1176] = 1205; em[1177] = 248; 
    	em[1178] = 1271; em[1179] = 256; 
    	em[1180] = 1274; em[1181] = 264; 
    	em[1182] = 1271; em[1183] = 272; 
    	em[1184] = 1274; em[1185] = 280; 
    	em[1186] = 1274; em[1187] = 288; 
    	em[1188] = 1277; em[1189] = 296; 
    em[1190] = 8884097; em[1191] = 8; em[1192] = 0; /* 1190: pointer.func */
    em[1193] = 8884097; em[1194] = 8; em[1195] = 0; /* 1193: pointer.func */
    em[1196] = 8884097; em[1197] = 8; em[1198] = 0; /* 1196: pointer.func */
    em[1199] = 8884097; em[1200] = 8; em[1201] = 0; /* 1199: pointer.func */
    em[1202] = 8884097; em[1203] = 8; em[1204] = 0; /* 1202: pointer.func */
    em[1205] = 8884097; em[1206] = 8; em[1207] = 0; /* 1205: pointer.func */
    em[1208] = 8884097; em[1209] = 8; em[1210] = 0; /* 1208: pointer.func */
    em[1211] = 8884097; em[1212] = 8; em[1213] = 0; /* 1211: pointer.func */
    em[1214] = 8884097; em[1215] = 8; em[1216] = 0; /* 1214: pointer.func */
    em[1217] = 8884097; em[1218] = 8; em[1219] = 0; /* 1217: pointer.func */
    em[1220] = 8884097; em[1221] = 8; em[1222] = 0; /* 1220: pointer.func */
    em[1223] = 8884097; em[1224] = 8; em[1225] = 0; /* 1223: pointer.func */
    em[1226] = 8884097; em[1227] = 8; em[1228] = 0; /* 1226: pointer.func */
    em[1229] = 8884097; em[1230] = 8; em[1231] = 0; /* 1229: pointer.func */
    em[1232] = 8884097; em[1233] = 8; em[1234] = 0; /* 1232: pointer.func */
    em[1235] = 8884097; em[1236] = 8; em[1237] = 0; /* 1235: pointer.func */
    em[1238] = 8884097; em[1239] = 8; em[1240] = 0; /* 1238: pointer.func */
    em[1241] = 8884097; em[1242] = 8; em[1243] = 0; /* 1241: pointer.func */
    em[1244] = 8884097; em[1245] = 8; em[1246] = 0; /* 1244: pointer.func */
    em[1247] = 8884097; em[1248] = 8; em[1249] = 0; /* 1247: pointer.func */
    em[1250] = 8884097; em[1251] = 8; em[1252] = 0; /* 1250: pointer.func */
    em[1253] = 8884097; em[1254] = 8; em[1255] = 0; /* 1253: pointer.func */
    em[1256] = 8884097; em[1257] = 8; em[1258] = 0; /* 1256: pointer.func */
    em[1259] = 8884097; em[1260] = 8; em[1261] = 0; /* 1259: pointer.func */
    em[1262] = 8884097; em[1263] = 8; em[1264] = 0; /* 1262: pointer.func */
    em[1265] = 8884097; em[1266] = 8; em[1267] = 0; /* 1265: pointer.func */
    em[1268] = 8884097; em[1269] = 8; em[1270] = 0; /* 1268: pointer.func */
    em[1271] = 8884097; em[1272] = 8; em[1273] = 0; /* 1271: pointer.func */
    em[1274] = 8884097; em[1275] = 8; em[1276] = 0; /* 1274: pointer.func */
    em[1277] = 8884097; em[1278] = 8; em[1279] = 0; /* 1277: pointer.func */
    em[1280] = 0; em[1281] = 24; em[1282] = 1; /* 1280: struct.bignum_st */
    	em[1283] = 1285; em[1284] = 0; 
    em[1285] = 8884099; em[1286] = 8; em[1287] = 2; /* 1285: pointer_to_array_of_pointers_to_stack */
    	em[1288] = 47; em[1289] = 0; 
    	em[1290] = 50; em[1291] = 12; 
    em[1292] = 0; em[1293] = 24; em[1294] = 1; /* 1292: struct.bignum_st */
    	em[1295] = 1297; em[1296] = 0; 
    em[1297] = 8884099; em[1298] = 8; em[1299] = 2; /* 1297: pointer_to_array_of_pointers_to_stack */
    	em[1300] = 47; em[1301] = 0; 
    	em[1302] = 50; em[1303] = 12; 
    em[1304] = 1; em[1305] = 8; em[1306] = 1; /* 1304: pointer.struct.ec_extra_data_st */
    	em[1307] = 1309; em[1308] = 0; 
    em[1309] = 0; em[1310] = 40; em[1311] = 5; /* 1309: struct.ec_extra_data_st */
    	em[1312] = 1322; em[1313] = 0; 
    	em[1314] = 705; em[1315] = 8; 
    	em[1316] = 1327; em[1317] = 16; 
    	em[1318] = 1330; em[1319] = 24; 
    	em[1320] = 1330; em[1321] = 32; 
    em[1322] = 1; em[1323] = 8; em[1324] = 1; /* 1322: pointer.struct.ec_extra_data_st */
    	em[1325] = 1309; em[1326] = 0; 
    em[1327] = 8884097; em[1328] = 8; em[1329] = 0; /* 1327: pointer.func */
    em[1330] = 8884097; em[1331] = 8; em[1332] = 0; /* 1330: pointer.func */
    em[1333] = 8884097; em[1334] = 8; em[1335] = 0; /* 1333: pointer.func */
    em[1336] = 1; em[1337] = 8; em[1338] = 1; /* 1336: pointer.struct.ec_point_st */
    	em[1339] = 1097; em[1340] = 0; 
    em[1341] = 1; em[1342] = 8; em[1343] = 1; /* 1341: pointer.struct.bignum_st */
    	em[1344] = 1346; em[1345] = 0; 
    em[1346] = 0; em[1347] = 24; em[1348] = 1; /* 1346: struct.bignum_st */
    	em[1349] = 1351; em[1350] = 0; 
    em[1351] = 8884099; em[1352] = 8; em[1353] = 2; /* 1351: pointer_to_array_of_pointers_to_stack */
    	em[1354] = 47; em[1355] = 0; 
    	em[1356] = 50; em[1357] = 12; 
    em[1358] = 1; em[1359] = 8; em[1360] = 1; /* 1358: pointer.struct.ec_extra_data_st */
    	em[1361] = 1363; em[1362] = 0; 
    em[1363] = 0; em[1364] = 40; em[1365] = 5; /* 1363: struct.ec_extra_data_st */
    	em[1366] = 1376; em[1367] = 0; 
    	em[1368] = 705; em[1369] = 8; 
    	em[1370] = 1327; em[1371] = 16; 
    	em[1372] = 1330; em[1373] = 24; 
    	em[1374] = 1330; em[1375] = 32; 
    em[1376] = 1; em[1377] = 8; em[1378] = 1; /* 1376: pointer.struct.ec_extra_data_st */
    	em[1379] = 1363; em[1380] = 0; 
    em[1381] = 1; em[1382] = 8; em[1383] = 1; /* 1381: pointer.int */
    	em[1384] = 50; em[1385] = 0; 
    em[1386] = 8884097; em[1387] = 8; em[1388] = 0; /* 1386: pointer.func */
    em[1389] = 0; em[1390] = 0; em[1391] = 0; /* 1389: struct.ASN1_VALUE_st */
    em[1392] = 1; em[1393] = 8; em[1394] = 1; /* 1392: pointer.struct.ASN1_VALUE_st */
    	em[1395] = 1389; em[1396] = 0; 
    em[1397] = 1; em[1398] = 8; em[1399] = 1; /* 1397: pointer.struct.asn1_string_st */
    	em[1400] = 1402; em[1401] = 0; 
    em[1402] = 0; em[1403] = 24; em[1404] = 1; /* 1402: struct.asn1_string_st */
    	em[1405] = 801; em[1406] = 8; 
    em[1407] = 1; em[1408] = 8; em[1409] = 1; /* 1407: pointer.struct.asn1_string_st */
    	em[1410] = 1402; em[1411] = 0; 
    em[1412] = 1; em[1413] = 8; em[1414] = 1; /* 1412: pointer.struct.asn1_string_st */
    	em[1415] = 1402; em[1416] = 0; 
    em[1417] = 1; em[1418] = 8; em[1419] = 1; /* 1417: pointer.struct.asn1_string_st */
    	em[1420] = 1402; em[1421] = 0; 
    em[1422] = 1; em[1423] = 8; em[1424] = 1; /* 1422: pointer.struct.asn1_string_st */
    	em[1425] = 1402; em[1426] = 0; 
    em[1427] = 1; em[1428] = 8; em[1429] = 1; /* 1427: pointer.struct.asn1_string_st */
    	em[1430] = 1402; em[1431] = 0; 
    em[1432] = 1; em[1433] = 8; em[1434] = 1; /* 1432: pointer.struct.asn1_string_st */
    	em[1435] = 1402; em[1436] = 0; 
    em[1437] = 1; em[1438] = 8; em[1439] = 1; /* 1437: pointer.struct.asn1_string_st */
    	em[1440] = 1402; em[1441] = 0; 
    em[1442] = 0; em[1443] = 16; em[1444] = 1; /* 1442: struct.asn1_type_st */
    	em[1445] = 1447; em[1446] = 8; 
    em[1447] = 0; em[1448] = 8; em[1449] = 20; /* 1447: union.unknown */
    	em[1450] = 94; em[1451] = 0; 
    	em[1452] = 1437; em[1453] = 0; 
    	em[1454] = 1490; em[1455] = 0; 
    	em[1456] = 1509; em[1457] = 0; 
    	em[1458] = 1432; em[1459] = 0; 
    	em[1460] = 1514; em[1461] = 0; 
    	em[1462] = 1427; em[1463] = 0; 
    	em[1464] = 1519; em[1465] = 0; 
    	em[1466] = 1422; em[1467] = 0; 
    	em[1468] = 1417; em[1469] = 0; 
    	em[1470] = 1412; em[1471] = 0; 
    	em[1472] = 1407; em[1473] = 0; 
    	em[1474] = 1524; em[1475] = 0; 
    	em[1476] = 1529; em[1477] = 0; 
    	em[1478] = 1534; em[1479] = 0; 
    	em[1480] = 1539; em[1481] = 0; 
    	em[1482] = 1397; em[1483] = 0; 
    	em[1484] = 1437; em[1485] = 0; 
    	em[1486] = 1437; em[1487] = 0; 
    	em[1488] = 1392; em[1489] = 0; 
    em[1490] = 1; em[1491] = 8; em[1492] = 1; /* 1490: pointer.struct.asn1_object_st */
    	em[1493] = 1495; em[1494] = 0; 
    em[1495] = 0; em[1496] = 40; em[1497] = 3; /* 1495: struct.asn1_object_st */
    	em[1498] = 132; em[1499] = 0; 
    	em[1500] = 132; em[1501] = 8; 
    	em[1502] = 1504; em[1503] = 24; 
    em[1504] = 1; em[1505] = 8; em[1506] = 1; /* 1504: pointer.unsigned char */
    	em[1507] = 806; em[1508] = 0; 
    em[1509] = 1; em[1510] = 8; em[1511] = 1; /* 1509: pointer.struct.asn1_string_st */
    	em[1512] = 1402; em[1513] = 0; 
    em[1514] = 1; em[1515] = 8; em[1516] = 1; /* 1514: pointer.struct.asn1_string_st */
    	em[1517] = 1402; em[1518] = 0; 
    em[1519] = 1; em[1520] = 8; em[1521] = 1; /* 1519: pointer.struct.asn1_string_st */
    	em[1522] = 1402; em[1523] = 0; 
    em[1524] = 1; em[1525] = 8; em[1526] = 1; /* 1524: pointer.struct.asn1_string_st */
    	em[1527] = 1402; em[1528] = 0; 
    em[1529] = 1; em[1530] = 8; em[1531] = 1; /* 1529: pointer.struct.asn1_string_st */
    	em[1532] = 1402; em[1533] = 0; 
    em[1534] = 1; em[1535] = 8; em[1536] = 1; /* 1534: pointer.struct.asn1_string_st */
    	em[1537] = 1402; em[1538] = 0; 
    em[1539] = 1; em[1540] = 8; em[1541] = 1; /* 1539: pointer.struct.asn1_string_st */
    	em[1542] = 1402; em[1543] = 0; 
    em[1544] = 0; em[1545] = 0; em[1546] = 0; /* 1544: struct.ASN1_VALUE_st */
    em[1547] = 1; em[1548] = 8; em[1549] = 1; /* 1547: pointer.struct.asn1_string_st */
    	em[1550] = 1552; em[1551] = 0; 
    em[1552] = 0; em[1553] = 24; em[1554] = 1; /* 1552: struct.asn1_string_st */
    	em[1555] = 801; em[1556] = 8; 
    em[1557] = 1; em[1558] = 8; em[1559] = 1; /* 1557: pointer.struct.asn1_string_st */
    	em[1560] = 1552; em[1561] = 0; 
    em[1562] = 1; em[1563] = 8; em[1564] = 1; /* 1562: pointer.struct.asn1_string_st */
    	em[1565] = 1552; em[1566] = 0; 
    em[1567] = 1; em[1568] = 8; em[1569] = 1; /* 1567: pointer.struct.asn1_string_st */
    	em[1570] = 1552; em[1571] = 0; 
    em[1572] = 1; em[1573] = 8; em[1574] = 1; /* 1572: pointer.struct.asn1_string_st */
    	em[1575] = 1552; em[1576] = 0; 
    em[1577] = 1; em[1578] = 8; em[1579] = 1; /* 1577: pointer.struct.asn1_string_st */
    	em[1580] = 1552; em[1581] = 0; 
    em[1582] = 1; em[1583] = 8; em[1584] = 1; /* 1582: pointer.struct.asn1_string_st */
    	em[1585] = 1552; em[1586] = 0; 
    em[1587] = 1; em[1588] = 8; em[1589] = 1; /* 1587: pointer.struct.asn1_string_st */
    	em[1590] = 1552; em[1591] = 0; 
    em[1592] = 0; em[1593] = 0; em[1594] = 1; /* 1592: ASN1_TYPE */
    	em[1595] = 1597; em[1596] = 0; 
    em[1597] = 0; em[1598] = 16; em[1599] = 1; /* 1597: struct.asn1_type_st */
    	em[1600] = 1602; em[1601] = 8; 
    em[1602] = 0; em[1603] = 8; em[1604] = 20; /* 1602: union.unknown */
    	em[1605] = 94; em[1606] = 0; 
    	em[1607] = 1587; em[1608] = 0; 
    	em[1609] = 1645; em[1610] = 0; 
    	em[1611] = 1582; em[1612] = 0; 
    	em[1613] = 1659; em[1614] = 0; 
    	em[1615] = 1577; em[1616] = 0; 
    	em[1617] = 1664; em[1618] = 0; 
    	em[1619] = 1572; em[1620] = 0; 
    	em[1621] = 1669; em[1622] = 0; 
    	em[1623] = 1567; em[1624] = 0; 
    	em[1625] = 1674; em[1626] = 0; 
    	em[1627] = 1679; em[1628] = 0; 
    	em[1629] = 1684; em[1630] = 0; 
    	em[1631] = 1689; em[1632] = 0; 
    	em[1633] = 1562; em[1634] = 0; 
    	em[1635] = 1557; em[1636] = 0; 
    	em[1637] = 1547; em[1638] = 0; 
    	em[1639] = 1587; em[1640] = 0; 
    	em[1641] = 1587; em[1642] = 0; 
    	em[1643] = 1694; em[1644] = 0; 
    em[1645] = 1; em[1646] = 8; em[1647] = 1; /* 1645: pointer.struct.asn1_object_st */
    	em[1648] = 1650; em[1649] = 0; 
    em[1650] = 0; em[1651] = 40; em[1652] = 3; /* 1650: struct.asn1_object_st */
    	em[1653] = 132; em[1654] = 0; 
    	em[1655] = 132; em[1656] = 8; 
    	em[1657] = 1504; em[1658] = 24; 
    em[1659] = 1; em[1660] = 8; em[1661] = 1; /* 1659: pointer.struct.asn1_string_st */
    	em[1662] = 1552; em[1663] = 0; 
    em[1664] = 1; em[1665] = 8; em[1666] = 1; /* 1664: pointer.struct.asn1_string_st */
    	em[1667] = 1552; em[1668] = 0; 
    em[1669] = 1; em[1670] = 8; em[1671] = 1; /* 1669: pointer.struct.asn1_string_st */
    	em[1672] = 1552; em[1673] = 0; 
    em[1674] = 1; em[1675] = 8; em[1676] = 1; /* 1674: pointer.struct.asn1_string_st */
    	em[1677] = 1552; em[1678] = 0; 
    em[1679] = 1; em[1680] = 8; em[1681] = 1; /* 1679: pointer.struct.asn1_string_st */
    	em[1682] = 1552; em[1683] = 0; 
    em[1684] = 1; em[1685] = 8; em[1686] = 1; /* 1684: pointer.struct.asn1_string_st */
    	em[1687] = 1552; em[1688] = 0; 
    em[1689] = 1; em[1690] = 8; em[1691] = 1; /* 1689: pointer.struct.asn1_string_st */
    	em[1692] = 1552; em[1693] = 0; 
    em[1694] = 1; em[1695] = 8; em[1696] = 1; /* 1694: pointer.struct.ASN1_VALUE_st */
    	em[1697] = 1544; em[1698] = 0; 
    em[1699] = 1; em[1700] = 8; em[1701] = 1; /* 1699: pointer.struct.stack_st_ASN1_TYPE */
    	em[1702] = 1704; em[1703] = 0; 
    em[1704] = 0; em[1705] = 32; em[1706] = 2; /* 1704: struct.stack_st_fake_ASN1_TYPE */
    	em[1707] = 1711; em[1708] = 8; 
    	em[1709] = 99; em[1710] = 24; 
    em[1711] = 8884099; em[1712] = 8; em[1713] = 2; /* 1711: pointer_to_array_of_pointers_to_stack */
    	em[1714] = 1718; em[1715] = 0; 
    	em[1716] = 50; em[1717] = 20; 
    em[1718] = 0; em[1719] = 8; em[1720] = 1; /* 1718: pointer.ASN1_TYPE */
    	em[1721] = 1592; em[1722] = 0; 
    em[1723] = 0; em[1724] = 24; em[1725] = 2; /* 1723: struct.x509_attributes_st */
    	em[1726] = 1490; em[1727] = 0; 
    	em[1728] = 1730; em[1729] = 16; 
    em[1730] = 0; em[1731] = 8; em[1732] = 3; /* 1730: union.unknown */
    	em[1733] = 94; em[1734] = 0; 
    	em[1735] = 1699; em[1736] = 0; 
    	em[1737] = 1739; em[1738] = 0; 
    em[1739] = 1; em[1740] = 8; em[1741] = 1; /* 1739: pointer.struct.asn1_type_st */
    	em[1742] = 1442; em[1743] = 0; 
    em[1744] = 0; em[1745] = 32; em[1746] = 2; /* 1744: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1747] = 1751; em[1748] = 8; 
    	em[1749] = 99; em[1750] = 24; 
    em[1751] = 8884099; em[1752] = 8; em[1753] = 2; /* 1751: pointer_to_array_of_pointers_to_stack */
    	em[1754] = 1758; em[1755] = 0; 
    	em[1756] = 50; em[1757] = 20; 
    em[1758] = 0; em[1759] = 8; em[1760] = 1; /* 1758: pointer.X509_ATTRIBUTE */
    	em[1761] = 1763; em[1762] = 0; 
    em[1763] = 0; em[1764] = 0; em[1765] = 1; /* 1763: X509_ATTRIBUTE */
    	em[1766] = 1723; em[1767] = 0; 
    em[1768] = 0; em[1769] = 48; em[1770] = 5; /* 1768: struct.env_md_ctx_st */
    	em[1771] = 1781; em[1772] = 0; 
    	em[1773] = 867; em[1774] = 8; 
    	em[1775] = 705; em[1776] = 24; 
    	em[1777] = 1826; em[1778] = 32; 
    	em[1779] = 1808; em[1780] = 40; 
    em[1781] = 1; em[1782] = 8; em[1783] = 1; /* 1781: pointer.struct.env_md_st */
    	em[1784] = 1786; em[1785] = 0; 
    em[1786] = 0; em[1787] = 120; em[1788] = 8; /* 1786: struct.env_md_st */
    	em[1789] = 1805; em[1790] = 24; 
    	em[1791] = 1808; em[1792] = 32; 
    	em[1793] = 1811; em[1794] = 40; 
    	em[1795] = 1814; em[1796] = 48; 
    	em[1797] = 1805; em[1798] = 56; 
    	em[1799] = 1817; em[1800] = 64; 
    	em[1801] = 1820; em[1802] = 72; 
    	em[1803] = 1823; em[1804] = 112; 
    em[1805] = 8884097; em[1806] = 8; em[1807] = 0; /* 1805: pointer.func */
    em[1808] = 8884097; em[1809] = 8; em[1810] = 0; /* 1808: pointer.func */
    em[1811] = 8884097; em[1812] = 8; em[1813] = 0; /* 1811: pointer.func */
    em[1814] = 8884097; em[1815] = 8; em[1816] = 0; /* 1814: pointer.func */
    em[1817] = 8884097; em[1818] = 8; em[1819] = 0; /* 1817: pointer.func */
    em[1820] = 8884097; em[1821] = 8; em[1822] = 0; /* 1820: pointer.func */
    em[1823] = 8884097; em[1824] = 8; em[1825] = 0; /* 1823: pointer.func */
    em[1826] = 1; em[1827] = 8; em[1828] = 1; /* 1826: pointer.struct.evp_pkey_ctx_st */
    	em[1829] = 1831; em[1830] = 0; 
    em[1831] = 0; em[1832] = 80; em[1833] = 8; /* 1831: struct.evp_pkey_ctx_st */
    	em[1834] = 1850; em[1835] = 0; 
    	em[1836] = 867; em[1837] = 8; 
    	em[1838] = 1944; em[1839] = 16; 
    	em[1840] = 1944; em[1841] = 24; 
    	em[1842] = 705; em[1843] = 40; 
    	em[1844] = 705; em[1845] = 48; 
    	em[1846] = 1386; em[1847] = 56; 
    	em[1848] = 1381; em[1849] = 64; 
    em[1850] = 1; em[1851] = 8; em[1852] = 1; /* 1850: pointer.struct.evp_pkey_method_st */
    	em[1853] = 1855; em[1854] = 0; 
    em[1855] = 0; em[1856] = 208; em[1857] = 25; /* 1855: struct.evp_pkey_method_st */
    	em[1858] = 1908; em[1859] = 8; 
    	em[1860] = 1911; em[1861] = 16; 
    	em[1862] = 1914; em[1863] = 24; 
    	em[1864] = 1908; em[1865] = 32; 
    	em[1866] = 1917; em[1867] = 40; 
    	em[1868] = 1908; em[1869] = 48; 
    	em[1870] = 1917; em[1871] = 56; 
    	em[1872] = 1908; em[1873] = 64; 
    	em[1874] = 1920; em[1875] = 72; 
    	em[1876] = 1908; em[1877] = 80; 
    	em[1878] = 1923; em[1879] = 88; 
    	em[1880] = 1908; em[1881] = 96; 
    	em[1882] = 1920; em[1883] = 104; 
    	em[1884] = 1926; em[1885] = 112; 
    	em[1886] = 1929; em[1887] = 120; 
    	em[1888] = 1926; em[1889] = 128; 
    	em[1890] = 1932; em[1891] = 136; 
    	em[1892] = 1908; em[1893] = 144; 
    	em[1894] = 1920; em[1895] = 152; 
    	em[1896] = 1908; em[1897] = 160; 
    	em[1898] = 1920; em[1899] = 168; 
    	em[1900] = 1908; em[1901] = 176; 
    	em[1902] = 1935; em[1903] = 184; 
    	em[1904] = 1938; em[1905] = 192; 
    	em[1906] = 1941; em[1907] = 200; 
    em[1908] = 8884097; em[1909] = 8; em[1910] = 0; /* 1908: pointer.func */
    em[1911] = 8884097; em[1912] = 8; em[1913] = 0; /* 1911: pointer.func */
    em[1914] = 8884097; em[1915] = 8; em[1916] = 0; /* 1914: pointer.func */
    em[1917] = 8884097; em[1918] = 8; em[1919] = 0; /* 1917: pointer.func */
    em[1920] = 8884097; em[1921] = 8; em[1922] = 0; /* 1920: pointer.func */
    em[1923] = 8884097; em[1924] = 8; em[1925] = 0; /* 1923: pointer.func */
    em[1926] = 8884097; em[1927] = 8; em[1928] = 0; /* 1926: pointer.func */
    em[1929] = 8884097; em[1930] = 8; em[1931] = 0; /* 1929: pointer.func */
    em[1932] = 8884097; em[1933] = 8; em[1934] = 0; /* 1932: pointer.func */
    em[1935] = 8884097; em[1936] = 8; em[1937] = 0; /* 1935: pointer.func */
    em[1938] = 8884097; em[1939] = 8; em[1940] = 0; /* 1938: pointer.func */
    em[1941] = 8884097; em[1942] = 8; em[1943] = 0; /* 1941: pointer.func */
    em[1944] = 1; em[1945] = 8; em[1946] = 1; /* 1944: pointer.struct.evp_pkey_st */
    	em[1947] = 1949; em[1948] = 0; 
    em[1949] = 0; em[1950] = 56; em[1951] = 4; /* 1949: struct.evp_pkey_st */
    	em[1952] = 1960; em[1953] = 16; 
    	em[1954] = 867; em[1955] = 24; 
    	em[1956] = 2061; em[1957] = 32; 
    	em[1958] = 2089; em[1959] = 48; 
    em[1960] = 1; em[1961] = 8; em[1962] = 1; /* 1960: pointer.struct.evp_pkey_asn1_method_st */
    	em[1963] = 1965; em[1964] = 0; 
    em[1965] = 0; em[1966] = 208; em[1967] = 24; /* 1965: struct.evp_pkey_asn1_method_st */
    	em[1968] = 94; em[1969] = 16; 
    	em[1970] = 94; em[1971] = 24; 
    	em[1972] = 2016; em[1973] = 32; 
    	em[1974] = 2019; em[1975] = 40; 
    	em[1976] = 2022; em[1977] = 48; 
    	em[1978] = 2025; em[1979] = 56; 
    	em[1980] = 2028; em[1981] = 64; 
    	em[1982] = 2031; em[1983] = 72; 
    	em[1984] = 2025; em[1985] = 80; 
    	em[1986] = 2034; em[1987] = 88; 
    	em[1988] = 2034; em[1989] = 96; 
    	em[1990] = 2037; em[1991] = 104; 
    	em[1992] = 2040; em[1993] = 112; 
    	em[1994] = 2034; em[1995] = 120; 
    	em[1996] = 2043; em[1997] = 128; 
    	em[1998] = 2022; em[1999] = 136; 
    	em[2000] = 2025; em[2001] = 144; 
    	em[2002] = 2046; em[2003] = 152; 
    	em[2004] = 2049; em[2005] = 160; 
    	em[2006] = 2052; em[2007] = 168; 
    	em[2008] = 2037; em[2009] = 176; 
    	em[2010] = 2040; em[2011] = 184; 
    	em[2012] = 2055; em[2013] = 192; 
    	em[2014] = 2058; em[2015] = 200; 
    em[2016] = 8884097; em[2017] = 8; em[2018] = 0; /* 2016: pointer.func */
    em[2019] = 8884097; em[2020] = 8; em[2021] = 0; /* 2019: pointer.func */
    em[2022] = 8884097; em[2023] = 8; em[2024] = 0; /* 2022: pointer.func */
    em[2025] = 8884097; em[2026] = 8; em[2027] = 0; /* 2025: pointer.func */
    em[2028] = 8884097; em[2029] = 8; em[2030] = 0; /* 2028: pointer.func */
    em[2031] = 8884097; em[2032] = 8; em[2033] = 0; /* 2031: pointer.func */
    em[2034] = 8884097; em[2035] = 8; em[2036] = 0; /* 2034: pointer.func */
    em[2037] = 8884097; em[2038] = 8; em[2039] = 0; /* 2037: pointer.func */
    em[2040] = 8884097; em[2041] = 8; em[2042] = 0; /* 2040: pointer.func */
    em[2043] = 8884097; em[2044] = 8; em[2045] = 0; /* 2043: pointer.func */
    em[2046] = 8884097; em[2047] = 8; em[2048] = 0; /* 2046: pointer.func */
    em[2049] = 8884097; em[2050] = 8; em[2051] = 0; /* 2049: pointer.func */
    em[2052] = 8884097; em[2053] = 8; em[2054] = 0; /* 2052: pointer.func */
    em[2055] = 8884097; em[2056] = 8; em[2057] = 0; /* 2055: pointer.func */
    em[2058] = 8884097; em[2059] = 8; em[2060] = 0; /* 2058: pointer.func */
    em[2061] = 0; em[2062] = 8; em[2063] = 5; /* 2061: union.unknown */
    	em[2064] = 94; em[2065] = 0; 
    	em[2066] = 2074; em[2067] = 0; 
    	em[2068] = 2079; em[2069] = 0; 
    	em[2070] = 2084; em[2071] = 0; 
    	em[2072] = 872; em[2073] = 0; 
    em[2074] = 1; em[2075] = 8; em[2076] = 1; /* 2074: pointer.struct.rsa_st */
    	em[2077] = 511; em[2078] = 0; 
    em[2079] = 1; em[2080] = 8; em[2081] = 1; /* 2079: pointer.struct.dsa_st */
    	em[2082] = 5; em[2083] = 0; 
    em[2084] = 1; em[2085] = 8; em[2086] = 1; /* 2084: pointer.struct.dh_st */
    	em[2087] = 743; em[2088] = 0; 
    em[2089] = 1; em[2090] = 8; em[2091] = 1; /* 2089: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[2092] = 2094; em[2093] = 0; 
    em[2094] = 0; em[2095] = 32; em[2096] = 2; /* 2094: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[2097] = 2101; em[2098] = 8; 
    	em[2099] = 99; em[2100] = 24; 
    em[2101] = 8884099; em[2102] = 8; em[2103] = 2; /* 2101: pointer_to_array_of_pointers_to_stack */
    	em[2104] = 2108; em[2105] = 0; 
    	em[2106] = 50; em[2107] = 20; 
    em[2108] = 0; em[2109] = 8; em[2110] = 1; /* 2108: pointer.X509_ATTRIBUTE */
    	em[2111] = 1763; em[2112] = 0; 
    em[2113] = 0; em[2114] = 1; em[2115] = 0; /* 2113: char */
    em[2116] = 1; em[2117] = 8; em[2118] = 1; /* 2116: pointer.struct.evp_pkey_st */
    	em[2119] = 2121; em[2120] = 0; 
    em[2121] = 0; em[2122] = 56; em[2123] = 4; /* 2121: struct.evp_pkey_st */
    	em[2124] = 1960; em[2125] = 16; 
    	em[2126] = 867; em[2127] = 24; 
    	em[2128] = 725; em[2129] = 32; 
    	em[2130] = 2132; em[2131] = 48; 
    em[2132] = 1; em[2133] = 8; em[2134] = 1; /* 2132: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[2135] = 1744; em[2136] = 0; 
    em[2137] = 1; em[2138] = 8; em[2139] = 1; /* 2137: pointer.struct.env_md_ctx_st */
    	em[2140] = 1768; em[2141] = 0; 
    em[2142] = 1; em[2143] = 8; em[2144] = 1; /* 2142: pointer.unsigned int */
    	em[2145] = 47; em[2146] = 0; 
    args_addr->arg_entity_index[0] = 2137;
    args_addr->arg_entity_index[1] = 801;
    args_addr->arg_entity_index[2] = 2142;
    args_addr->arg_entity_index[3] = 2116;
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

