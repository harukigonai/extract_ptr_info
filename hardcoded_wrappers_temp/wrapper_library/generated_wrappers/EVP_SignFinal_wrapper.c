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
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.int */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 4; em[7] = 0; /* 5: int */
    em[8] = 8884097; em[9] = 8; em[10] = 0; /* 8: pointer.func */
    em[11] = 1; em[12] = 8; em[13] = 1; /* 11: pointer.struct.ASN1_VALUE_st */
    	em[14] = 16; em[15] = 0; 
    em[16] = 0; em[17] = 0; em[18] = 0; /* 16: struct.ASN1_VALUE_st */
    em[19] = 1; em[20] = 8; em[21] = 1; /* 19: pointer.struct.asn1_string_st */
    	em[22] = 24; em[23] = 0; 
    em[24] = 0; em[25] = 24; em[26] = 1; /* 24: struct.asn1_string_st */
    	em[27] = 29; em[28] = 8; 
    em[29] = 1; em[30] = 8; em[31] = 1; /* 29: pointer.unsigned char */
    	em[32] = 34; em[33] = 0; 
    em[34] = 0; em[35] = 1; em[36] = 0; /* 34: unsigned char */
    em[37] = 1; em[38] = 8; em[39] = 1; /* 37: pointer.struct.asn1_string_st */
    	em[40] = 24; em[41] = 0; 
    em[42] = 1; em[43] = 8; em[44] = 1; /* 42: pointer.struct.rsa_st */
    	em[45] = 47; em[46] = 0; 
    em[47] = 0; em[48] = 168; em[49] = 17; /* 47: struct.rsa_st */
    	em[50] = 84; em[51] = 16; 
    	em[52] = 149; em[53] = 24; 
    	em[54] = 495; em[55] = 32; 
    	em[56] = 495; em[57] = 40; 
    	em[58] = 495; em[59] = 48; 
    	em[60] = 495; em[61] = 56; 
    	em[62] = 495; em[63] = 64; 
    	em[64] = 495; em[65] = 72; 
    	em[66] = 495; em[67] = 80; 
    	em[68] = 495; em[69] = 88; 
    	em[70] = 515; em[71] = 96; 
    	em[72] = 529; em[73] = 120; 
    	em[74] = 529; em[75] = 128; 
    	em[76] = 529; em[77] = 136; 
    	em[78] = 135; em[79] = 144; 
    	em[80] = 543; em[81] = 152; 
    	em[82] = 543; em[83] = 160; 
    em[84] = 1; em[85] = 8; em[86] = 1; /* 84: pointer.struct.rsa_meth_st */
    	em[87] = 89; em[88] = 0; 
    em[89] = 0; em[90] = 112; em[91] = 13; /* 89: struct.rsa_meth_st */
    	em[92] = 118; em[93] = 0; 
    	em[94] = 123; em[95] = 8; 
    	em[96] = 123; em[97] = 16; 
    	em[98] = 123; em[99] = 24; 
    	em[100] = 123; em[101] = 32; 
    	em[102] = 126; em[103] = 40; 
    	em[104] = 129; em[105] = 48; 
    	em[106] = 132; em[107] = 56; 
    	em[108] = 132; em[109] = 64; 
    	em[110] = 135; em[111] = 80; 
    	em[112] = 140; em[113] = 88; 
    	em[114] = 143; em[115] = 96; 
    	em[116] = 146; em[117] = 104; 
    em[118] = 1; em[119] = 8; em[120] = 1; /* 118: pointer.char */
    	em[121] = 8884096; em[122] = 0; 
    em[123] = 8884097; em[124] = 8; em[125] = 0; /* 123: pointer.func */
    em[126] = 8884097; em[127] = 8; em[128] = 0; /* 126: pointer.func */
    em[129] = 8884097; em[130] = 8; em[131] = 0; /* 129: pointer.func */
    em[132] = 8884097; em[133] = 8; em[134] = 0; /* 132: pointer.func */
    em[135] = 1; em[136] = 8; em[137] = 1; /* 135: pointer.char */
    	em[138] = 8884096; em[139] = 0; 
    em[140] = 8884097; em[141] = 8; em[142] = 0; /* 140: pointer.func */
    em[143] = 8884097; em[144] = 8; em[145] = 0; /* 143: pointer.func */
    em[146] = 8884097; em[147] = 8; em[148] = 0; /* 146: pointer.func */
    em[149] = 1; em[150] = 8; em[151] = 1; /* 149: pointer.struct.engine_st */
    	em[152] = 154; em[153] = 0; 
    em[154] = 0; em[155] = 216; em[156] = 24; /* 154: struct.engine_st */
    	em[157] = 118; em[158] = 0; 
    	em[159] = 118; em[160] = 8; 
    	em[161] = 205; em[162] = 16; 
    	em[163] = 260; em[164] = 24; 
    	em[165] = 311; em[166] = 32; 
    	em[167] = 347; em[168] = 40; 
    	em[169] = 364; em[170] = 48; 
    	em[171] = 391; em[172] = 56; 
    	em[173] = 426; em[174] = 64; 
    	em[175] = 434; em[176] = 72; 
    	em[177] = 437; em[178] = 80; 
    	em[179] = 440; em[180] = 88; 
    	em[181] = 443; em[182] = 96; 
    	em[183] = 446; em[184] = 104; 
    	em[185] = 446; em[186] = 112; 
    	em[187] = 446; em[188] = 120; 
    	em[189] = 449; em[190] = 128; 
    	em[191] = 452; em[192] = 136; 
    	em[193] = 452; em[194] = 144; 
    	em[195] = 455; em[196] = 152; 
    	em[197] = 458; em[198] = 160; 
    	em[199] = 470; em[200] = 184; 
    	em[201] = 490; em[202] = 200; 
    	em[203] = 490; em[204] = 208; 
    em[205] = 1; em[206] = 8; em[207] = 1; /* 205: pointer.struct.rsa_meth_st */
    	em[208] = 210; em[209] = 0; 
    em[210] = 0; em[211] = 112; em[212] = 13; /* 210: struct.rsa_meth_st */
    	em[213] = 118; em[214] = 0; 
    	em[215] = 239; em[216] = 8; 
    	em[217] = 239; em[218] = 16; 
    	em[219] = 239; em[220] = 24; 
    	em[221] = 239; em[222] = 32; 
    	em[223] = 242; em[224] = 40; 
    	em[225] = 245; em[226] = 48; 
    	em[227] = 248; em[228] = 56; 
    	em[229] = 248; em[230] = 64; 
    	em[231] = 135; em[232] = 80; 
    	em[233] = 251; em[234] = 88; 
    	em[235] = 254; em[236] = 96; 
    	em[237] = 257; em[238] = 104; 
    em[239] = 8884097; em[240] = 8; em[241] = 0; /* 239: pointer.func */
    em[242] = 8884097; em[243] = 8; em[244] = 0; /* 242: pointer.func */
    em[245] = 8884097; em[246] = 8; em[247] = 0; /* 245: pointer.func */
    em[248] = 8884097; em[249] = 8; em[250] = 0; /* 248: pointer.func */
    em[251] = 8884097; em[252] = 8; em[253] = 0; /* 251: pointer.func */
    em[254] = 8884097; em[255] = 8; em[256] = 0; /* 254: pointer.func */
    em[257] = 8884097; em[258] = 8; em[259] = 0; /* 257: pointer.func */
    em[260] = 1; em[261] = 8; em[262] = 1; /* 260: pointer.struct.dsa_method */
    	em[263] = 265; em[264] = 0; 
    em[265] = 0; em[266] = 96; em[267] = 11; /* 265: struct.dsa_method */
    	em[268] = 118; em[269] = 0; 
    	em[270] = 290; em[271] = 8; 
    	em[272] = 293; em[273] = 16; 
    	em[274] = 296; em[275] = 24; 
    	em[276] = 299; em[277] = 32; 
    	em[278] = 302; em[279] = 40; 
    	em[280] = 305; em[281] = 48; 
    	em[282] = 305; em[283] = 56; 
    	em[284] = 135; em[285] = 72; 
    	em[286] = 308; em[287] = 80; 
    	em[288] = 305; em[289] = 88; 
    em[290] = 8884097; em[291] = 8; em[292] = 0; /* 290: pointer.func */
    em[293] = 8884097; em[294] = 8; em[295] = 0; /* 293: pointer.func */
    em[296] = 8884097; em[297] = 8; em[298] = 0; /* 296: pointer.func */
    em[299] = 8884097; em[300] = 8; em[301] = 0; /* 299: pointer.func */
    em[302] = 8884097; em[303] = 8; em[304] = 0; /* 302: pointer.func */
    em[305] = 8884097; em[306] = 8; em[307] = 0; /* 305: pointer.func */
    em[308] = 8884097; em[309] = 8; em[310] = 0; /* 308: pointer.func */
    em[311] = 1; em[312] = 8; em[313] = 1; /* 311: pointer.struct.dh_method */
    	em[314] = 316; em[315] = 0; 
    em[316] = 0; em[317] = 72; em[318] = 8; /* 316: struct.dh_method */
    	em[319] = 118; em[320] = 0; 
    	em[321] = 335; em[322] = 8; 
    	em[323] = 338; em[324] = 16; 
    	em[325] = 341; em[326] = 24; 
    	em[327] = 335; em[328] = 32; 
    	em[329] = 335; em[330] = 40; 
    	em[331] = 135; em[332] = 56; 
    	em[333] = 344; em[334] = 64; 
    em[335] = 8884097; em[336] = 8; em[337] = 0; /* 335: pointer.func */
    em[338] = 8884097; em[339] = 8; em[340] = 0; /* 338: pointer.func */
    em[341] = 8884097; em[342] = 8; em[343] = 0; /* 341: pointer.func */
    em[344] = 8884097; em[345] = 8; em[346] = 0; /* 344: pointer.func */
    em[347] = 1; em[348] = 8; em[349] = 1; /* 347: pointer.struct.ecdh_method */
    	em[350] = 352; em[351] = 0; 
    em[352] = 0; em[353] = 32; em[354] = 3; /* 352: struct.ecdh_method */
    	em[355] = 118; em[356] = 0; 
    	em[357] = 361; em[358] = 8; 
    	em[359] = 135; em[360] = 24; 
    em[361] = 8884097; em[362] = 8; em[363] = 0; /* 361: pointer.func */
    em[364] = 1; em[365] = 8; em[366] = 1; /* 364: pointer.struct.ecdsa_method */
    	em[367] = 369; em[368] = 0; 
    em[369] = 0; em[370] = 48; em[371] = 5; /* 369: struct.ecdsa_method */
    	em[372] = 118; em[373] = 0; 
    	em[374] = 382; em[375] = 8; 
    	em[376] = 385; em[377] = 16; 
    	em[378] = 388; em[379] = 24; 
    	em[380] = 135; em[381] = 40; 
    em[382] = 8884097; em[383] = 8; em[384] = 0; /* 382: pointer.func */
    em[385] = 8884097; em[386] = 8; em[387] = 0; /* 385: pointer.func */
    em[388] = 8884097; em[389] = 8; em[390] = 0; /* 388: pointer.func */
    em[391] = 1; em[392] = 8; em[393] = 1; /* 391: pointer.struct.rand_meth_st */
    	em[394] = 396; em[395] = 0; 
    em[396] = 0; em[397] = 48; em[398] = 6; /* 396: struct.rand_meth_st */
    	em[399] = 411; em[400] = 0; 
    	em[401] = 414; em[402] = 8; 
    	em[403] = 417; em[404] = 16; 
    	em[405] = 420; em[406] = 24; 
    	em[407] = 414; em[408] = 32; 
    	em[409] = 423; em[410] = 40; 
    em[411] = 8884097; em[412] = 8; em[413] = 0; /* 411: pointer.func */
    em[414] = 8884097; em[415] = 8; em[416] = 0; /* 414: pointer.func */
    em[417] = 8884097; em[418] = 8; em[419] = 0; /* 417: pointer.func */
    em[420] = 8884097; em[421] = 8; em[422] = 0; /* 420: pointer.func */
    em[423] = 8884097; em[424] = 8; em[425] = 0; /* 423: pointer.func */
    em[426] = 1; em[427] = 8; em[428] = 1; /* 426: pointer.struct.store_method_st */
    	em[429] = 431; em[430] = 0; 
    em[431] = 0; em[432] = 0; em[433] = 0; /* 431: struct.store_method_st */
    em[434] = 8884097; em[435] = 8; em[436] = 0; /* 434: pointer.func */
    em[437] = 8884097; em[438] = 8; em[439] = 0; /* 437: pointer.func */
    em[440] = 8884097; em[441] = 8; em[442] = 0; /* 440: pointer.func */
    em[443] = 8884097; em[444] = 8; em[445] = 0; /* 443: pointer.func */
    em[446] = 8884097; em[447] = 8; em[448] = 0; /* 446: pointer.func */
    em[449] = 8884097; em[450] = 8; em[451] = 0; /* 449: pointer.func */
    em[452] = 8884097; em[453] = 8; em[454] = 0; /* 452: pointer.func */
    em[455] = 8884097; em[456] = 8; em[457] = 0; /* 455: pointer.func */
    em[458] = 1; em[459] = 8; em[460] = 1; /* 458: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[461] = 463; em[462] = 0; 
    em[463] = 0; em[464] = 32; em[465] = 2; /* 463: struct.ENGINE_CMD_DEFN_st */
    	em[466] = 118; em[467] = 8; 
    	em[468] = 118; em[469] = 16; 
    em[470] = 0; em[471] = 32; em[472] = 2; /* 470: struct.crypto_ex_data_st_fake */
    	em[473] = 477; em[474] = 8; 
    	em[475] = 487; em[476] = 24; 
    em[477] = 8884099; em[478] = 8; em[479] = 2; /* 477: pointer_to_array_of_pointers_to_stack */
    	em[480] = 484; em[481] = 0; 
    	em[482] = 5; em[483] = 20; 
    em[484] = 0; em[485] = 8; em[486] = 0; /* 484: pointer.void */
    em[487] = 8884097; em[488] = 8; em[489] = 0; /* 487: pointer.func */
    em[490] = 1; em[491] = 8; em[492] = 1; /* 490: pointer.struct.engine_st */
    	em[493] = 154; em[494] = 0; 
    em[495] = 1; em[496] = 8; em[497] = 1; /* 495: pointer.struct.bignum_st */
    	em[498] = 500; em[499] = 0; 
    em[500] = 0; em[501] = 24; em[502] = 1; /* 500: struct.bignum_st */
    	em[503] = 505; em[504] = 0; 
    em[505] = 8884099; em[506] = 8; em[507] = 2; /* 505: pointer_to_array_of_pointers_to_stack */
    	em[508] = 512; em[509] = 0; 
    	em[510] = 5; em[511] = 12; 
    em[512] = 0; em[513] = 8; em[514] = 0; /* 512: long unsigned int */
    em[515] = 0; em[516] = 32; em[517] = 2; /* 515: struct.crypto_ex_data_st_fake */
    	em[518] = 522; em[519] = 8; 
    	em[520] = 487; em[521] = 24; 
    em[522] = 8884099; em[523] = 8; em[524] = 2; /* 522: pointer_to_array_of_pointers_to_stack */
    	em[525] = 484; em[526] = 0; 
    	em[527] = 5; em[528] = 20; 
    em[529] = 1; em[530] = 8; em[531] = 1; /* 529: pointer.struct.bn_mont_ctx_st */
    	em[532] = 534; em[533] = 0; 
    em[534] = 0; em[535] = 96; em[536] = 3; /* 534: struct.bn_mont_ctx_st */
    	em[537] = 500; em[538] = 8; 
    	em[539] = 500; em[540] = 32; 
    	em[541] = 500; em[542] = 56; 
    em[543] = 1; em[544] = 8; em[545] = 1; /* 543: pointer.struct.bn_blinding_st */
    	em[546] = 548; em[547] = 0; 
    em[548] = 0; em[549] = 88; em[550] = 7; /* 548: struct.bn_blinding_st */
    	em[551] = 565; em[552] = 0; 
    	em[553] = 565; em[554] = 8; 
    	em[555] = 565; em[556] = 16; 
    	em[557] = 565; em[558] = 24; 
    	em[559] = 582; em[560] = 40; 
    	em[561] = 587; em[562] = 72; 
    	em[563] = 601; em[564] = 80; 
    em[565] = 1; em[566] = 8; em[567] = 1; /* 565: pointer.struct.bignum_st */
    	em[568] = 570; em[569] = 0; 
    em[570] = 0; em[571] = 24; em[572] = 1; /* 570: struct.bignum_st */
    	em[573] = 575; em[574] = 0; 
    em[575] = 8884099; em[576] = 8; em[577] = 2; /* 575: pointer_to_array_of_pointers_to_stack */
    	em[578] = 512; em[579] = 0; 
    	em[580] = 5; em[581] = 12; 
    em[582] = 0; em[583] = 16; em[584] = 1; /* 582: struct.crypto_threadid_st */
    	em[585] = 484; em[586] = 0; 
    em[587] = 1; em[588] = 8; em[589] = 1; /* 587: pointer.struct.bn_mont_ctx_st */
    	em[590] = 592; em[591] = 0; 
    em[592] = 0; em[593] = 96; em[594] = 3; /* 592: struct.bn_mont_ctx_st */
    	em[595] = 570; em[596] = 8; 
    	em[597] = 570; em[598] = 32; 
    	em[599] = 570; em[600] = 56; 
    em[601] = 8884097; em[602] = 8; em[603] = 0; /* 601: pointer.func */
    em[604] = 1; em[605] = 8; em[606] = 1; /* 604: pointer.struct.asn1_string_st */
    	em[607] = 24; em[608] = 0; 
    em[609] = 1; em[610] = 8; em[611] = 1; /* 609: pointer.struct.asn1_string_st */
    	em[612] = 24; em[613] = 0; 
    em[614] = 1; em[615] = 8; em[616] = 1; /* 614: pointer.struct.asn1_string_st */
    	em[617] = 24; em[618] = 0; 
    em[619] = 1; em[620] = 8; em[621] = 1; /* 619: pointer.struct.asn1_string_st */
    	em[622] = 24; em[623] = 0; 
    em[624] = 1; em[625] = 8; em[626] = 1; /* 624: pointer.struct.asn1_string_st */
    	em[627] = 24; em[628] = 0; 
    em[629] = 1; em[630] = 8; em[631] = 1; /* 629: pointer.struct.asn1_string_st */
    	em[632] = 24; em[633] = 0; 
    em[634] = 1; em[635] = 8; em[636] = 1; /* 634: pointer.struct.asn1_string_st */
    	em[637] = 24; em[638] = 0; 
    em[639] = 0; em[640] = 8; em[641] = 20; /* 639: union.unknown */
    	em[642] = 135; em[643] = 0; 
    	em[644] = 682; em[645] = 0; 
    	em[646] = 687; em[647] = 0; 
    	em[648] = 706; em[649] = 0; 
    	em[650] = 634; em[651] = 0; 
    	em[652] = 711; em[653] = 0; 
    	em[654] = 629; em[655] = 0; 
    	em[656] = 716; em[657] = 0; 
    	em[658] = 624; em[659] = 0; 
    	em[660] = 619; em[661] = 0; 
    	em[662] = 614; em[663] = 0; 
    	em[664] = 609; em[665] = 0; 
    	em[666] = 604; em[667] = 0; 
    	em[668] = 721; em[669] = 0; 
    	em[670] = 37; em[671] = 0; 
    	em[672] = 726; em[673] = 0; 
    	em[674] = 19; em[675] = 0; 
    	em[676] = 682; em[677] = 0; 
    	em[678] = 682; em[679] = 0; 
    	em[680] = 11; em[681] = 0; 
    em[682] = 1; em[683] = 8; em[684] = 1; /* 682: pointer.struct.asn1_string_st */
    	em[685] = 24; em[686] = 0; 
    em[687] = 1; em[688] = 8; em[689] = 1; /* 687: pointer.struct.asn1_object_st */
    	em[690] = 692; em[691] = 0; 
    em[692] = 0; em[693] = 40; em[694] = 3; /* 692: struct.asn1_object_st */
    	em[695] = 118; em[696] = 0; 
    	em[697] = 118; em[698] = 8; 
    	em[699] = 701; em[700] = 24; 
    em[701] = 1; em[702] = 8; em[703] = 1; /* 701: pointer.unsigned char */
    	em[704] = 34; em[705] = 0; 
    em[706] = 1; em[707] = 8; em[708] = 1; /* 706: pointer.struct.asn1_string_st */
    	em[709] = 24; em[710] = 0; 
    em[711] = 1; em[712] = 8; em[713] = 1; /* 711: pointer.struct.asn1_string_st */
    	em[714] = 24; em[715] = 0; 
    em[716] = 1; em[717] = 8; em[718] = 1; /* 716: pointer.struct.asn1_string_st */
    	em[719] = 24; em[720] = 0; 
    em[721] = 1; em[722] = 8; em[723] = 1; /* 721: pointer.struct.asn1_string_st */
    	em[724] = 24; em[725] = 0; 
    em[726] = 1; em[727] = 8; em[728] = 1; /* 726: pointer.struct.asn1_string_st */
    	em[729] = 24; em[730] = 0; 
    em[731] = 0; em[732] = 16; em[733] = 1; /* 731: struct.asn1_type_st */
    	em[734] = 639; em[735] = 8; 
    em[736] = 1; em[737] = 8; em[738] = 1; /* 736: pointer.struct.ASN1_VALUE_st */
    	em[739] = 741; em[740] = 0; 
    em[741] = 0; em[742] = 0; em[743] = 0; /* 741: struct.ASN1_VALUE_st */
    em[744] = 1; em[745] = 8; em[746] = 1; /* 744: pointer.struct.asn1_string_st */
    	em[747] = 749; em[748] = 0; 
    em[749] = 0; em[750] = 24; em[751] = 1; /* 749: struct.asn1_string_st */
    	em[752] = 29; em[753] = 8; 
    em[754] = 1; em[755] = 8; em[756] = 1; /* 754: pointer.struct.asn1_string_st */
    	em[757] = 749; em[758] = 0; 
    em[759] = 1; em[760] = 8; em[761] = 1; /* 759: pointer.struct.asn1_string_st */
    	em[762] = 749; em[763] = 0; 
    em[764] = 1; em[765] = 8; em[766] = 1; /* 764: pointer.struct.asn1_string_st */
    	em[767] = 749; em[768] = 0; 
    em[769] = 1; em[770] = 8; em[771] = 1; /* 769: pointer.struct.asn1_string_st */
    	em[772] = 749; em[773] = 0; 
    em[774] = 1; em[775] = 8; em[776] = 1; /* 774: pointer.struct.asn1_string_st */
    	em[777] = 749; em[778] = 0; 
    em[779] = 0; em[780] = 40; em[781] = 3; /* 779: struct.asn1_object_st */
    	em[782] = 118; em[783] = 0; 
    	em[784] = 118; em[785] = 8; 
    	em[786] = 701; em[787] = 24; 
    em[788] = 1; em[789] = 8; em[790] = 1; /* 788: pointer.struct.asn1_string_st */
    	em[791] = 749; em[792] = 0; 
    em[793] = 0; em[794] = 0; em[795] = 1; /* 793: ASN1_TYPE */
    	em[796] = 798; em[797] = 0; 
    em[798] = 0; em[799] = 16; em[800] = 1; /* 798: struct.asn1_type_st */
    	em[801] = 803; em[802] = 8; 
    em[803] = 0; em[804] = 8; em[805] = 20; /* 803: union.unknown */
    	em[806] = 135; em[807] = 0; 
    	em[808] = 788; em[809] = 0; 
    	em[810] = 846; em[811] = 0; 
    	em[812] = 774; em[813] = 0; 
    	em[814] = 769; em[815] = 0; 
    	em[816] = 764; em[817] = 0; 
    	em[818] = 851; em[819] = 0; 
    	em[820] = 856; em[821] = 0; 
    	em[822] = 759; em[823] = 0; 
    	em[824] = 754; em[825] = 0; 
    	em[826] = 861; em[827] = 0; 
    	em[828] = 866; em[829] = 0; 
    	em[830] = 871; em[831] = 0; 
    	em[832] = 876; em[833] = 0; 
    	em[834] = 881; em[835] = 0; 
    	em[836] = 886; em[837] = 0; 
    	em[838] = 744; em[839] = 0; 
    	em[840] = 788; em[841] = 0; 
    	em[842] = 788; em[843] = 0; 
    	em[844] = 736; em[845] = 0; 
    em[846] = 1; em[847] = 8; em[848] = 1; /* 846: pointer.struct.asn1_object_st */
    	em[849] = 779; em[850] = 0; 
    em[851] = 1; em[852] = 8; em[853] = 1; /* 851: pointer.struct.asn1_string_st */
    	em[854] = 749; em[855] = 0; 
    em[856] = 1; em[857] = 8; em[858] = 1; /* 856: pointer.struct.asn1_string_st */
    	em[859] = 749; em[860] = 0; 
    em[861] = 1; em[862] = 8; em[863] = 1; /* 861: pointer.struct.asn1_string_st */
    	em[864] = 749; em[865] = 0; 
    em[866] = 1; em[867] = 8; em[868] = 1; /* 866: pointer.struct.asn1_string_st */
    	em[869] = 749; em[870] = 0; 
    em[871] = 1; em[872] = 8; em[873] = 1; /* 871: pointer.struct.asn1_string_st */
    	em[874] = 749; em[875] = 0; 
    em[876] = 1; em[877] = 8; em[878] = 1; /* 876: pointer.struct.asn1_string_st */
    	em[879] = 749; em[880] = 0; 
    em[881] = 1; em[882] = 8; em[883] = 1; /* 881: pointer.struct.asn1_string_st */
    	em[884] = 749; em[885] = 0; 
    em[886] = 1; em[887] = 8; em[888] = 1; /* 886: pointer.struct.asn1_string_st */
    	em[889] = 749; em[890] = 0; 
    em[891] = 1; em[892] = 8; em[893] = 1; /* 891: pointer.struct.stack_st_ASN1_TYPE */
    	em[894] = 896; em[895] = 0; 
    em[896] = 0; em[897] = 32; em[898] = 2; /* 896: struct.stack_st_fake_ASN1_TYPE */
    	em[899] = 903; em[900] = 8; 
    	em[901] = 487; em[902] = 24; 
    em[903] = 8884099; em[904] = 8; em[905] = 2; /* 903: pointer_to_array_of_pointers_to_stack */
    	em[906] = 910; em[907] = 0; 
    	em[908] = 5; em[909] = 20; 
    em[910] = 0; em[911] = 8; em[912] = 1; /* 910: pointer.ASN1_TYPE */
    	em[913] = 793; em[914] = 0; 
    em[915] = 0; em[916] = 8; em[917] = 3; /* 915: union.unknown */
    	em[918] = 135; em[919] = 0; 
    	em[920] = 891; em[921] = 0; 
    	em[922] = 924; em[923] = 0; 
    em[924] = 1; em[925] = 8; em[926] = 1; /* 924: pointer.struct.asn1_type_st */
    	em[927] = 731; em[928] = 0; 
    em[929] = 8884097; em[930] = 8; em[931] = 0; /* 929: pointer.func */
    em[932] = 1; em[933] = 8; em[934] = 1; /* 932: pointer.struct.ec_key_st */
    	em[935] = 937; em[936] = 0; 
    em[937] = 0; em[938] = 56; em[939] = 4; /* 937: struct.ec_key_st */
    	em[940] = 948; em[941] = 8; 
    	em[942] = 1393; em[943] = 16; 
    	em[944] = 1398; em[945] = 24; 
    	em[946] = 1415; em[947] = 48; 
    em[948] = 1; em[949] = 8; em[950] = 1; /* 948: pointer.struct.ec_group_st */
    	em[951] = 953; em[952] = 0; 
    em[953] = 0; em[954] = 232; em[955] = 12; /* 953: struct.ec_group_st */
    	em[956] = 980; em[957] = 0; 
    	em[958] = 1149; em[959] = 8; 
    	em[960] = 1349; em[961] = 16; 
    	em[962] = 1349; em[963] = 40; 
    	em[964] = 29; em[965] = 80; 
    	em[966] = 1361; em[967] = 96; 
    	em[968] = 1349; em[969] = 104; 
    	em[970] = 1349; em[971] = 152; 
    	em[972] = 1349; em[973] = 176; 
    	em[974] = 484; em[975] = 208; 
    	em[976] = 484; em[977] = 216; 
    	em[978] = 1390; em[979] = 224; 
    em[980] = 1; em[981] = 8; em[982] = 1; /* 980: pointer.struct.ec_method_st */
    	em[983] = 985; em[984] = 0; 
    em[985] = 0; em[986] = 304; em[987] = 37; /* 985: struct.ec_method_st */
    	em[988] = 1062; em[989] = 8; 
    	em[990] = 1065; em[991] = 16; 
    	em[992] = 1065; em[993] = 24; 
    	em[994] = 1068; em[995] = 32; 
    	em[996] = 929; em[997] = 40; 
    	em[998] = 1071; em[999] = 48; 
    	em[1000] = 1074; em[1001] = 56; 
    	em[1002] = 1077; em[1003] = 64; 
    	em[1004] = 1080; em[1005] = 72; 
    	em[1006] = 1083; em[1007] = 80; 
    	em[1008] = 1083; em[1009] = 88; 
    	em[1010] = 1086; em[1011] = 96; 
    	em[1012] = 1089; em[1013] = 104; 
    	em[1014] = 1092; em[1015] = 112; 
    	em[1016] = 1095; em[1017] = 120; 
    	em[1018] = 1098; em[1019] = 128; 
    	em[1020] = 1101; em[1021] = 136; 
    	em[1022] = 1104; em[1023] = 144; 
    	em[1024] = 1107; em[1025] = 152; 
    	em[1026] = 1110; em[1027] = 160; 
    	em[1028] = 1113; em[1029] = 168; 
    	em[1030] = 1116; em[1031] = 176; 
    	em[1032] = 1119; em[1033] = 184; 
    	em[1034] = 1122; em[1035] = 192; 
    	em[1036] = 1125; em[1037] = 200; 
    	em[1038] = 1128; em[1039] = 208; 
    	em[1040] = 1119; em[1041] = 216; 
    	em[1042] = 1131; em[1043] = 224; 
    	em[1044] = 1134; em[1045] = 232; 
    	em[1046] = 1137; em[1047] = 240; 
    	em[1048] = 1074; em[1049] = 248; 
    	em[1050] = 1140; em[1051] = 256; 
    	em[1052] = 1143; em[1053] = 264; 
    	em[1054] = 1140; em[1055] = 272; 
    	em[1056] = 1143; em[1057] = 280; 
    	em[1058] = 1143; em[1059] = 288; 
    	em[1060] = 1146; em[1061] = 296; 
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
    em[1092] = 8884097; em[1093] = 8; em[1094] = 0; /* 1092: pointer.func */
    em[1095] = 8884097; em[1096] = 8; em[1097] = 0; /* 1095: pointer.func */
    em[1098] = 8884097; em[1099] = 8; em[1100] = 0; /* 1098: pointer.func */
    em[1101] = 8884097; em[1102] = 8; em[1103] = 0; /* 1101: pointer.func */
    em[1104] = 8884097; em[1105] = 8; em[1106] = 0; /* 1104: pointer.func */
    em[1107] = 8884097; em[1108] = 8; em[1109] = 0; /* 1107: pointer.func */
    em[1110] = 8884097; em[1111] = 8; em[1112] = 0; /* 1110: pointer.func */
    em[1113] = 8884097; em[1114] = 8; em[1115] = 0; /* 1113: pointer.func */
    em[1116] = 8884097; em[1117] = 8; em[1118] = 0; /* 1116: pointer.func */
    em[1119] = 8884097; em[1120] = 8; em[1121] = 0; /* 1119: pointer.func */
    em[1122] = 8884097; em[1123] = 8; em[1124] = 0; /* 1122: pointer.func */
    em[1125] = 8884097; em[1126] = 8; em[1127] = 0; /* 1125: pointer.func */
    em[1128] = 8884097; em[1129] = 8; em[1130] = 0; /* 1128: pointer.func */
    em[1131] = 8884097; em[1132] = 8; em[1133] = 0; /* 1131: pointer.func */
    em[1134] = 8884097; em[1135] = 8; em[1136] = 0; /* 1134: pointer.func */
    em[1137] = 8884097; em[1138] = 8; em[1139] = 0; /* 1137: pointer.func */
    em[1140] = 8884097; em[1141] = 8; em[1142] = 0; /* 1140: pointer.func */
    em[1143] = 8884097; em[1144] = 8; em[1145] = 0; /* 1143: pointer.func */
    em[1146] = 8884097; em[1147] = 8; em[1148] = 0; /* 1146: pointer.func */
    em[1149] = 1; em[1150] = 8; em[1151] = 1; /* 1149: pointer.struct.ec_point_st */
    	em[1152] = 1154; em[1153] = 0; 
    em[1154] = 0; em[1155] = 88; em[1156] = 4; /* 1154: struct.ec_point_st */
    	em[1157] = 1165; em[1158] = 0; 
    	em[1159] = 1337; em[1160] = 8; 
    	em[1161] = 1337; em[1162] = 32; 
    	em[1163] = 1337; em[1164] = 56; 
    em[1165] = 1; em[1166] = 8; em[1167] = 1; /* 1165: pointer.struct.ec_method_st */
    	em[1168] = 1170; em[1169] = 0; 
    em[1170] = 0; em[1171] = 304; em[1172] = 37; /* 1170: struct.ec_method_st */
    	em[1173] = 1247; em[1174] = 8; 
    	em[1175] = 1250; em[1176] = 16; 
    	em[1177] = 1250; em[1178] = 24; 
    	em[1179] = 1253; em[1180] = 32; 
    	em[1181] = 1256; em[1182] = 40; 
    	em[1183] = 1259; em[1184] = 48; 
    	em[1185] = 1262; em[1186] = 56; 
    	em[1187] = 1265; em[1188] = 64; 
    	em[1189] = 1268; em[1190] = 72; 
    	em[1191] = 1271; em[1192] = 80; 
    	em[1193] = 1271; em[1194] = 88; 
    	em[1195] = 1274; em[1196] = 96; 
    	em[1197] = 1277; em[1198] = 104; 
    	em[1199] = 1280; em[1200] = 112; 
    	em[1201] = 1283; em[1202] = 120; 
    	em[1203] = 1286; em[1204] = 128; 
    	em[1205] = 1289; em[1206] = 136; 
    	em[1207] = 1292; em[1208] = 144; 
    	em[1209] = 1295; em[1210] = 152; 
    	em[1211] = 1298; em[1212] = 160; 
    	em[1213] = 1301; em[1214] = 168; 
    	em[1215] = 1304; em[1216] = 176; 
    	em[1217] = 1307; em[1218] = 184; 
    	em[1219] = 1310; em[1220] = 192; 
    	em[1221] = 1313; em[1222] = 200; 
    	em[1223] = 1316; em[1224] = 208; 
    	em[1225] = 1307; em[1226] = 216; 
    	em[1227] = 1319; em[1228] = 224; 
    	em[1229] = 1322; em[1230] = 232; 
    	em[1231] = 1325; em[1232] = 240; 
    	em[1233] = 1262; em[1234] = 248; 
    	em[1235] = 1328; em[1236] = 256; 
    	em[1237] = 1331; em[1238] = 264; 
    	em[1239] = 1328; em[1240] = 272; 
    	em[1241] = 1331; em[1242] = 280; 
    	em[1243] = 1331; em[1244] = 288; 
    	em[1245] = 1334; em[1246] = 296; 
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
    em[1280] = 8884097; em[1281] = 8; em[1282] = 0; /* 1280: pointer.func */
    em[1283] = 8884097; em[1284] = 8; em[1285] = 0; /* 1283: pointer.func */
    em[1286] = 8884097; em[1287] = 8; em[1288] = 0; /* 1286: pointer.func */
    em[1289] = 8884097; em[1290] = 8; em[1291] = 0; /* 1289: pointer.func */
    em[1292] = 8884097; em[1293] = 8; em[1294] = 0; /* 1292: pointer.func */
    em[1295] = 8884097; em[1296] = 8; em[1297] = 0; /* 1295: pointer.func */
    em[1298] = 8884097; em[1299] = 8; em[1300] = 0; /* 1298: pointer.func */
    em[1301] = 8884097; em[1302] = 8; em[1303] = 0; /* 1301: pointer.func */
    em[1304] = 8884097; em[1305] = 8; em[1306] = 0; /* 1304: pointer.func */
    em[1307] = 8884097; em[1308] = 8; em[1309] = 0; /* 1307: pointer.func */
    em[1310] = 8884097; em[1311] = 8; em[1312] = 0; /* 1310: pointer.func */
    em[1313] = 8884097; em[1314] = 8; em[1315] = 0; /* 1313: pointer.func */
    em[1316] = 8884097; em[1317] = 8; em[1318] = 0; /* 1316: pointer.func */
    em[1319] = 8884097; em[1320] = 8; em[1321] = 0; /* 1319: pointer.func */
    em[1322] = 8884097; em[1323] = 8; em[1324] = 0; /* 1322: pointer.func */
    em[1325] = 8884097; em[1326] = 8; em[1327] = 0; /* 1325: pointer.func */
    em[1328] = 8884097; em[1329] = 8; em[1330] = 0; /* 1328: pointer.func */
    em[1331] = 8884097; em[1332] = 8; em[1333] = 0; /* 1331: pointer.func */
    em[1334] = 8884097; em[1335] = 8; em[1336] = 0; /* 1334: pointer.func */
    em[1337] = 0; em[1338] = 24; em[1339] = 1; /* 1337: struct.bignum_st */
    	em[1340] = 1342; em[1341] = 0; 
    em[1342] = 8884099; em[1343] = 8; em[1344] = 2; /* 1342: pointer_to_array_of_pointers_to_stack */
    	em[1345] = 512; em[1346] = 0; 
    	em[1347] = 5; em[1348] = 12; 
    em[1349] = 0; em[1350] = 24; em[1351] = 1; /* 1349: struct.bignum_st */
    	em[1352] = 1354; em[1353] = 0; 
    em[1354] = 8884099; em[1355] = 8; em[1356] = 2; /* 1354: pointer_to_array_of_pointers_to_stack */
    	em[1357] = 512; em[1358] = 0; 
    	em[1359] = 5; em[1360] = 12; 
    em[1361] = 1; em[1362] = 8; em[1363] = 1; /* 1361: pointer.struct.ec_extra_data_st */
    	em[1364] = 1366; em[1365] = 0; 
    em[1366] = 0; em[1367] = 40; em[1368] = 5; /* 1366: struct.ec_extra_data_st */
    	em[1369] = 1379; em[1370] = 0; 
    	em[1371] = 484; em[1372] = 8; 
    	em[1373] = 1384; em[1374] = 16; 
    	em[1375] = 1387; em[1376] = 24; 
    	em[1377] = 1387; em[1378] = 32; 
    em[1379] = 1; em[1380] = 8; em[1381] = 1; /* 1379: pointer.struct.ec_extra_data_st */
    	em[1382] = 1366; em[1383] = 0; 
    em[1384] = 8884097; em[1385] = 8; em[1386] = 0; /* 1384: pointer.func */
    em[1387] = 8884097; em[1388] = 8; em[1389] = 0; /* 1387: pointer.func */
    em[1390] = 8884097; em[1391] = 8; em[1392] = 0; /* 1390: pointer.func */
    em[1393] = 1; em[1394] = 8; em[1395] = 1; /* 1393: pointer.struct.ec_point_st */
    	em[1396] = 1154; em[1397] = 0; 
    em[1398] = 1; em[1399] = 8; em[1400] = 1; /* 1398: pointer.struct.bignum_st */
    	em[1401] = 1403; em[1402] = 0; 
    em[1403] = 0; em[1404] = 24; em[1405] = 1; /* 1403: struct.bignum_st */
    	em[1406] = 1408; em[1407] = 0; 
    em[1408] = 8884099; em[1409] = 8; em[1410] = 2; /* 1408: pointer_to_array_of_pointers_to_stack */
    	em[1411] = 512; em[1412] = 0; 
    	em[1413] = 5; em[1414] = 12; 
    em[1415] = 1; em[1416] = 8; em[1417] = 1; /* 1415: pointer.struct.ec_extra_data_st */
    	em[1418] = 1420; em[1419] = 0; 
    em[1420] = 0; em[1421] = 40; em[1422] = 5; /* 1420: struct.ec_extra_data_st */
    	em[1423] = 1433; em[1424] = 0; 
    	em[1425] = 484; em[1426] = 8; 
    	em[1427] = 1384; em[1428] = 16; 
    	em[1429] = 1387; em[1430] = 24; 
    	em[1431] = 1387; em[1432] = 32; 
    em[1433] = 1; em[1434] = 8; em[1435] = 1; /* 1433: pointer.struct.ec_extra_data_st */
    	em[1436] = 1420; em[1437] = 0; 
    em[1438] = 8884097; em[1439] = 8; em[1440] = 0; /* 1438: pointer.func */
    em[1441] = 1; em[1442] = 8; em[1443] = 1; /* 1441: pointer.struct.env_md_st */
    	em[1444] = 1446; em[1445] = 0; 
    em[1446] = 0; em[1447] = 120; em[1448] = 8; /* 1446: struct.env_md_st */
    	em[1449] = 1465; em[1450] = 24; 
    	em[1451] = 1468; em[1452] = 32; 
    	em[1453] = 1471; em[1454] = 40; 
    	em[1455] = 1474; em[1456] = 48; 
    	em[1457] = 1465; em[1458] = 56; 
    	em[1459] = 1477; em[1460] = 64; 
    	em[1461] = 1480; em[1462] = 72; 
    	em[1463] = 1483; em[1464] = 112; 
    em[1465] = 8884097; em[1466] = 8; em[1467] = 0; /* 1465: pointer.func */
    em[1468] = 8884097; em[1469] = 8; em[1470] = 0; /* 1468: pointer.func */
    em[1471] = 8884097; em[1472] = 8; em[1473] = 0; /* 1471: pointer.func */
    em[1474] = 8884097; em[1475] = 8; em[1476] = 0; /* 1474: pointer.func */
    em[1477] = 8884097; em[1478] = 8; em[1479] = 0; /* 1477: pointer.func */
    em[1480] = 8884097; em[1481] = 8; em[1482] = 0; /* 1480: pointer.func */
    em[1483] = 8884097; em[1484] = 8; em[1485] = 0; /* 1483: pointer.func */
    em[1486] = 8884101; em[1487] = 8; em[1488] = 6; /* 1486: union.union_of_evp_pkey_st */
    	em[1489] = 484; em[1490] = 0; 
    	em[1491] = 42; em[1492] = 6; 
    	em[1493] = 1501; em[1494] = 116; 
    	em[1495] = 1632; em[1496] = 28; 
    	em[1497] = 932; em[1498] = 408; 
    	em[1499] = 5; em[1500] = 0; 
    em[1501] = 1; em[1502] = 8; em[1503] = 1; /* 1501: pointer.struct.dsa_st */
    	em[1504] = 1506; em[1505] = 0; 
    em[1506] = 0; em[1507] = 136; em[1508] = 11; /* 1506: struct.dsa_st */
    	em[1509] = 1531; em[1510] = 24; 
    	em[1511] = 1531; em[1512] = 32; 
    	em[1513] = 1531; em[1514] = 40; 
    	em[1515] = 1531; em[1516] = 48; 
    	em[1517] = 1531; em[1518] = 56; 
    	em[1519] = 1531; em[1520] = 64; 
    	em[1521] = 1531; em[1522] = 72; 
    	em[1523] = 1548; em[1524] = 88; 
    	em[1525] = 1562; em[1526] = 104; 
    	em[1527] = 1576; em[1528] = 120; 
    	em[1529] = 1627; em[1530] = 128; 
    em[1531] = 1; em[1532] = 8; em[1533] = 1; /* 1531: pointer.struct.bignum_st */
    	em[1534] = 1536; em[1535] = 0; 
    em[1536] = 0; em[1537] = 24; em[1538] = 1; /* 1536: struct.bignum_st */
    	em[1539] = 1541; em[1540] = 0; 
    em[1541] = 8884099; em[1542] = 8; em[1543] = 2; /* 1541: pointer_to_array_of_pointers_to_stack */
    	em[1544] = 512; em[1545] = 0; 
    	em[1546] = 5; em[1547] = 12; 
    em[1548] = 1; em[1549] = 8; em[1550] = 1; /* 1548: pointer.struct.bn_mont_ctx_st */
    	em[1551] = 1553; em[1552] = 0; 
    em[1553] = 0; em[1554] = 96; em[1555] = 3; /* 1553: struct.bn_mont_ctx_st */
    	em[1556] = 1536; em[1557] = 8; 
    	em[1558] = 1536; em[1559] = 32; 
    	em[1560] = 1536; em[1561] = 56; 
    em[1562] = 0; em[1563] = 32; em[1564] = 2; /* 1562: struct.crypto_ex_data_st_fake */
    	em[1565] = 1569; em[1566] = 8; 
    	em[1567] = 487; em[1568] = 24; 
    em[1569] = 8884099; em[1570] = 8; em[1571] = 2; /* 1569: pointer_to_array_of_pointers_to_stack */
    	em[1572] = 484; em[1573] = 0; 
    	em[1574] = 5; em[1575] = 20; 
    em[1576] = 1; em[1577] = 8; em[1578] = 1; /* 1576: pointer.struct.dsa_method */
    	em[1579] = 1581; em[1580] = 0; 
    em[1581] = 0; em[1582] = 96; em[1583] = 11; /* 1581: struct.dsa_method */
    	em[1584] = 118; em[1585] = 0; 
    	em[1586] = 1606; em[1587] = 8; 
    	em[1588] = 1609; em[1589] = 16; 
    	em[1590] = 1612; em[1591] = 24; 
    	em[1592] = 1615; em[1593] = 32; 
    	em[1594] = 1618; em[1595] = 40; 
    	em[1596] = 1621; em[1597] = 48; 
    	em[1598] = 1621; em[1599] = 56; 
    	em[1600] = 135; em[1601] = 72; 
    	em[1602] = 1624; em[1603] = 80; 
    	em[1604] = 1621; em[1605] = 88; 
    em[1606] = 8884097; em[1607] = 8; em[1608] = 0; /* 1606: pointer.func */
    em[1609] = 8884097; em[1610] = 8; em[1611] = 0; /* 1609: pointer.func */
    em[1612] = 8884097; em[1613] = 8; em[1614] = 0; /* 1612: pointer.func */
    em[1615] = 8884097; em[1616] = 8; em[1617] = 0; /* 1615: pointer.func */
    em[1618] = 8884097; em[1619] = 8; em[1620] = 0; /* 1618: pointer.func */
    em[1621] = 8884097; em[1622] = 8; em[1623] = 0; /* 1621: pointer.func */
    em[1624] = 8884097; em[1625] = 8; em[1626] = 0; /* 1624: pointer.func */
    em[1627] = 1; em[1628] = 8; em[1629] = 1; /* 1627: pointer.struct.engine_st */
    	em[1630] = 154; em[1631] = 0; 
    em[1632] = 1; em[1633] = 8; em[1634] = 1; /* 1632: pointer.struct.dh_st */
    	em[1635] = 1637; em[1636] = 0; 
    em[1637] = 0; em[1638] = 144; em[1639] = 12; /* 1637: struct.dh_st */
    	em[1640] = 1664; em[1641] = 8; 
    	em[1642] = 1664; em[1643] = 16; 
    	em[1644] = 1664; em[1645] = 32; 
    	em[1646] = 1664; em[1647] = 40; 
    	em[1648] = 1681; em[1649] = 56; 
    	em[1650] = 1664; em[1651] = 64; 
    	em[1652] = 1664; em[1653] = 72; 
    	em[1654] = 29; em[1655] = 80; 
    	em[1656] = 1664; em[1657] = 96; 
    	em[1658] = 1695; em[1659] = 112; 
    	em[1660] = 1709; em[1661] = 128; 
    	em[1662] = 1745; em[1663] = 136; 
    em[1664] = 1; em[1665] = 8; em[1666] = 1; /* 1664: pointer.struct.bignum_st */
    	em[1667] = 1669; em[1668] = 0; 
    em[1669] = 0; em[1670] = 24; em[1671] = 1; /* 1669: struct.bignum_st */
    	em[1672] = 1674; em[1673] = 0; 
    em[1674] = 8884099; em[1675] = 8; em[1676] = 2; /* 1674: pointer_to_array_of_pointers_to_stack */
    	em[1677] = 512; em[1678] = 0; 
    	em[1679] = 5; em[1680] = 12; 
    em[1681] = 1; em[1682] = 8; em[1683] = 1; /* 1681: pointer.struct.bn_mont_ctx_st */
    	em[1684] = 1686; em[1685] = 0; 
    em[1686] = 0; em[1687] = 96; em[1688] = 3; /* 1686: struct.bn_mont_ctx_st */
    	em[1689] = 1669; em[1690] = 8; 
    	em[1691] = 1669; em[1692] = 32; 
    	em[1693] = 1669; em[1694] = 56; 
    em[1695] = 0; em[1696] = 32; em[1697] = 2; /* 1695: struct.crypto_ex_data_st_fake */
    	em[1698] = 1702; em[1699] = 8; 
    	em[1700] = 487; em[1701] = 24; 
    em[1702] = 8884099; em[1703] = 8; em[1704] = 2; /* 1702: pointer_to_array_of_pointers_to_stack */
    	em[1705] = 484; em[1706] = 0; 
    	em[1707] = 5; em[1708] = 20; 
    em[1709] = 1; em[1710] = 8; em[1711] = 1; /* 1709: pointer.struct.dh_method */
    	em[1712] = 1714; em[1713] = 0; 
    em[1714] = 0; em[1715] = 72; em[1716] = 8; /* 1714: struct.dh_method */
    	em[1717] = 118; em[1718] = 0; 
    	em[1719] = 1733; em[1720] = 8; 
    	em[1721] = 1736; em[1722] = 16; 
    	em[1723] = 1739; em[1724] = 24; 
    	em[1725] = 1733; em[1726] = 32; 
    	em[1727] = 1733; em[1728] = 40; 
    	em[1729] = 135; em[1730] = 56; 
    	em[1731] = 1742; em[1732] = 64; 
    em[1733] = 8884097; em[1734] = 8; em[1735] = 0; /* 1733: pointer.func */
    em[1736] = 8884097; em[1737] = 8; em[1738] = 0; /* 1736: pointer.func */
    em[1739] = 8884097; em[1740] = 8; em[1741] = 0; /* 1739: pointer.func */
    em[1742] = 8884097; em[1743] = 8; em[1744] = 0; /* 1742: pointer.func */
    em[1745] = 1; em[1746] = 8; em[1747] = 1; /* 1745: pointer.struct.engine_st */
    	em[1748] = 154; em[1749] = 0; 
    em[1750] = 8884097; em[1751] = 8; em[1752] = 0; /* 1750: pointer.func */
    em[1753] = 8884097; em[1754] = 8; em[1755] = 0; /* 1753: pointer.func */
    em[1756] = 8884097; em[1757] = 8; em[1758] = 0; /* 1756: pointer.func */
    em[1759] = 8884097; em[1760] = 8; em[1761] = 0; /* 1759: pointer.func */
    em[1762] = 1; em[1763] = 8; em[1764] = 1; /* 1762: pointer.struct.evp_pkey_asn1_method_st */
    	em[1765] = 1767; em[1766] = 0; 
    em[1767] = 0; em[1768] = 208; em[1769] = 24; /* 1767: struct.evp_pkey_asn1_method_st */
    	em[1770] = 135; em[1771] = 16; 
    	em[1772] = 135; em[1773] = 24; 
    	em[1774] = 1759; em[1775] = 32; 
    	em[1776] = 1756; em[1777] = 40; 
    	em[1778] = 1438; em[1779] = 48; 
    	em[1780] = 1818; em[1781] = 56; 
    	em[1782] = 1821; em[1783] = 64; 
    	em[1784] = 1824; em[1785] = 72; 
    	em[1786] = 1818; em[1787] = 80; 
    	em[1788] = 1827; em[1789] = 88; 
    	em[1790] = 1827; em[1791] = 96; 
    	em[1792] = 1750; em[1793] = 104; 
    	em[1794] = 1830; em[1795] = 112; 
    	em[1796] = 1827; em[1797] = 120; 
    	em[1798] = 1753; em[1799] = 128; 
    	em[1800] = 1438; em[1801] = 136; 
    	em[1802] = 1818; em[1803] = 144; 
    	em[1804] = 1833; em[1805] = 152; 
    	em[1806] = 1836; em[1807] = 160; 
    	em[1808] = 1839; em[1809] = 168; 
    	em[1810] = 1750; em[1811] = 176; 
    	em[1812] = 1830; em[1813] = 184; 
    	em[1814] = 1842; em[1815] = 192; 
    	em[1816] = 1845; em[1817] = 200; 
    em[1818] = 8884097; em[1819] = 8; em[1820] = 0; /* 1818: pointer.func */
    em[1821] = 8884097; em[1822] = 8; em[1823] = 0; /* 1821: pointer.func */
    em[1824] = 8884097; em[1825] = 8; em[1826] = 0; /* 1824: pointer.func */
    em[1827] = 8884097; em[1828] = 8; em[1829] = 0; /* 1827: pointer.func */
    em[1830] = 8884097; em[1831] = 8; em[1832] = 0; /* 1830: pointer.func */
    em[1833] = 8884097; em[1834] = 8; em[1835] = 0; /* 1833: pointer.func */
    em[1836] = 8884097; em[1837] = 8; em[1838] = 0; /* 1836: pointer.func */
    em[1839] = 8884097; em[1840] = 8; em[1841] = 0; /* 1839: pointer.func */
    em[1842] = 8884097; em[1843] = 8; em[1844] = 0; /* 1842: pointer.func */
    em[1845] = 8884097; em[1846] = 8; em[1847] = 0; /* 1845: pointer.func */
    em[1848] = 8884097; em[1849] = 8; em[1850] = 0; /* 1848: pointer.func */
    em[1851] = 1; em[1852] = 8; em[1853] = 1; /* 1851: pointer.struct.evp_pkey_st */
    	em[1854] = 1856; em[1855] = 0; 
    em[1856] = 0; em[1857] = 56; em[1858] = 4; /* 1856: struct.evp_pkey_st */
    	em[1859] = 1762; em[1860] = 16; 
    	em[1861] = 1745; em[1862] = 24; 
    	em[1863] = 1486; em[1864] = 32; 
    	em[1865] = 1867; em[1866] = 48; 
    em[1867] = 1; em[1868] = 8; em[1869] = 1; /* 1867: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1870] = 1872; em[1871] = 0; 
    em[1872] = 0; em[1873] = 32; em[1874] = 2; /* 1872: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1875] = 1879; em[1876] = 8; 
    	em[1877] = 487; em[1878] = 24; 
    em[1879] = 8884099; em[1880] = 8; em[1881] = 2; /* 1879: pointer_to_array_of_pointers_to_stack */
    	em[1882] = 1886; em[1883] = 0; 
    	em[1884] = 5; em[1885] = 20; 
    em[1886] = 0; em[1887] = 8; em[1888] = 1; /* 1886: pointer.X509_ATTRIBUTE */
    	em[1889] = 1891; em[1890] = 0; 
    em[1891] = 0; em[1892] = 0; em[1893] = 1; /* 1891: X509_ATTRIBUTE */
    	em[1894] = 1896; em[1895] = 0; 
    em[1896] = 0; em[1897] = 24; em[1898] = 2; /* 1896: struct.x509_attributes_st */
    	em[1899] = 687; em[1900] = 0; 
    	em[1901] = 915; em[1902] = 16; 
    em[1903] = 0; em[1904] = 1; em[1905] = 0; /* 1903: char */
    em[1906] = 8884097; em[1907] = 8; em[1908] = 0; /* 1906: pointer.func */
    em[1909] = 8884097; em[1910] = 8; em[1911] = 0; /* 1909: pointer.func */
    em[1912] = 8884097; em[1913] = 8; em[1914] = 0; /* 1912: pointer.func */
    em[1915] = 8884097; em[1916] = 8; em[1917] = 0; /* 1915: pointer.func */
    em[1918] = 1; em[1919] = 8; em[1920] = 1; /* 1918: pointer.struct.evp_pkey_method_st */
    	em[1921] = 1923; em[1922] = 0; 
    em[1923] = 0; em[1924] = 208; em[1925] = 25; /* 1923: struct.evp_pkey_method_st */
    	em[1926] = 1912; em[1927] = 8; 
    	em[1928] = 1976; em[1929] = 16; 
    	em[1930] = 1979; em[1931] = 24; 
    	em[1932] = 1912; em[1933] = 32; 
    	em[1934] = 1915; em[1935] = 40; 
    	em[1936] = 1912; em[1937] = 48; 
    	em[1938] = 1915; em[1939] = 56; 
    	em[1940] = 1912; em[1941] = 64; 
    	em[1942] = 1982; em[1943] = 72; 
    	em[1944] = 1912; em[1945] = 80; 
    	em[1946] = 1985; em[1947] = 88; 
    	em[1948] = 1912; em[1949] = 96; 
    	em[1950] = 1982; em[1951] = 104; 
    	em[1952] = 1988; em[1953] = 112; 
    	em[1954] = 1909; em[1955] = 120; 
    	em[1956] = 1988; em[1957] = 128; 
    	em[1958] = 1991; em[1959] = 136; 
    	em[1960] = 1912; em[1961] = 144; 
    	em[1962] = 1982; em[1963] = 152; 
    	em[1964] = 1912; em[1965] = 160; 
    	em[1966] = 1982; em[1967] = 168; 
    	em[1968] = 1912; em[1969] = 176; 
    	em[1970] = 1906; em[1971] = 184; 
    	em[1972] = 1994; em[1973] = 192; 
    	em[1974] = 1848; em[1975] = 200; 
    em[1976] = 8884097; em[1977] = 8; em[1978] = 0; /* 1976: pointer.func */
    em[1979] = 8884097; em[1980] = 8; em[1981] = 0; /* 1979: pointer.func */
    em[1982] = 8884097; em[1983] = 8; em[1984] = 0; /* 1982: pointer.func */
    em[1985] = 8884097; em[1986] = 8; em[1987] = 0; /* 1985: pointer.func */
    em[1988] = 8884097; em[1989] = 8; em[1990] = 0; /* 1988: pointer.func */
    em[1991] = 8884097; em[1992] = 8; em[1993] = 0; /* 1991: pointer.func */
    em[1994] = 8884097; em[1995] = 8; em[1996] = 0; /* 1994: pointer.func */
    em[1997] = 0; em[1998] = 80; em[1999] = 8; /* 1997: struct.evp_pkey_ctx_st */
    	em[2000] = 1918; em[2001] = 0; 
    	em[2002] = 1745; em[2003] = 8; 
    	em[2004] = 2016; em[2005] = 16; 
    	em[2006] = 2016; em[2007] = 24; 
    	em[2008] = 484; em[2009] = 40; 
    	em[2010] = 484; em[2011] = 48; 
    	em[2012] = 8; em[2013] = 56; 
    	em[2014] = 0; em[2015] = 64; 
    em[2016] = 1; em[2017] = 8; em[2018] = 1; /* 2016: pointer.struct.evp_pkey_st */
    	em[2019] = 2021; em[2020] = 0; 
    em[2021] = 0; em[2022] = 56; em[2023] = 4; /* 2021: struct.evp_pkey_st */
    	em[2024] = 1762; em[2025] = 16; 
    	em[2026] = 1745; em[2027] = 24; 
    	em[2028] = 2032; em[2029] = 32; 
    	em[2030] = 2062; em[2031] = 48; 
    em[2032] = 8884101; em[2033] = 8; em[2034] = 6; /* 2032: union.union_of_evp_pkey_st */
    	em[2035] = 484; em[2036] = 0; 
    	em[2037] = 2047; em[2038] = 6; 
    	em[2039] = 2052; em[2040] = 116; 
    	em[2041] = 2057; em[2042] = 28; 
    	em[2043] = 932; em[2044] = 408; 
    	em[2045] = 5; em[2046] = 0; 
    em[2047] = 1; em[2048] = 8; em[2049] = 1; /* 2047: pointer.struct.rsa_st */
    	em[2050] = 47; em[2051] = 0; 
    em[2052] = 1; em[2053] = 8; em[2054] = 1; /* 2052: pointer.struct.dsa_st */
    	em[2055] = 1506; em[2056] = 0; 
    em[2057] = 1; em[2058] = 8; em[2059] = 1; /* 2057: pointer.struct.dh_st */
    	em[2060] = 1637; em[2061] = 0; 
    em[2062] = 1; em[2063] = 8; em[2064] = 1; /* 2062: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[2065] = 2067; em[2066] = 0; 
    em[2067] = 0; em[2068] = 32; em[2069] = 2; /* 2067: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[2070] = 2074; em[2071] = 8; 
    	em[2072] = 487; em[2073] = 24; 
    em[2074] = 8884099; em[2075] = 8; em[2076] = 2; /* 2074: pointer_to_array_of_pointers_to_stack */
    	em[2077] = 2081; em[2078] = 0; 
    	em[2079] = 5; em[2080] = 20; 
    em[2081] = 0; em[2082] = 8; em[2083] = 1; /* 2081: pointer.X509_ATTRIBUTE */
    	em[2084] = 1891; em[2085] = 0; 
    em[2086] = 1; em[2087] = 8; em[2088] = 1; /* 2086: pointer.struct.evp_pkey_ctx_st */
    	em[2089] = 1997; em[2090] = 0; 
    em[2091] = 0; em[2092] = 48; em[2093] = 5; /* 2091: struct.env_md_ctx_st */
    	em[2094] = 1441; em[2095] = 0; 
    	em[2096] = 1745; em[2097] = 8; 
    	em[2098] = 484; em[2099] = 24; 
    	em[2100] = 2086; em[2101] = 32; 
    	em[2102] = 1468; em[2103] = 40; 
    em[2104] = 1; em[2105] = 8; em[2106] = 1; /* 2104: pointer.struct.env_md_ctx_st */
    	em[2107] = 2091; em[2108] = 0; 
    em[2109] = 0; em[2110] = 4; em[2111] = 0; /* 2109: unsigned int */
    em[2112] = 1; em[2113] = 8; em[2114] = 1; /* 2112: pointer.unsigned int */
    	em[2115] = 2109; em[2116] = 0; 
    args_addr->arg_entity_index[0] = 2104;
    args_addr->arg_entity_index[1] = 29;
    args_addr->arg_entity_index[2] = 2112;
    args_addr->arg_entity_index[3] = 1851;
    args_addr->ret_entity_index = 5;
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

