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
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 32; em[7] = 2; /* 5: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[8] = 12; em[9] = 8; 
    	em[10] = 264; em[11] = 24; 
    em[12] = 8884099; em[13] = 8; em[14] = 2; /* 12: pointer_to_array_of_pointers_to_stack */
    	em[15] = 19; em[16] = 0; 
    	em[17] = 261; em[18] = 20; 
    em[19] = 0; em[20] = 8; em[21] = 1; /* 19: pointer.X509_ATTRIBUTE */
    	em[22] = 24; em[23] = 0; 
    em[24] = 0; em[25] = 0; em[26] = 1; /* 24: X509_ATTRIBUTE */
    	em[27] = 29; em[28] = 0; 
    em[29] = 0; em[30] = 24; em[31] = 2; /* 29: struct.x509_attributes_st */
    	em[32] = 36; em[33] = 0; 
    	em[34] = 63; em[35] = 16; 
    em[36] = 1; em[37] = 8; em[38] = 1; /* 36: pointer.struct.asn1_object_st */
    	em[39] = 41; em[40] = 0; 
    em[41] = 0; em[42] = 40; em[43] = 3; /* 41: struct.asn1_object_st */
    	em[44] = 50; em[45] = 0; 
    	em[46] = 50; em[47] = 8; 
    	em[48] = 55; em[49] = 24; 
    em[50] = 1; em[51] = 8; em[52] = 1; /* 50: pointer.char */
    	em[53] = 8884096; em[54] = 0; 
    em[55] = 1; em[56] = 8; em[57] = 1; /* 55: pointer.unsigned char */
    	em[58] = 60; em[59] = 0; 
    em[60] = 0; em[61] = 1; em[62] = 0; /* 60: unsigned char */
    em[63] = 0; em[64] = 8; em[65] = 3; /* 63: union.unknown */
    	em[66] = 72; em[67] = 0; 
    	em[68] = 77; em[69] = 0; 
    	em[70] = 267; em[71] = 0; 
    em[72] = 1; em[73] = 8; em[74] = 1; /* 72: pointer.char */
    	em[75] = 8884096; em[76] = 0; 
    em[77] = 1; em[78] = 8; em[79] = 1; /* 77: pointer.struct.stack_st_ASN1_TYPE */
    	em[80] = 82; em[81] = 0; 
    em[82] = 0; em[83] = 32; em[84] = 2; /* 82: struct.stack_st_fake_ASN1_TYPE */
    	em[85] = 89; em[86] = 8; 
    	em[87] = 264; em[88] = 24; 
    em[89] = 8884099; em[90] = 8; em[91] = 2; /* 89: pointer_to_array_of_pointers_to_stack */
    	em[92] = 96; em[93] = 0; 
    	em[94] = 261; em[95] = 20; 
    em[96] = 0; em[97] = 8; em[98] = 1; /* 96: pointer.ASN1_TYPE */
    	em[99] = 101; em[100] = 0; 
    em[101] = 0; em[102] = 0; em[103] = 1; /* 101: ASN1_TYPE */
    	em[104] = 106; em[105] = 0; 
    em[106] = 0; em[107] = 16; em[108] = 1; /* 106: struct.asn1_type_st */
    	em[109] = 111; em[110] = 8; 
    em[111] = 0; em[112] = 8; em[113] = 20; /* 111: union.unknown */
    	em[114] = 72; em[115] = 0; 
    	em[116] = 154; em[117] = 0; 
    	em[118] = 169; em[119] = 0; 
    	em[120] = 183; em[121] = 0; 
    	em[122] = 188; em[123] = 0; 
    	em[124] = 193; em[125] = 0; 
    	em[126] = 198; em[127] = 0; 
    	em[128] = 203; em[129] = 0; 
    	em[130] = 208; em[131] = 0; 
    	em[132] = 213; em[133] = 0; 
    	em[134] = 218; em[135] = 0; 
    	em[136] = 223; em[137] = 0; 
    	em[138] = 228; em[139] = 0; 
    	em[140] = 233; em[141] = 0; 
    	em[142] = 238; em[143] = 0; 
    	em[144] = 243; em[145] = 0; 
    	em[146] = 248; em[147] = 0; 
    	em[148] = 154; em[149] = 0; 
    	em[150] = 154; em[151] = 0; 
    	em[152] = 253; em[153] = 0; 
    em[154] = 1; em[155] = 8; em[156] = 1; /* 154: pointer.struct.asn1_string_st */
    	em[157] = 159; em[158] = 0; 
    em[159] = 0; em[160] = 24; em[161] = 1; /* 159: struct.asn1_string_st */
    	em[162] = 164; em[163] = 8; 
    em[164] = 1; em[165] = 8; em[166] = 1; /* 164: pointer.unsigned char */
    	em[167] = 60; em[168] = 0; 
    em[169] = 1; em[170] = 8; em[171] = 1; /* 169: pointer.struct.asn1_object_st */
    	em[172] = 174; em[173] = 0; 
    em[174] = 0; em[175] = 40; em[176] = 3; /* 174: struct.asn1_object_st */
    	em[177] = 50; em[178] = 0; 
    	em[179] = 50; em[180] = 8; 
    	em[181] = 55; em[182] = 24; 
    em[183] = 1; em[184] = 8; em[185] = 1; /* 183: pointer.struct.asn1_string_st */
    	em[186] = 159; em[187] = 0; 
    em[188] = 1; em[189] = 8; em[190] = 1; /* 188: pointer.struct.asn1_string_st */
    	em[191] = 159; em[192] = 0; 
    em[193] = 1; em[194] = 8; em[195] = 1; /* 193: pointer.struct.asn1_string_st */
    	em[196] = 159; em[197] = 0; 
    em[198] = 1; em[199] = 8; em[200] = 1; /* 198: pointer.struct.asn1_string_st */
    	em[201] = 159; em[202] = 0; 
    em[203] = 1; em[204] = 8; em[205] = 1; /* 203: pointer.struct.asn1_string_st */
    	em[206] = 159; em[207] = 0; 
    em[208] = 1; em[209] = 8; em[210] = 1; /* 208: pointer.struct.asn1_string_st */
    	em[211] = 159; em[212] = 0; 
    em[213] = 1; em[214] = 8; em[215] = 1; /* 213: pointer.struct.asn1_string_st */
    	em[216] = 159; em[217] = 0; 
    em[218] = 1; em[219] = 8; em[220] = 1; /* 218: pointer.struct.asn1_string_st */
    	em[221] = 159; em[222] = 0; 
    em[223] = 1; em[224] = 8; em[225] = 1; /* 223: pointer.struct.asn1_string_st */
    	em[226] = 159; em[227] = 0; 
    em[228] = 1; em[229] = 8; em[230] = 1; /* 228: pointer.struct.asn1_string_st */
    	em[231] = 159; em[232] = 0; 
    em[233] = 1; em[234] = 8; em[235] = 1; /* 233: pointer.struct.asn1_string_st */
    	em[236] = 159; em[237] = 0; 
    em[238] = 1; em[239] = 8; em[240] = 1; /* 238: pointer.struct.asn1_string_st */
    	em[241] = 159; em[242] = 0; 
    em[243] = 1; em[244] = 8; em[245] = 1; /* 243: pointer.struct.asn1_string_st */
    	em[246] = 159; em[247] = 0; 
    em[248] = 1; em[249] = 8; em[250] = 1; /* 248: pointer.struct.asn1_string_st */
    	em[251] = 159; em[252] = 0; 
    em[253] = 1; em[254] = 8; em[255] = 1; /* 253: pointer.struct.ASN1_VALUE_st */
    	em[256] = 258; em[257] = 0; 
    em[258] = 0; em[259] = 0; em[260] = 0; /* 258: struct.ASN1_VALUE_st */
    em[261] = 0; em[262] = 4; em[263] = 0; /* 261: int */
    em[264] = 8884097; em[265] = 8; em[266] = 0; /* 264: pointer.func */
    em[267] = 1; em[268] = 8; em[269] = 1; /* 267: pointer.struct.asn1_type_st */
    	em[270] = 272; em[271] = 0; 
    em[272] = 0; em[273] = 16; em[274] = 1; /* 272: struct.asn1_type_st */
    	em[275] = 277; em[276] = 8; 
    em[277] = 0; em[278] = 8; em[279] = 20; /* 277: union.unknown */
    	em[280] = 72; em[281] = 0; 
    	em[282] = 320; em[283] = 0; 
    	em[284] = 36; em[285] = 0; 
    	em[286] = 330; em[287] = 0; 
    	em[288] = 335; em[289] = 0; 
    	em[290] = 340; em[291] = 0; 
    	em[292] = 345; em[293] = 0; 
    	em[294] = 350; em[295] = 0; 
    	em[296] = 355; em[297] = 0; 
    	em[298] = 360; em[299] = 0; 
    	em[300] = 365; em[301] = 0; 
    	em[302] = 370; em[303] = 0; 
    	em[304] = 375; em[305] = 0; 
    	em[306] = 380; em[307] = 0; 
    	em[308] = 385; em[309] = 0; 
    	em[310] = 390; em[311] = 0; 
    	em[312] = 395; em[313] = 0; 
    	em[314] = 320; em[315] = 0; 
    	em[316] = 320; em[317] = 0; 
    	em[318] = 400; em[319] = 0; 
    em[320] = 1; em[321] = 8; em[322] = 1; /* 320: pointer.struct.asn1_string_st */
    	em[323] = 325; em[324] = 0; 
    em[325] = 0; em[326] = 24; em[327] = 1; /* 325: struct.asn1_string_st */
    	em[328] = 164; em[329] = 8; 
    em[330] = 1; em[331] = 8; em[332] = 1; /* 330: pointer.struct.asn1_string_st */
    	em[333] = 325; em[334] = 0; 
    em[335] = 1; em[336] = 8; em[337] = 1; /* 335: pointer.struct.asn1_string_st */
    	em[338] = 325; em[339] = 0; 
    em[340] = 1; em[341] = 8; em[342] = 1; /* 340: pointer.struct.asn1_string_st */
    	em[343] = 325; em[344] = 0; 
    em[345] = 1; em[346] = 8; em[347] = 1; /* 345: pointer.struct.asn1_string_st */
    	em[348] = 325; em[349] = 0; 
    em[350] = 1; em[351] = 8; em[352] = 1; /* 350: pointer.struct.asn1_string_st */
    	em[353] = 325; em[354] = 0; 
    em[355] = 1; em[356] = 8; em[357] = 1; /* 355: pointer.struct.asn1_string_st */
    	em[358] = 325; em[359] = 0; 
    em[360] = 1; em[361] = 8; em[362] = 1; /* 360: pointer.struct.asn1_string_st */
    	em[363] = 325; em[364] = 0; 
    em[365] = 1; em[366] = 8; em[367] = 1; /* 365: pointer.struct.asn1_string_st */
    	em[368] = 325; em[369] = 0; 
    em[370] = 1; em[371] = 8; em[372] = 1; /* 370: pointer.struct.asn1_string_st */
    	em[373] = 325; em[374] = 0; 
    em[375] = 1; em[376] = 8; em[377] = 1; /* 375: pointer.struct.asn1_string_st */
    	em[378] = 325; em[379] = 0; 
    em[380] = 1; em[381] = 8; em[382] = 1; /* 380: pointer.struct.asn1_string_st */
    	em[383] = 325; em[384] = 0; 
    em[385] = 1; em[386] = 8; em[387] = 1; /* 385: pointer.struct.asn1_string_st */
    	em[388] = 325; em[389] = 0; 
    em[390] = 1; em[391] = 8; em[392] = 1; /* 390: pointer.struct.asn1_string_st */
    	em[393] = 325; em[394] = 0; 
    em[395] = 1; em[396] = 8; em[397] = 1; /* 395: pointer.struct.asn1_string_st */
    	em[398] = 325; em[399] = 0; 
    em[400] = 1; em[401] = 8; em[402] = 1; /* 400: pointer.struct.ASN1_VALUE_st */
    	em[403] = 405; em[404] = 0; 
    em[405] = 0; em[406] = 0; em[407] = 0; /* 405: struct.ASN1_VALUE_st */
    em[408] = 1; em[409] = 8; em[410] = 1; /* 408: pointer.struct.dh_st */
    	em[411] = 413; em[412] = 0; 
    em[413] = 0; em[414] = 144; em[415] = 12; /* 413: struct.dh_st */
    	em[416] = 440; em[417] = 8; 
    	em[418] = 440; em[419] = 16; 
    	em[420] = 440; em[421] = 32; 
    	em[422] = 440; em[423] = 40; 
    	em[424] = 460; em[425] = 56; 
    	em[426] = 440; em[427] = 64; 
    	em[428] = 440; em[429] = 72; 
    	em[430] = 164; em[431] = 80; 
    	em[432] = 440; em[433] = 96; 
    	em[434] = 474; em[435] = 112; 
    	em[436] = 491; em[437] = 128; 
    	em[438] = 527; em[439] = 136; 
    em[440] = 1; em[441] = 8; em[442] = 1; /* 440: pointer.struct.bignum_st */
    	em[443] = 445; em[444] = 0; 
    em[445] = 0; em[446] = 24; em[447] = 1; /* 445: struct.bignum_st */
    	em[448] = 450; em[449] = 0; 
    em[450] = 8884099; em[451] = 8; em[452] = 2; /* 450: pointer_to_array_of_pointers_to_stack */
    	em[453] = 457; em[454] = 0; 
    	em[455] = 261; em[456] = 12; 
    em[457] = 0; em[458] = 8; em[459] = 0; /* 457: long unsigned int */
    em[460] = 1; em[461] = 8; em[462] = 1; /* 460: pointer.struct.bn_mont_ctx_st */
    	em[463] = 465; em[464] = 0; 
    em[465] = 0; em[466] = 96; em[467] = 3; /* 465: struct.bn_mont_ctx_st */
    	em[468] = 445; em[469] = 8; 
    	em[470] = 445; em[471] = 32; 
    	em[472] = 445; em[473] = 56; 
    em[474] = 0; em[475] = 32; em[476] = 2; /* 474: struct.crypto_ex_data_st_fake */
    	em[477] = 481; em[478] = 8; 
    	em[479] = 264; em[480] = 24; 
    em[481] = 8884099; em[482] = 8; em[483] = 2; /* 481: pointer_to_array_of_pointers_to_stack */
    	em[484] = 488; em[485] = 0; 
    	em[486] = 261; em[487] = 20; 
    em[488] = 0; em[489] = 8; em[490] = 0; /* 488: pointer.void */
    em[491] = 1; em[492] = 8; em[493] = 1; /* 491: pointer.struct.dh_method */
    	em[494] = 496; em[495] = 0; 
    em[496] = 0; em[497] = 72; em[498] = 8; /* 496: struct.dh_method */
    	em[499] = 50; em[500] = 0; 
    	em[501] = 515; em[502] = 8; 
    	em[503] = 518; em[504] = 16; 
    	em[505] = 521; em[506] = 24; 
    	em[507] = 515; em[508] = 32; 
    	em[509] = 515; em[510] = 40; 
    	em[511] = 72; em[512] = 56; 
    	em[513] = 524; em[514] = 64; 
    em[515] = 8884097; em[516] = 8; em[517] = 0; /* 515: pointer.func */
    em[518] = 8884097; em[519] = 8; em[520] = 0; /* 518: pointer.func */
    em[521] = 8884097; em[522] = 8; em[523] = 0; /* 521: pointer.func */
    em[524] = 8884097; em[525] = 8; em[526] = 0; /* 524: pointer.func */
    em[527] = 1; em[528] = 8; em[529] = 1; /* 527: pointer.struct.engine_st */
    	em[530] = 532; em[531] = 0; 
    em[532] = 0; em[533] = 216; em[534] = 24; /* 532: struct.engine_st */
    	em[535] = 50; em[536] = 0; 
    	em[537] = 50; em[538] = 8; 
    	em[539] = 583; em[540] = 16; 
    	em[541] = 638; em[542] = 24; 
    	em[543] = 689; em[544] = 32; 
    	em[545] = 725; em[546] = 40; 
    	em[547] = 742; em[548] = 48; 
    	em[549] = 769; em[550] = 56; 
    	em[551] = 804; em[552] = 64; 
    	em[553] = 812; em[554] = 72; 
    	em[555] = 815; em[556] = 80; 
    	em[557] = 818; em[558] = 88; 
    	em[559] = 821; em[560] = 96; 
    	em[561] = 824; em[562] = 104; 
    	em[563] = 824; em[564] = 112; 
    	em[565] = 824; em[566] = 120; 
    	em[567] = 827; em[568] = 128; 
    	em[569] = 830; em[570] = 136; 
    	em[571] = 830; em[572] = 144; 
    	em[573] = 833; em[574] = 152; 
    	em[575] = 836; em[576] = 160; 
    	em[577] = 848; em[578] = 184; 
    	em[579] = 862; em[580] = 200; 
    	em[581] = 862; em[582] = 208; 
    em[583] = 1; em[584] = 8; em[585] = 1; /* 583: pointer.struct.rsa_meth_st */
    	em[586] = 588; em[587] = 0; 
    em[588] = 0; em[589] = 112; em[590] = 13; /* 588: struct.rsa_meth_st */
    	em[591] = 50; em[592] = 0; 
    	em[593] = 617; em[594] = 8; 
    	em[595] = 617; em[596] = 16; 
    	em[597] = 617; em[598] = 24; 
    	em[599] = 617; em[600] = 32; 
    	em[601] = 620; em[602] = 40; 
    	em[603] = 623; em[604] = 48; 
    	em[605] = 626; em[606] = 56; 
    	em[607] = 626; em[608] = 64; 
    	em[609] = 72; em[610] = 80; 
    	em[611] = 629; em[612] = 88; 
    	em[613] = 632; em[614] = 96; 
    	em[615] = 635; em[616] = 104; 
    em[617] = 8884097; em[618] = 8; em[619] = 0; /* 617: pointer.func */
    em[620] = 8884097; em[621] = 8; em[622] = 0; /* 620: pointer.func */
    em[623] = 8884097; em[624] = 8; em[625] = 0; /* 623: pointer.func */
    em[626] = 8884097; em[627] = 8; em[628] = 0; /* 626: pointer.func */
    em[629] = 8884097; em[630] = 8; em[631] = 0; /* 629: pointer.func */
    em[632] = 8884097; em[633] = 8; em[634] = 0; /* 632: pointer.func */
    em[635] = 8884097; em[636] = 8; em[637] = 0; /* 635: pointer.func */
    em[638] = 1; em[639] = 8; em[640] = 1; /* 638: pointer.struct.dsa_method */
    	em[641] = 643; em[642] = 0; 
    em[643] = 0; em[644] = 96; em[645] = 11; /* 643: struct.dsa_method */
    	em[646] = 50; em[647] = 0; 
    	em[648] = 668; em[649] = 8; 
    	em[650] = 671; em[651] = 16; 
    	em[652] = 674; em[653] = 24; 
    	em[654] = 677; em[655] = 32; 
    	em[656] = 680; em[657] = 40; 
    	em[658] = 683; em[659] = 48; 
    	em[660] = 683; em[661] = 56; 
    	em[662] = 72; em[663] = 72; 
    	em[664] = 686; em[665] = 80; 
    	em[666] = 683; em[667] = 88; 
    em[668] = 8884097; em[669] = 8; em[670] = 0; /* 668: pointer.func */
    em[671] = 8884097; em[672] = 8; em[673] = 0; /* 671: pointer.func */
    em[674] = 8884097; em[675] = 8; em[676] = 0; /* 674: pointer.func */
    em[677] = 8884097; em[678] = 8; em[679] = 0; /* 677: pointer.func */
    em[680] = 8884097; em[681] = 8; em[682] = 0; /* 680: pointer.func */
    em[683] = 8884097; em[684] = 8; em[685] = 0; /* 683: pointer.func */
    em[686] = 8884097; em[687] = 8; em[688] = 0; /* 686: pointer.func */
    em[689] = 1; em[690] = 8; em[691] = 1; /* 689: pointer.struct.dh_method */
    	em[692] = 694; em[693] = 0; 
    em[694] = 0; em[695] = 72; em[696] = 8; /* 694: struct.dh_method */
    	em[697] = 50; em[698] = 0; 
    	em[699] = 713; em[700] = 8; 
    	em[701] = 716; em[702] = 16; 
    	em[703] = 719; em[704] = 24; 
    	em[705] = 713; em[706] = 32; 
    	em[707] = 713; em[708] = 40; 
    	em[709] = 72; em[710] = 56; 
    	em[711] = 722; em[712] = 64; 
    em[713] = 8884097; em[714] = 8; em[715] = 0; /* 713: pointer.func */
    em[716] = 8884097; em[717] = 8; em[718] = 0; /* 716: pointer.func */
    em[719] = 8884097; em[720] = 8; em[721] = 0; /* 719: pointer.func */
    em[722] = 8884097; em[723] = 8; em[724] = 0; /* 722: pointer.func */
    em[725] = 1; em[726] = 8; em[727] = 1; /* 725: pointer.struct.ecdh_method */
    	em[728] = 730; em[729] = 0; 
    em[730] = 0; em[731] = 32; em[732] = 3; /* 730: struct.ecdh_method */
    	em[733] = 50; em[734] = 0; 
    	em[735] = 739; em[736] = 8; 
    	em[737] = 72; em[738] = 24; 
    em[739] = 8884097; em[740] = 8; em[741] = 0; /* 739: pointer.func */
    em[742] = 1; em[743] = 8; em[744] = 1; /* 742: pointer.struct.ecdsa_method */
    	em[745] = 747; em[746] = 0; 
    em[747] = 0; em[748] = 48; em[749] = 5; /* 747: struct.ecdsa_method */
    	em[750] = 50; em[751] = 0; 
    	em[752] = 760; em[753] = 8; 
    	em[754] = 763; em[755] = 16; 
    	em[756] = 766; em[757] = 24; 
    	em[758] = 72; em[759] = 40; 
    em[760] = 8884097; em[761] = 8; em[762] = 0; /* 760: pointer.func */
    em[763] = 8884097; em[764] = 8; em[765] = 0; /* 763: pointer.func */
    em[766] = 8884097; em[767] = 8; em[768] = 0; /* 766: pointer.func */
    em[769] = 1; em[770] = 8; em[771] = 1; /* 769: pointer.struct.rand_meth_st */
    	em[772] = 774; em[773] = 0; 
    em[774] = 0; em[775] = 48; em[776] = 6; /* 774: struct.rand_meth_st */
    	em[777] = 789; em[778] = 0; 
    	em[779] = 792; em[780] = 8; 
    	em[781] = 795; em[782] = 16; 
    	em[783] = 798; em[784] = 24; 
    	em[785] = 792; em[786] = 32; 
    	em[787] = 801; em[788] = 40; 
    em[789] = 8884097; em[790] = 8; em[791] = 0; /* 789: pointer.func */
    em[792] = 8884097; em[793] = 8; em[794] = 0; /* 792: pointer.func */
    em[795] = 8884097; em[796] = 8; em[797] = 0; /* 795: pointer.func */
    em[798] = 8884097; em[799] = 8; em[800] = 0; /* 798: pointer.func */
    em[801] = 8884097; em[802] = 8; em[803] = 0; /* 801: pointer.func */
    em[804] = 1; em[805] = 8; em[806] = 1; /* 804: pointer.struct.store_method_st */
    	em[807] = 809; em[808] = 0; 
    em[809] = 0; em[810] = 0; em[811] = 0; /* 809: struct.store_method_st */
    em[812] = 8884097; em[813] = 8; em[814] = 0; /* 812: pointer.func */
    em[815] = 8884097; em[816] = 8; em[817] = 0; /* 815: pointer.func */
    em[818] = 8884097; em[819] = 8; em[820] = 0; /* 818: pointer.func */
    em[821] = 8884097; em[822] = 8; em[823] = 0; /* 821: pointer.func */
    em[824] = 8884097; em[825] = 8; em[826] = 0; /* 824: pointer.func */
    em[827] = 8884097; em[828] = 8; em[829] = 0; /* 827: pointer.func */
    em[830] = 8884097; em[831] = 8; em[832] = 0; /* 830: pointer.func */
    em[833] = 8884097; em[834] = 8; em[835] = 0; /* 833: pointer.func */
    em[836] = 1; em[837] = 8; em[838] = 1; /* 836: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[839] = 841; em[840] = 0; 
    em[841] = 0; em[842] = 32; em[843] = 2; /* 841: struct.ENGINE_CMD_DEFN_st */
    	em[844] = 50; em[845] = 8; 
    	em[846] = 50; em[847] = 16; 
    em[848] = 0; em[849] = 32; em[850] = 2; /* 848: struct.crypto_ex_data_st_fake */
    	em[851] = 855; em[852] = 8; 
    	em[853] = 264; em[854] = 24; 
    em[855] = 8884099; em[856] = 8; em[857] = 2; /* 855: pointer_to_array_of_pointers_to_stack */
    	em[858] = 488; em[859] = 0; 
    	em[860] = 261; em[861] = 20; 
    em[862] = 1; em[863] = 8; em[864] = 1; /* 862: pointer.struct.engine_st */
    	em[865] = 532; em[866] = 0; 
    em[867] = 1; em[868] = 8; em[869] = 1; /* 867: pointer.struct.dsa_st */
    	em[870] = 872; em[871] = 0; 
    em[872] = 0; em[873] = 136; em[874] = 11; /* 872: struct.dsa_st */
    	em[875] = 897; em[876] = 24; 
    	em[877] = 897; em[878] = 32; 
    	em[879] = 897; em[880] = 40; 
    	em[881] = 897; em[882] = 48; 
    	em[883] = 897; em[884] = 56; 
    	em[885] = 897; em[886] = 64; 
    	em[887] = 897; em[888] = 72; 
    	em[889] = 914; em[890] = 88; 
    	em[891] = 928; em[892] = 104; 
    	em[893] = 942; em[894] = 120; 
    	em[895] = 993; em[896] = 128; 
    em[897] = 1; em[898] = 8; em[899] = 1; /* 897: pointer.struct.bignum_st */
    	em[900] = 902; em[901] = 0; 
    em[902] = 0; em[903] = 24; em[904] = 1; /* 902: struct.bignum_st */
    	em[905] = 907; em[906] = 0; 
    em[907] = 8884099; em[908] = 8; em[909] = 2; /* 907: pointer_to_array_of_pointers_to_stack */
    	em[910] = 457; em[911] = 0; 
    	em[912] = 261; em[913] = 12; 
    em[914] = 1; em[915] = 8; em[916] = 1; /* 914: pointer.struct.bn_mont_ctx_st */
    	em[917] = 919; em[918] = 0; 
    em[919] = 0; em[920] = 96; em[921] = 3; /* 919: struct.bn_mont_ctx_st */
    	em[922] = 902; em[923] = 8; 
    	em[924] = 902; em[925] = 32; 
    	em[926] = 902; em[927] = 56; 
    em[928] = 0; em[929] = 32; em[930] = 2; /* 928: struct.crypto_ex_data_st_fake */
    	em[931] = 935; em[932] = 8; 
    	em[933] = 264; em[934] = 24; 
    em[935] = 8884099; em[936] = 8; em[937] = 2; /* 935: pointer_to_array_of_pointers_to_stack */
    	em[938] = 488; em[939] = 0; 
    	em[940] = 261; em[941] = 20; 
    em[942] = 1; em[943] = 8; em[944] = 1; /* 942: pointer.struct.dsa_method */
    	em[945] = 947; em[946] = 0; 
    em[947] = 0; em[948] = 96; em[949] = 11; /* 947: struct.dsa_method */
    	em[950] = 50; em[951] = 0; 
    	em[952] = 972; em[953] = 8; 
    	em[954] = 975; em[955] = 16; 
    	em[956] = 978; em[957] = 24; 
    	em[958] = 981; em[959] = 32; 
    	em[960] = 984; em[961] = 40; 
    	em[962] = 987; em[963] = 48; 
    	em[964] = 987; em[965] = 56; 
    	em[966] = 72; em[967] = 72; 
    	em[968] = 990; em[969] = 80; 
    	em[970] = 987; em[971] = 88; 
    em[972] = 8884097; em[973] = 8; em[974] = 0; /* 972: pointer.func */
    em[975] = 8884097; em[976] = 8; em[977] = 0; /* 975: pointer.func */
    em[978] = 8884097; em[979] = 8; em[980] = 0; /* 978: pointer.func */
    em[981] = 8884097; em[982] = 8; em[983] = 0; /* 981: pointer.func */
    em[984] = 8884097; em[985] = 8; em[986] = 0; /* 984: pointer.func */
    em[987] = 8884097; em[988] = 8; em[989] = 0; /* 987: pointer.func */
    em[990] = 8884097; em[991] = 8; em[992] = 0; /* 990: pointer.func */
    em[993] = 1; em[994] = 8; em[995] = 1; /* 993: pointer.struct.engine_st */
    	em[996] = 532; em[997] = 0; 
    em[998] = 0; em[999] = 56; em[1000] = 4; /* 998: struct.evp_pkey_st */
    	em[1001] = 1009; em[1002] = 16; 
    	em[1003] = 1110; em[1004] = 24; 
    	em[1005] = 1115; em[1006] = 32; 
    	em[1007] = 0; em[1008] = 48; 
    em[1009] = 1; em[1010] = 8; em[1011] = 1; /* 1009: pointer.struct.evp_pkey_asn1_method_st */
    	em[1012] = 1014; em[1013] = 0; 
    em[1014] = 0; em[1015] = 208; em[1016] = 24; /* 1014: struct.evp_pkey_asn1_method_st */
    	em[1017] = 72; em[1018] = 16; 
    	em[1019] = 72; em[1020] = 24; 
    	em[1021] = 1065; em[1022] = 32; 
    	em[1023] = 1068; em[1024] = 40; 
    	em[1025] = 1071; em[1026] = 48; 
    	em[1027] = 1074; em[1028] = 56; 
    	em[1029] = 1077; em[1030] = 64; 
    	em[1031] = 1080; em[1032] = 72; 
    	em[1033] = 1074; em[1034] = 80; 
    	em[1035] = 1083; em[1036] = 88; 
    	em[1037] = 1083; em[1038] = 96; 
    	em[1039] = 1086; em[1040] = 104; 
    	em[1041] = 1089; em[1042] = 112; 
    	em[1043] = 1083; em[1044] = 120; 
    	em[1045] = 1092; em[1046] = 128; 
    	em[1047] = 1071; em[1048] = 136; 
    	em[1049] = 1074; em[1050] = 144; 
    	em[1051] = 1095; em[1052] = 152; 
    	em[1053] = 1098; em[1054] = 160; 
    	em[1055] = 1101; em[1056] = 168; 
    	em[1057] = 1086; em[1058] = 176; 
    	em[1059] = 1089; em[1060] = 184; 
    	em[1061] = 1104; em[1062] = 192; 
    	em[1063] = 1107; em[1064] = 200; 
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
    em[1110] = 1; em[1111] = 8; em[1112] = 1; /* 1110: pointer.struct.engine_st */
    	em[1113] = 532; em[1114] = 0; 
    em[1115] = 8884101; em[1116] = 8; em[1117] = 6; /* 1115: union.union_of_evp_pkey_st */
    	em[1118] = 488; em[1119] = 0; 
    	em[1120] = 1130; em[1121] = 6; 
    	em[1122] = 867; em[1123] = 116; 
    	em[1124] = 408; em[1125] = 28; 
    	em[1126] = 1302; em[1127] = 408; 
    	em[1128] = 261; em[1129] = 0; 
    em[1130] = 1; em[1131] = 8; em[1132] = 1; /* 1130: pointer.struct.rsa_st */
    	em[1133] = 1135; em[1134] = 0; 
    em[1135] = 0; em[1136] = 168; em[1137] = 17; /* 1135: struct.rsa_st */
    	em[1138] = 1172; em[1139] = 16; 
    	em[1140] = 527; em[1141] = 24; 
    	em[1142] = 440; em[1143] = 32; 
    	em[1144] = 440; em[1145] = 40; 
    	em[1146] = 440; em[1147] = 48; 
    	em[1148] = 440; em[1149] = 56; 
    	em[1150] = 440; em[1151] = 64; 
    	em[1152] = 440; em[1153] = 72; 
    	em[1154] = 440; em[1155] = 80; 
    	em[1156] = 440; em[1157] = 88; 
    	em[1158] = 1227; em[1159] = 96; 
    	em[1160] = 460; em[1161] = 120; 
    	em[1162] = 460; em[1163] = 128; 
    	em[1164] = 460; em[1165] = 136; 
    	em[1166] = 72; em[1167] = 144; 
    	em[1168] = 1241; em[1169] = 152; 
    	em[1170] = 1241; em[1171] = 160; 
    em[1172] = 1; em[1173] = 8; em[1174] = 1; /* 1172: pointer.struct.rsa_meth_st */
    	em[1175] = 1177; em[1176] = 0; 
    em[1177] = 0; em[1178] = 112; em[1179] = 13; /* 1177: struct.rsa_meth_st */
    	em[1180] = 50; em[1181] = 0; 
    	em[1182] = 1206; em[1183] = 8; 
    	em[1184] = 1206; em[1185] = 16; 
    	em[1186] = 1206; em[1187] = 24; 
    	em[1188] = 1206; em[1189] = 32; 
    	em[1190] = 1209; em[1191] = 40; 
    	em[1192] = 1212; em[1193] = 48; 
    	em[1194] = 1215; em[1195] = 56; 
    	em[1196] = 1215; em[1197] = 64; 
    	em[1198] = 72; em[1199] = 80; 
    	em[1200] = 1218; em[1201] = 88; 
    	em[1202] = 1221; em[1203] = 96; 
    	em[1204] = 1224; em[1205] = 104; 
    em[1206] = 8884097; em[1207] = 8; em[1208] = 0; /* 1206: pointer.func */
    em[1209] = 8884097; em[1210] = 8; em[1211] = 0; /* 1209: pointer.func */
    em[1212] = 8884097; em[1213] = 8; em[1214] = 0; /* 1212: pointer.func */
    em[1215] = 8884097; em[1216] = 8; em[1217] = 0; /* 1215: pointer.func */
    em[1218] = 8884097; em[1219] = 8; em[1220] = 0; /* 1218: pointer.func */
    em[1221] = 8884097; em[1222] = 8; em[1223] = 0; /* 1221: pointer.func */
    em[1224] = 8884097; em[1225] = 8; em[1226] = 0; /* 1224: pointer.func */
    em[1227] = 0; em[1228] = 32; em[1229] = 2; /* 1227: struct.crypto_ex_data_st_fake */
    	em[1230] = 1234; em[1231] = 8; 
    	em[1232] = 264; em[1233] = 24; 
    em[1234] = 8884099; em[1235] = 8; em[1236] = 2; /* 1234: pointer_to_array_of_pointers_to_stack */
    	em[1237] = 488; em[1238] = 0; 
    	em[1239] = 261; em[1240] = 20; 
    em[1241] = 1; em[1242] = 8; em[1243] = 1; /* 1241: pointer.struct.bn_blinding_st */
    	em[1244] = 1246; em[1245] = 0; 
    em[1246] = 0; em[1247] = 88; em[1248] = 7; /* 1246: struct.bn_blinding_st */
    	em[1249] = 1263; em[1250] = 0; 
    	em[1251] = 1263; em[1252] = 8; 
    	em[1253] = 1263; em[1254] = 16; 
    	em[1255] = 1263; em[1256] = 24; 
    	em[1257] = 1280; em[1258] = 40; 
    	em[1259] = 1285; em[1260] = 72; 
    	em[1261] = 1299; em[1262] = 80; 
    em[1263] = 1; em[1264] = 8; em[1265] = 1; /* 1263: pointer.struct.bignum_st */
    	em[1266] = 1268; em[1267] = 0; 
    em[1268] = 0; em[1269] = 24; em[1270] = 1; /* 1268: struct.bignum_st */
    	em[1271] = 1273; em[1272] = 0; 
    em[1273] = 8884099; em[1274] = 8; em[1275] = 2; /* 1273: pointer_to_array_of_pointers_to_stack */
    	em[1276] = 457; em[1277] = 0; 
    	em[1278] = 261; em[1279] = 12; 
    em[1280] = 0; em[1281] = 16; em[1282] = 1; /* 1280: struct.crypto_threadid_st */
    	em[1283] = 488; em[1284] = 0; 
    em[1285] = 1; em[1286] = 8; em[1287] = 1; /* 1285: pointer.struct.bn_mont_ctx_st */
    	em[1288] = 1290; em[1289] = 0; 
    em[1290] = 0; em[1291] = 96; em[1292] = 3; /* 1290: struct.bn_mont_ctx_st */
    	em[1293] = 1268; em[1294] = 8; 
    	em[1295] = 1268; em[1296] = 32; 
    	em[1297] = 1268; em[1298] = 56; 
    em[1299] = 8884097; em[1300] = 8; em[1301] = 0; /* 1299: pointer.func */
    em[1302] = 1; em[1303] = 8; em[1304] = 1; /* 1302: pointer.struct.ec_key_st */
    	em[1305] = 1307; em[1306] = 0; 
    em[1307] = 0; em[1308] = 56; em[1309] = 4; /* 1307: struct.ec_key_st */
    	em[1310] = 1318; em[1311] = 8; 
    	em[1312] = 1582; em[1313] = 16; 
    	em[1314] = 1587; em[1315] = 24; 
    	em[1316] = 1604; em[1317] = 48; 
    em[1318] = 1; em[1319] = 8; em[1320] = 1; /* 1318: pointer.struct.ec_group_st */
    	em[1321] = 1323; em[1322] = 0; 
    em[1323] = 0; em[1324] = 232; em[1325] = 12; /* 1323: struct.ec_group_st */
    	em[1326] = 1350; em[1327] = 0; 
    	em[1328] = 1522; em[1329] = 8; 
    	em[1330] = 1538; em[1331] = 16; 
    	em[1332] = 1538; em[1333] = 40; 
    	em[1334] = 164; em[1335] = 80; 
    	em[1336] = 1550; em[1337] = 96; 
    	em[1338] = 1538; em[1339] = 104; 
    	em[1340] = 1538; em[1341] = 152; 
    	em[1342] = 1538; em[1343] = 176; 
    	em[1344] = 488; em[1345] = 208; 
    	em[1346] = 488; em[1347] = 216; 
    	em[1348] = 1579; em[1349] = 224; 
    em[1350] = 1; em[1351] = 8; em[1352] = 1; /* 1350: pointer.struct.ec_method_st */
    	em[1353] = 1355; em[1354] = 0; 
    em[1355] = 0; em[1356] = 304; em[1357] = 37; /* 1355: struct.ec_method_st */
    	em[1358] = 1432; em[1359] = 8; 
    	em[1360] = 1435; em[1361] = 16; 
    	em[1362] = 1435; em[1363] = 24; 
    	em[1364] = 1438; em[1365] = 32; 
    	em[1366] = 1441; em[1367] = 40; 
    	em[1368] = 1444; em[1369] = 48; 
    	em[1370] = 1447; em[1371] = 56; 
    	em[1372] = 1450; em[1373] = 64; 
    	em[1374] = 1453; em[1375] = 72; 
    	em[1376] = 1456; em[1377] = 80; 
    	em[1378] = 1456; em[1379] = 88; 
    	em[1380] = 1459; em[1381] = 96; 
    	em[1382] = 1462; em[1383] = 104; 
    	em[1384] = 1465; em[1385] = 112; 
    	em[1386] = 1468; em[1387] = 120; 
    	em[1388] = 1471; em[1389] = 128; 
    	em[1390] = 1474; em[1391] = 136; 
    	em[1392] = 1477; em[1393] = 144; 
    	em[1394] = 1480; em[1395] = 152; 
    	em[1396] = 1483; em[1397] = 160; 
    	em[1398] = 1486; em[1399] = 168; 
    	em[1400] = 1489; em[1401] = 176; 
    	em[1402] = 1492; em[1403] = 184; 
    	em[1404] = 1495; em[1405] = 192; 
    	em[1406] = 1498; em[1407] = 200; 
    	em[1408] = 1501; em[1409] = 208; 
    	em[1410] = 1492; em[1411] = 216; 
    	em[1412] = 1504; em[1413] = 224; 
    	em[1414] = 1507; em[1415] = 232; 
    	em[1416] = 1510; em[1417] = 240; 
    	em[1418] = 1447; em[1419] = 248; 
    	em[1420] = 1513; em[1421] = 256; 
    	em[1422] = 1516; em[1423] = 264; 
    	em[1424] = 1513; em[1425] = 272; 
    	em[1426] = 1516; em[1427] = 280; 
    	em[1428] = 1516; em[1429] = 288; 
    	em[1430] = 1519; em[1431] = 296; 
    em[1432] = 8884097; em[1433] = 8; em[1434] = 0; /* 1432: pointer.func */
    em[1435] = 8884097; em[1436] = 8; em[1437] = 0; /* 1435: pointer.func */
    em[1438] = 8884097; em[1439] = 8; em[1440] = 0; /* 1438: pointer.func */
    em[1441] = 8884097; em[1442] = 8; em[1443] = 0; /* 1441: pointer.func */
    em[1444] = 8884097; em[1445] = 8; em[1446] = 0; /* 1444: pointer.func */
    em[1447] = 8884097; em[1448] = 8; em[1449] = 0; /* 1447: pointer.func */
    em[1450] = 8884097; em[1451] = 8; em[1452] = 0; /* 1450: pointer.func */
    em[1453] = 8884097; em[1454] = 8; em[1455] = 0; /* 1453: pointer.func */
    em[1456] = 8884097; em[1457] = 8; em[1458] = 0; /* 1456: pointer.func */
    em[1459] = 8884097; em[1460] = 8; em[1461] = 0; /* 1459: pointer.func */
    em[1462] = 8884097; em[1463] = 8; em[1464] = 0; /* 1462: pointer.func */
    em[1465] = 8884097; em[1466] = 8; em[1467] = 0; /* 1465: pointer.func */
    em[1468] = 8884097; em[1469] = 8; em[1470] = 0; /* 1468: pointer.func */
    em[1471] = 8884097; em[1472] = 8; em[1473] = 0; /* 1471: pointer.func */
    em[1474] = 8884097; em[1475] = 8; em[1476] = 0; /* 1474: pointer.func */
    em[1477] = 8884097; em[1478] = 8; em[1479] = 0; /* 1477: pointer.func */
    em[1480] = 8884097; em[1481] = 8; em[1482] = 0; /* 1480: pointer.func */
    em[1483] = 8884097; em[1484] = 8; em[1485] = 0; /* 1483: pointer.func */
    em[1486] = 8884097; em[1487] = 8; em[1488] = 0; /* 1486: pointer.func */
    em[1489] = 8884097; em[1490] = 8; em[1491] = 0; /* 1489: pointer.func */
    em[1492] = 8884097; em[1493] = 8; em[1494] = 0; /* 1492: pointer.func */
    em[1495] = 8884097; em[1496] = 8; em[1497] = 0; /* 1495: pointer.func */
    em[1498] = 8884097; em[1499] = 8; em[1500] = 0; /* 1498: pointer.func */
    em[1501] = 8884097; em[1502] = 8; em[1503] = 0; /* 1501: pointer.func */
    em[1504] = 8884097; em[1505] = 8; em[1506] = 0; /* 1504: pointer.func */
    em[1507] = 8884097; em[1508] = 8; em[1509] = 0; /* 1507: pointer.func */
    em[1510] = 8884097; em[1511] = 8; em[1512] = 0; /* 1510: pointer.func */
    em[1513] = 8884097; em[1514] = 8; em[1515] = 0; /* 1513: pointer.func */
    em[1516] = 8884097; em[1517] = 8; em[1518] = 0; /* 1516: pointer.func */
    em[1519] = 8884097; em[1520] = 8; em[1521] = 0; /* 1519: pointer.func */
    em[1522] = 1; em[1523] = 8; em[1524] = 1; /* 1522: pointer.struct.ec_point_st */
    	em[1525] = 1527; em[1526] = 0; 
    em[1527] = 0; em[1528] = 88; em[1529] = 4; /* 1527: struct.ec_point_st */
    	em[1530] = 1350; em[1531] = 0; 
    	em[1532] = 1538; em[1533] = 8; 
    	em[1534] = 1538; em[1535] = 32; 
    	em[1536] = 1538; em[1537] = 56; 
    em[1538] = 0; em[1539] = 24; em[1540] = 1; /* 1538: struct.bignum_st */
    	em[1541] = 1543; em[1542] = 0; 
    em[1543] = 8884099; em[1544] = 8; em[1545] = 2; /* 1543: pointer_to_array_of_pointers_to_stack */
    	em[1546] = 457; em[1547] = 0; 
    	em[1548] = 261; em[1549] = 12; 
    em[1550] = 1; em[1551] = 8; em[1552] = 1; /* 1550: pointer.struct.ec_extra_data_st */
    	em[1553] = 1555; em[1554] = 0; 
    em[1555] = 0; em[1556] = 40; em[1557] = 5; /* 1555: struct.ec_extra_data_st */
    	em[1558] = 1568; em[1559] = 0; 
    	em[1560] = 488; em[1561] = 8; 
    	em[1562] = 1573; em[1563] = 16; 
    	em[1564] = 1576; em[1565] = 24; 
    	em[1566] = 1576; em[1567] = 32; 
    em[1568] = 1; em[1569] = 8; em[1570] = 1; /* 1568: pointer.struct.ec_extra_data_st */
    	em[1571] = 1555; em[1572] = 0; 
    em[1573] = 8884097; em[1574] = 8; em[1575] = 0; /* 1573: pointer.func */
    em[1576] = 8884097; em[1577] = 8; em[1578] = 0; /* 1576: pointer.func */
    em[1579] = 8884097; em[1580] = 8; em[1581] = 0; /* 1579: pointer.func */
    em[1582] = 1; em[1583] = 8; em[1584] = 1; /* 1582: pointer.struct.ec_point_st */
    	em[1585] = 1527; em[1586] = 0; 
    em[1587] = 1; em[1588] = 8; em[1589] = 1; /* 1587: pointer.struct.bignum_st */
    	em[1590] = 1592; em[1591] = 0; 
    em[1592] = 0; em[1593] = 24; em[1594] = 1; /* 1592: struct.bignum_st */
    	em[1595] = 1597; em[1596] = 0; 
    em[1597] = 8884099; em[1598] = 8; em[1599] = 2; /* 1597: pointer_to_array_of_pointers_to_stack */
    	em[1600] = 457; em[1601] = 0; 
    	em[1602] = 261; em[1603] = 12; 
    em[1604] = 1; em[1605] = 8; em[1606] = 1; /* 1604: pointer.struct.ec_extra_data_st */
    	em[1607] = 1609; em[1608] = 0; 
    em[1609] = 0; em[1610] = 40; em[1611] = 5; /* 1609: struct.ec_extra_data_st */
    	em[1612] = 1622; em[1613] = 0; 
    	em[1614] = 488; em[1615] = 8; 
    	em[1616] = 1573; em[1617] = 16; 
    	em[1618] = 1576; em[1619] = 24; 
    	em[1620] = 1576; em[1621] = 32; 
    em[1622] = 1; em[1623] = 8; em[1624] = 1; /* 1622: pointer.struct.ec_extra_data_st */
    	em[1625] = 1609; em[1626] = 0; 
    em[1627] = 1; em[1628] = 8; em[1629] = 1; /* 1627: pointer.int */
    	em[1630] = 261; em[1631] = 0; 
    em[1632] = 8884097; em[1633] = 8; em[1634] = 0; /* 1632: pointer.func */
    em[1635] = 8884097; em[1636] = 8; em[1637] = 0; /* 1635: pointer.func */
    em[1638] = 8884097; em[1639] = 8; em[1640] = 0; /* 1638: pointer.func */
    em[1641] = 8884097; em[1642] = 8; em[1643] = 0; /* 1641: pointer.func */
    em[1644] = 8884097; em[1645] = 8; em[1646] = 0; /* 1644: pointer.func */
    em[1647] = 1; em[1648] = 8; em[1649] = 1; /* 1647: pointer.struct.dsa_st */
    	em[1650] = 872; em[1651] = 0; 
    em[1652] = 8884097; em[1653] = 8; em[1654] = 0; /* 1652: pointer.func */
    em[1655] = 8884097; em[1656] = 8; em[1657] = 0; /* 1655: pointer.func */
    em[1658] = 8884097; em[1659] = 8; em[1660] = 0; /* 1658: pointer.func */
    em[1661] = 0; em[1662] = 208; em[1663] = 25; /* 1661: struct.evp_pkey_method_st */
    	em[1664] = 1714; em[1665] = 8; 
    	em[1666] = 1717; em[1667] = 16; 
    	em[1668] = 1658; em[1669] = 24; 
    	em[1670] = 1714; em[1671] = 32; 
    	em[1672] = 1720; em[1673] = 40; 
    	em[1674] = 1714; em[1675] = 48; 
    	em[1676] = 1720; em[1677] = 56; 
    	em[1678] = 1714; em[1679] = 64; 
    	em[1680] = 1655; em[1681] = 72; 
    	em[1682] = 1714; em[1683] = 80; 
    	em[1684] = 1723; em[1685] = 88; 
    	em[1686] = 1714; em[1687] = 96; 
    	em[1688] = 1655; em[1689] = 104; 
    	em[1690] = 1652; em[1691] = 112; 
    	em[1692] = 1726; em[1693] = 120; 
    	em[1694] = 1652; em[1695] = 128; 
    	em[1696] = 1641; em[1697] = 136; 
    	em[1698] = 1714; em[1699] = 144; 
    	em[1700] = 1655; em[1701] = 152; 
    	em[1702] = 1714; em[1703] = 160; 
    	em[1704] = 1655; em[1705] = 168; 
    	em[1706] = 1714; em[1707] = 176; 
    	em[1708] = 1729; em[1709] = 184; 
    	em[1710] = 1732; em[1711] = 192; 
    	em[1712] = 1638; em[1713] = 200; 
    em[1714] = 8884097; em[1715] = 8; em[1716] = 0; /* 1714: pointer.func */
    em[1717] = 8884097; em[1718] = 8; em[1719] = 0; /* 1717: pointer.func */
    em[1720] = 8884097; em[1721] = 8; em[1722] = 0; /* 1720: pointer.func */
    em[1723] = 8884097; em[1724] = 8; em[1725] = 0; /* 1723: pointer.func */
    em[1726] = 8884097; em[1727] = 8; em[1728] = 0; /* 1726: pointer.func */
    em[1729] = 8884097; em[1730] = 8; em[1731] = 0; /* 1729: pointer.func */
    em[1732] = 8884097; em[1733] = 8; em[1734] = 0; /* 1732: pointer.func */
    em[1735] = 1; em[1736] = 8; em[1737] = 1; /* 1735: pointer.struct.evp_pkey_ctx_st */
    	em[1738] = 1740; em[1739] = 0; 
    em[1740] = 0; em[1741] = 80; em[1742] = 8; /* 1740: struct.evp_pkey_ctx_st */
    	em[1743] = 1759; em[1744] = 0; 
    	em[1745] = 1110; em[1746] = 8; 
    	em[1747] = 1764; em[1748] = 16; 
    	em[1749] = 1764; em[1750] = 24; 
    	em[1751] = 488; em[1752] = 40; 
    	em[1753] = 488; em[1754] = 48; 
    	em[1755] = 1632; em[1756] = 56; 
    	em[1757] = 1627; em[1758] = 64; 
    em[1759] = 1; em[1760] = 8; em[1761] = 1; /* 1759: pointer.struct.evp_pkey_method_st */
    	em[1762] = 1661; em[1763] = 0; 
    em[1764] = 1; em[1765] = 8; em[1766] = 1; /* 1764: pointer.struct.evp_pkey_st */
    	em[1767] = 1769; em[1768] = 0; 
    em[1769] = 0; em[1770] = 56; em[1771] = 4; /* 1769: struct.evp_pkey_st */
    	em[1772] = 1009; em[1773] = 16; 
    	em[1774] = 1110; em[1775] = 24; 
    	em[1776] = 1780; em[1777] = 32; 
    	em[1778] = 1805; em[1779] = 48; 
    em[1780] = 8884101; em[1781] = 8; em[1782] = 6; /* 1780: union.union_of_evp_pkey_st */
    	em[1783] = 488; em[1784] = 0; 
    	em[1785] = 1795; em[1786] = 6; 
    	em[1787] = 1647; em[1788] = 116; 
    	em[1789] = 1800; em[1790] = 28; 
    	em[1791] = 1302; em[1792] = 408; 
    	em[1793] = 261; em[1794] = 0; 
    em[1795] = 1; em[1796] = 8; em[1797] = 1; /* 1795: pointer.struct.rsa_st */
    	em[1798] = 1135; em[1799] = 0; 
    em[1800] = 1; em[1801] = 8; em[1802] = 1; /* 1800: pointer.struct.dh_st */
    	em[1803] = 413; em[1804] = 0; 
    em[1805] = 1; em[1806] = 8; em[1807] = 1; /* 1805: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1808] = 1810; em[1809] = 0; 
    em[1810] = 0; em[1811] = 32; em[1812] = 2; /* 1810: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1813] = 1817; em[1814] = 8; 
    	em[1815] = 264; em[1816] = 24; 
    em[1817] = 8884099; em[1818] = 8; em[1819] = 2; /* 1817: pointer_to_array_of_pointers_to_stack */
    	em[1820] = 1824; em[1821] = 0; 
    	em[1822] = 261; em[1823] = 20; 
    em[1824] = 0; em[1825] = 8; em[1826] = 1; /* 1824: pointer.X509_ATTRIBUTE */
    	em[1827] = 24; em[1828] = 0; 
    em[1829] = 0; em[1830] = 1; em[1831] = 0; /* 1829: char */
    em[1832] = 8884097; em[1833] = 8; em[1834] = 0; /* 1832: pointer.func */
    em[1835] = 0; em[1836] = 120; em[1837] = 8; /* 1835: struct.env_md_st */
    	em[1838] = 1854; em[1839] = 24; 
    	em[1840] = 1857; em[1841] = 32; 
    	em[1842] = 1644; em[1843] = 40; 
    	em[1844] = 1860; em[1845] = 48; 
    	em[1846] = 1854; em[1847] = 56; 
    	em[1848] = 1863; em[1849] = 64; 
    	em[1850] = 1635; em[1851] = 72; 
    	em[1852] = 1832; em[1853] = 112; 
    em[1854] = 8884097; em[1855] = 8; em[1856] = 0; /* 1854: pointer.func */
    em[1857] = 8884097; em[1858] = 8; em[1859] = 0; /* 1857: pointer.func */
    em[1860] = 8884097; em[1861] = 8; em[1862] = 0; /* 1860: pointer.func */
    em[1863] = 8884097; em[1864] = 8; em[1865] = 0; /* 1863: pointer.func */
    em[1866] = 1; em[1867] = 8; em[1868] = 1; /* 1866: pointer.struct.evp_pkey_st */
    	em[1869] = 998; em[1870] = 0; 
    em[1871] = 1; em[1872] = 8; em[1873] = 1; /* 1871: pointer.unsigned int */
    	em[1874] = 1876; em[1875] = 0; 
    em[1876] = 0; em[1877] = 4; em[1878] = 0; /* 1876: unsigned int */
    em[1879] = 1; em[1880] = 8; em[1881] = 1; /* 1879: pointer.struct.env_md_st */
    	em[1882] = 1835; em[1883] = 0; 
    em[1884] = 1; em[1885] = 8; em[1886] = 1; /* 1884: pointer.struct.env_md_ctx_st */
    	em[1887] = 1889; em[1888] = 0; 
    em[1889] = 0; em[1890] = 48; em[1891] = 5; /* 1889: struct.env_md_ctx_st */
    	em[1892] = 1879; em[1893] = 0; 
    	em[1894] = 1110; em[1895] = 8; 
    	em[1896] = 488; em[1897] = 24; 
    	em[1898] = 1735; em[1899] = 32; 
    	em[1900] = 1857; em[1901] = 40; 
    args_addr->arg_entity_index[0] = 1884;
    args_addr->arg_entity_index[1] = 164;
    args_addr->arg_entity_index[2] = 1871;
    args_addr->arg_entity_index[3] = 1866;
    args_addr->ret_entity_index = 261;
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

