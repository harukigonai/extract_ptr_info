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

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d);

EVP_PKEY * PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("PEM_read_bio_PrivateKey called %lu\n", in_lib);
    if (!in_lib)
        return bb_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    else {
        EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
        orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
        return orig_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    }
}

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    EVP_PKEY * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 0; em[4] = 32; em[5] = 2; /* 3: struct.stack_st */
    	em[6] = 10; em[7] = 8; 
    	em[8] = 20; em[9] = 24; 
    em[10] = 1; em[11] = 8; em[12] = 1; /* 10: pointer.pointer.char */
    	em[13] = 15; em[14] = 0; 
    em[15] = 1; em[16] = 8; em[17] = 1; /* 15: pointer.char */
    	em[18] = 8884096; em[19] = 0; 
    em[20] = 8884097; em[21] = 8; em[22] = 0; /* 20: pointer.func */
    em[23] = 0; em[24] = 32; em[25] = 1; /* 23: struct.stack_st_void */
    	em[26] = 3; em[27] = 0; 
    em[28] = 1; em[29] = 8; em[30] = 1; /* 28: pointer.struct.stack_st_void */
    	em[31] = 23; em[32] = 0; 
    em[33] = 8884097; em[34] = 8; em[35] = 0; /* 33: pointer.func */
    em[36] = 0; em[37] = 80; em[38] = 9; /* 36: struct.bio_method_st */
    	em[39] = 57; em[40] = 8; 
    	em[41] = 62; em[42] = 16; 
    	em[43] = 65; em[44] = 24; 
    	em[45] = 68; em[46] = 32; 
    	em[47] = 65; em[48] = 40; 
    	em[49] = 71; em[50] = 48; 
    	em[51] = 74; em[52] = 56; 
    	em[53] = 74; em[54] = 64; 
    	em[55] = 77; em[56] = 72; 
    em[57] = 1; em[58] = 8; em[59] = 1; /* 57: pointer.char */
    	em[60] = 8884096; em[61] = 0; 
    em[62] = 8884097; em[63] = 8; em[64] = 0; /* 62: pointer.func */
    em[65] = 8884097; em[66] = 8; em[67] = 0; /* 65: pointer.func */
    em[68] = 8884097; em[69] = 8; em[70] = 0; /* 68: pointer.func */
    em[71] = 8884097; em[72] = 8; em[73] = 0; /* 71: pointer.func */
    em[74] = 8884097; em[75] = 8; em[76] = 0; /* 74: pointer.func */
    em[77] = 8884097; em[78] = 8; em[79] = 0; /* 77: pointer.func */
    em[80] = 1; em[81] = 8; em[82] = 1; /* 80: pointer.struct.bio_method_st */
    	em[83] = 36; em[84] = 0; 
    em[85] = 1; em[86] = 8; em[87] = 1; /* 85: pointer.struct.bio_st */
    	em[88] = 90; em[89] = 0; 
    em[90] = 0; em[91] = 112; em[92] = 7; /* 90: struct.bio_st */
    	em[93] = 80; em[94] = 0; 
    	em[95] = 33; em[96] = 8; 
    	em[97] = 15; em[98] = 16; 
    	em[99] = 107; em[100] = 48; 
    	em[101] = 110; em[102] = 56; 
    	em[103] = 110; em[104] = 64; 
    	em[105] = 115; em[106] = 96; 
    em[107] = 0; em[108] = 8; em[109] = 0; /* 107: pointer.void */
    em[110] = 1; em[111] = 8; em[112] = 1; /* 110: pointer.struct.bio_st */
    	em[113] = 90; em[114] = 0; 
    em[115] = 0; em[116] = 16; em[117] = 1; /* 115: struct.crypto_ex_data_st */
    	em[118] = 28; em[119] = 0; 
    em[120] = 0; em[121] = 0; em[122] = 0; /* 120: struct.ASN1_VALUE_st */
    em[123] = 1; em[124] = 8; em[125] = 1; /* 123: pointer.struct.ASN1_VALUE_st */
    	em[126] = 120; em[127] = 0; 
    em[128] = 1; em[129] = 8; em[130] = 1; /* 128: pointer.struct.asn1_string_st */
    	em[131] = 133; em[132] = 0; 
    em[133] = 0; em[134] = 24; em[135] = 1; /* 133: struct.asn1_string_st */
    	em[136] = 138; em[137] = 8; 
    em[138] = 1; em[139] = 8; em[140] = 1; /* 138: pointer.unsigned char */
    	em[141] = 143; em[142] = 0; 
    em[143] = 0; em[144] = 1; em[145] = 0; /* 143: unsigned char */
    em[146] = 1; em[147] = 8; em[148] = 1; /* 146: pointer.struct.asn1_string_st */
    	em[149] = 133; em[150] = 0; 
    em[151] = 1; em[152] = 8; em[153] = 1; /* 151: pointer.struct.asn1_string_st */
    	em[154] = 133; em[155] = 0; 
    em[156] = 1; em[157] = 8; em[158] = 1; /* 156: pointer.struct.asn1_string_st */
    	em[159] = 133; em[160] = 0; 
    em[161] = 1; em[162] = 8; em[163] = 1; /* 161: pointer.struct.asn1_string_st */
    	em[164] = 133; em[165] = 0; 
    em[166] = 1; em[167] = 8; em[168] = 1; /* 166: pointer.struct.asn1_string_st */
    	em[169] = 133; em[170] = 0; 
    em[171] = 1; em[172] = 8; em[173] = 1; /* 171: pointer.struct.asn1_string_st */
    	em[174] = 133; em[175] = 0; 
    em[176] = 1; em[177] = 8; em[178] = 1; /* 176: pointer.struct.asn1_string_st */
    	em[179] = 133; em[180] = 0; 
    em[181] = 1; em[182] = 8; em[183] = 1; /* 181: pointer.struct.asn1_string_st */
    	em[184] = 133; em[185] = 0; 
    em[186] = 0; em[187] = 16; em[188] = 1; /* 186: struct.asn1_type_st */
    	em[189] = 191; em[190] = 8; 
    em[191] = 0; em[192] = 8; em[193] = 20; /* 191: union.unknown */
    	em[194] = 15; em[195] = 0; 
    	em[196] = 181; em[197] = 0; 
    	em[198] = 234; em[199] = 0; 
    	em[200] = 253; em[201] = 0; 
    	em[202] = 176; em[203] = 0; 
    	em[204] = 171; em[205] = 0; 
    	em[206] = 166; em[207] = 0; 
    	em[208] = 258; em[209] = 0; 
    	em[210] = 161; em[211] = 0; 
    	em[212] = 156; em[213] = 0; 
    	em[214] = 151; em[215] = 0; 
    	em[216] = 146; em[217] = 0; 
    	em[218] = 263; em[219] = 0; 
    	em[220] = 268; em[221] = 0; 
    	em[222] = 273; em[223] = 0; 
    	em[224] = 278; em[225] = 0; 
    	em[226] = 128; em[227] = 0; 
    	em[228] = 181; em[229] = 0; 
    	em[230] = 181; em[231] = 0; 
    	em[232] = 123; em[233] = 0; 
    em[234] = 1; em[235] = 8; em[236] = 1; /* 234: pointer.struct.asn1_object_st */
    	em[237] = 239; em[238] = 0; 
    em[239] = 0; em[240] = 40; em[241] = 3; /* 239: struct.asn1_object_st */
    	em[242] = 57; em[243] = 0; 
    	em[244] = 57; em[245] = 8; 
    	em[246] = 248; em[247] = 24; 
    em[248] = 1; em[249] = 8; em[250] = 1; /* 248: pointer.unsigned char */
    	em[251] = 143; em[252] = 0; 
    em[253] = 1; em[254] = 8; em[255] = 1; /* 253: pointer.struct.asn1_string_st */
    	em[256] = 133; em[257] = 0; 
    em[258] = 1; em[259] = 8; em[260] = 1; /* 258: pointer.struct.asn1_string_st */
    	em[261] = 133; em[262] = 0; 
    em[263] = 1; em[264] = 8; em[265] = 1; /* 263: pointer.struct.asn1_string_st */
    	em[266] = 133; em[267] = 0; 
    em[268] = 1; em[269] = 8; em[270] = 1; /* 268: pointer.struct.asn1_string_st */
    	em[271] = 133; em[272] = 0; 
    em[273] = 1; em[274] = 8; em[275] = 1; /* 273: pointer.struct.asn1_string_st */
    	em[276] = 133; em[277] = 0; 
    em[278] = 1; em[279] = 8; em[280] = 1; /* 278: pointer.struct.asn1_string_st */
    	em[281] = 133; em[282] = 0; 
    em[283] = 0; em[284] = 0; em[285] = 0; /* 283: struct.ASN1_VALUE_st */
    em[286] = 1; em[287] = 8; em[288] = 1; /* 286: pointer.struct.asn1_string_st */
    	em[289] = 291; em[290] = 0; 
    em[291] = 0; em[292] = 24; em[293] = 1; /* 291: struct.asn1_string_st */
    	em[294] = 138; em[295] = 8; 
    em[296] = 1; em[297] = 8; em[298] = 1; /* 296: pointer.struct.asn1_string_st */
    	em[299] = 291; em[300] = 0; 
    em[301] = 1; em[302] = 8; em[303] = 1; /* 301: pointer.struct.asn1_string_st */
    	em[304] = 291; em[305] = 0; 
    em[306] = 1; em[307] = 8; em[308] = 1; /* 306: pointer.struct.asn1_string_st */
    	em[309] = 291; em[310] = 0; 
    em[311] = 1; em[312] = 8; em[313] = 1; /* 311: pointer.struct.asn1_string_st */
    	em[314] = 291; em[315] = 0; 
    em[316] = 1; em[317] = 8; em[318] = 1; /* 316: pointer.struct.asn1_string_st */
    	em[319] = 291; em[320] = 0; 
    em[321] = 1; em[322] = 8; em[323] = 1; /* 321: pointer.struct.dsa_method */
    	em[324] = 326; em[325] = 0; 
    em[326] = 0; em[327] = 96; em[328] = 11; /* 326: struct.dsa_method */
    	em[329] = 57; em[330] = 0; 
    	em[331] = 351; em[332] = 8; 
    	em[333] = 354; em[334] = 16; 
    	em[335] = 357; em[336] = 24; 
    	em[337] = 360; em[338] = 32; 
    	em[339] = 363; em[340] = 40; 
    	em[341] = 366; em[342] = 48; 
    	em[343] = 366; em[344] = 56; 
    	em[345] = 15; em[346] = 72; 
    	em[347] = 369; em[348] = 80; 
    	em[349] = 366; em[350] = 88; 
    em[351] = 8884097; em[352] = 8; em[353] = 0; /* 351: pointer.func */
    em[354] = 8884097; em[355] = 8; em[356] = 0; /* 354: pointer.func */
    em[357] = 8884097; em[358] = 8; em[359] = 0; /* 357: pointer.func */
    em[360] = 8884097; em[361] = 8; em[362] = 0; /* 360: pointer.func */
    em[363] = 8884097; em[364] = 8; em[365] = 0; /* 363: pointer.func */
    em[366] = 8884097; em[367] = 8; em[368] = 0; /* 366: pointer.func */
    em[369] = 8884097; em[370] = 8; em[371] = 0; /* 369: pointer.func */
    em[372] = 8884097; em[373] = 8; em[374] = 0; /* 372: pointer.func */
    em[375] = 0; em[376] = 88; em[377] = 7; /* 375: struct.bn_blinding_st */
    	em[378] = 392; em[379] = 0; 
    	em[380] = 392; em[381] = 8; 
    	em[382] = 392; em[383] = 16; 
    	em[384] = 392; em[385] = 24; 
    	em[386] = 415; em[387] = 40; 
    	em[388] = 420; em[389] = 72; 
    	em[390] = 434; em[391] = 80; 
    em[392] = 1; em[393] = 8; em[394] = 1; /* 392: pointer.struct.bignum_st */
    	em[395] = 397; em[396] = 0; 
    em[397] = 0; em[398] = 24; em[399] = 1; /* 397: struct.bignum_st */
    	em[400] = 402; em[401] = 0; 
    em[402] = 8884099; em[403] = 8; em[404] = 2; /* 402: pointer_to_array_of_pointers_to_stack */
    	em[405] = 409; em[406] = 0; 
    	em[407] = 412; em[408] = 12; 
    em[409] = 0; em[410] = 4; em[411] = 0; /* 409: unsigned int */
    em[412] = 0; em[413] = 4; em[414] = 0; /* 412: int */
    em[415] = 0; em[416] = 16; em[417] = 1; /* 415: struct.crypto_threadid_st */
    	em[418] = 107; em[419] = 0; 
    em[420] = 1; em[421] = 8; em[422] = 1; /* 420: pointer.struct.bn_mont_ctx_st */
    	em[423] = 425; em[424] = 0; 
    em[425] = 0; em[426] = 96; em[427] = 3; /* 425: struct.bn_mont_ctx_st */
    	em[428] = 397; em[429] = 8; 
    	em[430] = 397; em[431] = 32; 
    	em[432] = 397; em[433] = 56; 
    em[434] = 8884097; em[435] = 8; em[436] = 0; /* 434: pointer.func */
    em[437] = 0; em[438] = 96; em[439] = 3; /* 437: struct.bn_mont_ctx_st */
    	em[440] = 446; em[441] = 8; 
    	em[442] = 446; em[443] = 32; 
    	em[444] = 446; em[445] = 56; 
    em[446] = 0; em[447] = 24; em[448] = 1; /* 446: struct.bignum_st */
    	em[449] = 451; em[450] = 0; 
    em[451] = 8884099; em[452] = 8; em[453] = 2; /* 451: pointer_to_array_of_pointers_to_stack */
    	em[454] = 409; em[455] = 0; 
    	em[456] = 412; em[457] = 12; 
    em[458] = 1; em[459] = 8; em[460] = 1; /* 458: pointer.struct.stack_st_void */
    	em[461] = 463; em[462] = 0; 
    em[463] = 0; em[464] = 32; em[465] = 1; /* 463: struct.stack_st_void */
    	em[466] = 468; em[467] = 0; 
    em[468] = 0; em[469] = 32; em[470] = 2; /* 468: struct.stack_st */
    	em[471] = 10; em[472] = 8; 
    	em[473] = 20; em[474] = 24; 
    em[475] = 8884097; em[476] = 8; em[477] = 0; /* 475: pointer.func */
    em[478] = 8884097; em[479] = 8; em[480] = 0; /* 478: pointer.func */
    em[481] = 1; em[482] = 8; em[483] = 1; /* 481: pointer.struct.asn1_string_st */
    	em[484] = 291; em[485] = 0; 
    em[486] = 8884097; em[487] = 8; em[488] = 0; /* 486: pointer.func */
    em[489] = 0; em[490] = 88; em[491] = 4; /* 489: struct.ec_point_st */
    	em[492] = 500; em[493] = 0; 
    	em[494] = 669; em[495] = 8; 
    	em[496] = 669; em[497] = 32; 
    	em[498] = 669; em[499] = 56; 
    em[500] = 1; em[501] = 8; em[502] = 1; /* 500: pointer.struct.ec_method_st */
    	em[503] = 505; em[504] = 0; 
    em[505] = 0; em[506] = 304; em[507] = 37; /* 505: struct.ec_method_st */
    	em[508] = 582; em[509] = 8; 
    	em[510] = 585; em[511] = 16; 
    	em[512] = 585; em[513] = 24; 
    	em[514] = 588; em[515] = 32; 
    	em[516] = 591; em[517] = 40; 
    	em[518] = 594; em[519] = 48; 
    	em[520] = 597; em[521] = 56; 
    	em[522] = 600; em[523] = 64; 
    	em[524] = 603; em[525] = 72; 
    	em[526] = 606; em[527] = 80; 
    	em[528] = 606; em[529] = 88; 
    	em[530] = 609; em[531] = 96; 
    	em[532] = 612; em[533] = 104; 
    	em[534] = 615; em[535] = 112; 
    	em[536] = 618; em[537] = 120; 
    	em[538] = 621; em[539] = 128; 
    	em[540] = 624; em[541] = 136; 
    	em[542] = 627; em[543] = 144; 
    	em[544] = 630; em[545] = 152; 
    	em[546] = 633; em[547] = 160; 
    	em[548] = 636; em[549] = 168; 
    	em[550] = 475; em[551] = 176; 
    	em[552] = 639; em[553] = 184; 
    	em[554] = 642; em[555] = 192; 
    	em[556] = 645; em[557] = 200; 
    	em[558] = 648; em[559] = 208; 
    	em[560] = 639; em[561] = 216; 
    	em[562] = 651; em[563] = 224; 
    	em[564] = 654; em[565] = 232; 
    	em[566] = 657; em[567] = 240; 
    	em[568] = 597; em[569] = 248; 
    	em[570] = 660; em[571] = 256; 
    	em[572] = 663; em[573] = 264; 
    	em[574] = 660; em[575] = 272; 
    	em[576] = 663; em[577] = 280; 
    	em[578] = 663; em[579] = 288; 
    	em[580] = 666; em[581] = 296; 
    em[582] = 8884097; em[583] = 8; em[584] = 0; /* 582: pointer.func */
    em[585] = 8884097; em[586] = 8; em[587] = 0; /* 585: pointer.func */
    em[588] = 8884097; em[589] = 8; em[590] = 0; /* 588: pointer.func */
    em[591] = 8884097; em[592] = 8; em[593] = 0; /* 591: pointer.func */
    em[594] = 8884097; em[595] = 8; em[596] = 0; /* 594: pointer.func */
    em[597] = 8884097; em[598] = 8; em[599] = 0; /* 597: pointer.func */
    em[600] = 8884097; em[601] = 8; em[602] = 0; /* 600: pointer.func */
    em[603] = 8884097; em[604] = 8; em[605] = 0; /* 603: pointer.func */
    em[606] = 8884097; em[607] = 8; em[608] = 0; /* 606: pointer.func */
    em[609] = 8884097; em[610] = 8; em[611] = 0; /* 609: pointer.func */
    em[612] = 8884097; em[613] = 8; em[614] = 0; /* 612: pointer.func */
    em[615] = 8884097; em[616] = 8; em[617] = 0; /* 615: pointer.func */
    em[618] = 8884097; em[619] = 8; em[620] = 0; /* 618: pointer.func */
    em[621] = 8884097; em[622] = 8; em[623] = 0; /* 621: pointer.func */
    em[624] = 8884097; em[625] = 8; em[626] = 0; /* 624: pointer.func */
    em[627] = 8884097; em[628] = 8; em[629] = 0; /* 627: pointer.func */
    em[630] = 8884097; em[631] = 8; em[632] = 0; /* 630: pointer.func */
    em[633] = 8884097; em[634] = 8; em[635] = 0; /* 633: pointer.func */
    em[636] = 8884097; em[637] = 8; em[638] = 0; /* 636: pointer.func */
    em[639] = 8884097; em[640] = 8; em[641] = 0; /* 639: pointer.func */
    em[642] = 8884097; em[643] = 8; em[644] = 0; /* 642: pointer.func */
    em[645] = 8884097; em[646] = 8; em[647] = 0; /* 645: pointer.func */
    em[648] = 8884097; em[649] = 8; em[650] = 0; /* 648: pointer.func */
    em[651] = 8884097; em[652] = 8; em[653] = 0; /* 651: pointer.func */
    em[654] = 8884097; em[655] = 8; em[656] = 0; /* 654: pointer.func */
    em[657] = 8884097; em[658] = 8; em[659] = 0; /* 657: pointer.func */
    em[660] = 8884097; em[661] = 8; em[662] = 0; /* 660: pointer.func */
    em[663] = 8884097; em[664] = 8; em[665] = 0; /* 663: pointer.func */
    em[666] = 8884097; em[667] = 8; em[668] = 0; /* 666: pointer.func */
    em[669] = 0; em[670] = 24; em[671] = 1; /* 669: struct.bignum_st */
    	em[672] = 674; em[673] = 0; 
    em[674] = 8884099; em[675] = 8; em[676] = 2; /* 674: pointer_to_array_of_pointers_to_stack */
    	em[677] = 409; em[678] = 0; 
    	em[679] = 412; em[680] = 12; 
    em[681] = 0; em[682] = 16; em[683] = 1; /* 681: struct.crypto_ex_data_st */
    	em[684] = 458; em[685] = 0; 
    em[686] = 8884097; em[687] = 8; em[688] = 0; /* 686: pointer.func */
    em[689] = 8884097; em[690] = 8; em[691] = 0; /* 689: pointer.func */
    em[692] = 1; em[693] = 8; em[694] = 1; /* 692: pointer.struct.bignum_st */
    	em[695] = 446; em[696] = 0; 
    em[697] = 0; em[698] = 16; em[699] = 1; /* 697: struct.crypto_ex_data_st */
    	em[700] = 702; em[701] = 0; 
    em[702] = 1; em[703] = 8; em[704] = 1; /* 702: pointer.struct.stack_st_void */
    	em[705] = 707; em[706] = 0; 
    em[707] = 0; em[708] = 32; em[709] = 1; /* 707: struct.stack_st_void */
    	em[710] = 712; em[711] = 0; 
    em[712] = 0; em[713] = 32; em[714] = 2; /* 712: struct.stack_st */
    	em[715] = 10; em[716] = 8; 
    	em[717] = 20; em[718] = 24; 
    em[719] = 8884097; em[720] = 8; em[721] = 0; /* 719: pointer.func */
    em[722] = 0; em[723] = 1; em[724] = 0; /* 722: char */
    em[725] = 1; em[726] = 8; em[727] = 1; /* 725: pointer.struct.asn1_object_st */
    	em[728] = 730; em[729] = 0; 
    em[730] = 0; em[731] = 40; em[732] = 3; /* 730: struct.asn1_object_st */
    	em[733] = 57; em[734] = 0; 
    	em[735] = 57; em[736] = 8; 
    	em[737] = 248; em[738] = 24; 
    em[739] = 0; em[740] = 8; em[741] = 1; /* 739: pointer.ASN1_TYPE */
    	em[742] = 744; em[743] = 0; 
    em[744] = 0; em[745] = 0; em[746] = 1; /* 744: ASN1_TYPE */
    	em[747] = 749; em[748] = 0; 
    em[749] = 0; em[750] = 16; em[751] = 1; /* 749: struct.asn1_type_st */
    	em[752] = 754; em[753] = 8; 
    em[754] = 0; em[755] = 8; em[756] = 20; /* 754: union.unknown */
    	em[757] = 15; em[758] = 0; 
    	em[759] = 797; em[760] = 0; 
    	em[761] = 725; em[762] = 0; 
    	em[763] = 802; em[764] = 0; 
    	em[765] = 807; em[766] = 0; 
    	em[767] = 316; em[768] = 0; 
    	em[769] = 481; em[770] = 0; 
    	em[771] = 311; em[772] = 0; 
    	em[773] = 812; em[774] = 0; 
    	em[775] = 306; em[776] = 0; 
    	em[777] = 817; em[778] = 0; 
    	em[779] = 822; em[780] = 0; 
    	em[781] = 827; em[782] = 0; 
    	em[783] = 832; em[784] = 0; 
    	em[785] = 301; em[786] = 0; 
    	em[787] = 296; em[788] = 0; 
    	em[789] = 286; em[790] = 0; 
    	em[791] = 797; em[792] = 0; 
    	em[793] = 797; em[794] = 0; 
    	em[795] = 837; em[796] = 0; 
    em[797] = 1; em[798] = 8; em[799] = 1; /* 797: pointer.struct.asn1_string_st */
    	em[800] = 291; em[801] = 0; 
    em[802] = 1; em[803] = 8; em[804] = 1; /* 802: pointer.struct.asn1_string_st */
    	em[805] = 291; em[806] = 0; 
    em[807] = 1; em[808] = 8; em[809] = 1; /* 807: pointer.struct.asn1_string_st */
    	em[810] = 291; em[811] = 0; 
    em[812] = 1; em[813] = 8; em[814] = 1; /* 812: pointer.struct.asn1_string_st */
    	em[815] = 291; em[816] = 0; 
    em[817] = 1; em[818] = 8; em[819] = 1; /* 817: pointer.struct.asn1_string_st */
    	em[820] = 291; em[821] = 0; 
    em[822] = 1; em[823] = 8; em[824] = 1; /* 822: pointer.struct.asn1_string_st */
    	em[825] = 291; em[826] = 0; 
    em[827] = 1; em[828] = 8; em[829] = 1; /* 827: pointer.struct.asn1_string_st */
    	em[830] = 291; em[831] = 0; 
    em[832] = 1; em[833] = 8; em[834] = 1; /* 832: pointer.struct.asn1_string_st */
    	em[835] = 291; em[836] = 0; 
    em[837] = 1; em[838] = 8; em[839] = 1; /* 837: pointer.struct.ASN1_VALUE_st */
    	em[840] = 283; em[841] = 0; 
    em[842] = 8884097; em[843] = 8; em[844] = 0; /* 842: pointer.func */
    em[845] = 8884097; em[846] = 8; em[847] = 0; /* 845: pointer.func */
    em[848] = 8884097; em[849] = 8; em[850] = 0; /* 848: pointer.func */
    em[851] = 8884097; em[852] = 8; em[853] = 0; /* 851: pointer.func */
    em[854] = 1; em[855] = 8; em[856] = 1; /* 854: pointer.struct.rsa_meth_st */
    	em[857] = 859; em[858] = 0; 
    em[859] = 0; em[860] = 112; em[861] = 13; /* 859: struct.rsa_meth_st */
    	em[862] = 57; em[863] = 0; 
    	em[864] = 888; em[865] = 8; 
    	em[866] = 888; em[867] = 16; 
    	em[868] = 888; em[869] = 24; 
    	em[870] = 888; em[871] = 32; 
    	em[872] = 891; em[873] = 40; 
    	em[874] = 894; em[875] = 48; 
    	em[876] = 845; em[877] = 56; 
    	em[878] = 845; em[879] = 64; 
    	em[880] = 15; em[881] = 80; 
    	em[882] = 719; em[883] = 88; 
    	em[884] = 897; em[885] = 96; 
    	em[886] = 900; em[887] = 104; 
    em[888] = 8884097; em[889] = 8; em[890] = 0; /* 888: pointer.func */
    em[891] = 8884097; em[892] = 8; em[893] = 0; /* 891: pointer.func */
    em[894] = 8884097; em[895] = 8; em[896] = 0; /* 894: pointer.func */
    em[897] = 8884097; em[898] = 8; em[899] = 0; /* 897: pointer.func */
    em[900] = 8884097; em[901] = 8; em[902] = 0; /* 900: pointer.func */
    em[903] = 8884097; em[904] = 8; em[905] = 0; /* 903: pointer.func */
    em[906] = 0; em[907] = 168; em[908] = 17; /* 906: struct.rsa_st */
    	em[909] = 854; em[910] = 16; 
    	em[911] = 943; em[912] = 24; 
    	em[913] = 692; em[914] = 32; 
    	em[915] = 692; em[916] = 40; 
    	em[917] = 692; em[918] = 48; 
    	em[919] = 692; em[920] = 56; 
    	em[921] = 692; em[922] = 64; 
    	em[923] = 692; em[924] = 72; 
    	em[925] = 692; em[926] = 80; 
    	em[927] = 692; em[928] = 88; 
    	em[929] = 681; em[930] = 96; 
    	em[931] = 1279; em[932] = 120; 
    	em[933] = 1279; em[934] = 128; 
    	em[935] = 1279; em[936] = 136; 
    	em[937] = 15; em[938] = 144; 
    	em[939] = 1284; em[940] = 152; 
    	em[941] = 1284; em[942] = 160; 
    em[943] = 1; em[944] = 8; em[945] = 1; /* 943: pointer.struct.engine_st */
    	em[946] = 948; em[947] = 0; 
    em[948] = 0; em[949] = 216; em[950] = 24; /* 948: struct.engine_st */
    	em[951] = 57; em[952] = 0; 
    	em[953] = 57; em[954] = 8; 
    	em[955] = 999; em[956] = 16; 
    	em[957] = 1051; em[958] = 24; 
    	em[959] = 1099; em[960] = 32; 
    	em[961] = 1132; em[962] = 40; 
    	em[963] = 1149; em[964] = 48; 
    	em[965] = 1176; em[966] = 56; 
    	em[967] = 1211; em[968] = 64; 
    	em[969] = 1219; em[970] = 72; 
    	em[971] = 1222; em[972] = 80; 
    	em[973] = 1225; em[974] = 88; 
    	em[975] = 1228; em[976] = 96; 
    	em[977] = 1231; em[978] = 104; 
    	em[979] = 1231; em[980] = 112; 
    	em[981] = 1231; em[982] = 120; 
    	em[983] = 1234; em[984] = 128; 
    	em[985] = 903; em[986] = 136; 
    	em[987] = 903; em[988] = 144; 
    	em[989] = 1237; em[990] = 152; 
    	em[991] = 1240; em[992] = 160; 
    	em[993] = 1252; em[994] = 184; 
    	em[995] = 1274; em[996] = 200; 
    	em[997] = 1274; em[998] = 208; 
    em[999] = 1; em[1000] = 8; em[1001] = 1; /* 999: pointer.struct.rsa_meth_st */
    	em[1002] = 1004; em[1003] = 0; 
    em[1004] = 0; em[1005] = 112; em[1006] = 13; /* 1004: struct.rsa_meth_st */
    	em[1007] = 57; em[1008] = 0; 
    	em[1009] = 848; em[1010] = 8; 
    	em[1011] = 848; em[1012] = 16; 
    	em[1013] = 848; em[1014] = 24; 
    	em[1015] = 848; em[1016] = 32; 
    	em[1017] = 1033; em[1018] = 40; 
    	em[1019] = 1036; em[1020] = 48; 
    	em[1021] = 1039; em[1022] = 56; 
    	em[1023] = 1039; em[1024] = 64; 
    	em[1025] = 15; em[1026] = 80; 
    	em[1027] = 1042; em[1028] = 88; 
    	em[1029] = 1045; em[1030] = 96; 
    	em[1031] = 1048; em[1032] = 104; 
    em[1033] = 8884097; em[1034] = 8; em[1035] = 0; /* 1033: pointer.func */
    em[1036] = 8884097; em[1037] = 8; em[1038] = 0; /* 1036: pointer.func */
    em[1039] = 8884097; em[1040] = 8; em[1041] = 0; /* 1039: pointer.func */
    em[1042] = 8884097; em[1043] = 8; em[1044] = 0; /* 1042: pointer.func */
    em[1045] = 8884097; em[1046] = 8; em[1047] = 0; /* 1045: pointer.func */
    em[1048] = 8884097; em[1049] = 8; em[1050] = 0; /* 1048: pointer.func */
    em[1051] = 1; em[1052] = 8; em[1053] = 1; /* 1051: pointer.struct.dsa_method */
    	em[1054] = 1056; em[1055] = 0; 
    em[1056] = 0; em[1057] = 96; em[1058] = 11; /* 1056: struct.dsa_method */
    	em[1059] = 57; em[1060] = 0; 
    	em[1061] = 851; em[1062] = 8; 
    	em[1063] = 1081; em[1064] = 16; 
    	em[1065] = 1084; em[1066] = 24; 
    	em[1067] = 1087; em[1068] = 32; 
    	em[1069] = 1090; em[1070] = 40; 
    	em[1071] = 1093; em[1072] = 48; 
    	em[1073] = 1093; em[1074] = 56; 
    	em[1075] = 15; em[1076] = 72; 
    	em[1077] = 1096; em[1078] = 80; 
    	em[1079] = 1093; em[1080] = 88; 
    em[1081] = 8884097; em[1082] = 8; em[1083] = 0; /* 1081: pointer.func */
    em[1084] = 8884097; em[1085] = 8; em[1086] = 0; /* 1084: pointer.func */
    em[1087] = 8884097; em[1088] = 8; em[1089] = 0; /* 1087: pointer.func */
    em[1090] = 8884097; em[1091] = 8; em[1092] = 0; /* 1090: pointer.func */
    em[1093] = 8884097; em[1094] = 8; em[1095] = 0; /* 1093: pointer.func */
    em[1096] = 8884097; em[1097] = 8; em[1098] = 0; /* 1096: pointer.func */
    em[1099] = 1; em[1100] = 8; em[1101] = 1; /* 1099: pointer.struct.dh_method */
    	em[1102] = 1104; em[1103] = 0; 
    em[1104] = 0; em[1105] = 72; em[1106] = 8; /* 1104: struct.dh_method */
    	em[1107] = 57; em[1108] = 0; 
    	em[1109] = 842; em[1110] = 8; 
    	em[1111] = 1123; em[1112] = 16; 
    	em[1113] = 1126; em[1114] = 24; 
    	em[1115] = 842; em[1116] = 32; 
    	em[1117] = 842; em[1118] = 40; 
    	em[1119] = 15; em[1120] = 56; 
    	em[1121] = 1129; em[1122] = 64; 
    em[1123] = 8884097; em[1124] = 8; em[1125] = 0; /* 1123: pointer.func */
    em[1126] = 8884097; em[1127] = 8; em[1128] = 0; /* 1126: pointer.func */
    em[1129] = 8884097; em[1130] = 8; em[1131] = 0; /* 1129: pointer.func */
    em[1132] = 1; em[1133] = 8; em[1134] = 1; /* 1132: pointer.struct.ecdh_method */
    	em[1135] = 1137; em[1136] = 0; 
    em[1137] = 0; em[1138] = 32; em[1139] = 3; /* 1137: struct.ecdh_method */
    	em[1140] = 57; em[1141] = 0; 
    	em[1142] = 1146; em[1143] = 8; 
    	em[1144] = 15; em[1145] = 24; 
    em[1146] = 8884097; em[1147] = 8; em[1148] = 0; /* 1146: pointer.func */
    em[1149] = 1; em[1150] = 8; em[1151] = 1; /* 1149: pointer.struct.ecdsa_method */
    	em[1152] = 1154; em[1153] = 0; 
    em[1154] = 0; em[1155] = 48; em[1156] = 5; /* 1154: struct.ecdsa_method */
    	em[1157] = 57; em[1158] = 0; 
    	em[1159] = 1167; em[1160] = 8; 
    	em[1161] = 1170; em[1162] = 16; 
    	em[1163] = 1173; em[1164] = 24; 
    	em[1165] = 15; em[1166] = 40; 
    em[1167] = 8884097; em[1168] = 8; em[1169] = 0; /* 1167: pointer.func */
    em[1170] = 8884097; em[1171] = 8; em[1172] = 0; /* 1170: pointer.func */
    em[1173] = 8884097; em[1174] = 8; em[1175] = 0; /* 1173: pointer.func */
    em[1176] = 1; em[1177] = 8; em[1178] = 1; /* 1176: pointer.struct.rand_meth_st */
    	em[1179] = 1181; em[1180] = 0; 
    em[1181] = 0; em[1182] = 48; em[1183] = 6; /* 1181: struct.rand_meth_st */
    	em[1184] = 1196; em[1185] = 0; 
    	em[1186] = 1199; em[1187] = 8; 
    	em[1188] = 1202; em[1189] = 16; 
    	em[1190] = 1205; em[1191] = 24; 
    	em[1192] = 1199; em[1193] = 32; 
    	em[1194] = 1208; em[1195] = 40; 
    em[1196] = 8884097; em[1197] = 8; em[1198] = 0; /* 1196: pointer.func */
    em[1199] = 8884097; em[1200] = 8; em[1201] = 0; /* 1199: pointer.func */
    em[1202] = 8884097; em[1203] = 8; em[1204] = 0; /* 1202: pointer.func */
    em[1205] = 8884097; em[1206] = 8; em[1207] = 0; /* 1205: pointer.func */
    em[1208] = 8884097; em[1209] = 8; em[1210] = 0; /* 1208: pointer.func */
    em[1211] = 1; em[1212] = 8; em[1213] = 1; /* 1211: pointer.struct.store_method_st */
    	em[1214] = 1216; em[1215] = 0; 
    em[1216] = 0; em[1217] = 0; em[1218] = 0; /* 1216: struct.store_method_st */
    em[1219] = 8884097; em[1220] = 8; em[1221] = 0; /* 1219: pointer.func */
    em[1222] = 8884097; em[1223] = 8; em[1224] = 0; /* 1222: pointer.func */
    em[1225] = 8884097; em[1226] = 8; em[1227] = 0; /* 1225: pointer.func */
    em[1228] = 8884097; em[1229] = 8; em[1230] = 0; /* 1228: pointer.func */
    em[1231] = 8884097; em[1232] = 8; em[1233] = 0; /* 1231: pointer.func */
    em[1234] = 8884097; em[1235] = 8; em[1236] = 0; /* 1234: pointer.func */
    em[1237] = 8884097; em[1238] = 8; em[1239] = 0; /* 1237: pointer.func */
    em[1240] = 1; em[1241] = 8; em[1242] = 1; /* 1240: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1243] = 1245; em[1244] = 0; 
    em[1245] = 0; em[1246] = 32; em[1247] = 2; /* 1245: struct.ENGINE_CMD_DEFN_st */
    	em[1248] = 57; em[1249] = 8; 
    	em[1250] = 57; em[1251] = 16; 
    em[1252] = 0; em[1253] = 16; em[1254] = 1; /* 1252: struct.crypto_ex_data_st */
    	em[1255] = 1257; em[1256] = 0; 
    em[1257] = 1; em[1258] = 8; em[1259] = 1; /* 1257: pointer.struct.stack_st_void */
    	em[1260] = 1262; em[1261] = 0; 
    em[1262] = 0; em[1263] = 32; em[1264] = 1; /* 1262: struct.stack_st_void */
    	em[1265] = 1267; em[1266] = 0; 
    em[1267] = 0; em[1268] = 32; em[1269] = 2; /* 1267: struct.stack_st */
    	em[1270] = 10; em[1271] = 8; 
    	em[1272] = 20; em[1273] = 24; 
    em[1274] = 1; em[1275] = 8; em[1276] = 1; /* 1274: pointer.struct.engine_st */
    	em[1277] = 948; em[1278] = 0; 
    em[1279] = 1; em[1280] = 8; em[1281] = 1; /* 1279: pointer.struct.bn_mont_ctx_st */
    	em[1282] = 437; em[1283] = 0; 
    em[1284] = 1; em[1285] = 8; em[1286] = 1; /* 1284: pointer.struct.bn_blinding_st */
    	em[1287] = 375; em[1288] = 0; 
    em[1289] = 0; em[1290] = 8; em[1291] = 5; /* 1289: union.unknown */
    	em[1292] = 15; em[1293] = 0; 
    	em[1294] = 1302; em[1295] = 0; 
    	em[1296] = 1307; em[1297] = 0; 
    	em[1298] = 1373; em[1299] = 0; 
    	em[1300] = 1499; em[1301] = 0; 
    em[1302] = 1; em[1303] = 8; em[1304] = 1; /* 1302: pointer.struct.rsa_st */
    	em[1305] = 906; em[1306] = 0; 
    em[1307] = 1; em[1308] = 8; em[1309] = 1; /* 1307: pointer.struct.dsa_st */
    	em[1310] = 1312; em[1311] = 0; 
    em[1312] = 0; em[1313] = 136; em[1314] = 11; /* 1312: struct.dsa_st */
    	em[1315] = 1337; em[1316] = 24; 
    	em[1317] = 1337; em[1318] = 32; 
    	em[1319] = 1337; em[1320] = 40; 
    	em[1321] = 1337; em[1322] = 48; 
    	em[1323] = 1337; em[1324] = 56; 
    	em[1325] = 1337; em[1326] = 64; 
    	em[1327] = 1337; em[1328] = 72; 
    	em[1329] = 1354; em[1330] = 88; 
    	em[1331] = 697; em[1332] = 104; 
    	em[1333] = 321; em[1334] = 120; 
    	em[1335] = 1368; em[1336] = 128; 
    em[1337] = 1; em[1338] = 8; em[1339] = 1; /* 1337: pointer.struct.bignum_st */
    	em[1340] = 1342; em[1341] = 0; 
    em[1342] = 0; em[1343] = 24; em[1344] = 1; /* 1342: struct.bignum_st */
    	em[1345] = 1347; em[1346] = 0; 
    em[1347] = 8884099; em[1348] = 8; em[1349] = 2; /* 1347: pointer_to_array_of_pointers_to_stack */
    	em[1350] = 409; em[1351] = 0; 
    	em[1352] = 412; em[1353] = 12; 
    em[1354] = 1; em[1355] = 8; em[1356] = 1; /* 1354: pointer.struct.bn_mont_ctx_st */
    	em[1357] = 1359; em[1358] = 0; 
    em[1359] = 0; em[1360] = 96; em[1361] = 3; /* 1359: struct.bn_mont_ctx_st */
    	em[1362] = 1342; em[1363] = 8; 
    	em[1364] = 1342; em[1365] = 32; 
    	em[1366] = 1342; em[1367] = 56; 
    em[1368] = 1; em[1369] = 8; em[1370] = 1; /* 1368: pointer.struct.engine_st */
    	em[1371] = 948; em[1372] = 0; 
    em[1373] = 1; em[1374] = 8; em[1375] = 1; /* 1373: pointer.struct.dh_st */
    	em[1376] = 1378; em[1377] = 0; 
    em[1378] = 0; em[1379] = 144; em[1380] = 12; /* 1378: struct.dh_st */
    	em[1381] = 1405; em[1382] = 8; 
    	em[1383] = 1405; em[1384] = 16; 
    	em[1385] = 1405; em[1386] = 32; 
    	em[1387] = 1405; em[1388] = 40; 
    	em[1389] = 1422; em[1390] = 56; 
    	em[1391] = 1405; em[1392] = 64; 
    	em[1393] = 1405; em[1394] = 72; 
    	em[1395] = 138; em[1396] = 80; 
    	em[1397] = 1405; em[1398] = 96; 
    	em[1399] = 1436; em[1400] = 112; 
    	em[1401] = 1458; em[1402] = 128; 
    	em[1403] = 1494; em[1404] = 136; 
    em[1405] = 1; em[1406] = 8; em[1407] = 1; /* 1405: pointer.struct.bignum_st */
    	em[1408] = 1410; em[1409] = 0; 
    em[1410] = 0; em[1411] = 24; em[1412] = 1; /* 1410: struct.bignum_st */
    	em[1413] = 1415; em[1414] = 0; 
    em[1415] = 8884099; em[1416] = 8; em[1417] = 2; /* 1415: pointer_to_array_of_pointers_to_stack */
    	em[1418] = 409; em[1419] = 0; 
    	em[1420] = 412; em[1421] = 12; 
    em[1422] = 1; em[1423] = 8; em[1424] = 1; /* 1422: pointer.struct.bn_mont_ctx_st */
    	em[1425] = 1427; em[1426] = 0; 
    em[1427] = 0; em[1428] = 96; em[1429] = 3; /* 1427: struct.bn_mont_ctx_st */
    	em[1430] = 1410; em[1431] = 8; 
    	em[1432] = 1410; em[1433] = 32; 
    	em[1434] = 1410; em[1435] = 56; 
    em[1436] = 0; em[1437] = 16; em[1438] = 1; /* 1436: struct.crypto_ex_data_st */
    	em[1439] = 1441; em[1440] = 0; 
    em[1441] = 1; em[1442] = 8; em[1443] = 1; /* 1441: pointer.struct.stack_st_void */
    	em[1444] = 1446; em[1445] = 0; 
    em[1446] = 0; em[1447] = 32; em[1448] = 1; /* 1446: struct.stack_st_void */
    	em[1449] = 1451; em[1450] = 0; 
    em[1451] = 0; em[1452] = 32; em[1453] = 2; /* 1451: struct.stack_st */
    	em[1454] = 10; em[1455] = 8; 
    	em[1456] = 20; em[1457] = 24; 
    em[1458] = 1; em[1459] = 8; em[1460] = 1; /* 1458: pointer.struct.dh_method */
    	em[1461] = 1463; em[1462] = 0; 
    em[1463] = 0; em[1464] = 72; em[1465] = 8; /* 1463: struct.dh_method */
    	em[1466] = 57; em[1467] = 0; 
    	em[1468] = 1482; em[1469] = 8; 
    	em[1470] = 1485; em[1471] = 16; 
    	em[1472] = 1488; em[1473] = 24; 
    	em[1474] = 1482; em[1475] = 32; 
    	em[1476] = 1482; em[1477] = 40; 
    	em[1478] = 15; em[1479] = 56; 
    	em[1480] = 1491; em[1481] = 64; 
    em[1482] = 8884097; em[1483] = 8; em[1484] = 0; /* 1482: pointer.func */
    em[1485] = 8884097; em[1486] = 8; em[1487] = 0; /* 1485: pointer.func */
    em[1488] = 8884097; em[1489] = 8; em[1490] = 0; /* 1488: pointer.func */
    em[1491] = 8884097; em[1492] = 8; em[1493] = 0; /* 1491: pointer.func */
    em[1494] = 1; em[1495] = 8; em[1496] = 1; /* 1494: pointer.struct.engine_st */
    	em[1497] = 948; em[1498] = 0; 
    em[1499] = 1; em[1500] = 8; em[1501] = 1; /* 1499: pointer.struct.ec_key_st */
    	em[1502] = 1504; em[1503] = 0; 
    em[1504] = 0; em[1505] = 56; em[1506] = 4; /* 1504: struct.ec_key_st */
    	em[1507] = 1515; em[1508] = 8; 
    	em[1509] = 1756; em[1510] = 16; 
    	em[1511] = 1761; em[1512] = 24; 
    	em[1513] = 1778; em[1514] = 48; 
    em[1515] = 1; em[1516] = 8; em[1517] = 1; /* 1515: pointer.struct.ec_group_st */
    	em[1518] = 1520; em[1519] = 0; 
    em[1520] = 0; em[1521] = 232; em[1522] = 12; /* 1520: struct.ec_group_st */
    	em[1523] = 1547; em[1524] = 0; 
    	em[1525] = 1707; em[1526] = 8; 
    	em[1527] = 1712; em[1528] = 16; 
    	em[1529] = 1712; em[1530] = 40; 
    	em[1531] = 138; em[1532] = 80; 
    	em[1533] = 1724; em[1534] = 96; 
    	em[1535] = 1712; em[1536] = 104; 
    	em[1537] = 1712; em[1538] = 152; 
    	em[1539] = 1712; em[1540] = 176; 
    	em[1541] = 107; em[1542] = 208; 
    	em[1543] = 107; em[1544] = 216; 
    	em[1545] = 1753; em[1546] = 224; 
    em[1547] = 1; em[1548] = 8; em[1549] = 1; /* 1547: pointer.struct.ec_method_st */
    	em[1550] = 1552; em[1551] = 0; 
    em[1552] = 0; em[1553] = 304; em[1554] = 37; /* 1552: struct.ec_method_st */
    	em[1555] = 1629; em[1556] = 8; 
    	em[1557] = 1632; em[1558] = 16; 
    	em[1559] = 1632; em[1560] = 24; 
    	em[1561] = 1635; em[1562] = 32; 
    	em[1563] = 689; em[1564] = 40; 
    	em[1565] = 1638; em[1566] = 48; 
    	em[1567] = 1641; em[1568] = 56; 
    	em[1569] = 1644; em[1570] = 64; 
    	em[1571] = 1647; em[1572] = 72; 
    	em[1573] = 1650; em[1574] = 80; 
    	em[1575] = 1650; em[1576] = 88; 
    	em[1577] = 1653; em[1578] = 96; 
    	em[1579] = 1656; em[1580] = 104; 
    	em[1581] = 1659; em[1582] = 112; 
    	em[1583] = 1662; em[1584] = 120; 
    	em[1585] = 1665; em[1586] = 128; 
    	em[1587] = 1668; em[1588] = 136; 
    	em[1589] = 478; em[1590] = 144; 
    	em[1591] = 1671; em[1592] = 152; 
    	em[1593] = 1674; em[1594] = 160; 
    	em[1595] = 1677; em[1596] = 168; 
    	em[1597] = 1680; em[1598] = 176; 
    	em[1599] = 1683; em[1600] = 184; 
    	em[1601] = 1686; em[1602] = 192; 
    	em[1603] = 1689; em[1604] = 200; 
    	em[1605] = 1692; em[1606] = 208; 
    	em[1607] = 1683; em[1608] = 216; 
    	em[1609] = 486; em[1610] = 224; 
    	em[1611] = 1695; em[1612] = 232; 
    	em[1613] = 1698; em[1614] = 240; 
    	em[1615] = 1641; em[1616] = 248; 
    	em[1617] = 1701; em[1618] = 256; 
    	em[1619] = 1704; em[1620] = 264; 
    	em[1621] = 1701; em[1622] = 272; 
    	em[1623] = 1704; em[1624] = 280; 
    	em[1625] = 1704; em[1626] = 288; 
    	em[1627] = 372; em[1628] = 296; 
    em[1629] = 8884097; em[1630] = 8; em[1631] = 0; /* 1629: pointer.func */
    em[1632] = 8884097; em[1633] = 8; em[1634] = 0; /* 1632: pointer.func */
    em[1635] = 8884097; em[1636] = 8; em[1637] = 0; /* 1635: pointer.func */
    em[1638] = 8884097; em[1639] = 8; em[1640] = 0; /* 1638: pointer.func */
    em[1641] = 8884097; em[1642] = 8; em[1643] = 0; /* 1641: pointer.func */
    em[1644] = 8884097; em[1645] = 8; em[1646] = 0; /* 1644: pointer.func */
    em[1647] = 8884097; em[1648] = 8; em[1649] = 0; /* 1647: pointer.func */
    em[1650] = 8884097; em[1651] = 8; em[1652] = 0; /* 1650: pointer.func */
    em[1653] = 8884097; em[1654] = 8; em[1655] = 0; /* 1653: pointer.func */
    em[1656] = 8884097; em[1657] = 8; em[1658] = 0; /* 1656: pointer.func */
    em[1659] = 8884097; em[1660] = 8; em[1661] = 0; /* 1659: pointer.func */
    em[1662] = 8884097; em[1663] = 8; em[1664] = 0; /* 1662: pointer.func */
    em[1665] = 8884097; em[1666] = 8; em[1667] = 0; /* 1665: pointer.func */
    em[1668] = 8884097; em[1669] = 8; em[1670] = 0; /* 1668: pointer.func */
    em[1671] = 8884097; em[1672] = 8; em[1673] = 0; /* 1671: pointer.func */
    em[1674] = 8884097; em[1675] = 8; em[1676] = 0; /* 1674: pointer.func */
    em[1677] = 8884097; em[1678] = 8; em[1679] = 0; /* 1677: pointer.func */
    em[1680] = 8884097; em[1681] = 8; em[1682] = 0; /* 1680: pointer.func */
    em[1683] = 8884097; em[1684] = 8; em[1685] = 0; /* 1683: pointer.func */
    em[1686] = 8884097; em[1687] = 8; em[1688] = 0; /* 1686: pointer.func */
    em[1689] = 8884097; em[1690] = 8; em[1691] = 0; /* 1689: pointer.func */
    em[1692] = 8884097; em[1693] = 8; em[1694] = 0; /* 1692: pointer.func */
    em[1695] = 8884097; em[1696] = 8; em[1697] = 0; /* 1695: pointer.func */
    em[1698] = 8884097; em[1699] = 8; em[1700] = 0; /* 1698: pointer.func */
    em[1701] = 8884097; em[1702] = 8; em[1703] = 0; /* 1701: pointer.func */
    em[1704] = 8884097; em[1705] = 8; em[1706] = 0; /* 1704: pointer.func */
    em[1707] = 1; em[1708] = 8; em[1709] = 1; /* 1707: pointer.struct.ec_point_st */
    	em[1710] = 489; em[1711] = 0; 
    em[1712] = 0; em[1713] = 24; em[1714] = 1; /* 1712: struct.bignum_st */
    	em[1715] = 1717; em[1716] = 0; 
    em[1717] = 8884099; em[1718] = 8; em[1719] = 2; /* 1717: pointer_to_array_of_pointers_to_stack */
    	em[1720] = 409; em[1721] = 0; 
    	em[1722] = 412; em[1723] = 12; 
    em[1724] = 1; em[1725] = 8; em[1726] = 1; /* 1724: pointer.struct.ec_extra_data_st */
    	em[1727] = 1729; em[1728] = 0; 
    em[1729] = 0; em[1730] = 40; em[1731] = 5; /* 1729: struct.ec_extra_data_st */
    	em[1732] = 1742; em[1733] = 0; 
    	em[1734] = 107; em[1735] = 8; 
    	em[1736] = 1747; em[1737] = 16; 
    	em[1738] = 1750; em[1739] = 24; 
    	em[1740] = 1750; em[1741] = 32; 
    em[1742] = 1; em[1743] = 8; em[1744] = 1; /* 1742: pointer.struct.ec_extra_data_st */
    	em[1745] = 1729; em[1746] = 0; 
    em[1747] = 8884097; em[1748] = 8; em[1749] = 0; /* 1747: pointer.func */
    em[1750] = 8884097; em[1751] = 8; em[1752] = 0; /* 1750: pointer.func */
    em[1753] = 8884097; em[1754] = 8; em[1755] = 0; /* 1753: pointer.func */
    em[1756] = 1; em[1757] = 8; em[1758] = 1; /* 1756: pointer.struct.ec_point_st */
    	em[1759] = 489; em[1760] = 0; 
    em[1761] = 1; em[1762] = 8; em[1763] = 1; /* 1761: pointer.struct.bignum_st */
    	em[1764] = 1766; em[1765] = 0; 
    em[1766] = 0; em[1767] = 24; em[1768] = 1; /* 1766: struct.bignum_st */
    	em[1769] = 1771; em[1770] = 0; 
    em[1771] = 8884099; em[1772] = 8; em[1773] = 2; /* 1771: pointer_to_array_of_pointers_to_stack */
    	em[1774] = 409; em[1775] = 0; 
    	em[1776] = 412; em[1777] = 12; 
    em[1778] = 1; em[1779] = 8; em[1780] = 1; /* 1778: pointer.struct.ec_extra_data_st */
    	em[1781] = 1783; em[1782] = 0; 
    em[1783] = 0; em[1784] = 40; em[1785] = 5; /* 1783: struct.ec_extra_data_st */
    	em[1786] = 1796; em[1787] = 0; 
    	em[1788] = 107; em[1789] = 8; 
    	em[1790] = 1747; em[1791] = 16; 
    	em[1792] = 1750; em[1793] = 24; 
    	em[1794] = 1750; em[1795] = 32; 
    em[1796] = 1; em[1797] = 8; em[1798] = 1; /* 1796: pointer.struct.ec_extra_data_st */
    	em[1799] = 1783; em[1800] = 0; 
    em[1801] = 8884097; em[1802] = 8; em[1803] = 0; /* 1801: pointer.func */
    em[1804] = 1; em[1805] = 8; em[1806] = 1; /* 1804: pointer.pointer.struct.evp_pkey_st */
    	em[1807] = 1809; em[1808] = 0; 
    em[1809] = 1; em[1810] = 8; em[1811] = 1; /* 1809: pointer.struct.evp_pkey_st */
    	em[1812] = 1814; em[1813] = 0; 
    em[1814] = 0; em[1815] = 56; em[1816] = 4; /* 1814: struct.evp_pkey_st */
    	em[1817] = 1825; em[1818] = 16; 
    	em[1819] = 1920; em[1820] = 24; 
    	em[1821] = 1289; em[1822] = 32; 
    	em[1823] = 1925; em[1824] = 48; 
    em[1825] = 1; em[1826] = 8; em[1827] = 1; /* 1825: pointer.struct.evp_pkey_asn1_method_st */
    	em[1828] = 1830; em[1829] = 0; 
    em[1830] = 0; em[1831] = 208; em[1832] = 24; /* 1830: struct.evp_pkey_asn1_method_st */
    	em[1833] = 15; em[1834] = 16; 
    	em[1835] = 15; em[1836] = 24; 
    	em[1837] = 1881; em[1838] = 32; 
    	em[1839] = 1884; em[1840] = 40; 
    	em[1841] = 1887; em[1842] = 48; 
    	em[1843] = 1890; em[1844] = 56; 
    	em[1845] = 1893; em[1846] = 64; 
    	em[1847] = 1896; em[1848] = 72; 
    	em[1849] = 1890; em[1850] = 80; 
    	em[1851] = 1899; em[1852] = 88; 
    	em[1853] = 1899; em[1854] = 96; 
    	em[1855] = 1902; em[1856] = 104; 
    	em[1857] = 1905; em[1858] = 112; 
    	em[1859] = 1899; em[1860] = 120; 
    	em[1861] = 1908; em[1862] = 128; 
    	em[1863] = 1887; em[1864] = 136; 
    	em[1865] = 1890; em[1866] = 144; 
    	em[1867] = 686; em[1868] = 152; 
    	em[1869] = 1911; em[1870] = 160; 
    	em[1871] = 1914; em[1872] = 168; 
    	em[1873] = 1902; em[1874] = 176; 
    	em[1875] = 1905; em[1876] = 184; 
    	em[1877] = 1801; em[1878] = 192; 
    	em[1879] = 1917; em[1880] = 200; 
    em[1881] = 8884097; em[1882] = 8; em[1883] = 0; /* 1881: pointer.func */
    em[1884] = 8884097; em[1885] = 8; em[1886] = 0; /* 1884: pointer.func */
    em[1887] = 8884097; em[1888] = 8; em[1889] = 0; /* 1887: pointer.func */
    em[1890] = 8884097; em[1891] = 8; em[1892] = 0; /* 1890: pointer.func */
    em[1893] = 8884097; em[1894] = 8; em[1895] = 0; /* 1893: pointer.func */
    em[1896] = 8884097; em[1897] = 8; em[1898] = 0; /* 1896: pointer.func */
    em[1899] = 8884097; em[1900] = 8; em[1901] = 0; /* 1899: pointer.func */
    em[1902] = 8884097; em[1903] = 8; em[1904] = 0; /* 1902: pointer.func */
    em[1905] = 8884097; em[1906] = 8; em[1907] = 0; /* 1905: pointer.func */
    em[1908] = 8884097; em[1909] = 8; em[1910] = 0; /* 1908: pointer.func */
    em[1911] = 8884097; em[1912] = 8; em[1913] = 0; /* 1911: pointer.func */
    em[1914] = 8884097; em[1915] = 8; em[1916] = 0; /* 1914: pointer.func */
    em[1917] = 8884097; em[1918] = 8; em[1919] = 0; /* 1917: pointer.func */
    em[1920] = 1; em[1921] = 8; em[1922] = 1; /* 1920: pointer.struct.engine_st */
    	em[1923] = 948; em[1924] = 0; 
    em[1925] = 1; em[1926] = 8; em[1927] = 1; /* 1925: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1928] = 1930; em[1929] = 0; 
    em[1930] = 0; em[1931] = 32; em[1932] = 2; /* 1930: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1933] = 1937; em[1934] = 8; 
    	em[1935] = 20; em[1936] = 24; 
    em[1937] = 8884099; em[1938] = 8; em[1939] = 2; /* 1937: pointer_to_array_of_pointers_to_stack */
    	em[1940] = 1944; em[1941] = 0; 
    	em[1942] = 412; em[1943] = 20; 
    em[1944] = 0; em[1945] = 8; em[1946] = 1; /* 1944: pointer.X509_ATTRIBUTE */
    	em[1947] = 1949; em[1948] = 0; 
    em[1949] = 0; em[1950] = 0; em[1951] = 1; /* 1949: X509_ATTRIBUTE */
    	em[1952] = 1954; em[1953] = 0; 
    em[1954] = 0; em[1955] = 24; em[1956] = 2; /* 1954: struct.x509_attributes_st */
    	em[1957] = 234; em[1958] = 0; 
    	em[1959] = 1961; em[1960] = 16; 
    em[1961] = 0; em[1962] = 8; em[1963] = 3; /* 1961: union.unknown */
    	em[1964] = 15; em[1965] = 0; 
    	em[1966] = 1970; em[1967] = 0; 
    	em[1968] = 1989; em[1969] = 0; 
    em[1970] = 1; em[1971] = 8; em[1972] = 1; /* 1970: pointer.struct.stack_st_ASN1_TYPE */
    	em[1973] = 1975; em[1974] = 0; 
    em[1975] = 0; em[1976] = 32; em[1977] = 2; /* 1975: struct.stack_st_fake_ASN1_TYPE */
    	em[1978] = 1982; em[1979] = 8; 
    	em[1980] = 20; em[1981] = 24; 
    em[1982] = 8884099; em[1983] = 8; em[1984] = 2; /* 1982: pointer_to_array_of_pointers_to_stack */
    	em[1985] = 739; em[1986] = 0; 
    	em[1987] = 412; em[1988] = 20; 
    em[1989] = 1; em[1990] = 8; em[1991] = 1; /* 1989: pointer.struct.asn1_type_st */
    	em[1992] = 186; em[1993] = 0; 
    args_addr->arg_entity_index[0] = 85;
    args_addr->arg_entity_index[1] = 1804;
    args_addr->arg_entity_index[2] = 0;
    args_addr->arg_entity_index[3] = 107;
    args_addr->ret_entity_index = 1809;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    EVP_PKEY ** new_arg_b = *((EVP_PKEY ** *)new_args->args[1]);

    pem_password_cb * new_arg_c = *((pem_password_cb * *)new_args->args[2]);

    void * new_arg_d = *((void * *)new_args->args[3]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
    orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
    *new_ret_ptr = (*orig_PEM_read_bio_PrivateKey)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    free(args_addr);

    return ret;
}

