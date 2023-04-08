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

int bb_EVP_PKEY_size(EVP_PKEY * arg_a);

int EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_size called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_PKEY_size(arg_a);
    else {
        int (*orig_EVP_PKEY_size)(EVP_PKEY *);
        orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
        return orig_EVP_PKEY_size(arg_a);
    }
}

int bb_EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.ASN1_VALUE_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 0; em[7] = 0; /* 5: struct.ASN1_VALUE_st */
    em[8] = 1; em[9] = 8; em[10] = 1; /* 8: pointer.struct.asn1_string_st */
    	em[11] = 13; em[12] = 0; 
    em[13] = 0; em[14] = 24; em[15] = 1; /* 13: struct.asn1_string_st */
    	em[16] = 18; em[17] = 8; 
    em[18] = 1; em[19] = 8; em[20] = 1; /* 18: pointer.unsigned char */
    	em[21] = 23; em[22] = 0; 
    em[23] = 0; em[24] = 1; em[25] = 0; /* 23: unsigned char */
    em[26] = 1; em[27] = 8; em[28] = 1; /* 26: pointer.struct.asn1_string_st */
    	em[29] = 13; em[30] = 0; 
    em[31] = 1; em[32] = 8; em[33] = 1; /* 31: pointer.struct.asn1_string_st */
    	em[34] = 13; em[35] = 0; 
    em[36] = 1; em[37] = 8; em[38] = 1; /* 36: pointer.struct.asn1_string_st */
    	em[39] = 13; em[40] = 0; 
    em[41] = 1; em[42] = 8; em[43] = 1; /* 41: pointer.struct.asn1_string_st */
    	em[44] = 13; em[45] = 0; 
    em[46] = 1; em[47] = 8; em[48] = 1; /* 46: pointer.struct.asn1_string_st */
    	em[49] = 13; em[50] = 0; 
    em[51] = 1; em[52] = 8; em[53] = 1; /* 51: pointer.struct.asn1_string_st */
    	em[54] = 13; em[55] = 0; 
    em[56] = 1; em[57] = 8; em[58] = 1; /* 56: pointer.struct.asn1_string_st */
    	em[59] = 13; em[60] = 0; 
    em[61] = 1; em[62] = 8; em[63] = 1; /* 61: pointer.struct.asn1_string_st */
    	em[64] = 13; em[65] = 0; 
    em[66] = 1; em[67] = 8; em[68] = 1; /* 66: pointer.struct.asn1_string_st */
    	em[69] = 13; em[70] = 0; 
    em[71] = 0; em[72] = 144; em[73] = 12; /* 71: struct.dh_st */
    	em[74] = 98; em[75] = 8; 
    	em[76] = 98; em[77] = 16; 
    	em[78] = 98; em[79] = 32; 
    	em[80] = 98; em[81] = 40; 
    	em[82] = 121; em[83] = 56; 
    	em[84] = 98; em[85] = 64; 
    	em[86] = 98; em[87] = 72; 
    	em[88] = 18; em[89] = 80; 
    	em[90] = 98; em[91] = 96; 
    	em[92] = 135; em[93] = 112; 
    	em[94] = 155; em[95] = 128; 
    	em[96] = 201; em[97] = 136; 
    em[98] = 1; em[99] = 8; em[100] = 1; /* 98: pointer.struct.bignum_st */
    	em[101] = 103; em[102] = 0; 
    em[103] = 0; em[104] = 24; em[105] = 1; /* 103: struct.bignum_st */
    	em[106] = 108; em[107] = 0; 
    em[108] = 8884099; em[109] = 8; em[110] = 2; /* 108: pointer_to_array_of_pointers_to_stack */
    	em[111] = 115; em[112] = 0; 
    	em[113] = 118; em[114] = 12; 
    em[115] = 0; em[116] = 8; em[117] = 0; /* 115: long unsigned int */
    em[118] = 0; em[119] = 4; em[120] = 0; /* 118: int */
    em[121] = 1; em[122] = 8; em[123] = 1; /* 121: pointer.struct.bn_mont_ctx_st */
    	em[124] = 126; em[125] = 0; 
    em[126] = 0; em[127] = 96; em[128] = 3; /* 126: struct.bn_mont_ctx_st */
    	em[129] = 103; em[130] = 8; 
    	em[131] = 103; em[132] = 32; 
    	em[133] = 103; em[134] = 56; 
    em[135] = 0; em[136] = 32; em[137] = 2; /* 135: struct.crypto_ex_data_st_fake */
    	em[138] = 142; em[139] = 8; 
    	em[140] = 152; em[141] = 24; 
    em[142] = 8884099; em[143] = 8; em[144] = 2; /* 142: pointer_to_array_of_pointers_to_stack */
    	em[145] = 149; em[146] = 0; 
    	em[147] = 118; em[148] = 20; 
    em[149] = 0; em[150] = 8; em[151] = 0; /* 149: pointer.void */
    em[152] = 8884097; em[153] = 8; em[154] = 0; /* 152: pointer.func */
    em[155] = 1; em[156] = 8; em[157] = 1; /* 155: pointer.struct.dh_method */
    	em[158] = 160; em[159] = 0; 
    em[160] = 0; em[161] = 72; em[162] = 8; /* 160: struct.dh_method */
    	em[163] = 179; em[164] = 0; 
    	em[165] = 184; em[166] = 8; 
    	em[167] = 187; em[168] = 16; 
    	em[169] = 190; em[170] = 24; 
    	em[171] = 184; em[172] = 32; 
    	em[173] = 184; em[174] = 40; 
    	em[175] = 193; em[176] = 56; 
    	em[177] = 198; em[178] = 64; 
    em[179] = 1; em[180] = 8; em[181] = 1; /* 179: pointer.char */
    	em[182] = 8884096; em[183] = 0; 
    em[184] = 8884097; em[185] = 8; em[186] = 0; /* 184: pointer.func */
    em[187] = 8884097; em[188] = 8; em[189] = 0; /* 187: pointer.func */
    em[190] = 8884097; em[191] = 8; em[192] = 0; /* 190: pointer.func */
    em[193] = 1; em[194] = 8; em[195] = 1; /* 193: pointer.char */
    	em[196] = 8884096; em[197] = 0; 
    em[198] = 8884097; em[199] = 8; em[200] = 0; /* 198: pointer.func */
    em[201] = 1; em[202] = 8; em[203] = 1; /* 201: pointer.struct.engine_st */
    	em[204] = 206; em[205] = 0; 
    em[206] = 0; em[207] = 216; em[208] = 24; /* 206: struct.engine_st */
    	em[209] = 179; em[210] = 0; 
    	em[211] = 179; em[212] = 8; 
    	em[213] = 257; em[214] = 16; 
    	em[215] = 312; em[216] = 24; 
    	em[217] = 363; em[218] = 32; 
    	em[219] = 399; em[220] = 40; 
    	em[221] = 416; em[222] = 48; 
    	em[223] = 443; em[224] = 56; 
    	em[225] = 478; em[226] = 64; 
    	em[227] = 486; em[228] = 72; 
    	em[229] = 489; em[230] = 80; 
    	em[231] = 492; em[232] = 88; 
    	em[233] = 495; em[234] = 96; 
    	em[235] = 498; em[236] = 104; 
    	em[237] = 498; em[238] = 112; 
    	em[239] = 498; em[240] = 120; 
    	em[241] = 501; em[242] = 128; 
    	em[243] = 504; em[244] = 136; 
    	em[245] = 504; em[246] = 144; 
    	em[247] = 507; em[248] = 152; 
    	em[249] = 510; em[250] = 160; 
    	em[251] = 522; em[252] = 184; 
    	em[253] = 536; em[254] = 200; 
    	em[255] = 536; em[256] = 208; 
    em[257] = 1; em[258] = 8; em[259] = 1; /* 257: pointer.struct.rsa_meth_st */
    	em[260] = 262; em[261] = 0; 
    em[262] = 0; em[263] = 112; em[264] = 13; /* 262: struct.rsa_meth_st */
    	em[265] = 179; em[266] = 0; 
    	em[267] = 291; em[268] = 8; 
    	em[269] = 291; em[270] = 16; 
    	em[271] = 291; em[272] = 24; 
    	em[273] = 291; em[274] = 32; 
    	em[275] = 294; em[276] = 40; 
    	em[277] = 297; em[278] = 48; 
    	em[279] = 300; em[280] = 56; 
    	em[281] = 300; em[282] = 64; 
    	em[283] = 193; em[284] = 80; 
    	em[285] = 303; em[286] = 88; 
    	em[287] = 306; em[288] = 96; 
    	em[289] = 309; em[290] = 104; 
    em[291] = 8884097; em[292] = 8; em[293] = 0; /* 291: pointer.func */
    em[294] = 8884097; em[295] = 8; em[296] = 0; /* 294: pointer.func */
    em[297] = 8884097; em[298] = 8; em[299] = 0; /* 297: pointer.func */
    em[300] = 8884097; em[301] = 8; em[302] = 0; /* 300: pointer.func */
    em[303] = 8884097; em[304] = 8; em[305] = 0; /* 303: pointer.func */
    em[306] = 8884097; em[307] = 8; em[308] = 0; /* 306: pointer.func */
    em[309] = 8884097; em[310] = 8; em[311] = 0; /* 309: pointer.func */
    em[312] = 1; em[313] = 8; em[314] = 1; /* 312: pointer.struct.dsa_method */
    	em[315] = 317; em[316] = 0; 
    em[317] = 0; em[318] = 96; em[319] = 11; /* 317: struct.dsa_method */
    	em[320] = 179; em[321] = 0; 
    	em[322] = 342; em[323] = 8; 
    	em[324] = 345; em[325] = 16; 
    	em[326] = 348; em[327] = 24; 
    	em[328] = 351; em[329] = 32; 
    	em[330] = 354; em[331] = 40; 
    	em[332] = 357; em[333] = 48; 
    	em[334] = 357; em[335] = 56; 
    	em[336] = 193; em[337] = 72; 
    	em[338] = 360; em[339] = 80; 
    	em[340] = 357; em[341] = 88; 
    em[342] = 8884097; em[343] = 8; em[344] = 0; /* 342: pointer.func */
    em[345] = 8884097; em[346] = 8; em[347] = 0; /* 345: pointer.func */
    em[348] = 8884097; em[349] = 8; em[350] = 0; /* 348: pointer.func */
    em[351] = 8884097; em[352] = 8; em[353] = 0; /* 351: pointer.func */
    em[354] = 8884097; em[355] = 8; em[356] = 0; /* 354: pointer.func */
    em[357] = 8884097; em[358] = 8; em[359] = 0; /* 357: pointer.func */
    em[360] = 8884097; em[361] = 8; em[362] = 0; /* 360: pointer.func */
    em[363] = 1; em[364] = 8; em[365] = 1; /* 363: pointer.struct.dh_method */
    	em[366] = 368; em[367] = 0; 
    em[368] = 0; em[369] = 72; em[370] = 8; /* 368: struct.dh_method */
    	em[371] = 179; em[372] = 0; 
    	em[373] = 387; em[374] = 8; 
    	em[375] = 390; em[376] = 16; 
    	em[377] = 393; em[378] = 24; 
    	em[379] = 387; em[380] = 32; 
    	em[381] = 387; em[382] = 40; 
    	em[383] = 193; em[384] = 56; 
    	em[385] = 396; em[386] = 64; 
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 8884097; em[391] = 8; em[392] = 0; /* 390: pointer.func */
    em[393] = 8884097; em[394] = 8; em[395] = 0; /* 393: pointer.func */
    em[396] = 8884097; em[397] = 8; em[398] = 0; /* 396: pointer.func */
    em[399] = 1; em[400] = 8; em[401] = 1; /* 399: pointer.struct.ecdh_method */
    	em[402] = 404; em[403] = 0; 
    em[404] = 0; em[405] = 32; em[406] = 3; /* 404: struct.ecdh_method */
    	em[407] = 179; em[408] = 0; 
    	em[409] = 413; em[410] = 8; 
    	em[411] = 193; em[412] = 24; 
    em[413] = 8884097; em[414] = 8; em[415] = 0; /* 413: pointer.func */
    em[416] = 1; em[417] = 8; em[418] = 1; /* 416: pointer.struct.ecdsa_method */
    	em[419] = 421; em[420] = 0; 
    em[421] = 0; em[422] = 48; em[423] = 5; /* 421: struct.ecdsa_method */
    	em[424] = 179; em[425] = 0; 
    	em[426] = 434; em[427] = 8; 
    	em[428] = 437; em[429] = 16; 
    	em[430] = 440; em[431] = 24; 
    	em[432] = 193; em[433] = 40; 
    em[434] = 8884097; em[435] = 8; em[436] = 0; /* 434: pointer.func */
    em[437] = 8884097; em[438] = 8; em[439] = 0; /* 437: pointer.func */
    em[440] = 8884097; em[441] = 8; em[442] = 0; /* 440: pointer.func */
    em[443] = 1; em[444] = 8; em[445] = 1; /* 443: pointer.struct.rand_meth_st */
    	em[446] = 448; em[447] = 0; 
    em[448] = 0; em[449] = 48; em[450] = 6; /* 448: struct.rand_meth_st */
    	em[451] = 463; em[452] = 0; 
    	em[453] = 466; em[454] = 8; 
    	em[455] = 469; em[456] = 16; 
    	em[457] = 472; em[458] = 24; 
    	em[459] = 466; em[460] = 32; 
    	em[461] = 475; em[462] = 40; 
    em[463] = 8884097; em[464] = 8; em[465] = 0; /* 463: pointer.func */
    em[466] = 8884097; em[467] = 8; em[468] = 0; /* 466: pointer.func */
    em[469] = 8884097; em[470] = 8; em[471] = 0; /* 469: pointer.func */
    em[472] = 8884097; em[473] = 8; em[474] = 0; /* 472: pointer.func */
    em[475] = 8884097; em[476] = 8; em[477] = 0; /* 475: pointer.func */
    em[478] = 1; em[479] = 8; em[480] = 1; /* 478: pointer.struct.store_method_st */
    	em[481] = 483; em[482] = 0; 
    em[483] = 0; em[484] = 0; em[485] = 0; /* 483: struct.store_method_st */
    em[486] = 8884097; em[487] = 8; em[488] = 0; /* 486: pointer.func */
    em[489] = 8884097; em[490] = 8; em[491] = 0; /* 489: pointer.func */
    em[492] = 8884097; em[493] = 8; em[494] = 0; /* 492: pointer.func */
    em[495] = 8884097; em[496] = 8; em[497] = 0; /* 495: pointer.func */
    em[498] = 8884097; em[499] = 8; em[500] = 0; /* 498: pointer.func */
    em[501] = 8884097; em[502] = 8; em[503] = 0; /* 501: pointer.func */
    em[504] = 8884097; em[505] = 8; em[506] = 0; /* 504: pointer.func */
    em[507] = 8884097; em[508] = 8; em[509] = 0; /* 507: pointer.func */
    em[510] = 1; em[511] = 8; em[512] = 1; /* 510: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[513] = 515; em[514] = 0; 
    em[515] = 0; em[516] = 32; em[517] = 2; /* 515: struct.ENGINE_CMD_DEFN_st */
    	em[518] = 179; em[519] = 8; 
    	em[520] = 179; em[521] = 16; 
    em[522] = 0; em[523] = 32; em[524] = 2; /* 522: struct.crypto_ex_data_st_fake */
    	em[525] = 529; em[526] = 8; 
    	em[527] = 152; em[528] = 24; 
    em[529] = 8884099; em[530] = 8; em[531] = 2; /* 529: pointer_to_array_of_pointers_to_stack */
    	em[532] = 149; em[533] = 0; 
    	em[534] = 118; em[535] = 20; 
    em[536] = 1; em[537] = 8; em[538] = 1; /* 536: pointer.struct.engine_st */
    	em[539] = 206; em[540] = 0; 
    em[541] = 8884097; em[542] = 8; em[543] = 0; /* 541: pointer.func */
    em[544] = 8884097; em[545] = 8; em[546] = 0; /* 544: pointer.func */
    em[547] = 1; em[548] = 8; em[549] = 1; /* 547: pointer.struct.asn1_string_st */
    	em[550] = 552; em[551] = 0; 
    em[552] = 0; em[553] = 24; em[554] = 1; /* 552: struct.asn1_string_st */
    	em[555] = 18; em[556] = 8; 
    em[557] = 1; em[558] = 8; em[559] = 1; /* 557: pointer.struct.dsa_method */
    	em[560] = 562; em[561] = 0; 
    em[562] = 0; em[563] = 96; em[564] = 11; /* 562: struct.dsa_method */
    	em[565] = 179; em[566] = 0; 
    	em[567] = 587; em[568] = 8; 
    	em[569] = 544; em[570] = 16; 
    	em[571] = 590; em[572] = 24; 
    	em[573] = 593; em[574] = 32; 
    	em[575] = 596; em[576] = 40; 
    	em[577] = 541; em[578] = 48; 
    	em[579] = 541; em[580] = 56; 
    	em[581] = 193; em[582] = 72; 
    	em[583] = 599; em[584] = 80; 
    	em[585] = 541; em[586] = 88; 
    em[587] = 8884097; em[588] = 8; em[589] = 0; /* 587: pointer.func */
    em[590] = 8884097; em[591] = 8; em[592] = 0; /* 590: pointer.func */
    em[593] = 8884097; em[594] = 8; em[595] = 0; /* 593: pointer.func */
    em[596] = 8884097; em[597] = 8; em[598] = 0; /* 596: pointer.func */
    em[599] = 8884097; em[600] = 8; em[601] = 0; /* 599: pointer.func */
    em[602] = 1; em[603] = 8; em[604] = 1; /* 602: pointer.struct.dsa_st */
    	em[605] = 607; em[606] = 0; 
    em[607] = 0; em[608] = 136; em[609] = 11; /* 607: struct.dsa_st */
    	em[610] = 632; em[611] = 24; 
    	em[612] = 632; em[613] = 32; 
    	em[614] = 632; em[615] = 40; 
    	em[616] = 632; em[617] = 48; 
    	em[618] = 632; em[619] = 56; 
    	em[620] = 632; em[621] = 64; 
    	em[622] = 632; em[623] = 72; 
    	em[624] = 649; em[625] = 88; 
    	em[626] = 663; em[627] = 104; 
    	em[628] = 557; em[629] = 120; 
    	em[630] = 677; em[631] = 128; 
    em[632] = 1; em[633] = 8; em[634] = 1; /* 632: pointer.struct.bignum_st */
    	em[635] = 637; em[636] = 0; 
    em[637] = 0; em[638] = 24; em[639] = 1; /* 637: struct.bignum_st */
    	em[640] = 642; em[641] = 0; 
    em[642] = 8884099; em[643] = 8; em[644] = 2; /* 642: pointer_to_array_of_pointers_to_stack */
    	em[645] = 115; em[646] = 0; 
    	em[647] = 118; em[648] = 12; 
    em[649] = 1; em[650] = 8; em[651] = 1; /* 649: pointer.struct.bn_mont_ctx_st */
    	em[652] = 654; em[653] = 0; 
    em[654] = 0; em[655] = 96; em[656] = 3; /* 654: struct.bn_mont_ctx_st */
    	em[657] = 637; em[658] = 8; 
    	em[659] = 637; em[660] = 32; 
    	em[661] = 637; em[662] = 56; 
    em[663] = 0; em[664] = 32; em[665] = 2; /* 663: struct.crypto_ex_data_st_fake */
    	em[666] = 670; em[667] = 8; 
    	em[668] = 152; em[669] = 24; 
    em[670] = 8884099; em[671] = 8; em[672] = 2; /* 670: pointer_to_array_of_pointers_to_stack */
    	em[673] = 149; em[674] = 0; 
    	em[675] = 118; em[676] = 20; 
    em[677] = 1; em[678] = 8; em[679] = 1; /* 677: pointer.struct.engine_st */
    	em[680] = 206; em[681] = 0; 
    em[682] = 8884097; em[683] = 8; em[684] = 0; /* 682: pointer.func */
    em[685] = 8884097; em[686] = 8; em[687] = 0; /* 685: pointer.func */
    em[688] = 1; em[689] = 8; em[690] = 1; /* 688: pointer.struct.engine_st */
    	em[691] = 206; em[692] = 0; 
    em[693] = 8884097; em[694] = 8; em[695] = 0; /* 693: pointer.func */
    em[696] = 1; em[697] = 8; em[698] = 1; /* 696: pointer.struct.ec_key_st */
    	em[699] = 701; em[700] = 0; 
    em[701] = 0; em[702] = 56; em[703] = 4; /* 701: struct.ec_key_st */
    	em[704] = 712; em[705] = 8; 
    	em[706] = 1154; em[707] = 16; 
    	em[708] = 1159; em[709] = 24; 
    	em[710] = 1176; em[711] = 48; 
    em[712] = 1; em[713] = 8; em[714] = 1; /* 712: pointer.struct.ec_group_st */
    	em[715] = 717; em[716] = 0; 
    em[717] = 0; em[718] = 232; em[719] = 12; /* 717: struct.ec_group_st */
    	em[720] = 744; em[721] = 0; 
    	em[722] = 910; em[723] = 8; 
    	em[724] = 1110; em[725] = 16; 
    	em[726] = 1110; em[727] = 40; 
    	em[728] = 18; em[729] = 80; 
    	em[730] = 1122; em[731] = 96; 
    	em[732] = 1110; em[733] = 104; 
    	em[734] = 1110; em[735] = 152; 
    	em[736] = 1110; em[737] = 176; 
    	em[738] = 149; em[739] = 208; 
    	em[740] = 149; em[741] = 216; 
    	em[742] = 1151; em[743] = 224; 
    em[744] = 1; em[745] = 8; em[746] = 1; /* 744: pointer.struct.ec_method_st */
    	em[747] = 749; em[748] = 0; 
    em[749] = 0; em[750] = 304; em[751] = 37; /* 749: struct.ec_method_st */
    	em[752] = 826; em[753] = 8; 
    	em[754] = 829; em[755] = 16; 
    	em[756] = 829; em[757] = 24; 
    	em[758] = 832; em[759] = 32; 
    	em[760] = 835; em[761] = 40; 
    	em[762] = 838; em[763] = 48; 
    	em[764] = 841; em[765] = 56; 
    	em[766] = 844; em[767] = 64; 
    	em[768] = 847; em[769] = 72; 
    	em[770] = 850; em[771] = 80; 
    	em[772] = 850; em[773] = 88; 
    	em[774] = 853; em[775] = 96; 
    	em[776] = 856; em[777] = 104; 
    	em[778] = 859; em[779] = 112; 
    	em[780] = 682; em[781] = 120; 
    	em[782] = 862; em[783] = 128; 
    	em[784] = 865; em[785] = 136; 
    	em[786] = 868; em[787] = 144; 
    	em[788] = 871; em[789] = 152; 
    	em[790] = 874; em[791] = 160; 
    	em[792] = 877; em[793] = 168; 
    	em[794] = 880; em[795] = 176; 
    	em[796] = 883; em[797] = 184; 
    	em[798] = 886; em[799] = 192; 
    	em[800] = 889; em[801] = 200; 
    	em[802] = 892; em[803] = 208; 
    	em[804] = 883; em[805] = 216; 
    	em[806] = 895; em[807] = 224; 
    	em[808] = 898; em[809] = 232; 
    	em[810] = 901; em[811] = 240; 
    	em[812] = 841; em[813] = 248; 
    	em[814] = 904; em[815] = 256; 
    	em[816] = 685; em[817] = 264; 
    	em[818] = 904; em[819] = 272; 
    	em[820] = 685; em[821] = 280; 
    	em[822] = 685; em[823] = 288; 
    	em[824] = 907; em[825] = 296; 
    em[826] = 8884097; em[827] = 8; em[828] = 0; /* 826: pointer.func */
    em[829] = 8884097; em[830] = 8; em[831] = 0; /* 829: pointer.func */
    em[832] = 8884097; em[833] = 8; em[834] = 0; /* 832: pointer.func */
    em[835] = 8884097; em[836] = 8; em[837] = 0; /* 835: pointer.func */
    em[838] = 8884097; em[839] = 8; em[840] = 0; /* 838: pointer.func */
    em[841] = 8884097; em[842] = 8; em[843] = 0; /* 841: pointer.func */
    em[844] = 8884097; em[845] = 8; em[846] = 0; /* 844: pointer.func */
    em[847] = 8884097; em[848] = 8; em[849] = 0; /* 847: pointer.func */
    em[850] = 8884097; em[851] = 8; em[852] = 0; /* 850: pointer.func */
    em[853] = 8884097; em[854] = 8; em[855] = 0; /* 853: pointer.func */
    em[856] = 8884097; em[857] = 8; em[858] = 0; /* 856: pointer.func */
    em[859] = 8884097; em[860] = 8; em[861] = 0; /* 859: pointer.func */
    em[862] = 8884097; em[863] = 8; em[864] = 0; /* 862: pointer.func */
    em[865] = 8884097; em[866] = 8; em[867] = 0; /* 865: pointer.func */
    em[868] = 8884097; em[869] = 8; em[870] = 0; /* 868: pointer.func */
    em[871] = 8884097; em[872] = 8; em[873] = 0; /* 871: pointer.func */
    em[874] = 8884097; em[875] = 8; em[876] = 0; /* 874: pointer.func */
    em[877] = 8884097; em[878] = 8; em[879] = 0; /* 877: pointer.func */
    em[880] = 8884097; em[881] = 8; em[882] = 0; /* 880: pointer.func */
    em[883] = 8884097; em[884] = 8; em[885] = 0; /* 883: pointer.func */
    em[886] = 8884097; em[887] = 8; em[888] = 0; /* 886: pointer.func */
    em[889] = 8884097; em[890] = 8; em[891] = 0; /* 889: pointer.func */
    em[892] = 8884097; em[893] = 8; em[894] = 0; /* 892: pointer.func */
    em[895] = 8884097; em[896] = 8; em[897] = 0; /* 895: pointer.func */
    em[898] = 8884097; em[899] = 8; em[900] = 0; /* 898: pointer.func */
    em[901] = 8884097; em[902] = 8; em[903] = 0; /* 901: pointer.func */
    em[904] = 8884097; em[905] = 8; em[906] = 0; /* 904: pointer.func */
    em[907] = 8884097; em[908] = 8; em[909] = 0; /* 907: pointer.func */
    em[910] = 1; em[911] = 8; em[912] = 1; /* 910: pointer.struct.ec_point_st */
    	em[913] = 915; em[914] = 0; 
    em[915] = 0; em[916] = 88; em[917] = 4; /* 915: struct.ec_point_st */
    	em[918] = 926; em[919] = 0; 
    	em[920] = 1098; em[921] = 8; 
    	em[922] = 1098; em[923] = 32; 
    	em[924] = 1098; em[925] = 56; 
    em[926] = 1; em[927] = 8; em[928] = 1; /* 926: pointer.struct.ec_method_st */
    	em[929] = 931; em[930] = 0; 
    em[931] = 0; em[932] = 304; em[933] = 37; /* 931: struct.ec_method_st */
    	em[934] = 1008; em[935] = 8; 
    	em[936] = 1011; em[937] = 16; 
    	em[938] = 1011; em[939] = 24; 
    	em[940] = 1014; em[941] = 32; 
    	em[942] = 1017; em[943] = 40; 
    	em[944] = 1020; em[945] = 48; 
    	em[946] = 1023; em[947] = 56; 
    	em[948] = 1026; em[949] = 64; 
    	em[950] = 1029; em[951] = 72; 
    	em[952] = 1032; em[953] = 80; 
    	em[954] = 1032; em[955] = 88; 
    	em[956] = 1035; em[957] = 96; 
    	em[958] = 1038; em[959] = 104; 
    	em[960] = 1041; em[961] = 112; 
    	em[962] = 1044; em[963] = 120; 
    	em[964] = 1047; em[965] = 128; 
    	em[966] = 1050; em[967] = 136; 
    	em[968] = 1053; em[969] = 144; 
    	em[970] = 1056; em[971] = 152; 
    	em[972] = 1059; em[973] = 160; 
    	em[974] = 1062; em[975] = 168; 
    	em[976] = 1065; em[977] = 176; 
    	em[978] = 1068; em[979] = 184; 
    	em[980] = 1071; em[981] = 192; 
    	em[982] = 1074; em[983] = 200; 
    	em[984] = 1077; em[985] = 208; 
    	em[986] = 1068; em[987] = 216; 
    	em[988] = 1080; em[989] = 224; 
    	em[990] = 1083; em[991] = 232; 
    	em[992] = 1086; em[993] = 240; 
    	em[994] = 1023; em[995] = 248; 
    	em[996] = 1089; em[997] = 256; 
    	em[998] = 1092; em[999] = 264; 
    	em[1000] = 1089; em[1001] = 272; 
    	em[1002] = 1092; em[1003] = 280; 
    	em[1004] = 1092; em[1005] = 288; 
    	em[1006] = 1095; em[1007] = 296; 
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
    em[1092] = 8884097; em[1093] = 8; em[1094] = 0; /* 1092: pointer.func */
    em[1095] = 8884097; em[1096] = 8; em[1097] = 0; /* 1095: pointer.func */
    em[1098] = 0; em[1099] = 24; em[1100] = 1; /* 1098: struct.bignum_st */
    	em[1101] = 1103; em[1102] = 0; 
    em[1103] = 8884099; em[1104] = 8; em[1105] = 2; /* 1103: pointer_to_array_of_pointers_to_stack */
    	em[1106] = 115; em[1107] = 0; 
    	em[1108] = 118; em[1109] = 12; 
    em[1110] = 0; em[1111] = 24; em[1112] = 1; /* 1110: struct.bignum_st */
    	em[1113] = 1115; em[1114] = 0; 
    em[1115] = 8884099; em[1116] = 8; em[1117] = 2; /* 1115: pointer_to_array_of_pointers_to_stack */
    	em[1118] = 115; em[1119] = 0; 
    	em[1120] = 118; em[1121] = 12; 
    em[1122] = 1; em[1123] = 8; em[1124] = 1; /* 1122: pointer.struct.ec_extra_data_st */
    	em[1125] = 1127; em[1126] = 0; 
    em[1127] = 0; em[1128] = 40; em[1129] = 5; /* 1127: struct.ec_extra_data_st */
    	em[1130] = 1140; em[1131] = 0; 
    	em[1132] = 149; em[1133] = 8; 
    	em[1134] = 1145; em[1135] = 16; 
    	em[1136] = 1148; em[1137] = 24; 
    	em[1138] = 1148; em[1139] = 32; 
    em[1140] = 1; em[1141] = 8; em[1142] = 1; /* 1140: pointer.struct.ec_extra_data_st */
    	em[1143] = 1127; em[1144] = 0; 
    em[1145] = 8884097; em[1146] = 8; em[1147] = 0; /* 1145: pointer.func */
    em[1148] = 8884097; em[1149] = 8; em[1150] = 0; /* 1148: pointer.func */
    em[1151] = 8884097; em[1152] = 8; em[1153] = 0; /* 1151: pointer.func */
    em[1154] = 1; em[1155] = 8; em[1156] = 1; /* 1154: pointer.struct.ec_point_st */
    	em[1157] = 915; em[1158] = 0; 
    em[1159] = 1; em[1160] = 8; em[1161] = 1; /* 1159: pointer.struct.bignum_st */
    	em[1162] = 1164; em[1163] = 0; 
    em[1164] = 0; em[1165] = 24; em[1166] = 1; /* 1164: struct.bignum_st */
    	em[1167] = 1169; em[1168] = 0; 
    em[1169] = 8884099; em[1170] = 8; em[1171] = 2; /* 1169: pointer_to_array_of_pointers_to_stack */
    	em[1172] = 115; em[1173] = 0; 
    	em[1174] = 118; em[1175] = 12; 
    em[1176] = 1; em[1177] = 8; em[1178] = 1; /* 1176: pointer.struct.ec_extra_data_st */
    	em[1179] = 1181; em[1180] = 0; 
    em[1181] = 0; em[1182] = 40; em[1183] = 5; /* 1181: struct.ec_extra_data_st */
    	em[1184] = 1194; em[1185] = 0; 
    	em[1186] = 149; em[1187] = 8; 
    	em[1188] = 1145; em[1189] = 16; 
    	em[1190] = 1148; em[1191] = 24; 
    	em[1192] = 1148; em[1193] = 32; 
    em[1194] = 1; em[1195] = 8; em[1196] = 1; /* 1194: pointer.struct.ec_extra_data_st */
    	em[1197] = 1181; em[1198] = 0; 
    em[1199] = 1; em[1200] = 8; em[1201] = 1; /* 1199: pointer.struct.bignum_st */
    	em[1202] = 1204; em[1203] = 0; 
    em[1204] = 0; em[1205] = 24; em[1206] = 1; /* 1204: struct.bignum_st */
    	em[1207] = 1209; em[1208] = 0; 
    em[1209] = 8884099; em[1210] = 8; em[1211] = 2; /* 1209: pointer_to_array_of_pointers_to_stack */
    	em[1212] = 115; em[1213] = 0; 
    	em[1214] = 118; em[1215] = 12; 
    em[1216] = 1; em[1217] = 8; em[1218] = 1; /* 1216: pointer.unsigned char */
    	em[1219] = 23; em[1220] = 0; 
    em[1221] = 8884097; em[1222] = 8; em[1223] = 0; /* 1221: pointer.func */
    em[1224] = 0; em[1225] = 1; em[1226] = 0; /* 1224: char */
    em[1227] = 1; em[1228] = 8; em[1229] = 1; /* 1227: pointer.struct.asn1_object_st */
    	em[1230] = 1232; em[1231] = 0; 
    em[1232] = 0; em[1233] = 40; em[1234] = 3; /* 1232: struct.asn1_object_st */
    	em[1235] = 179; em[1236] = 0; 
    	em[1237] = 179; em[1238] = 8; 
    	em[1239] = 1216; em[1240] = 24; 
    em[1241] = 8884097; em[1242] = 8; em[1243] = 0; /* 1241: pointer.func */
    em[1244] = 8884097; em[1245] = 8; em[1246] = 0; /* 1244: pointer.func */
    em[1247] = 8884097; em[1248] = 8; em[1249] = 0; /* 1247: pointer.func */
    em[1250] = 8884097; em[1251] = 8; em[1252] = 0; /* 1250: pointer.func */
    em[1253] = 0; em[1254] = 112; em[1255] = 13; /* 1253: struct.rsa_meth_st */
    	em[1256] = 179; em[1257] = 0; 
    	em[1258] = 1250; em[1259] = 8; 
    	em[1260] = 1250; em[1261] = 16; 
    	em[1262] = 1250; em[1263] = 24; 
    	em[1264] = 1250; em[1265] = 32; 
    	em[1266] = 1282; em[1267] = 40; 
    	em[1268] = 1247; em[1269] = 48; 
    	em[1270] = 1244; em[1271] = 56; 
    	em[1272] = 1244; em[1273] = 64; 
    	em[1274] = 193; em[1275] = 80; 
    	em[1276] = 1221; em[1277] = 88; 
    	em[1278] = 1285; em[1279] = 96; 
    	em[1280] = 693; em[1281] = 104; 
    em[1282] = 8884097; em[1283] = 8; em[1284] = 0; /* 1282: pointer.func */
    em[1285] = 8884097; em[1286] = 8; em[1287] = 0; /* 1285: pointer.func */
    em[1288] = 1; em[1289] = 8; em[1290] = 1; /* 1288: pointer.struct.rsa_meth_st */
    	em[1291] = 1253; em[1292] = 0; 
    em[1293] = 0; em[1294] = 168; em[1295] = 17; /* 1293: struct.rsa_st */
    	em[1296] = 1288; em[1297] = 16; 
    	em[1298] = 688; em[1299] = 24; 
    	em[1300] = 1199; em[1301] = 32; 
    	em[1302] = 1199; em[1303] = 40; 
    	em[1304] = 1199; em[1305] = 48; 
    	em[1306] = 1199; em[1307] = 56; 
    	em[1308] = 1199; em[1309] = 64; 
    	em[1310] = 1199; em[1311] = 72; 
    	em[1312] = 1199; em[1313] = 80; 
    	em[1314] = 1199; em[1315] = 88; 
    	em[1316] = 1330; em[1317] = 96; 
    	em[1318] = 1344; em[1319] = 120; 
    	em[1320] = 1344; em[1321] = 128; 
    	em[1322] = 1344; em[1323] = 136; 
    	em[1324] = 193; em[1325] = 144; 
    	em[1326] = 1358; em[1327] = 152; 
    	em[1328] = 1358; em[1329] = 160; 
    em[1330] = 0; em[1331] = 32; em[1332] = 2; /* 1330: struct.crypto_ex_data_st_fake */
    	em[1333] = 1337; em[1334] = 8; 
    	em[1335] = 152; em[1336] = 24; 
    em[1337] = 8884099; em[1338] = 8; em[1339] = 2; /* 1337: pointer_to_array_of_pointers_to_stack */
    	em[1340] = 149; em[1341] = 0; 
    	em[1342] = 118; em[1343] = 20; 
    em[1344] = 1; em[1345] = 8; em[1346] = 1; /* 1344: pointer.struct.bn_mont_ctx_st */
    	em[1347] = 1349; em[1348] = 0; 
    em[1349] = 0; em[1350] = 96; em[1351] = 3; /* 1349: struct.bn_mont_ctx_st */
    	em[1352] = 1204; em[1353] = 8; 
    	em[1354] = 1204; em[1355] = 32; 
    	em[1356] = 1204; em[1357] = 56; 
    em[1358] = 1; em[1359] = 8; em[1360] = 1; /* 1358: pointer.struct.bn_blinding_st */
    	em[1361] = 1363; em[1362] = 0; 
    em[1363] = 0; em[1364] = 88; em[1365] = 7; /* 1363: struct.bn_blinding_st */
    	em[1366] = 1380; em[1367] = 0; 
    	em[1368] = 1380; em[1369] = 8; 
    	em[1370] = 1380; em[1371] = 16; 
    	em[1372] = 1380; em[1373] = 24; 
    	em[1374] = 1397; em[1375] = 40; 
    	em[1376] = 1402; em[1377] = 72; 
    	em[1378] = 1416; em[1379] = 80; 
    em[1380] = 1; em[1381] = 8; em[1382] = 1; /* 1380: pointer.struct.bignum_st */
    	em[1383] = 1385; em[1384] = 0; 
    em[1385] = 0; em[1386] = 24; em[1387] = 1; /* 1385: struct.bignum_st */
    	em[1388] = 1390; em[1389] = 0; 
    em[1390] = 8884099; em[1391] = 8; em[1392] = 2; /* 1390: pointer_to_array_of_pointers_to_stack */
    	em[1393] = 115; em[1394] = 0; 
    	em[1395] = 118; em[1396] = 12; 
    em[1397] = 0; em[1398] = 16; em[1399] = 1; /* 1397: struct.crypto_threadid_st */
    	em[1400] = 149; em[1401] = 0; 
    em[1402] = 1; em[1403] = 8; em[1404] = 1; /* 1402: pointer.struct.bn_mont_ctx_st */
    	em[1405] = 1407; em[1406] = 0; 
    em[1407] = 0; em[1408] = 96; em[1409] = 3; /* 1407: struct.bn_mont_ctx_st */
    	em[1410] = 1385; em[1411] = 8; 
    	em[1412] = 1385; em[1413] = 32; 
    	em[1414] = 1385; em[1415] = 56; 
    em[1416] = 8884097; em[1417] = 8; em[1418] = 0; /* 1416: pointer.func */
    em[1419] = 8884101; em[1420] = 8; em[1421] = 6; /* 1419: union.union_of_evp_pkey_st */
    	em[1422] = 149; em[1423] = 0; 
    	em[1424] = 1434; em[1425] = 6; 
    	em[1426] = 602; em[1427] = 116; 
    	em[1428] = 1439; em[1429] = 28; 
    	em[1430] = 696; em[1431] = 408; 
    	em[1432] = 118; em[1433] = 0; 
    em[1434] = 1; em[1435] = 8; em[1436] = 1; /* 1434: pointer.struct.rsa_st */
    	em[1437] = 1293; em[1438] = 0; 
    em[1439] = 1; em[1440] = 8; em[1441] = 1; /* 1439: pointer.struct.dh_st */
    	em[1442] = 71; em[1443] = 0; 
    em[1444] = 8884097; em[1445] = 8; em[1446] = 0; /* 1444: pointer.func */
    em[1447] = 1; em[1448] = 8; em[1449] = 1; /* 1447: pointer.struct.evp_pkey_asn1_method_st */
    	em[1450] = 1452; em[1451] = 0; 
    em[1452] = 0; em[1453] = 208; em[1454] = 24; /* 1452: struct.evp_pkey_asn1_method_st */
    	em[1455] = 193; em[1456] = 16; 
    	em[1457] = 193; em[1458] = 24; 
    	em[1459] = 1503; em[1460] = 32; 
    	em[1461] = 1506; em[1462] = 40; 
    	em[1463] = 1509; em[1464] = 48; 
    	em[1465] = 1512; em[1466] = 56; 
    	em[1467] = 1515; em[1468] = 64; 
    	em[1469] = 1518; em[1470] = 72; 
    	em[1471] = 1512; em[1472] = 80; 
    	em[1473] = 1521; em[1474] = 88; 
    	em[1475] = 1521; em[1476] = 96; 
    	em[1477] = 1524; em[1478] = 104; 
    	em[1479] = 1527; em[1480] = 112; 
    	em[1481] = 1521; em[1482] = 120; 
    	em[1483] = 1241; em[1484] = 128; 
    	em[1485] = 1509; em[1486] = 136; 
    	em[1487] = 1512; em[1488] = 144; 
    	em[1489] = 1530; em[1490] = 152; 
    	em[1491] = 1533; em[1492] = 160; 
    	em[1493] = 1536; em[1494] = 168; 
    	em[1495] = 1524; em[1496] = 176; 
    	em[1497] = 1527; em[1498] = 184; 
    	em[1499] = 1444; em[1500] = 192; 
    	em[1501] = 1539; em[1502] = 200; 
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
    em[1536] = 8884097; em[1537] = 8; em[1538] = 0; /* 1536: pointer.func */
    em[1539] = 8884097; em[1540] = 8; em[1541] = 0; /* 1539: pointer.func */
    em[1542] = 8884099; em[1543] = 8; em[1544] = 2; /* 1542: pointer_to_array_of_pointers_to_stack */
    	em[1545] = 1549; em[1546] = 0; 
    	em[1547] = 118; em[1548] = 20; 
    em[1549] = 0; em[1550] = 8; em[1551] = 1; /* 1549: pointer.ASN1_TYPE */
    	em[1552] = 1554; em[1553] = 0; 
    em[1554] = 0; em[1555] = 0; em[1556] = 1; /* 1554: ASN1_TYPE */
    	em[1557] = 1559; em[1558] = 0; 
    em[1559] = 0; em[1560] = 16; em[1561] = 1; /* 1559: struct.asn1_type_st */
    	em[1562] = 1564; em[1563] = 8; 
    em[1564] = 0; em[1565] = 8; em[1566] = 20; /* 1564: union.unknown */
    	em[1567] = 193; em[1568] = 0; 
    	em[1569] = 1607; em[1570] = 0; 
    	em[1571] = 1227; em[1572] = 0; 
    	em[1573] = 1612; em[1574] = 0; 
    	em[1575] = 1617; em[1576] = 0; 
    	em[1577] = 1622; em[1578] = 0; 
    	em[1579] = 1627; em[1580] = 0; 
    	em[1581] = 1632; em[1582] = 0; 
    	em[1583] = 1637; em[1584] = 0; 
    	em[1585] = 547; em[1586] = 0; 
    	em[1587] = 1642; em[1588] = 0; 
    	em[1589] = 1647; em[1590] = 0; 
    	em[1591] = 1652; em[1592] = 0; 
    	em[1593] = 1657; em[1594] = 0; 
    	em[1595] = 1662; em[1596] = 0; 
    	em[1597] = 1667; em[1598] = 0; 
    	em[1599] = 1672; em[1600] = 0; 
    	em[1601] = 1607; em[1602] = 0; 
    	em[1603] = 1607; em[1604] = 0; 
    	em[1605] = 1677; em[1606] = 0; 
    em[1607] = 1; em[1608] = 8; em[1609] = 1; /* 1607: pointer.struct.asn1_string_st */
    	em[1610] = 552; em[1611] = 0; 
    em[1612] = 1; em[1613] = 8; em[1614] = 1; /* 1612: pointer.struct.asn1_string_st */
    	em[1615] = 552; em[1616] = 0; 
    em[1617] = 1; em[1618] = 8; em[1619] = 1; /* 1617: pointer.struct.asn1_string_st */
    	em[1620] = 552; em[1621] = 0; 
    em[1622] = 1; em[1623] = 8; em[1624] = 1; /* 1622: pointer.struct.asn1_string_st */
    	em[1625] = 552; em[1626] = 0; 
    em[1627] = 1; em[1628] = 8; em[1629] = 1; /* 1627: pointer.struct.asn1_string_st */
    	em[1630] = 552; em[1631] = 0; 
    em[1632] = 1; em[1633] = 8; em[1634] = 1; /* 1632: pointer.struct.asn1_string_st */
    	em[1635] = 552; em[1636] = 0; 
    em[1637] = 1; em[1638] = 8; em[1639] = 1; /* 1637: pointer.struct.asn1_string_st */
    	em[1640] = 552; em[1641] = 0; 
    em[1642] = 1; em[1643] = 8; em[1644] = 1; /* 1642: pointer.struct.asn1_string_st */
    	em[1645] = 552; em[1646] = 0; 
    em[1647] = 1; em[1648] = 8; em[1649] = 1; /* 1647: pointer.struct.asn1_string_st */
    	em[1650] = 552; em[1651] = 0; 
    em[1652] = 1; em[1653] = 8; em[1654] = 1; /* 1652: pointer.struct.asn1_string_st */
    	em[1655] = 552; em[1656] = 0; 
    em[1657] = 1; em[1658] = 8; em[1659] = 1; /* 1657: pointer.struct.asn1_string_st */
    	em[1660] = 552; em[1661] = 0; 
    em[1662] = 1; em[1663] = 8; em[1664] = 1; /* 1662: pointer.struct.asn1_string_st */
    	em[1665] = 552; em[1666] = 0; 
    em[1667] = 1; em[1668] = 8; em[1669] = 1; /* 1667: pointer.struct.asn1_string_st */
    	em[1670] = 552; em[1671] = 0; 
    em[1672] = 1; em[1673] = 8; em[1674] = 1; /* 1672: pointer.struct.asn1_string_st */
    	em[1675] = 552; em[1676] = 0; 
    em[1677] = 1; em[1678] = 8; em[1679] = 1; /* 1677: pointer.struct.ASN1_VALUE_st */
    	em[1680] = 1682; em[1681] = 0; 
    em[1682] = 0; em[1683] = 0; em[1684] = 0; /* 1682: struct.ASN1_VALUE_st */
    em[1685] = 0; em[1686] = 32; em[1687] = 2; /* 1685: struct.stack_st_fake_ASN1_TYPE */
    	em[1688] = 1542; em[1689] = 8; 
    	em[1690] = 152; em[1691] = 24; 
    em[1692] = 0; em[1693] = 24; em[1694] = 2; /* 1692: struct.x509_attributes_st */
    	em[1695] = 1699; em[1696] = 0; 
    	em[1697] = 1713; em[1698] = 16; 
    em[1699] = 1; em[1700] = 8; em[1701] = 1; /* 1699: pointer.struct.asn1_object_st */
    	em[1702] = 1704; em[1703] = 0; 
    em[1704] = 0; em[1705] = 40; em[1706] = 3; /* 1704: struct.asn1_object_st */
    	em[1707] = 179; em[1708] = 0; 
    	em[1709] = 179; em[1710] = 8; 
    	em[1711] = 1216; em[1712] = 24; 
    em[1713] = 0; em[1714] = 8; em[1715] = 3; /* 1713: union.unknown */
    	em[1716] = 193; em[1717] = 0; 
    	em[1718] = 1722; em[1719] = 0; 
    	em[1720] = 1727; em[1721] = 0; 
    em[1722] = 1; em[1723] = 8; em[1724] = 1; /* 1722: pointer.struct.stack_st_ASN1_TYPE */
    	em[1725] = 1685; em[1726] = 0; 
    em[1727] = 1; em[1728] = 8; em[1729] = 1; /* 1727: pointer.struct.asn1_type_st */
    	em[1730] = 1732; em[1731] = 0; 
    em[1732] = 0; em[1733] = 16; em[1734] = 1; /* 1732: struct.asn1_type_st */
    	em[1735] = 1737; em[1736] = 8; 
    em[1737] = 0; em[1738] = 8; em[1739] = 20; /* 1737: union.unknown */
    	em[1740] = 193; em[1741] = 0; 
    	em[1742] = 1780; em[1743] = 0; 
    	em[1744] = 1699; em[1745] = 0; 
    	em[1746] = 1785; em[1747] = 0; 
    	em[1748] = 66; em[1749] = 0; 
    	em[1750] = 61; em[1751] = 0; 
    	em[1752] = 56; em[1753] = 0; 
    	em[1754] = 1790; em[1755] = 0; 
    	em[1756] = 51; em[1757] = 0; 
    	em[1758] = 46; em[1759] = 0; 
    	em[1760] = 41; em[1761] = 0; 
    	em[1762] = 36; em[1763] = 0; 
    	em[1764] = 1795; em[1765] = 0; 
    	em[1766] = 31; em[1767] = 0; 
    	em[1768] = 26; em[1769] = 0; 
    	em[1770] = 1800; em[1771] = 0; 
    	em[1772] = 8; em[1773] = 0; 
    	em[1774] = 1780; em[1775] = 0; 
    	em[1776] = 1780; em[1777] = 0; 
    	em[1778] = 0; em[1779] = 0; 
    em[1780] = 1; em[1781] = 8; em[1782] = 1; /* 1780: pointer.struct.asn1_string_st */
    	em[1783] = 13; em[1784] = 0; 
    em[1785] = 1; em[1786] = 8; em[1787] = 1; /* 1785: pointer.struct.asn1_string_st */
    	em[1788] = 13; em[1789] = 0; 
    em[1790] = 1; em[1791] = 8; em[1792] = 1; /* 1790: pointer.struct.asn1_string_st */
    	em[1793] = 13; em[1794] = 0; 
    em[1795] = 1; em[1796] = 8; em[1797] = 1; /* 1795: pointer.struct.asn1_string_st */
    	em[1798] = 13; em[1799] = 0; 
    em[1800] = 1; em[1801] = 8; em[1802] = 1; /* 1800: pointer.struct.asn1_string_st */
    	em[1803] = 13; em[1804] = 0; 
    em[1805] = 0; em[1806] = 56; em[1807] = 4; /* 1805: struct.evp_pkey_st */
    	em[1808] = 1447; em[1809] = 16; 
    	em[1810] = 201; em[1811] = 24; 
    	em[1812] = 1419; em[1813] = 32; 
    	em[1814] = 1816; em[1815] = 48; 
    em[1816] = 1; em[1817] = 8; em[1818] = 1; /* 1816: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1819] = 1821; em[1820] = 0; 
    em[1821] = 0; em[1822] = 32; em[1823] = 2; /* 1821: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1824] = 1828; em[1825] = 8; 
    	em[1826] = 152; em[1827] = 24; 
    em[1828] = 8884099; em[1829] = 8; em[1830] = 2; /* 1828: pointer_to_array_of_pointers_to_stack */
    	em[1831] = 1835; em[1832] = 0; 
    	em[1833] = 118; em[1834] = 20; 
    em[1835] = 0; em[1836] = 8; em[1837] = 1; /* 1835: pointer.X509_ATTRIBUTE */
    	em[1838] = 1840; em[1839] = 0; 
    em[1840] = 0; em[1841] = 0; em[1842] = 1; /* 1840: X509_ATTRIBUTE */
    	em[1843] = 1692; em[1844] = 0; 
    em[1845] = 1; em[1846] = 8; em[1847] = 1; /* 1845: pointer.struct.evp_pkey_st */
    	em[1848] = 1805; em[1849] = 0; 
    args_addr->arg_entity_index[0] = 1845;
    args_addr->ret_entity_index = 118;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_PKEY_size)(EVP_PKEY *);
    orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
    *new_ret_ptr = (*orig_EVP_PKEY_size)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

