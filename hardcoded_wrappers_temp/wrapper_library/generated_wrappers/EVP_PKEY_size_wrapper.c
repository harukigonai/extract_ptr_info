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
    em[0] = 0; em[1] = 0; em[2] = 0; /* 0: struct.ASN1_VALUE_st */
    em[3] = 1; em[4] = 8; em[5] = 1; /* 3: pointer.struct.asn1_string_st */
    	em[6] = 8; em[7] = 0; 
    em[8] = 0; em[9] = 24; em[10] = 1; /* 8: struct.asn1_string_st */
    	em[11] = 13; em[12] = 8; 
    em[13] = 1; em[14] = 8; em[15] = 1; /* 13: pointer.unsigned char */
    	em[16] = 18; em[17] = 0; 
    em[18] = 0; em[19] = 1; em[20] = 0; /* 18: unsigned char */
    em[21] = 1; em[22] = 8; em[23] = 1; /* 21: pointer.struct.asn1_string_st */
    	em[24] = 8; em[25] = 0; 
    em[26] = 1; em[27] = 8; em[28] = 1; /* 26: pointer.struct.asn1_string_st */
    	em[29] = 8; em[30] = 0; 
    em[31] = 1; em[32] = 8; em[33] = 1; /* 31: pointer.struct.asn1_string_st */
    	em[34] = 8; em[35] = 0; 
    em[36] = 1; em[37] = 8; em[38] = 1; /* 36: pointer.struct.asn1_string_st */
    	em[39] = 8; em[40] = 0; 
    em[41] = 1; em[42] = 8; em[43] = 1; /* 41: pointer.struct.asn1_string_st */
    	em[44] = 8; em[45] = 0; 
    em[46] = 1; em[47] = 8; em[48] = 1; /* 46: pointer.struct.asn1_string_st */
    	em[49] = 8; em[50] = 0; 
    em[51] = 0; em[52] = 16; em[53] = 1; /* 51: struct.asn1_type_st */
    	em[54] = 56; em[55] = 8; 
    em[56] = 0; em[57] = 8; em[58] = 20; /* 56: union.unknown */
    	em[59] = 99; em[60] = 0; 
    	em[61] = 104; em[62] = 0; 
    	em[63] = 109; em[64] = 0; 
    	em[65] = 46; em[66] = 0; 
    	em[67] = 133; em[68] = 0; 
    	em[69] = 138; em[70] = 0; 
    	em[71] = 143; em[72] = 0; 
    	em[73] = 41; em[74] = 0; 
    	em[75] = 36; em[76] = 0; 
    	em[77] = 148; em[78] = 0; 
    	em[79] = 153; em[80] = 0; 
    	em[81] = 31; em[82] = 0; 
    	em[83] = 26; em[84] = 0; 
    	em[85] = 21; em[86] = 0; 
    	em[87] = 158; em[88] = 0; 
    	em[89] = 3; em[90] = 0; 
    	em[91] = 163; em[92] = 0; 
    	em[93] = 104; em[94] = 0; 
    	em[95] = 104; em[96] = 0; 
    	em[97] = 168; em[98] = 0; 
    em[99] = 1; em[100] = 8; em[101] = 1; /* 99: pointer.char */
    	em[102] = 8884096; em[103] = 0; 
    em[104] = 1; em[105] = 8; em[106] = 1; /* 104: pointer.struct.asn1_string_st */
    	em[107] = 8; em[108] = 0; 
    em[109] = 1; em[110] = 8; em[111] = 1; /* 109: pointer.struct.asn1_object_st */
    	em[112] = 114; em[113] = 0; 
    em[114] = 0; em[115] = 40; em[116] = 3; /* 114: struct.asn1_object_st */
    	em[117] = 123; em[118] = 0; 
    	em[119] = 123; em[120] = 8; 
    	em[121] = 128; em[122] = 24; 
    em[123] = 1; em[124] = 8; em[125] = 1; /* 123: pointer.char */
    	em[126] = 8884096; em[127] = 0; 
    em[128] = 1; em[129] = 8; em[130] = 1; /* 128: pointer.unsigned char */
    	em[131] = 18; em[132] = 0; 
    em[133] = 1; em[134] = 8; em[135] = 1; /* 133: pointer.struct.asn1_string_st */
    	em[136] = 8; em[137] = 0; 
    em[138] = 1; em[139] = 8; em[140] = 1; /* 138: pointer.struct.asn1_string_st */
    	em[141] = 8; em[142] = 0; 
    em[143] = 1; em[144] = 8; em[145] = 1; /* 143: pointer.struct.asn1_string_st */
    	em[146] = 8; em[147] = 0; 
    em[148] = 1; em[149] = 8; em[150] = 1; /* 148: pointer.struct.asn1_string_st */
    	em[151] = 8; em[152] = 0; 
    em[153] = 1; em[154] = 8; em[155] = 1; /* 153: pointer.struct.asn1_string_st */
    	em[156] = 8; em[157] = 0; 
    em[158] = 1; em[159] = 8; em[160] = 1; /* 158: pointer.struct.asn1_string_st */
    	em[161] = 8; em[162] = 0; 
    em[163] = 1; em[164] = 8; em[165] = 1; /* 163: pointer.struct.asn1_string_st */
    	em[166] = 8; em[167] = 0; 
    em[168] = 1; em[169] = 8; em[170] = 1; /* 168: pointer.struct.ASN1_VALUE_st */
    	em[171] = 0; em[172] = 0; 
    em[173] = 1; em[174] = 8; em[175] = 1; /* 173: pointer.struct.ASN1_VALUE_st */
    	em[176] = 178; em[177] = 0; 
    em[178] = 0; em[179] = 0; em[180] = 0; /* 178: struct.ASN1_VALUE_st */
    em[181] = 1; em[182] = 8; em[183] = 1; /* 181: pointer.struct.asn1_string_st */
    	em[184] = 186; em[185] = 0; 
    em[186] = 0; em[187] = 24; em[188] = 1; /* 186: struct.asn1_string_st */
    	em[189] = 13; em[190] = 8; 
    em[191] = 1; em[192] = 8; em[193] = 1; /* 191: pointer.struct.asn1_string_st */
    	em[194] = 186; em[195] = 0; 
    em[196] = 1; em[197] = 8; em[198] = 1; /* 196: pointer.struct.asn1_string_st */
    	em[199] = 186; em[200] = 0; 
    em[201] = 1; em[202] = 8; em[203] = 1; /* 201: pointer.struct.asn1_string_st */
    	em[204] = 186; em[205] = 0; 
    em[206] = 1; em[207] = 8; em[208] = 1; /* 206: pointer.struct.asn1_string_st */
    	em[209] = 186; em[210] = 0; 
    em[211] = 1; em[212] = 8; em[213] = 1; /* 211: pointer.struct.asn1_string_st */
    	em[214] = 186; em[215] = 0; 
    em[216] = 1; em[217] = 8; em[218] = 1; /* 216: pointer.struct.asn1_string_st */
    	em[219] = 186; em[220] = 0; 
    em[221] = 1; em[222] = 8; em[223] = 1; /* 221: pointer.struct.asn1_string_st */
    	em[224] = 186; em[225] = 0; 
    em[226] = 1; em[227] = 8; em[228] = 1; /* 226: pointer.struct.asn1_string_st */
    	em[229] = 186; em[230] = 0; 
    em[231] = 0; em[232] = 16; em[233] = 1; /* 231: struct.asn1_type_st */
    	em[234] = 236; em[235] = 8; 
    em[236] = 0; em[237] = 8; em[238] = 20; /* 236: union.unknown */
    	em[239] = 99; em[240] = 0; 
    	em[241] = 279; em[242] = 0; 
    	em[243] = 284; em[244] = 0; 
    	em[245] = 226; em[246] = 0; 
    	em[247] = 298; em[248] = 0; 
    	em[249] = 221; em[250] = 0; 
    	em[251] = 216; em[252] = 0; 
    	em[253] = 211; em[254] = 0; 
    	em[255] = 206; em[256] = 0; 
    	em[257] = 201; em[258] = 0; 
    	em[259] = 303; em[260] = 0; 
    	em[261] = 196; em[262] = 0; 
    	em[263] = 308; em[264] = 0; 
    	em[265] = 191; em[266] = 0; 
    	em[267] = 313; em[268] = 0; 
    	em[269] = 318; em[270] = 0; 
    	em[271] = 181; em[272] = 0; 
    	em[273] = 279; em[274] = 0; 
    	em[275] = 279; em[276] = 0; 
    	em[277] = 173; em[278] = 0; 
    em[279] = 1; em[280] = 8; em[281] = 1; /* 279: pointer.struct.asn1_string_st */
    	em[282] = 186; em[283] = 0; 
    em[284] = 1; em[285] = 8; em[286] = 1; /* 284: pointer.struct.asn1_object_st */
    	em[287] = 289; em[288] = 0; 
    em[289] = 0; em[290] = 40; em[291] = 3; /* 289: struct.asn1_object_st */
    	em[292] = 123; em[293] = 0; 
    	em[294] = 123; em[295] = 8; 
    	em[296] = 128; em[297] = 24; 
    em[298] = 1; em[299] = 8; em[300] = 1; /* 298: pointer.struct.asn1_string_st */
    	em[301] = 186; em[302] = 0; 
    em[303] = 1; em[304] = 8; em[305] = 1; /* 303: pointer.struct.asn1_string_st */
    	em[306] = 186; em[307] = 0; 
    em[308] = 1; em[309] = 8; em[310] = 1; /* 308: pointer.struct.asn1_string_st */
    	em[311] = 186; em[312] = 0; 
    em[313] = 1; em[314] = 8; em[315] = 1; /* 313: pointer.struct.asn1_string_st */
    	em[316] = 186; em[317] = 0; 
    em[318] = 1; em[319] = 8; em[320] = 1; /* 318: pointer.struct.asn1_string_st */
    	em[321] = 186; em[322] = 0; 
    em[323] = 0; em[324] = 0; em[325] = 1; /* 323: ASN1_TYPE */
    	em[326] = 231; em[327] = 0; 
    em[328] = 0; em[329] = 8; em[330] = 3; /* 328: union.unknown */
    	em[331] = 99; em[332] = 0; 
    	em[333] = 337; em[334] = 0; 
    	em[335] = 367; em[336] = 0; 
    em[337] = 1; em[338] = 8; em[339] = 1; /* 337: pointer.struct.stack_st_ASN1_TYPE */
    	em[340] = 342; em[341] = 0; 
    em[342] = 0; em[343] = 32; em[344] = 2; /* 342: struct.stack_st_fake_ASN1_TYPE */
    	em[345] = 349; em[346] = 8; 
    	em[347] = 364; em[348] = 24; 
    em[349] = 8884099; em[350] = 8; em[351] = 2; /* 349: pointer_to_array_of_pointers_to_stack */
    	em[352] = 356; em[353] = 0; 
    	em[354] = 361; em[355] = 20; 
    em[356] = 0; em[357] = 8; em[358] = 1; /* 356: pointer.ASN1_TYPE */
    	em[359] = 323; em[360] = 0; 
    em[361] = 0; em[362] = 4; em[363] = 0; /* 361: int */
    em[364] = 8884097; em[365] = 8; em[366] = 0; /* 364: pointer.func */
    em[367] = 1; em[368] = 8; em[369] = 1; /* 367: pointer.struct.asn1_type_st */
    	em[370] = 51; em[371] = 0; 
    em[372] = 0; em[373] = 24; em[374] = 2; /* 372: struct.x509_attributes_st */
    	em[375] = 109; em[376] = 0; 
    	em[377] = 328; em[378] = 16; 
    em[379] = 0; em[380] = 0; em[381] = 1; /* 379: X509_ATTRIBUTE */
    	em[382] = 372; em[383] = 0; 
    em[384] = 1; em[385] = 8; em[386] = 1; /* 384: pointer.struct.bignum_st */
    	em[387] = 389; em[388] = 0; 
    em[389] = 0; em[390] = 24; em[391] = 1; /* 389: struct.bignum_st */
    	em[392] = 394; em[393] = 0; 
    em[394] = 8884099; em[395] = 8; em[396] = 2; /* 394: pointer_to_array_of_pointers_to_stack */
    	em[397] = 401; em[398] = 0; 
    	em[399] = 361; em[400] = 12; 
    em[401] = 0; em[402] = 8; em[403] = 0; /* 401: long unsigned int */
    em[404] = 1; em[405] = 8; em[406] = 1; /* 404: pointer.struct.ec_point_st */
    	em[407] = 409; em[408] = 0; 
    em[409] = 0; em[410] = 88; em[411] = 4; /* 409: struct.ec_point_st */
    	em[412] = 420; em[413] = 0; 
    	em[414] = 592; em[415] = 8; 
    	em[416] = 592; em[417] = 32; 
    	em[418] = 592; em[419] = 56; 
    em[420] = 1; em[421] = 8; em[422] = 1; /* 420: pointer.struct.ec_method_st */
    	em[423] = 425; em[424] = 0; 
    em[425] = 0; em[426] = 304; em[427] = 37; /* 425: struct.ec_method_st */
    	em[428] = 502; em[429] = 8; 
    	em[430] = 505; em[431] = 16; 
    	em[432] = 505; em[433] = 24; 
    	em[434] = 508; em[435] = 32; 
    	em[436] = 511; em[437] = 40; 
    	em[438] = 514; em[439] = 48; 
    	em[440] = 517; em[441] = 56; 
    	em[442] = 520; em[443] = 64; 
    	em[444] = 523; em[445] = 72; 
    	em[446] = 526; em[447] = 80; 
    	em[448] = 526; em[449] = 88; 
    	em[450] = 529; em[451] = 96; 
    	em[452] = 532; em[453] = 104; 
    	em[454] = 535; em[455] = 112; 
    	em[456] = 538; em[457] = 120; 
    	em[458] = 541; em[459] = 128; 
    	em[460] = 544; em[461] = 136; 
    	em[462] = 547; em[463] = 144; 
    	em[464] = 550; em[465] = 152; 
    	em[466] = 553; em[467] = 160; 
    	em[468] = 556; em[469] = 168; 
    	em[470] = 559; em[471] = 176; 
    	em[472] = 562; em[473] = 184; 
    	em[474] = 565; em[475] = 192; 
    	em[476] = 568; em[477] = 200; 
    	em[478] = 571; em[479] = 208; 
    	em[480] = 562; em[481] = 216; 
    	em[482] = 574; em[483] = 224; 
    	em[484] = 577; em[485] = 232; 
    	em[486] = 580; em[487] = 240; 
    	em[488] = 517; em[489] = 248; 
    	em[490] = 583; em[491] = 256; 
    	em[492] = 586; em[493] = 264; 
    	em[494] = 583; em[495] = 272; 
    	em[496] = 586; em[497] = 280; 
    	em[498] = 586; em[499] = 288; 
    	em[500] = 589; em[501] = 296; 
    em[502] = 8884097; em[503] = 8; em[504] = 0; /* 502: pointer.func */
    em[505] = 8884097; em[506] = 8; em[507] = 0; /* 505: pointer.func */
    em[508] = 8884097; em[509] = 8; em[510] = 0; /* 508: pointer.func */
    em[511] = 8884097; em[512] = 8; em[513] = 0; /* 511: pointer.func */
    em[514] = 8884097; em[515] = 8; em[516] = 0; /* 514: pointer.func */
    em[517] = 8884097; em[518] = 8; em[519] = 0; /* 517: pointer.func */
    em[520] = 8884097; em[521] = 8; em[522] = 0; /* 520: pointer.func */
    em[523] = 8884097; em[524] = 8; em[525] = 0; /* 523: pointer.func */
    em[526] = 8884097; em[527] = 8; em[528] = 0; /* 526: pointer.func */
    em[529] = 8884097; em[530] = 8; em[531] = 0; /* 529: pointer.func */
    em[532] = 8884097; em[533] = 8; em[534] = 0; /* 532: pointer.func */
    em[535] = 8884097; em[536] = 8; em[537] = 0; /* 535: pointer.func */
    em[538] = 8884097; em[539] = 8; em[540] = 0; /* 538: pointer.func */
    em[541] = 8884097; em[542] = 8; em[543] = 0; /* 541: pointer.func */
    em[544] = 8884097; em[545] = 8; em[546] = 0; /* 544: pointer.func */
    em[547] = 8884097; em[548] = 8; em[549] = 0; /* 547: pointer.func */
    em[550] = 8884097; em[551] = 8; em[552] = 0; /* 550: pointer.func */
    em[553] = 8884097; em[554] = 8; em[555] = 0; /* 553: pointer.func */
    em[556] = 8884097; em[557] = 8; em[558] = 0; /* 556: pointer.func */
    em[559] = 8884097; em[560] = 8; em[561] = 0; /* 559: pointer.func */
    em[562] = 8884097; em[563] = 8; em[564] = 0; /* 562: pointer.func */
    em[565] = 8884097; em[566] = 8; em[567] = 0; /* 565: pointer.func */
    em[568] = 8884097; em[569] = 8; em[570] = 0; /* 568: pointer.func */
    em[571] = 8884097; em[572] = 8; em[573] = 0; /* 571: pointer.func */
    em[574] = 8884097; em[575] = 8; em[576] = 0; /* 574: pointer.func */
    em[577] = 8884097; em[578] = 8; em[579] = 0; /* 577: pointer.func */
    em[580] = 8884097; em[581] = 8; em[582] = 0; /* 580: pointer.func */
    em[583] = 8884097; em[584] = 8; em[585] = 0; /* 583: pointer.func */
    em[586] = 8884097; em[587] = 8; em[588] = 0; /* 586: pointer.func */
    em[589] = 8884097; em[590] = 8; em[591] = 0; /* 589: pointer.func */
    em[592] = 0; em[593] = 24; em[594] = 1; /* 592: struct.bignum_st */
    	em[595] = 597; em[596] = 0; 
    em[597] = 8884099; em[598] = 8; em[599] = 2; /* 597: pointer_to_array_of_pointers_to_stack */
    	em[600] = 401; em[601] = 0; 
    	em[602] = 361; em[603] = 12; 
    em[604] = 8884097; em[605] = 8; em[606] = 0; /* 604: pointer.func */
    em[607] = 1; em[608] = 8; em[609] = 1; /* 607: pointer.struct.ec_extra_data_st */
    	em[610] = 612; em[611] = 0; 
    em[612] = 0; em[613] = 40; em[614] = 5; /* 612: struct.ec_extra_data_st */
    	em[615] = 607; em[616] = 0; 
    	em[617] = 625; em[618] = 8; 
    	em[619] = 628; em[620] = 16; 
    	em[621] = 631; em[622] = 24; 
    	em[623] = 631; em[624] = 32; 
    em[625] = 0; em[626] = 8; em[627] = 0; /* 625: pointer.void */
    em[628] = 8884097; em[629] = 8; em[630] = 0; /* 628: pointer.func */
    em[631] = 8884097; em[632] = 8; em[633] = 0; /* 631: pointer.func */
    em[634] = 1; em[635] = 8; em[636] = 1; /* 634: pointer.struct.ec_extra_data_st */
    	em[637] = 639; em[638] = 0; 
    em[639] = 0; em[640] = 40; em[641] = 5; /* 639: struct.ec_extra_data_st */
    	em[642] = 652; em[643] = 0; 
    	em[644] = 625; em[645] = 8; 
    	em[646] = 628; em[647] = 16; 
    	em[648] = 631; em[649] = 24; 
    	em[650] = 631; em[651] = 32; 
    em[652] = 1; em[653] = 8; em[654] = 1; /* 652: pointer.struct.ec_extra_data_st */
    	em[655] = 639; em[656] = 0; 
    em[657] = 1; em[658] = 8; em[659] = 1; /* 657: pointer.struct.ec_extra_data_st */
    	em[660] = 612; em[661] = 0; 
    em[662] = 0; em[663] = 56; em[664] = 4; /* 662: struct.ec_key_st */
    	em[665] = 673; em[666] = 8; 
    	em[667] = 404; em[668] = 16; 
    	em[669] = 384; em[670] = 24; 
    	em[671] = 634; em[672] = 48; 
    em[673] = 1; em[674] = 8; em[675] = 1; /* 673: pointer.struct.ec_group_st */
    	em[676] = 678; em[677] = 0; 
    em[678] = 0; em[679] = 232; em[680] = 12; /* 678: struct.ec_group_st */
    	em[681] = 420; em[682] = 0; 
    	em[683] = 705; em[684] = 8; 
    	em[685] = 592; em[686] = 16; 
    	em[687] = 592; em[688] = 40; 
    	em[689] = 13; em[690] = 80; 
    	em[691] = 657; em[692] = 96; 
    	em[693] = 592; em[694] = 104; 
    	em[695] = 592; em[696] = 152; 
    	em[697] = 592; em[698] = 176; 
    	em[699] = 625; em[700] = 208; 
    	em[701] = 625; em[702] = 216; 
    	em[703] = 604; em[704] = 224; 
    em[705] = 1; em[706] = 8; em[707] = 1; /* 705: pointer.struct.ec_point_st */
    	em[708] = 409; em[709] = 0; 
    em[710] = 1; em[711] = 8; em[712] = 1; /* 710: pointer.struct.ec_key_st */
    	em[713] = 662; em[714] = 0; 
    em[715] = 8884097; em[716] = 8; em[717] = 0; /* 715: pointer.func */
    em[718] = 8884097; em[719] = 8; em[720] = 0; /* 718: pointer.func */
    em[721] = 8884097; em[722] = 8; em[723] = 0; /* 721: pointer.func */
    em[724] = 0; em[725] = 72; em[726] = 8; /* 724: struct.dh_method */
    	em[727] = 123; em[728] = 0; 
    	em[729] = 721; em[730] = 8; 
    	em[731] = 718; em[732] = 16; 
    	em[733] = 743; em[734] = 24; 
    	em[735] = 721; em[736] = 32; 
    	em[737] = 721; em[738] = 40; 
    	em[739] = 99; em[740] = 56; 
    	em[741] = 715; em[742] = 64; 
    em[743] = 8884097; em[744] = 8; em[745] = 0; /* 743: pointer.func */
    em[746] = 8884097; em[747] = 8; em[748] = 0; /* 746: pointer.func */
    em[749] = 8884097; em[750] = 8; em[751] = 0; /* 749: pointer.func */
    em[752] = 1; em[753] = 8; em[754] = 1; /* 752: pointer.struct.rand_meth_st */
    	em[755] = 757; em[756] = 0; 
    em[757] = 0; em[758] = 48; em[759] = 6; /* 757: struct.rand_meth_st */
    	em[760] = 772; em[761] = 0; 
    	em[762] = 775; em[763] = 8; 
    	em[764] = 778; em[765] = 16; 
    	em[766] = 781; em[767] = 24; 
    	em[768] = 775; em[769] = 32; 
    	em[770] = 784; em[771] = 40; 
    em[772] = 8884097; em[773] = 8; em[774] = 0; /* 772: pointer.func */
    em[775] = 8884097; em[776] = 8; em[777] = 0; /* 775: pointer.func */
    em[778] = 8884097; em[779] = 8; em[780] = 0; /* 778: pointer.func */
    em[781] = 8884097; em[782] = 8; em[783] = 0; /* 781: pointer.func */
    em[784] = 8884097; em[785] = 8; em[786] = 0; /* 784: pointer.func */
    em[787] = 8884097; em[788] = 8; em[789] = 0; /* 787: pointer.func */
    em[790] = 8884097; em[791] = 8; em[792] = 0; /* 790: pointer.func */
    em[793] = 8884097; em[794] = 8; em[795] = 0; /* 793: pointer.func */
    em[796] = 0; em[797] = 96; em[798] = 3; /* 796: struct.bn_mont_ctx_st */
    	em[799] = 805; em[800] = 8; 
    	em[801] = 805; em[802] = 32; 
    	em[803] = 805; em[804] = 56; 
    em[805] = 0; em[806] = 24; em[807] = 1; /* 805: struct.bignum_st */
    	em[808] = 810; em[809] = 0; 
    em[810] = 8884099; em[811] = 8; em[812] = 2; /* 810: pointer_to_array_of_pointers_to_stack */
    	em[813] = 401; em[814] = 0; 
    	em[815] = 361; em[816] = 12; 
    em[817] = 0; em[818] = 48; em[819] = 5; /* 817: struct.ecdsa_method */
    	em[820] = 123; em[821] = 0; 
    	em[822] = 793; em[823] = 8; 
    	em[824] = 790; em[825] = 16; 
    	em[826] = 787; em[827] = 24; 
    	em[828] = 99; em[829] = 40; 
    em[830] = 1; em[831] = 8; em[832] = 1; /* 830: pointer.struct.ecdh_method */
    	em[833] = 835; em[834] = 0; 
    em[835] = 0; em[836] = 32; em[837] = 3; /* 835: struct.ecdh_method */
    	em[838] = 123; em[839] = 0; 
    	em[840] = 844; em[841] = 8; 
    	em[842] = 99; em[843] = 24; 
    em[844] = 8884097; em[845] = 8; em[846] = 0; /* 844: pointer.func */
    em[847] = 8884097; em[848] = 8; em[849] = 0; /* 847: pointer.func */
    em[850] = 8884097; em[851] = 8; em[852] = 0; /* 850: pointer.func */
    em[853] = 1; em[854] = 8; em[855] = 1; /* 853: pointer.struct.bn_mont_ctx_st */
    	em[856] = 858; em[857] = 0; 
    em[858] = 0; em[859] = 96; em[860] = 3; /* 858: struct.bn_mont_ctx_st */
    	em[861] = 867; em[862] = 8; 
    	em[863] = 867; em[864] = 32; 
    	em[865] = 867; em[866] = 56; 
    em[867] = 0; em[868] = 24; em[869] = 1; /* 867: struct.bignum_st */
    	em[870] = 872; em[871] = 0; 
    em[872] = 8884099; em[873] = 8; em[874] = 2; /* 872: pointer_to_array_of_pointers_to_stack */
    	em[875] = 401; em[876] = 0; 
    	em[877] = 361; em[878] = 12; 
    em[879] = 0; em[880] = 72; em[881] = 8; /* 879: struct.dh_method */
    	em[882] = 123; em[883] = 0; 
    	em[884] = 850; em[885] = 8; 
    	em[886] = 898; em[887] = 16; 
    	em[888] = 847; em[889] = 24; 
    	em[890] = 850; em[891] = 32; 
    	em[892] = 850; em[893] = 40; 
    	em[894] = 99; em[895] = 56; 
    	em[896] = 901; em[897] = 64; 
    em[898] = 8884097; em[899] = 8; em[900] = 0; /* 898: pointer.func */
    em[901] = 8884097; em[902] = 8; em[903] = 0; /* 901: pointer.func */
    em[904] = 8884097; em[905] = 8; em[906] = 0; /* 904: pointer.func */
    em[907] = 8884097; em[908] = 8; em[909] = 0; /* 907: pointer.func */
    em[910] = 8884097; em[911] = 8; em[912] = 0; /* 910: pointer.func */
    em[913] = 0; em[914] = 168; em[915] = 17; /* 913: struct.rsa_st */
    	em[916] = 950; em[917] = 16; 
    	em[918] = 1005; em[919] = 24; 
    	em[920] = 1231; em[921] = 32; 
    	em[922] = 1231; em[923] = 40; 
    	em[924] = 1231; em[925] = 48; 
    	em[926] = 1231; em[927] = 56; 
    	em[928] = 1231; em[929] = 64; 
    	em[930] = 1231; em[931] = 72; 
    	em[932] = 1231; em[933] = 80; 
    	em[934] = 1231; em[935] = 88; 
    	em[936] = 1236; em[937] = 96; 
    	em[938] = 853; em[939] = 120; 
    	em[940] = 853; em[941] = 128; 
    	em[942] = 853; em[943] = 136; 
    	em[944] = 99; em[945] = 144; 
    	em[946] = 1250; em[947] = 152; 
    	em[948] = 1250; em[949] = 160; 
    em[950] = 1; em[951] = 8; em[952] = 1; /* 950: pointer.struct.rsa_meth_st */
    	em[953] = 955; em[954] = 0; 
    em[955] = 0; em[956] = 112; em[957] = 13; /* 955: struct.rsa_meth_st */
    	em[958] = 123; em[959] = 0; 
    	em[960] = 984; em[961] = 8; 
    	em[962] = 984; em[963] = 16; 
    	em[964] = 984; em[965] = 24; 
    	em[966] = 984; em[967] = 32; 
    	em[968] = 987; em[969] = 40; 
    	em[970] = 990; em[971] = 48; 
    	em[972] = 993; em[973] = 56; 
    	em[974] = 993; em[975] = 64; 
    	em[976] = 99; em[977] = 80; 
    	em[978] = 996; em[979] = 88; 
    	em[980] = 999; em[981] = 96; 
    	em[982] = 1002; em[983] = 104; 
    em[984] = 8884097; em[985] = 8; em[986] = 0; /* 984: pointer.func */
    em[987] = 8884097; em[988] = 8; em[989] = 0; /* 987: pointer.func */
    em[990] = 8884097; em[991] = 8; em[992] = 0; /* 990: pointer.func */
    em[993] = 8884097; em[994] = 8; em[995] = 0; /* 993: pointer.func */
    em[996] = 8884097; em[997] = 8; em[998] = 0; /* 996: pointer.func */
    em[999] = 8884097; em[1000] = 8; em[1001] = 0; /* 999: pointer.func */
    em[1002] = 8884097; em[1003] = 8; em[1004] = 0; /* 1002: pointer.func */
    em[1005] = 1; em[1006] = 8; em[1007] = 1; /* 1005: pointer.struct.engine_st */
    	em[1008] = 1010; em[1009] = 0; 
    em[1010] = 0; em[1011] = 216; em[1012] = 24; /* 1010: struct.engine_st */
    	em[1013] = 123; em[1014] = 0; 
    	em[1015] = 123; em[1016] = 8; 
    	em[1017] = 1061; em[1018] = 16; 
    	em[1019] = 1116; em[1020] = 24; 
    	em[1021] = 1164; em[1022] = 32; 
    	em[1023] = 830; em[1024] = 40; 
    	em[1025] = 1169; em[1026] = 48; 
    	em[1027] = 752; em[1028] = 56; 
    	em[1029] = 1174; em[1030] = 64; 
    	em[1031] = 1182; em[1032] = 72; 
    	em[1033] = 1185; em[1034] = 80; 
    	em[1035] = 1188; em[1036] = 88; 
    	em[1037] = 746; em[1038] = 96; 
    	em[1039] = 910; em[1040] = 104; 
    	em[1041] = 910; em[1042] = 112; 
    	em[1043] = 910; em[1044] = 120; 
    	em[1045] = 1191; em[1046] = 128; 
    	em[1047] = 1194; em[1048] = 136; 
    	em[1049] = 1194; em[1050] = 144; 
    	em[1051] = 1197; em[1052] = 152; 
    	em[1053] = 1200; em[1054] = 160; 
    	em[1055] = 1212; em[1056] = 184; 
    	em[1057] = 1226; em[1058] = 200; 
    	em[1059] = 1226; em[1060] = 208; 
    em[1061] = 1; em[1062] = 8; em[1063] = 1; /* 1061: pointer.struct.rsa_meth_st */
    	em[1064] = 1066; em[1065] = 0; 
    em[1066] = 0; em[1067] = 112; em[1068] = 13; /* 1066: struct.rsa_meth_st */
    	em[1069] = 123; em[1070] = 0; 
    	em[1071] = 1095; em[1072] = 8; 
    	em[1073] = 1095; em[1074] = 16; 
    	em[1075] = 1095; em[1076] = 24; 
    	em[1077] = 1095; em[1078] = 32; 
    	em[1079] = 1098; em[1080] = 40; 
    	em[1081] = 1101; em[1082] = 48; 
    	em[1083] = 1104; em[1084] = 56; 
    	em[1085] = 1104; em[1086] = 64; 
    	em[1087] = 99; em[1088] = 80; 
    	em[1089] = 1107; em[1090] = 88; 
    	em[1091] = 1110; em[1092] = 96; 
    	em[1093] = 1113; em[1094] = 104; 
    em[1095] = 8884097; em[1096] = 8; em[1097] = 0; /* 1095: pointer.func */
    em[1098] = 8884097; em[1099] = 8; em[1100] = 0; /* 1098: pointer.func */
    em[1101] = 8884097; em[1102] = 8; em[1103] = 0; /* 1101: pointer.func */
    em[1104] = 8884097; em[1105] = 8; em[1106] = 0; /* 1104: pointer.func */
    em[1107] = 8884097; em[1108] = 8; em[1109] = 0; /* 1107: pointer.func */
    em[1110] = 8884097; em[1111] = 8; em[1112] = 0; /* 1110: pointer.func */
    em[1113] = 8884097; em[1114] = 8; em[1115] = 0; /* 1113: pointer.func */
    em[1116] = 1; em[1117] = 8; em[1118] = 1; /* 1116: pointer.struct.dsa_method */
    	em[1119] = 1121; em[1120] = 0; 
    em[1121] = 0; em[1122] = 96; em[1123] = 11; /* 1121: struct.dsa_method */
    	em[1124] = 123; em[1125] = 0; 
    	em[1126] = 1146; em[1127] = 8; 
    	em[1128] = 1149; em[1129] = 16; 
    	em[1130] = 1152; em[1131] = 24; 
    	em[1132] = 1155; em[1133] = 32; 
    	em[1134] = 904; em[1135] = 40; 
    	em[1136] = 1158; em[1137] = 48; 
    	em[1138] = 1158; em[1139] = 56; 
    	em[1140] = 99; em[1141] = 72; 
    	em[1142] = 1161; em[1143] = 80; 
    	em[1144] = 1158; em[1145] = 88; 
    em[1146] = 8884097; em[1147] = 8; em[1148] = 0; /* 1146: pointer.func */
    em[1149] = 8884097; em[1150] = 8; em[1151] = 0; /* 1149: pointer.func */
    em[1152] = 8884097; em[1153] = 8; em[1154] = 0; /* 1152: pointer.func */
    em[1155] = 8884097; em[1156] = 8; em[1157] = 0; /* 1155: pointer.func */
    em[1158] = 8884097; em[1159] = 8; em[1160] = 0; /* 1158: pointer.func */
    em[1161] = 8884097; em[1162] = 8; em[1163] = 0; /* 1161: pointer.func */
    em[1164] = 1; em[1165] = 8; em[1166] = 1; /* 1164: pointer.struct.dh_method */
    	em[1167] = 879; em[1168] = 0; 
    em[1169] = 1; em[1170] = 8; em[1171] = 1; /* 1169: pointer.struct.ecdsa_method */
    	em[1172] = 817; em[1173] = 0; 
    em[1174] = 1; em[1175] = 8; em[1176] = 1; /* 1174: pointer.struct.store_method_st */
    	em[1177] = 1179; em[1178] = 0; 
    em[1179] = 0; em[1180] = 0; em[1181] = 0; /* 1179: struct.store_method_st */
    em[1182] = 8884097; em[1183] = 8; em[1184] = 0; /* 1182: pointer.func */
    em[1185] = 8884097; em[1186] = 8; em[1187] = 0; /* 1185: pointer.func */
    em[1188] = 8884097; em[1189] = 8; em[1190] = 0; /* 1188: pointer.func */
    em[1191] = 8884097; em[1192] = 8; em[1193] = 0; /* 1191: pointer.func */
    em[1194] = 8884097; em[1195] = 8; em[1196] = 0; /* 1194: pointer.func */
    em[1197] = 8884097; em[1198] = 8; em[1199] = 0; /* 1197: pointer.func */
    em[1200] = 1; em[1201] = 8; em[1202] = 1; /* 1200: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1203] = 1205; em[1204] = 0; 
    em[1205] = 0; em[1206] = 32; em[1207] = 2; /* 1205: struct.ENGINE_CMD_DEFN_st */
    	em[1208] = 123; em[1209] = 8; 
    	em[1210] = 123; em[1211] = 16; 
    em[1212] = 0; em[1213] = 32; em[1214] = 2; /* 1212: struct.crypto_ex_data_st_fake */
    	em[1215] = 1219; em[1216] = 8; 
    	em[1217] = 364; em[1218] = 24; 
    em[1219] = 8884099; em[1220] = 8; em[1221] = 2; /* 1219: pointer_to_array_of_pointers_to_stack */
    	em[1222] = 625; em[1223] = 0; 
    	em[1224] = 361; em[1225] = 20; 
    em[1226] = 1; em[1227] = 8; em[1228] = 1; /* 1226: pointer.struct.engine_st */
    	em[1229] = 1010; em[1230] = 0; 
    em[1231] = 1; em[1232] = 8; em[1233] = 1; /* 1231: pointer.struct.bignum_st */
    	em[1234] = 867; em[1235] = 0; 
    em[1236] = 0; em[1237] = 32; em[1238] = 2; /* 1236: struct.crypto_ex_data_st_fake */
    	em[1239] = 1243; em[1240] = 8; 
    	em[1241] = 364; em[1242] = 24; 
    em[1243] = 8884099; em[1244] = 8; em[1245] = 2; /* 1243: pointer_to_array_of_pointers_to_stack */
    	em[1246] = 625; em[1247] = 0; 
    	em[1248] = 361; em[1249] = 20; 
    em[1250] = 1; em[1251] = 8; em[1252] = 1; /* 1250: pointer.struct.bn_blinding_st */
    	em[1253] = 1255; em[1254] = 0; 
    em[1255] = 0; em[1256] = 88; em[1257] = 7; /* 1255: struct.bn_blinding_st */
    	em[1258] = 1272; em[1259] = 0; 
    	em[1260] = 1272; em[1261] = 8; 
    	em[1262] = 1272; em[1263] = 16; 
    	em[1264] = 1272; em[1265] = 24; 
    	em[1266] = 1289; em[1267] = 40; 
    	em[1268] = 1294; em[1269] = 72; 
    	em[1270] = 1308; em[1271] = 80; 
    em[1272] = 1; em[1273] = 8; em[1274] = 1; /* 1272: pointer.struct.bignum_st */
    	em[1275] = 1277; em[1276] = 0; 
    em[1277] = 0; em[1278] = 24; em[1279] = 1; /* 1277: struct.bignum_st */
    	em[1280] = 1282; em[1281] = 0; 
    em[1282] = 8884099; em[1283] = 8; em[1284] = 2; /* 1282: pointer_to_array_of_pointers_to_stack */
    	em[1285] = 401; em[1286] = 0; 
    	em[1287] = 361; em[1288] = 12; 
    em[1289] = 0; em[1290] = 16; em[1291] = 1; /* 1289: struct.crypto_threadid_st */
    	em[1292] = 625; em[1293] = 0; 
    em[1294] = 1; em[1295] = 8; em[1296] = 1; /* 1294: pointer.struct.bn_mont_ctx_st */
    	em[1297] = 1299; em[1298] = 0; 
    em[1299] = 0; em[1300] = 96; em[1301] = 3; /* 1299: struct.bn_mont_ctx_st */
    	em[1302] = 1277; em[1303] = 8; 
    	em[1304] = 1277; em[1305] = 32; 
    	em[1306] = 1277; em[1307] = 56; 
    em[1308] = 8884097; em[1309] = 8; em[1310] = 0; /* 1308: pointer.func */
    em[1311] = 8884097; em[1312] = 8; em[1313] = 0; /* 1311: pointer.func */
    em[1314] = 0; em[1315] = 96; em[1316] = 11; /* 1314: struct.dsa_method */
    	em[1317] = 123; em[1318] = 0; 
    	em[1319] = 1339; em[1320] = 8; 
    	em[1321] = 1342; em[1322] = 16; 
    	em[1323] = 1345; em[1324] = 24; 
    	em[1325] = 1348; em[1326] = 32; 
    	em[1327] = 1351; em[1328] = 40; 
    	em[1329] = 749; em[1330] = 48; 
    	em[1331] = 749; em[1332] = 56; 
    	em[1333] = 99; em[1334] = 72; 
    	em[1335] = 1354; em[1336] = 80; 
    	em[1337] = 749; em[1338] = 88; 
    em[1339] = 8884097; em[1340] = 8; em[1341] = 0; /* 1339: pointer.func */
    em[1342] = 8884097; em[1343] = 8; em[1344] = 0; /* 1342: pointer.func */
    em[1345] = 8884097; em[1346] = 8; em[1347] = 0; /* 1345: pointer.func */
    em[1348] = 8884097; em[1349] = 8; em[1350] = 0; /* 1348: pointer.func */
    em[1351] = 8884097; em[1352] = 8; em[1353] = 0; /* 1351: pointer.func */
    em[1354] = 8884097; em[1355] = 8; em[1356] = 0; /* 1354: pointer.func */
    em[1357] = 1; em[1358] = 8; em[1359] = 1; /* 1357: pointer.struct.dh_method */
    	em[1360] = 724; em[1361] = 0; 
    em[1362] = 8884097; em[1363] = 8; em[1364] = 0; /* 1362: pointer.func */
    em[1365] = 8884097; em[1366] = 8; em[1367] = 0; /* 1365: pointer.func */
    em[1368] = 1; em[1369] = 8; em[1370] = 1; /* 1368: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1371] = 1373; em[1372] = 0; 
    em[1373] = 0; em[1374] = 32; em[1375] = 2; /* 1373: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1376] = 1380; em[1377] = 8; 
    	em[1378] = 364; em[1379] = 24; 
    em[1380] = 8884099; em[1381] = 8; em[1382] = 2; /* 1380: pointer_to_array_of_pointers_to_stack */
    	em[1383] = 1387; em[1384] = 0; 
    	em[1385] = 361; em[1386] = 20; 
    em[1387] = 0; em[1388] = 8; em[1389] = 1; /* 1387: pointer.X509_ATTRIBUTE */
    	em[1390] = 379; em[1391] = 0; 
    em[1392] = 8884097; em[1393] = 8; em[1394] = 0; /* 1392: pointer.func */
    em[1395] = 8884097; em[1396] = 8; em[1397] = 0; /* 1395: pointer.func */
    em[1398] = 0; em[1399] = 208; em[1400] = 24; /* 1398: struct.evp_pkey_asn1_method_st */
    	em[1401] = 99; em[1402] = 16; 
    	em[1403] = 99; em[1404] = 24; 
    	em[1405] = 1365; em[1406] = 32; 
    	em[1407] = 1362; em[1408] = 40; 
    	em[1409] = 1449; em[1410] = 48; 
    	em[1411] = 1452; em[1412] = 56; 
    	em[1413] = 1311; em[1414] = 64; 
    	em[1415] = 1392; em[1416] = 72; 
    	em[1417] = 1452; em[1418] = 80; 
    	em[1419] = 1455; em[1420] = 88; 
    	em[1421] = 1455; em[1422] = 96; 
    	em[1423] = 1458; em[1424] = 104; 
    	em[1425] = 907; em[1426] = 112; 
    	em[1427] = 1455; em[1428] = 120; 
    	em[1429] = 1395; em[1430] = 128; 
    	em[1431] = 1449; em[1432] = 136; 
    	em[1433] = 1452; em[1434] = 144; 
    	em[1435] = 1461; em[1436] = 152; 
    	em[1437] = 1464; em[1438] = 160; 
    	em[1439] = 1467; em[1440] = 168; 
    	em[1441] = 1458; em[1442] = 176; 
    	em[1443] = 907; em[1444] = 184; 
    	em[1445] = 1470; em[1446] = 192; 
    	em[1447] = 1473; em[1448] = 200; 
    em[1449] = 8884097; em[1450] = 8; em[1451] = 0; /* 1449: pointer.func */
    em[1452] = 8884097; em[1453] = 8; em[1454] = 0; /* 1452: pointer.func */
    em[1455] = 8884097; em[1456] = 8; em[1457] = 0; /* 1455: pointer.func */
    em[1458] = 8884097; em[1459] = 8; em[1460] = 0; /* 1458: pointer.func */
    em[1461] = 8884097; em[1462] = 8; em[1463] = 0; /* 1461: pointer.func */
    em[1464] = 8884097; em[1465] = 8; em[1466] = 0; /* 1464: pointer.func */
    em[1467] = 8884097; em[1468] = 8; em[1469] = 0; /* 1467: pointer.func */
    em[1470] = 8884097; em[1471] = 8; em[1472] = 0; /* 1470: pointer.func */
    em[1473] = 8884097; em[1474] = 8; em[1475] = 0; /* 1473: pointer.func */
    em[1476] = 0; em[1477] = 1; em[1478] = 0; /* 1476: char */
    em[1479] = 0; em[1480] = 56; em[1481] = 4; /* 1479: struct.evp_pkey_st */
    	em[1482] = 1490; em[1483] = 16; 
    	em[1484] = 1495; em[1485] = 24; 
    	em[1486] = 1500; em[1487] = 32; 
    	em[1488] = 1368; em[1489] = 48; 
    em[1490] = 1; em[1491] = 8; em[1492] = 1; /* 1490: pointer.struct.evp_pkey_asn1_method_st */
    	em[1493] = 1398; em[1494] = 0; 
    em[1495] = 1; em[1496] = 8; em[1497] = 1; /* 1495: pointer.struct.engine_st */
    	em[1498] = 1010; em[1499] = 0; 
    em[1500] = 8884101; em[1501] = 8; em[1502] = 6; /* 1500: union.union_of_evp_pkey_st */
    	em[1503] = 625; em[1504] = 0; 
    	em[1505] = 1515; em[1506] = 6; 
    	em[1507] = 1520; em[1508] = 116; 
    	em[1509] = 1584; em[1510] = 28; 
    	em[1511] = 710; em[1512] = 408; 
    	em[1513] = 361; em[1514] = 0; 
    em[1515] = 1; em[1516] = 8; em[1517] = 1; /* 1515: pointer.struct.rsa_st */
    	em[1518] = 913; em[1519] = 0; 
    em[1520] = 1; em[1521] = 8; em[1522] = 1; /* 1520: pointer.struct.dsa_st */
    	em[1523] = 1525; em[1524] = 0; 
    em[1525] = 0; em[1526] = 136; em[1527] = 11; /* 1525: struct.dsa_st */
    	em[1528] = 1550; em[1529] = 24; 
    	em[1530] = 1550; em[1531] = 32; 
    	em[1532] = 1550; em[1533] = 40; 
    	em[1534] = 1550; em[1535] = 48; 
    	em[1536] = 1550; em[1537] = 56; 
    	em[1538] = 1550; em[1539] = 64; 
    	em[1540] = 1550; em[1541] = 72; 
    	em[1542] = 1555; em[1543] = 88; 
    	em[1544] = 1560; em[1545] = 104; 
    	em[1546] = 1574; em[1547] = 120; 
    	em[1548] = 1579; em[1549] = 128; 
    em[1550] = 1; em[1551] = 8; em[1552] = 1; /* 1550: pointer.struct.bignum_st */
    	em[1553] = 805; em[1554] = 0; 
    em[1555] = 1; em[1556] = 8; em[1557] = 1; /* 1555: pointer.struct.bn_mont_ctx_st */
    	em[1558] = 796; em[1559] = 0; 
    em[1560] = 0; em[1561] = 32; em[1562] = 2; /* 1560: struct.crypto_ex_data_st_fake */
    	em[1563] = 1567; em[1564] = 8; 
    	em[1565] = 364; em[1566] = 24; 
    em[1567] = 8884099; em[1568] = 8; em[1569] = 2; /* 1567: pointer_to_array_of_pointers_to_stack */
    	em[1570] = 625; em[1571] = 0; 
    	em[1572] = 361; em[1573] = 20; 
    em[1574] = 1; em[1575] = 8; em[1576] = 1; /* 1574: pointer.struct.dsa_method */
    	em[1577] = 1314; em[1578] = 0; 
    em[1579] = 1; em[1580] = 8; em[1581] = 1; /* 1579: pointer.struct.engine_st */
    	em[1582] = 1010; em[1583] = 0; 
    em[1584] = 1; em[1585] = 8; em[1586] = 1; /* 1584: pointer.struct.dh_st */
    	em[1587] = 1589; em[1588] = 0; 
    em[1589] = 0; em[1590] = 144; em[1591] = 12; /* 1589: struct.dh_st */
    	em[1592] = 1231; em[1593] = 8; 
    	em[1594] = 1231; em[1595] = 16; 
    	em[1596] = 1231; em[1597] = 32; 
    	em[1598] = 1231; em[1599] = 40; 
    	em[1600] = 853; em[1601] = 56; 
    	em[1602] = 1231; em[1603] = 64; 
    	em[1604] = 1231; em[1605] = 72; 
    	em[1606] = 13; em[1607] = 80; 
    	em[1608] = 1231; em[1609] = 96; 
    	em[1610] = 1616; em[1611] = 112; 
    	em[1612] = 1357; em[1613] = 128; 
    	em[1614] = 1005; em[1615] = 136; 
    em[1616] = 0; em[1617] = 32; em[1618] = 2; /* 1616: struct.crypto_ex_data_st_fake */
    	em[1619] = 1623; em[1620] = 8; 
    	em[1621] = 364; em[1622] = 24; 
    em[1623] = 8884099; em[1624] = 8; em[1625] = 2; /* 1623: pointer_to_array_of_pointers_to_stack */
    	em[1626] = 625; em[1627] = 0; 
    	em[1628] = 361; em[1629] = 20; 
    em[1630] = 1; em[1631] = 8; em[1632] = 1; /* 1630: pointer.struct.evp_pkey_st */
    	em[1633] = 1479; em[1634] = 0; 
    args_addr->arg_entity_index[0] = 1630;
    args_addr->ret_entity_index = 361;
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

