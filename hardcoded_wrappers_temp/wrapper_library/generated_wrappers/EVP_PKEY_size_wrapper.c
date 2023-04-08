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
    em[71] = 1; em[72] = 8; em[73] = 1; /* 71: pointer.struct.asn1_string_st */
    	em[74] = 13; em[75] = 0; 
    em[76] = 1; em[77] = 8; em[78] = 1; /* 76: pointer.struct.asn1_string_st */
    	em[79] = 13; em[80] = 0; 
    em[81] = 1; em[82] = 8; em[83] = 1; /* 81: pointer.struct.ecdsa_method */
    	em[84] = 86; em[85] = 0; 
    em[86] = 0; em[87] = 48; em[88] = 5; /* 86: struct.ecdsa_method */
    	em[89] = 99; em[90] = 0; 
    	em[91] = 104; em[92] = 8; 
    	em[93] = 107; em[94] = 16; 
    	em[95] = 110; em[96] = 24; 
    	em[97] = 113; em[98] = 40; 
    em[99] = 1; em[100] = 8; em[101] = 1; /* 99: pointer.char */
    	em[102] = 8884096; em[103] = 0; 
    em[104] = 8884097; em[105] = 8; em[106] = 0; /* 104: pointer.func */
    em[107] = 8884097; em[108] = 8; em[109] = 0; /* 107: pointer.func */
    em[110] = 8884097; em[111] = 8; em[112] = 0; /* 110: pointer.func */
    em[113] = 1; em[114] = 8; em[115] = 1; /* 113: pointer.char */
    	em[116] = 8884096; em[117] = 0; 
    em[118] = 1; em[119] = 8; em[120] = 1; /* 118: pointer.struct.asn1_string_st */
    	em[121] = 13; em[122] = 0; 
    em[123] = 8884097; em[124] = 8; em[125] = 0; /* 123: pointer.func */
    em[126] = 8884097; em[127] = 8; em[128] = 0; /* 126: pointer.func */
    em[129] = 8884097; em[130] = 8; em[131] = 0; /* 129: pointer.func */
    em[132] = 1; em[133] = 8; em[134] = 1; /* 132: pointer.struct.dsa_method */
    	em[135] = 137; em[136] = 0; 
    em[137] = 0; em[138] = 96; em[139] = 11; /* 137: struct.dsa_method */
    	em[140] = 99; em[141] = 0; 
    	em[142] = 162; em[143] = 8; 
    	em[144] = 129; em[145] = 16; 
    	em[146] = 165; em[147] = 24; 
    	em[148] = 123; em[149] = 32; 
    	em[150] = 168; em[151] = 40; 
    	em[152] = 171; em[153] = 48; 
    	em[154] = 171; em[155] = 56; 
    	em[156] = 113; em[157] = 72; 
    	em[158] = 174; em[159] = 80; 
    	em[160] = 171; em[161] = 88; 
    em[162] = 8884097; em[163] = 8; em[164] = 0; /* 162: pointer.func */
    em[165] = 8884097; em[166] = 8; em[167] = 0; /* 165: pointer.func */
    em[168] = 8884097; em[169] = 8; em[170] = 0; /* 168: pointer.func */
    em[171] = 8884097; em[172] = 8; em[173] = 0; /* 171: pointer.func */
    em[174] = 8884097; em[175] = 8; em[176] = 0; /* 174: pointer.func */
    em[177] = 1; em[178] = 8; em[179] = 1; /* 177: pointer.struct.bn_mont_ctx_st */
    	em[180] = 182; em[181] = 0; 
    em[182] = 0; em[183] = 96; em[184] = 3; /* 182: struct.bn_mont_ctx_st */
    	em[185] = 191; em[186] = 8; 
    	em[187] = 191; em[188] = 32; 
    	em[189] = 191; em[190] = 56; 
    em[191] = 0; em[192] = 24; em[193] = 1; /* 191: struct.bignum_st */
    	em[194] = 196; em[195] = 0; 
    em[196] = 8884099; em[197] = 8; em[198] = 2; /* 196: pointer_to_array_of_pointers_to_stack */
    	em[199] = 203; em[200] = 0; 
    	em[201] = 206; em[202] = 12; 
    em[203] = 0; em[204] = 8; em[205] = 0; /* 203: long unsigned int */
    em[206] = 0; em[207] = 4; em[208] = 0; /* 206: int */
    em[209] = 8884097; em[210] = 8; em[211] = 0; /* 209: pointer.func */
    em[212] = 0; em[213] = 0; em[214] = 1; /* 212: X509_ATTRIBUTE */
    	em[215] = 217; em[216] = 0; 
    em[217] = 0; em[218] = 24; em[219] = 2; /* 217: struct.x509_attributes_st */
    	em[220] = 224; em[221] = 0; 
    	em[222] = 243; em[223] = 16; 
    em[224] = 1; em[225] = 8; em[226] = 1; /* 224: pointer.struct.asn1_object_st */
    	em[227] = 229; em[228] = 0; 
    em[229] = 0; em[230] = 40; em[231] = 3; /* 229: struct.asn1_object_st */
    	em[232] = 99; em[233] = 0; 
    	em[234] = 99; em[235] = 8; 
    	em[236] = 238; em[237] = 24; 
    em[238] = 1; em[239] = 8; em[240] = 1; /* 238: pointer.unsigned char */
    	em[241] = 23; em[242] = 0; 
    em[243] = 0; em[244] = 8; em[245] = 3; /* 243: union.unknown */
    	em[246] = 113; em[247] = 0; 
    	em[248] = 252; em[249] = 0; 
    	em[250] = 434; em[251] = 0; 
    em[252] = 1; em[253] = 8; em[254] = 1; /* 252: pointer.struct.stack_st_ASN1_TYPE */
    	em[255] = 257; em[256] = 0; 
    em[257] = 0; em[258] = 32; em[259] = 2; /* 257: struct.stack_st_fake_ASN1_TYPE */
    	em[260] = 264; em[261] = 8; 
    	em[262] = 431; em[263] = 24; 
    em[264] = 8884099; em[265] = 8; em[266] = 2; /* 264: pointer_to_array_of_pointers_to_stack */
    	em[267] = 271; em[268] = 0; 
    	em[269] = 206; em[270] = 20; 
    em[271] = 0; em[272] = 8; em[273] = 1; /* 271: pointer.ASN1_TYPE */
    	em[274] = 276; em[275] = 0; 
    em[276] = 0; em[277] = 0; em[278] = 1; /* 276: ASN1_TYPE */
    	em[279] = 281; em[280] = 0; 
    em[281] = 0; em[282] = 16; em[283] = 1; /* 281: struct.asn1_type_st */
    	em[284] = 286; em[285] = 8; 
    em[286] = 0; em[287] = 8; em[288] = 20; /* 286: union.unknown */
    	em[289] = 113; em[290] = 0; 
    	em[291] = 329; em[292] = 0; 
    	em[293] = 339; em[294] = 0; 
    	em[295] = 353; em[296] = 0; 
    	em[297] = 358; em[298] = 0; 
    	em[299] = 363; em[300] = 0; 
    	em[301] = 368; em[302] = 0; 
    	em[303] = 373; em[304] = 0; 
    	em[305] = 378; em[306] = 0; 
    	em[307] = 383; em[308] = 0; 
    	em[309] = 388; em[310] = 0; 
    	em[311] = 393; em[312] = 0; 
    	em[313] = 398; em[314] = 0; 
    	em[315] = 403; em[316] = 0; 
    	em[317] = 408; em[318] = 0; 
    	em[319] = 413; em[320] = 0; 
    	em[321] = 418; em[322] = 0; 
    	em[323] = 329; em[324] = 0; 
    	em[325] = 329; em[326] = 0; 
    	em[327] = 423; em[328] = 0; 
    em[329] = 1; em[330] = 8; em[331] = 1; /* 329: pointer.struct.asn1_string_st */
    	em[332] = 334; em[333] = 0; 
    em[334] = 0; em[335] = 24; em[336] = 1; /* 334: struct.asn1_string_st */
    	em[337] = 18; em[338] = 8; 
    em[339] = 1; em[340] = 8; em[341] = 1; /* 339: pointer.struct.asn1_object_st */
    	em[342] = 344; em[343] = 0; 
    em[344] = 0; em[345] = 40; em[346] = 3; /* 344: struct.asn1_object_st */
    	em[347] = 99; em[348] = 0; 
    	em[349] = 99; em[350] = 8; 
    	em[351] = 238; em[352] = 24; 
    em[353] = 1; em[354] = 8; em[355] = 1; /* 353: pointer.struct.asn1_string_st */
    	em[356] = 334; em[357] = 0; 
    em[358] = 1; em[359] = 8; em[360] = 1; /* 358: pointer.struct.asn1_string_st */
    	em[361] = 334; em[362] = 0; 
    em[363] = 1; em[364] = 8; em[365] = 1; /* 363: pointer.struct.asn1_string_st */
    	em[366] = 334; em[367] = 0; 
    em[368] = 1; em[369] = 8; em[370] = 1; /* 368: pointer.struct.asn1_string_st */
    	em[371] = 334; em[372] = 0; 
    em[373] = 1; em[374] = 8; em[375] = 1; /* 373: pointer.struct.asn1_string_st */
    	em[376] = 334; em[377] = 0; 
    em[378] = 1; em[379] = 8; em[380] = 1; /* 378: pointer.struct.asn1_string_st */
    	em[381] = 334; em[382] = 0; 
    em[383] = 1; em[384] = 8; em[385] = 1; /* 383: pointer.struct.asn1_string_st */
    	em[386] = 334; em[387] = 0; 
    em[388] = 1; em[389] = 8; em[390] = 1; /* 388: pointer.struct.asn1_string_st */
    	em[391] = 334; em[392] = 0; 
    em[393] = 1; em[394] = 8; em[395] = 1; /* 393: pointer.struct.asn1_string_st */
    	em[396] = 334; em[397] = 0; 
    em[398] = 1; em[399] = 8; em[400] = 1; /* 398: pointer.struct.asn1_string_st */
    	em[401] = 334; em[402] = 0; 
    em[403] = 1; em[404] = 8; em[405] = 1; /* 403: pointer.struct.asn1_string_st */
    	em[406] = 334; em[407] = 0; 
    em[408] = 1; em[409] = 8; em[410] = 1; /* 408: pointer.struct.asn1_string_st */
    	em[411] = 334; em[412] = 0; 
    em[413] = 1; em[414] = 8; em[415] = 1; /* 413: pointer.struct.asn1_string_st */
    	em[416] = 334; em[417] = 0; 
    em[418] = 1; em[419] = 8; em[420] = 1; /* 418: pointer.struct.asn1_string_st */
    	em[421] = 334; em[422] = 0; 
    em[423] = 1; em[424] = 8; em[425] = 1; /* 423: pointer.struct.ASN1_VALUE_st */
    	em[426] = 428; em[427] = 0; 
    em[428] = 0; em[429] = 0; em[430] = 0; /* 428: struct.ASN1_VALUE_st */
    em[431] = 8884097; em[432] = 8; em[433] = 0; /* 431: pointer.func */
    em[434] = 1; em[435] = 8; em[436] = 1; /* 434: pointer.struct.asn1_type_st */
    	em[437] = 439; em[438] = 0; 
    em[439] = 0; em[440] = 16; em[441] = 1; /* 439: struct.asn1_type_st */
    	em[442] = 444; em[443] = 8; 
    em[444] = 0; em[445] = 8; em[446] = 20; /* 444: union.unknown */
    	em[447] = 113; em[448] = 0; 
    	em[449] = 76; em[450] = 0; 
    	em[451] = 224; em[452] = 0; 
    	em[453] = 71; em[454] = 0; 
    	em[455] = 66; em[456] = 0; 
    	em[457] = 61; em[458] = 0; 
    	em[459] = 56; em[460] = 0; 
    	em[461] = 487; em[462] = 0; 
    	em[463] = 51; em[464] = 0; 
    	em[465] = 46; em[466] = 0; 
    	em[467] = 41; em[468] = 0; 
    	em[469] = 36; em[470] = 0; 
    	em[471] = 492; em[472] = 0; 
    	em[473] = 31; em[474] = 0; 
    	em[475] = 26; em[476] = 0; 
    	em[477] = 118; em[478] = 0; 
    	em[479] = 8; em[480] = 0; 
    	em[481] = 76; em[482] = 0; 
    	em[483] = 76; em[484] = 0; 
    	em[485] = 0; em[486] = 0; 
    em[487] = 1; em[488] = 8; em[489] = 1; /* 487: pointer.struct.asn1_string_st */
    	em[490] = 13; em[491] = 0; 
    em[492] = 1; em[493] = 8; em[494] = 1; /* 492: pointer.struct.asn1_string_st */
    	em[495] = 13; em[496] = 0; 
    em[497] = 1; em[498] = 8; em[499] = 1; /* 497: pointer.struct.dsa_st */
    	em[500] = 502; em[501] = 0; 
    em[502] = 0; em[503] = 136; em[504] = 11; /* 502: struct.dsa_st */
    	em[505] = 527; em[506] = 24; 
    	em[507] = 527; em[508] = 32; 
    	em[509] = 527; em[510] = 40; 
    	em[511] = 527; em[512] = 48; 
    	em[513] = 527; em[514] = 56; 
    	em[515] = 527; em[516] = 64; 
    	em[517] = 527; em[518] = 72; 
    	em[519] = 177; em[520] = 88; 
    	em[521] = 532; em[522] = 104; 
    	em[523] = 132; em[524] = 120; 
    	em[525] = 549; em[526] = 128; 
    em[527] = 1; em[528] = 8; em[529] = 1; /* 527: pointer.struct.bignum_st */
    	em[530] = 191; em[531] = 0; 
    em[532] = 0; em[533] = 32; em[534] = 2; /* 532: struct.crypto_ex_data_st_fake */
    	em[535] = 539; em[536] = 8; 
    	em[537] = 431; em[538] = 24; 
    em[539] = 8884099; em[540] = 8; em[541] = 2; /* 539: pointer_to_array_of_pointers_to_stack */
    	em[542] = 546; em[543] = 0; 
    	em[544] = 206; em[545] = 20; 
    em[546] = 0; em[547] = 8; em[548] = 0; /* 546: pointer.void */
    em[549] = 1; em[550] = 8; em[551] = 1; /* 549: pointer.struct.engine_st */
    	em[552] = 554; em[553] = 0; 
    em[554] = 0; em[555] = 216; em[556] = 24; /* 554: struct.engine_st */
    	em[557] = 99; em[558] = 0; 
    	em[559] = 99; em[560] = 8; 
    	em[561] = 605; em[562] = 16; 
    	em[563] = 657; em[564] = 24; 
    	em[565] = 708; em[566] = 32; 
    	em[567] = 744; em[568] = 40; 
    	em[569] = 81; em[570] = 48; 
    	em[571] = 761; em[572] = 56; 
    	em[573] = 796; em[574] = 64; 
    	em[575] = 804; em[576] = 72; 
    	em[577] = 807; em[578] = 80; 
    	em[579] = 810; em[580] = 88; 
    	em[581] = 813; em[582] = 96; 
    	em[583] = 816; em[584] = 104; 
    	em[585] = 816; em[586] = 112; 
    	em[587] = 816; em[588] = 120; 
    	em[589] = 819; em[590] = 128; 
    	em[591] = 822; em[592] = 136; 
    	em[593] = 822; em[594] = 144; 
    	em[595] = 825; em[596] = 152; 
    	em[597] = 828; em[598] = 160; 
    	em[599] = 840; em[600] = 184; 
    	em[601] = 854; em[602] = 200; 
    	em[603] = 854; em[604] = 208; 
    em[605] = 1; em[606] = 8; em[607] = 1; /* 605: pointer.struct.rsa_meth_st */
    	em[608] = 610; em[609] = 0; 
    em[610] = 0; em[611] = 112; em[612] = 13; /* 610: struct.rsa_meth_st */
    	em[613] = 99; em[614] = 0; 
    	em[615] = 639; em[616] = 8; 
    	em[617] = 639; em[618] = 16; 
    	em[619] = 639; em[620] = 24; 
    	em[621] = 639; em[622] = 32; 
    	em[623] = 642; em[624] = 40; 
    	em[625] = 645; em[626] = 48; 
    	em[627] = 648; em[628] = 56; 
    	em[629] = 648; em[630] = 64; 
    	em[631] = 113; em[632] = 80; 
    	em[633] = 651; em[634] = 88; 
    	em[635] = 654; em[636] = 96; 
    	em[637] = 209; em[638] = 104; 
    em[639] = 8884097; em[640] = 8; em[641] = 0; /* 639: pointer.func */
    em[642] = 8884097; em[643] = 8; em[644] = 0; /* 642: pointer.func */
    em[645] = 8884097; em[646] = 8; em[647] = 0; /* 645: pointer.func */
    em[648] = 8884097; em[649] = 8; em[650] = 0; /* 648: pointer.func */
    em[651] = 8884097; em[652] = 8; em[653] = 0; /* 651: pointer.func */
    em[654] = 8884097; em[655] = 8; em[656] = 0; /* 654: pointer.func */
    em[657] = 1; em[658] = 8; em[659] = 1; /* 657: pointer.struct.dsa_method */
    	em[660] = 662; em[661] = 0; 
    em[662] = 0; em[663] = 96; em[664] = 11; /* 662: struct.dsa_method */
    	em[665] = 99; em[666] = 0; 
    	em[667] = 687; em[668] = 8; 
    	em[669] = 690; em[670] = 16; 
    	em[671] = 693; em[672] = 24; 
    	em[673] = 696; em[674] = 32; 
    	em[675] = 699; em[676] = 40; 
    	em[677] = 702; em[678] = 48; 
    	em[679] = 702; em[680] = 56; 
    	em[681] = 113; em[682] = 72; 
    	em[683] = 705; em[684] = 80; 
    	em[685] = 702; em[686] = 88; 
    em[687] = 8884097; em[688] = 8; em[689] = 0; /* 687: pointer.func */
    em[690] = 8884097; em[691] = 8; em[692] = 0; /* 690: pointer.func */
    em[693] = 8884097; em[694] = 8; em[695] = 0; /* 693: pointer.func */
    em[696] = 8884097; em[697] = 8; em[698] = 0; /* 696: pointer.func */
    em[699] = 8884097; em[700] = 8; em[701] = 0; /* 699: pointer.func */
    em[702] = 8884097; em[703] = 8; em[704] = 0; /* 702: pointer.func */
    em[705] = 8884097; em[706] = 8; em[707] = 0; /* 705: pointer.func */
    em[708] = 1; em[709] = 8; em[710] = 1; /* 708: pointer.struct.dh_method */
    	em[711] = 713; em[712] = 0; 
    em[713] = 0; em[714] = 72; em[715] = 8; /* 713: struct.dh_method */
    	em[716] = 99; em[717] = 0; 
    	em[718] = 732; em[719] = 8; 
    	em[720] = 735; em[721] = 16; 
    	em[722] = 738; em[723] = 24; 
    	em[724] = 732; em[725] = 32; 
    	em[726] = 732; em[727] = 40; 
    	em[728] = 113; em[729] = 56; 
    	em[730] = 741; em[731] = 64; 
    em[732] = 8884097; em[733] = 8; em[734] = 0; /* 732: pointer.func */
    em[735] = 8884097; em[736] = 8; em[737] = 0; /* 735: pointer.func */
    em[738] = 8884097; em[739] = 8; em[740] = 0; /* 738: pointer.func */
    em[741] = 8884097; em[742] = 8; em[743] = 0; /* 741: pointer.func */
    em[744] = 1; em[745] = 8; em[746] = 1; /* 744: pointer.struct.ecdh_method */
    	em[747] = 749; em[748] = 0; 
    em[749] = 0; em[750] = 32; em[751] = 3; /* 749: struct.ecdh_method */
    	em[752] = 99; em[753] = 0; 
    	em[754] = 758; em[755] = 8; 
    	em[756] = 113; em[757] = 24; 
    em[758] = 8884097; em[759] = 8; em[760] = 0; /* 758: pointer.func */
    em[761] = 1; em[762] = 8; em[763] = 1; /* 761: pointer.struct.rand_meth_st */
    	em[764] = 766; em[765] = 0; 
    em[766] = 0; em[767] = 48; em[768] = 6; /* 766: struct.rand_meth_st */
    	em[769] = 781; em[770] = 0; 
    	em[771] = 784; em[772] = 8; 
    	em[773] = 787; em[774] = 16; 
    	em[775] = 790; em[776] = 24; 
    	em[777] = 784; em[778] = 32; 
    	em[779] = 793; em[780] = 40; 
    em[781] = 8884097; em[782] = 8; em[783] = 0; /* 781: pointer.func */
    em[784] = 8884097; em[785] = 8; em[786] = 0; /* 784: pointer.func */
    em[787] = 8884097; em[788] = 8; em[789] = 0; /* 787: pointer.func */
    em[790] = 8884097; em[791] = 8; em[792] = 0; /* 790: pointer.func */
    em[793] = 8884097; em[794] = 8; em[795] = 0; /* 793: pointer.func */
    em[796] = 1; em[797] = 8; em[798] = 1; /* 796: pointer.struct.store_method_st */
    	em[799] = 801; em[800] = 0; 
    em[801] = 0; em[802] = 0; em[803] = 0; /* 801: struct.store_method_st */
    em[804] = 8884097; em[805] = 8; em[806] = 0; /* 804: pointer.func */
    em[807] = 8884097; em[808] = 8; em[809] = 0; /* 807: pointer.func */
    em[810] = 8884097; em[811] = 8; em[812] = 0; /* 810: pointer.func */
    em[813] = 8884097; em[814] = 8; em[815] = 0; /* 813: pointer.func */
    em[816] = 8884097; em[817] = 8; em[818] = 0; /* 816: pointer.func */
    em[819] = 8884097; em[820] = 8; em[821] = 0; /* 819: pointer.func */
    em[822] = 8884097; em[823] = 8; em[824] = 0; /* 822: pointer.func */
    em[825] = 8884097; em[826] = 8; em[827] = 0; /* 825: pointer.func */
    em[828] = 1; em[829] = 8; em[830] = 1; /* 828: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[831] = 833; em[832] = 0; 
    em[833] = 0; em[834] = 32; em[835] = 2; /* 833: struct.ENGINE_CMD_DEFN_st */
    	em[836] = 99; em[837] = 8; 
    	em[838] = 99; em[839] = 16; 
    em[840] = 0; em[841] = 32; em[842] = 2; /* 840: struct.crypto_ex_data_st_fake */
    	em[843] = 847; em[844] = 8; 
    	em[845] = 431; em[846] = 24; 
    em[847] = 8884099; em[848] = 8; em[849] = 2; /* 847: pointer_to_array_of_pointers_to_stack */
    	em[850] = 546; em[851] = 0; 
    	em[852] = 206; em[853] = 20; 
    em[854] = 1; em[855] = 8; em[856] = 1; /* 854: pointer.struct.engine_st */
    	em[857] = 554; em[858] = 0; 
    em[859] = 8884097; em[860] = 8; em[861] = 0; /* 859: pointer.func */
    em[862] = 8884097; em[863] = 8; em[864] = 0; /* 862: pointer.func */
    em[865] = 1; em[866] = 8; em[867] = 1; /* 865: pointer.struct.bignum_st */
    	em[868] = 870; em[869] = 0; 
    em[870] = 0; em[871] = 24; em[872] = 1; /* 870: struct.bignum_st */
    	em[873] = 875; em[874] = 0; 
    em[875] = 8884099; em[876] = 8; em[877] = 2; /* 875: pointer_to_array_of_pointers_to_stack */
    	em[878] = 203; em[879] = 0; 
    	em[880] = 206; em[881] = 12; 
    em[882] = 8884097; em[883] = 8; em[884] = 0; /* 882: pointer.func */
    em[885] = 0; em[886] = 88; em[887] = 7; /* 885: struct.bn_blinding_st */
    	em[888] = 902; em[889] = 0; 
    	em[890] = 902; em[891] = 8; 
    	em[892] = 902; em[893] = 16; 
    	em[894] = 902; em[895] = 24; 
    	em[896] = 919; em[897] = 40; 
    	em[898] = 924; em[899] = 72; 
    	em[900] = 938; em[901] = 80; 
    em[902] = 1; em[903] = 8; em[904] = 1; /* 902: pointer.struct.bignum_st */
    	em[905] = 907; em[906] = 0; 
    em[907] = 0; em[908] = 24; em[909] = 1; /* 907: struct.bignum_st */
    	em[910] = 912; em[911] = 0; 
    em[912] = 8884099; em[913] = 8; em[914] = 2; /* 912: pointer_to_array_of_pointers_to_stack */
    	em[915] = 203; em[916] = 0; 
    	em[917] = 206; em[918] = 12; 
    em[919] = 0; em[920] = 16; em[921] = 1; /* 919: struct.crypto_threadid_st */
    	em[922] = 546; em[923] = 0; 
    em[924] = 1; em[925] = 8; em[926] = 1; /* 924: pointer.struct.bn_mont_ctx_st */
    	em[927] = 929; em[928] = 0; 
    em[929] = 0; em[930] = 96; em[931] = 3; /* 929: struct.bn_mont_ctx_st */
    	em[932] = 907; em[933] = 8; 
    	em[934] = 907; em[935] = 32; 
    	em[936] = 907; em[937] = 56; 
    em[938] = 8884097; em[939] = 8; em[940] = 0; /* 938: pointer.func */
    em[941] = 0; em[942] = 96; em[943] = 3; /* 941: struct.bn_mont_ctx_st */
    	em[944] = 950; em[945] = 8; 
    	em[946] = 950; em[947] = 32; 
    	em[948] = 950; em[949] = 56; 
    em[950] = 0; em[951] = 24; em[952] = 1; /* 950: struct.bignum_st */
    	em[953] = 955; em[954] = 0; 
    em[955] = 8884099; em[956] = 8; em[957] = 2; /* 955: pointer_to_array_of_pointers_to_stack */
    	em[958] = 203; em[959] = 0; 
    	em[960] = 206; em[961] = 12; 
    em[962] = 1; em[963] = 8; em[964] = 1; /* 962: pointer.struct.ec_method_st */
    	em[965] = 967; em[966] = 0; 
    em[967] = 0; em[968] = 304; em[969] = 37; /* 967: struct.ec_method_st */
    	em[970] = 1044; em[971] = 8; 
    	em[972] = 1047; em[973] = 16; 
    	em[974] = 1047; em[975] = 24; 
    	em[976] = 1050; em[977] = 32; 
    	em[978] = 1053; em[979] = 40; 
    	em[980] = 1056; em[981] = 48; 
    	em[982] = 1059; em[983] = 56; 
    	em[984] = 1062; em[985] = 64; 
    	em[986] = 1065; em[987] = 72; 
    	em[988] = 1068; em[989] = 80; 
    	em[990] = 1068; em[991] = 88; 
    	em[992] = 1071; em[993] = 96; 
    	em[994] = 1074; em[995] = 104; 
    	em[996] = 1077; em[997] = 112; 
    	em[998] = 1080; em[999] = 120; 
    	em[1000] = 1083; em[1001] = 128; 
    	em[1002] = 1086; em[1003] = 136; 
    	em[1004] = 1089; em[1005] = 144; 
    	em[1006] = 1092; em[1007] = 152; 
    	em[1008] = 1095; em[1009] = 160; 
    	em[1010] = 1098; em[1011] = 168; 
    	em[1012] = 1101; em[1013] = 176; 
    	em[1014] = 1104; em[1015] = 184; 
    	em[1016] = 1107; em[1017] = 192; 
    	em[1018] = 126; em[1019] = 200; 
    	em[1020] = 1110; em[1021] = 208; 
    	em[1022] = 1104; em[1023] = 216; 
    	em[1024] = 1113; em[1025] = 224; 
    	em[1026] = 1116; em[1027] = 232; 
    	em[1028] = 1119; em[1029] = 240; 
    	em[1030] = 1059; em[1031] = 248; 
    	em[1032] = 1122; em[1033] = 256; 
    	em[1034] = 1125; em[1035] = 264; 
    	em[1036] = 1122; em[1037] = 272; 
    	em[1038] = 1125; em[1039] = 280; 
    	em[1040] = 1125; em[1041] = 288; 
    	em[1042] = 1128; em[1043] = 296; 
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
    em[1131] = 1; em[1132] = 8; em[1133] = 1; /* 1131: pointer.struct.bignum_st */
    	em[1134] = 950; em[1135] = 0; 
    em[1136] = 8884097; em[1137] = 8; em[1138] = 0; /* 1136: pointer.func */
    em[1139] = 8884097; em[1140] = 8; em[1141] = 0; /* 1139: pointer.func */
    em[1142] = 1; em[1143] = 8; em[1144] = 1; /* 1142: pointer.struct.rsa_st */
    	em[1145] = 1147; em[1146] = 0; 
    em[1147] = 0; em[1148] = 168; em[1149] = 17; /* 1147: struct.rsa_st */
    	em[1150] = 1184; em[1151] = 16; 
    	em[1152] = 1233; em[1153] = 24; 
    	em[1154] = 1131; em[1155] = 32; 
    	em[1156] = 1131; em[1157] = 40; 
    	em[1158] = 1131; em[1159] = 48; 
    	em[1160] = 1131; em[1161] = 56; 
    	em[1162] = 1131; em[1163] = 64; 
    	em[1164] = 1131; em[1165] = 72; 
    	em[1166] = 1131; em[1167] = 80; 
    	em[1168] = 1131; em[1169] = 88; 
    	em[1170] = 1238; em[1171] = 96; 
    	em[1172] = 1252; em[1173] = 120; 
    	em[1174] = 1252; em[1175] = 128; 
    	em[1176] = 1252; em[1177] = 136; 
    	em[1178] = 113; em[1179] = 144; 
    	em[1180] = 1257; em[1181] = 152; 
    	em[1182] = 1257; em[1183] = 160; 
    em[1184] = 1; em[1185] = 8; em[1186] = 1; /* 1184: pointer.struct.rsa_meth_st */
    	em[1187] = 1189; em[1188] = 0; 
    em[1189] = 0; em[1190] = 112; em[1191] = 13; /* 1189: struct.rsa_meth_st */
    	em[1192] = 99; em[1193] = 0; 
    	em[1194] = 1218; em[1195] = 8; 
    	em[1196] = 1218; em[1197] = 16; 
    	em[1198] = 1218; em[1199] = 24; 
    	em[1200] = 1218; em[1201] = 32; 
    	em[1202] = 1221; em[1203] = 40; 
    	em[1204] = 1224; em[1205] = 48; 
    	em[1206] = 1139; em[1207] = 56; 
    	em[1208] = 1139; em[1209] = 64; 
    	em[1210] = 113; em[1211] = 80; 
    	em[1212] = 1227; em[1213] = 88; 
    	em[1214] = 1230; em[1215] = 96; 
    	em[1216] = 1136; em[1217] = 104; 
    em[1218] = 8884097; em[1219] = 8; em[1220] = 0; /* 1218: pointer.func */
    em[1221] = 8884097; em[1222] = 8; em[1223] = 0; /* 1221: pointer.func */
    em[1224] = 8884097; em[1225] = 8; em[1226] = 0; /* 1224: pointer.func */
    em[1227] = 8884097; em[1228] = 8; em[1229] = 0; /* 1227: pointer.func */
    em[1230] = 8884097; em[1231] = 8; em[1232] = 0; /* 1230: pointer.func */
    em[1233] = 1; em[1234] = 8; em[1235] = 1; /* 1233: pointer.struct.engine_st */
    	em[1236] = 554; em[1237] = 0; 
    em[1238] = 0; em[1239] = 32; em[1240] = 2; /* 1238: struct.crypto_ex_data_st_fake */
    	em[1241] = 1245; em[1242] = 8; 
    	em[1243] = 431; em[1244] = 24; 
    em[1245] = 8884099; em[1246] = 8; em[1247] = 2; /* 1245: pointer_to_array_of_pointers_to_stack */
    	em[1248] = 546; em[1249] = 0; 
    	em[1250] = 206; em[1251] = 20; 
    em[1252] = 1; em[1253] = 8; em[1254] = 1; /* 1252: pointer.struct.bn_mont_ctx_st */
    	em[1255] = 941; em[1256] = 0; 
    em[1257] = 1; em[1258] = 8; em[1259] = 1; /* 1257: pointer.struct.bn_blinding_st */
    	em[1260] = 885; em[1261] = 0; 
    em[1262] = 8884097; em[1263] = 8; em[1264] = 0; /* 1262: pointer.func */
    em[1265] = 1; em[1266] = 8; em[1267] = 1; /* 1265: pointer.struct.evp_pkey_asn1_method_st */
    	em[1268] = 1270; em[1269] = 0; 
    em[1270] = 0; em[1271] = 208; em[1272] = 24; /* 1270: struct.evp_pkey_asn1_method_st */
    	em[1273] = 113; em[1274] = 16; 
    	em[1275] = 113; em[1276] = 24; 
    	em[1277] = 1321; em[1278] = 32; 
    	em[1279] = 1324; em[1280] = 40; 
    	em[1281] = 1327; em[1282] = 48; 
    	em[1283] = 1330; em[1284] = 56; 
    	em[1285] = 1333; em[1286] = 64; 
    	em[1287] = 1336; em[1288] = 72; 
    	em[1289] = 1330; em[1290] = 80; 
    	em[1291] = 1339; em[1292] = 88; 
    	em[1293] = 1339; em[1294] = 96; 
    	em[1295] = 1342; em[1296] = 104; 
    	em[1297] = 1345; em[1298] = 112; 
    	em[1299] = 1339; em[1300] = 120; 
    	em[1301] = 1348; em[1302] = 128; 
    	em[1303] = 1327; em[1304] = 136; 
    	em[1305] = 1330; em[1306] = 144; 
    	em[1307] = 862; em[1308] = 152; 
    	em[1309] = 1351; em[1310] = 160; 
    	em[1311] = 1354; em[1312] = 168; 
    	em[1313] = 1342; em[1314] = 176; 
    	em[1315] = 1345; em[1316] = 184; 
    	em[1317] = 1357; em[1318] = 192; 
    	em[1319] = 1360; em[1320] = 200; 
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
    em[1360] = 8884097; em[1361] = 8; em[1362] = 0; /* 1360: pointer.func */
    em[1363] = 8884097; em[1364] = 8; em[1365] = 0; /* 1363: pointer.func */
    em[1366] = 8884097; em[1367] = 8; em[1368] = 0; /* 1366: pointer.func */
    em[1369] = 1; em[1370] = 8; em[1371] = 1; /* 1369: pointer.struct.engine_st */
    	em[1372] = 554; em[1373] = 0; 
    em[1374] = 1; em[1375] = 8; em[1376] = 1; /* 1374: pointer.struct.ec_method_st */
    	em[1377] = 1379; em[1378] = 0; 
    em[1379] = 0; em[1380] = 304; em[1381] = 37; /* 1379: struct.ec_method_st */
    	em[1382] = 1456; em[1383] = 8; 
    	em[1384] = 1459; em[1385] = 16; 
    	em[1386] = 1459; em[1387] = 24; 
    	em[1388] = 1462; em[1389] = 32; 
    	em[1390] = 1465; em[1391] = 40; 
    	em[1392] = 1468; em[1393] = 48; 
    	em[1394] = 1471; em[1395] = 56; 
    	em[1396] = 1474; em[1397] = 64; 
    	em[1398] = 1477; em[1399] = 72; 
    	em[1400] = 1480; em[1401] = 80; 
    	em[1402] = 1480; em[1403] = 88; 
    	em[1404] = 1366; em[1405] = 96; 
    	em[1406] = 1483; em[1407] = 104; 
    	em[1408] = 1486; em[1409] = 112; 
    	em[1410] = 882; em[1411] = 120; 
    	em[1412] = 1489; em[1413] = 128; 
    	em[1414] = 1492; em[1415] = 136; 
    	em[1416] = 1363; em[1417] = 144; 
    	em[1418] = 1495; em[1419] = 152; 
    	em[1420] = 1498; em[1421] = 160; 
    	em[1422] = 1501; em[1423] = 168; 
    	em[1424] = 1504; em[1425] = 176; 
    	em[1426] = 1507; em[1427] = 184; 
    	em[1428] = 859; em[1429] = 192; 
    	em[1430] = 1510; em[1431] = 200; 
    	em[1432] = 1513; em[1433] = 208; 
    	em[1434] = 1507; em[1435] = 216; 
    	em[1436] = 1516; em[1437] = 224; 
    	em[1438] = 1519; em[1439] = 232; 
    	em[1440] = 1522; em[1441] = 240; 
    	em[1442] = 1471; em[1443] = 248; 
    	em[1444] = 1525; em[1445] = 256; 
    	em[1446] = 1528; em[1447] = 264; 
    	em[1448] = 1525; em[1449] = 272; 
    	em[1450] = 1528; em[1451] = 280; 
    	em[1452] = 1528; em[1453] = 288; 
    	em[1454] = 1531; em[1455] = 296; 
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
    em[1522] = 8884097; em[1523] = 8; em[1524] = 0; /* 1522: pointer.func */
    em[1525] = 8884097; em[1526] = 8; em[1527] = 0; /* 1525: pointer.func */
    em[1528] = 8884097; em[1529] = 8; em[1530] = 0; /* 1528: pointer.func */
    em[1531] = 8884097; em[1532] = 8; em[1533] = 0; /* 1531: pointer.func */
    em[1534] = 8884097; em[1535] = 8; em[1536] = 0; /* 1534: pointer.func */
    em[1537] = 1; em[1538] = 8; em[1539] = 1; /* 1537: pointer.struct.evp_pkey_st */
    	em[1540] = 1542; em[1541] = 0; 
    em[1542] = 0; em[1543] = 56; em[1544] = 4; /* 1542: struct.evp_pkey_st */
    	em[1545] = 1265; em[1546] = 16; 
    	em[1547] = 1369; em[1548] = 24; 
    	em[1549] = 1553; em[1550] = 32; 
    	em[1551] = 1828; em[1552] = 48; 
    em[1553] = 0; em[1554] = 8; em[1555] = 6; /* 1553: union.union_of_evp_pkey_st */
    	em[1556] = 546; em[1557] = 0; 
    	em[1558] = 1142; em[1559] = 6; 
    	em[1560] = 497; em[1561] = 116; 
    	em[1562] = 1568; em[1563] = 28; 
    	em[1564] = 1666; em[1565] = 408; 
    	em[1566] = 206; em[1567] = 0; 
    em[1568] = 1; em[1569] = 8; em[1570] = 1; /* 1568: pointer.struct.dh_st */
    	em[1571] = 1573; em[1572] = 0; 
    em[1573] = 0; em[1574] = 144; em[1575] = 12; /* 1573: struct.dh_st */
    	em[1576] = 865; em[1577] = 8; 
    	em[1578] = 865; em[1579] = 16; 
    	em[1580] = 865; em[1581] = 32; 
    	em[1582] = 865; em[1583] = 40; 
    	em[1584] = 1600; em[1585] = 56; 
    	em[1586] = 865; em[1587] = 64; 
    	em[1588] = 865; em[1589] = 72; 
    	em[1590] = 18; em[1591] = 80; 
    	em[1592] = 865; em[1593] = 96; 
    	em[1594] = 1614; em[1595] = 112; 
    	em[1596] = 1628; em[1597] = 128; 
    	em[1598] = 1661; em[1599] = 136; 
    em[1600] = 1; em[1601] = 8; em[1602] = 1; /* 1600: pointer.struct.bn_mont_ctx_st */
    	em[1603] = 1605; em[1604] = 0; 
    em[1605] = 0; em[1606] = 96; em[1607] = 3; /* 1605: struct.bn_mont_ctx_st */
    	em[1608] = 870; em[1609] = 8; 
    	em[1610] = 870; em[1611] = 32; 
    	em[1612] = 870; em[1613] = 56; 
    em[1614] = 0; em[1615] = 32; em[1616] = 2; /* 1614: struct.crypto_ex_data_st_fake */
    	em[1617] = 1621; em[1618] = 8; 
    	em[1619] = 431; em[1620] = 24; 
    em[1621] = 8884099; em[1622] = 8; em[1623] = 2; /* 1621: pointer_to_array_of_pointers_to_stack */
    	em[1624] = 546; em[1625] = 0; 
    	em[1626] = 206; em[1627] = 20; 
    em[1628] = 1; em[1629] = 8; em[1630] = 1; /* 1628: pointer.struct.dh_method */
    	em[1631] = 1633; em[1632] = 0; 
    em[1633] = 0; em[1634] = 72; em[1635] = 8; /* 1633: struct.dh_method */
    	em[1636] = 99; em[1637] = 0; 
    	em[1638] = 1652; em[1639] = 8; 
    	em[1640] = 1262; em[1641] = 16; 
    	em[1642] = 1655; em[1643] = 24; 
    	em[1644] = 1652; em[1645] = 32; 
    	em[1646] = 1652; em[1647] = 40; 
    	em[1648] = 113; em[1649] = 56; 
    	em[1650] = 1658; em[1651] = 64; 
    em[1652] = 8884097; em[1653] = 8; em[1654] = 0; /* 1652: pointer.func */
    em[1655] = 8884097; em[1656] = 8; em[1657] = 0; /* 1655: pointer.func */
    em[1658] = 8884097; em[1659] = 8; em[1660] = 0; /* 1658: pointer.func */
    em[1661] = 1; em[1662] = 8; em[1663] = 1; /* 1661: pointer.struct.engine_st */
    	em[1664] = 554; em[1665] = 0; 
    em[1666] = 1; em[1667] = 8; em[1668] = 1; /* 1666: pointer.struct.ec_key_st */
    	em[1669] = 1671; em[1670] = 0; 
    em[1671] = 0; em[1672] = 56; em[1673] = 4; /* 1671: struct.ec_key_st */
    	em[1674] = 1682; em[1675] = 8; 
    	em[1676] = 1783; em[1677] = 16; 
    	em[1678] = 1788; em[1679] = 24; 
    	em[1680] = 1805; em[1681] = 48; 
    em[1682] = 1; em[1683] = 8; em[1684] = 1; /* 1682: pointer.struct.ec_group_st */
    	em[1685] = 1687; em[1686] = 0; 
    em[1687] = 0; em[1688] = 232; em[1689] = 12; /* 1687: struct.ec_group_st */
    	em[1690] = 1374; em[1691] = 0; 
    	em[1692] = 1714; em[1693] = 8; 
    	em[1694] = 1742; em[1695] = 16; 
    	em[1696] = 1742; em[1697] = 40; 
    	em[1698] = 18; em[1699] = 80; 
    	em[1700] = 1754; em[1701] = 96; 
    	em[1702] = 1742; em[1703] = 104; 
    	em[1704] = 1742; em[1705] = 152; 
    	em[1706] = 1742; em[1707] = 176; 
    	em[1708] = 546; em[1709] = 208; 
    	em[1710] = 546; em[1711] = 216; 
    	em[1712] = 1534; em[1713] = 224; 
    em[1714] = 1; em[1715] = 8; em[1716] = 1; /* 1714: pointer.struct.ec_point_st */
    	em[1717] = 1719; em[1718] = 0; 
    em[1719] = 0; em[1720] = 88; em[1721] = 4; /* 1719: struct.ec_point_st */
    	em[1722] = 962; em[1723] = 0; 
    	em[1724] = 1730; em[1725] = 8; 
    	em[1726] = 1730; em[1727] = 32; 
    	em[1728] = 1730; em[1729] = 56; 
    em[1730] = 0; em[1731] = 24; em[1732] = 1; /* 1730: struct.bignum_st */
    	em[1733] = 1735; em[1734] = 0; 
    em[1735] = 8884099; em[1736] = 8; em[1737] = 2; /* 1735: pointer_to_array_of_pointers_to_stack */
    	em[1738] = 203; em[1739] = 0; 
    	em[1740] = 206; em[1741] = 12; 
    em[1742] = 0; em[1743] = 24; em[1744] = 1; /* 1742: struct.bignum_st */
    	em[1745] = 1747; em[1746] = 0; 
    em[1747] = 8884099; em[1748] = 8; em[1749] = 2; /* 1747: pointer_to_array_of_pointers_to_stack */
    	em[1750] = 203; em[1751] = 0; 
    	em[1752] = 206; em[1753] = 12; 
    em[1754] = 1; em[1755] = 8; em[1756] = 1; /* 1754: pointer.struct.ec_extra_data_st */
    	em[1757] = 1759; em[1758] = 0; 
    em[1759] = 0; em[1760] = 40; em[1761] = 5; /* 1759: struct.ec_extra_data_st */
    	em[1762] = 1772; em[1763] = 0; 
    	em[1764] = 546; em[1765] = 8; 
    	em[1766] = 1777; em[1767] = 16; 
    	em[1768] = 1780; em[1769] = 24; 
    	em[1770] = 1780; em[1771] = 32; 
    em[1772] = 1; em[1773] = 8; em[1774] = 1; /* 1772: pointer.struct.ec_extra_data_st */
    	em[1775] = 1759; em[1776] = 0; 
    em[1777] = 8884097; em[1778] = 8; em[1779] = 0; /* 1777: pointer.func */
    em[1780] = 8884097; em[1781] = 8; em[1782] = 0; /* 1780: pointer.func */
    em[1783] = 1; em[1784] = 8; em[1785] = 1; /* 1783: pointer.struct.ec_point_st */
    	em[1786] = 1719; em[1787] = 0; 
    em[1788] = 1; em[1789] = 8; em[1790] = 1; /* 1788: pointer.struct.bignum_st */
    	em[1791] = 1793; em[1792] = 0; 
    em[1793] = 0; em[1794] = 24; em[1795] = 1; /* 1793: struct.bignum_st */
    	em[1796] = 1798; em[1797] = 0; 
    em[1798] = 8884099; em[1799] = 8; em[1800] = 2; /* 1798: pointer_to_array_of_pointers_to_stack */
    	em[1801] = 203; em[1802] = 0; 
    	em[1803] = 206; em[1804] = 12; 
    em[1805] = 1; em[1806] = 8; em[1807] = 1; /* 1805: pointer.struct.ec_extra_data_st */
    	em[1808] = 1810; em[1809] = 0; 
    em[1810] = 0; em[1811] = 40; em[1812] = 5; /* 1810: struct.ec_extra_data_st */
    	em[1813] = 1823; em[1814] = 0; 
    	em[1815] = 546; em[1816] = 8; 
    	em[1817] = 1777; em[1818] = 16; 
    	em[1819] = 1780; em[1820] = 24; 
    	em[1821] = 1780; em[1822] = 32; 
    em[1823] = 1; em[1824] = 8; em[1825] = 1; /* 1823: pointer.struct.ec_extra_data_st */
    	em[1826] = 1810; em[1827] = 0; 
    em[1828] = 1; em[1829] = 8; em[1830] = 1; /* 1828: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1831] = 1833; em[1832] = 0; 
    em[1833] = 0; em[1834] = 32; em[1835] = 2; /* 1833: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1836] = 1840; em[1837] = 8; 
    	em[1838] = 431; em[1839] = 24; 
    em[1840] = 8884099; em[1841] = 8; em[1842] = 2; /* 1840: pointer_to_array_of_pointers_to_stack */
    	em[1843] = 1847; em[1844] = 0; 
    	em[1845] = 206; em[1846] = 20; 
    em[1847] = 0; em[1848] = 8; em[1849] = 1; /* 1847: pointer.X509_ATTRIBUTE */
    	em[1850] = 212; em[1851] = 0; 
    em[1852] = 0; em[1853] = 1; em[1854] = 0; /* 1852: char */
    args_addr->arg_entity_index[0] = 1537;
    args_addr->ret_entity_index = 206;
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

