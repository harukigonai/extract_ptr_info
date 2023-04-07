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
    	em[436] = 501; em[437] = 128; 
    	em[438] = 537; em[439] = 136; 
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
    em[474] = 0; em[475] = 16; em[476] = 1; /* 474: struct.crypto_ex_data_st */
    	em[477] = 479; em[478] = 0; 
    em[479] = 1; em[480] = 8; em[481] = 1; /* 479: pointer.struct.stack_st_void */
    	em[482] = 484; em[483] = 0; 
    em[484] = 0; em[485] = 32; em[486] = 1; /* 484: struct.stack_st_void */
    	em[487] = 489; em[488] = 0; 
    em[489] = 0; em[490] = 32; em[491] = 2; /* 489: struct.stack_st */
    	em[492] = 496; em[493] = 8; 
    	em[494] = 264; em[495] = 24; 
    em[496] = 1; em[497] = 8; em[498] = 1; /* 496: pointer.pointer.char */
    	em[499] = 72; em[500] = 0; 
    em[501] = 1; em[502] = 8; em[503] = 1; /* 501: pointer.struct.dh_method */
    	em[504] = 506; em[505] = 0; 
    em[506] = 0; em[507] = 72; em[508] = 8; /* 506: struct.dh_method */
    	em[509] = 50; em[510] = 0; 
    	em[511] = 525; em[512] = 8; 
    	em[513] = 528; em[514] = 16; 
    	em[515] = 531; em[516] = 24; 
    	em[517] = 525; em[518] = 32; 
    	em[519] = 525; em[520] = 40; 
    	em[521] = 72; em[522] = 56; 
    	em[523] = 534; em[524] = 64; 
    em[525] = 8884097; em[526] = 8; em[527] = 0; /* 525: pointer.func */
    em[528] = 8884097; em[529] = 8; em[530] = 0; /* 528: pointer.func */
    em[531] = 8884097; em[532] = 8; em[533] = 0; /* 531: pointer.func */
    em[534] = 8884097; em[535] = 8; em[536] = 0; /* 534: pointer.func */
    em[537] = 1; em[538] = 8; em[539] = 1; /* 537: pointer.struct.engine_st */
    	em[540] = 542; em[541] = 0; 
    em[542] = 0; em[543] = 216; em[544] = 24; /* 542: struct.engine_st */
    	em[545] = 50; em[546] = 0; 
    	em[547] = 50; em[548] = 8; 
    	em[549] = 593; em[550] = 16; 
    	em[551] = 648; em[552] = 24; 
    	em[553] = 699; em[554] = 32; 
    	em[555] = 735; em[556] = 40; 
    	em[557] = 752; em[558] = 48; 
    	em[559] = 779; em[560] = 56; 
    	em[561] = 814; em[562] = 64; 
    	em[563] = 822; em[564] = 72; 
    	em[565] = 825; em[566] = 80; 
    	em[567] = 828; em[568] = 88; 
    	em[569] = 831; em[570] = 96; 
    	em[571] = 834; em[572] = 104; 
    	em[573] = 834; em[574] = 112; 
    	em[575] = 834; em[576] = 120; 
    	em[577] = 837; em[578] = 128; 
    	em[579] = 840; em[580] = 136; 
    	em[581] = 840; em[582] = 144; 
    	em[583] = 843; em[584] = 152; 
    	em[585] = 846; em[586] = 160; 
    	em[587] = 858; em[588] = 184; 
    	em[589] = 880; em[590] = 200; 
    	em[591] = 880; em[592] = 208; 
    em[593] = 1; em[594] = 8; em[595] = 1; /* 593: pointer.struct.rsa_meth_st */
    	em[596] = 598; em[597] = 0; 
    em[598] = 0; em[599] = 112; em[600] = 13; /* 598: struct.rsa_meth_st */
    	em[601] = 50; em[602] = 0; 
    	em[603] = 627; em[604] = 8; 
    	em[605] = 627; em[606] = 16; 
    	em[607] = 627; em[608] = 24; 
    	em[609] = 627; em[610] = 32; 
    	em[611] = 630; em[612] = 40; 
    	em[613] = 633; em[614] = 48; 
    	em[615] = 636; em[616] = 56; 
    	em[617] = 636; em[618] = 64; 
    	em[619] = 72; em[620] = 80; 
    	em[621] = 639; em[622] = 88; 
    	em[623] = 642; em[624] = 96; 
    	em[625] = 645; em[626] = 104; 
    em[627] = 8884097; em[628] = 8; em[629] = 0; /* 627: pointer.func */
    em[630] = 8884097; em[631] = 8; em[632] = 0; /* 630: pointer.func */
    em[633] = 8884097; em[634] = 8; em[635] = 0; /* 633: pointer.func */
    em[636] = 8884097; em[637] = 8; em[638] = 0; /* 636: pointer.func */
    em[639] = 8884097; em[640] = 8; em[641] = 0; /* 639: pointer.func */
    em[642] = 8884097; em[643] = 8; em[644] = 0; /* 642: pointer.func */
    em[645] = 8884097; em[646] = 8; em[647] = 0; /* 645: pointer.func */
    em[648] = 1; em[649] = 8; em[650] = 1; /* 648: pointer.struct.dsa_method */
    	em[651] = 653; em[652] = 0; 
    em[653] = 0; em[654] = 96; em[655] = 11; /* 653: struct.dsa_method */
    	em[656] = 50; em[657] = 0; 
    	em[658] = 678; em[659] = 8; 
    	em[660] = 681; em[661] = 16; 
    	em[662] = 684; em[663] = 24; 
    	em[664] = 687; em[665] = 32; 
    	em[666] = 690; em[667] = 40; 
    	em[668] = 693; em[669] = 48; 
    	em[670] = 693; em[671] = 56; 
    	em[672] = 72; em[673] = 72; 
    	em[674] = 696; em[675] = 80; 
    	em[676] = 693; em[677] = 88; 
    em[678] = 8884097; em[679] = 8; em[680] = 0; /* 678: pointer.func */
    em[681] = 8884097; em[682] = 8; em[683] = 0; /* 681: pointer.func */
    em[684] = 8884097; em[685] = 8; em[686] = 0; /* 684: pointer.func */
    em[687] = 8884097; em[688] = 8; em[689] = 0; /* 687: pointer.func */
    em[690] = 8884097; em[691] = 8; em[692] = 0; /* 690: pointer.func */
    em[693] = 8884097; em[694] = 8; em[695] = 0; /* 693: pointer.func */
    em[696] = 8884097; em[697] = 8; em[698] = 0; /* 696: pointer.func */
    em[699] = 1; em[700] = 8; em[701] = 1; /* 699: pointer.struct.dh_method */
    	em[702] = 704; em[703] = 0; 
    em[704] = 0; em[705] = 72; em[706] = 8; /* 704: struct.dh_method */
    	em[707] = 50; em[708] = 0; 
    	em[709] = 723; em[710] = 8; 
    	em[711] = 726; em[712] = 16; 
    	em[713] = 729; em[714] = 24; 
    	em[715] = 723; em[716] = 32; 
    	em[717] = 723; em[718] = 40; 
    	em[719] = 72; em[720] = 56; 
    	em[721] = 732; em[722] = 64; 
    em[723] = 8884097; em[724] = 8; em[725] = 0; /* 723: pointer.func */
    em[726] = 8884097; em[727] = 8; em[728] = 0; /* 726: pointer.func */
    em[729] = 8884097; em[730] = 8; em[731] = 0; /* 729: pointer.func */
    em[732] = 8884097; em[733] = 8; em[734] = 0; /* 732: pointer.func */
    em[735] = 1; em[736] = 8; em[737] = 1; /* 735: pointer.struct.ecdh_method */
    	em[738] = 740; em[739] = 0; 
    em[740] = 0; em[741] = 32; em[742] = 3; /* 740: struct.ecdh_method */
    	em[743] = 50; em[744] = 0; 
    	em[745] = 749; em[746] = 8; 
    	em[747] = 72; em[748] = 24; 
    em[749] = 8884097; em[750] = 8; em[751] = 0; /* 749: pointer.func */
    em[752] = 1; em[753] = 8; em[754] = 1; /* 752: pointer.struct.ecdsa_method */
    	em[755] = 757; em[756] = 0; 
    em[757] = 0; em[758] = 48; em[759] = 5; /* 757: struct.ecdsa_method */
    	em[760] = 50; em[761] = 0; 
    	em[762] = 770; em[763] = 8; 
    	em[764] = 773; em[765] = 16; 
    	em[766] = 776; em[767] = 24; 
    	em[768] = 72; em[769] = 40; 
    em[770] = 8884097; em[771] = 8; em[772] = 0; /* 770: pointer.func */
    em[773] = 8884097; em[774] = 8; em[775] = 0; /* 773: pointer.func */
    em[776] = 8884097; em[777] = 8; em[778] = 0; /* 776: pointer.func */
    em[779] = 1; em[780] = 8; em[781] = 1; /* 779: pointer.struct.rand_meth_st */
    	em[782] = 784; em[783] = 0; 
    em[784] = 0; em[785] = 48; em[786] = 6; /* 784: struct.rand_meth_st */
    	em[787] = 799; em[788] = 0; 
    	em[789] = 802; em[790] = 8; 
    	em[791] = 805; em[792] = 16; 
    	em[793] = 808; em[794] = 24; 
    	em[795] = 802; em[796] = 32; 
    	em[797] = 811; em[798] = 40; 
    em[799] = 8884097; em[800] = 8; em[801] = 0; /* 799: pointer.func */
    em[802] = 8884097; em[803] = 8; em[804] = 0; /* 802: pointer.func */
    em[805] = 8884097; em[806] = 8; em[807] = 0; /* 805: pointer.func */
    em[808] = 8884097; em[809] = 8; em[810] = 0; /* 808: pointer.func */
    em[811] = 8884097; em[812] = 8; em[813] = 0; /* 811: pointer.func */
    em[814] = 1; em[815] = 8; em[816] = 1; /* 814: pointer.struct.store_method_st */
    	em[817] = 819; em[818] = 0; 
    em[819] = 0; em[820] = 0; em[821] = 0; /* 819: struct.store_method_st */
    em[822] = 8884097; em[823] = 8; em[824] = 0; /* 822: pointer.func */
    em[825] = 8884097; em[826] = 8; em[827] = 0; /* 825: pointer.func */
    em[828] = 8884097; em[829] = 8; em[830] = 0; /* 828: pointer.func */
    em[831] = 8884097; em[832] = 8; em[833] = 0; /* 831: pointer.func */
    em[834] = 8884097; em[835] = 8; em[836] = 0; /* 834: pointer.func */
    em[837] = 8884097; em[838] = 8; em[839] = 0; /* 837: pointer.func */
    em[840] = 8884097; em[841] = 8; em[842] = 0; /* 840: pointer.func */
    em[843] = 8884097; em[844] = 8; em[845] = 0; /* 843: pointer.func */
    em[846] = 1; em[847] = 8; em[848] = 1; /* 846: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[849] = 851; em[850] = 0; 
    em[851] = 0; em[852] = 32; em[853] = 2; /* 851: struct.ENGINE_CMD_DEFN_st */
    	em[854] = 50; em[855] = 8; 
    	em[856] = 50; em[857] = 16; 
    em[858] = 0; em[859] = 16; em[860] = 1; /* 858: struct.crypto_ex_data_st */
    	em[861] = 863; em[862] = 0; 
    em[863] = 1; em[864] = 8; em[865] = 1; /* 863: pointer.struct.stack_st_void */
    	em[866] = 868; em[867] = 0; 
    em[868] = 0; em[869] = 32; em[870] = 1; /* 868: struct.stack_st_void */
    	em[871] = 873; em[872] = 0; 
    em[873] = 0; em[874] = 32; em[875] = 2; /* 873: struct.stack_st */
    	em[876] = 496; em[877] = 8; 
    	em[878] = 264; em[879] = 24; 
    em[880] = 1; em[881] = 8; em[882] = 1; /* 880: pointer.struct.engine_st */
    	em[883] = 542; em[884] = 0; 
    em[885] = 1; em[886] = 8; em[887] = 1; /* 885: pointer.struct.rsa_st */
    	em[888] = 890; em[889] = 0; 
    em[890] = 0; em[891] = 168; em[892] = 17; /* 890: struct.rsa_st */
    	em[893] = 927; em[894] = 16; 
    	em[895] = 537; em[896] = 24; 
    	em[897] = 982; em[898] = 32; 
    	em[899] = 982; em[900] = 40; 
    	em[901] = 982; em[902] = 48; 
    	em[903] = 982; em[904] = 56; 
    	em[905] = 982; em[906] = 64; 
    	em[907] = 982; em[908] = 72; 
    	em[909] = 982; em[910] = 80; 
    	em[911] = 982; em[912] = 88; 
    	em[913] = 999; em[914] = 96; 
    	em[915] = 1021; em[916] = 120; 
    	em[917] = 1021; em[918] = 128; 
    	em[919] = 1021; em[920] = 136; 
    	em[921] = 72; em[922] = 144; 
    	em[923] = 1035; em[924] = 152; 
    	em[925] = 1035; em[926] = 160; 
    em[927] = 1; em[928] = 8; em[929] = 1; /* 927: pointer.struct.rsa_meth_st */
    	em[930] = 932; em[931] = 0; 
    em[932] = 0; em[933] = 112; em[934] = 13; /* 932: struct.rsa_meth_st */
    	em[935] = 50; em[936] = 0; 
    	em[937] = 961; em[938] = 8; 
    	em[939] = 961; em[940] = 16; 
    	em[941] = 961; em[942] = 24; 
    	em[943] = 961; em[944] = 32; 
    	em[945] = 964; em[946] = 40; 
    	em[947] = 967; em[948] = 48; 
    	em[949] = 970; em[950] = 56; 
    	em[951] = 970; em[952] = 64; 
    	em[953] = 72; em[954] = 80; 
    	em[955] = 973; em[956] = 88; 
    	em[957] = 976; em[958] = 96; 
    	em[959] = 979; em[960] = 104; 
    em[961] = 8884097; em[962] = 8; em[963] = 0; /* 961: pointer.func */
    em[964] = 8884097; em[965] = 8; em[966] = 0; /* 964: pointer.func */
    em[967] = 8884097; em[968] = 8; em[969] = 0; /* 967: pointer.func */
    em[970] = 8884097; em[971] = 8; em[972] = 0; /* 970: pointer.func */
    em[973] = 8884097; em[974] = 8; em[975] = 0; /* 973: pointer.func */
    em[976] = 8884097; em[977] = 8; em[978] = 0; /* 976: pointer.func */
    em[979] = 8884097; em[980] = 8; em[981] = 0; /* 979: pointer.func */
    em[982] = 1; em[983] = 8; em[984] = 1; /* 982: pointer.struct.bignum_st */
    	em[985] = 987; em[986] = 0; 
    em[987] = 0; em[988] = 24; em[989] = 1; /* 987: struct.bignum_st */
    	em[990] = 992; em[991] = 0; 
    em[992] = 8884099; em[993] = 8; em[994] = 2; /* 992: pointer_to_array_of_pointers_to_stack */
    	em[995] = 457; em[996] = 0; 
    	em[997] = 261; em[998] = 12; 
    em[999] = 0; em[1000] = 16; em[1001] = 1; /* 999: struct.crypto_ex_data_st */
    	em[1002] = 1004; em[1003] = 0; 
    em[1004] = 1; em[1005] = 8; em[1006] = 1; /* 1004: pointer.struct.stack_st_void */
    	em[1007] = 1009; em[1008] = 0; 
    em[1009] = 0; em[1010] = 32; em[1011] = 1; /* 1009: struct.stack_st_void */
    	em[1012] = 1014; em[1013] = 0; 
    em[1014] = 0; em[1015] = 32; em[1016] = 2; /* 1014: struct.stack_st */
    	em[1017] = 496; em[1018] = 8; 
    	em[1019] = 264; em[1020] = 24; 
    em[1021] = 1; em[1022] = 8; em[1023] = 1; /* 1021: pointer.struct.bn_mont_ctx_st */
    	em[1024] = 1026; em[1025] = 0; 
    em[1026] = 0; em[1027] = 96; em[1028] = 3; /* 1026: struct.bn_mont_ctx_st */
    	em[1029] = 987; em[1030] = 8; 
    	em[1031] = 987; em[1032] = 32; 
    	em[1033] = 987; em[1034] = 56; 
    em[1035] = 1; em[1036] = 8; em[1037] = 1; /* 1035: pointer.struct.bn_blinding_st */
    	em[1038] = 1040; em[1039] = 0; 
    em[1040] = 0; em[1041] = 88; em[1042] = 7; /* 1040: struct.bn_blinding_st */
    	em[1043] = 1057; em[1044] = 0; 
    	em[1045] = 1057; em[1046] = 8; 
    	em[1047] = 1057; em[1048] = 16; 
    	em[1049] = 1057; em[1050] = 24; 
    	em[1051] = 1074; em[1052] = 40; 
    	em[1053] = 1082; em[1054] = 72; 
    	em[1055] = 1096; em[1056] = 80; 
    em[1057] = 1; em[1058] = 8; em[1059] = 1; /* 1057: pointer.struct.bignum_st */
    	em[1060] = 1062; em[1061] = 0; 
    em[1062] = 0; em[1063] = 24; em[1064] = 1; /* 1062: struct.bignum_st */
    	em[1065] = 1067; em[1066] = 0; 
    em[1067] = 8884099; em[1068] = 8; em[1069] = 2; /* 1067: pointer_to_array_of_pointers_to_stack */
    	em[1070] = 457; em[1071] = 0; 
    	em[1072] = 261; em[1073] = 12; 
    em[1074] = 0; em[1075] = 16; em[1076] = 1; /* 1074: struct.crypto_threadid_st */
    	em[1077] = 1079; em[1078] = 0; 
    em[1079] = 0; em[1080] = 8; em[1081] = 0; /* 1079: pointer.void */
    em[1082] = 1; em[1083] = 8; em[1084] = 1; /* 1082: pointer.struct.bn_mont_ctx_st */
    	em[1085] = 1087; em[1086] = 0; 
    em[1087] = 0; em[1088] = 96; em[1089] = 3; /* 1087: struct.bn_mont_ctx_st */
    	em[1090] = 1062; em[1091] = 8; 
    	em[1092] = 1062; em[1093] = 32; 
    	em[1094] = 1062; em[1095] = 56; 
    em[1096] = 8884097; em[1097] = 8; em[1098] = 0; /* 1096: pointer.func */
    em[1099] = 0; em[1100] = 8; em[1101] = 5; /* 1099: union.unknown */
    	em[1102] = 72; em[1103] = 0; 
    	em[1104] = 885; em[1105] = 0; 
    	em[1106] = 1112; em[1107] = 0; 
    	em[1108] = 408; em[1109] = 0; 
    	em[1110] = 1193; em[1111] = 0; 
    em[1112] = 1; em[1113] = 8; em[1114] = 1; /* 1112: pointer.struct.dsa_st */
    	em[1115] = 1117; em[1116] = 0; 
    em[1117] = 0; em[1118] = 136; em[1119] = 11; /* 1117: struct.dsa_st */
    	em[1120] = 982; em[1121] = 24; 
    	em[1122] = 982; em[1123] = 32; 
    	em[1124] = 982; em[1125] = 40; 
    	em[1126] = 982; em[1127] = 48; 
    	em[1128] = 982; em[1129] = 56; 
    	em[1130] = 982; em[1131] = 64; 
    	em[1132] = 982; em[1133] = 72; 
    	em[1134] = 1021; em[1135] = 88; 
    	em[1136] = 999; em[1137] = 104; 
    	em[1138] = 1142; em[1139] = 120; 
    	em[1140] = 537; em[1141] = 128; 
    em[1142] = 1; em[1143] = 8; em[1144] = 1; /* 1142: pointer.struct.dsa_method */
    	em[1145] = 1147; em[1146] = 0; 
    em[1147] = 0; em[1148] = 96; em[1149] = 11; /* 1147: struct.dsa_method */
    	em[1150] = 50; em[1151] = 0; 
    	em[1152] = 1172; em[1153] = 8; 
    	em[1154] = 1175; em[1155] = 16; 
    	em[1156] = 1178; em[1157] = 24; 
    	em[1158] = 1181; em[1159] = 32; 
    	em[1160] = 1184; em[1161] = 40; 
    	em[1162] = 1187; em[1163] = 48; 
    	em[1164] = 1187; em[1165] = 56; 
    	em[1166] = 72; em[1167] = 72; 
    	em[1168] = 1190; em[1169] = 80; 
    	em[1170] = 1187; em[1171] = 88; 
    em[1172] = 8884097; em[1173] = 8; em[1174] = 0; /* 1172: pointer.func */
    em[1175] = 8884097; em[1176] = 8; em[1177] = 0; /* 1175: pointer.func */
    em[1178] = 8884097; em[1179] = 8; em[1180] = 0; /* 1178: pointer.func */
    em[1181] = 8884097; em[1182] = 8; em[1183] = 0; /* 1181: pointer.func */
    em[1184] = 8884097; em[1185] = 8; em[1186] = 0; /* 1184: pointer.func */
    em[1187] = 8884097; em[1188] = 8; em[1189] = 0; /* 1187: pointer.func */
    em[1190] = 8884097; em[1191] = 8; em[1192] = 0; /* 1190: pointer.func */
    em[1193] = 1; em[1194] = 8; em[1195] = 1; /* 1193: pointer.struct.ec_key_st */
    	em[1196] = 1198; em[1197] = 0; 
    em[1198] = 0; em[1199] = 56; em[1200] = 4; /* 1198: struct.ec_key_st */
    	em[1201] = 1209; em[1202] = 8; 
    	em[1203] = 1657; em[1204] = 16; 
    	em[1205] = 1662; em[1206] = 24; 
    	em[1207] = 1679; em[1208] = 48; 
    em[1209] = 1; em[1210] = 8; em[1211] = 1; /* 1209: pointer.struct.ec_group_st */
    	em[1212] = 1214; em[1213] = 0; 
    em[1214] = 0; em[1215] = 232; em[1216] = 12; /* 1214: struct.ec_group_st */
    	em[1217] = 1241; em[1218] = 0; 
    	em[1219] = 1413; em[1220] = 8; 
    	em[1221] = 1613; em[1222] = 16; 
    	em[1223] = 1613; em[1224] = 40; 
    	em[1225] = 164; em[1226] = 80; 
    	em[1227] = 1625; em[1228] = 96; 
    	em[1229] = 1613; em[1230] = 104; 
    	em[1231] = 1613; em[1232] = 152; 
    	em[1233] = 1613; em[1234] = 176; 
    	em[1235] = 1079; em[1236] = 208; 
    	em[1237] = 1079; em[1238] = 216; 
    	em[1239] = 1654; em[1240] = 224; 
    em[1241] = 1; em[1242] = 8; em[1243] = 1; /* 1241: pointer.struct.ec_method_st */
    	em[1244] = 1246; em[1245] = 0; 
    em[1246] = 0; em[1247] = 304; em[1248] = 37; /* 1246: struct.ec_method_st */
    	em[1249] = 1323; em[1250] = 8; 
    	em[1251] = 1326; em[1252] = 16; 
    	em[1253] = 1326; em[1254] = 24; 
    	em[1255] = 1329; em[1256] = 32; 
    	em[1257] = 1332; em[1258] = 40; 
    	em[1259] = 1335; em[1260] = 48; 
    	em[1261] = 1338; em[1262] = 56; 
    	em[1263] = 1341; em[1264] = 64; 
    	em[1265] = 1344; em[1266] = 72; 
    	em[1267] = 1347; em[1268] = 80; 
    	em[1269] = 1347; em[1270] = 88; 
    	em[1271] = 1350; em[1272] = 96; 
    	em[1273] = 1353; em[1274] = 104; 
    	em[1275] = 1356; em[1276] = 112; 
    	em[1277] = 1359; em[1278] = 120; 
    	em[1279] = 1362; em[1280] = 128; 
    	em[1281] = 1365; em[1282] = 136; 
    	em[1283] = 1368; em[1284] = 144; 
    	em[1285] = 1371; em[1286] = 152; 
    	em[1287] = 1374; em[1288] = 160; 
    	em[1289] = 1377; em[1290] = 168; 
    	em[1291] = 1380; em[1292] = 176; 
    	em[1293] = 1383; em[1294] = 184; 
    	em[1295] = 1386; em[1296] = 192; 
    	em[1297] = 1389; em[1298] = 200; 
    	em[1299] = 1392; em[1300] = 208; 
    	em[1301] = 1383; em[1302] = 216; 
    	em[1303] = 1395; em[1304] = 224; 
    	em[1305] = 1398; em[1306] = 232; 
    	em[1307] = 1401; em[1308] = 240; 
    	em[1309] = 1338; em[1310] = 248; 
    	em[1311] = 1404; em[1312] = 256; 
    	em[1313] = 1407; em[1314] = 264; 
    	em[1315] = 1404; em[1316] = 272; 
    	em[1317] = 1407; em[1318] = 280; 
    	em[1319] = 1407; em[1320] = 288; 
    	em[1321] = 1410; em[1322] = 296; 
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
    em[1362] = 8884097; em[1363] = 8; em[1364] = 0; /* 1362: pointer.func */
    em[1365] = 8884097; em[1366] = 8; em[1367] = 0; /* 1365: pointer.func */
    em[1368] = 8884097; em[1369] = 8; em[1370] = 0; /* 1368: pointer.func */
    em[1371] = 8884097; em[1372] = 8; em[1373] = 0; /* 1371: pointer.func */
    em[1374] = 8884097; em[1375] = 8; em[1376] = 0; /* 1374: pointer.func */
    em[1377] = 8884097; em[1378] = 8; em[1379] = 0; /* 1377: pointer.func */
    em[1380] = 8884097; em[1381] = 8; em[1382] = 0; /* 1380: pointer.func */
    em[1383] = 8884097; em[1384] = 8; em[1385] = 0; /* 1383: pointer.func */
    em[1386] = 8884097; em[1387] = 8; em[1388] = 0; /* 1386: pointer.func */
    em[1389] = 8884097; em[1390] = 8; em[1391] = 0; /* 1389: pointer.func */
    em[1392] = 8884097; em[1393] = 8; em[1394] = 0; /* 1392: pointer.func */
    em[1395] = 8884097; em[1396] = 8; em[1397] = 0; /* 1395: pointer.func */
    em[1398] = 8884097; em[1399] = 8; em[1400] = 0; /* 1398: pointer.func */
    em[1401] = 8884097; em[1402] = 8; em[1403] = 0; /* 1401: pointer.func */
    em[1404] = 8884097; em[1405] = 8; em[1406] = 0; /* 1404: pointer.func */
    em[1407] = 8884097; em[1408] = 8; em[1409] = 0; /* 1407: pointer.func */
    em[1410] = 8884097; em[1411] = 8; em[1412] = 0; /* 1410: pointer.func */
    em[1413] = 1; em[1414] = 8; em[1415] = 1; /* 1413: pointer.struct.ec_point_st */
    	em[1416] = 1418; em[1417] = 0; 
    em[1418] = 0; em[1419] = 88; em[1420] = 4; /* 1418: struct.ec_point_st */
    	em[1421] = 1429; em[1422] = 0; 
    	em[1423] = 1601; em[1424] = 8; 
    	em[1425] = 1601; em[1426] = 32; 
    	em[1427] = 1601; em[1428] = 56; 
    em[1429] = 1; em[1430] = 8; em[1431] = 1; /* 1429: pointer.struct.ec_method_st */
    	em[1432] = 1434; em[1433] = 0; 
    em[1434] = 0; em[1435] = 304; em[1436] = 37; /* 1434: struct.ec_method_st */
    	em[1437] = 1511; em[1438] = 8; 
    	em[1439] = 1514; em[1440] = 16; 
    	em[1441] = 1514; em[1442] = 24; 
    	em[1443] = 1517; em[1444] = 32; 
    	em[1445] = 1520; em[1446] = 40; 
    	em[1447] = 1523; em[1448] = 48; 
    	em[1449] = 1526; em[1450] = 56; 
    	em[1451] = 1529; em[1452] = 64; 
    	em[1453] = 1532; em[1454] = 72; 
    	em[1455] = 1535; em[1456] = 80; 
    	em[1457] = 1535; em[1458] = 88; 
    	em[1459] = 1538; em[1460] = 96; 
    	em[1461] = 1541; em[1462] = 104; 
    	em[1463] = 1544; em[1464] = 112; 
    	em[1465] = 1547; em[1466] = 120; 
    	em[1467] = 1550; em[1468] = 128; 
    	em[1469] = 1553; em[1470] = 136; 
    	em[1471] = 1556; em[1472] = 144; 
    	em[1473] = 1559; em[1474] = 152; 
    	em[1475] = 1562; em[1476] = 160; 
    	em[1477] = 1565; em[1478] = 168; 
    	em[1479] = 1568; em[1480] = 176; 
    	em[1481] = 1571; em[1482] = 184; 
    	em[1483] = 1574; em[1484] = 192; 
    	em[1485] = 1577; em[1486] = 200; 
    	em[1487] = 1580; em[1488] = 208; 
    	em[1489] = 1571; em[1490] = 216; 
    	em[1491] = 1583; em[1492] = 224; 
    	em[1493] = 1586; em[1494] = 232; 
    	em[1495] = 1589; em[1496] = 240; 
    	em[1497] = 1526; em[1498] = 248; 
    	em[1499] = 1592; em[1500] = 256; 
    	em[1501] = 1595; em[1502] = 264; 
    	em[1503] = 1592; em[1504] = 272; 
    	em[1505] = 1595; em[1506] = 280; 
    	em[1507] = 1595; em[1508] = 288; 
    	em[1509] = 1598; em[1510] = 296; 
    em[1511] = 8884097; em[1512] = 8; em[1513] = 0; /* 1511: pointer.func */
    em[1514] = 8884097; em[1515] = 8; em[1516] = 0; /* 1514: pointer.func */
    em[1517] = 8884097; em[1518] = 8; em[1519] = 0; /* 1517: pointer.func */
    em[1520] = 8884097; em[1521] = 8; em[1522] = 0; /* 1520: pointer.func */
    em[1523] = 8884097; em[1524] = 8; em[1525] = 0; /* 1523: pointer.func */
    em[1526] = 8884097; em[1527] = 8; em[1528] = 0; /* 1526: pointer.func */
    em[1529] = 8884097; em[1530] = 8; em[1531] = 0; /* 1529: pointer.func */
    em[1532] = 8884097; em[1533] = 8; em[1534] = 0; /* 1532: pointer.func */
    em[1535] = 8884097; em[1536] = 8; em[1537] = 0; /* 1535: pointer.func */
    em[1538] = 8884097; em[1539] = 8; em[1540] = 0; /* 1538: pointer.func */
    em[1541] = 8884097; em[1542] = 8; em[1543] = 0; /* 1541: pointer.func */
    em[1544] = 8884097; em[1545] = 8; em[1546] = 0; /* 1544: pointer.func */
    em[1547] = 8884097; em[1548] = 8; em[1549] = 0; /* 1547: pointer.func */
    em[1550] = 8884097; em[1551] = 8; em[1552] = 0; /* 1550: pointer.func */
    em[1553] = 8884097; em[1554] = 8; em[1555] = 0; /* 1553: pointer.func */
    em[1556] = 8884097; em[1557] = 8; em[1558] = 0; /* 1556: pointer.func */
    em[1559] = 8884097; em[1560] = 8; em[1561] = 0; /* 1559: pointer.func */
    em[1562] = 8884097; em[1563] = 8; em[1564] = 0; /* 1562: pointer.func */
    em[1565] = 8884097; em[1566] = 8; em[1567] = 0; /* 1565: pointer.func */
    em[1568] = 8884097; em[1569] = 8; em[1570] = 0; /* 1568: pointer.func */
    em[1571] = 8884097; em[1572] = 8; em[1573] = 0; /* 1571: pointer.func */
    em[1574] = 8884097; em[1575] = 8; em[1576] = 0; /* 1574: pointer.func */
    em[1577] = 8884097; em[1578] = 8; em[1579] = 0; /* 1577: pointer.func */
    em[1580] = 8884097; em[1581] = 8; em[1582] = 0; /* 1580: pointer.func */
    em[1583] = 8884097; em[1584] = 8; em[1585] = 0; /* 1583: pointer.func */
    em[1586] = 8884097; em[1587] = 8; em[1588] = 0; /* 1586: pointer.func */
    em[1589] = 8884097; em[1590] = 8; em[1591] = 0; /* 1589: pointer.func */
    em[1592] = 8884097; em[1593] = 8; em[1594] = 0; /* 1592: pointer.func */
    em[1595] = 8884097; em[1596] = 8; em[1597] = 0; /* 1595: pointer.func */
    em[1598] = 8884097; em[1599] = 8; em[1600] = 0; /* 1598: pointer.func */
    em[1601] = 0; em[1602] = 24; em[1603] = 1; /* 1601: struct.bignum_st */
    	em[1604] = 1606; em[1605] = 0; 
    em[1606] = 8884099; em[1607] = 8; em[1608] = 2; /* 1606: pointer_to_array_of_pointers_to_stack */
    	em[1609] = 457; em[1610] = 0; 
    	em[1611] = 261; em[1612] = 12; 
    em[1613] = 0; em[1614] = 24; em[1615] = 1; /* 1613: struct.bignum_st */
    	em[1616] = 1618; em[1617] = 0; 
    em[1618] = 8884099; em[1619] = 8; em[1620] = 2; /* 1618: pointer_to_array_of_pointers_to_stack */
    	em[1621] = 457; em[1622] = 0; 
    	em[1623] = 261; em[1624] = 12; 
    em[1625] = 1; em[1626] = 8; em[1627] = 1; /* 1625: pointer.struct.ec_extra_data_st */
    	em[1628] = 1630; em[1629] = 0; 
    em[1630] = 0; em[1631] = 40; em[1632] = 5; /* 1630: struct.ec_extra_data_st */
    	em[1633] = 1643; em[1634] = 0; 
    	em[1635] = 1079; em[1636] = 8; 
    	em[1637] = 1648; em[1638] = 16; 
    	em[1639] = 1651; em[1640] = 24; 
    	em[1641] = 1651; em[1642] = 32; 
    em[1643] = 1; em[1644] = 8; em[1645] = 1; /* 1643: pointer.struct.ec_extra_data_st */
    	em[1646] = 1630; em[1647] = 0; 
    em[1648] = 8884097; em[1649] = 8; em[1650] = 0; /* 1648: pointer.func */
    em[1651] = 8884097; em[1652] = 8; em[1653] = 0; /* 1651: pointer.func */
    em[1654] = 8884097; em[1655] = 8; em[1656] = 0; /* 1654: pointer.func */
    em[1657] = 1; em[1658] = 8; em[1659] = 1; /* 1657: pointer.struct.ec_point_st */
    	em[1660] = 1418; em[1661] = 0; 
    em[1662] = 1; em[1663] = 8; em[1664] = 1; /* 1662: pointer.struct.bignum_st */
    	em[1665] = 1667; em[1666] = 0; 
    em[1667] = 0; em[1668] = 24; em[1669] = 1; /* 1667: struct.bignum_st */
    	em[1670] = 1672; em[1671] = 0; 
    em[1672] = 8884099; em[1673] = 8; em[1674] = 2; /* 1672: pointer_to_array_of_pointers_to_stack */
    	em[1675] = 457; em[1676] = 0; 
    	em[1677] = 261; em[1678] = 12; 
    em[1679] = 1; em[1680] = 8; em[1681] = 1; /* 1679: pointer.struct.ec_extra_data_st */
    	em[1682] = 1684; em[1683] = 0; 
    em[1684] = 0; em[1685] = 40; em[1686] = 5; /* 1684: struct.ec_extra_data_st */
    	em[1687] = 1697; em[1688] = 0; 
    	em[1689] = 1079; em[1690] = 8; 
    	em[1691] = 1648; em[1692] = 16; 
    	em[1693] = 1651; em[1694] = 24; 
    	em[1695] = 1651; em[1696] = 32; 
    em[1697] = 1; em[1698] = 8; em[1699] = 1; /* 1697: pointer.struct.ec_extra_data_st */
    	em[1700] = 1684; em[1701] = 0; 
    em[1702] = 1; em[1703] = 8; em[1704] = 1; /* 1702: pointer.int */
    	em[1705] = 261; em[1706] = 0; 
    em[1707] = 1; em[1708] = 8; em[1709] = 1; /* 1707: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1710] = 1712; em[1711] = 0; 
    em[1712] = 0; em[1713] = 32; em[1714] = 2; /* 1712: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1715] = 1719; em[1716] = 8; 
    	em[1717] = 264; em[1718] = 24; 
    em[1719] = 8884099; em[1720] = 8; em[1721] = 2; /* 1719: pointer_to_array_of_pointers_to_stack */
    	em[1722] = 1726; em[1723] = 0; 
    	em[1724] = 261; em[1725] = 20; 
    em[1726] = 0; em[1727] = 8; em[1728] = 1; /* 1726: pointer.X509_ATTRIBUTE */
    	em[1729] = 24; em[1730] = 0; 
    em[1731] = 1; em[1732] = 8; em[1733] = 1; /* 1731: pointer.struct.evp_pkey_ctx_st */
    	em[1734] = 1736; em[1735] = 0; 
    em[1736] = 0; em[1737] = 80; em[1738] = 8; /* 1736: struct.evp_pkey_ctx_st */
    	em[1739] = 1755; em[1740] = 0; 
    	em[1741] = 1849; em[1742] = 8; 
    	em[1743] = 1854; em[1744] = 16; 
    	em[1745] = 1854; em[1746] = 24; 
    	em[1747] = 1079; em[1748] = 40; 
    	em[1749] = 1079; em[1750] = 48; 
    	em[1751] = 1999; em[1752] = 56; 
    	em[1753] = 1702; em[1754] = 64; 
    em[1755] = 1; em[1756] = 8; em[1757] = 1; /* 1755: pointer.struct.evp_pkey_method_st */
    	em[1758] = 1760; em[1759] = 0; 
    em[1760] = 0; em[1761] = 208; em[1762] = 25; /* 1760: struct.evp_pkey_method_st */
    	em[1763] = 1813; em[1764] = 8; 
    	em[1765] = 1816; em[1766] = 16; 
    	em[1767] = 1819; em[1768] = 24; 
    	em[1769] = 1813; em[1770] = 32; 
    	em[1771] = 1822; em[1772] = 40; 
    	em[1773] = 1813; em[1774] = 48; 
    	em[1775] = 1822; em[1776] = 56; 
    	em[1777] = 1813; em[1778] = 64; 
    	em[1779] = 1825; em[1780] = 72; 
    	em[1781] = 1813; em[1782] = 80; 
    	em[1783] = 1828; em[1784] = 88; 
    	em[1785] = 1813; em[1786] = 96; 
    	em[1787] = 1825; em[1788] = 104; 
    	em[1789] = 1831; em[1790] = 112; 
    	em[1791] = 1834; em[1792] = 120; 
    	em[1793] = 1831; em[1794] = 128; 
    	em[1795] = 1837; em[1796] = 136; 
    	em[1797] = 1813; em[1798] = 144; 
    	em[1799] = 1825; em[1800] = 152; 
    	em[1801] = 1813; em[1802] = 160; 
    	em[1803] = 1825; em[1804] = 168; 
    	em[1805] = 1813; em[1806] = 176; 
    	em[1807] = 1840; em[1808] = 184; 
    	em[1809] = 1843; em[1810] = 192; 
    	em[1811] = 1846; em[1812] = 200; 
    em[1813] = 8884097; em[1814] = 8; em[1815] = 0; /* 1813: pointer.func */
    em[1816] = 8884097; em[1817] = 8; em[1818] = 0; /* 1816: pointer.func */
    em[1819] = 8884097; em[1820] = 8; em[1821] = 0; /* 1819: pointer.func */
    em[1822] = 8884097; em[1823] = 8; em[1824] = 0; /* 1822: pointer.func */
    em[1825] = 8884097; em[1826] = 8; em[1827] = 0; /* 1825: pointer.func */
    em[1828] = 8884097; em[1829] = 8; em[1830] = 0; /* 1828: pointer.func */
    em[1831] = 8884097; em[1832] = 8; em[1833] = 0; /* 1831: pointer.func */
    em[1834] = 8884097; em[1835] = 8; em[1836] = 0; /* 1834: pointer.func */
    em[1837] = 8884097; em[1838] = 8; em[1839] = 0; /* 1837: pointer.func */
    em[1840] = 8884097; em[1841] = 8; em[1842] = 0; /* 1840: pointer.func */
    em[1843] = 8884097; em[1844] = 8; em[1845] = 0; /* 1843: pointer.func */
    em[1846] = 8884097; em[1847] = 8; em[1848] = 0; /* 1846: pointer.func */
    em[1849] = 1; em[1850] = 8; em[1851] = 1; /* 1849: pointer.struct.engine_st */
    	em[1852] = 542; em[1853] = 0; 
    em[1854] = 1; em[1855] = 8; em[1856] = 1; /* 1854: pointer.struct.evp_pkey_st */
    	em[1857] = 1859; em[1858] = 0; 
    em[1859] = 0; em[1860] = 56; em[1861] = 4; /* 1859: struct.evp_pkey_st */
    	em[1862] = 1870; em[1863] = 16; 
    	em[1864] = 1849; em[1865] = 24; 
    	em[1866] = 1971; em[1867] = 32; 
    	em[1868] = 1707; em[1869] = 48; 
    em[1870] = 1; em[1871] = 8; em[1872] = 1; /* 1870: pointer.struct.evp_pkey_asn1_method_st */
    	em[1873] = 1875; em[1874] = 0; 
    em[1875] = 0; em[1876] = 208; em[1877] = 24; /* 1875: struct.evp_pkey_asn1_method_st */
    	em[1878] = 72; em[1879] = 16; 
    	em[1880] = 72; em[1881] = 24; 
    	em[1882] = 1926; em[1883] = 32; 
    	em[1884] = 1929; em[1885] = 40; 
    	em[1886] = 1932; em[1887] = 48; 
    	em[1888] = 1935; em[1889] = 56; 
    	em[1890] = 1938; em[1891] = 64; 
    	em[1892] = 1941; em[1893] = 72; 
    	em[1894] = 1935; em[1895] = 80; 
    	em[1896] = 1944; em[1897] = 88; 
    	em[1898] = 1944; em[1899] = 96; 
    	em[1900] = 1947; em[1901] = 104; 
    	em[1902] = 1950; em[1903] = 112; 
    	em[1904] = 1944; em[1905] = 120; 
    	em[1906] = 1953; em[1907] = 128; 
    	em[1908] = 1932; em[1909] = 136; 
    	em[1910] = 1935; em[1911] = 144; 
    	em[1912] = 1956; em[1913] = 152; 
    	em[1914] = 1959; em[1915] = 160; 
    	em[1916] = 1962; em[1917] = 168; 
    	em[1918] = 1947; em[1919] = 176; 
    	em[1920] = 1950; em[1921] = 184; 
    	em[1922] = 1965; em[1923] = 192; 
    	em[1924] = 1968; em[1925] = 200; 
    em[1926] = 8884097; em[1927] = 8; em[1928] = 0; /* 1926: pointer.func */
    em[1929] = 8884097; em[1930] = 8; em[1931] = 0; /* 1929: pointer.func */
    em[1932] = 8884097; em[1933] = 8; em[1934] = 0; /* 1932: pointer.func */
    em[1935] = 8884097; em[1936] = 8; em[1937] = 0; /* 1935: pointer.func */
    em[1938] = 8884097; em[1939] = 8; em[1940] = 0; /* 1938: pointer.func */
    em[1941] = 8884097; em[1942] = 8; em[1943] = 0; /* 1941: pointer.func */
    em[1944] = 8884097; em[1945] = 8; em[1946] = 0; /* 1944: pointer.func */
    em[1947] = 8884097; em[1948] = 8; em[1949] = 0; /* 1947: pointer.func */
    em[1950] = 8884097; em[1951] = 8; em[1952] = 0; /* 1950: pointer.func */
    em[1953] = 8884097; em[1954] = 8; em[1955] = 0; /* 1953: pointer.func */
    em[1956] = 8884097; em[1957] = 8; em[1958] = 0; /* 1956: pointer.func */
    em[1959] = 8884097; em[1960] = 8; em[1961] = 0; /* 1959: pointer.func */
    em[1962] = 8884097; em[1963] = 8; em[1964] = 0; /* 1962: pointer.func */
    em[1965] = 8884097; em[1966] = 8; em[1967] = 0; /* 1965: pointer.func */
    em[1968] = 8884097; em[1969] = 8; em[1970] = 0; /* 1968: pointer.func */
    em[1971] = 0; em[1972] = 8; em[1973] = 5; /* 1971: union.unknown */
    	em[1974] = 72; em[1975] = 0; 
    	em[1976] = 1984; em[1977] = 0; 
    	em[1978] = 1989; em[1979] = 0; 
    	em[1980] = 1994; em[1981] = 0; 
    	em[1982] = 1193; em[1983] = 0; 
    em[1984] = 1; em[1985] = 8; em[1986] = 1; /* 1984: pointer.struct.rsa_st */
    	em[1987] = 890; em[1988] = 0; 
    em[1989] = 1; em[1990] = 8; em[1991] = 1; /* 1989: pointer.struct.dsa_st */
    	em[1992] = 1117; em[1993] = 0; 
    em[1994] = 1; em[1995] = 8; em[1996] = 1; /* 1994: pointer.struct.dh_st */
    	em[1997] = 413; em[1998] = 0; 
    em[1999] = 8884097; em[2000] = 8; em[2001] = 0; /* 1999: pointer.func */
    em[2002] = 8884097; em[2003] = 8; em[2004] = 0; /* 2002: pointer.func */
    em[2005] = 8884097; em[2006] = 8; em[2007] = 0; /* 2005: pointer.func */
    em[2008] = 0; em[2009] = 1; em[2010] = 0; /* 2008: char */
    em[2011] = 8884097; em[2012] = 8; em[2013] = 0; /* 2011: pointer.func */
    em[2014] = 1; em[2015] = 8; em[2016] = 1; /* 2014: pointer.unsigned int */
    	em[2017] = 2019; em[2018] = 0; 
    em[2019] = 0; em[2020] = 4; em[2021] = 0; /* 2019: unsigned int */
    em[2022] = 1; em[2023] = 8; em[2024] = 1; /* 2022: pointer.struct.env_md_ctx_st */
    	em[2025] = 2027; em[2026] = 0; 
    em[2027] = 0; em[2028] = 48; em[2029] = 5; /* 2027: struct.env_md_ctx_st */
    	em[2030] = 2040; em[2031] = 0; 
    	em[2032] = 1849; em[2033] = 8; 
    	em[2034] = 1079; em[2035] = 24; 
    	em[2036] = 1731; em[2037] = 32; 
    	em[2038] = 2064; em[2039] = 40; 
    em[2040] = 1; em[2041] = 8; em[2042] = 1; /* 2040: pointer.struct.env_md_st */
    	em[2043] = 2045; em[2044] = 0; 
    em[2045] = 0; em[2046] = 120; em[2047] = 8; /* 2045: struct.env_md_st */
    	em[2048] = 2005; em[2049] = 24; 
    	em[2050] = 2064; em[2051] = 32; 
    	em[2052] = 2067; em[2053] = 40; 
    	em[2054] = 2070; em[2055] = 48; 
    	em[2056] = 2005; em[2057] = 56; 
    	em[2058] = 2073; em[2059] = 64; 
    	em[2060] = 2002; em[2061] = 72; 
    	em[2062] = 2011; em[2063] = 112; 
    em[2064] = 8884097; em[2065] = 8; em[2066] = 0; /* 2064: pointer.func */
    em[2067] = 8884097; em[2068] = 8; em[2069] = 0; /* 2067: pointer.func */
    em[2070] = 8884097; em[2071] = 8; em[2072] = 0; /* 2070: pointer.func */
    em[2073] = 8884097; em[2074] = 8; em[2075] = 0; /* 2073: pointer.func */
    em[2076] = 1; em[2077] = 8; em[2078] = 1; /* 2076: pointer.struct.evp_pkey_st */
    	em[2079] = 2081; em[2080] = 0; 
    em[2081] = 0; em[2082] = 56; em[2083] = 4; /* 2081: struct.evp_pkey_st */
    	em[2084] = 1870; em[2085] = 16; 
    	em[2086] = 1849; em[2087] = 24; 
    	em[2088] = 1099; em[2089] = 32; 
    	em[2090] = 0; em[2091] = 48; 
    args_addr->arg_entity_index[0] = 2022;
    args_addr->arg_entity_index[1] = 164;
    args_addr->arg_entity_index[2] = 2014;
    args_addr->arg_entity_index[3] = 2076;
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

