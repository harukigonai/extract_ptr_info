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

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e);

int HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
{
    unsigned long in_lib = syscall(890);
    printf("HMAC_Init_ex called %lu\n", in_lib);
    if (!in_lib)
        return bb_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    else {
        int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
        orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
        return orig_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    }
}

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
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
    em[42] = 1; em[43] = 8; em[44] = 1; /* 42: pointer.struct.asn1_string_st */
    	em[45] = 24; em[46] = 0; 
    em[47] = 1; em[48] = 8; em[49] = 1; /* 47: pointer.struct.asn1_string_st */
    	em[50] = 24; em[51] = 0; 
    em[52] = 1; em[53] = 8; em[54] = 1; /* 52: pointer.struct.asn1_string_st */
    	em[55] = 24; em[56] = 0; 
    em[57] = 1; em[58] = 8; em[59] = 1; /* 57: pointer.struct.asn1_string_st */
    	em[60] = 24; em[61] = 0; 
    em[62] = 1; em[63] = 8; em[64] = 1; /* 62: pointer.struct.asn1_string_st */
    	em[65] = 24; em[66] = 0; 
    em[67] = 1; em[68] = 8; em[69] = 1; /* 67: pointer.struct.asn1_string_st */
    	em[70] = 24; em[71] = 0; 
    em[72] = 1; em[73] = 8; em[74] = 1; /* 72: pointer.struct.asn1_string_st */
    	em[75] = 24; em[76] = 0; 
    em[77] = 1; em[78] = 8; em[79] = 1; /* 77: pointer.struct.asn1_string_st */
    	em[80] = 24; em[81] = 0; 
    em[82] = 1; em[83] = 8; em[84] = 1; /* 82: pointer.struct.asn1_string_st */
    	em[85] = 24; em[86] = 0; 
    em[87] = 1; em[88] = 8; em[89] = 1; /* 87: pointer.struct.asn1_string_st */
    	em[90] = 24; em[91] = 0; 
    em[92] = 0; em[93] = 16; em[94] = 1; /* 92: struct.asn1_type_st */
    	em[95] = 97; em[96] = 8; 
    em[97] = 0; em[98] = 8; em[99] = 20; /* 97: union.unknown */
    	em[100] = 140; em[101] = 0; 
    	em[102] = 87; em[103] = 0; 
    	em[104] = 145; em[105] = 0; 
    	em[106] = 169; em[107] = 0; 
    	em[108] = 82; em[109] = 0; 
    	em[110] = 77; em[111] = 0; 
    	em[112] = 72; em[113] = 0; 
    	em[114] = 67; em[115] = 0; 
    	em[116] = 174; em[117] = 0; 
    	em[118] = 62; em[119] = 0; 
    	em[120] = 57; em[121] = 0; 
    	em[122] = 52; em[123] = 0; 
    	em[124] = 47; em[125] = 0; 
    	em[126] = 179; em[127] = 0; 
    	em[128] = 42; em[129] = 0; 
    	em[130] = 37; em[131] = 0; 
    	em[132] = 19; em[133] = 0; 
    	em[134] = 87; em[135] = 0; 
    	em[136] = 87; em[137] = 0; 
    	em[138] = 11; em[139] = 0; 
    em[140] = 1; em[141] = 8; em[142] = 1; /* 140: pointer.char */
    	em[143] = 8884096; em[144] = 0; 
    em[145] = 1; em[146] = 8; em[147] = 1; /* 145: pointer.struct.asn1_object_st */
    	em[148] = 150; em[149] = 0; 
    em[150] = 0; em[151] = 40; em[152] = 3; /* 150: struct.asn1_object_st */
    	em[153] = 159; em[154] = 0; 
    	em[155] = 159; em[156] = 8; 
    	em[157] = 164; em[158] = 24; 
    em[159] = 1; em[160] = 8; em[161] = 1; /* 159: pointer.char */
    	em[162] = 8884096; em[163] = 0; 
    em[164] = 1; em[165] = 8; em[166] = 1; /* 164: pointer.unsigned char */
    	em[167] = 34; em[168] = 0; 
    em[169] = 1; em[170] = 8; em[171] = 1; /* 169: pointer.struct.asn1_string_st */
    	em[172] = 24; em[173] = 0; 
    em[174] = 1; em[175] = 8; em[176] = 1; /* 174: pointer.struct.asn1_string_st */
    	em[177] = 24; em[178] = 0; 
    em[179] = 1; em[180] = 8; em[181] = 1; /* 179: pointer.struct.asn1_string_st */
    	em[182] = 24; em[183] = 0; 
    em[184] = 1; em[185] = 8; em[186] = 1; /* 184: pointer.struct.asn1_string_st */
    	em[187] = 189; em[188] = 0; 
    em[189] = 0; em[190] = 24; em[191] = 1; /* 189: struct.asn1_string_st */
    	em[192] = 29; em[193] = 8; 
    em[194] = 1; em[195] = 8; em[196] = 1; /* 194: pointer.struct.asn1_string_st */
    	em[197] = 189; em[198] = 0; 
    em[199] = 1; em[200] = 8; em[201] = 1; /* 199: pointer.struct.asn1_string_st */
    	em[202] = 189; em[203] = 0; 
    em[204] = 1; em[205] = 8; em[206] = 1; /* 204: pointer.struct.asn1_string_st */
    	em[207] = 189; em[208] = 0; 
    em[209] = 1; em[210] = 8; em[211] = 1; /* 209: pointer.struct.asn1_string_st */
    	em[212] = 189; em[213] = 0; 
    em[214] = 1; em[215] = 8; em[216] = 1; /* 214: pointer.struct.asn1_string_st */
    	em[217] = 189; em[218] = 0; 
    em[219] = 1; em[220] = 8; em[221] = 1; /* 219: pointer.struct.asn1_string_st */
    	em[222] = 189; em[223] = 0; 
    em[224] = 1; em[225] = 8; em[226] = 1; /* 224: pointer.struct.asn1_string_st */
    	em[227] = 189; em[228] = 0; 
    em[229] = 1; em[230] = 8; em[231] = 1; /* 229: pointer.struct.asn1_string_st */
    	em[232] = 189; em[233] = 0; 
    em[234] = 0; em[235] = 40; em[236] = 3; /* 234: struct.asn1_object_st */
    	em[237] = 159; em[238] = 0; 
    	em[239] = 159; em[240] = 8; 
    	em[241] = 164; em[242] = 24; 
    em[243] = 1; em[244] = 8; em[245] = 1; /* 243: pointer.struct.asn1_object_st */
    	em[246] = 234; em[247] = 0; 
    em[248] = 1; em[249] = 8; em[250] = 1; /* 248: pointer.struct.asn1_string_st */
    	em[251] = 189; em[252] = 0; 
    em[253] = 0; em[254] = 8; em[255] = 20; /* 253: union.unknown */
    	em[256] = 140; em[257] = 0; 
    	em[258] = 248; em[259] = 0; 
    	em[260] = 243; em[261] = 0; 
    	em[262] = 229; em[263] = 0; 
    	em[264] = 224; em[265] = 0; 
    	em[266] = 296; em[267] = 0; 
    	em[268] = 219; em[269] = 0; 
    	em[270] = 301; em[271] = 0; 
    	em[272] = 306; em[273] = 0; 
    	em[274] = 214; em[275] = 0; 
    	em[276] = 209; em[277] = 0; 
    	em[278] = 311; em[279] = 0; 
    	em[280] = 204; em[281] = 0; 
    	em[282] = 199; em[283] = 0; 
    	em[284] = 194; em[285] = 0; 
    	em[286] = 316; em[287] = 0; 
    	em[288] = 184; em[289] = 0; 
    	em[290] = 248; em[291] = 0; 
    	em[292] = 248; em[293] = 0; 
    	em[294] = 321; em[295] = 0; 
    em[296] = 1; em[297] = 8; em[298] = 1; /* 296: pointer.struct.asn1_string_st */
    	em[299] = 189; em[300] = 0; 
    em[301] = 1; em[302] = 8; em[303] = 1; /* 301: pointer.struct.asn1_string_st */
    	em[304] = 189; em[305] = 0; 
    em[306] = 1; em[307] = 8; em[308] = 1; /* 306: pointer.struct.asn1_string_st */
    	em[309] = 189; em[310] = 0; 
    em[311] = 1; em[312] = 8; em[313] = 1; /* 311: pointer.struct.asn1_string_st */
    	em[314] = 189; em[315] = 0; 
    em[316] = 1; em[317] = 8; em[318] = 1; /* 316: pointer.struct.asn1_string_st */
    	em[319] = 189; em[320] = 0; 
    em[321] = 1; em[322] = 8; em[323] = 1; /* 321: pointer.struct.ASN1_VALUE_st */
    	em[324] = 326; em[325] = 0; 
    em[326] = 0; em[327] = 0; em[328] = 0; /* 326: struct.ASN1_VALUE_st */
    em[329] = 0; em[330] = 16; em[331] = 1; /* 329: struct.asn1_type_st */
    	em[332] = 253; em[333] = 8; 
    em[334] = 0; em[335] = 0; em[336] = 1; /* 334: ASN1_TYPE */
    	em[337] = 329; em[338] = 0; 
    em[339] = 1; em[340] = 8; em[341] = 1; /* 339: pointer.struct.stack_st_ASN1_TYPE */
    	em[342] = 344; em[343] = 0; 
    em[344] = 0; em[345] = 32; em[346] = 2; /* 344: struct.stack_st_fake_ASN1_TYPE */
    	em[347] = 351; em[348] = 8; 
    	em[349] = 363; em[350] = 24; 
    em[351] = 8884099; em[352] = 8; em[353] = 2; /* 351: pointer_to_array_of_pointers_to_stack */
    	em[354] = 358; em[355] = 0; 
    	em[356] = 5; em[357] = 20; 
    em[358] = 0; em[359] = 8; em[360] = 1; /* 358: pointer.ASN1_TYPE */
    	em[361] = 334; em[362] = 0; 
    em[363] = 8884097; em[364] = 8; em[365] = 0; /* 363: pointer.func */
    em[366] = 0; em[367] = 8; em[368] = 3; /* 366: union.unknown */
    	em[369] = 140; em[370] = 0; 
    	em[371] = 339; em[372] = 0; 
    	em[373] = 375; em[374] = 0; 
    em[375] = 1; em[376] = 8; em[377] = 1; /* 375: pointer.struct.asn1_type_st */
    	em[378] = 92; em[379] = 0; 
    em[380] = 1; em[381] = 8; em[382] = 1; /* 380: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[383] = 385; em[384] = 0; 
    em[385] = 0; em[386] = 32; em[387] = 2; /* 385: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[388] = 392; em[389] = 8; 
    	em[390] = 363; em[391] = 24; 
    em[392] = 8884099; em[393] = 8; em[394] = 2; /* 392: pointer_to_array_of_pointers_to_stack */
    	em[395] = 399; em[396] = 0; 
    	em[397] = 5; em[398] = 20; 
    em[399] = 0; em[400] = 8; em[401] = 1; /* 399: pointer.X509_ATTRIBUTE */
    	em[402] = 404; em[403] = 0; 
    em[404] = 0; em[405] = 0; em[406] = 1; /* 404: X509_ATTRIBUTE */
    	em[407] = 409; em[408] = 0; 
    em[409] = 0; em[410] = 24; em[411] = 2; /* 409: struct.x509_attributes_st */
    	em[412] = 145; em[413] = 0; 
    	em[414] = 366; em[415] = 16; 
    em[416] = 0; em[417] = 112; em[418] = 13; /* 416: struct.rsa_meth_st */
    	em[419] = 159; em[420] = 0; 
    	em[421] = 445; em[422] = 8; 
    	em[423] = 445; em[424] = 16; 
    	em[425] = 445; em[426] = 24; 
    	em[427] = 445; em[428] = 32; 
    	em[429] = 448; em[430] = 40; 
    	em[431] = 451; em[432] = 48; 
    	em[433] = 454; em[434] = 56; 
    	em[435] = 454; em[436] = 64; 
    	em[437] = 140; em[438] = 80; 
    	em[439] = 457; em[440] = 88; 
    	em[441] = 460; em[442] = 96; 
    	em[443] = 463; em[444] = 104; 
    em[445] = 8884097; em[446] = 8; em[447] = 0; /* 445: pointer.func */
    em[448] = 8884097; em[449] = 8; em[450] = 0; /* 448: pointer.func */
    em[451] = 8884097; em[452] = 8; em[453] = 0; /* 451: pointer.func */
    em[454] = 8884097; em[455] = 8; em[456] = 0; /* 454: pointer.func */
    em[457] = 8884097; em[458] = 8; em[459] = 0; /* 457: pointer.func */
    em[460] = 8884097; em[461] = 8; em[462] = 0; /* 460: pointer.func */
    em[463] = 8884097; em[464] = 8; em[465] = 0; /* 463: pointer.func */
    em[466] = 0; em[467] = 32; em[468] = 2; /* 466: struct.stack_st */
    	em[469] = 473; em[470] = 8; 
    	em[471] = 363; em[472] = 24; 
    em[473] = 1; em[474] = 8; em[475] = 1; /* 473: pointer.pointer.char */
    	em[476] = 140; em[477] = 0; 
    em[478] = 0; em[479] = 168; em[480] = 17; /* 478: struct.rsa_st */
    	em[481] = 515; em[482] = 16; 
    	em[483] = 520; em[484] = 24; 
    	em[485] = 868; em[486] = 32; 
    	em[487] = 868; em[488] = 40; 
    	em[489] = 868; em[490] = 48; 
    	em[491] = 868; em[492] = 56; 
    	em[493] = 868; em[494] = 64; 
    	em[495] = 868; em[496] = 72; 
    	em[497] = 868; em[498] = 80; 
    	em[499] = 868; em[500] = 88; 
    	em[501] = 888; em[502] = 96; 
    	em[503] = 910; em[504] = 120; 
    	em[505] = 910; em[506] = 128; 
    	em[507] = 910; em[508] = 136; 
    	em[509] = 140; em[510] = 144; 
    	em[511] = 924; em[512] = 152; 
    	em[513] = 924; em[514] = 160; 
    em[515] = 1; em[516] = 8; em[517] = 1; /* 515: pointer.struct.rsa_meth_st */
    	em[518] = 416; em[519] = 0; 
    em[520] = 1; em[521] = 8; em[522] = 1; /* 520: pointer.struct.engine_st */
    	em[523] = 525; em[524] = 0; 
    em[525] = 0; em[526] = 216; em[527] = 24; /* 525: struct.engine_st */
    	em[528] = 159; em[529] = 0; 
    	em[530] = 159; em[531] = 8; 
    	em[532] = 576; em[533] = 16; 
    	em[534] = 631; em[535] = 24; 
    	em[536] = 682; em[537] = 32; 
    	em[538] = 718; em[539] = 40; 
    	em[540] = 735; em[541] = 48; 
    	em[542] = 762; em[543] = 56; 
    	em[544] = 797; em[545] = 64; 
    	em[546] = 805; em[547] = 72; 
    	em[548] = 808; em[549] = 80; 
    	em[550] = 811; em[551] = 88; 
    	em[552] = 814; em[553] = 96; 
    	em[554] = 817; em[555] = 104; 
    	em[556] = 817; em[557] = 112; 
    	em[558] = 817; em[559] = 120; 
    	em[560] = 820; em[561] = 128; 
    	em[562] = 823; em[563] = 136; 
    	em[564] = 823; em[565] = 144; 
    	em[566] = 826; em[567] = 152; 
    	em[568] = 829; em[569] = 160; 
    	em[570] = 841; em[571] = 184; 
    	em[572] = 863; em[573] = 200; 
    	em[574] = 863; em[575] = 208; 
    em[576] = 1; em[577] = 8; em[578] = 1; /* 576: pointer.struct.rsa_meth_st */
    	em[579] = 581; em[580] = 0; 
    em[581] = 0; em[582] = 112; em[583] = 13; /* 581: struct.rsa_meth_st */
    	em[584] = 159; em[585] = 0; 
    	em[586] = 610; em[587] = 8; 
    	em[588] = 610; em[589] = 16; 
    	em[590] = 610; em[591] = 24; 
    	em[592] = 610; em[593] = 32; 
    	em[594] = 613; em[595] = 40; 
    	em[596] = 616; em[597] = 48; 
    	em[598] = 619; em[599] = 56; 
    	em[600] = 619; em[601] = 64; 
    	em[602] = 140; em[603] = 80; 
    	em[604] = 622; em[605] = 88; 
    	em[606] = 625; em[607] = 96; 
    	em[608] = 628; em[609] = 104; 
    em[610] = 8884097; em[611] = 8; em[612] = 0; /* 610: pointer.func */
    em[613] = 8884097; em[614] = 8; em[615] = 0; /* 613: pointer.func */
    em[616] = 8884097; em[617] = 8; em[618] = 0; /* 616: pointer.func */
    em[619] = 8884097; em[620] = 8; em[621] = 0; /* 619: pointer.func */
    em[622] = 8884097; em[623] = 8; em[624] = 0; /* 622: pointer.func */
    em[625] = 8884097; em[626] = 8; em[627] = 0; /* 625: pointer.func */
    em[628] = 8884097; em[629] = 8; em[630] = 0; /* 628: pointer.func */
    em[631] = 1; em[632] = 8; em[633] = 1; /* 631: pointer.struct.dsa_method */
    	em[634] = 636; em[635] = 0; 
    em[636] = 0; em[637] = 96; em[638] = 11; /* 636: struct.dsa_method */
    	em[639] = 159; em[640] = 0; 
    	em[641] = 661; em[642] = 8; 
    	em[643] = 664; em[644] = 16; 
    	em[645] = 667; em[646] = 24; 
    	em[647] = 670; em[648] = 32; 
    	em[649] = 673; em[650] = 40; 
    	em[651] = 676; em[652] = 48; 
    	em[653] = 676; em[654] = 56; 
    	em[655] = 140; em[656] = 72; 
    	em[657] = 679; em[658] = 80; 
    	em[659] = 676; em[660] = 88; 
    em[661] = 8884097; em[662] = 8; em[663] = 0; /* 661: pointer.func */
    em[664] = 8884097; em[665] = 8; em[666] = 0; /* 664: pointer.func */
    em[667] = 8884097; em[668] = 8; em[669] = 0; /* 667: pointer.func */
    em[670] = 8884097; em[671] = 8; em[672] = 0; /* 670: pointer.func */
    em[673] = 8884097; em[674] = 8; em[675] = 0; /* 673: pointer.func */
    em[676] = 8884097; em[677] = 8; em[678] = 0; /* 676: pointer.func */
    em[679] = 8884097; em[680] = 8; em[681] = 0; /* 679: pointer.func */
    em[682] = 1; em[683] = 8; em[684] = 1; /* 682: pointer.struct.dh_method */
    	em[685] = 687; em[686] = 0; 
    em[687] = 0; em[688] = 72; em[689] = 8; /* 687: struct.dh_method */
    	em[690] = 159; em[691] = 0; 
    	em[692] = 706; em[693] = 8; 
    	em[694] = 709; em[695] = 16; 
    	em[696] = 712; em[697] = 24; 
    	em[698] = 706; em[699] = 32; 
    	em[700] = 706; em[701] = 40; 
    	em[702] = 140; em[703] = 56; 
    	em[704] = 715; em[705] = 64; 
    em[706] = 8884097; em[707] = 8; em[708] = 0; /* 706: pointer.func */
    em[709] = 8884097; em[710] = 8; em[711] = 0; /* 709: pointer.func */
    em[712] = 8884097; em[713] = 8; em[714] = 0; /* 712: pointer.func */
    em[715] = 8884097; em[716] = 8; em[717] = 0; /* 715: pointer.func */
    em[718] = 1; em[719] = 8; em[720] = 1; /* 718: pointer.struct.ecdh_method */
    	em[721] = 723; em[722] = 0; 
    em[723] = 0; em[724] = 32; em[725] = 3; /* 723: struct.ecdh_method */
    	em[726] = 159; em[727] = 0; 
    	em[728] = 732; em[729] = 8; 
    	em[730] = 140; em[731] = 24; 
    em[732] = 8884097; em[733] = 8; em[734] = 0; /* 732: pointer.func */
    em[735] = 1; em[736] = 8; em[737] = 1; /* 735: pointer.struct.ecdsa_method */
    	em[738] = 740; em[739] = 0; 
    em[740] = 0; em[741] = 48; em[742] = 5; /* 740: struct.ecdsa_method */
    	em[743] = 159; em[744] = 0; 
    	em[745] = 753; em[746] = 8; 
    	em[747] = 756; em[748] = 16; 
    	em[749] = 759; em[750] = 24; 
    	em[751] = 140; em[752] = 40; 
    em[753] = 8884097; em[754] = 8; em[755] = 0; /* 753: pointer.func */
    em[756] = 8884097; em[757] = 8; em[758] = 0; /* 756: pointer.func */
    em[759] = 8884097; em[760] = 8; em[761] = 0; /* 759: pointer.func */
    em[762] = 1; em[763] = 8; em[764] = 1; /* 762: pointer.struct.rand_meth_st */
    	em[765] = 767; em[766] = 0; 
    em[767] = 0; em[768] = 48; em[769] = 6; /* 767: struct.rand_meth_st */
    	em[770] = 782; em[771] = 0; 
    	em[772] = 785; em[773] = 8; 
    	em[774] = 788; em[775] = 16; 
    	em[776] = 791; em[777] = 24; 
    	em[778] = 785; em[779] = 32; 
    	em[780] = 794; em[781] = 40; 
    em[782] = 8884097; em[783] = 8; em[784] = 0; /* 782: pointer.func */
    em[785] = 8884097; em[786] = 8; em[787] = 0; /* 785: pointer.func */
    em[788] = 8884097; em[789] = 8; em[790] = 0; /* 788: pointer.func */
    em[791] = 8884097; em[792] = 8; em[793] = 0; /* 791: pointer.func */
    em[794] = 8884097; em[795] = 8; em[796] = 0; /* 794: pointer.func */
    em[797] = 1; em[798] = 8; em[799] = 1; /* 797: pointer.struct.store_method_st */
    	em[800] = 802; em[801] = 0; 
    em[802] = 0; em[803] = 0; em[804] = 0; /* 802: struct.store_method_st */
    em[805] = 8884097; em[806] = 8; em[807] = 0; /* 805: pointer.func */
    em[808] = 8884097; em[809] = 8; em[810] = 0; /* 808: pointer.func */
    em[811] = 8884097; em[812] = 8; em[813] = 0; /* 811: pointer.func */
    em[814] = 8884097; em[815] = 8; em[816] = 0; /* 814: pointer.func */
    em[817] = 8884097; em[818] = 8; em[819] = 0; /* 817: pointer.func */
    em[820] = 8884097; em[821] = 8; em[822] = 0; /* 820: pointer.func */
    em[823] = 8884097; em[824] = 8; em[825] = 0; /* 823: pointer.func */
    em[826] = 8884097; em[827] = 8; em[828] = 0; /* 826: pointer.func */
    em[829] = 1; em[830] = 8; em[831] = 1; /* 829: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[832] = 834; em[833] = 0; 
    em[834] = 0; em[835] = 32; em[836] = 2; /* 834: struct.ENGINE_CMD_DEFN_st */
    	em[837] = 159; em[838] = 8; 
    	em[839] = 159; em[840] = 16; 
    em[841] = 0; em[842] = 16; em[843] = 1; /* 841: struct.crypto_ex_data_st */
    	em[844] = 846; em[845] = 0; 
    em[846] = 1; em[847] = 8; em[848] = 1; /* 846: pointer.struct.stack_st_void */
    	em[849] = 851; em[850] = 0; 
    em[851] = 0; em[852] = 32; em[853] = 1; /* 851: struct.stack_st_void */
    	em[854] = 856; em[855] = 0; 
    em[856] = 0; em[857] = 32; em[858] = 2; /* 856: struct.stack_st */
    	em[859] = 473; em[860] = 8; 
    	em[861] = 363; em[862] = 24; 
    em[863] = 1; em[864] = 8; em[865] = 1; /* 863: pointer.struct.engine_st */
    	em[866] = 525; em[867] = 0; 
    em[868] = 1; em[869] = 8; em[870] = 1; /* 868: pointer.struct.bignum_st */
    	em[871] = 873; em[872] = 0; 
    em[873] = 0; em[874] = 24; em[875] = 1; /* 873: struct.bignum_st */
    	em[876] = 878; em[877] = 0; 
    em[878] = 8884099; em[879] = 8; em[880] = 2; /* 878: pointer_to_array_of_pointers_to_stack */
    	em[881] = 885; em[882] = 0; 
    	em[883] = 5; em[884] = 12; 
    em[885] = 0; em[886] = 8; em[887] = 0; /* 885: long unsigned int */
    em[888] = 0; em[889] = 16; em[890] = 1; /* 888: struct.crypto_ex_data_st */
    	em[891] = 893; em[892] = 0; 
    em[893] = 1; em[894] = 8; em[895] = 1; /* 893: pointer.struct.stack_st_void */
    	em[896] = 898; em[897] = 0; 
    em[898] = 0; em[899] = 32; em[900] = 1; /* 898: struct.stack_st_void */
    	em[901] = 903; em[902] = 0; 
    em[903] = 0; em[904] = 32; em[905] = 2; /* 903: struct.stack_st */
    	em[906] = 473; em[907] = 8; 
    	em[908] = 363; em[909] = 24; 
    em[910] = 1; em[911] = 8; em[912] = 1; /* 910: pointer.struct.bn_mont_ctx_st */
    	em[913] = 915; em[914] = 0; 
    em[915] = 0; em[916] = 96; em[917] = 3; /* 915: struct.bn_mont_ctx_st */
    	em[918] = 873; em[919] = 8; 
    	em[920] = 873; em[921] = 32; 
    	em[922] = 873; em[923] = 56; 
    em[924] = 1; em[925] = 8; em[926] = 1; /* 924: pointer.struct.bn_blinding_st */
    	em[927] = 929; em[928] = 0; 
    em[929] = 0; em[930] = 88; em[931] = 7; /* 929: struct.bn_blinding_st */
    	em[932] = 946; em[933] = 0; 
    	em[934] = 946; em[935] = 8; 
    	em[936] = 946; em[937] = 16; 
    	em[938] = 946; em[939] = 24; 
    	em[940] = 963; em[941] = 40; 
    	em[942] = 971; em[943] = 72; 
    	em[944] = 985; em[945] = 80; 
    em[946] = 1; em[947] = 8; em[948] = 1; /* 946: pointer.struct.bignum_st */
    	em[949] = 951; em[950] = 0; 
    em[951] = 0; em[952] = 24; em[953] = 1; /* 951: struct.bignum_st */
    	em[954] = 956; em[955] = 0; 
    em[956] = 8884099; em[957] = 8; em[958] = 2; /* 956: pointer_to_array_of_pointers_to_stack */
    	em[959] = 885; em[960] = 0; 
    	em[961] = 5; em[962] = 12; 
    em[963] = 0; em[964] = 16; em[965] = 1; /* 963: struct.crypto_threadid_st */
    	em[966] = 968; em[967] = 0; 
    em[968] = 0; em[969] = 8; em[970] = 0; /* 968: pointer.void */
    em[971] = 1; em[972] = 8; em[973] = 1; /* 971: pointer.struct.bn_mont_ctx_st */
    	em[974] = 976; em[975] = 0; 
    em[976] = 0; em[977] = 96; em[978] = 3; /* 976: struct.bn_mont_ctx_st */
    	em[979] = 951; em[980] = 8; 
    	em[981] = 951; em[982] = 32; 
    	em[983] = 951; em[984] = 56; 
    em[985] = 8884097; em[986] = 8; em[987] = 0; /* 985: pointer.func */
    em[988] = 0; em[989] = 8; em[990] = 5; /* 988: union.unknown */
    	em[991] = 140; em[992] = 0; 
    	em[993] = 1001; em[994] = 0; 
    	em[995] = 1006; em[996] = 0; 
    	em[997] = 1087; em[998] = 0; 
    	em[999] = 1201; em[1000] = 0; 
    em[1001] = 1; em[1002] = 8; em[1003] = 1; /* 1001: pointer.struct.rsa_st */
    	em[1004] = 478; em[1005] = 0; 
    em[1006] = 1; em[1007] = 8; em[1008] = 1; /* 1006: pointer.struct.dsa_st */
    	em[1009] = 1011; em[1010] = 0; 
    em[1011] = 0; em[1012] = 136; em[1013] = 11; /* 1011: struct.dsa_st */
    	em[1014] = 868; em[1015] = 24; 
    	em[1016] = 868; em[1017] = 32; 
    	em[1018] = 868; em[1019] = 40; 
    	em[1020] = 868; em[1021] = 48; 
    	em[1022] = 868; em[1023] = 56; 
    	em[1024] = 868; em[1025] = 64; 
    	em[1026] = 868; em[1027] = 72; 
    	em[1028] = 910; em[1029] = 88; 
    	em[1030] = 888; em[1031] = 104; 
    	em[1032] = 1036; em[1033] = 120; 
    	em[1034] = 520; em[1035] = 128; 
    em[1036] = 1; em[1037] = 8; em[1038] = 1; /* 1036: pointer.struct.dsa_method */
    	em[1039] = 1041; em[1040] = 0; 
    em[1041] = 0; em[1042] = 96; em[1043] = 11; /* 1041: struct.dsa_method */
    	em[1044] = 159; em[1045] = 0; 
    	em[1046] = 1066; em[1047] = 8; 
    	em[1048] = 1069; em[1049] = 16; 
    	em[1050] = 1072; em[1051] = 24; 
    	em[1052] = 1075; em[1053] = 32; 
    	em[1054] = 1078; em[1055] = 40; 
    	em[1056] = 1081; em[1057] = 48; 
    	em[1058] = 1081; em[1059] = 56; 
    	em[1060] = 140; em[1061] = 72; 
    	em[1062] = 1084; em[1063] = 80; 
    	em[1064] = 1081; em[1065] = 88; 
    em[1066] = 8884097; em[1067] = 8; em[1068] = 0; /* 1066: pointer.func */
    em[1069] = 8884097; em[1070] = 8; em[1071] = 0; /* 1069: pointer.func */
    em[1072] = 8884097; em[1073] = 8; em[1074] = 0; /* 1072: pointer.func */
    em[1075] = 8884097; em[1076] = 8; em[1077] = 0; /* 1075: pointer.func */
    em[1078] = 8884097; em[1079] = 8; em[1080] = 0; /* 1078: pointer.func */
    em[1081] = 8884097; em[1082] = 8; em[1083] = 0; /* 1081: pointer.func */
    em[1084] = 8884097; em[1085] = 8; em[1086] = 0; /* 1084: pointer.func */
    em[1087] = 1; em[1088] = 8; em[1089] = 1; /* 1087: pointer.struct.dh_st */
    	em[1090] = 1092; em[1091] = 0; 
    em[1092] = 0; em[1093] = 144; em[1094] = 12; /* 1092: struct.dh_st */
    	em[1095] = 1119; em[1096] = 8; 
    	em[1097] = 1119; em[1098] = 16; 
    	em[1099] = 1119; em[1100] = 32; 
    	em[1101] = 1119; em[1102] = 40; 
    	em[1103] = 1136; em[1104] = 56; 
    	em[1105] = 1119; em[1106] = 64; 
    	em[1107] = 1119; em[1108] = 72; 
    	em[1109] = 29; em[1110] = 80; 
    	em[1111] = 1119; em[1112] = 96; 
    	em[1113] = 1150; em[1114] = 112; 
    	em[1115] = 1165; em[1116] = 128; 
    	em[1117] = 520; em[1118] = 136; 
    em[1119] = 1; em[1120] = 8; em[1121] = 1; /* 1119: pointer.struct.bignum_st */
    	em[1122] = 1124; em[1123] = 0; 
    em[1124] = 0; em[1125] = 24; em[1126] = 1; /* 1124: struct.bignum_st */
    	em[1127] = 1129; em[1128] = 0; 
    em[1129] = 8884099; em[1130] = 8; em[1131] = 2; /* 1129: pointer_to_array_of_pointers_to_stack */
    	em[1132] = 885; em[1133] = 0; 
    	em[1134] = 5; em[1135] = 12; 
    em[1136] = 1; em[1137] = 8; em[1138] = 1; /* 1136: pointer.struct.bn_mont_ctx_st */
    	em[1139] = 1141; em[1140] = 0; 
    em[1141] = 0; em[1142] = 96; em[1143] = 3; /* 1141: struct.bn_mont_ctx_st */
    	em[1144] = 1124; em[1145] = 8; 
    	em[1146] = 1124; em[1147] = 32; 
    	em[1148] = 1124; em[1149] = 56; 
    em[1150] = 0; em[1151] = 16; em[1152] = 1; /* 1150: struct.crypto_ex_data_st */
    	em[1153] = 1155; em[1154] = 0; 
    em[1155] = 1; em[1156] = 8; em[1157] = 1; /* 1155: pointer.struct.stack_st_void */
    	em[1158] = 1160; em[1159] = 0; 
    em[1160] = 0; em[1161] = 32; em[1162] = 1; /* 1160: struct.stack_st_void */
    	em[1163] = 466; em[1164] = 0; 
    em[1165] = 1; em[1166] = 8; em[1167] = 1; /* 1165: pointer.struct.dh_method */
    	em[1168] = 1170; em[1169] = 0; 
    em[1170] = 0; em[1171] = 72; em[1172] = 8; /* 1170: struct.dh_method */
    	em[1173] = 159; em[1174] = 0; 
    	em[1175] = 1189; em[1176] = 8; 
    	em[1177] = 1192; em[1178] = 16; 
    	em[1179] = 1195; em[1180] = 24; 
    	em[1181] = 1189; em[1182] = 32; 
    	em[1183] = 1189; em[1184] = 40; 
    	em[1185] = 140; em[1186] = 56; 
    	em[1187] = 1198; em[1188] = 64; 
    em[1189] = 8884097; em[1190] = 8; em[1191] = 0; /* 1189: pointer.func */
    em[1192] = 8884097; em[1193] = 8; em[1194] = 0; /* 1192: pointer.func */
    em[1195] = 8884097; em[1196] = 8; em[1197] = 0; /* 1195: pointer.func */
    em[1198] = 8884097; em[1199] = 8; em[1200] = 0; /* 1198: pointer.func */
    em[1201] = 1; em[1202] = 8; em[1203] = 1; /* 1201: pointer.struct.ec_key_st */
    	em[1204] = 1206; em[1205] = 0; 
    em[1206] = 0; em[1207] = 56; em[1208] = 4; /* 1206: struct.ec_key_st */
    	em[1209] = 1217; em[1210] = 8; 
    	em[1211] = 1665; em[1212] = 16; 
    	em[1213] = 1670; em[1214] = 24; 
    	em[1215] = 1687; em[1216] = 48; 
    em[1217] = 1; em[1218] = 8; em[1219] = 1; /* 1217: pointer.struct.ec_group_st */
    	em[1220] = 1222; em[1221] = 0; 
    em[1222] = 0; em[1223] = 232; em[1224] = 12; /* 1222: struct.ec_group_st */
    	em[1225] = 1249; em[1226] = 0; 
    	em[1227] = 1421; em[1228] = 8; 
    	em[1229] = 1621; em[1230] = 16; 
    	em[1231] = 1621; em[1232] = 40; 
    	em[1233] = 29; em[1234] = 80; 
    	em[1235] = 1633; em[1236] = 96; 
    	em[1237] = 1621; em[1238] = 104; 
    	em[1239] = 1621; em[1240] = 152; 
    	em[1241] = 1621; em[1242] = 176; 
    	em[1243] = 968; em[1244] = 208; 
    	em[1245] = 968; em[1246] = 216; 
    	em[1247] = 1662; em[1248] = 224; 
    em[1249] = 1; em[1250] = 8; em[1251] = 1; /* 1249: pointer.struct.ec_method_st */
    	em[1252] = 1254; em[1253] = 0; 
    em[1254] = 0; em[1255] = 304; em[1256] = 37; /* 1254: struct.ec_method_st */
    	em[1257] = 1331; em[1258] = 8; 
    	em[1259] = 1334; em[1260] = 16; 
    	em[1261] = 1334; em[1262] = 24; 
    	em[1263] = 1337; em[1264] = 32; 
    	em[1265] = 1340; em[1266] = 40; 
    	em[1267] = 1343; em[1268] = 48; 
    	em[1269] = 1346; em[1270] = 56; 
    	em[1271] = 1349; em[1272] = 64; 
    	em[1273] = 1352; em[1274] = 72; 
    	em[1275] = 1355; em[1276] = 80; 
    	em[1277] = 1355; em[1278] = 88; 
    	em[1279] = 1358; em[1280] = 96; 
    	em[1281] = 1361; em[1282] = 104; 
    	em[1283] = 1364; em[1284] = 112; 
    	em[1285] = 1367; em[1286] = 120; 
    	em[1287] = 1370; em[1288] = 128; 
    	em[1289] = 1373; em[1290] = 136; 
    	em[1291] = 1376; em[1292] = 144; 
    	em[1293] = 1379; em[1294] = 152; 
    	em[1295] = 1382; em[1296] = 160; 
    	em[1297] = 1385; em[1298] = 168; 
    	em[1299] = 1388; em[1300] = 176; 
    	em[1301] = 1391; em[1302] = 184; 
    	em[1303] = 1394; em[1304] = 192; 
    	em[1305] = 1397; em[1306] = 200; 
    	em[1307] = 1400; em[1308] = 208; 
    	em[1309] = 1391; em[1310] = 216; 
    	em[1311] = 1403; em[1312] = 224; 
    	em[1313] = 1406; em[1314] = 232; 
    	em[1315] = 1409; em[1316] = 240; 
    	em[1317] = 1346; em[1318] = 248; 
    	em[1319] = 1412; em[1320] = 256; 
    	em[1321] = 1415; em[1322] = 264; 
    	em[1323] = 1412; em[1324] = 272; 
    	em[1325] = 1415; em[1326] = 280; 
    	em[1327] = 1415; em[1328] = 288; 
    	em[1329] = 1418; em[1330] = 296; 
    em[1331] = 8884097; em[1332] = 8; em[1333] = 0; /* 1331: pointer.func */
    em[1334] = 8884097; em[1335] = 8; em[1336] = 0; /* 1334: pointer.func */
    em[1337] = 8884097; em[1338] = 8; em[1339] = 0; /* 1337: pointer.func */
    em[1340] = 8884097; em[1341] = 8; em[1342] = 0; /* 1340: pointer.func */
    em[1343] = 8884097; em[1344] = 8; em[1345] = 0; /* 1343: pointer.func */
    em[1346] = 8884097; em[1347] = 8; em[1348] = 0; /* 1346: pointer.func */
    em[1349] = 8884097; em[1350] = 8; em[1351] = 0; /* 1349: pointer.func */
    em[1352] = 8884097; em[1353] = 8; em[1354] = 0; /* 1352: pointer.func */
    em[1355] = 8884097; em[1356] = 8; em[1357] = 0; /* 1355: pointer.func */
    em[1358] = 8884097; em[1359] = 8; em[1360] = 0; /* 1358: pointer.func */
    em[1361] = 8884097; em[1362] = 8; em[1363] = 0; /* 1361: pointer.func */
    em[1364] = 8884097; em[1365] = 8; em[1366] = 0; /* 1364: pointer.func */
    em[1367] = 8884097; em[1368] = 8; em[1369] = 0; /* 1367: pointer.func */
    em[1370] = 8884097; em[1371] = 8; em[1372] = 0; /* 1370: pointer.func */
    em[1373] = 8884097; em[1374] = 8; em[1375] = 0; /* 1373: pointer.func */
    em[1376] = 8884097; em[1377] = 8; em[1378] = 0; /* 1376: pointer.func */
    em[1379] = 8884097; em[1380] = 8; em[1381] = 0; /* 1379: pointer.func */
    em[1382] = 8884097; em[1383] = 8; em[1384] = 0; /* 1382: pointer.func */
    em[1385] = 8884097; em[1386] = 8; em[1387] = 0; /* 1385: pointer.func */
    em[1388] = 8884097; em[1389] = 8; em[1390] = 0; /* 1388: pointer.func */
    em[1391] = 8884097; em[1392] = 8; em[1393] = 0; /* 1391: pointer.func */
    em[1394] = 8884097; em[1395] = 8; em[1396] = 0; /* 1394: pointer.func */
    em[1397] = 8884097; em[1398] = 8; em[1399] = 0; /* 1397: pointer.func */
    em[1400] = 8884097; em[1401] = 8; em[1402] = 0; /* 1400: pointer.func */
    em[1403] = 8884097; em[1404] = 8; em[1405] = 0; /* 1403: pointer.func */
    em[1406] = 8884097; em[1407] = 8; em[1408] = 0; /* 1406: pointer.func */
    em[1409] = 8884097; em[1410] = 8; em[1411] = 0; /* 1409: pointer.func */
    em[1412] = 8884097; em[1413] = 8; em[1414] = 0; /* 1412: pointer.func */
    em[1415] = 8884097; em[1416] = 8; em[1417] = 0; /* 1415: pointer.func */
    em[1418] = 8884097; em[1419] = 8; em[1420] = 0; /* 1418: pointer.func */
    em[1421] = 1; em[1422] = 8; em[1423] = 1; /* 1421: pointer.struct.ec_point_st */
    	em[1424] = 1426; em[1425] = 0; 
    em[1426] = 0; em[1427] = 88; em[1428] = 4; /* 1426: struct.ec_point_st */
    	em[1429] = 1437; em[1430] = 0; 
    	em[1431] = 1609; em[1432] = 8; 
    	em[1433] = 1609; em[1434] = 32; 
    	em[1435] = 1609; em[1436] = 56; 
    em[1437] = 1; em[1438] = 8; em[1439] = 1; /* 1437: pointer.struct.ec_method_st */
    	em[1440] = 1442; em[1441] = 0; 
    em[1442] = 0; em[1443] = 304; em[1444] = 37; /* 1442: struct.ec_method_st */
    	em[1445] = 1519; em[1446] = 8; 
    	em[1447] = 1522; em[1448] = 16; 
    	em[1449] = 1522; em[1450] = 24; 
    	em[1451] = 1525; em[1452] = 32; 
    	em[1453] = 1528; em[1454] = 40; 
    	em[1455] = 1531; em[1456] = 48; 
    	em[1457] = 1534; em[1458] = 56; 
    	em[1459] = 1537; em[1460] = 64; 
    	em[1461] = 1540; em[1462] = 72; 
    	em[1463] = 1543; em[1464] = 80; 
    	em[1465] = 1543; em[1466] = 88; 
    	em[1467] = 1546; em[1468] = 96; 
    	em[1469] = 1549; em[1470] = 104; 
    	em[1471] = 1552; em[1472] = 112; 
    	em[1473] = 1555; em[1474] = 120; 
    	em[1475] = 1558; em[1476] = 128; 
    	em[1477] = 1561; em[1478] = 136; 
    	em[1479] = 1564; em[1480] = 144; 
    	em[1481] = 1567; em[1482] = 152; 
    	em[1483] = 1570; em[1484] = 160; 
    	em[1485] = 1573; em[1486] = 168; 
    	em[1487] = 1576; em[1488] = 176; 
    	em[1489] = 1579; em[1490] = 184; 
    	em[1491] = 1582; em[1492] = 192; 
    	em[1493] = 1585; em[1494] = 200; 
    	em[1495] = 1588; em[1496] = 208; 
    	em[1497] = 1579; em[1498] = 216; 
    	em[1499] = 1591; em[1500] = 224; 
    	em[1501] = 1594; em[1502] = 232; 
    	em[1503] = 1597; em[1504] = 240; 
    	em[1505] = 1534; em[1506] = 248; 
    	em[1507] = 1600; em[1508] = 256; 
    	em[1509] = 1603; em[1510] = 264; 
    	em[1511] = 1600; em[1512] = 272; 
    	em[1513] = 1603; em[1514] = 280; 
    	em[1515] = 1603; em[1516] = 288; 
    	em[1517] = 1606; em[1518] = 296; 
    em[1519] = 8884097; em[1520] = 8; em[1521] = 0; /* 1519: pointer.func */
    em[1522] = 8884097; em[1523] = 8; em[1524] = 0; /* 1522: pointer.func */
    em[1525] = 8884097; em[1526] = 8; em[1527] = 0; /* 1525: pointer.func */
    em[1528] = 8884097; em[1529] = 8; em[1530] = 0; /* 1528: pointer.func */
    em[1531] = 8884097; em[1532] = 8; em[1533] = 0; /* 1531: pointer.func */
    em[1534] = 8884097; em[1535] = 8; em[1536] = 0; /* 1534: pointer.func */
    em[1537] = 8884097; em[1538] = 8; em[1539] = 0; /* 1537: pointer.func */
    em[1540] = 8884097; em[1541] = 8; em[1542] = 0; /* 1540: pointer.func */
    em[1543] = 8884097; em[1544] = 8; em[1545] = 0; /* 1543: pointer.func */
    em[1546] = 8884097; em[1547] = 8; em[1548] = 0; /* 1546: pointer.func */
    em[1549] = 8884097; em[1550] = 8; em[1551] = 0; /* 1549: pointer.func */
    em[1552] = 8884097; em[1553] = 8; em[1554] = 0; /* 1552: pointer.func */
    em[1555] = 8884097; em[1556] = 8; em[1557] = 0; /* 1555: pointer.func */
    em[1558] = 8884097; em[1559] = 8; em[1560] = 0; /* 1558: pointer.func */
    em[1561] = 8884097; em[1562] = 8; em[1563] = 0; /* 1561: pointer.func */
    em[1564] = 8884097; em[1565] = 8; em[1566] = 0; /* 1564: pointer.func */
    em[1567] = 8884097; em[1568] = 8; em[1569] = 0; /* 1567: pointer.func */
    em[1570] = 8884097; em[1571] = 8; em[1572] = 0; /* 1570: pointer.func */
    em[1573] = 8884097; em[1574] = 8; em[1575] = 0; /* 1573: pointer.func */
    em[1576] = 8884097; em[1577] = 8; em[1578] = 0; /* 1576: pointer.func */
    em[1579] = 8884097; em[1580] = 8; em[1581] = 0; /* 1579: pointer.func */
    em[1582] = 8884097; em[1583] = 8; em[1584] = 0; /* 1582: pointer.func */
    em[1585] = 8884097; em[1586] = 8; em[1587] = 0; /* 1585: pointer.func */
    em[1588] = 8884097; em[1589] = 8; em[1590] = 0; /* 1588: pointer.func */
    em[1591] = 8884097; em[1592] = 8; em[1593] = 0; /* 1591: pointer.func */
    em[1594] = 8884097; em[1595] = 8; em[1596] = 0; /* 1594: pointer.func */
    em[1597] = 8884097; em[1598] = 8; em[1599] = 0; /* 1597: pointer.func */
    em[1600] = 8884097; em[1601] = 8; em[1602] = 0; /* 1600: pointer.func */
    em[1603] = 8884097; em[1604] = 8; em[1605] = 0; /* 1603: pointer.func */
    em[1606] = 8884097; em[1607] = 8; em[1608] = 0; /* 1606: pointer.func */
    em[1609] = 0; em[1610] = 24; em[1611] = 1; /* 1609: struct.bignum_st */
    	em[1612] = 1614; em[1613] = 0; 
    em[1614] = 8884099; em[1615] = 8; em[1616] = 2; /* 1614: pointer_to_array_of_pointers_to_stack */
    	em[1617] = 885; em[1618] = 0; 
    	em[1619] = 5; em[1620] = 12; 
    em[1621] = 0; em[1622] = 24; em[1623] = 1; /* 1621: struct.bignum_st */
    	em[1624] = 1626; em[1625] = 0; 
    em[1626] = 8884099; em[1627] = 8; em[1628] = 2; /* 1626: pointer_to_array_of_pointers_to_stack */
    	em[1629] = 885; em[1630] = 0; 
    	em[1631] = 5; em[1632] = 12; 
    em[1633] = 1; em[1634] = 8; em[1635] = 1; /* 1633: pointer.struct.ec_extra_data_st */
    	em[1636] = 1638; em[1637] = 0; 
    em[1638] = 0; em[1639] = 40; em[1640] = 5; /* 1638: struct.ec_extra_data_st */
    	em[1641] = 1651; em[1642] = 0; 
    	em[1643] = 968; em[1644] = 8; 
    	em[1645] = 1656; em[1646] = 16; 
    	em[1647] = 1659; em[1648] = 24; 
    	em[1649] = 1659; em[1650] = 32; 
    em[1651] = 1; em[1652] = 8; em[1653] = 1; /* 1651: pointer.struct.ec_extra_data_st */
    	em[1654] = 1638; em[1655] = 0; 
    em[1656] = 8884097; em[1657] = 8; em[1658] = 0; /* 1656: pointer.func */
    em[1659] = 8884097; em[1660] = 8; em[1661] = 0; /* 1659: pointer.func */
    em[1662] = 8884097; em[1663] = 8; em[1664] = 0; /* 1662: pointer.func */
    em[1665] = 1; em[1666] = 8; em[1667] = 1; /* 1665: pointer.struct.ec_point_st */
    	em[1668] = 1426; em[1669] = 0; 
    em[1670] = 1; em[1671] = 8; em[1672] = 1; /* 1670: pointer.struct.bignum_st */
    	em[1673] = 1675; em[1674] = 0; 
    em[1675] = 0; em[1676] = 24; em[1677] = 1; /* 1675: struct.bignum_st */
    	em[1678] = 1680; em[1679] = 0; 
    em[1680] = 8884099; em[1681] = 8; em[1682] = 2; /* 1680: pointer_to_array_of_pointers_to_stack */
    	em[1683] = 885; em[1684] = 0; 
    	em[1685] = 5; em[1686] = 12; 
    em[1687] = 1; em[1688] = 8; em[1689] = 1; /* 1687: pointer.struct.ec_extra_data_st */
    	em[1690] = 1692; em[1691] = 0; 
    em[1692] = 0; em[1693] = 40; em[1694] = 5; /* 1692: struct.ec_extra_data_st */
    	em[1695] = 1705; em[1696] = 0; 
    	em[1697] = 968; em[1698] = 8; 
    	em[1699] = 1656; em[1700] = 16; 
    	em[1701] = 1659; em[1702] = 24; 
    	em[1703] = 1659; em[1704] = 32; 
    em[1705] = 1; em[1706] = 8; em[1707] = 1; /* 1705: pointer.struct.ec_extra_data_st */
    	em[1708] = 1692; em[1709] = 0; 
    em[1710] = 8884097; em[1711] = 8; em[1712] = 0; /* 1710: pointer.func */
    em[1713] = 8884097; em[1714] = 8; em[1715] = 0; /* 1713: pointer.func */
    em[1716] = 8884097; em[1717] = 8; em[1718] = 0; /* 1716: pointer.func */
    em[1719] = 8884097; em[1720] = 8; em[1721] = 0; /* 1719: pointer.func */
    em[1722] = 8884097; em[1723] = 8; em[1724] = 0; /* 1722: pointer.func */
    em[1725] = 0; em[1726] = 208; em[1727] = 24; /* 1725: struct.evp_pkey_asn1_method_st */
    	em[1728] = 140; em[1729] = 16; 
    	em[1730] = 140; em[1731] = 24; 
    	em[1732] = 1776; em[1733] = 32; 
    	em[1734] = 1779; em[1735] = 40; 
    	em[1736] = 1782; em[1737] = 48; 
    	em[1738] = 1785; em[1739] = 56; 
    	em[1740] = 1788; em[1741] = 64; 
    	em[1742] = 1791; em[1743] = 72; 
    	em[1744] = 1785; em[1745] = 80; 
    	em[1746] = 1719; em[1747] = 88; 
    	em[1748] = 1719; em[1749] = 96; 
    	em[1750] = 1794; em[1751] = 104; 
    	em[1752] = 1797; em[1753] = 112; 
    	em[1754] = 1719; em[1755] = 120; 
    	em[1756] = 1722; em[1757] = 128; 
    	em[1758] = 1782; em[1759] = 136; 
    	em[1760] = 1785; em[1761] = 144; 
    	em[1762] = 1800; em[1763] = 152; 
    	em[1764] = 1803; em[1765] = 160; 
    	em[1766] = 1716; em[1767] = 168; 
    	em[1768] = 1794; em[1769] = 176; 
    	em[1770] = 1797; em[1771] = 184; 
    	em[1772] = 1806; em[1773] = 192; 
    	em[1774] = 1710; em[1775] = 200; 
    em[1776] = 8884097; em[1777] = 8; em[1778] = 0; /* 1776: pointer.func */
    em[1779] = 8884097; em[1780] = 8; em[1781] = 0; /* 1779: pointer.func */
    em[1782] = 8884097; em[1783] = 8; em[1784] = 0; /* 1782: pointer.func */
    em[1785] = 8884097; em[1786] = 8; em[1787] = 0; /* 1785: pointer.func */
    em[1788] = 8884097; em[1789] = 8; em[1790] = 0; /* 1788: pointer.func */
    em[1791] = 8884097; em[1792] = 8; em[1793] = 0; /* 1791: pointer.func */
    em[1794] = 8884097; em[1795] = 8; em[1796] = 0; /* 1794: pointer.func */
    em[1797] = 8884097; em[1798] = 8; em[1799] = 0; /* 1797: pointer.func */
    em[1800] = 8884097; em[1801] = 8; em[1802] = 0; /* 1800: pointer.func */
    em[1803] = 8884097; em[1804] = 8; em[1805] = 0; /* 1803: pointer.func */
    em[1806] = 8884097; em[1807] = 8; em[1808] = 0; /* 1806: pointer.func */
    em[1809] = 8884097; em[1810] = 8; em[1811] = 0; /* 1809: pointer.func */
    em[1812] = 0; em[1813] = 56; em[1814] = 4; /* 1812: struct.evp_pkey_st */
    	em[1815] = 1823; em[1816] = 16; 
    	em[1817] = 1828; em[1818] = 24; 
    	em[1819] = 988; em[1820] = 32; 
    	em[1821] = 380; em[1822] = 48; 
    em[1823] = 1; em[1824] = 8; em[1825] = 1; /* 1823: pointer.struct.evp_pkey_asn1_method_st */
    	em[1826] = 1725; em[1827] = 0; 
    em[1828] = 1; em[1829] = 8; em[1830] = 1; /* 1828: pointer.struct.engine_st */
    	em[1831] = 525; em[1832] = 0; 
    em[1833] = 1; em[1834] = 8; em[1835] = 1; /* 1833: pointer.struct.engine_st */
    	em[1836] = 525; em[1837] = 0; 
    em[1838] = 8884097; em[1839] = 8; em[1840] = 0; /* 1838: pointer.func */
    em[1841] = 8884097; em[1842] = 8; em[1843] = 0; /* 1841: pointer.func */
    em[1844] = 8884097; em[1845] = 8; em[1846] = 0; /* 1844: pointer.func */
    em[1847] = 8884097; em[1848] = 8; em[1849] = 0; /* 1847: pointer.func */
    em[1850] = 8884097; em[1851] = 8; em[1852] = 0; /* 1850: pointer.func */
    em[1853] = 0; em[1854] = 208; em[1855] = 25; /* 1853: struct.evp_pkey_method_st */
    	em[1856] = 1906; em[1857] = 8; 
    	em[1858] = 1909; em[1859] = 16; 
    	em[1860] = 1850; em[1861] = 24; 
    	em[1862] = 1906; em[1863] = 32; 
    	em[1864] = 1912; em[1865] = 40; 
    	em[1866] = 1906; em[1867] = 48; 
    	em[1868] = 1912; em[1869] = 56; 
    	em[1870] = 1906; em[1871] = 64; 
    	em[1872] = 1847; em[1873] = 72; 
    	em[1874] = 1906; em[1875] = 80; 
    	em[1876] = 1915; em[1877] = 88; 
    	em[1878] = 1906; em[1879] = 96; 
    	em[1880] = 1847; em[1881] = 104; 
    	em[1882] = 1844; em[1883] = 112; 
    	em[1884] = 1841; em[1885] = 120; 
    	em[1886] = 1844; em[1887] = 128; 
    	em[1888] = 1838; em[1889] = 136; 
    	em[1890] = 1906; em[1891] = 144; 
    	em[1892] = 1847; em[1893] = 152; 
    	em[1894] = 1906; em[1895] = 160; 
    	em[1896] = 1847; em[1897] = 168; 
    	em[1898] = 1906; em[1899] = 176; 
    	em[1900] = 1918; em[1901] = 184; 
    	em[1902] = 1921; em[1903] = 192; 
    	em[1904] = 1924; em[1905] = 200; 
    em[1906] = 8884097; em[1907] = 8; em[1908] = 0; /* 1906: pointer.func */
    em[1909] = 8884097; em[1910] = 8; em[1911] = 0; /* 1909: pointer.func */
    em[1912] = 8884097; em[1913] = 8; em[1914] = 0; /* 1912: pointer.func */
    em[1915] = 8884097; em[1916] = 8; em[1917] = 0; /* 1915: pointer.func */
    em[1918] = 8884097; em[1919] = 8; em[1920] = 0; /* 1918: pointer.func */
    em[1921] = 8884097; em[1922] = 8; em[1923] = 0; /* 1921: pointer.func */
    em[1924] = 8884097; em[1925] = 8; em[1926] = 0; /* 1924: pointer.func */
    em[1927] = 0; em[1928] = 288; em[1929] = 4; /* 1927: struct.hmac_ctx_st */
    	em[1930] = 1938; em[1931] = 0; 
    	em[1932] = 1977; em[1933] = 8; 
    	em[1934] = 1977; em[1935] = 56; 
    	em[1936] = 1977; em[1937] = 104; 
    em[1938] = 1; em[1939] = 8; em[1940] = 1; /* 1938: pointer.struct.env_md_st */
    	em[1941] = 1943; em[1942] = 0; 
    em[1943] = 0; em[1944] = 120; em[1945] = 8; /* 1943: struct.env_md_st */
    	em[1946] = 1962; em[1947] = 24; 
    	em[1948] = 1965; em[1949] = 32; 
    	em[1950] = 1968; em[1951] = 40; 
    	em[1952] = 1971; em[1953] = 48; 
    	em[1954] = 1962; em[1955] = 56; 
    	em[1956] = 1974; em[1957] = 64; 
    	em[1958] = 1809; em[1959] = 72; 
    	em[1960] = 1713; em[1961] = 112; 
    em[1962] = 8884097; em[1963] = 8; em[1964] = 0; /* 1962: pointer.func */
    em[1965] = 8884097; em[1966] = 8; em[1967] = 0; /* 1965: pointer.func */
    em[1968] = 8884097; em[1969] = 8; em[1970] = 0; /* 1968: pointer.func */
    em[1971] = 8884097; em[1972] = 8; em[1973] = 0; /* 1971: pointer.func */
    em[1974] = 8884097; em[1975] = 8; em[1976] = 0; /* 1974: pointer.func */
    em[1977] = 0; em[1978] = 48; em[1979] = 5; /* 1977: struct.env_md_ctx_st */
    	em[1980] = 1938; em[1981] = 0; 
    	em[1982] = 1833; em[1983] = 8; 
    	em[1984] = 968; em[1985] = 24; 
    	em[1986] = 1990; em[1987] = 32; 
    	em[1988] = 1965; em[1989] = 40; 
    em[1990] = 1; em[1991] = 8; em[1992] = 1; /* 1990: pointer.struct.evp_pkey_ctx_st */
    	em[1993] = 1995; em[1994] = 0; 
    em[1995] = 0; em[1996] = 80; em[1997] = 8; /* 1995: struct.evp_pkey_ctx_st */
    	em[1998] = 2014; em[1999] = 0; 
    	em[2000] = 1828; em[2001] = 8; 
    	em[2002] = 2019; em[2003] = 16; 
    	em[2004] = 2019; em[2005] = 24; 
    	em[2006] = 968; em[2007] = 40; 
    	em[2008] = 968; em[2009] = 48; 
    	em[2010] = 8; em[2011] = 56; 
    	em[2012] = 0; em[2013] = 64; 
    em[2014] = 1; em[2015] = 8; em[2016] = 1; /* 2014: pointer.struct.evp_pkey_method_st */
    	em[2017] = 1853; em[2018] = 0; 
    em[2019] = 1; em[2020] = 8; em[2021] = 1; /* 2019: pointer.struct.evp_pkey_st */
    	em[2022] = 1812; em[2023] = 0; 
    em[2024] = 0; em[2025] = 1; em[2026] = 0; /* 2024: char */
    em[2027] = 1; em[2028] = 8; em[2029] = 1; /* 2027: pointer.struct.hmac_ctx_st */
    	em[2030] = 1927; em[2031] = 0; 
    args_addr->arg_entity_index[0] = 2027;
    args_addr->arg_entity_index[1] = 968;
    args_addr->arg_entity_index[2] = 5;
    args_addr->arg_entity_index[3] = 1938;
    args_addr->arg_entity_index[4] = 1833;
    args_addr->ret_entity_index = 5;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_arg(args_addr, arg_e);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    HMAC_CTX * new_arg_a = *((HMAC_CTX * *)new_args->args[0]);

    const void * new_arg_b = *((const void * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    const EVP_MD * new_arg_d = *((const EVP_MD * *)new_args->args[3]);

    ENGINE * new_arg_e = *((ENGINE * *)new_args->args[4]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
    orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
    *new_ret_ptr = (*orig_HMAC_Init_ex)(new_arg_a,new_arg_b,new_arg_c,new_arg_d,new_arg_e);

    syscall(889);

    free(args_addr);

    return ret;
}

