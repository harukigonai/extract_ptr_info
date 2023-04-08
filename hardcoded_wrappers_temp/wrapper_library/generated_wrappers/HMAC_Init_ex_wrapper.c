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
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 1; em[4] = 8; em[5] = 1; /* 3: pointer.struct.ASN1_VALUE_st */
    	em[6] = 8; em[7] = 0; 
    em[8] = 0; em[9] = 0; em[10] = 0; /* 8: struct.ASN1_VALUE_st */
    em[11] = 1; em[12] = 8; em[13] = 1; /* 11: pointer.struct.asn1_string_st */
    	em[14] = 16; em[15] = 0; 
    em[16] = 0; em[17] = 24; em[18] = 1; /* 16: struct.asn1_string_st */
    	em[19] = 21; em[20] = 8; 
    em[21] = 1; em[22] = 8; em[23] = 1; /* 21: pointer.unsigned char */
    	em[24] = 26; em[25] = 0; 
    em[26] = 0; em[27] = 1; em[28] = 0; /* 26: unsigned char */
    em[29] = 1; em[30] = 8; em[31] = 1; /* 29: pointer.struct.asn1_string_st */
    	em[32] = 16; em[33] = 0; 
    em[34] = 1; em[35] = 8; em[36] = 1; /* 34: pointer.struct.asn1_string_st */
    	em[37] = 16; em[38] = 0; 
    em[39] = 1; em[40] = 8; em[41] = 1; /* 39: pointer.struct.asn1_string_st */
    	em[42] = 16; em[43] = 0; 
    em[44] = 1; em[45] = 8; em[46] = 1; /* 44: pointer.struct.asn1_string_st */
    	em[47] = 16; em[48] = 0; 
    em[49] = 1; em[50] = 8; em[51] = 1; /* 49: pointer.struct.asn1_string_st */
    	em[52] = 16; em[53] = 0; 
    em[54] = 1; em[55] = 8; em[56] = 1; /* 54: pointer.struct.asn1_string_st */
    	em[57] = 16; em[58] = 0; 
    em[59] = 1; em[60] = 8; em[61] = 1; /* 59: pointer.struct.asn1_string_st */
    	em[62] = 16; em[63] = 0; 
    em[64] = 1; em[65] = 8; em[66] = 1; /* 64: pointer.struct.asn1_string_st */
    	em[67] = 16; em[68] = 0; 
    em[69] = 1; em[70] = 8; em[71] = 1; /* 69: pointer.struct.asn1_string_st */
    	em[72] = 16; em[73] = 0; 
    em[74] = 0; em[75] = 16; em[76] = 1; /* 74: struct.asn1_type_st */
    	em[77] = 79; em[78] = 8; 
    em[79] = 0; em[80] = 8; em[81] = 20; /* 79: union.unknown */
    	em[82] = 122; em[83] = 0; 
    	em[84] = 69; em[85] = 0; 
    	em[86] = 127; em[87] = 0; 
    	em[88] = 64; em[89] = 0; 
    	em[90] = 59; em[91] = 0; 
    	em[92] = 54; em[93] = 0; 
    	em[94] = 49; em[95] = 0; 
    	em[96] = 151; em[97] = 0; 
    	em[98] = 44; em[99] = 0; 
    	em[100] = 39; em[101] = 0; 
    	em[102] = 34; em[103] = 0; 
    	em[104] = 29; em[105] = 0; 
    	em[106] = 156; em[107] = 0; 
    	em[108] = 161; em[109] = 0; 
    	em[110] = 166; em[111] = 0; 
    	em[112] = 171; em[113] = 0; 
    	em[114] = 11; em[115] = 0; 
    	em[116] = 69; em[117] = 0; 
    	em[118] = 69; em[119] = 0; 
    	em[120] = 3; em[121] = 0; 
    em[122] = 1; em[123] = 8; em[124] = 1; /* 122: pointer.char */
    	em[125] = 8884096; em[126] = 0; 
    em[127] = 1; em[128] = 8; em[129] = 1; /* 127: pointer.struct.asn1_object_st */
    	em[130] = 132; em[131] = 0; 
    em[132] = 0; em[133] = 40; em[134] = 3; /* 132: struct.asn1_object_st */
    	em[135] = 141; em[136] = 0; 
    	em[137] = 141; em[138] = 8; 
    	em[139] = 146; em[140] = 24; 
    em[141] = 1; em[142] = 8; em[143] = 1; /* 141: pointer.char */
    	em[144] = 8884096; em[145] = 0; 
    em[146] = 1; em[147] = 8; em[148] = 1; /* 146: pointer.unsigned char */
    	em[149] = 26; em[150] = 0; 
    em[151] = 1; em[152] = 8; em[153] = 1; /* 151: pointer.struct.asn1_string_st */
    	em[154] = 16; em[155] = 0; 
    em[156] = 1; em[157] = 8; em[158] = 1; /* 156: pointer.struct.asn1_string_st */
    	em[159] = 16; em[160] = 0; 
    em[161] = 1; em[162] = 8; em[163] = 1; /* 161: pointer.struct.asn1_string_st */
    	em[164] = 16; em[165] = 0; 
    em[166] = 1; em[167] = 8; em[168] = 1; /* 166: pointer.struct.asn1_string_st */
    	em[169] = 16; em[170] = 0; 
    em[171] = 1; em[172] = 8; em[173] = 1; /* 171: pointer.struct.asn1_string_st */
    	em[174] = 16; em[175] = 0; 
    em[176] = 1; em[177] = 8; em[178] = 1; /* 176: pointer.struct.asn1_string_st */
    	em[179] = 181; em[180] = 0; 
    em[181] = 0; em[182] = 24; em[183] = 1; /* 181: struct.asn1_string_st */
    	em[184] = 21; em[185] = 8; 
    em[186] = 1; em[187] = 8; em[188] = 1; /* 186: pointer.struct.asn1_string_st */
    	em[189] = 181; em[190] = 0; 
    em[191] = 1; em[192] = 8; em[193] = 1; /* 191: pointer.struct.asn1_string_st */
    	em[194] = 181; em[195] = 0; 
    em[196] = 1; em[197] = 8; em[198] = 1; /* 196: pointer.struct.asn1_string_st */
    	em[199] = 181; em[200] = 0; 
    em[201] = 1; em[202] = 8; em[203] = 1; /* 201: pointer.struct.asn1_string_st */
    	em[204] = 181; em[205] = 0; 
    em[206] = 1; em[207] = 8; em[208] = 1; /* 206: pointer.struct.asn1_string_st */
    	em[209] = 181; em[210] = 0; 
    em[211] = 1; em[212] = 8; em[213] = 1; /* 211: pointer.struct.asn1_string_st */
    	em[214] = 181; em[215] = 0; 
    em[216] = 1; em[217] = 8; em[218] = 1; /* 216: pointer.struct.asn1_string_st */
    	em[219] = 181; em[220] = 0; 
    em[221] = 1; em[222] = 8; em[223] = 1; /* 221: pointer.struct.asn1_string_st */
    	em[224] = 181; em[225] = 0; 
    em[226] = 0; em[227] = 40; em[228] = 3; /* 226: struct.asn1_object_st */
    	em[229] = 141; em[230] = 0; 
    	em[231] = 141; em[232] = 8; 
    	em[233] = 146; em[234] = 24; 
    em[235] = 1; em[236] = 8; em[237] = 1; /* 235: pointer.struct.asn1_string_st */
    	em[238] = 181; em[239] = 0; 
    em[240] = 0; em[241] = 8; em[242] = 20; /* 240: union.unknown */
    	em[243] = 122; em[244] = 0; 
    	em[245] = 235; em[246] = 0; 
    	em[247] = 283; em[248] = 0; 
    	em[249] = 221; em[250] = 0; 
    	em[251] = 216; em[252] = 0; 
    	em[253] = 211; em[254] = 0; 
    	em[255] = 206; em[256] = 0; 
    	em[257] = 288; em[258] = 0; 
    	em[259] = 293; em[260] = 0; 
    	em[261] = 201; em[262] = 0; 
    	em[263] = 196; em[264] = 0; 
    	em[265] = 191; em[266] = 0; 
    	em[267] = 298; em[268] = 0; 
    	em[269] = 303; em[270] = 0; 
    	em[271] = 186; em[272] = 0; 
    	em[273] = 308; em[274] = 0; 
    	em[275] = 176; em[276] = 0; 
    	em[277] = 235; em[278] = 0; 
    	em[279] = 235; em[280] = 0; 
    	em[281] = 313; em[282] = 0; 
    em[283] = 1; em[284] = 8; em[285] = 1; /* 283: pointer.struct.asn1_object_st */
    	em[286] = 226; em[287] = 0; 
    em[288] = 1; em[289] = 8; em[290] = 1; /* 288: pointer.struct.asn1_string_st */
    	em[291] = 181; em[292] = 0; 
    em[293] = 1; em[294] = 8; em[295] = 1; /* 293: pointer.struct.asn1_string_st */
    	em[296] = 181; em[297] = 0; 
    em[298] = 1; em[299] = 8; em[300] = 1; /* 298: pointer.struct.asn1_string_st */
    	em[301] = 181; em[302] = 0; 
    em[303] = 1; em[304] = 8; em[305] = 1; /* 303: pointer.struct.asn1_string_st */
    	em[306] = 181; em[307] = 0; 
    em[308] = 1; em[309] = 8; em[310] = 1; /* 308: pointer.struct.asn1_string_st */
    	em[311] = 181; em[312] = 0; 
    em[313] = 1; em[314] = 8; em[315] = 1; /* 313: pointer.struct.ASN1_VALUE_st */
    	em[316] = 318; em[317] = 0; 
    em[318] = 0; em[319] = 0; em[320] = 0; /* 318: struct.ASN1_VALUE_st */
    em[321] = 0; em[322] = 16; em[323] = 1; /* 321: struct.asn1_type_st */
    	em[324] = 240; em[325] = 8; 
    em[326] = 1; em[327] = 8; em[328] = 1; /* 326: pointer.struct.stack_st_ASN1_TYPE */
    	em[329] = 331; em[330] = 0; 
    em[331] = 0; em[332] = 32; em[333] = 2; /* 331: struct.stack_st_fake_ASN1_TYPE */
    	em[334] = 338; em[335] = 8; 
    	em[336] = 358; em[337] = 24; 
    em[338] = 8884099; em[339] = 8; em[340] = 2; /* 338: pointer_to_array_of_pointers_to_stack */
    	em[341] = 345; em[342] = 0; 
    	em[343] = 355; em[344] = 20; 
    em[345] = 0; em[346] = 8; em[347] = 1; /* 345: pointer.ASN1_TYPE */
    	em[348] = 350; em[349] = 0; 
    em[350] = 0; em[351] = 0; em[352] = 1; /* 350: ASN1_TYPE */
    	em[353] = 321; em[354] = 0; 
    em[355] = 0; em[356] = 4; em[357] = 0; /* 355: int */
    em[358] = 8884097; em[359] = 8; em[360] = 0; /* 358: pointer.func */
    em[361] = 0; em[362] = 8; em[363] = 3; /* 361: union.unknown */
    	em[364] = 122; em[365] = 0; 
    	em[366] = 326; em[367] = 0; 
    	em[368] = 370; em[369] = 0; 
    em[370] = 1; em[371] = 8; em[372] = 1; /* 370: pointer.struct.asn1_type_st */
    	em[373] = 74; em[374] = 0; 
    em[375] = 8884097; em[376] = 8; em[377] = 0; /* 375: pointer.func */
    em[378] = 8884097; em[379] = 8; em[380] = 0; /* 378: pointer.func */
    em[381] = 8884097; em[382] = 8; em[383] = 0; /* 381: pointer.func */
    em[384] = 1; em[385] = 8; em[386] = 1; /* 384: pointer.struct.bignum_st */
    	em[387] = 389; em[388] = 0; 
    em[389] = 0; em[390] = 24; em[391] = 1; /* 389: struct.bignum_st */
    	em[392] = 394; em[393] = 0; 
    em[394] = 8884099; em[395] = 8; em[396] = 2; /* 394: pointer_to_array_of_pointers_to_stack */
    	em[397] = 401; em[398] = 0; 
    	em[399] = 355; em[400] = 12; 
    em[401] = 0; em[402] = 8; em[403] = 0; /* 401: long unsigned int */
    em[404] = 8884097; em[405] = 8; em[406] = 0; /* 404: pointer.func */
    em[407] = 8884097; em[408] = 8; em[409] = 0; /* 407: pointer.func */
    em[410] = 0; em[411] = 8; em[412] = 0; /* 410: pointer.void */
    em[413] = 0; em[414] = 168; em[415] = 17; /* 413: struct.rsa_st */
    	em[416] = 450; em[417] = 16; 
    	em[418] = 499; em[419] = 24; 
    	em[420] = 384; em[421] = 32; 
    	em[422] = 384; em[423] = 40; 
    	em[424] = 384; em[425] = 48; 
    	em[426] = 384; em[427] = 56; 
    	em[428] = 384; em[429] = 64; 
    	em[430] = 384; em[431] = 72; 
    	em[432] = 384; em[433] = 80; 
    	em[434] = 384; em[435] = 88; 
    	em[436] = 839; em[437] = 96; 
    	em[438] = 853; em[439] = 120; 
    	em[440] = 853; em[441] = 128; 
    	em[442] = 853; em[443] = 136; 
    	em[444] = 122; em[445] = 144; 
    	em[446] = 867; em[447] = 152; 
    	em[448] = 867; em[449] = 160; 
    em[450] = 1; em[451] = 8; em[452] = 1; /* 450: pointer.struct.rsa_meth_st */
    	em[453] = 455; em[454] = 0; 
    em[455] = 0; em[456] = 112; em[457] = 13; /* 455: struct.rsa_meth_st */
    	em[458] = 141; em[459] = 0; 
    	em[460] = 484; em[461] = 8; 
    	em[462] = 484; em[463] = 16; 
    	em[464] = 484; em[465] = 24; 
    	em[466] = 484; em[467] = 32; 
    	em[468] = 487; em[469] = 40; 
    	em[470] = 490; em[471] = 48; 
    	em[472] = 407; em[473] = 56; 
    	em[474] = 407; em[475] = 64; 
    	em[476] = 122; em[477] = 80; 
    	em[478] = 493; em[479] = 88; 
    	em[480] = 496; em[481] = 96; 
    	em[482] = 404; em[483] = 104; 
    em[484] = 8884097; em[485] = 8; em[486] = 0; /* 484: pointer.func */
    em[487] = 8884097; em[488] = 8; em[489] = 0; /* 487: pointer.func */
    em[490] = 8884097; em[491] = 8; em[492] = 0; /* 490: pointer.func */
    em[493] = 8884097; em[494] = 8; em[495] = 0; /* 493: pointer.func */
    em[496] = 8884097; em[497] = 8; em[498] = 0; /* 496: pointer.func */
    em[499] = 1; em[500] = 8; em[501] = 1; /* 499: pointer.struct.engine_st */
    	em[502] = 504; em[503] = 0; 
    em[504] = 0; em[505] = 216; em[506] = 24; /* 504: struct.engine_st */
    	em[507] = 141; em[508] = 0; 
    	em[509] = 141; em[510] = 8; 
    	em[511] = 555; em[512] = 16; 
    	em[513] = 610; em[514] = 24; 
    	em[515] = 661; em[516] = 32; 
    	em[517] = 697; em[518] = 40; 
    	em[519] = 714; em[520] = 48; 
    	em[521] = 741; em[522] = 56; 
    	em[523] = 776; em[524] = 64; 
    	em[525] = 784; em[526] = 72; 
    	em[527] = 787; em[528] = 80; 
    	em[529] = 790; em[530] = 88; 
    	em[531] = 793; em[532] = 96; 
    	em[533] = 796; em[534] = 104; 
    	em[535] = 796; em[536] = 112; 
    	em[537] = 796; em[538] = 120; 
    	em[539] = 799; em[540] = 128; 
    	em[541] = 802; em[542] = 136; 
    	em[543] = 802; em[544] = 144; 
    	em[545] = 805; em[546] = 152; 
    	em[547] = 808; em[548] = 160; 
    	em[549] = 820; em[550] = 184; 
    	em[551] = 834; em[552] = 200; 
    	em[553] = 834; em[554] = 208; 
    em[555] = 1; em[556] = 8; em[557] = 1; /* 555: pointer.struct.rsa_meth_st */
    	em[558] = 560; em[559] = 0; 
    em[560] = 0; em[561] = 112; em[562] = 13; /* 560: struct.rsa_meth_st */
    	em[563] = 141; em[564] = 0; 
    	em[565] = 589; em[566] = 8; 
    	em[567] = 589; em[568] = 16; 
    	em[569] = 589; em[570] = 24; 
    	em[571] = 589; em[572] = 32; 
    	em[573] = 592; em[574] = 40; 
    	em[575] = 595; em[576] = 48; 
    	em[577] = 598; em[578] = 56; 
    	em[579] = 598; em[580] = 64; 
    	em[581] = 122; em[582] = 80; 
    	em[583] = 601; em[584] = 88; 
    	em[585] = 604; em[586] = 96; 
    	em[587] = 607; em[588] = 104; 
    em[589] = 8884097; em[590] = 8; em[591] = 0; /* 589: pointer.func */
    em[592] = 8884097; em[593] = 8; em[594] = 0; /* 592: pointer.func */
    em[595] = 8884097; em[596] = 8; em[597] = 0; /* 595: pointer.func */
    em[598] = 8884097; em[599] = 8; em[600] = 0; /* 598: pointer.func */
    em[601] = 8884097; em[602] = 8; em[603] = 0; /* 601: pointer.func */
    em[604] = 8884097; em[605] = 8; em[606] = 0; /* 604: pointer.func */
    em[607] = 8884097; em[608] = 8; em[609] = 0; /* 607: pointer.func */
    em[610] = 1; em[611] = 8; em[612] = 1; /* 610: pointer.struct.dsa_method */
    	em[613] = 615; em[614] = 0; 
    em[615] = 0; em[616] = 96; em[617] = 11; /* 615: struct.dsa_method */
    	em[618] = 141; em[619] = 0; 
    	em[620] = 640; em[621] = 8; 
    	em[622] = 643; em[623] = 16; 
    	em[624] = 646; em[625] = 24; 
    	em[626] = 649; em[627] = 32; 
    	em[628] = 652; em[629] = 40; 
    	em[630] = 655; em[631] = 48; 
    	em[632] = 655; em[633] = 56; 
    	em[634] = 122; em[635] = 72; 
    	em[636] = 658; em[637] = 80; 
    	em[638] = 655; em[639] = 88; 
    em[640] = 8884097; em[641] = 8; em[642] = 0; /* 640: pointer.func */
    em[643] = 8884097; em[644] = 8; em[645] = 0; /* 643: pointer.func */
    em[646] = 8884097; em[647] = 8; em[648] = 0; /* 646: pointer.func */
    em[649] = 8884097; em[650] = 8; em[651] = 0; /* 649: pointer.func */
    em[652] = 8884097; em[653] = 8; em[654] = 0; /* 652: pointer.func */
    em[655] = 8884097; em[656] = 8; em[657] = 0; /* 655: pointer.func */
    em[658] = 8884097; em[659] = 8; em[660] = 0; /* 658: pointer.func */
    em[661] = 1; em[662] = 8; em[663] = 1; /* 661: pointer.struct.dh_method */
    	em[664] = 666; em[665] = 0; 
    em[666] = 0; em[667] = 72; em[668] = 8; /* 666: struct.dh_method */
    	em[669] = 141; em[670] = 0; 
    	em[671] = 685; em[672] = 8; 
    	em[673] = 688; em[674] = 16; 
    	em[675] = 691; em[676] = 24; 
    	em[677] = 685; em[678] = 32; 
    	em[679] = 685; em[680] = 40; 
    	em[681] = 122; em[682] = 56; 
    	em[683] = 694; em[684] = 64; 
    em[685] = 8884097; em[686] = 8; em[687] = 0; /* 685: pointer.func */
    em[688] = 8884097; em[689] = 8; em[690] = 0; /* 688: pointer.func */
    em[691] = 8884097; em[692] = 8; em[693] = 0; /* 691: pointer.func */
    em[694] = 8884097; em[695] = 8; em[696] = 0; /* 694: pointer.func */
    em[697] = 1; em[698] = 8; em[699] = 1; /* 697: pointer.struct.ecdh_method */
    	em[700] = 702; em[701] = 0; 
    em[702] = 0; em[703] = 32; em[704] = 3; /* 702: struct.ecdh_method */
    	em[705] = 141; em[706] = 0; 
    	em[707] = 711; em[708] = 8; 
    	em[709] = 122; em[710] = 24; 
    em[711] = 8884097; em[712] = 8; em[713] = 0; /* 711: pointer.func */
    em[714] = 1; em[715] = 8; em[716] = 1; /* 714: pointer.struct.ecdsa_method */
    	em[717] = 719; em[718] = 0; 
    em[719] = 0; em[720] = 48; em[721] = 5; /* 719: struct.ecdsa_method */
    	em[722] = 141; em[723] = 0; 
    	em[724] = 732; em[725] = 8; 
    	em[726] = 735; em[727] = 16; 
    	em[728] = 738; em[729] = 24; 
    	em[730] = 122; em[731] = 40; 
    em[732] = 8884097; em[733] = 8; em[734] = 0; /* 732: pointer.func */
    em[735] = 8884097; em[736] = 8; em[737] = 0; /* 735: pointer.func */
    em[738] = 8884097; em[739] = 8; em[740] = 0; /* 738: pointer.func */
    em[741] = 1; em[742] = 8; em[743] = 1; /* 741: pointer.struct.rand_meth_st */
    	em[744] = 746; em[745] = 0; 
    em[746] = 0; em[747] = 48; em[748] = 6; /* 746: struct.rand_meth_st */
    	em[749] = 761; em[750] = 0; 
    	em[751] = 764; em[752] = 8; 
    	em[753] = 767; em[754] = 16; 
    	em[755] = 770; em[756] = 24; 
    	em[757] = 764; em[758] = 32; 
    	em[759] = 773; em[760] = 40; 
    em[761] = 8884097; em[762] = 8; em[763] = 0; /* 761: pointer.func */
    em[764] = 8884097; em[765] = 8; em[766] = 0; /* 764: pointer.func */
    em[767] = 8884097; em[768] = 8; em[769] = 0; /* 767: pointer.func */
    em[770] = 8884097; em[771] = 8; em[772] = 0; /* 770: pointer.func */
    em[773] = 8884097; em[774] = 8; em[775] = 0; /* 773: pointer.func */
    em[776] = 1; em[777] = 8; em[778] = 1; /* 776: pointer.struct.store_method_st */
    	em[779] = 781; em[780] = 0; 
    em[781] = 0; em[782] = 0; em[783] = 0; /* 781: struct.store_method_st */
    em[784] = 8884097; em[785] = 8; em[786] = 0; /* 784: pointer.func */
    em[787] = 8884097; em[788] = 8; em[789] = 0; /* 787: pointer.func */
    em[790] = 8884097; em[791] = 8; em[792] = 0; /* 790: pointer.func */
    em[793] = 8884097; em[794] = 8; em[795] = 0; /* 793: pointer.func */
    em[796] = 8884097; em[797] = 8; em[798] = 0; /* 796: pointer.func */
    em[799] = 8884097; em[800] = 8; em[801] = 0; /* 799: pointer.func */
    em[802] = 8884097; em[803] = 8; em[804] = 0; /* 802: pointer.func */
    em[805] = 8884097; em[806] = 8; em[807] = 0; /* 805: pointer.func */
    em[808] = 1; em[809] = 8; em[810] = 1; /* 808: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[811] = 813; em[812] = 0; 
    em[813] = 0; em[814] = 32; em[815] = 2; /* 813: struct.ENGINE_CMD_DEFN_st */
    	em[816] = 141; em[817] = 8; 
    	em[818] = 141; em[819] = 16; 
    em[820] = 0; em[821] = 32; em[822] = 2; /* 820: struct.crypto_ex_data_st_fake */
    	em[823] = 827; em[824] = 8; 
    	em[825] = 358; em[826] = 24; 
    em[827] = 8884099; em[828] = 8; em[829] = 2; /* 827: pointer_to_array_of_pointers_to_stack */
    	em[830] = 410; em[831] = 0; 
    	em[832] = 355; em[833] = 20; 
    em[834] = 1; em[835] = 8; em[836] = 1; /* 834: pointer.struct.engine_st */
    	em[837] = 504; em[838] = 0; 
    em[839] = 0; em[840] = 32; em[841] = 2; /* 839: struct.crypto_ex_data_st_fake */
    	em[842] = 846; em[843] = 8; 
    	em[844] = 358; em[845] = 24; 
    em[846] = 8884099; em[847] = 8; em[848] = 2; /* 846: pointer_to_array_of_pointers_to_stack */
    	em[849] = 410; em[850] = 0; 
    	em[851] = 355; em[852] = 20; 
    em[853] = 1; em[854] = 8; em[855] = 1; /* 853: pointer.struct.bn_mont_ctx_st */
    	em[856] = 858; em[857] = 0; 
    em[858] = 0; em[859] = 96; em[860] = 3; /* 858: struct.bn_mont_ctx_st */
    	em[861] = 389; em[862] = 8; 
    	em[863] = 389; em[864] = 32; 
    	em[865] = 389; em[866] = 56; 
    em[867] = 1; em[868] = 8; em[869] = 1; /* 867: pointer.struct.bn_blinding_st */
    	em[870] = 872; em[871] = 0; 
    em[872] = 0; em[873] = 88; em[874] = 7; /* 872: struct.bn_blinding_st */
    	em[875] = 889; em[876] = 0; 
    	em[877] = 889; em[878] = 8; 
    	em[879] = 889; em[880] = 16; 
    	em[881] = 889; em[882] = 24; 
    	em[883] = 906; em[884] = 40; 
    	em[885] = 911; em[886] = 72; 
    	em[887] = 925; em[888] = 80; 
    em[889] = 1; em[890] = 8; em[891] = 1; /* 889: pointer.struct.bignum_st */
    	em[892] = 894; em[893] = 0; 
    em[894] = 0; em[895] = 24; em[896] = 1; /* 894: struct.bignum_st */
    	em[897] = 899; em[898] = 0; 
    em[899] = 8884099; em[900] = 8; em[901] = 2; /* 899: pointer_to_array_of_pointers_to_stack */
    	em[902] = 401; em[903] = 0; 
    	em[904] = 355; em[905] = 12; 
    em[906] = 0; em[907] = 16; em[908] = 1; /* 906: struct.crypto_threadid_st */
    	em[909] = 410; em[910] = 0; 
    em[911] = 1; em[912] = 8; em[913] = 1; /* 911: pointer.struct.bn_mont_ctx_st */
    	em[914] = 916; em[915] = 0; 
    em[916] = 0; em[917] = 96; em[918] = 3; /* 916: struct.bn_mont_ctx_st */
    	em[919] = 894; em[920] = 8; 
    	em[921] = 894; em[922] = 32; 
    	em[923] = 894; em[924] = 56; 
    em[925] = 8884097; em[926] = 8; em[927] = 0; /* 925: pointer.func */
    em[928] = 8884097; em[929] = 8; em[930] = 0; /* 928: pointer.func */
    em[931] = 8884097; em[932] = 8; em[933] = 0; /* 931: pointer.func */
    em[934] = 8884097; em[935] = 8; em[936] = 0; /* 934: pointer.func */
    em[937] = 8884097; em[938] = 8; em[939] = 0; /* 937: pointer.func */
    em[940] = 0; em[941] = 208; em[942] = 24; /* 940: struct.evp_pkey_asn1_method_st */
    	em[943] = 122; em[944] = 16; 
    	em[945] = 122; em[946] = 24; 
    	em[947] = 991; em[948] = 32; 
    	em[949] = 994; em[950] = 40; 
    	em[951] = 997; em[952] = 48; 
    	em[953] = 1000; em[954] = 56; 
    	em[955] = 1003; em[956] = 64; 
    	em[957] = 1006; em[958] = 72; 
    	em[959] = 1000; em[960] = 80; 
    	em[961] = 934; em[962] = 88; 
    	em[963] = 934; em[964] = 96; 
    	em[965] = 1009; em[966] = 104; 
    	em[967] = 1012; em[968] = 112; 
    	em[969] = 934; em[970] = 120; 
    	em[971] = 937; em[972] = 128; 
    	em[973] = 997; em[974] = 136; 
    	em[975] = 1000; em[976] = 144; 
    	em[977] = 1015; em[978] = 152; 
    	em[979] = 1018; em[980] = 160; 
    	em[981] = 931; em[982] = 168; 
    	em[983] = 1009; em[984] = 176; 
    	em[985] = 1012; em[986] = 184; 
    	em[987] = 1021; em[988] = 192; 
    	em[989] = 1024; em[990] = 200; 
    em[991] = 8884097; em[992] = 8; em[993] = 0; /* 991: pointer.func */
    em[994] = 8884097; em[995] = 8; em[996] = 0; /* 994: pointer.func */
    em[997] = 8884097; em[998] = 8; em[999] = 0; /* 997: pointer.func */
    em[1000] = 8884097; em[1001] = 8; em[1002] = 0; /* 1000: pointer.func */
    em[1003] = 8884097; em[1004] = 8; em[1005] = 0; /* 1003: pointer.func */
    em[1006] = 8884097; em[1007] = 8; em[1008] = 0; /* 1006: pointer.func */
    em[1009] = 8884097; em[1010] = 8; em[1011] = 0; /* 1009: pointer.func */
    em[1012] = 8884097; em[1013] = 8; em[1014] = 0; /* 1012: pointer.func */
    em[1015] = 8884097; em[1016] = 8; em[1017] = 0; /* 1015: pointer.func */
    em[1018] = 8884097; em[1019] = 8; em[1020] = 0; /* 1018: pointer.func */
    em[1021] = 8884097; em[1022] = 8; em[1023] = 0; /* 1021: pointer.func */
    em[1024] = 8884097; em[1025] = 8; em[1026] = 0; /* 1024: pointer.func */
    em[1027] = 8884097; em[1028] = 8; em[1029] = 0; /* 1027: pointer.func */
    em[1030] = 8884097; em[1031] = 8; em[1032] = 0; /* 1030: pointer.func */
    em[1033] = 8884097; em[1034] = 8; em[1035] = 0; /* 1033: pointer.func */
    em[1036] = 1; em[1037] = 8; em[1038] = 1; /* 1036: pointer.struct.engine_st */
    	em[1039] = 504; em[1040] = 0; 
    em[1041] = 1; em[1042] = 8; em[1043] = 1; /* 1041: pointer.struct.rsa_st */
    	em[1044] = 413; em[1045] = 0; 
    em[1046] = 8884097; em[1047] = 8; em[1048] = 0; /* 1046: pointer.func */
    em[1049] = 8884097; em[1050] = 8; em[1051] = 0; /* 1049: pointer.func */
    em[1052] = 1; em[1053] = 8; em[1054] = 1; /* 1052: pointer.struct.engine_st */
    	em[1055] = 504; em[1056] = 0; 
    em[1057] = 8884097; em[1058] = 8; em[1059] = 0; /* 1057: pointer.func */
    em[1060] = 8884097; em[1061] = 8; em[1062] = 0; /* 1060: pointer.func */
    em[1063] = 8884097; em[1064] = 8; em[1065] = 0; /* 1063: pointer.func */
    em[1066] = 0; em[1067] = 208; em[1068] = 25; /* 1066: struct.evp_pkey_method_st */
    	em[1069] = 1063; em[1070] = 8; 
    	em[1071] = 1119; em[1072] = 16; 
    	em[1073] = 1122; em[1074] = 24; 
    	em[1075] = 1063; em[1076] = 32; 
    	em[1077] = 1125; em[1078] = 40; 
    	em[1079] = 1063; em[1080] = 48; 
    	em[1081] = 1125; em[1082] = 56; 
    	em[1083] = 1063; em[1084] = 64; 
    	em[1085] = 1128; em[1086] = 72; 
    	em[1087] = 1063; em[1088] = 80; 
    	em[1089] = 1057; em[1090] = 88; 
    	em[1091] = 1063; em[1092] = 96; 
    	em[1093] = 1128; em[1094] = 104; 
    	em[1095] = 1131; em[1096] = 112; 
    	em[1097] = 1049; em[1098] = 120; 
    	em[1099] = 1131; em[1100] = 128; 
    	em[1101] = 1134; em[1102] = 136; 
    	em[1103] = 1063; em[1104] = 144; 
    	em[1105] = 1128; em[1106] = 152; 
    	em[1107] = 1063; em[1108] = 160; 
    	em[1109] = 1128; em[1110] = 168; 
    	em[1111] = 1063; em[1112] = 176; 
    	em[1113] = 1137; em[1114] = 184; 
    	em[1115] = 1046; em[1116] = 192; 
    	em[1117] = 1140; em[1118] = 200; 
    em[1119] = 8884097; em[1120] = 8; em[1121] = 0; /* 1119: pointer.func */
    em[1122] = 8884097; em[1123] = 8; em[1124] = 0; /* 1122: pointer.func */
    em[1125] = 8884097; em[1126] = 8; em[1127] = 0; /* 1125: pointer.func */
    em[1128] = 8884097; em[1129] = 8; em[1130] = 0; /* 1128: pointer.func */
    em[1131] = 8884097; em[1132] = 8; em[1133] = 0; /* 1131: pointer.func */
    em[1134] = 8884097; em[1135] = 8; em[1136] = 0; /* 1134: pointer.func */
    em[1137] = 8884097; em[1138] = 8; em[1139] = 0; /* 1137: pointer.func */
    em[1140] = 8884097; em[1141] = 8; em[1142] = 0; /* 1140: pointer.func */
    em[1143] = 8884097; em[1144] = 8; em[1145] = 0; /* 1143: pointer.func */
    em[1146] = 1; em[1147] = 8; em[1148] = 1; /* 1146: pointer.struct.bn_mont_ctx_st */
    	em[1149] = 1151; em[1150] = 0; 
    em[1151] = 0; em[1152] = 96; em[1153] = 3; /* 1151: struct.bn_mont_ctx_st */
    	em[1154] = 1160; em[1155] = 8; 
    	em[1156] = 1160; em[1157] = 32; 
    	em[1158] = 1160; em[1159] = 56; 
    em[1160] = 0; em[1161] = 24; em[1162] = 1; /* 1160: struct.bignum_st */
    	em[1163] = 1165; em[1164] = 0; 
    em[1165] = 8884099; em[1166] = 8; em[1167] = 2; /* 1165: pointer_to_array_of_pointers_to_stack */
    	em[1168] = 401; em[1169] = 0; 
    	em[1170] = 355; em[1171] = 12; 
    em[1172] = 0; em[1173] = 24; em[1174] = 1; /* 1172: struct.bignum_st */
    	em[1175] = 1177; em[1176] = 0; 
    em[1177] = 8884099; em[1178] = 8; em[1179] = 2; /* 1177: pointer_to_array_of_pointers_to_stack */
    	em[1180] = 401; em[1181] = 0; 
    	em[1182] = 355; em[1183] = 12; 
    em[1184] = 1; em[1185] = 8; em[1186] = 1; /* 1184: pointer.struct.bignum_st */
    	em[1187] = 1160; em[1188] = 0; 
    em[1189] = 8884097; em[1190] = 8; em[1191] = 0; /* 1189: pointer.func */
    em[1192] = 8884097; em[1193] = 8; em[1194] = 0; /* 1192: pointer.func */
    em[1195] = 0; em[1196] = 48; em[1197] = 5; /* 1195: struct.env_md_ctx_st */
    	em[1198] = 1208; em[1199] = 0; 
    	em[1200] = 1036; em[1201] = 8; 
    	em[1202] = 410; em[1203] = 24; 
    	em[1204] = 1241; em[1205] = 32; 
    	em[1206] = 1235; em[1207] = 40; 
    em[1208] = 1; em[1209] = 8; em[1210] = 1; /* 1208: pointer.struct.env_md_st */
    	em[1211] = 1213; em[1212] = 0; 
    em[1213] = 0; em[1214] = 120; em[1215] = 8; /* 1213: struct.env_md_st */
    	em[1216] = 1232; em[1217] = 24; 
    	em[1218] = 1235; em[1219] = 32; 
    	em[1220] = 1192; em[1221] = 40; 
    	em[1222] = 1238; em[1223] = 48; 
    	em[1224] = 1232; em[1225] = 56; 
    	em[1226] = 1189; em[1227] = 64; 
    	em[1228] = 1027; em[1229] = 72; 
    	em[1230] = 375; em[1231] = 112; 
    em[1232] = 8884097; em[1233] = 8; em[1234] = 0; /* 1232: pointer.func */
    em[1235] = 8884097; em[1236] = 8; em[1237] = 0; /* 1235: pointer.func */
    em[1238] = 8884097; em[1239] = 8; em[1240] = 0; /* 1238: pointer.func */
    em[1241] = 1; em[1242] = 8; em[1243] = 1; /* 1241: pointer.struct.evp_pkey_ctx_st */
    	em[1244] = 1246; em[1245] = 0; 
    em[1246] = 0; em[1247] = 80; em[1248] = 8; /* 1246: struct.evp_pkey_ctx_st */
    	em[1249] = 1265; em[1250] = 0; 
    	em[1251] = 1052; em[1252] = 8; 
    	em[1253] = 1270; em[1254] = 16; 
    	em[1255] = 1270; em[1256] = 24; 
    	em[1257] = 410; em[1258] = 40; 
    	em[1259] = 410; em[1260] = 48; 
    	em[1261] = 0; em[1262] = 56; 
    	em[1263] = 2036; em[1264] = 64; 
    em[1265] = 1; em[1266] = 8; em[1267] = 1; /* 1265: pointer.struct.evp_pkey_method_st */
    	em[1268] = 1066; em[1269] = 0; 
    em[1270] = 1; em[1271] = 8; em[1272] = 1; /* 1270: pointer.struct.evp_pkey_st */
    	em[1273] = 1275; em[1274] = 0; 
    em[1275] = 0; em[1276] = 56; em[1277] = 4; /* 1275: struct.evp_pkey_st */
    	em[1278] = 1286; em[1279] = 16; 
    	em[1280] = 1052; em[1281] = 24; 
    	em[1282] = 1291; em[1283] = 32; 
    	em[1284] = 2000; em[1285] = 48; 
    em[1286] = 1; em[1287] = 8; em[1288] = 1; /* 1286: pointer.struct.evp_pkey_asn1_method_st */
    	em[1289] = 940; em[1290] = 0; 
    em[1291] = 0; em[1292] = 8; em[1293] = 6; /* 1291: union.union_of_evp_pkey_st */
    	em[1294] = 410; em[1295] = 0; 
    	em[1296] = 1041; em[1297] = 6; 
    	em[1298] = 1306; em[1299] = 116; 
    	em[1300] = 1403; em[1301] = 28; 
    	em[1302] = 1521; em[1303] = 408; 
    	em[1304] = 355; em[1305] = 0; 
    em[1306] = 1; em[1307] = 8; em[1308] = 1; /* 1306: pointer.struct.dsa_st */
    	em[1309] = 1311; em[1310] = 0; 
    em[1311] = 0; em[1312] = 136; em[1313] = 11; /* 1311: struct.dsa_st */
    	em[1314] = 1184; em[1315] = 24; 
    	em[1316] = 1184; em[1317] = 32; 
    	em[1318] = 1184; em[1319] = 40; 
    	em[1320] = 1184; em[1321] = 48; 
    	em[1322] = 1184; em[1323] = 56; 
    	em[1324] = 1184; em[1325] = 64; 
    	em[1326] = 1184; em[1327] = 72; 
    	em[1328] = 1146; em[1329] = 88; 
    	em[1330] = 1336; em[1331] = 104; 
    	em[1332] = 1350; em[1333] = 120; 
    	em[1334] = 1398; em[1335] = 128; 
    em[1336] = 0; em[1337] = 32; em[1338] = 2; /* 1336: struct.crypto_ex_data_st_fake */
    	em[1339] = 1343; em[1340] = 8; 
    	em[1341] = 358; em[1342] = 24; 
    em[1343] = 8884099; em[1344] = 8; em[1345] = 2; /* 1343: pointer_to_array_of_pointers_to_stack */
    	em[1346] = 410; em[1347] = 0; 
    	em[1348] = 355; em[1349] = 20; 
    em[1350] = 1; em[1351] = 8; em[1352] = 1; /* 1350: pointer.struct.dsa_method */
    	em[1353] = 1355; em[1354] = 0; 
    em[1355] = 0; em[1356] = 96; em[1357] = 11; /* 1355: struct.dsa_method */
    	em[1358] = 141; em[1359] = 0; 
    	em[1360] = 1380; em[1361] = 8; 
    	em[1362] = 1383; em[1363] = 16; 
    	em[1364] = 1386; em[1365] = 24; 
    	em[1366] = 378; em[1367] = 32; 
    	em[1368] = 1389; em[1369] = 40; 
    	em[1370] = 1392; em[1371] = 48; 
    	em[1372] = 1392; em[1373] = 56; 
    	em[1374] = 122; em[1375] = 72; 
    	em[1376] = 1395; em[1377] = 80; 
    	em[1378] = 1392; em[1379] = 88; 
    em[1380] = 8884097; em[1381] = 8; em[1382] = 0; /* 1380: pointer.func */
    em[1383] = 8884097; em[1384] = 8; em[1385] = 0; /* 1383: pointer.func */
    em[1386] = 8884097; em[1387] = 8; em[1388] = 0; /* 1386: pointer.func */
    em[1389] = 8884097; em[1390] = 8; em[1391] = 0; /* 1389: pointer.func */
    em[1392] = 8884097; em[1393] = 8; em[1394] = 0; /* 1392: pointer.func */
    em[1395] = 8884097; em[1396] = 8; em[1397] = 0; /* 1395: pointer.func */
    em[1398] = 1; em[1399] = 8; em[1400] = 1; /* 1398: pointer.struct.engine_st */
    	em[1401] = 504; em[1402] = 0; 
    em[1403] = 1; em[1404] = 8; em[1405] = 1; /* 1403: pointer.struct.dh_st */
    	em[1406] = 1408; em[1407] = 0; 
    em[1408] = 0; em[1409] = 144; em[1410] = 12; /* 1408: struct.dh_st */
    	em[1411] = 1435; em[1412] = 8; 
    	em[1413] = 1435; em[1414] = 16; 
    	em[1415] = 1435; em[1416] = 32; 
    	em[1417] = 1435; em[1418] = 40; 
    	em[1419] = 1452; em[1420] = 56; 
    	em[1421] = 1435; em[1422] = 64; 
    	em[1423] = 1435; em[1424] = 72; 
    	em[1425] = 21; em[1426] = 80; 
    	em[1427] = 1435; em[1428] = 96; 
    	em[1429] = 1466; em[1430] = 112; 
    	em[1431] = 1480; em[1432] = 128; 
    	em[1433] = 1516; em[1434] = 136; 
    em[1435] = 1; em[1436] = 8; em[1437] = 1; /* 1435: pointer.struct.bignum_st */
    	em[1438] = 1440; em[1439] = 0; 
    em[1440] = 0; em[1441] = 24; em[1442] = 1; /* 1440: struct.bignum_st */
    	em[1443] = 1445; em[1444] = 0; 
    em[1445] = 8884099; em[1446] = 8; em[1447] = 2; /* 1445: pointer_to_array_of_pointers_to_stack */
    	em[1448] = 401; em[1449] = 0; 
    	em[1450] = 355; em[1451] = 12; 
    em[1452] = 1; em[1453] = 8; em[1454] = 1; /* 1452: pointer.struct.bn_mont_ctx_st */
    	em[1455] = 1457; em[1456] = 0; 
    em[1457] = 0; em[1458] = 96; em[1459] = 3; /* 1457: struct.bn_mont_ctx_st */
    	em[1460] = 1440; em[1461] = 8; 
    	em[1462] = 1440; em[1463] = 32; 
    	em[1464] = 1440; em[1465] = 56; 
    em[1466] = 0; em[1467] = 32; em[1468] = 2; /* 1466: struct.crypto_ex_data_st_fake */
    	em[1469] = 1473; em[1470] = 8; 
    	em[1471] = 358; em[1472] = 24; 
    em[1473] = 8884099; em[1474] = 8; em[1475] = 2; /* 1473: pointer_to_array_of_pointers_to_stack */
    	em[1476] = 410; em[1477] = 0; 
    	em[1478] = 355; em[1479] = 20; 
    em[1480] = 1; em[1481] = 8; em[1482] = 1; /* 1480: pointer.struct.dh_method */
    	em[1483] = 1485; em[1484] = 0; 
    em[1485] = 0; em[1486] = 72; em[1487] = 8; /* 1485: struct.dh_method */
    	em[1488] = 141; em[1489] = 0; 
    	em[1490] = 1504; em[1491] = 8; 
    	em[1492] = 1507; em[1493] = 16; 
    	em[1494] = 1510; em[1495] = 24; 
    	em[1496] = 1504; em[1497] = 32; 
    	em[1498] = 1504; em[1499] = 40; 
    	em[1500] = 122; em[1501] = 56; 
    	em[1502] = 1513; em[1503] = 64; 
    em[1504] = 8884097; em[1505] = 8; em[1506] = 0; /* 1504: pointer.func */
    em[1507] = 8884097; em[1508] = 8; em[1509] = 0; /* 1507: pointer.func */
    em[1510] = 8884097; em[1511] = 8; em[1512] = 0; /* 1510: pointer.func */
    em[1513] = 8884097; em[1514] = 8; em[1515] = 0; /* 1513: pointer.func */
    em[1516] = 1; em[1517] = 8; em[1518] = 1; /* 1516: pointer.struct.engine_st */
    	em[1519] = 504; em[1520] = 0; 
    em[1521] = 1; em[1522] = 8; em[1523] = 1; /* 1521: pointer.struct.ec_key_st */
    	em[1524] = 1526; em[1525] = 0; 
    em[1526] = 0; em[1527] = 56; em[1528] = 4; /* 1526: struct.ec_key_st */
    	em[1529] = 1537; em[1530] = 8; 
    	em[1531] = 1955; em[1532] = 16; 
    	em[1533] = 1960; em[1534] = 24; 
    	em[1535] = 1977; em[1536] = 48; 
    em[1537] = 1; em[1538] = 8; em[1539] = 1; /* 1537: pointer.struct.ec_group_st */
    	em[1540] = 1542; em[1541] = 0; 
    em[1542] = 0; em[1543] = 232; em[1544] = 12; /* 1542: struct.ec_group_st */
    	em[1545] = 1569; em[1546] = 0; 
    	em[1547] = 1729; em[1548] = 8; 
    	em[1549] = 1172; em[1550] = 16; 
    	em[1551] = 1172; em[1552] = 40; 
    	em[1553] = 21; em[1554] = 80; 
    	em[1555] = 1923; em[1556] = 96; 
    	em[1557] = 1172; em[1558] = 104; 
    	em[1559] = 1172; em[1560] = 152; 
    	em[1561] = 1172; em[1562] = 176; 
    	em[1563] = 410; em[1564] = 208; 
    	em[1565] = 410; em[1566] = 216; 
    	em[1567] = 1952; em[1568] = 224; 
    em[1569] = 1; em[1570] = 8; em[1571] = 1; /* 1569: pointer.struct.ec_method_st */
    	em[1572] = 1574; em[1573] = 0; 
    em[1574] = 0; em[1575] = 304; em[1576] = 37; /* 1574: struct.ec_method_st */
    	em[1577] = 1651; em[1578] = 8; 
    	em[1579] = 1654; em[1580] = 16; 
    	em[1581] = 1654; em[1582] = 24; 
    	em[1583] = 1657; em[1584] = 32; 
    	em[1585] = 1660; em[1586] = 40; 
    	em[1587] = 1030; em[1588] = 48; 
    	em[1589] = 1663; em[1590] = 56; 
    	em[1591] = 1666; em[1592] = 64; 
    	em[1593] = 1060; em[1594] = 72; 
    	em[1595] = 1669; em[1596] = 80; 
    	em[1597] = 1669; em[1598] = 88; 
    	em[1599] = 928; em[1600] = 96; 
    	em[1601] = 1672; em[1602] = 104; 
    	em[1603] = 1675; em[1604] = 112; 
    	em[1605] = 1678; em[1606] = 120; 
    	em[1607] = 1681; em[1608] = 128; 
    	em[1609] = 1684; em[1610] = 136; 
    	em[1611] = 1687; em[1612] = 144; 
    	em[1613] = 1690; em[1614] = 152; 
    	em[1615] = 1693; em[1616] = 160; 
    	em[1617] = 1696; em[1618] = 168; 
    	em[1619] = 1699; em[1620] = 176; 
    	em[1621] = 1702; em[1622] = 184; 
    	em[1623] = 1705; em[1624] = 192; 
    	em[1625] = 1708; em[1626] = 200; 
    	em[1627] = 1711; em[1628] = 208; 
    	em[1629] = 1702; em[1630] = 216; 
    	em[1631] = 1714; em[1632] = 224; 
    	em[1633] = 1717; em[1634] = 232; 
    	em[1635] = 1720; em[1636] = 240; 
    	em[1637] = 1663; em[1638] = 248; 
    	em[1639] = 1723; em[1640] = 256; 
    	em[1641] = 1726; em[1642] = 264; 
    	em[1643] = 1723; em[1644] = 272; 
    	em[1645] = 1726; em[1646] = 280; 
    	em[1647] = 1726; em[1648] = 288; 
    	em[1649] = 1033; em[1650] = 296; 
    em[1651] = 8884097; em[1652] = 8; em[1653] = 0; /* 1651: pointer.func */
    em[1654] = 8884097; em[1655] = 8; em[1656] = 0; /* 1654: pointer.func */
    em[1657] = 8884097; em[1658] = 8; em[1659] = 0; /* 1657: pointer.func */
    em[1660] = 8884097; em[1661] = 8; em[1662] = 0; /* 1660: pointer.func */
    em[1663] = 8884097; em[1664] = 8; em[1665] = 0; /* 1663: pointer.func */
    em[1666] = 8884097; em[1667] = 8; em[1668] = 0; /* 1666: pointer.func */
    em[1669] = 8884097; em[1670] = 8; em[1671] = 0; /* 1669: pointer.func */
    em[1672] = 8884097; em[1673] = 8; em[1674] = 0; /* 1672: pointer.func */
    em[1675] = 8884097; em[1676] = 8; em[1677] = 0; /* 1675: pointer.func */
    em[1678] = 8884097; em[1679] = 8; em[1680] = 0; /* 1678: pointer.func */
    em[1681] = 8884097; em[1682] = 8; em[1683] = 0; /* 1681: pointer.func */
    em[1684] = 8884097; em[1685] = 8; em[1686] = 0; /* 1684: pointer.func */
    em[1687] = 8884097; em[1688] = 8; em[1689] = 0; /* 1687: pointer.func */
    em[1690] = 8884097; em[1691] = 8; em[1692] = 0; /* 1690: pointer.func */
    em[1693] = 8884097; em[1694] = 8; em[1695] = 0; /* 1693: pointer.func */
    em[1696] = 8884097; em[1697] = 8; em[1698] = 0; /* 1696: pointer.func */
    em[1699] = 8884097; em[1700] = 8; em[1701] = 0; /* 1699: pointer.func */
    em[1702] = 8884097; em[1703] = 8; em[1704] = 0; /* 1702: pointer.func */
    em[1705] = 8884097; em[1706] = 8; em[1707] = 0; /* 1705: pointer.func */
    em[1708] = 8884097; em[1709] = 8; em[1710] = 0; /* 1708: pointer.func */
    em[1711] = 8884097; em[1712] = 8; em[1713] = 0; /* 1711: pointer.func */
    em[1714] = 8884097; em[1715] = 8; em[1716] = 0; /* 1714: pointer.func */
    em[1717] = 8884097; em[1718] = 8; em[1719] = 0; /* 1717: pointer.func */
    em[1720] = 8884097; em[1721] = 8; em[1722] = 0; /* 1720: pointer.func */
    em[1723] = 8884097; em[1724] = 8; em[1725] = 0; /* 1723: pointer.func */
    em[1726] = 8884097; em[1727] = 8; em[1728] = 0; /* 1726: pointer.func */
    em[1729] = 1; em[1730] = 8; em[1731] = 1; /* 1729: pointer.struct.ec_point_st */
    	em[1732] = 1734; em[1733] = 0; 
    em[1734] = 0; em[1735] = 88; em[1736] = 4; /* 1734: struct.ec_point_st */
    	em[1737] = 1745; em[1738] = 0; 
    	em[1739] = 1911; em[1740] = 8; 
    	em[1741] = 1911; em[1742] = 32; 
    	em[1743] = 1911; em[1744] = 56; 
    em[1745] = 1; em[1746] = 8; em[1747] = 1; /* 1745: pointer.struct.ec_method_st */
    	em[1748] = 1750; em[1749] = 0; 
    em[1750] = 0; em[1751] = 304; em[1752] = 37; /* 1750: struct.ec_method_st */
    	em[1753] = 1827; em[1754] = 8; 
    	em[1755] = 1830; em[1756] = 16; 
    	em[1757] = 1830; em[1758] = 24; 
    	em[1759] = 1833; em[1760] = 32; 
    	em[1761] = 1836; em[1762] = 40; 
    	em[1763] = 1839; em[1764] = 48; 
    	em[1765] = 1842; em[1766] = 56; 
    	em[1767] = 1143; em[1768] = 64; 
    	em[1769] = 1845; em[1770] = 72; 
    	em[1771] = 1848; em[1772] = 80; 
    	em[1773] = 1848; em[1774] = 88; 
    	em[1775] = 1851; em[1776] = 96; 
    	em[1777] = 1854; em[1778] = 104; 
    	em[1779] = 1857; em[1780] = 112; 
    	em[1781] = 1860; em[1782] = 120; 
    	em[1783] = 1863; em[1784] = 128; 
    	em[1785] = 1866; em[1786] = 136; 
    	em[1787] = 1869; em[1788] = 144; 
    	em[1789] = 1872; em[1790] = 152; 
    	em[1791] = 1875; em[1792] = 160; 
    	em[1793] = 1878; em[1794] = 168; 
    	em[1795] = 1881; em[1796] = 176; 
    	em[1797] = 1884; em[1798] = 184; 
    	em[1799] = 1887; em[1800] = 192; 
    	em[1801] = 381; em[1802] = 200; 
    	em[1803] = 1890; em[1804] = 208; 
    	em[1805] = 1884; em[1806] = 216; 
    	em[1807] = 1893; em[1808] = 224; 
    	em[1809] = 1896; em[1810] = 232; 
    	em[1811] = 1899; em[1812] = 240; 
    	em[1813] = 1842; em[1814] = 248; 
    	em[1815] = 1902; em[1816] = 256; 
    	em[1817] = 1905; em[1818] = 264; 
    	em[1819] = 1902; em[1820] = 272; 
    	em[1821] = 1905; em[1822] = 280; 
    	em[1823] = 1905; em[1824] = 288; 
    	em[1825] = 1908; em[1826] = 296; 
    em[1827] = 8884097; em[1828] = 8; em[1829] = 0; /* 1827: pointer.func */
    em[1830] = 8884097; em[1831] = 8; em[1832] = 0; /* 1830: pointer.func */
    em[1833] = 8884097; em[1834] = 8; em[1835] = 0; /* 1833: pointer.func */
    em[1836] = 8884097; em[1837] = 8; em[1838] = 0; /* 1836: pointer.func */
    em[1839] = 8884097; em[1840] = 8; em[1841] = 0; /* 1839: pointer.func */
    em[1842] = 8884097; em[1843] = 8; em[1844] = 0; /* 1842: pointer.func */
    em[1845] = 8884097; em[1846] = 8; em[1847] = 0; /* 1845: pointer.func */
    em[1848] = 8884097; em[1849] = 8; em[1850] = 0; /* 1848: pointer.func */
    em[1851] = 8884097; em[1852] = 8; em[1853] = 0; /* 1851: pointer.func */
    em[1854] = 8884097; em[1855] = 8; em[1856] = 0; /* 1854: pointer.func */
    em[1857] = 8884097; em[1858] = 8; em[1859] = 0; /* 1857: pointer.func */
    em[1860] = 8884097; em[1861] = 8; em[1862] = 0; /* 1860: pointer.func */
    em[1863] = 8884097; em[1864] = 8; em[1865] = 0; /* 1863: pointer.func */
    em[1866] = 8884097; em[1867] = 8; em[1868] = 0; /* 1866: pointer.func */
    em[1869] = 8884097; em[1870] = 8; em[1871] = 0; /* 1869: pointer.func */
    em[1872] = 8884097; em[1873] = 8; em[1874] = 0; /* 1872: pointer.func */
    em[1875] = 8884097; em[1876] = 8; em[1877] = 0; /* 1875: pointer.func */
    em[1878] = 8884097; em[1879] = 8; em[1880] = 0; /* 1878: pointer.func */
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
    em[1911] = 0; em[1912] = 24; em[1913] = 1; /* 1911: struct.bignum_st */
    	em[1914] = 1916; em[1915] = 0; 
    em[1916] = 8884099; em[1917] = 8; em[1918] = 2; /* 1916: pointer_to_array_of_pointers_to_stack */
    	em[1919] = 401; em[1920] = 0; 
    	em[1921] = 355; em[1922] = 12; 
    em[1923] = 1; em[1924] = 8; em[1925] = 1; /* 1923: pointer.struct.ec_extra_data_st */
    	em[1926] = 1928; em[1927] = 0; 
    em[1928] = 0; em[1929] = 40; em[1930] = 5; /* 1928: struct.ec_extra_data_st */
    	em[1931] = 1941; em[1932] = 0; 
    	em[1933] = 410; em[1934] = 8; 
    	em[1935] = 1946; em[1936] = 16; 
    	em[1937] = 1949; em[1938] = 24; 
    	em[1939] = 1949; em[1940] = 32; 
    em[1941] = 1; em[1942] = 8; em[1943] = 1; /* 1941: pointer.struct.ec_extra_data_st */
    	em[1944] = 1928; em[1945] = 0; 
    em[1946] = 8884097; em[1947] = 8; em[1948] = 0; /* 1946: pointer.func */
    em[1949] = 8884097; em[1950] = 8; em[1951] = 0; /* 1949: pointer.func */
    em[1952] = 8884097; em[1953] = 8; em[1954] = 0; /* 1952: pointer.func */
    em[1955] = 1; em[1956] = 8; em[1957] = 1; /* 1955: pointer.struct.ec_point_st */
    	em[1958] = 1734; em[1959] = 0; 
    em[1960] = 1; em[1961] = 8; em[1962] = 1; /* 1960: pointer.struct.bignum_st */
    	em[1963] = 1965; em[1964] = 0; 
    em[1965] = 0; em[1966] = 24; em[1967] = 1; /* 1965: struct.bignum_st */
    	em[1968] = 1970; em[1969] = 0; 
    em[1970] = 8884099; em[1971] = 8; em[1972] = 2; /* 1970: pointer_to_array_of_pointers_to_stack */
    	em[1973] = 401; em[1974] = 0; 
    	em[1975] = 355; em[1976] = 12; 
    em[1977] = 1; em[1978] = 8; em[1979] = 1; /* 1977: pointer.struct.ec_extra_data_st */
    	em[1980] = 1982; em[1981] = 0; 
    em[1982] = 0; em[1983] = 40; em[1984] = 5; /* 1982: struct.ec_extra_data_st */
    	em[1985] = 1995; em[1986] = 0; 
    	em[1987] = 410; em[1988] = 8; 
    	em[1989] = 1946; em[1990] = 16; 
    	em[1991] = 1949; em[1992] = 24; 
    	em[1993] = 1949; em[1994] = 32; 
    em[1995] = 1; em[1996] = 8; em[1997] = 1; /* 1995: pointer.struct.ec_extra_data_st */
    	em[1998] = 1982; em[1999] = 0; 
    em[2000] = 1; em[2001] = 8; em[2002] = 1; /* 2000: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[2003] = 2005; em[2004] = 0; 
    em[2005] = 0; em[2006] = 32; em[2007] = 2; /* 2005: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[2008] = 2012; em[2009] = 8; 
    	em[2010] = 358; em[2011] = 24; 
    em[2012] = 8884099; em[2013] = 8; em[2014] = 2; /* 2012: pointer_to_array_of_pointers_to_stack */
    	em[2015] = 2019; em[2016] = 0; 
    	em[2017] = 355; em[2018] = 20; 
    em[2019] = 0; em[2020] = 8; em[2021] = 1; /* 2019: pointer.X509_ATTRIBUTE */
    	em[2022] = 2024; em[2023] = 0; 
    em[2024] = 0; em[2025] = 0; em[2026] = 1; /* 2024: X509_ATTRIBUTE */
    	em[2027] = 2029; em[2028] = 0; 
    em[2029] = 0; em[2030] = 24; em[2031] = 2; /* 2029: struct.x509_attributes_st */
    	em[2032] = 127; em[2033] = 0; 
    	em[2034] = 361; em[2035] = 16; 
    em[2036] = 1; em[2037] = 8; em[2038] = 1; /* 2036: pointer.int */
    	em[2039] = 355; em[2040] = 0; 
    em[2041] = 0; em[2042] = 1; em[2043] = 0; /* 2041: char */
    em[2044] = 1; em[2045] = 8; em[2046] = 1; /* 2044: pointer.struct.hmac_ctx_st */
    	em[2047] = 2049; em[2048] = 0; 
    em[2049] = 0; em[2050] = 288; em[2051] = 4; /* 2049: struct.hmac_ctx_st */
    	em[2052] = 1208; em[2053] = 0; 
    	em[2054] = 1195; em[2055] = 8; 
    	em[2056] = 1195; em[2057] = 56; 
    	em[2058] = 1195; em[2059] = 104; 
    args_addr->arg_entity_index[0] = 2044;
    args_addr->arg_entity_index[1] = 410;
    args_addr->arg_entity_index[2] = 355;
    args_addr->arg_entity_index[3] = 1208;
    args_addr->arg_entity_index[4] = 1036;
    args_addr->ret_entity_index = 355;
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

