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
    em[87] = 0; em[88] = 8; em[89] = 20; /* 87: union.unknown */
    	em[90] = 130; em[91] = 0; 
    	em[92] = 82; em[93] = 0; 
    	em[94] = 135; em[95] = 0; 
    	em[96] = 159; em[97] = 0; 
    	em[98] = 77; em[99] = 0; 
    	em[100] = 72; em[101] = 0; 
    	em[102] = 67; em[103] = 0; 
    	em[104] = 62; em[105] = 0; 
    	em[106] = 57; em[107] = 0; 
    	em[108] = 52; em[109] = 0; 
    	em[110] = 47; em[111] = 0; 
    	em[112] = 42; em[113] = 0; 
    	em[114] = 37; em[115] = 0; 
    	em[116] = 164; em[117] = 0; 
    	em[118] = 169; em[119] = 0; 
    	em[120] = 174; em[121] = 0; 
    	em[122] = 19; em[123] = 0; 
    	em[124] = 82; em[125] = 0; 
    	em[126] = 82; em[127] = 0; 
    	em[128] = 11; em[129] = 0; 
    em[130] = 1; em[131] = 8; em[132] = 1; /* 130: pointer.char */
    	em[133] = 8884096; em[134] = 0; 
    em[135] = 1; em[136] = 8; em[137] = 1; /* 135: pointer.struct.asn1_object_st */
    	em[138] = 140; em[139] = 0; 
    em[140] = 0; em[141] = 40; em[142] = 3; /* 140: struct.asn1_object_st */
    	em[143] = 149; em[144] = 0; 
    	em[145] = 149; em[146] = 8; 
    	em[147] = 154; em[148] = 24; 
    em[149] = 1; em[150] = 8; em[151] = 1; /* 149: pointer.char */
    	em[152] = 8884096; em[153] = 0; 
    em[154] = 1; em[155] = 8; em[156] = 1; /* 154: pointer.unsigned char */
    	em[157] = 34; em[158] = 0; 
    em[159] = 1; em[160] = 8; em[161] = 1; /* 159: pointer.struct.asn1_string_st */
    	em[162] = 24; em[163] = 0; 
    em[164] = 1; em[165] = 8; em[166] = 1; /* 164: pointer.struct.asn1_string_st */
    	em[167] = 24; em[168] = 0; 
    em[169] = 1; em[170] = 8; em[171] = 1; /* 169: pointer.struct.asn1_string_st */
    	em[172] = 24; em[173] = 0; 
    em[174] = 1; em[175] = 8; em[176] = 1; /* 174: pointer.struct.asn1_string_st */
    	em[177] = 24; em[178] = 0; 
    em[179] = 0; em[180] = 16; em[181] = 1; /* 179: struct.asn1_type_st */
    	em[182] = 87; em[183] = 8; 
    em[184] = 0; em[185] = 0; em[186] = 0; /* 184: struct.ASN1_VALUE_st */
    em[187] = 1; em[188] = 8; em[189] = 1; /* 187: pointer.struct.ASN1_VALUE_st */
    	em[190] = 184; em[191] = 0; 
    em[192] = 1; em[193] = 8; em[194] = 1; /* 192: pointer.struct.asn1_string_st */
    	em[195] = 197; em[196] = 0; 
    em[197] = 0; em[198] = 24; em[199] = 1; /* 197: struct.asn1_string_st */
    	em[200] = 29; em[201] = 8; 
    em[202] = 1; em[203] = 8; em[204] = 1; /* 202: pointer.struct.asn1_string_st */
    	em[205] = 197; em[206] = 0; 
    em[207] = 1; em[208] = 8; em[209] = 1; /* 207: pointer.struct.asn1_string_st */
    	em[210] = 197; em[211] = 0; 
    em[212] = 1; em[213] = 8; em[214] = 1; /* 212: pointer.struct.asn1_string_st */
    	em[215] = 197; em[216] = 0; 
    em[217] = 1; em[218] = 8; em[219] = 1; /* 217: pointer.struct.asn1_string_st */
    	em[220] = 197; em[221] = 0; 
    em[222] = 1; em[223] = 8; em[224] = 1; /* 222: pointer.struct.asn1_string_st */
    	em[225] = 197; em[226] = 0; 
    em[227] = 1; em[228] = 8; em[229] = 1; /* 227: pointer.struct.asn1_string_st */
    	em[230] = 197; em[231] = 0; 
    em[232] = 1; em[233] = 8; em[234] = 1; /* 232: pointer.struct.asn1_string_st */
    	em[235] = 197; em[236] = 0; 
    em[237] = 1; em[238] = 8; em[239] = 1; /* 237: pointer.struct.asn1_string_st */
    	em[240] = 197; em[241] = 0; 
    em[242] = 1; em[243] = 8; em[244] = 1; /* 242: pointer.struct.asn1_string_st */
    	em[245] = 197; em[246] = 0; 
    em[247] = 1; em[248] = 8; em[249] = 1; /* 247: pointer.struct.asn1_string_st */
    	em[250] = 197; em[251] = 0; 
    em[252] = 0; em[253] = 40; em[254] = 3; /* 252: struct.asn1_object_st */
    	em[255] = 149; em[256] = 0; 
    	em[257] = 149; em[258] = 8; 
    	em[259] = 154; em[260] = 24; 
    em[261] = 1; em[262] = 8; em[263] = 1; /* 261: pointer.struct.asn1_string_st */
    	em[264] = 197; em[265] = 0; 
    em[266] = 0; em[267] = 16; em[268] = 1; /* 266: struct.asn1_type_st */
    	em[269] = 271; em[270] = 8; 
    em[271] = 0; em[272] = 8; em[273] = 20; /* 271: union.unknown */
    	em[274] = 130; em[275] = 0; 
    	em[276] = 261; em[277] = 0; 
    	em[278] = 314; em[279] = 0; 
    	em[280] = 242; em[281] = 0; 
    	em[282] = 237; em[283] = 0; 
    	em[284] = 232; em[285] = 0; 
    	em[286] = 227; em[287] = 0; 
    	em[288] = 222; em[289] = 0; 
    	em[290] = 319; em[291] = 0; 
    	em[292] = 217; em[293] = 0; 
    	em[294] = 324; em[295] = 0; 
    	em[296] = 212; em[297] = 0; 
    	em[298] = 247; em[299] = 0; 
    	em[300] = 207; em[301] = 0; 
    	em[302] = 202; em[303] = 0; 
    	em[304] = 192; em[305] = 0; 
    	em[306] = 329; em[307] = 0; 
    	em[308] = 261; em[309] = 0; 
    	em[310] = 261; em[311] = 0; 
    	em[312] = 187; em[313] = 0; 
    em[314] = 1; em[315] = 8; em[316] = 1; /* 314: pointer.struct.asn1_object_st */
    	em[317] = 252; em[318] = 0; 
    em[319] = 1; em[320] = 8; em[321] = 1; /* 319: pointer.struct.asn1_string_st */
    	em[322] = 197; em[323] = 0; 
    em[324] = 1; em[325] = 8; em[326] = 1; /* 324: pointer.struct.asn1_string_st */
    	em[327] = 197; em[328] = 0; 
    em[329] = 1; em[330] = 8; em[331] = 1; /* 329: pointer.struct.asn1_string_st */
    	em[332] = 197; em[333] = 0; 
    em[334] = 0; em[335] = 0; em[336] = 1; /* 334: ASN1_TYPE */
    	em[337] = 266; em[338] = 0; 
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
    	em[369] = 130; em[370] = 0; 
    	em[371] = 339; em[372] = 0; 
    	em[373] = 375; em[374] = 0; 
    em[375] = 1; em[376] = 8; em[377] = 1; /* 375: pointer.struct.asn1_type_st */
    	em[378] = 179; em[379] = 0; 
    em[380] = 0; em[381] = 8; em[382] = 0; /* 380: long unsigned int */
    em[383] = 1; em[384] = 8; em[385] = 1; /* 383: pointer.struct.engine_st */
    	em[386] = 388; em[387] = 0; 
    em[388] = 0; em[389] = 216; em[390] = 24; /* 388: struct.engine_st */
    	em[391] = 149; em[392] = 0; 
    	em[393] = 149; em[394] = 8; 
    	em[395] = 439; em[396] = 16; 
    	em[397] = 494; em[398] = 24; 
    	em[399] = 545; em[400] = 32; 
    	em[401] = 581; em[402] = 40; 
    	em[403] = 598; em[404] = 48; 
    	em[405] = 625; em[406] = 56; 
    	em[407] = 660; em[408] = 64; 
    	em[409] = 668; em[410] = 72; 
    	em[411] = 671; em[412] = 80; 
    	em[413] = 674; em[414] = 88; 
    	em[415] = 677; em[416] = 96; 
    	em[417] = 680; em[418] = 104; 
    	em[419] = 680; em[420] = 112; 
    	em[421] = 680; em[422] = 120; 
    	em[423] = 683; em[424] = 128; 
    	em[425] = 686; em[426] = 136; 
    	em[427] = 686; em[428] = 144; 
    	em[429] = 689; em[430] = 152; 
    	em[431] = 692; em[432] = 160; 
    	em[433] = 704; em[434] = 184; 
    	em[435] = 721; em[436] = 200; 
    	em[437] = 721; em[438] = 208; 
    em[439] = 1; em[440] = 8; em[441] = 1; /* 439: pointer.struct.rsa_meth_st */
    	em[442] = 444; em[443] = 0; 
    em[444] = 0; em[445] = 112; em[446] = 13; /* 444: struct.rsa_meth_st */
    	em[447] = 149; em[448] = 0; 
    	em[449] = 473; em[450] = 8; 
    	em[451] = 473; em[452] = 16; 
    	em[453] = 473; em[454] = 24; 
    	em[455] = 473; em[456] = 32; 
    	em[457] = 476; em[458] = 40; 
    	em[459] = 479; em[460] = 48; 
    	em[461] = 482; em[462] = 56; 
    	em[463] = 482; em[464] = 64; 
    	em[465] = 130; em[466] = 80; 
    	em[467] = 485; em[468] = 88; 
    	em[469] = 488; em[470] = 96; 
    	em[471] = 491; em[472] = 104; 
    em[473] = 8884097; em[474] = 8; em[475] = 0; /* 473: pointer.func */
    em[476] = 8884097; em[477] = 8; em[478] = 0; /* 476: pointer.func */
    em[479] = 8884097; em[480] = 8; em[481] = 0; /* 479: pointer.func */
    em[482] = 8884097; em[483] = 8; em[484] = 0; /* 482: pointer.func */
    em[485] = 8884097; em[486] = 8; em[487] = 0; /* 485: pointer.func */
    em[488] = 8884097; em[489] = 8; em[490] = 0; /* 488: pointer.func */
    em[491] = 8884097; em[492] = 8; em[493] = 0; /* 491: pointer.func */
    em[494] = 1; em[495] = 8; em[496] = 1; /* 494: pointer.struct.dsa_method */
    	em[497] = 499; em[498] = 0; 
    em[499] = 0; em[500] = 96; em[501] = 11; /* 499: struct.dsa_method */
    	em[502] = 149; em[503] = 0; 
    	em[504] = 524; em[505] = 8; 
    	em[506] = 527; em[507] = 16; 
    	em[508] = 530; em[509] = 24; 
    	em[510] = 533; em[511] = 32; 
    	em[512] = 536; em[513] = 40; 
    	em[514] = 539; em[515] = 48; 
    	em[516] = 539; em[517] = 56; 
    	em[518] = 130; em[519] = 72; 
    	em[520] = 542; em[521] = 80; 
    	em[522] = 539; em[523] = 88; 
    em[524] = 8884097; em[525] = 8; em[526] = 0; /* 524: pointer.func */
    em[527] = 8884097; em[528] = 8; em[529] = 0; /* 527: pointer.func */
    em[530] = 8884097; em[531] = 8; em[532] = 0; /* 530: pointer.func */
    em[533] = 8884097; em[534] = 8; em[535] = 0; /* 533: pointer.func */
    em[536] = 8884097; em[537] = 8; em[538] = 0; /* 536: pointer.func */
    em[539] = 8884097; em[540] = 8; em[541] = 0; /* 539: pointer.func */
    em[542] = 8884097; em[543] = 8; em[544] = 0; /* 542: pointer.func */
    em[545] = 1; em[546] = 8; em[547] = 1; /* 545: pointer.struct.dh_method */
    	em[548] = 550; em[549] = 0; 
    em[550] = 0; em[551] = 72; em[552] = 8; /* 550: struct.dh_method */
    	em[553] = 149; em[554] = 0; 
    	em[555] = 569; em[556] = 8; 
    	em[557] = 572; em[558] = 16; 
    	em[559] = 575; em[560] = 24; 
    	em[561] = 569; em[562] = 32; 
    	em[563] = 569; em[564] = 40; 
    	em[565] = 130; em[566] = 56; 
    	em[567] = 578; em[568] = 64; 
    em[569] = 8884097; em[570] = 8; em[571] = 0; /* 569: pointer.func */
    em[572] = 8884097; em[573] = 8; em[574] = 0; /* 572: pointer.func */
    em[575] = 8884097; em[576] = 8; em[577] = 0; /* 575: pointer.func */
    em[578] = 8884097; em[579] = 8; em[580] = 0; /* 578: pointer.func */
    em[581] = 1; em[582] = 8; em[583] = 1; /* 581: pointer.struct.ecdh_method */
    	em[584] = 586; em[585] = 0; 
    em[586] = 0; em[587] = 32; em[588] = 3; /* 586: struct.ecdh_method */
    	em[589] = 149; em[590] = 0; 
    	em[591] = 595; em[592] = 8; 
    	em[593] = 130; em[594] = 24; 
    em[595] = 8884097; em[596] = 8; em[597] = 0; /* 595: pointer.func */
    em[598] = 1; em[599] = 8; em[600] = 1; /* 598: pointer.struct.ecdsa_method */
    	em[601] = 603; em[602] = 0; 
    em[603] = 0; em[604] = 48; em[605] = 5; /* 603: struct.ecdsa_method */
    	em[606] = 149; em[607] = 0; 
    	em[608] = 616; em[609] = 8; 
    	em[610] = 619; em[611] = 16; 
    	em[612] = 622; em[613] = 24; 
    	em[614] = 130; em[615] = 40; 
    em[616] = 8884097; em[617] = 8; em[618] = 0; /* 616: pointer.func */
    em[619] = 8884097; em[620] = 8; em[621] = 0; /* 619: pointer.func */
    em[622] = 8884097; em[623] = 8; em[624] = 0; /* 622: pointer.func */
    em[625] = 1; em[626] = 8; em[627] = 1; /* 625: pointer.struct.rand_meth_st */
    	em[628] = 630; em[629] = 0; 
    em[630] = 0; em[631] = 48; em[632] = 6; /* 630: struct.rand_meth_st */
    	em[633] = 645; em[634] = 0; 
    	em[635] = 648; em[636] = 8; 
    	em[637] = 651; em[638] = 16; 
    	em[639] = 654; em[640] = 24; 
    	em[641] = 648; em[642] = 32; 
    	em[643] = 657; em[644] = 40; 
    em[645] = 8884097; em[646] = 8; em[647] = 0; /* 645: pointer.func */
    em[648] = 8884097; em[649] = 8; em[650] = 0; /* 648: pointer.func */
    em[651] = 8884097; em[652] = 8; em[653] = 0; /* 651: pointer.func */
    em[654] = 8884097; em[655] = 8; em[656] = 0; /* 654: pointer.func */
    em[657] = 8884097; em[658] = 8; em[659] = 0; /* 657: pointer.func */
    em[660] = 1; em[661] = 8; em[662] = 1; /* 660: pointer.struct.store_method_st */
    	em[663] = 665; em[664] = 0; 
    em[665] = 0; em[666] = 0; em[667] = 0; /* 665: struct.store_method_st */
    em[668] = 8884097; em[669] = 8; em[670] = 0; /* 668: pointer.func */
    em[671] = 8884097; em[672] = 8; em[673] = 0; /* 671: pointer.func */
    em[674] = 8884097; em[675] = 8; em[676] = 0; /* 674: pointer.func */
    em[677] = 8884097; em[678] = 8; em[679] = 0; /* 677: pointer.func */
    em[680] = 8884097; em[681] = 8; em[682] = 0; /* 680: pointer.func */
    em[683] = 8884097; em[684] = 8; em[685] = 0; /* 683: pointer.func */
    em[686] = 8884097; em[687] = 8; em[688] = 0; /* 686: pointer.func */
    em[689] = 8884097; em[690] = 8; em[691] = 0; /* 689: pointer.func */
    em[692] = 1; em[693] = 8; em[694] = 1; /* 692: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[695] = 697; em[696] = 0; 
    em[697] = 0; em[698] = 32; em[699] = 2; /* 697: struct.ENGINE_CMD_DEFN_st */
    	em[700] = 149; em[701] = 8; 
    	em[702] = 149; em[703] = 16; 
    em[704] = 0; em[705] = 32; em[706] = 2; /* 704: struct.crypto_ex_data_st_fake */
    	em[707] = 711; em[708] = 8; 
    	em[709] = 363; em[710] = 24; 
    em[711] = 8884099; em[712] = 8; em[713] = 2; /* 711: pointer_to_array_of_pointers_to_stack */
    	em[714] = 718; em[715] = 0; 
    	em[716] = 5; em[717] = 20; 
    em[718] = 0; em[719] = 8; em[720] = 0; /* 718: pointer.void */
    em[721] = 1; em[722] = 8; em[723] = 1; /* 721: pointer.struct.engine_st */
    	em[724] = 388; em[725] = 0; 
    em[726] = 8884097; em[727] = 8; em[728] = 0; /* 726: pointer.func */
    em[729] = 8884097; em[730] = 8; em[731] = 0; /* 729: pointer.func */
    em[732] = 8884097; em[733] = 8; em[734] = 0; /* 732: pointer.func */
    em[735] = 0; em[736] = 112; em[737] = 13; /* 735: struct.rsa_meth_st */
    	em[738] = 149; em[739] = 0; 
    	em[740] = 729; em[741] = 8; 
    	em[742] = 729; em[743] = 16; 
    	em[744] = 729; em[745] = 24; 
    	em[746] = 729; em[747] = 32; 
    	em[748] = 764; em[749] = 40; 
    	em[750] = 767; em[751] = 48; 
    	em[752] = 770; em[753] = 56; 
    	em[754] = 770; em[755] = 64; 
    	em[756] = 130; em[757] = 80; 
    	em[758] = 773; em[759] = 88; 
    	em[760] = 776; em[761] = 96; 
    	em[762] = 726; em[763] = 104; 
    em[764] = 8884097; em[765] = 8; em[766] = 0; /* 764: pointer.func */
    em[767] = 8884097; em[768] = 8; em[769] = 0; /* 767: pointer.func */
    em[770] = 8884097; em[771] = 8; em[772] = 0; /* 770: pointer.func */
    em[773] = 8884097; em[774] = 8; em[775] = 0; /* 773: pointer.func */
    em[776] = 8884097; em[777] = 8; em[778] = 0; /* 776: pointer.func */
    em[779] = 0; em[780] = 1; em[781] = 0; /* 779: char */
    em[782] = 0; em[783] = 24; em[784] = 1; /* 782: struct.bignum_st */
    	em[785] = 787; em[786] = 0; 
    em[787] = 8884099; em[788] = 8; em[789] = 2; /* 787: pointer_to_array_of_pointers_to_stack */
    	em[790] = 380; em[791] = 0; 
    	em[792] = 5; em[793] = 12; 
    em[794] = 0; em[795] = 232; em[796] = 12; /* 794: struct.ec_group_st */
    	em[797] = 821; em[798] = 0; 
    	em[799] = 990; em[800] = 8; 
    	em[801] = 1178; em[802] = 16; 
    	em[803] = 1178; em[804] = 40; 
    	em[805] = 29; em[806] = 80; 
    	em[807] = 1190; em[808] = 96; 
    	em[809] = 1178; em[810] = 104; 
    	em[811] = 1178; em[812] = 152; 
    	em[813] = 1178; em[814] = 176; 
    	em[815] = 718; em[816] = 208; 
    	em[817] = 718; em[818] = 216; 
    	em[819] = 1219; em[820] = 224; 
    em[821] = 1; em[822] = 8; em[823] = 1; /* 821: pointer.struct.ec_method_st */
    	em[824] = 826; em[825] = 0; 
    em[826] = 0; em[827] = 304; em[828] = 37; /* 826: struct.ec_method_st */
    	em[829] = 903; em[830] = 8; 
    	em[831] = 906; em[832] = 16; 
    	em[833] = 906; em[834] = 24; 
    	em[835] = 909; em[836] = 32; 
    	em[837] = 912; em[838] = 40; 
    	em[839] = 915; em[840] = 48; 
    	em[841] = 918; em[842] = 56; 
    	em[843] = 921; em[844] = 64; 
    	em[845] = 924; em[846] = 72; 
    	em[847] = 927; em[848] = 80; 
    	em[849] = 927; em[850] = 88; 
    	em[851] = 930; em[852] = 96; 
    	em[853] = 933; em[854] = 104; 
    	em[855] = 936; em[856] = 112; 
    	em[857] = 939; em[858] = 120; 
    	em[859] = 942; em[860] = 128; 
    	em[861] = 945; em[862] = 136; 
    	em[863] = 948; em[864] = 144; 
    	em[865] = 951; em[866] = 152; 
    	em[867] = 954; em[868] = 160; 
    	em[869] = 957; em[870] = 168; 
    	em[871] = 960; em[872] = 176; 
    	em[873] = 963; em[874] = 184; 
    	em[875] = 966; em[876] = 192; 
    	em[877] = 969; em[878] = 200; 
    	em[879] = 972; em[880] = 208; 
    	em[881] = 963; em[882] = 216; 
    	em[883] = 975; em[884] = 224; 
    	em[885] = 978; em[886] = 232; 
    	em[887] = 732; em[888] = 240; 
    	em[889] = 918; em[890] = 248; 
    	em[891] = 981; em[892] = 256; 
    	em[893] = 984; em[894] = 264; 
    	em[895] = 981; em[896] = 272; 
    	em[897] = 984; em[898] = 280; 
    	em[899] = 984; em[900] = 288; 
    	em[901] = 987; em[902] = 296; 
    em[903] = 8884097; em[904] = 8; em[905] = 0; /* 903: pointer.func */
    em[906] = 8884097; em[907] = 8; em[908] = 0; /* 906: pointer.func */
    em[909] = 8884097; em[910] = 8; em[911] = 0; /* 909: pointer.func */
    em[912] = 8884097; em[913] = 8; em[914] = 0; /* 912: pointer.func */
    em[915] = 8884097; em[916] = 8; em[917] = 0; /* 915: pointer.func */
    em[918] = 8884097; em[919] = 8; em[920] = 0; /* 918: pointer.func */
    em[921] = 8884097; em[922] = 8; em[923] = 0; /* 921: pointer.func */
    em[924] = 8884097; em[925] = 8; em[926] = 0; /* 924: pointer.func */
    em[927] = 8884097; em[928] = 8; em[929] = 0; /* 927: pointer.func */
    em[930] = 8884097; em[931] = 8; em[932] = 0; /* 930: pointer.func */
    em[933] = 8884097; em[934] = 8; em[935] = 0; /* 933: pointer.func */
    em[936] = 8884097; em[937] = 8; em[938] = 0; /* 936: pointer.func */
    em[939] = 8884097; em[940] = 8; em[941] = 0; /* 939: pointer.func */
    em[942] = 8884097; em[943] = 8; em[944] = 0; /* 942: pointer.func */
    em[945] = 8884097; em[946] = 8; em[947] = 0; /* 945: pointer.func */
    em[948] = 8884097; em[949] = 8; em[950] = 0; /* 948: pointer.func */
    em[951] = 8884097; em[952] = 8; em[953] = 0; /* 951: pointer.func */
    em[954] = 8884097; em[955] = 8; em[956] = 0; /* 954: pointer.func */
    em[957] = 8884097; em[958] = 8; em[959] = 0; /* 957: pointer.func */
    em[960] = 8884097; em[961] = 8; em[962] = 0; /* 960: pointer.func */
    em[963] = 8884097; em[964] = 8; em[965] = 0; /* 963: pointer.func */
    em[966] = 8884097; em[967] = 8; em[968] = 0; /* 966: pointer.func */
    em[969] = 8884097; em[970] = 8; em[971] = 0; /* 969: pointer.func */
    em[972] = 8884097; em[973] = 8; em[974] = 0; /* 972: pointer.func */
    em[975] = 8884097; em[976] = 8; em[977] = 0; /* 975: pointer.func */
    em[978] = 8884097; em[979] = 8; em[980] = 0; /* 978: pointer.func */
    em[981] = 8884097; em[982] = 8; em[983] = 0; /* 981: pointer.func */
    em[984] = 8884097; em[985] = 8; em[986] = 0; /* 984: pointer.func */
    em[987] = 8884097; em[988] = 8; em[989] = 0; /* 987: pointer.func */
    em[990] = 1; em[991] = 8; em[992] = 1; /* 990: pointer.struct.ec_point_st */
    	em[993] = 995; em[994] = 0; 
    em[995] = 0; em[996] = 88; em[997] = 4; /* 995: struct.ec_point_st */
    	em[998] = 1006; em[999] = 0; 
    	em[1000] = 782; em[1001] = 8; 
    	em[1002] = 782; em[1003] = 32; 
    	em[1004] = 782; em[1005] = 56; 
    em[1006] = 1; em[1007] = 8; em[1008] = 1; /* 1006: pointer.struct.ec_method_st */
    	em[1009] = 1011; em[1010] = 0; 
    em[1011] = 0; em[1012] = 304; em[1013] = 37; /* 1011: struct.ec_method_st */
    	em[1014] = 1088; em[1015] = 8; 
    	em[1016] = 1091; em[1017] = 16; 
    	em[1018] = 1091; em[1019] = 24; 
    	em[1020] = 1094; em[1021] = 32; 
    	em[1022] = 1097; em[1023] = 40; 
    	em[1024] = 1100; em[1025] = 48; 
    	em[1026] = 1103; em[1027] = 56; 
    	em[1028] = 1106; em[1029] = 64; 
    	em[1030] = 1109; em[1031] = 72; 
    	em[1032] = 1112; em[1033] = 80; 
    	em[1034] = 1112; em[1035] = 88; 
    	em[1036] = 1115; em[1037] = 96; 
    	em[1038] = 1118; em[1039] = 104; 
    	em[1040] = 1121; em[1041] = 112; 
    	em[1042] = 1124; em[1043] = 120; 
    	em[1044] = 1127; em[1045] = 128; 
    	em[1046] = 1130; em[1047] = 136; 
    	em[1048] = 1133; em[1049] = 144; 
    	em[1050] = 1136; em[1051] = 152; 
    	em[1052] = 1139; em[1053] = 160; 
    	em[1054] = 1142; em[1055] = 168; 
    	em[1056] = 1145; em[1057] = 176; 
    	em[1058] = 1148; em[1059] = 184; 
    	em[1060] = 1151; em[1061] = 192; 
    	em[1062] = 1154; em[1063] = 200; 
    	em[1064] = 1157; em[1065] = 208; 
    	em[1066] = 1148; em[1067] = 216; 
    	em[1068] = 1160; em[1069] = 224; 
    	em[1070] = 1163; em[1071] = 232; 
    	em[1072] = 1166; em[1073] = 240; 
    	em[1074] = 1103; em[1075] = 248; 
    	em[1076] = 1169; em[1077] = 256; 
    	em[1078] = 1172; em[1079] = 264; 
    	em[1080] = 1169; em[1081] = 272; 
    	em[1082] = 1172; em[1083] = 280; 
    	em[1084] = 1172; em[1085] = 288; 
    	em[1086] = 1175; em[1087] = 296; 
    em[1088] = 8884097; em[1089] = 8; em[1090] = 0; /* 1088: pointer.func */
    em[1091] = 8884097; em[1092] = 8; em[1093] = 0; /* 1091: pointer.func */
    em[1094] = 8884097; em[1095] = 8; em[1096] = 0; /* 1094: pointer.func */
    em[1097] = 8884097; em[1098] = 8; em[1099] = 0; /* 1097: pointer.func */
    em[1100] = 8884097; em[1101] = 8; em[1102] = 0; /* 1100: pointer.func */
    em[1103] = 8884097; em[1104] = 8; em[1105] = 0; /* 1103: pointer.func */
    em[1106] = 8884097; em[1107] = 8; em[1108] = 0; /* 1106: pointer.func */
    em[1109] = 8884097; em[1110] = 8; em[1111] = 0; /* 1109: pointer.func */
    em[1112] = 8884097; em[1113] = 8; em[1114] = 0; /* 1112: pointer.func */
    em[1115] = 8884097; em[1116] = 8; em[1117] = 0; /* 1115: pointer.func */
    em[1118] = 8884097; em[1119] = 8; em[1120] = 0; /* 1118: pointer.func */
    em[1121] = 8884097; em[1122] = 8; em[1123] = 0; /* 1121: pointer.func */
    em[1124] = 8884097; em[1125] = 8; em[1126] = 0; /* 1124: pointer.func */
    em[1127] = 8884097; em[1128] = 8; em[1129] = 0; /* 1127: pointer.func */
    em[1130] = 8884097; em[1131] = 8; em[1132] = 0; /* 1130: pointer.func */
    em[1133] = 8884097; em[1134] = 8; em[1135] = 0; /* 1133: pointer.func */
    em[1136] = 8884097; em[1137] = 8; em[1138] = 0; /* 1136: pointer.func */
    em[1139] = 8884097; em[1140] = 8; em[1141] = 0; /* 1139: pointer.func */
    em[1142] = 8884097; em[1143] = 8; em[1144] = 0; /* 1142: pointer.func */
    em[1145] = 8884097; em[1146] = 8; em[1147] = 0; /* 1145: pointer.func */
    em[1148] = 8884097; em[1149] = 8; em[1150] = 0; /* 1148: pointer.func */
    em[1151] = 8884097; em[1152] = 8; em[1153] = 0; /* 1151: pointer.func */
    em[1154] = 8884097; em[1155] = 8; em[1156] = 0; /* 1154: pointer.func */
    em[1157] = 8884097; em[1158] = 8; em[1159] = 0; /* 1157: pointer.func */
    em[1160] = 8884097; em[1161] = 8; em[1162] = 0; /* 1160: pointer.func */
    em[1163] = 8884097; em[1164] = 8; em[1165] = 0; /* 1163: pointer.func */
    em[1166] = 8884097; em[1167] = 8; em[1168] = 0; /* 1166: pointer.func */
    em[1169] = 8884097; em[1170] = 8; em[1171] = 0; /* 1169: pointer.func */
    em[1172] = 8884097; em[1173] = 8; em[1174] = 0; /* 1172: pointer.func */
    em[1175] = 8884097; em[1176] = 8; em[1177] = 0; /* 1175: pointer.func */
    em[1178] = 0; em[1179] = 24; em[1180] = 1; /* 1178: struct.bignum_st */
    	em[1181] = 1183; em[1182] = 0; 
    em[1183] = 8884099; em[1184] = 8; em[1185] = 2; /* 1183: pointer_to_array_of_pointers_to_stack */
    	em[1186] = 380; em[1187] = 0; 
    	em[1188] = 5; em[1189] = 12; 
    em[1190] = 1; em[1191] = 8; em[1192] = 1; /* 1190: pointer.struct.ec_extra_data_st */
    	em[1193] = 1195; em[1194] = 0; 
    em[1195] = 0; em[1196] = 40; em[1197] = 5; /* 1195: struct.ec_extra_data_st */
    	em[1198] = 1208; em[1199] = 0; 
    	em[1200] = 718; em[1201] = 8; 
    	em[1202] = 1213; em[1203] = 16; 
    	em[1204] = 1216; em[1205] = 24; 
    	em[1206] = 1216; em[1207] = 32; 
    em[1208] = 1; em[1209] = 8; em[1210] = 1; /* 1208: pointer.struct.ec_extra_data_st */
    	em[1211] = 1195; em[1212] = 0; 
    em[1213] = 8884097; em[1214] = 8; em[1215] = 0; /* 1213: pointer.func */
    em[1216] = 8884097; em[1217] = 8; em[1218] = 0; /* 1216: pointer.func */
    em[1219] = 8884097; em[1220] = 8; em[1221] = 0; /* 1219: pointer.func */
    em[1222] = 0; em[1223] = 56; em[1224] = 4; /* 1222: struct.evp_pkey_st */
    	em[1225] = 1233; em[1226] = 16; 
    	em[1227] = 1334; em[1228] = 24; 
    	em[1229] = 1339; em[1230] = 32; 
    	em[1231] = 1820; em[1232] = 48; 
    em[1233] = 1; em[1234] = 8; em[1235] = 1; /* 1233: pointer.struct.evp_pkey_asn1_method_st */
    	em[1236] = 1238; em[1237] = 0; 
    em[1238] = 0; em[1239] = 208; em[1240] = 24; /* 1238: struct.evp_pkey_asn1_method_st */
    	em[1241] = 130; em[1242] = 16; 
    	em[1243] = 130; em[1244] = 24; 
    	em[1245] = 1289; em[1246] = 32; 
    	em[1247] = 1292; em[1248] = 40; 
    	em[1249] = 1295; em[1250] = 48; 
    	em[1251] = 1298; em[1252] = 56; 
    	em[1253] = 1301; em[1254] = 64; 
    	em[1255] = 1304; em[1256] = 72; 
    	em[1257] = 1298; em[1258] = 80; 
    	em[1259] = 1307; em[1260] = 88; 
    	em[1261] = 1307; em[1262] = 96; 
    	em[1263] = 1310; em[1264] = 104; 
    	em[1265] = 1313; em[1266] = 112; 
    	em[1267] = 1307; em[1268] = 120; 
    	em[1269] = 1316; em[1270] = 128; 
    	em[1271] = 1295; em[1272] = 136; 
    	em[1273] = 1298; em[1274] = 144; 
    	em[1275] = 1319; em[1276] = 152; 
    	em[1277] = 1322; em[1278] = 160; 
    	em[1279] = 1325; em[1280] = 168; 
    	em[1281] = 1310; em[1282] = 176; 
    	em[1283] = 1313; em[1284] = 184; 
    	em[1285] = 1328; em[1286] = 192; 
    	em[1287] = 1331; em[1288] = 200; 
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
    em[1334] = 1; em[1335] = 8; em[1336] = 1; /* 1334: pointer.struct.engine_st */
    	em[1337] = 388; em[1338] = 0; 
    em[1339] = 0; em[1340] = 8; em[1341] = 5; /* 1339: union.unknown */
    	em[1342] = 130; em[1343] = 0; 
    	em[1344] = 1352; em[1345] = 0; 
    	em[1346] = 1505; em[1347] = 0; 
    	em[1348] = 1636; em[1349] = 0; 
    	em[1350] = 1754; em[1351] = 0; 
    em[1352] = 1; em[1353] = 8; em[1354] = 1; /* 1352: pointer.struct.rsa_st */
    	em[1355] = 1357; em[1356] = 0; 
    em[1357] = 0; em[1358] = 168; em[1359] = 17; /* 1357: struct.rsa_st */
    	em[1360] = 1394; em[1361] = 16; 
    	em[1362] = 383; em[1363] = 24; 
    	em[1364] = 1399; em[1365] = 32; 
    	em[1366] = 1399; em[1367] = 40; 
    	em[1368] = 1399; em[1369] = 48; 
    	em[1370] = 1399; em[1371] = 56; 
    	em[1372] = 1399; em[1373] = 64; 
    	em[1374] = 1399; em[1375] = 72; 
    	em[1376] = 1399; em[1377] = 80; 
    	em[1378] = 1399; em[1379] = 88; 
    	em[1380] = 1416; em[1381] = 96; 
    	em[1382] = 1430; em[1383] = 120; 
    	em[1384] = 1430; em[1385] = 128; 
    	em[1386] = 1430; em[1387] = 136; 
    	em[1388] = 130; em[1389] = 144; 
    	em[1390] = 1444; em[1391] = 152; 
    	em[1392] = 1444; em[1393] = 160; 
    em[1394] = 1; em[1395] = 8; em[1396] = 1; /* 1394: pointer.struct.rsa_meth_st */
    	em[1397] = 735; em[1398] = 0; 
    em[1399] = 1; em[1400] = 8; em[1401] = 1; /* 1399: pointer.struct.bignum_st */
    	em[1402] = 1404; em[1403] = 0; 
    em[1404] = 0; em[1405] = 24; em[1406] = 1; /* 1404: struct.bignum_st */
    	em[1407] = 1409; em[1408] = 0; 
    em[1409] = 8884099; em[1410] = 8; em[1411] = 2; /* 1409: pointer_to_array_of_pointers_to_stack */
    	em[1412] = 380; em[1413] = 0; 
    	em[1414] = 5; em[1415] = 12; 
    em[1416] = 0; em[1417] = 32; em[1418] = 2; /* 1416: struct.crypto_ex_data_st_fake */
    	em[1419] = 1423; em[1420] = 8; 
    	em[1421] = 363; em[1422] = 24; 
    em[1423] = 8884099; em[1424] = 8; em[1425] = 2; /* 1423: pointer_to_array_of_pointers_to_stack */
    	em[1426] = 718; em[1427] = 0; 
    	em[1428] = 5; em[1429] = 20; 
    em[1430] = 1; em[1431] = 8; em[1432] = 1; /* 1430: pointer.struct.bn_mont_ctx_st */
    	em[1433] = 1435; em[1434] = 0; 
    em[1435] = 0; em[1436] = 96; em[1437] = 3; /* 1435: struct.bn_mont_ctx_st */
    	em[1438] = 1404; em[1439] = 8; 
    	em[1440] = 1404; em[1441] = 32; 
    	em[1442] = 1404; em[1443] = 56; 
    em[1444] = 1; em[1445] = 8; em[1446] = 1; /* 1444: pointer.struct.bn_blinding_st */
    	em[1447] = 1449; em[1448] = 0; 
    em[1449] = 0; em[1450] = 88; em[1451] = 7; /* 1449: struct.bn_blinding_st */
    	em[1452] = 1466; em[1453] = 0; 
    	em[1454] = 1466; em[1455] = 8; 
    	em[1456] = 1466; em[1457] = 16; 
    	em[1458] = 1466; em[1459] = 24; 
    	em[1460] = 1483; em[1461] = 40; 
    	em[1462] = 1488; em[1463] = 72; 
    	em[1464] = 1502; em[1465] = 80; 
    em[1466] = 1; em[1467] = 8; em[1468] = 1; /* 1466: pointer.struct.bignum_st */
    	em[1469] = 1471; em[1470] = 0; 
    em[1471] = 0; em[1472] = 24; em[1473] = 1; /* 1471: struct.bignum_st */
    	em[1474] = 1476; em[1475] = 0; 
    em[1476] = 8884099; em[1477] = 8; em[1478] = 2; /* 1476: pointer_to_array_of_pointers_to_stack */
    	em[1479] = 380; em[1480] = 0; 
    	em[1481] = 5; em[1482] = 12; 
    em[1483] = 0; em[1484] = 16; em[1485] = 1; /* 1483: struct.crypto_threadid_st */
    	em[1486] = 718; em[1487] = 0; 
    em[1488] = 1; em[1489] = 8; em[1490] = 1; /* 1488: pointer.struct.bn_mont_ctx_st */
    	em[1491] = 1493; em[1492] = 0; 
    em[1493] = 0; em[1494] = 96; em[1495] = 3; /* 1493: struct.bn_mont_ctx_st */
    	em[1496] = 1471; em[1497] = 8; 
    	em[1498] = 1471; em[1499] = 32; 
    	em[1500] = 1471; em[1501] = 56; 
    em[1502] = 8884097; em[1503] = 8; em[1504] = 0; /* 1502: pointer.func */
    em[1505] = 1; em[1506] = 8; em[1507] = 1; /* 1505: pointer.struct.dsa_st */
    	em[1508] = 1510; em[1509] = 0; 
    em[1510] = 0; em[1511] = 136; em[1512] = 11; /* 1510: struct.dsa_st */
    	em[1513] = 1535; em[1514] = 24; 
    	em[1515] = 1535; em[1516] = 32; 
    	em[1517] = 1535; em[1518] = 40; 
    	em[1519] = 1535; em[1520] = 48; 
    	em[1521] = 1535; em[1522] = 56; 
    	em[1523] = 1535; em[1524] = 64; 
    	em[1525] = 1535; em[1526] = 72; 
    	em[1527] = 1552; em[1528] = 88; 
    	em[1529] = 1566; em[1530] = 104; 
    	em[1531] = 1580; em[1532] = 120; 
    	em[1533] = 1631; em[1534] = 128; 
    em[1535] = 1; em[1536] = 8; em[1537] = 1; /* 1535: pointer.struct.bignum_st */
    	em[1538] = 1540; em[1539] = 0; 
    em[1540] = 0; em[1541] = 24; em[1542] = 1; /* 1540: struct.bignum_st */
    	em[1543] = 1545; em[1544] = 0; 
    em[1545] = 8884099; em[1546] = 8; em[1547] = 2; /* 1545: pointer_to_array_of_pointers_to_stack */
    	em[1548] = 380; em[1549] = 0; 
    	em[1550] = 5; em[1551] = 12; 
    em[1552] = 1; em[1553] = 8; em[1554] = 1; /* 1552: pointer.struct.bn_mont_ctx_st */
    	em[1555] = 1557; em[1556] = 0; 
    em[1557] = 0; em[1558] = 96; em[1559] = 3; /* 1557: struct.bn_mont_ctx_st */
    	em[1560] = 1540; em[1561] = 8; 
    	em[1562] = 1540; em[1563] = 32; 
    	em[1564] = 1540; em[1565] = 56; 
    em[1566] = 0; em[1567] = 32; em[1568] = 2; /* 1566: struct.crypto_ex_data_st_fake */
    	em[1569] = 1573; em[1570] = 8; 
    	em[1571] = 363; em[1572] = 24; 
    em[1573] = 8884099; em[1574] = 8; em[1575] = 2; /* 1573: pointer_to_array_of_pointers_to_stack */
    	em[1576] = 718; em[1577] = 0; 
    	em[1578] = 5; em[1579] = 20; 
    em[1580] = 1; em[1581] = 8; em[1582] = 1; /* 1580: pointer.struct.dsa_method */
    	em[1583] = 1585; em[1584] = 0; 
    em[1585] = 0; em[1586] = 96; em[1587] = 11; /* 1585: struct.dsa_method */
    	em[1588] = 149; em[1589] = 0; 
    	em[1590] = 1610; em[1591] = 8; 
    	em[1592] = 1613; em[1593] = 16; 
    	em[1594] = 1616; em[1595] = 24; 
    	em[1596] = 1619; em[1597] = 32; 
    	em[1598] = 1622; em[1599] = 40; 
    	em[1600] = 1625; em[1601] = 48; 
    	em[1602] = 1625; em[1603] = 56; 
    	em[1604] = 130; em[1605] = 72; 
    	em[1606] = 1628; em[1607] = 80; 
    	em[1608] = 1625; em[1609] = 88; 
    em[1610] = 8884097; em[1611] = 8; em[1612] = 0; /* 1610: pointer.func */
    em[1613] = 8884097; em[1614] = 8; em[1615] = 0; /* 1613: pointer.func */
    em[1616] = 8884097; em[1617] = 8; em[1618] = 0; /* 1616: pointer.func */
    em[1619] = 8884097; em[1620] = 8; em[1621] = 0; /* 1619: pointer.func */
    em[1622] = 8884097; em[1623] = 8; em[1624] = 0; /* 1622: pointer.func */
    em[1625] = 8884097; em[1626] = 8; em[1627] = 0; /* 1625: pointer.func */
    em[1628] = 8884097; em[1629] = 8; em[1630] = 0; /* 1628: pointer.func */
    em[1631] = 1; em[1632] = 8; em[1633] = 1; /* 1631: pointer.struct.engine_st */
    	em[1634] = 388; em[1635] = 0; 
    em[1636] = 1; em[1637] = 8; em[1638] = 1; /* 1636: pointer.struct.dh_st */
    	em[1639] = 1641; em[1640] = 0; 
    em[1641] = 0; em[1642] = 144; em[1643] = 12; /* 1641: struct.dh_st */
    	em[1644] = 1668; em[1645] = 8; 
    	em[1646] = 1668; em[1647] = 16; 
    	em[1648] = 1668; em[1649] = 32; 
    	em[1650] = 1668; em[1651] = 40; 
    	em[1652] = 1685; em[1653] = 56; 
    	em[1654] = 1668; em[1655] = 64; 
    	em[1656] = 1668; em[1657] = 72; 
    	em[1658] = 29; em[1659] = 80; 
    	em[1660] = 1668; em[1661] = 96; 
    	em[1662] = 1699; em[1663] = 112; 
    	em[1664] = 1713; em[1665] = 128; 
    	em[1666] = 1749; em[1667] = 136; 
    em[1668] = 1; em[1669] = 8; em[1670] = 1; /* 1668: pointer.struct.bignum_st */
    	em[1671] = 1673; em[1672] = 0; 
    em[1673] = 0; em[1674] = 24; em[1675] = 1; /* 1673: struct.bignum_st */
    	em[1676] = 1678; em[1677] = 0; 
    em[1678] = 8884099; em[1679] = 8; em[1680] = 2; /* 1678: pointer_to_array_of_pointers_to_stack */
    	em[1681] = 380; em[1682] = 0; 
    	em[1683] = 5; em[1684] = 12; 
    em[1685] = 1; em[1686] = 8; em[1687] = 1; /* 1685: pointer.struct.bn_mont_ctx_st */
    	em[1688] = 1690; em[1689] = 0; 
    em[1690] = 0; em[1691] = 96; em[1692] = 3; /* 1690: struct.bn_mont_ctx_st */
    	em[1693] = 1673; em[1694] = 8; 
    	em[1695] = 1673; em[1696] = 32; 
    	em[1697] = 1673; em[1698] = 56; 
    em[1699] = 0; em[1700] = 32; em[1701] = 2; /* 1699: struct.crypto_ex_data_st_fake */
    	em[1702] = 1706; em[1703] = 8; 
    	em[1704] = 363; em[1705] = 24; 
    em[1706] = 8884099; em[1707] = 8; em[1708] = 2; /* 1706: pointer_to_array_of_pointers_to_stack */
    	em[1709] = 718; em[1710] = 0; 
    	em[1711] = 5; em[1712] = 20; 
    em[1713] = 1; em[1714] = 8; em[1715] = 1; /* 1713: pointer.struct.dh_method */
    	em[1716] = 1718; em[1717] = 0; 
    em[1718] = 0; em[1719] = 72; em[1720] = 8; /* 1718: struct.dh_method */
    	em[1721] = 149; em[1722] = 0; 
    	em[1723] = 1737; em[1724] = 8; 
    	em[1725] = 1740; em[1726] = 16; 
    	em[1727] = 1743; em[1728] = 24; 
    	em[1729] = 1737; em[1730] = 32; 
    	em[1731] = 1737; em[1732] = 40; 
    	em[1733] = 130; em[1734] = 56; 
    	em[1735] = 1746; em[1736] = 64; 
    em[1737] = 8884097; em[1738] = 8; em[1739] = 0; /* 1737: pointer.func */
    em[1740] = 8884097; em[1741] = 8; em[1742] = 0; /* 1740: pointer.func */
    em[1743] = 8884097; em[1744] = 8; em[1745] = 0; /* 1743: pointer.func */
    em[1746] = 8884097; em[1747] = 8; em[1748] = 0; /* 1746: pointer.func */
    em[1749] = 1; em[1750] = 8; em[1751] = 1; /* 1749: pointer.struct.engine_st */
    	em[1752] = 388; em[1753] = 0; 
    em[1754] = 1; em[1755] = 8; em[1756] = 1; /* 1754: pointer.struct.ec_key_st */
    	em[1757] = 1759; em[1758] = 0; 
    em[1759] = 0; em[1760] = 56; em[1761] = 4; /* 1759: struct.ec_key_st */
    	em[1762] = 1770; em[1763] = 8; 
    	em[1764] = 1775; em[1765] = 16; 
    	em[1766] = 1780; em[1767] = 24; 
    	em[1768] = 1797; em[1769] = 48; 
    em[1770] = 1; em[1771] = 8; em[1772] = 1; /* 1770: pointer.struct.ec_group_st */
    	em[1773] = 794; em[1774] = 0; 
    em[1775] = 1; em[1776] = 8; em[1777] = 1; /* 1775: pointer.struct.ec_point_st */
    	em[1778] = 995; em[1779] = 0; 
    em[1780] = 1; em[1781] = 8; em[1782] = 1; /* 1780: pointer.struct.bignum_st */
    	em[1783] = 1785; em[1784] = 0; 
    em[1785] = 0; em[1786] = 24; em[1787] = 1; /* 1785: struct.bignum_st */
    	em[1788] = 1790; em[1789] = 0; 
    em[1790] = 8884099; em[1791] = 8; em[1792] = 2; /* 1790: pointer_to_array_of_pointers_to_stack */
    	em[1793] = 380; em[1794] = 0; 
    	em[1795] = 5; em[1796] = 12; 
    em[1797] = 1; em[1798] = 8; em[1799] = 1; /* 1797: pointer.struct.ec_extra_data_st */
    	em[1800] = 1802; em[1801] = 0; 
    em[1802] = 0; em[1803] = 40; em[1804] = 5; /* 1802: struct.ec_extra_data_st */
    	em[1805] = 1815; em[1806] = 0; 
    	em[1807] = 718; em[1808] = 8; 
    	em[1809] = 1213; em[1810] = 16; 
    	em[1811] = 1216; em[1812] = 24; 
    	em[1813] = 1216; em[1814] = 32; 
    em[1815] = 1; em[1816] = 8; em[1817] = 1; /* 1815: pointer.struct.ec_extra_data_st */
    	em[1818] = 1802; em[1819] = 0; 
    em[1820] = 1; em[1821] = 8; em[1822] = 1; /* 1820: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1823] = 1825; em[1824] = 0; 
    em[1825] = 0; em[1826] = 32; em[1827] = 2; /* 1825: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1828] = 1832; em[1829] = 8; 
    	em[1830] = 363; em[1831] = 24; 
    em[1832] = 8884099; em[1833] = 8; em[1834] = 2; /* 1832: pointer_to_array_of_pointers_to_stack */
    	em[1835] = 1839; em[1836] = 0; 
    	em[1837] = 5; em[1838] = 20; 
    em[1839] = 0; em[1840] = 8; em[1841] = 1; /* 1839: pointer.X509_ATTRIBUTE */
    	em[1842] = 1844; em[1843] = 0; 
    em[1844] = 0; em[1845] = 0; em[1846] = 1; /* 1844: X509_ATTRIBUTE */
    	em[1847] = 1849; em[1848] = 0; 
    em[1849] = 0; em[1850] = 24; em[1851] = 2; /* 1849: struct.x509_attributes_st */
    	em[1852] = 135; em[1853] = 0; 
    	em[1854] = 366; em[1855] = 16; 
    em[1856] = 8884097; em[1857] = 8; em[1858] = 0; /* 1856: pointer.func */
    em[1859] = 1; em[1860] = 8; em[1861] = 1; /* 1859: pointer.struct.engine_st */
    	em[1862] = 388; em[1863] = 0; 
    em[1864] = 8884097; em[1865] = 8; em[1866] = 0; /* 1864: pointer.func */
    em[1867] = 8884097; em[1868] = 8; em[1869] = 0; /* 1867: pointer.func */
    em[1870] = 8884097; em[1871] = 8; em[1872] = 0; /* 1870: pointer.func */
    em[1873] = 8884097; em[1874] = 8; em[1875] = 0; /* 1873: pointer.func */
    em[1876] = 0; em[1877] = 208; em[1878] = 25; /* 1876: struct.evp_pkey_method_st */
    	em[1879] = 1929; em[1880] = 8; 
    	em[1881] = 1932; em[1882] = 16; 
    	em[1883] = 1873; em[1884] = 24; 
    	em[1885] = 1929; em[1886] = 32; 
    	em[1887] = 1935; em[1888] = 40; 
    	em[1889] = 1929; em[1890] = 48; 
    	em[1891] = 1935; em[1892] = 56; 
    	em[1893] = 1929; em[1894] = 64; 
    	em[1895] = 1870; em[1896] = 72; 
    	em[1897] = 1929; em[1898] = 80; 
    	em[1899] = 1867; em[1900] = 88; 
    	em[1901] = 1929; em[1902] = 96; 
    	em[1903] = 1870; em[1904] = 104; 
    	em[1905] = 1938; em[1906] = 112; 
    	em[1907] = 1864; em[1908] = 120; 
    	em[1909] = 1938; em[1910] = 128; 
    	em[1911] = 1941; em[1912] = 136; 
    	em[1913] = 1929; em[1914] = 144; 
    	em[1915] = 1870; em[1916] = 152; 
    	em[1917] = 1929; em[1918] = 160; 
    	em[1919] = 1870; em[1920] = 168; 
    	em[1921] = 1929; em[1922] = 176; 
    	em[1923] = 1944; em[1924] = 184; 
    	em[1925] = 1947; em[1926] = 192; 
    	em[1927] = 1856; em[1928] = 200; 
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
    em[1959] = 0; em[1960] = 48; em[1961] = 5; /* 1959: struct.env_md_ctx_st */
    	em[1962] = 1972; em[1963] = 0; 
    	em[1964] = 1859; em[1965] = 8; 
    	em[1966] = 718; em[1967] = 24; 
    	em[1968] = 2008; em[1969] = 32; 
    	em[1970] = 1999; em[1971] = 40; 
    em[1972] = 1; em[1973] = 8; em[1974] = 1; /* 1972: pointer.struct.env_md_st */
    	em[1975] = 1977; em[1976] = 0; 
    em[1977] = 0; em[1978] = 120; em[1979] = 8; /* 1977: struct.env_md_st */
    	em[1980] = 1996; em[1981] = 24; 
    	em[1982] = 1999; em[1983] = 32; 
    	em[1984] = 1956; em[1985] = 40; 
    	em[1986] = 2002; em[1987] = 48; 
    	em[1988] = 1996; em[1989] = 56; 
    	em[1990] = 1953; em[1991] = 64; 
    	em[1992] = 2005; em[1993] = 72; 
    	em[1994] = 1950; em[1995] = 112; 
    em[1996] = 8884097; em[1997] = 8; em[1998] = 0; /* 1996: pointer.func */
    em[1999] = 8884097; em[2000] = 8; em[2001] = 0; /* 1999: pointer.func */
    em[2002] = 8884097; em[2003] = 8; em[2004] = 0; /* 2002: pointer.func */
    em[2005] = 8884097; em[2006] = 8; em[2007] = 0; /* 2005: pointer.func */
    em[2008] = 1; em[2009] = 8; em[2010] = 1; /* 2008: pointer.struct.evp_pkey_ctx_st */
    	em[2011] = 2013; em[2012] = 0; 
    em[2013] = 0; em[2014] = 80; em[2015] = 8; /* 2013: struct.evp_pkey_ctx_st */
    	em[2016] = 2032; em[2017] = 0; 
    	em[2018] = 1334; em[2019] = 8; 
    	em[2020] = 2037; em[2021] = 16; 
    	em[2022] = 2037; em[2023] = 24; 
    	em[2024] = 718; em[2025] = 40; 
    	em[2026] = 718; em[2027] = 48; 
    	em[2028] = 8; em[2029] = 56; 
    	em[2030] = 0; em[2031] = 64; 
    em[2032] = 1; em[2033] = 8; em[2034] = 1; /* 2032: pointer.struct.evp_pkey_method_st */
    	em[2035] = 1876; em[2036] = 0; 
    em[2037] = 1; em[2038] = 8; em[2039] = 1; /* 2037: pointer.struct.evp_pkey_st */
    	em[2040] = 1222; em[2041] = 0; 
    em[2042] = 0; em[2043] = 288; em[2044] = 4; /* 2042: struct.hmac_ctx_st */
    	em[2045] = 1972; em[2046] = 0; 
    	em[2047] = 1959; em[2048] = 8; 
    	em[2049] = 1959; em[2050] = 56; 
    	em[2051] = 1959; em[2052] = 104; 
    em[2053] = 1; em[2054] = 8; em[2055] = 1; /* 2053: pointer.struct.hmac_ctx_st */
    	em[2056] = 2042; em[2057] = 0; 
    args_addr->arg_entity_index[0] = 2053;
    args_addr->arg_entity_index[1] = 718;
    args_addr->arg_entity_index[2] = 5;
    args_addr->arg_entity_index[3] = 1972;
    args_addr->arg_entity_index[4] = 1859;
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

