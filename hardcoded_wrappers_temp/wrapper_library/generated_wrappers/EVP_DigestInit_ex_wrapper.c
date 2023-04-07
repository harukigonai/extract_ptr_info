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

int bb_EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c);

int EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestInit_ex called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestInit_ex(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
        orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
        return orig_EVP_DigestInit_ex(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
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
    em[184] = 1; em[185] = 8; em[186] = 1; /* 184: pointer.struct.ASN1_VALUE_st */
    	em[187] = 189; em[188] = 0; 
    em[189] = 0; em[190] = 0; em[191] = 0; /* 189: struct.ASN1_VALUE_st */
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
    em[242] = 0; em[243] = 40; em[244] = 3; /* 242: struct.asn1_object_st */
    	em[245] = 159; em[246] = 0; 
    	em[247] = 159; em[248] = 8; 
    	em[249] = 164; em[250] = 24; 
    em[251] = 1; em[252] = 8; em[253] = 1; /* 251: pointer.struct.asn1_object_st */
    	em[254] = 242; em[255] = 0; 
    em[256] = 1; em[257] = 8; em[258] = 1; /* 256: pointer.struct.asn1_string_st */
    	em[259] = 197; em[260] = 0; 
    em[261] = 0; em[262] = 8; em[263] = 20; /* 261: union.unknown */
    	em[264] = 140; em[265] = 0; 
    	em[266] = 256; em[267] = 0; 
    	em[268] = 251; em[269] = 0; 
    	em[270] = 237; em[271] = 0; 
    	em[272] = 232; em[273] = 0; 
    	em[274] = 304; em[275] = 0; 
    	em[276] = 227; em[277] = 0; 
    	em[278] = 309; em[279] = 0; 
    	em[280] = 314; em[281] = 0; 
    	em[282] = 222; em[283] = 0; 
    	em[284] = 217; em[285] = 0; 
    	em[286] = 319; em[287] = 0; 
    	em[288] = 212; em[289] = 0; 
    	em[290] = 207; em[291] = 0; 
    	em[292] = 202; em[293] = 0; 
    	em[294] = 324; em[295] = 0; 
    	em[296] = 192; em[297] = 0; 
    	em[298] = 256; em[299] = 0; 
    	em[300] = 256; em[301] = 0; 
    	em[302] = 184; em[303] = 0; 
    em[304] = 1; em[305] = 8; em[306] = 1; /* 304: pointer.struct.asn1_string_st */
    	em[307] = 197; em[308] = 0; 
    em[309] = 1; em[310] = 8; em[311] = 1; /* 309: pointer.struct.asn1_string_st */
    	em[312] = 197; em[313] = 0; 
    em[314] = 1; em[315] = 8; em[316] = 1; /* 314: pointer.struct.asn1_string_st */
    	em[317] = 197; em[318] = 0; 
    em[319] = 1; em[320] = 8; em[321] = 1; /* 319: pointer.struct.asn1_string_st */
    	em[322] = 197; em[323] = 0; 
    em[324] = 1; em[325] = 8; em[326] = 1; /* 324: pointer.struct.asn1_string_st */
    	em[327] = 197; em[328] = 0; 
    em[329] = 0; em[330] = 16; em[331] = 1; /* 329: struct.asn1_type_st */
    	em[332] = 261; em[333] = 8; 
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
    em[380] = 8884097; em[381] = 8; em[382] = 0; /* 380: pointer.func */
    em[383] = 0; em[384] = 112; em[385] = 13; /* 383: struct.rsa_meth_st */
    	em[386] = 159; em[387] = 0; 
    	em[388] = 412; em[389] = 8; 
    	em[390] = 412; em[391] = 16; 
    	em[392] = 412; em[393] = 24; 
    	em[394] = 412; em[395] = 32; 
    	em[396] = 415; em[397] = 40; 
    	em[398] = 418; em[399] = 48; 
    	em[400] = 421; em[401] = 56; 
    	em[402] = 421; em[403] = 64; 
    	em[404] = 140; em[405] = 80; 
    	em[406] = 424; em[407] = 88; 
    	em[408] = 427; em[409] = 96; 
    	em[410] = 430; em[411] = 104; 
    em[412] = 8884097; em[413] = 8; em[414] = 0; /* 412: pointer.func */
    em[415] = 8884097; em[416] = 8; em[417] = 0; /* 415: pointer.func */
    em[418] = 8884097; em[419] = 8; em[420] = 0; /* 418: pointer.func */
    em[421] = 8884097; em[422] = 8; em[423] = 0; /* 421: pointer.func */
    em[424] = 8884097; em[425] = 8; em[426] = 0; /* 424: pointer.func */
    em[427] = 8884097; em[428] = 8; em[429] = 0; /* 427: pointer.func */
    em[430] = 8884097; em[431] = 8; em[432] = 0; /* 430: pointer.func */
    em[433] = 0; em[434] = 32; em[435] = 2; /* 433: struct.stack_st */
    	em[436] = 440; em[437] = 8; 
    	em[438] = 363; em[439] = 24; 
    em[440] = 1; em[441] = 8; em[442] = 1; /* 440: pointer.pointer.char */
    	em[443] = 140; em[444] = 0; 
    em[445] = 0; em[446] = 168; em[447] = 17; /* 445: struct.rsa_st */
    	em[448] = 482; em[449] = 16; 
    	em[450] = 487; em[451] = 24; 
    	em[452] = 832; em[453] = 32; 
    	em[454] = 832; em[455] = 40; 
    	em[456] = 832; em[457] = 48; 
    	em[458] = 832; em[459] = 56; 
    	em[460] = 832; em[461] = 64; 
    	em[462] = 832; em[463] = 72; 
    	em[464] = 832; em[465] = 80; 
    	em[466] = 832; em[467] = 88; 
    	em[468] = 852; em[469] = 96; 
    	em[470] = 874; em[471] = 120; 
    	em[472] = 874; em[473] = 128; 
    	em[474] = 874; em[475] = 136; 
    	em[476] = 140; em[477] = 144; 
    	em[478] = 888; em[479] = 152; 
    	em[480] = 888; em[481] = 160; 
    em[482] = 1; em[483] = 8; em[484] = 1; /* 482: pointer.struct.rsa_meth_st */
    	em[485] = 383; em[486] = 0; 
    em[487] = 1; em[488] = 8; em[489] = 1; /* 487: pointer.struct.engine_st */
    	em[490] = 492; em[491] = 0; 
    em[492] = 0; em[493] = 216; em[494] = 24; /* 492: struct.engine_st */
    	em[495] = 159; em[496] = 0; 
    	em[497] = 159; em[498] = 8; 
    	em[499] = 543; em[500] = 16; 
    	em[501] = 598; em[502] = 24; 
    	em[503] = 649; em[504] = 32; 
    	em[505] = 685; em[506] = 40; 
    	em[507] = 702; em[508] = 48; 
    	em[509] = 726; em[510] = 56; 
    	em[511] = 761; em[512] = 64; 
    	em[513] = 769; em[514] = 72; 
    	em[515] = 772; em[516] = 80; 
    	em[517] = 775; em[518] = 88; 
    	em[519] = 778; em[520] = 96; 
    	em[521] = 781; em[522] = 104; 
    	em[523] = 781; em[524] = 112; 
    	em[525] = 781; em[526] = 120; 
    	em[527] = 784; em[528] = 128; 
    	em[529] = 787; em[530] = 136; 
    	em[531] = 787; em[532] = 144; 
    	em[533] = 790; em[534] = 152; 
    	em[535] = 793; em[536] = 160; 
    	em[537] = 805; em[538] = 184; 
    	em[539] = 827; em[540] = 200; 
    	em[541] = 827; em[542] = 208; 
    em[543] = 1; em[544] = 8; em[545] = 1; /* 543: pointer.struct.rsa_meth_st */
    	em[546] = 548; em[547] = 0; 
    em[548] = 0; em[549] = 112; em[550] = 13; /* 548: struct.rsa_meth_st */
    	em[551] = 159; em[552] = 0; 
    	em[553] = 577; em[554] = 8; 
    	em[555] = 577; em[556] = 16; 
    	em[557] = 577; em[558] = 24; 
    	em[559] = 577; em[560] = 32; 
    	em[561] = 580; em[562] = 40; 
    	em[563] = 583; em[564] = 48; 
    	em[565] = 586; em[566] = 56; 
    	em[567] = 586; em[568] = 64; 
    	em[569] = 140; em[570] = 80; 
    	em[571] = 589; em[572] = 88; 
    	em[573] = 592; em[574] = 96; 
    	em[575] = 595; em[576] = 104; 
    em[577] = 8884097; em[578] = 8; em[579] = 0; /* 577: pointer.func */
    em[580] = 8884097; em[581] = 8; em[582] = 0; /* 580: pointer.func */
    em[583] = 8884097; em[584] = 8; em[585] = 0; /* 583: pointer.func */
    em[586] = 8884097; em[587] = 8; em[588] = 0; /* 586: pointer.func */
    em[589] = 8884097; em[590] = 8; em[591] = 0; /* 589: pointer.func */
    em[592] = 8884097; em[593] = 8; em[594] = 0; /* 592: pointer.func */
    em[595] = 8884097; em[596] = 8; em[597] = 0; /* 595: pointer.func */
    em[598] = 1; em[599] = 8; em[600] = 1; /* 598: pointer.struct.dsa_method */
    	em[601] = 603; em[602] = 0; 
    em[603] = 0; em[604] = 96; em[605] = 11; /* 603: struct.dsa_method */
    	em[606] = 159; em[607] = 0; 
    	em[608] = 628; em[609] = 8; 
    	em[610] = 631; em[611] = 16; 
    	em[612] = 634; em[613] = 24; 
    	em[614] = 637; em[615] = 32; 
    	em[616] = 640; em[617] = 40; 
    	em[618] = 643; em[619] = 48; 
    	em[620] = 643; em[621] = 56; 
    	em[622] = 140; em[623] = 72; 
    	em[624] = 646; em[625] = 80; 
    	em[626] = 643; em[627] = 88; 
    em[628] = 8884097; em[629] = 8; em[630] = 0; /* 628: pointer.func */
    em[631] = 8884097; em[632] = 8; em[633] = 0; /* 631: pointer.func */
    em[634] = 8884097; em[635] = 8; em[636] = 0; /* 634: pointer.func */
    em[637] = 8884097; em[638] = 8; em[639] = 0; /* 637: pointer.func */
    em[640] = 8884097; em[641] = 8; em[642] = 0; /* 640: pointer.func */
    em[643] = 8884097; em[644] = 8; em[645] = 0; /* 643: pointer.func */
    em[646] = 8884097; em[647] = 8; em[648] = 0; /* 646: pointer.func */
    em[649] = 1; em[650] = 8; em[651] = 1; /* 649: pointer.struct.dh_method */
    	em[652] = 654; em[653] = 0; 
    em[654] = 0; em[655] = 72; em[656] = 8; /* 654: struct.dh_method */
    	em[657] = 159; em[658] = 0; 
    	em[659] = 673; em[660] = 8; 
    	em[661] = 676; em[662] = 16; 
    	em[663] = 679; em[664] = 24; 
    	em[665] = 673; em[666] = 32; 
    	em[667] = 673; em[668] = 40; 
    	em[669] = 140; em[670] = 56; 
    	em[671] = 682; em[672] = 64; 
    em[673] = 8884097; em[674] = 8; em[675] = 0; /* 673: pointer.func */
    em[676] = 8884097; em[677] = 8; em[678] = 0; /* 676: pointer.func */
    em[679] = 8884097; em[680] = 8; em[681] = 0; /* 679: pointer.func */
    em[682] = 8884097; em[683] = 8; em[684] = 0; /* 682: pointer.func */
    em[685] = 1; em[686] = 8; em[687] = 1; /* 685: pointer.struct.ecdh_method */
    	em[688] = 690; em[689] = 0; 
    em[690] = 0; em[691] = 32; em[692] = 3; /* 690: struct.ecdh_method */
    	em[693] = 159; em[694] = 0; 
    	em[695] = 699; em[696] = 8; 
    	em[697] = 140; em[698] = 24; 
    em[699] = 8884097; em[700] = 8; em[701] = 0; /* 699: pointer.func */
    em[702] = 1; em[703] = 8; em[704] = 1; /* 702: pointer.struct.ecdsa_method */
    	em[705] = 707; em[706] = 0; 
    em[707] = 0; em[708] = 48; em[709] = 5; /* 707: struct.ecdsa_method */
    	em[710] = 159; em[711] = 0; 
    	em[712] = 720; em[713] = 8; 
    	em[714] = 723; em[715] = 16; 
    	em[716] = 380; em[717] = 24; 
    	em[718] = 140; em[719] = 40; 
    em[720] = 8884097; em[721] = 8; em[722] = 0; /* 720: pointer.func */
    em[723] = 8884097; em[724] = 8; em[725] = 0; /* 723: pointer.func */
    em[726] = 1; em[727] = 8; em[728] = 1; /* 726: pointer.struct.rand_meth_st */
    	em[729] = 731; em[730] = 0; 
    em[731] = 0; em[732] = 48; em[733] = 6; /* 731: struct.rand_meth_st */
    	em[734] = 746; em[735] = 0; 
    	em[736] = 749; em[737] = 8; 
    	em[738] = 752; em[739] = 16; 
    	em[740] = 755; em[741] = 24; 
    	em[742] = 749; em[743] = 32; 
    	em[744] = 758; em[745] = 40; 
    em[746] = 8884097; em[747] = 8; em[748] = 0; /* 746: pointer.func */
    em[749] = 8884097; em[750] = 8; em[751] = 0; /* 749: pointer.func */
    em[752] = 8884097; em[753] = 8; em[754] = 0; /* 752: pointer.func */
    em[755] = 8884097; em[756] = 8; em[757] = 0; /* 755: pointer.func */
    em[758] = 8884097; em[759] = 8; em[760] = 0; /* 758: pointer.func */
    em[761] = 1; em[762] = 8; em[763] = 1; /* 761: pointer.struct.store_method_st */
    	em[764] = 766; em[765] = 0; 
    em[766] = 0; em[767] = 0; em[768] = 0; /* 766: struct.store_method_st */
    em[769] = 8884097; em[770] = 8; em[771] = 0; /* 769: pointer.func */
    em[772] = 8884097; em[773] = 8; em[774] = 0; /* 772: pointer.func */
    em[775] = 8884097; em[776] = 8; em[777] = 0; /* 775: pointer.func */
    em[778] = 8884097; em[779] = 8; em[780] = 0; /* 778: pointer.func */
    em[781] = 8884097; em[782] = 8; em[783] = 0; /* 781: pointer.func */
    em[784] = 8884097; em[785] = 8; em[786] = 0; /* 784: pointer.func */
    em[787] = 8884097; em[788] = 8; em[789] = 0; /* 787: pointer.func */
    em[790] = 8884097; em[791] = 8; em[792] = 0; /* 790: pointer.func */
    em[793] = 1; em[794] = 8; em[795] = 1; /* 793: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[796] = 798; em[797] = 0; 
    em[798] = 0; em[799] = 32; em[800] = 2; /* 798: struct.ENGINE_CMD_DEFN_st */
    	em[801] = 159; em[802] = 8; 
    	em[803] = 159; em[804] = 16; 
    em[805] = 0; em[806] = 16; em[807] = 1; /* 805: struct.crypto_ex_data_st */
    	em[808] = 810; em[809] = 0; 
    em[810] = 1; em[811] = 8; em[812] = 1; /* 810: pointer.struct.stack_st_void */
    	em[813] = 815; em[814] = 0; 
    em[815] = 0; em[816] = 32; em[817] = 1; /* 815: struct.stack_st_void */
    	em[818] = 820; em[819] = 0; 
    em[820] = 0; em[821] = 32; em[822] = 2; /* 820: struct.stack_st */
    	em[823] = 440; em[824] = 8; 
    	em[825] = 363; em[826] = 24; 
    em[827] = 1; em[828] = 8; em[829] = 1; /* 827: pointer.struct.engine_st */
    	em[830] = 492; em[831] = 0; 
    em[832] = 1; em[833] = 8; em[834] = 1; /* 832: pointer.struct.bignum_st */
    	em[835] = 837; em[836] = 0; 
    em[837] = 0; em[838] = 24; em[839] = 1; /* 837: struct.bignum_st */
    	em[840] = 842; em[841] = 0; 
    em[842] = 8884099; em[843] = 8; em[844] = 2; /* 842: pointer_to_array_of_pointers_to_stack */
    	em[845] = 849; em[846] = 0; 
    	em[847] = 5; em[848] = 12; 
    em[849] = 0; em[850] = 8; em[851] = 0; /* 849: long unsigned int */
    em[852] = 0; em[853] = 16; em[854] = 1; /* 852: struct.crypto_ex_data_st */
    	em[855] = 857; em[856] = 0; 
    em[857] = 1; em[858] = 8; em[859] = 1; /* 857: pointer.struct.stack_st_void */
    	em[860] = 862; em[861] = 0; 
    em[862] = 0; em[863] = 32; em[864] = 1; /* 862: struct.stack_st_void */
    	em[865] = 867; em[866] = 0; 
    em[867] = 0; em[868] = 32; em[869] = 2; /* 867: struct.stack_st */
    	em[870] = 440; em[871] = 8; 
    	em[872] = 363; em[873] = 24; 
    em[874] = 1; em[875] = 8; em[876] = 1; /* 874: pointer.struct.bn_mont_ctx_st */
    	em[877] = 879; em[878] = 0; 
    em[879] = 0; em[880] = 96; em[881] = 3; /* 879: struct.bn_mont_ctx_st */
    	em[882] = 837; em[883] = 8; 
    	em[884] = 837; em[885] = 32; 
    	em[886] = 837; em[887] = 56; 
    em[888] = 1; em[889] = 8; em[890] = 1; /* 888: pointer.struct.bn_blinding_st */
    	em[891] = 893; em[892] = 0; 
    em[893] = 0; em[894] = 88; em[895] = 7; /* 893: struct.bn_blinding_st */
    	em[896] = 910; em[897] = 0; 
    	em[898] = 910; em[899] = 8; 
    	em[900] = 910; em[901] = 16; 
    	em[902] = 910; em[903] = 24; 
    	em[904] = 927; em[905] = 40; 
    	em[906] = 935; em[907] = 72; 
    	em[908] = 949; em[909] = 80; 
    em[910] = 1; em[911] = 8; em[912] = 1; /* 910: pointer.struct.bignum_st */
    	em[913] = 915; em[914] = 0; 
    em[915] = 0; em[916] = 24; em[917] = 1; /* 915: struct.bignum_st */
    	em[918] = 920; em[919] = 0; 
    em[920] = 8884099; em[921] = 8; em[922] = 2; /* 920: pointer_to_array_of_pointers_to_stack */
    	em[923] = 849; em[924] = 0; 
    	em[925] = 5; em[926] = 12; 
    em[927] = 0; em[928] = 16; em[929] = 1; /* 927: struct.crypto_threadid_st */
    	em[930] = 932; em[931] = 0; 
    em[932] = 0; em[933] = 8; em[934] = 0; /* 932: pointer.void */
    em[935] = 1; em[936] = 8; em[937] = 1; /* 935: pointer.struct.bn_mont_ctx_st */
    	em[938] = 940; em[939] = 0; 
    em[940] = 0; em[941] = 96; em[942] = 3; /* 940: struct.bn_mont_ctx_st */
    	em[943] = 915; em[944] = 8; 
    	em[945] = 915; em[946] = 32; 
    	em[947] = 915; em[948] = 56; 
    em[949] = 8884097; em[950] = 8; em[951] = 0; /* 949: pointer.func */
    em[952] = 1; em[953] = 8; em[954] = 1; /* 952: pointer.struct.evp_pkey_ctx_st */
    	em[955] = 957; em[956] = 0; 
    em[957] = 0; em[958] = 80; em[959] = 8; /* 957: struct.evp_pkey_ctx_st */
    	em[960] = 976; em[961] = 0; 
    	em[962] = 1070; em[963] = 8; 
    	em[964] = 1075; em[965] = 16; 
    	em[966] = 1075; em[967] = 24; 
    	em[968] = 932; em[969] = 40; 
    	em[970] = 932; em[971] = 48; 
    	em[972] = 8; em[973] = 56; 
    	em[974] = 0; em[975] = 64; 
    em[976] = 1; em[977] = 8; em[978] = 1; /* 976: pointer.struct.evp_pkey_method_st */
    	em[979] = 981; em[980] = 0; 
    em[981] = 0; em[982] = 208; em[983] = 25; /* 981: struct.evp_pkey_method_st */
    	em[984] = 1034; em[985] = 8; 
    	em[986] = 1037; em[987] = 16; 
    	em[988] = 1040; em[989] = 24; 
    	em[990] = 1034; em[991] = 32; 
    	em[992] = 1043; em[993] = 40; 
    	em[994] = 1034; em[995] = 48; 
    	em[996] = 1043; em[997] = 56; 
    	em[998] = 1034; em[999] = 64; 
    	em[1000] = 1046; em[1001] = 72; 
    	em[1002] = 1034; em[1003] = 80; 
    	em[1004] = 1049; em[1005] = 88; 
    	em[1006] = 1034; em[1007] = 96; 
    	em[1008] = 1046; em[1009] = 104; 
    	em[1010] = 1052; em[1011] = 112; 
    	em[1012] = 1055; em[1013] = 120; 
    	em[1014] = 1052; em[1015] = 128; 
    	em[1016] = 1058; em[1017] = 136; 
    	em[1018] = 1034; em[1019] = 144; 
    	em[1020] = 1046; em[1021] = 152; 
    	em[1022] = 1034; em[1023] = 160; 
    	em[1024] = 1046; em[1025] = 168; 
    	em[1026] = 1034; em[1027] = 176; 
    	em[1028] = 1061; em[1029] = 184; 
    	em[1030] = 1064; em[1031] = 192; 
    	em[1032] = 1067; em[1033] = 200; 
    em[1034] = 8884097; em[1035] = 8; em[1036] = 0; /* 1034: pointer.func */
    em[1037] = 8884097; em[1038] = 8; em[1039] = 0; /* 1037: pointer.func */
    em[1040] = 8884097; em[1041] = 8; em[1042] = 0; /* 1040: pointer.func */
    em[1043] = 8884097; em[1044] = 8; em[1045] = 0; /* 1043: pointer.func */
    em[1046] = 8884097; em[1047] = 8; em[1048] = 0; /* 1046: pointer.func */
    em[1049] = 8884097; em[1050] = 8; em[1051] = 0; /* 1049: pointer.func */
    em[1052] = 8884097; em[1053] = 8; em[1054] = 0; /* 1052: pointer.func */
    em[1055] = 8884097; em[1056] = 8; em[1057] = 0; /* 1055: pointer.func */
    em[1058] = 8884097; em[1059] = 8; em[1060] = 0; /* 1058: pointer.func */
    em[1061] = 8884097; em[1062] = 8; em[1063] = 0; /* 1061: pointer.func */
    em[1064] = 8884097; em[1065] = 8; em[1066] = 0; /* 1064: pointer.func */
    em[1067] = 8884097; em[1068] = 8; em[1069] = 0; /* 1067: pointer.func */
    em[1070] = 1; em[1071] = 8; em[1072] = 1; /* 1070: pointer.struct.engine_st */
    	em[1073] = 492; em[1074] = 0; 
    em[1075] = 1; em[1076] = 8; em[1077] = 1; /* 1075: pointer.struct.evp_pkey_st */
    	em[1078] = 1080; em[1079] = 0; 
    em[1080] = 0; em[1081] = 56; em[1082] = 4; /* 1080: struct.evp_pkey_st */
    	em[1083] = 1091; em[1084] = 16; 
    	em[1085] = 1070; em[1086] = 24; 
    	em[1087] = 1192; em[1088] = 32; 
    	em[1089] = 1914; em[1090] = 48; 
    em[1091] = 1; em[1092] = 8; em[1093] = 1; /* 1091: pointer.struct.evp_pkey_asn1_method_st */
    	em[1094] = 1096; em[1095] = 0; 
    em[1096] = 0; em[1097] = 208; em[1098] = 24; /* 1096: struct.evp_pkey_asn1_method_st */
    	em[1099] = 140; em[1100] = 16; 
    	em[1101] = 140; em[1102] = 24; 
    	em[1103] = 1147; em[1104] = 32; 
    	em[1105] = 1150; em[1106] = 40; 
    	em[1107] = 1153; em[1108] = 48; 
    	em[1109] = 1156; em[1110] = 56; 
    	em[1111] = 1159; em[1112] = 64; 
    	em[1113] = 1162; em[1114] = 72; 
    	em[1115] = 1156; em[1116] = 80; 
    	em[1117] = 1165; em[1118] = 88; 
    	em[1119] = 1165; em[1120] = 96; 
    	em[1121] = 1168; em[1122] = 104; 
    	em[1123] = 1171; em[1124] = 112; 
    	em[1125] = 1165; em[1126] = 120; 
    	em[1127] = 1174; em[1128] = 128; 
    	em[1129] = 1153; em[1130] = 136; 
    	em[1131] = 1156; em[1132] = 144; 
    	em[1133] = 1177; em[1134] = 152; 
    	em[1135] = 1180; em[1136] = 160; 
    	em[1137] = 1183; em[1138] = 168; 
    	em[1139] = 1168; em[1140] = 176; 
    	em[1141] = 1171; em[1142] = 184; 
    	em[1143] = 1186; em[1144] = 192; 
    	em[1145] = 1189; em[1146] = 200; 
    em[1147] = 8884097; em[1148] = 8; em[1149] = 0; /* 1147: pointer.func */
    em[1150] = 8884097; em[1151] = 8; em[1152] = 0; /* 1150: pointer.func */
    em[1153] = 8884097; em[1154] = 8; em[1155] = 0; /* 1153: pointer.func */
    em[1156] = 8884097; em[1157] = 8; em[1158] = 0; /* 1156: pointer.func */
    em[1159] = 8884097; em[1160] = 8; em[1161] = 0; /* 1159: pointer.func */
    em[1162] = 8884097; em[1163] = 8; em[1164] = 0; /* 1162: pointer.func */
    em[1165] = 8884097; em[1166] = 8; em[1167] = 0; /* 1165: pointer.func */
    em[1168] = 8884097; em[1169] = 8; em[1170] = 0; /* 1168: pointer.func */
    em[1171] = 8884097; em[1172] = 8; em[1173] = 0; /* 1171: pointer.func */
    em[1174] = 8884097; em[1175] = 8; em[1176] = 0; /* 1174: pointer.func */
    em[1177] = 8884097; em[1178] = 8; em[1179] = 0; /* 1177: pointer.func */
    em[1180] = 8884097; em[1181] = 8; em[1182] = 0; /* 1180: pointer.func */
    em[1183] = 8884097; em[1184] = 8; em[1185] = 0; /* 1183: pointer.func */
    em[1186] = 8884097; em[1187] = 8; em[1188] = 0; /* 1186: pointer.func */
    em[1189] = 8884097; em[1190] = 8; em[1191] = 0; /* 1189: pointer.func */
    em[1192] = 0; em[1193] = 8; em[1194] = 5; /* 1192: union.unknown */
    	em[1195] = 140; em[1196] = 0; 
    	em[1197] = 1205; em[1198] = 0; 
    	em[1199] = 1210; em[1200] = 0; 
    	em[1201] = 1291; em[1202] = 0; 
    	em[1203] = 1405; em[1204] = 0; 
    em[1205] = 1; em[1206] = 8; em[1207] = 1; /* 1205: pointer.struct.rsa_st */
    	em[1208] = 445; em[1209] = 0; 
    em[1210] = 1; em[1211] = 8; em[1212] = 1; /* 1210: pointer.struct.dsa_st */
    	em[1213] = 1215; em[1214] = 0; 
    em[1215] = 0; em[1216] = 136; em[1217] = 11; /* 1215: struct.dsa_st */
    	em[1218] = 832; em[1219] = 24; 
    	em[1220] = 832; em[1221] = 32; 
    	em[1222] = 832; em[1223] = 40; 
    	em[1224] = 832; em[1225] = 48; 
    	em[1226] = 832; em[1227] = 56; 
    	em[1228] = 832; em[1229] = 64; 
    	em[1230] = 832; em[1231] = 72; 
    	em[1232] = 874; em[1233] = 88; 
    	em[1234] = 852; em[1235] = 104; 
    	em[1236] = 1240; em[1237] = 120; 
    	em[1238] = 487; em[1239] = 128; 
    em[1240] = 1; em[1241] = 8; em[1242] = 1; /* 1240: pointer.struct.dsa_method */
    	em[1243] = 1245; em[1244] = 0; 
    em[1245] = 0; em[1246] = 96; em[1247] = 11; /* 1245: struct.dsa_method */
    	em[1248] = 159; em[1249] = 0; 
    	em[1250] = 1270; em[1251] = 8; 
    	em[1252] = 1273; em[1253] = 16; 
    	em[1254] = 1276; em[1255] = 24; 
    	em[1256] = 1279; em[1257] = 32; 
    	em[1258] = 1282; em[1259] = 40; 
    	em[1260] = 1285; em[1261] = 48; 
    	em[1262] = 1285; em[1263] = 56; 
    	em[1264] = 140; em[1265] = 72; 
    	em[1266] = 1288; em[1267] = 80; 
    	em[1268] = 1285; em[1269] = 88; 
    em[1270] = 8884097; em[1271] = 8; em[1272] = 0; /* 1270: pointer.func */
    em[1273] = 8884097; em[1274] = 8; em[1275] = 0; /* 1273: pointer.func */
    em[1276] = 8884097; em[1277] = 8; em[1278] = 0; /* 1276: pointer.func */
    em[1279] = 8884097; em[1280] = 8; em[1281] = 0; /* 1279: pointer.func */
    em[1282] = 8884097; em[1283] = 8; em[1284] = 0; /* 1282: pointer.func */
    em[1285] = 8884097; em[1286] = 8; em[1287] = 0; /* 1285: pointer.func */
    em[1288] = 8884097; em[1289] = 8; em[1290] = 0; /* 1288: pointer.func */
    em[1291] = 1; em[1292] = 8; em[1293] = 1; /* 1291: pointer.struct.dh_st */
    	em[1294] = 1296; em[1295] = 0; 
    em[1296] = 0; em[1297] = 144; em[1298] = 12; /* 1296: struct.dh_st */
    	em[1299] = 1323; em[1300] = 8; 
    	em[1301] = 1323; em[1302] = 16; 
    	em[1303] = 1323; em[1304] = 32; 
    	em[1305] = 1323; em[1306] = 40; 
    	em[1307] = 1340; em[1308] = 56; 
    	em[1309] = 1323; em[1310] = 64; 
    	em[1311] = 1323; em[1312] = 72; 
    	em[1313] = 29; em[1314] = 80; 
    	em[1315] = 1323; em[1316] = 96; 
    	em[1317] = 1354; em[1318] = 112; 
    	em[1319] = 1369; em[1320] = 128; 
    	em[1321] = 487; em[1322] = 136; 
    em[1323] = 1; em[1324] = 8; em[1325] = 1; /* 1323: pointer.struct.bignum_st */
    	em[1326] = 1328; em[1327] = 0; 
    em[1328] = 0; em[1329] = 24; em[1330] = 1; /* 1328: struct.bignum_st */
    	em[1331] = 1333; em[1332] = 0; 
    em[1333] = 8884099; em[1334] = 8; em[1335] = 2; /* 1333: pointer_to_array_of_pointers_to_stack */
    	em[1336] = 849; em[1337] = 0; 
    	em[1338] = 5; em[1339] = 12; 
    em[1340] = 1; em[1341] = 8; em[1342] = 1; /* 1340: pointer.struct.bn_mont_ctx_st */
    	em[1343] = 1345; em[1344] = 0; 
    em[1345] = 0; em[1346] = 96; em[1347] = 3; /* 1345: struct.bn_mont_ctx_st */
    	em[1348] = 1328; em[1349] = 8; 
    	em[1350] = 1328; em[1351] = 32; 
    	em[1352] = 1328; em[1353] = 56; 
    em[1354] = 0; em[1355] = 16; em[1356] = 1; /* 1354: struct.crypto_ex_data_st */
    	em[1357] = 1359; em[1358] = 0; 
    em[1359] = 1; em[1360] = 8; em[1361] = 1; /* 1359: pointer.struct.stack_st_void */
    	em[1362] = 1364; em[1363] = 0; 
    em[1364] = 0; em[1365] = 32; em[1366] = 1; /* 1364: struct.stack_st_void */
    	em[1367] = 433; em[1368] = 0; 
    em[1369] = 1; em[1370] = 8; em[1371] = 1; /* 1369: pointer.struct.dh_method */
    	em[1372] = 1374; em[1373] = 0; 
    em[1374] = 0; em[1375] = 72; em[1376] = 8; /* 1374: struct.dh_method */
    	em[1377] = 159; em[1378] = 0; 
    	em[1379] = 1393; em[1380] = 8; 
    	em[1381] = 1396; em[1382] = 16; 
    	em[1383] = 1399; em[1384] = 24; 
    	em[1385] = 1393; em[1386] = 32; 
    	em[1387] = 1393; em[1388] = 40; 
    	em[1389] = 140; em[1390] = 56; 
    	em[1391] = 1402; em[1392] = 64; 
    em[1393] = 8884097; em[1394] = 8; em[1395] = 0; /* 1393: pointer.func */
    em[1396] = 8884097; em[1397] = 8; em[1398] = 0; /* 1396: pointer.func */
    em[1399] = 8884097; em[1400] = 8; em[1401] = 0; /* 1399: pointer.func */
    em[1402] = 8884097; em[1403] = 8; em[1404] = 0; /* 1402: pointer.func */
    em[1405] = 1; em[1406] = 8; em[1407] = 1; /* 1405: pointer.struct.ec_key_st */
    	em[1408] = 1410; em[1409] = 0; 
    em[1410] = 0; em[1411] = 56; em[1412] = 4; /* 1410: struct.ec_key_st */
    	em[1413] = 1421; em[1414] = 8; 
    	em[1415] = 1869; em[1416] = 16; 
    	em[1417] = 1874; em[1418] = 24; 
    	em[1419] = 1891; em[1420] = 48; 
    em[1421] = 1; em[1422] = 8; em[1423] = 1; /* 1421: pointer.struct.ec_group_st */
    	em[1424] = 1426; em[1425] = 0; 
    em[1426] = 0; em[1427] = 232; em[1428] = 12; /* 1426: struct.ec_group_st */
    	em[1429] = 1453; em[1430] = 0; 
    	em[1431] = 1625; em[1432] = 8; 
    	em[1433] = 1825; em[1434] = 16; 
    	em[1435] = 1825; em[1436] = 40; 
    	em[1437] = 29; em[1438] = 80; 
    	em[1439] = 1837; em[1440] = 96; 
    	em[1441] = 1825; em[1442] = 104; 
    	em[1443] = 1825; em[1444] = 152; 
    	em[1445] = 1825; em[1446] = 176; 
    	em[1447] = 932; em[1448] = 208; 
    	em[1449] = 932; em[1450] = 216; 
    	em[1451] = 1866; em[1452] = 224; 
    em[1453] = 1; em[1454] = 8; em[1455] = 1; /* 1453: pointer.struct.ec_method_st */
    	em[1456] = 1458; em[1457] = 0; 
    em[1458] = 0; em[1459] = 304; em[1460] = 37; /* 1458: struct.ec_method_st */
    	em[1461] = 1535; em[1462] = 8; 
    	em[1463] = 1538; em[1464] = 16; 
    	em[1465] = 1538; em[1466] = 24; 
    	em[1467] = 1541; em[1468] = 32; 
    	em[1469] = 1544; em[1470] = 40; 
    	em[1471] = 1547; em[1472] = 48; 
    	em[1473] = 1550; em[1474] = 56; 
    	em[1475] = 1553; em[1476] = 64; 
    	em[1477] = 1556; em[1478] = 72; 
    	em[1479] = 1559; em[1480] = 80; 
    	em[1481] = 1559; em[1482] = 88; 
    	em[1483] = 1562; em[1484] = 96; 
    	em[1485] = 1565; em[1486] = 104; 
    	em[1487] = 1568; em[1488] = 112; 
    	em[1489] = 1571; em[1490] = 120; 
    	em[1491] = 1574; em[1492] = 128; 
    	em[1493] = 1577; em[1494] = 136; 
    	em[1495] = 1580; em[1496] = 144; 
    	em[1497] = 1583; em[1498] = 152; 
    	em[1499] = 1586; em[1500] = 160; 
    	em[1501] = 1589; em[1502] = 168; 
    	em[1503] = 1592; em[1504] = 176; 
    	em[1505] = 1595; em[1506] = 184; 
    	em[1507] = 1598; em[1508] = 192; 
    	em[1509] = 1601; em[1510] = 200; 
    	em[1511] = 1604; em[1512] = 208; 
    	em[1513] = 1595; em[1514] = 216; 
    	em[1515] = 1607; em[1516] = 224; 
    	em[1517] = 1610; em[1518] = 232; 
    	em[1519] = 1613; em[1520] = 240; 
    	em[1521] = 1550; em[1522] = 248; 
    	em[1523] = 1616; em[1524] = 256; 
    	em[1525] = 1619; em[1526] = 264; 
    	em[1527] = 1616; em[1528] = 272; 
    	em[1529] = 1619; em[1530] = 280; 
    	em[1531] = 1619; em[1532] = 288; 
    	em[1533] = 1622; em[1534] = 296; 
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
    em[1601] = 8884097; em[1602] = 8; em[1603] = 0; /* 1601: pointer.func */
    em[1604] = 8884097; em[1605] = 8; em[1606] = 0; /* 1604: pointer.func */
    em[1607] = 8884097; em[1608] = 8; em[1609] = 0; /* 1607: pointer.func */
    em[1610] = 8884097; em[1611] = 8; em[1612] = 0; /* 1610: pointer.func */
    em[1613] = 8884097; em[1614] = 8; em[1615] = 0; /* 1613: pointer.func */
    em[1616] = 8884097; em[1617] = 8; em[1618] = 0; /* 1616: pointer.func */
    em[1619] = 8884097; em[1620] = 8; em[1621] = 0; /* 1619: pointer.func */
    em[1622] = 8884097; em[1623] = 8; em[1624] = 0; /* 1622: pointer.func */
    em[1625] = 1; em[1626] = 8; em[1627] = 1; /* 1625: pointer.struct.ec_point_st */
    	em[1628] = 1630; em[1629] = 0; 
    em[1630] = 0; em[1631] = 88; em[1632] = 4; /* 1630: struct.ec_point_st */
    	em[1633] = 1641; em[1634] = 0; 
    	em[1635] = 1813; em[1636] = 8; 
    	em[1637] = 1813; em[1638] = 32; 
    	em[1639] = 1813; em[1640] = 56; 
    em[1641] = 1; em[1642] = 8; em[1643] = 1; /* 1641: pointer.struct.ec_method_st */
    	em[1644] = 1646; em[1645] = 0; 
    em[1646] = 0; em[1647] = 304; em[1648] = 37; /* 1646: struct.ec_method_st */
    	em[1649] = 1723; em[1650] = 8; 
    	em[1651] = 1726; em[1652] = 16; 
    	em[1653] = 1726; em[1654] = 24; 
    	em[1655] = 1729; em[1656] = 32; 
    	em[1657] = 1732; em[1658] = 40; 
    	em[1659] = 1735; em[1660] = 48; 
    	em[1661] = 1738; em[1662] = 56; 
    	em[1663] = 1741; em[1664] = 64; 
    	em[1665] = 1744; em[1666] = 72; 
    	em[1667] = 1747; em[1668] = 80; 
    	em[1669] = 1747; em[1670] = 88; 
    	em[1671] = 1750; em[1672] = 96; 
    	em[1673] = 1753; em[1674] = 104; 
    	em[1675] = 1756; em[1676] = 112; 
    	em[1677] = 1759; em[1678] = 120; 
    	em[1679] = 1762; em[1680] = 128; 
    	em[1681] = 1765; em[1682] = 136; 
    	em[1683] = 1768; em[1684] = 144; 
    	em[1685] = 1771; em[1686] = 152; 
    	em[1687] = 1774; em[1688] = 160; 
    	em[1689] = 1777; em[1690] = 168; 
    	em[1691] = 1780; em[1692] = 176; 
    	em[1693] = 1783; em[1694] = 184; 
    	em[1695] = 1786; em[1696] = 192; 
    	em[1697] = 1789; em[1698] = 200; 
    	em[1699] = 1792; em[1700] = 208; 
    	em[1701] = 1783; em[1702] = 216; 
    	em[1703] = 1795; em[1704] = 224; 
    	em[1705] = 1798; em[1706] = 232; 
    	em[1707] = 1801; em[1708] = 240; 
    	em[1709] = 1738; em[1710] = 248; 
    	em[1711] = 1804; em[1712] = 256; 
    	em[1713] = 1807; em[1714] = 264; 
    	em[1715] = 1804; em[1716] = 272; 
    	em[1717] = 1807; em[1718] = 280; 
    	em[1719] = 1807; em[1720] = 288; 
    	em[1721] = 1810; em[1722] = 296; 
    em[1723] = 8884097; em[1724] = 8; em[1725] = 0; /* 1723: pointer.func */
    em[1726] = 8884097; em[1727] = 8; em[1728] = 0; /* 1726: pointer.func */
    em[1729] = 8884097; em[1730] = 8; em[1731] = 0; /* 1729: pointer.func */
    em[1732] = 8884097; em[1733] = 8; em[1734] = 0; /* 1732: pointer.func */
    em[1735] = 8884097; em[1736] = 8; em[1737] = 0; /* 1735: pointer.func */
    em[1738] = 8884097; em[1739] = 8; em[1740] = 0; /* 1738: pointer.func */
    em[1741] = 8884097; em[1742] = 8; em[1743] = 0; /* 1741: pointer.func */
    em[1744] = 8884097; em[1745] = 8; em[1746] = 0; /* 1744: pointer.func */
    em[1747] = 8884097; em[1748] = 8; em[1749] = 0; /* 1747: pointer.func */
    em[1750] = 8884097; em[1751] = 8; em[1752] = 0; /* 1750: pointer.func */
    em[1753] = 8884097; em[1754] = 8; em[1755] = 0; /* 1753: pointer.func */
    em[1756] = 8884097; em[1757] = 8; em[1758] = 0; /* 1756: pointer.func */
    em[1759] = 8884097; em[1760] = 8; em[1761] = 0; /* 1759: pointer.func */
    em[1762] = 8884097; em[1763] = 8; em[1764] = 0; /* 1762: pointer.func */
    em[1765] = 8884097; em[1766] = 8; em[1767] = 0; /* 1765: pointer.func */
    em[1768] = 8884097; em[1769] = 8; em[1770] = 0; /* 1768: pointer.func */
    em[1771] = 8884097; em[1772] = 8; em[1773] = 0; /* 1771: pointer.func */
    em[1774] = 8884097; em[1775] = 8; em[1776] = 0; /* 1774: pointer.func */
    em[1777] = 8884097; em[1778] = 8; em[1779] = 0; /* 1777: pointer.func */
    em[1780] = 8884097; em[1781] = 8; em[1782] = 0; /* 1780: pointer.func */
    em[1783] = 8884097; em[1784] = 8; em[1785] = 0; /* 1783: pointer.func */
    em[1786] = 8884097; em[1787] = 8; em[1788] = 0; /* 1786: pointer.func */
    em[1789] = 8884097; em[1790] = 8; em[1791] = 0; /* 1789: pointer.func */
    em[1792] = 8884097; em[1793] = 8; em[1794] = 0; /* 1792: pointer.func */
    em[1795] = 8884097; em[1796] = 8; em[1797] = 0; /* 1795: pointer.func */
    em[1798] = 8884097; em[1799] = 8; em[1800] = 0; /* 1798: pointer.func */
    em[1801] = 8884097; em[1802] = 8; em[1803] = 0; /* 1801: pointer.func */
    em[1804] = 8884097; em[1805] = 8; em[1806] = 0; /* 1804: pointer.func */
    em[1807] = 8884097; em[1808] = 8; em[1809] = 0; /* 1807: pointer.func */
    em[1810] = 8884097; em[1811] = 8; em[1812] = 0; /* 1810: pointer.func */
    em[1813] = 0; em[1814] = 24; em[1815] = 1; /* 1813: struct.bignum_st */
    	em[1816] = 1818; em[1817] = 0; 
    em[1818] = 8884099; em[1819] = 8; em[1820] = 2; /* 1818: pointer_to_array_of_pointers_to_stack */
    	em[1821] = 849; em[1822] = 0; 
    	em[1823] = 5; em[1824] = 12; 
    em[1825] = 0; em[1826] = 24; em[1827] = 1; /* 1825: struct.bignum_st */
    	em[1828] = 1830; em[1829] = 0; 
    em[1830] = 8884099; em[1831] = 8; em[1832] = 2; /* 1830: pointer_to_array_of_pointers_to_stack */
    	em[1833] = 849; em[1834] = 0; 
    	em[1835] = 5; em[1836] = 12; 
    em[1837] = 1; em[1838] = 8; em[1839] = 1; /* 1837: pointer.struct.ec_extra_data_st */
    	em[1840] = 1842; em[1841] = 0; 
    em[1842] = 0; em[1843] = 40; em[1844] = 5; /* 1842: struct.ec_extra_data_st */
    	em[1845] = 1855; em[1846] = 0; 
    	em[1847] = 932; em[1848] = 8; 
    	em[1849] = 1860; em[1850] = 16; 
    	em[1851] = 1863; em[1852] = 24; 
    	em[1853] = 1863; em[1854] = 32; 
    em[1855] = 1; em[1856] = 8; em[1857] = 1; /* 1855: pointer.struct.ec_extra_data_st */
    	em[1858] = 1842; em[1859] = 0; 
    em[1860] = 8884097; em[1861] = 8; em[1862] = 0; /* 1860: pointer.func */
    em[1863] = 8884097; em[1864] = 8; em[1865] = 0; /* 1863: pointer.func */
    em[1866] = 8884097; em[1867] = 8; em[1868] = 0; /* 1866: pointer.func */
    em[1869] = 1; em[1870] = 8; em[1871] = 1; /* 1869: pointer.struct.ec_point_st */
    	em[1872] = 1630; em[1873] = 0; 
    em[1874] = 1; em[1875] = 8; em[1876] = 1; /* 1874: pointer.struct.bignum_st */
    	em[1877] = 1879; em[1878] = 0; 
    em[1879] = 0; em[1880] = 24; em[1881] = 1; /* 1879: struct.bignum_st */
    	em[1882] = 1884; em[1883] = 0; 
    em[1884] = 8884099; em[1885] = 8; em[1886] = 2; /* 1884: pointer_to_array_of_pointers_to_stack */
    	em[1887] = 849; em[1888] = 0; 
    	em[1889] = 5; em[1890] = 12; 
    em[1891] = 1; em[1892] = 8; em[1893] = 1; /* 1891: pointer.struct.ec_extra_data_st */
    	em[1894] = 1896; em[1895] = 0; 
    em[1896] = 0; em[1897] = 40; em[1898] = 5; /* 1896: struct.ec_extra_data_st */
    	em[1899] = 1909; em[1900] = 0; 
    	em[1901] = 932; em[1902] = 8; 
    	em[1903] = 1860; em[1904] = 16; 
    	em[1905] = 1863; em[1906] = 24; 
    	em[1907] = 1863; em[1908] = 32; 
    em[1909] = 1; em[1910] = 8; em[1911] = 1; /* 1909: pointer.struct.ec_extra_data_st */
    	em[1912] = 1896; em[1913] = 0; 
    em[1914] = 1; em[1915] = 8; em[1916] = 1; /* 1914: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1917] = 1919; em[1918] = 0; 
    em[1919] = 0; em[1920] = 32; em[1921] = 2; /* 1919: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1922] = 1926; em[1923] = 8; 
    	em[1924] = 363; em[1925] = 24; 
    em[1926] = 8884099; em[1927] = 8; em[1928] = 2; /* 1926: pointer_to_array_of_pointers_to_stack */
    	em[1929] = 1933; em[1930] = 0; 
    	em[1931] = 5; em[1932] = 20; 
    em[1933] = 0; em[1934] = 8; em[1935] = 1; /* 1933: pointer.X509_ATTRIBUTE */
    	em[1936] = 1938; em[1937] = 0; 
    em[1938] = 0; em[1939] = 0; em[1940] = 1; /* 1938: X509_ATTRIBUTE */
    	em[1941] = 1943; em[1942] = 0; 
    em[1943] = 0; em[1944] = 24; em[1945] = 2; /* 1943: struct.x509_attributes_st */
    	em[1946] = 145; em[1947] = 0; 
    	em[1948] = 366; em[1949] = 16; 
    em[1950] = 8884097; em[1951] = 8; em[1952] = 0; /* 1950: pointer.func */
    em[1953] = 8884097; em[1954] = 8; em[1955] = 0; /* 1953: pointer.func */
    em[1956] = 0; em[1957] = 120; em[1958] = 8; /* 1956: struct.env_md_st */
    	em[1959] = 1953; em[1960] = 24; 
    	em[1961] = 1975; em[1962] = 32; 
    	em[1963] = 1978; em[1964] = 40; 
    	em[1965] = 1981; em[1966] = 48; 
    	em[1967] = 1953; em[1968] = 56; 
    	em[1969] = 1984; em[1970] = 64; 
    	em[1971] = 1950; em[1972] = 72; 
    	em[1973] = 1987; em[1974] = 112; 
    em[1975] = 8884097; em[1976] = 8; em[1977] = 0; /* 1975: pointer.func */
    em[1978] = 8884097; em[1979] = 8; em[1980] = 0; /* 1978: pointer.func */
    em[1981] = 8884097; em[1982] = 8; em[1983] = 0; /* 1981: pointer.func */
    em[1984] = 8884097; em[1985] = 8; em[1986] = 0; /* 1984: pointer.func */
    em[1987] = 8884097; em[1988] = 8; em[1989] = 0; /* 1987: pointer.func */
    em[1990] = 0; em[1991] = 48; em[1992] = 5; /* 1990: struct.env_md_ctx_st */
    	em[1993] = 2003; em[1994] = 0; 
    	em[1995] = 1070; em[1996] = 8; 
    	em[1997] = 932; em[1998] = 24; 
    	em[1999] = 952; em[2000] = 32; 
    	em[2001] = 1975; em[2002] = 40; 
    em[2003] = 1; em[2004] = 8; em[2005] = 1; /* 2003: pointer.struct.env_md_st */
    	em[2006] = 1956; em[2007] = 0; 
    em[2008] = 0; em[2009] = 1; em[2010] = 0; /* 2008: char */
    em[2011] = 1; em[2012] = 8; em[2013] = 1; /* 2011: pointer.struct.env_md_ctx_st */
    	em[2014] = 1990; em[2015] = 0; 
    args_addr->arg_entity_index[0] = 2011;
    args_addr->arg_entity_index[1] = 2003;
    args_addr->arg_entity_index[2] = 1070;
    args_addr->ret_entity_index = 5;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    const EVP_MD * new_arg_b = *((const EVP_MD * *)new_args->args[1]);

    ENGINE * new_arg_c = *((ENGINE * *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
    orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
    *new_ret_ptr = (*orig_EVP_DigestInit_ex)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    free(args_addr);

    return ret;
}

