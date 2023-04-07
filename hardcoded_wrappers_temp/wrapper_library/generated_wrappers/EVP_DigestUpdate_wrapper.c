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

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c);

int EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestUpdate called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
        orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
        return orig_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
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
    em[735] = 8884097; em[736] = 8; em[737] = 0; /* 735: pointer.func */
    em[738] = 8884097; em[739] = 8; em[740] = 0; /* 738: pointer.func */
    em[741] = 0; em[742] = 112; em[743] = 13; /* 741: struct.rsa_meth_st */
    	em[744] = 149; em[745] = 0; 
    	em[746] = 735; em[747] = 8; 
    	em[748] = 735; em[749] = 16; 
    	em[750] = 735; em[751] = 24; 
    	em[752] = 735; em[753] = 32; 
    	em[754] = 732; em[755] = 40; 
    	em[756] = 729; em[757] = 48; 
    	em[758] = 770; em[759] = 56; 
    	em[760] = 770; em[761] = 64; 
    	em[762] = 130; em[763] = 80; 
    	em[764] = 773; em[765] = 88; 
    	em[766] = 776; em[767] = 96; 
    	em[768] = 726; em[769] = 104; 
    em[770] = 8884097; em[771] = 8; em[772] = 0; /* 770: pointer.func */
    em[773] = 8884097; em[774] = 8; em[775] = 0; /* 773: pointer.func */
    em[776] = 8884097; em[777] = 8; em[778] = 0; /* 776: pointer.func */
    em[779] = 0; em[780] = 1; em[781] = 0; /* 779: char */
    em[782] = 0; em[783] = 24; em[784] = 1; /* 782: struct.bignum_st */
    	em[785] = 787; em[786] = 0; 
    em[787] = 8884099; em[788] = 8; em[789] = 2; /* 787: pointer_to_array_of_pointers_to_stack */
    	em[790] = 380; em[791] = 0; 
    	em[792] = 5; em[793] = 12; 
    em[794] = 0; em[795] = 8; em[796] = 5; /* 794: union.unknown */
    	em[797] = 130; em[798] = 0; 
    	em[799] = 807; em[800] = 0; 
    	em[801] = 960; em[802] = 0; 
    	em[803] = 1091; em[804] = 0; 
    	em[805] = 1209; em[806] = 0; 
    em[807] = 1; em[808] = 8; em[809] = 1; /* 807: pointer.struct.rsa_st */
    	em[810] = 812; em[811] = 0; 
    em[812] = 0; em[813] = 168; em[814] = 17; /* 812: struct.rsa_st */
    	em[815] = 849; em[816] = 16; 
    	em[817] = 383; em[818] = 24; 
    	em[819] = 854; em[820] = 32; 
    	em[821] = 854; em[822] = 40; 
    	em[823] = 854; em[824] = 48; 
    	em[825] = 854; em[826] = 56; 
    	em[827] = 854; em[828] = 64; 
    	em[829] = 854; em[830] = 72; 
    	em[831] = 854; em[832] = 80; 
    	em[833] = 854; em[834] = 88; 
    	em[835] = 871; em[836] = 96; 
    	em[837] = 885; em[838] = 120; 
    	em[839] = 885; em[840] = 128; 
    	em[841] = 885; em[842] = 136; 
    	em[843] = 130; em[844] = 144; 
    	em[845] = 899; em[846] = 152; 
    	em[847] = 899; em[848] = 160; 
    em[849] = 1; em[850] = 8; em[851] = 1; /* 849: pointer.struct.rsa_meth_st */
    	em[852] = 741; em[853] = 0; 
    em[854] = 1; em[855] = 8; em[856] = 1; /* 854: pointer.struct.bignum_st */
    	em[857] = 859; em[858] = 0; 
    em[859] = 0; em[860] = 24; em[861] = 1; /* 859: struct.bignum_st */
    	em[862] = 864; em[863] = 0; 
    em[864] = 8884099; em[865] = 8; em[866] = 2; /* 864: pointer_to_array_of_pointers_to_stack */
    	em[867] = 380; em[868] = 0; 
    	em[869] = 5; em[870] = 12; 
    em[871] = 0; em[872] = 32; em[873] = 2; /* 871: struct.crypto_ex_data_st_fake */
    	em[874] = 878; em[875] = 8; 
    	em[876] = 363; em[877] = 24; 
    em[878] = 8884099; em[879] = 8; em[880] = 2; /* 878: pointer_to_array_of_pointers_to_stack */
    	em[881] = 718; em[882] = 0; 
    	em[883] = 5; em[884] = 20; 
    em[885] = 1; em[886] = 8; em[887] = 1; /* 885: pointer.struct.bn_mont_ctx_st */
    	em[888] = 890; em[889] = 0; 
    em[890] = 0; em[891] = 96; em[892] = 3; /* 890: struct.bn_mont_ctx_st */
    	em[893] = 859; em[894] = 8; 
    	em[895] = 859; em[896] = 32; 
    	em[897] = 859; em[898] = 56; 
    em[899] = 1; em[900] = 8; em[901] = 1; /* 899: pointer.struct.bn_blinding_st */
    	em[902] = 904; em[903] = 0; 
    em[904] = 0; em[905] = 88; em[906] = 7; /* 904: struct.bn_blinding_st */
    	em[907] = 921; em[908] = 0; 
    	em[909] = 921; em[910] = 8; 
    	em[911] = 921; em[912] = 16; 
    	em[913] = 921; em[914] = 24; 
    	em[915] = 938; em[916] = 40; 
    	em[917] = 943; em[918] = 72; 
    	em[919] = 957; em[920] = 80; 
    em[921] = 1; em[922] = 8; em[923] = 1; /* 921: pointer.struct.bignum_st */
    	em[924] = 926; em[925] = 0; 
    em[926] = 0; em[927] = 24; em[928] = 1; /* 926: struct.bignum_st */
    	em[929] = 931; em[930] = 0; 
    em[931] = 8884099; em[932] = 8; em[933] = 2; /* 931: pointer_to_array_of_pointers_to_stack */
    	em[934] = 380; em[935] = 0; 
    	em[936] = 5; em[937] = 12; 
    em[938] = 0; em[939] = 16; em[940] = 1; /* 938: struct.crypto_threadid_st */
    	em[941] = 718; em[942] = 0; 
    em[943] = 1; em[944] = 8; em[945] = 1; /* 943: pointer.struct.bn_mont_ctx_st */
    	em[946] = 948; em[947] = 0; 
    em[948] = 0; em[949] = 96; em[950] = 3; /* 948: struct.bn_mont_ctx_st */
    	em[951] = 926; em[952] = 8; 
    	em[953] = 926; em[954] = 32; 
    	em[955] = 926; em[956] = 56; 
    em[957] = 8884097; em[958] = 8; em[959] = 0; /* 957: pointer.func */
    em[960] = 1; em[961] = 8; em[962] = 1; /* 960: pointer.struct.dsa_st */
    	em[963] = 965; em[964] = 0; 
    em[965] = 0; em[966] = 136; em[967] = 11; /* 965: struct.dsa_st */
    	em[968] = 990; em[969] = 24; 
    	em[970] = 990; em[971] = 32; 
    	em[972] = 990; em[973] = 40; 
    	em[974] = 990; em[975] = 48; 
    	em[976] = 990; em[977] = 56; 
    	em[978] = 990; em[979] = 64; 
    	em[980] = 990; em[981] = 72; 
    	em[982] = 1007; em[983] = 88; 
    	em[984] = 1021; em[985] = 104; 
    	em[986] = 1035; em[987] = 120; 
    	em[988] = 1086; em[989] = 128; 
    em[990] = 1; em[991] = 8; em[992] = 1; /* 990: pointer.struct.bignum_st */
    	em[993] = 995; em[994] = 0; 
    em[995] = 0; em[996] = 24; em[997] = 1; /* 995: struct.bignum_st */
    	em[998] = 1000; em[999] = 0; 
    em[1000] = 8884099; em[1001] = 8; em[1002] = 2; /* 1000: pointer_to_array_of_pointers_to_stack */
    	em[1003] = 380; em[1004] = 0; 
    	em[1005] = 5; em[1006] = 12; 
    em[1007] = 1; em[1008] = 8; em[1009] = 1; /* 1007: pointer.struct.bn_mont_ctx_st */
    	em[1010] = 1012; em[1011] = 0; 
    em[1012] = 0; em[1013] = 96; em[1014] = 3; /* 1012: struct.bn_mont_ctx_st */
    	em[1015] = 995; em[1016] = 8; 
    	em[1017] = 995; em[1018] = 32; 
    	em[1019] = 995; em[1020] = 56; 
    em[1021] = 0; em[1022] = 32; em[1023] = 2; /* 1021: struct.crypto_ex_data_st_fake */
    	em[1024] = 1028; em[1025] = 8; 
    	em[1026] = 363; em[1027] = 24; 
    em[1028] = 8884099; em[1029] = 8; em[1030] = 2; /* 1028: pointer_to_array_of_pointers_to_stack */
    	em[1031] = 718; em[1032] = 0; 
    	em[1033] = 5; em[1034] = 20; 
    em[1035] = 1; em[1036] = 8; em[1037] = 1; /* 1035: pointer.struct.dsa_method */
    	em[1038] = 1040; em[1039] = 0; 
    em[1040] = 0; em[1041] = 96; em[1042] = 11; /* 1040: struct.dsa_method */
    	em[1043] = 149; em[1044] = 0; 
    	em[1045] = 1065; em[1046] = 8; 
    	em[1047] = 1068; em[1048] = 16; 
    	em[1049] = 1071; em[1050] = 24; 
    	em[1051] = 1074; em[1052] = 32; 
    	em[1053] = 1077; em[1054] = 40; 
    	em[1055] = 1080; em[1056] = 48; 
    	em[1057] = 1080; em[1058] = 56; 
    	em[1059] = 130; em[1060] = 72; 
    	em[1061] = 1083; em[1062] = 80; 
    	em[1063] = 1080; em[1064] = 88; 
    em[1065] = 8884097; em[1066] = 8; em[1067] = 0; /* 1065: pointer.func */
    em[1068] = 8884097; em[1069] = 8; em[1070] = 0; /* 1068: pointer.func */
    em[1071] = 8884097; em[1072] = 8; em[1073] = 0; /* 1071: pointer.func */
    em[1074] = 8884097; em[1075] = 8; em[1076] = 0; /* 1074: pointer.func */
    em[1077] = 8884097; em[1078] = 8; em[1079] = 0; /* 1077: pointer.func */
    em[1080] = 8884097; em[1081] = 8; em[1082] = 0; /* 1080: pointer.func */
    em[1083] = 8884097; em[1084] = 8; em[1085] = 0; /* 1083: pointer.func */
    em[1086] = 1; em[1087] = 8; em[1088] = 1; /* 1086: pointer.struct.engine_st */
    	em[1089] = 388; em[1090] = 0; 
    em[1091] = 1; em[1092] = 8; em[1093] = 1; /* 1091: pointer.struct.dh_st */
    	em[1094] = 1096; em[1095] = 0; 
    em[1096] = 0; em[1097] = 144; em[1098] = 12; /* 1096: struct.dh_st */
    	em[1099] = 1123; em[1100] = 8; 
    	em[1101] = 1123; em[1102] = 16; 
    	em[1103] = 1123; em[1104] = 32; 
    	em[1105] = 1123; em[1106] = 40; 
    	em[1107] = 1140; em[1108] = 56; 
    	em[1109] = 1123; em[1110] = 64; 
    	em[1111] = 1123; em[1112] = 72; 
    	em[1113] = 29; em[1114] = 80; 
    	em[1115] = 1123; em[1116] = 96; 
    	em[1117] = 1154; em[1118] = 112; 
    	em[1119] = 1168; em[1120] = 128; 
    	em[1121] = 1204; em[1122] = 136; 
    em[1123] = 1; em[1124] = 8; em[1125] = 1; /* 1123: pointer.struct.bignum_st */
    	em[1126] = 1128; em[1127] = 0; 
    em[1128] = 0; em[1129] = 24; em[1130] = 1; /* 1128: struct.bignum_st */
    	em[1131] = 1133; em[1132] = 0; 
    em[1133] = 8884099; em[1134] = 8; em[1135] = 2; /* 1133: pointer_to_array_of_pointers_to_stack */
    	em[1136] = 380; em[1137] = 0; 
    	em[1138] = 5; em[1139] = 12; 
    em[1140] = 1; em[1141] = 8; em[1142] = 1; /* 1140: pointer.struct.bn_mont_ctx_st */
    	em[1143] = 1145; em[1144] = 0; 
    em[1145] = 0; em[1146] = 96; em[1147] = 3; /* 1145: struct.bn_mont_ctx_st */
    	em[1148] = 1128; em[1149] = 8; 
    	em[1150] = 1128; em[1151] = 32; 
    	em[1152] = 1128; em[1153] = 56; 
    em[1154] = 0; em[1155] = 32; em[1156] = 2; /* 1154: struct.crypto_ex_data_st_fake */
    	em[1157] = 1161; em[1158] = 8; 
    	em[1159] = 363; em[1160] = 24; 
    em[1161] = 8884099; em[1162] = 8; em[1163] = 2; /* 1161: pointer_to_array_of_pointers_to_stack */
    	em[1164] = 718; em[1165] = 0; 
    	em[1166] = 5; em[1167] = 20; 
    em[1168] = 1; em[1169] = 8; em[1170] = 1; /* 1168: pointer.struct.dh_method */
    	em[1171] = 1173; em[1172] = 0; 
    em[1173] = 0; em[1174] = 72; em[1175] = 8; /* 1173: struct.dh_method */
    	em[1176] = 149; em[1177] = 0; 
    	em[1178] = 1192; em[1179] = 8; 
    	em[1180] = 1195; em[1181] = 16; 
    	em[1182] = 1198; em[1183] = 24; 
    	em[1184] = 1192; em[1185] = 32; 
    	em[1186] = 1192; em[1187] = 40; 
    	em[1188] = 130; em[1189] = 56; 
    	em[1190] = 1201; em[1191] = 64; 
    em[1192] = 8884097; em[1193] = 8; em[1194] = 0; /* 1192: pointer.func */
    em[1195] = 8884097; em[1196] = 8; em[1197] = 0; /* 1195: pointer.func */
    em[1198] = 8884097; em[1199] = 8; em[1200] = 0; /* 1198: pointer.func */
    em[1201] = 8884097; em[1202] = 8; em[1203] = 0; /* 1201: pointer.func */
    em[1204] = 1; em[1205] = 8; em[1206] = 1; /* 1204: pointer.struct.engine_st */
    	em[1207] = 388; em[1208] = 0; 
    em[1209] = 1; em[1210] = 8; em[1211] = 1; /* 1209: pointer.struct.ec_key_st */
    	em[1212] = 1214; em[1213] = 0; 
    em[1214] = 0; em[1215] = 56; em[1216] = 4; /* 1214: struct.ec_key_st */
    	em[1217] = 1225; em[1218] = 8; 
    	em[1219] = 1658; em[1220] = 16; 
    	em[1221] = 1663; em[1222] = 24; 
    	em[1223] = 1680; em[1224] = 48; 
    em[1225] = 1; em[1226] = 8; em[1227] = 1; /* 1225: pointer.struct.ec_group_st */
    	em[1228] = 1230; em[1229] = 0; 
    em[1230] = 0; em[1231] = 232; em[1232] = 12; /* 1230: struct.ec_group_st */
    	em[1233] = 1257; em[1234] = 0; 
    	em[1235] = 1426; em[1236] = 8; 
    	em[1237] = 1614; em[1238] = 16; 
    	em[1239] = 1614; em[1240] = 40; 
    	em[1241] = 29; em[1242] = 80; 
    	em[1243] = 1626; em[1244] = 96; 
    	em[1245] = 1614; em[1246] = 104; 
    	em[1247] = 1614; em[1248] = 152; 
    	em[1249] = 1614; em[1250] = 176; 
    	em[1251] = 718; em[1252] = 208; 
    	em[1253] = 718; em[1254] = 216; 
    	em[1255] = 1655; em[1256] = 224; 
    em[1257] = 1; em[1258] = 8; em[1259] = 1; /* 1257: pointer.struct.ec_method_st */
    	em[1260] = 1262; em[1261] = 0; 
    em[1262] = 0; em[1263] = 304; em[1264] = 37; /* 1262: struct.ec_method_st */
    	em[1265] = 1339; em[1266] = 8; 
    	em[1267] = 1342; em[1268] = 16; 
    	em[1269] = 1342; em[1270] = 24; 
    	em[1271] = 1345; em[1272] = 32; 
    	em[1273] = 1348; em[1274] = 40; 
    	em[1275] = 1351; em[1276] = 48; 
    	em[1277] = 1354; em[1278] = 56; 
    	em[1279] = 1357; em[1280] = 64; 
    	em[1281] = 1360; em[1282] = 72; 
    	em[1283] = 1363; em[1284] = 80; 
    	em[1285] = 1363; em[1286] = 88; 
    	em[1287] = 1366; em[1288] = 96; 
    	em[1289] = 1369; em[1290] = 104; 
    	em[1291] = 1372; em[1292] = 112; 
    	em[1293] = 1375; em[1294] = 120; 
    	em[1295] = 1378; em[1296] = 128; 
    	em[1297] = 1381; em[1298] = 136; 
    	em[1299] = 1384; em[1300] = 144; 
    	em[1301] = 1387; em[1302] = 152; 
    	em[1303] = 1390; em[1304] = 160; 
    	em[1305] = 1393; em[1306] = 168; 
    	em[1307] = 1396; em[1308] = 176; 
    	em[1309] = 1399; em[1310] = 184; 
    	em[1311] = 1402; em[1312] = 192; 
    	em[1313] = 1405; em[1314] = 200; 
    	em[1315] = 1408; em[1316] = 208; 
    	em[1317] = 1399; em[1318] = 216; 
    	em[1319] = 1411; em[1320] = 224; 
    	em[1321] = 1414; em[1322] = 232; 
    	em[1323] = 738; em[1324] = 240; 
    	em[1325] = 1354; em[1326] = 248; 
    	em[1327] = 1417; em[1328] = 256; 
    	em[1329] = 1420; em[1330] = 264; 
    	em[1331] = 1417; em[1332] = 272; 
    	em[1333] = 1420; em[1334] = 280; 
    	em[1335] = 1420; em[1336] = 288; 
    	em[1337] = 1423; em[1338] = 296; 
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
    em[1369] = 8884097; em[1370] = 8; em[1371] = 0; /* 1369: pointer.func */
    em[1372] = 8884097; em[1373] = 8; em[1374] = 0; /* 1372: pointer.func */
    em[1375] = 8884097; em[1376] = 8; em[1377] = 0; /* 1375: pointer.func */
    em[1378] = 8884097; em[1379] = 8; em[1380] = 0; /* 1378: pointer.func */
    em[1381] = 8884097; em[1382] = 8; em[1383] = 0; /* 1381: pointer.func */
    em[1384] = 8884097; em[1385] = 8; em[1386] = 0; /* 1384: pointer.func */
    em[1387] = 8884097; em[1388] = 8; em[1389] = 0; /* 1387: pointer.func */
    em[1390] = 8884097; em[1391] = 8; em[1392] = 0; /* 1390: pointer.func */
    em[1393] = 8884097; em[1394] = 8; em[1395] = 0; /* 1393: pointer.func */
    em[1396] = 8884097; em[1397] = 8; em[1398] = 0; /* 1396: pointer.func */
    em[1399] = 8884097; em[1400] = 8; em[1401] = 0; /* 1399: pointer.func */
    em[1402] = 8884097; em[1403] = 8; em[1404] = 0; /* 1402: pointer.func */
    em[1405] = 8884097; em[1406] = 8; em[1407] = 0; /* 1405: pointer.func */
    em[1408] = 8884097; em[1409] = 8; em[1410] = 0; /* 1408: pointer.func */
    em[1411] = 8884097; em[1412] = 8; em[1413] = 0; /* 1411: pointer.func */
    em[1414] = 8884097; em[1415] = 8; em[1416] = 0; /* 1414: pointer.func */
    em[1417] = 8884097; em[1418] = 8; em[1419] = 0; /* 1417: pointer.func */
    em[1420] = 8884097; em[1421] = 8; em[1422] = 0; /* 1420: pointer.func */
    em[1423] = 8884097; em[1424] = 8; em[1425] = 0; /* 1423: pointer.func */
    em[1426] = 1; em[1427] = 8; em[1428] = 1; /* 1426: pointer.struct.ec_point_st */
    	em[1429] = 1431; em[1430] = 0; 
    em[1431] = 0; em[1432] = 88; em[1433] = 4; /* 1431: struct.ec_point_st */
    	em[1434] = 1442; em[1435] = 0; 
    	em[1436] = 782; em[1437] = 8; 
    	em[1438] = 782; em[1439] = 32; 
    	em[1440] = 782; em[1441] = 56; 
    em[1442] = 1; em[1443] = 8; em[1444] = 1; /* 1442: pointer.struct.ec_method_st */
    	em[1445] = 1447; em[1446] = 0; 
    em[1447] = 0; em[1448] = 304; em[1449] = 37; /* 1447: struct.ec_method_st */
    	em[1450] = 1524; em[1451] = 8; 
    	em[1452] = 1527; em[1453] = 16; 
    	em[1454] = 1527; em[1455] = 24; 
    	em[1456] = 1530; em[1457] = 32; 
    	em[1458] = 1533; em[1459] = 40; 
    	em[1460] = 1536; em[1461] = 48; 
    	em[1462] = 1539; em[1463] = 56; 
    	em[1464] = 1542; em[1465] = 64; 
    	em[1466] = 1545; em[1467] = 72; 
    	em[1468] = 1548; em[1469] = 80; 
    	em[1470] = 1548; em[1471] = 88; 
    	em[1472] = 1551; em[1473] = 96; 
    	em[1474] = 1554; em[1475] = 104; 
    	em[1476] = 1557; em[1477] = 112; 
    	em[1478] = 1560; em[1479] = 120; 
    	em[1480] = 1563; em[1481] = 128; 
    	em[1482] = 1566; em[1483] = 136; 
    	em[1484] = 1569; em[1485] = 144; 
    	em[1486] = 1572; em[1487] = 152; 
    	em[1488] = 1575; em[1489] = 160; 
    	em[1490] = 1578; em[1491] = 168; 
    	em[1492] = 1581; em[1493] = 176; 
    	em[1494] = 1584; em[1495] = 184; 
    	em[1496] = 1587; em[1497] = 192; 
    	em[1498] = 1590; em[1499] = 200; 
    	em[1500] = 1593; em[1501] = 208; 
    	em[1502] = 1584; em[1503] = 216; 
    	em[1504] = 1596; em[1505] = 224; 
    	em[1506] = 1599; em[1507] = 232; 
    	em[1508] = 1602; em[1509] = 240; 
    	em[1510] = 1539; em[1511] = 248; 
    	em[1512] = 1605; em[1513] = 256; 
    	em[1514] = 1608; em[1515] = 264; 
    	em[1516] = 1605; em[1517] = 272; 
    	em[1518] = 1608; em[1519] = 280; 
    	em[1520] = 1608; em[1521] = 288; 
    	em[1522] = 1611; em[1523] = 296; 
    em[1524] = 8884097; em[1525] = 8; em[1526] = 0; /* 1524: pointer.func */
    em[1527] = 8884097; em[1528] = 8; em[1529] = 0; /* 1527: pointer.func */
    em[1530] = 8884097; em[1531] = 8; em[1532] = 0; /* 1530: pointer.func */
    em[1533] = 8884097; em[1534] = 8; em[1535] = 0; /* 1533: pointer.func */
    em[1536] = 8884097; em[1537] = 8; em[1538] = 0; /* 1536: pointer.func */
    em[1539] = 8884097; em[1540] = 8; em[1541] = 0; /* 1539: pointer.func */
    em[1542] = 8884097; em[1543] = 8; em[1544] = 0; /* 1542: pointer.func */
    em[1545] = 8884097; em[1546] = 8; em[1547] = 0; /* 1545: pointer.func */
    em[1548] = 8884097; em[1549] = 8; em[1550] = 0; /* 1548: pointer.func */
    em[1551] = 8884097; em[1552] = 8; em[1553] = 0; /* 1551: pointer.func */
    em[1554] = 8884097; em[1555] = 8; em[1556] = 0; /* 1554: pointer.func */
    em[1557] = 8884097; em[1558] = 8; em[1559] = 0; /* 1557: pointer.func */
    em[1560] = 8884097; em[1561] = 8; em[1562] = 0; /* 1560: pointer.func */
    em[1563] = 8884097; em[1564] = 8; em[1565] = 0; /* 1563: pointer.func */
    em[1566] = 8884097; em[1567] = 8; em[1568] = 0; /* 1566: pointer.func */
    em[1569] = 8884097; em[1570] = 8; em[1571] = 0; /* 1569: pointer.func */
    em[1572] = 8884097; em[1573] = 8; em[1574] = 0; /* 1572: pointer.func */
    em[1575] = 8884097; em[1576] = 8; em[1577] = 0; /* 1575: pointer.func */
    em[1578] = 8884097; em[1579] = 8; em[1580] = 0; /* 1578: pointer.func */
    em[1581] = 8884097; em[1582] = 8; em[1583] = 0; /* 1581: pointer.func */
    em[1584] = 8884097; em[1585] = 8; em[1586] = 0; /* 1584: pointer.func */
    em[1587] = 8884097; em[1588] = 8; em[1589] = 0; /* 1587: pointer.func */
    em[1590] = 8884097; em[1591] = 8; em[1592] = 0; /* 1590: pointer.func */
    em[1593] = 8884097; em[1594] = 8; em[1595] = 0; /* 1593: pointer.func */
    em[1596] = 8884097; em[1597] = 8; em[1598] = 0; /* 1596: pointer.func */
    em[1599] = 8884097; em[1600] = 8; em[1601] = 0; /* 1599: pointer.func */
    em[1602] = 8884097; em[1603] = 8; em[1604] = 0; /* 1602: pointer.func */
    em[1605] = 8884097; em[1606] = 8; em[1607] = 0; /* 1605: pointer.func */
    em[1608] = 8884097; em[1609] = 8; em[1610] = 0; /* 1608: pointer.func */
    em[1611] = 8884097; em[1612] = 8; em[1613] = 0; /* 1611: pointer.func */
    em[1614] = 0; em[1615] = 24; em[1616] = 1; /* 1614: struct.bignum_st */
    	em[1617] = 1619; em[1618] = 0; 
    em[1619] = 8884099; em[1620] = 8; em[1621] = 2; /* 1619: pointer_to_array_of_pointers_to_stack */
    	em[1622] = 380; em[1623] = 0; 
    	em[1624] = 5; em[1625] = 12; 
    em[1626] = 1; em[1627] = 8; em[1628] = 1; /* 1626: pointer.struct.ec_extra_data_st */
    	em[1629] = 1631; em[1630] = 0; 
    em[1631] = 0; em[1632] = 40; em[1633] = 5; /* 1631: struct.ec_extra_data_st */
    	em[1634] = 1644; em[1635] = 0; 
    	em[1636] = 718; em[1637] = 8; 
    	em[1638] = 1649; em[1639] = 16; 
    	em[1640] = 1652; em[1641] = 24; 
    	em[1642] = 1652; em[1643] = 32; 
    em[1644] = 1; em[1645] = 8; em[1646] = 1; /* 1644: pointer.struct.ec_extra_data_st */
    	em[1647] = 1631; em[1648] = 0; 
    em[1649] = 8884097; em[1650] = 8; em[1651] = 0; /* 1649: pointer.func */
    em[1652] = 8884097; em[1653] = 8; em[1654] = 0; /* 1652: pointer.func */
    em[1655] = 8884097; em[1656] = 8; em[1657] = 0; /* 1655: pointer.func */
    em[1658] = 1; em[1659] = 8; em[1660] = 1; /* 1658: pointer.struct.ec_point_st */
    	em[1661] = 1431; em[1662] = 0; 
    em[1663] = 1; em[1664] = 8; em[1665] = 1; /* 1663: pointer.struct.bignum_st */
    	em[1666] = 1668; em[1667] = 0; 
    em[1668] = 0; em[1669] = 24; em[1670] = 1; /* 1668: struct.bignum_st */
    	em[1671] = 1673; em[1672] = 0; 
    em[1673] = 8884099; em[1674] = 8; em[1675] = 2; /* 1673: pointer_to_array_of_pointers_to_stack */
    	em[1676] = 380; em[1677] = 0; 
    	em[1678] = 5; em[1679] = 12; 
    em[1680] = 1; em[1681] = 8; em[1682] = 1; /* 1680: pointer.struct.ec_extra_data_st */
    	em[1683] = 1685; em[1684] = 0; 
    em[1685] = 0; em[1686] = 40; em[1687] = 5; /* 1685: struct.ec_extra_data_st */
    	em[1688] = 1698; em[1689] = 0; 
    	em[1690] = 718; em[1691] = 8; 
    	em[1692] = 1649; em[1693] = 16; 
    	em[1694] = 1652; em[1695] = 24; 
    	em[1696] = 1652; em[1697] = 32; 
    em[1698] = 1; em[1699] = 8; em[1700] = 1; /* 1698: pointer.struct.ec_extra_data_st */
    	em[1701] = 1685; em[1702] = 0; 
    em[1703] = 8884097; em[1704] = 8; em[1705] = 0; /* 1703: pointer.func */
    em[1706] = 0; em[1707] = 56; em[1708] = 4; /* 1706: struct.evp_pkey_st */
    	em[1709] = 1717; em[1710] = 16; 
    	em[1711] = 1815; em[1712] = 24; 
    	em[1713] = 794; em[1714] = 32; 
    	em[1715] = 1820; em[1716] = 48; 
    em[1717] = 1; em[1718] = 8; em[1719] = 1; /* 1717: pointer.struct.evp_pkey_asn1_method_st */
    	em[1720] = 1722; em[1721] = 0; 
    em[1722] = 0; em[1723] = 208; em[1724] = 24; /* 1722: struct.evp_pkey_asn1_method_st */
    	em[1725] = 130; em[1726] = 16; 
    	em[1727] = 130; em[1728] = 24; 
    	em[1729] = 1773; em[1730] = 32; 
    	em[1731] = 1776; em[1732] = 40; 
    	em[1733] = 1779; em[1734] = 48; 
    	em[1735] = 1703; em[1736] = 56; 
    	em[1737] = 1782; em[1738] = 64; 
    	em[1739] = 1785; em[1740] = 72; 
    	em[1741] = 1703; em[1742] = 80; 
    	em[1743] = 1788; em[1744] = 88; 
    	em[1745] = 1788; em[1746] = 96; 
    	em[1747] = 1791; em[1748] = 104; 
    	em[1749] = 1794; em[1750] = 112; 
    	em[1751] = 1788; em[1752] = 120; 
    	em[1753] = 1797; em[1754] = 128; 
    	em[1755] = 1779; em[1756] = 136; 
    	em[1757] = 1703; em[1758] = 144; 
    	em[1759] = 1800; em[1760] = 152; 
    	em[1761] = 1803; em[1762] = 160; 
    	em[1763] = 1806; em[1764] = 168; 
    	em[1765] = 1791; em[1766] = 176; 
    	em[1767] = 1794; em[1768] = 184; 
    	em[1769] = 1809; em[1770] = 192; 
    	em[1771] = 1812; em[1772] = 200; 
    em[1773] = 8884097; em[1774] = 8; em[1775] = 0; /* 1773: pointer.func */
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
    em[1812] = 8884097; em[1813] = 8; em[1814] = 0; /* 1812: pointer.func */
    em[1815] = 1; em[1816] = 8; em[1817] = 1; /* 1815: pointer.struct.engine_st */
    	em[1818] = 388; em[1819] = 0; 
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
    em[1859] = 8884097; em[1860] = 8; em[1861] = 0; /* 1859: pointer.func */
    em[1862] = 8884097; em[1863] = 8; em[1864] = 0; /* 1862: pointer.func */
    em[1865] = 8884097; em[1866] = 8; em[1867] = 0; /* 1865: pointer.func */
    em[1868] = 8884097; em[1869] = 8; em[1870] = 0; /* 1868: pointer.func */
    em[1871] = 1; em[1872] = 8; em[1873] = 1; /* 1871: pointer.struct.evp_pkey_ctx_st */
    	em[1874] = 1876; em[1875] = 0; 
    em[1876] = 0; em[1877] = 80; em[1878] = 8; /* 1876: struct.evp_pkey_ctx_st */
    	em[1879] = 1895; em[1880] = 0; 
    	em[1881] = 1815; em[1882] = 8; 
    	em[1883] = 1974; em[1884] = 16; 
    	em[1885] = 1974; em[1886] = 24; 
    	em[1887] = 718; em[1888] = 40; 
    	em[1889] = 718; em[1890] = 48; 
    	em[1891] = 8; em[1892] = 56; 
    	em[1893] = 0; em[1894] = 64; 
    em[1895] = 1; em[1896] = 8; em[1897] = 1; /* 1895: pointer.struct.evp_pkey_method_st */
    	em[1898] = 1900; em[1899] = 0; 
    em[1900] = 0; em[1901] = 208; em[1902] = 25; /* 1900: struct.evp_pkey_method_st */
    	em[1903] = 1953; em[1904] = 8; 
    	em[1905] = 1956; em[1906] = 16; 
    	em[1907] = 1868; em[1908] = 24; 
    	em[1909] = 1953; em[1910] = 32; 
    	em[1911] = 1959; em[1912] = 40; 
    	em[1913] = 1953; em[1914] = 48; 
    	em[1915] = 1959; em[1916] = 56; 
    	em[1917] = 1953; em[1918] = 64; 
    	em[1919] = 1865; em[1920] = 72; 
    	em[1921] = 1953; em[1922] = 80; 
    	em[1923] = 1862; em[1924] = 88; 
    	em[1925] = 1953; em[1926] = 96; 
    	em[1927] = 1865; em[1928] = 104; 
    	em[1929] = 1962; em[1930] = 112; 
    	em[1931] = 1859; em[1932] = 120; 
    	em[1933] = 1962; em[1934] = 128; 
    	em[1935] = 1965; em[1936] = 136; 
    	em[1937] = 1953; em[1938] = 144; 
    	em[1939] = 1865; em[1940] = 152; 
    	em[1941] = 1953; em[1942] = 160; 
    	em[1943] = 1865; em[1944] = 168; 
    	em[1945] = 1953; em[1946] = 176; 
    	em[1947] = 1968; em[1948] = 184; 
    	em[1949] = 1971; em[1950] = 192; 
    	em[1951] = 1856; em[1952] = 200; 
    em[1953] = 8884097; em[1954] = 8; em[1955] = 0; /* 1953: pointer.func */
    em[1956] = 8884097; em[1957] = 8; em[1958] = 0; /* 1956: pointer.func */
    em[1959] = 8884097; em[1960] = 8; em[1961] = 0; /* 1959: pointer.func */
    em[1962] = 8884097; em[1963] = 8; em[1964] = 0; /* 1962: pointer.func */
    em[1965] = 8884097; em[1966] = 8; em[1967] = 0; /* 1965: pointer.func */
    em[1968] = 8884097; em[1969] = 8; em[1970] = 0; /* 1968: pointer.func */
    em[1971] = 8884097; em[1972] = 8; em[1973] = 0; /* 1971: pointer.func */
    em[1974] = 1; em[1975] = 8; em[1976] = 1; /* 1974: pointer.struct.evp_pkey_st */
    	em[1977] = 1706; em[1978] = 0; 
    em[1979] = 8884097; em[1980] = 8; em[1981] = 0; /* 1979: pointer.func */
    em[1982] = 8884097; em[1983] = 8; em[1984] = 0; /* 1982: pointer.func */
    em[1985] = 0; em[1986] = 120; em[1987] = 8; /* 1985: struct.env_md_st */
    	em[1988] = 2004; em[1989] = 24; 
    	em[1990] = 2007; em[1991] = 32; 
    	em[1992] = 2010; em[1993] = 40; 
    	em[1994] = 1979; em[1995] = 48; 
    	em[1996] = 2004; em[1997] = 56; 
    	em[1998] = 1982; em[1999] = 64; 
    	em[2000] = 2013; em[2001] = 72; 
    	em[2002] = 2016; em[2003] = 112; 
    em[2004] = 8884097; em[2005] = 8; em[2006] = 0; /* 2004: pointer.func */
    em[2007] = 8884097; em[2008] = 8; em[2009] = 0; /* 2007: pointer.func */
    em[2010] = 8884097; em[2011] = 8; em[2012] = 0; /* 2010: pointer.func */
    em[2013] = 8884097; em[2014] = 8; em[2015] = 0; /* 2013: pointer.func */
    em[2016] = 8884097; em[2017] = 8; em[2018] = 0; /* 2016: pointer.func */
    em[2019] = 0; em[2020] = 48; em[2021] = 5; /* 2019: struct.env_md_ctx_st */
    	em[2022] = 2032; em[2023] = 0; 
    	em[2024] = 1815; em[2025] = 8; 
    	em[2026] = 718; em[2027] = 24; 
    	em[2028] = 1871; em[2029] = 32; 
    	em[2030] = 2007; em[2031] = 40; 
    em[2032] = 1; em[2033] = 8; em[2034] = 1; /* 2032: pointer.struct.env_md_st */
    	em[2035] = 1985; em[2036] = 0; 
    em[2037] = 0; em[2038] = 0; em[2039] = 0; /* 2037: size_t */
    em[2040] = 1; em[2041] = 8; em[2042] = 1; /* 2040: pointer.struct.env_md_ctx_st */
    	em[2043] = 2019; em[2044] = 0; 
    args_addr->arg_entity_index[0] = 2040;
    args_addr->arg_entity_index[1] = 718;
    args_addr->arg_entity_index[2] = 2037;
    args_addr->ret_entity_index = 5;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

     const void * new_arg_b = *(( const void * *)new_args->args[1]);

    size_t new_arg_c = *((size_t *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
    orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
    *new_ret_ptr = (*orig_EVP_DigestUpdate)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    free(args_addr);

    return ret;
}

