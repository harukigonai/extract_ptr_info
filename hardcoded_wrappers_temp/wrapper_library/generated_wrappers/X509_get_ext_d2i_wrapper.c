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

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d);

void * X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_ext_d2i called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    else {
        void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
        orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
        return orig_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    }
}

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    void * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 16; em[2] = 2; /* 0: struct.EDIPartyName_st */
    	em[3] = 7; em[4] = 0; 
    	em[5] = 7; em[6] = 8; 
    em[7] = 1; em[8] = 8; em[9] = 1; /* 7: pointer.struct.asn1_string_st */
    	em[10] = 12; em[11] = 0; 
    em[12] = 0; em[13] = 24; em[14] = 1; /* 12: struct.asn1_string_st */
    	em[15] = 17; em[16] = 8; 
    em[17] = 1; em[18] = 8; em[19] = 1; /* 17: pointer.unsigned char */
    	em[20] = 22; em[21] = 0; 
    em[22] = 0; em[23] = 1; em[24] = 0; /* 22: unsigned char */
    em[25] = 1; em[26] = 8; em[27] = 1; /* 25: pointer.struct.EDIPartyName_st */
    	em[28] = 0; em[29] = 0; 
    em[30] = 0; em[31] = 24; em[32] = 1; /* 30: struct.buf_mem_st */
    	em[33] = 35; em[34] = 8; 
    em[35] = 1; em[36] = 8; em[37] = 1; /* 35: pointer.char */
    	em[38] = 8884096; em[39] = 0; 
    em[40] = 1; em[41] = 8; em[42] = 1; /* 40: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[43] = 45; em[44] = 0; 
    em[45] = 0; em[46] = 32; em[47] = 2; /* 45: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[48] = 52; em[49] = 8; 
    	em[50] = 113; em[51] = 24; 
    em[52] = 8884099; em[53] = 8; em[54] = 2; /* 52: pointer_to_array_of_pointers_to_stack */
    	em[55] = 59; em[56] = 0; 
    	em[57] = 110; em[58] = 20; 
    em[59] = 0; em[60] = 8; em[61] = 1; /* 59: pointer.X509_NAME_ENTRY */
    	em[62] = 64; em[63] = 0; 
    em[64] = 0; em[65] = 0; em[66] = 1; /* 64: X509_NAME_ENTRY */
    	em[67] = 69; em[68] = 0; 
    em[69] = 0; em[70] = 24; em[71] = 2; /* 69: struct.X509_name_entry_st */
    	em[72] = 76; em[73] = 0; 
    	em[74] = 100; em[75] = 8; 
    em[76] = 1; em[77] = 8; em[78] = 1; /* 76: pointer.struct.asn1_object_st */
    	em[79] = 81; em[80] = 0; 
    em[81] = 0; em[82] = 40; em[83] = 3; /* 81: struct.asn1_object_st */
    	em[84] = 90; em[85] = 0; 
    	em[86] = 90; em[87] = 8; 
    	em[88] = 95; em[89] = 24; 
    em[90] = 1; em[91] = 8; em[92] = 1; /* 90: pointer.char */
    	em[93] = 8884096; em[94] = 0; 
    em[95] = 1; em[96] = 8; em[97] = 1; /* 95: pointer.unsigned char */
    	em[98] = 22; em[99] = 0; 
    em[100] = 1; em[101] = 8; em[102] = 1; /* 100: pointer.struct.asn1_string_st */
    	em[103] = 105; em[104] = 0; 
    em[105] = 0; em[106] = 24; em[107] = 1; /* 105: struct.asn1_string_st */
    	em[108] = 17; em[109] = 8; 
    em[110] = 0; em[111] = 4; em[112] = 0; /* 110: int */
    em[113] = 8884097; em[114] = 8; em[115] = 0; /* 113: pointer.func */
    em[116] = 1; em[117] = 8; em[118] = 1; /* 116: pointer.struct.X509_name_st */
    	em[119] = 121; em[120] = 0; 
    em[121] = 0; em[122] = 40; em[123] = 3; /* 121: struct.X509_name_st */
    	em[124] = 40; em[125] = 0; 
    	em[126] = 130; em[127] = 16; 
    	em[128] = 17; em[129] = 24; 
    em[130] = 1; em[131] = 8; em[132] = 1; /* 130: pointer.struct.buf_mem_st */
    	em[133] = 30; em[134] = 0; 
    em[135] = 1; em[136] = 8; em[137] = 1; /* 135: pointer.struct.asn1_string_st */
    	em[138] = 12; em[139] = 0; 
    em[140] = 1; em[141] = 8; em[142] = 1; /* 140: pointer.struct.asn1_string_st */
    	em[143] = 12; em[144] = 0; 
    em[145] = 1; em[146] = 8; em[147] = 1; /* 145: pointer.struct.asn1_string_st */
    	em[148] = 12; em[149] = 0; 
    em[150] = 1; em[151] = 8; em[152] = 1; /* 150: pointer.struct.asn1_string_st */
    	em[153] = 12; em[154] = 0; 
    em[155] = 0; em[156] = 8; em[157] = 20; /* 155: union.unknown */
    	em[158] = 35; em[159] = 0; 
    	em[160] = 7; em[161] = 0; 
    	em[162] = 198; em[163] = 0; 
    	em[164] = 212; em[165] = 0; 
    	em[166] = 217; em[167] = 0; 
    	em[168] = 222; em[169] = 0; 
    	em[170] = 150; em[171] = 0; 
    	em[172] = 227; em[173] = 0; 
    	em[174] = 232; em[175] = 0; 
    	em[176] = 237; em[177] = 0; 
    	em[178] = 145; em[179] = 0; 
    	em[180] = 140; em[181] = 0; 
    	em[182] = 242; em[183] = 0; 
    	em[184] = 247; em[185] = 0; 
    	em[186] = 135; em[187] = 0; 
    	em[188] = 252; em[189] = 0; 
    	em[190] = 257; em[191] = 0; 
    	em[192] = 7; em[193] = 0; 
    	em[194] = 7; em[195] = 0; 
    	em[196] = 262; em[197] = 0; 
    em[198] = 1; em[199] = 8; em[200] = 1; /* 198: pointer.struct.asn1_object_st */
    	em[201] = 203; em[202] = 0; 
    em[203] = 0; em[204] = 40; em[205] = 3; /* 203: struct.asn1_object_st */
    	em[206] = 90; em[207] = 0; 
    	em[208] = 90; em[209] = 8; 
    	em[210] = 95; em[211] = 24; 
    em[212] = 1; em[213] = 8; em[214] = 1; /* 212: pointer.struct.asn1_string_st */
    	em[215] = 12; em[216] = 0; 
    em[217] = 1; em[218] = 8; em[219] = 1; /* 217: pointer.struct.asn1_string_st */
    	em[220] = 12; em[221] = 0; 
    em[222] = 1; em[223] = 8; em[224] = 1; /* 222: pointer.struct.asn1_string_st */
    	em[225] = 12; em[226] = 0; 
    em[227] = 1; em[228] = 8; em[229] = 1; /* 227: pointer.struct.asn1_string_st */
    	em[230] = 12; em[231] = 0; 
    em[232] = 1; em[233] = 8; em[234] = 1; /* 232: pointer.struct.asn1_string_st */
    	em[235] = 12; em[236] = 0; 
    em[237] = 1; em[238] = 8; em[239] = 1; /* 237: pointer.struct.asn1_string_st */
    	em[240] = 12; em[241] = 0; 
    em[242] = 1; em[243] = 8; em[244] = 1; /* 242: pointer.struct.asn1_string_st */
    	em[245] = 12; em[246] = 0; 
    em[247] = 1; em[248] = 8; em[249] = 1; /* 247: pointer.struct.asn1_string_st */
    	em[250] = 12; em[251] = 0; 
    em[252] = 1; em[253] = 8; em[254] = 1; /* 252: pointer.struct.asn1_string_st */
    	em[255] = 12; em[256] = 0; 
    em[257] = 1; em[258] = 8; em[259] = 1; /* 257: pointer.struct.asn1_string_st */
    	em[260] = 12; em[261] = 0; 
    em[262] = 1; em[263] = 8; em[264] = 1; /* 262: pointer.struct.ASN1_VALUE_st */
    	em[265] = 267; em[266] = 0; 
    em[267] = 0; em[268] = 0; em[269] = 0; /* 267: struct.ASN1_VALUE_st */
    em[270] = 0; em[271] = 16; em[272] = 1; /* 270: struct.asn1_type_st */
    	em[273] = 155; em[274] = 8; 
    em[275] = 0; em[276] = 16; em[277] = 1; /* 275: struct.GENERAL_NAME_st */
    	em[278] = 280; em[279] = 8; 
    em[280] = 0; em[281] = 8; em[282] = 15; /* 280: union.unknown */
    	em[283] = 35; em[284] = 0; 
    	em[285] = 313; em[286] = 0; 
    	em[287] = 237; em[288] = 0; 
    	em[289] = 237; em[290] = 0; 
    	em[291] = 325; em[292] = 0; 
    	em[293] = 116; em[294] = 0; 
    	em[295] = 25; em[296] = 0; 
    	em[297] = 237; em[298] = 0; 
    	em[299] = 150; em[300] = 0; 
    	em[301] = 198; em[302] = 0; 
    	em[303] = 150; em[304] = 0; 
    	em[305] = 116; em[306] = 0; 
    	em[307] = 237; em[308] = 0; 
    	em[309] = 198; em[310] = 0; 
    	em[311] = 325; em[312] = 0; 
    em[313] = 1; em[314] = 8; em[315] = 1; /* 313: pointer.struct.otherName_st */
    	em[316] = 318; em[317] = 0; 
    em[318] = 0; em[319] = 16; em[320] = 2; /* 318: struct.otherName_st */
    	em[321] = 198; em[322] = 0; 
    	em[323] = 325; em[324] = 8; 
    em[325] = 1; em[326] = 8; em[327] = 1; /* 325: pointer.struct.asn1_type_st */
    	em[328] = 270; em[329] = 0; 
    em[330] = 1; em[331] = 8; em[332] = 1; /* 330: pointer.struct.asn1_string_st */
    	em[333] = 335; em[334] = 0; 
    em[335] = 0; em[336] = 24; em[337] = 1; /* 335: struct.asn1_string_st */
    	em[338] = 17; em[339] = 8; 
    em[340] = 0; em[341] = 0; em[342] = 1; /* 340: GENERAL_SUBTREE */
    	em[343] = 345; em[344] = 0; 
    em[345] = 0; em[346] = 24; em[347] = 3; /* 345: struct.GENERAL_SUBTREE_st */
    	em[348] = 354; em[349] = 0; 
    	em[350] = 212; em[351] = 8; 
    	em[352] = 212; em[353] = 16; 
    em[354] = 1; em[355] = 8; em[356] = 1; /* 354: pointer.struct.GENERAL_NAME_st */
    	em[357] = 275; em[358] = 0; 
    em[359] = 1; em[360] = 8; em[361] = 1; /* 359: pointer.struct.NAME_CONSTRAINTS_st */
    	em[362] = 364; em[363] = 0; 
    em[364] = 0; em[365] = 16; em[366] = 2; /* 364: struct.NAME_CONSTRAINTS_st */
    	em[367] = 371; em[368] = 0; 
    	em[369] = 371; em[370] = 8; 
    em[371] = 1; em[372] = 8; em[373] = 1; /* 371: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[374] = 376; em[375] = 0; 
    em[376] = 0; em[377] = 32; em[378] = 2; /* 376: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[379] = 383; em[380] = 8; 
    	em[381] = 113; em[382] = 24; 
    em[383] = 8884099; em[384] = 8; em[385] = 2; /* 383: pointer_to_array_of_pointers_to_stack */
    	em[386] = 390; em[387] = 0; 
    	em[388] = 110; em[389] = 20; 
    em[390] = 0; em[391] = 8; em[392] = 1; /* 390: pointer.GENERAL_SUBTREE */
    	em[393] = 340; em[394] = 0; 
    em[395] = 1; em[396] = 8; em[397] = 1; /* 395: pointer.struct.stack_st_GENERAL_NAME */
    	em[398] = 400; em[399] = 0; 
    em[400] = 0; em[401] = 32; em[402] = 2; /* 400: struct.stack_st_fake_GENERAL_NAME */
    	em[403] = 407; em[404] = 8; 
    	em[405] = 113; em[406] = 24; 
    em[407] = 8884099; em[408] = 8; em[409] = 2; /* 407: pointer_to_array_of_pointers_to_stack */
    	em[410] = 414; em[411] = 0; 
    	em[412] = 110; em[413] = 20; 
    em[414] = 0; em[415] = 8; em[416] = 1; /* 414: pointer.GENERAL_NAME */
    	em[417] = 419; em[418] = 0; 
    em[419] = 0; em[420] = 0; em[421] = 1; /* 419: GENERAL_NAME */
    	em[422] = 424; em[423] = 0; 
    em[424] = 0; em[425] = 16; em[426] = 1; /* 424: struct.GENERAL_NAME_st */
    	em[427] = 429; em[428] = 8; 
    em[429] = 0; em[430] = 8; em[431] = 15; /* 429: union.unknown */
    	em[432] = 35; em[433] = 0; 
    	em[434] = 462; em[435] = 0; 
    	em[436] = 581; em[437] = 0; 
    	em[438] = 581; em[439] = 0; 
    	em[440] = 488; em[441] = 0; 
    	em[442] = 629; em[443] = 0; 
    	em[444] = 677; em[445] = 0; 
    	em[446] = 581; em[447] = 0; 
    	em[448] = 566; em[449] = 0; 
    	em[450] = 474; em[451] = 0; 
    	em[452] = 566; em[453] = 0; 
    	em[454] = 629; em[455] = 0; 
    	em[456] = 581; em[457] = 0; 
    	em[458] = 474; em[459] = 0; 
    	em[460] = 488; em[461] = 0; 
    em[462] = 1; em[463] = 8; em[464] = 1; /* 462: pointer.struct.otherName_st */
    	em[465] = 467; em[466] = 0; 
    em[467] = 0; em[468] = 16; em[469] = 2; /* 467: struct.otherName_st */
    	em[470] = 474; em[471] = 0; 
    	em[472] = 488; em[473] = 8; 
    em[474] = 1; em[475] = 8; em[476] = 1; /* 474: pointer.struct.asn1_object_st */
    	em[477] = 479; em[478] = 0; 
    em[479] = 0; em[480] = 40; em[481] = 3; /* 479: struct.asn1_object_st */
    	em[482] = 90; em[483] = 0; 
    	em[484] = 90; em[485] = 8; 
    	em[486] = 95; em[487] = 24; 
    em[488] = 1; em[489] = 8; em[490] = 1; /* 488: pointer.struct.asn1_type_st */
    	em[491] = 493; em[492] = 0; 
    em[493] = 0; em[494] = 16; em[495] = 1; /* 493: struct.asn1_type_st */
    	em[496] = 498; em[497] = 8; 
    em[498] = 0; em[499] = 8; em[500] = 20; /* 498: union.unknown */
    	em[501] = 35; em[502] = 0; 
    	em[503] = 541; em[504] = 0; 
    	em[505] = 474; em[506] = 0; 
    	em[507] = 551; em[508] = 0; 
    	em[509] = 556; em[510] = 0; 
    	em[511] = 561; em[512] = 0; 
    	em[513] = 566; em[514] = 0; 
    	em[515] = 571; em[516] = 0; 
    	em[517] = 576; em[518] = 0; 
    	em[519] = 581; em[520] = 0; 
    	em[521] = 586; em[522] = 0; 
    	em[523] = 591; em[524] = 0; 
    	em[525] = 596; em[526] = 0; 
    	em[527] = 601; em[528] = 0; 
    	em[529] = 606; em[530] = 0; 
    	em[531] = 611; em[532] = 0; 
    	em[533] = 616; em[534] = 0; 
    	em[535] = 541; em[536] = 0; 
    	em[537] = 541; em[538] = 0; 
    	em[539] = 621; em[540] = 0; 
    em[541] = 1; em[542] = 8; em[543] = 1; /* 541: pointer.struct.asn1_string_st */
    	em[544] = 546; em[545] = 0; 
    em[546] = 0; em[547] = 24; em[548] = 1; /* 546: struct.asn1_string_st */
    	em[549] = 17; em[550] = 8; 
    em[551] = 1; em[552] = 8; em[553] = 1; /* 551: pointer.struct.asn1_string_st */
    	em[554] = 546; em[555] = 0; 
    em[556] = 1; em[557] = 8; em[558] = 1; /* 556: pointer.struct.asn1_string_st */
    	em[559] = 546; em[560] = 0; 
    em[561] = 1; em[562] = 8; em[563] = 1; /* 561: pointer.struct.asn1_string_st */
    	em[564] = 546; em[565] = 0; 
    em[566] = 1; em[567] = 8; em[568] = 1; /* 566: pointer.struct.asn1_string_st */
    	em[569] = 546; em[570] = 0; 
    em[571] = 1; em[572] = 8; em[573] = 1; /* 571: pointer.struct.asn1_string_st */
    	em[574] = 546; em[575] = 0; 
    em[576] = 1; em[577] = 8; em[578] = 1; /* 576: pointer.struct.asn1_string_st */
    	em[579] = 546; em[580] = 0; 
    em[581] = 1; em[582] = 8; em[583] = 1; /* 581: pointer.struct.asn1_string_st */
    	em[584] = 546; em[585] = 0; 
    em[586] = 1; em[587] = 8; em[588] = 1; /* 586: pointer.struct.asn1_string_st */
    	em[589] = 546; em[590] = 0; 
    em[591] = 1; em[592] = 8; em[593] = 1; /* 591: pointer.struct.asn1_string_st */
    	em[594] = 546; em[595] = 0; 
    em[596] = 1; em[597] = 8; em[598] = 1; /* 596: pointer.struct.asn1_string_st */
    	em[599] = 546; em[600] = 0; 
    em[601] = 1; em[602] = 8; em[603] = 1; /* 601: pointer.struct.asn1_string_st */
    	em[604] = 546; em[605] = 0; 
    em[606] = 1; em[607] = 8; em[608] = 1; /* 606: pointer.struct.asn1_string_st */
    	em[609] = 546; em[610] = 0; 
    em[611] = 1; em[612] = 8; em[613] = 1; /* 611: pointer.struct.asn1_string_st */
    	em[614] = 546; em[615] = 0; 
    em[616] = 1; em[617] = 8; em[618] = 1; /* 616: pointer.struct.asn1_string_st */
    	em[619] = 546; em[620] = 0; 
    em[621] = 1; em[622] = 8; em[623] = 1; /* 621: pointer.struct.ASN1_VALUE_st */
    	em[624] = 626; em[625] = 0; 
    em[626] = 0; em[627] = 0; em[628] = 0; /* 626: struct.ASN1_VALUE_st */
    em[629] = 1; em[630] = 8; em[631] = 1; /* 629: pointer.struct.X509_name_st */
    	em[632] = 634; em[633] = 0; 
    em[634] = 0; em[635] = 40; em[636] = 3; /* 634: struct.X509_name_st */
    	em[637] = 643; em[638] = 0; 
    	em[639] = 667; em[640] = 16; 
    	em[641] = 17; em[642] = 24; 
    em[643] = 1; em[644] = 8; em[645] = 1; /* 643: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[646] = 648; em[647] = 0; 
    em[648] = 0; em[649] = 32; em[650] = 2; /* 648: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[651] = 655; em[652] = 8; 
    	em[653] = 113; em[654] = 24; 
    em[655] = 8884099; em[656] = 8; em[657] = 2; /* 655: pointer_to_array_of_pointers_to_stack */
    	em[658] = 662; em[659] = 0; 
    	em[660] = 110; em[661] = 20; 
    em[662] = 0; em[663] = 8; em[664] = 1; /* 662: pointer.X509_NAME_ENTRY */
    	em[665] = 64; em[666] = 0; 
    em[667] = 1; em[668] = 8; em[669] = 1; /* 667: pointer.struct.buf_mem_st */
    	em[670] = 672; em[671] = 0; 
    em[672] = 0; em[673] = 24; em[674] = 1; /* 672: struct.buf_mem_st */
    	em[675] = 35; em[676] = 8; 
    em[677] = 1; em[678] = 8; em[679] = 1; /* 677: pointer.struct.EDIPartyName_st */
    	em[680] = 682; em[681] = 0; 
    em[682] = 0; em[683] = 16; em[684] = 2; /* 682: struct.EDIPartyName_st */
    	em[685] = 541; em[686] = 0; 
    	em[687] = 541; em[688] = 8; 
    em[689] = 0; em[690] = 24; em[691] = 1; /* 689: struct.asn1_string_st */
    	em[692] = 17; em[693] = 8; 
    em[694] = 1; em[695] = 8; em[696] = 1; /* 694: pointer.struct.buf_mem_st */
    	em[697] = 699; em[698] = 0; 
    em[699] = 0; em[700] = 24; em[701] = 1; /* 699: struct.buf_mem_st */
    	em[702] = 35; em[703] = 8; 
    em[704] = 0; em[705] = 40; em[706] = 3; /* 704: struct.X509_name_st */
    	em[707] = 713; em[708] = 0; 
    	em[709] = 694; em[710] = 16; 
    	em[711] = 17; em[712] = 24; 
    em[713] = 1; em[714] = 8; em[715] = 1; /* 713: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[716] = 718; em[717] = 0; 
    em[718] = 0; em[719] = 32; em[720] = 2; /* 718: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[721] = 725; em[722] = 8; 
    	em[723] = 113; em[724] = 24; 
    em[725] = 8884099; em[726] = 8; em[727] = 2; /* 725: pointer_to_array_of_pointers_to_stack */
    	em[728] = 732; em[729] = 0; 
    	em[730] = 110; em[731] = 20; 
    em[732] = 0; em[733] = 8; em[734] = 1; /* 732: pointer.X509_NAME_ENTRY */
    	em[735] = 64; em[736] = 0; 
    em[737] = 1; em[738] = 8; em[739] = 1; /* 737: pointer.struct.stack_st_DIST_POINT */
    	em[740] = 742; em[741] = 0; 
    em[742] = 0; em[743] = 32; em[744] = 2; /* 742: struct.stack_st_fake_DIST_POINT */
    	em[745] = 749; em[746] = 8; 
    	em[747] = 113; em[748] = 24; 
    em[749] = 8884099; em[750] = 8; em[751] = 2; /* 749: pointer_to_array_of_pointers_to_stack */
    	em[752] = 756; em[753] = 0; 
    	em[754] = 110; em[755] = 20; 
    em[756] = 0; em[757] = 8; em[758] = 1; /* 756: pointer.DIST_POINT */
    	em[759] = 761; em[760] = 0; 
    em[761] = 0; em[762] = 0; em[763] = 1; /* 761: DIST_POINT */
    	em[764] = 766; em[765] = 0; 
    em[766] = 0; em[767] = 32; em[768] = 3; /* 766: struct.DIST_POINT_st */
    	em[769] = 775; em[770] = 0; 
    	em[771] = 823; em[772] = 8; 
    	em[773] = 794; em[774] = 16; 
    em[775] = 1; em[776] = 8; em[777] = 1; /* 775: pointer.struct.DIST_POINT_NAME_st */
    	em[778] = 780; em[779] = 0; 
    em[780] = 0; em[781] = 24; em[782] = 2; /* 780: struct.DIST_POINT_NAME_st */
    	em[783] = 787; em[784] = 8; 
    	em[785] = 818; em[786] = 16; 
    em[787] = 0; em[788] = 8; em[789] = 2; /* 787: union.unknown */
    	em[790] = 794; em[791] = 0; 
    	em[792] = 713; em[793] = 0; 
    em[794] = 1; em[795] = 8; em[796] = 1; /* 794: pointer.struct.stack_st_GENERAL_NAME */
    	em[797] = 799; em[798] = 0; 
    em[799] = 0; em[800] = 32; em[801] = 2; /* 799: struct.stack_st_fake_GENERAL_NAME */
    	em[802] = 806; em[803] = 8; 
    	em[804] = 113; em[805] = 24; 
    em[806] = 8884099; em[807] = 8; em[808] = 2; /* 806: pointer_to_array_of_pointers_to_stack */
    	em[809] = 813; em[810] = 0; 
    	em[811] = 110; em[812] = 20; 
    em[813] = 0; em[814] = 8; em[815] = 1; /* 813: pointer.GENERAL_NAME */
    	em[816] = 419; em[817] = 0; 
    em[818] = 1; em[819] = 8; em[820] = 1; /* 818: pointer.struct.X509_name_st */
    	em[821] = 704; em[822] = 0; 
    em[823] = 1; em[824] = 8; em[825] = 1; /* 823: pointer.struct.asn1_string_st */
    	em[826] = 689; em[827] = 0; 
    em[828] = 1; em[829] = 8; em[830] = 1; /* 828: pointer.struct.stack_st_ASN1_OBJECT */
    	em[831] = 833; em[832] = 0; 
    em[833] = 0; em[834] = 32; em[835] = 2; /* 833: struct.stack_st_fake_ASN1_OBJECT */
    	em[836] = 840; em[837] = 8; 
    	em[838] = 113; em[839] = 24; 
    em[840] = 8884099; em[841] = 8; em[842] = 2; /* 840: pointer_to_array_of_pointers_to_stack */
    	em[843] = 847; em[844] = 0; 
    	em[845] = 110; em[846] = 20; 
    em[847] = 0; em[848] = 8; em[849] = 1; /* 847: pointer.ASN1_OBJECT */
    	em[850] = 852; em[851] = 0; 
    em[852] = 0; em[853] = 0; em[854] = 1; /* 852: ASN1_OBJECT */
    	em[855] = 857; em[856] = 0; 
    em[857] = 0; em[858] = 40; em[859] = 3; /* 857: struct.asn1_object_st */
    	em[860] = 90; em[861] = 0; 
    	em[862] = 90; em[863] = 8; 
    	em[864] = 95; em[865] = 24; 
    em[866] = 1; em[867] = 8; em[868] = 1; /* 866: pointer.struct.stack_st_POLICYQUALINFO */
    	em[869] = 871; em[870] = 0; 
    em[871] = 0; em[872] = 32; em[873] = 2; /* 871: struct.stack_st_fake_POLICYQUALINFO */
    	em[874] = 878; em[875] = 8; 
    	em[876] = 113; em[877] = 24; 
    em[878] = 8884099; em[879] = 8; em[880] = 2; /* 878: pointer_to_array_of_pointers_to_stack */
    	em[881] = 885; em[882] = 0; 
    	em[883] = 110; em[884] = 20; 
    em[885] = 0; em[886] = 8; em[887] = 1; /* 885: pointer.POLICYQUALINFO */
    	em[888] = 890; em[889] = 0; 
    em[890] = 0; em[891] = 0; em[892] = 1; /* 890: POLICYQUALINFO */
    	em[893] = 895; em[894] = 0; 
    em[895] = 0; em[896] = 16; em[897] = 2; /* 895: struct.POLICYQUALINFO_st */
    	em[898] = 902; em[899] = 0; 
    	em[900] = 916; em[901] = 8; 
    em[902] = 1; em[903] = 8; em[904] = 1; /* 902: pointer.struct.asn1_object_st */
    	em[905] = 907; em[906] = 0; 
    em[907] = 0; em[908] = 40; em[909] = 3; /* 907: struct.asn1_object_st */
    	em[910] = 90; em[911] = 0; 
    	em[912] = 90; em[913] = 8; 
    	em[914] = 95; em[915] = 24; 
    em[916] = 0; em[917] = 8; em[918] = 3; /* 916: union.unknown */
    	em[919] = 925; em[920] = 0; 
    	em[921] = 935; em[922] = 0; 
    	em[923] = 998; em[924] = 0; 
    em[925] = 1; em[926] = 8; em[927] = 1; /* 925: pointer.struct.asn1_string_st */
    	em[928] = 930; em[929] = 0; 
    em[930] = 0; em[931] = 24; em[932] = 1; /* 930: struct.asn1_string_st */
    	em[933] = 17; em[934] = 8; 
    em[935] = 1; em[936] = 8; em[937] = 1; /* 935: pointer.struct.USERNOTICE_st */
    	em[938] = 940; em[939] = 0; 
    em[940] = 0; em[941] = 16; em[942] = 2; /* 940: struct.USERNOTICE_st */
    	em[943] = 947; em[944] = 0; 
    	em[945] = 959; em[946] = 8; 
    em[947] = 1; em[948] = 8; em[949] = 1; /* 947: pointer.struct.NOTICEREF_st */
    	em[950] = 952; em[951] = 0; 
    em[952] = 0; em[953] = 16; em[954] = 2; /* 952: struct.NOTICEREF_st */
    	em[955] = 959; em[956] = 0; 
    	em[957] = 964; em[958] = 8; 
    em[959] = 1; em[960] = 8; em[961] = 1; /* 959: pointer.struct.asn1_string_st */
    	em[962] = 930; em[963] = 0; 
    em[964] = 1; em[965] = 8; em[966] = 1; /* 964: pointer.struct.stack_st_ASN1_INTEGER */
    	em[967] = 969; em[968] = 0; 
    em[969] = 0; em[970] = 32; em[971] = 2; /* 969: struct.stack_st_fake_ASN1_INTEGER */
    	em[972] = 976; em[973] = 8; 
    	em[974] = 113; em[975] = 24; 
    em[976] = 8884099; em[977] = 8; em[978] = 2; /* 976: pointer_to_array_of_pointers_to_stack */
    	em[979] = 983; em[980] = 0; 
    	em[981] = 110; em[982] = 20; 
    em[983] = 0; em[984] = 8; em[985] = 1; /* 983: pointer.ASN1_INTEGER */
    	em[986] = 988; em[987] = 0; 
    em[988] = 0; em[989] = 0; em[990] = 1; /* 988: ASN1_INTEGER */
    	em[991] = 993; em[992] = 0; 
    em[993] = 0; em[994] = 24; em[995] = 1; /* 993: struct.asn1_string_st */
    	em[996] = 17; em[997] = 8; 
    em[998] = 1; em[999] = 8; em[1000] = 1; /* 998: pointer.struct.asn1_type_st */
    	em[1001] = 1003; em[1002] = 0; 
    em[1003] = 0; em[1004] = 16; em[1005] = 1; /* 1003: struct.asn1_type_st */
    	em[1006] = 1008; em[1007] = 8; 
    em[1008] = 0; em[1009] = 8; em[1010] = 20; /* 1008: union.unknown */
    	em[1011] = 35; em[1012] = 0; 
    	em[1013] = 959; em[1014] = 0; 
    	em[1015] = 902; em[1016] = 0; 
    	em[1017] = 1051; em[1018] = 0; 
    	em[1019] = 1056; em[1020] = 0; 
    	em[1021] = 1061; em[1022] = 0; 
    	em[1023] = 1066; em[1024] = 0; 
    	em[1025] = 1071; em[1026] = 0; 
    	em[1027] = 1076; em[1028] = 0; 
    	em[1029] = 925; em[1030] = 0; 
    	em[1031] = 1081; em[1032] = 0; 
    	em[1033] = 1086; em[1034] = 0; 
    	em[1035] = 1091; em[1036] = 0; 
    	em[1037] = 1096; em[1038] = 0; 
    	em[1039] = 1101; em[1040] = 0; 
    	em[1041] = 1106; em[1042] = 0; 
    	em[1043] = 1111; em[1044] = 0; 
    	em[1045] = 959; em[1046] = 0; 
    	em[1047] = 959; em[1048] = 0; 
    	em[1049] = 262; em[1050] = 0; 
    em[1051] = 1; em[1052] = 8; em[1053] = 1; /* 1051: pointer.struct.asn1_string_st */
    	em[1054] = 930; em[1055] = 0; 
    em[1056] = 1; em[1057] = 8; em[1058] = 1; /* 1056: pointer.struct.asn1_string_st */
    	em[1059] = 930; em[1060] = 0; 
    em[1061] = 1; em[1062] = 8; em[1063] = 1; /* 1061: pointer.struct.asn1_string_st */
    	em[1064] = 930; em[1065] = 0; 
    em[1066] = 1; em[1067] = 8; em[1068] = 1; /* 1066: pointer.struct.asn1_string_st */
    	em[1069] = 930; em[1070] = 0; 
    em[1071] = 1; em[1072] = 8; em[1073] = 1; /* 1071: pointer.struct.asn1_string_st */
    	em[1074] = 930; em[1075] = 0; 
    em[1076] = 1; em[1077] = 8; em[1078] = 1; /* 1076: pointer.struct.asn1_string_st */
    	em[1079] = 930; em[1080] = 0; 
    em[1081] = 1; em[1082] = 8; em[1083] = 1; /* 1081: pointer.struct.asn1_string_st */
    	em[1084] = 930; em[1085] = 0; 
    em[1086] = 1; em[1087] = 8; em[1088] = 1; /* 1086: pointer.struct.asn1_string_st */
    	em[1089] = 930; em[1090] = 0; 
    em[1091] = 1; em[1092] = 8; em[1093] = 1; /* 1091: pointer.struct.asn1_string_st */
    	em[1094] = 930; em[1095] = 0; 
    em[1096] = 1; em[1097] = 8; em[1098] = 1; /* 1096: pointer.struct.asn1_string_st */
    	em[1099] = 930; em[1100] = 0; 
    em[1101] = 1; em[1102] = 8; em[1103] = 1; /* 1101: pointer.struct.asn1_string_st */
    	em[1104] = 930; em[1105] = 0; 
    em[1106] = 1; em[1107] = 8; em[1108] = 1; /* 1106: pointer.struct.asn1_string_st */
    	em[1109] = 930; em[1110] = 0; 
    em[1111] = 1; em[1112] = 8; em[1113] = 1; /* 1111: pointer.struct.asn1_string_st */
    	em[1114] = 930; em[1115] = 0; 
    em[1116] = 1; em[1117] = 8; em[1118] = 1; /* 1116: pointer.struct.asn1_object_st */
    	em[1119] = 1121; em[1120] = 0; 
    em[1121] = 0; em[1122] = 40; em[1123] = 3; /* 1121: struct.asn1_object_st */
    	em[1124] = 90; em[1125] = 0; 
    	em[1126] = 90; em[1127] = 8; 
    	em[1128] = 95; em[1129] = 24; 
    em[1130] = 0; em[1131] = 32; em[1132] = 3; /* 1130: struct.X509_POLICY_DATA_st */
    	em[1133] = 1116; em[1134] = 8; 
    	em[1135] = 866; em[1136] = 16; 
    	em[1137] = 828; em[1138] = 24; 
    em[1139] = 1; em[1140] = 8; em[1141] = 1; /* 1139: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[1142] = 1144; em[1143] = 0; 
    em[1144] = 0; em[1145] = 32; em[1146] = 2; /* 1144: struct.stack_st_fake_X509_POLICY_DATA */
    	em[1147] = 1151; em[1148] = 8; 
    	em[1149] = 113; em[1150] = 24; 
    em[1151] = 8884099; em[1152] = 8; em[1153] = 2; /* 1151: pointer_to_array_of_pointers_to_stack */
    	em[1154] = 1158; em[1155] = 0; 
    	em[1156] = 110; em[1157] = 20; 
    em[1158] = 0; em[1159] = 8; em[1160] = 1; /* 1158: pointer.X509_POLICY_DATA */
    	em[1161] = 1163; em[1162] = 0; 
    em[1163] = 0; em[1164] = 0; em[1165] = 1; /* 1163: X509_POLICY_DATA */
    	em[1166] = 1130; em[1167] = 0; 
    em[1168] = 0; em[1169] = 32; em[1170] = 3; /* 1168: struct.X509_POLICY_DATA_st */
    	em[1171] = 1177; em[1172] = 8; 
    	em[1173] = 1191; em[1174] = 16; 
    	em[1175] = 1215; em[1176] = 24; 
    em[1177] = 1; em[1178] = 8; em[1179] = 1; /* 1177: pointer.struct.asn1_object_st */
    	em[1180] = 1182; em[1181] = 0; 
    em[1182] = 0; em[1183] = 40; em[1184] = 3; /* 1182: struct.asn1_object_st */
    	em[1185] = 90; em[1186] = 0; 
    	em[1187] = 90; em[1188] = 8; 
    	em[1189] = 95; em[1190] = 24; 
    em[1191] = 1; em[1192] = 8; em[1193] = 1; /* 1191: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1194] = 1196; em[1195] = 0; 
    em[1196] = 0; em[1197] = 32; em[1198] = 2; /* 1196: struct.stack_st_fake_POLICYQUALINFO */
    	em[1199] = 1203; em[1200] = 8; 
    	em[1201] = 113; em[1202] = 24; 
    em[1203] = 8884099; em[1204] = 8; em[1205] = 2; /* 1203: pointer_to_array_of_pointers_to_stack */
    	em[1206] = 1210; em[1207] = 0; 
    	em[1208] = 110; em[1209] = 20; 
    em[1210] = 0; em[1211] = 8; em[1212] = 1; /* 1210: pointer.POLICYQUALINFO */
    	em[1213] = 890; em[1214] = 0; 
    em[1215] = 1; em[1216] = 8; em[1217] = 1; /* 1215: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1218] = 1220; em[1219] = 0; 
    em[1220] = 0; em[1221] = 32; em[1222] = 2; /* 1220: struct.stack_st_fake_ASN1_OBJECT */
    	em[1223] = 1227; em[1224] = 8; 
    	em[1225] = 113; em[1226] = 24; 
    em[1227] = 8884099; em[1228] = 8; em[1229] = 2; /* 1227: pointer_to_array_of_pointers_to_stack */
    	em[1230] = 1234; em[1231] = 0; 
    	em[1232] = 110; em[1233] = 20; 
    em[1234] = 0; em[1235] = 8; em[1236] = 1; /* 1234: pointer.ASN1_OBJECT */
    	em[1237] = 852; em[1238] = 0; 
    em[1239] = 0; em[1240] = 40; em[1241] = 2; /* 1239: struct.X509_POLICY_CACHE_st */
    	em[1242] = 1246; em[1243] = 0; 
    	em[1244] = 1139; em[1245] = 8; 
    em[1246] = 1; em[1247] = 8; em[1248] = 1; /* 1246: pointer.struct.X509_POLICY_DATA_st */
    	em[1249] = 1168; em[1250] = 0; 
    em[1251] = 1; em[1252] = 8; em[1253] = 1; /* 1251: pointer.struct.asn1_string_st */
    	em[1254] = 1256; em[1255] = 0; 
    em[1256] = 0; em[1257] = 24; em[1258] = 1; /* 1256: struct.asn1_string_st */
    	em[1259] = 17; em[1260] = 8; 
    em[1261] = 1; em[1262] = 8; em[1263] = 1; /* 1261: pointer.struct.stack_st_GENERAL_NAME */
    	em[1264] = 1266; em[1265] = 0; 
    em[1266] = 0; em[1267] = 32; em[1268] = 2; /* 1266: struct.stack_st_fake_GENERAL_NAME */
    	em[1269] = 1273; em[1270] = 8; 
    	em[1271] = 113; em[1272] = 24; 
    em[1273] = 8884099; em[1274] = 8; em[1275] = 2; /* 1273: pointer_to_array_of_pointers_to_stack */
    	em[1276] = 1280; em[1277] = 0; 
    	em[1278] = 110; em[1279] = 20; 
    em[1280] = 0; em[1281] = 8; em[1282] = 1; /* 1280: pointer.GENERAL_NAME */
    	em[1283] = 419; em[1284] = 0; 
    em[1285] = 1; em[1286] = 8; em[1287] = 1; /* 1285: pointer.struct.asn1_string_st */
    	em[1288] = 1256; em[1289] = 0; 
    em[1290] = 0; em[1291] = 40; em[1292] = 3; /* 1290: struct.asn1_object_st */
    	em[1293] = 90; em[1294] = 0; 
    	em[1295] = 90; em[1296] = 8; 
    	em[1297] = 95; em[1298] = 24; 
    em[1299] = 0; em[1300] = 24; em[1301] = 2; /* 1299: struct.X509_extension_st */
    	em[1302] = 1306; em[1303] = 0; 
    	em[1304] = 1311; em[1305] = 16; 
    em[1306] = 1; em[1307] = 8; em[1308] = 1; /* 1306: pointer.struct.asn1_object_st */
    	em[1309] = 1290; em[1310] = 0; 
    em[1311] = 1; em[1312] = 8; em[1313] = 1; /* 1311: pointer.struct.asn1_string_st */
    	em[1314] = 1316; em[1315] = 0; 
    em[1316] = 0; em[1317] = 24; em[1318] = 1; /* 1316: struct.asn1_string_st */
    	em[1319] = 17; em[1320] = 8; 
    em[1321] = 0; em[1322] = 0; em[1323] = 1; /* 1321: X509_EXTENSION */
    	em[1324] = 1299; em[1325] = 0; 
    em[1326] = 1; em[1327] = 8; em[1328] = 1; /* 1326: pointer.struct.asn1_string_st */
    	em[1329] = 335; em[1330] = 0; 
    em[1331] = 1; em[1332] = 8; em[1333] = 1; /* 1331: pointer.struct.ASN1_VALUE_st */
    	em[1334] = 1336; em[1335] = 0; 
    em[1336] = 0; em[1337] = 0; em[1338] = 0; /* 1336: struct.ASN1_VALUE_st */
    em[1339] = 1; em[1340] = 8; em[1341] = 1; /* 1339: pointer.struct.asn1_string_st */
    	em[1342] = 1344; em[1343] = 0; 
    em[1344] = 0; em[1345] = 24; em[1346] = 1; /* 1344: struct.asn1_string_st */
    	em[1347] = 17; em[1348] = 8; 
    em[1349] = 1; em[1350] = 8; em[1351] = 1; /* 1349: pointer.struct.asn1_string_st */
    	em[1352] = 1344; em[1353] = 0; 
    em[1354] = 1; em[1355] = 8; em[1356] = 1; /* 1354: pointer.struct.asn1_string_st */
    	em[1357] = 1344; em[1358] = 0; 
    em[1359] = 1; em[1360] = 8; em[1361] = 1; /* 1359: pointer.struct.asn1_string_st */
    	em[1362] = 1344; em[1363] = 0; 
    em[1364] = 1; em[1365] = 8; em[1366] = 1; /* 1364: pointer.struct.asn1_string_st */
    	em[1367] = 1344; em[1368] = 0; 
    em[1369] = 1; em[1370] = 8; em[1371] = 1; /* 1369: pointer.struct.asn1_string_st */
    	em[1372] = 1344; em[1373] = 0; 
    em[1374] = 1; em[1375] = 8; em[1376] = 1; /* 1374: pointer.struct.asn1_string_st */
    	em[1377] = 1344; em[1378] = 0; 
    em[1379] = 1; em[1380] = 8; em[1381] = 1; /* 1379: pointer.struct.asn1_string_st */
    	em[1382] = 1344; em[1383] = 0; 
    em[1384] = 1; em[1385] = 8; em[1386] = 1; /* 1384: pointer.struct.asn1_string_st */
    	em[1387] = 1344; em[1388] = 0; 
    em[1389] = 1; em[1390] = 8; em[1391] = 1; /* 1389: pointer.struct.asn1_string_st */
    	em[1392] = 1344; em[1393] = 0; 
    em[1394] = 1; em[1395] = 8; em[1396] = 1; /* 1394: pointer.struct.asn1_string_st */
    	em[1397] = 1344; em[1398] = 0; 
    em[1399] = 1; em[1400] = 8; em[1401] = 1; /* 1399: pointer.struct.asn1_string_st */
    	em[1402] = 1344; em[1403] = 0; 
    em[1404] = 0; em[1405] = 16; em[1406] = 1; /* 1404: struct.asn1_type_st */
    	em[1407] = 1409; em[1408] = 8; 
    em[1409] = 0; em[1410] = 8; em[1411] = 20; /* 1409: union.unknown */
    	em[1412] = 35; em[1413] = 0; 
    	em[1414] = 1399; em[1415] = 0; 
    	em[1416] = 1452; em[1417] = 0; 
    	em[1418] = 1466; em[1419] = 0; 
    	em[1420] = 1394; em[1421] = 0; 
    	em[1422] = 1389; em[1423] = 0; 
    	em[1424] = 1384; em[1425] = 0; 
    	em[1426] = 1379; em[1427] = 0; 
    	em[1428] = 1471; em[1429] = 0; 
    	em[1430] = 1374; em[1431] = 0; 
    	em[1432] = 1369; em[1433] = 0; 
    	em[1434] = 1364; em[1435] = 0; 
    	em[1436] = 1476; em[1437] = 0; 
    	em[1438] = 1359; em[1439] = 0; 
    	em[1440] = 1354; em[1441] = 0; 
    	em[1442] = 1349; em[1443] = 0; 
    	em[1444] = 1339; em[1445] = 0; 
    	em[1446] = 1399; em[1447] = 0; 
    	em[1448] = 1399; em[1449] = 0; 
    	em[1450] = 1331; em[1451] = 0; 
    em[1452] = 1; em[1453] = 8; em[1454] = 1; /* 1452: pointer.struct.asn1_object_st */
    	em[1455] = 1457; em[1456] = 0; 
    em[1457] = 0; em[1458] = 40; em[1459] = 3; /* 1457: struct.asn1_object_st */
    	em[1460] = 90; em[1461] = 0; 
    	em[1462] = 90; em[1463] = 8; 
    	em[1464] = 95; em[1465] = 24; 
    em[1466] = 1; em[1467] = 8; em[1468] = 1; /* 1466: pointer.struct.asn1_string_st */
    	em[1469] = 1344; em[1470] = 0; 
    em[1471] = 1; em[1472] = 8; em[1473] = 1; /* 1471: pointer.struct.asn1_string_st */
    	em[1474] = 1344; em[1475] = 0; 
    em[1476] = 1; em[1477] = 8; em[1478] = 1; /* 1476: pointer.struct.asn1_string_st */
    	em[1479] = 1344; em[1480] = 0; 
    em[1481] = 1; em[1482] = 8; em[1483] = 1; /* 1481: pointer.struct.ASN1_VALUE_st */
    	em[1484] = 1486; em[1485] = 0; 
    em[1486] = 0; em[1487] = 0; em[1488] = 0; /* 1486: struct.ASN1_VALUE_st */
    em[1489] = 1; em[1490] = 8; em[1491] = 1; /* 1489: pointer.struct.asn1_string_st */
    	em[1492] = 1494; em[1493] = 0; 
    em[1494] = 0; em[1495] = 24; em[1496] = 1; /* 1494: struct.asn1_string_st */
    	em[1497] = 17; em[1498] = 8; 
    em[1499] = 1; em[1500] = 8; em[1501] = 1; /* 1499: pointer.struct.asn1_string_st */
    	em[1502] = 1494; em[1503] = 0; 
    em[1504] = 1; em[1505] = 8; em[1506] = 1; /* 1504: pointer.struct.asn1_string_st */
    	em[1507] = 1494; em[1508] = 0; 
    em[1509] = 1; em[1510] = 8; em[1511] = 1; /* 1509: pointer.struct.asn1_string_st */
    	em[1512] = 1494; em[1513] = 0; 
    em[1514] = 1; em[1515] = 8; em[1516] = 1; /* 1514: pointer.struct.asn1_string_st */
    	em[1517] = 1494; em[1518] = 0; 
    em[1519] = 1; em[1520] = 8; em[1521] = 1; /* 1519: pointer.struct.asn1_string_st */
    	em[1522] = 1494; em[1523] = 0; 
    em[1524] = 1; em[1525] = 8; em[1526] = 1; /* 1524: pointer.struct.asn1_string_st */
    	em[1527] = 1494; em[1528] = 0; 
    em[1529] = 1; em[1530] = 8; em[1531] = 1; /* 1529: pointer.struct.asn1_string_st */
    	em[1532] = 1494; em[1533] = 0; 
    em[1534] = 1; em[1535] = 8; em[1536] = 1; /* 1534: pointer.struct.asn1_string_st */
    	em[1537] = 1494; em[1538] = 0; 
    em[1539] = 0; em[1540] = 40; em[1541] = 3; /* 1539: struct.asn1_object_st */
    	em[1542] = 90; em[1543] = 0; 
    	em[1544] = 90; em[1545] = 8; 
    	em[1546] = 95; em[1547] = 24; 
    em[1548] = 1; em[1549] = 8; em[1550] = 1; /* 1548: pointer.struct.asn1_object_st */
    	em[1551] = 1539; em[1552] = 0; 
    em[1553] = 1; em[1554] = 8; em[1555] = 1; /* 1553: pointer.struct.asn1_string_st */
    	em[1556] = 1494; em[1557] = 0; 
    em[1558] = 0; em[1559] = 8; em[1560] = 20; /* 1558: union.unknown */
    	em[1561] = 35; em[1562] = 0; 
    	em[1563] = 1553; em[1564] = 0; 
    	em[1565] = 1548; em[1566] = 0; 
    	em[1567] = 1534; em[1568] = 0; 
    	em[1569] = 1529; em[1570] = 0; 
    	em[1571] = 1601; em[1572] = 0; 
    	em[1573] = 1524; em[1574] = 0; 
    	em[1575] = 1606; em[1576] = 0; 
    	em[1577] = 1611; em[1578] = 0; 
    	em[1579] = 1519; em[1580] = 0; 
    	em[1581] = 1514; em[1582] = 0; 
    	em[1583] = 1616; em[1584] = 0; 
    	em[1585] = 1509; em[1586] = 0; 
    	em[1587] = 1504; em[1588] = 0; 
    	em[1589] = 1499; em[1590] = 0; 
    	em[1591] = 1621; em[1592] = 0; 
    	em[1593] = 1489; em[1594] = 0; 
    	em[1595] = 1553; em[1596] = 0; 
    	em[1597] = 1553; em[1598] = 0; 
    	em[1599] = 1481; em[1600] = 0; 
    em[1601] = 1; em[1602] = 8; em[1603] = 1; /* 1601: pointer.struct.asn1_string_st */
    	em[1604] = 1494; em[1605] = 0; 
    em[1606] = 1; em[1607] = 8; em[1608] = 1; /* 1606: pointer.struct.asn1_string_st */
    	em[1609] = 1494; em[1610] = 0; 
    em[1611] = 1; em[1612] = 8; em[1613] = 1; /* 1611: pointer.struct.asn1_string_st */
    	em[1614] = 1494; em[1615] = 0; 
    em[1616] = 1; em[1617] = 8; em[1618] = 1; /* 1616: pointer.struct.asn1_string_st */
    	em[1619] = 1494; em[1620] = 0; 
    em[1621] = 1; em[1622] = 8; em[1623] = 1; /* 1621: pointer.struct.asn1_string_st */
    	em[1624] = 1494; em[1625] = 0; 
    em[1626] = 0; em[1627] = 16; em[1628] = 1; /* 1626: struct.asn1_type_st */
    	em[1629] = 1558; em[1630] = 8; 
    em[1631] = 0; em[1632] = 0; em[1633] = 1; /* 1631: ASN1_TYPE */
    	em[1634] = 1626; em[1635] = 0; 
    em[1636] = 1; em[1637] = 8; em[1638] = 1; /* 1636: pointer.struct.stack_st_ASN1_TYPE */
    	em[1639] = 1641; em[1640] = 0; 
    em[1641] = 0; em[1642] = 32; em[1643] = 2; /* 1641: struct.stack_st_fake_ASN1_TYPE */
    	em[1644] = 1648; em[1645] = 8; 
    	em[1646] = 113; em[1647] = 24; 
    em[1648] = 8884099; em[1649] = 8; em[1650] = 2; /* 1648: pointer_to_array_of_pointers_to_stack */
    	em[1651] = 1655; em[1652] = 0; 
    	em[1653] = 110; em[1654] = 20; 
    em[1655] = 0; em[1656] = 8; em[1657] = 1; /* 1655: pointer.ASN1_TYPE */
    	em[1658] = 1631; em[1659] = 0; 
    em[1660] = 0; em[1661] = 8; em[1662] = 3; /* 1660: union.unknown */
    	em[1663] = 35; em[1664] = 0; 
    	em[1665] = 1636; em[1666] = 0; 
    	em[1667] = 1669; em[1668] = 0; 
    em[1669] = 1; em[1670] = 8; em[1671] = 1; /* 1669: pointer.struct.asn1_type_st */
    	em[1672] = 1404; em[1673] = 0; 
    em[1674] = 0; em[1675] = 24; em[1676] = 2; /* 1674: struct.x509_attributes_st */
    	em[1677] = 1452; em[1678] = 0; 
    	em[1679] = 1660; em[1680] = 16; 
    em[1681] = 1; em[1682] = 8; em[1683] = 1; /* 1681: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1684] = 1686; em[1685] = 0; 
    em[1686] = 0; em[1687] = 32; em[1688] = 2; /* 1686: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1689] = 1693; em[1690] = 8; 
    	em[1691] = 113; em[1692] = 24; 
    em[1693] = 8884099; em[1694] = 8; em[1695] = 2; /* 1693: pointer_to_array_of_pointers_to_stack */
    	em[1696] = 1700; em[1697] = 0; 
    	em[1698] = 110; em[1699] = 20; 
    em[1700] = 0; em[1701] = 8; em[1702] = 1; /* 1700: pointer.X509_ATTRIBUTE */
    	em[1703] = 1705; em[1704] = 0; 
    em[1705] = 0; em[1706] = 0; em[1707] = 1; /* 1705: X509_ATTRIBUTE */
    	em[1708] = 1674; em[1709] = 0; 
    em[1710] = 1; em[1711] = 8; em[1712] = 1; /* 1710: pointer.struct.ec_extra_data_st */
    	em[1713] = 1715; em[1714] = 0; 
    em[1715] = 0; em[1716] = 40; em[1717] = 5; /* 1715: struct.ec_extra_data_st */
    	em[1718] = 1728; em[1719] = 0; 
    	em[1720] = 1733; em[1721] = 8; 
    	em[1722] = 1736; em[1723] = 16; 
    	em[1724] = 1739; em[1725] = 24; 
    	em[1726] = 1739; em[1727] = 32; 
    em[1728] = 1; em[1729] = 8; em[1730] = 1; /* 1728: pointer.struct.ec_extra_data_st */
    	em[1731] = 1715; em[1732] = 0; 
    em[1733] = 0; em[1734] = 8; em[1735] = 0; /* 1733: pointer.void */
    em[1736] = 8884097; em[1737] = 8; em[1738] = 0; /* 1736: pointer.func */
    em[1739] = 8884097; em[1740] = 8; em[1741] = 0; /* 1739: pointer.func */
    em[1742] = 1; em[1743] = 8; em[1744] = 1; /* 1742: pointer.struct.stack_st_X509_ALGOR */
    	em[1745] = 1747; em[1746] = 0; 
    em[1747] = 0; em[1748] = 32; em[1749] = 2; /* 1747: struct.stack_st_fake_X509_ALGOR */
    	em[1750] = 1754; em[1751] = 8; 
    	em[1752] = 113; em[1753] = 24; 
    em[1754] = 8884099; em[1755] = 8; em[1756] = 2; /* 1754: pointer_to_array_of_pointers_to_stack */
    	em[1757] = 1761; em[1758] = 0; 
    	em[1759] = 110; em[1760] = 20; 
    em[1761] = 0; em[1762] = 8; em[1763] = 1; /* 1761: pointer.X509_ALGOR */
    	em[1764] = 1766; em[1765] = 0; 
    em[1766] = 0; em[1767] = 0; em[1768] = 1; /* 1766: X509_ALGOR */
    	em[1769] = 1771; em[1770] = 0; 
    em[1771] = 0; em[1772] = 16; em[1773] = 2; /* 1771: struct.X509_algor_st */
    	em[1774] = 1778; em[1775] = 0; 
    	em[1776] = 1792; em[1777] = 8; 
    em[1778] = 1; em[1779] = 8; em[1780] = 1; /* 1778: pointer.struct.asn1_object_st */
    	em[1781] = 1783; em[1782] = 0; 
    em[1783] = 0; em[1784] = 40; em[1785] = 3; /* 1783: struct.asn1_object_st */
    	em[1786] = 90; em[1787] = 0; 
    	em[1788] = 90; em[1789] = 8; 
    	em[1790] = 95; em[1791] = 24; 
    em[1792] = 1; em[1793] = 8; em[1794] = 1; /* 1792: pointer.struct.asn1_type_st */
    	em[1795] = 1797; em[1796] = 0; 
    em[1797] = 0; em[1798] = 16; em[1799] = 1; /* 1797: struct.asn1_type_st */
    	em[1800] = 1802; em[1801] = 8; 
    em[1802] = 0; em[1803] = 8; em[1804] = 20; /* 1802: union.unknown */
    	em[1805] = 35; em[1806] = 0; 
    	em[1807] = 1845; em[1808] = 0; 
    	em[1809] = 1778; em[1810] = 0; 
    	em[1811] = 1855; em[1812] = 0; 
    	em[1813] = 1860; em[1814] = 0; 
    	em[1815] = 1865; em[1816] = 0; 
    	em[1817] = 1870; em[1818] = 0; 
    	em[1819] = 1875; em[1820] = 0; 
    	em[1821] = 1880; em[1822] = 0; 
    	em[1823] = 1885; em[1824] = 0; 
    	em[1825] = 1890; em[1826] = 0; 
    	em[1827] = 1895; em[1828] = 0; 
    	em[1829] = 1900; em[1830] = 0; 
    	em[1831] = 1905; em[1832] = 0; 
    	em[1833] = 1910; em[1834] = 0; 
    	em[1835] = 1915; em[1836] = 0; 
    	em[1837] = 1920; em[1838] = 0; 
    	em[1839] = 1845; em[1840] = 0; 
    	em[1841] = 1845; em[1842] = 0; 
    	em[1843] = 1925; em[1844] = 0; 
    em[1845] = 1; em[1846] = 8; em[1847] = 1; /* 1845: pointer.struct.asn1_string_st */
    	em[1848] = 1850; em[1849] = 0; 
    em[1850] = 0; em[1851] = 24; em[1852] = 1; /* 1850: struct.asn1_string_st */
    	em[1853] = 17; em[1854] = 8; 
    em[1855] = 1; em[1856] = 8; em[1857] = 1; /* 1855: pointer.struct.asn1_string_st */
    	em[1858] = 1850; em[1859] = 0; 
    em[1860] = 1; em[1861] = 8; em[1862] = 1; /* 1860: pointer.struct.asn1_string_st */
    	em[1863] = 1850; em[1864] = 0; 
    em[1865] = 1; em[1866] = 8; em[1867] = 1; /* 1865: pointer.struct.asn1_string_st */
    	em[1868] = 1850; em[1869] = 0; 
    em[1870] = 1; em[1871] = 8; em[1872] = 1; /* 1870: pointer.struct.asn1_string_st */
    	em[1873] = 1850; em[1874] = 0; 
    em[1875] = 1; em[1876] = 8; em[1877] = 1; /* 1875: pointer.struct.asn1_string_st */
    	em[1878] = 1850; em[1879] = 0; 
    em[1880] = 1; em[1881] = 8; em[1882] = 1; /* 1880: pointer.struct.asn1_string_st */
    	em[1883] = 1850; em[1884] = 0; 
    em[1885] = 1; em[1886] = 8; em[1887] = 1; /* 1885: pointer.struct.asn1_string_st */
    	em[1888] = 1850; em[1889] = 0; 
    em[1890] = 1; em[1891] = 8; em[1892] = 1; /* 1890: pointer.struct.asn1_string_st */
    	em[1893] = 1850; em[1894] = 0; 
    em[1895] = 1; em[1896] = 8; em[1897] = 1; /* 1895: pointer.struct.asn1_string_st */
    	em[1898] = 1850; em[1899] = 0; 
    em[1900] = 1; em[1901] = 8; em[1902] = 1; /* 1900: pointer.struct.asn1_string_st */
    	em[1903] = 1850; em[1904] = 0; 
    em[1905] = 1; em[1906] = 8; em[1907] = 1; /* 1905: pointer.struct.asn1_string_st */
    	em[1908] = 1850; em[1909] = 0; 
    em[1910] = 1; em[1911] = 8; em[1912] = 1; /* 1910: pointer.struct.asn1_string_st */
    	em[1913] = 1850; em[1914] = 0; 
    em[1915] = 1; em[1916] = 8; em[1917] = 1; /* 1915: pointer.struct.asn1_string_st */
    	em[1918] = 1850; em[1919] = 0; 
    em[1920] = 1; em[1921] = 8; em[1922] = 1; /* 1920: pointer.struct.asn1_string_st */
    	em[1923] = 1850; em[1924] = 0; 
    em[1925] = 1; em[1926] = 8; em[1927] = 1; /* 1925: pointer.struct.ASN1_VALUE_st */
    	em[1928] = 1930; em[1929] = 0; 
    em[1930] = 0; em[1931] = 0; em[1932] = 0; /* 1930: struct.ASN1_VALUE_st */
    em[1933] = 0; em[1934] = 24; em[1935] = 1; /* 1933: struct.bignum_st */
    	em[1936] = 1938; em[1937] = 0; 
    em[1938] = 8884099; em[1939] = 8; em[1940] = 2; /* 1938: pointer_to_array_of_pointers_to_stack */
    	em[1941] = 1945; em[1942] = 0; 
    	em[1943] = 110; em[1944] = 12; 
    em[1945] = 0; em[1946] = 8; em[1947] = 0; /* 1945: long unsigned int */
    em[1948] = 1; em[1949] = 8; em[1950] = 1; /* 1948: pointer.struct.ec_point_st */
    	em[1951] = 1953; em[1952] = 0; 
    em[1953] = 0; em[1954] = 88; em[1955] = 4; /* 1953: struct.ec_point_st */
    	em[1956] = 1964; em[1957] = 0; 
    	em[1958] = 2136; em[1959] = 8; 
    	em[1960] = 2136; em[1961] = 32; 
    	em[1962] = 2136; em[1963] = 56; 
    em[1964] = 1; em[1965] = 8; em[1966] = 1; /* 1964: pointer.struct.ec_method_st */
    	em[1967] = 1969; em[1968] = 0; 
    em[1969] = 0; em[1970] = 304; em[1971] = 37; /* 1969: struct.ec_method_st */
    	em[1972] = 2046; em[1973] = 8; 
    	em[1974] = 2049; em[1975] = 16; 
    	em[1976] = 2049; em[1977] = 24; 
    	em[1978] = 2052; em[1979] = 32; 
    	em[1980] = 2055; em[1981] = 40; 
    	em[1982] = 2058; em[1983] = 48; 
    	em[1984] = 2061; em[1985] = 56; 
    	em[1986] = 2064; em[1987] = 64; 
    	em[1988] = 2067; em[1989] = 72; 
    	em[1990] = 2070; em[1991] = 80; 
    	em[1992] = 2070; em[1993] = 88; 
    	em[1994] = 2073; em[1995] = 96; 
    	em[1996] = 2076; em[1997] = 104; 
    	em[1998] = 2079; em[1999] = 112; 
    	em[2000] = 2082; em[2001] = 120; 
    	em[2002] = 2085; em[2003] = 128; 
    	em[2004] = 2088; em[2005] = 136; 
    	em[2006] = 2091; em[2007] = 144; 
    	em[2008] = 2094; em[2009] = 152; 
    	em[2010] = 2097; em[2011] = 160; 
    	em[2012] = 2100; em[2013] = 168; 
    	em[2014] = 2103; em[2015] = 176; 
    	em[2016] = 2106; em[2017] = 184; 
    	em[2018] = 2109; em[2019] = 192; 
    	em[2020] = 2112; em[2021] = 200; 
    	em[2022] = 2115; em[2023] = 208; 
    	em[2024] = 2106; em[2025] = 216; 
    	em[2026] = 2118; em[2027] = 224; 
    	em[2028] = 2121; em[2029] = 232; 
    	em[2030] = 2124; em[2031] = 240; 
    	em[2032] = 2061; em[2033] = 248; 
    	em[2034] = 2127; em[2035] = 256; 
    	em[2036] = 2130; em[2037] = 264; 
    	em[2038] = 2127; em[2039] = 272; 
    	em[2040] = 2130; em[2041] = 280; 
    	em[2042] = 2130; em[2043] = 288; 
    	em[2044] = 2133; em[2045] = 296; 
    em[2046] = 8884097; em[2047] = 8; em[2048] = 0; /* 2046: pointer.func */
    em[2049] = 8884097; em[2050] = 8; em[2051] = 0; /* 2049: pointer.func */
    em[2052] = 8884097; em[2053] = 8; em[2054] = 0; /* 2052: pointer.func */
    em[2055] = 8884097; em[2056] = 8; em[2057] = 0; /* 2055: pointer.func */
    em[2058] = 8884097; em[2059] = 8; em[2060] = 0; /* 2058: pointer.func */
    em[2061] = 8884097; em[2062] = 8; em[2063] = 0; /* 2061: pointer.func */
    em[2064] = 8884097; em[2065] = 8; em[2066] = 0; /* 2064: pointer.func */
    em[2067] = 8884097; em[2068] = 8; em[2069] = 0; /* 2067: pointer.func */
    em[2070] = 8884097; em[2071] = 8; em[2072] = 0; /* 2070: pointer.func */
    em[2073] = 8884097; em[2074] = 8; em[2075] = 0; /* 2073: pointer.func */
    em[2076] = 8884097; em[2077] = 8; em[2078] = 0; /* 2076: pointer.func */
    em[2079] = 8884097; em[2080] = 8; em[2081] = 0; /* 2079: pointer.func */
    em[2082] = 8884097; em[2083] = 8; em[2084] = 0; /* 2082: pointer.func */
    em[2085] = 8884097; em[2086] = 8; em[2087] = 0; /* 2085: pointer.func */
    em[2088] = 8884097; em[2089] = 8; em[2090] = 0; /* 2088: pointer.func */
    em[2091] = 8884097; em[2092] = 8; em[2093] = 0; /* 2091: pointer.func */
    em[2094] = 8884097; em[2095] = 8; em[2096] = 0; /* 2094: pointer.func */
    em[2097] = 8884097; em[2098] = 8; em[2099] = 0; /* 2097: pointer.func */
    em[2100] = 8884097; em[2101] = 8; em[2102] = 0; /* 2100: pointer.func */
    em[2103] = 8884097; em[2104] = 8; em[2105] = 0; /* 2103: pointer.func */
    em[2106] = 8884097; em[2107] = 8; em[2108] = 0; /* 2106: pointer.func */
    em[2109] = 8884097; em[2110] = 8; em[2111] = 0; /* 2109: pointer.func */
    em[2112] = 8884097; em[2113] = 8; em[2114] = 0; /* 2112: pointer.func */
    em[2115] = 8884097; em[2116] = 8; em[2117] = 0; /* 2115: pointer.func */
    em[2118] = 8884097; em[2119] = 8; em[2120] = 0; /* 2118: pointer.func */
    em[2121] = 8884097; em[2122] = 8; em[2123] = 0; /* 2121: pointer.func */
    em[2124] = 8884097; em[2125] = 8; em[2126] = 0; /* 2124: pointer.func */
    em[2127] = 8884097; em[2128] = 8; em[2129] = 0; /* 2127: pointer.func */
    em[2130] = 8884097; em[2131] = 8; em[2132] = 0; /* 2130: pointer.func */
    em[2133] = 8884097; em[2134] = 8; em[2135] = 0; /* 2133: pointer.func */
    em[2136] = 0; em[2137] = 24; em[2138] = 1; /* 2136: struct.bignum_st */
    	em[2139] = 2141; em[2140] = 0; 
    em[2141] = 8884099; em[2142] = 8; em[2143] = 2; /* 2141: pointer_to_array_of_pointers_to_stack */
    	em[2144] = 1945; em[2145] = 0; 
    	em[2146] = 110; em[2147] = 12; 
    em[2148] = 8884097; em[2149] = 8; em[2150] = 0; /* 2148: pointer.func */
    em[2151] = 1; em[2152] = 8; em[2153] = 1; /* 2151: pointer.struct.ec_extra_data_st */
    	em[2154] = 2156; em[2155] = 0; 
    em[2156] = 0; em[2157] = 40; em[2158] = 5; /* 2156: struct.ec_extra_data_st */
    	em[2159] = 2169; em[2160] = 0; 
    	em[2161] = 1733; em[2162] = 8; 
    	em[2163] = 1736; em[2164] = 16; 
    	em[2165] = 1739; em[2166] = 24; 
    	em[2167] = 1739; em[2168] = 32; 
    em[2169] = 1; em[2170] = 8; em[2171] = 1; /* 2169: pointer.struct.ec_extra_data_st */
    	em[2172] = 2156; em[2173] = 0; 
    em[2174] = 0; em[2175] = 24; em[2176] = 1; /* 2174: struct.bignum_st */
    	em[2177] = 2179; em[2178] = 0; 
    em[2179] = 8884099; em[2180] = 8; em[2181] = 2; /* 2179: pointer_to_array_of_pointers_to_stack */
    	em[2182] = 1945; em[2183] = 0; 
    	em[2184] = 110; em[2185] = 12; 
    em[2186] = 1; em[2187] = 8; em[2188] = 1; /* 2186: pointer.struct.store_method_st */
    	em[2189] = 2191; em[2190] = 0; 
    em[2191] = 0; em[2192] = 0; em[2193] = 0; /* 2191: struct.store_method_st */
    em[2194] = 1; em[2195] = 8; em[2196] = 1; /* 2194: pointer.struct.stack_st_void */
    	em[2197] = 2199; em[2198] = 0; 
    em[2199] = 0; em[2200] = 32; em[2201] = 1; /* 2199: struct.stack_st_void */
    	em[2202] = 2204; em[2203] = 0; 
    em[2204] = 0; em[2205] = 32; em[2206] = 2; /* 2204: struct.stack_st */
    	em[2207] = 2211; em[2208] = 8; 
    	em[2209] = 113; em[2210] = 24; 
    em[2211] = 1; em[2212] = 8; em[2213] = 1; /* 2211: pointer.pointer.char */
    	em[2214] = 35; em[2215] = 0; 
    em[2216] = 8884097; em[2217] = 8; em[2218] = 0; /* 2216: pointer.func */
    em[2219] = 1; em[2220] = 8; em[2221] = 1; /* 2219: pointer.struct.X509_val_st */
    	em[2222] = 2224; em[2223] = 0; 
    em[2224] = 0; em[2225] = 16; em[2226] = 2; /* 2224: struct.X509_val_st */
    	em[2227] = 2231; em[2228] = 0; 
    	em[2229] = 2231; em[2230] = 8; 
    em[2231] = 1; em[2232] = 8; em[2233] = 1; /* 2231: pointer.struct.asn1_string_st */
    	em[2234] = 335; em[2235] = 0; 
    em[2236] = 8884097; em[2237] = 8; em[2238] = 0; /* 2236: pointer.func */
    em[2239] = 8884097; em[2240] = 8; em[2241] = 0; /* 2239: pointer.func */
    em[2242] = 8884097; em[2243] = 8; em[2244] = 0; /* 2242: pointer.func */
    em[2245] = 8884097; em[2246] = 8; em[2247] = 0; /* 2245: pointer.func */
    em[2248] = 0; em[2249] = 8; em[2250] = 5; /* 2248: union.unknown */
    	em[2251] = 35; em[2252] = 0; 
    	em[2253] = 2261; em[2254] = 0; 
    	em[2255] = 2783; em[2256] = 0; 
    	em[2257] = 2864; em[2258] = 0; 
    	em[2259] = 2985; em[2260] = 0; 
    em[2261] = 1; em[2262] = 8; em[2263] = 1; /* 2261: pointer.struct.rsa_st */
    	em[2264] = 2266; em[2265] = 0; 
    em[2266] = 0; em[2267] = 168; em[2268] = 17; /* 2266: struct.rsa_st */
    	em[2269] = 2303; em[2270] = 16; 
    	em[2271] = 2358; em[2272] = 24; 
    	em[2273] = 2669; em[2274] = 32; 
    	em[2275] = 2669; em[2276] = 40; 
    	em[2277] = 2669; em[2278] = 48; 
    	em[2279] = 2669; em[2280] = 56; 
    	em[2281] = 2669; em[2282] = 64; 
    	em[2283] = 2669; em[2284] = 72; 
    	em[2285] = 2669; em[2286] = 80; 
    	em[2287] = 2669; em[2288] = 88; 
    	em[2289] = 2686; em[2290] = 96; 
    	em[2291] = 2708; em[2292] = 120; 
    	em[2293] = 2708; em[2294] = 128; 
    	em[2295] = 2708; em[2296] = 136; 
    	em[2297] = 35; em[2298] = 144; 
    	em[2299] = 2722; em[2300] = 152; 
    	em[2301] = 2722; em[2302] = 160; 
    em[2303] = 1; em[2304] = 8; em[2305] = 1; /* 2303: pointer.struct.rsa_meth_st */
    	em[2306] = 2308; em[2307] = 0; 
    em[2308] = 0; em[2309] = 112; em[2310] = 13; /* 2308: struct.rsa_meth_st */
    	em[2311] = 90; em[2312] = 0; 
    	em[2313] = 2337; em[2314] = 8; 
    	em[2315] = 2337; em[2316] = 16; 
    	em[2317] = 2337; em[2318] = 24; 
    	em[2319] = 2337; em[2320] = 32; 
    	em[2321] = 2340; em[2322] = 40; 
    	em[2323] = 2343; em[2324] = 48; 
    	em[2325] = 2346; em[2326] = 56; 
    	em[2327] = 2346; em[2328] = 64; 
    	em[2329] = 35; em[2330] = 80; 
    	em[2331] = 2349; em[2332] = 88; 
    	em[2333] = 2352; em[2334] = 96; 
    	em[2335] = 2355; em[2336] = 104; 
    em[2337] = 8884097; em[2338] = 8; em[2339] = 0; /* 2337: pointer.func */
    em[2340] = 8884097; em[2341] = 8; em[2342] = 0; /* 2340: pointer.func */
    em[2343] = 8884097; em[2344] = 8; em[2345] = 0; /* 2343: pointer.func */
    em[2346] = 8884097; em[2347] = 8; em[2348] = 0; /* 2346: pointer.func */
    em[2349] = 8884097; em[2350] = 8; em[2351] = 0; /* 2349: pointer.func */
    em[2352] = 8884097; em[2353] = 8; em[2354] = 0; /* 2352: pointer.func */
    em[2355] = 8884097; em[2356] = 8; em[2357] = 0; /* 2355: pointer.func */
    em[2358] = 1; em[2359] = 8; em[2360] = 1; /* 2358: pointer.struct.engine_st */
    	em[2361] = 2363; em[2362] = 0; 
    em[2363] = 0; em[2364] = 216; em[2365] = 24; /* 2363: struct.engine_st */
    	em[2366] = 90; em[2367] = 0; 
    	em[2368] = 90; em[2369] = 8; 
    	em[2370] = 2414; em[2371] = 16; 
    	em[2372] = 2469; em[2373] = 24; 
    	em[2374] = 2520; em[2375] = 32; 
    	em[2376] = 2556; em[2377] = 40; 
    	em[2378] = 2573; em[2379] = 48; 
    	em[2380] = 2597; em[2381] = 56; 
    	em[2382] = 2186; em[2383] = 64; 
    	em[2384] = 2623; em[2385] = 72; 
    	em[2386] = 2626; em[2387] = 80; 
    	em[2388] = 2629; em[2389] = 88; 
    	em[2390] = 2632; em[2391] = 96; 
    	em[2392] = 2635; em[2393] = 104; 
    	em[2394] = 2635; em[2395] = 112; 
    	em[2396] = 2635; em[2397] = 120; 
    	em[2398] = 2638; em[2399] = 128; 
    	em[2400] = 2641; em[2401] = 136; 
    	em[2402] = 2641; em[2403] = 144; 
    	em[2404] = 2644; em[2405] = 152; 
    	em[2406] = 2647; em[2407] = 160; 
    	em[2408] = 2659; em[2409] = 184; 
    	em[2410] = 2664; em[2411] = 200; 
    	em[2412] = 2664; em[2413] = 208; 
    em[2414] = 1; em[2415] = 8; em[2416] = 1; /* 2414: pointer.struct.rsa_meth_st */
    	em[2417] = 2419; em[2418] = 0; 
    em[2419] = 0; em[2420] = 112; em[2421] = 13; /* 2419: struct.rsa_meth_st */
    	em[2422] = 90; em[2423] = 0; 
    	em[2424] = 2448; em[2425] = 8; 
    	em[2426] = 2448; em[2427] = 16; 
    	em[2428] = 2448; em[2429] = 24; 
    	em[2430] = 2448; em[2431] = 32; 
    	em[2432] = 2451; em[2433] = 40; 
    	em[2434] = 2454; em[2435] = 48; 
    	em[2436] = 2457; em[2437] = 56; 
    	em[2438] = 2457; em[2439] = 64; 
    	em[2440] = 35; em[2441] = 80; 
    	em[2442] = 2460; em[2443] = 88; 
    	em[2444] = 2463; em[2445] = 96; 
    	em[2446] = 2466; em[2447] = 104; 
    em[2448] = 8884097; em[2449] = 8; em[2450] = 0; /* 2448: pointer.func */
    em[2451] = 8884097; em[2452] = 8; em[2453] = 0; /* 2451: pointer.func */
    em[2454] = 8884097; em[2455] = 8; em[2456] = 0; /* 2454: pointer.func */
    em[2457] = 8884097; em[2458] = 8; em[2459] = 0; /* 2457: pointer.func */
    em[2460] = 8884097; em[2461] = 8; em[2462] = 0; /* 2460: pointer.func */
    em[2463] = 8884097; em[2464] = 8; em[2465] = 0; /* 2463: pointer.func */
    em[2466] = 8884097; em[2467] = 8; em[2468] = 0; /* 2466: pointer.func */
    em[2469] = 1; em[2470] = 8; em[2471] = 1; /* 2469: pointer.struct.dsa_method */
    	em[2472] = 2474; em[2473] = 0; 
    em[2474] = 0; em[2475] = 96; em[2476] = 11; /* 2474: struct.dsa_method */
    	em[2477] = 90; em[2478] = 0; 
    	em[2479] = 2499; em[2480] = 8; 
    	em[2481] = 2502; em[2482] = 16; 
    	em[2483] = 2505; em[2484] = 24; 
    	em[2485] = 2508; em[2486] = 32; 
    	em[2487] = 2511; em[2488] = 40; 
    	em[2489] = 2514; em[2490] = 48; 
    	em[2491] = 2514; em[2492] = 56; 
    	em[2493] = 35; em[2494] = 72; 
    	em[2495] = 2517; em[2496] = 80; 
    	em[2497] = 2514; em[2498] = 88; 
    em[2499] = 8884097; em[2500] = 8; em[2501] = 0; /* 2499: pointer.func */
    em[2502] = 8884097; em[2503] = 8; em[2504] = 0; /* 2502: pointer.func */
    em[2505] = 8884097; em[2506] = 8; em[2507] = 0; /* 2505: pointer.func */
    em[2508] = 8884097; em[2509] = 8; em[2510] = 0; /* 2508: pointer.func */
    em[2511] = 8884097; em[2512] = 8; em[2513] = 0; /* 2511: pointer.func */
    em[2514] = 8884097; em[2515] = 8; em[2516] = 0; /* 2514: pointer.func */
    em[2517] = 8884097; em[2518] = 8; em[2519] = 0; /* 2517: pointer.func */
    em[2520] = 1; em[2521] = 8; em[2522] = 1; /* 2520: pointer.struct.dh_method */
    	em[2523] = 2525; em[2524] = 0; 
    em[2525] = 0; em[2526] = 72; em[2527] = 8; /* 2525: struct.dh_method */
    	em[2528] = 90; em[2529] = 0; 
    	em[2530] = 2544; em[2531] = 8; 
    	em[2532] = 2547; em[2533] = 16; 
    	em[2534] = 2550; em[2535] = 24; 
    	em[2536] = 2544; em[2537] = 32; 
    	em[2538] = 2544; em[2539] = 40; 
    	em[2540] = 35; em[2541] = 56; 
    	em[2542] = 2553; em[2543] = 64; 
    em[2544] = 8884097; em[2545] = 8; em[2546] = 0; /* 2544: pointer.func */
    em[2547] = 8884097; em[2548] = 8; em[2549] = 0; /* 2547: pointer.func */
    em[2550] = 8884097; em[2551] = 8; em[2552] = 0; /* 2550: pointer.func */
    em[2553] = 8884097; em[2554] = 8; em[2555] = 0; /* 2553: pointer.func */
    em[2556] = 1; em[2557] = 8; em[2558] = 1; /* 2556: pointer.struct.ecdh_method */
    	em[2559] = 2561; em[2560] = 0; 
    em[2561] = 0; em[2562] = 32; em[2563] = 3; /* 2561: struct.ecdh_method */
    	em[2564] = 90; em[2565] = 0; 
    	em[2566] = 2570; em[2567] = 8; 
    	em[2568] = 35; em[2569] = 24; 
    em[2570] = 8884097; em[2571] = 8; em[2572] = 0; /* 2570: pointer.func */
    em[2573] = 1; em[2574] = 8; em[2575] = 1; /* 2573: pointer.struct.ecdsa_method */
    	em[2576] = 2578; em[2577] = 0; 
    em[2578] = 0; em[2579] = 48; em[2580] = 5; /* 2578: struct.ecdsa_method */
    	em[2581] = 90; em[2582] = 0; 
    	em[2583] = 2591; em[2584] = 8; 
    	em[2585] = 2245; em[2586] = 16; 
    	em[2587] = 2594; em[2588] = 24; 
    	em[2589] = 35; em[2590] = 40; 
    em[2591] = 8884097; em[2592] = 8; em[2593] = 0; /* 2591: pointer.func */
    em[2594] = 8884097; em[2595] = 8; em[2596] = 0; /* 2594: pointer.func */
    em[2597] = 1; em[2598] = 8; em[2599] = 1; /* 2597: pointer.struct.rand_meth_st */
    	em[2600] = 2602; em[2601] = 0; 
    em[2602] = 0; em[2603] = 48; em[2604] = 6; /* 2602: struct.rand_meth_st */
    	em[2605] = 2242; em[2606] = 0; 
    	em[2607] = 2617; em[2608] = 8; 
    	em[2609] = 2239; em[2610] = 16; 
    	em[2611] = 2216; em[2612] = 24; 
    	em[2613] = 2617; em[2614] = 32; 
    	em[2615] = 2620; em[2616] = 40; 
    em[2617] = 8884097; em[2618] = 8; em[2619] = 0; /* 2617: pointer.func */
    em[2620] = 8884097; em[2621] = 8; em[2622] = 0; /* 2620: pointer.func */
    em[2623] = 8884097; em[2624] = 8; em[2625] = 0; /* 2623: pointer.func */
    em[2626] = 8884097; em[2627] = 8; em[2628] = 0; /* 2626: pointer.func */
    em[2629] = 8884097; em[2630] = 8; em[2631] = 0; /* 2629: pointer.func */
    em[2632] = 8884097; em[2633] = 8; em[2634] = 0; /* 2632: pointer.func */
    em[2635] = 8884097; em[2636] = 8; em[2637] = 0; /* 2635: pointer.func */
    em[2638] = 8884097; em[2639] = 8; em[2640] = 0; /* 2638: pointer.func */
    em[2641] = 8884097; em[2642] = 8; em[2643] = 0; /* 2641: pointer.func */
    em[2644] = 8884097; em[2645] = 8; em[2646] = 0; /* 2644: pointer.func */
    em[2647] = 1; em[2648] = 8; em[2649] = 1; /* 2647: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[2650] = 2652; em[2651] = 0; 
    em[2652] = 0; em[2653] = 32; em[2654] = 2; /* 2652: struct.ENGINE_CMD_DEFN_st */
    	em[2655] = 90; em[2656] = 8; 
    	em[2657] = 90; em[2658] = 16; 
    em[2659] = 0; em[2660] = 16; em[2661] = 1; /* 2659: struct.crypto_ex_data_st */
    	em[2662] = 2194; em[2663] = 0; 
    em[2664] = 1; em[2665] = 8; em[2666] = 1; /* 2664: pointer.struct.engine_st */
    	em[2667] = 2363; em[2668] = 0; 
    em[2669] = 1; em[2670] = 8; em[2671] = 1; /* 2669: pointer.struct.bignum_st */
    	em[2672] = 2674; em[2673] = 0; 
    em[2674] = 0; em[2675] = 24; em[2676] = 1; /* 2674: struct.bignum_st */
    	em[2677] = 2679; em[2678] = 0; 
    em[2679] = 8884099; em[2680] = 8; em[2681] = 2; /* 2679: pointer_to_array_of_pointers_to_stack */
    	em[2682] = 1945; em[2683] = 0; 
    	em[2684] = 110; em[2685] = 12; 
    em[2686] = 0; em[2687] = 16; em[2688] = 1; /* 2686: struct.crypto_ex_data_st */
    	em[2689] = 2691; em[2690] = 0; 
    em[2691] = 1; em[2692] = 8; em[2693] = 1; /* 2691: pointer.struct.stack_st_void */
    	em[2694] = 2696; em[2695] = 0; 
    em[2696] = 0; em[2697] = 32; em[2698] = 1; /* 2696: struct.stack_st_void */
    	em[2699] = 2701; em[2700] = 0; 
    em[2701] = 0; em[2702] = 32; em[2703] = 2; /* 2701: struct.stack_st */
    	em[2704] = 2211; em[2705] = 8; 
    	em[2706] = 113; em[2707] = 24; 
    em[2708] = 1; em[2709] = 8; em[2710] = 1; /* 2708: pointer.struct.bn_mont_ctx_st */
    	em[2711] = 2713; em[2712] = 0; 
    em[2713] = 0; em[2714] = 96; em[2715] = 3; /* 2713: struct.bn_mont_ctx_st */
    	em[2716] = 2674; em[2717] = 8; 
    	em[2718] = 2674; em[2719] = 32; 
    	em[2720] = 2674; em[2721] = 56; 
    em[2722] = 1; em[2723] = 8; em[2724] = 1; /* 2722: pointer.struct.bn_blinding_st */
    	em[2725] = 2727; em[2726] = 0; 
    em[2727] = 0; em[2728] = 88; em[2729] = 7; /* 2727: struct.bn_blinding_st */
    	em[2730] = 2744; em[2731] = 0; 
    	em[2732] = 2744; em[2733] = 8; 
    	em[2734] = 2744; em[2735] = 16; 
    	em[2736] = 2744; em[2737] = 24; 
    	em[2738] = 2761; em[2739] = 40; 
    	em[2740] = 2766; em[2741] = 72; 
    	em[2742] = 2780; em[2743] = 80; 
    em[2744] = 1; em[2745] = 8; em[2746] = 1; /* 2744: pointer.struct.bignum_st */
    	em[2747] = 2749; em[2748] = 0; 
    em[2749] = 0; em[2750] = 24; em[2751] = 1; /* 2749: struct.bignum_st */
    	em[2752] = 2754; em[2753] = 0; 
    em[2754] = 8884099; em[2755] = 8; em[2756] = 2; /* 2754: pointer_to_array_of_pointers_to_stack */
    	em[2757] = 1945; em[2758] = 0; 
    	em[2759] = 110; em[2760] = 12; 
    em[2761] = 0; em[2762] = 16; em[2763] = 1; /* 2761: struct.crypto_threadid_st */
    	em[2764] = 1733; em[2765] = 0; 
    em[2766] = 1; em[2767] = 8; em[2768] = 1; /* 2766: pointer.struct.bn_mont_ctx_st */
    	em[2769] = 2771; em[2770] = 0; 
    em[2771] = 0; em[2772] = 96; em[2773] = 3; /* 2771: struct.bn_mont_ctx_st */
    	em[2774] = 2749; em[2775] = 8; 
    	em[2776] = 2749; em[2777] = 32; 
    	em[2778] = 2749; em[2779] = 56; 
    em[2780] = 8884097; em[2781] = 8; em[2782] = 0; /* 2780: pointer.func */
    em[2783] = 1; em[2784] = 8; em[2785] = 1; /* 2783: pointer.struct.dsa_st */
    	em[2786] = 2788; em[2787] = 0; 
    em[2788] = 0; em[2789] = 136; em[2790] = 11; /* 2788: struct.dsa_st */
    	em[2791] = 2669; em[2792] = 24; 
    	em[2793] = 2669; em[2794] = 32; 
    	em[2795] = 2669; em[2796] = 40; 
    	em[2797] = 2669; em[2798] = 48; 
    	em[2799] = 2669; em[2800] = 56; 
    	em[2801] = 2669; em[2802] = 64; 
    	em[2803] = 2669; em[2804] = 72; 
    	em[2805] = 2708; em[2806] = 88; 
    	em[2807] = 2686; em[2808] = 104; 
    	em[2809] = 2813; em[2810] = 120; 
    	em[2811] = 2358; em[2812] = 128; 
    em[2813] = 1; em[2814] = 8; em[2815] = 1; /* 2813: pointer.struct.dsa_method */
    	em[2816] = 2818; em[2817] = 0; 
    em[2818] = 0; em[2819] = 96; em[2820] = 11; /* 2818: struct.dsa_method */
    	em[2821] = 90; em[2822] = 0; 
    	em[2823] = 2843; em[2824] = 8; 
    	em[2825] = 2846; em[2826] = 16; 
    	em[2827] = 2849; em[2828] = 24; 
    	em[2829] = 2852; em[2830] = 32; 
    	em[2831] = 2855; em[2832] = 40; 
    	em[2833] = 2858; em[2834] = 48; 
    	em[2835] = 2858; em[2836] = 56; 
    	em[2837] = 35; em[2838] = 72; 
    	em[2839] = 2861; em[2840] = 80; 
    	em[2841] = 2858; em[2842] = 88; 
    em[2843] = 8884097; em[2844] = 8; em[2845] = 0; /* 2843: pointer.func */
    em[2846] = 8884097; em[2847] = 8; em[2848] = 0; /* 2846: pointer.func */
    em[2849] = 8884097; em[2850] = 8; em[2851] = 0; /* 2849: pointer.func */
    em[2852] = 8884097; em[2853] = 8; em[2854] = 0; /* 2852: pointer.func */
    em[2855] = 8884097; em[2856] = 8; em[2857] = 0; /* 2855: pointer.func */
    em[2858] = 8884097; em[2859] = 8; em[2860] = 0; /* 2858: pointer.func */
    em[2861] = 8884097; em[2862] = 8; em[2863] = 0; /* 2861: pointer.func */
    em[2864] = 1; em[2865] = 8; em[2866] = 1; /* 2864: pointer.struct.dh_st */
    	em[2867] = 2869; em[2868] = 0; 
    em[2869] = 0; em[2870] = 144; em[2871] = 12; /* 2869: struct.dh_st */
    	em[2872] = 2896; em[2873] = 8; 
    	em[2874] = 2896; em[2875] = 16; 
    	em[2876] = 2896; em[2877] = 32; 
    	em[2878] = 2896; em[2879] = 40; 
    	em[2880] = 2913; em[2881] = 56; 
    	em[2882] = 2896; em[2883] = 64; 
    	em[2884] = 2896; em[2885] = 72; 
    	em[2886] = 17; em[2887] = 80; 
    	em[2888] = 2896; em[2889] = 96; 
    	em[2890] = 2927; em[2891] = 112; 
    	em[2892] = 2949; em[2893] = 128; 
    	em[2894] = 2358; em[2895] = 136; 
    em[2896] = 1; em[2897] = 8; em[2898] = 1; /* 2896: pointer.struct.bignum_st */
    	em[2899] = 2901; em[2900] = 0; 
    em[2901] = 0; em[2902] = 24; em[2903] = 1; /* 2901: struct.bignum_st */
    	em[2904] = 2906; em[2905] = 0; 
    em[2906] = 8884099; em[2907] = 8; em[2908] = 2; /* 2906: pointer_to_array_of_pointers_to_stack */
    	em[2909] = 1945; em[2910] = 0; 
    	em[2911] = 110; em[2912] = 12; 
    em[2913] = 1; em[2914] = 8; em[2915] = 1; /* 2913: pointer.struct.bn_mont_ctx_st */
    	em[2916] = 2918; em[2917] = 0; 
    em[2918] = 0; em[2919] = 96; em[2920] = 3; /* 2918: struct.bn_mont_ctx_st */
    	em[2921] = 2901; em[2922] = 8; 
    	em[2923] = 2901; em[2924] = 32; 
    	em[2925] = 2901; em[2926] = 56; 
    em[2927] = 0; em[2928] = 16; em[2929] = 1; /* 2927: struct.crypto_ex_data_st */
    	em[2930] = 2932; em[2931] = 0; 
    em[2932] = 1; em[2933] = 8; em[2934] = 1; /* 2932: pointer.struct.stack_st_void */
    	em[2935] = 2937; em[2936] = 0; 
    em[2937] = 0; em[2938] = 32; em[2939] = 1; /* 2937: struct.stack_st_void */
    	em[2940] = 2942; em[2941] = 0; 
    em[2942] = 0; em[2943] = 32; em[2944] = 2; /* 2942: struct.stack_st */
    	em[2945] = 2211; em[2946] = 8; 
    	em[2947] = 113; em[2948] = 24; 
    em[2949] = 1; em[2950] = 8; em[2951] = 1; /* 2949: pointer.struct.dh_method */
    	em[2952] = 2954; em[2953] = 0; 
    em[2954] = 0; em[2955] = 72; em[2956] = 8; /* 2954: struct.dh_method */
    	em[2957] = 90; em[2958] = 0; 
    	em[2959] = 2973; em[2960] = 8; 
    	em[2961] = 2976; em[2962] = 16; 
    	em[2963] = 2979; em[2964] = 24; 
    	em[2965] = 2973; em[2966] = 32; 
    	em[2967] = 2973; em[2968] = 40; 
    	em[2969] = 35; em[2970] = 56; 
    	em[2971] = 2982; em[2972] = 64; 
    em[2973] = 8884097; em[2974] = 8; em[2975] = 0; /* 2973: pointer.func */
    em[2976] = 8884097; em[2977] = 8; em[2978] = 0; /* 2976: pointer.func */
    em[2979] = 8884097; em[2980] = 8; em[2981] = 0; /* 2979: pointer.func */
    em[2982] = 8884097; em[2983] = 8; em[2984] = 0; /* 2982: pointer.func */
    em[2985] = 1; em[2986] = 8; em[2987] = 1; /* 2985: pointer.struct.ec_key_st */
    	em[2988] = 2990; em[2989] = 0; 
    em[2990] = 0; em[2991] = 56; em[2992] = 4; /* 2990: struct.ec_key_st */
    	em[2993] = 3001; em[2994] = 8; 
    	em[2995] = 1948; em[2996] = 16; 
    	em[2997] = 3210; em[2998] = 24; 
    	em[2999] = 1710; em[3000] = 48; 
    em[3001] = 1; em[3002] = 8; em[3003] = 1; /* 3001: pointer.struct.ec_group_st */
    	em[3004] = 3006; em[3005] = 0; 
    em[3006] = 0; em[3007] = 232; em[3008] = 12; /* 3006: struct.ec_group_st */
    	em[3009] = 3033; em[3010] = 0; 
    	em[3011] = 3205; em[3012] = 8; 
    	em[3013] = 2174; em[3014] = 16; 
    	em[3015] = 2174; em[3016] = 40; 
    	em[3017] = 17; em[3018] = 80; 
    	em[3019] = 2151; em[3020] = 96; 
    	em[3021] = 2174; em[3022] = 104; 
    	em[3023] = 2174; em[3024] = 152; 
    	em[3025] = 2174; em[3026] = 176; 
    	em[3027] = 1733; em[3028] = 208; 
    	em[3029] = 1733; em[3030] = 216; 
    	em[3031] = 2148; em[3032] = 224; 
    em[3033] = 1; em[3034] = 8; em[3035] = 1; /* 3033: pointer.struct.ec_method_st */
    	em[3036] = 3038; em[3037] = 0; 
    em[3038] = 0; em[3039] = 304; em[3040] = 37; /* 3038: struct.ec_method_st */
    	em[3041] = 3115; em[3042] = 8; 
    	em[3043] = 3118; em[3044] = 16; 
    	em[3045] = 3118; em[3046] = 24; 
    	em[3047] = 3121; em[3048] = 32; 
    	em[3049] = 3124; em[3050] = 40; 
    	em[3051] = 3127; em[3052] = 48; 
    	em[3053] = 3130; em[3054] = 56; 
    	em[3055] = 3133; em[3056] = 64; 
    	em[3057] = 3136; em[3058] = 72; 
    	em[3059] = 3139; em[3060] = 80; 
    	em[3061] = 3139; em[3062] = 88; 
    	em[3063] = 3142; em[3064] = 96; 
    	em[3065] = 3145; em[3066] = 104; 
    	em[3067] = 3148; em[3068] = 112; 
    	em[3069] = 3151; em[3070] = 120; 
    	em[3071] = 3154; em[3072] = 128; 
    	em[3073] = 3157; em[3074] = 136; 
    	em[3075] = 3160; em[3076] = 144; 
    	em[3077] = 3163; em[3078] = 152; 
    	em[3079] = 3166; em[3080] = 160; 
    	em[3081] = 3169; em[3082] = 168; 
    	em[3083] = 3172; em[3084] = 176; 
    	em[3085] = 3175; em[3086] = 184; 
    	em[3087] = 3178; em[3088] = 192; 
    	em[3089] = 3181; em[3090] = 200; 
    	em[3091] = 3184; em[3092] = 208; 
    	em[3093] = 3175; em[3094] = 216; 
    	em[3095] = 3187; em[3096] = 224; 
    	em[3097] = 3190; em[3098] = 232; 
    	em[3099] = 3193; em[3100] = 240; 
    	em[3101] = 3130; em[3102] = 248; 
    	em[3103] = 3196; em[3104] = 256; 
    	em[3105] = 3199; em[3106] = 264; 
    	em[3107] = 3196; em[3108] = 272; 
    	em[3109] = 3199; em[3110] = 280; 
    	em[3111] = 3199; em[3112] = 288; 
    	em[3113] = 3202; em[3114] = 296; 
    em[3115] = 8884097; em[3116] = 8; em[3117] = 0; /* 3115: pointer.func */
    em[3118] = 8884097; em[3119] = 8; em[3120] = 0; /* 3118: pointer.func */
    em[3121] = 8884097; em[3122] = 8; em[3123] = 0; /* 3121: pointer.func */
    em[3124] = 8884097; em[3125] = 8; em[3126] = 0; /* 3124: pointer.func */
    em[3127] = 8884097; em[3128] = 8; em[3129] = 0; /* 3127: pointer.func */
    em[3130] = 8884097; em[3131] = 8; em[3132] = 0; /* 3130: pointer.func */
    em[3133] = 8884097; em[3134] = 8; em[3135] = 0; /* 3133: pointer.func */
    em[3136] = 8884097; em[3137] = 8; em[3138] = 0; /* 3136: pointer.func */
    em[3139] = 8884097; em[3140] = 8; em[3141] = 0; /* 3139: pointer.func */
    em[3142] = 8884097; em[3143] = 8; em[3144] = 0; /* 3142: pointer.func */
    em[3145] = 8884097; em[3146] = 8; em[3147] = 0; /* 3145: pointer.func */
    em[3148] = 8884097; em[3149] = 8; em[3150] = 0; /* 3148: pointer.func */
    em[3151] = 8884097; em[3152] = 8; em[3153] = 0; /* 3151: pointer.func */
    em[3154] = 8884097; em[3155] = 8; em[3156] = 0; /* 3154: pointer.func */
    em[3157] = 8884097; em[3158] = 8; em[3159] = 0; /* 3157: pointer.func */
    em[3160] = 8884097; em[3161] = 8; em[3162] = 0; /* 3160: pointer.func */
    em[3163] = 8884097; em[3164] = 8; em[3165] = 0; /* 3163: pointer.func */
    em[3166] = 8884097; em[3167] = 8; em[3168] = 0; /* 3166: pointer.func */
    em[3169] = 8884097; em[3170] = 8; em[3171] = 0; /* 3169: pointer.func */
    em[3172] = 8884097; em[3173] = 8; em[3174] = 0; /* 3172: pointer.func */
    em[3175] = 8884097; em[3176] = 8; em[3177] = 0; /* 3175: pointer.func */
    em[3178] = 8884097; em[3179] = 8; em[3180] = 0; /* 3178: pointer.func */
    em[3181] = 8884097; em[3182] = 8; em[3183] = 0; /* 3181: pointer.func */
    em[3184] = 8884097; em[3185] = 8; em[3186] = 0; /* 3184: pointer.func */
    em[3187] = 8884097; em[3188] = 8; em[3189] = 0; /* 3187: pointer.func */
    em[3190] = 8884097; em[3191] = 8; em[3192] = 0; /* 3190: pointer.func */
    em[3193] = 8884097; em[3194] = 8; em[3195] = 0; /* 3193: pointer.func */
    em[3196] = 8884097; em[3197] = 8; em[3198] = 0; /* 3196: pointer.func */
    em[3199] = 8884097; em[3200] = 8; em[3201] = 0; /* 3199: pointer.func */
    em[3202] = 8884097; em[3203] = 8; em[3204] = 0; /* 3202: pointer.func */
    em[3205] = 1; em[3206] = 8; em[3207] = 1; /* 3205: pointer.struct.ec_point_st */
    	em[3208] = 1953; em[3209] = 0; 
    em[3210] = 1; em[3211] = 8; em[3212] = 1; /* 3210: pointer.struct.bignum_st */
    	em[3213] = 1933; em[3214] = 0; 
    em[3215] = 0; em[3216] = 24; em[3217] = 1; /* 3215: struct.ASN1_ENCODING_st */
    	em[3218] = 17; em[3219] = 0; 
    em[3220] = 8884097; em[3221] = 8; em[3222] = 0; /* 3220: pointer.func */
    em[3223] = 1; em[3224] = 8; em[3225] = 1; /* 3223: pointer.struct.AUTHORITY_KEYID_st */
    	em[3226] = 3228; em[3227] = 0; 
    em[3228] = 0; em[3229] = 24; em[3230] = 3; /* 3228: struct.AUTHORITY_KEYID_st */
    	em[3231] = 1285; em[3232] = 0; 
    	em[3233] = 1261; em[3234] = 8; 
    	em[3235] = 1251; em[3236] = 16; 
    em[3237] = 8884097; em[3238] = 8; em[3239] = 0; /* 3237: pointer.func */
    em[3240] = 8884097; em[3241] = 8; em[3242] = 0; /* 3240: pointer.func */
    em[3243] = 8884097; em[3244] = 8; em[3245] = 0; /* 3243: pointer.func */
    em[3246] = 1; em[3247] = 8; em[3248] = 1; /* 3246: pointer.struct.X509_algor_st */
    	em[3249] = 1771; em[3250] = 0; 
    em[3251] = 8884097; em[3252] = 8; em[3253] = 0; /* 3251: pointer.func */
    em[3254] = 0; em[3255] = 208; em[3256] = 24; /* 3254: struct.evp_pkey_asn1_method_st */
    	em[3257] = 35; em[3258] = 16; 
    	em[3259] = 35; em[3260] = 24; 
    	em[3261] = 3251; em[3262] = 32; 
    	em[3263] = 3305; em[3264] = 40; 
    	em[3265] = 3308; em[3266] = 48; 
    	em[3267] = 3243; em[3268] = 56; 
    	em[3269] = 3311; em[3270] = 64; 
    	em[3271] = 3314; em[3272] = 72; 
    	em[3273] = 3243; em[3274] = 80; 
    	em[3275] = 3237; em[3276] = 88; 
    	em[3277] = 3237; em[3278] = 96; 
    	em[3279] = 3317; em[3280] = 104; 
    	em[3281] = 3320; em[3282] = 112; 
    	em[3283] = 3237; em[3284] = 120; 
    	em[3285] = 3323; em[3286] = 128; 
    	em[3287] = 3308; em[3288] = 136; 
    	em[3289] = 3243; em[3290] = 144; 
    	em[3291] = 3240; em[3292] = 152; 
    	em[3293] = 3220; em[3294] = 160; 
    	em[3295] = 3326; em[3296] = 168; 
    	em[3297] = 3317; em[3298] = 176; 
    	em[3299] = 3320; em[3300] = 184; 
    	em[3301] = 2236; em[3302] = 192; 
    	em[3303] = 3329; em[3304] = 200; 
    em[3305] = 8884097; em[3306] = 8; em[3307] = 0; /* 3305: pointer.func */
    em[3308] = 8884097; em[3309] = 8; em[3310] = 0; /* 3308: pointer.func */
    em[3311] = 8884097; em[3312] = 8; em[3313] = 0; /* 3311: pointer.func */
    em[3314] = 8884097; em[3315] = 8; em[3316] = 0; /* 3314: pointer.func */
    em[3317] = 8884097; em[3318] = 8; em[3319] = 0; /* 3317: pointer.func */
    em[3320] = 8884097; em[3321] = 8; em[3322] = 0; /* 3320: pointer.func */
    em[3323] = 8884097; em[3324] = 8; em[3325] = 0; /* 3323: pointer.func */
    em[3326] = 8884097; em[3327] = 8; em[3328] = 0; /* 3326: pointer.func */
    em[3329] = 8884097; em[3330] = 8; em[3331] = 0; /* 3329: pointer.func */
    em[3332] = 1; em[3333] = 8; em[3334] = 1; /* 3332: pointer.struct.evp_pkey_asn1_method_st */
    	em[3335] = 3254; em[3336] = 0; 
    em[3337] = 0; em[3338] = 56; em[3339] = 4; /* 3337: struct.evp_pkey_st */
    	em[3340] = 3332; em[3341] = 16; 
    	em[3342] = 3348; em[3343] = 24; 
    	em[3344] = 2248; em[3345] = 32; 
    	em[3346] = 1681; em[3347] = 48; 
    em[3348] = 1; em[3349] = 8; em[3350] = 1; /* 3348: pointer.struct.engine_st */
    	em[3351] = 2363; em[3352] = 0; 
    em[3353] = 1; em[3354] = 8; em[3355] = 1; /* 3353: pointer.struct.evp_pkey_st */
    	em[3356] = 3337; em[3357] = 0; 
    em[3358] = 0; em[3359] = 1; em[3360] = 0; /* 3358: char */
    em[3361] = 1; em[3362] = 8; em[3363] = 1; /* 3361: pointer.struct.asn1_string_st */
    	em[3364] = 335; em[3365] = 0; 
    em[3366] = 0; em[3367] = 24; em[3368] = 1; /* 3366: struct.asn1_string_st */
    	em[3369] = 17; em[3370] = 8; 
    em[3371] = 1; em[3372] = 8; em[3373] = 1; /* 3371: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3374] = 3376; em[3375] = 0; 
    em[3376] = 0; em[3377] = 32; em[3378] = 2; /* 3376: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3379] = 3383; em[3380] = 8; 
    	em[3381] = 113; em[3382] = 24; 
    em[3383] = 8884099; em[3384] = 8; em[3385] = 2; /* 3383: pointer_to_array_of_pointers_to_stack */
    	em[3386] = 3390; em[3387] = 0; 
    	em[3388] = 110; em[3389] = 20; 
    em[3390] = 0; em[3391] = 8; em[3392] = 1; /* 3390: pointer.X509_NAME_ENTRY */
    	em[3393] = 64; em[3394] = 0; 
    em[3395] = 1; em[3396] = 8; em[3397] = 1; /* 3395: pointer.struct.X509_name_st */
    	em[3398] = 3400; em[3399] = 0; 
    em[3400] = 0; em[3401] = 40; em[3402] = 3; /* 3400: struct.X509_name_st */
    	em[3403] = 3371; em[3404] = 0; 
    	em[3405] = 3409; em[3406] = 16; 
    	em[3407] = 17; em[3408] = 24; 
    em[3409] = 1; em[3410] = 8; em[3411] = 1; /* 3409: pointer.struct.buf_mem_st */
    	em[3412] = 3414; em[3413] = 0; 
    em[3414] = 0; em[3415] = 24; em[3416] = 1; /* 3414: struct.buf_mem_st */
    	em[3417] = 35; em[3418] = 8; 
    em[3419] = 1; em[3420] = 8; em[3421] = 1; /* 3419: pointer.struct.x509_st */
    	em[3422] = 3424; em[3423] = 0; 
    em[3424] = 0; em[3425] = 184; em[3426] = 12; /* 3424: struct.x509_st */
    	em[3427] = 3451; em[3428] = 0; 
    	em[3429] = 3486; em[3430] = 8; 
    	em[3431] = 1326; em[3432] = 16; 
    	em[3433] = 35; em[3434] = 32; 
    	em[3435] = 2927; em[3436] = 40; 
    	em[3437] = 3361; em[3438] = 104; 
    	em[3439] = 3223; em[3440] = 112; 
    	em[3441] = 3534; em[3442] = 120; 
    	em[3443] = 737; em[3444] = 128; 
    	em[3445] = 395; em[3446] = 136; 
    	em[3447] = 359; em[3448] = 144; 
    	em[3449] = 3539; em[3450] = 176; 
    em[3451] = 1; em[3452] = 8; em[3453] = 1; /* 3451: pointer.struct.x509_cinf_st */
    	em[3454] = 3456; em[3455] = 0; 
    em[3456] = 0; em[3457] = 104; em[3458] = 11; /* 3456: struct.x509_cinf_st */
    	em[3459] = 3481; em[3460] = 0; 
    	em[3461] = 3481; em[3462] = 8; 
    	em[3463] = 3486; em[3464] = 16; 
    	em[3465] = 3395; em[3466] = 24; 
    	em[3467] = 2219; em[3468] = 32; 
    	em[3469] = 3395; em[3470] = 40; 
    	em[3471] = 3491; em[3472] = 48; 
    	em[3473] = 1326; em[3474] = 56; 
    	em[3475] = 1326; em[3476] = 64; 
    	em[3477] = 3510; em[3478] = 72; 
    	em[3479] = 3215; em[3480] = 80; 
    em[3481] = 1; em[3482] = 8; em[3483] = 1; /* 3481: pointer.struct.asn1_string_st */
    	em[3484] = 335; em[3485] = 0; 
    em[3486] = 1; em[3487] = 8; em[3488] = 1; /* 3486: pointer.struct.X509_algor_st */
    	em[3489] = 1771; em[3490] = 0; 
    em[3491] = 1; em[3492] = 8; em[3493] = 1; /* 3491: pointer.struct.X509_pubkey_st */
    	em[3494] = 3496; em[3495] = 0; 
    em[3496] = 0; em[3497] = 24; em[3498] = 3; /* 3496: struct.X509_pubkey_st */
    	em[3499] = 3246; em[3500] = 0; 
    	em[3501] = 3505; em[3502] = 8; 
    	em[3503] = 3353; em[3504] = 16; 
    em[3505] = 1; em[3506] = 8; em[3507] = 1; /* 3505: pointer.struct.asn1_string_st */
    	em[3508] = 3366; em[3509] = 0; 
    em[3510] = 1; em[3511] = 8; em[3512] = 1; /* 3510: pointer.struct.stack_st_X509_EXTENSION */
    	em[3513] = 3515; em[3514] = 0; 
    em[3515] = 0; em[3516] = 32; em[3517] = 2; /* 3515: struct.stack_st_fake_X509_EXTENSION */
    	em[3518] = 3522; em[3519] = 8; 
    	em[3520] = 113; em[3521] = 24; 
    em[3522] = 8884099; em[3523] = 8; em[3524] = 2; /* 3522: pointer_to_array_of_pointers_to_stack */
    	em[3525] = 3529; em[3526] = 0; 
    	em[3527] = 110; em[3528] = 20; 
    em[3529] = 0; em[3530] = 8; em[3531] = 1; /* 3529: pointer.X509_EXTENSION */
    	em[3532] = 1321; em[3533] = 0; 
    em[3534] = 1; em[3535] = 8; em[3536] = 1; /* 3534: pointer.struct.X509_POLICY_CACHE_st */
    	em[3537] = 1239; em[3538] = 0; 
    em[3539] = 1; em[3540] = 8; em[3541] = 1; /* 3539: pointer.struct.x509_cert_aux_st */
    	em[3542] = 3544; em[3543] = 0; 
    em[3544] = 0; em[3545] = 40; em[3546] = 5; /* 3544: struct.x509_cert_aux_st */
    	em[3547] = 3557; em[3548] = 0; 
    	em[3549] = 3557; em[3550] = 8; 
    	em[3551] = 330; em[3552] = 16; 
    	em[3553] = 3361; em[3554] = 24; 
    	em[3555] = 1742; em[3556] = 32; 
    em[3557] = 1; em[3558] = 8; em[3559] = 1; /* 3557: pointer.struct.stack_st_ASN1_OBJECT */
    	em[3560] = 3562; em[3561] = 0; 
    em[3562] = 0; em[3563] = 32; em[3564] = 2; /* 3562: struct.stack_st_fake_ASN1_OBJECT */
    	em[3565] = 3569; em[3566] = 8; 
    	em[3567] = 113; em[3568] = 24; 
    em[3569] = 8884099; em[3570] = 8; em[3571] = 2; /* 3569: pointer_to_array_of_pointers_to_stack */
    	em[3572] = 3576; em[3573] = 0; 
    	em[3574] = 110; em[3575] = 20; 
    em[3576] = 0; em[3577] = 8; em[3578] = 1; /* 3576: pointer.ASN1_OBJECT */
    	em[3579] = 852; em[3580] = 0; 
    em[3581] = 1; em[3582] = 8; em[3583] = 1; /* 3581: pointer.int */
    	em[3584] = 110; em[3585] = 0; 
    args_addr->arg_entity_index[0] = 3419;
    args_addr->arg_entity_index[1] = 110;
    args_addr->arg_entity_index[2] = 3581;
    args_addr->arg_entity_index[3] = 3581;
    args_addr->ret_entity_index = 1733;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int * new_arg_c = *((int * *)new_args->args[2]);

    int * new_arg_d = *((int * *)new_args->args[3]);

    void * *new_ret_ptr = (void * *)new_args->ret;

    void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
    orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
    *new_ret_ptr = (*orig_X509_get_ext_d2i)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    free(args_addr);

    return ret;
}

