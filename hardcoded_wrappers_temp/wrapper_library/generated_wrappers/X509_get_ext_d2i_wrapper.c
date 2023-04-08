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
    em[0] = 0; em[1] = 0; em[2] = 1; /* 0: X509_ALGOR */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 16; em[7] = 2; /* 5: struct.X509_algor_st */
    	em[8] = 12; em[9] = 0; 
    	em[10] = 39; em[11] = 8; 
    em[12] = 1; em[13] = 8; em[14] = 1; /* 12: pointer.struct.asn1_object_st */
    	em[15] = 17; em[16] = 0; 
    em[17] = 0; em[18] = 40; em[19] = 3; /* 17: struct.asn1_object_st */
    	em[20] = 26; em[21] = 0; 
    	em[22] = 26; em[23] = 8; 
    	em[24] = 31; em[25] = 24; 
    em[26] = 1; em[27] = 8; em[28] = 1; /* 26: pointer.char */
    	em[29] = 8884096; em[30] = 0; 
    em[31] = 1; em[32] = 8; em[33] = 1; /* 31: pointer.unsigned char */
    	em[34] = 36; em[35] = 0; 
    em[36] = 0; em[37] = 1; em[38] = 0; /* 36: unsigned char */
    em[39] = 1; em[40] = 8; em[41] = 1; /* 39: pointer.struct.asn1_type_st */
    	em[42] = 44; em[43] = 0; 
    em[44] = 0; em[45] = 16; em[46] = 1; /* 44: struct.asn1_type_st */
    	em[47] = 49; em[48] = 8; 
    em[49] = 0; em[50] = 8; em[51] = 20; /* 49: union.unknown */
    	em[52] = 92; em[53] = 0; 
    	em[54] = 97; em[55] = 0; 
    	em[56] = 12; em[57] = 0; 
    	em[58] = 112; em[59] = 0; 
    	em[60] = 117; em[61] = 0; 
    	em[62] = 122; em[63] = 0; 
    	em[64] = 127; em[65] = 0; 
    	em[66] = 132; em[67] = 0; 
    	em[68] = 137; em[69] = 0; 
    	em[70] = 142; em[71] = 0; 
    	em[72] = 147; em[73] = 0; 
    	em[74] = 152; em[75] = 0; 
    	em[76] = 157; em[77] = 0; 
    	em[78] = 162; em[79] = 0; 
    	em[80] = 167; em[81] = 0; 
    	em[82] = 172; em[83] = 0; 
    	em[84] = 177; em[85] = 0; 
    	em[86] = 97; em[87] = 0; 
    	em[88] = 97; em[89] = 0; 
    	em[90] = 182; em[91] = 0; 
    em[92] = 1; em[93] = 8; em[94] = 1; /* 92: pointer.char */
    	em[95] = 8884096; em[96] = 0; 
    em[97] = 1; em[98] = 8; em[99] = 1; /* 97: pointer.struct.asn1_string_st */
    	em[100] = 102; em[101] = 0; 
    em[102] = 0; em[103] = 24; em[104] = 1; /* 102: struct.asn1_string_st */
    	em[105] = 107; em[106] = 8; 
    em[107] = 1; em[108] = 8; em[109] = 1; /* 107: pointer.unsigned char */
    	em[110] = 36; em[111] = 0; 
    em[112] = 1; em[113] = 8; em[114] = 1; /* 112: pointer.struct.asn1_string_st */
    	em[115] = 102; em[116] = 0; 
    em[117] = 1; em[118] = 8; em[119] = 1; /* 117: pointer.struct.asn1_string_st */
    	em[120] = 102; em[121] = 0; 
    em[122] = 1; em[123] = 8; em[124] = 1; /* 122: pointer.struct.asn1_string_st */
    	em[125] = 102; em[126] = 0; 
    em[127] = 1; em[128] = 8; em[129] = 1; /* 127: pointer.struct.asn1_string_st */
    	em[130] = 102; em[131] = 0; 
    em[132] = 1; em[133] = 8; em[134] = 1; /* 132: pointer.struct.asn1_string_st */
    	em[135] = 102; em[136] = 0; 
    em[137] = 1; em[138] = 8; em[139] = 1; /* 137: pointer.struct.asn1_string_st */
    	em[140] = 102; em[141] = 0; 
    em[142] = 1; em[143] = 8; em[144] = 1; /* 142: pointer.struct.asn1_string_st */
    	em[145] = 102; em[146] = 0; 
    em[147] = 1; em[148] = 8; em[149] = 1; /* 147: pointer.struct.asn1_string_st */
    	em[150] = 102; em[151] = 0; 
    em[152] = 1; em[153] = 8; em[154] = 1; /* 152: pointer.struct.asn1_string_st */
    	em[155] = 102; em[156] = 0; 
    em[157] = 1; em[158] = 8; em[159] = 1; /* 157: pointer.struct.asn1_string_st */
    	em[160] = 102; em[161] = 0; 
    em[162] = 1; em[163] = 8; em[164] = 1; /* 162: pointer.struct.asn1_string_st */
    	em[165] = 102; em[166] = 0; 
    em[167] = 1; em[168] = 8; em[169] = 1; /* 167: pointer.struct.asn1_string_st */
    	em[170] = 102; em[171] = 0; 
    em[172] = 1; em[173] = 8; em[174] = 1; /* 172: pointer.struct.asn1_string_st */
    	em[175] = 102; em[176] = 0; 
    em[177] = 1; em[178] = 8; em[179] = 1; /* 177: pointer.struct.asn1_string_st */
    	em[180] = 102; em[181] = 0; 
    em[182] = 1; em[183] = 8; em[184] = 1; /* 182: pointer.struct.ASN1_VALUE_st */
    	em[185] = 187; em[186] = 0; 
    em[187] = 0; em[188] = 0; em[189] = 0; /* 187: struct.ASN1_VALUE_st */
    em[190] = 1; em[191] = 8; em[192] = 1; /* 190: pointer.struct.stack_st_X509_ALGOR */
    	em[193] = 195; em[194] = 0; 
    em[195] = 0; em[196] = 32; em[197] = 2; /* 195: struct.stack_st_fake_X509_ALGOR */
    	em[198] = 202; em[199] = 8; 
    	em[200] = 217; em[201] = 24; 
    em[202] = 8884099; em[203] = 8; em[204] = 2; /* 202: pointer_to_array_of_pointers_to_stack */
    	em[205] = 209; em[206] = 0; 
    	em[207] = 214; em[208] = 20; 
    em[209] = 0; em[210] = 8; em[211] = 1; /* 209: pointer.X509_ALGOR */
    	em[212] = 0; em[213] = 0; 
    em[214] = 0; em[215] = 4; em[216] = 0; /* 214: int */
    em[217] = 8884097; em[218] = 8; em[219] = 0; /* 217: pointer.func */
    em[220] = 1; em[221] = 8; em[222] = 1; /* 220: pointer.struct.stack_st_ASN1_OBJECT */
    	em[223] = 225; em[224] = 0; 
    em[225] = 0; em[226] = 32; em[227] = 2; /* 225: struct.stack_st_fake_ASN1_OBJECT */
    	em[228] = 232; em[229] = 8; 
    	em[230] = 217; em[231] = 24; 
    em[232] = 8884099; em[233] = 8; em[234] = 2; /* 232: pointer_to_array_of_pointers_to_stack */
    	em[235] = 239; em[236] = 0; 
    	em[237] = 214; em[238] = 20; 
    em[239] = 0; em[240] = 8; em[241] = 1; /* 239: pointer.ASN1_OBJECT */
    	em[242] = 244; em[243] = 0; 
    em[244] = 0; em[245] = 0; em[246] = 1; /* 244: ASN1_OBJECT */
    	em[247] = 249; em[248] = 0; 
    em[249] = 0; em[250] = 40; em[251] = 3; /* 249: struct.asn1_object_st */
    	em[252] = 26; em[253] = 0; 
    	em[254] = 26; em[255] = 8; 
    	em[256] = 31; em[257] = 24; 
    em[258] = 1; em[259] = 8; em[260] = 1; /* 258: pointer.struct.x509_cert_aux_st */
    	em[261] = 263; em[262] = 0; 
    em[263] = 0; em[264] = 40; em[265] = 5; /* 263: struct.x509_cert_aux_st */
    	em[266] = 220; em[267] = 0; 
    	em[268] = 220; em[269] = 8; 
    	em[270] = 276; em[271] = 16; 
    	em[272] = 286; em[273] = 24; 
    	em[274] = 190; em[275] = 32; 
    em[276] = 1; em[277] = 8; em[278] = 1; /* 276: pointer.struct.asn1_string_st */
    	em[279] = 281; em[280] = 0; 
    em[281] = 0; em[282] = 24; em[283] = 1; /* 281: struct.asn1_string_st */
    	em[284] = 107; em[285] = 8; 
    em[286] = 1; em[287] = 8; em[288] = 1; /* 286: pointer.struct.asn1_string_st */
    	em[289] = 281; em[290] = 0; 
    em[291] = 0; em[292] = 16; em[293] = 2; /* 291: struct.EDIPartyName_st */
    	em[294] = 298; em[295] = 0; 
    	em[296] = 298; em[297] = 8; 
    em[298] = 1; em[299] = 8; em[300] = 1; /* 298: pointer.struct.asn1_string_st */
    	em[301] = 303; em[302] = 0; 
    em[303] = 0; em[304] = 24; em[305] = 1; /* 303: struct.asn1_string_st */
    	em[306] = 107; em[307] = 8; 
    em[308] = 1; em[309] = 8; em[310] = 1; /* 308: pointer.struct.EDIPartyName_st */
    	em[311] = 291; em[312] = 0; 
    em[313] = 1; em[314] = 8; em[315] = 1; /* 313: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[316] = 318; em[317] = 0; 
    em[318] = 0; em[319] = 32; em[320] = 2; /* 318: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[321] = 325; em[322] = 8; 
    	em[323] = 217; em[324] = 24; 
    em[325] = 8884099; em[326] = 8; em[327] = 2; /* 325: pointer_to_array_of_pointers_to_stack */
    	em[328] = 332; em[329] = 0; 
    	em[330] = 214; em[331] = 20; 
    em[332] = 0; em[333] = 8; em[334] = 1; /* 332: pointer.X509_NAME_ENTRY */
    	em[335] = 337; em[336] = 0; 
    em[337] = 0; em[338] = 0; em[339] = 1; /* 337: X509_NAME_ENTRY */
    	em[340] = 342; em[341] = 0; 
    em[342] = 0; em[343] = 24; em[344] = 2; /* 342: struct.X509_name_entry_st */
    	em[345] = 349; em[346] = 0; 
    	em[347] = 363; em[348] = 8; 
    em[349] = 1; em[350] = 8; em[351] = 1; /* 349: pointer.struct.asn1_object_st */
    	em[352] = 354; em[353] = 0; 
    em[354] = 0; em[355] = 40; em[356] = 3; /* 354: struct.asn1_object_st */
    	em[357] = 26; em[358] = 0; 
    	em[359] = 26; em[360] = 8; 
    	em[361] = 31; em[362] = 24; 
    em[363] = 1; em[364] = 8; em[365] = 1; /* 363: pointer.struct.asn1_string_st */
    	em[366] = 368; em[367] = 0; 
    em[368] = 0; em[369] = 24; em[370] = 1; /* 368: struct.asn1_string_st */
    	em[371] = 107; em[372] = 8; 
    em[373] = 0; em[374] = 40; em[375] = 3; /* 373: struct.X509_name_st */
    	em[376] = 313; em[377] = 0; 
    	em[378] = 382; em[379] = 16; 
    	em[380] = 107; em[381] = 24; 
    em[382] = 1; em[383] = 8; em[384] = 1; /* 382: pointer.struct.buf_mem_st */
    	em[385] = 387; em[386] = 0; 
    em[387] = 0; em[388] = 24; em[389] = 1; /* 387: struct.buf_mem_st */
    	em[390] = 92; em[391] = 8; 
    em[392] = 1; em[393] = 8; em[394] = 1; /* 392: pointer.struct.asn1_string_st */
    	em[395] = 303; em[396] = 0; 
    em[397] = 1; em[398] = 8; em[399] = 1; /* 397: pointer.struct.asn1_string_st */
    	em[400] = 303; em[401] = 0; 
    em[402] = 1; em[403] = 8; em[404] = 1; /* 402: pointer.struct.asn1_string_st */
    	em[405] = 303; em[406] = 0; 
    em[407] = 1; em[408] = 8; em[409] = 1; /* 407: pointer.struct.asn1_string_st */
    	em[410] = 303; em[411] = 0; 
    em[412] = 1; em[413] = 8; em[414] = 1; /* 412: pointer.struct.asn1_string_st */
    	em[415] = 303; em[416] = 0; 
    em[417] = 0; em[418] = 8; em[419] = 20; /* 417: union.unknown */
    	em[420] = 92; em[421] = 0; 
    	em[422] = 298; em[423] = 0; 
    	em[424] = 460; em[425] = 0; 
    	em[426] = 474; em[427] = 0; 
    	em[428] = 479; em[429] = 0; 
    	em[430] = 484; em[431] = 0; 
    	em[432] = 412; em[433] = 0; 
    	em[434] = 489; em[435] = 0; 
    	em[436] = 407; em[437] = 0; 
    	em[438] = 494; em[439] = 0; 
    	em[440] = 402; em[441] = 0; 
    	em[442] = 397; em[443] = 0; 
    	em[444] = 499; em[445] = 0; 
    	em[446] = 504; em[447] = 0; 
    	em[448] = 392; em[449] = 0; 
    	em[450] = 509; em[451] = 0; 
    	em[452] = 514; em[453] = 0; 
    	em[454] = 298; em[455] = 0; 
    	em[456] = 298; em[457] = 0; 
    	em[458] = 519; em[459] = 0; 
    em[460] = 1; em[461] = 8; em[462] = 1; /* 460: pointer.struct.asn1_object_st */
    	em[463] = 465; em[464] = 0; 
    em[465] = 0; em[466] = 40; em[467] = 3; /* 465: struct.asn1_object_st */
    	em[468] = 26; em[469] = 0; 
    	em[470] = 26; em[471] = 8; 
    	em[472] = 31; em[473] = 24; 
    em[474] = 1; em[475] = 8; em[476] = 1; /* 474: pointer.struct.asn1_string_st */
    	em[477] = 303; em[478] = 0; 
    em[479] = 1; em[480] = 8; em[481] = 1; /* 479: pointer.struct.asn1_string_st */
    	em[482] = 303; em[483] = 0; 
    em[484] = 1; em[485] = 8; em[486] = 1; /* 484: pointer.struct.asn1_string_st */
    	em[487] = 303; em[488] = 0; 
    em[489] = 1; em[490] = 8; em[491] = 1; /* 489: pointer.struct.asn1_string_st */
    	em[492] = 303; em[493] = 0; 
    em[494] = 1; em[495] = 8; em[496] = 1; /* 494: pointer.struct.asn1_string_st */
    	em[497] = 303; em[498] = 0; 
    em[499] = 1; em[500] = 8; em[501] = 1; /* 499: pointer.struct.asn1_string_st */
    	em[502] = 303; em[503] = 0; 
    em[504] = 1; em[505] = 8; em[506] = 1; /* 504: pointer.struct.asn1_string_st */
    	em[507] = 303; em[508] = 0; 
    em[509] = 1; em[510] = 8; em[511] = 1; /* 509: pointer.struct.asn1_string_st */
    	em[512] = 303; em[513] = 0; 
    em[514] = 1; em[515] = 8; em[516] = 1; /* 514: pointer.struct.asn1_string_st */
    	em[517] = 303; em[518] = 0; 
    em[519] = 1; em[520] = 8; em[521] = 1; /* 519: pointer.struct.ASN1_VALUE_st */
    	em[522] = 524; em[523] = 0; 
    em[524] = 0; em[525] = 0; em[526] = 0; /* 524: struct.ASN1_VALUE_st */
    em[527] = 1; em[528] = 8; em[529] = 1; /* 527: pointer.struct.otherName_st */
    	em[530] = 532; em[531] = 0; 
    em[532] = 0; em[533] = 16; em[534] = 2; /* 532: struct.otherName_st */
    	em[535] = 460; em[536] = 0; 
    	em[537] = 539; em[538] = 8; 
    em[539] = 1; em[540] = 8; em[541] = 1; /* 539: pointer.struct.asn1_type_st */
    	em[542] = 544; em[543] = 0; 
    em[544] = 0; em[545] = 16; em[546] = 1; /* 544: struct.asn1_type_st */
    	em[547] = 417; em[548] = 8; 
    em[549] = 0; em[550] = 16; em[551] = 1; /* 549: struct.GENERAL_NAME_st */
    	em[552] = 554; em[553] = 8; 
    em[554] = 0; em[555] = 8; em[556] = 15; /* 554: union.unknown */
    	em[557] = 92; em[558] = 0; 
    	em[559] = 527; em[560] = 0; 
    	em[561] = 494; em[562] = 0; 
    	em[563] = 494; em[564] = 0; 
    	em[565] = 539; em[566] = 0; 
    	em[567] = 587; em[568] = 0; 
    	em[569] = 308; em[570] = 0; 
    	em[571] = 494; em[572] = 0; 
    	em[573] = 412; em[574] = 0; 
    	em[575] = 460; em[576] = 0; 
    	em[577] = 412; em[578] = 0; 
    	em[579] = 587; em[580] = 0; 
    	em[581] = 494; em[582] = 0; 
    	em[583] = 460; em[584] = 0; 
    	em[585] = 539; em[586] = 0; 
    em[587] = 1; em[588] = 8; em[589] = 1; /* 587: pointer.struct.X509_name_st */
    	em[590] = 373; em[591] = 0; 
    em[592] = 1; em[593] = 8; em[594] = 1; /* 592: pointer.struct.GENERAL_NAME_st */
    	em[595] = 549; em[596] = 0; 
    em[597] = 1; em[598] = 8; em[599] = 1; /* 597: pointer.struct.NAME_CONSTRAINTS_st */
    	em[600] = 602; em[601] = 0; 
    em[602] = 0; em[603] = 16; em[604] = 2; /* 602: struct.NAME_CONSTRAINTS_st */
    	em[605] = 609; em[606] = 0; 
    	em[607] = 609; em[608] = 8; 
    em[609] = 1; em[610] = 8; em[611] = 1; /* 609: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[612] = 614; em[613] = 0; 
    em[614] = 0; em[615] = 32; em[616] = 2; /* 614: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[617] = 621; em[618] = 8; 
    	em[619] = 217; em[620] = 24; 
    em[621] = 8884099; em[622] = 8; em[623] = 2; /* 621: pointer_to_array_of_pointers_to_stack */
    	em[624] = 628; em[625] = 0; 
    	em[626] = 214; em[627] = 20; 
    em[628] = 0; em[629] = 8; em[630] = 1; /* 628: pointer.GENERAL_SUBTREE */
    	em[631] = 633; em[632] = 0; 
    em[633] = 0; em[634] = 0; em[635] = 1; /* 633: GENERAL_SUBTREE */
    	em[636] = 638; em[637] = 0; 
    em[638] = 0; em[639] = 24; em[640] = 3; /* 638: struct.GENERAL_SUBTREE_st */
    	em[641] = 592; em[642] = 0; 
    	em[643] = 474; em[644] = 8; 
    	em[645] = 474; em[646] = 16; 
    em[647] = 1; em[648] = 8; em[649] = 1; /* 647: pointer.struct.stack_st_GENERAL_NAME */
    	em[650] = 652; em[651] = 0; 
    em[652] = 0; em[653] = 32; em[654] = 2; /* 652: struct.stack_st_fake_GENERAL_NAME */
    	em[655] = 659; em[656] = 8; 
    	em[657] = 217; em[658] = 24; 
    em[659] = 8884099; em[660] = 8; em[661] = 2; /* 659: pointer_to_array_of_pointers_to_stack */
    	em[662] = 666; em[663] = 0; 
    	em[664] = 214; em[665] = 20; 
    em[666] = 0; em[667] = 8; em[668] = 1; /* 666: pointer.GENERAL_NAME */
    	em[669] = 671; em[670] = 0; 
    em[671] = 0; em[672] = 0; em[673] = 1; /* 671: GENERAL_NAME */
    	em[674] = 676; em[675] = 0; 
    em[676] = 0; em[677] = 16; em[678] = 1; /* 676: struct.GENERAL_NAME_st */
    	em[679] = 681; em[680] = 8; 
    em[681] = 0; em[682] = 8; em[683] = 15; /* 681: union.unknown */
    	em[684] = 92; em[685] = 0; 
    	em[686] = 714; em[687] = 0; 
    	em[688] = 833; em[689] = 0; 
    	em[690] = 833; em[691] = 0; 
    	em[692] = 740; em[693] = 0; 
    	em[694] = 873; em[695] = 0; 
    	em[696] = 921; em[697] = 0; 
    	em[698] = 833; em[699] = 0; 
    	em[700] = 818; em[701] = 0; 
    	em[702] = 726; em[703] = 0; 
    	em[704] = 818; em[705] = 0; 
    	em[706] = 873; em[707] = 0; 
    	em[708] = 833; em[709] = 0; 
    	em[710] = 726; em[711] = 0; 
    	em[712] = 740; em[713] = 0; 
    em[714] = 1; em[715] = 8; em[716] = 1; /* 714: pointer.struct.otherName_st */
    	em[717] = 719; em[718] = 0; 
    em[719] = 0; em[720] = 16; em[721] = 2; /* 719: struct.otherName_st */
    	em[722] = 726; em[723] = 0; 
    	em[724] = 740; em[725] = 8; 
    em[726] = 1; em[727] = 8; em[728] = 1; /* 726: pointer.struct.asn1_object_st */
    	em[729] = 731; em[730] = 0; 
    em[731] = 0; em[732] = 40; em[733] = 3; /* 731: struct.asn1_object_st */
    	em[734] = 26; em[735] = 0; 
    	em[736] = 26; em[737] = 8; 
    	em[738] = 31; em[739] = 24; 
    em[740] = 1; em[741] = 8; em[742] = 1; /* 740: pointer.struct.asn1_type_st */
    	em[743] = 745; em[744] = 0; 
    em[745] = 0; em[746] = 16; em[747] = 1; /* 745: struct.asn1_type_st */
    	em[748] = 750; em[749] = 8; 
    em[750] = 0; em[751] = 8; em[752] = 20; /* 750: union.unknown */
    	em[753] = 92; em[754] = 0; 
    	em[755] = 793; em[756] = 0; 
    	em[757] = 726; em[758] = 0; 
    	em[759] = 803; em[760] = 0; 
    	em[761] = 808; em[762] = 0; 
    	em[763] = 813; em[764] = 0; 
    	em[765] = 818; em[766] = 0; 
    	em[767] = 823; em[768] = 0; 
    	em[769] = 828; em[770] = 0; 
    	em[771] = 833; em[772] = 0; 
    	em[773] = 838; em[774] = 0; 
    	em[775] = 843; em[776] = 0; 
    	em[777] = 848; em[778] = 0; 
    	em[779] = 853; em[780] = 0; 
    	em[781] = 858; em[782] = 0; 
    	em[783] = 863; em[784] = 0; 
    	em[785] = 868; em[786] = 0; 
    	em[787] = 793; em[788] = 0; 
    	em[789] = 793; em[790] = 0; 
    	em[791] = 519; em[792] = 0; 
    em[793] = 1; em[794] = 8; em[795] = 1; /* 793: pointer.struct.asn1_string_st */
    	em[796] = 798; em[797] = 0; 
    em[798] = 0; em[799] = 24; em[800] = 1; /* 798: struct.asn1_string_st */
    	em[801] = 107; em[802] = 8; 
    em[803] = 1; em[804] = 8; em[805] = 1; /* 803: pointer.struct.asn1_string_st */
    	em[806] = 798; em[807] = 0; 
    em[808] = 1; em[809] = 8; em[810] = 1; /* 808: pointer.struct.asn1_string_st */
    	em[811] = 798; em[812] = 0; 
    em[813] = 1; em[814] = 8; em[815] = 1; /* 813: pointer.struct.asn1_string_st */
    	em[816] = 798; em[817] = 0; 
    em[818] = 1; em[819] = 8; em[820] = 1; /* 818: pointer.struct.asn1_string_st */
    	em[821] = 798; em[822] = 0; 
    em[823] = 1; em[824] = 8; em[825] = 1; /* 823: pointer.struct.asn1_string_st */
    	em[826] = 798; em[827] = 0; 
    em[828] = 1; em[829] = 8; em[830] = 1; /* 828: pointer.struct.asn1_string_st */
    	em[831] = 798; em[832] = 0; 
    em[833] = 1; em[834] = 8; em[835] = 1; /* 833: pointer.struct.asn1_string_st */
    	em[836] = 798; em[837] = 0; 
    em[838] = 1; em[839] = 8; em[840] = 1; /* 838: pointer.struct.asn1_string_st */
    	em[841] = 798; em[842] = 0; 
    em[843] = 1; em[844] = 8; em[845] = 1; /* 843: pointer.struct.asn1_string_st */
    	em[846] = 798; em[847] = 0; 
    em[848] = 1; em[849] = 8; em[850] = 1; /* 848: pointer.struct.asn1_string_st */
    	em[851] = 798; em[852] = 0; 
    em[853] = 1; em[854] = 8; em[855] = 1; /* 853: pointer.struct.asn1_string_st */
    	em[856] = 798; em[857] = 0; 
    em[858] = 1; em[859] = 8; em[860] = 1; /* 858: pointer.struct.asn1_string_st */
    	em[861] = 798; em[862] = 0; 
    em[863] = 1; em[864] = 8; em[865] = 1; /* 863: pointer.struct.asn1_string_st */
    	em[866] = 798; em[867] = 0; 
    em[868] = 1; em[869] = 8; em[870] = 1; /* 868: pointer.struct.asn1_string_st */
    	em[871] = 798; em[872] = 0; 
    em[873] = 1; em[874] = 8; em[875] = 1; /* 873: pointer.struct.X509_name_st */
    	em[876] = 878; em[877] = 0; 
    em[878] = 0; em[879] = 40; em[880] = 3; /* 878: struct.X509_name_st */
    	em[881] = 887; em[882] = 0; 
    	em[883] = 911; em[884] = 16; 
    	em[885] = 107; em[886] = 24; 
    em[887] = 1; em[888] = 8; em[889] = 1; /* 887: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[890] = 892; em[891] = 0; 
    em[892] = 0; em[893] = 32; em[894] = 2; /* 892: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[895] = 899; em[896] = 8; 
    	em[897] = 217; em[898] = 24; 
    em[899] = 8884099; em[900] = 8; em[901] = 2; /* 899: pointer_to_array_of_pointers_to_stack */
    	em[902] = 906; em[903] = 0; 
    	em[904] = 214; em[905] = 20; 
    em[906] = 0; em[907] = 8; em[908] = 1; /* 906: pointer.X509_NAME_ENTRY */
    	em[909] = 337; em[910] = 0; 
    em[911] = 1; em[912] = 8; em[913] = 1; /* 911: pointer.struct.buf_mem_st */
    	em[914] = 916; em[915] = 0; 
    em[916] = 0; em[917] = 24; em[918] = 1; /* 916: struct.buf_mem_st */
    	em[919] = 92; em[920] = 8; 
    em[921] = 1; em[922] = 8; em[923] = 1; /* 921: pointer.struct.EDIPartyName_st */
    	em[924] = 926; em[925] = 0; 
    em[926] = 0; em[927] = 16; em[928] = 2; /* 926: struct.EDIPartyName_st */
    	em[929] = 793; em[930] = 0; 
    	em[931] = 793; em[932] = 8; 
    em[933] = 0; em[934] = 24; em[935] = 1; /* 933: struct.asn1_string_st */
    	em[936] = 107; em[937] = 8; 
    em[938] = 1; em[939] = 8; em[940] = 1; /* 938: pointer.struct.buf_mem_st */
    	em[941] = 943; em[942] = 0; 
    em[943] = 0; em[944] = 24; em[945] = 1; /* 943: struct.buf_mem_st */
    	em[946] = 92; em[947] = 8; 
    em[948] = 1; em[949] = 8; em[950] = 1; /* 948: pointer.struct.stack_st_GENERAL_NAME */
    	em[951] = 953; em[952] = 0; 
    em[953] = 0; em[954] = 32; em[955] = 2; /* 953: struct.stack_st_fake_GENERAL_NAME */
    	em[956] = 960; em[957] = 8; 
    	em[958] = 217; em[959] = 24; 
    em[960] = 8884099; em[961] = 8; em[962] = 2; /* 960: pointer_to_array_of_pointers_to_stack */
    	em[963] = 967; em[964] = 0; 
    	em[965] = 214; em[966] = 20; 
    em[967] = 0; em[968] = 8; em[969] = 1; /* 967: pointer.GENERAL_NAME */
    	em[970] = 671; em[971] = 0; 
    em[972] = 0; em[973] = 8; em[974] = 2; /* 972: union.unknown */
    	em[975] = 948; em[976] = 0; 
    	em[977] = 979; em[978] = 0; 
    em[979] = 1; em[980] = 8; em[981] = 1; /* 979: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[982] = 984; em[983] = 0; 
    em[984] = 0; em[985] = 32; em[986] = 2; /* 984: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[987] = 991; em[988] = 8; 
    	em[989] = 217; em[990] = 24; 
    em[991] = 8884099; em[992] = 8; em[993] = 2; /* 991: pointer_to_array_of_pointers_to_stack */
    	em[994] = 998; em[995] = 0; 
    	em[996] = 214; em[997] = 20; 
    em[998] = 0; em[999] = 8; em[1000] = 1; /* 998: pointer.X509_NAME_ENTRY */
    	em[1001] = 337; em[1002] = 0; 
    em[1003] = 0; em[1004] = 24; em[1005] = 2; /* 1003: struct.DIST_POINT_NAME_st */
    	em[1006] = 972; em[1007] = 8; 
    	em[1008] = 1010; em[1009] = 16; 
    em[1010] = 1; em[1011] = 8; em[1012] = 1; /* 1010: pointer.struct.X509_name_st */
    	em[1013] = 1015; em[1014] = 0; 
    em[1015] = 0; em[1016] = 40; em[1017] = 3; /* 1015: struct.X509_name_st */
    	em[1018] = 979; em[1019] = 0; 
    	em[1020] = 938; em[1021] = 16; 
    	em[1022] = 107; em[1023] = 24; 
    em[1024] = 1; em[1025] = 8; em[1026] = 1; /* 1024: pointer.struct.DIST_POINT_NAME_st */
    	em[1027] = 1003; em[1028] = 0; 
    em[1029] = 0; em[1030] = 0; em[1031] = 1; /* 1029: DIST_POINT */
    	em[1032] = 1034; em[1033] = 0; 
    em[1034] = 0; em[1035] = 32; em[1036] = 3; /* 1034: struct.DIST_POINT_st */
    	em[1037] = 1024; em[1038] = 0; 
    	em[1039] = 1043; em[1040] = 8; 
    	em[1041] = 948; em[1042] = 16; 
    em[1043] = 1; em[1044] = 8; em[1045] = 1; /* 1043: pointer.struct.asn1_string_st */
    	em[1046] = 933; em[1047] = 0; 
    em[1048] = 1; em[1049] = 8; em[1050] = 1; /* 1048: pointer.struct.stack_st_DIST_POINT */
    	em[1051] = 1053; em[1052] = 0; 
    em[1053] = 0; em[1054] = 32; em[1055] = 2; /* 1053: struct.stack_st_fake_DIST_POINT */
    	em[1056] = 1060; em[1057] = 8; 
    	em[1058] = 217; em[1059] = 24; 
    em[1060] = 8884099; em[1061] = 8; em[1062] = 2; /* 1060: pointer_to_array_of_pointers_to_stack */
    	em[1063] = 1067; em[1064] = 0; 
    	em[1065] = 214; em[1066] = 20; 
    em[1067] = 0; em[1068] = 8; em[1069] = 1; /* 1067: pointer.DIST_POINT */
    	em[1070] = 1029; em[1071] = 0; 
    em[1072] = 1; em[1073] = 8; em[1074] = 1; /* 1072: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1075] = 1077; em[1076] = 0; 
    em[1077] = 0; em[1078] = 32; em[1079] = 2; /* 1077: struct.stack_st_fake_ASN1_OBJECT */
    	em[1080] = 1084; em[1081] = 8; 
    	em[1082] = 217; em[1083] = 24; 
    em[1084] = 8884099; em[1085] = 8; em[1086] = 2; /* 1084: pointer_to_array_of_pointers_to_stack */
    	em[1087] = 1091; em[1088] = 0; 
    	em[1089] = 214; em[1090] = 20; 
    em[1091] = 0; em[1092] = 8; em[1093] = 1; /* 1091: pointer.ASN1_OBJECT */
    	em[1094] = 244; em[1095] = 0; 
    em[1096] = 1; em[1097] = 8; em[1098] = 1; /* 1096: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1099] = 1101; em[1100] = 0; 
    em[1101] = 0; em[1102] = 32; em[1103] = 2; /* 1101: struct.stack_st_fake_POLICYQUALINFO */
    	em[1104] = 1108; em[1105] = 8; 
    	em[1106] = 217; em[1107] = 24; 
    em[1108] = 8884099; em[1109] = 8; em[1110] = 2; /* 1108: pointer_to_array_of_pointers_to_stack */
    	em[1111] = 1115; em[1112] = 0; 
    	em[1113] = 214; em[1114] = 20; 
    em[1115] = 0; em[1116] = 8; em[1117] = 1; /* 1115: pointer.POLICYQUALINFO */
    	em[1118] = 1120; em[1119] = 0; 
    em[1120] = 0; em[1121] = 0; em[1122] = 1; /* 1120: POLICYQUALINFO */
    	em[1123] = 1125; em[1124] = 0; 
    em[1125] = 0; em[1126] = 16; em[1127] = 2; /* 1125: struct.POLICYQUALINFO_st */
    	em[1128] = 1132; em[1129] = 0; 
    	em[1130] = 1146; em[1131] = 8; 
    em[1132] = 1; em[1133] = 8; em[1134] = 1; /* 1132: pointer.struct.asn1_object_st */
    	em[1135] = 1137; em[1136] = 0; 
    em[1137] = 0; em[1138] = 40; em[1139] = 3; /* 1137: struct.asn1_object_st */
    	em[1140] = 26; em[1141] = 0; 
    	em[1142] = 26; em[1143] = 8; 
    	em[1144] = 31; em[1145] = 24; 
    em[1146] = 0; em[1147] = 8; em[1148] = 3; /* 1146: union.unknown */
    	em[1149] = 1155; em[1150] = 0; 
    	em[1151] = 1165; em[1152] = 0; 
    	em[1153] = 1223; em[1154] = 0; 
    em[1155] = 1; em[1156] = 8; em[1157] = 1; /* 1155: pointer.struct.asn1_string_st */
    	em[1158] = 1160; em[1159] = 0; 
    em[1160] = 0; em[1161] = 24; em[1162] = 1; /* 1160: struct.asn1_string_st */
    	em[1163] = 107; em[1164] = 8; 
    em[1165] = 1; em[1166] = 8; em[1167] = 1; /* 1165: pointer.struct.USERNOTICE_st */
    	em[1168] = 1170; em[1169] = 0; 
    em[1170] = 0; em[1171] = 16; em[1172] = 2; /* 1170: struct.USERNOTICE_st */
    	em[1173] = 1177; em[1174] = 0; 
    	em[1175] = 1189; em[1176] = 8; 
    em[1177] = 1; em[1178] = 8; em[1179] = 1; /* 1177: pointer.struct.NOTICEREF_st */
    	em[1180] = 1182; em[1181] = 0; 
    em[1182] = 0; em[1183] = 16; em[1184] = 2; /* 1182: struct.NOTICEREF_st */
    	em[1185] = 1189; em[1186] = 0; 
    	em[1187] = 1194; em[1188] = 8; 
    em[1189] = 1; em[1190] = 8; em[1191] = 1; /* 1189: pointer.struct.asn1_string_st */
    	em[1192] = 1160; em[1193] = 0; 
    em[1194] = 1; em[1195] = 8; em[1196] = 1; /* 1194: pointer.struct.stack_st_ASN1_INTEGER */
    	em[1197] = 1199; em[1198] = 0; 
    em[1199] = 0; em[1200] = 32; em[1201] = 2; /* 1199: struct.stack_st_fake_ASN1_INTEGER */
    	em[1202] = 1206; em[1203] = 8; 
    	em[1204] = 217; em[1205] = 24; 
    em[1206] = 8884099; em[1207] = 8; em[1208] = 2; /* 1206: pointer_to_array_of_pointers_to_stack */
    	em[1209] = 1213; em[1210] = 0; 
    	em[1211] = 214; em[1212] = 20; 
    em[1213] = 0; em[1214] = 8; em[1215] = 1; /* 1213: pointer.ASN1_INTEGER */
    	em[1216] = 1218; em[1217] = 0; 
    em[1218] = 0; em[1219] = 0; em[1220] = 1; /* 1218: ASN1_INTEGER */
    	em[1221] = 102; em[1222] = 0; 
    em[1223] = 1; em[1224] = 8; em[1225] = 1; /* 1223: pointer.struct.asn1_type_st */
    	em[1226] = 1228; em[1227] = 0; 
    em[1228] = 0; em[1229] = 16; em[1230] = 1; /* 1228: struct.asn1_type_st */
    	em[1231] = 1233; em[1232] = 8; 
    em[1233] = 0; em[1234] = 8; em[1235] = 20; /* 1233: union.unknown */
    	em[1236] = 92; em[1237] = 0; 
    	em[1238] = 1189; em[1239] = 0; 
    	em[1240] = 1132; em[1241] = 0; 
    	em[1242] = 1276; em[1243] = 0; 
    	em[1244] = 1281; em[1245] = 0; 
    	em[1246] = 1286; em[1247] = 0; 
    	em[1248] = 1291; em[1249] = 0; 
    	em[1250] = 1296; em[1251] = 0; 
    	em[1252] = 1301; em[1253] = 0; 
    	em[1254] = 1155; em[1255] = 0; 
    	em[1256] = 1306; em[1257] = 0; 
    	em[1258] = 1311; em[1259] = 0; 
    	em[1260] = 1316; em[1261] = 0; 
    	em[1262] = 1321; em[1263] = 0; 
    	em[1264] = 1326; em[1265] = 0; 
    	em[1266] = 1331; em[1267] = 0; 
    	em[1268] = 1336; em[1269] = 0; 
    	em[1270] = 1189; em[1271] = 0; 
    	em[1272] = 1189; em[1273] = 0; 
    	em[1274] = 519; em[1275] = 0; 
    em[1276] = 1; em[1277] = 8; em[1278] = 1; /* 1276: pointer.struct.asn1_string_st */
    	em[1279] = 1160; em[1280] = 0; 
    em[1281] = 1; em[1282] = 8; em[1283] = 1; /* 1281: pointer.struct.asn1_string_st */
    	em[1284] = 1160; em[1285] = 0; 
    em[1286] = 1; em[1287] = 8; em[1288] = 1; /* 1286: pointer.struct.asn1_string_st */
    	em[1289] = 1160; em[1290] = 0; 
    em[1291] = 1; em[1292] = 8; em[1293] = 1; /* 1291: pointer.struct.asn1_string_st */
    	em[1294] = 1160; em[1295] = 0; 
    em[1296] = 1; em[1297] = 8; em[1298] = 1; /* 1296: pointer.struct.asn1_string_st */
    	em[1299] = 1160; em[1300] = 0; 
    em[1301] = 1; em[1302] = 8; em[1303] = 1; /* 1301: pointer.struct.asn1_string_st */
    	em[1304] = 1160; em[1305] = 0; 
    em[1306] = 1; em[1307] = 8; em[1308] = 1; /* 1306: pointer.struct.asn1_string_st */
    	em[1309] = 1160; em[1310] = 0; 
    em[1311] = 1; em[1312] = 8; em[1313] = 1; /* 1311: pointer.struct.asn1_string_st */
    	em[1314] = 1160; em[1315] = 0; 
    em[1316] = 1; em[1317] = 8; em[1318] = 1; /* 1316: pointer.struct.asn1_string_st */
    	em[1319] = 1160; em[1320] = 0; 
    em[1321] = 1; em[1322] = 8; em[1323] = 1; /* 1321: pointer.struct.asn1_string_st */
    	em[1324] = 1160; em[1325] = 0; 
    em[1326] = 1; em[1327] = 8; em[1328] = 1; /* 1326: pointer.struct.asn1_string_st */
    	em[1329] = 1160; em[1330] = 0; 
    em[1331] = 1; em[1332] = 8; em[1333] = 1; /* 1331: pointer.struct.asn1_string_st */
    	em[1334] = 1160; em[1335] = 0; 
    em[1336] = 1; em[1337] = 8; em[1338] = 1; /* 1336: pointer.struct.asn1_string_st */
    	em[1339] = 1160; em[1340] = 0; 
    em[1341] = 0; em[1342] = 32; em[1343] = 3; /* 1341: struct.X509_POLICY_DATA_st */
    	em[1344] = 1350; em[1345] = 8; 
    	em[1346] = 1096; em[1347] = 16; 
    	em[1348] = 1072; em[1349] = 24; 
    em[1350] = 1; em[1351] = 8; em[1352] = 1; /* 1350: pointer.struct.asn1_object_st */
    	em[1353] = 1355; em[1354] = 0; 
    em[1355] = 0; em[1356] = 40; em[1357] = 3; /* 1355: struct.asn1_object_st */
    	em[1358] = 26; em[1359] = 0; 
    	em[1360] = 26; em[1361] = 8; 
    	em[1362] = 31; em[1363] = 24; 
    em[1364] = 1; em[1365] = 8; em[1366] = 1; /* 1364: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[1367] = 1369; em[1368] = 0; 
    em[1369] = 0; em[1370] = 32; em[1371] = 2; /* 1369: struct.stack_st_fake_X509_POLICY_DATA */
    	em[1372] = 1376; em[1373] = 8; 
    	em[1374] = 217; em[1375] = 24; 
    em[1376] = 8884099; em[1377] = 8; em[1378] = 2; /* 1376: pointer_to_array_of_pointers_to_stack */
    	em[1379] = 1383; em[1380] = 0; 
    	em[1381] = 214; em[1382] = 20; 
    em[1383] = 0; em[1384] = 8; em[1385] = 1; /* 1383: pointer.X509_POLICY_DATA */
    	em[1386] = 1388; em[1387] = 0; 
    em[1388] = 0; em[1389] = 0; em[1390] = 1; /* 1388: X509_POLICY_DATA */
    	em[1391] = 1341; em[1392] = 0; 
    em[1393] = 1; em[1394] = 8; em[1395] = 1; /* 1393: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1396] = 1398; em[1397] = 0; 
    em[1398] = 0; em[1399] = 32; em[1400] = 2; /* 1398: struct.stack_st_fake_ASN1_OBJECT */
    	em[1401] = 1405; em[1402] = 8; 
    	em[1403] = 217; em[1404] = 24; 
    em[1405] = 8884099; em[1406] = 8; em[1407] = 2; /* 1405: pointer_to_array_of_pointers_to_stack */
    	em[1408] = 1412; em[1409] = 0; 
    	em[1410] = 214; em[1411] = 20; 
    em[1412] = 0; em[1413] = 8; em[1414] = 1; /* 1412: pointer.ASN1_OBJECT */
    	em[1415] = 244; em[1416] = 0; 
    em[1417] = 1; em[1418] = 8; em[1419] = 1; /* 1417: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1420] = 1422; em[1421] = 0; 
    em[1422] = 0; em[1423] = 32; em[1424] = 2; /* 1422: struct.stack_st_fake_POLICYQUALINFO */
    	em[1425] = 1429; em[1426] = 8; 
    	em[1427] = 217; em[1428] = 24; 
    em[1429] = 8884099; em[1430] = 8; em[1431] = 2; /* 1429: pointer_to_array_of_pointers_to_stack */
    	em[1432] = 1436; em[1433] = 0; 
    	em[1434] = 214; em[1435] = 20; 
    em[1436] = 0; em[1437] = 8; em[1438] = 1; /* 1436: pointer.POLICYQUALINFO */
    	em[1439] = 1120; em[1440] = 0; 
    em[1441] = 0; em[1442] = 40; em[1443] = 3; /* 1441: struct.asn1_object_st */
    	em[1444] = 26; em[1445] = 0; 
    	em[1446] = 26; em[1447] = 8; 
    	em[1448] = 31; em[1449] = 24; 
    em[1450] = 0; em[1451] = 32; em[1452] = 3; /* 1450: struct.X509_POLICY_DATA_st */
    	em[1453] = 1459; em[1454] = 8; 
    	em[1455] = 1417; em[1456] = 16; 
    	em[1457] = 1393; em[1458] = 24; 
    em[1459] = 1; em[1460] = 8; em[1461] = 1; /* 1459: pointer.struct.asn1_object_st */
    	em[1462] = 1441; em[1463] = 0; 
    em[1464] = 1; em[1465] = 8; em[1466] = 1; /* 1464: pointer.struct.X509_POLICY_DATA_st */
    	em[1467] = 1450; em[1468] = 0; 
    em[1469] = 0; em[1470] = 40; em[1471] = 2; /* 1469: struct.X509_POLICY_CACHE_st */
    	em[1472] = 1464; em[1473] = 0; 
    	em[1474] = 1364; em[1475] = 8; 
    em[1476] = 1; em[1477] = 8; em[1478] = 1; /* 1476: pointer.struct.asn1_string_st */
    	em[1479] = 1481; em[1480] = 0; 
    em[1481] = 0; em[1482] = 24; em[1483] = 1; /* 1481: struct.asn1_string_st */
    	em[1484] = 107; em[1485] = 8; 
    em[1486] = 1; em[1487] = 8; em[1488] = 1; /* 1486: pointer.struct.stack_st_GENERAL_NAME */
    	em[1489] = 1491; em[1490] = 0; 
    em[1491] = 0; em[1492] = 32; em[1493] = 2; /* 1491: struct.stack_st_fake_GENERAL_NAME */
    	em[1494] = 1498; em[1495] = 8; 
    	em[1496] = 217; em[1497] = 24; 
    em[1498] = 8884099; em[1499] = 8; em[1500] = 2; /* 1498: pointer_to_array_of_pointers_to_stack */
    	em[1501] = 1505; em[1502] = 0; 
    	em[1503] = 214; em[1504] = 20; 
    em[1505] = 0; em[1506] = 8; em[1507] = 1; /* 1505: pointer.GENERAL_NAME */
    	em[1508] = 671; em[1509] = 0; 
    em[1510] = 0; em[1511] = 24; em[1512] = 1; /* 1510: struct.asn1_string_st */
    	em[1513] = 107; em[1514] = 8; 
    em[1515] = 1; em[1516] = 8; em[1517] = 1; /* 1515: pointer.struct.asn1_string_st */
    	em[1518] = 1510; em[1519] = 0; 
    em[1520] = 1; em[1521] = 8; em[1522] = 1; /* 1520: pointer.struct.stack_st_X509_EXTENSION */
    	em[1523] = 1525; em[1524] = 0; 
    em[1525] = 0; em[1526] = 32; em[1527] = 2; /* 1525: struct.stack_st_fake_X509_EXTENSION */
    	em[1528] = 1532; em[1529] = 8; 
    	em[1530] = 217; em[1531] = 24; 
    em[1532] = 8884099; em[1533] = 8; em[1534] = 2; /* 1532: pointer_to_array_of_pointers_to_stack */
    	em[1535] = 1539; em[1536] = 0; 
    	em[1537] = 214; em[1538] = 20; 
    em[1539] = 0; em[1540] = 8; em[1541] = 1; /* 1539: pointer.X509_EXTENSION */
    	em[1542] = 1544; em[1543] = 0; 
    em[1544] = 0; em[1545] = 0; em[1546] = 1; /* 1544: X509_EXTENSION */
    	em[1547] = 1549; em[1548] = 0; 
    em[1549] = 0; em[1550] = 24; em[1551] = 2; /* 1549: struct.X509_extension_st */
    	em[1552] = 1556; em[1553] = 0; 
    	em[1554] = 1515; em[1555] = 16; 
    em[1556] = 1; em[1557] = 8; em[1558] = 1; /* 1556: pointer.struct.asn1_object_st */
    	em[1559] = 1561; em[1560] = 0; 
    em[1561] = 0; em[1562] = 40; em[1563] = 3; /* 1561: struct.asn1_object_st */
    	em[1564] = 26; em[1565] = 0; 
    	em[1566] = 26; em[1567] = 8; 
    	em[1568] = 31; em[1569] = 24; 
    em[1570] = 1; em[1571] = 8; em[1572] = 1; /* 1570: pointer.struct.asn1_string_st */
    	em[1573] = 281; em[1574] = 0; 
    em[1575] = 1; em[1576] = 8; em[1577] = 1; /* 1575: pointer.struct.asn1_string_st */
    	em[1578] = 1580; em[1579] = 0; 
    em[1580] = 0; em[1581] = 24; em[1582] = 1; /* 1580: struct.asn1_string_st */
    	em[1583] = 107; em[1584] = 8; 
    em[1585] = 1; em[1586] = 8; em[1587] = 1; /* 1585: pointer.struct.asn1_string_st */
    	em[1588] = 1580; em[1589] = 0; 
    em[1590] = 1; em[1591] = 8; em[1592] = 1; /* 1590: pointer.struct.asn1_string_st */
    	em[1593] = 1580; em[1594] = 0; 
    em[1595] = 1; em[1596] = 8; em[1597] = 1; /* 1595: pointer.struct.asn1_string_st */
    	em[1598] = 1580; em[1599] = 0; 
    em[1600] = 1; em[1601] = 8; em[1602] = 1; /* 1600: pointer.struct.asn1_string_st */
    	em[1603] = 1580; em[1604] = 0; 
    em[1605] = 1; em[1606] = 8; em[1607] = 1; /* 1605: pointer.struct.asn1_string_st */
    	em[1608] = 1580; em[1609] = 0; 
    em[1610] = 1; em[1611] = 8; em[1612] = 1; /* 1610: pointer.struct.asn1_string_st */
    	em[1613] = 1580; em[1614] = 0; 
    em[1615] = 1; em[1616] = 8; em[1617] = 1; /* 1615: pointer.struct.asn1_string_st */
    	em[1618] = 1580; em[1619] = 0; 
    em[1620] = 1; em[1621] = 8; em[1622] = 1; /* 1620: pointer.struct.asn1_string_st */
    	em[1623] = 1580; em[1624] = 0; 
    em[1625] = 0; em[1626] = 8; em[1627] = 20; /* 1625: union.unknown */
    	em[1628] = 92; em[1629] = 0; 
    	em[1630] = 1668; em[1631] = 0; 
    	em[1632] = 1673; em[1633] = 0; 
    	em[1634] = 1687; em[1635] = 0; 
    	em[1636] = 1620; em[1637] = 0; 
    	em[1638] = 1692; em[1639] = 0; 
    	em[1640] = 1615; em[1641] = 0; 
    	em[1642] = 1697; em[1643] = 0; 
    	em[1644] = 1610; em[1645] = 0; 
    	em[1646] = 1605; em[1647] = 0; 
    	em[1648] = 1600; em[1649] = 0; 
    	em[1650] = 1595; em[1651] = 0; 
    	em[1652] = 1702; em[1653] = 0; 
    	em[1654] = 1590; em[1655] = 0; 
    	em[1656] = 1585; em[1657] = 0; 
    	em[1658] = 1707; em[1659] = 0; 
    	em[1660] = 1575; em[1661] = 0; 
    	em[1662] = 1668; em[1663] = 0; 
    	em[1664] = 1668; em[1665] = 0; 
    	em[1666] = 182; em[1667] = 0; 
    em[1668] = 1; em[1669] = 8; em[1670] = 1; /* 1668: pointer.struct.asn1_string_st */
    	em[1671] = 1580; em[1672] = 0; 
    em[1673] = 1; em[1674] = 8; em[1675] = 1; /* 1673: pointer.struct.asn1_object_st */
    	em[1676] = 1678; em[1677] = 0; 
    em[1678] = 0; em[1679] = 40; em[1680] = 3; /* 1678: struct.asn1_object_st */
    	em[1681] = 26; em[1682] = 0; 
    	em[1683] = 26; em[1684] = 8; 
    	em[1685] = 31; em[1686] = 24; 
    em[1687] = 1; em[1688] = 8; em[1689] = 1; /* 1687: pointer.struct.asn1_string_st */
    	em[1690] = 1580; em[1691] = 0; 
    em[1692] = 1; em[1693] = 8; em[1694] = 1; /* 1692: pointer.struct.asn1_string_st */
    	em[1695] = 1580; em[1696] = 0; 
    em[1697] = 1; em[1698] = 8; em[1699] = 1; /* 1697: pointer.struct.asn1_string_st */
    	em[1700] = 1580; em[1701] = 0; 
    em[1702] = 1; em[1703] = 8; em[1704] = 1; /* 1702: pointer.struct.asn1_string_st */
    	em[1705] = 1580; em[1706] = 0; 
    em[1707] = 1; em[1708] = 8; em[1709] = 1; /* 1707: pointer.struct.asn1_string_st */
    	em[1710] = 1580; em[1711] = 0; 
    em[1712] = 0; em[1713] = 16; em[1714] = 1; /* 1712: struct.asn1_type_st */
    	em[1715] = 1625; em[1716] = 8; 
    em[1717] = 1; em[1718] = 8; em[1719] = 1; /* 1717: pointer.struct.ASN1_VALUE_st */
    	em[1720] = 1722; em[1721] = 0; 
    em[1722] = 0; em[1723] = 0; em[1724] = 0; /* 1722: struct.ASN1_VALUE_st */
    em[1725] = 1; em[1726] = 8; em[1727] = 1; /* 1725: pointer.struct.asn1_string_st */
    	em[1728] = 1730; em[1729] = 0; 
    em[1730] = 0; em[1731] = 24; em[1732] = 1; /* 1730: struct.asn1_string_st */
    	em[1733] = 107; em[1734] = 8; 
    em[1735] = 1; em[1736] = 8; em[1737] = 1; /* 1735: pointer.struct.asn1_string_st */
    	em[1738] = 1730; em[1739] = 0; 
    em[1740] = 1; em[1741] = 8; em[1742] = 1; /* 1740: pointer.struct.asn1_string_st */
    	em[1743] = 1730; em[1744] = 0; 
    em[1745] = 1; em[1746] = 8; em[1747] = 1; /* 1745: pointer.struct.asn1_string_st */
    	em[1748] = 1730; em[1749] = 0; 
    em[1750] = 1; em[1751] = 8; em[1752] = 1; /* 1750: pointer.struct.asn1_string_st */
    	em[1753] = 1730; em[1754] = 0; 
    em[1755] = 0; em[1756] = 40; em[1757] = 3; /* 1755: struct.asn1_object_st */
    	em[1758] = 26; em[1759] = 0; 
    	em[1760] = 26; em[1761] = 8; 
    	em[1762] = 31; em[1763] = 24; 
    em[1764] = 1; em[1765] = 8; em[1766] = 1; /* 1764: pointer.struct.asn1_object_st */
    	em[1767] = 1755; em[1768] = 0; 
    em[1769] = 1; em[1770] = 8; em[1771] = 1; /* 1769: pointer.struct.asn1_string_st */
    	em[1772] = 1730; em[1773] = 0; 
    em[1774] = 1; em[1775] = 8; em[1776] = 1; /* 1774: pointer.struct.stack_st_ASN1_TYPE */
    	em[1777] = 1779; em[1778] = 0; 
    em[1779] = 0; em[1780] = 32; em[1781] = 2; /* 1779: struct.stack_st_fake_ASN1_TYPE */
    	em[1782] = 1786; em[1783] = 8; 
    	em[1784] = 217; em[1785] = 24; 
    em[1786] = 8884099; em[1787] = 8; em[1788] = 2; /* 1786: pointer_to_array_of_pointers_to_stack */
    	em[1789] = 1793; em[1790] = 0; 
    	em[1791] = 214; em[1792] = 20; 
    em[1793] = 0; em[1794] = 8; em[1795] = 1; /* 1793: pointer.ASN1_TYPE */
    	em[1796] = 1798; em[1797] = 0; 
    em[1798] = 0; em[1799] = 0; em[1800] = 1; /* 1798: ASN1_TYPE */
    	em[1801] = 1803; em[1802] = 0; 
    em[1803] = 0; em[1804] = 16; em[1805] = 1; /* 1803: struct.asn1_type_st */
    	em[1806] = 1808; em[1807] = 8; 
    em[1808] = 0; em[1809] = 8; em[1810] = 20; /* 1808: union.unknown */
    	em[1811] = 92; em[1812] = 0; 
    	em[1813] = 1769; em[1814] = 0; 
    	em[1815] = 1764; em[1816] = 0; 
    	em[1817] = 1750; em[1818] = 0; 
    	em[1819] = 1745; em[1820] = 0; 
    	em[1821] = 1851; em[1822] = 0; 
    	em[1823] = 1856; em[1824] = 0; 
    	em[1825] = 1861; em[1826] = 0; 
    	em[1827] = 1740; em[1828] = 0; 
    	em[1829] = 1735; em[1830] = 0; 
    	em[1831] = 1866; em[1832] = 0; 
    	em[1833] = 1871; em[1834] = 0; 
    	em[1835] = 1876; em[1836] = 0; 
    	em[1837] = 1881; em[1838] = 0; 
    	em[1839] = 1886; em[1840] = 0; 
    	em[1841] = 1891; em[1842] = 0; 
    	em[1843] = 1725; em[1844] = 0; 
    	em[1845] = 1769; em[1846] = 0; 
    	em[1847] = 1769; em[1848] = 0; 
    	em[1849] = 1717; em[1850] = 0; 
    em[1851] = 1; em[1852] = 8; em[1853] = 1; /* 1851: pointer.struct.asn1_string_st */
    	em[1854] = 1730; em[1855] = 0; 
    em[1856] = 1; em[1857] = 8; em[1858] = 1; /* 1856: pointer.struct.asn1_string_st */
    	em[1859] = 1730; em[1860] = 0; 
    em[1861] = 1; em[1862] = 8; em[1863] = 1; /* 1861: pointer.struct.asn1_string_st */
    	em[1864] = 1730; em[1865] = 0; 
    em[1866] = 1; em[1867] = 8; em[1868] = 1; /* 1866: pointer.struct.asn1_string_st */
    	em[1869] = 1730; em[1870] = 0; 
    em[1871] = 1; em[1872] = 8; em[1873] = 1; /* 1871: pointer.struct.asn1_string_st */
    	em[1874] = 1730; em[1875] = 0; 
    em[1876] = 1; em[1877] = 8; em[1878] = 1; /* 1876: pointer.struct.asn1_string_st */
    	em[1879] = 1730; em[1880] = 0; 
    em[1881] = 1; em[1882] = 8; em[1883] = 1; /* 1881: pointer.struct.asn1_string_st */
    	em[1884] = 1730; em[1885] = 0; 
    em[1886] = 1; em[1887] = 8; em[1888] = 1; /* 1886: pointer.struct.asn1_string_st */
    	em[1889] = 1730; em[1890] = 0; 
    em[1891] = 1; em[1892] = 8; em[1893] = 1; /* 1891: pointer.struct.asn1_string_st */
    	em[1894] = 1730; em[1895] = 0; 
    em[1896] = 0; em[1897] = 8; em[1898] = 3; /* 1896: union.unknown */
    	em[1899] = 92; em[1900] = 0; 
    	em[1901] = 1774; em[1902] = 0; 
    	em[1903] = 1905; em[1904] = 0; 
    em[1905] = 1; em[1906] = 8; em[1907] = 1; /* 1905: pointer.struct.asn1_type_st */
    	em[1908] = 1712; em[1909] = 0; 
    em[1910] = 0; em[1911] = 24; em[1912] = 2; /* 1910: struct.x509_attributes_st */
    	em[1913] = 1673; em[1914] = 0; 
    	em[1915] = 1896; em[1916] = 16; 
    em[1917] = 1; em[1918] = 8; em[1919] = 1; /* 1917: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1920] = 1922; em[1921] = 0; 
    em[1922] = 0; em[1923] = 32; em[1924] = 2; /* 1922: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1925] = 1929; em[1926] = 8; 
    	em[1927] = 217; em[1928] = 24; 
    em[1929] = 8884099; em[1930] = 8; em[1931] = 2; /* 1929: pointer_to_array_of_pointers_to_stack */
    	em[1932] = 1936; em[1933] = 0; 
    	em[1934] = 214; em[1935] = 20; 
    em[1936] = 0; em[1937] = 8; em[1938] = 1; /* 1936: pointer.X509_ATTRIBUTE */
    	em[1939] = 1941; em[1940] = 0; 
    em[1941] = 0; em[1942] = 0; em[1943] = 1; /* 1941: X509_ATTRIBUTE */
    	em[1944] = 1910; em[1945] = 0; 
    em[1946] = 0; em[1947] = 40; em[1948] = 5; /* 1946: struct.ec_extra_data_st */
    	em[1949] = 1959; em[1950] = 0; 
    	em[1951] = 1964; em[1952] = 8; 
    	em[1953] = 1967; em[1954] = 16; 
    	em[1955] = 1970; em[1956] = 24; 
    	em[1957] = 1970; em[1958] = 32; 
    em[1959] = 1; em[1960] = 8; em[1961] = 1; /* 1959: pointer.struct.ec_extra_data_st */
    	em[1962] = 1946; em[1963] = 0; 
    em[1964] = 0; em[1965] = 8; em[1966] = 0; /* 1964: pointer.void */
    em[1967] = 8884097; em[1968] = 8; em[1969] = 0; /* 1967: pointer.func */
    em[1970] = 8884097; em[1971] = 8; em[1972] = 0; /* 1970: pointer.func */
    em[1973] = 1; em[1974] = 8; em[1975] = 1; /* 1973: pointer.struct.ec_extra_data_st */
    	em[1976] = 1946; em[1977] = 0; 
    em[1978] = 0; em[1979] = 24; em[1980] = 1; /* 1978: struct.bignum_st */
    	em[1981] = 1983; em[1982] = 0; 
    em[1983] = 8884099; em[1984] = 8; em[1985] = 2; /* 1983: pointer_to_array_of_pointers_to_stack */
    	em[1986] = 1990; em[1987] = 0; 
    	em[1988] = 214; em[1989] = 12; 
    em[1990] = 0; em[1991] = 8; em[1992] = 0; /* 1990: long unsigned int */
    em[1993] = 1; em[1994] = 8; em[1995] = 1; /* 1993: pointer.struct.bignum_st */
    	em[1996] = 1978; em[1997] = 0; 
    em[1998] = 1; em[1999] = 8; em[2000] = 1; /* 1998: pointer.struct.ec_point_st */
    	em[2001] = 2003; em[2002] = 0; 
    em[2003] = 0; em[2004] = 88; em[2005] = 4; /* 2003: struct.ec_point_st */
    	em[2006] = 2014; em[2007] = 0; 
    	em[2008] = 2186; em[2009] = 8; 
    	em[2010] = 2186; em[2011] = 32; 
    	em[2012] = 2186; em[2013] = 56; 
    em[2014] = 1; em[2015] = 8; em[2016] = 1; /* 2014: pointer.struct.ec_method_st */
    	em[2017] = 2019; em[2018] = 0; 
    em[2019] = 0; em[2020] = 304; em[2021] = 37; /* 2019: struct.ec_method_st */
    	em[2022] = 2096; em[2023] = 8; 
    	em[2024] = 2099; em[2025] = 16; 
    	em[2026] = 2099; em[2027] = 24; 
    	em[2028] = 2102; em[2029] = 32; 
    	em[2030] = 2105; em[2031] = 40; 
    	em[2032] = 2108; em[2033] = 48; 
    	em[2034] = 2111; em[2035] = 56; 
    	em[2036] = 2114; em[2037] = 64; 
    	em[2038] = 2117; em[2039] = 72; 
    	em[2040] = 2120; em[2041] = 80; 
    	em[2042] = 2120; em[2043] = 88; 
    	em[2044] = 2123; em[2045] = 96; 
    	em[2046] = 2126; em[2047] = 104; 
    	em[2048] = 2129; em[2049] = 112; 
    	em[2050] = 2132; em[2051] = 120; 
    	em[2052] = 2135; em[2053] = 128; 
    	em[2054] = 2138; em[2055] = 136; 
    	em[2056] = 2141; em[2057] = 144; 
    	em[2058] = 2144; em[2059] = 152; 
    	em[2060] = 2147; em[2061] = 160; 
    	em[2062] = 2150; em[2063] = 168; 
    	em[2064] = 2153; em[2065] = 176; 
    	em[2066] = 2156; em[2067] = 184; 
    	em[2068] = 2159; em[2069] = 192; 
    	em[2070] = 2162; em[2071] = 200; 
    	em[2072] = 2165; em[2073] = 208; 
    	em[2074] = 2156; em[2075] = 216; 
    	em[2076] = 2168; em[2077] = 224; 
    	em[2078] = 2171; em[2079] = 232; 
    	em[2080] = 2174; em[2081] = 240; 
    	em[2082] = 2111; em[2083] = 248; 
    	em[2084] = 2177; em[2085] = 256; 
    	em[2086] = 2180; em[2087] = 264; 
    	em[2088] = 2177; em[2089] = 272; 
    	em[2090] = 2180; em[2091] = 280; 
    	em[2092] = 2180; em[2093] = 288; 
    	em[2094] = 2183; em[2095] = 296; 
    em[2096] = 8884097; em[2097] = 8; em[2098] = 0; /* 2096: pointer.func */
    em[2099] = 8884097; em[2100] = 8; em[2101] = 0; /* 2099: pointer.func */
    em[2102] = 8884097; em[2103] = 8; em[2104] = 0; /* 2102: pointer.func */
    em[2105] = 8884097; em[2106] = 8; em[2107] = 0; /* 2105: pointer.func */
    em[2108] = 8884097; em[2109] = 8; em[2110] = 0; /* 2108: pointer.func */
    em[2111] = 8884097; em[2112] = 8; em[2113] = 0; /* 2111: pointer.func */
    em[2114] = 8884097; em[2115] = 8; em[2116] = 0; /* 2114: pointer.func */
    em[2117] = 8884097; em[2118] = 8; em[2119] = 0; /* 2117: pointer.func */
    em[2120] = 8884097; em[2121] = 8; em[2122] = 0; /* 2120: pointer.func */
    em[2123] = 8884097; em[2124] = 8; em[2125] = 0; /* 2123: pointer.func */
    em[2126] = 8884097; em[2127] = 8; em[2128] = 0; /* 2126: pointer.func */
    em[2129] = 8884097; em[2130] = 8; em[2131] = 0; /* 2129: pointer.func */
    em[2132] = 8884097; em[2133] = 8; em[2134] = 0; /* 2132: pointer.func */
    em[2135] = 8884097; em[2136] = 8; em[2137] = 0; /* 2135: pointer.func */
    em[2138] = 8884097; em[2139] = 8; em[2140] = 0; /* 2138: pointer.func */
    em[2141] = 8884097; em[2142] = 8; em[2143] = 0; /* 2141: pointer.func */
    em[2144] = 8884097; em[2145] = 8; em[2146] = 0; /* 2144: pointer.func */
    em[2147] = 8884097; em[2148] = 8; em[2149] = 0; /* 2147: pointer.func */
    em[2150] = 8884097; em[2151] = 8; em[2152] = 0; /* 2150: pointer.func */
    em[2153] = 8884097; em[2154] = 8; em[2155] = 0; /* 2153: pointer.func */
    em[2156] = 8884097; em[2157] = 8; em[2158] = 0; /* 2156: pointer.func */
    em[2159] = 8884097; em[2160] = 8; em[2161] = 0; /* 2159: pointer.func */
    em[2162] = 8884097; em[2163] = 8; em[2164] = 0; /* 2162: pointer.func */
    em[2165] = 8884097; em[2166] = 8; em[2167] = 0; /* 2165: pointer.func */
    em[2168] = 8884097; em[2169] = 8; em[2170] = 0; /* 2168: pointer.func */
    em[2171] = 8884097; em[2172] = 8; em[2173] = 0; /* 2171: pointer.func */
    em[2174] = 8884097; em[2175] = 8; em[2176] = 0; /* 2174: pointer.func */
    em[2177] = 8884097; em[2178] = 8; em[2179] = 0; /* 2177: pointer.func */
    em[2180] = 8884097; em[2181] = 8; em[2182] = 0; /* 2180: pointer.func */
    em[2183] = 8884097; em[2184] = 8; em[2185] = 0; /* 2183: pointer.func */
    em[2186] = 0; em[2187] = 24; em[2188] = 1; /* 2186: struct.bignum_st */
    	em[2189] = 2191; em[2190] = 0; 
    em[2191] = 8884099; em[2192] = 8; em[2193] = 2; /* 2191: pointer_to_array_of_pointers_to_stack */
    	em[2194] = 1990; em[2195] = 0; 
    	em[2196] = 214; em[2197] = 12; 
    em[2198] = 8884097; em[2199] = 8; em[2200] = 0; /* 2198: pointer.func */
    em[2201] = 1; em[2202] = 8; em[2203] = 1; /* 2201: pointer.struct.ec_extra_data_st */
    	em[2204] = 2206; em[2205] = 0; 
    em[2206] = 0; em[2207] = 40; em[2208] = 5; /* 2206: struct.ec_extra_data_st */
    	em[2209] = 2201; em[2210] = 0; 
    	em[2211] = 1964; em[2212] = 8; 
    	em[2213] = 1967; em[2214] = 16; 
    	em[2215] = 1970; em[2216] = 24; 
    	em[2217] = 1970; em[2218] = 32; 
    em[2219] = 1; em[2220] = 8; em[2221] = 1; /* 2219: pointer.struct.ec_extra_data_st */
    	em[2222] = 2206; em[2223] = 0; 
    em[2224] = 8884097; em[2225] = 8; em[2226] = 0; /* 2224: pointer.func */
    em[2227] = 8884097; em[2228] = 8; em[2229] = 0; /* 2227: pointer.func */
    em[2230] = 8884097; em[2231] = 8; em[2232] = 0; /* 2230: pointer.func */
    em[2233] = 8884097; em[2234] = 8; em[2235] = 0; /* 2233: pointer.func */
    em[2236] = 1; em[2237] = 8; em[2238] = 1; /* 2236: pointer.struct.X509_val_st */
    	em[2239] = 2241; em[2240] = 0; 
    em[2241] = 0; em[2242] = 16; em[2243] = 2; /* 2241: struct.X509_val_st */
    	em[2244] = 2248; em[2245] = 0; 
    	em[2246] = 2248; em[2247] = 8; 
    em[2248] = 1; em[2249] = 8; em[2250] = 1; /* 2248: pointer.struct.asn1_string_st */
    	em[2251] = 281; em[2252] = 0; 
    em[2253] = 8884097; em[2254] = 8; em[2255] = 0; /* 2253: pointer.func */
    em[2256] = 8884097; em[2257] = 8; em[2258] = 0; /* 2256: pointer.func */
    em[2259] = 0; em[2260] = 16; em[2261] = 1; /* 2259: struct.crypto_threadid_st */
    	em[2262] = 1964; em[2263] = 0; 
    em[2264] = 8884097; em[2265] = 8; em[2266] = 0; /* 2264: pointer.func */
    em[2267] = 1; em[2268] = 8; em[2269] = 1; /* 2267: pointer.struct.dh_method */
    	em[2270] = 2272; em[2271] = 0; 
    em[2272] = 0; em[2273] = 72; em[2274] = 8; /* 2272: struct.dh_method */
    	em[2275] = 26; em[2276] = 0; 
    	em[2277] = 2291; em[2278] = 8; 
    	em[2279] = 2294; em[2280] = 16; 
    	em[2281] = 2297; em[2282] = 24; 
    	em[2283] = 2291; em[2284] = 32; 
    	em[2285] = 2291; em[2286] = 40; 
    	em[2287] = 92; em[2288] = 56; 
    	em[2289] = 2300; em[2290] = 64; 
    em[2291] = 8884097; em[2292] = 8; em[2293] = 0; /* 2291: pointer.func */
    em[2294] = 8884097; em[2295] = 8; em[2296] = 0; /* 2294: pointer.func */
    em[2297] = 8884097; em[2298] = 8; em[2299] = 0; /* 2297: pointer.func */
    em[2300] = 8884097; em[2301] = 8; em[2302] = 0; /* 2300: pointer.func */
    em[2303] = 8884097; em[2304] = 8; em[2305] = 0; /* 2303: pointer.func */
    em[2306] = 8884097; em[2307] = 8; em[2308] = 0; /* 2306: pointer.func */
    em[2309] = 0; em[2310] = 48; em[2311] = 6; /* 2309: struct.rand_meth_st */
    	em[2312] = 2324; em[2313] = 0; 
    	em[2314] = 2327; em[2315] = 8; 
    	em[2316] = 2330; em[2317] = 16; 
    	em[2318] = 2233; em[2319] = 24; 
    	em[2320] = 2327; em[2321] = 32; 
    	em[2322] = 2227; em[2323] = 40; 
    em[2324] = 8884097; em[2325] = 8; em[2326] = 0; /* 2324: pointer.func */
    em[2327] = 8884097; em[2328] = 8; em[2329] = 0; /* 2327: pointer.func */
    em[2330] = 8884097; em[2331] = 8; em[2332] = 0; /* 2330: pointer.func */
    em[2333] = 1; em[2334] = 8; em[2335] = 1; /* 2333: pointer.struct.engine_st */
    	em[2336] = 2338; em[2337] = 0; 
    em[2338] = 0; em[2339] = 216; em[2340] = 24; /* 2338: struct.engine_st */
    	em[2341] = 26; em[2342] = 0; 
    	em[2343] = 26; em[2344] = 8; 
    	em[2345] = 2389; em[2346] = 16; 
    	em[2347] = 2441; em[2348] = 24; 
    	em[2349] = 2267; em[2350] = 32; 
    	em[2351] = 2489; em[2352] = 40; 
    	em[2353] = 2506; em[2354] = 48; 
    	em[2355] = 2527; em[2356] = 56; 
    	em[2357] = 2532; em[2358] = 64; 
    	em[2359] = 2224; em[2360] = 72; 
    	em[2361] = 2540; em[2362] = 80; 
    	em[2363] = 2543; em[2364] = 88; 
    	em[2365] = 2546; em[2366] = 96; 
    	em[2367] = 2549; em[2368] = 104; 
    	em[2369] = 2549; em[2370] = 112; 
    	em[2371] = 2549; em[2372] = 120; 
    	em[2373] = 2552; em[2374] = 128; 
    	em[2375] = 2555; em[2376] = 136; 
    	em[2377] = 2555; em[2378] = 144; 
    	em[2379] = 2558; em[2380] = 152; 
    	em[2381] = 2561; em[2382] = 160; 
    	em[2383] = 2573; em[2384] = 184; 
    	em[2385] = 2587; em[2386] = 200; 
    	em[2387] = 2587; em[2388] = 208; 
    em[2389] = 1; em[2390] = 8; em[2391] = 1; /* 2389: pointer.struct.rsa_meth_st */
    	em[2392] = 2394; em[2393] = 0; 
    em[2394] = 0; em[2395] = 112; em[2396] = 13; /* 2394: struct.rsa_meth_st */
    	em[2397] = 26; em[2398] = 0; 
    	em[2399] = 2423; em[2400] = 8; 
    	em[2401] = 2423; em[2402] = 16; 
    	em[2403] = 2423; em[2404] = 24; 
    	em[2405] = 2423; em[2406] = 32; 
    	em[2407] = 2426; em[2408] = 40; 
    	em[2409] = 2429; em[2410] = 48; 
    	em[2411] = 2303; em[2412] = 56; 
    	em[2413] = 2303; em[2414] = 64; 
    	em[2415] = 92; em[2416] = 80; 
    	em[2417] = 2432; em[2418] = 88; 
    	em[2419] = 2435; em[2420] = 96; 
    	em[2421] = 2438; em[2422] = 104; 
    em[2423] = 8884097; em[2424] = 8; em[2425] = 0; /* 2423: pointer.func */
    em[2426] = 8884097; em[2427] = 8; em[2428] = 0; /* 2426: pointer.func */
    em[2429] = 8884097; em[2430] = 8; em[2431] = 0; /* 2429: pointer.func */
    em[2432] = 8884097; em[2433] = 8; em[2434] = 0; /* 2432: pointer.func */
    em[2435] = 8884097; em[2436] = 8; em[2437] = 0; /* 2435: pointer.func */
    em[2438] = 8884097; em[2439] = 8; em[2440] = 0; /* 2438: pointer.func */
    em[2441] = 1; em[2442] = 8; em[2443] = 1; /* 2441: pointer.struct.dsa_method */
    	em[2444] = 2446; em[2445] = 0; 
    em[2446] = 0; em[2447] = 96; em[2448] = 11; /* 2446: struct.dsa_method */
    	em[2449] = 26; em[2450] = 0; 
    	em[2451] = 2471; em[2452] = 8; 
    	em[2453] = 2474; em[2454] = 16; 
    	em[2455] = 2477; em[2456] = 24; 
    	em[2457] = 2480; em[2458] = 32; 
    	em[2459] = 2264; em[2460] = 40; 
    	em[2461] = 2483; em[2462] = 48; 
    	em[2463] = 2483; em[2464] = 56; 
    	em[2465] = 92; em[2466] = 72; 
    	em[2467] = 2486; em[2468] = 80; 
    	em[2469] = 2483; em[2470] = 88; 
    em[2471] = 8884097; em[2472] = 8; em[2473] = 0; /* 2471: pointer.func */
    em[2474] = 8884097; em[2475] = 8; em[2476] = 0; /* 2474: pointer.func */
    em[2477] = 8884097; em[2478] = 8; em[2479] = 0; /* 2477: pointer.func */
    em[2480] = 8884097; em[2481] = 8; em[2482] = 0; /* 2480: pointer.func */
    em[2483] = 8884097; em[2484] = 8; em[2485] = 0; /* 2483: pointer.func */
    em[2486] = 8884097; em[2487] = 8; em[2488] = 0; /* 2486: pointer.func */
    em[2489] = 1; em[2490] = 8; em[2491] = 1; /* 2489: pointer.struct.ecdh_method */
    	em[2492] = 2494; em[2493] = 0; 
    em[2494] = 0; em[2495] = 32; em[2496] = 3; /* 2494: struct.ecdh_method */
    	em[2497] = 26; em[2498] = 0; 
    	em[2499] = 2503; em[2500] = 8; 
    	em[2501] = 92; em[2502] = 24; 
    em[2503] = 8884097; em[2504] = 8; em[2505] = 0; /* 2503: pointer.func */
    em[2506] = 1; em[2507] = 8; em[2508] = 1; /* 2506: pointer.struct.ecdsa_method */
    	em[2509] = 2511; em[2510] = 0; 
    em[2511] = 0; em[2512] = 48; em[2513] = 5; /* 2511: struct.ecdsa_method */
    	em[2514] = 26; em[2515] = 0; 
    	em[2516] = 2256; em[2517] = 8; 
    	em[2518] = 2253; em[2519] = 16; 
    	em[2520] = 2524; em[2521] = 24; 
    	em[2522] = 92; em[2523] = 40; 
    em[2524] = 8884097; em[2525] = 8; em[2526] = 0; /* 2524: pointer.func */
    em[2527] = 1; em[2528] = 8; em[2529] = 1; /* 2527: pointer.struct.rand_meth_st */
    	em[2530] = 2309; em[2531] = 0; 
    em[2532] = 1; em[2533] = 8; em[2534] = 1; /* 2532: pointer.struct.store_method_st */
    	em[2535] = 2537; em[2536] = 0; 
    em[2537] = 0; em[2538] = 0; em[2539] = 0; /* 2537: struct.store_method_st */
    em[2540] = 8884097; em[2541] = 8; em[2542] = 0; /* 2540: pointer.func */
    em[2543] = 8884097; em[2544] = 8; em[2545] = 0; /* 2543: pointer.func */
    em[2546] = 8884097; em[2547] = 8; em[2548] = 0; /* 2546: pointer.func */
    em[2549] = 8884097; em[2550] = 8; em[2551] = 0; /* 2549: pointer.func */
    em[2552] = 8884097; em[2553] = 8; em[2554] = 0; /* 2552: pointer.func */
    em[2555] = 8884097; em[2556] = 8; em[2557] = 0; /* 2555: pointer.func */
    em[2558] = 8884097; em[2559] = 8; em[2560] = 0; /* 2558: pointer.func */
    em[2561] = 1; em[2562] = 8; em[2563] = 1; /* 2561: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[2564] = 2566; em[2565] = 0; 
    em[2566] = 0; em[2567] = 32; em[2568] = 2; /* 2566: struct.ENGINE_CMD_DEFN_st */
    	em[2569] = 26; em[2570] = 8; 
    	em[2571] = 26; em[2572] = 16; 
    em[2573] = 0; em[2574] = 32; em[2575] = 2; /* 2573: struct.crypto_ex_data_st_fake */
    	em[2576] = 2580; em[2577] = 8; 
    	em[2578] = 217; em[2579] = 24; 
    em[2580] = 8884099; em[2581] = 8; em[2582] = 2; /* 2580: pointer_to_array_of_pointers_to_stack */
    	em[2583] = 1964; em[2584] = 0; 
    	em[2585] = 214; em[2586] = 20; 
    em[2587] = 1; em[2588] = 8; em[2589] = 1; /* 2587: pointer.struct.engine_st */
    	em[2590] = 2338; em[2591] = 0; 
    em[2592] = 8884097; em[2593] = 8; em[2594] = 0; /* 2592: pointer.func */
    em[2595] = 8884097; em[2596] = 8; em[2597] = 0; /* 2595: pointer.func */
    em[2598] = 8884097; em[2599] = 8; em[2600] = 0; /* 2598: pointer.func */
    em[2601] = 1; em[2602] = 8; em[2603] = 1; /* 2601: pointer.struct.ec_method_st */
    	em[2604] = 2606; em[2605] = 0; 
    em[2606] = 0; em[2607] = 304; em[2608] = 37; /* 2606: struct.ec_method_st */
    	em[2609] = 2683; em[2610] = 8; 
    	em[2611] = 2686; em[2612] = 16; 
    	em[2613] = 2686; em[2614] = 24; 
    	em[2615] = 2689; em[2616] = 32; 
    	em[2617] = 2692; em[2618] = 40; 
    	em[2619] = 2695; em[2620] = 48; 
    	em[2621] = 2698; em[2622] = 56; 
    	em[2623] = 2701; em[2624] = 64; 
    	em[2625] = 2704; em[2626] = 72; 
    	em[2627] = 2707; em[2628] = 80; 
    	em[2629] = 2707; em[2630] = 88; 
    	em[2631] = 2710; em[2632] = 96; 
    	em[2633] = 2713; em[2634] = 104; 
    	em[2635] = 2716; em[2636] = 112; 
    	em[2637] = 2719; em[2638] = 120; 
    	em[2639] = 2230; em[2640] = 128; 
    	em[2641] = 2722; em[2642] = 136; 
    	em[2643] = 2725; em[2644] = 144; 
    	em[2645] = 2728; em[2646] = 152; 
    	em[2647] = 2731; em[2648] = 160; 
    	em[2649] = 2734; em[2650] = 168; 
    	em[2651] = 2737; em[2652] = 176; 
    	em[2653] = 2740; em[2654] = 184; 
    	em[2655] = 2743; em[2656] = 192; 
    	em[2657] = 2746; em[2658] = 200; 
    	em[2659] = 2749; em[2660] = 208; 
    	em[2661] = 2740; em[2662] = 216; 
    	em[2663] = 2752; em[2664] = 224; 
    	em[2665] = 2755; em[2666] = 232; 
    	em[2667] = 2758; em[2668] = 240; 
    	em[2669] = 2698; em[2670] = 248; 
    	em[2671] = 2761; em[2672] = 256; 
    	em[2673] = 2764; em[2674] = 264; 
    	em[2675] = 2761; em[2676] = 272; 
    	em[2677] = 2764; em[2678] = 280; 
    	em[2679] = 2764; em[2680] = 288; 
    	em[2681] = 2767; em[2682] = 296; 
    em[2683] = 8884097; em[2684] = 8; em[2685] = 0; /* 2683: pointer.func */
    em[2686] = 8884097; em[2687] = 8; em[2688] = 0; /* 2686: pointer.func */
    em[2689] = 8884097; em[2690] = 8; em[2691] = 0; /* 2689: pointer.func */
    em[2692] = 8884097; em[2693] = 8; em[2694] = 0; /* 2692: pointer.func */
    em[2695] = 8884097; em[2696] = 8; em[2697] = 0; /* 2695: pointer.func */
    em[2698] = 8884097; em[2699] = 8; em[2700] = 0; /* 2698: pointer.func */
    em[2701] = 8884097; em[2702] = 8; em[2703] = 0; /* 2701: pointer.func */
    em[2704] = 8884097; em[2705] = 8; em[2706] = 0; /* 2704: pointer.func */
    em[2707] = 8884097; em[2708] = 8; em[2709] = 0; /* 2707: pointer.func */
    em[2710] = 8884097; em[2711] = 8; em[2712] = 0; /* 2710: pointer.func */
    em[2713] = 8884097; em[2714] = 8; em[2715] = 0; /* 2713: pointer.func */
    em[2716] = 8884097; em[2717] = 8; em[2718] = 0; /* 2716: pointer.func */
    em[2719] = 8884097; em[2720] = 8; em[2721] = 0; /* 2719: pointer.func */
    em[2722] = 8884097; em[2723] = 8; em[2724] = 0; /* 2722: pointer.func */
    em[2725] = 8884097; em[2726] = 8; em[2727] = 0; /* 2725: pointer.func */
    em[2728] = 8884097; em[2729] = 8; em[2730] = 0; /* 2728: pointer.func */
    em[2731] = 8884097; em[2732] = 8; em[2733] = 0; /* 2731: pointer.func */
    em[2734] = 8884097; em[2735] = 8; em[2736] = 0; /* 2734: pointer.func */
    em[2737] = 8884097; em[2738] = 8; em[2739] = 0; /* 2737: pointer.func */
    em[2740] = 8884097; em[2741] = 8; em[2742] = 0; /* 2740: pointer.func */
    em[2743] = 8884097; em[2744] = 8; em[2745] = 0; /* 2743: pointer.func */
    em[2746] = 8884097; em[2747] = 8; em[2748] = 0; /* 2746: pointer.func */
    em[2749] = 8884097; em[2750] = 8; em[2751] = 0; /* 2749: pointer.func */
    em[2752] = 8884097; em[2753] = 8; em[2754] = 0; /* 2752: pointer.func */
    em[2755] = 8884097; em[2756] = 8; em[2757] = 0; /* 2755: pointer.func */
    em[2758] = 8884097; em[2759] = 8; em[2760] = 0; /* 2758: pointer.func */
    em[2761] = 8884097; em[2762] = 8; em[2763] = 0; /* 2761: pointer.func */
    em[2764] = 8884097; em[2765] = 8; em[2766] = 0; /* 2764: pointer.func */
    em[2767] = 8884097; em[2768] = 8; em[2769] = 0; /* 2767: pointer.func */
    em[2770] = 1; em[2771] = 8; em[2772] = 1; /* 2770: pointer.struct.asn1_string_st */
    	em[2773] = 1481; em[2774] = 0; 
    em[2775] = 8884097; em[2776] = 8; em[2777] = 0; /* 2775: pointer.func */
    em[2778] = 8884097; em[2779] = 8; em[2780] = 0; /* 2778: pointer.func */
    em[2781] = 8884097; em[2782] = 8; em[2783] = 0; /* 2781: pointer.func */
    em[2784] = 8884097; em[2785] = 8; em[2786] = 0; /* 2784: pointer.func */
    em[2787] = 1; em[2788] = 8; em[2789] = 1; /* 2787: pointer.struct.dh_method */
    	em[2790] = 2792; em[2791] = 0; 
    em[2792] = 0; em[2793] = 72; em[2794] = 8; /* 2792: struct.dh_method */
    	em[2795] = 26; em[2796] = 0; 
    	em[2797] = 2811; em[2798] = 8; 
    	em[2799] = 2814; em[2800] = 16; 
    	em[2801] = 2778; em[2802] = 24; 
    	em[2803] = 2811; em[2804] = 32; 
    	em[2805] = 2811; em[2806] = 40; 
    	em[2807] = 92; em[2808] = 56; 
    	em[2809] = 2817; em[2810] = 64; 
    em[2811] = 8884097; em[2812] = 8; em[2813] = 0; /* 2811: pointer.func */
    em[2814] = 8884097; em[2815] = 8; em[2816] = 0; /* 2814: pointer.func */
    em[2817] = 8884097; em[2818] = 8; em[2819] = 0; /* 2817: pointer.func */
    em[2820] = 8884097; em[2821] = 8; em[2822] = 0; /* 2820: pointer.func */
    em[2823] = 8884097; em[2824] = 8; em[2825] = 0; /* 2823: pointer.func */
    em[2826] = 8884097; em[2827] = 8; em[2828] = 0; /* 2826: pointer.func */
    em[2829] = 0; em[2830] = 208; em[2831] = 24; /* 2829: struct.evp_pkey_asn1_method_st */
    	em[2832] = 92; em[2833] = 16; 
    	em[2834] = 92; em[2835] = 24; 
    	em[2836] = 2595; em[2837] = 32; 
    	em[2838] = 2826; em[2839] = 40; 
    	em[2840] = 2880; em[2841] = 48; 
    	em[2842] = 2883; em[2843] = 56; 
    	em[2844] = 2886; em[2845] = 64; 
    	em[2846] = 2306; em[2847] = 72; 
    	em[2848] = 2883; em[2849] = 80; 
    	em[2850] = 2889; em[2851] = 88; 
    	em[2852] = 2889; em[2853] = 96; 
    	em[2854] = 2820; em[2855] = 104; 
    	em[2856] = 2823; em[2857] = 112; 
    	em[2858] = 2889; em[2859] = 120; 
    	em[2860] = 2892; em[2861] = 128; 
    	em[2862] = 2880; em[2863] = 136; 
    	em[2864] = 2883; em[2865] = 144; 
    	em[2866] = 2784; em[2867] = 152; 
    	em[2868] = 2895; em[2869] = 160; 
    	em[2870] = 2898; em[2871] = 168; 
    	em[2872] = 2820; em[2873] = 176; 
    	em[2874] = 2823; em[2875] = 184; 
    	em[2876] = 2781; em[2877] = 192; 
    	em[2878] = 2775; em[2879] = 200; 
    em[2880] = 8884097; em[2881] = 8; em[2882] = 0; /* 2880: pointer.func */
    em[2883] = 8884097; em[2884] = 8; em[2885] = 0; /* 2883: pointer.func */
    em[2886] = 8884097; em[2887] = 8; em[2888] = 0; /* 2886: pointer.func */
    em[2889] = 8884097; em[2890] = 8; em[2891] = 0; /* 2889: pointer.func */
    em[2892] = 8884097; em[2893] = 8; em[2894] = 0; /* 2892: pointer.func */
    em[2895] = 8884097; em[2896] = 8; em[2897] = 0; /* 2895: pointer.func */
    em[2898] = 8884097; em[2899] = 8; em[2900] = 0; /* 2898: pointer.func */
    em[2901] = 1; em[2902] = 8; em[2903] = 1; /* 2901: pointer.struct.evp_pkey_asn1_method_st */
    	em[2904] = 2829; em[2905] = 0; 
    em[2906] = 0; em[2907] = 56; em[2908] = 4; /* 2906: struct.evp_pkey_st */
    	em[2909] = 2901; em[2910] = 16; 
    	em[2911] = 2917; em[2912] = 24; 
    	em[2913] = 2922; em[2914] = 32; 
    	em[2915] = 1917; em[2916] = 48; 
    em[2917] = 1; em[2918] = 8; em[2919] = 1; /* 2917: pointer.struct.engine_st */
    	em[2920] = 2338; em[2921] = 0; 
    em[2922] = 0; em[2923] = 8; em[2924] = 5; /* 2922: union.unknown */
    	em[2925] = 92; em[2926] = 0; 
    	em[2927] = 2935; em[2928] = 0; 
    	em[2929] = 3132; em[2930] = 0; 
    	em[2931] = 3263; em[2932] = 0; 
    	em[2933] = 3340; em[2934] = 0; 
    em[2935] = 1; em[2936] = 8; em[2937] = 1; /* 2935: pointer.struct.rsa_st */
    	em[2938] = 2940; em[2939] = 0; 
    em[2940] = 0; em[2941] = 168; em[2942] = 17; /* 2940: struct.rsa_st */
    	em[2943] = 2977; em[2944] = 16; 
    	em[2945] = 3026; em[2946] = 24; 
    	em[2947] = 3031; em[2948] = 32; 
    	em[2949] = 3031; em[2950] = 40; 
    	em[2951] = 3031; em[2952] = 48; 
    	em[2953] = 3031; em[2954] = 56; 
    	em[2955] = 3031; em[2956] = 64; 
    	em[2957] = 3031; em[2958] = 72; 
    	em[2959] = 3031; em[2960] = 80; 
    	em[2961] = 3031; em[2962] = 88; 
    	em[2963] = 3048; em[2964] = 96; 
    	em[2965] = 3062; em[2966] = 120; 
    	em[2967] = 3062; em[2968] = 128; 
    	em[2969] = 3062; em[2970] = 136; 
    	em[2971] = 92; em[2972] = 144; 
    	em[2973] = 3076; em[2974] = 152; 
    	em[2975] = 3076; em[2976] = 160; 
    em[2977] = 1; em[2978] = 8; em[2979] = 1; /* 2977: pointer.struct.rsa_meth_st */
    	em[2980] = 2982; em[2981] = 0; 
    em[2982] = 0; em[2983] = 112; em[2984] = 13; /* 2982: struct.rsa_meth_st */
    	em[2985] = 26; em[2986] = 0; 
    	em[2987] = 3011; em[2988] = 8; 
    	em[2989] = 3011; em[2990] = 16; 
    	em[2991] = 3011; em[2992] = 24; 
    	em[2993] = 3011; em[2994] = 32; 
    	em[2995] = 3014; em[2996] = 40; 
    	em[2997] = 2592; em[2998] = 48; 
    	em[2999] = 3017; em[3000] = 56; 
    	em[3001] = 3017; em[3002] = 64; 
    	em[3003] = 92; em[3004] = 80; 
    	em[3005] = 3020; em[3006] = 88; 
    	em[3007] = 2598; em[3008] = 96; 
    	em[3009] = 3023; em[3010] = 104; 
    em[3011] = 8884097; em[3012] = 8; em[3013] = 0; /* 3011: pointer.func */
    em[3014] = 8884097; em[3015] = 8; em[3016] = 0; /* 3014: pointer.func */
    em[3017] = 8884097; em[3018] = 8; em[3019] = 0; /* 3017: pointer.func */
    em[3020] = 8884097; em[3021] = 8; em[3022] = 0; /* 3020: pointer.func */
    em[3023] = 8884097; em[3024] = 8; em[3025] = 0; /* 3023: pointer.func */
    em[3026] = 1; em[3027] = 8; em[3028] = 1; /* 3026: pointer.struct.engine_st */
    	em[3029] = 2338; em[3030] = 0; 
    em[3031] = 1; em[3032] = 8; em[3033] = 1; /* 3031: pointer.struct.bignum_st */
    	em[3034] = 3036; em[3035] = 0; 
    em[3036] = 0; em[3037] = 24; em[3038] = 1; /* 3036: struct.bignum_st */
    	em[3039] = 3041; em[3040] = 0; 
    em[3041] = 8884099; em[3042] = 8; em[3043] = 2; /* 3041: pointer_to_array_of_pointers_to_stack */
    	em[3044] = 1990; em[3045] = 0; 
    	em[3046] = 214; em[3047] = 12; 
    em[3048] = 0; em[3049] = 32; em[3050] = 2; /* 3048: struct.crypto_ex_data_st_fake */
    	em[3051] = 3055; em[3052] = 8; 
    	em[3053] = 217; em[3054] = 24; 
    em[3055] = 8884099; em[3056] = 8; em[3057] = 2; /* 3055: pointer_to_array_of_pointers_to_stack */
    	em[3058] = 1964; em[3059] = 0; 
    	em[3060] = 214; em[3061] = 20; 
    em[3062] = 1; em[3063] = 8; em[3064] = 1; /* 3062: pointer.struct.bn_mont_ctx_st */
    	em[3065] = 3067; em[3066] = 0; 
    em[3067] = 0; em[3068] = 96; em[3069] = 3; /* 3067: struct.bn_mont_ctx_st */
    	em[3070] = 3036; em[3071] = 8; 
    	em[3072] = 3036; em[3073] = 32; 
    	em[3074] = 3036; em[3075] = 56; 
    em[3076] = 1; em[3077] = 8; em[3078] = 1; /* 3076: pointer.struct.bn_blinding_st */
    	em[3079] = 3081; em[3080] = 0; 
    em[3081] = 0; em[3082] = 88; em[3083] = 7; /* 3081: struct.bn_blinding_st */
    	em[3084] = 3098; em[3085] = 0; 
    	em[3086] = 3098; em[3087] = 8; 
    	em[3088] = 3098; em[3089] = 16; 
    	em[3090] = 3098; em[3091] = 24; 
    	em[3092] = 2259; em[3093] = 40; 
    	em[3094] = 3115; em[3095] = 72; 
    	em[3096] = 3129; em[3097] = 80; 
    em[3098] = 1; em[3099] = 8; em[3100] = 1; /* 3098: pointer.struct.bignum_st */
    	em[3101] = 3103; em[3102] = 0; 
    em[3103] = 0; em[3104] = 24; em[3105] = 1; /* 3103: struct.bignum_st */
    	em[3106] = 3108; em[3107] = 0; 
    em[3108] = 8884099; em[3109] = 8; em[3110] = 2; /* 3108: pointer_to_array_of_pointers_to_stack */
    	em[3111] = 1990; em[3112] = 0; 
    	em[3113] = 214; em[3114] = 12; 
    em[3115] = 1; em[3116] = 8; em[3117] = 1; /* 3115: pointer.struct.bn_mont_ctx_st */
    	em[3118] = 3120; em[3119] = 0; 
    em[3120] = 0; em[3121] = 96; em[3122] = 3; /* 3120: struct.bn_mont_ctx_st */
    	em[3123] = 3103; em[3124] = 8; 
    	em[3125] = 3103; em[3126] = 32; 
    	em[3127] = 3103; em[3128] = 56; 
    em[3129] = 8884097; em[3130] = 8; em[3131] = 0; /* 3129: pointer.func */
    em[3132] = 1; em[3133] = 8; em[3134] = 1; /* 3132: pointer.struct.dsa_st */
    	em[3135] = 3137; em[3136] = 0; 
    em[3137] = 0; em[3138] = 136; em[3139] = 11; /* 3137: struct.dsa_st */
    	em[3140] = 3162; em[3141] = 24; 
    	em[3142] = 3162; em[3143] = 32; 
    	em[3144] = 3162; em[3145] = 40; 
    	em[3146] = 3162; em[3147] = 48; 
    	em[3148] = 3162; em[3149] = 56; 
    	em[3150] = 3162; em[3151] = 64; 
    	em[3152] = 3162; em[3153] = 72; 
    	em[3154] = 3179; em[3155] = 88; 
    	em[3156] = 3193; em[3157] = 104; 
    	em[3158] = 3207; em[3159] = 120; 
    	em[3160] = 3258; em[3161] = 128; 
    em[3162] = 1; em[3163] = 8; em[3164] = 1; /* 3162: pointer.struct.bignum_st */
    	em[3165] = 3167; em[3166] = 0; 
    em[3167] = 0; em[3168] = 24; em[3169] = 1; /* 3167: struct.bignum_st */
    	em[3170] = 3172; em[3171] = 0; 
    em[3172] = 8884099; em[3173] = 8; em[3174] = 2; /* 3172: pointer_to_array_of_pointers_to_stack */
    	em[3175] = 1990; em[3176] = 0; 
    	em[3177] = 214; em[3178] = 12; 
    em[3179] = 1; em[3180] = 8; em[3181] = 1; /* 3179: pointer.struct.bn_mont_ctx_st */
    	em[3182] = 3184; em[3183] = 0; 
    em[3184] = 0; em[3185] = 96; em[3186] = 3; /* 3184: struct.bn_mont_ctx_st */
    	em[3187] = 3167; em[3188] = 8; 
    	em[3189] = 3167; em[3190] = 32; 
    	em[3191] = 3167; em[3192] = 56; 
    em[3193] = 0; em[3194] = 32; em[3195] = 2; /* 3193: struct.crypto_ex_data_st_fake */
    	em[3196] = 3200; em[3197] = 8; 
    	em[3198] = 217; em[3199] = 24; 
    em[3200] = 8884099; em[3201] = 8; em[3202] = 2; /* 3200: pointer_to_array_of_pointers_to_stack */
    	em[3203] = 1964; em[3204] = 0; 
    	em[3205] = 214; em[3206] = 20; 
    em[3207] = 1; em[3208] = 8; em[3209] = 1; /* 3207: pointer.struct.dsa_method */
    	em[3210] = 3212; em[3211] = 0; 
    em[3212] = 0; em[3213] = 96; em[3214] = 11; /* 3212: struct.dsa_method */
    	em[3215] = 26; em[3216] = 0; 
    	em[3217] = 3237; em[3218] = 8; 
    	em[3219] = 3240; em[3220] = 16; 
    	em[3221] = 3243; em[3222] = 24; 
    	em[3223] = 3246; em[3224] = 32; 
    	em[3225] = 3249; em[3226] = 40; 
    	em[3227] = 3252; em[3228] = 48; 
    	em[3229] = 3252; em[3230] = 56; 
    	em[3231] = 92; em[3232] = 72; 
    	em[3233] = 3255; em[3234] = 80; 
    	em[3235] = 3252; em[3236] = 88; 
    em[3237] = 8884097; em[3238] = 8; em[3239] = 0; /* 3237: pointer.func */
    em[3240] = 8884097; em[3241] = 8; em[3242] = 0; /* 3240: pointer.func */
    em[3243] = 8884097; em[3244] = 8; em[3245] = 0; /* 3243: pointer.func */
    em[3246] = 8884097; em[3247] = 8; em[3248] = 0; /* 3246: pointer.func */
    em[3249] = 8884097; em[3250] = 8; em[3251] = 0; /* 3249: pointer.func */
    em[3252] = 8884097; em[3253] = 8; em[3254] = 0; /* 3252: pointer.func */
    em[3255] = 8884097; em[3256] = 8; em[3257] = 0; /* 3255: pointer.func */
    em[3258] = 1; em[3259] = 8; em[3260] = 1; /* 3258: pointer.struct.engine_st */
    	em[3261] = 2338; em[3262] = 0; 
    em[3263] = 1; em[3264] = 8; em[3265] = 1; /* 3263: pointer.struct.dh_st */
    	em[3266] = 3268; em[3267] = 0; 
    em[3268] = 0; em[3269] = 144; em[3270] = 12; /* 3268: struct.dh_st */
    	em[3271] = 3295; em[3272] = 8; 
    	em[3273] = 3295; em[3274] = 16; 
    	em[3275] = 3295; em[3276] = 32; 
    	em[3277] = 3295; em[3278] = 40; 
    	em[3279] = 3312; em[3280] = 56; 
    	em[3281] = 3295; em[3282] = 64; 
    	em[3283] = 3295; em[3284] = 72; 
    	em[3285] = 107; em[3286] = 80; 
    	em[3287] = 3295; em[3288] = 96; 
    	em[3289] = 3326; em[3290] = 112; 
    	em[3291] = 2787; em[3292] = 128; 
    	em[3293] = 2333; em[3294] = 136; 
    em[3295] = 1; em[3296] = 8; em[3297] = 1; /* 3295: pointer.struct.bignum_st */
    	em[3298] = 3300; em[3299] = 0; 
    em[3300] = 0; em[3301] = 24; em[3302] = 1; /* 3300: struct.bignum_st */
    	em[3303] = 3305; em[3304] = 0; 
    em[3305] = 8884099; em[3306] = 8; em[3307] = 2; /* 3305: pointer_to_array_of_pointers_to_stack */
    	em[3308] = 1990; em[3309] = 0; 
    	em[3310] = 214; em[3311] = 12; 
    em[3312] = 1; em[3313] = 8; em[3314] = 1; /* 3312: pointer.struct.bn_mont_ctx_st */
    	em[3315] = 3317; em[3316] = 0; 
    em[3317] = 0; em[3318] = 96; em[3319] = 3; /* 3317: struct.bn_mont_ctx_st */
    	em[3320] = 3300; em[3321] = 8; 
    	em[3322] = 3300; em[3323] = 32; 
    	em[3324] = 3300; em[3325] = 56; 
    em[3326] = 0; em[3327] = 32; em[3328] = 2; /* 3326: struct.crypto_ex_data_st_fake */
    	em[3329] = 3333; em[3330] = 8; 
    	em[3331] = 217; em[3332] = 24; 
    em[3333] = 8884099; em[3334] = 8; em[3335] = 2; /* 3333: pointer_to_array_of_pointers_to_stack */
    	em[3336] = 1964; em[3337] = 0; 
    	em[3338] = 214; em[3339] = 20; 
    em[3340] = 1; em[3341] = 8; em[3342] = 1; /* 3340: pointer.struct.ec_key_st */
    	em[3343] = 3345; em[3344] = 0; 
    em[3345] = 0; em[3346] = 56; em[3347] = 4; /* 3345: struct.ec_key_st */
    	em[3348] = 3356; em[3349] = 8; 
    	em[3350] = 1998; em[3351] = 16; 
    	em[3352] = 1993; em[3353] = 24; 
    	em[3354] = 1973; em[3355] = 48; 
    em[3356] = 1; em[3357] = 8; em[3358] = 1; /* 3356: pointer.struct.ec_group_st */
    	em[3359] = 3361; em[3360] = 0; 
    em[3361] = 0; em[3362] = 232; em[3363] = 12; /* 3361: struct.ec_group_st */
    	em[3364] = 2601; em[3365] = 0; 
    	em[3366] = 3388; em[3367] = 8; 
    	em[3368] = 3393; em[3369] = 16; 
    	em[3370] = 3393; em[3371] = 40; 
    	em[3372] = 107; em[3373] = 80; 
    	em[3374] = 2219; em[3375] = 96; 
    	em[3376] = 3393; em[3377] = 104; 
    	em[3378] = 3393; em[3379] = 152; 
    	em[3380] = 3393; em[3381] = 176; 
    	em[3382] = 1964; em[3383] = 208; 
    	em[3384] = 1964; em[3385] = 216; 
    	em[3386] = 2198; em[3387] = 224; 
    em[3388] = 1; em[3389] = 8; em[3390] = 1; /* 3388: pointer.struct.ec_point_st */
    	em[3391] = 2003; em[3392] = 0; 
    em[3393] = 0; em[3394] = 24; em[3395] = 1; /* 3393: struct.bignum_st */
    	em[3396] = 3398; em[3397] = 0; 
    em[3398] = 8884099; em[3399] = 8; em[3400] = 2; /* 3398: pointer_to_array_of_pointers_to_stack */
    	em[3401] = 1990; em[3402] = 0; 
    	em[3403] = 214; em[3404] = 12; 
    em[3405] = 1; em[3406] = 8; em[3407] = 1; /* 3405: pointer.struct.evp_pkey_st */
    	em[3408] = 2906; em[3409] = 0; 
    em[3410] = 0; em[3411] = 24; em[3412] = 1; /* 3410: struct.asn1_string_st */
    	em[3413] = 107; em[3414] = 8; 
    em[3415] = 1; em[3416] = 8; em[3417] = 1; /* 3415: pointer.struct.X509_algor_st */
    	em[3418] = 5; em[3419] = 0; 
    em[3420] = 1; em[3421] = 8; em[3422] = 1; /* 3420: pointer.int */
    	em[3423] = 214; em[3424] = 0; 
    em[3425] = 0; em[3426] = 184; em[3427] = 12; /* 3425: struct.x509_st */
    	em[3428] = 3452; em[3429] = 0; 
    	em[3430] = 3487; em[3431] = 8; 
    	em[3432] = 1570; em[3433] = 16; 
    	em[3434] = 92; em[3435] = 32; 
    	em[3436] = 3564; em[3437] = 40; 
    	em[3438] = 286; em[3439] = 104; 
    	em[3440] = 3578; em[3441] = 112; 
    	em[3442] = 3592; em[3443] = 120; 
    	em[3444] = 1048; em[3445] = 128; 
    	em[3446] = 647; em[3447] = 136; 
    	em[3448] = 597; em[3449] = 144; 
    	em[3450] = 258; em[3451] = 176; 
    em[3452] = 1; em[3453] = 8; em[3454] = 1; /* 3452: pointer.struct.x509_cinf_st */
    	em[3455] = 3457; em[3456] = 0; 
    em[3457] = 0; em[3458] = 104; em[3459] = 11; /* 3457: struct.x509_cinf_st */
    	em[3460] = 3482; em[3461] = 0; 
    	em[3462] = 3482; em[3463] = 8; 
    	em[3464] = 3487; em[3465] = 16; 
    	em[3466] = 3492; em[3467] = 24; 
    	em[3468] = 2236; em[3469] = 32; 
    	em[3470] = 3492; em[3471] = 40; 
    	em[3472] = 3540; em[3473] = 48; 
    	em[3474] = 1570; em[3475] = 56; 
    	em[3476] = 1570; em[3477] = 64; 
    	em[3478] = 1520; em[3479] = 72; 
    	em[3480] = 3559; em[3481] = 80; 
    em[3482] = 1; em[3483] = 8; em[3484] = 1; /* 3482: pointer.struct.asn1_string_st */
    	em[3485] = 281; em[3486] = 0; 
    em[3487] = 1; em[3488] = 8; em[3489] = 1; /* 3487: pointer.struct.X509_algor_st */
    	em[3490] = 5; em[3491] = 0; 
    em[3492] = 1; em[3493] = 8; em[3494] = 1; /* 3492: pointer.struct.X509_name_st */
    	em[3495] = 3497; em[3496] = 0; 
    em[3497] = 0; em[3498] = 40; em[3499] = 3; /* 3497: struct.X509_name_st */
    	em[3500] = 3506; em[3501] = 0; 
    	em[3502] = 3530; em[3503] = 16; 
    	em[3504] = 107; em[3505] = 24; 
    em[3506] = 1; em[3507] = 8; em[3508] = 1; /* 3506: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3509] = 3511; em[3510] = 0; 
    em[3511] = 0; em[3512] = 32; em[3513] = 2; /* 3511: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3514] = 3518; em[3515] = 8; 
    	em[3516] = 217; em[3517] = 24; 
    em[3518] = 8884099; em[3519] = 8; em[3520] = 2; /* 3518: pointer_to_array_of_pointers_to_stack */
    	em[3521] = 3525; em[3522] = 0; 
    	em[3523] = 214; em[3524] = 20; 
    em[3525] = 0; em[3526] = 8; em[3527] = 1; /* 3525: pointer.X509_NAME_ENTRY */
    	em[3528] = 337; em[3529] = 0; 
    em[3530] = 1; em[3531] = 8; em[3532] = 1; /* 3530: pointer.struct.buf_mem_st */
    	em[3533] = 3535; em[3534] = 0; 
    em[3535] = 0; em[3536] = 24; em[3537] = 1; /* 3535: struct.buf_mem_st */
    	em[3538] = 92; em[3539] = 8; 
    em[3540] = 1; em[3541] = 8; em[3542] = 1; /* 3540: pointer.struct.X509_pubkey_st */
    	em[3543] = 3545; em[3544] = 0; 
    em[3545] = 0; em[3546] = 24; em[3547] = 3; /* 3545: struct.X509_pubkey_st */
    	em[3548] = 3415; em[3549] = 0; 
    	em[3550] = 3554; em[3551] = 8; 
    	em[3552] = 3405; em[3553] = 16; 
    em[3554] = 1; em[3555] = 8; em[3556] = 1; /* 3554: pointer.struct.asn1_string_st */
    	em[3557] = 3410; em[3558] = 0; 
    em[3559] = 0; em[3560] = 24; em[3561] = 1; /* 3559: struct.ASN1_ENCODING_st */
    	em[3562] = 107; em[3563] = 0; 
    em[3564] = 0; em[3565] = 32; em[3566] = 2; /* 3564: struct.crypto_ex_data_st_fake */
    	em[3567] = 3571; em[3568] = 8; 
    	em[3569] = 217; em[3570] = 24; 
    em[3571] = 8884099; em[3572] = 8; em[3573] = 2; /* 3571: pointer_to_array_of_pointers_to_stack */
    	em[3574] = 1964; em[3575] = 0; 
    	em[3576] = 214; em[3577] = 20; 
    em[3578] = 1; em[3579] = 8; em[3580] = 1; /* 3578: pointer.struct.AUTHORITY_KEYID_st */
    	em[3581] = 3583; em[3582] = 0; 
    em[3583] = 0; em[3584] = 24; em[3585] = 3; /* 3583: struct.AUTHORITY_KEYID_st */
    	em[3586] = 2770; em[3587] = 0; 
    	em[3588] = 1486; em[3589] = 8; 
    	em[3590] = 1476; em[3591] = 16; 
    em[3592] = 1; em[3593] = 8; em[3594] = 1; /* 3592: pointer.struct.X509_POLICY_CACHE_st */
    	em[3595] = 1469; em[3596] = 0; 
    em[3597] = 0; em[3598] = 1; em[3599] = 0; /* 3597: char */
    em[3600] = 1; em[3601] = 8; em[3602] = 1; /* 3600: pointer.struct.x509_st */
    	em[3603] = 3425; em[3604] = 0; 
    args_addr->arg_entity_index[0] = 3600;
    args_addr->arg_entity_index[1] = 214;
    args_addr->arg_entity_index[2] = 3420;
    args_addr->arg_entity_index[3] = 3420;
    args_addr->ret_entity_index = 1964;
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

