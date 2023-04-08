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
    em[190] = 1; em[191] = 8; em[192] = 1; /* 190: pointer.struct.x509_cert_aux_st */
    	em[193] = 195; em[194] = 0; 
    em[195] = 0; em[196] = 40; em[197] = 5; /* 195: struct.x509_cert_aux_st */
    	em[198] = 208; em[199] = 0; 
    	em[200] = 208; em[201] = 8; 
    	em[202] = 252; em[203] = 16; 
    	em[204] = 262; em[205] = 24; 
    	em[206] = 267; em[207] = 32; 
    em[208] = 1; em[209] = 8; em[210] = 1; /* 208: pointer.struct.stack_st_ASN1_OBJECT */
    	em[211] = 213; em[212] = 0; 
    em[213] = 0; em[214] = 32; em[215] = 2; /* 213: struct.stack_st_fake_ASN1_OBJECT */
    	em[216] = 220; em[217] = 8; 
    	em[218] = 249; em[219] = 24; 
    em[220] = 8884099; em[221] = 8; em[222] = 2; /* 220: pointer_to_array_of_pointers_to_stack */
    	em[223] = 227; em[224] = 0; 
    	em[225] = 246; em[226] = 20; 
    em[227] = 0; em[228] = 8; em[229] = 1; /* 227: pointer.ASN1_OBJECT */
    	em[230] = 232; em[231] = 0; 
    em[232] = 0; em[233] = 0; em[234] = 1; /* 232: ASN1_OBJECT */
    	em[235] = 237; em[236] = 0; 
    em[237] = 0; em[238] = 40; em[239] = 3; /* 237: struct.asn1_object_st */
    	em[240] = 26; em[241] = 0; 
    	em[242] = 26; em[243] = 8; 
    	em[244] = 31; em[245] = 24; 
    em[246] = 0; em[247] = 4; em[248] = 0; /* 246: int */
    em[249] = 8884097; em[250] = 8; em[251] = 0; /* 249: pointer.func */
    em[252] = 1; em[253] = 8; em[254] = 1; /* 252: pointer.struct.asn1_string_st */
    	em[255] = 257; em[256] = 0; 
    em[257] = 0; em[258] = 24; em[259] = 1; /* 257: struct.asn1_string_st */
    	em[260] = 107; em[261] = 8; 
    em[262] = 1; em[263] = 8; em[264] = 1; /* 262: pointer.struct.asn1_string_st */
    	em[265] = 257; em[266] = 0; 
    em[267] = 1; em[268] = 8; em[269] = 1; /* 267: pointer.struct.stack_st_X509_ALGOR */
    	em[270] = 272; em[271] = 0; 
    em[272] = 0; em[273] = 32; em[274] = 2; /* 272: struct.stack_st_fake_X509_ALGOR */
    	em[275] = 279; em[276] = 8; 
    	em[277] = 249; em[278] = 24; 
    em[279] = 8884099; em[280] = 8; em[281] = 2; /* 279: pointer_to_array_of_pointers_to_stack */
    	em[282] = 286; em[283] = 0; 
    	em[284] = 246; em[285] = 20; 
    em[286] = 0; em[287] = 8; em[288] = 1; /* 286: pointer.X509_ALGOR */
    	em[289] = 0; em[290] = 0; 
    em[291] = 0; em[292] = 16; em[293] = 2; /* 291: struct.EDIPartyName_st */
    	em[294] = 298; em[295] = 0; 
    	em[296] = 298; em[297] = 8; 
    em[298] = 1; em[299] = 8; em[300] = 1; /* 298: pointer.struct.asn1_string_st */
    	em[301] = 303; em[302] = 0; 
    em[303] = 0; em[304] = 24; em[305] = 1; /* 303: struct.asn1_string_st */
    	em[306] = 107; em[307] = 8; 
    em[308] = 1; em[309] = 8; em[310] = 1; /* 308: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[311] = 313; em[312] = 0; 
    em[313] = 0; em[314] = 32; em[315] = 2; /* 313: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[316] = 320; em[317] = 8; 
    	em[318] = 249; em[319] = 24; 
    em[320] = 8884099; em[321] = 8; em[322] = 2; /* 320: pointer_to_array_of_pointers_to_stack */
    	em[323] = 327; em[324] = 0; 
    	em[325] = 246; em[326] = 20; 
    em[327] = 0; em[328] = 8; em[329] = 1; /* 327: pointer.X509_NAME_ENTRY */
    	em[330] = 332; em[331] = 0; 
    em[332] = 0; em[333] = 0; em[334] = 1; /* 332: X509_NAME_ENTRY */
    	em[335] = 337; em[336] = 0; 
    em[337] = 0; em[338] = 24; em[339] = 2; /* 337: struct.X509_name_entry_st */
    	em[340] = 344; em[341] = 0; 
    	em[342] = 358; em[343] = 8; 
    em[344] = 1; em[345] = 8; em[346] = 1; /* 344: pointer.struct.asn1_object_st */
    	em[347] = 349; em[348] = 0; 
    em[349] = 0; em[350] = 40; em[351] = 3; /* 349: struct.asn1_object_st */
    	em[352] = 26; em[353] = 0; 
    	em[354] = 26; em[355] = 8; 
    	em[356] = 31; em[357] = 24; 
    em[358] = 1; em[359] = 8; em[360] = 1; /* 358: pointer.struct.asn1_string_st */
    	em[361] = 363; em[362] = 0; 
    em[363] = 0; em[364] = 24; em[365] = 1; /* 363: struct.asn1_string_st */
    	em[366] = 107; em[367] = 8; 
    em[368] = 1; em[369] = 8; em[370] = 1; /* 368: pointer.struct.X509_name_st */
    	em[371] = 373; em[372] = 0; 
    em[373] = 0; em[374] = 40; em[375] = 3; /* 373: struct.X509_name_st */
    	em[376] = 308; em[377] = 0; 
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
    em[417] = 0; em[418] = 16; em[419] = 1; /* 417: struct.asn1_type_st */
    	em[420] = 422; em[421] = 8; 
    em[422] = 0; em[423] = 8; em[424] = 20; /* 422: union.unknown */
    	em[425] = 92; em[426] = 0; 
    	em[427] = 298; em[428] = 0; 
    	em[429] = 465; em[430] = 0; 
    	em[431] = 479; em[432] = 0; 
    	em[433] = 484; em[434] = 0; 
    	em[435] = 489; em[436] = 0; 
    	em[437] = 412; em[438] = 0; 
    	em[439] = 494; em[440] = 0; 
    	em[441] = 407; em[442] = 0; 
    	em[443] = 499; em[444] = 0; 
    	em[445] = 402; em[446] = 0; 
    	em[447] = 397; em[448] = 0; 
    	em[449] = 504; em[450] = 0; 
    	em[451] = 509; em[452] = 0; 
    	em[453] = 392; em[454] = 0; 
    	em[455] = 514; em[456] = 0; 
    	em[457] = 519; em[458] = 0; 
    	em[459] = 298; em[460] = 0; 
    	em[461] = 298; em[462] = 0; 
    	em[463] = 524; em[464] = 0; 
    em[465] = 1; em[466] = 8; em[467] = 1; /* 465: pointer.struct.asn1_object_st */
    	em[468] = 470; em[469] = 0; 
    em[470] = 0; em[471] = 40; em[472] = 3; /* 470: struct.asn1_object_st */
    	em[473] = 26; em[474] = 0; 
    	em[475] = 26; em[476] = 8; 
    	em[477] = 31; em[478] = 24; 
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
    em[519] = 1; em[520] = 8; em[521] = 1; /* 519: pointer.struct.asn1_string_st */
    	em[522] = 303; em[523] = 0; 
    em[524] = 1; em[525] = 8; em[526] = 1; /* 524: pointer.struct.ASN1_VALUE_st */
    	em[527] = 529; em[528] = 0; 
    em[529] = 0; em[530] = 0; em[531] = 0; /* 529: struct.ASN1_VALUE_st */
    em[532] = 0; em[533] = 16; em[534] = 2; /* 532: struct.otherName_st */
    	em[535] = 465; em[536] = 0; 
    	em[537] = 539; em[538] = 8; 
    em[539] = 1; em[540] = 8; em[541] = 1; /* 539: pointer.struct.asn1_type_st */
    	em[542] = 417; em[543] = 0; 
    em[544] = 0; em[545] = 16; em[546] = 1; /* 544: struct.GENERAL_NAME_st */
    	em[547] = 549; em[548] = 8; 
    em[549] = 0; em[550] = 8; em[551] = 15; /* 549: union.unknown */
    	em[552] = 92; em[553] = 0; 
    	em[554] = 582; em[555] = 0; 
    	em[556] = 499; em[557] = 0; 
    	em[558] = 499; em[559] = 0; 
    	em[560] = 539; em[561] = 0; 
    	em[562] = 368; em[563] = 0; 
    	em[564] = 587; em[565] = 0; 
    	em[566] = 499; em[567] = 0; 
    	em[568] = 412; em[569] = 0; 
    	em[570] = 465; em[571] = 0; 
    	em[572] = 412; em[573] = 0; 
    	em[574] = 368; em[575] = 0; 
    	em[576] = 499; em[577] = 0; 
    	em[578] = 465; em[579] = 0; 
    	em[580] = 539; em[581] = 0; 
    em[582] = 1; em[583] = 8; em[584] = 1; /* 582: pointer.struct.otherName_st */
    	em[585] = 532; em[586] = 0; 
    em[587] = 1; em[588] = 8; em[589] = 1; /* 587: pointer.struct.EDIPartyName_st */
    	em[590] = 291; em[591] = 0; 
    em[592] = 1; em[593] = 8; em[594] = 1; /* 592: pointer.struct.GENERAL_NAME_st */
    	em[595] = 544; em[596] = 0; 
    em[597] = 0; em[598] = 0; em[599] = 1; /* 597: GENERAL_SUBTREE */
    	em[600] = 602; em[601] = 0; 
    em[602] = 0; em[603] = 24; em[604] = 3; /* 602: struct.GENERAL_SUBTREE_st */
    	em[605] = 592; em[606] = 0; 
    	em[607] = 479; em[608] = 8; 
    	em[609] = 479; em[610] = 16; 
    em[611] = 1; em[612] = 8; em[613] = 1; /* 611: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[614] = 616; em[615] = 0; 
    em[616] = 0; em[617] = 32; em[618] = 2; /* 616: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[619] = 623; em[620] = 8; 
    	em[621] = 249; em[622] = 24; 
    em[623] = 8884099; em[624] = 8; em[625] = 2; /* 623: pointer_to_array_of_pointers_to_stack */
    	em[626] = 630; em[627] = 0; 
    	em[628] = 246; em[629] = 20; 
    em[630] = 0; em[631] = 8; em[632] = 1; /* 630: pointer.GENERAL_SUBTREE */
    	em[633] = 597; em[634] = 0; 
    em[635] = 0; em[636] = 16; em[637] = 2; /* 635: struct.NAME_CONSTRAINTS_st */
    	em[638] = 611; em[639] = 0; 
    	em[640] = 611; em[641] = 8; 
    em[642] = 1; em[643] = 8; em[644] = 1; /* 642: pointer.struct.NAME_CONSTRAINTS_st */
    	em[645] = 635; em[646] = 0; 
    em[647] = 1; em[648] = 8; em[649] = 1; /* 647: pointer.struct.stack_st_GENERAL_NAME */
    	em[650] = 652; em[651] = 0; 
    em[652] = 0; em[653] = 32; em[654] = 2; /* 652: struct.stack_st_fake_GENERAL_NAME */
    	em[655] = 659; em[656] = 8; 
    	em[657] = 249; em[658] = 24; 
    em[659] = 8884099; em[660] = 8; em[661] = 2; /* 659: pointer_to_array_of_pointers_to_stack */
    	em[662] = 666; em[663] = 0; 
    	em[664] = 246; em[665] = 20; 
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
    	em[694] = 881; em[695] = 0; 
    	em[696] = 929; em[697] = 0; 
    	em[698] = 833; em[699] = 0; 
    	em[700] = 818; em[701] = 0; 
    	em[702] = 726; em[703] = 0; 
    	em[704] = 818; em[705] = 0; 
    	em[706] = 881; em[707] = 0; 
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
    	em[791] = 873; em[792] = 0; 
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
    em[873] = 1; em[874] = 8; em[875] = 1; /* 873: pointer.struct.ASN1_VALUE_st */
    	em[876] = 878; em[877] = 0; 
    em[878] = 0; em[879] = 0; em[880] = 0; /* 878: struct.ASN1_VALUE_st */
    em[881] = 1; em[882] = 8; em[883] = 1; /* 881: pointer.struct.X509_name_st */
    	em[884] = 886; em[885] = 0; 
    em[886] = 0; em[887] = 40; em[888] = 3; /* 886: struct.X509_name_st */
    	em[889] = 895; em[890] = 0; 
    	em[891] = 919; em[892] = 16; 
    	em[893] = 107; em[894] = 24; 
    em[895] = 1; em[896] = 8; em[897] = 1; /* 895: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[898] = 900; em[899] = 0; 
    em[900] = 0; em[901] = 32; em[902] = 2; /* 900: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[903] = 907; em[904] = 8; 
    	em[905] = 249; em[906] = 24; 
    em[907] = 8884099; em[908] = 8; em[909] = 2; /* 907: pointer_to_array_of_pointers_to_stack */
    	em[910] = 914; em[911] = 0; 
    	em[912] = 246; em[913] = 20; 
    em[914] = 0; em[915] = 8; em[916] = 1; /* 914: pointer.X509_NAME_ENTRY */
    	em[917] = 332; em[918] = 0; 
    em[919] = 1; em[920] = 8; em[921] = 1; /* 919: pointer.struct.buf_mem_st */
    	em[922] = 924; em[923] = 0; 
    em[924] = 0; em[925] = 24; em[926] = 1; /* 924: struct.buf_mem_st */
    	em[927] = 92; em[928] = 8; 
    em[929] = 1; em[930] = 8; em[931] = 1; /* 929: pointer.struct.EDIPartyName_st */
    	em[932] = 934; em[933] = 0; 
    em[934] = 0; em[935] = 16; em[936] = 2; /* 934: struct.EDIPartyName_st */
    	em[937] = 793; em[938] = 0; 
    	em[939] = 793; em[940] = 8; 
    em[941] = 0; em[942] = 24; em[943] = 1; /* 941: struct.asn1_string_st */
    	em[944] = 107; em[945] = 8; 
    em[946] = 1; em[947] = 8; em[948] = 1; /* 946: pointer.struct.buf_mem_st */
    	em[949] = 951; em[950] = 0; 
    em[951] = 0; em[952] = 24; em[953] = 1; /* 951: struct.buf_mem_st */
    	em[954] = 92; em[955] = 8; 
    em[956] = 0; em[957] = 40; em[958] = 3; /* 956: struct.X509_name_st */
    	em[959] = 965; em[960] = 0; 
    	em[961] = 946; em[962] = 16; 
    	em[963] = 107; em[964] = 24; 
    em[965] = 1; em[966] = 8; em[967] = 1; /* 965: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[968] = 970; em[969] = 0; 
    em[970] = 0; em[971] = 32; em[972] = 2; /* 970: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[973] = 977; em[974] = 8; 
    	em[975] = 249; em[976] = 24; 
    em[977] = 8884099; em[978] = 8; em[979] = 2; /* 977: pointer_to_array_of_pointers_to_stack */
    	em[980] = 984; em[981] = 0; 
    	em[982] = 246; em[983] = 20; 
    em[984] = 0; em[985] = 8; em[986] = 1; /* 984: pointer.X509_NAME_ENTRY */
    	em[987] = 332; em[988] = 0; 
    em[989] = 1; em[990] = 8; em[991] = 1; /* 989: pointer.struct.DIST_POINT_NAME_st */
    	em[992] = 994; em[993] = 0; 
    em[994] = 0; em[995] = 24; em[996] = 2; /* 994: struct.DIST_POINT_NAME_st */
    	em[997] = 1001; em[998] = 8; 
    	em[999] = 1032; em[1000] = 16; 
    em[1001] = 0; em[1002] = 8; em[1003] = 2; /* 1001: union.unknown */
    	em[1004] = 1008; em[1005] = 0; 
    	em[1006] = 965; em[1007] = 0; 
    em[1008] = 1; em[1009] = 8; em[1010] = 1; /* 1008: pointer.struct.stack_st_GENERAL_NAME */
    	em[1011] = 1013; em[1012] = 0; 
    em[1013] = 0; em[1014] = 32; em[1015] = 2; /* 1013: struct.stack_st_fake_GENERAL_NAME */
    	em[1016] = 1020; em[1017] = 8; 
    	em[1018] = 249; em[1019] = 24; 
    em[1020] = 8884099; em[1021] = 8; em[1022] = 2; /* 1020: pointer_to_array_of_pointers_to_stack */
    	em[1023] = 1027; em[1024] = 0; 
    	em[1025] = 246; em[1026] = 20; 
    em[1027] = 0; em[1028] = 8; em[1029] = 1; /* 1027: pointer.GENERAL_NAME */
    	em[1030] = 671; em[1031] = 0; 
    em[1032] = 1; em[1033] = 8; em[1034] = 1; /* 1032: pointer.struct.X509_name_st */
    	em[1035] = 956; em[1036] = 0; 
    em[1037] = 1; em[1038] = 8; em[1039] = 1; /* 1037: pointer.struct.stack_st_DIST_POINT */
    	em[1040] = 1042; em[1041] = 0; 
    em[1042] = 0; em[1043] = 32; em[1044] = 2; /* 1042: struct.stack_st_fake_DIST_POINT */
    	em[1045] = 1049; em[1046] = 8; 
    	em[1047] = 249; em[1048] = 24; 
    em[1049] = 8884099; em[1050] = 8; em[1051] = 2; /* 1049: pointer_to_array_of_pointers_to_stack */
    	em[1052] = 1056; em[1053] = 0; 
    	em[1054] = 246; em[1055] = 20; 
    em[1056] = 0; em[1057] = 8; em[1058] = 1; /* 1056: pointer.DIST_POINT */
    	em[1059] = 1061; em[1060] = 0; 
    em[1061] = 0; em[1062] = 0; em[1063] = 1; /* 1061: DIST_POINT */
    	em[1064] = 1066; em[1065] = 0; 
    em[1066] = 0; em[1067] = 32; em[1068] = 3; /* 1066: struct.DIST_POINT_st */
    	em[1069] = 989; em[1070] = 0; 
    	em[1071] = 1075; em[1072] = 8; 
    	em[1073] = 1008; em[1074] = 16; 
    em[1075] = 1; em[1076] = 8; em[1077] = 1; /* 1075: pointer.struct.asn1_string_st */
    	em[1078] = 941; em[1079] = 0; 
    em[1080] = 0; em[1081] = 40; em[1082] = 3; /* 1080: struct.asn1_object_st */
    	em[1083] = 26; em[1084] = 0; 
    	em[1085] = 26; em[1086] = 8; 
    	em[1087] = 31; em[1088] = 24; 
    em[1089] = 0; em[1090] = 0; em[1091] = 1; /* 1089: X509_POLICY_DATA */
    	em[1092] = 1094; em[1093] = 0; 
    em[1094] = 0; em[1095] = 32; em[1096] = 3; /* 1094: struct.X509_POLICY_DATA_st */
    	em[1097] = 1103; em[1098] = 8; 
    	em[1099] = 1108; em[1100] = 16; 
    	em[1101] = 1358; em[1102] = 24; 
    em[1103] = 1; em[1104] = 8; em[1105] = 1; /* 1103: pointer.struct.asn1_object_st */
    	em[1106] = 1080; em[1107] = 0; 
    em[1108] = 1; em[1109] = 8; em[1110] = 1; /* 1108: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1111] = 1113; em[1112] = 0; 
    em[1113] = 0; em[1114] = 32; em[1115] = 2; /* 1113: struct.stack_st_fake_POLICYQUALINFO */
    	em[1116] = 1120; em[1117] = 8; 
    	em[1118] = 249; em[1119] = 24; 
    em[1120] = 8884099; em[1121] = 8; em[1122] = 2; /* 1120: pointer_to_array_of_pointers_to_stack */
    	em[1123] = 1127; em[1124] = 0; 
    	em[1125] = 246; em[1126] = 20; 
    em[1127] = 0; em[1128] = 8; em[1129] = 1; /* 1127: pointer.POLICYQUALINFO */
    	em[1130] = 1132; em[1131] = 0; 
    em[1132] = 0; em[1133] = 0; em[1134] = 1; /* 1132: POLICYQUALINFO */
    	em[1135] = 1137; em[1136] = 0; 
    em[1137] = 0; em[1138] = 16; em[1139] = 2; /* 1137: struct.POLICYQUALINFO_st */
    	em[1140] = 1144; em[1141] = 0; 
    	em[1142] = 1158; em[1143] = 8; 
    em[1144] = 1; em[1145] = 8; em[1146] = 1; /* 1144: pointer.struct.asn1_object_st */
    	em[1147] = 1149; em[1148] = 0; 
    em[1149] = 0; em[1150] = 40; em[1151] = 3; /* 1149: struct.asn1_object_st */
    	em[1152] = 26; em[1153] = 0; 
    	em[1154] = 26; em[1155] = 8; 
    	em[1156] = 31; em[1157] = 24; 
    em[1158] = 0; em[1159] = 8; em[1160] = 3; /* 1158: union.unknown */
    	em[1161] = 1167; em[1162] = 0; 
    	em[1163] = 1177; em[1164] = 0; 
    	em[1165] = 1240; em[1166] = 0; 
    em[1167] = 1; em[1168] = 8; em[1169] = 1; /* 1167: pointer.struct.asn1_string_st */
    	em[1170] = 1172; em[1171] = 0; 
    em[1172] = 0; em[1173] = 24; em[1174] = 1; /* 1172: struct.asn1_string_st */
    	em[1175] = 107; em[1176] = 8; 
    em[1177] = 1; em[1178] = 8; em[1179] = 1; /* 1177: pointer.struct.USERNOTICE_st */
    	em[1180] = 1182; em[1181] = 0; 
    em[1182] = 0; em[1183] = 16; em[1184] = 2; /* 1182: struct.USERNOTICE_st */
    	em[1185] = 1189; em[1186] = 0; 
    	em[1187] = 1201; em[1188] = 8; 
    em[1189] = 1; em[1190] = 8; em[1191] = 1; /* 1189: pointer.struct.NOTICEREF_st */
    	em[1192] = 1194; em[1193] = 0; 
    em[1194] = 0; em[1195] = 16; em[1196] = 2; /* 1194: struct.NOTICEREF_st */
    	em[1197] = 1201; em[1198] = 0; 
    	em[1199] = 1206; em[1200] = 8; 
    em[1201] = 1; em[1202] = 8; em[1203] = 1; /* 1201: pointer.struct.asn1_string_st */
    	em[1204] = 1172; em[1205] = 0; 
    em[1206] = 1; em[1207] = 8; em[1208] = 1; /* 1206: pointer.struct.stack_st_ASN1_INTEGER */
    	em[1209] = 1211; em[1210] = 0; 
    em[1211] = 0; em[1212] = 32; em[1213] = 2; /* 1211: struct.stack_st_fake_ASN1_INTEGER */
    	em[1214] = 1218; em[1215] = 8; 
    	em[1216] = 249; em[1217] = 24; 
    em[1218] = 8884099; em[1219] = 8; em[1220] = 2; /* 1218: pointer_to_array_of_pointers_to_stack */
    	em[1221] = 1225; em[1222] = 0; 
    	em[1223] = 246; em[1224] = 20; 
    em[1225] = 0; em[1226] = 8; em[1227] = 1; /* 1225: pointer.ASN1_INTEGER */
    	em[1228] = 1230; em[1229] = 0; 
    em[1230] = 0; em[1231] = 0; em[1232] = 1; /* 1230: ASN1_INTEGER */
    	em[1233] = 1235; em[1234] = 0; 
    em[1235] = 0; em[1236] = 24; em[1237] = 1; /* 1235: struct.asn1_string_st */
    	em[1238] = 107; em[1239] = 8; 
    em[1240] = 1; em[1241] = 8; em[1242] = 1; /* 1240: pointer.struct.asn1_type_st */
    	em[1243] = 1245; em[1244] = 0; 
    em[1245] = 0; em[1246] = 16; em[1247] = 1; /* 1245: struct.asn1_type_st */
    	em[1248] = 1250; em[1249] = 8; 
    em[1250] = 0; em[1251] = 8; em[1252] = 20; /* 1250: union.unknown */
    	em[1253] = 92; em[1254] = 0; 
    	em[1255] = 1201; em[1256] = 0; 
    	em[1257] = 1144; em[1258] = 0; 
    	em[1259] = 1293; em[1260] = 0; 
    	em[1261] = 1298; em[1262] = 0; 
    	em[1263] = 1303; em[1264] = 0; 
    	em[1265] = 1308; em[1266] = 0; 
    	em[1267] = 1313; em[1268] = 0; 
    	em[1269] = 1318; em[1270] = 0; 
    	em[1271] = 1167; em[1272] = 0; 
    	em[1273] = 1323; em[1274] = 0; 
    	em[1275] = 1328; em[1276] = 0; 
    	em[1277] = 1333; em[1278] = 0; 
    	em[1279] = 1338; em[1280] = 0; 
    	em[1281] = 1343; em[1282] = 0; 
    	em[1283] = 1348; em[1284] = 0; 
    	em[1285] = 1353; em[1286] = 0; 
    	em[1287] = 1201; em[1288] = 0; 
    	em[1289] = 1201; em[1290] = 0; 
    	em[1291] = 524; em[1292] = 0; 
    em[1293] = 1; em[1294] = 8; em[1295] = 1; /* 1293: pointer.struct.asn1_string_st */
    	em[1296] = 1172; em[1297] = 0; 
    em[1298] = 1; em[1299] = 8; em[1300] = 1; /* 1298: pointer.struct.asn1_string_st */
    	em[1301] = 1172; em[1302] = 0; 
    em[1303] = 1; em[1304] = 8; em[1305] = 1; /* 1303: pointer.struct.asn1_string_st */
    	em[1306] = 1172; em[1307] = 0; 
    em[1308] = 1; em[1309] = 8; em[1310] = 1; /* 1308: pointer.struct.asn1_string_st */
    	em[1311] = 1172; em[1312] = 0; 
    em[1313] = 1; em[1314] = 8; em[1315] = 1; /* 1313: pointer.struct.asn1_string_st */
    	em[1316] = 1172; em[1317] = 0; 
    em[1318] = 1; em[1319] = 8; em[1320] = 1; /* 1318: pointer.struct.asn1_string_st */
    	em[1321] = 1172; em[1322] = 0; 
    em[1323] = 1; em[1324] = 8; em[1325] = 1; /* 1323: pointer.struct.asn1_string_st */
    	em[1326] = 1172; em[1327] = 0; 
    em[1328] = 1; em[1329] = 8; em[1330] = 1; /* 1328: pointer.struct.asn1_string_st */
    	em[1331] = 1172; em[1332] = 0; 
    em[1333] = 1; em[1334] = 8; em[1335] = 1; /* 1333: pointer.struct.asn1_string_st */
    	em[1336] = 1172; em[1337] = 0; 
    em[1338] = 1; em[1339] = 8; em[1340] = 1; /* 1338: pointer.struct.asn1_string_st */
    	em[1341] = 1172; em[1342] = 0; 
    em[1343] = 1; em[1344] = 8; em[1345] = 1; /* 1343: pointer.struct.asn1_string_st */
    	em[1346] = 1172; em[1347] = 0; 
    em[1348] = 1; em[1349] = 8; em[1350] = 1; /* 1348: pointer.struct.asn1_string_st */
    	em[1351] = 1172; em[1352] = 0; 
    em[1353] = 1; em[1354] = 8; em[1355] = 1; /* 1353: pointer.struct.asn1_string_st */
    	em[1356] = 1172; em[1357] = 0; 
    em[1358] = 1; em[1359] = 8; em[1360] = 1; /* 1358: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1361] = 1363; em[1362] = 0; 
    em[1363] = 0; em[1364] = 32; em[1365] = 2; /* 1363: struct.stack_st_fake_ASN1_OBJECT */
    	em[1366] = 1370; em[1367] = 8; 
    	em[1368] = 249; em[1369] = 24; 
    em[1370] = 8884099; em[1371] = 8; em[1372] = 2; /* 1370: pointer_to_array_of_pointers_to_stack */
    	em[1373] = 1377; em[1374] = 0; 
    	em[1375] = 246; em[1376] = 20; 
    em[1377] = 0; em[1378] = 8; em[1379] = 1; /* 1377: pointer.ASN1_OBJECT */
    	em[1380] = 232; em[1381] = 0; 
    em[1382] = 1; em[1383] = 8; em[1384] = 1; /* 1382: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[1385] = 1387; em[1386] = 0; 
    em[1387] = 0; em[1388] = 32; em[1389] = 2; /* 1387: struct.stack_st_fake_X509_POLICY_DATA */
    	em[1390] = 1394; em[1391] = 8; 
    	em[1392] = 249; em[1393] = 24; 
    em[1394] = 8884099; em[1395] = 8; em[1396] = 2; /* 1394: pointer_to_array_of_pointers_to_stack */
    	em[1397] = 1401; em[1398] = 0; 
    	em[1399] = 246; em[1400] = 20; 
    em[1401] = 0; em[1402] = 8; em[1403] = 1; /* 1401: pointer.X509_POLICY_DATA */
    	em[1404] = 1089; em[1405] = 0; 
    em[1406] = 1; em[1407] = 8; em[1408] = 1; /* 1406: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1409] = 1411; em[1410] = 0; 
    em[1411] = 0; em[1412] = 32; em[1413] = 2; /* 1411: struct.stack_st_fake_ASN1_OBJECT */
    	em[1414] = 1418; em[1415] = 8; 
    	em[1416] = 249; em[1417] = 24; 
    em[1418] = 8884099; em[1419] = 8; em[1420] = 2; /* 1418: pointer_to_array_of_pointers_to_stack */
    	em[1421] = 1425; em[1422] = 0; 
    	em[1423] = 246; em[1424] = 20; 
    em[1425] = 0; em[1426] = 8; em[1427] = 1; /* 1425: pointer.ASN1_OBJECT */
    	em[1428] = 232; em[1429] = 0; 
    em[1430] = 1; em[1431] = 8; em[1432] = 1; /* 1430: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1433] = 1435; em[1434] = 0; 
    em[1435] = 0; em[1436] = 32; em[1437] = 2; /* 1435: struct.stack_st_fake_POLICYQUALINFO */
    	em[1438] = 1442; em[1439] = 8; 
    	em[1440] = 249; em[1441] = 24; 
    em[1442] = 8884099; em[1443] = 8; em[1444] = 2; /* 1442: pointer_to_array_of_pointers_to_stack */
    	em[1445] = 1449; em[1446] = 0; 
    	em[1447] = 246; em[1448] = 20; 
    em[1449] = 0; em[1450] = 8; em[1451] = 1; /* 1449: pointer.POLICYQUALINFO */
    	em[1452] = 1132; em[1453] = 0; 
    em[1454] = 0; em[1455] = 32; em[1456] = 3; /* 1454: struct.X509_POLICY_DATA_st */
    	em[1457] = 1144; em[1458] = 8; 
    	em[1459] = 1430; em[1460] = 16; 
    	em[1461] = 1406; em[1462] = 24; 
    em[1463] = 1; em[1464] = 8; em[1465] = 1; /* 1463: pointer.struct.asn1_string_st */
    	em[1466] = 1468; em[1467] = 0; 
    em[1468] = 0; em[1469] = 24; em[1470] = 1; /* 1468: struct.asn1_string_st */
    	em[1471] = 107; em[1472] = 8; 
    em[1473] = 1; em[1474] = 8; em[1475] = 1; /* 1473: pointer.struct.asn1_string_st */
    	em[1476] = 1478; em[1477] = 0; 
    em[1478] = 0; em[1479] = 24; em[1480] = 1; /* 1478: struct.asn1_string_st */
    	em[1481] = 107; em[1482] = 8; 
    em[1483] = 1; em[1484] = 8; em[1485] = 1; /* 1483: pointer.struct.asn1_object_st */
    	em[1486] = 1488; em[1487] = 0; 
    em[1488] = 0; em[1489] = 40; em[1490] = 3; /* 1488: struct.asn1_object_st */
    	em[1491] = 26; em[1492] = 0; 
    	em[1493] = 26; em[1494] = 8; 
    	em[1495] = 31; em[1496] = 24; 
    em[1497] = 0; em[1498] = 24; em[1499] = 2; /* 1497: struct.X509_extension_st */
    	em[1500] = 1483; em[1501] = 0; 
    	em[1502] = 1473; em[1503] = 16; 
    em[1504] = 0; em[1505] = 0; em[1506] = 1; /* 1504: X509_EXTENSION */
    	em[1507] = 1497; em[1508] = 0; 
    em[1509] = 1; em[1510] = 8; em[1511] = 1; /* 1509: pointer.struct.asn1_string_st */
    	em[1512] = 1514; em[1513] = 0; 
    em[1514] = 0; em[1515] = 24; em[1516] = 1; /* 1514: struct.asn1_string_st */
    	em[1517] = 107; em[1518] = 8; 
    em[1519] = 1; em[1520] = 8; em[1521] = 1; /* 1519: pointer.struct.asn1_string_st */
    	em[1522] = 1514; em[1523] = 0; 
    em[1524] = 1; em[1525] = 8; em[1526] = 1; /* 1524: pointer.struct.asn1_string_st */
    	em[1527] = 1514; em[1528] = 0; 
    em[1529] = 1; em[1530] = 8; em[1531] = 1; /* 1529: pointer.struct.asn1_string_st */
    	em[1532] = 1514; em[1533] = 0; 
    em[1534] = 1; em[1535] = 8; em[1536] = 1; /* 1534: pointer.struct.asn1_string_st */
    	em[1537] = 1514; em[1538] = 0; 
    em[1539] = 1; em[1540] = 8; em[1541] = 1; /* 1539: pointer.struct.asn1_string_st */
    	em[1542] = 1514; em[1543] = 0; 
    em[1544] = 1; em[1545] = 8; em[1546] = 1; /* 1544: pointer.struct.asn1_string_st */
    	em[1547] = 1514; em[1548] = 0; 
    em[1549] = 1; em[1550] = 8; em[1551] = 1; /* 1549: pointer.struct.asn1_string_st */
    	em[1552] = 1514; em[1553] = 0; 
    em[1554] = 1; em[1555] = 8; em[1556] = 1; /* 1554: pointer.struct.asn1_string_st */
    	em[1557] = 1514; em[1558] = 0; 
    em[1559] = 1; em[1560] = 8; em[1561] = 1; /* 1559: pointer.struct.asn1_string_st */
    	em[1562] = 1514; em[1563] = 0; 
    em[1564] = 1; em[1565] = 8; em[1566] = 1; /* 1564: pointer.struct.asn1_string_st */
    	em[1567] = 1514; em[1568] = 0; 
    em[1569] = 1; em[1570] = 8; em[1571] = 1; /* 1569: pointer.struct.asn1_string_st */
    	em[1572] = 1514; em[1573] = 0; 
    em[1574] = 0; em[1575] = 16; em[1576] = 1; /* 1574: struct.asn1_type_st */
    	em[1577] = 1579; em[1578] = 8; 
    em[1579] = 0; em[1580] = 8; em[1581] = 20; /* 1579: union.unknown */
    	em[1582] = 92; em[1583] = 0; 
    	em[1584] = 1569; em[1585] = 0; 
    	em[1586] = 1622; em[1587] = 0; 
    	em[1588] = 1564; em[1589] = 0; 
    	em[1590] = 1559; em[1591] = 0; 
    	em[1592] = 1554; em[1593] = 0; 
    	em[1594] = 1549; em[1595] = 0; 
    	em[1596] = 1636; em[1597] = 0; 
    	em[1598] = 1544; em[1599] = 0; 
    	em[1600] = 1539; em[1601] = 0; 
    	em[1602] = 1534; em[1603] = 0; 
    	em[1604] = 1529; em[1605] = 0; 
    	em[1606] = 1641; em[1607] = 0; 
    	em[1608] = 1524; em[1609] = 0; 
    	em[1610] = 1519; em[1611] = 0; 
    	em[1612] = 1646; em[1613] = 0; 
    	em[1614] = 1509; em[1615] = 0; 
    	em[1616] = 1569; em[1617] = 0; 
    	em[1618] = 1569; em[1619] = 0; 
    	em[1620] = 182; em[1621] = 0; 
    em[1622] = 1; em[1623] = 8; em[1624] = 1; /* 1622: pointer.struct.asn1_object_st */
    	em[1625] = 1627; em[1626] = 0; 
    em[1627] = 0; em[1628] = 40; em[1629] = 3; /* 1627: struct.asn1_object_st */
    	em[1630] = 26; em[1631] = 0; 
    	em[1632] = 26; em[1633] = 8; 
    	em[1634] = 31; em[1635] = 24; 
    em[1636] = 1; em[1637] = 8; em[1638] = 1; /* 1636: pointer.struct.asn1_string_st */
    	em[1639] = 1514; em[1640] = 0; 
    em[1641] = 1; em[1642] = 8; em[1643] = 1; /* 1641: pointer.struct.asn1_string_st */
    	em[1644] = 1514; em[1645] = 0; 
    em[1646] = 1; em[1647] = 8; em[1648] = 1; /* 1646: pointer.struct.asn1_string_st */
    	em[1649] = 1514; em[1650] = 0; 
    em[1651] = 1; em[1652] = 8; em[1653] = 1; /* 1651: pointer.struct.ASN1_VALUE_st */
    	em[1654] = 1656; em[1655] = 0; 
    em[1656] = 0; em[1657] = 0; em[1658] = 0; /* 1656: struct.ASN1_VALUE_st */
    em[1659] = 1; em[1660] = 8; em[1661] = 1; /* 1659: pointer.struct.asn1_string_st */
    	em[1662] = 1664; em[1663] = 0; 
    em[1664] = 0; em[1665] = 24; em[1666] = 1; /* 1664: struct.asn1_string_st */
    	em[1667] = 107; em[1668] = 8; 
    em[1669] = 1; em[1670] = 8; em[1671] = 1; /* 1669: pointer.struct.asn1_string_st */
    	em[1672] = 1664; em[1673] = 0; 
    em[1674] = 1; em[1675] = 8; em[1676] = 1; /* 1674: pointer.struct.asn1_string_st */
    	em[1677] = 1664; em[1678] = 0; 
    em[1679] = 1; em[1680] = 8; em[1681] = 1; /* 1679: pointer.struct.asn1_string_st */
    	em[1682] = 1664; em[1683] = 0; 
    em[1684] = 1; em[1685] = 8; em[1686] = 1; /* 1684: pointer.struct.asn1_string_st */
    	em[1687] = 1664; em[1688] = 0; 
    em[1689] = 1; em[1690] = 8; em[1691] = 1; /* 1689: pointer.struct.asn1_string_st */
    	em[1692] = 1664; em[1693] = 0; 
    em[1694] = 1; em[1695] = 8; em[1696] = 1; /* 1694: pointer.struct.asn1_string_st */
    	em[1697] = 1664; em[1698] = 0; 
    em[1699] = 1; em[1700] = 8; em[1701] = 1; /* 1699: pointer.struct.asn1_string_st */
    	em[1702] = 1664; em[1703] = 0; 
    em[1704] = 0; em[1705] = 40; em[1706] = 3; /* 1704: struct.asn1_object_st */
    	em[1707] = 26; em[1708] = 0; 
    	em[1709] = 26; em[1710] = 8; 
    	em[1711] = 31; em[1712] = 24; 
    em[1713] = 1; em[1714] = 8; em[1715] = 1; /* 1713: pointer.struct.asn1_object_st */
    	em[1716] = 1704; em[1717] = 0; 
    em[1718] = 1; em[1719] = 8; em[1720] = 1; /* 1718: pointer.struct.asn1_string_st */
    	em[1721] = 1664; em[1722] = 0; 
    em[1723] = 0; em[1724] = 8; em[1725] = 20; /* 1723: union.unknown */
    	em[1726] = 92; em[1727] = 0; 
    	em[1728] = 1718; em[1729] = 0; 
    	em[1730] = 1713; em[1731] = 0; 
    	em[1732] = 1699; em[1733] = 0; 
    	em[1734] = 1694; em[1735] = 0; 
    	em[1736] = 1766; em[1737] = 0; 
    	em[1738] = 1689; em[1739] = 0; 
    	em[1740] = 1771; em[1741] = 0; 
    	em[1742] = 1776; em[1743] = 0; 
    	em[1744] = 1684; em[1745] = 0; 
    	em[1746] = 1679; em[1747] = 0; 
    	em[1748] = 1674; em[1749] = 0; 
    	em[1750] = 1781; em[1751] = 0; 
    	em[1752] = 1786; em[1753] = 0; 
    	em[1754] = 1669; em[1755] = 0; 
    	em[1756] = 1791; em[1757] = 0; 
    	em[1758] = 1659; em[1759] = 0; 
    	em[1760] = 1718; em[1761] = 0; 
    	em[1762] = 1718; em[1763] = 0; 
    	em[1764] = 1651; em[1765] = 0; 
    em[1766] = 1; em[1767] = 8; em[1768] = 1; /* 1766: pointer.struct.asn1_string_st */
    	em[1769] = 1664; em[1770] = 0; 
    em[1771] = 1; em[1772] = 8; em[1773] = 1; /* 1771: pointer.struct.asn1_string_st */
    	em[1774] = 1664; em[1775] = 0; 
    em[1776] = 1; em[1777] = 8; em[1778] = 1; /* 1776: pointer.struct.asn1_string_st */
    	em[1779] = 1664; em[1780] = 0; 
    em[1781] = 1; em[1782] = 8; em[1783] = 1; /* 1781: pointer.struct.asn1_string_st */
    	em[1784] = 1664; em[1785] = 0; 
    em[1786] = 1; em[1787] = 8; em[1788] = 1; /* 1786: pointer.struct.asn1_string_st */
    	em[1789] = 1664; em[1790] = 0; 
    em[1791] = 1; em[1792] = 8; em[1793] = 1; /* 1791: pointer.struct.asn1_string_st */
    	em[1794] = 1664; em[1795] = 0; 
    em[1796] = 0; em[1797] = 16; em[1798] = 1; /* 1796: struct.asn1_type_st */
    	em[1799] = 1723; em[1800] = 8; 
    em[1801] = 1; em[1802] = 8; em[1803] = 1; /* 1801: pointer.struct.stack_st_ASN1_TYPE */
    	em[1804] = 1806; em[1805] = 0; 
    em[1806] = 0; em[1807] = 32; em[1808] = 2; /* 1806: struct.stack_st_fake_ASN1_TYPE */
    	em[1809] = 1813; em[1810] = 8; 
    	em[1811] = 249; em[1812] = 24; 
    em[1813] = 8884099; em[1814] = 8; em[1815] = 2; /* 1813: pointer_to_array_of_pointers_to_stack */
    	em[1816] = 1820; em[1817] = 0; 
    	em[1818] = 246; em[1819] = 20; 
    em[1820] = 0; em[1821] = 8; em[1822] = 1; /* 1820: pointer.ASN1_TYPE */
    	em[1823] = 1825; em[1824] = 0; 
    em[1825] = 0; em[1826] = 0; em[1827] = 1; /* 1825: ASN1_TYPE */
    	em[1828] = 1796; em[1829] = 0; 
    em[1830] = 0; em[1831] = 24; em[1832] = 2; /* 1830: struct.x509_attributes_st */
    	em[1833] = 1622; em[1834] = 0; 
    	em[1835] = 1837; em[1836] = 16; 
    em[1837] = 0; em[1838] = 8; em[1839] = 3; /* 1837: union.unknown */
    	em[1840] = 92; em[1841] = 0; 
    	em[1842] = 1801; em[1843] = 0; 
    	em[1844] = 1846; em[1845] = 0; 
    em[1846] = 1; em[1847] = 8; em[1848] = 1; /* 1846: pointer.struct.asn1_type_st */
    	em[1849] = 1574; em[1850] = 0; 
    em[1851] = 0; em[1852] = 0; em[1853] = 1; /* 1851: X509_ATTRIBUTE */
    	em[1854] = 1830; em[1855] = 0; 
    em[1856] = 1; em[1857] = 8; em[1858] = 1; /* 1856: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1859] = 1861; em[1860] = 0; 
    em[1861] = 0; em[1862] = 32; em[1863] = 2; /* 1861: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1864] = 1868; em[1865] = 8; 
    	em[1866] = 249; em[1867] = 24; 
    em[1868] = 8884099; em[1869] = 8; em[1870] = 2; /* 1868: pointer_to_array_of_pointers_to_stack */
    	em[1871] = 1875; em[1872] = 0; 
    	em[1873] = 246; em[1874] = 20; 
    em[1875] = 0; em[1876] = 8; em[1877] = 1; /* 1875: pointer.X509_ATTRIBUTE */
    	em[1878] = 1851; em[1879] = 0; 
    em[1880] = 0; em[1881] = 40; em[1882] = 5; /* 1880: struct.ec_extra_data_st */
    	em[1883] = 1893; em[1884] = 0; 
    	em[1885] = 1898; em[1886] = 8; 
    	em[1887] = 1901; em[1888] = 16; 
    	em[1889] = 1904; em[1890] = 24; 
    	em[1891] = 1904; em[1892] = 32; 
    em[1893] = 1; em[1894] = 8; em[1895] = 1; /* 1893: pointer.struct.ec_extra_data_st */
    	em[1896] = 1880; em[1897] = 0; 
    em[1898] = 0; em[1899] = 8; em[1900] = 0; /* 1898: pointer.void */
    em[1901] = 8884097; em[1902] = 8; em[1903] = 0; /* 1901: pointer.func */
    em[1904] = 8884097; em[1905] = 8; em[1906] = 0; /* 1904: pointer.func */
    em[1907] = 1; em[1908] = 8; em[1909] = 1; /* 1907: pointer.struct.ec_extra_data_st */
    	em[1910] = 1880; em[1911] = 0; 
    em[1912] = 0; em[1913] = 24; em[1914] = 1; /* 1912: struct.bignum_st */
    	em[1915] = 1917; em[1916] = 0; 
    em[1917] = 8884099; em[1918] = 8; em[1919] = 2; /* 1917: pointer_to_array_of_pointers_to_stack */
    	em[1920] = 1924; em[1921] = 0; 
    	em[1922] = 246; em[1923] = 12; 
    em[1924] = 0; em[1925] = 8; em[1926] = 0; /* 1924: long unsigned int */
    em[1927] = 1; em[1928] = 8; em[1929] = 1; /* 1927: pointer.struct.ec_point_st */
    	em[1930] = 1932; em[1931] = 0; 
    em[1932] = 0; em[1933] = 88; em[1934] = 4; /* 1932: struct.ec_point_st */
    	em[1935] = 1943; em[1936] = 0; 
    	em[1937] = 2115; em[1938] = 8; 
    	em[1939] = 2115; em[1940] = 32; 
    	em[1941] = 2115; em[1942] = 56; 
    em[1943] = 1; em[1944] = 8; em[1945] = 1; /* 1943: pointer.struct.ec_method_st */
    	em[1946] = 1948; em[1947] = 0; 
    em[1948] = 0; em[1949] = 304; em[1950] = 37; /* 1948: struct.ec_method_st */
    	em[1951] = 2025; em[1952] = 8; 
    	em[1953] = 2028; em[1954] = 16; 
    	em[1955] = 2028; em[1956] = 24; 
    	em[1957] = 2031; em[1958] = 32; 
    	em[1959] = 2034; em[1960] = 40; 
    	em[1961] = 2037; em[1962] = 48; 
    	em[1963] = 2040; em[1964] = 56; 
    	em[1965] = 2043; em[1966] = 64; 
    	em[1967] = 2046; em[1968] = 72; 
    	em[1969] = 2049; em[1970] = 80; 
    	em[1971] = 2049; em[1972] = 88; 
    	em[1973] = 2052; em[1974] = 96; 
    	em[1975] = 2055; em[1976] = 104; 
    	em[1977] = 2058; em[1978] = 112; 
    	em[1979] = 2061; em[1980] = 120; 
    	em[1981] = 2064; em[1982] = 128; 
    	em[1983] = 2067; em[1984] = 136; 
    	em[1985] = 2070; em[1986] = 144; 
    	em[1987] = 2073; em[1988] = 152; 
    	em[1989] = 2076; em[1990] = 160; 
    	em[1991] = 2079; em[1992] = 168; 
    	em[1993] = 2082; em[1994] = 176; 
    	em[1995] = 2085; em[1996] = 184; 
    	em[1997] = 2088; em[1998] = 192; 
    	em[1999] = 2091; em[2000] = 200; 
    	em[2001] = 2094; em[2002] = 208; 
    	em[2003] = 2085; em[2004] = 216; 
    	em[2005] = 2097; em[2006] = 224; 
    	em[2007] = 2100; em[2008] = 232; 
    	em[2009] = 2103; em[2010] = 240; 
    	em[2011] = 2040; em[2012] = 248; 
    	em[2013] = 2106; em[2014] = 256; 
    	em[2015] = 2109; em[2016] = 264; 
    	em[2017] = 2106; em[2018] = 272; 
    	em[2019] = 2109; em[2020] = 280; 
    	em[2021] = 2109; em[2022] = 288; 
    	em[2023] = 2112; em[2024] = 296; 
    em[2025] = 8884097; em[2026] = 8; em[2027] = 0; /* 2025: pointer.func */
    em[2028] = 8884097; em[2029] = 8; em[2030] = 0; /* 2028: pointer.func */
    em[2031] = 8884097; em[2032] = 8; em[2033] = 0; /* 2031: pointer.func */
    em[2034] = 8884097; em[2035] = 8; em[2036] = 0; /* 2034: pointer.func */
    em[2037] = 8884097; em[2038] = 8; em[2039] = 0; /* 2037: pointer.func */
    em[2040] = 8884097; em[2041] = 8; em[2042] = 0; /* 2040: pointer.func */
    em[2043] = 8884097; em[2044] = 8; em[2045] = 0; /* 2043: pointer.func */
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
    em[2115] = 0; em[2116] = 24; em[2117] = 1; /* 2115: struct.bignum_st */
    	em[2118] = 2120; em[2119] = 0; 
    em[2120] = 8884099; em[2121] = 8; em[2122] = 2; /* 2120: pointer_to_array_of_pointers_to_stack */
    	em[2123] = 1924; em[2124] = 0; 
    	em[2125] = 246; em[2126] = 12; 
    em[2127] = 8884097; em[2128] = 8; em[2129] = 0; /* 2127: pointer.func */
    em[2130] = 1; em[2131] = 8; em[2132] = 1; /* 2130: pointer.struct.ec_extra_data_st */
    	em[2133] = 2135; em[2134] = 0; 
    em[2135] = 0; em[2136] = 40; em[2137] = 5; /* 2135: struct.ec_extra_data_st */
    	em[2138] = 2130; em[2139] = 0; 
    	em[2140] = 1898; em[2141] = 8; 
    	em[2142] = 1901; em[2143] = 16; 
    	em[2144] = 1904; em[2145] = 24; 
    	em[2146] = 1904; em[2147] = 32; 
    em[2148] = 1; em[2149] = 8; em[2150] = 1; /* 2148: pointer.struct.ec_extra_data_st */
    	em[2151] = 2135; em[2152] = 0; 
    em[2153] = 0; em[2154] = 24; em[2155] = 1; /* 2153: struct.bignum_st */
    	em[2156] = 2158; em[2157] = 0; 
    em[2158] = 8884099; em[2159] = 8; em[2160] = 2; /* 2158: pointer_to_array_of_pointers_to_stack */
    	em[2161] = 1924; em[2162] = 0; 
    	em[2163] = 246; em[2164] = 12; 
    em[2165] = 8884097; em[2166] = 8; em[2167] = 0; /* 2165: pointer.func */
    em[2168] = 8884097; em[2169] = 8; em[2170] = 0; /* 2168: pointer.func */
    em[2171] = 8884097; em[2172] = 8; em[2173] = 0; /* 2171: pointer.func */
    em[2174] = 8884097; em[2175] = 8; em[2176] = 0; /* 2174: pointer.func */
    em[2177] = 1; em[2178] = 8; em[2179] = 1; /* 2177: pointer.struct.X509_val_st */
    	em[2180] = 2182; em[2181] = 0; 
    em[2182] = 0; em[2183] = 16; em[2184] = 2; /* 2182: struct.X509_val_st */
    	em[2185] = 2189; em[2186] = 0; 
    	em[2187] = 2189; em[2188] = 8; 
    em[2189] = 1; em[2190] = 8; em[2191] = 1; /* 2189: pointer.struct.asn1_string_st */
    	em[2192] = 257; em[2193] = 0; 
    em[2194] = 1; em[2195] = 8; em[2196] = 1; /* 2194: pointer.struct.rsa_meth_st */
    	em[2197] = 2199; em[2198] = 0; 
    em[2199] = 0; em[2200] = 112; em[2201] = 13; /* 2199: struct.rsa_meth_st */
    	em[2202] = 26; em[2203] = 0; 
    	em[2204] = 2228; em[2205] = 8; 
    	em[2206] = 2228; em[2207] = 16; 
    	em[2208] = 2228; em[2209] = 24; 
    	em[2210] = 2228; em[2211] = 32; 
    	em[2212] = 2231; em[2213] = 40; 
    	em[2214] = 2234; em[2215] = 48; 
    	em[2216] = 2237; em[2217] = 56; 
    	em[2218] = 2237; em[2219] = 64; 
    	em[2220] = 92; em[2221] = 80; 
    	em[2222] = 2240; em[2223] = 88; 
    	em[2224] = 2243; em[2225] = 96; 
    	em[2226] = 2246; em[2227] = 104; 
    em[2228] = 8884097; em[2229] = 8; em[2230] = 0; /* 2228: pointer.func */
    em[2231] = 8884097; em[2232] = 8; em[2233] = 0; /* 2231: pointer.func */
    em[2234] = 8884097; em[2235] = 8; em[2236] = 0; /* 2234: pointer.func */
    em[2237] = 8884097; em[2238] = 8; em[2239] = 0; /* 2237: pointer.func */
    em[2240] = 8884097; em[2241] = 8; em[2242] = 0; /* 2240: pointer.func */
    em[2243] = 8884097; em[2244] = 8; em[2245] = 0; /* 2243: pointer.func */
    em[2246] = 8884097; em[2247] = 8; em[2248] = 0; /* 2246: pointer.func */
    em[2249] = 8884097; em[2250] = 8; em[2251] = 0; /* 2249: pointer.func */
    em[2252] = 8884097; em[2253] = 8; em[2254] = 0; /* 2252: pointer.func */
    em[2255] = 8884097; em[2256] = 8; em[2257] = 0; /* 2255: pointer.func */
    em[2258] = 8884097; em[2259] = 8; em[2260] = 0; /* 2258: pointer.func */
    em[2261] = 1; em[2262] = 8; em[2263] = 1; /* 2261: pointer.struct.rand_meth_st */
    	em[2264] = 2266; em[2265] = 0; 
    em[2266] = 0; em[2267] = 48; em[2268] = 6; /* 2266: struct.rand_meth_st */
    	em[2269] = 2258; em[2270] = 0; 
    	em[2271] = 2281; em[2272] = 8; 
    	em[2273] = 2284; em[2274] = 16; 
    	em[2275] = 2171; em[2276] = 24; 
    	em[2277] = 2281; em[2278] = 32; 
    	em[2279] = 2165; em[2280] = 40; 
    em[2281] = 8884097; em[2282] = 8; em[2283] = 0; /* 2281: pointer.func */
    em[2284] = 8884097; em[2285] = 8; em[2286] = 0; /* 2284: pointer.func */
    em[2287] = 8884097; em[2288] = 8; em[2289] = 0; /* 2287: pointer.func */
    em[2290] = 1; em[2291] = 8; em[2292] = 1; /* 2290: pointer.struct.bn_blinding_st */
    	em[2293] = 2295; em[2294] = 0; 
    em[2295] = 0; em[2296] = 88; em[2297] = 7; /* 2295: struct.bn_blinding_st */
    	em[2298] = 2312; em[2299] = 0; 
    	em[2300] = 2312; em[2301] = 8; 
    	em[2302] = 2312; em[2303] = 16; 
    	em[2304] = 2312; em[2305] = 24; 
    	em[2306] = 2329; em[2307] = 40; 
    	em[2308] = 2334; em[2309] = 72; 
    	em[2310] = 2348; em[2311] = 80; 
    em[2312] = 1; em[2313] = 8; em[2314] = 1; /* 2312: pointer.struct.bignum_st */
    	em[2315] = 2317; em[2316] = 0; 
    em[2317] = 0; em[2318] = 24; em[2319] = 1; /* 2317: struct.bignum_st */
    	em[2320] = 2322; em[2321] = 0; 
    em[2322] = 8884099; em[2323] = 8; em[2324] = 2; /* 2322: pointer_to_array_of_pointers_to_stack */
    	em[2325] = 1924; em[2326] = 0; 
    	em[2327] = 246; em[2328] = 12; 
    em[2329] = 0; em[2330] = 16; em[2331] = 1; /* 2329: struct.crypto_threadid_st */
    	em[2332] = 1898; em[2333] = 0; 
    em[2334] = 1; em[2335] = 8; em[2336] = 1; /* 2334: pointer.struct.bn_mont_ctx_st */
    	em[2337] = 2339; em[2338] = 0; 
    em[2339] = 0; em[2340] = 96; em[2341] = 3; /* 2339: struct.bn_mont_ctx_st */
    	em[2342] = 2317; em[2343] = 8; 
    	em[2344] = 2317; em[2345] = 32; 
    	em[2346] = 2317; em[2347] = 56; 
    em[2348] = 8884097; em[2349] = 8; em[2350] = 0; /* 2348: pointer.func */
    em[2351] = 8884097; em[2352] = 8; em[2353] = 0; /* 2351: pointer.func */
    em[2354] = 8884097; em[2355] = 8; em[2356] = 0; /* 2354: pointer.func */
    em[2357] = 0; em[2358] = 32; em[2359] = 3; /* 2357: struct.ecdh_method */
    	em[2360] = 26; em[2361] = 0; 
    	em[2362] = 2366; em[2363] = 8; 
    	em[2364] = 92; em[2365] = 24; 
    em[2366] = 8884097; em[2367] = 8; em[2368] = 0; /* 2366: pointer.func */
    em[2369] = 1; em[2370] = 8; em[2371] = 1; /* 2369: pointer.struct.X509_algor_st */
    	em[2372] = 5; em[2373] = 0; 
    em[2374] = 8884097; em[2375] = 8; em[2376] = 0; /* 2374: pointer.func */
    em[2377] = 8884097; em[2378] = 8; em[2379] = 0; /* 2377: pointer.func */
    em[2380] = 8884097; em[2381] = 8; em[2382] = 0; /* 2380: pointer.func */
    em[2383] = 8884097; em[2384] = 8; em[2385] = 0; /* 2383: pointer.func */
    em[2386] = 8884097; em[2387] = 8; em[2388] = 0; /* 2386: pointer.func */
    em[2389] = 0; em[2390] = 24; em[2391] = 3; /* 2389: struct.AUTHORITY_KEYID_st */
    	em[2392] = 2398; em[2393] = 0; 
    	em[2394] = 2403; em[2395] = 8; 
    	em[2396] = 1463; em[2397] = 16; 
    em[2398] = 1; em[2399] = 8; em[2400] = 1; /* 2398: pointer.struct.asn1_string_st */
    	em[2401] = 1468; em[2402] = 0; 
    em[2403] = 1; em[2404] = 8; em[2405] = 1; /* 2403: pointer.struct.stack_st_GENERAL_NAME */
    	em[2406] = 2408; em[2407] = 0; 
    em[2408] = 0; em[2409] = 32; em[2410] = 2; /* 2408: struct.stack_st_fake_GENERAL_NAME */
    	em[2411] = 2415; em[2412] = 8; 
    	em[2413] = 249; em[2414] = 24; 
    em[2415] = 8884099; em[2416] = 8; em[2417] = 2; /* 2415: pointer_to_array_of_pointers_to_stack */
    	em[2418] = 2422; em[2419] = 0; 
    	em[2420] = 246; em[2421] = 20; 
    em[2422] = 0; em[2423] = 8; em[2424] = 1; /* 2422: pointer.GENERAL_NAME */
    	em[2425] = 671; em[2426] = 0; 
    em[2427] = 0; em[2428] = 24; em[2429] = 1; /* 2427: struct.bignum_st */
    	em[2430] = 2432; em[2431] = 0; 
    em[2432] = 8884099; em[2433] = 8; em[2434] = 2; /* 2432: pointer_to_array_of_pointers_to_stack */
    	em[2435] = 1924; em[2436] = 0; 
    	em[2437] = 246; em[2438] = 12; 
    em[2439] = 8884097; em[2440] = 8; em[2441] = 0; /* 2439: pointer.func */
    em[2442] = 8884097; em[2443] = 8; em[2444] = 0; /* 2442: pointer.func */
    em[2445] = 8884097; em[2446] = 8; em[2447] = 0; /* 2445: pointer.func */
    em[2448] = 8884097; em[2449] = 8; em[2450] = 0; /* 2448: pointer.func */
    em[2451] = 0; em[2452] = 112; em[2453] = 13; /* 2451: struct.rsa_meth_st */
    	em[2454] = 26; em[2455] = 0; 
    	em[2456] = 2445; em[2457] = 8; 
    	em[2458] = 2445; em[2459] = 16; 
    	em[2460] = 2445; em[2461] = 24; 
    	em[2462] = 2445; em[2463] = 32; 
    	em[2464] = 2480; em[2465] = 40; 
    	em[2466] = 2442; em[2467] = 48; 
    	em[2468] = 2483; em[2469] = 56; 
    	em[2470] = 2483; em[2471] = 64; 
    	em[2472] = 92; em[2473] = 80; 
    	em[2474] = 2439; em[2475] = 88; 
    	em[2476] = 2486; em[2477] = 96; 
    	em[2478] = 2489; em[2479] = 104; 
    em[2480] = 8884097; em[2481] = 8; em[2482] = 0; /* 2480: pointer.func */
    em[2483] = 8884097; em[2484] = 8; em[2485] = 0; /* 2483: pointer.func */
    em[2486] = 8884097; em[2487] = 8; em[2488] = 0; /* 2486: pointer.func */
    em[2489] = 8884097; em[2490] = 8; em[2491] = 0; /* 2489: pointer.func */
    em[2492] = 1; em[2493] = 8; em[2494] = 1; /* 2492: pointer.struct.ecdh_method */
    	em[2495] = 2357; em[2496] = 0; 
    em[2497] = 8884097; em[2498] = 8; em[2499] = 0; /* 2497: pointer.func */
    em[2500] = 1; em[2501] = 8; em[2502] = 1; /* 2500: pointer.struct.rsa_meth_st */
    	em[2503] = 2451; em[2504] = 0; 
    em[2505] = 8884097; em[2506] = 8; em[2507] = 0; /* 2505: pointer.func */
    em[2508] = 1; em[2509] = 8; em[2510] = 1; /* 2508: pointer.struct.engine_st */
    	em[2511] = 2513; em[2512] = 0; 
    em[2513] = 0; em[2514] = 216; em[2515] = 24; /* 2513: struct.engine_st */
    	em[2516] = 26; em[2517] = 0; 
    	em[2518] = 26; em[2519] = 8; 
    	em[2520] = 2500; em[2521] = 16; 
    	em[2522] = 2564; em[2523] = 24; 
    	em[2524] = 2600; em[2525] = 32; 
    	em[2526] = 2492; em[2527] = 40; 
    	em[2528] = 2636; em[2529] = 48; 
    	em[2530] = 2261; em[2531] = 56; 
    	em[2532] = 2657; em[2533] = 64; 
    	em[2534] = 2252; em[2535] = 72; 
    	em[2536] = 2665; em[2537] = 80; 
    	em[2538] = 2668; em[2539] = 88; 
    	em[2540] = 2671; em[2541] = 96; 
    	em[2542] = 2674; em[2543] = 104; 
    	em[2544] = 2674; em[2545] = 112; 
    	em[2546] = 2674; em[2547] = 120; 
    	em[2548] = 2677; em[2549] = 128; 
    	em[2550] = 2497; em[2551] = 136; 
    	em[2552] = 2497; em[2553] = 144; 
    	em[2554] = 2680; em[2555] = 152; 
    	em[2556] = 2683; em[2557] = 160; 
    	em[2558] = 2695; em[2559] = 184; 
    	em[2560] = 2709; em[2561] = 200; 
    	em[2562] = 2709; em[2563] = 208; 
    em[2564] = 1; em[2565] = 8; em[2566] = 1; /* 2564: pointer.struct.dsa_method */
    	em[2567] = 2569; em[2568] = 0; 
    em[2569] = 0; em[2570] = 96; em[2571] = 11; /* 2569: struct.dsa_method */
    	em[2572] = 26; em[2573] = 0; 
    	em[2574] = 2594; em[2575] = 8; 
    	em[2576] = 2386; em[2577] = 16; 
    	em[2578] = 2377; em[2579] = 24; 
    	em[2580] = 2374; em[2581] = 32; 
    	em[2582] = 2597; em[2583] = 40; 
    	em[2584] = 2168; em[2585] = 48; 
    	em[2586] = 2168; em[2587] = 56; 
    	em[2588] = 92; em[2589] = 72; 
    	em[2590] = 2505; em[2591] = 80; 
    	em[2592] = 2168; em[2593] = 88; 
    em[2594] = 8884097; em[2595] = 8; em[2596] = 0; /* 2594: pointer.func */
    em[2597] = 8884097; em[2598] = 8; em[2599] = 0; /* 2597: pointer.func */
    em[2600] = 1; em[2601] = 8; em[2602] = 1; /* 2600: pointer.struct.dh_method */
    	em[2603] = 2605; em[2604] = 0; 
    em[2605] = 0; em[2606] = 72; em[2607] = 8; /* 2605: struct.dh_method */
    	em[2608] = 26; em[2609] = 0; 
    	em[2610] = 2624; em[2611] = 8; 
    	em[2612] = 2627; em[2613] = 16; 
    	em[2614] = 2630; em[2615] = 24; 
    	em[2616] = 2624; em[2617] = 32; 
    	em[2618] = 2624; em[2619] = 40; 
    	em[2620] = 92; em[2621] = 56; 
    	em[2622] = 2633; em[2623] = 64; 
    em[2624] = 8884097; em[2625] = 8; em[2626] = 0; /* 2624: pointer.func */
    em[2627] = 8884097; em[2628] = 8; em[2629] = 0; /* 2627: pointer.func */
    em[2630] = 8884097; em[2631] = 8; em[2632] = 0; /* 2630: pointer.func */
    em[2633] = 8884097; em[2634] = 8; em[2635] = 0; /* 2633: pointer.func */
    em[2636] = 1; em[2637] = 8; em[2638] = 1; /* 2636: pointer.struct.ecdsa_method */
    	em[2639] = 2641; em[2640] = 0; 
    em[2641] = 0; em[2642] = 48; em[2643] = 5; /* 2641: struct.ecdsa_method */
    	em[2644] = 26; em[2645] = 0; 
    	em[2646] = 2351; em[2647] = 8; 
    	em[2648] = 2287; em[2649] = 16; 
    	em[2650] = 2654; em[2651] = 24; 
    	em[2652] = 92; em[2653] = 40; 
    em[2654] = 8884097; em[2655] = 8; em[2656] = 0; /* 2654: pointer.func */
    em[2657] = 1; em[2658] = 8; em[2659] = 1; /* 2657: pointer.struct.store_method_st */
    	em[2660] = 2662; em[2661] = 0; 
    em[2662] = 0; em[2663] = 0; em[2664] = 0; /* 2662: struct.store_method_st */
    em[2665] = 8884097; em[2666] = 8; em[2667] = 0; /* 2665: pointer.func */
    em[2668] = 8884097; em[2669] = 8; em[2670] = 0; /* 2668: pointer.func */
    em[2671] = 8884097; em[2672] = 8; em[2673] = 0; /* 2671: pointer.func */
    em[2674] = 8884097; em[2675] = 8; em[2676] = 0; /* 2674: pointer.func */
    em[2677] = 8884097; em[2678] = 8; em[2679] = 0; /* 2677: pointer.func */
    em[2680] = 8884097; em[2681] = 8; em[2682] = 0; /* 2680: pointer.func */
    em[2683] = 1; em[2684] = 8; em[2685] = 1; /* 2683: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[2686] = 2688; em[2687] = 0; 
    em[2688] = 0; em[2689] = 32; em[2690] = 2; /* 2688: struct.ENGINE_CMD_DEFN_st */
    	em[2691] = 26; em[2692] = 8; 
    	em[2693] = 26; em[2694] = 16; 
    em[2695] = 0; em[2696] = 32; em[2697] = 2; /* 2695: struct.crypto_ex_data_st_fake */
    	em[2698] = 2702; em[2699] = 8; 
    	em[2700] = 249; em[2701] = 24; 
    em[2702] = 8884099; em[2703] = 8; em[2704] = 2; /* 2702: pointer_to_array_of_pointers_to_stack */
    	em[2705] = 1898; em[2706] = 0; 
    	em[2707] = 246; em[2708] = 20; 
    em[2709] = 1; em[2710] = 8; em[2711] = 1; /* 2709: pointer.struct.engine_st */
    	em[2712] = 2513; em[2713] = 0; 
    em[2714] = 1; em[2715] = 8; em[2716] = 1; /* 2714: pointer.struct.AUTHORITY_KEYID_st */
    	em[2717] = 2389; em[2718] = 0; 
    em[2719] = 1; em[2720] = 8; em[2721] = 1; /* 2719: pointer.struct.engine_st */
    	em[2722] = 2513; em[2723] = 0; 
    em[2724] = 8884097; em[2725] = 8; em[2726] = 0; /* 2724: pointer.func */
    em[2727] = 1; em[2728] = 8; em[2729] = 1; /* 2727: pointer.struct.asn1_string_st */
    	em[2730] = 257; em[2731] = 0; 
    em[2732] = 8884097; em[2733] = 8; em[2734] = 0; /* 2732: pointer.func */
    em[2735] = 8884097; em[2736] = 8; em[2737] = 0; /* 2735: pointer.func */
    em[2738] = 8884097; em[2739] = 8; em[2740] = 0; /* 2738: pointer.func */
    em[2741] = 1; em[2742] = 8; em[2743] = 1; /* 2741: pointer.struct.bignum_st */
    	em[2744] = 2427; em[2745] = 0; 
    em[2746] = 8884097; em[2747] = 8; em[2748] = 0; /* 2746: pointer.func */
    em[2749] = 8884097; em[2750] = 8; em[2751] = 0; /* 2749: pointer.func */
    em[2752] = 0; em[2753] = 208; em[2754] = 24; /* 2752: struct.evp_pkey_asn1_method_st */
    	em[2755] = 92; em[2756] = 16; 
    	em[2757] = 92; em[2758] = 24; 
    	em[2759] = 2803; em[2760] = 32; 
    	em[2761] = 2806; em[2762] = 40; 
    	em[2763] = 2749; em[2764] = 48; 
    	em[2765] = 2746; em[2766] = 56; 
    	em[2767] = 2809; em[2768] = 64; 
    	em[2769] = 2812; em[2770] = 72; 
    	em[2771] = 2746; em[2772] = 80; 
    	em[2773] = 2815; em[2774] = 88; 
    	em[2775] = 2815; em[2776] = 96; 
    	em[2777] = 2818; em[2778] = 104; 
    	em[2779] = 2821; em[2780] = 112; 
    	em[2781] = 2815; em[2782] = 120; 
    	em[2783] = 2824; em[2784] = 128; 
    	em[2785] = 2749; em[2786] = 136; 
    	em[2787] = 2746; em[2788] = 144; 
    	em[2789] = 2738; em[2790] = 152; 
    	em[2791] = 2380; em[2792] = 160; 
    	em[2793] = 2724; em[2794] = 168; 
    	em[2795] = 2818; em[2796] = 176; 
    	em[2797] = 2821; em[2798] = 184; 
    	em[2799] = 2174; em[2800] = 192; 
    	em[2801] = 2827; em[2802] = 200; 
    em[2803] = 8884097; em[2804] = 8; em[2805] = 0; /* 2803: pointer.func */
    em[2806] = 8884097; em[2807] = 8; em[2808] = 0; /* 2806: pointer.func */
    em[2809] = 8884097; em[2810] = 8; em[2811] = 0; /* 2809: pointer.func */
    em[2812] = 8884097; em[2813] = 8; em[2814] = 0; /* 2812: pointer.func */
    em[2815] = 8884097; em[2816] = 8; em[2817] = 0; /* 2815: pointer.func */
    em[2818] = 8884097; em[2819] = 8; em[2820] = 0; /* 2818: pointer.func */
    em[2821] = 8884097; em[2822] = 8; em[2823] = 0; /* 2821: pointer.func */
    em[2824] = 8884097; em[2825] = 8; em[2826] = 0; /* 2824: pointer.func */
    em[2827] = 8884097; em[2828] = 8; em[2829] = 0; /* 2827: pointer.func */
    em[2830] = 1; em[2831] = 8; em[2832] = 1; /* 2830: pointer.struct.evp_pkey_asn1_method_st */
    	em[2833] = 2752; em[2834] = 0; 
    em[2835] = 0; em[2836] = 24; em[2837] = 3; /* 2835: struct.X509_pubkey_st */
    	em[2838] = 2369; em[2839] = 0; 
    	em[2840] = 122; em[2841] = 8; 
    	em[2842] = 2844; em[2843] = 16; 
    em[2844] = 1; em[2845] = 8; em[2846] = 1; /* 2844: pointer.struct.evp_pkey_st */
    	em[2847] = 2849; em[2848] = 0; 
    em[2849] = 0; em[2850] = 56; em[2851] = 4; /* 2849: struct.evp_pkey_st */
    	em[2852] = 2830; em[2853] = 16; 
    	em[2854] = 2719; em[2855] = 24; 
    	em[2856] = 2860; em[2857] = 32; 
    	em[2858] = 1856; em[2859] = 48; 
    em[2860] = 0; em[2861] = 8; em[2862] = 6; /* 2860: union.union_of_evp_pkey_st */
    	em[2863] = 1898; em[2864] = 0; 
    	em[2865] = 2875; em[2866] = 6; 
    	em[2867] = 2967; em[2868] = 116; 
    	em[2869] = 3070; em[2870] = 28; 
    	em[2871] = 3185; em[2872] = 408; 
    	em[2873] = 246; em[2874] = 0; 
    em[2875] = 1; em[2876] = 8; em[2877] = 1; /* 2875: pointer.struct.rsa_st */
    	em[2878] = 2880; em[2879] = 0; 
    em[2880] = 0; em[2881] = 168; em[2882] = 17; /* 2880: struct.rsa_st */
    	em[2883] = 2194; em[2884] = 16; 
    	em[2885] = 2917; em[2886] = 24; 
    	em[2887] = 2922; em[2888] = 32; 
    	em[2889] = 2922; em[2890] = 40; 
    	em[2891] = 2922; em[2892] = 48; 
    	em[2893] = 2922; em[2894] = 56; 
    	em[2895] = 2922; em[2896] = 64; 
    	em[2897] = 2922; em[2898] = 72; 
    	em[2899] = 2922; em[2900] = 80; 
    	em[2901] = 2922; em[2902] = 88; 
    	em[2903] = 2939; em[2904] = 96; 
    	em[2905] = 2953; em[2906] = 120; 
    	em[2907] = 2953; em[2908] = 128; 
    	em[2909] = 2953; em[2910] = 136; 
    	em[2911] = 92; em[2912] = 144; 
    	em[2913] = 2290; em[2914] = 152; 
    	em[2915] = 2290; em[2916] = 160; 
    em[2917] = 1; em[2918] = 8; em[2919] = 1; /* 2917: pointer.struct.engine_st */
    	em[2920] = 2513; em[2921] = 0; 
    em[2922] = 1; em[2923] = 8; em[2924] = 1; /* 2922: pointer.struct.bignum_st */
    	em[2925] = 2927; em[2926] = 0; 
    em[2927] = 0; em[2928] = 24; em[2929] = 1; /* 2927: struct.bignum_st */
    	em[2930] = 2932; em[2931] = 0; 
    em[2932] = 8884099; em[2933] = 8; em[2934] = 2; /* 2932: pointer_to_array_of_pointers_to_stack */
    	em[2935] = 1924; em[2936] = 0; 
    	em[2937] = 246; em[2938] = 12; 
    em[2939] = 0; em[2940] = 32; em[2941] = 2; /* 2939: struct.crypto_ex_data_st_fake */
    	em[2942] = 2946; em[2943] = 8; 
    	em[2944] = 249; em[2945] = 24; 
    em[2946] = 8884099; em[2947] = 8; em[2948] = 2; /* 2946: pointer_to_array_of_pointers_to_stack */
    	em[2949] = 1898; em[2950] = 0; 
    	em[2951] = 246; em[2952] = 20; 
    em[2953] = 1; em[2954] = 8; em[2955] = 1; /* 2953: pointer.struct.bn_mont_ctx_st */
    	em[2956] = 2958; em[2957] = 0; 
    em[2958] = 0; em[2959] = 96; em[2960] = 3; /* 2958: struct.bn_mont_ctx_st */
    	em[2961] = 2927; em[2962] = 8; 
    	em[2963] = 2927; em[2964] = 32; 
    	em[2965] = 2927; em[2966] = 56; 
    em[2967] = 1; em[2968] = 8; em[2969] = 1; /* 2967: pointer.struct.dsa_st */
    	em[2970] = 2972; em[2971] = 0; 
    em[2972] = 0; em[2973] = 136; em[2974] = 11; /* 2972: struct.dsa_st */
    	em[2975] = 2741; em[2976] = 24; 
    	em[2977] = 2741; em[2978] = 32; 
    	em[2979] = 2741; em[2980] = 40; 
    	em[2981] = 2741; em[2982] = 48; 
    	em[2983] = 2741; em[2984] = 56; 
    	em[2985] = 2741; em[2986] = 64; 
    	em[2987] = 2741; em[2988] = 72; 
    	em[2989] = 2997; em[2990] = 88; 
    	em[2991] = 3011; em[2992] = 104; 
    	em[2993] = 3025; em[2994] = 120; 
    	em[2995] = 2508; em[2996] = 128; 
    em[2997] = 1; em[2998] = 8; em[2999] = 1; /* 2997: pointer.struct.bn_mont_ctx_st */
    	em[3000] = 3002; em[3001] = 0; 
    em[3002] = 0; em[3003] = 96; em[3004] = 3; /* 3002: struct.bn_mont_ctx_st */
    	em[3005] = 2427; em[3006] = 8; 
    	em[3007] = 2427; em[3008] = 32; 
    	em[3009] = 2427; em[3010] = 56; 
    em[3011] = 0; em[3012] = 32; em[3013] = 2; /* 3011: struct.crypto_ex_data_st_fake */
    	em[3014] = 3018; em[3015] = 8; 
    	em[3016] = 249; em[3017] = 24; 
    em[3018] = 8884099; em[3019] = 8; em[3020] = 2; /* 3018: pointer_to_array_of_pointers_to_stack */
    	em[3021] = 1898; em[3022] = 0; 
    	em[3023] = 246; em[3024] = 20; 
    em[3025] = 1; em[3026] = 8; em[3027] = 1; /* 3025: pointer.struct.dsa_method */
    	em[3028] = 3030; em[3029] = 0; 
    em[3030] = 0; em[3031] = 96; em[3032] = 11; /* 3030: struct.dsa_method */
    	em[3033] = 26; em[3034] = 0; 
    	em[3035] = 3055; em[3036] = 8; 
    	em[3037] = 2255; em[3038] = 16; 
    	em[3039] = 3058; em[3040] = 24; 
    	em[3041] = 3061; em[3042] = 32; 
    	em[3043] = 3064; em[3044] = 40; 
    	em[3045] = 3067; em[3046] = 48; 
    	em[3047] = 3067; em[3048] = 56; 
    	em[3049] = 92; em[3050] = 72; 
    	em[3051] = 2448; em[3052] = 80; 
    	em[3053] = 3067; em[3054] = 88; 
    em[3055] = 8884097; em[3056] = 8; em[3057] = 0; /* 3055: pointer.func */
    em[3058] = 8884097; em[3059] = 8; em[3060] = 0; /* 3058: pointer.func */
    em[3061] = 8884097; em[3062] = 8; em[3063] = 0; /* 3061: pointer.func */
    em[3064] = 8884097; em[3065] = 8; em[3066] = 0; /* 3064: pointer.func */
    em[3067] = 8884097; em[3068] = 8; em[3069] = 0; /* 3067: pointer.func */
    em[3070] = 1; em[3071] = 8; em[3072] = 1; /* 3070: pointer.struct.dh_st */
    	em[3073] = 3075; em[3074] = 0; 
    em[3075] = 0; em[3076] = 144; em[3077] = 12; /* 3075: struct.dh_st */
    	em[3078] = 3102; em[3079] = 8; 
    	em[3080] = 3102; em[3081] = 16; 
    	em[3082] = 3102; em[3083] = 32; 
    	em[3084] = 3102; em[3085] = 40; 
    	em[3086] = 3119; em[3087] = 56; 
    	em[3088] = 3102; em[3089] = 64; 
    	em[3090] = 3102; em[3091] = 72; 
    	em[3092] = 107; em[3093] = 80; 
    	em[3094] = 3102; em[3095] = 96; 
    	em[3096] = 3133; em[3097] = 112; 
    	em[3098] = 3147; em[3099] = 128; 
    	em[3100] = 3180; em[3101] = 136; 
    em[3102] = 1; em[3103] = 8; em[3104] = 1; /* 3102: pointer.struct.bignum_st */
    	em[3105] = 3107; em[3106] = 0; 
    em[3107] = 0; em[3108] = 24; em[3109] = 1; /* 3107: struct.bignum_st */
    	em[3110] = 3112; em[3111] = 0; 
    em[3112] = 8884099; em[3113] = 8; em[3114] = 2; /* 3112: pointer_to_array_of_pointers_to_stack */
    	em[3115] = 1924; em[3116] = 0; 
    	em[3117] = 246; em[3118] = 12; 
    em[3119] = 1; em[3120] = 8; em[3121] = 1; /* 3119: pointer.struct.bn_mont_ctx_st */
    	em[3122] = 3124; em[3123] = 0; 
    em[3124] = 0; em[3125] = 96; em[3126] = 3; /* 3124: struct.bn_mont_ctx_st */
    	em[3127] = 3107; em[3128] = 8; 
    	em[3129] = 3107; em[3130] = 32; 
    	em[3131] = 3107; em[3132] = 56; 
    em[3133] = 0; em[3134] = 32; em[3135] = 2; /* 3133: struct.crypto_ex_data_st_fake */
    	em[3136] = 3140; em[3137] = 8; 
    	em[3138] = 249; em[3139] = 24; 
    em[3140] = 8884099; em[3141] = 8; em[3142] = 2; /* 3140: pointer_to_array_of_pointers_to_stack */
    	em[3143] = 1898; em[3144] = 0; 
    	em[3145] = 246; em[3146] = 20; 
    em[3147] = 1; em[3148] = 8; em[3149] = 1; /* 3147: pointer.struct.dh_method */
    	em[3150] = 3152; em[3151] = 0; 
    em[3152] = 0; em[3153] = 72; em[3154] = 8; /* 3152: struct.dh_method */
    	em[3155] = 26; em[3156] = 0; 
    	em[3157] = 3171; em[3158] = 8; 
    	em[3159] = 3174; em[3160] = 16; 
    	em[3161] = 2732; em[3162] = 24; 
    	em[3163] = 3171; em[3164] = 32; 
    	em[3165] = 3171; em[3166] = 40; 
    	em[3167] = 92; em[3168] = 56; 
    	em[3169] = 3177; em[3170] = 64; 
    em[3171] = 8884097; em[3172] = 8; em[3173] = 0; /* 3171: pointer.func */
    em[3174] = 8884097; em[3175] = 8; em[3176] = 0; /* 3174: pointer.func */
    em[3177] = 8884097; em[3178] = 8; em[3179] = 0; /* 3177: pointer.func */
    em[3180] = 1; em[3181] = 8; em[3182] = 1; /* 3180: pointer.struct.engine_st */
    	em[3183] = 2513; em[3184] = 0; 
    em[3185] = 1; em[3186] = 8; em[3187] = 1; /* 3185: pointer.struct.ec_key_st */
    	em[3188] = 3190; em[3189] = 0; 
    em[3190] = 0; em[3191] = 56; em[3192] = 4; /* 3190: struct.ec_key_st */
    	em[3193] = 3201; em[3194] = 8; 
    	em[3195] = 1927; em[3196] = 16; 
    	em[3197] = 3398; em[3198] = 24; 
    	em[3199] = 1907; em[3200] = 48; 
    em[3201] = 1; em[3202] = 8; em[3203] = 1; /* 3201: pointer.struct.ec_group_st */
    	em[3204] = 3206; em[3205] = 0; 
    em[3206] = 0; em[3207] = 232; em[3208] = 12; /* 3206: struct.ec_group_st */
    	em[3209] = 3233; em[3210] = 0; 
    	em[3211] = 3393; em[3212] = 8; 
    	em[3213] = 2153; em[3214] = 16; 
    	em[3215] = 2153; em[3216] = 40; 
    	em[3217] = 107; em[3218] = 80; 
    	em[3219] = 2148; em[3220] = 96; 
    	em[3221] = 2153; em[3222] = 104; 
    	em[3223] = 2153; em[3224] = 152; 
    	em[3225] = 2153; em[3226] = 176; 
    	em[3227] = 1898; em[3228] = 208; 
    	em[3229] = 1898; em[3230] = 216; 
    	em[3231] = 2127; em[3232] = 224; 
    em[3233] = 1; em[3234] = 8; em[3235] = 1; /* 3233: pointer.struct.ec_method_st */
    	em[3236] = 3238; em[3237] = 0; 
    em[3238] = 0; em[3239] = 304; em[3240] = 37; /* 3238: struct.ec_method_st */
    	em[3241] = 3315; em[3242] = 8; 
    	em[3243] = 3318; em[3244] = 16; 
    	em[3245] = 3318; em[3246] = 24; 
    	em[3247] = 3321; em[3248] = 32; 
    	em[3249] = 2354; em[3250] = 40; 
    	em[3251] = 3324; em[3252] = 48; 
    	em[3253] = 3327; em[3254] = 56; 
    	em[3255] = 3330; em[3256] = 64; 
    	em[3257] = 3333; em[3258] = 72; 
    	em[3259] = 3336; em[3260] = 80; 
    	em[3261] = 3336; em[3262] = 88; 
    	em[3263] = 3339; em[3264] = 96; 
    	em[3265] = 3342; em[3266] = 104; 
    	em[3267] = 3345; em[3268] = 112; 
    	em[3269] = 3348; em[3270] = 120; 
    	em[3271] = 3351; em[3272] = 128; 
    	em[3273] = 3354; em[3274] = 136; 
    	em[3275] = 2249; em[3276] = 144; 
    	em[3277] = 3357; em[3278] = 152; 
    	em[3279] = 3360; em[3280] = 160; 
    	em[3281] = 3363; em[3282] = 168; 
    	em[3283] = 3366; em[3284] = 176; 
    	em[3285] = 3369; em[3286] = 184; 
    	em[3287] = 2735; em[3288] = 192; 
    	em[3289] = 3372; em[3290] = 200; 
    	em[3291] = 3375; em[3292] = 208; 
    	em[3293] = 3369; em[3294] = 216; 
    	em[3295] = 3378; em[3296] = 224; 
    	em[3297] = 3381; em[3298] = 232; 
    	em[3299] = 3384; em[3300] = 240; 
    	em[3301] = 3327; em[3302] = 248; 
    	em[3303] = 3387; em[3304] = 256; 
    	em[3305] = 3390; em[3306] = 264; 
    	em[3307] = 3387; em[3308] = 272; 
    	em[3309] = 3390; em[3310] = 280; 
    	em[3311] = 3390; em[3312] = 288; 
    	em[3313] = 2383; em[3314] = 296; 
    em[3315] = 8884097; em[3316] = 8; em[3317] = 0; /* 3315: pointer.func */
    em[3318] = 8884097; em[3319] = 8; em[3320] = 0; /* 3318: pointer.func */
    em[3321] = 8884097; em[3322] = 8; em[3323] = 0; /* 3321: pointer.func */
    em[3324] = 8884097; em[3325] = 8; em[3326] = 0; /* 3324: pointer.func */
    em[3327] = 8884097; em[3328] = 8; em[3329] = 0; /* 3327: pointer.func */
    em[3330] = 8884097; em[3331] = 8; em[3332] = 0; /* 3330: pointer.func */
    em[3333] = 8884097; em[3334] = 8; em[3335] = 0; /* 3333: pointer.func */
    em[3336] = 8884097; em[3337] = 8; em[3338] = 0; /* 3336: pointer.func */
    em[3339] = 8884097; em[3340] = 8; em[3341] = 0; /* 3339: pointer.func */
    em[3342] = 8884097; em[3343] = 8; em[3344] = 0; /* 3342: pointer.func */
    em[3345] = 8884097; em[3346] = 8; em[3347] = 0; /* 3345: pointer.func */
    em[3348] = 8884097; em[3349] = 8; em[3350] = 0; /* 3348: pointer.func */
    em[3351] = 8884097; em[3352] = 8; em[3353] = 0; /* 3351: pointer.func */
    em[3354] = 8884097; em[3355] = 8; em[3356] = 0; /* 3354: pointer.func */
    em[3357] = 8884097; em[3358] = 8; em[3359] = 0; /* 3357: pointer.func */
    em[3360] = 8884097; em[3361] = 8; em[3362] = 0; /* 3360: pointer.func */
    em[3363] = 8884097; em[3364] = 8; em[3365] = 0; /* 3363: pointer.func */
    em[3366] = 8884097; em[3367] = 8; em[3368] = 0; /* 3366: pointer.func */
    em[3369] = 8884097; em[3370] = 8; em[3371] = 0; /* 3369: pointer.func */
    em[3372] = 8884097; em[3373] = 8; em[3374] = 0; /* 3372: pointer.func */
    em[3375] = 8884097; em[3376] = 8; em[3377] = 0; /* 3375: pointer.func */
    em[3378] = 8884097; em[3379] = 8; em[3380] = 0; /* 3378: pointer.func */
    em[3381] = 8884097; em[3382] = 8; em[3383] = 0; /* 3381: pointer.func */
    em[3384] = 8884097; em[3385] = 8; em[3386] = 0; /* 3384: pointer.func */
    em[3387] = 8884097; em[3388] = 8; em[3389] = 0; /* 3387: pointer.func */
    em[3390] = 8884097; em[3391] = 8; em[3392] = 0; /* 3390: pointer.func */
    em[3393] = 1; em[3394] = 8; em[3395] = 1; /* 3393: pointer.struct.ec_point_st */
    	em[3396] = 1932; em[3397] = 0; 
    em[3398] = 1; em[3399] = 8; em[3400] = 1; /* 3398: pointer.struct.bignum_st */
    	em[3401] = 1912; em[3402] = 0; 
    em[3403] = 0; em[3404] = 1; em[3405] = 0; /* 3403: char */
    em[3406] = 1; em[3407] = 8; em[3408] = 1; /* 3406: pointer.struct.buf_mem_st */
    	em[3409] = 3411; em[3410] = 0; 
    em[3411] = 0; em[3412] = 24; em[3413] = 1; /* 3411: struct.buf_mem_st */
    	em[3414] = 92; em[3415] = 8; 
    em[3416] = 1; em[3417] = 8; em[3418] = 1; /* 3416: pointer.struct.stack_st_X509_EXTENSION */
    	em[3419] = 3421; em[3420] = 0; 
    em[3421] = 0; em[3422] = 32; em[3423] = 2; /* 3421: struct.stack_st_fake_X509_EXTENSION */
    	em[3424] = 3428; em[3425] = 8; 
    	em[3426] = 249; em[3427] = 24; 
    em[3428] = 8884099; em[3429] = 8; em[3430] = 2; /* 3428: pointer_to_array_of_pointers_to_stack */
    	em[3431] = 3435; em[3432] = 0; 
    	em[3433] = 246; em[3434] = 20; 
    em[3435] = 0; em[3436] = 8; em[3437] = 1; /* 3435: pointer.X509_EXTENSION */
    	em[3438] = 1504; em[3439] = 0; 
    em[3440] = 1; em[3441] = 8; em[3442] = 1; /* 3440: pointer.struct.X509_algor_st */
    	em[3443] = 5; em[3444] = 0; 
    em[3445] = 1; em[3446] = 8; em[3447] = 1; /* 3445: pointer.struct.x509_st */
    	em[3448] = 3450; em[3449] = 0; 
    em[3450] = 0; em[3451] = 184; em[3452] = 12; /* 3450: struct.x509_st */
    	em[3453] = 3477; em[3454] = 0; 
    	em[3455] = 3440; em[3456] = 8; 
    	em[3457] = 2727; em[3458] = 16; 
    	em[3459] = 92; em[3460] = 32; 
    	em[3461] = 3560; em[3462] = 40; 
    	em[3463] = 262; em[3464] = 104; 
    	em[3465] = 2714; em[3466] = 112; 
    	em[3467] = 3574; em[3468] = 120; 
    	em[3469] = 1037; em[3470] = 128; 
    	em[3471] = 647; em[3472] = 136; 
    	em[3473] = 642; em[3474] = 144; 
    	em[3475] = 190; em[3476] = 176; 
    em[3477] = 1; em[3478] = 8; em[3479] = 1; /* 3477: pointer.struct.x509_cinf_st */
    	em[3480] = 3482; em[3481] = 0; 
    em[3482] = 0; em[3483] = 104; em[3484] = 11; /* 3482: struct.x509_cinf_st */
    	em[3485] = 3507; em[3486] = 0; 
    	em[3487] = 3507; em[3488] = 8; 
    	em[3489] = 3440; em[3490] = 16; 
    	em[3491] = 3512; em[3492] = 24; 
    	em[3493] = 2177; em[3494] = 32; 
    	em[3495] = 3512; em[3496] = 40; 
    	em[3497] = 3550; em[3498] = 48; 
    	em[3499] = 2727; em[3500] = 56; 
    	em[3501] = 2727; em[3502] = 64; 
    	em[3503] = 3416; em[3504] = 72; 
    	em[3505] = 3555; em[3506] = 80; 
    em[3507] = 1; em[3508] = 8; em[3509] = 1; /* 3507: pointer.struct.asn1_string_st */
    	em[3510] = 257; em[3511] = 0; 
    em[3512] = 1; em[3513] = 8; em[3514] = 1; /* 3512: pointer.struct.X509_name_st */
    	em[3515] = 3517; em[3516] = 0; 
    em[3517] = 0; em[3518] = 40; em[3519] = 3; /* 3517: struct.X509_name_st */
    	em[3520] = 3526; em[3521] = 0; 
    	em[3522] = 3406; em[3523] = 16; 
    	em[3524] = 107; em[3525] = 24; 
    em[3526] = 1; em[3527] = 8; em[3528] = 1; /* 3526: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3529] = 3531; em[3530] = 0; 
    em[3531] = 0; em[3532] = 32; em[3533] = 2; /* 3531: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3534] = 3538; em[3535] = 8; 
    	em[3536] = 249; em[3537] = 24; 
    em[3538] = 8884099; em[3539] = 8; em[3540] = 2; /* 3538: pointer_to_array_of_pointers_to_stack */
    	em[3541] = 3545; em[3542] = 0; 
    	em[3543] = 246; em[3544] = 20; 
    em[3545] = 0; em[3546] = 8; em[3547] = 1; /* 3545: pointer.X509_NAME_ENTRY */
    	em[3548] = 332; em[3549] = 0; 
    em[3550] = 1; em[3551] = 8; em[3552] = 1; /* 3550: pointer.struct.X509_pubkey_st */
    	em[3553] = 2835; em[3554] = 0; 
    em[3555] = 0; em[3556] = 24; em[3557] = 1; /* 3555: struct.ASN1_ENCODING_st */
    	em[3558] = 107; em[3559] = 0; 
    em[3560] = 0; em[3561] = 32; em[3562] = 2; /* 3560: struct.crypto_ex_data_st_fake */
    	em[3563] = 3567; em[3564] = 8; 
    	em[3565] = 249; em[3566] = 24; 
    em[3567] = 8884099; em[3568] = 8; em[3569] = 2; /* 3567: pointer_to_array_of_pointers_to_stack */
    	em[3570] = 1898; em[3571] = 0; 
    	em[3572] = 246; em[3573] = 20; 
    em[3574] = 1; em[3575] = 8; em[3576] = 1; /* 3574: pointer.struct.X509_POLICY_CACHE_st */
    	em[3577] = 3579; em[3578] = 0; 
    em[3579] = 0; em[3580] = 40; em[3581] = 2; /* 3579: struct.X509_POLICY_CACHE_st */
    	em[3582] = 3586; em[3583] = 0; 
    	em[3584] = 1382; em[3585] = 8; 
    em[3586] = 1; em[3587] = 8; em[3588] = 1; /* 3586: pointer.struct.X509_POLICY_DATA_st */
    	em[3589] = 1454; em[3590] = 0; 
    em[3591] = 1; em[3592] = 8; em[3593] = 1; /* 3591: pointer.int */
    	em[3594] = 246; em[3595] = 0; 
    args_addr->arg_entity_index[0] = 3445;
    args_addr->arg_entity_index[1] = 246;
    args_addr->arg_entity_index[2] = 3591;
    args_addr->arg_entity_index[3] = 3591;
    args_addr->ret_entity_index = 1898;
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

