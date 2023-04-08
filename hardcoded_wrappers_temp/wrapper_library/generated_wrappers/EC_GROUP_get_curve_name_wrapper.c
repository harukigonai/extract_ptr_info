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

int bb_EC_GROUP_get_curve_name(const EC_GROUP * arg_a);

int EC_GROUP_get_curve_name(const EC_GROUP * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_GROUP_get_curve_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_GROUP_get_curve_name(arg_a);
    else {
        int (*orig_EC_GROUP_get_curve_name)(const EC_GROUP *);
        orig_EC_GROUP_get_curve_name = dlsym(RTLD_NEXT, "EC_GROUP_get_curve_name");
        return orig_EC_GROUP_get_curve_name(arg_a);
    }
}

int bb_EC_GROUP_get_curve_name(const EC_GROUP * arg_a) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 8884097; em[4] = 8; em[5] = 0; /* 3: pointer.func */
    em[6] = 0; em[7] = 8; em[8] = 0; /* 6: pointer.void */
    em[9] = 1; em[10] = 8; em[11] = 1; /* 9: pointer.struct.ec_extra_data_st */
    	em[12] = 14; em[13] = 0; 
    em[14] = 0; em[15] = 40; em[16] = 5; /* 14: struct.ec_extra_data_st */
    	em[17] = 9; em[18] = 0; 
    	em[19] = 6; em[20] = 8; 
    	em[21] = 3; em[22] = 16; 
    	em[23] = 27; em[24] = 24; 
    	em[25] = 27; em[26] = 32; 
    em[27] = 8884097; em[28] = 8; em[29] = 0; /* 27: pointer.func */
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.struct.ec_extra_data_st */
    	em[33] = 14; em[34] = 0; 
    em[35] = 1; em[36] = 8; em[37] = 1; /* 35: pointer.unsigned char */
    	em[38] = 40; em[39] = 0; 
    em[40] = 0; em[41] = 1; em[42] = 0; /* 40: unsigned char */
    em[43] = 0; em[44] = 24; em[45] = 1; /* 43: struct.bignum_st */
    	em[46] = 48; em[47] = 0; 
    em[48] = 8884099; em[49] = 8; em[50] = 2; /* 48: pointer_to_array_of_pointers_to_stack */
    	em[51] = 55; em[52] = 0; 
    	em[53] = 58; em[54] = 12; 
    em[55] = 0; em[56] = 8; em[57] = 0; /* 55: long unsigned int */
    em[58] = 0; em[59] = 4; em[60] = 0; /* 58: int */
    em[61] = 8884097; em[62] = 8; em[63] = 0; /* 61: pointer.func */
    em[64] = 8884097; em[65] = 8; em[66] = 0; /* 64: pointer.func */
    em[67] = 8884097; em[68] = 8; em[69] = 0; /* 67: pointer.func */
    em[70] = 8884097; em[71] = 8; em[72] = 0; /* 70: pointer.func */
    em[73] = 8884097; em[74] = 8; em[75] = 0; /* 73: pointer.func */
    em[76] = 8884097; em[77] = 8; em[78] = 0; /* 76: pointer.func */
    em[79] = 8884097; em[80] = 8; em[81] = 0; /* 79: pointer.func */
    em[82] = 8884097; em[83] = 8; em[84] = 0; /* 82: pointer.func */
    em[85] = 8884097; em[86] = 8; em[87] = 0; /* 85: pointer.func */
    em[88] = 8884097; em[89] = 8; em[90] = 0; /* 88: pointer.func */
    em[91] = 0; em[92] = 24; em[93] = 1; /* 91: struct.bignum_st */
    	em[94] = 96; em[95] = 0; 
    em[96] = 8884099; em[97] = 8; em[98] = 2; /* 96: pointer_to_array_of_pointers_to_stack */
    	em[99] = 55; em[100] = 0; 
    	em[101] = 58; em[102] = 12; 
    em[103] = 8884097; em[104] = 8; em[105] = 0; /* 103: pointer.func */
    em[106] = 8884097; em[107] = 8; em[108] = 0; /* 106: pointer.func */
    em[109] = 8884097; em[110] = 8; em[111] = 0; /* 109: pointer.func */
    em[112] = 0; em[113] = 304; em[114] = 37; /* 112: struct.ec_method_st */
    	em[115] = 189; em[116] = 8; 
    	em[117] = 192; em[118] = 16; 
    	em[119] = 192; em[120] = 24; 
    	em[121] = 195; em[122] = 32; 
    	em[123] = 198; em[124] = 40; 
    	em[125] = 201; em[126] = 48; 
    	em[127] = 204; em[128] = 56; 
    	em[129] = 207; em[130] = 64; 
    	em[131] = 210; em[132] = 72; 
    	em[133] = 213; em[134] = 80; 
    	em[135] = 213; em[136] = 88; 
    	em[137] = 216; em[138] = 96; 
    	em[139] = 219; em[140] = 104; 
    	em[141] = 222; em[142] = 112; 
    	em[143] = 225; em[144] = 120; 
    	em[145] = 228; em[146] = 128; 
    	em[147] = 231; em[148] = 136; 
    	em[149] = 109; em[150] = 144; 
    	em[151] = 234; em[152] = 152; 
    	em[153] = 237; em[154] = 160; 
    	em[155] = 240; em[156] = 168; 
    	em[157] = 243; em[158] = 176; 
    	em[159] = 246; em[160] = 184; 
    	em[161] = 249; em[162] = 192; 
    	em[163] = 85; em[164] = 200; 
    	em[165] = 252; em[166] = 208; 
    	em[167] = 246; em[168] = 216; 
    	em[169] = 255; em[170] = 224; 
    	em[171] = 258; em[172] = 232; 
    	em[173] = 261; em[174] = 240; 
    	em[175] = 204; em[176] = 248; 
    	em[177] = 264; em[178] = 256; 
    	em[179] = 267; em[180] = 264; 
    	em[181] = 264; em[182] = 272; 
    	em[183] = 267; em[184] = 280; 
    	em[185] = 267; em[186] = 288; 
    	em[187] = 270; em[188] = 296; 
    em[189] = 8884097; em[190] = 8; em[191] = 0; /* 189: pointer.func */
    em[192] = 8884097; em[193] = 8; em[194] = 0; /* 192: pointer.func */
    em[195] = 8884097; em[196] = 8; em[197] = 0; /* 195: pointer.func */
    em[198] = 8884097; em[199] = 8; em[200] = 0; /* 198: pointer.func */
    em[201] = 8884097; em[202] = 8; em[203] = 0; /* 201: pointer.func */
    em[204] = 8884097; em[205] = 8; em[206] = 0; /* 204: pointer.func */
    em[207] = 8884097; em[208] = 8; em[209] = 0; /* 207: pointer.func */
    em[210] = 8884097; em[211] = 8; em[212] = 0; /* 210: pointer.func */
    em[213] = 8884097; em[214] = 8; em[215] = 0; /* 213: pointer.func */
    em[216] = 8884097; em[217] = 8; em[218] = 0; /* 216: pointer.func */
    em[219] = 8884097; em[220] = 8; em[221] = 0; /* 219: pointer.func */
    em[222] = 8884097; em[223] = 8; em[224] = 0; /* 222: pointer.func */
    em[225] = 8884097; em[226] = 8; em[227] = 0; /* 225: pointer.func */
    em[228] = 8884097; em[229] = 8; em[230] = 0; /* 228: pointer.func */
    em[231] = 8884097; em[232] = 8; em[233] = 0; /* 231: pointer.func */
    em[234] = 8884097; em[235] = 8; em[236] = 0; /* 234: pointer.func */
    em[237] = 8884097; em[238] = 8; em[239] = 0; /* 237: pointer.func */
    em[240] = 8884097; em[241] = 8; em[242] = 0; /* 240: pointer.func */
    em[243] = 8884097; em[244] = 8; em[245] = 0; /* 243: pointer.func */
    em[246] = 8884097; em[247] = 8; em[248] = 0; /* 246: pointer.func */
    em[249] = 8884097; em[250] = 8; em[251] = 0; /* 249: pointer.func */
    em[252] = 8884097; em[253] = 8; em[254] = 0; /* 252: pointer.func */
    em[255] = 8884097; em[256] = 8; em[257] = 0; /* 255: pointer.func */
    em[258] = 8884097; em[259] = 8; em[260] = 0; /* 258: pointer.func */
    em[261] = 8884097; em[262] = 8; em[263] = 0; /* 261: pointer.func */
    em[264] = 8884097; em[265] = 8; em[266] = 0; /* 264: pointer.func */
    em[267] = 8884097; em[268] = 8; em[269] = 0; /* 267: pointer.func */
    em[270] = 8884097; em[271] = 8; em[272] = 0; /* 270: pointer.func */
    em[273] = 0; em[274] = 88; em[275] = 4; /* 273: struct.ec_point_st */
    	em[276] = 284; em[277] = 0; 
    	em[278] = 91; em[279] = 8; 
    	em[280] = 91; em[281] = 32; 
    	em[282] = 91; em[283] = 56; 
    em[284] = 1; em[285] = 8; em[286] = 1; /* 284: pointer.struct.ec_method_st */
    	em[287] = 289; em[288] = 0; 
    em[289] = 0; em[290] = 304; em[291] = 37; /* 289: struct.ec_method_st */
    	em[292] = 366; em[293] = 8; 
    	em[294] = 88; em[295] = 16; 
    	em[296] = 88; em[297] = 24; 
    	em[298] = 369; em[299] = 32; 
    	em[300] = 372; em[301] = 40; 
    	em[302] = 375; em[303] = 48; 
    	em[304] = 378; em[305] = 56; 
    	em[306] = 381; em[307] = 64; 
    	em[308] = 384; em[309] = 72; 
    	em[310] = 387; em[311] = 80; 
    	em[312] = 387; em[313] = 88; 
    	em[314] = 390; em[315] = 96; 
    	em[316] = 393; em[317] = 104; 
    	em[318] = 396; em[319] = 112; 
    	em[320] = 399; em[321] = 120; 
    	em[322] = 402; em[323] = 128; 
    	em[324] = 405; em[325] = 136; 
    	em[326] = 408; em[327] = 144; 
    	em[328] = 411; em[329] = 152; 
    	em[330] = 106; em[331] = 160; 
    	em[332] = 103; em[333] = 168; 
    	em[334] = 414; em[335] = 176; 
    	em[336] = 417; em[337] = 184; 
    	em[338] = 82; em[339] = 192; 
    	em[340] = 79; em[341] = 200; 
    	em[342] = 76; em[343] = 208; 
    	em[344] = 417; em[345] = 216; 
    	em[346] = 73; em[347] = 224; 
    	em[348] = 70; em[349] = 232; 
    	em[350] = 67; em[351] = 240; 
    	em[352] = 378; em[353] = 248; 
    	em[354] = 64; em[355] = 256; 
    	em[356] = 420; em[357] = 264; 
    	em[358] = 64; em[359] = 272; 
    	em[360] = 420; em[361] = 280; 
    	em[362] = 420; em[363] = 288; 
    	em[364] = 61; em[365] = 296; 
    em[366] = 8884097; em[367] = 8; em[368] = 0; /* 366: pointer.func */
    em[369] = 8884097; em[370] = 8; em[371] = 0; /* 369: pointer.func */
    em[372] = 8884097; em[373] = 8; em[374] = 0; /* 372: pointer.func */
    em[375] = 8884097; em[376] = 8; em[377] = 0; /* 375: pointer.func */
    em[378] = 8884097; em[379] = 8; em[380] = 0; /* 378: pointer.func */
    em[381] = 8884097; em[382] = 8; em[383] = 0; /* 381: pointer.func */
    em[384] = 8884097; em[385] = 8; em[386] = 0; /* 384: pointer.func */
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 8884097; em[391] = 8; em[392] = 0; /* 390: pointer.func */
    em[393] = 8884097; em[394] = 8; em[395] = 0; /* 393: pointer.func */
    em[396] = 8884097; em[397] = 8; em[398] = 0; /* 396: pointer.func */
    em[399] = 8884097; em[400] = 8; em[401] = 0; /* 399: pointer.func */
    em[402] = 8884097; em[403] = 8; em[404] = 0; /* 402: pointer.func */
    em[405] = 8884097; em[406] = 8; em[407] = 0; /* 405: pointer.func */
    em[408] = 8884097; em[409] = 8; em[410] = 0; /* 408: pointer.func */
    em[411] = 8884097; em[412] = 8; em[413] = 0; /* 411: pointer.func */
    em[414] = 8884097; em[415] = 8; em[416] = 0; /* 414: pointer.func */
    em[417] = 8884097; em[418] = 8; em[419] = 0; /* 417: pointer.func */
    em[420] = 8884097; em[421] = 8; em[422] = 0; /* 420: pointer.func */
    em[423] = 1; em[424] = 8; em[425] = 1; /* 423: pointer.struct.ec_group_st */
    	em[426] = 428; em[427] = 0; 
    em[428] = 0; em[429] = 232; em[430] = 12; /* 428: struct.ec_group_st */
    	em[431] = 455; em[432] = 0; 
    	em[433] = 460; em[434] = 8; 
    	em[435] = 43; em[436] = 16; 
    	em[437] = 43; em[438] = 40; 
    	em[439] = 35; em[440] = 80; 
    	em[441] = 30; em[442] = 96; 
    	em[443] = 43; em[444] = 104; 
    	em[445] = 43; em[446] = 152; 
    	em[447] = 43; em[448] = 176; 
    	em[449] = 6; em[450] = 208; 
    	em[451] = 6; em[452] = 216; 
    	em[453] = 0; em[454] = 224; 
    em[455] = 1; em[456] = 8; em[457] = 1; /* 455: pointer.struct.ec_method_st */
    	em[458] = 112; em[459] = 0; 
    em[460] = 1; em[461] = 8; em[462] = 1; /* 460: pointer.struct.ec_point_st */
    	em[463] = 273; em[464] = 0; 
    args_addr->arg_entity_index[0] = 423;
    args_addr->ret_entity_index = 58;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EC_GROUP * new_arg_a = *((const EC_GROUP * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EC_GROUP_get_curve_name)(const EC_GROUP *);
    orig_EC_GROUP_get_curve_name = dlsym(RTLD_NEXT, "EC_GROUP_get_curve_name");
    *new_ret_ptr = (*orig_EC_GROUP_get_curve_name)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

