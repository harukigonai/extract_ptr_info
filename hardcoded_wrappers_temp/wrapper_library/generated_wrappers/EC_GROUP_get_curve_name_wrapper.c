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
    em[3] = 1; em[4] = 8; em[5] = 1; /* 3: pointer.struct.ec_extra_data_st */
    	em[6] = 8; em[7] = 0; 
    em[8] = 0; em[9] = 40; em[10] = 5; /* 8: struct.ec_extra_data_st */
    	em[11] = 3; em[12] = 0; 
    	em[13] = 21; em[14] = 8; 
    	em[15] = 24; em[16] = 16; 
    	em[17] = 27; em[18] = 24; 
    	em[19] = 27; em[20] = 32; 
    em[21] = 0; em[22] = 8; em[23] = 0; /* 21: pointer.void */
    em[24] = 8884097; em[25] = 8; em[26] = 0; /* 24: pointer.func */
    em[27] = 8884097; em[28] = 8; em[29] = 0; /* 27: pointer.func */
    em[30] = 8884097; em[31] = 8; em[32] = 0; /* 30: pointer.func */
    em[33] = 8884097; em[34] = 8; em[35] = 0; /* 33: pointer.func */
    em[36] = 8884097; em[37] = 8; em[38] = 0; /* 36: pointer.func */
    em[39] = 8884097; em[40] = 8; em[41] = 0; /* 39: pointer.func */
    em[42] = 8884097; em[43] = 8; em[44] = 0; /* 42: pointer.func */
    em[45] = 8884097; em[46] = 8; em[47] = 0; /* 45: pointer.func */
    em[48] = 8884097; em[49] = 8; em[50] = 0; /* 48: pointer.func */
    em[51] = 8884097; em[52] = 8; em[53] = 0; /* 51: pointer.func */
    em[54] = 8884097; em[55] = 8; em[56] = 0; /* 54: pointer.func */
    em[57] = 1; em[58] = 8; em[59] = 1; /* 57: pointer.unsigned char */
    	em[60] = 62; em[61] = 0; 
    em[62] = 0; em[63] = 1; em[64] = 0; /* 62: unsigned char */
    em[65] = 8884097; em[66] = 8; em[67] = 0; /* 65: pointer.func */
    em[68] = 8884097; em[69] = 8; em[70] = 0; /* 68: pointer.func */
    em[71] = 8884097; em[72] = 8; em[73] = 0; /* 71: pointer.func */
    em[74] = 0; em[75] = 24; em[76] = 1; /* 74: struct.bignum_st */
    	em[77] = 79; em[78] = 0; 
    em[79] = 8884099; em[80] = 8; em[81] = 2; /* 79: pointer_to_array_of_pointers_to_stack */
    	em[82] = 86; em[83] = 0; 
    	em[84] = 89; em[85] = 12; 
    em[86] = 0; em[87] = 8; em[88] = 0; /* 86: long unsigned int */
    em[89] = 0; em[90] = 4; em[91] = 0; /* 89: int */
    em[92] = 8884097; em[93] = 8; em[94] = 0; /* 92: pointer.func */
    em[95] = 8884097; em[96] = 8; em[97] = 0; /* 95: pointer.func */
    em[98] = 0; em[99] = 24; em[100] = 1; /* 98: struct.bignum_st */
    	em[101] = 103; em[102] = 0; 
    em[103] = 8884099; em[104] = 8; em[105] = 2; /* 103: pointer_to_array_of_pointers_to_stack */
    	em[106] = 86; em[107] = 0; 
    	em[108] = 89; em[109] = 12; 
    em[110] = 8884097; em[111] = 8; em[112] = 0; /* 110: pointer.func */
    em[113] = 8884097; em[114] = 8; em[115] = 0; /* 113: pointer.func */
    em[116] = 8884097; em[117] = 8; em[118] = 0; /* 116: pointer.func */
    em[119] = 8884097; em[120] = 8; em[121] = 0; /* 119: pointer.func */
    em[122] = 8884097; em[123] = 8; em[124] = 0; /* 122: pointer.func */
    em[125] = 8884097; em[126] = 8; em[127] = 0; /* 125: pointer.func */
    em[128] = 8884097; em[129] = 8; em[130] = 0; /* 128: pointer.func */
    em[131] = 8884097; em[132] = 8; em[133] = 0; /* 131: pointer.func */
    em[134] = 8884097; em[135] = 8; em[136] = 0; /* 134: pointer.func */
    em[137] = 8884097; em[138] = 8; em[139] = 0; /* 137: pointer.func */
    em[140] = 8884097; em[141] = 8; em[142] = 0; /* 140: pointer.func */
    em[143] = 8884097; em[144] = 8; em[145] = 0; /* 143: pointer.func */
    em[146] = 8884097; em[147] = 8; em[148] = 0; /* 146: pointer.func */
    em[149] = 8884097; em[150] = 8; em[151] = 0; /* 149: pointer.func */
    em[152] = 1; em[153] = 8; em[154] = 1; /* 152: pointer.struct.ec_point_st */
    	em[155] = 157; em[156] = 0; 
    em[157] = 0; em[158] = 88; em[159] = 4; /* 157: struct.ec_point_st */
    	em[160] = 168; em[161] = 0; 
    	em[162] = 98; em[163] = 8; 
    	em[164] = 98; em[165] = 32; 
    	em[166] = 98; em[167] = 56; 
    em[168] = 1; em[169] = 8; em[170] = 1; /* 168: pointer.struct.ec_method_st */
    	em[171] = 173; em[172] = 0; 
    em[173] = 0; em[174] = 304; em[175] = 37; /* 173: struct.ec_method_st */
    	em[176] = 250; em[177] = 8; 
    	em[178] = 95; em[179] = 16; 
    	em[180] = 95; em[181] = 24; 
    	em[182] = 253; em[183] = 32; 
    	em[184] = 256; em[185] = 40; 
    	em[186] = 259; em[187] = 48; 
    	em[188] = 262; em[189] = 56; 
    	em[190] = 131; em[191] = 64; 
    	em[192] = 265; em[193] = 72; 
    	em[194] = 140; em[195] = 80; 
    	em[196] = 140; em[197] = 88; 
    	em[198] = 268; em[199] = 96; 
    	em[200] = 271; em[201] = 104; 
    	em[202] = 274; em[203] = 112; 
    	em[204] = 277; em[205] = 120; 
    	em[206] = 280; em[207] = 128; 
    	em[208] = 283; em[209] = 136; 
    	em[210] = 286; em[211] = 144; 
    	em[212] = 289; em[213] = 152; 
    	em[214] = 292; em[215] = 160; 
    	em[216] = 110; em[217] = 168; 
    	em[218] = 295; em[219] = 176; 
    	em[220] = 298; em[221] = 184; 
    	em[222] = 51; em[223] = 192; 
    	em[224] = 48; em[225] = 200; 
    	em[226] = 45; em[227] = 208; 
    	em[228] = 298; em[229] = 216; 
    	em[230] = 42; em[231] = 224; 
    	em[232] = 39; em[233] = 232; 
    	em[234] = 36; em[235] = 240; 
    	em[236] = 262; em[237] = 248; 
    	em[238] = 33; em[239] = 256; 
    	em[240] = 301; em[241] = 264; 
    	em[242] = 33; em[243] = 272; 
    	em[244] = 301; em[245] = 280; 
    	em[246] = 301; em[247] = 288; 
    	em[248] = 30; em[249] = 296; 
    em[250] = 8884097; em[251] = 8; em[252] = 0; /* 250: pointer.func */
    em[253] = 8884097; em[254] = 8; em[255] = 0; /* 253: pointer.func */
    em[256] = 8884097; em[257] = 8; em[258] = 0; /* 256: pointer.func */
    em[259] = 8884097; em[260] = 8; em[261] = 0; /* 259: pointer.func */
    em[262] = 8884097; em[263] = 8; em[264] = 0; /* 262: pointer.func */
    em[265] = 8884097; em[266] = 8; em[267] = 0; /* 265: pointer.func */
    em[268] = 8884097; em[269] = 8; em[270] = 0; /* 268: pointer.func */
    em[271] = 8884097; em[272] = 8; em[273] = 0; /* 271: pointer.func */
    em[274] = 8884097; em[275] = 8; em[276] = 0; /* 274: pointer.func */
    em[277] = 8884097; em[278] = 8; em[279] = 0; /* 277: pointer.func */
    em[280] = 8884097; em[281] = 8; em[282] = 0; /* 280: pointer.func */
    em[283] = 8884097; em[284] = 8; em[285] = 0; /* 283: pointer.func */
    em[286] = 8884097; em[287] = 8; em[288] = 0; /* 286: pointer.func */
    em[289] = 8884097; em[290] = 8; em[291] = 0; /* 289: pointer.func */
    em[292] = 8884097; em[293] = 8; em[294] = 0; /* 292: pointer.func */
    em[295] = 8884097; em[296] = 8; em[297] = 0; /* 295: pointer.func */
    em[298] = 8884097; em[299] = 8; em[300] = 0; /* 298: pointer.func */
    em[301] = 8884097; em[302] = 8; em[303] = 0; /* 301: pointer.func */
    em[304] = 8884097; em[305] = 8; em[306] = 0; /* 304: pointer.func */
    em[307] = 1; em[308] = 8; em[309] = 1; /* 307: pointer.struct.ec_group_st */
    	em[310] = 312; em[311] = 0; 
    em[312] = 0; em[313] = 232; em[314] = 12; /* 312: struct.ec_group_st */
    	em[315] = 339; em[316] = 0; 
    	em[317] = 152; em[318] = 8; 
    	em[319] = 74; em[320] = 16; 
    	em[321] = 74; em[322] = 40; 
    	em[323] = 57; em[324] = 80; 
    	em[325] = 460; em[326] = 96; 
    	em[327] = 74; em[328] = 104; 
    	em[329] = 74; em[330] = 152; 
    	em[331] = 74; em[332] = 176; 
    	em[333] = 21; em[334] = 208; 
    	em[335] = 21; em[336] = 216; 
    	em[337] = 0; em[338] = 224; 
    em[339] = 1; em[340] = 8; em[341] = 1; /* 339: pointer.struct.ec_method_st */
    	em[342] = 344; em[343] = 0; 
    em[344] = 0; em[345] = 304; em[346] = 37; /* 344: struct.ec_method_st */
    	em[347] = 149; em[348] = 8; 
    	em[349] = 304; em[350] = 16; 
    	em[351] = 304; em[352] = 24; 
    	em[353] = 134; em[354] = 32; 
    	em[355] = 146; em[356] = 40; 
    	em[357] = 116; em[358] = 48; 
    	em[359] = 421; em[360] = 56; 
    	em[361] = 68; em[362] = 64; 
    	em[363] = 424; em[364] = 72; 
    	em[365] = 119; em[366] = 80; 
    	em[367] = 119; em[368] = 88; 
    	em[369] = 427; em[370] = 96; 
    	em[371] = 122; em[372] = 104; 
    	em[373] = 430; em[374] = 112; 
    	em[375] = 92; em[376] = 120; 
    	em[377] = 128; em[378] = 128; 
    	em[379] = 65; em[380] = 136; 
    	em[381] = 433; em[382] = 144; 
    	em[383] = 143; em[384] = 152; 
    	em[385] = 113; em[386] = 160; 
    	em[387] = 71; em[388] = 168; 
    	em[389] = 137; em[390] = 176; 
    	em[391] = 436; em[392] = 184; 
    	em[393] = 439; em[394] = 192; 
    	em[395] = 54; em[396] = 200; 
    	em[397] = 125; em[398] = 208; 
    	em[399] = 436; em[400] = 216; 
    	em[401] = 442; em[402] = 224; 
    	em[403] = 445; em[404] = 232; 
    	em[405] = 448; em[406] = 240; 
    	em[407] = 421; em[408] = 248; 
    	em[409] = 451; em[410] = 256; 
    	em[411] = 454; em[412] = 264; 
    	em[413] = 451; em[414] = 272; 
    	em[415] = 454; em[416] = 280; 
    	em[417] = 454; em[418] = 288; 
    	em[419] = 457; em[420] = 296; 
    em[421] = 8884097; em[422] = 8; em[423] = 0; /* 421: pointer.func */
    em[424] = 8884097; em[425] = 8; em[426] = 0; /* 424: pointer.func */
    em[427] = 8884097; em[428] = 8; em[429] = 0; /* 427: pointer.func */
    em[430] = 8884097; em[431] = 8; em[432] = 0; /* 430: pointer.func */
    em[433] = 8884097; em[434] = 8; em[435] = 0; /* 433: pointer.func */
    em[436] = 8884097; em[437] = 8; em[438] = 0; /* 436: pointer.func */
    em[439] = 8884097; em[440] = 8; em[441] = 0; /* 439: pointer.func */
    em[442] = 8884097; em[443] = 8; em[444] = 0; /* 442: pointer.func */
    em[445] = 8884097; em[446] = 8; em[447] = 0; /* 445: pointer.func */
    em[448] = 8884097; em[449] = 8; em[450] = 0; /* 448: pointer.func */
    em[451] = 8884097; em[452] = 8; em[453] = 0; /* 451: pointer.func */
    em[454] = 8884097; em[455] = 8; em[456] = 0; /* 454: pointer.func */
    em[457] = 8884097; em[458] = 8; em[459] = 0; /* 457: pointer.func */
    em[460] = 1; em[461] = 8; em[462] = 1; /* 460: pointer.struct.ec_extra_data_st */
    	em[463] = 8; em[464] = 0; 
    args_addr->arg_entity_index[0] = 307;
    args_addr->ret_entity_index = 89;
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

