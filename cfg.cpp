#line 1 "cfg.rl"
// Copyright 2016-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <string>
#include <cstdio>
#include <nk/scopeguard.hpp>
#include <nk/from_string.hpp>
#include "dhcp_state.hpp"
extern "C" {
#include "nk/log.h"
}
extern void set_user_runas(size_t linenum, std::string &&username);
extern void set_chroot_path(size_t linenum, std::string &&path);
extern void set_s6_notify_fd(size_t linenum, int fd);

#define MAX_LINE 2048

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

extern void create_dns_search_blob();

struct cfg_parse_state {
	cfg_parse_state() : st(nullptr), cs(0), last_addr(addr_type::null), default_lifetime(7200),
	default_preference(0), parse_error(false) {}
	void newline() {
		duid.clear();
		iaid.clear();
		macaddr.clear();
		ipaddr.clear();
		ipaddr2.clear();
		last_addr = addr_type::null;
		parse_error = false;
	}
	const char *st;
	int cs;
	
	std::string duid;
	std::string iaid;
	std::string macaddr;
	std::string ipaddr;
	std::string ipaddr2;
	addr_type last_addr;
	std::string interface;
	uint32_t default_lifetime;
	uint8_t default_preference;
	bool parse_error;
};

#define MARKED_STRING() cps.st, (p > cps.st ? static_cast<size_t>(p - cps.st) : 0)

static inline std::string lc_string(const char *s, size_t slen)
{
	auto r = std::string(s, slen);
	for (auto &i: r) i = tolower(i);
	return r;
}


#line 168 "cfg.rl"



#line 66 "cfg.cpp"
static const int cfg_line_m_start = 161;
static const int cfg_line_m_first_final = 161;
static const int cfg_line_m_error = 0;

static const int cfg_line_m_en_main = 161;


#line 170 "cfg.rl"


static int do_parse_cfg_line(cfg_parse_state &cps, const char *p, size_t plen,
const size_t linenum)
{
	const char *pe = p + plen;
	const char *eof = pe;
	
	
#line 84 "cfg.cpp"
	{
		cps.cs = (int)cfg_line_m_start;
	}
	
#line 178 "cfg.rl"
	
	
#line 92 "cfg.cpp"
	{
		switch ( cps.cs ) {
			case 161:
			goto st_case_161;
			case 0:
			goto st_case_0;
			case 1:
			goto st_case_1;
			case 162:
			goto st_case_162;
			case 2:
			goto st_case_2;
			case 3:
			goto st_case_3;
			case 4:
			goto st_case_4;
			case 5:
			goto st_case_5;
			case 6:
			goto st_case_6;
			case 7:
			goto st_case_7;
			case 163:
			goto st_case_163;
			case 8:
			goto st_case_8;
			case 9:
			goto st_case_9;
			case 10:
			goto st_case_10;
			case 164:
			goto st_case_164;
			case 11:
			goto st_case_11;
			case 12:
			goto st_case_12;
			case 13:
			goto st_case_13;
			case 14:
			goto st_case_14;
			case 15:
			goto st_case_15;
			case 16:
			goto st_case_16;
			case 17:
			goto st_case_17;
			case 18:
			goto st_case_18;
			case 165:
			goto st_case_165;
			case 19:
			goto st_case_19;
			case 20:
			goto st_case_20;
			case 21:
			goto st_case_21;
			case 22:
			goto st_case_22;
			case 23:
			goto st_case_23;
			case 24:
			goto st_case_24;
			case 25:
			goto st_case_25;
			case 26:
			goto st_case_26;
			case 27:
			goto st_case_27;
			case 28:
			goto st_case_28;
			case 29:
			goto st_case_29;
			case 30:
			goto st_case_30;
			case 31:
			goto st_case_31;
			case 32:
			goto st_case_32;
			case 33:
			goto st_case_33;
			case 34:
			goto st_case_34;
			case 35:
			goto st_case_35;
			case 36:
			goto st_case_36;
			case 166:
			goto st_case_166;
			case 37:
			goto st_case_37;
			case 38:
			goto st_case_38;
			case 39:
			goto st_case_39;
			case 40:
			goto st_case_40;
			case 41:
			goto st_case_41;
			case 42:
			goto st_case_42;
			case 43:
			goto st_case_43;
			case 44:
			goto st_case_44;
			case 45:
			goto st_case_45;
			case 46:
			goto st_case_46;
			case 47:
			goto st_case_47;
			case 167:
			goto st_case_167;
			case 48:
			goto st_case_48;
			case 49:
			goto st_case_49;
			case 50:
			goto st_case_50;
			case 51:
			goto st_case_51;
			case 52:
			goto st_case_52;
			case 53:
			goto st_case_53;
			case 54:
			goto st_case_54;
			case 55:
			goto st_case_55;
			case 56:
			goto st_case_56;
			case 57:
			goto st_case_57;
			case 168:
			goto st_case_168;
			case 58:
			goto st_case_58;
			case 169:
			goto st_case_169;
			case 170:
			goto st_case_170;
			case 171:
			goto st_case_171;
			case 59:
			goto st_case_59;
			case 60:
			goto st_case_60;
			case 61:
			goto st_case_61;
			case 62:
			goto st_case_62;
			case 63:
			goto st_case_63;
			case 172:
			goto st_case_172;
			case 64:
			goto st_case_64;
			case 173:
			goto st_case_173;
			case 174:
			goto st_case_174;
			case 65:
			goto st_case_65;
			case 66:
			goto st_case_66;
			case 67:
			goto st_case_67;
			case 68:
			goto st_case_68;
			case 69:
			goto st_case_69;
			case 70:
			goto st_case_70;
			case 71:
			goto st_case_71;
			case 72:
			goto st_case_72;
			case 73:
			goto st_case_73;
			case 74:
			goto st_case_74;
			case 75:
			goto st_case_75;
			case 76:
			goto st_case_76;
			case 77:
			goto st_case_77;
			case 78:
			goto st_case_78;
			case 79:
			goto st_case_79;
			case 175:
			goto st_case_175;
			case 80:
			goto st_case_80;
			case 176:
			goto st_case_176;
			case 81:
			goto st_case_81;
			case 82:
			goto st_case_82;
			case 83:
			goto st_case_83;
			case 84:
			goto st_case_84;
			case 85:
			goto st_case_85;
			case 86:
			goto st_case_86;
			case 87:
			goto st_case_87;
			case 88:
			goto st_case_88;
			case 177:
			goto st_case_177;
			case 89:
			goto st_case_89;
			case 90:
			goto st_case_90;
			case 91:
			goto st_case_91;
			case 92:
			goto st_case_92;
			case 93:
			goto st_case_93;
			case 94:
			goto st_case_94;
			case 95:
			goto st_case_95;
			case 96:
			goto st_case_96;
			case 97:
			goto st_case_97;
			case 98:
			goto st_case_98;
			case 178:
			goto st_case_178;
			case 99:
			goto st_case_99;
			case 100:
			goto st_case_100;
			case 101:
			goto st_case_101;
			case 102:
			goto st_case_102;
			case 103:
			goto st_case_103;
			case 104:
			goto st_case_104;
			case 105:
			goto st_case_105;
			case 106:
			goto st_case_106;
			case 107:
			goto st_case_107;
			case 108:
			goto st_case_108;
			case 109:
			goto st_case_109;
			case 179:
			goto st_case_179;
			case 110:
			goto st_case_110;
			case 180:
			goto st_case_180;
			case 181:
			goto st_case_181;
			case 111:
			goto st_case_111;
			case 112:
			goto st_case_112;
			case 113:
			goto st_case_113;
			case 114:
			goto st_case_114;
			case 115:
			goto st_case_115;
			case 116:
			goto st_case_116;
			case 117:
			goto st_case_117;
			case 118:
			goto st_case_118;
			case 119:
			goto st_case_119;
			case 120:
			goto st_case_120;
			case 182:
			goto st_case_182;
			case 121:
			goto st_case_121;
			case 122:
			goto st_case_122;
			case 123:
			goto st_case_123;
			case 124:
			goto st_case_124;
			case 125:
			goto st_case_125;
			case 183:
			goto st_case_183;
			case 126:
			goto st_case_126;
			case 127:
			goto st_case_127;
			case 128:
			goto st_case_128;
			case 129:
			goto st_case_129;
			case 130:
			goto st_case_130;
			case 131:
			goto st_case_131;
			case 132:
			goto st_case_132;
			case 133:
			goto st_case_133;
			case 134:
			goto st_case_134;
			case 135:
			goto st_case_135;
			case 136:
			goto st_case_136;
			case 137:
			goto st_case_137;
			case 138:
			goto st_case_138;
			case 139:
			goto st_case_139;
			case 140:
			goto st_case_140;
			case 141:
			goto st_case_141;
			case 142:
			goto st_case_142;
			case 143:
			goto st_case_143;
			case 144:
			goto st_case_144;
			case 145:
			goto st_case_145;
			case 146:
			goto st_case_146;
			case 184:
			goto st_case_184;
			case 147:
			goto st_case_147;
			case 148:
			goto st_case_148;
			case 185:
			goto st_case_185;
			case 149:
			goto st_case_149;
			case 150:
			goto st_case_150;
			case 151:
			goto st_case_151;
			case 152:
			goto st_case_152;
			case 153:
			goto st_case_153;
			case 154:
			goto st_case_154;
			case 186:
			goto st_case_186;
			case 155:
			goto st_case_155;
			case 156:
			goto st_case_156;
			case 187:
			goto st_case_187;
			case 157:
			goto st_case_157;
			case 158:
			goto st_case_158;
			case 159:
			goto st_case_159;
			case 160:
			goto st_case_160;
		}
		_st161:
		if ( p == eof )
			goto _out161;
		p+= 1;
		st_case_161:
		if ( p == pe && p != eof )
			goto _out161;
		if ( p == eof ) {
			goto _st161;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st161;
				}
				case 47: {
					goto _st1;
				}
				case 98: {
					goto _st2;
				}
				case 99: {
					goto _st12;
				}
				case 100: {
					goto _st20;
				}
				case 103: {
					goto _st81;
				}
				case 105: {
					goto _st89;
				}
				case 110: {
					goto _st99;
				}
				case 115: {
					goto _st111;
				}
				case 117: {
					goto _st121;
				}
				case 118: {
					goto _st126;
				}
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st161;
			}
			goto _st0;
		}
		_st0:
		if ( p == eof )
			goto _out0;
		st_case_0:
		goto _out0;
		_st1:
		if ( p == eof )
			goto _out1;
		p+= 1;
		st_case_1:
		if ( p == pe && p != eof )
			goto _out1;
		if ( p == eof ) {
			goto _st1;}
		else {
			if ( ( (*( p))) == 47 ) {
				goto _st162;
			}
			goto _st0;
		}
		_st162:
		if ( p == eof )
			goto _out162;
		p+= 1;
		st_case_162:
		if ( p == pe && p != eof )
			goto _out162;
		if ( p == eof ) {
			goto _st162;}
		else {
			goto _st162;
		}
		_st2:
		if ( p == eof )
			goto _out2;
		p+= 1;
		st_case_2:
		if ( p == pe && p != eof )
			goto _out2;
		if ( p == eof ) {
			goto _st2;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st3;
			}
			goto _st0;
		}
		_st3:
		if ( p == eof )
			goto _out3;
		p+= 1;
		st_case_3:
		if ( p == pe && p != eof )
			goto _out3;
		if ( p == eof ) {
			goto _st3;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st4;
			}
			goto _st0;
		}
		_st4:
		if ( p == eof )
			goto _out4;
		p+= 1;
		st_case_4:
		if ( p == pe && p != eof )
			goto _out4;
		if ( p == eof ) {
			goto _st4;}
		else {
			if ( ( (*( p))) == 100 ) {
				goto _st5;
			}
			goto _st0;
		}
		_st5:
		if ( p == eof )
			goto _out5;
		p+= 1;
		st_case_5:
		if ( p == pe && p != eof )
			goto _out5;
		if ( p == eof ) {
			goto _st5;}
		else {
			switch( ( (*( p))) ) {
				case 52: {
					goto _st6;
				}
				case 54: {
					goto _st9;
				}
			}
			goto _st0;
		}
		_st6:
		if ( p == eof )
			goto _out6;
		p+= 1;
		st_case_6:
		if ( p == pe && p != eof )
			goto _out6;
		if ( p == eof ) {
			goto _st6;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st7;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st7;
			}
			goto _st0;
		}
		_st7:
		if ( p == eof )
			goto _out7;
		p+= 1;
		st_case_7:
		if ( p == pe && p != eof )
			goto _out7;
		if ( p == eof ) {
			goto _st7;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st7;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st7;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _ctr10;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr10;
				}
			} else {
				goto _ctr10;
			}
			goto _st0;
		}
		_ctr10:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 672 "cfg.cpp"
		
		goto _st163;
		_ctr194:
		{
#line 76 "cfg.rl"
			emplace_bind(linenum, std::string(MARKED_STRING()), true); }
		
#line 680 "cfg.cpp"
		
		goto _st163;
		_st163:
		if ( p == eof )
			goto _out163;
		p+= 1;
		st_case_163:
		if ( p == pe && p != eof )
			goto _out163;
		if ( p == eof ) {
			goto _ctr194;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr195;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr195;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _st163;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st163;
				}
			} else {
				goto _st163;
			}
			goto _st0;
		}
		_ctr195:
		{
#line 76 "cfg.rl"
			emplace_bind(linenum, std::string(MARKED_STRING()), true); }
		
#line 718 "cfg.cpp"
		
		goto _st8;
		_st8:
		if ( p == eof )
			goto _out8;
		p+= 1;
		st_case_8:
		if ( p == pe && p != eof )
			goto _out8;
		if ( p == eof ) {
			goto _st8;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st8;
				}
				case 47: {
					goto _st1;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st8;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _ctr10;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr10;
				}
			} else {
				goto _ctr10;
			}
			goto _st0;
		}
		_st9:
		if ( p == eof )
			goto _out9;
		p+= 1;
		st_case_9:
		if ( p == pe && p != eof )
			goto _out9;
		if ( p == eof ) {
			goto _st9;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st10;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st10;
			}
			goto _st0;
		}
		_st10:
		if ( p == eof )
			goto _out10;
		p+= 1;
		st_case_10:
		if ( p == pe && p != eof )
			goto _out10;
		if ( p == eof ) {
			goto _st10;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st10;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st10;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _ctr13;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr13;
				}
			} else {
				goto _ctr13;
			}
			goto _st0;
		}
		_ctr13:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 809 "cfg.cpp"
		
		goto _st164;
		_ctr197:
		{
#line 77 "cfg.rl"
			emplace_bind(linenum, std::string(MARKED_STRING()), false); }
		
#line 817 "cfg.cpp"
		
		goto _st164;
		_st164:
		if ( p == eof )
			goto _out164;
		p+= 1;
		st_case_164:
		if ( p == pe && p != eof )
			goto _out164;
		if ( p == eof ) {
			goto _ctr197;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr198;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr198;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _st164;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st164;
				}
			} else {
				goto _st164;
			}
			goto _st0;
		}
		_ctr198:
		{
#line 77 "cfg.rl"
			emplace_bind(linenum, std::string(MARKED_STRING()), false); }
		
#line 855 "cfg.cpp"
		
		goto _st11;
		_st11:
		if ( p == eof )
			goto _out11;
		p+= 1;
		st_case_11:
		if ( p == pe && p != eof )
			goto _out11;
		if ( p == eof ) {
			goto _st11;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st11;
				}
				case 47: {
					goto _st1;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st11;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _ctr13;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr13;
				}
			} else {
				goto _ctr13;
			}
			goto _st0;
		}
		_st12:
		if ( p == eof )
			goto _out12;
		p+= 1;
		st_case_12:
		if ( p == pe && p != eof )
			goto _out12;
		if ( p == eof ) {
			goto _st12;}
		else {
			if ( ( (*( p))) == 104 ) {
				goto _st13;
			}
			goto _st0;
		}
		_st13:
		if ( p == eof )
			goto _out13;
		p+= 1;
		st_case_13:
		if ( p == pe && p != eof )
			goto _out13;
		if ( p == eof ) {
			goto _st13;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st14;
			}
			goto _st0;
		}
		_st14:
		if ( p == eof )
			goto _out14;
		p+= 1;
		st_case_14:
		if ( p == pe && p != eof )
			goto _out14;
		if ( p == eof ) {
			goto _st14;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st15;
			}
			goto _st0;
		}
		_st15:
		if ( p == eof )
			goto _out15;
		p+= 1;
		st_case_15:
		if ( p == pe && p != eof )
			goto _out15;
		if ( p == eof ) {
			goto _st15;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st16;
			}
			goto _st0;
		}
		_st16:
		if ( p == eof )
			goto _out16;
		p+= 1;
		st_case_16:
		if ( p == pe && p != eof )
			goto _out16;
		if ( p == eof ) {
			goto _st16;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st17;
			}
			goto _st0;
		}
		_st17:
		if ( p == eof )
			goto _out17;
		p+= 1;
		st_case_17:
		if ( p == pe && p != eof )
			goto _out17;
		if ( p == eof ) {
			goto _st17;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st18;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st18;
			}
			goto _st0;
		}
		_st18:
		if ( p == eof )
			goto _out18;
		p+= 1;
		st_case_18:
		if ( p == pe && p != eof )
			goto _out18;
		if ( p == eof ) {
			goto _st18;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st18;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 33 <= ( (*( p))) && ( (*( p))) <= 126 ) {
					goto _ctr22;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st18;
			}
			goto _st0;
		}
		_ctr22:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 1013 "cfg.cpp"
		
		goto _st165;
		_ctr200:
		{
#line 79 "cfg.rl"
			set_chroot_path(linenum, std::string(MARKED_STRING())); }
		
#line 1021 "cfg.cpp"
		
		goto _st165;
		_st165:
		if ( p == eof )
			goto _out165;
		p+= 1;
		st_case_165:
		if ( p == pe && p != eof )
			goto _out165;
		if ( p == eof ) {
			goto _ctr200;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr201;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 33 <= ( (*( p))) && ( (*( p))) <= 126 ) {
					goto _st165;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr201;
			}
			goto _st0;
		}
		_ctr201:
		{
#line 79 "cfg.rl"
			set_chroot_path(linenum, std::string(MARKED_STRING())); }
		
#line 1051 "cfg.cpp"
		
		goto _st19;
		_ctr204:
		{
#line 86 "cfg.rl"
			
			if (auto t = nk::from_string<uint32_t>(MARKED_STRING())) cps.default_lifetime = *t; else {
				cps.parse_error = true;
				{p+= 1; cps.cs = 19; goto _out;}
			}
		}
		
#line 1064 "cfg.cpp"
		
		goto _st19;
		_ctr207:
		{
#line 92 "cfg.rl"
			
			if (auto t = nk::from_string<uint8_t>(MARKED_STRING())) cps.default_preference = *t; else {
				log_line("default_preference on line %zu out of range [0,255]: %s",
				linenum, std::string(MARKED_STRING()).c_str());
				cps.parse_error = true;
				{p+= 1; cps.cs = 19; goto _out;}
			}
		}
		
#line 1079 "cfg.cpp"
		
		goto _st19;
		_ctr228:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 1090 "cfg.cpp"
		
		{
#line 119 "cfg.rl"
			
			emplace_dynamic_range(linenum, cps.interface, cps.ipaddr2, cps.ipaddr,
			cps.default_lifetime);
		}
		
#line 1099 "cfg.cpp"
		
		goto _st19;
		_ctr231:
		{
#line 123 "cfg.rl"
			
			emplace_dynamic_v6(linenum, cps.interface);
		}
		
#line 1109 "cfg.cpp"
		
		goto _st19;
		_ctr233:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 1120 "cfg.cpp"
		
		{
#line 113 "cfg.rl"
			
			emplace_gateway(linenum, cps.interface, cps.ipaddr);
		}
		
#line 1128 "cfg.cpp"
		
		goto _st19;
		_ctr236:
		{
#line 100 "cfg.rl"
			
			cps.interface = std::string(MARKED_STRING());
			emplace_interface(linenum, cps.interface, cps.default_preference);
		}
		
#line 1139 "cfg.cpp"
		
		goto _st19;
		_ctr248:
		{
#line 80 "cfg.rl"
			
			if (auto t = nk::from_string<int>(MARKED_STRING())) set_s6_notify_fd(linenum, *t); else {
				cps.parse_error = true;
				{p+= 1; cps.cs = 19; goto _out;}
			}
		}
		
#line 1152 "cfg.cpp"
		
		goto _st19;
		_ctr251:
		{
#line 78 "cfg.rl"
			set_user_runas(linenum, std::string(MARKED_STRING())); }
		
#line 1160 "cfg.cpp"
		
		goto _st19;
		_st19:
		if ( p == eof )
			goto _out19;
		p+= 1;
		st_case_19:
		if ( p == pe && p != eof )
			goto _out19;
		if ( p == eof ) {
			goto _st19;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st19;
				}
				case 47: {
					goto _st1;
				}
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st19;
			}
			goto _st0;
		}
		_st20:
		if ( p == eof )
			goto _out20;
		p+= 1;
		st_case_20:
		if ( p == pe && p != eof )
			goto _out20;
		if ( p == eof ) {
			goto _st20;}
		else {
			switch( ( (*( p))) ) {
				case 101: {
					goto _st21;
				}
				case 110: {
					goto _st48;
				}
				case 121: {
					goto _st65;
				}
			}
			goto _st0;
		}
		_st21:
		if ( p == eof )
			goto _out21;
		p+= 1;
		st_case_21:
		if ( p == pe && p != eof )
			goto _out21;
		if ( p == eof ) {
			goto _st21;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st22;
			}
			goto _st0;
		}
		_st22:
		if ( p == eof )
			goto _out22;
		p+= 1;
		st_case_22:
		if ( p == pe && p != eof )
			goto _out22;
		if ( p == eof ) {
			goto _st22;}
		else {
			if ( ( (*( p))) == 97 ) {
				goto _st23;
			}
			goto _st0;
		}
		_st23:
		if ( p == eof )
			goto _out23;
		p+= 1;
		st_case_23:
		if ( p == pe && p != eof )
			goto _out23;
		if ( p == eof ) {
			goto _st23;}
		else {
			if ( ( (*( p))) == 117 ) {
				goto _st24;
			}
			goto _st0;
		}
		_st24:
		if ( p == eof )
			goto _out24;
		p+= 1;
		st_case_24:
		if ( p == pe && p != eof )
			goto _out24;
		if ( p == eof ) {
			goto _st24;}
		else {
			if ( ( (*( p))) == 108 ) {
				goto _st25;
			}
			goto _st0;
		}
		_st25:
		if ( p == eof )
			goto _out25;
		p+= 1;
		st_case_25:
		if ( p == pe && p != eof )
			goto _out25;
		if ( p == eof ) {
			goto _st25;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st26;
			}
			goto _st0;
		}
		_st26:
		if ( p == eof )
			goto _out26;
		p+= 1;
		st_case_26:
		if ( p == pe && p != eof )
			goto _out26;
		if ( p == eof ) {
			goto _st26;}
		else {
			if ( ( (*( p))) == 95 ) {
				goto _st27;
			}
			goto _st0;
		}
		_st27:
		if ( p == eof )
			goto _out27;
		p+= 1;
		st_case_27:
		if ( p == pe && p != eof )
			goto _out27;
		if ( p == eof ) {
			goto _st27;}
		else {
			switch( ( (*( p))) ) {
				case 108: {
					goto _st28;
				}
				case 112: {
					goto _st37;
				}
			}
			goto _st0;
		}
		_st28:
		if ( p == eof )
			goto _out28;
		p+= 1;
		st_case_28:
		if ( p == pe && p != eof )
			goto _out28;
		if ( p == eof ) {
			goto _st28;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st29;
			}
			goto _st0;
		}
		_st29:
		if ( p == eof )
			goto _out29;
		p+= 1;
		st_case_29:
		if ( p == pe && p != eof )
			goto _out29;
		if ( p == eof ) {
			goto _st29;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st30;
			}
			goto _st0;
		}
		_st30:
		if ( p == eof )
			goto _out30;
		p+= 1;
		st_case_30:
		if ( p == pe && p != eof )
			goto _out30;
		if ( p == eof ) {
			goto _st30;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st31;
			}
			goto _st0;
		}
		_st31:
		if ( p == eof )
			goto _out31;
		p+= 1;
		st_case_31:
		if ( p == pe && p != eof )
			goto _out31;
		if ( p == eof ) {
			goto _st31;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st32;
			}
			goto _st0;
		}
		_st32:
		if ( p == eof )
			goto _out32;
		p+= 1;
		st_case_32:
		if ( p == pe && p != eof )
			goto _out32;
		if ( p == eof ) {
			goto _st32;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st33;
			}
			goto _st0;
		}
		_st33:
		if ( p == eof )
			goto _out33;
		p+= 1;
		st_case_33:
		if ( p == pe && p != eof )
			goto _out33;
		if ( p == eof ) {
			goto _st33;}
		else {
			if ( ( (*( p))) == 109 ) {
				goto _st34;
			}
			goto _st0;
		}
		_st34:
		if ( p == eof )
			goto _out34;
		p+= 1;
		st_case_34:
		if ( p == pe && p != eof )
			goto _out34;
		if ( p == eof ) {
			goto _st34;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st35;
			}
			goto _st0;
		}
		_st35:
		if ( p == eof )
			goto _out35;
		p+= 1;
		st_case_35:
		if ( p == pe && p != eof )
			goto _out35;
		if ( p == eof ) {
			goto _st35;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st36;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st36;
			}
			goto _st0;
		}
		_st36:
		if ( p == eof )
			goto _out36;
		p+= 1;
		st_case_36:
		if ( p == pe && p != eof )
			goto _out36;
		if ( p == eof ) {
			goto _st36;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st36;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _ctr44;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st36;
			}
			goto _st0;
		}
		_ctr44:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 1469 "cfg.cpp"
		
		goto _st166;
		_ctr203:
		{
#line 86 "cfg.rl"
			
			if (auto t = nk::from_string<uint32_t>(MARKED_STRING())) cps.default_lifetime = *t; else {
				cps.parse_error = true;
				{p+= 1; cps.cs = 166; goto _out;}
			}
		}
		
#line 1482 "cfg.cpp"
		
		goto _st166;
		_st166:
		if ( p == eof )
			goto _out166;
		p+= 1;
		st_case_166:
		if ( p == pe && p != eof )
			goto _out166;
		if ( p == eof ) {
			goto _ctr203;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr204;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st166;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr204;
			}
			goto _st0;
		}
		_st37:
		if ( p == eof )
			goto _out37;
		p+= 1;
		st_case_37:
		if ( p == pe && p != eof )
			goto _out37;
		if ( p == eof ) {
			goto _st37;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st38;
			}
			goto _st0;
		}
		_st38:
		if ( p == eof )
			goto _out38;
		p+= 1;
		st_case_38:
		if ( p == pe && p != eof )
			goto _out38;
		if ( p == eof ) {
			goto _st38;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st39;
			}
			goto _st0;
		}
		_st39:
		if ( p == eof )
			goto _out39;
		p+= 1;
		st_case_39:
		if ( p == pe && p != eof )
			goto _out39;
		if ( p == eof ) {
			goto _st39;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st40;
			}
			goto _st0;
		}
		_st40:
		if ( p == eof )
			goto _out40;
		p+= 1;
		st_case_40:
		if ( p == pe && p != eof )
			goto _out40;
		if ( p == eof ) {
			goto _st40;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st41;
			}
			goto _st0;
		}
		_st41:
		if ( p == eof )
			goto _out41;
		p+= 1;
		st_case_41:
		if ( p == pe && p != eof )
			goto _out41;
		if ( p == eof ) {
			goto _st41;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st42;
			}
			goto _st0;
		}
		_st42:
		if ( p == eof )
			goto _out42;
		p+= 1;
		st_case_42:
		if ( p == pe && p != eof )
			goto _out42;
		if ( p == eof ) {
			goto _st42;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st43;
			}
			goto _st0;
		}
		_st43:
		if ( p == eof )
			goto _out43;
		p+= 1;
		st_case_43:
		if ( p == pe && p != eof )
			goto _out43;
		if ( p == eof ) {
			goto _st43;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st44;
			}
			goto _st0;
		}
		_st44:
		if ( p == eof )
			goto _out44;
		p+= 1;
		st_case_44:
		if ( p == pe && p != eof )
			goto _out44;
		if ( p == eof ) {
			goto _st44;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st45;
			}
			goto _st0;
		}
		_st45:
		if ( p == eof )
			goto _out45;
		p+= 1;
		st_case_45:
		if ( p == pe && p != eof )
			goto _out45;
		if ( p == eof ) {
			goto _st45;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st46;
			}
			goto _st0;
		}
		_st46:
		if ( p == eof )
			goto _out46;
		p+= 1;
		st_case_46:
		if ( p == pe && p != eof )
			goto _out46;
		if ( p == eof ) {
			goto _st46;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st47;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st47;
			}
			goto _st0;
		}
		_st47:
		if ( p == eof )
			goto _out47;
		p+= 1;
		st_case_47:
		if ( p == pe && p != eof )
			goto _out47;
		if ( p == eof ) {
			goto _st47;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st47;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _ctr55;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st47;
			}
			goto _st0;
		}
		_ctr55:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 1687 "cfg.cpp"
		
		goto _st167;
		_ctr206:
		{
#line 92 "cfg.rl"
			
			if (auto t = nk::from_string<uint8_t>(MARKED_STRING())) cps.default_preference = *t; else {
				log_line("default_preference on line %zu out of range [0,255]: %s",
				linenum, std::string(MARKED_STRING()).c_str());
				cps.parse_error = true;
				{p+= 1; cps.cs = 167; goto _out;}
			}
		}
		
#line 1702 "cfg.cpp"
		
		goto _st167;
		_st167:
		if ( p == eof )
			goto _out167;
		p+= 1;
		st_case_167:
		if ( p == pe && p != eof )
			goto _out167;
		if ( p == eof ) {
			goto _ctr206;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr207;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st167;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr207;
			}
			goto _st0;
		}
		_st48:
		if ( p == eof )
			goto _out48;
		p+= 1;
		st_case_48:
		if ( p == pe && p != eof )
			goto _out48;
		if ( p == eof ) {
			goto _st48;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st49;
			}
			goto _st0;
		}
		_st49:
		if ( p == eof )
			goto _out49;
		p+= 1;
		st_case_49:
		if ( p == pe && p != eof )
			goto _out49;
		if ( p == eof ) {
			goto _st49;}
		else {
			if ( ( (*( p))) == 95 ) {
				goto _st50;
			}
			goto _st0;
		}
		_st50:
		if ( p == eof )
			goto _out50;
		p+= 1;
		st_case_50:
		if ( p == pe && p != eof )
			goto _out50;
		if ( p == eof ) {
			goto _st50;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st51;
			}
			goto _st0;
		}
		_st51:
		if ( p == eof )
			goto _out51;
		p+= 1;
		st_case_51:
		if ( p == pe && p != eof )
			goto _out51;
		if ( p == eof ) {
			goto _st51;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st52;
			}
			goto _st0;
		}
		_st52:
		if ( p == eof )
			goto _out52;
		p+= 1;
		st_case_52:
		if ( p == pe && p != eof )
			goto _out52;
		if ( p == eof ) {
			goto _st52;}
		else {
			switch( ( (*( p))) ) {
				case 97: {
					goto _st53;
				}
				case 114: {
					goto _st59;
				}
			}
			goto _st0;
		}
		_st53:
		if ( p == eof )
			goto _out53;
		p+= 1;
		st_case_53:
		if ( p == pe && p != eof )
			goto _out53;
		if ( p == eof ) {
			goto _st53;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st54;
			}
			goto _st0;
		}
		_st54:
		if ( p == eof )
			goto _out54;
		p+= 1;
		st_case_54:
		if ( p == pe && p != eof )
			goto _out54;
		if ( p == eof ) {
			goto _st54;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st55;
			}
			goto _st0;
		}
		_st55:
		if ( p == eof )
			goto _out55;
		p+= 1;
		st_case_55:
		if ( p == pe && p != eof )
			goto _out55;
		if ( p == eof ) {
			goto _st55;}
		else {
			if ( ( (*( p))) == 104 ) {
				goto _st56;
			}
			goto _st0;
		}
		_st56:
		if ( p == eof )
			goto _out56;
		p+= 1;
		st_case_56:
		if ( p == pe && p != eof )
			goto _out56;
		if ( p == eof ) {
			goto _st56;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st57;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st57;
			}
			goto _st0;
		}
		_st57:
		if ( p == eof )
			goto _out57;
		p+= 1;
		st_case_57:
		if ( p == pe && p != eof )
			goto _out57;
		if ( p == eof ) {
			goto _st57;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st57;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 33 <= ( (*( p))) && ( (*( p))) <= 126 ) {
					goto _ctr66;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st57;
			}
			goto _st0;
		}
		_ctr66:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 1897 "cfg.cpp"
		
		goto _st168;
		_ctr209:
		{
#line 107 "cfg.rl"
			
			emplace_dns_search(linenum, cps.interface, std::string(MARKED_STRING()));
		}
		
#line 1907 "cfg.cpp"
		
		goto _st168;
		_st168:
		if ( p == eof )
			goto _out168;
		p+= 1;
		st_case_168:
		if ( p == pe && p != eof )
			goto _out168;
		if ( p == eof ) {
			goto _ctr209;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr210;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 33 <= ( (*( p))) && ( (*( p))) <= 126 ) {
					goto _st168;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr210;
			}
			goto _st0;
		}
		_ctr210:
		{
#line 107 "cfg.rl"
			
			emplace_dns_search(linenum, cps.interface, std::string(MARKED_STRING()));
		}
		
#line 1939 "cfg.cpp"
		
		goto _st58;
		_st58:
		if ( p == eof )
			goto _out58;
		p+= 1;
		st_case_58:
		if ( p == pe && p != eof )
			goto _out58;
		if ( p == eof ) {
			goto _st58;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st58;
				}
				case 47: {
					goto _ctr68;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 33 <= ( (*( p))) && ( (*( p))) <= 126 ) {
					goto _ctr66;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st58;
			}
			goto _st0;
		}
		_ctr68:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 1974 "cfg.cpp"
		
		goto _st169;
		_ctr212:
		{
#line 107 "cfg.rl"
			
			emplace_dns_search(linenum, cps.interface, std::string(MARKED_STRING()));
		}
		
#line 1984 "cfg.cpp"
		
		goto _st169;
		_st169:
		if ( p == eof )
			goto _out169;
		p+= 1;
		st_case_169:
		if ( p == pe && p != eof )
			goto _out169;
		if ( p == eof ) {
			goto _ctr212;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr210;
				}
				case 47: {
					goto _st170;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 33 <= ( (*( p))) && ( (*( p))) <= 126 ) {
					goto _st168;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr210;
			}
			goto _st0;
		}
		_ctr217:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 2019 "cfg.cpp"
		
		goto _st170;
		_ctr214:
		{
#line 107 "cfg.rl"
			
			emplace_dns_search(linenum, cps.interface, std::string(MARKED_STRING()));
		}
		
#line 2029 "cfg.cpp"
		
		goto _st170;
		_st170:
		if ( p == eof )
			goto _out170;
		p+= 1;
		st_case_170:
		if ( p == pe && p != eof )
			goto _out170;
		if ( p == eof ) {
			goto _ctr214;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr215;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 33 <= ( (*( p))) && ( (*( p))) <= 126 ) {
					goto _st170;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr215;
			}
			goto _st162;
		}
		_ctr215:
		{
#line 107 "cfg.rl"
			
			emplace_dns_search(linenum, cps.interface, std::string(MARKED_STRING()));
		}
		
#line 2061 "cfg.cpp"
		
		goto _st171;
		_st171:
		if ( p == eof )
			goto _out171;
		p+= 1;
		st_case_171:
		if ( p == pe && p != eof )
			goto _out171;
		if ( p == eof ) {
			goto _st171;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st171;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 33 <= ( (*( p))) && ( (*( p))) <= 126 ) {
					goto _ctr217;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st171;
			}
			goto _st162;
		}
		_st59:
		if ( p == eof )
			goto _out59;
		p+= 1;
		st_case_59:
		if ( p == pe && p != eof )
			goto _out59;
		if ( p == eof ) {
			goto _st59;}
		else {
			if ( ( (*( p))) == 118 ) {
				goto _st60;
			}
			goto _st0;
		}
		_st60:
		if ( p == eof )
			goto _out60;
		p+= 1;
		st_case_60:
		if ( p == pe && p != eof )
			goto _out60;
		if ( p == eof ) {
			goto _st60;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st61;
			}
			goto _st0;
		}
		_st61:
		if ( p == eof )
			goto _out61;
		p+= 1;
		st_case_61:
		if ( p == pe && p != eof )
			goto _out61;
		if ( p == eof ) {
			goto _st61;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st62;
			}
			goto _st0;
		}
		_st62:
		if ( p == eof )
			goto _out62;
		p+= 1;
		st_case_62:
		if ( p == pe && p != eof )
			goto _out62;
		if ( p == eof ) {
			goto _st62;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st63;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st63;
			}
			goto _st0;
		}
		_st63:
		if ( p == eof )
			goto _out63;
		p+= 1;
		st_case_63:
		if ( p == pe && p != eof )
			goto _out63;
		if ( p == eof ) {
			goto _st63;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st63;
				}
				case 46: {
					goto _ctr73;
				}
				case 58: {
					goto _ctr75;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st63;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _ctr75;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr75;
				}
			} else {
				goto _ctr74;
			}
			goto _st0;
		}
		_ctr73:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 2192 "cfg.cpp"
		
		goto _st172;
		_ctr218:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 2203 "cfg.cpp"
		
		{
#line 104 "cfg.rl"
			
			emplace_dns_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 2211 "cfg.cpp"
		
		goto _st172;
		_st172:
		if ( p == eof )
			goto _out172;
		p+= 1;
		st_case_172:
		if ( p == pe && p != eof )
			goto _out172;
		if ( p == eof ) {
			goto _ctr218;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr219;
				}
				case 46: {
					goto _st172;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st172;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr219;
			}
			goto _st0;
		}
		_ctr219:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 2249 "cfg.cpp"
		
		{
#line 104 "cfg.rl"
			
			emplace_dns_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 2257 "cfg.cpp"
		
		goto _st64;
		_ctr222:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 2268 "cfg.cpp"
		
		{
#line 72 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v6;
		}
		
#line 2277 "cfg.cpp"
		
		{
#line 104 "cfg.rl"
			
			emplace_dns_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 2285 "cfg.cpp"
		
		goto _st64;
		_ctr226:
		{
#line 72 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v6;
		}
		
#line 2296 "cfg.cpp"
		
		{
#line 104 "cfg.rl"
			
			emplace_dns_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 2304 "cfg.cpp"
		
		goto _st64;
		_st64:
		if ( p == eof )
			goto _out64;
		p+= 1;
		st_case_64:
		if ( p == pe && p != eof )
			goto _out64;
		if ( p == eof ) {
			goto _st64;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st64;
				}
				case 46: {
					goto _ctr73;
				}
				case 47: {
					goto _st1;
				}
				case 58: {
					goto _ctr75;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st64;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _ctr75;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr75;
				}
			} else {
				goto _ctr74;
			}
			goto _st0;
		}
		_ctr74:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 2353 "cfg.cpp"
		
		goto _st173;
		_ctr221:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 2364 "cfg.cpp"
		
		{
#line 72 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v6;
		}
		
#line 2373 "cfg.cpp"
		
		{
#line 104 "cfg.rl"
			
			emplace_dns_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 2381 "cfg.cpp"
		
		goto _st173;
		_st173:
		if ( p == eof )
			goto _out173;
		p+= 1;
		st_case_173:
		if ( p == pe && p != eof )
			goto _out173;
		if ( p == eof ) {
			goto _ctr221;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr222;
				}
				case 46: {
					goto _st172;
				}
				case 58: {
					goto _st174;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr222;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st174;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st174;
				}
			} else {
				goto _st173;
			}
			goto _st0;
		}
		_ctr75:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 2427 "cfg.cpp"
		
		goto _st174;
		_ctr225:
		{
#line 72 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v6;
		}
		
#line 2438 "cfg.cpp"
		
		{
#line 104 "cfg.rl"
			
			emplace_dns_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 2446 "cfg.cpp"
		
		goto _st174;
		_st174:
		if ( p == eof )
			goto _out174;
		p+= 1;
		st_case_174:
		if ( p == pe && p != eof )
			goto _out174;
		if ( p == eof ) {
			goto _ctr225;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr226;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr226;
				}
			} else if ( ( (*( p))) > 58 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st174;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st174;
				}
			} else {
				goto _st174;
			}
			goto _st0;
		}
		_st65:
		if ( p == eof )
			goto _out65;
		p+= 1;
		st_case_65:
		if ( p == pe && p != eof )
			goto _out65;
		if ( p == eof ) {
			goto _st65;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st66;
			}
			goto _st0;
		}
		_st66:
		if ( p == eof )
			goto _out66;
		p+= 1;
		st_case_66:
		if ( p == pe && p != eof )
			goto _out66;
		if ( p == eof ) {
			goto _st66;}
		else {
			if ( ( (*( p))) == 97 ) {
				goto _st67;
			}
			goto _st0;
		}
		_st67:
		if ( p == eof )
			goto _out67;
		p+= 1;
		st_case_67:
		if ( p == pe && p != eof )
			goto _out67;
		if ( p == eof ) {
			goto _st67;}
		else {
			if ( ( (*( p))) == 109 ) {
				goto _st68;
			}
			goto _st0;
		}
		_st68:
		if ( p == eof )
			goto _out68;
		p+= 1;
		st_case_68:
		if ( p == pe && p != eof )
			goto _out68;
		if ( p == eof ) {
			goto _st68;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st69;
			}
			goto _st0;
		}
		_st69:
		if ( p == eof )
			goto _out69;
		p+= 1;
		st_case_69:
		if ( p == pe && p != eof )
			goto _out69;
		if ( p == eof ) {
			goto _st69;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st70;
			}
			goto _st0;
		}
		_st70:
		if ( p == eof )
			goto _out70;
		p+= 1;
		st_case_70:
		if ( p == pe && p != eof )
			goto _out70;
		if ( p == eof ) {
			goto _st70;}
		else {
			if ( ( (*( p))) == 95 ) {
				goto _st71;
			}
			goto _st0;
		}
		_st71:
		if ( p == eof )
			goto _out71;
		p+= 1;
		st_case_71:
		if ( p == pe && p != eof )
			goto _out71;
		if ( p == eof ) {
			goto _st71;}
		else {
			switch( ( (*( p))) ) {
				case 114: {
					goto _st72;
				}
				case 118: {
					goto _st80;
				}
			}
			goto _st0;
		}
		_st72:
		if ( p == eof )
			goto _out72;
		p+= 1;
		st_case_72:
		if ( p == pe && p != eof )
			goto _out72;
		if ( p == eof ) {
			goto _st72;}
		else {
			if ( ( (*( p))) == 97 ) {
				goto _st73;
			}
			goto _st0;
		}
		_st73:
		if ( p == eof )
			goto _out73;
		p+= 1;
		st_case_73:
		if ( p == pe && p != eof )
			goto _out73;
		if ( p == eof ) {
			goto _st73;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st74;
			}
			goto _st0;
		}
		_st74:
		if ( p == eof )
			goto _out74;
		p+= 1;
		st_case_74:
		if ( p == pe && p != eof )
			goto _out74;
		if ( p == eof ) {
			goto _st74;}
		else {
			if ( ( (*( p))) == 103 ) {
				goto _st75;
			}
			goto _st0;
		}
		_st75:
		if ( p == eof )
			goto _out75;
		p+= 1;
		st_case_75:
		if ( p == pe && p != eof )
			goto _out75;
		if ( p == eof ) {
			goto _st75;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st76;
			}
			goto _st0;
		}
		_st76:
		if ( p == eof )
			goto _out76;
		p+= 1;
		st_case_76:
		if ( p == pe && p != eof )
			goto _out76;
		if ( p == eof ) {
			goto _st76;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st77;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st77;
			}
			goto _st0;
		}
		_st77:
		if ( p == eof )
			goto _out77;
		p+= 1;
		st_case_77:
		if ( p == pe && p != eof )
			goto _out77;
		if ( p == eof ) {
			goto _st77;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st77;
				}
				case 46: {
					goto _ctr90;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _ctr90;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st77;
			}
			goto _st0;
		}
		_ctr90:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 2699 "cfg.cpp"
		
		goto _st78;
		_st78:
		if ( p == eof )
			goto _out78;
		p+= 1;
		st_case_78:
		if ( p == pe && p != eof )
			goto _out78;
		if ( p == eof ) {
			goto _st78;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr92;
				}
				case 46: {
					goto _st78;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st78;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr92;
			}
			goto _st0;
		}
		_ctr92:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 2737 "cfg.cpp"
		
		{
#line 116 "cfg.rl"
			
			cps.ipaddr2 = std::move(cps.ipaddr);
		}
		
#line 2745 "cfg.cpp"
		
		goto _st79;
		_st79:
		if ( p == eof )
			goto _out79;
		p+= 1;
		st_case_79:
		if ( p == pe && p != eof )
			goto _out79;
		if ( p == eof ) {
			goto _st79;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st79;
				}
				case 46: {
					goto _ctr94;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _ctr94;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st79;
			}
			goto _st0;
		}
		_ctr94:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 2780 "cfg.cpp"
		
		goto _st175;
		_ctr227:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 2791 "cfg.cpp"
		
		{
#line 119 "cfg.rl"
			
			emplace_dynamic_range(linenum, cps.interface, cps.ipaddr2, cps.ipaddr,
			cps.default_lifetime);
		}
		
#line 2800 "cfg.cpp"
		
		goto _st175;
		_st175:
		if ( p == eof )
			goto _out175;
		p+= 1;
		st_case_175:
		if ( p == pe && p != eof )
			goto _out175;
		if ( p == eof ) {
			goto _ctr227;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr228;
				}
				case 46: {
					goto _st175;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st175;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr228;
			}
			goto _st0;
		}
		_st80:
		if ( p == eof )
			goto _out80;
		p+= 1;
		st_case_80:
		if ( p == pe && p != eof )
			goto _out80;
		if ( p == eof ) {
			goto _st80;}
		else {
			if ( ( (*( p))) == 54 ) {
				goto _st176;
			}
			goto _st0;
		}
		_ctr230:
		{
#line 123 "cfg.rl"
			
			emplace_dynamic_v6(linenum, cps.interface);
		}
		
#line 2852 "cfg.cpp"
		
		goto _st176;
		_st176:
		if ( p == eof )
			goto _out176;
		p+= 1;
		st_case_176:
		if ( p == pe && p != eof )
			goto _out176;
		if ( p == eof ) {
			goto _ctr230;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr231;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _ctr231;
			}
			goto _st0;
		}
		_st81:
		if ( p == eof )
			goto _out81;
		p+= 1;
		st_case_81:
		if ( p == pe && p != eof )
			goto _out81;
		if ( p == eof ) {
			goto _st81;}
		else {
			if ( ( (*( p))) == 97 ) {
				goto _st82;
			}
			goto _st0;
		}
		_st82:
		if ( p == eof )
			goto _out82;
		p+= 1;
		st_case_82:
		if ( p == pe && p != eof )
			goto _out82;
		if ( p == eof ) {
			goto _st82;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st83;
			}
			goto _st0;
		}
		_st83:
		if ( p == eof )
			goto _out83;
		p+= 1;
		st_case_83:
		if ( p == pe && p != eof )
			goto _out83;
		if ( p == eof ) {
			goto _st83;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st84;
			}
			goto _st0;
		}
		_st84:
		if ( p == eof )
			goto _out84;
		p+= 1;
		st_case_84:
		if ( p == pe && p != eof )
			goto _out84;
		if ( p == eof ) {
			goto _st84;}
		else {
			if ( ( (*( p))) == 119 ) {
				goto _st85;
			}
			goto _st0;
		}
		_st85:
		if ( p == eof )
			goto _out85;
		p+= 1;
		st_case_85:
		if ( p == pe && p != eof )
			goto _out85;
		if ( p == eof ) {
			goto _st85;}
		else {
			if ( ( (*( p))) == 97 ) {
				goto _st86;
			}
			goto _st0;
		}
		_st86:
		if ( p == eof )
			goto _out86;
		p+= 1;
		st_case_86:
		if ( p == pe && p != eof )
			goto _out86;
		if ( p == eof ) {
			goto _st86;}
		else {
			if ( ( (*( p))) == 121 ) {
				goto _st87;
			}
			goto _st0;
		}
		_st87:
		if ( p == eof )
			goto _out87;
		p+= 1;
		st_case_87:
		if ( p == pe && p != eof )
			goto _out87;
		if ( p == eof ) {
			goto _st87;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st88;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st88;
			}
			goto _st0;
		}
		_st88:
		if ( p == eof )
			goto _out88;
		p+= 1;
		st_case_88:
		if ( p == pe && p != eof )
			goto _out88;
		if ( p == eof ) {
			goto _st88;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st88;
				}
				case 46: {
					goto _ctr104;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _ctr104;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st88;
			}
			goto _st0;
		}
		_ctr104:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 3013 "cfg.cpp"
		
		goto _st177;
		_ctr232:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 3024 "cfg.cpp"
		
		{
#line 113 "cfg.rl"
			
			emplace_gateway(linenum, cps.interface, cps.ipaddr);
		}
		
#line 3032 "cfg.cpp"
		
		goto _st177;
		_st177:
		if ( p == eof )
			goto _out177;
		p+= 1;
		st_case_177:
		if ( p == pe && p != eof )
			goto _out177;
		if ( p == eof ) {
			goto _ctr232;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr233;
				}
				case 46: {
					goto _st177;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st177;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr233;
			}
			goto _st0;
		}
		_st89:
		if ( p == eof )
			goto _out89;
		p+= 1;
		st_case_89:
		if ( p == pe && p != eof )
			goto _out89;
		if ( p == eof ) {
			goto _st89;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st90;
			}
			goto _st0;
		}
		_st90:
		if ( p == eof )
			goto _out90;
		p+= 1;
		st_case_90:
		if ( p == pe && p != eof )
			goto _out90;
		if ( p == eof ) {
			goto _st90;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st91;
			}
			goto _st0;
		}
		_st91:
		if ( p == eof )
			goto _out91;
		p+= 1;
		st_case_91:
		if ( p == pe && p != eof )
			goto _out91;
		if ( p == eof ) {
			goto _st91;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st92;
			}
			goto _st0;
		}
		_st92:
		if ( p == eof )
			goto _out92;
		p+= 1;
		st_case_92:
		if ( p == pe && p != eof )
			goto _out92;
		if ( p == eof ) {
			goto _st92;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st93;
			}
			goto _st0;
		}
		_st93:
		if ( p == eof )
			goto _out93;
		p+= 1;
		st_case_93:
		if ( p == pe && p != eof )
			goto _out93;
		if ( p == eof ) {
			goto _st93;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st94;
			}
			goto _st0;
		}
		_st94:
		if ( p == eof )
			goto _out94;
		p+= 1;
		st_case_94:
		if ( p == pe && p != eof )
			goto _out94;
		if ( p == eof ) {
			goto _st94;}
		else {
			if ( ( (*( p))) == 97 ) {
				goto _st95;
			}
			goto _st0;
		}
		_st95:
		if ( p == eof )
			goto _out95;
		p+= 1;
		st_case_95:
		if ( p == pe && p != eof )
			goto _out95;
		if ( p == eof ) {
			goto _st95;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st96;
			}
			goto _st0;
		}
		_st96:
		if ( p == eof )
			goto _out96;
		p+= 1;
		st_case_96:
		if ( p == pe && p != eof )
			goto _out96;
		if ( p == eof ) {
			goto _st96;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st97;
			}
			goto _st0;
		}
		_st97:
		if ( p == eof )
			goto _out97;
		p+= 1;
		st_case_97:
		if ( p == pe && p != eof )
			goto _out97;
		if ( p == eof ) {
			goto _st97;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st98;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st98;
			}
			goto _st0;
		}
		_st98:
		if ( p == eof )
			goto _out98;
		p+= 1;
		st_case_98:
		if ( p == pe && p != eof )
			goto _out98;
		if ( p == eof ) {
			goto _st98;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st98;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st98;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _ctr115;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr115;
				}
			} else {
				goto _ctr115;
			}
			goto _st0;
		}
		_ctr115:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 3235 "cfg.cpp"
		
		goto _st178;
		_ctr235:
		{
#line 100 "cfg.rl"
			
			cps.interface = std::string(MARKED_STRING());
			emplace_interface(linenum, cps.interface, cps.default_preference);
		}
		
#line 3246 "cfg.cpp"
		
		goto _st178;
		_st178:
		if ( p == eof )
			goto _out178;
		p+= 1;
		st_case_178:
		if ( p == pe && p != eof )
			goto _out178;
		if ( p == eof ) {
			goto _ctr235;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr236;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr236;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _st178;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st178;
				}
			} else {
				goto _st178;
			}
			goto _st0;
		}
		_st99:
		if ( p == eof )
			goto _out99;
		p+= 1;
		st_case_99:
		if ( p == pe && p != eof )
			goto _out99;
		if ( p == eof ) {
			goto _st99;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st100;
			}
			goto _st0;
		}
		_st100:
		if ( p == eof )
			goto _out100;
		p+= 1;
		st_case_100:
		if ( p == pe && p != eof )
			goto _out100;
		if ( p == eof ) {
			goto _st100;}
		else {
			if ( ( (*( p))) == 112 ) {
				goto _st101;
			}
			goto _st0;
		}
		_st101:
		if ( p == eof )
			goto _out101;
		p+= 1;
		st_case_101:
		if ( p == pe && p != eof )
			goto _out101;
		if ( p == eof ) {
			goto _st101;}
		else {
			if ( ( (*( p))) == 95 ) {
				goto _st102;
			}
			goto _st0;
		}
		_st102:
		if ( p == eof )
			goto _out102;
		p+= 1;
		st_case_102:
		if ( p == pe && p != eof )
			goto _out102;
		if ( p == eof ) {
			goto _st102;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st103;
			}
			goto _st0;
		}
		_st103:
		if ( p == eof )
			goto _out103;
		p+= 1;
		st_case_103:
		if ( p == pe && p != eof )
			goto _out103;
		if ( p == eof ) {
			goto _st103;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st104;
			}
			goto _st0;
		}
		_st104:
		if ( p == eof )
			goto _out104;
		p+= 1;
		st_case_104:
		if ( p == pe && p != eof )
			goto _out104;
		if ( p == eof ) {
			goto _st104;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st105;
			}
			goto _st0;
		}
		_st105:
		if ( p == eof )
			goto _out105;
		p+= 1;
		st_case_105:
		if ( p == pe && p != eof )
			goto _out105;
		if ( p == eof ) {
			goto _st105;}
		else {
			if ( ( (*( p))) == 118 ) {
				goto _st106;
			}
			goto _st0;
		}
		_st106:
		if ( p == eof )
			goto _out106;
		p+= 1;
		st_case_106:
		if ( p == pe && p != eof )
			goto _out106;
		if ( p == eof ) {
			goto _st106;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st107;
			}
			goto _st0;
		}
		_st107:
		if ( p == eof )
			goto _out107;
		p+= 1;
		st_case_107:
		if ( p == pe && p != eof )
			goto _out107;
		if ( p == eof ) {
			goto _st107;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st108;
			}
			goto _st0;
		}
		_st108:
		if ( p == eof )
			goto _out108;
		p+= 1;
		st_case_108:
		if ( p == pe && p != eof )
			goto _out108;
		if ( p == eof ) {
			goto _st108;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st109;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st109;
			}
			goto _st0;
		}
		_st109:
		if ( p == eof )
			goto _out109;
		p+= 1;
		st_case_109:
		if ( p == pe && p != eof )
			goto _out109;
		if ( p == eof ) {
			goto _st109;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st109;
				}
				case 46: {
					goto _ctr127;
				}
				case 58: {
					goto _ctr129;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st109;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _ctr129;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr129;
				}
			} else {
				goto _ctr128;
			}
			goto _st0;
		}
		_ctr127:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 3475 "cfg.cpp"
		
		goto _st179;
		_ctr238:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 3486 "cfg.cpp"
		
		{
#line 110 "cfg.rl"
			
			emplace_ntp_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 3494 "cfg.cpp"
		
		goto _st179;
		_st179:
		if ( p == eof )
			goto _out179;
		p+= 1;
		st_case_179:
		if ( p == pe && p != eof )
			goto _out179;
		if ( p == eof ) {
			goto _ctr238;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr239;
				}
				case 46: {
					goto _st179;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st179;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr239;
			}
			goto _st0;
		}
		_ctr239:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 3532 "cfg.cpp"
		
		{
#line 110 "cfg.rl"
			
			emplace_ntp_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 3540 "cfg.cpp"
		
		goto _st110;
		_ctr242:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 3551 "cfg.cpp"
		
		{
#line 72 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v6;
		}
		
#line 3560 "cfg.cpp"
		
		{
#line 110 "cfg.rl"
			
			emplace_ntp_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 3568 "cfg.cpp"
		
		goto _st110;
		_ctr246:
		{
#line 72 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v6;
		}
		
#line 3579 "cfg.cpp"
		
		{
#line 110 "cfg.rl"
			
			emplace_ntp_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 3587 "cfg.cpp"
		
		goto _st110;
		_st110:
		if ( p == eof )
			goto _out110;
		p+= 1;
		st_case_110:
		if ( p == pe && p != eof )
			goto _out110;
		if ( p == eof ) {
			goto _st110;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st110;
				}
				case 46: {
					goto _ctr127;
				}
				case 47: {
					goto _st1;
				}
				case 58: {
					goto _ctr129;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st110;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _ctr129;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr129;
				}
			} else {
				goto _ctr128;
			}
			goto _st0;
		}
		_ctr128:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 3636 "cfg.cpp"
		
		goto _st180;
		_ctr241:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 3647 "cfg.cpp"
		
		{
#line 72 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v6;
		}
		
#line 3656 "cfg.cpp"
		
		{
#line 110 "cfg.rl"
			
			emplace_ntp_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 3664 "cfg.cpp"
		
		goto _st180;
		_st180:
		if ( p == eof )
			goto _out180;
		p+= 1;
		st_case_180:
		if ( p == pe && p != eof )
			goto _out180;
		if ( p == eof ) {
			goto _ctr241;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr242;
				}
				case 46: {
					goto _st179;
				}
				case 58: {
					goto _st181;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr242;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st181;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st181;
				}
			} else {
				goto _st180;
			}
			goto _st0;
		}
		_ctr129:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 3710 "cfg.cpp"
		
		goto _st181;
		_ctr245:
		{
#line 72 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v6;
		}
		
#line 3721 "cfg.cpp"
		
		{
#line 110 "cfg.rl"
			
			emplace_ntp_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
		}
		
#line 3729 "cfg.cpp"
		
		goto _st181;
		_st181:
		if ( p == eof )
			goto _out181;
		p+= 1;
		st_case_181:
		if ( p == pe && p != eof )
			goto _out181;
		if ( p == eof ) {
			goto _ctr245;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr246;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr246;
				}
			} else if ( ( (*( p))) > 58 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st181;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st181;
				}
			} else {
				goto _st181;
			}
			goto _st0;
		}
		_st111:
		if ( p == eof )
			goto _out111;
		p+= 1;
		st_case_111:
		if ( p == pe && p != eof )
			goto _out111;
		if ( p == eof ) {
			goto _st111;}
		else {
			if ( ( (*( p))) == 54 ) {
				goto _st112;
			}
			goto _st0;
		}
		_st112:
		if ( p == eof )
			goto _out112;
		p+= 1;
		st_case_112:
		if ( p == pe && p != eof )
			goto _out112;
		if ( p == eof ) {
			goto _st112;}
		else {
			if ( ( (*( p))) == 95 ) {
				goto _st113;
			}
			goto _st0;
		}
		_st113:
		if ( p == eof )
			goto _out113;
		p+= 1;
		st_case_113:
		if ( p == pe && p != eof )
			goto _out113;
		if ( p == eof ) {
			goto _st113;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st114;
			}
			goto _st0;
		}
		_st114:
		if ( p == eof )
			goto _out114;
		p+= 1;
		st_case_114:
		if ( p == pe && p != eof )
			goto _out114;
		if ( p == eof ) {
			goto _st114;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st115;
			}
			goto _st0;
		}
		_st115:
		if ( p == eof )
			goto _out115;
		p+= 1;
		st_case_115:
		if ( p == pe && p != eof )
			goto _out115;
		if ( p == eof ) {
			goto _st115;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st116;
			}
			goto _st0;
		}
		_st116:
		if ( p == eof )
			goto _out116;
		p+= 1;
		st_case_116:
		if ( p == pe && p != eof )
			goto _out116;
		if ( p == eof ) {
			goto _st116;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st117;
			}
			goto _st0;
		}
		_st117:
		if ( p == eof )
			goto _out117;
		p+= 1;
		st_case_117:
		if ( p == pe && p != eof )
			goto _out117;
		if ( p == eof ) {
			goto _st117;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st118;
			}
			goto _st0;
		}
		_st118:
		if ( p == eof )
			goto _out118;
		p+= 1;
		st_case_118:
		if ( p == pe && p != eof )
			goto _out118;
		if ( p == eof ) {
			goto _st118;}
		else {
			if ( ( (*( p))) == 121 ) {
				goto _st119;
			}
			goto _st0;
		}
		_st119:
		if ( p == eof )
			goto _out119;
		p+= 1;
		st_case_119:
		if ( p == pe && p != eof )
			goto _out119;
		if ( p == eof ) {
			goto _st119;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st120;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st120;
			}
			goto _st0;
		}
		_st120:
		if ( p == eof )
			goto _out120;
		p+= 1;
		st_case_120:
		if ( p == pe && p != eof )
			goto _out120;
		if ( p == eof ) {
			goto _st120;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st120;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _ctr141;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st120;
			}
			goto _st0;
		}
		_ctr141:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 3927 "cfg.cpp"
		
		goto _st182;
		_ctr247:
		{
#line 80 "cfg.rl"
			
			if (auto t = nk::from_string<int>(MARKED_STRING())) set_s6_notify_fd(linenum, *t); else {
				cps.parse_error = true;
				{p+= 1; cps.cs = 182; goto _out;}
			}
		}
		
#line 3940 "cfg.cpp"
		
		goto _st182;
		_st182:
		if ( p == eof )
			goto _out182;
		p+= 1;
		st_case_182:
		if ( p == pe && p != eof )
			goto _out182;
		if ( p == eof ) {
			goto _ctr247;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr248;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st182;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr248;
			}
			goto _st0;
		}
		_st121:
		if ( p == eof )
			goto _out121;
		p+= 1;
		st_case_121:
		if ( p == pe && p != eof )
			goto _out121;
		if ( p == eof ) {
			goto _st121;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st122;
			}
			goto _st0;
		}
		_st122:
		if ( p == eof )
			goto _out122;
		p+= 1;
		st_case_122:
		if ( p == pe && p != eof )
			goto _out122;
		if ( p == eof ) {
			goto _st122;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st123;
			}
			goto _st0;
		}
		_st123:
		if ( p == eof )
			goto _out123;
		p+= 1;
		st_case_123:
		if ( p == pe && p != eof )
			goto _out123;
		if ( p == eof ) {
			goto _st123;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st124;
			}
			goto _st0;
		}
		_st124:
		if ( p == eof )
			goto _out124;
		p+= 1;
		st_case_124:
		if ( p == pe && p != eof )
			goto _out124;
		if ( p == eof ) {
			goto _st124;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st125;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st125;
			}
			goto _st0;
		}
		_st125:
		if ( p == eof )
			goto _out125;
		p+= 1;
		st_case_125:
		if ( p == pe && p != eof )
			goto _out125;
		if ( p == eof ) {
			goto _st125;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st125;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 33 <= ( (*( p))) && ( (*( p))) <= 126 ) {
					goto _ctr147;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st125;
			}
			goto _st0;
		}
		_ctr147:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 4055 "cfg.cpp"
		
		goto _st183;
		_ctr250:
		{
#line 78 "cfg.rl"
			set_user_runas(linenum, std::string(MARKED_STRING())); }
		
#line 4063 "cfg.cpp"
		
		goto _st183;
		_st183:
		if ( p == eof )
			goto _out183;
		p+= 1;
		st_case_183:
		if ( p == pe && p != eof )
			goto _out183;
		if ( p == eof ) {
			goto _ctr250;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr251;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 33 <= ( (*( p))) && ( (*( p))) <= 126 ) {
					goto _st183;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr251;
			}
			goto _st0;
		}
		_st126:
		if ( p == eof )
			goto _out126;
		p+= 1;
		st_case_126:
		if ( p == pe && p != eof )
			goto _out126;
		if ( p == eof ) {
			goto _st126;}
		else {
			switch( ( (*( p))) ) {
				case 52: {
					goto _st127;
				}
				case 54: {
					goto _st149;
				}
			}
			goto _st0;
		}
		_st127:
		if ( p == eof )
			goto _out127;
		p+= 1;
		st_case_127:
		if ( p == pe && p != eof )
			goto _out127;
		if ( p == eof ) {
			goto _st127;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st128;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st128;
			}
			goto _st0;
		}
		_st128:
		if ( p == eof )
			goto _out128;
		p+= 1;
		st_case_128:
		if ( p == pe && p != eof )
			goto _out128;
		if ( p == eof ) {
			goto _st128;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st128;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st128;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _ctr152;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr152;
				}
			} else {
				goto _ctr152;
			}
			goto _st0;
		}
		_ctr152:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 4161 "cfg.cpp"
		
		goto _st129;
		_st129:
		if ( p == eof )
			goto _out129;
		p+= 1;
		st_case_129:
		if ( p == pe && p != eof )
			goto _out129;
		if ( p == eof ) {
			goto _st129;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st130;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st130;
				}
			} else {
				goto _st130;
			}
			goto _st0;
		}
		_st130:
		if ( p == eof )
			goto _out130;
		p+= 1;
		st_case_130:
		if ( p == pe && p != eof )
			goto _out130;
		if ( p == eof ) {
			goto _st130;}
		else {
			if ( ( (*( p))) == 58 ) {
				goto _st131;
			}
			goto _st0;
		}
		_st131:
		if ( p == eof )
			goto _out131;
		p+= 1;
		st_case_131:
		if ( p == pe && p != eof )
			goto _out131;
		if ( p == eof ) {
			goto _st131;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st132;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st132;
				}
			} else {
				goto _st132;
			}
			goto _st0;
		}
		_st132:
		if ( p == eof )
			goto _out132;
		p+= 1;
		st_case_132:
		if ( p == pe && p != eof )
			goto _out132;
		if ( p == eof ) {
			goto _st132;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st133;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st133;
				}
			} else {
				goto _st133;
			}
			goto _st0;
		}
		_st133:
		if ( p == eof )
			goto _out133;
		p+= 1;
		st_case_133:
		if ( p == pe && p != eof )
			goto _out133;
		if ( p == eof ) {
			goto _st133;}
		else {
			if ( ( (*( p))) == 58 ) {
				goto _st134;
			}
			goto _st0;
		}
		_st134:
		if ( p == eof )
			goto _out134;
		p+= 1;
		st_case_134:
		if ( p == pe && p != eof )
			goto _out134;
		if ( p == eof ) {
			goto _st134;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st135;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st135;
				}
			} else {
				goto _st135;
			}
			goto _st0;
		}
		_st135:
		if ( p == eof )
			goto _out135;
		p+= 1;
		st_case_135:
		if ( p == pe && p != eof )
			goto _out135;
		if ( p == eof ) {
			goto _st135;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st136;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st136;
				}
			} else {
				goto _st136;
			}
			goto _st0;
		}
		_st136:
		if ( p == eof )
			goto _out136;
		p+= 1;
		st_case_136:
		if ( p == pe && p != eof )
			goto _out136;
		if ( p == eof ) {
			goto _st136;}
		else {
			if ( ( (*( p))) == 58 ) {
				goto _st137;
			}
			goto _st0;
		}
		_st137:
		if ( p == eof )
			goto _out137;
		p+= 1;
		st_case_137:
		if ( p == pe && p != eof )
			goto _out137;
		if ( p == eof ) {
			goto _st137;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st138;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st138;
				}
			} else {
				goto _st138;
			}
			goto _st0;
		}
		_st138:
		if ( p == eof )
			goto _out138;
		p+= 1;
		st_case_138:
		if ( p == pe && p != eof )
			goto _out138;
		if ( p == eof ) {
			goto _st138;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st139;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st139;
				}
			} else {
				goto _st139;
			}
			goto _st0;
		}
		_st139:
		if ( p == eof )
			goto _out139;
		p+= 1;
		st_case_139:
		if ( p == pe && p != eof )
			goto _out139;
		if ( p == eof ) {
			goto _st139;}
		else {
			if ( ( (*( p))) == 58 ) {
				goto _st140;
			}
			goto _st0;
		}
		_st140:
		if ( p == eof )
			goto _out140;
		p+= 1;
		st_case_140:
		if ( p == pe && p != eof )
			goto _out140;
		if ( p == eof ) {
			goto _st140;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st141;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st141;
				}
			} else {
				goto _st141;
			}
			goto _st0;
		}
		_st141:
		if ( p == eof )
			goto _out141;
		p+= 1;
		st_case_141:
		if ( p == pe && p != eof )
			goto _out141;
		if ( p == eof ) {
			goto _st141;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st142;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st142;
				}
			} else {
				goto _st142;
			}
			goto _st0;
		}
		_st142:
		if ( p == eof )
			goto _out142;
		p+= 1;
		st_case_142:
		if ( p == pe && p != eof )
			goto _out142;
		if ( p == eof ) {
			goto _st142;}
		else {
			if ( ( (*( p))) == 58 ) {
				goto _st143;
			}
			goto _st0;
		}
		_st143:
		if ( p == eof )
			goto _out143;
		p+= 1;
		st_case_143:
		if ( p == pe && p != eof )
			goto _out143;
		if ( p == eof ) {
			goto _st143;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st144;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st144;
				}
			} else {
				goto _st144;
			}
			goto _st0;
		}
		_st144:
		if ( p == eof )
			goto _out144;
		p+= 1;
		st_case_144:
		if ( p == pe && p != eof )
			goto _out144;
		if ( p == eof ) {
			goto _st144;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st145;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st145;
				}
			} else {
				goto _st145;
			}
			goto _st0;
		}
		_st145:
		if ( p == eof )
			goto _out145;
		p+= 1;
		st_case_145:
		if ( p == pe && p != eof )
			goto _out145;
		if ( p == eof ) {
			goto _st145;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr170;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _ctr170;
			}
			goto _st0;
		}
		_ctr170:
		{
#line 67 "cfg.rl"
			cps.macaddr = lc_string(MARKED_STRING()); }
		
#line 4515 "cfg.cpp"
		
		goto _st146;
		_st146:
		if ( p == eof )
			goto _out146;
		p+= 1;
		st_case_146:
		if ( p == pe && p != eof )
			goto _out146;
		if ( p == eof ) {
			goto _st146;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st146;
				}
				case 46: {
					goto _ctr172;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _ctr172;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st146;
			}
			goto _st0;
		}
		_ctr172:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 4550 "cfg.cpp"
		
		goto _st184;
		_ctr253:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 4561 "cfg.cpp"
		
		{
#line 126 "cfg.rl"
			
			emplace_dhcp_state(linenum, cps.interface, cps.macaddr, cps.ipaddr,
			cps.default_lifetime);
		}
		
#line 4570 "cfg.cpp"
		
		goto _st184;
		_st184:
		if ( p == eof )
			goto _out184;
		p+= 1;
		st_case_184:
		if ( p == pe && p != eof )
			goto _out184;
		if ( p == eof ) {
			goto _ctr253;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr254;
				}
				case 46: {
					goto _st184;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st184;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr254;
			}
			goto _st0;
		}
		_ctr254:
		{
#line 68 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v4;
		}
		
#line 4608 "cfg.cpp"
		
		goto _st147;
		_st147:
		if ( p == eof )
			goto _out147;
		p+= 1;
		st_case_147:
		if ( p == pe && p != eof )
			goto _out147;
		if ( p == eof ) {
			goto _st147;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st147;
				}
				case 47: {
					goto _st148;
				}
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st147;
			}
			goto _st0;
		}
		_st148:
		if ( p == eof )
			goto _out148;
		p+= 1;
		st_case_148:
		if ( p == pe && p != eof )
			goto _out148;
		if ( p == eof ) {
			goto _st148;}
		else {
			if ( ( (*( p))) == 47 ) {
				goto _st185;
			}
			goto _st0;
		}
		_ctr256:
		{
#line 126 "cfg.rl"
			
			emplace_dhcp_state(linenum, cps.interface, cps.macaddr, cps.ipaddr,
			cps.default_lifetime);
		}
		
#line 4657 "cfg.cpp"
		
		goto _st185;
		_st185:
		if ( p == eof )
			goto _out185;
		p+= 1;
		st_case_185:
		if ( p == pe && p != eof )
			goto _out185;
		if ( p == eof ) {
			goto _ctr256;}
		else {
			goto _st185;
		}
		_st149:
		if ( p == eof )
			goto _out149;
		p+= 1;
		st_case_149:
		if ( p == pe && p != eof )
			goto _out149;
		if ( p == eof ) {
			goto _st149;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st150;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st150;
			}
			goto _st0;
		}
		_st150:
		if ( p == eof )
			goto _out150;
		p+= 1;
		st_case_150:
		if ( p == pe && p != eof )
			goto _out150;
		if ( p == eof ) {
			goto _st150;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st150;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st150;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _ctr177;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr177;
				}
			} else {
				goto _ctr177;
			}
			goto _st0;
		}
		_ctr177:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 4725 "cfg.cpp"
		
		goto _st151;
		_st151:
		if ( p == eof )
			goto _out151;
		p+= 1;
		st_case_151:
		if ( p == pe && p != eof )
			goto _out151;
		if ( p == eof ) {
			goto _st151;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr179;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr179;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st157;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st157;
				}
			} else {
				goto _st157;
			}
			goto _st0;
		}
		_ctr179:
		{
#line 65 "cfg.rl"
			cps.duid = lc_string(MARKED_STRING()); }
		
#line 4763 "cfg.cpp"
		
		goto _st152;
		_st152:
		if ( p == eof )
			goto _out152;
		p+= 1;
		st_case_152:
		if ( p == pe && p != eof )
			goto _out152;
		if ( p == eof ) {
			goto _st152;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st152;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _ctr182;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st152;
			}
			goto _st0;
		}
		_ctr182:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 4793 "cfg.cpp"
		
		goto _st153;
		_st153:
		if ( p == eof )
			goto _out153;
		p+= 1;
		st_case_153:
		if ( p == pe && p != eof )
			goto _out153;
		if ( p == eof ) {
			goto _st153;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr184;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st153;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr184;
			}
			goto _st0;
		}
		_ctr184:
		{
#line 66 "cfg.rl"
			cps.iaid = lc_string(MARKED_STRING()); }
		
#line 4823 "cfg.cpp"
		
		goto _st154;
		_st154:
		if ( p == eof )
			goto _out154;
		p+= 1;
		st_case_154:
		if ( p == pe && p != eof )
			goto _out154;
		if ( p == eof ) {
			goto _st154;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st154;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st154;
				}
			} else if ( ( (*( p))) > 58 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _ctr186;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr186;
				}
			} else {
				goto _ctr186;
			}
			goto _st0;
		}
		_ctr186:
		{
#line 63 "cfg.rl"
			cps.st = p; }
		
#line 4861 "cfg.cpp"
		
		goto _st186;
		_ctr257:
		{
#line 72 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v6;
		}
		
#line 4872 "cfg.cpp"
		
		{
#line 130 "cfg.rl"
			
			if (auto iaid = nk::from_string<uint32_t>(cps.iaid)) {
				emplace_dhcp_state(linenum, cps.interface, std::move(cps.duid),
				*iaid, cps.ipaddr, cps.default_lifetime);
			} else {
				cps.parse_error = true;
				{p+= 1; cps.cs = 186; goto _out;}
			}
		}
		
#line 4886 "cfg.cpp"
		
		goto _st186;
		_st186:
		if ( p == eof )
			goto _out186;
		p+= 1;
		st_case_186:
		if ( p == pe && p != eof )
			goto _out186;
		if ( p == eof ) {
			goto _ctr257;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr258;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr258;
				}
			} else if ( ( (*( p))) > 58 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st186;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st186;
				}
			} else {
				goto _st186;
			}
			goto _st0;
		}
		_ctr258:
		{
#line 72 "cfg.rl"
			
			cps.ipaddr = lc_string(MARKED_STRING());
			cps.last_addr = addr_type::v6;
		}
		
#line 4927 "cfg.cpp"
		
		goto _st155;
		_st155:
		if ( p == eof )
			goto _out155;
		p+= 1;
		st_case_155:
		if ( p == pe && p != eof )
			goto _out155;
		if ( p == eof ) {
			goto _st155;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _st155;
				}
				case 47: {
					goto _st156;
				}
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st155;
			}
			goto _st0;
		}
		_st156:
		if ( p == eof )
			goto _out156;
		p+= 1;
		st_case_156:
		if ( p == pe && p != eof )
			goto _out156;
		if ( p == eof ) {
			goto _st156;}
		else {
			if ( ( (*( p))) == 47 ) {
				goto _st187;
			}
			goto _st0;
		}
		_ctr260:
		{
#line 130 "cfg.rl"
			
			if (auto iaid = nk::from_string<uint32_t>(cps.iaid)) {
				emplace_dhcp_state(linenum, cps.interface, std::move(cps.duid),
				*iaid, cps.ipaddr, cps.default_lifetime);
			} else {
				cps.parse_error = true;
				{p+= 1; cps.cs = 187; goto _out;}
			}
		}
		
#line 4981 "cfg.cpp"
		
		goto _st187;
		_st187:
		if ( p == eof )
			goto _out187;
		p+= 1;
		st_case_187:
		if ( p == pe && p != eof )
			goto _out187;
		if ( p == eof ) {
			goto _ctr260;}
		else {
			goto _st187;
		}
		_st157:
		if ( p == eof )
			goto _out157;
		p+= 1;
		st_case_157:
		if ( p == pe && p != eof )
			goto _out157;
		if ( p == eof ) {
			goto _st157;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr179;
				}
				case 45: {
					goto _st158;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr179;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st151;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st151;
				}
			} else {
				goto _st151;
			}
			goto _st0;
		}
		_st158:
		if ( p == eof )
			goto _out158;
		p+= 1;
		st_case_158:
		if ( p == pe && p != eof )
			goto _out158;
		if ( p == eof ) {
			goto _st158;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st159;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st159;
				}
			} else {
				goto _st159;
			}
			goto _st0;
		}
		_st159:
		if ( p == eof )
			goto _out159;
		p+= 1;
		st_case_159:
		if ( p == pe && p != eof )
			goto _out159;
		if ( p == eof ) {
			goto _st159;}
		else {
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st160;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st160;
				}
			} else {
				goto _st160;
			}
			goto _st0;
		}
		_st160:
		if ( p == eof )
			goto _out160;
		p+= 1;
		st_case_160:
		if ( p == pe && p != eof )
			goto _out160;
		if ( p == eof ) {
			goto _st160;}
		else {
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr179;
				}
				case 45: {
					goto _st158;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr179;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st159;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st159;
				}
			} else {
				goto _st159;
			}
			goto _st0;
		}
		_out161: cps.cs = 161; goto _out; 
		_out0: cps.cs = 0; goto _out; 
		_out1: cps.cs = 1; goto _out; 
		_out162: cps.cs = 162; goto _out; 
		_out2: cps.cs = 2; goto _out; 
		_out3: cps.cs = 3; goto _out; 
		_out4: cps.cs = 4; goto _out; 
		_out5: cps.cs = 5; goto _out; 
		_out6: cps.cs = 6; goto _out; 
		_out7: cps.cs = 7; goto _out; 
		_out163: cps.cs = 163; goto _out; 
		_out8: cps.cs = 8; goto _out; 
		_out9: cps.cs = 9; goto _out; 
		_out10: cps.cs = 10; goto _out; 
		_out164: cps.cs = 164; goto _out; 
		_out11: cps.cs = 11; goto _out; 
		_out12: cps.cs = 12; goto _out; 
		_out13: cps.cs = 13; goto _out; 
		_out14: cps.cs = 14; goto _out; 
		_out15: cps.cs = 15; goto _out; 
		_out16: cps.cs = 16; goto _out; 
		_out17: cps.cs = 17; goto _out; 
		_out18: cps.cs = 18; goto _out; 
		_out165: cps.cs = 165; goto _out; 
		_out19: cps.cs = 19; goto _out; 
		_out20: cps.cs = 20; goto _out; 
		_out21: cps.cs = 21; goto _out; 
		_out22: cps.cs = 22; goto _out; 
		_out23: cps.cs = 23; goto _out; 
		_out24: cps.cs = 24; goto _out; 
		_out25: cps.cs = 25; goto _out; 
		_out26: cps.cs = 26; goto _out; 
		_out27: cps.cs = 27; goto _out; 
		_out28: cps.cs = 28; goto _out; 
		_out29: cps.cs = 29; goto _out; 
		_out30: cps.cs = 30; goto _out; 
		_out31: cps.cs = 31; goto _out; 
		_out32: cps.cs = 32; goto _out; 
		_out33: cps.cs = 33; goto _out; 
		_out34: cps.cs = 34; goto _out; 
		_out35: cps.cs = 35; goto _out; 
		_out36: cps.cs = 36; goto _out; 
		_out166: cps.cs = 166; goto _out; 
		_out37: cps.cs = 37; goto _out; 
		_out38: cps.cs = 38; goto _out; 
		_out39: cps.cs = 39; goto _out; 
		_out40: cps.cs = 40; goto _out; 
		_out41: cps.cs = 41; goto _out; 
		_out42: cps.cs = 42; goto _out; 
		_out43: cps.cs = 43; goto _out; 
		_out44: cps.cs = 44; goto _out; 
		_out45: cps.cs = 45; goto _out; 
		_out46: cps.cs = 46; goto _out; 
		_out47: cps.cs = 47; goto _out; 
		_out167: cps.cs = 167; goto _out; 
		_out48: cps.cs = 48; goto _out; 
		_out49: cps.cs = 49; goto _out; 
		_out50: cps.cs = 50; goto _out; 
		_out51: cps.cs = 51; goto _out; 
		_out52: cps.cs = 52; goto _out; 
		_out53: cps.cs = 53; goto _out; 
		_out54: cps.cs = 54; goto _out; 
		_out55: cps.cs = 55; goto _out; 
		_out56: cps.cs = 56; goto _out; 
		_out57: cps.cs = 57; goto _out; 
		_out168: cps.cs = 168; goto _out; 
		_out58: cps.cs = 58; goto _out; 
		_out169: cps.cs = 169; goto _out; 
		_out170: cps.cs = 170; goto _out; 
		_out171: cps.cs = 171; goto _out; 
		_out59: cps.cs = 59; goto _out; 
		_out60: cps.cs = 60; goto _out; 
		_out61: cps.cs = 61; goto _out; 
		_out62: cps.cs = 62; goto _out; 
		_out63: cps.cs = 63; goto _out; 
		_out172: cps.cs = 172; goto _out; 
		_out64: cps.cs = 64; goto _out; 
		_out173: cps.cs = 173; goto _out; 
		_out174: cps.cs = 174; goto _out; 
		_out65: cps.cs = 65; goto _out; 
		_out66: cps.cs = 66; goto _out; 
		_out67: cps.cs = 67; goto _out; 
		_out68: cps.cs = 68; goto _out; 
		_out69: cps.cs = 69; goto _out; 
		_out70: cps.cs = 70; goto _out; 
		_out71: cps.cs = 71; goto _out; 
		_out72: cps.cs = 72; goto _out; 
		_out73: cps.cs = 73; goto _out; 
		_out74: cps.cs = 74; goto _out; 
		_out75: cps.cs = 75; goto _out; 
		_out76: cps.cs = 76; goto _out; 
		_out77: cps.cs = 77; goto _out; 
		_out78: cps.cs = 78; goto _out; 
		_out79: cps.cs = 79; goto _out; 
		_out175: cps.cs = 175; goto _out; 
		_out80: cps.cs = 80; goto _out; 
		_out176: cps.cs = 176; goto _out; 
		_out81: cps.cs = 81; goto _out; 
		_out82: cps.cs = 82; goto _out; 
		_out83: cps.cs = 83; goto _out; 
		_out84: cps.cs = 84; goto _out; 
		_out85: cps.cs = 85; goto _out; 
		_out86: cps.cs = 86; goto _out; 
		_out87: cps.cs = 87; goto _out; 
		_out88: cps.cs = 88; goto _out; 
		_out177: cps.cs = 177; goto _out; 
		_out89: cps.cs = 89; goto _out; 
		_out90: cps.cs = 90; goto _out; 
		_out91: cps.cs = 91; goto _out; 
		_out92: cps.cs = 92; goto _out; 
		_out93: cps.cs = 93; goto _out; 
		_out94: cps.cs = 94; goto _out; 
		_out95: cps.cs = 95; goto _out; 
		_out96: cps.cs = 96; goto _out; 
		_out97: cps.cs = 97; goto _out; 
		_out98: cps.cs = 98; goto _out; 
		_out178: cps.cs = 178; goto _out; 
		_out99: cps.cs = 99; goto _out; 
		_out100: cps.cs = 100; goto _out; 
		_out101: cps.cs = 101; goto _out; 
		_out102: cps.cs = 102; goto _out; 
		_out103: cps.cs = 103; goto _out; 
		_out104: cps.cs = 104; goto _out; 
		_out105: cps.cs = 105; goto _out; 
		_out106: cps.cs = 106; goto _out; 
		_out107: cps.cs = 107; goto _out; 
		_out108: cps.cs = 108; goto _out; 
		_out109: cps.cs = 109; goto _out; 
		_out179: cps.cs = 179; goto _out; 
		_out110: cps.cs = 110; goto _out; 
		_out180: cps.cs = 180; goto _out; 
		_out181: cps.cs = 181; goto _out; 
		_out111: cps.cs = 111; goto _out; 
		_out112: cps.cs = 112; goto _out; 
		_out113: cps.cs = 113; goto _out; 
		_out114: cps.cs = 114; goto _out; 
		_out115: cps.cs = 115; goto _out; 
		_out116: cps.cs = 116; goto _out; 
		_out117: cps.cs = 117; goto _out; 
		_out118: cps.cs = 118; goto _out; 
		_out119: cps.cs = 119; goto _out; 
		_out120: cps.cs = 120; goto _out; 
		_out182: cps.cs = 182; goto _out; 
		_out121: cps.cs = 121; goto _out; 
		_out122: cps.cs = 122; goto _out; 
		_out123: cps.cs = 123; goto _out; 
		_out124: cps.cs = 124; goto _out; 
		_out125: cps.cs = 125; goto _out; 
		_out183: cps.cs = 183; goto _out; 
		_out126: cps.cs = 126; goto _out; 
		_out127: cps.cs = 127; goto _out; 
		_out128: cps.cs = 128; goto _out; 
		_out129: cps.cs = 129; goto _out; 
		_out130: cps.cs = 130; goto _out; 
		_out131: cps.cs = 131; goto _out; 
		_out132: cps.cs = 132; goto _out; 
		_out133: cps.cs = 133; goto _out; 
		_out134: cps.cs = 134; goto _out; 
		_out135: cps.cs = 135; goto _out; 
		_out136: cps.cs = 136; goto _out; 
		_out137: cps.cs = 137; goto _out; 
		_out138: cps.cs = 138; goto _out; 
		_out139: cps.cs = 139; goto _out; 
		_out140: cps.cs = 140; goto _out; 
		_out141: cps.cs = 141; goto _out; 
		_out142: cps.cs = 142; goto _out; 
		_out143: cps.cs = 143; goto _out; 
		_out144: cps.cs = 144; goto _out; 
		_out145: cps.cs = 145; goto _out; 
		_out146: cps.cs = 146; goto _out; 
		_out184: cps.cs = 184; goto _out; 
		_out147: cps.cs = 147; goto _out; 
		_out148: cps.cs = 148; goto _out; 
		_out185: cps.cs = 185; goto _out; 
		_out149: cps.cs = 149; goto _out; 
		_out150: cps.cs = 150; goto _out; 
		_out151: cps.cs = 151; goto _out; 
		_out152: cps.cs = 152; goto _out; 
		_out153: cps.cs = 153; goto _out; 
		_out154: cps.cs = 154; goto _out; 
		_out186: cps.cs = 186; goto _out; 
		_out155: cps.cs = 155; goto _out; 
		_out156: cps.cs = 156; goto _out; 
		_out187: cps.cs = 187; goto _out; 
		_out157: cps.cs = 157; goto _out; 
		_out158: cps.cs = 158; goto _out; 
		_out159: cps.cs = 159; goto _out; 
		_out160: cps.cs = 160; goto _out; 
		_out: {}
	}
	
#line 179 "cfg.rl"
	
	
	if (cps.parse_error) return -1;
		if (cps.cs >= cfg_line_m_first_final)
		return 1;
	if (cps.cs == cfg_line_m_error)
		return -1;
	return -2;
}

void parse_config(const std::string &path)
{
	char buf[MAX_LINE];
	auto f = fopen(path.c_str(), "r");
	if (!f) {
		log_line("%s: failed to open config file \"%s\" for read: %s",
		__func__, path.c_str(), strerror(errno));
		return;
	}
	SCOPE_EXIT{ fclose(f); };
	size_t linenum = 0;
	cfg_parse_state ps;
	while (!feof(f)) {
		if (!fgets(buf, sizeof buf, f)) {
			if (!feof(f))
				log_line("%s: io error fetching line of '%s'", __func__, path.c_str());
			break;
		}
		auto llen = strlen(buf);
		if (llen == 0)
			continue;
		if (buf[llen-1] == '\n')
			buf[--llen] = 0;
		++linenum;
		ps.newline();
		const auto r = do_parse_cfg_line(ps, buf, llen, linenum);
		if (r < 0) {
			if (r == -2)
				log_line("%s: Incomplete configuration at line %zu; ignoring",
			__func__, linenum);
			else
				log_line("%s: Malformed configuration at line %zu; ignoring.",
			__func__, linenum);
			continue;
		}
	}
	create_blobs();
}

