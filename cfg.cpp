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



#line 63 "cfg.cpp"
static const signed char _cfg_line_m_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1,
	3, 1, 4, 1, 5, 1, 6, 1,
	7, 1, 8, 1, 9, 1, 10, 1,
	11, 1, 12, 1, 13, 1, 15, 1,
	20, 1, 21, 1, 22, 2, 4, 14,
	2, 4, 16, 2, 4, 17, 2, 4,
	18, 2, 4, 19, 2, 4, 21, 2,
	5, 14, 2, 5, 16, 2, 5, 22,
	3, 4, 5, 14, 3, 4, 5, 16,
	0
};

static const short _cfg_line_m_key_offsets[] = {
	0, 0, 1, 2, 3, 4, 6, 9,
	18, 28, 31, 40, 50, 51, 52, 53,
	54, 55, 58, 63, 67, 70, 71, 72,
	73, 74, 75, 76, 78, 79, 80, 81,
	82, 83, 84, 85, 88, 93, 94, 95,
	96, 97, 98, 99, 100, 101, 102, 105,
	110, 111, 112, 113, 114, 116, 117, 118,
	119, 122, 127, 133, 134, 135, 136, 139,
	150, 162, 163, 164, 165, 166, 167, 168,
	170, 171, 172, 173, 174, 177, 183, 189,
	195, 196, 197, 198, 199, 200, 201, 202,
	205, 211, 212, 213, 214, 215, 216, 217,
	218, 219, 222, 231, 232, 233, 234, 235,
	236, 237, 238, 239, 240, 243, 254, 266,
	267, 268, 269, 270, 271, 272, 273, 274,
	277, 282, 283, 284, 285, 288, 293, 295,
	298, 307, 313, 314, 320, 326, 327, 333,
	339, 340, 346, 352, 353, 359, 365, 366,
	372, 378, 381, 387, 391, 392, 395, 404,
	413, 418, 423, 432, 436, 437, 447, 453,
	459, 469, 482, 482, 491, 500, 505, 510,
	515, 520, 526, 531, 536, 542, 553, 562,
	568, 571, 577, 586, 592, 603, 612, 617,
	622, 628, 628, 637, 0
};

static const char _cfg_line_m_trans_keys[] = {
	47, 105, 110, 100, 52, 54, 32, 9,
	13, 32, 9, 13, 48, 57, 65, 90,
	97, 122, 32, 47, 9, 13, 48, 57,
	65, 90, 97, 122, 32, 9, 13, 32,
	9, 13, 48, 57, 65, 90, 97, 122,
	32, 47, 9, 13, 48, 57, 65, 90,
	97, 122, 104, 114, 111, 111, 116, 32,
	9, 13, 32, 9, 13, 33, 126, 32,
	47, 9, 13, 101, 110, 121, 102, 97,
	117, 108, 116, 95, 108, 112, 105, 102,
	101, 116, 105, 109, 101, 32, 9, 13,
	32, 9, 13, 48, 57, 114, 101, 102,
	101, 114, 101, 110, 99, 101, 32, 9,
	13, 32, 9, 13, 48, 57, 115, 95,
	115, 101, 97, 114, 114, 99, 104, 32,
	9, 13, 32, 9, 13, 33, 126, 32,
	47, 9, 13, 33, 126, 118, 101, 114,
	32, 9, 13, 32, 46, 58, 9, 13,
	48, 57, 65, 70, 97, 102, 32, 46,
	47, 58, 9, 13, 48, 57, 65, 70,
	97, 102, 110, 97, 109, 105, 99, 95,
	114, 118, 97, 110, 103, 101, 32, 9,
	13, 32, 46, 9, 13, 48, 57, 32,
	46, 9, 13, 48, 57, 32, 46, 9,
	13, 48, 57, 54, 97, 116, 101, 119,
	97, 121, 32, 9, 13, 32, 46, 9,
	13, 48, 57, 110, 116, 101, 114, 102,
	97, 99, 101, 32, 9, 13, 32, 9,
	13, 48, 57, 65, 90, 97, 122, 116,
	112, 95, 115, 101, 114, 118, 101, 114,
	32, 9, 13, 32, 46, 58, 9, 13,
	48, 57, 65, 70, 97, 102, 32, 46,
	47, 58, 9, 13, 48, 57, 65, 70,
	97, 102, 54, 95, 110, 111, 116, 105,
	102, 121, 32, 9, 13, 32, 9, 13,
	48, 57, 115, 101, 114, 32, 9, 13,
	32, 9, 13, 33, 126, 52, 54, 32,
	9, 13, 32, 9, 13, 48, 57, 65,
	70, 97, 102, 48, 57, 65, 70, 97,
	102, 58, 48, 57, 65, 70, 97, 102,
	48, 57, 65, 70, 97, 102, 58, 48,
	57, 65, 70, 97, 102, 48, 57, 65,
	70, 97, 102, 58, 48, 57, 65, 70,
	97, 102, 48, 57, 65, 70, 97, 102,
	58, 48, 57, 65, 70, 97, 102, 48,
	57, 65, 70, 97, 102, 58, 48, 57,
	65, 70, 97, 102, 48, 57, 65, 70,
	97, 102, 32, 9, 13, 32, 46, 9,
	13, 48, 57, 32, 47, 9, 13, 47,
	32, 9, 13, 32, 9, 13, 48, 57,
	65, 70, 97, 102, 32, 9, 13, 48,
	57, 65, 70, 97, 102, 32, 9, 13,
	48, 57, 32, 9, 13, 48, 57, 32,
	9, 13, 48, 58, 65, 70, 97, 102,
	32, 47, 9, 13, 47, 32, 45, 9,
	13, 48, 57, 65, 70, 97, 102, 48,
	57, 65, 70, 97, 102, 48, 57, 65,
	70, 97, 102, 32, 45, 9, 13, 48,
	57, 65, 70, 97, 102, 32, 47, 98,
	99, 100, 103, 105, 110, 115, 117, 118,
	9, 13, 32, 9, 13, 48, 57, 65,
	90, 97, 122, 32, 9, 13, 48, 57,
	65, 90, 97, 122, 32, 9, 13, 33,
	126, 32, 9, 13, 48, 57, 32, 9,
	13, 48, 57, 32, 9, 13, 33, 126,
	32, 47, 9, 13, 33, 126, 32, 9,
	13, 33, 126, 32, 9, 13, 33, 126,
	32, 46, 9, 13, 48, 57, 32, 46,
	58, 9, 13, 48, 57, 65, 70, 97,
	102, 32, 9, 13, 48, 58, 65, 70,
	97, 102, 32, 46, 9, 13, 48, 57,
	32, 9, 13, 32, 46, 9, 13, 48,
	57, 32, 9, 13, 48, 57, 65, 90,
	97, 122, 32, 46, 9, 13, 48, 57,
	32, 46, 58, 9, 13, 48, 57, 65,
	70, 97, 102, 32, 9, 13, 48, 58,
	65, 70, 97, 102, 32, 9, 13, 48,
	57, 32, 9, 13, 33, 126, 32, 46,
	9, 13, 48, 57, 32, 9, 13, 48,
	58, 65, 70, 97, 102, 0
};

static const signed char _cfg_line_m_single_lengths[] = {
	0, 1, 1, 1, 1, 2, 1, 1,
	2, 1, 1, 2, 1, 1, 1, 1,
	1, 1, 1, 2, 3, 1, 1, 1,
	1, 1, 1, 2, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 2, 1, 1, 1,
	1, 1, 2, 1, 1, 1, 1, 3,
	4, 1, 1, 1, 1, 1, 1, 2,
	1, 1, 1, 1, 1, 2, 2, 2,
	1, 1, 1, 1, 1, 1, 1, 1,
	2, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 3, 4, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 2, 1,
	1, 0, 1, 0, 0, 1, 0, 0,
	1, 0, 0, 1, 0, 0, 1, 0,
	0, 1, 2, 2, 1, 1, 1, 1,
	1, 1, 1, 2, 1, 2, 0, 0,
	2, 11, 0, 1, 1, 1, 1, 1,
	1, 2, 1, 1, 2, 3, 1, 2,
	1, 2, 1, 2, 3, 1, 1, 1,
	2, 0, 1, 0, 0
};

static const signed char _cfg_line_m_range_lengths[] = {
	0, 0, 0, 0, 0, 0, 1, 4,
	4, 1, 4, 4, 0, 0, 0, 0,
	0, 1, 2, 1, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 1, 2, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 2,
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 2, 2, 0, 0, 0, 1, 4,
	4, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 2, 2, 2,
	0, 0, 0, 0, 0, 0, 0, 1,
	2, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 4, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 4, 4, 0,
	0, 0, 0, 0, 0, 0, 0, 1,
	2, 0, 0, 0, 1, 2, 0, 1,
	4, 3, 0, 3, 3, 0, 3, 3,
	0, 3, 3, 0, 3, 3, 0, 3,
	3, 1, 2, 1, 0, 1, 4, 4,
	2, 2, 4, 1, 0, 4, 3, 3,
	4, 1, 0, 4, 4, 2, 2, 2,
	2, 2, 2, 2, 2, 4, 4, 2,
	1, 2, 4, 2, 4, 4, 2, 2,
	2, 0, 4, 0, 0
};

static const short _cfg_line_m_index_offsets[] = {
	0, 0, 2, 4, 6, 8, 11, 14,
	20, 27, 30, 36, 43, 45, 47, 49,
	51, 53, 56, 60, 64, 68, 70, 72,
	74, 76, 78, 80, 83, 85, 87, 89,
	91, 93, 95, 97, 100, 104, 106, 108,
	110, 112, 114, 116, 118, 120, 122, 125,
	129, 131, 133, 135, 137, 140, 142, 144,
	146, 149, 153, 158, 160, 162, 164, 167,
	175, 184, 186, 188, 190, 192, 194, 196,
	199, 201, 203, 205, 207, 210, 215, 220,
	225, 227, 229, 231, 233, 235, 237, 239,
	242, 247, 249, 251, 253, 255, 257, 259,
	261, 263, 266, 272, 274, 276, 278, 280,
	282, 284, 286, 288, 290, 293, 301, 310,
	312, 314, 316, 318, 320, 322, 324, 326,
	329, 333, 335, 337, 339, 342, 346, 349,
	352, 358, 362, 364, 368, 372, 374, 378,
	382, 384, 388, 392, 394, 398, 402, 404,
	408, 412, 415, 420, 424, 426, 429, 435,
	441, 445, 449, 455, 459, 461, 468, 472,
	476, 483, 496, 497, 503, 509, 513, 517,
	521, 525, 530, 534, 538, 543, 551, 557,
	562, 565, 570, 576, 581, 589, 595, 599,
	603, 608, 609, 615, 0
};

static const short _cfg_line_m_cond_targs[] = {
	162, 0, 3, 0, 4, 0, 5, 0,
	6, 9, 0, 7, 7, 0, 7, 7,
	163, 163, 163, 0, 8, 1, 8, 163,
	163, 163, 0, 10, 10, 0, 10, 10,
	164, 164, 164, 0, 11, 1, 11, 164,
	164, 164, 0, 13, 0, 14, 0, 15,
	0, 16, 0, 17, 0, 18, 18, 0,
	18, 18, 165, 0, 19, 1, 19, 0,
	21, 48, 65, 0, 22, 0, 23, 0,
	24, 0, 25, 0, 26, 0, 27, 0,
	28, 37, 0, 29, 0, 30, 0, 31,
	0, 32, 0, 33, 0, 34, 0, 35,
	0, 36, 36, 0, 36, 36, 166, 0,
	38, 0, 39, 0, 40, 0, 41, 0,
	42, 0, 43, 0, 44, 0, 45, 0,
	46, 0, 47, 47, 0, 47, 47, 167,
	0, 49, 0, 50, 0, 51, 0, 52,
	0, 53, 59, 0, 54, 0, 55, 0,
	56, 0, 57, 57, 0, 57, 57, 168,
	0, 58, 169, 58, 168, 0, 60, 0,
	61, 0, 62, 0, 63, 63, 0, 63,
	172, 174, 63, 173, 174, 174, 0, 64,
	172, 1, 174, 64, 173, 174, 174, 0,
	66, 0, 67, 0, 68, 0, 69, 0,
	70, 0, 71, 0, 72, 80, 0, 73,
	0, 74, 0, 75, 0, 76, 0, 77,
	77, 0, 77, 78, 77, 78, 0, 79,
	78, 79, 78, 0, 79, 175, 79, 175,
	0, 176, 0, 82, 0, 83, 0, 84,
	0, 85, 0, 86, 0, 87, 0, 88,
	88, 0, 88, 177, 88, 177, 0, 90,
	0, 91, 0, 92, 0, 93, 0, 94,
	0, 95, 0, 96, 0, 97, 0, 98,
	98, 0, 98, 98, 178, 178, 178, 0,
	100, 0, 101, 0, 102, 0, 103, 0,
	104, 0, 105, 0, 106, 0, 107, 0,
	108, 0, 109, 109, 0, 109, 179, 181,
	109, 180, 181, 181, 0, 110, 179, 1,
	181, 110, 180, 181, 181, 0, 112, 0,
	113, 0, 114, 0, 115, 0, 116, 0,
	117, 0, 118, 0, 119, 0, 120, 120,
	0, 120, 120, 182, 0, 122, 0, 123,
	0, 124, 0, 125, 125, 0, 125, 125,
	183, 0, 127, 149, 0, 128, 128, 0,
	128, 128, 129, 129, 129, 0, 130, 130,
	130, 0, 131, 0, 132, 132, 132, 0,
	133, 133, 133, 0, 134, 0, 135, 135,
	135, 0, 136, 136, 136, 0, 137, 0,
	138, 138, 138, 0, 139, 139, 139, 0,
	140, 0, 141, 141, 141, 0, 142, 142,
	142, 0, 143, 0, 144, 144, 144, 0,
	145, 145, 145, 0, 146, 146, 0, 146,
	184, 146, 184, 0, 147, 148, 147, 0,
	185, 0, 150, 150, 0, 150, 150, 151,
	151, 151, 0, 152, 152, 157, 157, 157,
	0, 152, 152, 153, 0, 154, 154, 153,
	0, 154, 154, 186, 186, 186, 0, 155,
	156, 155, 0, 187, 0, 152, 158, 152,
	151, 151, 151, 0, 159, 159, 159, 0,
	160, 160, 160, 0, 152, 158, 152, 159,
	159, 159, 0, 161, 1, 2, 12, 20,
	81, 89, 99, 111, 121, 126, 161, 0,
	162, 8, 8, 163, 163, 163, 0, 11,
	11, 164, 164, 164, 0, 19, 19, 165,
	0, 19, 19, 166, 0, 19, 19, 167,
	0, 58, 58, 168, 0, 58, 170, 58,
	168, 0, 171, 171, 170, 162, 171, 171,
	170, 162, 64, 172, 64, 172, 0, 64,
	172, 174, 64, 173, 174, 174, 0, 64,
	64, 174, 174, 174, 0, 19, 175, 19,
	175, 0, 19, 19, 0, 19, 177, 19,
	177, 0, 19, 19, 178, 178, 178, 0,
	110, 179, 110, 179, 0, 110, 179, 181,
	110, 180, 181, 181, 0, 110, 110, 181,
	181, 181, 0, 19, 19, 182, 0, 19,
	19, 183, 0, 147, 184, 147, 184, 0,
	185, 155, 155, 186, 186, 186, 0, 187,
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
	24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39,
	40, 41, 42, 43, 44, 45, 46, 47,
	48, 49, 50, 51, 52, 53, 54, 55,
	56, 57, 58, 59, 60, 61, 62, 63,
	64, 65, 66, 67, 68, 69, 70, 71,
	72, 73, 74, 75, 76, 77, 78, 79,
	80, 81, 82, 83, 84, 85, 86, 87,
	88, 89, 90, 91, 92, 93, 94, 95,
	96, 97, 98, 99, 100, 101, 102, 103,
	104, 105, 106, 107, 108, 109, 110, 111,
	112, 113, 114, 115, 116, 117, 118, 119,
	120, 121, 122, 123, 124, 125, 126, 127,
	128, 129, 130, 131, 132, 133, 134, 135,
	136, 137, 138, 139, 140, 141, 142, 143,
	144, 145, 146, 147, 148, 149, 150, 151,
	152, 153, 154, 155, 156, 157, 158, 159,
	160, 161, 162, 163, 164, 165, 166, 167,
	168, 169, 170, 171, 172, 173, 174, 175,
	176, 177, 178, 179, 180, 181, 182, 183,
	184, 185, 186, 187, 0
};

static const signed char _cfg_line_m_cond_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 0, 0, 0, 0, 1,
	1, 1, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 0, 0, 0, 0, 1,
	1, 1, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 1,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 1,
	0, 0, 1, 0, 1, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 0, 1, 1, 1, 0, 0,
	1, 0, 1, 0, 1, 1, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 1, 0, 1, 0, 46,
	0, 46, 0, 0, 0, 1, 0, 1,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 1, 0, 1, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 1, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 1,
	0, 1, 1, 1, 0, 0, 1, 0,
	1, 0, 1, 1, 1, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 1, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 1, 1, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 7, 7, 0, 0,
	1, 0, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 1,
	1, 1, 0, 3, 3, 0, 0, 0,
	0, 0, 0, 1, 0, 5, 5, 0,
	0, 0, 0, 1, 1, 1, 0, 0,
	0, 0, 0, 0, 0, 3, 0, 3,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 3, 0, 3, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 13, 13, 0, 0, 0, 0, 15,
	15, 0, 0, 0, 0, 19, 19, 0,
	0, 23, 23, 0, 0, 25, 25, 0,
	0, 29, 29, 0, 0, 29, 0, 29,
	0, 0, 29, 29, 0, 0, 0, 0,
	1, 0, 37, 0, 37, 0, 0, 64,
	0, 0, 64, 0, 0, 0, 0, 55,
	55, 0, 0, 0, 0, 49, 0, 49,
	0, 0, 31, 31, 0, 43, 0, 43,
	0, 0, 27, 27, 0, 0, 0, 0,
	40, 0, 40, 0, 0, 68, 0, 0,
	68, 0, 0, 0, 0, 58, 58, 0,
	0, 0, 0, 21, 21, 0, 0, 17,
	17, 0, 0, 9, 0, 9, 0, 0,
	0, 11, 11, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 13, 15, 19, 23, 25,
	29, 29, 29, 0, 37, 64, 55, 49,
	31, 43, 27, 40, 68, 58, 21, 17,
	52, 33, 61, 35, 0
};

static const short _cfg_line_m_eof_trans[] = {
	617, 618, 619, 620, 621, 622, 623, 624,
	625, 626, 627, 628, 629, 630, 631, 632,
	633, 634, 635, 636, 637, 638, 639, 640,
	641, 642, 643, 644, 645, 646, 647, 648,
	649, 650, 651, 652, 653, 654, 655, 656,
	657, 658, 659, 660, 661, 662, 663, 664,
	665, 666, 667, 668, 669, 670, 671, 672,
	673, 674, 675, 676, 677, 678, 679, 680,
	681, 682, 683, 684, 685, 686, 687, 688,
	689, 690, 691, 692, 693, 694, 695, 696,
	697, 698, 699, 700, 701, 702, 703, 704,
	705, 706, 707, 708, 709, 710, 711, 712,
	713, 714, 715, 716, 717, 718, 719, 720,
	721, 722, 723, 724, 725, 726, 727, 728,
	729, 730, 731, 732, 733, 734, 735, 736,
	737, 738, 739, 740, 741, 742, 743, 744,
	745, 746, 747, 748, 749, 750, 751, 752,
	753, 754, 755, 756, 757, 758, 759, 760,
	761, 762, 763, 764, 765, 766, 767, 768,
	769, 770, 771, 772, 773, 774, 775, 776,
	777, 778, 779, 780, 781, 782, 783, 784,
	785, 786, 787, 788, 789, 790, 791, 792,
	793, 794, 795, 796, 797, 798, 799, 800,
	801, 802, 803, 804, 0
};

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
	

#line 517 "cfg.cpp"
	{
		cps.cs = (int)cfg_line_m_start;
	}
	
#line 178 "cfg.rl"


#line 522 "cfg.cpp"
	{
		int _klen;
		unsigned int _trans = 0;
		const char * _keys;
		const signed char * _acts;
		unsigned int _nacts;
		_resume: {}
		if ( p == pe && p != eof )
			goto _out;
		if ( p == eof ) {
			if ( _cfg_line_m_eof_trans[cps.cs] > 0 ) {
				_trans = (unsigned int)_cfg_line_m_eof_trans[cps.cs] - 1;
			}
		}
		else {
			_keys = ( _cfg_line_m_trans_keys + (_cfg_line_m_key_offsets[cps.cs]));
			_trans = (unsigned int)_cfg_line_m_index_offsets[cps.cs];
			
			_klen = (int)_cfg_line_m_single_lengths[cps.cs];
			if ( _klen > 0 ) {
				const char *_lower = _keys;
				const char *_upper = _keys + _klen - 1;
				const char *_mid;
				while ( 1 ) {
					if ( _upper < _lower ) {
						_keys += _klen;
						_trans += (unsigned int)_klen;
						break;
					}
					
					_mid = _lower + ((_upper-_lower) >> 1);
					if ( ( (*( p))) < (*( _mid)) )
						_upper = _mid - 1;
					else if ( ( (*( p))) > (*( _mid)) )
						_lower = _mid + 1;
					else {
						_trans += (unsigned int)(_mid - _keys);
						goto _match;
					}
				}
			}
			
			_klen = (int)_cfg_line_m_range_lengths[cps.cs];
			if ( _klen > 0 ) {
				const char *_lower = _keys;
				const char *_upper = _keys + (_klen<<1) - 2;
				const char *_mid;
				while ( 1 ) {
					if ( _upper < _lower ) {
						_trans += (unsigned int)_klen;
						break;
					}
					
					_mid = _lower + (((_upper-_lower) >> 1) & ~1);
					if ( ( (*( p))) < (*( _mid)) )
						_upper = _mid - 2;
					else if ( ( (*( p))) > (*( _mid + 1)) )
						_lower = _mid + 2;
					else {
						_trans += (unsigned int)((_mid - _keys)>>1);
						break;
					}
				}
			}
			
			_match: {}
		}
		cps.cs = (int)_cfg_line_m_cond_targs[_trans];
		
		if ( _cfg_line_m_cond_actions[_trans] != 0 ) {
			
			_acts = ( _cfg_line_m_actions + (_cfg_line_m_cond_actions[_trans]));
			_nacts = (unsigned int)(*( _acts));
			_acts += 1;
			while ( _nacts > 0 ) {
				switch ( (*( _acts)) )
				{
					case 0:  {
							{
#line 63 "cfg.rl"
							cps.st = p; }
						
#line 604 "cfg.cpp"

						break; 
					}
					case 1:  {
							{
#line 65 "cfg.rl"
							cps.duid = lc_string(MARKED_STRING()); }
						
#line 612 "cfg.cpp"

						break; 
					}
					case 2:  {
							{
#line 66 "cfg.rl"
							cps.iaid = lc_string(MARKED_STRING()); }
						
#line 620 "cfg.cpp"

						break; 
					}
					case 3:  {
							{
#line 67 "cfg.rl"
							cps.macaddr = lc_string(MARKED_STRING()); }
						
#line 628 "cfg.cpp"

						break; 
					}
					case 4:  {
							{
#line 68 "cfg.rl"
							
							cps.ipaddr = lc_string(MARKED_STRING());
							cps.last_addr = addr_type::v4;
						}
						
#line 639 "cfg.cpp"

						break; 
					}
					case 5:  {
							{
#line 72 "cfg.rl"
							
							cps.ipaddr = lc_string(MARKED_STRING());
							cps.last_addr = addr_type::v6;
						}
						
#line 650 "cfg.cpp"

						break; 
					}
					case 6:  {
							{
#line 76 "cfg.rl"
							emplace_bind(linenum, std::string(MARKED_STRING()), true); }
						
#line 658 "cfg.cpp"

						break; 
					}
					case 7:  {
							{
#line 77 "cfg.rl"
							emplace_bind(linenum, std::string(MARKED_STRING()), false); }
						
#line 666 "cfg.cpp"

						break; 
					}
					case 8:  {
							{
#line 78 "cfg.rl"
							set_user_runas(linenum, std::string(MARKED_STRING())); }
						
#line 674 "cfg.cpp"

						break; 
					}
					case 9:  {
							{
#line 79 "cfg.rl"
							set_chroot_path(linenum, std::string(MARKED_STRING())); }
						
#line 682 "cfg.cpp"

						break; 
					}
					case 10:  {
							{
#line 80 "cfg.rl"
							
							if (auto t = nk::from_string<int>(MARKED_STRING())) set_s6_notify_fd(linenum, *t); else {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
						}
						
#line 695 "cfg.cpp"

						break; 
					}
					case 11:  {
							{
#line 86 "cfg.rl"
							
							if (auto t = nk::from_string<uint32_t>(MARKED_STRING())) cps.default_lifetime = *t; else {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
						}
						
#line 708 "cfg.cpp"

						break; 
					}
					case 12:  {
							{
#line 92 "cfg.rl"
							
							if (auto t = nk::from_string<uint8_t>(MARKED_STRING())) cps.default_preference = *t; else {
								log_line("default_preference on line %zu out of range [0,255]: %s",
								linenum, std::string(MARKED_STRING()).c_str());
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
						}
						
#line 723 "cfg.cpp"

						break; 
					}
					case 13:  {
							{
#line 100 "cfg.rl"
							
							cps.interface = std::string(MARKED_STRING());
							emplace_interface(linenum, cps.interface, cps.default_preference);
						}
						
#line 734 "cfg.cpp"

						break; 
					}
					case 14:  {
							{
#line 104 "cfg.rl"
							
							emplace_dns_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
						}
						
#line 744 "cfg.cpp"

						break; 
					}
					case 15:  {
							{
#line 107 "cfg.rl"
							
							emplace_dns_search(linenum, cps.interface, std::string(MARKED_STRING()));
						}
						
#line 754 "cfg.cpp"

						break; 
					}
					case 16:  {
							{
#line 110 "cfg.rl"
							
							emplace_ntp_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
						}
						
#line 764 "cfg.cpp"

						break; 
					}
					case 17:  {
							{
#line 113 "cfg.rl"
							
							emplace_gateway(linenum, cps.interface, cps.ipaddr);
						}
						
#line 774 "cfg.cpp"

						break; 
					}
					case 18:  {
							{
#line 116 "cfg.rl"
							
							cps.ipaddr2 = std::move(cps.ipaddr);
						}
						
#line 784 "cfg.cpp"

						break; 
					}
					case 19:  {
							{
#line 119 "cfg.rl"
							
							emplace_dynamic_range(linenum, cps.interface, cps.ipaddr2, cps.ipaddr,
							cps.default_lifetime);
						}
						
#line 795 "cfg.cpp"

						break; 
					}
					case 20:  {
							{
#line 123 "cfg.rl"
							
							emplace_dynamic_v6(linenum, cps.interface);
						}
						
#line 805 "cfg.cpp"

						break; 
					}
					case 21:  {
							{
#line 126 "cfg.rl"
							
							emplace_dhcp_state(linenum, cps.interface, cps.macaddr, cps.ipaddr,
							cps.default_lifetime);
						}
						
#line 816 "cfg.cpp"

						break; 
					}
					case 22:  {
							{
#line 130 "cfg.rl"
							
							if (auto iaid = nk::from_string<uint32_t>(cps.iaid)) {
								emplace_dhcp_state(linenum, cps.interface, std::move(cps.duid),
								*iaid, cps.ipaddr, cps.default_lifetime);
							} else {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
						}
						
#line 832 "cfg.cpp"

						break; 
					}
				}
				_nacts -= 1;
				_acts += 1;
			}
			
		}
		
		if ( p == eof ) {
			if ( cps.cs >= 161 )
				goto _out;
		}
		else {
			if ( cps.cs != 0 ) {
				p += 1;
				goto _resume;
			}
		}
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

