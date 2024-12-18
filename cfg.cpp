#line 1 "cfg.rl"
// -*- c++ -*-
// Copyright 2016-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <inttypes.h>
#include "dhcp_state.hpp"
extern "C" {
#include "ipaddr.h"
#include "nk/log.h"
#include <net/if.h>
}
extern void set_user_runas(const char *username, size_t len);
extern void set_chroot_path(const char *path, size_t len);
extern void set_s6_notify_fd(int fd);

#define MAX_LINE 2048

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

struct cfg_parse_state {
	cfg_parse_state() : st(nullptr), cs(0), last_addr(addr_type::null), ifindex(-1), default_lifetime(7200),
	default_preference(0), parse_error(false) {}
	void newline() {
		// Do NOT clear ifindex here; it is stateful between lines!
		memset(duid, 0, sizeof duid);
		memset(ipaddr, 0, sizeof ipaddr);
		memset(ipaddr2, 0, sizeof ipaddr2);
		memset(macaddr, 0, sizeof macaddr);
		duid_len = 0;
		last_addr = addr_type::null;
		iaid = 0;
		parse_error = false;
	}
	const char *st;
	int cs;
	
	char duid[128];
	char ipaddr[48];
	char ipaddr2[48];
	uint8_t macaddr[6];
	size_t duid_len;
	addr_type last_addr;
	int ifindex;
	uint32_t iaid;
	uint32_t default_lifetime;
	uint8_t default_preference;
	bool parse_error;
};

#define MARKED_STRING() cps.st, (p > cps.st ? static_cast<size_t>(p - cps.st) : 0)

#include "parsehelp.h"

bool string_to_ipaddr(in6_addr *r, const char *s, size_t linenum)
{
	if (!ipaddr_from_string(r, s)) {
		log_line("ip address on line %zu is invalid\n", linenum);
		return false;
	}
	return true;
}


#line 288 "cfg.rl"



#line 69 "cfg.cpp"
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
	0, 0, 1, 2, 3, 5, 8, 17,
	27, 30, 39, 49, 50, 51, 52, 53,
	54, 57, 62, 66, 69, 70, 71, 72,
	73, 74, 75, 77, 78, 79, 80, 81,
	82, 83, 84, 87, 92, 93, 94, 95,
	96, 97, 98, 99, 100, 101, 104, 109,
	110, 111, 112, 113, 115, 116, 117, 118,
	121, 126, 132, 133, 134, 135, 138, 149,
	161, 162, 163, 164, 165, 166, 167, 169,
	170, 171, 172, 173, 176, 182, 188, 194,
	195, 196, 197, 198, 199, 200, 201, 204,
	210, 211, 212, 213, 214, 215, 216, 217,
	218, 221, 230, 231, 232, 233, 234, 235,
	236, 237, 238, 239, 242, 253, 265, 266,
	267, 268, 269, 270, 271, 272, 273, 276,
	281, 282, 283, 284, 287, 292, 294, 297,
	306, 312, 313, 319, 325, 326, 332, 338,
	339, 345, 351, 352, 358, 364, 365, 371,
	377, 380, 386, 390, 393, 402, 411, 416,
	421, 430, 434, 447, 447, 456, 465, 470,
	475, 480, 485, 490, 495, 501, 512, 521,
	527, 530, 536, 545, 551, 562, 571, 576,
	581, 587, 587, 596, 0
};

static const char _cfg_line_m_trans_keys[] = {
	105, 110, 100, 52, 54, 32, 9, 13,
	32, 9, 13, 48, 57, 65, 90, 97,
	122, 32, 35, 9, 13, 48, 57, 65,
	90, 97, 122, 32, 9, 13, 32, 9,
	13, 48, 57, 65, 90, 97, 122, 32,
	35, 9, 13, 48, 57, 65, 90, 97,
	122, 104, 114, 111, 111, 116, 32, 9,
	13, 32, 9, 13, 33, 126, 32, 35,
	9, 13, 101, 110, 121, 102, 97, 117,
	108, 116, 95, 108, 112, 105, 102, 101,
	116, 105, 109, 101, 32, 9, 13, 32,
	9, 13, 48, 57, 114, 101, 102, 101,
	114, 101, 110, 99, 101, 32, 9, 13,
	32, 9, 13, 48, 57, 115, 95, 115,
	101, 97, 114, 114, 99, 104, 32, 9,
	13, 32, 9, 13, 33, 126, 32, 35,
	9, 13, 33, 126, 118, 101, 114, 32,
	9, 13, 32, 46, 58, 9, 13, 48,
	57, 65, 70, 97, 102, 32, 35, 46,
	58, 9, 13, 48, 57, 65, 70, 97,
	102, 110, 97, 109, 105, 99, 95, 114,
	118, 97, 110, 103, 101, 32, 9, 13,
	32, 46, 9, 13, 48, 57, 32, 46,
	9, 13, 48, 57, 32, 46, 9, 13,
	48, 57, 54, 97, 116, 101, 119, 97,
	121, 32, 9, 13, 32, 46, 9, 13,
	48, 57, 110, 116, 101, 114, 102, 97,
	99, 101, 32, 9, 13, 32, 9, 13,
	48, 57, 65, 90, 97, 122, 116, 112,
	95, 115, 101, 114, 118, 101, 114, 32,
	9, 13, 32, 46, 58, 9, 13, 48,
	57, 65, 70, 97, 102, 32, 35, 46,
	58, 9, 13, 48, 57, 65, 70, 97,
	102, 54, 95, 110, 111, 116, 105, 102,
	121, 32, 9, 13, 32, 9, 13, 48,
	57, 115, 101, 114, 32, 9, 13, 32,
	9, 13, 33, 126, 52, 54, 32, 9,
	13, 32, 9, 13, 48, 57, 65, 70,
	97, 102, 48, 57, 65, 70, 97, 102,
	58, 48, 57, 65, 70, 97, 102, 48,
	57, 65, 70, 97, 102, 58, 48, 57,
	65, 70, 97, 102, 48, 57, 65, 70,
	97, 102, 58, 48, 57, 65, 70, 97,
	102, 48, 57, 65, 70, 97, 102, 58,
	48, 57, 65, 70, 97, 102, 48, 57,
	65, 70, 97, 102, 58, 48, 57, 65,
	70, 97, 102, 48, 57, 65, 70, 97,
	102, 32, 9, 13, 32, 46, 9, 13,
	48, 57, 32, 35, 9, 13, 32, 9,
	13, 32, 9, 13, 48, 57, 65, 70,
	97, 102, 32, 9, 13, 48, 57, 65,
	70, 97, 102, 32, 9, 13, 48, 57,
	32, 9, 13, 48, 57, 32, 9, 13,
	48, 58, 65, 70, 97, 102, 32, 35,
	9, 13, 32, 35, 98, 99, 100, 103,
	105, 110, 115, 117, 118, 9, 13, 32,
	9, 13, 48, 57, 65, 90, 97, 122,
	32, 9, 13, 48, 57, 65, 90, 97,
	122, 32, 9, 13, 33, 126, 32, 9,
	13, 48, 57, 32, 9, 13, 48, 57,
	32, 9, 13, 33, 126, 32, 9, 13,
	33, 126, 32, 9, 13, 33, 126, 32,
	46, 9, 13, 48, 57, 32, 46, 58,
	9, 13, 48, 57, 65, 70, 97, 102,
	32, 9, 13, 48, 58, 65, 70, 97,
	102, 32, 46, 9, 13, 48, 57, 32,
	9, 13, 32, 46, 9, 13, 48, 57,
	32, 9, 13, 48, 57, 65, 90, 97,
	122, 32, 46, 9, 13, 48, 57, 32,
	46, 58, 9, 13, 48, 57, 65, 70,
	97, 102, 32, 9, 13, 48, 58, 65,
	70, 97, 102, 32, 9, 13, 48, 57,
	32, 9, 13, 33, 126, 32, 46, 9,
	13, 48, 57, 32, 9, 13, 48, 58,
	65, 70, 97, 102, 0
};

static const signed char _cfg_line_m_single_lengths[] = {
	0, 1, 1, 1, 2, 1, 1, 2,
	1, 1, 2, 1, 1, 1, 1, 1,
	1, 1, 2, 3, 1, 1, 1, 1,
	1, 1, 2, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 2, 1, 1, 1, 1,
	1, 2, 1, 1, 1, 1, 3, 4,
	1, 1, 1, 1, 1, 1, 2, 1,
	1, 1, 1, 1, 2, 2, 2, 1,
	1, 1, 1, 1, 1, 1, 1, 2,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 3, 4, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 2, 1, 1,
	0, 1, 0, 0, 1, 0, 0, 1,
	0, 0, 1, 0, 0, 1, 0, 0,
	1, 2, 2, 1, 1, 1, 1, 1,
	1, 2, 11, 0, 1, 1, 1, 1,
	1, 1, 1, 1, 2, 3, 1, 2,
	1, 2, 1, 2, 3, 1, 1, 1,
	2, 0, 1, 0, 0
};

static const signed char _cfg_line_m_range_lengths[] = {
	0, 0, 0, 0, 0, 1, 4, 4,
	1, 4, 4, 0, 0, 0, 0, 0,
	1, 2, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 2, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 1, 2, 0,
	0, 0, 0, 0, 0, 0, 0, 1,
	2, 2, 0, 0, 0, 1, 4, 4,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 1, 2, 2, 2, 0,
	0, 0, 0, 0, 0, 0, 1, 2,
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 4, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 1, 4, 4, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 2,
	0, 0, 0, 1, 2, 0, 1, 4,
	3, 0, 3, 3, 0, 3, 3, 0,
	3, 3, 0, 3, 3, 0, 3, 3,
	1, 2, 1, 1, 4, 4, 2, 2,
	4, 1, 1, 0, 4, 4, 2, 2,
	2, 2, 2, 2, 2, 4, 4, 2,
	1, 2, 4, 2, 4, 4, 2, 2,
	2, 0, 4, 0, 0
};

static const short _cfg_line_m_index_offsets[] = {
	0, 0, 2, 4, 6, 9, 12, 18,
	25, 28, 34, 41, 43, 45, 47, 49,
	51, 54, 58, 62, 66, 68, 70, 72,
	74, 76, 78, 81, 83, 85, 87, 89,
	91, 93, 95, 98, 102, 104, 106, 108,
	110, 112, 114, 116, 118, 120, 123, 127,
	129, 131, 133, 135, 138, 140, 142, 144,
	147, 151, 156, 158, 160, 162, 165, 173,
	182, 184, 186, 188, 190, 192, 194, 197,
	199, 201, 203, 205, 208, 213, 218, 223,
	225, 227, 229, 231, 233, 235, 237, 240,
	245, 247, 249, 251, 253, 255, 257, 259,
	261, 264, 270, 272, 274, 276, 278, 280,
	282, 284, 286, 288, 291, 299, 308, 310,
	312, 314, 316, 318, 320, 322, 324, 327,
	331, 333, 335, 337, 340, 344, 347, 350,
	356, 360, 362, 366, 370, 372, 376, 380,
	382, 386, 390, 392, 396, 400, 402, 406,
	410, 413, 418, 422, 425, 431, 437, 441,
	445, 451, 455, 468, 469, 475, 481, 485,
	489, 493, 497, 501, 505, 510, 518, 524,
	529, 532, 537, 543, 548, 556, 562, 566,
	570, 575, 576, 582, 0
};

static const short _cfg_line_m_cond_targs[] = {
	2, 0, 3, 0, 4, 0, 5, 8,
	0, 6, 6, 0, 6, 6, 156, 156,
	156, 0, 7, 155, 7, 156, 156, 156,
	0, 9, 9, 0, 9, 9, 157, 157,
	157, 0, 10, 155, 10, 157, 157, 157,
	0, 12, 0, 13, 0, 14, 0, 15,
	0, 16, 0, 17, 17, 0, 17, 17,
	158, 0, 18, 155, 18, 0, 20, 47,
	64, 0, 21, 0, 22, 0, 23, 0,
	24, 0, 25, 0, 26, 0, 27, 36,
	0, 28, 0, 29, 0, 30, 0, 31,
	0, 32, 0, 33, 0, 34, 0, 35,
	35, 0, 35, 35, 159, 0, 37, 0,
	38, 0, 39, 0, 40, 0, 41, 0,
	42, 0, 43, 0, 44, 0, 45, 0,
	46, 46, 0, 46, 46, 160, 0, 48,
	0, 49, 0, 50, 0, 51, 0, 52,
	58, 0, 53, 0, 54, 0, 55, 0,
	56, 56, 0, 56, 56, 161, 0, 57,
	162, 57, 161, 0, 59, 0, 60, 0,
	61, 0, 62, 62, 0, 62, 164, 166,
	62, 165, 166, 166, 0, 63, 155, 164,
	166, 63, 165, 166, 166, 0, 65, 0,
	66, 0, 67, 0, 68, 0, 69, 0,
	70, 0, 71, 79, 0, 72, 0, 73,
	0, 74, 0, 75, 0, 76, 76, 0,
	76, 77, 76, 77, 0, 78, 77, 78,
	77, 0, 78, 167, 78, 167, 0, 168,
	0, 81, 0, 82, 0, 83, 0, 84,
	0, 85, 0, 86, 0, 87, 87, 0,
	87, 169, 87, 169, 0, 89, 0, 90,
	0, 91, 0, 92, 0, 93, 0, 94,
	0, 95, 0, 96, 0, 97, 97, 0,
	97, 97, 170, 170, 170, 0, 99, 0,
	100, 0, 101, 0, 102, 0, 103, 0,
	104, 0, 105, 0, 106, 0, 107, 0,
	108, 108, 0, 108, 171, 173, 108, 172,
	173, 173, 0, 109, 155, 171, 173, 109,
	172, 173, 173, 0, 111, 0, 112, 0,
	113, 0, 114, 0, 115, 0, 116, 0,
	117, 0, 118, 0, 119, 119, 0, 119,
	119, 174, 0, 121, 0, 122, 0, 123,
	0, 124, 124, 0, 124, 124, 175, 0,
	126, 147, 0, 127, 127, 0, 127, 127,
	128, 128, 128, 0, 129, 129, 129, 0,
	130, 0, 131, 131, 131, 0, 132, 132,
	132, 0, 133, 0, 134, 134, 134, 0,
	135, 135, 135, 0, 136, 0, 137, 137,
	137, 0, 138, 138, 138, 0, 139, 0,
	140, 140, 140, 0, 141, 141, 141, 0,
	142, 0, 143, 143, 143, 0, 144, 144,
	144, 0, 145, 145, 0, 145, 176, 145,
	176, 0, 146, 177, 146, 0, 148, 148,
	0, 148, 148, 149, 149, 149, 0, 150,
	150, 149, 149, 149, 0, 150, 150, 151,
	0, 152, 152, 151, 0, 152, 152, 178,
	178, 178, 0, 153, 179, 153, 0, 154,
	155, 1, 11, 19, 80, 88, 98, 110,
	120, 125, 154, 0, 155, 7, 7, 156,
	156, 156, 0, 10, 10, 157, 157, 157,
	0, 18, 18, 158, 0, 18, 18, 159,
	0, 18, 18, 160, 0, 57, 57, 161,
	0, 163, 163, 162, 155, 163, 163, 162,
	155, 63, 164, 63, 164, 0, 63, 164,
	166, 63, 165, 166, 166, 0, 63, 63,
	166, 166, 166, 0, 18, 167, 18, 167,
	0, 18, 18, 0, 18, 169, 18, 169,
	0, 18, 18, 170, 170, 170, 0, 109,
	171, 109, 171, 0, 109, 171, 173, 109,
	172, 173, 173, 0, 109, 109, 173, 173,
	173, 0, 18, 18, 174, 0, 18, 18,
	175, 0, 146, 176, 146, 176, 0, 177,
	153, 153, 178, 178, 178, 0, 179, 0,
	1, 2, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32,
	33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48,
	49, 50, 51, 52, 53, 54, 55, 56,
	57, 58, 59, 60, 61, 62, 63, 64,
	65, 66, 67, 68, 69, 70, 71, 72,
	73, 74, 75, 76, 77, 78, 79, 80,
	81, 82, 83, 84, 85, 86, 87, 88,
	89, 90, 91, 92, 93, 94, 95, 96,
	97, 98, 99, 100, 101, 102, 103, 104,
	105, 106, 107, 108, 109, 110, 111, 112,
	113, 114, 115, 116, 117, 118, 119, 120,
	121, 122, 123, 124, 125, 126, 127, 128,
	129, 130, 131, 132, 133, 134, 135, 136,
	137, 138, 139, 140, 141, 142, 143, 144,
	145, 146, 147, 148, 149, 150, 151, 152,
	153, 154, 155, 156, 157, 158, 159, 160,
	161, 162, 163, 164, 165, 166, 167, 168,
	169, 170, 171, 172, 173, 174, 175, 176,
	177, 178, 179, 0
};

static const signed char _cfg_line_m_cond_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 1,
	1, 0, 0, 0, 0, 1, 1, 1,
	0, 0, 0, 0, 0, 0, 1, 1,
	1, 0, 0, 0, 0, 1, 1, 1,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 1, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 1, 0, 0,
	1, 0, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 1,
	0, 1, 1, 1, 0, 0, 0, 1,
	1, 0, 1, 1, 1, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 1, 0, 46, 0, 46,
	0, 0, 0, 1, 0, 1, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 1, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 1, 1, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 1, 0, 1,
	1, 1, 0, 0, 0, 1, 1, 0,
	1, 1, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 7, 7, 0, 0, 1, 0,
	1, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 1, 1, 1, 0, 3,
	3, 0, 0, 0, 0, 0, 0, 1,
	0, 5, 5, 0, 0, 0, 0, 1,
	1, 1, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 13, 13, 0,
	0, 0, 0, 15, 15, 0, 0, 0,
	0, 19, 19, 0, 0, 23, 23, 0,
	0, 25, 25, 0, 0, 29, 29, 0,
	0, 29, 29, 0, 0, 0, 0, 1,
	0, 37, 0, 37, 0, 0, 64, 0,
	0, 64, 0, 0, 0, 0, 55, 55,
	0, 0, 0, 0, 49, 0, 49, 0,
	0, 31, 31, 0, 43, 0, 43, 0,
	0, 27, 27, 0, 0, 0, 0, 40,
	0, 40, 0, 0, 68, 0, 0, 68,
	0, 0, 0, 0, 58, 58, 0, 0,
	0, 0, 21, 21, 0, 0, 17, 17,
	0, 0, 9, 0, 9, 0, 0, 0,
	11, 11, 0, 0, 0, 0, 0, 0,
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
	29, 29, 0, 37, 64, 55, 49, 31,
	43, 27, 40, 68, 58, 21, 17, 52,
	33, 61, 35, 0
};

static const short _cfg_line_m_eof_trans[] = {
	584, 585, 586, 587, 588, 589, 590, 591,
	592, 593, 594, 595, 596, 597, 598, 599,
	600, 601, 602, 603, 604, 605, 606, 607,
	608, 609, 610, 611, 612, 613, 614, 615,
	616, 617, 618, 619, 620, 621, 622, 623,
	624, 625, 626, 627, 628, 629, 630, 631,
	632, 633, 634, 635, 636, 637, 638, 639,
	640, 641, 642, 643, 644, 645, 646, 647,
	648, 649, 650, 651, 652, 653, 654, 655,
	656, 657, 658, 659, 660, 661, 662, 663,
	664, 665, 666, 667, 668, 669, 670, 671,
	672, 673, 674, 675, 676, 677, 678, 679,
	680, 681, 682, 683, 684, 685, 686, 687,
	688, 689, 690, 691, 692, 693, 694, 695,
	696, 697, 698, 699, 700, 701, 702, 703,
	704, 705, 706, 707, 708, 709, 710, 711,
	712, 713, 714, 715, 716, 717, 718, 719,
	720, 721, 722, 723, 724, 725, 726, 727,
	728, 729, 730, 731, 732, 733, 734, 735,
	736, 737, 738, 739, 740, 741, 742, 743,
	744, 745, 746, 747, 748, 749, 750, 751,
	752, 753, 754, 755, 756, 757, 758, 759,
	760, 761, 762, 763, 0
};

static const int cfg_line_m_start = 154;
static const int cfg_line_m_first_final = 154;
static const int cfg_line_m_error = 0;

static const int cfg_line_m_en_main = 154;


#line 290 "cfg.rl"


static int do_parse_cfg_line(cfg_parse_state &cps, const char *p, size_t plen,
const size_t linenum)
{
	const char *pe = p + plen;
	const char *eof = pe;
	

#line 503 "cfg.cpp"
	{
		cps.cs = (int)cfg_line_m_start;
	}
	
#line 298 "cfg.rl"


#line 508 "cfg.cpp"
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
#line 69 "cfg.rl"
							cps.st = p; }
						
#line 590 "cfg.cpp"

						break; 
					}
					case 1:  {
							{
#line 71 "cfg.rl"
							
							assign_strbuf(cps.duid, &cps.duid_len, sizeof cps.duid, cps.st, p);
							lc_string_inplace(cps.duid, cps.duid_len);
						}
						
#line 601 "cfg.cpp"

						break; 
					}
					case 2:  {
							{
#line 75 "cfg.rl"
							
							char buf[64];
							ptrdiff_t blen = p - cps.st;
							if (blen < 0 || blen >= (int)sizeof buf) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							memcpy(buf, cps.st, (size_t)blen); buf[blen] = 0;
							if (sscanf(buf, "%" SCNu32, &cps.iaid) != 1) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
						}
						
#line 621 "cfg.cpp"

						break; 
					}
					case 3:  {
							{
#line 88 "cfg.rl"
							
							char buf[32];
							ptrdiff_t blen = p - cps.st;
							if (blen < 0 || blen >= (int)sizeof buf) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							*(char *)mempcpy(buf, cps.st, (size_t)blen) = 0;
							if (sscanf(buf, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
							&cps.macaddr[0], &cps.macaddr[1], &cps.macaddr[2],
							&cps.macaddr[3], &cps.macaddr[4], &cps.macaddr[5]) != 6) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
						}
						
#line 643 "cfg.cpp"

						break; 
					}
					case 4:  {
							{
#line 103 "cfg.rl"
							
							size_t l;
							assign_strbuf(cps.ipaddr, &l, sizeof cps.ipaddr, cps.st, p);
							lc_string_inplace(cps.ipaddr, l);
							cps.last_addr = addr_type::v4;
						}
						
#line 656 "cfg.cpp"

						break; 
					}
					case 5:  {
							{
#line 109 "cfg.rl"
							
							size_t l;
							assign_strbuf(cps.ipaddr, &l, sizeof cps.ipaddr, cps.st, p);
							lc_string_inplace(cps.ipaddr, l);
							cps.last_addr = addr_type::v6;
						}
						
#line 669 "cfg.cpp"

						break; 
					}
					case 6:  {
							{
#line 115 "cfg.rl"
							
							char buf[IFNAMSIZ];
							ptrdiff_t blen = p - cps.st;
							if (blen < 0 || blen >= IFNAMSIZ) {
								log_line("interface name on line %zu is too long (>= %d)\n", linenum, IFNAMSIZ);
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							memcpy(buf, cps.st, (size_t)blen);
							buf[blen] = 0;
							emplace_bind4(linenum, buf);
						}
						
#line 688 "cfg.cpp"

						break; 
					}
					case 7:  {
							{
#line 127 "cfg.rl"
							
							char buf[IFNAMSIZ];
							ptrdiff_t blen = p - cps.st;
							if (blen < 0 || blen >= IFNAMSIZ) {
								log_line("interface name on line %zu is too long (>= %d)\n", linenum, IFNAMSIZ);
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							memcpy(buf, cps.st, (size_t)blen);
							buf[blen] = 0;
							emplace_bind6(linenum, buf);
						}
						
#line 707 "cfg.cpp"

						break; 
					}
					case 8:  {
							{
#line 139 "cfg.rl"
							set_user_runas(MARKED_STRING()); }
						
#line 715 "cfg.cpp"

						break; 
					}
					case 9:  {
							{
#line 140 "cfg.rl"
							set_chroot_path(MARKED_STRING()); }
						
#line 723 "cfg.cpp"

						break; 
					}
					case 10:  {
							{
#line 141 "cfg.rl"
							
							char buf[64];
							ptrdiff_t blen = p - cps.st;
							if (blen < 0 || blen >= (int)sizeof buf) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							memcpy(buf, cps.st, (size_t)blen); buf[blen] = 0;
							int fd;
							if (sscanf(buf, "%d", &fd) != 1) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							set_s6_notify_fd(fd);
						}
						
#line 745 "cfg.cpp"

						break; 
					}
					case 11:  {
							{
#line 156 "cfg.rl"
							
							char buf[64];
							ptrdiff_t blen = p - cps.st;
							if (blen < 0 || blen >= (int)sizeof buf) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							memcpy(buf, cps.st, (size_t)blen); buf[blen] = 0;
							if (sscanf(buf, "%" SCNu32, &cps.default_lifetime) != 1) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
						}
						
#line 765 "cfg.cpp"

						break; 
					}
					case 12:  {
							{
#line 169 "cfg.rl"
							
							char buf[64];
							ptrdiff_t blen = p - cps.st;
							if (blen < 0 || blen >= (int)sizeof buf) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							memcpy(buf, cps.st, (size_t)blen); buf[blen] = 0;
							if (sscanf(buf, "%" SCNu8, &cps.default_preference) != 1) {
								log_line("default_preference on line %zu out of range [0,255]\n", linenum);
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
						}
						
#line 786 "cfg.cpp"

						break; 
					}
					case 13:  {
							{
#line 183 "cfg.rl"
							
							char interface[IFNAMSIZ];
							ptrdiff_t blen = p - cps.st;
							if (blen < 0 || blen >= (int)sizeof interface) {
								log_line("interface name on line %zu is too long (>= %d)\n", linenum, IFNAMSIZ);
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							memcpy(interface, cps.st, (size_t)blen);
							interface[blen] = 0;
							cps.ifindex = emplace_interface(linenum, interface, cps.default_preference);
						}
						
#line 805 "cfg.cpp"

						break; 
					}
					case 14:  {
							{
#line 195 "cfg.rl"
							
							in6_addr t;
							if (!string_to_ipaddr(&t, cps.ipaddr, linenum)) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							emplace_dns_server(linenum, cps.ifindex, &t, cps.last_addr);
						}
						
#line 820 "cfg.cpp"

						break; 
					}
					case 15:  {
							{
#line 203 "cfg.rl"
							
							emplace_dns_search(linenum, cps.ifindex, MARKED_STRING());
						}
						
#line 830 "cfg.cpp"

						break; 
					}
					case 16:  {
							{
#line 206 "cfg.rl"
							
							in6_addr t;
							if (!string_to_ipaddr(&t, cps.ipaddr, linenum)) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							emplace_ntp_server(linenum, cps.ifindex, &t, cps.last_addr);
						}
						
#line 845 "cfg.cpp"

						break; 
					}
					case 17:  {
							{
#line 214 "cfg.rl"
							
							in6_addr t;
							if (!string_to_ipaddr(&t, cps.ipaddr, linenum)) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							emplace_gateway_v4(linenum, cps.ifindex, &t);
						}
						
#line 860 "cfg.cpp"

						break; 
					}
					case 18:  {
							{
#line 222 "cfg.rl"
							
							memcpy(cps.ipaddr2, cps.ipaddr, sizeof cps.ipaddr2);
						}
						
#line 870 "cfg.cpp"

						break; 
					}
					case 19:  {
							{
#line 225 "cfg.rl"
							
							in6_addr tlo;
							if (!string_to_ipaddr(&tlo, cps.ipaddr2, linenum)) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							in6_addr thi;
							if (!string_to_ipaddr(&thi, cps.ipaddr, linenum)) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							emplace_dynamic_range(linenum, cps.ifindex, &tlo, &thi, cps.default_lifetime);
						}
						
#line 890 "cfg.cpp"

						break; 
					}
					case 20:  {
							{
#line 238 "cfg.rl"
							
							emplace_dynamic_v6(linenum, cps.ifindex);
						}
						
#line 900 "cfg.cpp"

						break; 
					}
					case 21:  {
							{
#line 241 "cfg.rl"
							
							in6_addr t;
							if (!string_to_ipaddr(&t, cps.ipaddr, linenum)) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							emplace_dhcp4_state(linenum, cps.ifindex, cps.macaddr, &t, cps.default_lifetime);
						}
						
#line 915 "cfg.cpp"

						break; 
					}
					case 22:  {
							{
#line 249 "cfg.rl"
							
							in6_addr t;
							if (!string_to_ipaddr(&t, cps.ipaddr, linenum)) {
								cps.parse_error = true;
								{p += 1; goto _out; }
							}
							emplace_dhcp6_state(linenum, cps.ifindex,
							cps.duid, cps.duid_len,
							cps.iaid, &t, cps.default_lifetime);
						}
						
#line 932 "cfg.cpp"

						break; 
					}
				}
				_nacts -= 1;
				_acts += 1;
			}
			
		}
		
		if ( p == eof ) {
			if ( cps.cs >= 154 )
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
	
#line 299 "cfg.rl"

	
	if (cps.parse_error) return -1;
		if (cps.cs >= cfg_line_m_first_final)
		return 1;
	if (cps.cs == cfg_line_m_error)
		return -1;
	return -2;
}

bool parse_config(const char *path)
{
	bool ret = false;
	size_t linenum = 0;
	cfg_parse_state ps;
	char buf[MAX_LINE];
	FILE *f = fopen(path, "r");
	if (!f) {
		log_line("%s: failed to open config file '%s' for read: %s\n",
		__func__, path, strerror(errno));
		goto out0;
	}
	while (!feof(f)) {
		if (!fgets(buf, sizeof buf, f)) {
			if (!feof(f)) {
				log_line("%s: io error fetching line of '%s'\n", __func__, path);
				goto out1;
			}
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
				log_line("%s: Incomplete configuration at line %zu; ignoring\n",
			__func__, linenum);
			else
				log_line("%s: Malformed configuration at line %zu; ignoring.\n",
			__func__, linenum);
			continue;
		}
	}
	create_blobs();
	ret = true;
	out1:
	fclose(f);
	out0:
	return ret;
}

