#line 1 "dynlease.rl"
// -*- c++ -*-
// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <limits.h>
#include <inttypes.h>
#include <string>
#include <vector>
#include <assert.h>
#include <nk/scopeguard.hpp>
#include <nk/net/ip_address.hpp>
extern "C" {
#include <net/if.h>
#include "nk/log.h"
}

#define MAX_LINE 2048

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

extern int64_t get_current_ts();

struct lease_state_v4
{
	lease_state_v4(const nk::ip_address &addr_, const char *macaddr_, int64_t et)
	: addr(addr_), expire_time(et)
	{
		memcpy(macaddr, macaddr_, 6);
	}
	nk::ip_address addr;
	uint8_t macaddr[6];
	int64_t expire_time;
};

struct lease_state_v6
{
	lease_state_v6(const nk::ip_address &addr_, const char *duid_, size_t duid_len_, uint32_t iaid_, int64_t et)
	: addr(addr_), duid_len(duid_len_), expire_time(et), iaid(iaid_)
	{
		memcpy(duid, duid_, duid_len_);
	}
	nk::ip_address addr;
	size_t duid_len;
	int64_t expire_time;
	uint32_t iaid;
	char duid[128]; // not null terminated
};

// The vectors here are sorted by addr.
struct dynlease_map_v4
{
	char ifname[IFNAMSIZ];
	std::vector<lease_state_v4> state;
};
struct dynlease_map_v6
{
	char ifname[IFNAMSIZ];
	std::vector<lease_state_v6> state;
};

// Maps interfaces to lease data.
static std::vector<dynlease_map_v4> dyn_leases_v4;
static std::vector<dynlease_map_v6> dyn_leases_v6;

std::vector<lease_state_v4> *lease_state4_by_name(const char *interface)
{
	for (auto &i: dyn_leases_v4) {
		if (!strcmp(i.ifname, interface)) {
			return &i.state;
		}
	}
	return nullptr;
}

std::vector<lease_state_v6> *lease_state6_by_name(const char *interface)
{
	for (auto &i: dyn_leases_v6) {
		if (!strcmp(i.ifname, interface)) {
			return &i.state;
		}
	}
	return nullptr;
}

static auto create_new_dynlease4_state(const char *interface)
{
	dynlease_map_v4 nn;
	memccpy(nn.ifname, interface, 0, sizeof nn.ifname);
	dyn_leases_v4.emplace_back(std::move(nn));
	return &dyn_leases_v4.back().state;
}

static auto create_new_dynlease6_state(const char *interface)
{
	dynlease_map_v6 nn;
	memccpy(nn.ifname, interface, 0, sizeof nn.ifname);
	dyn_leases_v6.emplace_back(std::move(nn));
	return &dyn_leases_v6.back().state;
}

static bool emplace_dynlease4_state(size_t linenum, const char *interface,
const char *v4_addr, const char *macaddr,
int64_t expire_time)
{
	auto is = lease_state4_by_name(interface);
	if (!is) is = create_new_dynlease4_state(interface);
		nk::ip_address ipa;
	if (!ipa.from_string(v4_addr)) {
		log_line("Bad IP address at line %zu: %s\n", linenum, v4_addr);
		return false;
	}
	// We won't get duplicates unless someone manually edits the file.  If they do,
	// then they get what they deserve.
	is->emplace_back(ipa, macaddr, expire_time);
	return true;
}

static bool emplace_dynlease6_state(size_t linenum, const char *interface,
const char *v6_addr,
const char *duid, size_t duid_len,
uint32_t iaid, int64_t expire_time)
{
	auto is = lease_state6_by_name(interface);
	if (!is) is = create_new_dynlease6_state(interface);
		nk::ip_address ipa;
	if (!ipa.from_string(v6_addr)) {
		log_line("Bad IP address at line %zu: %s\n", linenum, v6_addr);
		return false;
	}
	is->emplace_back(ipa, duid, duid_len, iaid, expire_time);
	return true;
}

size_t dynlease4_count(const char *interface)
{
	auto is = lease_state4_by_name(interface);
	if (!is) return 0;
		return is->size();
}

size_t dynlease6_count(const char *interface)
{
	auto is = lease_state6_by_name(interface);
	if (!is) return 0;
		return is->size();
}

void dynlease_gc()
{
	for (auto &i: dyn_leases_v4) {
		std::erase_if(i.state, [](lease_state_v4 &x){ return x.expire_time < get_current_ts(); });
	}
	for (auto &i: dyn_leases_v6) {
		std::erase_if(i.state, [](lease_state_v6 &x){ return x.expire_time < get_current_ts(); });
	}
}

bool dynlease4_add(const char *interface, const nk::ip_address &v4_addr, const uint8_t *macaddr,
int64_t expire_time)
{
	auto is = lease_state4_by_name(interface);
	if (!is) is = create_new_dynlease4_state(interface);
		
	for (auto &i: *is) {
		if (i.addr == v4_addr) {
			if (memcmp(&i.macaddr, macaddr, 6) == 0) {
				i.expire_time = expire_time;
				return true;
			}
			return false;
		}
	}
	char tmac[6];
	memcpy(tmac, macaddr, sizeof tmac);
	is->emplace_back(std::move(v4_addr), tmac, expire_time);
	return true;
}

static bool duid_compare(const char *a, size_t al, const char *b, size_t bl)
{
	return al == bl && !memcmp(a, b, al);
}

bool dynlease6_add(const char *interface, const nk::ip_address &v6_addr,
const char *duid, size_t duid_len, uint32_t iaid, int64_t expire_time)
{
	auto is = lease_state6_by_name(interface);
	if (!is) is = create_new_dynlease6_state(interface);
		
	for (auto &i: *is) {
		if (i.addr == v6_addr) {
			if (!duid_compare(i.duid, i.duid_len, duid, duid_len) && i.iaid == iaid) {
				i.expire_time = expire_time;
				return true;
			}
			return false;
		}
	}
	is->emplace_back(std::move(v6_addr), duid, duid_len, iaid, expire_time);
	return true;
}

nk::ip_address dynlease4_query_refresh(const char *interface, const uint8_t *macaddr,
int64_t expire_time)
{
	auto is = lease_state4_by_name(interface);
	if (!is) return {};
	
	for (auto &i: *is) {
		if (memcmp(&i.macaddr, macaddr, 6) == 0) {
			i.expire_time = expire_time;
			return i.addr;
		}
	}
	return {};
}

nk::ip_address dynlease6_query_refresh(const char *interface, const char *duid, size_t duid_len,
uint32_t iaid, int64_t expire_time)
{
	auto is = lease_state6_by_name(interface);
	if (!is) return {};
	
	for (auto &i: *is) {
		if (!duid_compare(i.duid, i.duid_len, duid, duid_len) && i.iaid == iaid) {
			i.expire_time = expire_time;
			return i.addr;
		}
	}
	return {};
}

bool dynlease4_exists(const char *interface, const nk::ip_address &v4_addr, const uint8_t *macaddr)
{
	auto is = lease_state4_by_name(interface);
	if (!is) return false;
		
	for (auto &i: *is) {
		if (i.addr == v4_addr && memcmp(&i.macaddr, macaddr, 6) == 0) {
			return get_current_ts() < i.expire_time;
		}
	}
	return false;
}

bool dynlease6_exists(const char *interface, const nk::ip_address &v6_addr,
const char *duid, size_t duid_len, uint32_t iaid)
{
	auto is = lease_state6_by_name(interface);
	if (!is) return false;
		
	for (auto &i: *is) {
		if (i.addr == v6_addr && !duid_compare(i.duid, i.duid_len, duid, duid_len) && i.iaid == iaid) {
			return get_current_ts() < i.expire_time;
		}
	}
	return false;
}

bool dynlease4_del(const char *interface, const nk::ip_address &v4_addr, const uint8_t *macaddr)
{
	auto is = lease_state4_by_name(interface);
	if (!is) return false;
		
	for (auto i = is->begin(), iend = is->end(); i != iend; ++i) {
		if (i->addr == v4_addr && memcmp(&i->macaddr, macaddr, 6) == 0) {
			is->erase(i);
			return true;
		}
	}
	return false;
}

bool dynlease6_del(const char *interface, const nk::ip_address &v6_addr,
const char *duid, size_t duid_len, uint32_t iaid)
{
	auto is = lease_state6_by_name(interface);
	if (!is) return false;
		
	for (auto i = is->begin(), iend = is->end(); i != iend; ++i) {
		if (i->addr == v6_addr && !duid_compare(i->duid, i->duid_len, duid, duid_len) && i->iaid == iaid) {
			is->erase(i);
			return true;
		}
	}
	return false;
}

bool dynlease_unused_addr(const char *interface, const nk::ip_address &addr)
{
	auto is = lease_state6_by_name(interface);
	if (!is) return true;
		
	for (auto i = is->begin(), iend = is->end(); i != iend; ++i) {
		if (i->addr == addr)
			return false;
	}
	return true;
}

// v4 <interface> <ip> <macaddr> <expire_time>
// v6 <interface> <ip> <duid> <iaid> <expire_time>

bool dynlease_serialize(const char *path)
{
	char tmp_path[PATH_MAX];
	size_t pathlen = strlen(path);
	if (pathlen + 5 > sizeof tmp_path) abort();
		memcpy(tmp_path, path, pathlen);
	memcpy(tmp_path + pathlen, ".tmp", 5);
	
	const auto f = fopen(tmp_path, "w");
	if (!f) {
		log_line("%s: failed to open '%s' for dynamic lease serialization\n",
		__func__, path);
		return false;
	}
	SCOPE_EXIT{ fclose(f); unlink(tmp_path); };
	for (const auto &i: dyn_leases_v4) {
		const auto iface = i.ifname;
		const auto &ls = i.state;
		for (const auto &j: ls) {
			// Don't write out dynamic leases that have expired.
			if (get_current_ts() >= j.expire_time)
				continue;
			if (fprintf(f, "v4 %s %s %2.x%2.x%2.x%2.x%2.x%2.x %zu\n",
				iface, j.addr.to_string().c_str(),
			j.macaddr[0], j.macaddr[1], j.macaddr[2],
			j.macaddr[3], j.macaddr[4], j.macaddr[5], j.expire_time) < 0) {
				log_line("%s: fprintf failed: %s\n", __func__, strerror(errno));
				return false;
			}
		}
	}
	for (const auto &i: dyn_leases_v6) {
		const auto iface = i.ifname;
		const auto &ls = i.state;
		for (const auto &j: ls) {
			// Don't write out dynamic leases that have expired.
			if (get_current_ts() >= j.expire_time)
				continue;
			
			if (fprintf(f, "v6 %s %s ", iface, j.addr.to_string().c_str()) < 0) goto err0;
				for (const auto &k: j.duid) if (fprintf(f, "%.2hhx", k) < 0) goto err0;
			if (fprintf(f, " %u %lu\n", j.iaid, j.expire_time) < 0) goto err0;
				continue;
			err0:
			log_line("%s: fprintf failed: %s\n", __func__, strerror(errno));
			return false;
		}
	}
	if (fflush(f)) {
		log_line("%s: fflush failed: %s\n", __func__, strerror(errno));
		return false;
	}
	const auto fd = fileno(f);
	if (fdatasync(fd)) {
		log_line("%s: fdatasync failed: %s\n", __func__, strerror(errno));
		return false;
	}
	if (rename(tmp_path, path)) {
		log_line("%s: rename failed: %s\n", __func__, strerror(errno));
		return false;
	}
	return true;
}

// v4 <interface> <ip> <macaddr> <expire_time>
// v6 <interface> <ip> <duid> <iaid> <expire_time>

struct dynlease_parse_state {
	dynlease_parse_state() : st(nullptr), cs(0), parse_error(false) {}
	void newline() {
		duid.clear();
		memset(macaddr, 0, sizeof macaddr);
		v4_addr.clear();
		v6_addr.clear();
		memset(interface, 0, sizeof interface);
		iaid = 0;
		expire_time = 0;
		parse_error = false;
	}
	const char *st;
	int cs;
	
	std::string duid;
	std::string v4_addr;
	std::string v6_addr;
	char interface[IFNAMSIZ];
	int64_t expire_time;
	uint32_t iaid;
	bool parse_error;
	char macaddr[6];
};

#define MARKED_STRING() std::string(cps.st, (p > cps.st ? static_cast<size_t>(p - cps.st) : 0))

static inline void lc_string_inplace(char *s, size_t len)
{
	for (size_t i = 0; i < len; ++i) s[i] = tolower(s[i]);
}


#line 486 "dynlease.rl"



#line 410 "dynlease.cpp"
static const int dynlease_line_m_start = 1;
static const int dynlease_line_m_first_final = 41;
static const int dynlease_line_m_error = 0;

static const int dynlease_line_m_en_main = 1;


#line 488 "dynlease.rl"


static int do_parse_dynlease_line(dynlease_parse_state &cps, const char *p, size_t plen,
const size_t linenum)
{
	const char *pe = p + plen;
	const char *eof = pe;
	

#line 425 "dynlease.cpp"
	{
		cps.cs = (int)dynlease_line_m_start;
	}
	
#line 496 "dynlease.rl"


#line 430 "dynlease.cpp"
{
		switch ( cps.cs ) {
			case 1:
			goto st_case_1;
			case 0:
			goto st_case_0;
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
			case 8:
			goto st_case_8;
			case 9:
			goto st_case_9;
			case 10:
			goto st_case_10;
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
			case 41:
			goto st_case_41;
			case 42:
			goto st_case_42;
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
			case 43:
			goto st_case_43;
			case 44:
			goto st_case_44;
			case 37:
			goto st_case_37;
			case 38:
			goto st_case_38;
			case 39:
			goto st_case_39;
			case 40:
			goto st_case_40;
		}
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
			switch( ( (*( p))) ) {
				case 32: {
					goto _st1;
				}
				case 118: {
					goto _st2;
				}
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st1;
			}
			goto _st0;
		}
		_st0:
		if ( p == eof )
			goto _out0;
		st_case_0:
		goto _out0;
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
			switch( ( (*( p))) ) {
				case 52: {
					goto _st3;
				}
				case 54: {
					goto _st27;
				}
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
			if ( ( (*( p))) == 32 ) {
				goto _st4;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
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
			if ( ( (*( p))) == 32 ) {
				goto _st4;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st4;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _ctr6;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr6;
				}
			} else {
				goto _ctr6;
			}
			goto _st0;
		}
		_ctr6:
			{
#line 410 "dynlease.rl"
			cps.st = p; }
		
#line 624 "dynlease.cpp"

		goto _st5;
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
			if ( ( (*( p))) == 32 ) {
				goto _ctr8;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr8;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _st5;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st5;
				}
			} else {
				goto _st5;
			}
			goto _st0;
		}
		_ctr8:
			{
#line 412 "dynlease.rl"
			
			ptrdiff_t l = p - cps.st;
			if (l < 0 || (size_t)l >= sizeof cps.interface) abort();
			*(char *)mempcpy(cps.interface, cps.st, (size_t)l) = 0;
		}
		
#line 665 "dynlease.cpp"

		goto _st6;
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
			switch( ( (*( p))) ) {
				case 32: {
					goto _st6;
				}
				case 46: {
					goto _ctr10;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _ctr10;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st6;
			}
			goto _st0;
		}
		_ctr10:
			{
#line 410 "dynlease.rl"
			cps.st = p; }
		
#line 699 "dynlease.cpp"

		goto _st7;
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
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr12;
				}
				case 46: {
					goto _st7;
				}
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st7;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr12;
			}
			goto _st0;
		}
		_ctr12:
			{
#line 443 "dynlease.rl"
			
			cps.v4_addr = MARKED_STRING();
			lc_string_inplace(cps.v4_addr.data(), cps.v4_addr.size());
		}
		
#line 736 "dynlease.cpp"

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
			if ( ( (*( p))) == 32 ) {
				goto _st8;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st8;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _ctr14;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr14;
				}
			} else {
				goto _ctr14;
			}
			goto _st0;
		}
		_ctr14:
			{
#line 410 "dynlease.rl"
			cps.st = p; }
		
#line 773 "dynlease.cpp"

		goto _st9;
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st10;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st10;
				}
			} else {
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
			if ( ( (*( p))) == 58 ) {
				goto _st11;
			}
			goto _st0;
		}
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st12;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st12;
				}
			} else {
				goto _st12;
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st13;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st13;
				}
			} else {
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
			if ( ( (*( p))) == 58 ) {
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st15;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st15;
				}
			} else {
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st16;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st16;
				}
			} else {
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
			if ( ( (*( p))) == 58 ) {
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st18;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st18;
				}
			} else {
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st19;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st19;
				}
			} else {
				goto _st19;
			}
			goto _st0;
		}
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
			if ( ( (*( p))) == 58 ) {
				goto _st20;
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st21;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st21;
				}
			} else {
				goto _st21;
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st22;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st22;
				}
			} else {
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
			if ( ( (*( p))) == 58 ) {
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st24;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st24;
				}
			} else {
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st25;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st25;
				}
			} else {
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
			if ( ( (*( p))) == 32 ) {
				goto _ctr32;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _ctr32;
			}
			goto _st0;
		}
		_ctr32:
			{
#line 434 "dynlease.rl"
			
			ptrdiff_t blen = p - cps.st;
			if (blen < 0 || blen >= (int)sizeof cps.macaddr) {
				cps.parse_error = true;
				{p+= 1; cps.cs = 26; goto _out;}
			}
			memcpy(cps.macaddr, cps.st, 6);
			lc_string_inplace(cps.macaddr, sizeof cps.macaddr);
		}
		
#line 1134 "dynlease.cpp"

		goto _st26;
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
			if ( ( (*( p))) == 32 ) {
				goto _st26;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _ctr34;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st26;
			}
			goto _st0;
		}
		_ctr34:
			{
#line 410 "dynlease.rl"
			cps.st = p; }
		
#line 1163 "dynlease.cpp"

		goto _st41;
		_ctr57:
			{
#line 451 "dynlease.rl"
			
			char buf[64];
			ptrdiff_t blen = p - cps.st;
			if (blen < 0 || blen >= (int)sizeof buf) {
				cps.parse_error = true;
				{p+= 1; cps.cs = 41; goto _out;}
			}
			memcpy(buf, p, (size_t)blen); buf[blen] = 0;
			if (sscanf(cps.st, SCNi64, &cps.expire_time) != 1) {
				cps.parse_error = true;
				{p+= 1; cps.cs = 41; goto _out;}
			}
		}
		
#line 1182 "dynlease.cpp"

			{
#line 465 "dynlease.rl"
			
			emplace_dynlease4_state(linenum, cps.interface, cps.v4_addr.c_str(),
			cps.macaddr, cps.expire_time);
		}
		
#line 1190 "dynlease.cpp"

		goto _st41;
		_st41:
		if ( p == eof )
			goto _out41;
		p+= 1;
		st_case_41:
		if ( p == pe && p != eof )
			goto _out41;
		if ( p == eof ) {
			goto _ctr57;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr58;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st41;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr58;
			}
			goto _st0;
		}
		_ctr58:
			{
#line 451 "dynlease.rl"
			
			char buf[64];
			ptrdiff_t blen = p - cps.st;
			if (blen < 0 || blen >= (int)sizeof buf) {
				cps.parse_error = true;
				{p+= 1; cps.cs = 42; goto _out;}
			}
			memcpy(buf, p, (size_t)blen); buf[blen] = 0;
			if (sscanf(cps.st, SCNi64, &cps.expire_time) != 1) {
				cps.parse_error = true;
				{p+= 1; cps.cs = 42; goto _out;}
			}
		}
		
#line 1231 "dynlease.cpp"

		goto _st42;
		_ctr60:
			{
#line 465 "dynlease.rl"
			
			emplace_dynlease4_state(linenum, cps.interface, cps.v4_addr.c_str(),
			cps.macaddr, cps.expire_time);
		}
		
#line 1241 "dynlease.cpp"

		goto _st42;
		_st42:
		if ( p == eof )
			goto _out42;
		p+= 1;
		st_case_42:
		if ( p == pe && p != eof )
			goto _out42;
		if ( p == eof ) {
			goto _ctr60;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st42;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st42;
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
			if ( ( (*( p))) == 32 ) {
				goto _st28;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st28;
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
			if ( ( (*( p))) == 32 ) {
				goto _st28;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st28;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _ctr36;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr36;
				}
			} else {
				goto _ctr36;
			}
			goto _st0;
		}
		_ctr36:
			{
#line 410 "dynlease.rl"
			cps.st = p; }
		
#line 1314 "dynlease.cpp"

		goto _st29;
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
			if ( ( (*( p))) == 32 ) {
				goto _ctr38;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr38;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 90 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 122 ) {
						goto _st29;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st29;
				}
			} else {
				goto _st29;
			}
			goto _st0;
		}
		_ctr38:
			{
#line 412 "dynlease.rl"
			
			ptrdiff_t l = p - cps.st;
			if (l < 0 || (size_t)l >= sizeof cps.interface) abort();
			*(char *)mempcpy(cps.interface, cps.st, (size_t)l) = 0;
		}
		
#line 1355 "dynlease.cpp"

		goto _st30;
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
			if ( ( (*( p))) == 32 ) {
				goto _st30;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st30;
				}
			} else if ( ( (*( p))) > 58 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _ctr40;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr40;
				}
			} else {
				goto _ctr40;
			}
			goto _st0;
		}
		_ctr40:
			{
#line 410 "dynlease.rl"
			cps.st = p; }
		
#line 1392 "dynlease.cpp"

		goto _st31;
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
			if ( ( (*( p))) == 32 ) {
				goto _ctr42;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr42;
				}
			} else if ( ( (*( p))) > 58 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st31;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st31;
				}
			} else {
				goto _st31;
			}
			goto _st0;
		}
		_ctr42:
			{
#line 447 "dynlease.rl"
			
			cps.v6_addr = MARKED_STRING();
			lc_string_inplace(cps.v6_addr.data(), cps.v6_addr.size());
		}
		
#line 1432 "dynlease.cpp"

		goto _st32;
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
			if ( ( (*( p))) == 32 ) {
				goto _st32;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _st32;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _ctr44;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _ctr44;
				}
			} else {
				goto _ctr44;
			}
			goto _st0;
		}
		_ctr44:
			{
#line 410 "dynlease.rl"
			cps.st = p; }
		
#line 1469 "dynlease.cpp"

		goto _st33;
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
			if ( ( (*( p))) == 32 ) {
				goto _ctr46;
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr46;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st37;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st37;
				}
			} else {
				goto _st37;
			}
			goto _st0;
		}
		_ctr46:
			{
#line 417 "dynlease.rl"
			
			cps.duid = MARKED_STRING();
			lc_string_inplace(cps.duid.data(), cps.duid.size());
		}
		
#line 1509 "dynlease.cpp"

		goto _st34;
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
			if ( ( (*( p))) == 32 ) {
				goto _st34;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _ctr49;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st34;
			}
			goto _st0;
		}
		_ctr49:
			{
#line 410 "dynlease.rl"
			cps.st = p; }
		
#line 1538 "dynlease.cpp"

		goto _st35;
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
				goto _ctr51;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st35;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr51;
			}
			goto _st0;
		}
		_ctr51:
			{
#line 421 "dynlease.rl"
			
			char buf[64];
			ptrdiff_t blen = p - cps.st;
			if (blen < 0 || blen >= (int)sizeof buf) {
				cps.parse_error = true;
				{p+= 1; cps.cs = 36; goto _out;}
			}
			memcpy(buf, p, (size_t)blen); buf[blen] = 0;
			if (sscanf(cps.st, SCNu32, &cps.iaid) != 1) {
				cps.parse_error = true;
				{p+= 1; cps.cs = 36; goto _out;}
			}
		}
		
#line 1579 "dynlease.cpp"

		goto _st36;
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
					goto _ctr53;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _st36;
			}
			goto _st0;
		}
		_ctr53:
			{
#line 410 "dynlease.rl"
			cps.st = p; }
		
#line 1608 "dynlease.cpp"

		goto _st43;
		_ctr62:
			{
#line 451 "dynlease.rl"
			
			char buf[64];
			ptrdiff_t blen = p - cps.st;
			if (blen < 0 || blen >= (int)sizeof buf) {
				cps.parse_error = true;
				{p+= 1; cps.cs = 43; goto _out;}
			}
			memcpy(buf, p, (size_t)blen); buf[blen] = 0;
			if (sscanf(cps.st, SCNi64, &cps.expire_time) != 1) {
				cps.parse_error = true;
				{p+= 1; cps.cs = 43; goto _out;}
			}
		}
		
#line 1627 "dynlease.cpp"

			{
#line 469 "dynlease.rl"
			
			emplace_dynlease6_state(linenum, cps.interface, cps.v6_addr.c_str(),
			cps.duid.data(), cps.duid.size(), cps.iaid, cps.expire_time);
		}
		
#line 1635 "dynlease.cpp"

		goto _st43;
		_st43:
		if ( p == eof )
			goto _out43;
		p+= 1;
		st_case_43:
		if ( p == pe && p != eof )
			goto _out43;
		if ( p == eof ) {
			goto _ctr62;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _ctr63;
			}
			if ( ( (*( p))) > 13 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st43;
				}
			} else if ( ( (*( p))) >= 9 ) {
				goto _ctr63;
			}
			goto _st0;
		}
		_ctr63:
			{
#line 451 "dynlease.rl"
			
			char buf[64];
			ptrdiff_t blen = p - cps.st;
			if (blen < 0 || blen >= (int)sizeof buf) {
				cps.parse_error = true;
				{p+= 1; cps.cs = 44; goto _out;}
			}
			memcpy(buf, p, (size_t)blen); buf[blen] = 0;
			if (sscanf(cps.st, SCNi64, &cps.expire_time) != 1) {
				cps.parse_error = true;
				{p+= 1; cps.cs = 44; goto _out;}
			}
		}
		
#line 1676 "dynlease.cpp"

		goto _st44;
		_ctr65:
			{
#line 469 "dynlease.rl"
			
			emplace_dynlease6_state(linenum, cps.interface, cps.v6_addr.c_str(),
			cps.duid.data(), cps.duid.size(), cps.iaid, cps.expire_time);
		}
		
#line 1686 "dynlease.cpp"

		goto _st44;
		_st44:
		if ( p == eof )
			goto _out44;
		p+= 1;
		st_case_44:
		if ( p == pe && p != eof )
			goto _out44;
		if ( p == eof ) {
			goto _ctr65;}
		else {
			if ( ( (*( p))) == 32 ) {
				goto _st44;
			}
			if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
				goto _st44;
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
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr46;
				}
				case 45: {
					goto _st38;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr46;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st33;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st33;
				}
			} else {
				goto _st33;
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st39;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st39;
				}
			} else {
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
			if ( ( (*( p))) < 65 ) {
				if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
					goto _st40;
				}
			} else if ( ( (*( p))) > 70 ) {
				if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
					goto _st40;
				}
			} else {
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
			switch( ( (*( p))) ) {
				case 32: {
					goto _ctr46;
				}
				case 45: {
					goto _st38;
				}
			}
			if ( ( (*( p))) < 48 ) {
				if ( 9 <= ( (*( p))) && ( (*( p))) <= 13 ) {
					goto _ctr46;
				}
			} else if ( ( (*( p))) > 57 ) {
				if ( ( (*( p))) > 70 ) {
					if ( 97 <= ( (*( p))) && ( (*( p))) <= 102 ) {
						goto _st39;
					}
				} else if ( ( (*( p))) >= 65 ) {
					goto _st39;
				}
			} else {
				goto _st39;
			}
			goto _st0;
		}
		_out1: cps.cs = 1; goto _out; 
		_out0: cps.cs = 0; goto _out; 
		_out2: cps.cs = 2; goto _out; 
		_out3: cps.cs = 3; goto _out; 
		_out4: cps.cs = 4; goto _out; 
		_out5: cps.cs = 5; goto _out; 
		_out6: cps.cs = 6; goto _out; 
		_out7: cps.cs = 7; goto _out; 
		_out8: cps.cs = 8; goto _out; 
		_out9: cps.cs = 9; goto _out; 
		_out10: cps.cs = 10; goto _out; 
		_out11: cps.cs = 11; goto _out; 
		_out12: cps.cs = 12; goto _out; 
		_out13: cps.cs = 13; goto _out; 
		_out14: cps.cs = 14; goto _out; 
		_out15: cps.cs = 15; goto _out; 
		_out16: cps.cs = 16; goto _out; 
		_out17: cps.cs = 17; goto _out; 
		_out18: cps.cs = 18; goto _out; 
		_out19: cps.cs = 19; goto _out; 
		_out20: cps.cs = 20; goto _out; 
		_out21: cps.cs = 21; goto _out; 
		_out22: cps.cs = 22; goto _out; 
		_out23: cps.cs = 23; goto _out; 
		_out24: cps.cs = 24; goto _out; 
		_out25: cps.cs = 25; goto _out; 
		_out26: cps.cs = 26; goto _out; 
		_out41: cps.cs = 41; goto _out; 
		_out42: cps.cs = 42; goto _out; 
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
		_out43: cps.cs = 43; goto _out; 
		_out44: cps.cs = 44; goto _out; 
		_out37: cps.cs = 37; goto _out; 
		_out38: cps.cs = 38; goto _out; 
		_out39: cps.cs = 39; goto _out; 
		_out40: cps.cs = 40; goto _out; 
		_out: {}
	}
	
#line 497 "dynlease.rl"

	
	if (cps.parse_error) return -1;
		if (cps.cs >= dynlease_line_m_first_final)
		return 1;
	if (cps.cs == dynlease_line_m_error)
		return -1;
	return -2;
}

bool dynlease_deserialize(const char *path)
{
	char buf[MAX_LINE];
	const auto f = fopen(path, "r");
	if (!f) {
		log_line("%s: failed to open '%s' for dynamic lease deserialization\n",
		__func__, path);
		return false;
	}
	SCOPE_EXIT{ fclose(f); };
	dyn_leases_v4.clear();
	dyn_leases_v6.clear();
	size_t linenum = 0;
	dynlease_parse_state ps;
	while (!feof(f)) {
		if (!fgets(buf, sizeof buf, f)) {
			if (!feof(f))
				log_line("%s: io error fetching line of '%s'\n", __func__, path);
			break;
		}
		auto llen = strlen(buf);
		if (llen == 0)
			continue;
		if (buf[llen-1] == '\n')
			buf[--llen] = 0;
		++linenum;
		ps.newline();
		const auto r = do_parse_dynlease_line(ps, buf, llen, linenum);
		if (r < 0) {
			if (r == -2)
				log_line("%s: Incomplete dynlease at line %zu; ignoring\n",
			__func__, linenum);
			else
				log_line("%s: Malformed dynlease at line %zu; ignoring.\n",
			__func__, linenum);
			continue;
		}
	}
	return true;
}

