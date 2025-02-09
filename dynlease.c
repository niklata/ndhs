#line 1 "dynlease.rl"
// -*- c -*-
// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <limits.h>
#include <inttypes.h>
#include <assert.h>
#include <nlsocket.h> // for MAX_NL_INTERFACES
#include <ipaddr.h>
#include <net/if.h>
#include "nk/log.h"
#include <dynlease.h>
#include <get_current_ts.h>

#define MAX_LINE 2048
// The RFC allows for 128 raw bytes, which corresponds
// to a value of 256.
#define MAX_DUID 256

extern struct NLSocket nl_socket;

struct lease_state_v4
{
	struct lease_state_v4 *next;
	struct in6_addr addr;
	uint8_t macaddr[6];
	int64_t expire_time;
};

struct lease_state_v6
{
	struct lease_state_v6 *next;
	struct in6_addr addr;
	size_t duid_len;
	int64_t expire_time;
	uint32_t iaid;
	char duid[]; // not null terminated, hex string
};

// Maps interfaces to lease data.
static struct lease_state_v4 *dyn_leases_v4[MAX_NL_INTERFACES];
static struct lease_state_v6 *dyn_leases_v6[MAX_NL_INTERFACES];
static struct lease_state_v4 *ls4_freelist;
static struct lease_state_v6 *ls6_freelist;
static uint32_t n_leases_v6[MAX_NL_INTERFACES];

size_t dynlease6_count(int ifindex)
{
	if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return 0;
		return n_leases_v6[ifindex];
}

void dynlease_gc(void)
{
	int64_t ts = get_current_ts();
	for (size_t i = 0; i < MAX_NL_INTERFACES; ++i) {
		if (dyn_leases_v4[i]) {
			struct lease_state_v4 **prev = &dyn_leases_v4[i];
			for (struct lease_state_v4 *p = dyn_leases_v4[i]; p;) {
				if (p->expire_time < ts) {
					*prev = p->next;
					p->next = ls4_freelist;
					ls4_freelist = p->next;
					p = p->next;
				}
				if (p) {
					prev = &p->next;
					p = p->next;
				}
			}
		}
		if (dyn_leases_v6[i]) {
			struct lease_state_v6 **prev = &dyn_leases_v6[i];
			for (struct lease_state_v6 *p = dyn_leases_v6[i]; p;) {
				if (p->expire_time < ts) {
					*prev = p->next;
					p->next = ls6_freelist;
					ls6_freelist = p->next;
					p = p->next;
					assert(n_leases_v6[i] > 0);
					--n_leases_v6[i];
				}
				if (p) {
					prev = &p->next;
					p = p->next;
				}
			}
		}
	}
}

bool dynlease4_add(int ifindex, const struct in6_addr *v4_addr, const uint8_t *macaddr,
int64_t expire_time)
{
	if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
		
	for (struct lease_state_v4 *p = dyn_leases_v4[ifindex]; p; p = p->next) {
		if (!memcmp(&p->addr, v4_addr, sizeof p->addr)) {
			if (!memcmp(&p->macaddr, macaddr, 6)) {
				p->expire_time = expire_time;
				return true;
			}
			return false;
		}
	}
	struct lease_state_v4 *n = ls4_freelist;
	if (n) {
		ls4_freelist = n->next;
	} else {
		n = malloc(sizeof(struct lease_state_v4));
		if (!n) abort();
		}
	n->next = dyn_leases_v4[ifindex];
	n->addr = *v4_addr;
	memcpy(n->macaddr, macaddr, sizeof n->macaddr);
	n->expire_time = expire_time;
	dyn_leases_v4[ifindex] = n;
	return true;
}

static bool duid_compare(const char *a, size_t al, const char *b, size_t bl)
{
	return al == bl && !memcmp(a, b, al);
}

bool dynlease6_add(int ifindex, const struct in6_addr *v6_addr,
const char *duid, size_t duid_len, uint32_t iaid, int64_t expire_time)
{
	if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
		
	for (struct lease_state_v6 *p = dyn_leases_v6[ifindex]; p; p = p->next) {
		if (!memcmp(&p->addr, v6_addr, sizeof p->addr)) {
			if (!duid_compare(p->duid, p->duid_len, duid, duid_len) && p->iaid == iaid) {
				p->expire_time = expire_time;
				return true;
			}
			return false;
		}
	}
	struct lease_state_v6 *n = ls6_freelist;
	if (n && n->duid_len < duid_len) n = NULL;
		if (n) {
		ls6_freelist = n->next;
	} else {
		n = malloc(sizeof(struct lease_state_v6) + duid_len);
		if (!n) abort();
		}
	n->next = dyn_leases_v6[ifindex];
	n->addr = *v6_addr;
	n->duid_len = duid_len;
	n->expire_time = expire_time;
	n->iaid = iaid;
	memcpy(n->duid, duid, duid_len);
	dyn_leases_v6[ifindex] = n;
	++n_leases_v6[ifindex];
	return true;
}

struct in6_addr dynlease4_query_refresh(int ifindex, const uint8_t *macaddr,
int64_t expire_time)
{
	if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return in6addr_any;
		
	for (struct lease_state_v4 *p = dyn_leases_v4[ifindex]; p; p = p->next) {
		if (!memcmp(&p->macaddr, macaddr, 6)) {
			p->expire_time = expire_time;
			return p->addr;
		}
	}
	return in6addr_any;
}

struct in6_addr dynlease6_query_refresh(int ifindex, const char *duid, size_t duid_len,
uint32_t iaid, int64_t expire_time)
{
	if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return in6addr_any;
		
	for (struct lease_state_v6 *p = dyn_leases_v6[ifindex]; p; p = p->next) {
		if (!duid_compare(p->duid, p->duid_len, duid, duid_len) && p->iaid == iaid) {
			p->expire_time = expire_time;
			return p->addr;
		}
	}
	return in6addr_any;
}

bool dynlease4_exists(int ifindex, const struct in6_addr *v4_addr, const uint8_t *macaddr)
{
	if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
		
	int64_t ts = get_current_ts();
	for (struct lease_state_v4 *p = dyn_leases_v4[ifindex]; p; p = p->next) {
		if (!memcmp(&p->addr, v4_addr, sizeof p->addr) && !memcmp(&p->macaddr, macaddr, 6)) {
			return ts < p->expire_time;
		}
	}
	return false;
}

bool dynlease4_del(int ifindex, const struct in6_addr *v4_addr, const uint8_t *macaddr)
{
	if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
		
	struct lease_state_v4 **prev = &dyn_leases_v4[ifindex];
	for (struct lease_state_v4 *p = dyn_leases_v4[ifindex]; p; prev = &p->next, p = p->next) {
		if (!memcmp(&p->addr, v4_addr, sizeof p->addr) && !memcmp(&p->macaddr, macaddr, 6)) {
			*prev = p->next;
			p->next = ls4_freelist;
			ls4_freelist = p->next;
			return true;
		}
	}
	return false;
}

bool dynlease6_del(int ifindex, const struct in6_addr *v6_addr,
const char *duid, size_t duid_len, uint32_t iaid)
{
	if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
		
	struct lease_state_v6 **prev = &dyn_leases_v6[ifindex];
	for (struct lease_state_v6 *p = dyn_leases_v6[ifindex]; p; prev = &p->next, p = p->next) {
		if (!memcmp(&p->addr, v6_addr, sizeof p->addr)
			&& !duid_compare(p->duid, p->duid_len, duid, duid_len) && p->iaid == iaid) {
			*prev = p->next;
			p->next = ls6_freelist;
			ls6_freelist = p->next;
			assert(n_leases_v6[ifindex] > 0);
			--n_leases_v6[ifindex];
			return true;
		}
	}
	return false;
}

// v4 <interface> <ip> <macaddr> <expire_time>
// v6 <interface> <ip> <duid> <iaid> <expire_time>

bool dynlease_serialize(const char *path)
{
	bool ret = false;
	size_t pathlen = strlen(path);
	int fd = -1;
	char tmp_path[PATH_MAX];
	if (pathlen + 5 > sizeof tmp_path) abort();
		memcpy(tmp_path, path, pathlen);
	memcpy(tmp_path + pathlen, ".tmp", 5);
	
	FILE *f = fopen(tmp_path, "w");
	if (!f) {
		log_line("%s: failed to open '%s' for dynamic lease serialization\n",
		__func__, path);
		goto out0;
	}
	int64_t ts = get_current_ts();
	for (size_t c = 0; c < MAX_NL_INTERFACES; ++c) {
		if (!dyn_leases_v4[c]) continue;
			const struct netif_info *nlinfo = NLSocket_get_ifinfo(&nl_socket, c);
		if (!nlinfo) continue;
			const char *iface = nlinfo->name;
		for (struct lease_state_v4 *p = dyn_leases_v4[c]; p; p = p->next) {
			// Don't write out dynamic leases that have expired.
			if (ts >= p->expire_time)
				continue;
			char abuf[48];
			if (!ipaddr_to_string(abuf, sizeof abuf, &p->addr)) goto out1;
				if (fprintf(f, "v4 %s %s %.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx %zu\n",
				iface, abuf,
			p->macaddr[0], p->macaddr[1], p->macaddr[2],
			p->macaddr[3], p->macaddr[4], p->macaddr[5], p->expire_time) < 0) {
				log_line("%s: fprintf failed: %s\n", __func__, strerror(errno));
				goto out1;
			}
		}
	}
	for (size_t c = 0; c < MAX_NL_INTERFACES; ++c) {
		if (!dyn_leases_v6[c]) continue;
			const struct netif_info *nlinfo = NLSocket_get_ifinfo(&nl_socket, c);
		if (!nlinfo) continue;
			const char *iface = nlinfo->name;
		for (struct lease_state_v6 *p = dyn_leases_v6[c]; p; p = p->next) {
			// Don't write out dynamic leases that have expired.
			if (ts >= p->expire_time) continue;
				// A valid DUID is required.
			if (p->duid_len == 0) continue;
				
			char abuf[48];
			if (!ipaddr_to_string(abuf, sizeof abuf, &p->addr)) goto out1;
				if (fprintf(f, "v6 %s %s ", iface, abuf) < 0) goto err0;
				for (size_t k = 0; k < p->duid_len; ++k) {
				if (fprintf(f, "%.2hhx", p->duid[k]) < 0) goto err0;
				}
			if (fprintf(f, " %u %lu\n", p->iaid, p->expire_time) < 0) goto err0;
				continue;
			err0:
			log_line("%s: fprintf failed: %s\n", __func__, strerror(errno));
			goto out1;
		}
	}
	if (fflush(f)) {
		log_line("%s: fflush failed: %s\n", __func__, strerror(errno));
		goto out1;
	}
	fd = fileno(f);
	if (fdatasync(fd)) {
		log_line("%s: fdatasync failed: %s\n", __func__, strerror(errno));
		goto out1;
	}
	if (rename(tmp_path, path)) {
		log_line("%s: rename failed: %s\n", __func__, strerror(errno));
		goto out1;
	}
	ret = true;
	out1:
	fclose(f);
	unlink(tmp_path);
	out0:
	return ret;
}

// v4 <interface> <ip> <macaddr> <expire_time>
// v6 <interface> <ip> <duid> <iaid> <expire_time>

struct dynlease_parse_state {
	const char *st;
	int cs;
	
	int64_t expire_time;
	size_t duid_len;
	int ifindex;
	uint32_t iaid;
	bool parse_error;
	char duid[MAX_DUID];
	char interface[IFNAMSIZ];
	char v6_addr[48];
	char v4_addr[16];
	uint8_t macaddr[6];
};

static void newline(struct dynlease_parse_state *self) {
	*self = (struct dynlease_parse_state){
		.st = self->st,
		.cs = self->cs,
		.ifindex = -1,
	};
}

#include "parsehelp.h"


#line 450 "dynlease.rl"


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-const-variable"

#line 358 "dynlease.c"
static const signed char _dynlease_line_m_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1,
	3, 1, 4, 1, 5, 1, 6, 1,
	7, 1, 8, 1, 9, 2, 7, 8,
	2, 7, 9, 0
};

static const short _dynlease_line_m_key_offsets[] = {
	0, 0, 4, 6, 9, 18, 27, 33,
	39, 48, 54, 55, 61, 67, 68, 74,
	80, 81, 87, 93, 94, 100, 106, 107,
	113, 119, 122, 127, 130, 139, 148, 157,
	166, 175, 184, 189, 194, 199, 209, 215,
	221, 231, 236, 239, 244, 0
};

static const char _dynlease_line_m_trans_keys[] = {
	32, 118, 9, 13, 52, 54, 32, 9,
	13, 32, 9, 13, 48, 57, 65, 90,
	97, 122, 32, 9, 13, 48, 57, 65,
	90, 97, 122, 32, 46, 9, 13, 48,
	57, 32, 46, 9, 13, 48, 57, 32,
	9, 13, 48, 57, 65, 70, 97, 102,
	48, 57, 65, 70, 97, 102, 58, 48,
	57, 65, 70, 97, 102, 48, 57, 65,
	70, 97, 102, 58, 48, 57, 65, 70,
	97, 102, 48, 57, 65, 70, 97, 102,
	58, 48, 57, 65, 70, 97, 102, 48,
	57, 65, 70, 97, 102, 58, 48, 57,
	65, 70, 97, 102, 48, 57, 65, 70,
	97, 102, 58, 48, 57, 65, 70, 97,
	102, 48, 57, 65, 70, 97, 102, 32,
	9, 13, 32, 9, 13, 48, 57, 32,
	9, 13, 32, 9, 13, 48, 57, 65,
	90, 97, 122, 32, 9, 13, 48, 57,
	65, 90, 97, 122, 32, 9, 13, 48,
	58, 65, 70, 97, 102, 32, 9, 13,
	48, 58, 65, 70, 97, 102, 32, 9,
	13, 48, 57, 65, 70, 97, 102, 32,
	9, 13, 48, 57, 65, 70, 97, 102,
	32, 9, 13, 48, 57, 32, 9, 13,
	48, 57, 32, 9, 13, 48, 57, 32,
	45, 9, 13, 48, 57, 65, 70, 97,
	102, 48, 57, 65, 70, 97, 102, 48,
	57, 65, 70, 97, 102, 32, 45, 9,
	13, 48, 57, 65, 70, 97, 102, 32,
	9, 13, 48, 57, 32, 9, 13, 32,
	9, 13, 48, 57, 32, 9, 13, 0
};

static const signed char _dynlease_line_m_single_lengths[] = {
	0, 2, 2, 1, 1, 1, 2, 2,
	1, 0, 1, 0, 0, 1, 0, 0,
	1, 0, 0, 1, 0, 0, 1, 0,
	0, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 2, 0, 0,
	2, 1, 1, 1, 1, 0
};

static const signed char _dynlease_line_m_range_lengths[] = {
	0, 1, 0, 1, 4, 4, 2, 2,
	4, 3, 0, 3, 3, 0, 3, 3,
	0, 3, 3, 0, 3, 3, 0, 3,
	3, 1, 2, 1, 4, 4, 4, 4,
	4, 4, 2, 2, 2, 4, 3, 3,
	4, 2, 1, 2, 1, 0
};

static const short _dynlease_line_m_index_offsets[] = {
	0, 0, 4, 7, 10, 16, 22, 27,
	32, 38, 42, 44, 48, 52, 54, 58,
	62, 64, 68, 72, 74, 78, 82, 84,
	88, 92, 95, 99, 102, 108, 114, 120,
	126, 132, 138, 142, 146, 150, 157, 161,
	165, 172, 176, 179, 183, 0
};

static const signed char _dynlease_line_m_cond_targs[] = {
	1, 2, 1, 0, 3, 27, 0, 4,
	4, 0, 4, 4, 5, 5, 5, 0,
	6, 6, 5, 5, 5, 0, 6, 7,
	6, 7, 0, 8, 7, 8, 7, 0,
	8, 8, 9, 9, 9, 0, 10, 10,
	10, 0, 11, 0, 12, 12, 12, 0,
	13, 13, 13, 0, 14, 0, 15, 15,
	15, 0, 16, 16, 16, 0, 17, 0,
	18, 18, 18, 0, 19, 19, 19, 0,
	20, 0, 21, 21, 21, 0, 22, 22,
	22, 0, 23, 0, 24, 24, 24, 0,
	25, 25, 25, 0, 26, 26, 0, 26,
	26, 41, 0, 28, 28, 0, 28, 28,
	29, 29, 29, 0, 30, 30, 29, 29,
	29, 0, 30, 30, 31, 31, 31, 0,
	32, 32, 31, 31, 31, 0, 32, 32,
	33, 33, 33, 0, 34, 34, 37, 37,
	37, 0, 34, 34, 35, 0, 36, 36,
	35, 0, 36, 36, 43, 0, 34, 38,
	34, 33, 33, 33, 0, 39, 39, 39,
	0, 40, 40, 40, 0, 34, 38, 34,
	39, 39, 39, 0, 42, 42, 41, 0,
	42, 42, 0, 44, 44, 43, 0, 44,
	44, 0, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13,
	14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29,
	30, 31, 32, 33, 34, 35, 36, 37,
	38, 39, 40, 41, 42, 43, 44, 0
};

static const signed char _dynlease_line_m_cond_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 1, 1, 0,
	3, 3, 0, 0, 0, 0, 0, 1,
	0, 1, 0, 11, 0, 11, 0, 0,
	0, 0, 1, 1, 1, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 9, 9, 0, 0,
	0, 1, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 0, 3, 3, 0, 0,
	0, 0, 0, 0, 1, 1, 1, 0,
	13, 13, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 0, 5, 5, 0, 0,
	0, 0, 0, 0, 1, 0, 7, 7,
	0, 0, 0, 0, 1, 0, 5, 0,
	5, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 5, 0, 5,
	0, 0, 0, 0, 15, 15, 0, 0,
	0, 0, 0, 15, 15, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 21, 17, 24, 19, 0
};

static const short _dynlease_line_m_eof_trans[] = {
	187, 188, 189, 190, 191, 192, 193, 194,
	195, 196, 197, 198, 199, 200, 201, 202,
	203, 204, 205, 206, 207, 208, 209, 210,
	211, 212, 213, 214, 215, 216, 217, 218,
	219, 220, 221, 222, 223, 224, 225, 226,
	227, 228, 229, 230, 231, 0
};

static const int dynlease_line_m_start = 1;
static const int dynlease_line_m_first_final = 41;
static const int dynlease_line_m_error = 0;

static const int dynlease_line_m_en_main = 1;


#line 454 "dynlease.rl"

#pragma GCC diagnostic pop

static int do_parse_dynlease_line(struct dynlease_parse_state *cps, const char *p, size_t plen,
const size_t linenum)
{
	const char *pe = p + plen;
	const char *eof = pe;
	

#line 524 "dynlease.c"
	{
		cps->cs = (int)dynlease_line_m_start;
	}
	
#line 463 "dynlease.rl"


#line 529 "dynlease.c"
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
			if ( _dynlease_line_m_eof_trans[cps->cs] > 0 ) {
				_trans = (unsigned int)_dynlease_line_m_eof_trans[cps->cs] - 1;
			}
		}
		else {
			_keys = ( _dynlease_line_m_trans_keys + (_dynlease_line_m_key_offsets[cps->cs]));
			_trans = (unsigned int)_dynlease_line_m_index_offsets[cps->cs];
			
			_klen = (int)_dynlease_line_m_single_lengths[cps->cs];
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
			
			_klen = (int)_dynlease_line_m_range_lengths[cps->cs];
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
		cps->cs = (int)_dynlease_line_m_cond_targs[_trans];
		
		if ( _dynlease_line_m_cond_actions[_trans] != 0 ) {
			
			_acts = ( _dynlease_line_m_actions + (_dynlease_line_m_cond_actions[_trans]));
			_nacts = (unsigned int)(*( _acts));
			_acts += 1;
			while ( _nacts > 0 ) {
				switch ( (*( _acts)) )
				{
					case 0:  {
							{
#line 356 "dynlease.rl"
							cps->st = p; }
						
#line 611 "dynlease.c"

						break; 
					}
					case 1:  {
							{
#line 358 "dynlease.rl"
							
							assign_strbuf(cps->interface, NULL, sizeof cps->interface, cps->st, p);
							const struct netif_info *nlinfo = NLSocket_get_ifinfo_by_name(&nl_socket, cps->interface);
							cps->ifindex = nlinfo ? nlinfo->index : -1;
						}
						
#line 623 "dynlease.c"

						break; 
					}
					case 2:  {
							{
#line 363 "dynlease.rl"
							
							assign_strbuf(cps->duid, &cps->duid_len, sizeof cps->duid, cps->st, p);
							lc_string_inplace(cps->duid, cps->duid_len);
						}
						
#line 634 "dynlease.c"

						break; 
					}
					case 3:  {
							{
#line 367 "dynlease.rl"
							
							char buf[64];
							ptrdiff_t blen = p - cps->st;
							if (blen < 0 || blen >= (int)sizeof buf) {
								cps->parse_error = true;
								{p += 1; goto _out; }
							}
							memcpy(buf, cps->st, (size_t)blen); buf[blen] = 0;
							if (sscanf(buf, "%" SCNu32, &cps->iaid) != 1) {
								cps->parse_error = true;
								{p += 1; goto _out; }
							}
						}
						
#line 654 "dynlease.c"

						break; 
					}
					case 4:  {
							{
#line 380 "dynlease.rl"
							
							char buf[32];
							ptrdiff_t blen = p - cps->st;
							if (blen < 0 || blen >= (int)sizeof buf) {
								cps->parse_error = true;
								{p += 1; goto _out; }
							}
							*((char *)mempcpy(buf, cps->st, (size_t)blen)) = 0;
							if (sscanf(buf, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
							&cps->macaddr[0], &cps->macaddr[1], &cps->macaddr[2],
							&cps->macaddr[3], &cps->macaddr[4], &cps->macaddr[5]) != 6) {
								cps->parse_error = true;
								{p += 1; goto _out; }
							}
						}
						
#line 676 "dynlease.c"

						break; 
					}
					case 5:  {
							{
#line 395 "dynlease.rl"
							
							size_t l;
							assign_strbuf(cps->v4_addr, &l, sizeof cps->v4_addr, cps->st, p);
							lc_string_inplace(cps->v4_addr, l);
						}
						
#line 688 "dynlease.c"

						break; 
					}
					case 6:  {
							{
#line 400 "dynlease.rl"
							
							size_t l;
							assign_strbuf(cps->v6_addr, &l, sizeof cps->v6_addr, cps->st, p);
							lc_string_inplace(cps->v6_addr, l);
						}
						
#line 700 "dynlease.c"

						break; 
					}
					case 7:  {
							{
#line 405 "dynlease.rl"
							
							char buf[64];
							ptrdiff_t blen = p - cps->st;
							if (blen < 0 || blen >= (int)sizeof buf) {
								cps->parse_error = true;
								{p += 1; goto _out; }
							}
							memcpy(buf, cps->st, (size_t)blen); buf[blen] = 0;
							if (sscanf(buf, "%" SCNi64, &cps->expire_time) != 1) {
								cps->parse_error = true;
								{p += 1; goto _out; }
							}
						}
						
#line 720 "dynlease.c"

						break; 
					}
					case 8:  {
							{
#line 419 "dynlease.rl"
							
							struct in6_addr ipa;
							if (!ipaddr_from_string(&ipa, cps->v4_addr)) {
								log_line("Bad IP address at line %zu: %s\n", linenum, cps->v4_addr);
								cps->parse_error = true;
								{p += 1; goto _out; }
							}
							dynlease4_add(cps->ifindex, &ipa, cps->macaddr, cps->expire_time);
						}
						
#line 736 "dynlease.c"

						break; 
					}
					case 9:  {
							{
#line 428 "dynlease.rl"
							
							struct in6_addr ipa;
							if (!ipaddr_from_string(&ipa, cps->v6_addr)) {
								log_line("Bad IP address at line %zu: %s\n", linenum, cps->v6_addr);
								cps->parse_error = true;
								{p += 1; goto _out; }
							}
							dynlease6_add(cps->ifindex, &ipa, cps->duid, cps->duid_len, cps->iaid, cps->expire_time);
						}
						
#line 752 "dynlease.c"

						break; 
					}
				}
				_nacts -= 1;
				_acts += 1;
			}
			
		}
		
		if ( p == eof ) {
			if ( cps->cs >= 41 )
				goto _out;
		}
		else {
			if ( cps->cs != 0 ) {
				p += 1;
				goto _resume;
			}
		}
		_out: {}
	}
	
#line 464 "dynlease.rl"

	
	if (cps->parse_error) return -1;
		if (cps->cs >= dynlease_line_m_first_final)
		return 1;
	if (cps->cs == dynlease_line_m_error)
		return -1;
	return -2;
}

bool dynlease_deserialize(const char *path)
{
	bool ret = false;
	size_t linenum = 0;
	struct dynlease_parse_state ps = { .st = NULL, .cs = 0, .parse_error = false };
	char buf[MAX_LINE];
	FILE *f = fopen(path, "r");
	if (!f) {
		log_line("%s: failed to open '%s' for dynamic lease deserialization\n",
		__func__, path);
		goto out0;
	}
	for (size_t i = 0; i < MAX_NL_INTERFACES; ++i) {
		if (dyn_leases_v4[i]) abort();
			if (dyn_leases_v6[i]) abort();
		}
	while (!feof(f)) {
		if (!fgets(buf, sizeof buf, f)) {
			if (!feof(f)) {
				log_line("%s: io error fetching line of '%s'\n", __func__, path);
				goto out1;
			}
			break;
		}
		size_t llen = strlen(buf);
		if (llen == 0)
			continue;
		if (buf[llen-1] == '\n')
			buf[--llen] = 0;
		++linenum;
		newline(&ps);
		int r = do_parse_dynlease_line(&ps, buf, llen, linenum);
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
	ret = true;
	out1:
	fclose(f);
	out0:
	return ret;
}

