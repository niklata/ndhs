// -*- c++ -*-
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

#define MAX_LINE 2048
// The RFC allows for 128 raw bytes, which corresponds
// to a value of 256.
#define MAX_DUID 256

extern struct NLSocket nl_socket;
int64_t get_current_ts();

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
                prev = &p->next, p = p->next;
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
                prev = &p->next, p = p->next;
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
    for (size_t c = 0; c < MAX_NL_INTERFACES; ++c) {
        if (!dyn_leases_v4[c]) continue;
        const struct netif_info *nlinfo = NLSocket_get_ifinfo(&nl_socket, c);
        if (!nlinfo) continue;
        const char *iface = nlinfo->name;
        for (struct lease_state_v4 *p = dyn_leases_v4[c]; p; p = p->next) {
            // Don't write out dynamic leases that have expired.
            if (get_current_ts() >= p->expire_time)
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
            if (get_current_ts() >= p->expire_time) continue;
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

%%{
    machine dynlease_line_m;
    access cps->;

    action St { cps->st = p; }

    action InterfaceEn {
        assign_strbuf(cps->interface, NULL, sizeof cps->interface, cps->st, p);
        const struct netif_info *nlinfo = NLSocket_get_ifinfo_by_name(&nl_socket, cps->interface);
        cps->ifindex = nlinfo ? nlinfo->index : -1;
    }
    action DuidEn {
        assign_strbuf(cps->duid, &cps->duid_len, sizeof cps->duid, cps->st, p);
        lc_string_inplace(cps->duid, cps->duid_len);
    }
    action IaidEn {
        char buf[64];
        ptrdiff_t blen = p - cps->st;
        if (blen < 0 || blen >= (int)sizeof buf) {
            cps->parse_error = true;
            fbreak;
        }
        memcpy(buf, cps->st, (size_t)blen); buf[blen] = 0;
        if (sscanf(buf, "%" SCNu32, &cps->iaid) != 1) {
            cps->parse_error = true;
            fbreak;
        }
    }
    action MacAddrEn {
        char buf[32];
        ptrdiff_t blen = p - cps->st;
        if (blen < 0 || blen >= (int)sizeof buf) {
            cps->parse_error = true;
            fbreak;
        }
        *((char *)mempcpy(buf, cps->st, (size_t)blen)) = 0;
        if (sscanf(buf, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
                   &cps->macaddr[0], &cps->macaddr[1], &cps->macaddr[2],
                   &cps->macaddr[3], &cps->macaddr[4], &cps->macaddr[5]) != 6) {
            cps->parse_error = true;
            fbreak;
        }
    }
    action V4AddrEn {
        size_t l;
        assign_strbuf(cps->v4_addr, &l, sizeof cps->v4_addr, cps->st, p);
        lc_string_inplace(cps->v4_addr, l);
    }
    action V6AddrEn {
        size_t l;
        assign_strbuf(cps->v6_addr, &l, sizeof cps->v6_addr, cps->st, p);
        lc_string_inplace(cps->v6_addr, l);
    }
    action ExpireTimeEn {
        char buf[64];
        ptrdiff_t blen = p - cps->st;
        if (blen < 0 || blen >= (int)sizeof buf) {
            cps->parse_error = true;
            fbreak;
        }
        memcpy(buf, cps->st, (size_t)blen); buf[blen] = 0;
        if (sscanf(buf, "%" SCNi64, &cps->expire_time) != 1) {
            cps->parse_error = true;
            fbreak;
        }
    }

    action V4EntryEn {
        struct in6_addr ipa;
        if (!ipaddr_from_string(&ipa, cps->v4_addr)) {
            log_line("Bad IP address at line %zu: %s\n", linenum, cps->v4_addr);
            cps->parse_error = true;
            fbreak;
        }
        dynlease4_add(cps->ifindex, &ipa, cps->macaddr, cps->expire_time);
    }
    action V6EntryEn {
        struct in6_addr ipa;
        if (!ipaddr_from_string(&ipa, cps->v6_addr)) {
            log_line("Bad IP address at line %zu: %s\n", linenum, cps->v6_addr);
            cps->parse_error = true;
            fbreak;
        }
        dynlease6_add(cps->ifindex, &ipa, cps->duid, cps->duid_len, cps->iaid, cps->expire_time);
    }

    interface = alnum+ >St %InterfaceEn;
    duid = (xdigit+ | (xdigit{2} ('-' xdigit{2})*)+) >St %DuidEn;
    iaid = digit+ >St %IaidEn;
    macaddr = ((xdigit{2} ':'){5} xdigit{2}) >St %MacAddrEn;
    v4_addr = (digit{1,3} | '.')+ >St %V4AddrEn;
    v6_addr = (xdigit{1,4} | ':')+ >St %V6AddrEn;
    expire_time = digit+ >St %ExpireTimeEn;

    v4_entry = space* 'v4' space+ interface space+ v4_addr space+ macaddr space+ expire_time space*;
    v6_entry = space* 'v6' space+ interface space+ v6_addr space+ duid space+ iaid space+ expire_time space*;

    main := v4_entry %V4EntryEn | v6_entry %V6EntryEn;
}%%

%% write data;

static int do_parse_dynlease_line(struct dynlease_parse_state *cps, const char *p, size_t plen,
                                  const size_t linenum)
{
    const char *pe = p + plen;
    const char *eof = pe;

    %% write init;
    %% write exec;

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

