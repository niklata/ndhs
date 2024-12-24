// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <assert.h>
#include "dhcp_state.h"
#include <nlsocket.h>
#include <net/if.h>
#include "nk/log.h"

extern struct NLSocket nl_socket;

struct str_slist
{
    struct str_slist *next;
    char str[];
};

static void str_slist_append(struct str_slist **head, const char *s, size_t slen)
{
    struct str_slist **e = head;
    while (*e) e = &(*e)->next;
    assert(!*e);
    *e = malloc(sizeof(struct str_slist) + slen + 1);
    if (!*e) abort();
    (*e)->next = NULL;
    *(char *)mempcpy(&((*e)->str), s, slen) = 0;
}

static void str_slist_destroy(struct str_slist **head)
{
    struct str_slist *e = *head;
    while (e) {
        struct str_slist *n = e->next;
        free(e);
        e = n;
    }
    *head = NULL;
}

struct interface_data
{
    int ifindex;
    struct dhcpv4_entry *s4addrs; // static assigned v4 leases
    struct dhcpv6_entry *s6addrs; // static assigned v6 leases
    struct addrlist dnsaddrs;
    struct addrlist ntpaddrs;
    struct in6_addr subnet;
    struct in6_addr broadcast;
    struct in6_addr gateway_v4;
    struct in6_addr dynamic_range_lo;
    struct in6_addr dynamic_range_hi;
    struct str_slist *p_dns_search;
    char *d4_dns_search_blob;
    char *ra6_dns_search_blob;
    size_t d4_dns_search_blob_size;
    size_t ra6_dns_search_blob_size;
    uint32_t dynamic_lifetime;
    uint8_t preference;
    bool use_dhcpv4:1;
    bool use_dhcpv6:1;
    bool use_dynamic_v4:1;
    bool use_dynamic_v6:1;
};

static struct interface_data *interface_state[MAX_NL_INTERFACES];

// Performs DNS label wire encoding cf RFC1035 3.1
// Returns negative values on error, positive values are the number
// of bytes added to the out buffer.
// return of -2 means input was invalid
// return of -1 means out buffer ran out of space
#define MAX_DNS_LABELS 256
static int dns_label(char *out, size_t outlen, const char *ds)
{
    size_t locx[MAX_DNS_LABELS * 2];
    size_t locn = 0;
    size_t dslen = strlen(ds);
    const char *out_st = out;

    if (dslen <= 0)
        return 0;

    // First we build up a list of label start/end offsets.
    size_t s = 0, idx = 0;
    bool in_label = false;
    for (size_t j = 0; j < dslen; ++j) {
        char i = ds[j];
        if (i == '.') {
            if (in_label) {
                if (locn >= MAX_DNS_LABELS) return -2; // label too long
                locx[2 * locn    ] = s;
                locx[2 * locn + 1] = idx;
                ++locn;
                in_label = false;
            } else {
                return -2; // malformed input
            }
        } else {
            if (!in_label) {
                s = idx;
                in_label = true;
            }
        }
        ++idx;
    }
    // We don't demand a trailing dot.
    if (in_label) {
        if (locn >= MAX_DNS_LABELS) return -2;
        locx[2 * locn    ] = s;
        locx[2 * locn + 1] = idx;
        ++locn;
        in_label = false;
    }

    // Now we just need to attach the label length octet followed
    // by the label contents.
    for (size_t i = 0, imax = locn; i < imax; ++i) {
        size_t st = locx[2 * i];
        size_t en = locx[2 * i + 1];
        size_t len = en >= st ? en - st : 0;
        if (len > 63) return -2; // label too long
        if (outlen < 1 + en - st) return -1; // out of space
        *out++ = len; --outlen;
        memcpy(out, &ds[st], en - st); outlen -= en - st;
    }
    // Terminating zero length label.
    if (outlen < 1) return -1; // out of space
    *out++ = 0; --outlen;

    // false means domain name is too long
    return out - out_st <= 255 ? out - out_st : -2;
}

static void create_d4_dns_search_blob(char **out, size_t *outlen,
                                      struct str_slist *dns_search)
{
    size_t blen = 0;
    char buf[256]; // must be >= 255 bytes

    for (struct str_slist *e = dns_search; e; e = e->next) {
        int r = dns_label(buf + blen, sizeof buf - blen, e->str);
        if (r < 0) {
            if (r == -1) {
                log_line("too many names in dns_search\n");
                break;
            } else {
                log_line("malformed input to dns_search\n");
                continue;
            }
        }
        blen += (size_t)r;
    }
    assert(blen <= 255);
    if (*out) { free(*out); *out = NULL; }
    *out = malloc(blen);
    if (!*out) abort();
    *outlen = blen;
    memcpy(*out, buf, blen);
}

static void create_ra6_dns_search_blob(char **out, size_t *outlen,
                                       struct str_slist *dns_search)
{
    size_t blen = 0;
    char buf[2048]; // must be >= 8*256 bytes

    for (struct str_slist *e = dns_search; e; e = e->next) {
        int r = dns_label(buf + blen, sizeof buf - blen, e->str);
        if (r < 0) {
            if (r == -1) {
                log_line("too many names in dns_search\n");
                break;
            } else {
                log_line("malformed input to dns_search\n");
                continue;
            }
        }
        blen += (size_t)r;
    }
    assert(blen <= 8 * 254);
    if (*out) { free(*out); *out = NULL; }
    *out = malloc(blen);
    if (!*out) abort();
    *outlen = blen;
    memcpy(*out, buf, blen);
}

void create_blobs(void)
{
    for (size_t i = 0; i < MAX_NL_INTERFACES; ++i) {
        struct interface_data *p = interface_state[i];
        if (p) {
            create_d4_dns_search_blob(&p->d4_dns_search_blob, &p->d4_dns_search_blob_size, p->p_dns_search);
            create_ra6_dns_search_blob(&p->ra6_dns_search_blob, &p->ra6_dns_search_blob_size, p->p_dns_search);
            str_slist_destroy(&p->p_dns_search);
        }
    }
}

static struct interface_data *lookup_interface_by_name(const char *interface)
{
    if (!strlen(interface)) return NULL;

    int ifindex = NLSocket_get_ifindex(&nl_socket, interface);
    if (ifindex == -1) return NULL;
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return NULL;
    return interface_state[ifindex];
}

static struct interface_data *lookup_or_create_interface(const char *interface)
{
    if (!strlen(interface)) return NULL;
    struct interface_data *is = lookup_interface_by_name(interface);
    if (!is) {
        int ifindex = NLSocket_get_ifindex(&nl_socket, interface);
        if (ifindex == -1) return NULL;
        assert(!interface_state[ifindex]);
        interface_state[ifindex] = calloc(1, sizeof(struct interface_data));
        if (!interface_state[ifindex]) abort();
        interface_state[ifindex]->ifindex = ifindex;
        is = interface_state[ifindex];
    }
    return is;
}

bool emplace_bind4(size_t linenum, const char *interface)
{
    struct interface_data *is = lookup_or_create_interface(interface);
    if (!is) {
        log_line("interface specified at line %zu does not exist\n", linenum);
        return false;
    }
    is->use_dhcpv4 = true;
    return true;
}

bool emplace_bind6(size_t linenum, const char *interface)
{
    struct interface_data *is = lookup_or_create_interface(interface);
    if (!is) {
        log_line("interface specified at line %zu does not exist\n", linenum);
        return false;
    }
    is->use_dhcpv6 = true;
    return true;
}

int emplace_interface(size_t linenum, const char *interface, uint8_t preference)
{
    struct interface_data *is = lookup_interface_by_name(interface);
    if (is) {
        is->preference = preference;
        return is->ifindex;
    }
    log_line("interface specified at line %zu is not bound\n", linenum);
    return -1;
}

bool emplace_dhcp6_state(size_t linenum, int ifindex,
                         const char *duid, size_t duid_len,
                         uint32_t iaid, const struct in6_addr *v6_addr, uint32_t default_lifetime)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (is) {
        struct dhcpv6_entry *t = malloc(sizeof(struct dhcpv6_entry) + duid_len);
        if (!t) abort();
        memcpy(t->duid, duid, duid_len);
        t->address = *v6_addr;
        t->duid_len = duid_len;
        t->lifetime = default_lifetime;
        t->iaid = iaid;
        t->next = is->s6addrs;
        is->s6addrs = t;
        return true;
    }
    log_line("%s: No interface specified at line %zu\n", __func__, linenum);
    return false;
}

bool emplace_dhcp4_state(size_t linenum, int ifindex, const uint8_t *macaddr,
                         const struct in6_addr *v4_addr, uint32_t default_lifetime)
{
    if (!ipaddr_is_v4(v4_addr)) {
        log_line("Bad IPv4 address at line %zu\n", linenum);
        return false;
    }
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (is) {
        struct dhcpv4_entry *t = malloc(sizeof(struct dhcpv4_entry));
        if (!t) abort();
        memcpy(t->macaddr, macaddr, sizeof t->macaddr);
        t->address = *v4_addr;
        t->lifetime = default_lifetime;
        t->next = is->s4addrs;
        is->s4addrs = t;
        return true;
    }
    log_line("%s: No interface specified at line %zu\n", __func__, linenum);
    return false;
}

bool emplace_dns_servers(size_t linenum, int ifindex, struct in6_addr *addrs, size_t naddrs)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (is) {
        free(is->dnsaddrs.addrs);
        is->dnsaddrs.n = naddrs;
        is->dnsaddrs.addrs = addrs;
        return true;
    }
    free(addrs);
    log_line("%s: No interface specified at line %zu\n", __func__, linenum);
    return false;
}

bool emplace_ntp_servers(size_t linenum, int ifindex, struct in6_addr *addrs, size_t naddrs)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (is) {
        free(is->ntpaddrs.addrs);
        is->ntpaddrs.n = naddrs;
        is->ntpaddrs.addrs = addrs;
        return true;
    }
    free(addrs);
    log_line("%s: No interface specified at line %zu\n", __func__, linenum);
    return false;
}

bool emplace_subnet(int ifindex, const struct in6_addr *addr)
{
    if (!ipaddr_is_v4(addr)) {
        log_line("%s: Bad IP address for interface #%d\n", __func__, ifindex);
        return false;
    }
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (is) {
        is->subnet = *addr;
        return true;
    }
    return false;
}

bool emplace_gateway_v4(size_t linenum, int ifindex, const struct in6_addr *addr)
{
    if (!ipaddr_is_v4(addr)) {
        log_line("%s: Bad IP address for interface #%d\n", __func__, ifindex);
        return false;
    }
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (is) {
        is->gateway_v4 = *addr;
        return true;
    }
    log_line("%s: No interface specified at line %zu\n", __func__, linenum);
    return false;
}

bool emplace_broadcast(int ifindex, const struct in6_addr *addr)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (is) {
        is->broadcast = *addr;
        return true;
    }
    return false;
}

bool emplace_dynamic_range(size_t linenum, int ifindex,
                           const struct in6_addr *lo_addr, const struct in6_addr *hi_addr,
                           uint32_t dynamic_lifetime)
{
    if (!ipaddr_is_v4(lo_addr) || !ipaddr_is_v4(hi_addr)) {
        log_line("Bad IPv4 address at line %zu\n", linenum);
        return false;
    }
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (is) {
        bool inorder = memcmp(lo_addr, hi_addr, sizeof *lo_addr) <= 0;
        is->dynamic_range_lo = inorder? *lo_addr : *hi_addr;
        is->dynamic_range_hi = inorder? *hi_addr : *lo_addr;
        is->dynamic_lifetime = dynamic_lifetime;
        is->use_dynamic_v4 = true;
        return true;
    }
    log_line("%s: No interface specified at line %zu\n", __func__, linenum);
    return false;
}

bool emplace_dynamic_v6(size_t linenum, int ifindex)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (is) {
        is->use_dynamic_v6 = true;
        return true;
    }
    log_line("%s: No interface specified at line %zu\n", __func__, linenum);
    return false;
}

bool emplace_dns_search(size_t linenum, int ifindex, const char *label, size_t label_len)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (is) {
        str_slist_append(&is->p_dns_search, label, label_len);
        return true;
    }
    log_line("%s: No interface specified at line %zu\n", __func__, linenum);
    return false;
}

const struct dhcpv6_entry *query_dhcp6_state(int ifindex,
                                             const char *duid, size_t duid_len,
                                             uint32_t iaid)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return NULL;
    struct interface_data *is = interface_state[ifindex];
    if (!is) return NULL;
    for (struct dhcpv6_entry *p = is->s6addrs; p; p = p->next) {
        if (p->duid_len == duid_len && p->iaid == iaid
            && !memcmp(p->duid, duid, duid_len))
            return p;
    }
    return NULL;
}

const struct dhcpv4_entry *query_dhcp4_state(int ifindex, const uint8_t *hwaddr)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return NULL;
    struct interface_data *is = interface_state[ifindex];
    if (!is) return NULL;
    for (struct dhcpv4_entry *p = is->s4addrs; p; p = p->next) {
        if (!memcmp(p->macaddr, hwaddr, sizeof p->macaddr)) return p;
    }
    return NULL;
}

struct addrlist query_dns_servers(int ifindex)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) {
    err: return (struct addrlist){ .n = 0, .addrs = NULL };
    }
    struct interface_data *is = interface_state[ifindex];
    if (!is) goto err;
    return is->dnsaddrs;
}

struct addrlist query_ntp_servers(int ifindex)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) {
    err: return (struct addrlist){ .n = 0, .addrs = NULL };
    }
    struct interface_data *is = interface_state[ifindex];
    if (!is) goto err;
    return is->ntpaddrs;
}

struct blob query_dns4_search_blob(int ifindex)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) {
    err: return (struct blob){ .n = 0, .s = NULL };
    }
    struct interface_data *is = interface_state[ifindex];
    if (!is) goto err;
    return (struct blob){ .n = is->d4_dns_search_blob_size, .s = is->d4_dns_search_blob };
}

struct blob query_dns6_search_blob(int ifindex)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) {
    err: return (struct blob){ .n = 0, .s = NULL };
    }
    struct interface_data *is = interface_state[ifindex];
    if (!is) goto err;
    return (struct blob){ .n = is->ra6_dns_search_blob_size, .s = is->ra6_dns_search_blob };
}

const struct in6_addr *query_gateway_v4(int ifindex)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return NULL;
    struct interface_data *is = interface_state[ifindex];
    if (!is) return NULL;
    return &is->gateway_v4;
}

const struct in6_addr *query_subnet(int ifindex)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return NULL;
    struct interface_data *is = interface_state[ifindex];
    if (!is) return NULL;
    return &is->subnet;
}

const struct in6_addr *query_broadcast(int ifindex)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return NULL;
    struct interface_data *is = interface_state[ifindex];
    if (!is) return NULL;
    return &is->broadcast;
}

bool query_dynamic_range(int ifindex, struct in6_addr *lo, struct in6_addr *hi)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (!is) return false;
    *lo = is->dynamic_range_lo;
    *hi = is->dynamic_range_hi;
    return true;
}

bool query_use_dynamic_v4(int ifindex, uint32_t *dynamic_lifetime)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (!is) return false;
    *dynamic_lifetime = is->dynamic_lifetime;
    return is->use_dynamic_v4;
}

bool query_use_dynamic_v6(int ifindex, uint32_t *dynamic_lifetime)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (!is) return false;
    *dynamic_lifetime = is->dynamic_lifetime;
    return is->use_dynamic_v6;
}

bool query_unused_addr_v6(int ifindex, const struct in6_addr *addr)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return false;
    struct interface_data *is = interface_state[ifindex];
    if (!is) return true;
    for (struct dhcpv6_entry *p = is->s6addrs; p; p = p->next) {
        if (!memcmp(&p->address, addr, sizeof *addr)) return false;
    }
    return true;
}

size_t bound_interfaces_count(void)
{
    size_t ret = 0;
    for (size_t i = 0; i < MAX_NL_INTERFACES; ++i) {
        if (interface_state[i]) ++ret;
    }
    return ret;
}

void bound_interfaces_foreach(void (*fn)(const struct netif_info *, bool, bool, uint8_t, void *), void *userptr)
{
    for (size_t i = 0; i < MAX_NL_INTERFACES; ++i) {
        struct interface_data *p = interface_state[i];
        if (p) {
            struct netif_info *ifinfo = NLSocket_get_ifinfo(&nl_socket, p->ifindex);
            if (!ifinfo) continue;
            fn(ifinfo, p->use_dhcpv4, p->use_dhcpv6, p->preference, userptr);
        }
    }
}
