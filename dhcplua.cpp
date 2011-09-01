#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "dhcplua.hpp"

static std::string macraw_to_str(const std::string &macraw)
{
    char buf[32];
    snprintf(buf, sizeof buf, "%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx",
             macraw[0], macraw[1], macraw[2], macraw[3], macraw[4], macraw[5]);
    return std::string(buf);
}

static bool is_macstr(const std::string &ms)
{
    if (ms.size() == 17 && ms[2] == ':' && ms[5] == ':' && ms[8] == ':' &&
        ms[11] == ':' && ms[14] == ':' &&
        isxdigit(ms[0]) && isxdigit(ms[1]) && isxdigit(ms[3]) &&
        isxdigit(ms[4]) && isxdigit(ms[6]) && isxdigit(ms[7]) &&
        isxdigit(ms[9]) && isxdigit(ms[10]) && isxdigit(ms[12]) &&
        isxdigit(ms[13]) && isxdigit(ms[15]) && isxdigit(ms[16])
        )
        return true;
    return false;
}

static std::string macstr_to_raw(const std::string &macstr)
{
    char buf[7];
    if (!is_macstr(macstr))
        return std::string("\0\0\0\0\0\0\0", 6);
    buf[0] = strtol(macstr.c_str(), NULL, 16);
    buf[1] = strtol(macstr.c_str()+3, NULL, 16);
    buf[2] = strtol(macstr.c_str()+6, NULL, 16);
    buf[3] = strtol(macstr.c_str()+9, NULL, 16);
    buf[4] = strtol(macstr.c_str()+12, NULL, 16);
    buf[5] = strtol(macstr.c_str()+15, NULL, 16);
    buf[6] = '\0';
    return std::string(buf, 6);
}

extern "C" {
#include "log.h"
#include "options.h"

int dlua_set_lease_time(lua_State *L)
{
    if (lua_gettop(L) != 2 || !lua_islightuserdata(L, 1) ||
        !lua_isnumber(L, 2))
        return 0;
    struct dhcpmsg *dm = static_cast<struct dhcpmsg *>(lua_touserdata(L, 1));
    uint32_t ltime = lua_tointeger(L, 2);
    add_u32_option(dm, DCODE_LEASET, htonl(ltime));
    return 0;
}

int dlua_set_ip(lua_State *L)
{
    if (lua_gettop(L) != 2 || !lua_islightuserdata(L, 1) ||
        !lua_isstring(L, 2))
        return 0;
    printf("called dlua_set_ip\n");
    struct dhcpmsg *dm = static_cast<struct dhcpmsg *>(lua_touserdata(L, 1));
    size_t ipstrlen;
    const char *ipstr = lua_tolstring(L, 2, &ipstrlen);
    uint32_t ip;
    int r = inet_pton(AF_INET, ipstr, &ip);
    printf("called dlua_set_ip::inet_pton\n");
    if (r != 1)
        return 0;
    printf("yiaddr == %s\n", ipstr);
    dm->yiaddr = ip;
    return 0;
}

int dlua_set_domain_name(lua_State *L)
{
    if (lua_gettop(L) != 2 || !lua_islightuserdata(L, 1) ||
        !lua_isstring(L, 2))
        return 0;
    struct dhcpmsg *dm = static_cast<struct dhcpmsg *>(lua_touserdata(L, 1));
    size_t domlen;
    const char *dom = lua_tolstring(L, 2, &domlen);
    add_option_domain_name(dm, const_cast<char *>(dom), domlen);
    return 0;
}

int dlua_set_subnet(lua_State *L)
{
    if (lua_gettop(L) != 2 || !lua_islightuserdata(L, 1) ||
        !lua_isstring(L, 2))
        return 0;
    struct dhcpmsg *dm = static_cast<struct dhcpmsg *>(lua_touserdata(L, 1));
    size_t subnetlen;
    const char *subnetstr = lua_tolstring(L, 2, &subnetlen);
    uint32_t subnet;
    int r = inet_pton(AF_INET, subnetstr, &subnet);
    if (r != 1)
        return 0;
    add_option_subnet_mask(dm, subnet);
    return 0;
}

int dlua_set_broadcast(lua_State *L)
{
    if (lua_gettop(L) != 2 || !lua_islightuserdata(L, 1) ||
        !lua_isstring(L, 2))
        return 0;
    struct dhcpmsg *dm = static_cast<struct dhcpmsg *>(lua_touserdata(L, 1));
    size_t broadcastlen;
    const char *broadcaststr = lua_tolstring(L, 2, &broadcastlen);
    uint32_t broadcast;
    int r = inet_pton(AF_INET, broadcaststr, &broadcast);
    if (r != 1)
        return 0;
    add_option_broadcast(dm, broadcast);
    return 0;
}

int dlua_set_routers(lua_State *L)
{
    if (lua_gettop(L) != 2 || !lua_islightuserdata(L, 1) ||
        !lua_isstring(L, 2))
        return 0;
    struct dhcpmsg *dm = static_cast<struct dhcpmsg *>(lua_touserdata(L, 1));
    size_t routerlen;
    const char *routerstr = lua_tolstring(L, 2, &routerlen);
    uint32_t router;
    int r = inet_pton(AF_INET, routerstr, &router);
    if (r != 1)
        return 0;
    // XXX: support multiple routers
    add_option_router(dm, router);
    return 0;
}

int dlua_set_dns(lua_State *L)
{
    if (lua_gettop(L) != 2 || !lua_islightuserdata(L, 1) ||
        !lua_isstring(L, 2))
        return 0;
    struct dhcpmsg *dm = static_cast<struct dhcpmsg *>(lua_touserdata(L, 1));
    size_t dnslen;
    const char *dnsstr = lua_tolstring(L, 2, &dnslen);
    uint32_t dns;
    int r = inet_pton(AF_INET, dnsstr, &dns);
    if (r != 1)
        return 0;
    // XXX: support multiple dns
    add_option_dns(dm, dns);
    return 0;
}

int dlua_set_ntp(lua_State *L)
{
    if (lua_gettop(L) != 2 || !lua_islightuserdata(L, 1) ||
        !lua_isstring(L, 2))
        return 0;
    struct dhcpmsg *dm = static_cast<struct dhcpmsg *>(lua_touserdata(L, 1));
    size_t ntplen;
    const char *ntpstr = lua_tolstring(L, 2, &ntplen);
    uint32_t ntp;
    int r = inet_pton(AF_INET, ntpstr, &ntp);
    if (r != 1)
        return 0;
    // XXX: support multiple ntp
    add_option_ntp(dm, ntp);
    return 0;
}

int dlua_assign_range(lua_State *L)
{
    // XXX: dm, rlo<str>, rhi<str>
    // XXX: complete

    return 0;
}

}

DhcpLua::DhcpLua(const std::string &cfg)
{
    L_ = lua_open();
    luaopen_base(L_);
    luaopen_string(L_);
    lua_pushcfunction(L_, dlua_set_lease_time);
    lua_setglobal(L_, "dhcpmsg_set_lease_time");
    lua_pushcfunction(L_, dlua_set_ip);
    lua_setglobal(L_, "dhcpmsg_set_ip");
    lua_pushcfunction(L_, dlua_set_domain_name);
    lua_setglobal(L_, "dhcpmsg_set_domain_name");
    lua_pushcfunction(L_, dlua_set_subnet);
    lua_setglobal(L_, "dhcpmsg_set_subnet");
    lua_pushcfunction(L_, dlua_set_broadcast);
    lua_setglobal(L_, "dhcpmsg_set_broadcast");
    lua_pushcfunction(L_, dlua_set_routers);
    lua_setglobal(L_, "dhcpmsg_set_routers");
    lua_pushcfunction(L_, dlua_set_dns);
    lua_setglobal(L_, "dhcpmsg_set_dns");
    lua_pushcfunction(L_, dlua_set_ntp);
    lua_setglobal(L_, "dhcpmsg_set_ntp");
    lua_pushcfunction(L_, dlua_assign_range);
    lua_setglobal(L_, "dhcpmsg_assign_range");
    int r = luaL_loadfile(L_, cfg.c_str());
    if (r) {
        std::string errmsg("Unknown error in config file: %s");
        switch (r) {
        case LUA_ERRFILE:
            errmsg = "Invalid configuration file: %s"; break;
        case LUA_ERRSYNTAX:
            errmsg = "Syntax error in configuration file: %s"; break;
        case LUA_ERRMEM:
            errmsg = "Memory error loading configuration file: %s"; break;
        }
        log_error(errmsg.c_str(), cfg.c_str());
        exit(1);
    }
    if (lua_pcall(L_, 0, 0, 0) != 0) {
        log_error("failed to run configuration file: %s", lua_tostring(L_, -1));
        exit(1);
    }
}

DhcpLua::~DhcpLua()
{
    lua_close(L_);
}

void DhcpLua::reply_discover(struct dhcpmsg *dm, const std::string &lip,
                             const std::string &rip, const std::string &chaddr)
{
    auto macstr = macraw_to_str(chaddr);
    lua_getglobal(L_, "dhcp_reply_discover");
    lua_pushlightuserdata(L_, dm);
    lua_pushlstring(L_, lip.c_str(), lip.size());
    lua_pushlstring(L_, rip.c_str(), rip.size());
    lua_pushlstring(L_, macstr.c_str(), macstr.size());
    if (lua_pcall(L_, 4, 0, 0) != 0)
        log_warning("failed to call Lua function dhcp_reply_discover(): %s",
                    lua_tostring(L_, -1));
}

void DhcpLua::reply_request(struct dhcpmsg *dm, const std::string &lip,
                            const std::string &rip, const std::string &chaddr)
{
    auto macstr = macraw_to_str(chaddr);
    lua_getglobal(L_, "dhcp_reply_request");
    lua_pushlightuserdata(L_, dm);
    lua_pushlstring(L_, lip.c_str(), lip.size());
    lua_pushlstring(L_, rip.c_str(), rip.size());
    lua_pushlstring(L_, macstr.c_str(), macstr.size());
    if (lua_pcall(L_, 4, 0, 0) != 0)
        log_warning("failed to call Lua function dhcp_reply_request(): %s",
                    lua_tostring(L_, -1));
}

