#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <format.hpp>

#include "dhcplua.hpp"
#include "leasestore.hpp"

extern "C" {
#include "options.h"
}

extern LeaseStore *gLeaseStore;

static int add_option_iplist(lua_State *L, uint8_t code)
{
    if (lua_gettop(L) != 2 || !lua_islightuserdata(L, 1))
        return 0;
    struct dhcpmsg *dm = static_cast<struct dhcpmsg *>(lua_touserdata(L, 1));
    size_t iplen;
    uint32_t ip;
    if (lua_isstring(L, 2)) {
        const char *ipstr = lua_tolstring(L, 2, &iplen);
        if (inet_pton(AF_INET, ipstr, &ip) != 1)
            return 0;
        add_u32_option(dm, code, ip);
    } else if (lua_istable(L, 2)) {
        union {
            uint32_t ip32;
            uint8_t ip8[4];
        };
        std::string iplist;
        lua_pushnil(L);
        while (lua_next(L, 2) != 0) {
            if (!lua_isstring(L, -1)) {
                lua_pop(L, 1);
                continue;
            }
            const char *ipstr = lua_tolstring(L, -1, &iplen);
            if (inet_pton(AF_INET, ipstr, &ip32) != 1) {
                lua_pop(L, 1);
                continue;
            }
            iplist.push_back(ip8[0]);
            iplist.push_back(ip8[1]);
            iplist.push_back(ip8[2]);
            iplist.push_back(ip8[3]);
            lua_pop(L, 1);
        }
        if (iplist.size())
            add_option_string(dm, code, iplist.c_str(), iplist.size());
    }
    return 0;
}

extern "C" {

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
    struct dhcpmsg *dm = static_cast<struct dhcpmsg *>(lua_touserdata(L, 1));
    size_t ipstrlen;
    const char *ipstr = lua_tolstring(L, 2, &ipstrlen);
    uint32_t ip;
    int r = inet_pton(AF_INET, ipstr, &ip);
    if (r != 1)
        return 0;
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
    return add_option_iplist(L, DCODE_ROUTER);
}

int dlua_set_dns(lua_State *L)
{
    return add_option_iplist(L, DCODE_DNS);
}

int dlua_set_ntp(lua_State *L)
{
    return add_option_iplist(L, DCODE_NTPSVR);
}

// Returns bool, args(ifip:str, ip:str, clientid:str|nil)
int dlua_is_ip_leased(lua_State *L)
{
    if (lua_gettop(L) != 3 ||
        !lua_isstring(L, 1) || !lua_isstring(L, 2) || !lua_isstring(L, 3))
        return 0;

    size_t cidlen;
    const char *cid = lua_tolstring(L, 3, &cidlen);
    if (cidlen < 1)
        return 0;
    ClientID clientid(std::string(cid, cidlen));

    size_t ifiplen;
    const char *ifipstr = lua_tolstring(L, 1, &ifiplen);
    std::string ifip(ifipstr, ifiplen);

    size_t iplen;
    const char *ipstr = lua_tolstring(L, 2, &iplen);
    std::string ip(ipstr, iplen);

    lua_pushboolean(L, gLeaseStore->ipTaken(ifip, clientid, ip) ? 1 : 0);
    return 1;
}

// Returns str or nil, args(ifip:str, clientid:str)
int dlua_get_current_lease(lua_State *L)
{
    if (lua_gettop(L) != 2 || !lua_isstring(L, 1) || !lua_isstring(L, 2))
        return 0;

    size_t cidlen;
    const char *cid = lua_tolstring(L, 2, &cidlen);
    if (cidlen < 1)
        return 0;
    ClientID clientid(std::string(cid, cidlen));

    size_t ifiplen;
    const char *ifipstr = lua_tolstring(L, 1, &ifiplen);
    std::string ifip(ifipstr, ifiplen);

    std::string leaseip = gLeaseStore->getLease(ifip, clientid);
    if (leaseip.size())
        lua_pushlstring(L, leaseip.c_str(), leaseip.size());
    else
        lua_pushnil(L);
    return 1;
}

}

DhcpLua::DhcpLua(const std::string &cfg)
{
    L_ = luaL_newstate();
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
    lua_pushcfunction(L_, dlua_is_ip_leased);
    lua_setglobal(L_, "dhcp_is_ip_leased");
    lua_pushcfunction(L_, dlua_get_current_lease);
    lua_setglobal(L_, "dhcp_get_current_lease");
    int r = luaL_loadfile(L_, cfg.c_str());
    if (r) {
        std::string errmsg("Unknown error in config file: {}\n");
        switch (r) {
        case LUA_ERRFILE:
            errmsg = "Invalid configuration file: {}\n"; break;
        case LUA_ERRSYNTAX:
            errmsg = "Syntax error in configuration file: {}\n"; break;
        case LUA_ERRMEM:
            errmsg = "Memory error loading configuration file: {}\n"; break;
        }
        fmt::print(stderr, errmsg, cfg);
        std::exit(EXIT_FAILURE);
    }
    if (lua_pcall(L_, 0, 0, 0) != 0) {
        fmt::print(stderr, "failed to run configuration file: {}\n",
                   lua_tostring(L_, -1));
        std::exit(EXIT_FAILURE);
    }
}

DhcpLua::~DhcpLua()
{
    lua_close(L_);
}

bool DhcpLua::reply_discover(dhcpmsg &dm, const std::string &lip,
                             const std::string &rip, const ClientID &cid)
{
    auto macstr = cid.mac();
    auto cidstr = cid.value();
    lua_getglobal(L_, "dhcp_reply_discover");
    lua_pushlightuserdata(L_, &dm);
    lua_pushlstring(L_, lip.c_str(), lip.size());
    lua_pushlstring(L_, rip.c_str(), rip.size());
    lua_pushlstring(L_, macstr.c_str(), macstr.size());
    lua_pushlstring(L_, cidstr.c_str(), cidstr.size());
    if (lua_pcall(L_, 5, 1, 0) != 0)
        fmt::print(stderr, "failed to call Lua function dhcp_reply_discover(): {}\n",
                   lua_tostring(L_, -1));
    return lua_toboolean(L_, 1);
}

bool DhcpLua::reply_request(dhcpmsg &dm, const std::string &lip,
                            const std::string &rip, const ClientID &cid)
{
    auto macstr = cid.mac();
    auto cidstr = cid.value();
    lua_getglobal(L_, "dhcp_reply_request");
    lua_pushlightuserdata(L_, &dm);
    lua_pushlstring(L_, lip.c_str(), lip.size());
    lua_pushlstring(L_, rip.c_str(), rip.size());
    lua_pushlstring(L_, macstr.c_str(), macstr.size());
    lua_pushlstring(L_, cidstr.c_str(), cidstr.size());
    if (lua_pcall(L_, 5, 1, 0) != 0)
        fmt::print(stderr, "failed to call Lua function dhcp_reply_request(): {}\n",
                    lua_tostring(L_, -1));
    return lua_toboolean(L_, 1);
}

bool DhcpLua::reply_inform(dhcpmsg &dm, const std::string &lip,
                           const std::string &rip, const ClientID &cid)
{
    auto macstr = cid.mac();
    auto cidstr = cid.value();
    lua_getglobal(L_, "dhcp_reply_inform");
    lua_pushlightuserdata(L_, &dm);
    lua_pushlstring(L_, lip.c_str(), lip.size());
    lua_pushlstring(L_, rip.c_str(), rip.size());
    lua_pushlstring(L_, macstr.c_str(), macstr.size());
    lua_pushlstring(L_, cidstr.c_str(), cidstr.size());
    if (lua_pcall(L_, 5, 1, 0) != 0)
        fmt::print(stderr, "failed to call Lua function dhcp_reply_inform(): {}\n",
                    lua_tostring(L_, -1));
    return lua_toboolean(L_, 1);
}

