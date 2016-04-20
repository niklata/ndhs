#ifndef NDHS_DHCPLUA_HPP_
#define NDHS_DHCPLUA_HPP_

#include <string>
#include "clientid.hpp"

extern "C" {
#include "dhcp.h"
#include "lua/lua.h"
#include "lua/lauxlib.h"
#include "lua/lualib.h"
}

class DhcpLua
{
public:
    DhcpLua(const std::string &cfg);
    DhcpLua(const DhcpLua &) = delete;
    DhcpLua &operator=(const DhcpLua &) = delete;
    ~DhcpLua();
    bool reply_discover(dhcpmsg &dm, const std::string &lip,
                        const std::string &rip, const ClientID &clientid);
    bool reply_request(dhcpmsg &dm, const std::string &lip,
                       const std::string &rip, const ClientID &clientid);
    bool reply_inform(dhcpmsg &dm, const std::string &lip,
                      const std::string &rip, const ClientID &clientid);
private:
    lua_State *L_;
};

#endif

