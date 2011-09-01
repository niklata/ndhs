#ifndef NDHS_DHCPLUA_HPP_
#define NDHS_DHCPLUA_HPP_

#include <string>

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

class DhcpLua
{
public:
    DhcpLua(const std::string &cfg);
    ~DhcpLua();
    void reply_discover(struct dhcpmsg *dm, const std::string &lip,
                       const std::string &rip, const std::string &chaddr);
    void reply_request(struct dhcpmsg *dm, const std::string &lip,
                       const std::string &rip, const std::string &chaddr);
private:
    lua_State *L_;
};

#endif

