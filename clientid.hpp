#ifndef NJK_NDHS_CLIENTID_HPP_
#define NJK_NDHS_CLIENTID_HPP_

#include <string.h>
#include <stdexcept>
#include "macstr.hpp"

class ClientID
{
public:
    explicit ClientID(const std::string &s)
            : value_(s), mac_(6, 0), hadopt_(true) {}
    ClientID(const std::string &clientid, const std::string &chaddr)
            : value_(clientid), mac_(chaddr), hadopt_(clientid.size()) {
        if (chaddr.size() != 6)
            throw std::logic_error("ClientID chaddr.size() != 6");
        if (clientid.size() < 2) {
            hadopt_ = false;
            value_ = std::string(1, 1);
            value_.append(chaddr);
        }
    }
    ClientID(const ClientID &o)
            : value_(o.value_), mac_(o.mac_), hadopt_(o.hadopt_) {}
    ClientID(ClientID &&o)
            : value_(o.value_), mac_(o.mac_), hadopt_(o.hadopt_) {}
    ClientID& operator=(ClientID o) {
        std::swap(o.value_, value_);
        std::swap(o.mac_, mac_);
        hadopt_ = o.hadopt_;
        return *this;
    }
    ClientID& operator=(ClientID &&o) {
        std::swap(o.value_, value_);
        std::swap(o.mac_, mac_);
        hadopt_ = o.hadopt_;
        return *this;
    }
    bool had_option() const { return hadopt_; }
    const std::string &value() const { return value_; }
    std::string mac() const { return macraw_to_str(mac_); }
private:
    std::string value_;
    std::string mac_;
    bool hadopt_;
};

#endif /* NJK_NDHS_CLIENTID_HPP_ */

