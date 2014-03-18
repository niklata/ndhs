#ifndef NJK_NDHS_CLIENTID_HPP_
#define NJK_NDHS_CLIENTID_HPP_

#include <string.h>
#include <stdexcept>
#include "macstr.hpp"

class ClientID
{
public:
    explicit ClientID(const std::string &s) : value_(s), hadopt_(true) {
        for (size_t i = 0; i < sizeof mac_; ++i)
            mac_[i] = 0;
    }
    ClientID(const std::string &clientid,
             const std::string &chaddr) {
        hadopt_ = clientid.size() > 0;
        if (chaddr.size() != 6)
            throw std::logic_error("ClientID chaddr.size() != 6");
        memcpy(mac_, chaddr.data(), sizeof mac_);
        if (clientid.size() < 2) {
            hadopt_ = false;
            value_ = std::string(1, 1);
            value_.append(chaddr);
            return;
        }
        value_ = clientid;
    }
    ClientID(const ClientID &o) : value_(o.value_), hadopt_(o.hadopt_) {
        memcpy(mac_, o.mac_, sizeof mac_);
    }
    ClientID(ClientID &&o) : value_(o.value_), hadopt_(o.hadopt_) {
        memcpy(mac_, o.mac_, sizeof mac_);
    }
    ClientID& operator=(ClientID o) {
        std::swap(o.value_, value_);
        memcpy(mac_, o.mac_, sizeof mac_);
        hadopt_ = o.hadopt_;
        return *this;
    }
    ClientID& operator=(ClientID &&o) {
        std::swap(o.value_, value_);
        memcpy(mac_, o.mac_, sizeof mac_);
        hadopt_ = o.hadopt_;
        return *this;
    }
    bool ismac() const { return value_[0] == 1 && value_.size() == 6; }
    bool had_option() const { return hadopt_; }
    const std::string &raw() const { return value_; }
    std::string pretty() const {
        if (ismac())
            return macraw_to_str(value_.substr(1));
        return value_.substr(1);
    }
    std::string mac() const {
        return std::string((char *)&mac_, 6);
    }
private:
    std::string value_;
    char mac_[6];
    bool hadopt_;
};

#endif /* NJK_NDHS_CLIENTID_HPP_ */

