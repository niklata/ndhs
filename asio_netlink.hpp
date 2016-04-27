#ifndef NK_ASIO_NETLINK_HPP_
#define NK_ASIO_NETLINK_HPP_

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

template <typename Proto>
class nl_endpoint
{
public:
    typedef Proto protocol_type;
    typedef asio::detail::socket_addr_type data_type;

    nl_endpoint(int group, int pid = getpid()) {
        sockaddr_.nl_family = PF_NETLINK;
        sockaddr_.nl_groups = group;
        sockaddr_.nl_pid = pid;
    }

    nl_endpoint() : nl_endpoint(0) {}

    nl_endpoint(const nl_endpoint &other) {
        sockaddr_ = other.sockaddr_;
    }

    nl_endpoint &operator=(const nl_endpoint &other) {
        sockaddr_ = other.sockaddr_;
        return *this;
    }

    protocol_type protocol() const { return protocol_type(); }
    data_type *data() {
        return reinterpret_cast<struct sockaddr *>(&sockaddr_);
    }
    const data_type *data() const {
        return reinterpret_cast<const struct sockaddr *>(&sockaddr_);
    }
    void resize(std::size_t size) {}
    std::size_t size() const { return sizeof sockaddr_; }
    std::size_t capacity() const { return sizeof sockaddr_; }

    friend bool operator==(const nl_endpoint<Proto> &self,
                           const nl_endpoint<Proto> &other) {
        return self.sockaddr_ == other.sockaddr_;
    }
    friend bool operator!=(const nl_endpoint<Proto> &self,
                           const nl_endpoint<Proto> &other) {
        return self.sockaddr_ != other.sockaddr_;
    }
    friend bool operator<(const nl_endpoint<Proto> &self,
                          const nl_endpoint<Proto> &other) {
        return self.sockaddr_ < other.sockaddr_;
    }
    friend bool operator>(const nl_endpoint<Proto> &self,
                          const nl_endpoint<Proto> &other) {
        return self.sockaddr_ > other.sockaddr_;
    }
    friend bool operator>=(const nl_endpoint<Proto> &self,
                           const nl_endpoint<Proto> &other) {
        return !(self < other);
    }
    friend bool operator<=(const nl_endpoint<Proto> &self,
                           const nl_endpoint<Proto> &other) {
        return !(other < self);
    }
private:
    sockaddr_nl sockaddr_;
};

class nl_protocol
{
public:
    nl_protocol() : proto_(0) {}
    nl_protocol(int proto) : proto_(proto) {}
    int type() const { return SOCK_RAW; }
    int protocol() const { return proto_; }
    int family() const { return PF_NETLINK; }
    typedef nl_endpoint<nl_protocol> endpoint;
    typedef asio::basic_raw_socket<nl_protocol> socket;
private:
    int proto_;
};

#endif
