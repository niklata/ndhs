#ifndef NDHS_LEASESTORE_H_
#define NDHS_LEASESTORE_H_

#include <string>
#include <stdint.h>
#include <boost/utility.hpp>
#include "clientid.hpp"

extern "C" {
#include <sqlite3.h>
}

class LeaseStore : boost::noncopyable
{
public:
    LeaseStore(const std::string &path);
    ~LeaseStore();

    bool addLease(const std::string &ifip, const ClientID &clientid,
                  const std::string &ip, uint64_t expirets);
    bool delLease(const std::string &ifip, const ClientID &clientid);
    const std::string getLease(const std::string &ifip,
                               const ClientID &clientid);
    bool ipTaken(const std::string &ifip, const ClientID &clientid,
                 const std::string &ip);
    void clean(void);
private:
    bool runSql(sqlite3_stmt *ss, const char *parentfn);
    uint64_t nowTs() const;
    sqlite3 *db_;
};

#endif /* NDHS_LEASESTORE_H_ */
