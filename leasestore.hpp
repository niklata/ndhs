#ifndef NDHS_LEASESTORE_H_
#define NDHS_LEASESTORE_H_

#include <string>
#include <stdint.h>

extern "C" {
#include <sqlite3.h>
}

class LeaseStore {
public:
    LeaseStore(const std::string &path);
    ~LeaseStore();

    bool addLease(const std::string &ifip, const std::string &chaddr,
                  const std::string &ip, uint64_t expirets);
    bool delLease(const std::string &ifip, const std::string &chaddr);
    const std::string getLease(const std::string &ifip,
                               const std::string &chaddr);
    void clean(void);
private:
    bool execSql(const std::string &sql, const std::string &parentfn);
    uint64_t nowTs() const;
    sqlite3 *db_;
};

#endif /* NDHS_LEASESTORE_H_ */
