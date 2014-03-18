#include <sys/time.h>
#include <boost/lexical_cast.hpp>

extern "C" {
#include "log.h"
}
#include "leasestore.hpp"

LeaseStore::LeaseStore(const std::string &path)
{
    int r = sqlite3_open(path.c_str(), &db_);
    if (r) {
        log_error("failed to open lease database '%s'", path.c_str());
        sqlite3_close(db_);
        exit(1);
    }
}

LeaseStore::~LeaseStore()
{
    sqlite3_close(db_);
}

bool LeaseStore::execSql(const std::string &sql, const std::string &parentfn)
{
    bool ret = false;
    sqlite3_stmt *ss;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), sql.size(), &ss, NULL);
    if (rc != SQLITE_OK) {
        log_warning("LeaseStore::execSql() prepare failed!  rc == %d", rc);
        return ret;
    }
    for (;;) {
        rc = sqlite3_step(ss);
        if (rc == SQLITE_DONE || rc == SQLITE_OK) {
            ret = true;
            break;
        }
        if (rc == SQLITE_ROW)
            continue;
        log_warning("%s - step error %d", parentfn.c_str(), rc);
        break;
    }
    sqlite3_finalize(ss);
    return ret;
}

bool LeaseStore::addLease(const std::string &ifip, const ClientID &clientid,
                          const std::string &ip, uint64_t expirets)
{
    std::string sql("CREATE TABLE IF NOT EXISTS '");
    sql.append(ifip);
    sql.append("' (clientid TEXT PRIMARY KEY, ip TEXT, expirets INTEGER)");
    execSql(sql, "LeaseStore::addLease");
    sql.clear();
    sql.append("INSERT OR REPLACE INTO '");
    sql.append(ifip);
    sql.append("' VALUES ('");
    sql.append(clientid.raw());
    sql.append("','");
    sql.append(ip);
    sql.append("',");
    sql.append(boost::lexical_cast<std::string>(expirets));
    sql.append(")");
    return execSql(sql, "LeaseStore::addLease");
}

bool LeaseStore::delLease(const std::string &ifip, const ClientID &clientid)
{
    std::string sql("DELETE FROM '");
    sql.append(ifip);
    sql.append("' WHERE clientid LIKE '");
    sql.append(clientid.raw());
    sql.append("'");
    return execSql(sql, "LeaseStore::delLease");
}

uint64_t LeaseStore::nowTs() const
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

const std::string LeaseStore::getLease(const std::string &ifip,
                                       const ClientID &clientid)
{
    sqlite3_stmt *ss;
    std::string ret("");
    std::string sql("SELECT FROM '");
    sql.append(ifip);
    sql.append("' WHERE clientid LIKE '");
    sql.append(clientid.raw());
    sql.append("'");

    int rc = sqlite3_prepare(db_, sql.c_str(), sql.size(), &ss, NULL);
    if (rc != SQLITE_OK)
        return ret;
    for (;;) {
        rc = sqlite3_step(ss);
        if (rc == SQLITE_DONE || rc == SQLITE_OK)
            break;
        if (rc == SQLITE_ROW) {
            uint64_t ets = sqlite3_column_int64(ss, 2);
            if (ets >= nowTs()) {
                ret = std::string(reinterpret_cast<const char *>(
                                  sqlite3_column_text(ss, 1)));
                break;
            } else
                delLease(ifip, clientid);
        }
        log_warning("LeaseStore::getLease - step error %d", rc);
        break;
    }
    sqlite3_finalize(ss);
    return ret;
}

bool LeaseStore::ipTaken(const std::string &ifip, const ClientID &clientid,
                         const std::string &ip)
{
    sqlite3_stmt *ss;
    bool ret = false;
    std::string sql("SELECT FROM '");
    sql.append(ifip);
    sql.append("' WHERE ip LIKE '");
    sql.append(ip);
    sql.append("'");

    int rc = sqlite3_prepare(db_, sql.c_str(), sql.size(), &ss, NULL);
    if (rc != SQLITE_OK)
        return ret;
    for (;;) {
        rc = sqlite3_step(ss);
        if (rc == SQLITE_DONE || rc == SQLITE_OK)
            break;
        if (rc == SQLITE_ROW) {
            uint64_t ets = sqlite3_column_int64(ss, 2);
            if (ets >= nowTs()) {
                std::string id(reinterpret_cast<const char *>
                               (sqlite3_column_text(ss, 0)));
                if (id != clientid.raw())
                    ret = true;
                break;
            } else {
                delLease(ifip, clientid);
                break;
            }
        }
        log_warning("LeaseStore::ipTaken - step error %d", rc);
        break;
    }
    sqlite3_finalize(ss);
    return ret;
}

void LeaseStore::clean(void)
{

}

