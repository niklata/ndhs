#include <sys/time.h>
#include <boost/lexical_cast.hpp>

extern "C" {
#include "log.h"
}
#include "leasestore.hpp"
#include "macstr.hpp"

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
    log_line("sql: '%s'", sql.c_str());
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

bool LeaseStore::addLease(const std::string &ifip, const std::string &chaddr,
                          const std::string &ip, uint64_t expirets)
{
    std::string sql("CREATE TABLE IF NOT EXISTS '");
    sql.append(ifip);
    sql.append("' (mac TEXT PRIMARY KEY, ip TEXT, expirets INTEGER)");
    execSql(sql, "LeaseStore::addLease");
    sql.clear();
    sql.append("INSERT OR REPLACE INTO '");
    sql.append(ifip);
    sql.append("' VALUES ('");
    sql.append(macraw_to_str(chaddr));
    sql.append("','");
    sql.append(ip);
    sql.append("',");
    sql.append(boost::lexical_cast<std::string>(expirets));
    sql.append(")");
    return execSql(sql, "LeaseStore::addLease");
}

bool LeaseStore::delLease(const std::string &ifip, const std::string &chaddr)
{
    std::string sql("DELETE FROM '");
    sql.append(ifip);
    sql.append("' WHERE mac LIKE '");
    sql.append(macraw_to_str(chaddr));
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
                                       const std::string &chaddr)
{
    sqlite3_stmt *ss;
    std::string ret("");
    std::string sql("SELECT FROM '");
    sql.append(ifip);
    sql.append("' WHERE mac LIKE '");
    sql.append(macraw_to_str(chaddr));
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
            if (ets > nowTs())
                ret = std::string(reinterpret_cast<const char *>(
                                  sqlite3_column_text(ss, 1)));
            break;
        }
        log_warning("LeaseStore::getLease - step error %d", rc);
        break;
    }
    sqlite3_finalize(ss);
    return ret;
}

void LeaseStore::clean(void)
{

}

