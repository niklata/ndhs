#include <string>
#include <stdio.h>

std::string macraw_to_str(const std::string &macraw)
{
    char buf[32];
    snprintf(buf, sizeof buf, "%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx",
             macraw[0], macraw[1], macraw[2], macraw[3], macraw[4], macraw[5]);
    return std::string(buf);
}

bool is_macstr(const std::string &ms)
{
    if (ms.size() == 17 && ms[2] == ':' && ms[5] == ':' && ms[8] == ':' &&
        ms[11] == ':' && ms[14] == ':' &&
        isxdigit(ms[0]) && isxdigit(ms[1]) && isxdigit(ms[3]) &&
        isxdigit(ms[4]) && isxdigit(ms[6]) && isxdigit(ms[7]) &&
        isxdigit(ms[9]) && isxdigit(ms[10]) && isxdigit(ms[12]) &&
        isxdigit(ms[13]) && isxdigit(ms[15]) && isxdigit(ms[16])
        )
        return true;
    return false;
}

std::string macstr_to_raw(const std::string &macstr)
{
    char buf[7];
    if (!is_macstr(macstr))
        return std::string("\0\0\0\0\0\0\0", 6);
    buf[0] = strtol(macstr.c_str(), NULL, 16);
    buf[1] = strtol(macstr.c_str()+3, NULL, 16);
    buf[2] = strtol(macstr.c_str()+6, NULL, 16);
    buf[3] = strtol(macstr.c_str()+9, NULL, 16);
    buf[4] = strtol(macstr.c_str()+12, NULL, 16);
    buf[5] = strtol(macstr.c_str()+15, NULL, 16);
    buf[6] = '\0';
    return std::string(buf, 6);
}
