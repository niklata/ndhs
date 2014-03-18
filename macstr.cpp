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

std::string macstr_to_raw(std::string macstr)
{
    char buf[6];
    if (!is_macstr(macstr))
        return macstr;
    for (size_t i = 0; i < 6; ++i)
        buf[i] = strtol(macstr.c_str() + 3*i, NULL, 16);
    return std::string(buf, 6);
}
