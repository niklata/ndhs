#ifndef NK_MACSTR_H_
#define NK_MACSTR_H_

#include <string>

std::string macraw_to_str(const std::string &macraw);
bool is_macstr(const std::string &ms);
std::string macstr_to_raw(const std::string &macstr);


#endif /* NK_MACSTR_H_ */
