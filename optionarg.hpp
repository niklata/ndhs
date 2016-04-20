#ifndef NKXA_OPTIONARG_HPP_
#define NKXA_OPTIONARG_HPP_

#include "optionparser.hpp"

struct Arg : public option::Arg
{
    static void print_error(const char *head, const option::Option &opt, const char *tail)
    {
        fmt::fprintf(stderr, "%s%.*s%s", head, opt.namelen, opt.name, tail);
    }
    static option::ArgStatus Unknown(const option::Option &opt, bool msg)
    {
        if (msg) print_error("Unknown option '", opt, "'\n");
        return option::ARG_ILLEGAL;
    }
    static option::ArgStatus String(const option::Option &opt, bool msg)
    {
        if (opt.arg && opt.arg[0])
            return option::ARG_OK;
        if (msg) print_error("Option '", opt, "' requires an argument\n");
        return option::ARG_ILLEGAL;
    }
    static option::ArgStatus Integer(const option::Option &opt, bool msg)
    {
        char *endptr{nullptr};
        if (opt.arg && strtol(opt.arg, &endptr, 10)){}
        if (endptr != opt.arg && !*endptr)
            return option::ARG_OK;
        if (msg) print_error("Option '", opt, "' requires an integer argument\n");
        return option::ARG_ILLEGAL;
    }
};

#endif

