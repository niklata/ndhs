#ifndef NDHS_PARSEHELP_H_
#define NDHS_PARSEHELP_H_

static inline void lc_string_inplace(char *s, size_t len)
{
    for (size_t i = 0; i < len; ++i) s[i] = tolower(s[i]);
}

static void assign_strbuf(char *dest, size_t *destlen, size_t maxlen, const char *start, const char *end)
{
    ptrdiff_t d = end - start;
    size_t l = (size_t)d;
    if (d < 0 || l >= maxlen) abort();
    *(char *)mempcpy(dest, start, l) = 0;
    if (destlen) *destlen = l;
}

#endif
