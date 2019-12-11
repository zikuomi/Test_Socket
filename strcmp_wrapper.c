#ifndef __STRCMP_WRAPPER__
#define __STRCMP_WRAPPER__

#include <string.h>

int __strcmp__(const char *s1, const char *s2)
{
  return strcmp(s1, s2);
}

int __strncmp__(const char *s1, const char *s2, size_t n)
{
  return strncmp(s1, s2, n);
}

#define strcmp(s1, s2) __strcmp__(s1, s2)
#define strncmp(s1, s2, n) __strncmp__(s1, s2, n)

#endif//__STRCMP_WRAPPER__
