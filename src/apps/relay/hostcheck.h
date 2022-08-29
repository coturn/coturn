// TODO SLG - do we want a copyright block here?

#ifndef WILDCARD_HOSTCHECK_H
#define WILDCARD_HOSTCHECK_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Match a hostname against a wildcard pattern.
 * ie. foo.host.com matches *.host.com
 *
 * This implementation follows the rules from RFC6125, section 6.4.3.
 * http://tools.ietf.org/html/rfc6125#section-6.4.3
 * 
 * Note: the RFC does not cover two interesting cases.
 * 1) Are multiple * characters allowed?  ie: *f*.example.com . We assume no.
 * 2) Does b*z.example.com match bz.example.com? We assume no.
 * 
 * Returns 0 for no match, and 1 for a match
 */
int wildcard_hostcheck(const char *hostname, const char *pattern);

void run_wildcard_hostcheck_unit_tests(void);

#ifdef __cplusplus
}
#endif

#endif /* WILDCARD_HOSTCHECK_H */
