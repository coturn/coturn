// TODO SLG - do we want a copyright block here?

#define __USE_GNU
#include "hostcheck.h"
#include <string.h>
#include <assert.h>

static void initial_scan(const char* str, size_t* len, size_t* dot_count, size_t* first_label_end_pos, size_t* first_label_star_count, size_t* first_star_pos) {
    size_t cur_pos = 0;
    *dot_count = 0;
    *first_label_end_pos = -1;
    *first_label_star_count = 0;
    *first_star_pos = -1;
    while(str[cur_pos] != 0) {
        // Record info on dots in string
        if(str[cur_pos] == '.') {
            (*dot_count)++;
            if(*first_label_end_pos == (size_t)-1) {
                *first_label_end_pos = cur_pos;
            }
        }
        
        // Record info on stars in string
        if(str[cur_pos] == '*') {
            if(*first_label_end_pos == (size_t)-1) {  // we are still in the first label
                (*first_label_star_count)++;
            }
            if(*first_star_pos == (size_t)-1) {
                *first_star_pos = cur_pos;
            }
        }
        cur_pos++;
    }
    *len = cur_pos;

    // Trim any trailing .'s from length
    if(str[*len-1] == '.') {
        (*len)--;
        (*dot_count)--;
    }

    // Make compiler stop spewing warnings about unused params that are used as outputs
    (void)len;
    (void)dot_count;
    (void)first_label_end_pos;
    (void)first_label_star_count;
    (void)first_star_pos;
}

// 0 - not equal, 1 equal
static int compare_no_case(const char* str1, size_t str1_len, const char* str2, size_t str2_len) {
    if(str1_len != str2_len) return 0;
    return strncasecmp(str1,str2, str1_len) == 0;
}

// 0 - no match, 1 match
int wildcard_hostcheck(const char *hostname, const char *pattern) {
    if(!pattern || !*pattern || !hostname || !*hostname) return 0;

    // Walk pattern string recording the positions of important items
    size_t pattern_len;
    size_t pattern_dot_count;
    size_t pattern_first_label_end_pos;
    size_t pattern_first_label_star_count;
    size_t pattern_first_star_pos;
    initial_scan(pattern, &pattern_len, &pattern_dot_count, &pattern_first_label_end_pos, &pattern_first_label_star_count, &pattern_first_star_pos);

    // If there is more than one star in the pattern first label - we fail the match
    if(pattern_first_label_star_count > 1) return 0;
    
    // Walk hostname string recording the positions of important items
    size_t hostname_len;
    size_t hostname_dot_count;
    size_t hostname_first_label_end_pos;
    size_t hostname_first_label_star_count;
    size_t hostname_first_star_pos;
    initial_scan(hostname, &hostname_len, &hostname_dot_count, &hostname_first_label_end_pos, &hostname_first_label_star_count, &hostname_first_star_pos);

    // If there is no star in the pattern, then we just do a case insentive compare on both strings
    if(pattern_first_label_star_count == 0) {
        return compare_no_case(hostname, hostname_len, pattern, pattern_len);
    }

    // Pattern has 1 star, ensure it is in first label, if not fail
    if(pattern_first_star_pos > pattern_first_label_end_pos) return 0;

    // At this point we have identified that the pattern has 1 star in it, and we need to wildcard matching

    // If the hostname contains a star anywhere - we fail the match
    if(hostname_first_star_pos != (size_t)-1) return 0;

    // If the number of dots less than two or the two string contain a different number of dots - we fail the match
    if(pattern_dot_count < 2 || pattern_dot_count != hostname_dot_count) return 0;

    // If the pattern starts with "xn--" - we fail the match
    // Note: using strncasecmp directly to avoid unnecesary length check in compare_no_case
    if(strncasecmp("xn--", pattern, 4) == 0) return 0;

    // If the hostname is an IP address, then fail the match.  
    // We use the fact that a real hostname must begin with an alpha character, so if the hostname begins with 
    // a numberic we assume it is an ip v4 address, we throw in a check for num dots being 3 for good measure.
    // Note: IPv6 addresses use ':' separators instead of '.', so they will also fail the min 2 dots test if 
    //       they are attempted to be used with wildcards.
    if(hostname_dot_count == 3 && hostname[0] >= '0' && hostname[0] <= '9') return 0;

    // Check if the strings right of the first label are equal
    if(compare_no_case(&hostname[hostname_first_label_end_pos], hostname_len - hostname_first_label_end_pos, &pattern[pattern_first_label_end_pos], pattern_len - pattern_first_label_end_pos) == 0) return 0;

    // If hostname first label length is less than pattern first label length, then no match - star must match to at least one character
    if(hostname_first_label_end_pos < pattern_first_label_end_pos) return 0;

    // Check if string left of "star in pattern first label" is not equal to start of hostname first label
    // Note: using strncasecmp directly to avoid unnecesary length check in compare_no_case
    if(strncasecmp(hostname, pattern, pattern_first_star_pos) != 0) return 0;

    // Check if string right of "star in pattern first label" is not equal to end of hostname first label
    // Note: using strncasecmp directly to avoid unnecesary length check in compare_no_case
    size_t right_of_star_len = pattern_first_label_end_pos - pattern_first_star_pos -1;
    if(strncasecmp(&hostname[hostname_first_label_end_pos - right_of_star_len], &pattern[pattern_first_star_pos+1], right_of_star_len) != 0) return 0;

    // We have a match!
    return 1;
}

void run_wildcard_hostcheck_unit_tests(void) {
    // Success tests no wildcards in pattern
    assert(wildcard_hostcheck("foo.example.com", "foo.example.COM"));
    assert(wildcard_hostcheck("hostname", "hostname"));
    assert(wildcard_hostcheck("foo.example.com.", "foo.EXAMPLE.com"));  // trailing dot ignored
    assert(wildcard_hostcheck("FOO.example.com", "foo.Example.com."));  // trailing dot ignored
    assert(wildcard_hostcheck("xn--MXarccr1ahws", "xn--mxarccr1ahws"));  // 'xn--' in pattern
    assert(wildcard_hostcheck("192.168.0.1", "192.168.0.1")); // ipv4 address
    assert(wildcard_hostcheck("fe80::9c38:259f:1db:e3c7", "fe80::9c38:259f:1db:e3c7")); // ipv6 address

    // Success tests with wildcard in pattern
    assert(wildcard_hostcheck("foo.example.com", "*.example.com."));  // matches whole label
    assert(wildcard_hostcheck("foo.example.com", "F*O.example.com."));  // matches one char
    assert(wildcard_hostcheck("PREBLAHPOST.example.COM", "pre*post.example.com.")); // matches middle of first label
    assert(wildcard_hostcheck("preblahpost.example.com", "pre*.example.com."));     // matches end of first label
    assert(wildcard_hostcheck("preblahpost.example.com", "*POST.EXAMPLE.COM"));     // matches start of first label

    // Failure tests no wildcards in pattern
    assert(!wildcard_hostcheck("foo.example.com", "bar.example.COM"));
    assert(!wildcard_hostcheck("f*o.example.com", "bar.example.COM")); // wildcard in hostname
    assert(!wildcard_hostcheck("XN--FOO", "xn--mxarccr1ahws"));  // 'xn--' in pattern
    assert(!wildcard_hostcheck("foo2.foo.example.com", "foo.example.COM"));  // unequal number of dots
    assert(!wildcard_hostcheck("foo.example.com", "foo2.foo.example.COM"));  // unequal number of dots

    // Failure tests with wildcards in pattern
    assert(!wildcard_hostcheck("hostname", "*"));  // not enough dots
    assert(!wildcard_hostcheck("hostname.com", "*.com"));  // not enough dots
    assert(!wildcard_hostcheck("foo.example.com", "foo*.example.COM"));  // star must match at least 1 char
    assert(!wildcard_hostcheck("foo.example.com", "fo*o.example.COM"));  // star must match at least 1 char
    assert(!wildcard_hostcheck("foo.example.com", "*foo*.example.COM")); // star must match at least 1 char
    assert(!wildcard_hostcheck("xn--mxarccr1ahws", "xn--*ahws"));  // 'xn--' in pattern
    assert(!wildcard_hostcheck("foo.example.com", "*"));  // unequal number of dots
    assert(!wildcard_hostcheck("example.com.", "*.example.com"));  // unequal number of dots
    assert(!wildcard_hostcheck("foo2.foo.example.com", "foo*.example.COM"));  // unequal number of dots
    assert(!wildcard_hostcheck("foo2.example.com", "foo*.foo2.example.COM"));  // unequal number of dots
    assert(!wildcard_hostcheck("foo.example.com", "foo.ex*.COM"));  // star no in first label
    assert(!wildcard_hostcheck("foo1bar2.example.com", "foo*bar*.example.COM"));  // multiple stars in first label
    assert(!wildcard_hostcheck("fooXXbar.example.com", "foo*bar.ex*ple.COM"));  // multiple stars in pattern
    assert(!wildcard_hostcheck("foobar.example.com", "foobar.ex*ple.C*M"));  // multiple stars in pattern
    assert(!wildcard_hostcheck("foobar.example.com", "foo*.bar.COM"));  // no match right of first label
    assert(!wildcard_hostcheck("foblahbar.example.com", "foo*bar.example.COM"));  // no match left of star in first label
    assert(!wildcard_hostcheck("blahbar.example.com", "foo*bar.example.COM"));  // no match left of star in first label
    assert(!wildcard_hostcheck("fooblahba.example.com", "foo*bar.example.COM"));  // no match right of star in first label
    assert(!wildcard_hostcheck("fooblah.example.com", "foo*bar.example.COM"));  // no match right of star in first label
    assert(!wildcard_hostcheck("fe80::9c38:259f:1db:e3c7", "*::9c38:259f:1db:e3c7"));  // ipv6 address with wildcard
    assert(!wildcard_hostcheck("192.168.0.1", "*.168.0.1"));  // ipv4 address with wildcard
}