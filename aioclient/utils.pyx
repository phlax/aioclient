"""Various helper functions"""

import functools
import re


cdef _ipv4_pattern = (r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                      r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
cdef _ipv6_pattern = (
    r'^(?:(?:(?:[A-F0-9]{1,4}:){6}|(?=(?:[A-F0-9]{0,4}:){0,6}'
    r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)(([0-9A-F]{1,4}:){0,5}|:)'
    r'((:[0-9A-F]{1,4}){1,5}:|:)|::(?:[A-F0-9]{1,4}:){5})'
    r'(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|(?:[A-F0-9]{1,4}:){7}'
    r'[A-F0-9]{1,4}|(?=(?:[A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}$)'
    r'(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4}){1,7}|:)|(?:[A-F0-9]{1,4}:){7}'
    r':|:(:[A-F0-9]{1,4}){7})$')
cdef _ipv4_regex = re.compile(_ipv4_pattern)
cdef _ipv6_regex = re.compile(_ipv6_pattern, flags=re.IGNORECASE)
cdef _ipv4_regexb = re.compile(_ipv4_pattern.encode('ascii'))
cdef _ipv6_regexb = re.compile(_ipv6_pattern.encode('ascii'), flags=re.IGNORECASE)


cpdef bool _is_ip_address(
        regex,
        regexb,
        host):
    if host is None:
        return False
    if isinstance(host, str):
        return bool(regex.match(host))
    elif isinstance(host, (bytes, bytearray, memoryview)):
        return bool(regexb.match(host))
    else:
        raise TypeError("{} [{}] is not a str or bytes"
                        .format(host, type(host)))


cpdef bool is_ipv4_address(host):
    return _is_ip_address(_ipv4_regex, _ipv4_regexb, host)
cpdef bool is_ipv6_address(host):
    return _is_ip_address(_ipv6_regex, _ipv6_regexb, host)
