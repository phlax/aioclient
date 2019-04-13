# cython: language_level=3
# -*- coding: utf-8 -*-

from cpython cimport bool, unicode

cimport cython

from .info cimport RequestInfo
from .response cimport ClientResponse


cdef class ClientRequest(object):
    cdef public unicode method
    cdef public bool chunked
    cdef public RequestInfo request_info
    cdef public ClientResponse response
    cdef public list _traces
    cdef public auth
    cdef public compress
    cdef public response_class

    cdef public body
    cdef public headers
    cdef public length
    cdef public loop
    cdef public original_url
    cdef public proxy
    cdef public proxy_auth
    cdef public proxy_headers
    cdef public skip_auto_headers
    cdef public url
    cdef public version
    cdef public _continue
    cdef public _session
    cdef public _source_traceback
    cdef public _ssl
    cdef public _timer
    cdef public _writer

    cpdef bool is_ssl(self)
    cpdef bool keep_alive(self)
    cpdef terminate(self)
    cpdef update_auth(self, auth)
    cpdef update_auto_headers(self, skip_auto_headers)
    cpdef update_body_from_data(self, body)
    cpdef update_expect_continue(self, bool expect=*)
    @cython.locals(netloc=unicode, _is_header_dict=bool)
    cpdef update_headers(self, headers)
    cpdef update_host(self, url)
    @cython.locals(bad_compress=bool)
    cpdef update_content_encoding(self, data)
    cpdef update_cookies(self, cookies)
    cpdef update_proxy(self, proxy, proxy_auth, proxy_header)
    @cython.locals(bad_transfer_encoding=bool)
    cpdef update_transfer_encoding(self)
    @cython.locals(v=list, l=unicode)
    cpdef update_version(self, version)
