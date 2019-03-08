# distutils: define_macros=CYTHON_TRACE_NOGIL=1
# cython: linetrace=True
# cython: binding=True
# cython: language_level=3

from cpython cimport bool

from aioclient.response cimport ClientResponse


cdef class ClientRequest(object):
    cdef public unicode method
    cdef public unicode chunked
    cdef public unicode compress
    cdef public list _traces
    cdef public ClientResponse response
    cdef public auth

    cdef public _writer
    cdef public _session
    cdef public original_url
    cdef public url
    cdef public loop
    cdef public length
    cdef public version
    cdef public headers
    cdef public skip_auto_headers
    cdef public proxy
    cdef public proxy_auth
    cdef public proxy_headers
    cdef public body
    cdef public _response_class
    cdef public _timer
    cdef public _ssl
    cdef public _source_traceback

    cpdef bool is_ssl(self)
    cpdef bool keep_alive(self)
    cpdef update_host(self, url)
    cpdef update_version(self, version)
    cpdef update_headers(self, headers)
    cpdef update_auto_headers(self, skip_auto_headers)
    cpdef update_cookies(self, cookies)
    cpdef update_content_encoding(self, data)
    cpdef update_transfer_encoding(self)
    cpdef update_auth(self, auth)
    cpdef update_expect_continue(self, bool expect=*)
    cpdef update_proxy(self, proxy, proxy_auth, proxy_header)
    cpdef terminate(self)
    cpdef _update_body_from_data(self, body)
    cpdef update_body_from_data(self, data)
    cpdef update_path(self, params)
