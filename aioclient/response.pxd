# distutils: define_macros=CYTHON_TRACE_NOGIL=1
# cython: linetrace=True
# cython: binding=True
# cython: language_level=3
# -*- coding: utf-8 -*-

from cpython cimport bool

from .info cimport RequestInfo


cdef class HeadersMixin:
    cdef public unicode _content_type
    cdef public dict _content_dict
    cdef public _stored_content_type
    cdef public _headers
    cpdef tuple _parse_content_type(self, unicode raw)


cdef class ClientResponse(HeadersMixin):
    cdef public version
    cdef public unicode method
    cdef public int status
    cdef public unicode reason
    cdef public bool _continue
    cdef public bool _closed
    cdef public bool _released
    cdef public tuple _history
    cdef public dict _cache
    cdef public list _traces
    cdef public tuple _raw_headers
    cdef public RequestInfo _request_info
    cdef public cookies
    cdef public content
    cdef public _protocol
    cdef public _connection
    cdef public _real_url
    cdef public _url
    cdef public _body
    cdef public _writer
    cdef public _timer
    cdef public _loop
    cdef public _session
    cdef public _source_traceback

    cpdef unicode get_encoding(self)
    cpdef _notify_content(self)
    cpdef close(self)
    cpdef release(self)
    cpdef _cleanup_writer(self)
    cpdef _response_eof(self)
