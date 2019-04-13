# cython: language_level=3
# -*- coding: utf-8 -*-

from cpython cimport bool

cimport cython

from .info cimport RequestInfo


cdef class ClientResponse:
    cdef public unicode method
    cdef public unicode reason
    cdef public int status
    cdef public dict _cache
    cdef public bool _closed
    cdef public dict _content_dict
    cdef public unicode _content_type
    cdef public tuple _history
    cdef public tuple _raw_headers
    cdef public RequestInfo _request_info
    cdef public bool _released
    cdef public list _traces
    cdef public cookies
    cdef public content
    cdef public version
    cdef public _body
    cdef public _connection
    cdef public _continue
    cdef public _headers
    cdef public _loop
    cdef public _protocol
    cdef public _real_url
    cdef public _session
    cdef public _source_traceback
    cdef public _stored_content_type
    cdef public _timer
    cdef public _url
    cdef public _writer

    @cython.locals(
        mimetype=unicode,
        encoding=unicode)
    cpdef unicode get_encoding(self)
    cpdef tuple _parse_content_type(self, unicode raw)
    cpdef close(self)
    cpdef raise_for_status(self)
    cpdef release(self)
    cpdef _cleanup_writer(self)
    cpdef _notify_content(self)
    cpdef _response_eof(self)
