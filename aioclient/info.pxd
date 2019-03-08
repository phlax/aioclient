# distutils: define_macros=CYTHON_TRACE_NOGIL=1
# cython: linetrace=True
# cython: binding=True
# cython: language_level=3
# -*- coding: utf-8 -*-


cdef class RequestInfo(object):
    cdef public url
    cdef public unicode method
    cdef public headers
    cdef public real_url
