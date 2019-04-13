# cython: language_level=3
# -*- coding: utf-8 -*-


cdef class RequestInfo(object):
    cdef public url
    cdef public unicode method
    cdef public headers
    cdef public real_url
