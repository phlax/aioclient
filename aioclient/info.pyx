# distutils: define_macros=CYTHON_TRACE_NOGIL=1
# cython: linetrace=True
# cython: binding=True
# cython: language_level=3
# -*- coding: utf-8 -*-

from yarl import URL


cdef class RequestInfo(object):

    # @real_url.default
    @property
    def real_url_default(self) -> URL:
        return self.url
