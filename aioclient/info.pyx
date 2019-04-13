# cython: language_level=3
# -*- coding: utf-8 -*-

from yarl import URL

import multidict


cdef class RequestInfo(object):

    def __cinit__(
            self, url: URL,
            str method,
            headers: multidict.CIMultiDictProxy,
            real_url: URL = None):
        self.url = url
        self.method = method
        self.headers = headers
        self.real_url = real_url or url


class Py__RequestInfo(RequestInfo):
    pass
