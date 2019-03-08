
import asyncio

import yarl

from aioclient.response import ClientResponse
from aioclient.request import ClientRequest
from aiohttp.client_reqrep import (
    ClientResponse as BaseClientResponse,
    ClientRequest as BaseClientRequest)


_URL = yarl.URL('http://bar.foo')


def test_response_comparison():
    loop = asyncio.get_event_loop()
    import time
    start = time.time()

    for i in range(10000):
        ClientResponse(
            'get',
            _URL,
            request_info=None,
            writer=None,
            continue100=None,
            timer=None,
            traces=[],
            loop=loop,
            session=None)

    print("aioclient completed: %s" % (time.time() - start))

    start = time.time()
    for i in range(10000):
        BaseClientResponse(
            'get',
            _URL,
            request_info=None,
            writer=None,
            continue100=None,
            timer=None,
            traces=[],
            loop=loop,
            session=None)

    print("aiohttp.client completed: %s" % (time.time() - start))


def test_request_comparison():
    loop = asyncio.get_event_loop()
    import time
    start = time.time()

    for i in range(10000):
        ClientRequest("GET", _URL)

    print("aioclient completed: %s" % (time.time() - start))

    for i in range(10000):
        BaseClientRequest("GET", _URL)
    print("aiohttp.client completed: %s" % (time.time() - start))
