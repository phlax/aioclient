# distutils: define_macros=CYTHON_TRACE_NOGIL=1
# cython: linetrace=True
# cython: binding=True
# cython: language_level=3
# -*- coding: utf-8 -*-

import io
import json
import types
import asyncio
import codecs
import io
import re
import sys
import traceback
import warnings
from hashlib import md5, sha1, sha256
from http.cookies import CookieError, Morsel, SimpleCookie
from typing import (
    Any,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    Union,
    cast)

from yarl import URL

from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy

import attr

from aiocouchdb.multipart import MultipartWriter
from aiohttp import abc, hdrs, helpers, http, client_reqrep, payload, typedefs
from aiohttp.client_exceptions import ClientOSError, InvalidURL
from aiohttp.formdata import FormData


try:
    import ssl
    from ssl import SSLContext
except ImportError:  # pragma: no cover
    ssl = None  # type: ignore
    SSLContext = object  # type: ignore

try:
    import cchardet as chardet
except ImportError:  # pragma: no cover
    import chardet


from .info cimport RequestInfo
from cpython cimport bool


cdef class ClientRequest(object):
    GET_METHODS = {
        hdrs.METH_GET,
        hdrs.METH_HEAD,
        hdrs.METH_OPTIONS,
        hdrs.METH_TRACE,
    }
    POST_METHODS = {hdrs.METH_PATCH, hdrs.METH_POST, hdrs.METH_PUT}
    ALL_METHODS = GET_METHODS.union(POST_METHODS).union({hdrs.METH_DELETE})

    DEFAULT_HEADERS = {
        hdrs.ACCEPT: '*/*',
        hdrs.ACCEPT_ENCODING: 'gzip, deflate',
    }

    # body = b''
    # auth = None
    # response = None
    response_class = None

    # _writer = None  # async task for streaming data
    _continue = None  # waiter future for '100 Continue' response

    #: Default HTTP request headers.
    DEFAULT_HEADERS = {
        hdrs.ACCEPT: 'application/json',
        hdrs.ACCEPT_ENCODING: 'gzip, deflate',
        hdrs.CONTENT_TYPE: 'application/json'
    }
    CHUNK_SIZE = 8192

    # N.B.
    # Adding __del__ method with self._writer closing doesn't make sense
    # because _writer is instance method, thus it keeps a reference to self.
    # Until writer has finished finalizer will not be called.

    def __init__(
            self,
            method: str,
            url: URL,
            *,
            params: Optional[Mapping[str, str]] = None,
            headers: Optional[typedefs.LooseHeaders] = None,
            skip_auto_headers: Iterable[str] = frozenset(),
            data: Any = None,
            cookies: Optional[typedefs.LooseCookies] = None,
            auth: Optional[helpers.BasicAuth] = None,
            version: http.HttpVersion = http.HttpVersion11,
            compress: Optional[str] = None,
            chunked: Optional[bool] = None,
            expect100: bool = False,
            loop: Optional[asyncio.AbstractEventLoop] = None,
            response_class: Optional[Type['ClientResponse']] = None,
            proxy: Optional[URL] = None,
            proxy_auth: Optional[helpers.BasicAuth] = None,
            timer: Optional[helpers.BaseTimerContext] = None,
            session: Optional['ClientSession'] = None,
            ssl: Union[SSLContext, bool, client_reqrep.Fingerprint, None] = None,
            proxy_headers: Optional[typedefs.LooseHeaders] = None,
            traces: Optional[List['Trace']] = None):
        self.body = b''
        if loop is None:
            loop = asyncio.get_event_loop()

        assert isinstance(url, URL), url
        assert isinstance(proxy, (URL, type(None))), proxy
        # FIXME: session is None in tests only, need to fix tests
        # assert session is not None
        self._session = cast('ClientSession', session)
        if params:
            q = MultiDict(url.query)
            url2 = url.with_query(params)
            q.extend(url2.query)
            url = url.with_query(q)
        self.original_url = url
        self.url = url.with_fragment(None)
        self.method = method.upper()
        self.chunked = chunked
        self.compress = compress
        self.loop = loop
        self.length = None
        if response_class is None:
            real_response_class = client_reqrep.ClientResponse
        else:
            real_response_class = response_class
        self._response_class = real_response_class  # type: Type[ClientResponse]
        self._timer = timer if timer is not None else helpers.TimerNoop()
        self._ssl = ssl

        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

        self.update_version(version)
        self.update_host(url)
        self.update_headers(headers)
        self.update_auto_headers(skip_auto_headers)
        self.update_cookies(cookies)
        self.update_content_encoding(data)
        self.update_auth(auth)
        self.update_proxy(proxy, proxy_auth, proxy_headers)

        self.update_body_from_data(data)
        if data or self.method not in self.GET_METHODS:
            self.update_transfer_encoding()
        self.update_expect_continue(expect100)
        if traces is None:
            traces = []
        self._traces = traces

    cpdef bool is_ssl(self):
        return self.url.scheme in ('https', 'wss')

    @property
    def ssl(self) -> Union['SSLContext', None, bool, client_reqrep.Fingerprint]:
        return self._ssl

    @property
    def connection_key(self) -> client_reqrep.ConnectionKey:
        proxy_headers = self.proxy_headers
        if proxy_headers:
            h = hash(tuple((k, v) for k, v in proxy_headers.items()))  # type: Optional[int]  # noqa
        else:
            h = None
        return client_reqrep.ConnectionKey(self.host, self.port, self.is_ssl(),
                                           self.ssl,
                                           self.proxy, self.proxy_auth, h)

    @property
    def host(self) -> str:
        ret = self.url.host
        assert ret is not None
        return ret

    @property
    def port(self) -> Optional[int]:
        return self.url.port

    cpdef update_host(self, url: URL):
        """Update destination host, port and connection type (ssl)."""
        # get host/port
        if not url.host:
            raise InvalidURL(url)

        # basic auth info
        username, password = url.user, url.password
        if username:
            self.auth = helpers.BasicAuth(username, password or '')

    cpdef update_version(self, version: Union[http.HttpVersion, str]):
        """Convert request version to two elements tuple.

        parser HTTP version '1.1' => (1, 1)
        """
        if isinstance(version, str):
            v = [l.strip() for l in version.split('.', 1)]
            try:
                version = http.HttpVersion(int(v[0]), int(v[1]))
            except ValueError:
                raise ValueError(
                    'Can not parse http version number: {}'
                    .format(version)) from None
        self.version = version

    cpdef update_headers(self, headers: Optional[typedefs.LooseHeaders]):
        """Update request headers."""
        self.headers = CIMultiDict()  # type: CIMultiDict[str]

        # add host
        netloc = cast(str, self.url.raw_host)
        if helpers.is_ipv6_address(netloc):
            netloc = '[{}]'.format(netloc)
        if not self.url.is_default_port():
            netloc += ':' + str(self.url.port)
        self.headers[hdrs.HOST] = netloc

        if headers:
            if isinstance(headers, (dict, MultiDictProxy, MultiDict)):
                headers = headers.items()  # type: ignore

            for key, value in headers:
                # A special case for Host header
                if key.lower() == 'host':
                    self.headers[key] = value
                else:
                    self.headers.add(key, value)

    cpdef update_auto_headers(self, skip_auto_headers: Iterable[str]):
        self.skip_auto_headers = CIMultiDict(
            [(hdr, None) for hdr in sorted(skip_auto_headers)])
        used_headers = self.headers.copy()
        used_headers.extend(self.skip_auto_headers)  # type: ignore

        for hdr, val in self.DEFAULT_HEADERS.items():
            if hdr not in used_headers:
                self.headers.add(hdr, val)

        if hdrs.USER_AGENT not in used_headers:
            self.headers[hdrs.USER_AGENT] = http.SERVER_SOFTWARE

    cpdef update_cookies(self, cookies: Optional[typedefs.LooseCookies]):
        """Update request cookies header."""
        if not cookies:
            return

        c = SimpleCookie()
        if hdrs.COOKIE in self.headers:
            c.load(self.headers.get(hdrs.COOKIE, ''))
            del self.headers[hdrs.COOKIE]

        if isinstance(cookies, Mapping):
            iter_cookies = cookies.items()
        else:
            iter_cookies = cookies  # type: ignore
        for name, value in iter_cookies:
            if isinstance(value, Morsel):
                # Preserve coded_value
                mrsl_val = value.get(value.key, Morsel())
                mrsl_val.set(value.key, value.value, value.coded_value)  # type: ignore  # noqa
                c[name] = mrsl_val
            else:
                c[name] = value  # type: ignore

        self.headers[hdrs.COOKIE] = c.output(header='', sep=';').strip()

    cpdef update_content_encoding(self, data: Any):
        """Set request content encoding."""
        if not data:
            return

        enc = self.headers.get(hdrs.CONTENT_ENCODING, '').lower()
        if enc:
            if self.compress:
                raise ValueError(
                    'compress can not be set '
                    'if Content-Encoding header is set')
        elif self.compress:
            if not isinstance(self.compress, str):
                self.compress = 'deflate'
            self.headers[hdrs.CONTENT_ENCODING] = self.compress
            self.chunked = True  # enable chunked, no need to deal with length

    cpdef update_transfer_encoding(self):
        """Analyze transfer-encoding header."""
        cdef unicode te = self.headers.get(hdrs.TRANSFER_ENCODING, '').lower()

        if 'chunked' in te:
            if self.chunked:
                raise ValueError(
                    'chunked can not be set '
                    'if "Transfer-Encoding: chunked" header is set')

        elif self.chunked:
            if hdrs.CONTENT_LENGTH in self.headers:
                raise ValueError(
                    'chunked can not be set '
                    'if Content-Length header is set')

            self.headers[hdrs.TRANSFER_ENCODING] = 'chunked'
        else:
            if hdrs.CONTENT_LENGTH not in self.headers:
                self.headers[hdrs.CONTENT_LENGTH] = str(len(self.body))

    cpdef update_auth(self, auth: Optional[helpers.BasicAuth]):
        """Set basic auth."""
        if auth is None:
            auth = self.auth
        if auth is None:
            return

        if not isinstance(auth, helpers.BasicAuth):
            raise TypeError('BasicAuth() tuple is required instead')

        self.headers[hdrs.AUTHORIZATION] = auth.encode()


    cpdef update_expect_continue(self, bool expect=False):
        if expect:
            self.headers[hdrs.EXPECT] = '100-continue'
        elif self.headers.get(hdrs.EXPECT, '').lower() == '100-continue':
            expect = True

        if expect:
            self._continue = self.loop.create_future()

    cpdef update_proxy(self, proxy: Optional[URL],
                     proxy_auth: Optional[helpers.BasicAuth],
                     proxy_headers: Optional[typedefs.LooseHeaders]):
        if proxy and not proxy.scheme == 'http':
            raise ValueError("Only http proxies are supported")
        if proxy_auth and not isinstance(proxy_auth, helpers.BasicAuth):
            raise ValueError("proxy_auth must be None or BasicAuth() tuple")
        self.proxy = proxy
        self.proxy_auth = proxy_auth
        self.proxy_headers = proxy_headers

    cpdef bool keep_alive(self):
        if self.version < http.HttpVersion10:
            # keep alive not supported at all
            return False
        if self.version == http.HttpVersion10:
            if self.headers.get(hdrs.CONNECTION) == 'keep-alive':
                return True
            else:  # no headers means we close for Http 1.0
                return False
        elif self.headers.get(hdrs.CONNECTION) == 'close':
            return False

        return True

    async def write_bytes(self, writer: abc.AbstractStreamWriter,
                          conn: 'Connection'):
        """Support coroutines that yields bytes objects."""
        # 100 response
        if self._continue is not None:
            await writer.drain()
            await self._continue

        protocol = conn.protocol
        assert protocol is not None
        try:
            if isinstance(self.body, payload.Payload):
                await self.body.write(writer)
            else:
                if isinstance(self.body, (bytes, bytearray)):
                    self.body = (self.body,)  # type: ignore

                for chunk in self.body:
                    await writer.write(chunk)  # type: ignore

            await writer.write_eof()
        except OSError as exc:
            new_exc = ClientOSError(
                exc.errno,
                'Can not write request body for %s' % self.url)
            new_exc.__context__ = exc
            new_exc.__cause__ = exc
            protocol.set_exception(new_exc)
        except asyncio.CancelledError as exc:
            if not conn.closed:
                protocol.set_exception(exc)
        except Exception as exc:
            protocol.set_exception(exc)
        finally:
            self._writer = None

    async def send(self, conn: 'Connection') -> 'ClientResponse':
        # Specify request target:
        # - CONNECT request must send authority form URI
        # - not CONNECT proxy must send absolute form URI
        # - most common is origin form URI
        if self.method == hdrs.METH_CONNECT:
            path = '{}:{}'.format(self.url.raw_host, self.url.port)
        elif self.proxy and not self.is_ssl():
            path = str(self.url)
        else:
            path = self.url.raw_path
            if self.url.raw_query_string:
                path += '?' + self.url.raw_query_string

        protocol = conn.protocol
        assert protocol is not None
        writer = http.StreamWriter(
            protocol, self.loop,
            on_chunk_sent=self._on_chunk_request_sent
        )

        if self.compress:
            writer.enable_compression(self.compress)

        if self.chunked is not None:
            writer.enable_chunking()

        # set default content-type
        if (self.method in self.POST_METHODS and
                hdrs.CONTENT_TYPE not in self.skip_auto_headers and
                hdrs.CONTENT_TYPE not in self.headers):
            self.headers[hdrs.CONTENT_TYPE] = 'application/octet-stream'

        # set the connection header
        connection = self.headers.get(hdrs.CONNECTION)
        if not connection:
            if self.keep_alive():
                if self.version == http.HttpVersion10:
                    connection = 'keep-alive'
            else:
                if self.version == http.HttpVersion11:
                    connection = 'close'

        if connection is not None:
            self.headers[hdrs.CONNECTION] = connection

        # status + headers
        status_line = '{0} {1} HTTP/{2[0]}.{2[1]}'.format(
            self.method, path, self.version)
        await writer.write_headers(status_line, self.headers)
        self._writer = self.loop.create_task(self.write_bytes(writer, conn))

        response_class = self._response_class
        assert response_class is not None
        self.response = response_class(
            self.method, self.original_url,
            writer=self._writer, continue100=self._continue, timer=self._timer,
            request_info=self.request_info,
            traces=self._traces,
            loop=self.loop,
            session=self._session
        )
        return self.response

    async def close(self) -> None:
        if self._writer is not None:
            try:
                await self._writer
            finally:
                self._writer = None

    cpdef terminate(self):
        if self._writer is not None:
            if not self.loop.is_closed():
                self._writer.cancel()
            self._writer = None

    async def _on_chunk_request_sent(self, chunk: bytes) -> None:
        for trace in self._traces:
            await trace.send_request_chunk_sent(chunk)

    @property
    def request_info(self) -> RequestInfo:
        headers = CIMultiDictProxy(self.headers)
        return RequestInfo(
            self.url,
            self.method,
            headers,
            self.original_url)

    cpdef _update_body_from_data(self, body: Any):
        if not body:
            return

        # FormData
        if isinstance(body, FormData):
            body = body()

        try:
            body = payload.PAYLOAD_REGISTRY.get(body, disposition=None)
        except payload.LookupError:
            body = FormData(body)()

        self.body = body

        # enable chunked encoding if needed
        if not self.chunked:
            if hdrs.CONTENT_LENGTH not in self.headers:
                size = body.size
                if size is None:
                    self.chunked = True
                else:
                    if hdrs.CONTENT_LENGTH not in self.headers:
                        self.headers[hdrs.CONTENT_LENGTH] = str(size)

        # copy payload headers
        assert body.headers
        for (key, value) in body.headers.items():
            if key in self.headers:
                continue
            if key in self.skip_auto_headers:
                continue
            self.headers[key] = value

    cpdef update_body_from_data(self, data):
        """Encodes ``data`` as JSON if `Content-Type`
        is :mimetype:`application/json`."""
        if data is None:
            return
        from aiohttp.payload import AsyncIterablePayload
        if self.headers.get(hdrs.CONTENT_TYPE) == 'application/json':
            non_json_types = (types.GeneratorType, io.IOBase, MultipartWriter, AsyncIterablePayload)
            if not (isinstance(data, non_json_types)):
                data = json.dumps(data)

        rv = self._update_body_from_data(data)
        if hdrs.CONTENT_LENGTH in self.headers and isinstance(data, MultipartWriter):
            self.chunked = False
        return rv

    cpdef update_path(self, params):
        if isinstance(params, dict):
            params = params.copy()
            for key, value in params.items():
                if value is True:
                    params[key] = 'true'
                elif value is False:
                    params[key] = 'false'
        return super().update_path(params)
