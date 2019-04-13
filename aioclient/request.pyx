# cython: language_level=3
# -*- coding: utf-8 -*-

import asyncio
import io
import sys
import traceback
from http.cookies import CookieError, Morsel, SimpleCookie
from typing import (
    Any,
    Iterable, List, Mapping,
    Optional, Type,
    Union, cast)

import multidict
from yarl import URL

import aiohttp
from aiohttp import (
    abc, client_exceptions, # client_reqrep,
    hdrs, helpers, http,
    payload, typedefs)
from aiohttp.formdata import FormData

try:
    import ssl
    from ssl import SSLContext
except ImportError:
    ssl = None
    SSLContext = object
try:
    import cchardet as chardet
except ImportError:
    import chardet

# Cimports
from cpython cimport bool

from .info cimport RequestInfo
from .response cimport ClientResponse
from .utils cimport is_ipv6_address


cdef class ClientRequest(object):
    default_response_class = ClientResponse

    # mutable ?
    # ALL_METHODS = aiohttp.client_reqrep.ClientRequest.ALL_METHODS
    # GET_METHODS = aiohttp.client_reqrep.ClientRequest.GET_METHODS
    # POST_METHODS = aiohttp.client_reqrep.ClientRequest.POST_METHODS
    # DEFAULT_HEADERS = aiohttp.client_reqrep.ClientRequest.DEFAULT_HEADERS
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

    def __cinit__(
            self,
            unicode method,
            url: URL,
            *,
            compress: Optional[str] = None,
            bool chunked: Optional[bool] = None,
            bool expect100=False,
            loop: Optional[asyncio.AbstractEventLoop] = None,
            list traces: Optional[List['Trace']] = None,
            **kwargs):
        self.body = b''
        self.method = method.upper()
        self.chunked = chunked
        self.compress = compress
        self.loop = (
            asyncio.get_event_loop()
            if loop is None
            else loop)
        self.length = None
        self._traces = traces or []

    def __init__(
            self,
            unicode method,
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
            bool chunked: Optional[bool] = None,
            bool expect100=False,
            loop: Optional[asyncio.AbstractEventLoop] = None,
            response_class: Optional[Type[ClientResponse]] = None,
            proxy: Optional[URL] = None,
            proxy_auth: Optional[helpers.BasicAuth] = None,
            timer: Optional[helpers.BaseTimerContext] = None,
            session: Optional['ClientSession'] = None,
            ssl: Union[SSLContext, bool, aiohttp.client_reqrep.Fingerprint, None] = None,
            proxy_headers: Optional[typedefs.LooseHeaders] = None,
            list traces: Optional[List['Trace']] = None):

        assert not isinstance(url, str)
        assert not isinstance(proxy, str)
        # assert isinstance(url, URL), url
        # assert isinstance(proxy, (URL, type(None))), proxy
        # FIXME: session is None in tests only, need to fix tests
        # assert session is not None
        self._session = cast('ClientSession', session)
        if params:
            q = multidict.MultiDict(url.query)
            q.extend(url.with_query(params).query)
            url = url.with_query(q)
        self.original_url = url
        self.url = (
            url.with_fragment(None)
            if url.fragment
            else url)
        self.response_class = (
            self.default_response_class
            if response_class is None
            else response_class)
        self._timer = (
            timer if timer is not None
            else helpers.TimerNoop())
        self._ssl = ssl
        if self.loop.get_debug():
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
        self.request_info = RequestInfo(
            self.url,
            self.method,
            multidict.CIMultiDictProxy(self.headers),
            self.original_url)
        print("ALLDONE", self.headers)

    @property
    def ssl(self) -> Union['SSLContext', None, bool, aiohttp.client_reqrep.Fingerprint]:
        return self._ssl

    @property
    def connection_key(self) -> aiohttp.client_reqrep.ConnectionKey:
        h = (
            hash(tuple(
                (k, v) for k, v
                in self.proxy_headers.items()))
            if self.proxy_headers
            else None)
        return aiohttp.client_reqrep.ConnectionKey(
            self.host, self.port,
            self.is_ssl(),
            self.ssl,
            self.proxy,
            self.proxy_auth, h)

    @property
    def host(self) -> str:
        assert self.url.host is not None
        return self.url.host

    @property
    def port(self) -> Optional[int]:
        return self.url.port

    cpdef bool is_ssl(self):
        return self.url.scheme in ('https', 'wss')

    cpdef bool keep_alive(self):
        return not (
            self.version < http.HttpVersion10
            or self.headers.get(hdrs.CONNECTION) == 'close'
            or (self.version == http.HttpVersion10
                and self.headers.get(hdrs.CONNECTION) != 'keep-alive'))

    cpdef terminate(self):
        if self._writer is None:
            return
        elif not self.loop.is_closed():
            self._writer.cancel()
        self._writer = None

    cpdef update_body_from_data(self, body: Any):
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
                elif hdrs.CONTENT_LENGTH not in self.headers:
                    self.headers[hdrs.CONTENT_LENGTH] = str(size)

        # copy payload headers
        assert body.headers
        for (key, value) in body.headers.items():
            if key in (set(self.headers) | set(self.skip_auto_headers)):
                continue
            self.headers[key] = value

    cpdef update_auth(self, auth: Optional[helpers.BasicAuth]):
        """Set basic auth."""
        if auth is None:
            auth = self.auth
        if auth is None:
            return

        if not isinstance(auth, helpers.BasicAuth):
            raise TypeError('BasicAuth() tuple is required instead')

        self.headers[hdrs.AUTHORIZATION] = auth.encode()

    cpdef update_auto_headers(self, skip_auto_headers: Iterable[str]):
        self.skip_auto_headers = multidict.CIMultiDict(
            [(hdr, None) for hdr in sorted(skip_auto_headers)])
        used_headers = self.headers.copy()
        used_headers.extend(self.skip_auto_headers)
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
        iter_cookies = (
            cookies.items()
            if isinstance(cookies, Mapping)
            else cookies)
        for name, value in iter_cookies:
            if isinstance(value, Morsel):
                # Preserve coded_value
                mrsl_val = value.get(value.key, Morsel())
                mrsl_val.set(
                    value.key,
                    value.value,
                    value.coded_value)
                c[name] = mrsl_val
            else:
                c[name] = value
        self.headers[hdrs.COOKIE] = c.output(header='', sep=';').strip()

    cpdef update_content_encoding(self, data: Any):
        """Set request content encoding."""
        if not data:
            return
        bad_compress = (
            self.compress
            and self.headers.get(hdrs.CONTENT_ENCODING, '').lower())
        if bad_compress:
            raise ValueError(
                'compress can not be set '
                'if Content-Encoding header is set')
        elif self.compress:
            if not isinstance(self.compress, str):
                self.compress = 'deflate'
            self.headers[hdrs.CONTENT_ENCODING] = self.compress
            self.chunked = True

    cpdef update_expect_continue(self, bool expect=False):
        if expect:
            self.headers[hdrs.EXPECT] = '100-continue'
        elif self.headers.get(hdrs.EXPECT, '').lower() == '100-continue':
            expect = True

        if expect:
            self._continue = self.loop.create_future()

    cpdef update_headers(self, headers: Optional[typedefs.LooseHeaders]):
        """Update request headers."""
        self.headers = multidict.CIMultiDict()

        # add host
        netloc = cast(str, self.url.raw_host)
        if is_ipv6_address(netloc):
            netloc = '[{}]'.format(netloc)
        if not self.url.is_default_port():
            netloc += ':' + str(self.url.port)
        self.headers[hdrs.HOST] = netloc
        if not headers:
            return
        headers = (
            headers.items()
            if isinstance(
                    headers,
                    (dict,
                     multidict.MultiDictProxy,
                     multidict.MultiDict))
            else headers)
        for key, value in headers:
            # A special case for Host header
            if key.lower() == 'host':
                self.headers[key] = value
            else:
                self.headers.add(key, value)

    cpdef update_host(self, url: URL):
        """Update destination host, port and connection type (ssl)."""
        # get host/port
        if not url.host:
            raise client_exceptions.InvalidURL(url)

        # basic auth info
        if url.user:
            self.auth = helpers.BasicAuth(
                url.user,
                url.password or '')

    cpdef update_proxy(
            self,
            proxy: Optional[URL],
            proxy_auth: Optional[helpers.BasicAuth],
            proxy_headers: Optional[typedefs.LooseHeaders]):
        if proxy and not proxy.scheme == 'http':
            raise ValueError("Only http proxies are supported")
        if proxy_auth and not isinstance(proxy_auth, helpers.BasicAuth):
            raise ValueError("proxy_auth must be None or BasicAuth() tuple")
        self.proxy = proxy
        self.proxy_auth = proxy_auth
        self.proxy_headers = proxy_headers

    cpdef update_transfer_encoding(self):
        """Analyze transfer-encoding header."""
        bad_transfer_encoding = (
            self.chunked
            and ('chunked'
                 in self.headers.get(
                     hdrs.TRANSFER_ENCODING, '').lower()))
        if bad_transfer_encoding:
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
        print("enabled TRANSFSER ENCODING", self.headers)

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

    async def close(self) -> None:
        if self._writer is not None:
            try:
                await self._writer
            finally:
                self._writer = None

    async def send(self, conn: 'Connection') -> ClientResponse:
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

        assert conn.protocol is not None
        writer = http.StreamWriter(
            conn.protocol,
            self.loop,
            on_chunk_sent=self._on_chunk_request_sent)

        if self.compress:
            writer.enable_compression(self.compress)

        if self.chunked is not None:
            writer.enable_chunking()

        # set default content-type
        set_default_content_type = (
            self.method in self.POST_METHODS
            and hdrs.CONTENT_TYPE not in self.skip_auto_headers
            and hdrs.CONTENT_TYPE not in self.headers)
        if set_default_content_type:
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

        assert self.response_class is not None
        self.response = self.response_class(
            self.method,
            self.original_url,
            writer=self._writer,
            continue100=self._continue,
            timer=self._timer,
            request_info=self.request_info,
            traces=self._traces,
            loop=self.loop,
            session=self._session)
        return self.response

    async def write_bytes(
            self,
            writer: abc.AbstractStreamWriter,
            conn: 'Connection'):
        """Support coroutines that yields bytes objects."""
        # 100 response
        if self._continue is not None:
            await writer.drain()
            await self._continue

        assert conn.protocol is not None
        try:
            if isinstance(self.body, payload.Payload):
                await self.body.write(writer)
            else:
                if isinstance(self.body, (bytes, bytearray)):
                    self.body = (self.body, )

                for chunk in self.body:
                    await writer.write(chunk)
            await writer.write_eof()
        except OSError as exc:
            new_exc = client_exceptions.ClientOSError(
                exc.errno,
                'Can not write request body for %s' % self.url)
            new_exc.__context__ = exc
            new_exc.__cause__ = exc
            conn.protocol.set_exception(new_exc)
        except asyncio.CancelledError as exc:
            if not conn.closed:
                conn.protocol.set_exception(exc)
        except Exception as exc:
            conn.protocol.set_exception(exc)
        finally:
            self._writer = None

    async def _on_chunk_request_sent(self, chunk: bytes) -> None:
        for trace in self._traces:
            await trace.send_request_chunk_sent(chunk)


class Py__ClientRequest(ClientRequest):
    pass
