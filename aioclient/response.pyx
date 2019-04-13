# cython: language_level=3
# -*- coding: utf-8 -*-

import asyncio
import cgi
import codecs
import io
import re
import sys
import traceback
import warnings
from http.cookies import CookieError, SimpleCookie
from types import MappingProxyType, TracebackType
from typing import (
    Any,
    List,
    Optional,
    Tuple,
    Type)

import multidict
from yarl import URL

import aiohttp
from aiohttp import (
    client_exceptions, hdrs, helpers, http,
    log, multipart, typedefs)
#  client_reqrep,

try:
    import cchardet as chardet
except ImportError:
    import chardet

from .info cimport RequestInfo


sentinel = object()


cdef class ClientResponse(object):

    ATTRS = frozenset([
        '_content_type',
        '_content_dict',
        '_stored_content_type'])

    def __cinit__(
            self,
            unicode method,
            url: URL,
            *,
            writer: 'asyncio.Task[None]',
            continue100: Optional['asyncio.Future[bool]'],
            timer: helpers.BaseTimerContext,
            RequestInfo request_info,
            list traces: List['Trace'],
            loop: asyncio.AbstractEventLoop,
            session: 'ClientSession',
            **kwargs) -> None:
        self.method = method
        self._body = None
        self._writer = writer
        self._continue = continue100
        self._closed = True
        self._history = ()
        self._request_info = request_info
        self._cache = {}
        self._traces = traces
        self._loop = loop
        # store a reference to session #1985
        self._session = None
        self._stored_content_type = sentinel

    def __init__(
            self,
            unicode method,
            url: URL, *,
            writer: 'asyncio.Task[None]',
            continue100: Optional['asyncio.Future[bool]'],
            timer: helpers.BaseTimerContext,
            RequestInfo request_info,
            list traces: List['Trace'],
            loop: asyncio.AbstractEventLoop,
            session: 'ClientSession') -> None:
        assert not isinstance(url, str), url
        # assert isinstance(url, URL)
        self.cookies = SimpleCookie()
        self._real_url = url
        self._url = (
            url.with_fragment(None)
            if url.fragment
            else url)
        self._timer = (
            timer
            if timer is not None
            else helpers.TimerNoop())
        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

    def __del__(self, _warnings: Any = warnings) -> None:
        if self._closed or self._connection is None:
            return
        self._connection.release()
        self._cleanup_writer()
        if not self._loop.get_debug():
            return
        _warnings.warn(
            "Unclosed response {!r}".format(self),
            ResourceWarning,
            **({'source': self}
               if helpers.PY_36
               else {}))
        context = {
            'client_response': self,
            'message': 'Unclosed response'}
        if self._source_traceback:
            context['source_traceback'] = self._source_traceback
        self._loop.call_exception_handler(context)

    def __repr__(self) -> str:
        out = io.StringIO()
        ascii_encodable_reason = (
            self.reason.encode(
                'ascii',
                'backslashreplace').decode('ascii')
            if self.reason
            else self.reason)
        print(
            '<ClientResponse({}) [{} {}]>'.format(
                str(self.url),
                self.status if self.status else None,
                ascii_encodable_reason),
            file=out)
        print(self.headers, file=out)
        return out.getvalue()

    # @helpers.reify ?
    @property
    def charset(self) -> Optional[str]:
        """The value of charset part for Content-Type HTTP header."""
        raw = self._headers.get(hdrs.CONTENT_TYPE)
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_dict.get('charset')

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def connection(self) -> Optional['Connection']:
        return self._connection

    @property
    def content_length(self) -> Optional[int]:
        """The value of Content-Length HTTP header."""
        content_length = self._headers.get(hdrs.CONTENT_LENGTH)
        return (
            int(content_length)
            if content_length is not None
            else None)

    @property
    def content_type(self) -> str:
        """The value of content part for Content-Type HTTP header."""
        raw = self._headers.get(hdrs.CONTENT_TYPE)
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_type

    @helpers.reify
    def content_disposition(self) -> Optional["aiohttp.client_reqrep.ContentDisposition"]:
        raw = self._headers.get(hdrs.CONTENT_DISPOSITION)
        if raw is None:
            return None
        disposition_type, params_dct = multipart.parse_content_disposition(raw)
        params = MappingProxyType(params_dct)
        return aiohttp.client_reqrep.ContentDisposition(
            disposition_type,
            params,
            multipart.content_disposition_filename(params))

    @helpers.reify
    def real_url(self) -> URL:
        return self._real_url

    @helpers.reify
    def headers(self) -> 'multidict.CIMultiDictProxy[str]':
        return self._headers

    @helpers.reify
    def history(self) -> Tuple['ClientResponse', ...]:
        """A sequence of of responses, if redirects occurred."""
        return self._history

    @helpers.reify
    def host(self) -> str:
        assert self._url.host is not None
        return self._url.host

    @helpers.reify
    def links(self) -> 'multidict.MultiDictProxy[multidict.MultiDictProxy[Union[str, URL]]]':
        links_str = ", ".join(self.headers.getall("link", []))

        if not links_str:
            return multidict.MultiDictProxy(multidict.MultiDict())

        links = multidict.MultiDict()

        for val in re.split(r",(?=\s*<)", links_str):
            match = re.match(r"\s*<(.*)>(.*)", val)
            if match is None:
                # the check exists to suppress mypy error
                continue
            url, params_str = match.groups()
            params = params_str.split(";")[1:]

            link = multidict.MultiDict()

            for param in params:
                match = re.match(
                    r"^\s*(\S*)\s*=\s*(['\"]?)(.*?)(\2)\s*$",
                    param, re.M
                )
                if match is None:
                    # the check exists to suppress mypy error
                    continue
                key, _, value, _ = match.groups()

                link.add(key, value)

            key = link.get("rel", url)
            link.add("url", self.url.join(URL(url)))

            links.add(key, multidict.MultiDictProxy(link))
        return multidict.MultiDictProxy(links)

    @helpers.reify
    def raw_headers(self) -> typedefs.RawHeaders:
        return self._raw_headers

    @helpers.reify
    def request_info(self) -> RequestInfo:
        return self._request_info

    @helpers.reify
    def url(self) -> URL:
        return self._url

    @helpers.reify
    def url_obj(self) -> URL:
        warnings.warn(
            "Deprecated, use .url #1654",
            DeprecationWarning,
            stacklevel=2)
        return self._url

    cpdef close(self):
        if not self._released:
            self._notify_content()
        if self._closed:
            return

        self._closed = True
        if self._loop is None or self._loop.is_closed():
            return

        if self._connection is not None:
            self._connection.close()
            self._connection = None
        self._cleanup_writer()

    cpdef unicode get_encoding(self):
        mimetype = helpers.parse_mimetype(
            self.headers.get(hdrs.CONTENT_TYPE, '').lower())
        encoding = mimetype.parameters.get('charset')
        print("got encoding from params", encoding)
        if encoding:
            try:
                codecs.lookup(encoding)
            except LookupError:
                encoding = None
        if not encoding:
            print("NOT getting here")
            # RFC 7159 states that the default encoding is UTF-8.
            encoding = (
                'utf-8'
                if (mimetype.type == 'application'
                    and mimetype.subtype == 'json')
                else chardet.detect(self._body)['encoding'])
        return encoding or 'utf-8'

    cpdef raise_for_status(self):
        # always not None for started response
        if self.status < 400:
            return
        print("RAISING", self.reason)
        assert self.reason is not None
        self.release()
        raise client_exceptions.ClientResponseError(
            self.request_info,
            self.history,
            status=self.status,
            message=self.reason,
            headers=self.headers)

    cpdef release(self):
        if not self._released:
            self._notify_content()
        if self._closed:
            return helpers.noop()
        self._closed = True
        if self._connection is not None:
            self._connection.release()
            self._connection = None
        self._cleanup_writer()
        return helpers.noop()

    cpdef tuple _parse_content_type(self, str raw):
        self._stored_content_type = raw
        self._content_type, self._content_dict = (
            ('application/octet-stream', {})
            if raw is None
            else cgi.parse_header(raw))
        return self.content_type, self._content_dict

    cpdef _response_eof(self):
        if self._closed:
            return

        if self._connection is not None:
            # websocket, protocol could be None because
            # connection could be detached
            if (self._connection.protocol is not None and
                    self._connection.protocol.upgraded):
                return

            self._connection.release()
            self._connection = None

        self._closed = True
        self._cleanup_writer()

    cpdef _cleanup_writer(self):
        if self._writer is not None:
            self._writer.cancel()
        self._writer = None
        self._session = None

    cpdef _notify_content(self):
        content = self.content
        if content and content.exception() is None:
            content.set_exception(
                client_exceptions.ClientConnectionError('Connection closed'))
        self._released = True

    async def __aenter__(self) -> ClientResponse:
        return self

    async def __aexit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_val: Optional[BaseException],
            exc_tb: Optional[TracebackType]) -> None:
        # similar to _RequestContextManager, we do not need to check
        # for exceptions, response object can closes connection
        # is state is broken
        self.release()

    async def json(
            self,
            *, encoding: str = None,
            loads: typedefs.JSONDecoder = typedefs.DEFAULT_JSON_DECODER,
            content_type: Optional[str] = 'application/json') -> Any:
        """Read and decodes JSON response."""
        print("GETTING JSON!")
        if self._body is None:
            await self.read()

        if content_type:
            ctype = self.headers.get(hdrs.CONTENT_TYPE, '').lower()
            if not aiohttp.client_reqrep._is_expected_content_type(ctype, content_type):
                raise client_exceptions.ContentTypeError(
                    self.request_info,
                    self.history,
                    message=('Attempt to decode JSON with '
                             'unexpected mimetype: %s' % ctype),
                    headers=self.headers)
        return loads(
            self._body.decode(
                self.get_encoding()
                if encoding is None
                else encoding))

    async def read(self) -> bytes:
        """Read response payload."""
        if self._body is None:
            try:
                self._body = await self.content.read()
                for trace in self._traces:
                    await trace.send_response_chunk_received(self._body)
            except BaseException:
                self.close()
                raise
        elif self._released:
            raise client_exceptions.ClientConnectionError('Connection closed')

        return self._body

    async def start(self, connection: 'Connection') -> 'ClientResponse':
        """Start response processing."""
        self._closed = False
        self._protocol = connection.protocol
        self._connection = connection
        with self._timer:
            while True:
                # read response
                try:
                    message, payload = await self._protocol.read()  # type: ignore  # noqa
                except http.HttpProcessingError as exc:
                    raise client_exceptions.ClientResponseError(
                        self.request_info, self.history,
                        status=exc.code,
                        message=exc.message, headers=exc.headers) from exc

                if (message.code < 100 or
                        message.code > 199 or message.code == 101):
                    break

                if self._continue is not None:
                    helpers.set_result(self._continue, True)
                    self._continue = None

        # payload eof handler
        payload.on_eof(self._response_eof)

        # response status
        self.version = message.version
        self.status = message.code
        print("REASON", type(message.reason))
        self.reason = message.reason

        # headers
        self._headers = message.headers  # type is CIMultiDictProxy
        self._raw_headers = message.raw_headers

        # payload
        self.content = payload

        # cookies
        for hdr in self.headers.getall(hdrs.SET_COOKIE, ()):
            try:
                self.cookies.load(hdr)
            except CookieError as exc:
                log.client_logger.warning(
                    'Can not load response cookies: %s', exc)
        return self

    async def text(
            self,
            encoding: Optional[str] = None,
            errors: str = 'strict') -> str:
        """Read response payload and decode."""
        if self._body is None:
            await self.read()

        if encoding is None:
            encoding = self.get_encoding()
        print("GOT text encoding...", encoding, self._body)
        return self._body.decode(encoding, errors=errors)  # type: ignore

    async def wait_for_close(self) -> None:
        if self._writer is not None:
            try:
                await self._writer
            finally:
                self._writer = None
        self.release()


class Py__ClientResponse(ClientResponse):
    pass
