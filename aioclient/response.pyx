# distutils: define_macros=CYTHON_TRACE_NOGIL=1
# cython: linetrace=True
# cython: binding=True
# cython: language_level=3

import asyncio
import cgi
import codecs
import io
import re
import sys
import traceback
import warnings
from hashlib import md5, sha1, sha256
from http.cookies import CookieError, Morsel, SimpleCookie
from types import MappingProxyType, TracebackType
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    Union,
    cast)

from aiohttp.helpers import (
    PY_36,
    BaseTimerContext,
    BasicAuth,
    TimerNoop,
    noop,
    reify,
    set_result)

from aiohttp.client_exceptions import (
    ClientConnectionError,
    ClientOSError,
    ClientResponseError,
    ContentTypeError,
    InvalidURL,
    ServerFingerprintMismatch)

try:
    import cchardet as chardet
except ImportError:
    import chardet

from yarl import URL

sentinel = object()

from aiohttp.client_reqrep import ContentDisposition, _is_expected_content_type
from aiohttp.typedefs import (
    DEFAULT_JSON_DECODER,
    JSONDecoder,
    LooseCookies,
    LooseHeaders,
    RawHeaders)

from aiohttp import hdrs, helpers, http, multipart
from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy

from aiohttp.log import client_logger

from .info cimport RequestInfo


cdef class HeadersMixin(object):

    ATTRS = frozenset([
        '_content_type', '_content_dict', '_stored_content_type'])

    def __init__(self):
        self._stored_content_type = sentinel

    cpdef tuple _parse_content_type(self, str raw):
        self._stored_content_type = raw
        self._content_type, self._content_dict = (
            'application/octet-stream', {}
            if raw is None
            else cgi.parse_header(raw))

    @property
    def content_type(self) -> str:
        """The value of content part for Content-Type HTTP header."""
        raw = self._headers.get(hdrs.CONTENT_TYPE)
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_type

    @property
    def charset(self) -> Optional[str]:
        """The value of charset part for Content-Type HTTP header."""
        raw = self._headers.get(hdrs.CONTENT_TYPE)
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_dict.get('charset')

    @property
    def content_length(self) -> Optional[int]:
        """The value of Content-Length HTTP header."""
        content_length = self._headers.get(hdrs.CONTENT_LENGTH)
        if content_length is not None:
            return int(content_length)
        else:
            return None


cdef class ClientResponse(HeadersMixin):

    # from the Status-Line of the response
    # version = None  # HTTP-Version
    # status = None   # type: int  # Status-Code
    # reason = None   # Reason-Phrase

    # content = None  # type: StreamReader  # Payload stream
    # _headers = None  # type: CIMultiDictProxy[str]  # Response headers
    # _raw_headers = None  # type: RawHeaders  # Response raw headers

    # _connection = None  # current connection
    # _source_traceback = None
    # setted up by ClientRequest after ClientResponse object creation
    # post-init stage allows to not change ctor signature
    # _closed = True  # to allow __del__ for non-initialized properly response
    # _released = False

    def __cinit__(
            self,
            str method,
            url: URL,
            *,
            writer: 'asyncio.Task[None]',
            continue100: Optional['asyncio.Future[bool]'],
            timer: BaseTimerContext,
            RequestInfo request_info,
            traces: List['Trace'],
            loop: asyncio.AbstractEventLoop,
            session: 'ClientSession') -> None:
        # assert isinstance(url, URL)
        self.method = method
        self.cookies = SimpleCookie()
        self._real_url = url
        self._url = url  # .with_fragment(None)
        self._body = None  # type: Any
        self._writer = writer  # type: Optional[asyncio.Task[None]]
        self._continue = continue100  # None by default
        self._closed = True
        self._history = ()  # type: Tuple[ClientResponse, ...]
        self._request_info = request_info
        self._timer = timer if timer is not None else TimerNoop()
        self._cache = {}  # type: Dict[str, Any]
        self._traces = traces
        self._loop = loop
        # store a reference to session #1985
        self._session = None  # session  # type: Optional[ClientSession]
        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

    def __init__(
            self,
            str method,
            url: URL, *,
            writer: 'asyncio.Task[None]',
            continue100: Optional['asyncio.Future[bool]'],
            timer: BaseTimerContext,
            request_info: RequestInfo,
            traces: List['Trace'],
            loop: asyncio.AbstractEventLoop,
            session: 'ClientSession') -> None:
        pass

    @reify
    def url(self) -> URL:
        return self._url

    @reify
    def url_obj(self) -> URL:
        warnings.warn(
            "Deprecated, use .url #1654", DeprecationWarning, stacklevel=2)
        return self._url

    @reify
    def real_url(self) -> URL:
        return self._real_url

    @reify
    def host(self) -> str:
        assert self._url.host is not None
        return self._url.host

    @reify
    def headers(self) -> 'CIMultiDictProxy[str]':
        return self._headers

    @reify
    def raw_headers(self) -> RawHeaders:
        return self._raw_headers

    @reify
    def request_info(self) -> RequestInfo:
        return self._request_info

    @reify
    def content_disposition(self) -> Optional[ContentDisposition]:
        raw = self._headers.get(hdrs.CONTENT_DISPOSITION)
        if raw is None:
            return None
        disposition_type, params_dct = multipart.parse_content_disposition(raw)
        params = MappingProxyType(params_dct)
        filename = multipart.content_disposition_filename(params)
        return ContentDisposition(disposition_type, params, filename)

    def __del__(self, _warnings: Any = warnings) -> None:
        if self._closed:
            return

        if self._connection is not None:
            self._connection.release()
            self._cleanup_writer()

            if self._loop.get_debug():
                if PY_36:
                    kwargs = {'source': self}
                else:
                    kwargs = {}
                _warnings.warn("Unclosed response {!r}".format(self),
                               ResourceWarning,
                               **kwargs)
                context = {'client_response': self,
                           'message': 'Unclosed response'}
                if self._source_traceback:
                    context['source_traceback'] = self._source_traceback
                self._loop.call_exception_handler(context)

    def __repr__(self) -> str:
        out = io.StringIO()
        ascii_encodable_url = str(self.url)
        if self.reason:
            ascii_encodable_reason = self.reason.encode('ascii',
                                                        'backslashreplace') \
                .decode('ascii')
        else:
            ascii_encodable_reason = self.reason
        print('<ClientResponse({}) [{} {}]>'.format(
            ascii_encodable_url, self.status, ascii_encodable_reason),
            file=out)
        print(self.headers, file=out)
        return out.getvalue()

    @property
    def connection(self) -> Optional['Connection']:
        return self._connection

    @reify
    def history(self) -> Tuple['ClientResponse', ...]:
        """A sequence of of responses, if redirects occurred."""
        return self._history

    @reify
    def links(self) -> 'MultiDictProxy[MultiDictProxy[Union[str, URL]]]':
        links_str = ", ".join(self.headers.getall("link", []))

        if not links_str:
            return MultiDictProxy(MultiDict())

        links = MultiDict()  # type: MultiDict[MultiDictProxy[Union[str, URL]]]

        for val in re.split(r",(?=\s*<)", links_str):
            match = re.match(r"\s*<(.*)>(.*)", val)
            if match is None:  # pragma: no cover
                # the check exists to suppress mypy error
                continue
            url, params_str = match.groups()
            params = params_str.split(";")[1:]

            link = MultiDict()  # type: MultiDict[Union[str, URL]]

            for param in params:
                match = re.match(
                    r"^\s*(\S*)\s*=\s*(['\"]?)(.*?)(\2)\s*$",
                    param, re.M
                )
                if match is None:  # pragma: no cover
                    # the check exists to suppress mypy error
                    continue
                key, _, value, _ = match.groups()

                link.add(key, value)

            key = link.get("rel", url)  # type: ignore
            link.add("url", self.url.join(URL(url)))

            links.add(key, MultiDictProxy(link))
        return MultiDictProxy(links)

    async def start(self, connection: 'Connection') -> 'ClientResponse':
        """Start response processing."""
        print("STARTING!!!", connection)
        self._closed = False
        self._protocol = connection.protocol
        self._connection = connection
        with self._timer:
            while True:
                # read response
                try:
                    message, payload = await self._protocol.read()  # type: ignore  # noqa
                except http.HttpProcessingError as exc:
                    raise ClientResponseError(
                        self.request_info, self.history,
                        status=exc.code,
                        message=exc.message, headers=exc.headers) from exc

                if (message.code < 100 or
                        message.code > 199 or message.code == 101):
                    break

                if self._continue is not None:
                    set_result(self._continue, True)
                    self._continue = None

        # payload eof handler
        payload.on_eof(self._response_eof)

        # response status
        self.version = message.version
        self.status = message.code
        self.reason = message.reason

        # headers
        self._headers = message.headers  # type is CIMultiDictProxy
        self._raw_headers = message.raw_headers  # type is Tuple[bytes, bytes]

        # payload
        self.content = payload

        # cookies
        for hdr in self.headers.getall(hdrs.SET_COOKIE, ()):
            try:
                self.cookies.load(hdr)
            except CookieError as exc:
                client_logger.warning(
                    'Can not load response cookies: %s', exc)
        return self

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

    @property
    def closed(self) -> bool:
        return self._closed

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

    cpdef release(self):
        if not self._released:
            self._notify_content()
        if self._closed:
            return noop()

        self._closed = True
        if self._connection is not None:
            self._connection.release()
            self._connection = None

        self._cleanup_writer()
        return noop()

    def raise_for_status(self) -> None:
        if 400 <= self.status:
            assert self.reason  # always not None for started response
            self.release()
            raise ClientResponseError(
                self.request_info,
                self.history,
                status=self.status,
                message=self.reason,
                headers=self.headers)

    cpdef _cleanup_writer(self):
        if self._writer is not None:
            self._writer.cancel()
        self._writer = None
        self._session = None

    cpdef _notify_content(self):
        content = self.content
        if content and content.exception() is None:
            content.set_exception(
                ClientConnectionError('Connection closed'))
        self._released = True

    async def wait_for_close(self) -> None:
        if self._writer is not None:
            try:
                await self._writer
            finally:
                self._writer = None
        self.release()

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
            raise ClientConnectionError('Connection closed')

        return self._body

    cpdef unicode get_encoding(self):
        ctype = self.headers.get(hdrs.CONTENT_TYPE, '').lower()
        mimetype = helpers.parse_mimetype(ctype)

        encoding = mimetype.parameters.get('charset')
        if encoding:
            try:
                codecs.lookup(encoding)
            except LookupError:
                encoding = None
        if not encoding:
            if mimetype.type == 'application' and mimetype.subtype == 'json':
                # RFC 7159 states that the default encoding is UTF-8.
                encoding = 'utf-8'
            else:
                encoding = chardet.detect(self._body)['encoding']
        if not encoding:
            encoding = 'utf-8'

        return encoding

    async def text(
            self,
            encoding: Optional[str] = None,
            errors: str = 'strict') -> str:
        """Read response payload and decode."""
        if self._body is None:
            await self.read()

        if encoding is None:
            encoding = self.get_encoding()

        return self._body.decode(encoding, errors=errors)  # type: ignore

    async def json(
            self,
            *, encoding: str = None,
            loads: JSONDecoder = DEFAULT_JSON_DECODER,
            content_type: Optional[str] = 'application/json') -> Any:
        """Read and decodes JSON response."""
        print("GETTING JSON!")
        if self._body is None:
            await self.read()

        if content_type:
            ctype = self.headers.get(hdrs.CONTENT_TYPE, '').lower()
            if not _is_expected_content_type(ctype, content_type):
                raise ContentTypeError(
                    self.request_info,
                    self.history,
                    message=('Attempt to decode JSON with '
                             'unexpected mimetype: %s' % ctype),
                    headers=self.headers)

        stripped = self._body.strip()  # type: ignore
        if not stripped:
            return None

        if encoding is None:
            encoding = self.get_encoding()

        return loads(stripped.decode(encoding))

    async def __aenter__(self) -> 'ClientResponse':
        return self

    async def __aexit__(self,
                        exc_type: Optional[Type[BaseException]],
                        exc_val: Optional[BaseException],
                        exc_tb: Optional[TracebackType]) -> None:
        # similar to _RequestContextManager, we do not need to check
        # for exceptions, response object can closes connection
        # is state is broken
        self.release()
