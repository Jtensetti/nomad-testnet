"""A second implementation of the renderer URL gate.

Written from the published decision corpus and the rules stated in
docs/ and in egress/policy.go's *documentation*, not by transliterating the Go.
The corpus is the specification here: each case names a URL, the decision, and
why. An implementation that agreed with the Go by construction would test
nothing, so this parses URLs with Python's own urllib and normalises paths with
Python's own posixpath, and where the two languages disagree that disagreement
is the finding.

It shares no code with the Go implementation and depends on nothing outside the
Python standard library.

FINDINGS while writing this:

1. The corpus says a "nomad:" URL with a host is denied, which reads as a rule
   about hosts. It is really a rule about *authority*: "nomad://host/x" and
   "nomad://user@host/x" both carry one. Python's urlsplit exposes netloc for
   both, so the rule is written against netloc rather than against a hostname,
   and the two implementations agree only because Go checks User and Host
   separately. A third implementer reading "no host" would likely miss userinfo.

2. Path canonicalisation is not the same operation in both languages.
   Go's path.Clean and Python's posixpath.normpath differ on a trailing slash:
   normpath("/a/") is "/a", Clean("/a/") is "/a" -- they agree there -- but
   normpath("//a") is "//a" while Clean("//a") is "/a". POSIX reserves a leading
   double slash. The corpus contains "//" cases and the rule that reconciles
   them is "reject any empty segment", which is stated directly here rather than
   inherited from whichever normaliser the language provides.

3. A data: URL's media type is compared case-insensitively and its parameters
   are ignored, but ";base64" is a transfer encoding rather than a parameter and
   is stripped before parsing. Reading only the corpus, ";base64" looks like a
   parameter that happens to be allowed everywhere.

4. The corpus caught two bugs in this file on its first run, and both are
   mistakes a third implementer would make:

   "nomad:/" -- the bundle root -- was denied here for having an empty segment,
   because "/".split("/") is ["", ""]. The root is the one path that is
   trivially canonical, and whether a resource exists at it is the adapter's
   lookup rather than this gate's.

   "data:text/plain;base64;charset=x,y" was *allowed* here, by taking the text
   before the first ";" as the media type. That is a prefix match, and a prefix
   match is how a scriptable type gets through: the header is not a media type
   at all, and only parsing the whole of it refuses. The corpus case says so in
   its own "why", which is what made the disagreement legible instead of
   puzzling.
"""

from __future__ import annotations

import posixpath
import urllib.parse

MAX_RESOURCE_PATH = 4096

# The non-scriptable allowlist. A data: URL is its own document with an opaque
# origin, so it does not inherit the adapter's Content-Security-Policy: a
# scriptable type here would run unconstrained by that header.
ALLOWED_DATA_MEDIA_TYPES = frozenset({
    "text/plain",
    "text/css",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
    "font/woff",
    "font/woff2",
    "font/ttf",
    "font/otf",
    "application/pdf",
})


class Denied(Exception):
    """A URL this implementation refuses, with the reason."""


def canonical_resource_path(resource_path: str) -> None:
    """The rule a resolved local path must satisfy. Raises Denied."""
    if resource_path == "":
        raise Denied("resource path is empty")
    if len(resource_path.encode()) > MAX_RESOURCE_PATH:
        raise Denied("resource path is too long")
    if not resource_path.startswith("/"):
        raise Denied("resource path must be absolute")
    # Backslash is refused because platforms disagree about whether it is a
    # separator, and a rule that means different things on different platforms
    # is not a rule.
    for forbidden in ("\\", "?", "#", "\x00"):
        if forbidden in resource_path:
            raise Denied("resource path contains URL syntax or a separator alias")
    for character in resource_path:
        if ord(character) < 0x20 or ord(character) == 0x7F:
            raise Denied("resource path contains a control character")
    # Stated directly rather than delegated to a normaliser: no "..", no ".",
    # and no empty segment, which covers "//" wherever it appears.
    #
    # The root is the exception and it is not a special case being made to fit:
    # "/" is one empty segment by the split, and it is also the one path that
    # is trivially canonical. Whether a resource exists there is the adapter's
    # lookup to answer, not this gate's.
    if resource_path != "/":
        segments = resource_path.split("/")
        if segments[0] != "":
            raise Denied("resource path must be absolute")
        for segment in segments[1:]:
            if segment == "":
                raise Denied("resource path has an empty segment")
            if segment in (".", ".."):
                raise Denied("resource path is not canonical")
    if posixpath.normpath(resource_path) != resource_path:
        raise Denied("resource path is not canonical")


def _check_data_url(opaque: str) -> None:
    comma = opaque.find(",")
    if comma < 0:
        raise Denied("malformed data URL")
    header = opaque[:comma]
    # ";base64" is a transfer encoding, not a media-type parameter, so it is
    # stripped before the type is parsed.
    if header.endswith(";base64"):
        header = header[: -len(";base64")]
    if header == "":
        # No media type means text/plain, which is allowed.
        return
    # The whole header has to parse, not just its first token. Taking the
    # prefix before the first ";" and calling it the media type is exactly how
    # a scriptable type slips past: "text/plain;base64;charset=x" has an
    # allowed prefix and a header that is not a media type at all.
    parts = header.split(";")
    media_type = parts[0].strip().lower()
    if "/" not in media_type or media_type.count("/") != 1:
        raise Denied("unparsable data URL media type")
    type_part, subtype = media_type.split("/")
    if type_part == "" or subtype == "":
        raise Denied("unparsable data URL media type")
    for parameter in parts[1:]:
        name, separator, value = parameter.partition("=")
        if separator != "=" or name.strip() == "" or value == "":
            raise Denied("unparsable data URL media type: malformed parameter")
    if media_type not in ALLOWED_DATA_MEDIA_TYPES:
        raise Denied(f"data URL media type {media_type!r} is not in the allowlist")


def check_renderer_url(raw: str) -> None:
    """Decide one URL a renderer might dispatch. Raises Denied to refuse."""
    if len(raw.encode()) > MAX_RESOURCE_PATH:
        raise Denied("URL is too long")
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError as failure:
        raise Denied("malformed URL") from failure

    scheme = parsed.scheme.lower()
    if scheme == "nomad":
        # netloc rather than hostname: "nomad://user@host/x" carries authority
        # too, and a rule written against hosts alone would miss it.
        if parsed.netloc != "":
            raise Denied("invalid local Nomad URL: it carries authority")
        if parsed.query != "" or "?" in raw:
            raise Denied("invalid local Nomad URL: a query is reader state")
        if parsed.fragment != "" or "#" in raw:
            raise Denied("invalid local Nomad URL: it carries a fragment")
        # urlsplit puts a scheme-relative path in .path only when the URL had a
        # "//"; for "nomad:/x" the path is "/x" and for "nomad:x" it is "x",
        # which the absolute-path rule then refuses.
        path = urllib.parse.unquote(parsed.path)
        canonical_resource_path(path)
        return
    if scheme == "data":
        _check_data_url(raw[len("data:"):])
        return
    if scheme == "about":
        if raw == "about:blank":
            return
        raise Denied("only about:blank is allowed")
    raise Denied(f"scheme {parsed.scheme!r}")


def allows(raw: str) -> bool:
    try:
        check_renderer_url(raw)
    except Denied:
        return False
    return True
