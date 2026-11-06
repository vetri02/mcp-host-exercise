"""Your hardened MCP host. Replace every ``NotImplementedError``.

Contract, called by ``check.py``:

- ``__init__(servers, pins, signing_key)``: ``servers`` maps a server name to
  an object with ``handle(request, headers)``; ``pins`` maps a qualified tool
  name ``server/tool`` to ``{"digest": hex, "scopes": [...]}`` as written by the
  host administrator; ``signing_key`` signs the per-server tokens you mint.
  Call ``refresh()`` at the end.
- ``refresh()``: ask every server for ``tools/list``. Keep a tool only if its
  qualified name is pinned and ``servers.digest(definition)`` equals the pin.
  Record every other announced tool in ``rejected()`` with a reason.
- ``tools_for_model()``: list of ``{"name": "server/tool", "description",
  "inputSchema"}`` for the kept tools only.
- ``rejected()``: ``{"server/tool": reason}`` for every announced tool that was
  not kept, including a pinned tool whose digest changed.
- ``call(server, tool, arguments)``: ``ValueError`` unless the tool is kept
  and ``arguments`` satisfy its pinned schema exactly (required keys present,
  no additional keys, declared types, ``maxLength``, ``pattern`` anchored).
  Send ``tools/call`` to that server and no other, with an ``authorization``
  header of ``"Bearer " + tokens.mint(sub, server, pin_scopes, ttl)`` where
  ``ttl <= tokens.MAX_TTL``. Never send ``servers.UPSTREAM_TOKEN`` anywhere.
  Return ``ToolResult(server, tool, content, trusted=False, followups=[])``
  where ``content`` is the list of text strings from the result. Ignore any
  ``next_call`` or other instruction-shaped field in the result.
"""
from collections import namedtuple

ToolResult = namedtuple("ToolResult", "server tool content trusted followups")
SUBJECT = "user-1"


class HardenedHost:
    def __init__(self, servers, pins, signing_key):
        self.servers = servers
        self.pins = pins
        self.signing_key = signing_key
        raise NotImplementedError("build your host here")

    def refresh(self):
        raise NotImplementedError

    def tools_for_model(self):
        raise NotImplementedError

    def rejected(self):
        raise NotImplementedError

    def call(self, server, tool, arguments):
        raise NotImplementedError


HOST = HardenedHost
