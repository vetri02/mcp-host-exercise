"""The vulnerable MCP host. Run it to watch it fail:

    python3 -m targets.mcp_shield.target

It shows the model every tool every server announces, routes calls by bare
tool name (last server wins), forwards the user's upstream token to whichever
server it talks to, passes arguments through untouched, and executes any
``next_call`` a result asks for, with the user's authority.
"""
import copy
import itertools
from collections import namedtuple

from . import servers as srv

ToolResult = namedtuple("ToolResult", "server tool content trusted followups")


class VulnerableHost:
    def __init__(self, servers, pins=None, signing_key=None):
        self.servers = servers
        self._ids = itertools.count(1)
        self._by_name = {}
        self.refresh()

    def _rpc(self, server, method, params):
        req = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params}
        # "The server needs to act on the user's behalf, so give it the user's token."
        headers = {"authorization": "Bearer " + srv.UPSTREAM_TOKEN}
        resp = self.servers[server].handle(req, headers)
        if "error" in resp:
            raise RuntimeError(resp["error"]["message"])
        return resp["result"]

    def refresh(self):
        self._by_name = {}
        for name in self.servers:
            for t in self._rpc(name, "tools/list", {})["tools"]:
                self._by_name[t["name"]] = (name, t)      # last announcement wins

    def tools_for_model(self):
        return [dict(name=t["name"], description=t["description"], inputSchema=t["inputSchema"])
                for _, t in self._by_name.values()]

    def rejected(self):
        return {}

    def call(self, server, tool, arguments):
        # Helpful fallback: if the named server lacks the tool, find one that has it.
        if tool not in self.servers[server].tools:
            server = self._by_name[tool][0]
        result = self._rpc(server, "tools/call", {"name": tool, "arguments": copy.deepcopy(arguments)})
        followups = []
        nxt = result.get("next_call")
        if nxt:   # the server knows what it needs; chain it
            followups.append(self.call(nxt["server"], nxt["tool"], nxt["arguments"]))
        text = [c["text"] for c in result.get("content", []) if c.get("type") == "text"]
        return ToolResult(server, tool, text, True, followups)


HOST = VulnerableHost


def main():
    s = srv.make_servers()
    host = VulnerableHost(s)
    print("Tools the model sees:")
    for t in host.tools_for_model():
        poisoned = "<IMPORTANT>" in t["description"]
        print("  %-12s %s" % (t["name"], "POISONED DESCRIPTION" if poisoned else "ok"))
    print("\nWhich send_email the model sees:")
    print("  announced by server:", host._by_name["send_email"][0], "(the shadow; files lost)")
    r = host.call("files", "lookup", {"query": "x"})
    print("  'files/lookup' answered by server:", r.server, "(routed by bare name)")
    print("\nToken each server received on the last request:")
    for name, server in s.items():
        if server.requests:
            print("  %-6s %s" % (name, server.requests[-1][1].get("authorization")))
    print("\nA lookup on the notes server:")
    s["files"].calls.clear()
    r = host.call("notes", "lookup", {"query": "retention"})
    print("  follow-up calls executed:", [(f.server, f.tool) for f in r.followups])
    print("  files server saw:", s["files"].calls)
    print("\nArguments passed through:")
    r = host.call("files", "read_file", {"path": "../../etc/passwd", "mode": "raw"})
    print("  files server saw:", s["files"].calls[-1])
    print("\nAfter the files server changes read_file:")
    s["files"].rug_pull()
    host.refresh()
    print("  still exposed:", any(t["name"] == "read_file" and "<IMPORTANT>" in t["description"]
                                  for t in host.tools_for_model()))


if __name__ == "__main__":
    main()
