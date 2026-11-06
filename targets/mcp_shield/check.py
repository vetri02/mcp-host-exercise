"""Grader for the MCP shield target.

    python3 -m targets.mcp_shield.check
    python3 -m targets.mcp_shield.check --solution targets.mcp_shield.target
"""
import argparse
import importlib
import sys
import time

from . import servers as srv, tokens

FLAGS = {
    1: "FLAG{shd1-only-pinned-definitions-reach-the-model}",
    2: "FLAG{shd2-a-changed-definition-is-a-new-tool}",
    3: "FLAG{shd3-the-upstream-token-never-leaves-the-host}",
    4: "FLAG{shd4-a-result-is-data-not-a-call}",
    5: "FLAG{shd5-arguments-meet-the-pinned-schema}",
}


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def expect_value_error(fn, label):
    try:
        fn()
    except ValueError:
        return
    except Exception as e:
        raise AssertionError("%s raised %s, expected ValueError" % (label, type(e).__name__))
    raise AssertionError("%s was accepted" % label)


def names(host):
    return sorted(t["name"] for t in host.tools_for_model())


def stage_1(host, s):
    """Only pinned definitions reach the model; shadows and poisoned tools are rejected."""
    check(names(host) == ["files/read_file", "files/send_email", "notes/lookup"],
          "model sees %r" % names(host))
    for t in host.tools_for_model():
        check("<IMPORTANT>" not in t["description"], "%s carries hidden instructions" % t["name"])
    rej = host.rejected()
    for q in ("notes/send_email", "notes/summarise"):
        check(q in rej and rej[q], "%s not recorded as rejected with a reason" % q)
    expect_value_error(lambda: host.call("notes", "send_email", {"to": "a@example.com", "body": "x"}),
                       "call to the unpinned shadow tool")
    expect_value_error(lambda: host.call("notes", "summarise", {"text": "x"}), "call to a poisoned tool")
    check(not s["notes"].calls, "notes server received a call it should not have")


def stage_2(host, s):
    """A changed definition is a new tool: the old approval does not carry over."""
    s["files"].rug_pull()
    host.refresh()
    check("files/read_file" not in names(host), "changed read_file still exposed")
    rej = host.rejected()
    check("files/read_file" in rej and rej["files/read_file"], "changed read_file not reported")
    before = len(s["files"].calls)
    expect_value_error(lambda: host.call("files", "read_file", {"path": "docs/a.txt"}),
                       "call to the changed tool")
    check(len(s["files"].calls) == before, "the changed tool was still called")
    check("files/send_email" in names(host), "an unrelated tool was dropped by the change")
    s["files"].restore()
    host.refresh()
    check("files/read_file" in names(host), "restored definition not re-admitted")
    r = host.call("files", "read_file", {"path": "docs/a.txt"})
    check(r.content == ["contents of docs/a.txt"], "restored tool returned %r" % (r.content,))


def _auth_claims(server):
    req, headers = server.requests[-1]
    auth = headers.get("authorization", "")
    check(srv.UPSTREAM_TOKEN not in auth, "upstream token forwarded to %s" % server.name)
    check(auth.startswith("Bearer "), "no bearer token sent to %s" % server.name)
    return tokens.decode(auth[len("Bearer "):])


def stage_3(host, s):
    """The upstream token never leaves the host; each server gets its own short, scoped token."""
    for server in s.values():
        for _, headers in server.requests:
            check(srv.UPSTREAM_TOKEN not in headers.get("authorization", ""),
                  "upstream token was sent to %s during tools/list" % server.name)
    host.call("files", "read_file", {"path": "docs/a.txt"})
    c1 = _auth_claims(s["files"])
    check(c1.get("aud") == "files", "files token audience is %r" % c1.get("aud"))
    check(c1.get("scope") == ["files:read"], "files token scope is %r" % c1.get("scope"))
    check(0 < c1.get("exp", 0) - c1.get("iat", 0) <= tokens.MAX_TTL, "files token lifetime too long")
    check(c1.get("exp", 0) > int(time.time()) - 1, "files token already expired")
    host.call("notes", "lookup", {"query": "retention"})
    c2 = _auth_claims(s["notes"])
    check(c2.get("aud") == "notes", "notes token audience is %r" % c2.get("aud"))
    check(c2.get("scope") == ["notes:read"], "notes token scope is %r" % c2.get("scope"))
    host.call("files", "send_email", {"to": "ops@example.com", "body": "hello"})
    c3 = _auth_claims(s["files"])
    check(c3.get("scope") == ["mail:send"], "send_email token scope is %r" % c3.get("scope"))


def stage_4(host, s):
    """A result is data, not a call: nothing a server asks for runs with the user's authority."""
    s["files"].calls.clear()
    r = host.call("notes", "lookup", {"query": "retention"})
    check(not s["files"].calls, "a follow-up call reached the files server: %r" % s["files"].calls)
    check(r.server == "notes" and r.tool == "lookup", "result provenance is %r/%r" % (r.server, r.tool))
    check(r.trusted is False, "a server result was marked trusted")
    check(not r.followups, "follow-ups were executed: %r" % (r.followups,))
    check(isinstance(r.content, list) and all(isinstance(c, str) for c in r.content),
          "content is not a list of strings")
    check(r.content and "30 days" in r.content[0], "the text content was lost")
    check("next_call" not in repr(r), "next_call was passed on to the model")
    # A result cannot borrow another server's name either.
    expect_value_error(lambda: host.call("notes", "read_file", {"path": "docs/a.txt"}),
                       "calling a files tool through the notes server")


def stage_5(host, s):
    """Arguments meet the pinned schema before any server sees them."""
    before = len(s["files"].calls)
    bad = [("path climbing", {"path": "../../etc/passwd"}),
           ("undeclared field", {"path": "docs/a.txt", "mode": "raw"}),
           ("wrong type", {"path": 42}),
           ("missing required", {}),
           ("over length", {"path": "a" * 200}),
           ("absolute path", {"path": "/etc/passwd"})]
    for label, args in bad:
        expect_value_error(lambda: host.call("files", "read_file", args), label)
    expect_value_error(lambda: host.call("files", "send_email", {"to": "x@evil.test", "body": "hi"}),
                       "recipient outside the declared pattern")
    check(len(s["files"].calls) == before, "a rejected call still reached the server")
    r = host.call("files", "read_file", {"path": "docs/a.txt"})
    check(s["files"].calls[-1] == ("read_file", {"path": "docs/a.txt"}),
          "server received %r" % (s["files"].calls[-1],))
    check(r.content == ["contents of docs/a.txt"], "valid call returned %r" % (r.content,))


def run(module_name="targets.mcp_shield.hardened"):
    mod = importlib.import_module(module_name)
    cls = getattr(mod, "HOST")
    s = srv.make_servers()
    try:
        host = cls(s, srv.pinned(), tokens.SIGNING_KEY)
    except NotImplementedError as e:
        return [(n, False, "not implemented: %s" % e) for n in FLAGS]
    results = []
    for n, fn in ((1, stage_1), (2, stage_2), (3, stage_3), (4, stage_4), (5, stage_5)):
        try:
            fn(host, s)
            results.append((n, True, fn.__doc__.split("\n")[0]))
        except Exception as e:
            results.append((n, False, "%s: %s" % (type(e).__name__, e)))
    return results


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--solution", default="targets.mcp_shield.hardened", help="module exposing HOST")
    args = p.parse_args(argv)
    results = run(args.solution)
    passed = 0
    for n, ok, msg in results:
        if ok:
            passed += 1
            print("stage %d  PASS  %s\n         %s" % (n, msg, FLAGS[n]))
        else:
            print("stage %d  FAIL  %s" % (n, msg))
    print("%d of %d stages passed" % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
