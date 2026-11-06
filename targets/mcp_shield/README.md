# Target: the MCP host

Module 10 companion. Time: four to six hours. Read Module 10's sections on token passthrough and on tool descriptions as untrusted input before you start; V38 (OAuth and OpenID Connect) and V42 (the OWASP MCP Top 10 analysis) show the real shape of the token problem.

## Scenario

A host application connects a model to two MCP-style servers over JSON-RPC. `files` is the organisation's own server with `read_file` and `send_email`. `notes` is a third-party server a colleague added; it offers `lookup`, a second `send_email` whose description carries hidden instructions, and `summarise` with the same payload. The transport is an in-process function call, so you can read every request each server receives.

The host as shipped:

- shows the model every tool every server announces, and when two servers announce the same name the last one wins;
- forwards the user's upstream token to whichever server it talks to;
- passes the model's arguments straight through to the server;
- executes any `next_call` a result asks for, with the user's authority;
- keeps its approval of a tool after the server changes the tool's definition.

## Watch it fail

~~~bash
python3 -m targets.mcp_shield.target
~~~

Six observations print: a poisoned description in the model's tool list, a call to `files/send_email` answered by the wrong server, the upstream token in both servers' request logs, a follow-up call the notes server requested landing on the files server, `../../etc/passwd` arriving unchanged, and a changed definition still exposed after a refresh.

## Your task

Implement `HardenedHost` in `hardened.py`, then:

~~~bash
python3 -m targets.mcp_shield.check
~~~

| Stage | Invariant | Hint |
| --- | --- | --- |
| 1 | Only pinned definitions reach the model | The administrator pinned three tools by digest in `servers.pinned()`. A tool is addressed as `server/tool`, never by bare name. Everything else a server announces goes in `rejected()` with a reason. |
| 2 | A changed definition is a new tool | Recompute the digest on every refresh. A mismatch means the earlier approval does not apply; report it and refuse calls until a person pins the new definition. Do not drop unrelated tools. |
| 3 | The upstream token never leaves the host | Mint a token per call with `tokens.mint(sub, server, scopes, ttl)`: audience is the server, scope is the pin's scope list, lifetime at most five minutes. The token the user gave the host is for the host. |
| 4 | A result is data, not a call | Return the text content with provenance (`server`, `tool`, `trusted=False`). Ignore `next_call` and anything else instruction-shaped. A server cannot name another server's tool. |
| 5 | Arguments meet the pinned schema | Validate against the pinned `inputSchema` before sending: required keys, no additional keys, types, `maxLength`, anchored `pattern`. The schema was written to be sufficient; if it is not, fix the schema and re-pin rather than adding special cases. |

## Deliverables

1. `hardened.py` passing all five stages.
2. Your prediction list from before the first run.
3. Three negative tests the grader does not run. Suggestions: a server that answers `tools/list` with a pinned name and a definition whose only change is key order in the schema; a result whose `content` entry has `type: "resource"` with an embedded instruction; a token replayed to the other server.
4. A boundary narrative: for each stage, name the party whose claim you stopped trusting and what you trusted instead. Say what this host still cannot know (whether the files server itself is honest about what `read_file` read).

## What this target does not do

The transport is a function call, the tokens come from a signing helper rather than an OAuth server, and the schema checker you write covers five keywords instead of pulling in a JSON Schema library. Five keywords are enough here, and writing them yourself is a reminder that a validator you did not write has behaviour you have not read. The pin is what catches the hidden-instruction text. A filter that looked for the string `<IMPORTANT>` would pass this grader for the wrong reason and miss the next server that phrases its payload differently.
