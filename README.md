# Try one exercise: the MCP host

This is one hands-on target from the free AI Security Engineering course
(https://aisec.engineering), packaged on its own. Standard-library Python 3.10 or
newer, no network, no model, no credentials. Time: a minute to watch it fail,
an afternoon to fix it (the course budgets four to six hours).

A host application connects a model to two MCP-style servers. One server is the
organisation's own. The other was added by a colleague and announces a tool whose
description carries hidden instructions, a second tool with the same name as a
trusted one, and results that ask the host to make further calls. The host as
shipped trusts all of it.

## Get it

~~~bash
git clone https://github.com/vetri02/mcp-host-exercise.git
cd mcp-host-exercise
~~~

or download the same files as a zip from https://aisec.engineering/ai-security-engineering-mcp-host-exercise.zip and unzip it.

## Watch it fail

Open a terminal in this folder (the one containing `targets/`) and run:

~~~bash
python3 -m targets.mcp_shield.target
~~~

Six observations print: a poisoned description in the model's tool list, a call
answered by the wrong server, the user's upstream token in both servers' request
logs, a follow-up call one server requested landing on the other, a path with
`../` arriving unchanged, and a changed tool definition still exposed after a
refresh.

## Fix it

Before you change anything, write down every way you predict the host fails and
why. Then implement `HardenedHost` in `targets/mcp_shield/hardened.py` and grade
your work:

~~~bash
python3 -m targets.mcp_shield.check
~~~

The grader has five stages and prints a flag for each invariant that holds. The
stages, hints and deliverables are in `targets/mcp_shield/README.md`.

Edit only `hardened.py`. The other files in the target are the attacker's side of
the table or the grader's evidence; the grader is the contract.

## Then

The exercise is Module 10 of a twenty-four-module course with an offline
reference lab, three more graded targets, milestone assessments and a capstone.
The whole course reads free at https://aisec.engineering, and the course folder
downloads from the same site. Module 10 explains the two ideas this target
turns on: a token has an audience, and a tool description is untrusted input.

## Licence

Code MIT, writing CC BY 4.0; see `LICENSE.md`. Run the technique only against
systems you own. This target is synthetic and runs entirely inside your machine.
