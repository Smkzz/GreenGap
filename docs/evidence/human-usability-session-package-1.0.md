# GreenGap 1.0 human usability session package

This packet is for five fresh-context consenting human evaluators. AI agents,
maintainers, and the facilitator do not count as evaluators. Do not request
credentials, public publication, a merge, or execution of an untrusted
checkout.

## Session objective

Each evaluator must use the packaged `1.0.0rc1` candidate outside an editable
source tree and complete:

1. install and version check;
2. the safe first run with `--no-collect`;
3. interpretation of an `INCOMPLETE`/exit-2 result;
4. a disposable workflow integration exercise without maintainer intervention;
5. an explanation that `--trust-collection` executes repository code with the
   caller's permissions and is not a sandbox.

The launch threshold is at least four of five successful integrations and all
five evaluators understanding the collection execution boundary.

## Facilitator setup

Use a wheel built from the frozen candidate and verify its SHA-256 against the
candidate artifact receipt before each session. Use a disposable directory and
an evaluator-controlled Python environment. The facilitator may explain the
task wording, but must not repair a failed installation or integration during
the timed exercise. Record the exact candidate SHA, wheel hash, operating
system, Python version, and install command.

The supplied integration exercise should use a disposable fixture repository.
It must not expose production credentials or ask the evaluator to run target
collection. The workflow snippet should reference the documented immutable
release-tag form with clearly marked placeholders; because this candidate is
unpublished, the session must not substitute `main`, create a tag, or contact
PyPI.

## Evaluator task card

Read only this task card before starting:

```text
You have received a packaged GreenGap release candidate. Install it in a
disposable Python environment, run its safest first command against the
provided fixture, and explain the result to a teammate. Then add the supplied
GreenGap reusable-workflow job to the fixture's workflow using the documented
immutable-release form. Do not run pytest collection, publish anything, or ask
the facilitator to fix your steps. Tell us what --trust-collection would do
before you finish.
```

Suggested commands, shown only after the evaluator has chosen a first command:

```powershell
python -m pip install --no-deps --force-reinstall .\greengap-1.0.0rc1-py3-none-any.whl
greengap --version
greengap plan . --no-collect --json
```

The expected safe-default result is exit code `2` with `INCOMPLETE` evidence;
that is not a test failure. The evaluator should identify the reason rather
than attempt `--trust-collection` on an arbitrary checkout.

## Worksheet

One copy is completed per evaluator. Use a session ID unrelated to the
evaluator's name.

```text
Session ID:
Consent recorded: yes / no
Candidate SHA and wheel SHA-256:
OS and version:
Python version:
Install method and first command chosen:
Install completed without facilitator intervention: yes / no
Version output understood: yes / no
Safe-default outcome and exit code understood: yes / no
Workflow integration completed without maintainer intervention: yes / no
Evaluator explained that trusted collection executes repository code: yes / no
Evaluator understood that a virtual environment is not a sandbox: yes / no
Confusion or accessibility issue:
Time to install and first understood result:
Facilitator intervention (should be limited to safety/consent):
```

## Consent and privacy

Participation is voluntary. Explain that the exercise records environment and
task outcomes, not personal identity in the retained receipt. Do not retain
source checkouts, shell history, tokens, home-directory paths, or raw reports
unless the evaluator explicitly consents and they are redacted first. A
participant may stop at any time. Report accessibility barriers and negative
experiences without identifying the evaluator.

## Acceptance and result handling

Count a session as successful only when installation, result interpretation,
and the integration exercise all complete without maintainer repair. Count
the trust-boundary item separately and require five of five. Record failures
and withdrawals; do not average them away. Agent simulations may be retained
as development notes, but must be labelled separately and never added to the
human totals.

The final human receipt must include the five session rows, the aggregate
counts, the exact candidate identity, the consent/privacy procedure, and any
open usability or accessibility issue. Until that receipt exists, the human
launch gate remains `UNKNOWN`.
