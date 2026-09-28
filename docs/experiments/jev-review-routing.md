# Jev review-depth experiment

Recorded 2026-09-28 for transfer to the `metaprompts` cross-project agent. This is an
experiment history and handoff, not a permanent engineering policy. The user has requested
expansion to all projects; the implementation of that expansion belongs to `metaprompts`.

## Purpose and boundaries

We are testing whether Jev provides useful advice about the depth of independent review for a
coherent software change, beyond the implementing agent's own judgment. We measure consequential
findings, missed issues, review effort, and unnecessary implementation complexity. Agreement
with the author alone is not success.

This is not a comparison of author models. Codex and Claude both contributed because a Codex
outage interrupted development. Author and reviewer identities are contextual metadata; task
mix, related changes, and incomplete model-version records prevent controlled model comparisons.

Jev is advisory. It does not approve commits, authorize mutations, dispatch reviewers, or impose
human sign-off. Existing mandatory safety and review rules still apply. Missing evidence,
low confidence, or an unavailable service never means a change is safe to skip reviewing.

Project tracking is in archive-ledger Bead `al-hk1`. Its completed children are `al-hk1.1`
(first evaluation), `al-hk1.2` (round-two setup), and this documentation/handoff task `al-hk1.3`.
Use `bd -C /home/ubuntu/projects/archive-ledger show al-hk1` for the current durable context.

## Round one: method and results

The prospective trial began on 2026-09-25. A four-case exploratory pilot preceded it and is
excluded from its results. We adapted the TypeSafe community PR-review questions to whole
commits, without adopting automatic human-review gates. The pinned upstream material is
retained with the experiment evidence.

For every prospective commit we froze its diff and verification evidence, recorded the
author's recommendation before consulting Jev, excluded that recommendation and rationale
from Jev's input, and retained Jev's full response separately from the final routing decision.
We recorded review findings and bound the assessed and final diffs to exact Git commits.
Actual review moved to coherent feature/bug-fix boundaries, so a review could cover several
commits even though Jev still assessed individual commits in round one.

Rubric v1 asked about safety, possible bugs, missing tests, security, compatibility,
generated/vendor code, missing context, and review depth. V2 added review timing. Run one
used v1 plus a separate timing supplement; subsequent runs used v2. The depth threshold
remained `.65`, using `min(selected probability, reported confidence)`.

At the 2026-09-27 checkpoint:

| Measure | Result |
|---|---:|
| Prospective commits | 21 |
| Author recommendations: focused / self | 11 / 10 |
| Successful original Jev requests | 20 |
| Successful raw Jev routes | 20 focused; none self or deep |
| Effective Jev routes | 14 focused; 6 below threshold; 1 unavailable |
| Final routing: focused / self | 15 / 6 |
| Distinct focused feature reviews | 13, covering 15 commits |
| Reviews recording findings / P2 findings | 12 / 8 |

Four reviews were added over author self-review recommendations. The dry-run preview review
found two unambiguous P2s and one P2/P3 item counted as P2 in its outcome; the other three
added reviews produced P3 findings. Across all focused reviews, outcome summaries count
14 P2s, while detailed records support 13 unambiguous P2s plus that mixed item. Do not count
the shared `al-m1q` and `al-4ph` feature reviews twice.

The repair feature received Jev certainty `.59`, below threshold, although its focused
review found three P2s. Its probability distribution was self `.00`, focused `.70`, deep `.30`:
uncertainty about depth differed from evidence against independent review. Jev never positively
selected `possible_bug` in the 20 successful original calls. Its observed benefit was review
and coverage advice, not specific bug diagnosis or calibrated probabilities of defects.

All successful responses resolved to `typesafe/jev-1.13-20260917`. Original successful calls
cost `$0.007887474`, with median provider latency 450 ms. Including the timing supplement
and late retry, recorded cost was `$0.009044448`. These figures exclude review and orchestration
cost. Review-time records were incomplete or inconsistent, so net time savings cannot be
estimated reliably. The failed request's later successful retry is retained as retrospective;
it does not replace the unavailable prospective result.

### Audit of skipped reviews

A separate reviewer audited all six self-routed original changes. The primary independently
reproduced two findings with disposable archives:

| Original change | Jev certainty | Finding | Fixed by |
|---|---:|---|---|
| `3979ad0`, unfinished-scan guard | `.91`, focused overridden by author | P2: rebuilding removed job rows, allowing a duplicate scan that then blocked original resume | `al-8rt`, `54e26a8` |
| `fdc120a`, lifecycle guide | `.64`, below threshold | P1: inherited `ARCHIVE_LEDGER_ARCHIVE` redirected test mutations into the caller-selected catalog | `al-fa2`, `8118079` |

Both defects are fixed. Their regressions failed before and passed after the fixes; independent
focused reviews found no actionable issues in the corrections. The other four skipped changes
had no substantive audit findings. These observations do not establish a general miss rate,
and Jev did not itself diagnose either bug.

The full checkpoint report is the authoritative detailed analysis. It predates these fixes
and round-two activation; statements there that the bugs remain open describe that earlier
snapshot. Other limitations include a small nonrandom sample, dependent changes, selective
review, author-written context, incomplete exact model identities, and review summaries rather
than complete reviewer transcripts. All 21 final Git diff bindings were verified.

## Round two: approved and active

The user approved round two on 2026-09-28. Both author/Jev assessments and actual reviews now
occur at the smallest coherent feature or bug-fix boundary. Intermediate commits keep their
feature association without requiring another Jev call. Consequential actions can require an
earlier checkpoint, which must not be double-counted as another feature.

The exact frozen questions and choices are in `rubric-v3.json`:

| Question identifier | Purpose |
|---|---|
| `independent_review_value` | Whether another reader adds material value, separately from depth |
| `review_route` | Least costly sufficient depth: self / focused / deep / insufficient |
| `consequential_boundary` | Unverified user-data, isolation, recovery, security, or consumer boundary |
| `missing_test` | Specific important verification gap, considering existing evidence |
| `needs_context` | Essential missing evidence rather than ordinary uncertainty |
| `unnecessary_complexity` | Implementation burden disproportionate to the stated requirement |

Inputs include the complete feature diff, purpose, affected boundaries and consumers,
structured related-commit and prior-review context, and actual tested/untested behavior.
Current author recommendations, risk ratings, and future review outcomes stay out of Jev's
input. Preserve exact inputs/questions, all answers and distributions, requested/resolved
model, usage, latency, errors, decisions, findings, and final commit-range bindings.

The frozen hypothetical policies use thresholds `.50`, `.65`, and `.85`. A valid depth
above threshold is hypothetically adopted; below threshold, insufficient, malformed, or
unavailable responses fall back to the author's recommendation recorded beforehand. Mandatory
review requirements remain a floor. Baselines are author judgment alone and focused review
for every feature. Other question answers are diagnostics, not automatic gates. Actual review
depth remains a separately recorded author decision.

Audit every second new feature whose actual pre-audit decision would be self-review, ordered
by final-decision time and selected before seeing outcomes. Keep audit coverage distinct from
the operational routing decision. Record reviewer identity, measured start/end/duration and
unknown portions; record findings, attribution, fix complexity, and whether suggestions were
fixed, simplified, accepted, or rejected. Substantive reviewer suggestions receive a separate
complexity assessment before choosing their implementation; never add them to the original
pre-review input. No findings does not automatically mean a review was wasted.

The target is **12 new feature boundaries**, with a process-quality check after 6. The earlier
check is for outages, incomplete evidence, and recording problems, not threshold tuning.
Substantive changes require separate versioning. The two known-defect fixes are shakedown
cases excluded from the target and audit counter:

| Assessment | Jev route / certainty | Timing | Review outcome |
|---|---|---|---|
| `al-fa2-01` | focused / `.74` | Post-routing due to export-approval delay | No findings; 23 seconds |
| `al-8rt-01` | focused / `.93` | Author → Jev → final decision → review | No findings; 54 seconds |

As of this record, **0/12 new features** have been collected. All six answers, input/rubric
hashes, reviews, checks, and exact commit bindings are retained for both shakedown cases.

### Planned retrospective replay

At the next evaluation, replay **all 21 original frozen round-one inputs** with v3 questions.
Preserve their original evidence and commit boundaries; exclude later fixes, findings, and
audit outcomes. This is an exploratory paired comparison, not held-out prospective evidence:
round one informed the revised questions. Report all frozen threshold policies, record the
resolved Jev version, and disclose any model change as another difference.

An optional reconstruction of completed round-one feature boundaries is a separate comparison
using only evidence available at each original boundary. Do not mix changed questions and
changed context and then attribute the result solely to the questions. The replay has not run.

## Evidence and execution locations

The retained host-local root is:

```text
/home/ubuntu/tmp/archive-ledger-al-hk1-review-8URfIdEU
```

These files are intentionally outside the product repository. Paths below are relative to
that root; the current JSON protocol and rubric are authoritative for execution.

| Path | Contents |
|---|---|
| `protocol.json` | Active round-two protocol and status |
| `protocol-round1.json` | Preserved round-one protocol |
| `rubric-v1.json`, `rubric-v2.json`, `rubric-v3.json` | Exact versioned questions and routing definitions |
| `records.jsonl` | Original append-only round-one journal |
| `al-*/` | Round-one frozen inputs, responses, patches, review artifacts and checks |
| `evaluation-2026-09-27.md`, `.json` | First checkpoint analysis and structured record |
| `evaluation-2026-09-27-repro.py`, `.log` | Independent audit reproductions and output |
| `round2/protocol.json`, `round2/records.jsonl` | Active protocol copy and separate round-two journal |
| `round2/assess-feature.py` | Local assessment helper: freeze author/input, call Jev, record shadow routes |
| `round2/al-fa2-01/`, `round2/al-8rt-01/` | Known-defect assessment, review, verification and commit-binding evidence |
| `upstream/`, `exploratory-pilot/` | Pinned question source and excluded initial pilot |

Evidence owner is `Codex/al-hk1`. Retain the root until the experiment is adopted or rejected
and useful evidence is archived. A fleet implementation must preserve this provenance and
record any new location; do not delete or rewrite the original journals during migration.

The existing provider is OpenRouter's Decisions API through
`/home/ubuntu/projects/jev-experiments/jev.py:decide`, using that project's existing local
credentials and virtual environment. Never copy credentials into documentation, tasks, logs,
or payloads. Import with `PYTHONDONTWRITEBYTECODE=1`; do not call `log_result`, which writes
into the sibling repository. Requested model is `~typesafe/jev-latest`; retain its resolved
version. Oversized inputs are not silently truncated; errors permit one bounded retry and
otherwise remain unavailable.

The user explicitly authorized the lifecycle payload and equivalent round-two feature
assessments to OpenRouter on 2026-09-28. An earlier automatic export rejection delayed the
first shakedown response; that response is correctly labeled post-routing. Preserve applicable
project data boundaries and do not include unrelated data or secrets in future payloads.

The helper is a host-specific experiment tool, not a finished fleet service: paths and cwd
assumptions are local, and final decisions, audit selection, review outcomes, measured time,
and commit bindings have also been recorded by the primary agent. Inspect the protocol and
actual events rather than assuming the helper implements the complete workflow.

## Cross-project expansion handoff

The metaprompts agent should extend this advisory experiment through the shared harness's
normal adoption mechanisms. It owns project discovery, a proportionate reusable integration,
project-scoped adoption and verification, and durable evaluation tracking. The archive-ledger
agent is documenting and creating the task, not deploying that expansion itself.

Before collecting fleet results, explicitly define repository/feature identifiers, ownership,
concurrent record handling, and whether evaluation/audit counters are portfolio-wide or
per-project. Preserve the existing archive-ledger counts and distinguish historical,
retrospective, shakedown, and new prospective evidence. Keep v3 and the shadow thresholds
frozen; separately version any necessary changes. Carry forward source-model metadata without
turning the experiment into an author-model comparison.

Reuse existing tools and supported harness mechanisms before introducing infrastructure.
Expansion of an experiment is not evidence for a permanent automatic gate, and does not waive
project-specific authority, safety rules, or credential boundaries. Record adoption scope and
verification so a future evaluator can distinguish intended policy from actual execution.
