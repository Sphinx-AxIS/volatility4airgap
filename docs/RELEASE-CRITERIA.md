# From 0.5 beta to a production release candidate

**Status:** current target. Written 2026-08-17 against 0.5.0b1.

## Why not just "it works"

The tool works. It has run against real captures on an air-gapped Windows x64
workstation and produced useful findings. What is not yet known is how it behaves across
*varied* real captures, and that is the whole difference between beta and a release
candidate for this kind of software.

Two false positives have already been found and fixed this way — `smss` parented by
`smss`, and an `_EPROCESS`-shaped chunk of memory with 7,143,525 threads that sent eight
follow-up plugins hunting a process that never existed. Both were invisible to a
synthetic fixture and obvious on a real image. The question a release candidate has to
answer is whether that stream has dried up or merely paused.

So the central criterion below is not a count. It is **B4: the plateau test**. Everything
else exists to make B4 meaningful — a corpus too small or too uniform would let it pass
by accident.

## A — Corpus coverage

Counted by distinct image SHA-256, as recorded in each `run-manifest.json`.

| | Criterion | Target | Why |
| --- | --- | --- | --- |
| A1 | Distinct images analysed | **≥ 20** | Below this, B4 can pass on luck |
| A2 | Distinct Windows builds | **≥ 6**, spanning Win10, Win11 and ≥1 Server | Structure offsets and plugin behaviour vary by build; PsXView and SvcDiff have hard version floors |
| A3 | Acquisition formats | **≥ 3** of raw, VMEM+VMSS, crash dump, hibernation | The layer Volatility picks changes what resolves |
| A4 | Runs with a pagefile | **≥ 5** with, **≥ 5** without | The swap layer changes which VADs and handles resolve, and the follow-up path depends on carrying it |
| A5 | Size spread | ≥1 image **≥ 32 GB**, ≥1 **≤ 4 GB** | Timeout and scan-cost behaviour differs by an order of magnitude |
| A6 | Ground-truth images | **≥ 2** | Without these, false negatives are unmeasurable |
| A7 | Known-clean baselines | **≥ 3** | A tool that flags nothing on a clean host is as important as one that flags the right thing on a dirty one |

A6 means a capture where the malicious artefact is known independently — a deliberately
infected lab VM, or a public sample with published analysis. A7 means a freshly built,
patched host doing ordinary work.

## B — Detection quality

This is the section that decides the release.

| | Criterion | Target | Why |
| --- | --- | --- | --- |
| B1 | Rules that have fired at least once | **100%**, or a documented reason for the exception | A rule that never fires is unvalidated, not silent. `SVC-HIDDEN` was dead code for two commits and looked exactly like a quiet rule |
| B2 | Rules with ≥1 adjudicated true positive | **100% of rules that fired** | A rule that only ever produces false positives must be demoted or removed |
| B3 | Rules where false positives outnumber true positives | **0** | Better than a global FP rate: it names the rule to fix |
| B4 | **Consecutive images producing no new false-positive class** | **≥ 5** | The plateau test. See below |
| B5 | Ground-truth artefacts detected | **100%** of A6 images | False negatives are the expensive kind of wrong here |
| B6 | Findings on a clean baseline | **0 critical**, **≤ 2 high**, each explainable | Noise on a clean host destroys trust in the whole category |

**B4 in detail.** A *false-positive class* is a rule firing for a reason not previously
seen — not a repeat count. `smss`-parented-by-`smss` was one class however many times it
fired. Record each new class when found; the criterion is met when five consecutive
newly-analysed images add none. If image 18 turns up a new class, the counter resets and
the target moves to image 23.

Reset the counter on any rule-pack change that alters an existing rule's condition. New
rules start their own count.

## C — Robustness

| | Criterion | Target | Source |
| --- | --- | --- | --- |
| C1 | Unhandled exceptions across the corpus | **0** | Any traceback instead of an exit code |
| C2 | Extractor drift notices | **0** | `"no recognised … column"` in analyse output |
| C3 | Follow-up tasks failing or timing out | **< 5%**, excluding plugins absent from the run | `next-steps.json` → `status` |
| C4 | Follow-up runs > 5 min returning an empty file | **0** | The `c3426fe` failure: expensive work on a phantom entity |
| C5 | Archived runs re-analysed later that still verify | **100%** | `analysis-manifest.json` → `triage_run.inputs` |
| C6 | Rules skipped as `not_evaluated` on a full run | **0** | A plugin that always fails makes its rules permanently dead |

## D — Build and reproducibility

The gap the beta label is currently carrying.

| | Criterion | Target |
| --- | --- | --- |
| D1 | Build run on Windows x64, `payload_sha256` matching a macOS or Linux build | **verified once** |
| D2 | CI green on Windows and Linux | **configured and passing** |
| D3 | `v4ag check` passes on a bundle extracted on the target workstation | **every release** |
| D4 | Independent rebuild by a second person reproducing `payload_sha256` | **verified once** |

D1 and D4 matter more than they look: the README tells an approval authority they can
rebuild and compare digests. Until someone has, that is an assertion rather than a
property.

## What to record, per case

Most of this the tool already writes. The missing piece is adjudication — whether a
finding was right — which only a human can supply.

Already emitted, per run:

- `run-manifest.json` — image SHA-256, size, Windows build, pagefiles, per-plugin outcome
- `analysis-manifest.json` — rule pack digest, findings by severity, `rules_not_evaluated`, `plugins_missing`, input verification
- `findings/next-steps.json` — every follow-up task, its status and duration

To add by hand, one small file per case, `findings/adjudication.json`:

```json
{
  "image_sha256": "…",
  "windows_build": "10.0.19045",
  "adjudicated_by": "…",
  "verdicts": {
    "PROC-0001": {"verdict": "true_positive",  "note": "confirmed Cobalt Strike beacon"},
    "SVC-0003": {"verdict": "false_positive", "note": "vendor updater legitimately in ProgramData",
                 "new_class": true}
  }
}
```

`verdict` is `true_positive`, `false_positive` or `unknown`. `new_class` marks the first
sighting of a *kind* of false positive, and is what B4 counts.

Once a handful of these exist, a `v4ag stats <dir>...` subcommand could compute A1–A7 and
B1–B6 directly and remove the bookkeeping. Not worth building before the format has been
used on real cases.

## Not gating

Deliberately excluded, so they do not accumulate as implied blockers:

- **File entities.** No rule over FileScan or MutantScan output clears the confidence bar
  the rest of the pack is held to. Absence of a feature is not a defect.
- **Executed dumping by default.** The mechanism exists behind `--dump`. Whether a shipped
  rule should recommend it is a policy question for after the quarantine behaviour has
  been observed on a real endpoint, not a correctness question.
- **Rule count.** More rules is not better. B3 is the constraint that matters.
