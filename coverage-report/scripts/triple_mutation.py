"""Third-order mutation — the last unmeasured form of masking.

Pairs were measured in all three validator corpora and found clean except for one mutual
pair in the third. Triples were left as a stated gap. This closes it for the first corpus,
where pairs are clean, so anything found here is new rather than a consequence of a pair
result.

The question is the conditional one again, lifted by a rank:

> Given an implementation that already omits *b* and *c*, is additionally omitting *a*
> detectable?

*a* is masked by {*b*, *c*} when `outcomes(drop {a,b,c}) == outcomes(drop {b,c})`.

**Only *new* masking is reported.** If *a* is already masked by *b* alone, it is unsurprising
that it is masked by {*b*, *c*} as well, and counting those would inflate the result with
restatements of a second-order fact. A triple finding counts only when neither of its
two-element subsets already masks the same obligation. In this corpus no pair masks
anything, so the filter is vacuous here — but it is written in because the same script run
against the third corpus would otherwise report derivatives of the known 363/365 pair.

Cost: every pair and every triple is evaluated once and cached, which is
C(n,2) + C(n,3) mutants rather than one per comparison.

Run: python triple_mutation.py [path-to-trace-spec]
"""

from __future__ import annotations

import ast
import itertools
import sys
import types
from pathlib import Path

from mutation_report import (
    FIXTURES,
    VERIFIER,
    Site,
    _outcomes,
    _sites,
    drop_sites,
    reconcile_or_refuse,
)


def _run(sites: tuple[Site, ...]) -> list:
    """Re-execute the verifier with an arbitrary set of emission sites neutralised.

    Shares `drop_sites` with the other two scripts. See the note there: three copies
    of one transformer is how a discovered site form goes unapplied.
    """
    mutated = drop_sites(ast.parse(VERIFIER.read_text(encoding="utf-8")), sites)
    name = "_mut3_" + "_".join(str(s.lineno) for s in sites)
    module = types.ModuleType(name)
    module.__file__ = str(VERIFIER)
    sys.modules[name] = module
    try:
        exec(compile(mutated, str(VERIFIER), "exec"), module.__dict__)  # noqa: S102
        return _outcomes(module.__dict__["_verify_fixture"])
    finally:
        del sys.modules[name]


def main() -> int:
    import test_action_receipt_fixtures as reference

    baseline = _outcomes(reference._verify_fixture)
    sites = _sites()
    index = {s.code: s for s in sites}
    codes = sorted(index)

    pairs = list(itertools.combinations(codes, 2))
    triples = list(itertools.combinations(codes, 3))
    print(f"verifier: {VERIFIER}")
    print(f"vectors:  {len(FIXTURES)}   obligations: {len(codes)}")
    reconcile_or_refuse(sites)
    if len(sites) < 3:
        print(
            f"\nREFUSING TO REPORT: {len(sites)} site(s) yields no triple to evaluate.\n"
            "\"Nothing new at rank three\" over zero third-order mutants says nothing\n"
            "about rank three.",
            file=sys.stderr,
        )
        return 2
    print(f"mutants:  {len(pairs)} pairs + {len(triples)} triples = "
          f"{len(pairs) + len(triples)}")
    print()

    pair_out = {
        frozenset(p): _run(tuple(index[c] for c in p)) for p in pairs
    }
    print(f"[pairs]   {len(pair_out)} evaluated")

    # Second-order masking, needed only to filter restatements out of the triple result.
    pair_masks: set[tuple[str, frozenset]] = set()
    single = {c: _run((index[c],)) for c in codes}
    for a, b in pairs:
        joint = pair_out[frozenset((a, b))]
        if joint == single[b]:
            pair_masks.add((a, frozenset((b,))))
        if joint == single[a]:
            pair_masks.add((b, frozenset((a,))))
    print(f"[pairs]   second-order masking: {len(pair_masks)}")
    print()

    new_masking: list[tuple[str, tuple[str, str]]] = []
    joint_invisible: list[tuple[str, ...]] = []
    for triple in triples:
        joint = _run(tuple(index[c] for c in triple))
        if joint == baseline:
            joint_invisible.append(triple)
        for dropped in triple:
            rest = tuple(c for c in triple if c != dropped)
            if joint != pair_out[frozenset(rest)]:
                continue
            # Masked by the pair. New only if neither element masks it alone.
            if any((dropped, frozenset((r,))) in pair_masks for r in rest):
                continue
            new_masking.append((dropped, rest))

    print(f"[triples] {len(triples)} evaluated")
    print()
    if joint_invisible:
        print(f"[joint] {len(joint_invisible)} triple(s) whose removal no vector notices:")
        for triple in joint_invisible:
            print(f"  {{{', '.join(triple)}}}")
    else:
        print("[joint] every triple's joint removal is noticed by some vector")
    print()
    if new_masking:
        print(f"[third-order] {len(new_masking)} obligation(s) free once a PAIR is omitted,")
        print("              and not already free once either element alone is omitted:")
        for dropped, rest in new_masking:
            print(f"  {dropped}\n      is masked by  {{{rest[0]}, {rest[1]}}}")
    else:
        print("[third-order] no obligation becomes free that a pair alone did not already")
        print("              make free. Nothing new at rank three.")

    return 1 if (new_masking or joint_invisible) else 0


if __name__ == "__main__":
    raise SystemExit(main())
