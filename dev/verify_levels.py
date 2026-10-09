"""Run the reference solvers over train seeds and report solve rates per level.

    python dev/verify_levels.py --level 2 --seeds 0 50 [--budget-s 1800] [--out results.jsonl]

A task counts as solved when the solver's key scores reward >= 0.95.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import solve  # noqa: E402
import tasks  # noqa: E402
from enigma_env import score_key  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", type=int, required=True)
    ap.add_argument("--seeds", type=int, nargs=2, default=[0, 50])
    ap.add_argument("--budget-s", type=float, default=None)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = open(a.out, "a") if a.out else None
    for seed in range(*a.seeds):
        task = tasks.build_task(a.level, seed)
        t0 = time.time()
        deadline = t0 + a.budget_s if a.budget_s else None
        if task["cribs"]:
            key, n_cand = solve.solve_crib(task, deadline=deadline)
        else:
            key, n_cand = solve.solve_cto(task, deadline=deadline)
        dt = time.time() - t0
        s = score_key(task, key) if key else {"reward": 0.0, "accuracy": 0.0}
        rec = {"level": a.level, "seed": seed, "reward": round(s["reward"], 4), "accuracy": round(s["accuracy"], 4),
               "seconds": round(dt, 1), "candidates": n_cand,
               "order_ok": bool(key) and key["rotor_order"] == task["key"]["rotor_order"],
               "len": len(task["ciphertext"]), "plugs": len(task["key"]["plugboard"])}
        print(json.dumps(rec), flush=True)
        if out:
            out.write(json.dumps(rec) + "\n")
            out.flush()


if __name__ == "__main__":
    main()
