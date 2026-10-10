"""Rank of the true rotor setting in the empty-plugboard IC scan, and the IC
after adding k of the true plugboard pairs (ciphertext-only levels)."""
import itertools, json, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bombe, solve, tasks
from enigma_machine import ALPHABET

level, seeds = int(sys.argv[1]), range(int(sys.argv[2]), int(sys.argv[3]))
grid = np.array(list(itertools.product(range(26), repeat=3)))
for seed in seeds:
    t = tasks.build_task(level, seed); k = t["key"]
    c = solve.to_idx(t["ciphertext"]); n = len(c)
    rings = [r - 1 for r in k["ring_settings"]]; wins = [p - 1 for p in k["initial_positions"]]
    o = [(wins[i] - rings[i]) % 26 for i in range(3)]
    true_order, rr = k["rotor_order"], rings[2]
    true_w = (o[0], o[1], (o[2] + rr) % 26)
    all_ic = []
    true_ic = None
    for order in solve.ORDERS:
        Sf = bombe.scrambler(order, "UKW-B").ravel().astype(np.int64)
        for r in range(26):
            offs = solve.offsets(order, (0, 0, r), (grid[:, 0], grid[:, 1], grid[:, 2]), n)
            ic = solve.ic_rows(Sf[((offs[0] * 26 + offs[1]) * 26 + offs[2]) * 26 + c[None, :]])
            all_ic.append(np.sort(ic)[-2000:])
            if order == true_order and r == rr:
                true_ic = ic[(true_w[0] * 26 + true_w[1]) * 26 + true_w[2]]
    top = np.sort(np.concatenate(all_ic))[::-1]
    rank = int((top > true_ic).sum())
    # IC with k true plugs at the exact key
    Sf = bombe.scrambler(true_order, "UKW-B").ravel().astype(np.int64)
    T = solve.position_tables(Sf, solve.offsets(true_order, rings, wins, n))[0]
    ics = []
    for kk in range(len(k["plugboard"]) + 1):
        P = np.arange(26)
        for p in k["plugboard"][:kk]:
            a, b = ALPHABET.index(p[0]), ALPHABET.index(p[1]); P[a], P[b] = b, a
        ics.append(round(float(solve.ic_rows(solve.decrypt_with(T, c, P[None]))[0]), 4))
    print(json.dumps({"level": level, "seed": seed, "n": n, "plugs": len(k["plugboard"]), "true_ic": round(float(true_ic), 4),
                      "rank_of_true": rank, "ic_top1": round(float(top[0]), 4), "ic_top200": round(float(top[199]), 4),
                      "ic_by_true_plugs": ics}), flush=True)
