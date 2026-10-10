"""Reference solvers used to check that every level is solvable (not shipped).

    solve_crib(task)  bombe over the cribs -> per stop: plugboard hill-climb
                      seeded with the implied pairs, middle-ring search
    solve_cto(task)   index-of-coincidence scan over rotor orders, core
                      offsets and right ring (empty plugboard) -> plugboard
                      hill-climb (IC, then trigrams) on the best candidates

Both return a key dict in the environment's submit format.
"""

import itertools
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bombe  # noqa: E402
import tasks  # noqa: E402
from enigma_machine import ALPHABET, ROTORS  # noqa: E402

A = np.arange(26)
NOTCH = {name: ALPHABET.index(r["turnover"]) for name, r in ROTORS.items()}
ORDERS = [list(p) for p in itertools.permutations(sorted(ROTORS), 3)]


def _trigram_table() -> np.ndarray:
    text = np.array([ALPHABET.index(c) for c in tasks.sample_text() if c in ALPHABET])
    counts = np.ones(26 ** 3)
    np.add.at(counts, (text[:-2] * 26 + text[1:-1]) * 26 + text[2:], 1)
    return np.log(counts / counts.sum()).astype(np.float32)


TRI = _trigram_table()


def to_idx(s: str) -> np.ndarray:
    return np.array([ALPHABET.index(c) for c in s], dtype=np.int64)


def offsets(order, rings, windows, n):
    """Core offsets (left, middle, right) for n letters; windows/rings 0-indexed,
    windows may be arrays (vectorised over keys). Returns three (K, n) arrays."""
    wl, wm, wr = (np.atleast_1d(np.asarray(w, dtype=np.int64)).copy() for w in windows)
    rl, rm, rr = (np.atleast_1d(np.asarray(r, dtype=np.int64)) for r in rings)
    nm, nr = NOTCH[order[1]], NOTCH[order[2]]
    K = max(len(wl), len(wm), len(wr), len(rr), len(rm))
    wl, wm, wr = (np.broadcast_to(w, (K,)).copy() for w in (wl, wm, wr))
    out = np.empty((3, K, n), dtype=np.int64)
    for i in range(n):
        mid, right = wm == nm, wr == nr
        wl = np.where(mid, wl + 1, wl) % 26
        wm = np.where(mid | right, wm + 1, wm) % 26
        wr = (wr + 1) % 26
        out[0, :, i], out[1, :, i], out[2, :, i] = (wl - rl) % 26, (wm - rm) % 26, (wr - rr) % 26
    return out


def position_tables(Sf, offs):
    """(K, n, 26) permutation per letter position (plugboard excluded)."""
    base = ((offs[0] * 26 + offs[1]) * 26 + offs[2]) * 26
    return Sf[base[..., None] + A]


def ic_rows(dec):
    K, n = dec.shape
    counts = np.bincount((dec + 26 * np.arange(K)[:, None]).ravel(), minlength=26 * K).reshape(K, 26)
    return (counts * (counts - 1)).sum(1) / (n * (n - 1))


def tri_score(dec):
    return TRI[(dec[..., :-2] * 26 + dec[..., 1:-1]) * 26 + dec[..., 2:]].mean(-1)


def _neighbours(P, max_pairs):
    """All plugboards one change away: connect a-b (unplugging their partners),
    or disconnect a pair."""
    out = []
    pairs = sum(P != A) // 2
    for a, b in itertools.combinations(range(26), 2):
        Q = P.copy()
        if Q[a] == b:
            Q[a], Q[b] = a, b
        else:
            for x in (a, b):
                if Q[x] != x:
                    Q[Q[x]] = Q[x]
                    Q[x] = x
            Q[a], Q[b] = b, a
            if sum(Q != A) // 2 > max_pairs:
                continue
        out.append(Q)
    return np.array(out) if out else np.empty((0, 26), dtype=np.int64)


def decrypt_with(T, c, P):
    """T: (n, 26) position tables, c: ciphertext indices, P: (B, 26) plugboards."""
    n = len(c)
    inner = T[np.arange(n)[None, :], P[:, c]]
    return np.take_along_axis(P, inner, axis=1)


def hill_climb(T, c, P, max_pairs, score, fixed=()):
    """Greedy best-improvement over single plugboard changes."""
    P = P.copy()
    best = score(decrypt_with(T, c, P[None]))[0]
    while True:
        N = _neighbours(P, max_pairs)
        if fixed:
            keep = np.all([N[:, a] == P[a] for a in fixed], axis=0)
            N = N[keep]
        if not len(N):
            return P, best
        s = score(decrypt_with(T, c, N))
        i = int(np.argmax(s))
        if s[i] <= best + 1e-9:
            return P, best
        P, best = N[i], s[i]


def key_dict(order, rings, windows, P):
    pairs = sorted({"".join(sorted((ALPHABET[a], ALPHABET[P[a]]))) for a in range(26) if P[a] != a})
    return {"rotor_order": list(order), "reflector": "UKW-B",
            "ring_settings": [r + 1 for r in rings], "initial_positions": [w + 1 for w in windows],
            "plugboard": pairs}


def refine_rings(order, rings, windows, P, c, Sf):
    """Try all 26 x 26 middle and right rings, keeping the core offsets the key
    was found with: this fixes when the middle rotor steps and when it
    double-steps. A double step before the cribs leaves the left and middle
    start offsets one lower than during the cribs, so that variant is tried too."""
    o = [(windows[i] - rings[i]) % 26 for i in range(3)]
    rm, rr = (g.ravel() for g in np.meshgrid(A, A, indexing="ij"))
    best = None
    for d in (0, -1):
        ol, om = (o[0] + d) % 26, (o[1] + d) % 26
        rings_v = (np.full(676, rings[0]), rm, rr)
        wins_v = (np.full(676, (ol + rings[0]) % 26), (om + rm) % 26, (o[2] + rr) % 26)
        T = position_tables(Sf, offsets(order, rings_v, wins_v, len(c)))
        inner = np.take_along_axis(T, P[c][None, :, None].repeat(676, 0), axis=2)[:, :, 0]
        s = tri_score(P[inner])
        i = int(np.argmax(s))
        if best is None or s[i] > best[0]:
            best = (s[i], (rings[0], int(rm[i]), int(rr[i])),
                    (int(wins_v[0][i]), int(wins_v[1][i]), int(wins_v[2][i])))
    return best


def _stop_plugboard(stop):
    P = A.copy()
    for a, b in stop["implied_plugboard"]:
        P[ALPHABET.index(a)], P[ALPHABET.index(b)] = ALPHABET.index(b), ALPHABET.index(a)
    return P


def rank_stops(stops, c):
    """Cheap score per stop: trigrams of the whole message decrypted with only
    the plugboard pairs the menu implies."""
    scores = np.empty(len(stops))
    by_order = {}
    for i, st in enumerate(stops):
        by_order.setdefault(tuple(st["rotor_order"]), []).append(i)
    for order, idx in by_order.items():
        Sf = bombe.scrambler(list(order), "UKW-B").ravel().astype(np.int64)
        for chunk in range(0, len(idx), 2000):
            ids = idx[chunk:chunk + 2000]
            rings = np.array([[r - 1 for r in stops[i]["ring_settings"]] for i in ids]).T
            wins = np.array([[p - 1 for p in stops[i]["positions"]] for i in ids]).T
            T = position_tables(Sf, offsets(order, rings, wins, len(c)))
            P = np.array([_stop_plugboard(stops[i]) for i in ids])
            inner = np.take_along_axis(T, P[:, c][:, :, None], axis=2)[:, :, 0]
            dec = np.take_along_axis(P, inner, axis=1)
            scores[ids] = tri_score(dec)
    return scores


def solve_crib(task, max_stops=20000, refine=30, deadline=None):
    c = to_idx(task["ciphertext"])
    n_pairs = task["known"]["plugboard_pairs"]
    orders = [task["known"]["rotor_order"]] if "rotor_order" in task["known"] else ORDERS
    stops, info = bombe.run_orders(orders, "UKW-B", task["cribs"], task["ciphertext"], max_report=max_stops)
    n_stops = info["n_stops"] if info else 0
    if stops:
        scores = rank_stops(stops, c)
        stops = [stops[i] for i in np.argsort(-scores)[:refine]]
    crib_pos = [(cr["position"] + i, ALPHABET.index(ch)) for cr in task["cribs"] for i, ch in enumerate(cr["text"])]
    best = None
    for stop in stops:
        if deadline and time.time() > deadline:
            break
        order = stop["rotor_order"]
        Sf = bombe.scrambler(order, "UKW-B").ravel().astype(np.int64)
        rings = tuple(r - 1 for r in stop["ring_settings"])
        windows = tuple(p - 1 for p in stop["positions"])
        P = _stop_plugboard(stop)
        fixed = tuple(ALPHABET.index(x) for pair in stop["implied_plugboard"] for x in pair) + tuple(
            ALPHABET.index(x) for x in stop["unsteckered"])
        T = position_tables(Sf, offsets(order, rings, windows, len(c)))[0]
        P, _ = hill_climb(T, c, P, n_pairs, tri_score, fixed=fixed)
        s, rings, windows = refine_rings(order, rings, windows, P, c, Sf)
        T = position_tables(Sf, offsets(order, rings, windows, len(c)))[0]
        P, s = hill_climb(T, c, P, n_pairs, tri_score)
        dec = decrypt_with(T, c, P[None])[0]
        crib_ok = sum(dec[i] == ch for i, ch in crib_pos) / len(crib_pos)
        rank = (crib_ok, s)
        if best is None or rank > best[0]:
            best = (rank, key_dict(order, rings, windows, P))
    return best[1] if best else None, n_stops


def solve_cto(task, top_k=200, deadline=None):
    c = to_idx(task["ciphertext"])
    n, n_pairs = len(c), task["known"]["plugboard_pairs"]
    grid = np.array(list(itertools.product(range(26), repeat=3)))
    cands = []
    for order in ORDERS:
        Sf = bombe.scrambler(order, "UKW-B").ravel().astype(np.int64)
        # The middle window starts just past its turnover letter, so the left
        # rotor never steps; the grid runs over the core offsets in effect.
        wm = (NOTCH[order[1]] + 1) % 26
        rm = (wm - grid[:, 1]) % 26
        for rr in range(26):
            offs = offsets(order, (0, rm, rr), (grid[:, 0], wm, (grid[:, 2] + rr) % 26), n)
            dec = Sf[((offs[0] * 26 + offs[1]) * 26 + offs[2]) * 26 + c[None, :]]
            ic = ic_rows(dec)
            top = np.argpartition(-ic, top_k)[:top_k]
            cands += [(ic[i], tuple(order), (0, int(rm[i]), rr), (int(grid[i, 0]), wm, int((grid[i, 2] + rr) % 26)))
                      for i in top]
    cands.sort(reverse=True)
    best = None
    for ic, order, rings, w in cands[:top_k]:
        if deadline and time.time() > deadline:
            break
        Sf = bombe.scrambler(list(order), "UKW-B").ravel().astype(np.int64)
        T = position_tables(Sf, offsets(order, rings, w, n))[0]
        P, _ = hill_climb(T, c, A.copy(), n_pairs, ic_rows)
        P, s = hill_climb(T, c, P, n_pairs, tri_score)
        if best is None or s > best[0]:
            best = (s, order, rings, w, P)
    s, order, rings, w, P = best
    Sf = bombe.scrambler(list(order), "UKW-B").ravel().astype(np.int64)
    _, rings, w = refine_rings(order, rings, w, P, c, Sf)
    T = position_tables(Sf, offsets(order, rings, w, n))[0]
    P, _ = hill_climb(T, c, P, n_pairs, tri_score)
    return key_dict(order, rings, w, P), len(cands)
