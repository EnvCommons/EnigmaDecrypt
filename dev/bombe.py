"""Turing-Welchman bombe for the EnigmaDecrypt machine (Enigma I, rotors I-V).

A run takes a rotor order, a reflector and one or more cribs (known plaintext at
known message positions), and tests every rotor core position together with
every right-rotor turnover point, so cribs anywhere in the message can be
combined. It ignores the rare double step of the middle rotor (which also moves
the left rotor): a crib after such a step may not stop at the true setting. The
cribs form a menu (a graph on letters, one edge per crib letter). For each core
position and each hypothesis for the plugboard partner of the menu's most
connected letter, the hypothesis is propagated along the menu; it survives if
every loop closes and the implied partners form a valid set of swaps. Each
surviving (position, hypothesis) is a stop.

Stops are reported as a full rotor setting (start positions and ring settings)
that reproduces the right- and middle-rotor motion, with the middle rotor placed
just past its notch so it does not double-step early, plus the plugboard pairs
the menu implies.
"""
from __future__ import annotations

import itertools
from collections import deque

import numpy as np

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ROTORS = {
    "I": "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "II": "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "III": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "IV": "ESOVPZJAYQUIRHXLNFTGKDCMWB",
    "V": "VZBRGITYUPSDNHLXAWMJQOFECK",
}
REFLECTORS = {
    "UKW-A": "EJMZALYXVBWFCRQUONTSPIKHGD",
    "UKW-B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "UKW-C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
}
TURNOVER = {"I": "Q", "II": "E", "III": "V", "IV": "J", "V": "Z"}
ALL_ORDERS = [list(p) for p in itertools.permutations(ROTORS, 3)]
REFINE_LIMIT = 26 ** 4

_X = np.arange(26)
_SCRAMBLERS: dict[tuple[str, ...], np.ndarray] = {}


def _rotor_tables(name: str) -> tuple[np.ndarray, np.ndarray]:
    """fwd[o, x], bwd[o, x]: contact reached from contact x with core offset o."""
    w = np.array([ALPHABET.index(c) for c in ROTORS[name]])
    inv = np.argsort(w)
    o = _X[:, None]
    return (w[(_X[None, :] + o) % 26] - o) % 26, (inv[(_X[None, :] + o) % 26] - o) % 26


def scrambler(order: list[str], reflector: str) -> np.ndarray:
    """S[l, m, r, x]: the rotors-and-reflector permutation at core offsets (l, m, r),
    plugboard excluded. Each S[l, m, r] is a fixed-point-free involution."""
    key = (*order, reflector)
    if key not in _SCRAMBLERS:
        (lf, lb), (mf, mb), (rf, rb) = (_rotor_tables(n) for n in order)
        u = np.array([ALPHABET.index(c) for c in REFLECTORS[reflector]])
        l, m, r, x = np.ix_(_X, _X, _X, _X)
        s = rb[r, mb[m, lb[l, u[lf[l, mf[m, rf[r, x]]]]]]]
        _SCRAMBLERS[key] = s.astype(np.int8)
    return _SCRAMBLERS[key]


def _components(edges):
    adj: dict[int, list[int]] = {}
    for k, (a, b, _) in enumerate(edges):
        adj.setdefault(a, []).append(k)
        adj.setdefault(b, []).append(k)
    comps, seen = [], set()
    for s in sorted(adj, key=lambda a: -len(adj[a])):
        if s in seen:
            continue
        order, tree, used, q = [s], [], set(), deque([s])
        seen.add(s)
        while q:
            u = q.popleft()
            for k in adj[u]:
                if k in used:
                    continue
                a, b, step = edges[k]
                v = b if a == u else a
                if v not in seen:
                    used.add(k)
                    seen.add(v)
                    order.append(v)
                    tree.append((u, v, step))
                    q.append(v)
        letters = set(order)
        loops = [edges[k] for k in range(len(edges))
                 if k not in used and edges[k][0] in letters and edges[k][1] in letters]
        comps.append({"root": s, "letters": order, "tree": tree, "loops": loops})
    # Search the most constraining component first: most loops, then most edges.
    comps.sort(key=lambda c: (len(c["loops"]), len(c["tree"])), reverse=True)
    return comps


def _offsets(m, r0, u, j):
    """Middle and right core offsets at message index j. The right rotor steps
    before every letter; the middle rotor steps on keystrokes u+1, u+27, ..."""
    steps = np.where(j >= u, (j - u) // 26 + 1, 0)
    return (m + steps) % 26, (r0 + j + 1) % 26


def _search(Sf, cand, comp, root_values, known, fixed=None):
    """Propagate plugboard hypotheses over one menu component for arrays of
    candidates (l, m, r0, u), pruning as soon as a letter's partner contradicts a
    loop, a known stecker, or the swap structure. Returns (indices into cand of
    survivors, hypothesis index per survivor, partner arrays per letter)."""
    l, m, r0, u = cand
    n = l.shape[0]
    fixed0 = fixed or {}
    out_idx, out_h, out_val = [], [], {a: [] for a in comp["letters"]}
    for h, v in enumerate(root_values):
        alive = np.arange(n)
        fixed = dict(fixed0)
        val = {comp["root"]: np.full(n, v, np.int32)}
        assigned = [comp["root"]]
        pending = list(comp["loops"])
        ok = np.ones(n, bool)
        if comp["root"] in known:
            ok &= val[comp["root"]] == known[comp["root"]]
        steps = list(comp["tree"])
        while True:
            # loops whose ends are both assigned
            for e in [e for e in pending if e[0] in val and e[1] in val]:
                a, b, j = e
                mm, rr = _offsets(m[alive], r0[alive], u[alive], j)
                ok &= Sf[((l[alive] * 26 + mm) * 26 + rr) * 26 + val[a]] == val[b]
                pending.remove(e)
            if not ok.all():
                keep = np.nonzero(ok)[0]
                alive = alive[keep]
                val = {k: x[keep] for k, x in val.items()}
                fixed = {k: x[keep] for k, x in fixed.items()}
                ok = np.ones(alive.size, bool)
            if alive.size == 0 or not steps:
                break
            a, b, j = steps.pop(0)
            mm, rr = _offsets(m[alive], r0[alive], u[alive], j)
            vb = Sf[((l[alive] * 26 + mm) * 26 + rr) * 26 + val[a]].astype(np.int32)
            if b in known:
                ok &= vb == known[b]
            for x, vx in list(val.items()) + list(fixed.items()):
                ok &= vb != vx
                ok &= (vb != x) | (vx == b)
                ok &= (vx != b) | (vb == x)
            val[b] = vb
            assigned.append(b)
        # the root against the fixed letters (other letters were checked on assignment)
        r = comp["root"]
        if alive.size and r in val and fixed:
            ok = np.ones(alive.size, bool)
            for x, vx in fixed.items():
                ok &= (val[r] != vx) & ((val[r] != x) | (vx == r)) & ((vx != r) | (val[r] == x))
            keep = np.nonzero(ok)[0]
            alive = alive[keep]
            val = {k: y[keep] for k, y in val.items()}
        out_idx.append(alive)
        out_h.append(np.full(alive.size, h))
        for a in comp["letters"]:
            out_val[a].append(val[a] if a in val else np.empty(0, np.int32))
    return (np.concatenate(out_idx), np.concatenate(out_h),
            {a: np.concatenate(x) for a, x in out_val.items()})


def run(order, reflector, cribs, ciphertext, known_plugboard=None, max_report=300, probe=None):
    """Stops for one rotor order. cribs: [{"text", "position"}]. known_plugboard:
    optional pairs already known (all other menu letters stay unknown).
    Returns (stops, info)."""
    edges = []
    for c in cribs:
        text, pos = c["text"].upper(), int(c["position"])
        seg = ciphertext[pos:pos + len(text)]
        if len(seg) != len(text) or any(ch not in ALPHABET for ch in text):
            raise ValueError(f"crib {text!r} at {pos} does not fit the ciphertext")
        for i, (p, q) in enumerate(zip(text, seg)):
            if p == q:
                return [], {"impossible": f"crib letter {p} at {pos + i} equals the ciphertext letter; "
                                          "Enigma never encrypts a letter to itself"}
            edges.append((ALPHABET.index(p), ALPHABET.index(q), pos + i))
    known = {}
    for a, b in known_plugboard or []:
        a, b = ALPHABET.index(a.upper()), ALPHABET.index(b.upper())
        known[a], known[b] = b, a
    comps = _components(edges)
    Sf = scrambler(order, reflector).ravel().astype(np.int32)
    cand = tuple(g.ravel() for g in np.meshgrid(_X, _X, _X, _X, indexing="ij"))  # l, m, r0, u
    notch = ALPHABET.index(TURNOVER[order[2]])
    notch_m = ALPHABET.index(TURNOVER[order[1]])
    main = comps[0]
    roots = [known[main["root"]]] if main["root"] in known else list(range(26))
    idx, hyp, val = _search(Sf, cand, main, roots, known)
    refined = idx.size <= REFINE_LIMIT
    agreed = dict(val)
    if refined:
        for comp in comps[1:]:
            # checked against the main component only, never jointly with other side
            # components, so a true stop is never lost
            sub = tuple(c[idx] for c in cand)
            croots = [known[comp["root"]]] if comp["root"] in known else list(range(26))
            cidx, _, cval = _search(Sf, sub, comp, croots, known, fixed=dict(val))
            count = np.bincount(cidx, minlength=idx.size)
            keep = count > 0
            first = {a: np.full(idx.size, -1, np.int32) for a in comp["letters"]}
            for a in comp["letters"]:
                first[a][cidx[::-1]] = cval[a][::-1]   # value of the first surviving hypothesis
            idx, hyp = idx[keep], hyp[keep]
            val = {a: x[keep] for a, x in val.items()}
            agreed = {a: x[keep] for a, x in agreed.items()}
            for a in comp["letters"]:
                agreed[a] = np.where(count[keep] == 1, first[a][keep], -1)
    stops, probe_pairs = [], []
    report = list(range(min(max_report, idx.size)))
    if probe is not None:
        hit = np.nonzero((cand[0][idx] == probe[0]) & (cand[1][idx] == probe[1])
                         & (cand[2][idx] == probe[2]) & (cand[3][idx] == probe[3]))[0]
    for j in report + ([int(k) for k in hit] if probe is not None else []):
        pairs, self_s = set(), []
        for a, x in agreed.items():
            b = int(x[j])
            if b < 0:
                continue
            if b == a:
                self_s.append(ALPHABET[a])
            else:
                pairs.add(tuple(sorted((ALPHABET[a], ALPHABET[b]))))
        L, M, R0, U = (int(c[idx[j]]) for c in cand)
        if probe is not None and (L, M, R0, U) == tuple(probe):
            probe_pairs.append(sorted(pairs))
        if j not in report:
            continue
        pos_r = (notch - U) % 26          # right rotor window at the start
        ring_r = (pos_r - R0) % 26        # keeps the right core offset
        # Middle window one past its notch: the most middle steps (25) before it
        # can reach the notch and double-step, which the search does not model.
        pos_m = (notch_m + 1) % 26
        ring_m = (pos_m - M) % 26
        stops.append({
            "rotor_order": list(order),
            "ring_settings": [1, ring_m + 1, ring_r + 1],
            "positions": [L + 1, pos_m + 1, pos_r + 1],
            "implied_plugboard": [list(p) for p in sorted(pairs)],
            "unsteckered": sorted(self_s),
        })
    info = {"n_stops": int(idx.size), "refined": refined, "probe_pairs": probe_pairs,
            "menu_letters": len({a for e in edges for a in e[:2]}), "menu_edges": len(edges),
            "loops": sum(len(c["loops"]) for c in comps), "components": len(comps)}
    return stops, info


def run_orders(orders, reflector, cribs, ciphertext, known_plugboard=None, max_report=300):
    stops, total, info = [], 0, None
    for o in orders:
        s, info = run(o, reflector, cribs, ciphertext, known_plugboard, max_report - len(stops))[0:2]
        stops.extend(s)
        total += info.get("n_stops", 0)
    if info is not None:
        info["n_stops"] = total
    return stops, info
