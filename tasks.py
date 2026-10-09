"""Procedural Enigma tasks.

A task is identified by (level, seed) and rebuilt deterministically on demand:
a fresh German military plaintext, a random Enigma I key, the ciphertext, and
(for crib levels) known-plaintext cribs whose menus meet a loop minimum.

Levels trade cryptanalytic difficulty against how much help the sandbox gets:

    L1  crib attack, rotor order known, short message, 6 plugs, simulator + text sample
    L2  crib attack, rotor order unknown, 10 plugs, simulator + text sample
    L3  as L2, specification only (no simulator, no text sample)
    L4  ciphertext only, long message, 5-6 plugs, simulator + text sample
    L5  ciphertext only, slightly shorter message, 6 plugs, specification only

On every level except L1 the left rotor stays still over the span that matters
(between the cribs, or the whole ciphertext-only message), so the middle ring
setting never affects the decryption there.
"""

import functools
import hashlib
import random

import german
from enigma_machine import ALPHABET, ROTORS, EnigmaMachine

NAMESPACE = "enigma-v1"
REFLECTOR = "UKW-B"
TRAIN_SEEDS = range(0, 2000)
TEST_SEEDS = range(1_000_000, 1_000_100)
SAMPLE_CHARS = 80_000
SAMPLE_OVERLAP = 40

LEVELS = {
    1: dict(attack="crib", length=(80, 120), plugs=(6, 6), known_order=True, kit=True,
            n_cribs=1, crib_len=(14, 16), min_loops=1, motion="no_middle_step"),
    2: dict(attack="crib", length=(100, 150), plugs=(10, 10), known_order=False, kit=True,
            n_cribs=2, crib_len=(12, 16), min_loops=3, motion="no_left_step"),
    3: dict(attack="crib", length=(100, 150), plugs=(10, 10), known_order=False, kit=False,
            n_cribs=2, crib_len=(12, 16), min_loops=3, motion="no_left_step"),
    4: dict(attack="ciphertext_only", length=(400, 500), plugs=(5, 6), known_order=False, kit=True,
            motion="no_left_step"),
    5: dict(attack="ciphertext_only", length=(350, 450), plugs=(6, 6), known_order=False, kit=False,
            motion="no_left_step"),
}

MAX_ATTEMPTS = 500
CRIB_DRAWS = 300


def _rng(*parts) -> random.Random:
    digest = hashlib.sha256(":".join(str(p) for p in (NAMESPACE, *parts)).encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


@functools.lru_cache(maxsize=1)
def sample_text() -> str:
    """German text sample for language statistics; disjoint from every task."""
    return german.sample_corpus(_rng("sample"), SAMPLE_CHARS)


@functools.lru_cache(maxsize=1)
def _sample_windows() -> frozenset:
    out = set()
    for line in sample_text().split():
        out.update(line[i:i + SAMPLE_OVERLAP] for i in range(len(line) - SAMPLE_OVERLAP + 1))
    return frozenset(out)


def overlaps_sample(plaintext: str) -> bool:
    windows = _sample_windows()
    return any(plaintext[i:i + SAMPLE_OVERLAP] in windows
               for i in range(len(plaintext) - SAMPLE_OVERLAP + 1))


def random_key(rng: random.Random, n_plugs: int) -> dict:
    letters = rng.sample(ALPHABET, 2 * n_plugs)
    return {
        "rotor_order": rng.sample(sorted(ROTORS), 3),
        "reflector": REFLECTOR,
        "ring_settings": [rng.randint(1, 26) for _ in range(3)],
        "initial_positions": [rng.randint(1, 26) for _ in range(3)],
        "plugboard": sorted("".join(sorted(letters[i:i + 2])) for i in range(0, len(letters), 2)),
    }


def machine(key: dict) -> EnigmaMachine:
    return EnigmaMachine(key["rotor_order"], key["ring_settings"], key["initial_positions"],
                         key["reflector"], [(p[0], p[1]) for p in key["plugboard"]])


def rotor_trace(key: dict, n: int) -> list:
    """Rotor window positions (left, middle, right) in effect for each of n letters."""
    m = machine(key)
    out = []
    for _ in range(n):
        m._step_rotors()
        out.append(tuple(r.position for r in m.rotors))
    return out


def menu_loops(pairs) -> int:
    """Independent cycles in the menu graph: one edge per (plain, cipher) letter
    pair, one node per letter. loops = edges - nodes + components."""
    parent = {}

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    edges = 0
    for p, c in pairs:
        for x in (p, c):
            parent.setdefault(x, x)
        parent[find(p)] = find(c)
        edges += 1
    components = len({find(x) for x in parent})
    return edges - len(parent) + components


def _choose_cribs(rng, plaintext, ciphertext, trace, cfg):
    n, (lo, hi) = cfg["n_cribs"], cfg["crib_len"]
    for _ in range(CRIB_DRAWS):
        spans = []
        for _ in range(n):
            length = rng.randint(lo, hi)
            spans.append((rng.randint(0, len(plaintext) - length), length))
        spans.sort()
        if any(a + la > b for (a, la), (b, _) in zip(spans, spans[1:])):
            continue
        start, end = spans[0][0], spans[-1][0] + spans[-1][1]
        if cfg["motion"] == "no_middle_step":
            if any(len({trace[i][1] for i in range(a, a + la)}) > 1 for a, la in spans):
                continue
        elif len({trace[i][0] for i in range(start, end)}) > 1:
            continue
        pairs = [(plaintext[i], ciphertext[i]) for a, la in spans for i in range(a, a + la)]
        if menu_loops(pairs) < cfg["min_loops"]:
            continue
        return [{"text": plaintext[a:a + la], "position": a} for a, la in spans]
    return None


@functools.lru_cache(maxsize=256)
def build_task(level: int, seed: int) -> dict:
    cfg = LEVELS[level]
    for attempt in range(MAX_ATTEMPTS):
        rng = _rng(level, seed, attempt)
        plaintext = german.message(rng, *cfg["length"])
        if overlaps_sample(plaintext):
            continue
        key = random_key(rng, rng.randint(*cfg["plugs"]))
        ciphertext = machine(key).encrypt(plaintext)
        cribs = []
        if cfg["attack"] != "crib":
            if len({w[0] for w in rotor_trace(key, len(plaintext))}) > 1:
                continue
        else:
            cribs = _choose_cribs(rng, plaintext, ciphertext, rotor_trace(key, len(plaintext)), cfg)
            if cribs is None:
                continue
        return {
            "id": task_id(level, seed),
            "level": level,
            "seed": seed,
            "plaintext": plaintext,
            "ciphertext": ciphertext,
            "key": key,
            "cribs": cribs,
            "known": {
                "reflector": key["reflector"],
                "plugboard_pairs": len(key["plugboard"]),
                **({"rotor_order": key["rotor_order"]} if cfg["known_order"] else {}),
            },
            "kit": cfg["kit"],
        }
    raise RuntimeError(f"could not build task L{level}-{seed}")


def task_id(level: int, seed: int) -> str:
    return f"L{level}-{seed}"


def list_specs(split: str) -> list:
    seeds = {"train": TRAIN_SEEDS, "test": TEST_SEEDS}[split]
    return [{"id": task_id(level, s), "level": level, "seed": s} for level in sorted(LEVELS) for s in seeds]
