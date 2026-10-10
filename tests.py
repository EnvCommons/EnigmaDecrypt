"""
Tests for the Enigma Decrypt environment.

1. Enigma machine correctness (historical test vectors, properties)
2. Plaintext generator
3. Procedural tasks (determinism, cribs, splits)
4. Reference simulator shipped in the kit
5. Key scoring (gold, equivalent, random, partial, invalid)
6. Environment with a fake sandbox (uploads per level, leaks, submit)
"""

import ast
import asyncio
import collections
import hashlib
import json
import os
import random
import subprocess
import sys
from dataclasses import dataclass, field

import pytest

import enigma_env
import german
import tasks
from enigma_env import (EnigmaDecrypt, SubmitKeyParams, parse_key, score_key, scored_positions,
                        simulator_source)
from enigma_machine import ALPHABET, REFLECTORS, ROTORS, EnigmaMachine


# ============================================================================
# 1. ENIGMA MACHINE UNIT TESTS
# ============================================================================

class TestEnigmaMachine:

    def test_1930_manual_vector(self):
        """The canonical 1930 German military manual test message."""
        machine = EnigmaMachine(
            rotor_order=["II", "I", "III"],
            ring_settings=[24, 13, 22],
            initial_positions=[1, 2, 12],  # ABL (message key)
            reflector="UKW-A",
            plugboard=[("A", "M"), ("F", "I"), ("N", "V"), ("P", "S"), ("T", "U"), ("W", "Z")],
        )
        plaintext = "FEINDLIQEINFANTERIEKOLONNEBEOBAQTETXANFANGSUEDAUSGANGBAERWALDEXENDEDREIKMOSTWAERTSNEUSTADT"
        expected = "GCDSEAHUGWTQGRKVLFGXUCALXVYMIGMMNMFDXTGNVHVRMMEVOUYFZSLRHDRRXFJWCFHUHMUNZEFRDISIKBGPMYVXUZ"
        assert machine.encrypt(plaintext) == expected

    def test_known_output_aaa(self):
        """Known output for AAAAAAAAAA with standard settings (cross-validated with online simulators)."""
        machine = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        )
        assert machine.encrypt("AAAAAAAAAA") == "BDZGOWCXLT"

    def test_reciprocity_no_plugboard(self):
        """Encrypting ciphertext with same settings returns plaintext."""
        plaintext = "HELLOWORLD"
        m1 = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        )
        ciphertext = m1.encrypt(plaintext)

        m2 = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        )
        assert m2.encrypt(ciphertext) == plaintext

    def test_reciprocity_with_plugboard(self):
        """Reciprocity holds with plugboard connections."""
        plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        m1 = EnigmaMachine(
            rotor_order=["III", "I", "IV"],
            ring_settings=[5, 17, 3],
            initial_positions=[10, 20, 8],
            reflector="UKW-C",
            plugboard=[("A", "B"), ("C", "D"), ("E", "F"), ("G", "H")],
        )
        ciphertext = m1.encrypt(plaintext)

        m2 = EnigmaMachine(
            rotor_order=["III", "I", "IV"],
            ring_settings=[5, 17, 3],
            initial_positions=[10, 20, 8],
            reflector="UKW-C",
            plugboard=[("A", "B"), ("C", "D"), ("E", "F"), ("G", "H")],
        )
        assert m2.encrypt(ciphertext) == plaintext

    def test_reciprocity_complex_settings(self):
        """Reciprocity with complex settings: many plugboard pairs, various rotors."""
        plaintext = "WETTERBERIQTXWINDSTAERKEDREIAUSNORDWESTXBEWOELKTXSIQTUNTERFUENFKILOMETERX"
        m1 = EnigmaMachine(
            rotor_order=["V", "II", "IV"],
            ring_settings=[26, 1, 13],
            initial_positions=[7, 19, 25],
            reflector="UKW-A",
            plugboard=[("A", "Z"), ("B", "Y"), ("C", "X"), ("D", "W"), ("E", "V"),
                        ("F", "U"), ("G", "T"), ("H", "S"), ("I", "R"), ("J", "Q")],
        )
        ciphertext = m1.encrypt(plaintext)

        m2 = EnigmaMachine(
            rotor_order=["V", "II", "IV"],
            ring_settings=[26, 1, 13],
            initial_positions=[7, 19, 25],
            reflector="UKW-A",
            plugboard=[("A", "Z"), ("B", "Y"), ("C", "X"), ("D", "W"), ("E", "V"),
                        ("F", "U"), ("G", "T"), ("H", "S"), ("I", "R"), ("J", "Q")],
        )
        assert m2.encrypt(ciphertext) == plaintext

    def test_no_self_encryption(self):
        """No character ever encrypts to itself (fundamental Enigma property)."""
        for letter in ALPHABET:
            machine = EnigmaMachine(
                rotor_order=["I", "II", "III"],
                ring_settings=[1, 1, 1],
                initial_positions=[1, 1, 1],
                reflector="UKW-B",
                plugboard=[],
            )
            test_input = letter * 100
            result = machine.encrypt(test_input)
            for i, (p, c) in enumerate(zip(test_input, result)):
                assert p != c, f"Self-encryption at position {i}: {letter} -> {c}"

    def test_no_self_encryption_with_plugboard(self):
        """No self-encryption even with plugboard."""
        machine = EnigmaMachine(
            rotor_order=["IV", "V", "I"],
            ring_settings=[12, 5, 20],
            initial_positions=[3, 15, 22],
            reflector="UKW-C",
            plugboard=[("A", "B"), ("C", "D"), ("E", "F")],
        )
        for letter in ALPHABET:
            machine.reset([3, 15, 22])
            result = machine.encrypt(letter * 50)
            for i, (p, c) in enumerate(zip(letter * 50, result)):
                assert p != c, f"Self-encryption at position {i}: {letter} -> {c}"

    def test_double_stepping(self):
        """Verify the double-stepping anomaly."""
        # Rotor II turnover at E (index 4), Rotor III turnover at V (index 21)
        machine = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 4, 21],  # A, D, U
            reflector="UKW-B",
            plugboard=[],
        )

        expected_positions = [
            [1, 4, 22],   # A, D, V — right steps (U->V)
            [1, 5, 23],   # A, E, W — right at turnover V, middle steps (D->E)
            [2, 6, 24],   # B, F, X — middle at turnover E, DOUBLE STEP: left+middle step
            [2, 6, 25],   # B, F, Y — normal, only right steps
        ]

        for expected in expected_positions:
            machine.encrypt_char("A")
            assert machine.positions == expected, (
                f"Expected positions {expected}, got {machine.positions}"
            )

    def test_different_reflectors_give_different_output(self):
        """Different reflectors produce different ciphertext."""
        plaintext = "TESTMESSAGE"
        results = {}
        for ref in REFLECTORS:
            machine = EnigmaMachine(
                rotor_order=["I", "II", "III"],
                ring_settings=[1, 1, 1],
                initial_positions=[1, 1, 1],
                reflector=ref,
                plugboard=[],
            )
            results[ref] = machine.encrypt(plaintext)

        # All three should be different
        result_values = list(results.values())
        assert len(set(result_values)) == 3, f"Not all reflectors produce unique output: {results}"

    def test_different_rotors_give_different_output(self):
        """Different rotor orders produce different ciphertext."""
        plaintext = "TESTMESSAGE"
        orders = [
            ["I", "II", "III"],
            ["III", "II", "I"],
            ["II", "III", "I"],
        ]
        results = []
        for order in orders:
            machine = EnigmaMachine(
                rotor_order=order,
                ring_settings=[1, 1, 1],
                initial_positions=[1, 1, 1],
                reflector="UKW-B",
                plugboard=[],
            )
            results.append(machine.encrypt(plaintext))

        assert len(set(results)) == 3, f"Not all rotor orders produce unique output: {results}"

    def test_ring_setting_effect(self):
        """Ring settings affect the output."""
        plaintext = "TESTMESSAGE"
        m1 = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        )
        m2 = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[2, 2, 2],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        )
        assert m1.encrypt(plaintext) != m2.encrypt(plaintext)

    def test_initial_position_effect(self):
        """Different initial positions produce different output."""
        plaintext = "TESTMESSAGE"
        m1 = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        )
        m2 = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 2],
            reflector="UKW-B",
            plugboard=[],
        )
        assert m1.encrypt(plaintext) != m2.encrypt(plaintext)

    def test_plugboard_effect(self):
        """Plugboard changes the output."""
        plaintext = "TESTMESSAGE"
        m1 = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        )
        m2 = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[("A", "B")],
        )
        assert m1.encrypt(plaintext) != m2.encrypt(plaintext)

    def test_reset_restores_initial_positions(self):
        """Reset returns machine to initial state."""
        machine = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[5, 10, 15],
            reflector="UKW-B",
            plugboard=[],
        )
        machine.encrypt("ABCDEF")
        assert machine.positions != [5, 10, 15]
        machine.reset()
        assert machine.positions == [5, 10, 15]

    def test_only_az_processed(self):
        """Non-A-Z characters are stripped from output."""
        machine = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        )
        result = machine.encrypt("ABC 123 DEF")
        assert len(result) == 6  # Only A, B, C, D, E, F processed

    def test_invalid_rotor_raises(self):
        """Invalid rotor name raises ValueError."""
        with pytest.raises(ValueError, match="Unknown rotor"):
            EnigmaMachine(
                rotor_order=["I", "II", "VI"],
                ring_settings=[1, 1, 1],
                initial_positions=[1, 1, 1],
                reflector="UKW-B",
                plugboard=[],
            )

    def test_invalid_reflector_raises(self):
        """Invalid reflector name raises ValueError."""
        with pytest.raises(ValueError, match="Unknown reflector"):
            EnigmaMachine(
                rotor_order=["I", "II", "III"],
                ring_settings=[1, 1, 1],
                initial_positions=[1, 1, 1],
                reflector="UKW-D",
                plugboard=[],
            )

    def test_duplicate_plugboard_raises(self):
        """Duplicate letters in plugboard raises ValueError."""
        with pytest.raises(ValueError, match="Duplicate plugboard"):
            EnigmaMachine(
                rotor_order=["I", "II", "III"],
                ring_settings=[1, 1, 1],
                initial_positions=[1, 1, 1],
                reflector="UKW-B",
                plugboard=[("A", "B"), ("A", "C")],
            )

    def test_long_message_reciprocity(self):
        """Reciprocity holds for longer messages (tests rotor cycling)."""
        plaintext = "ABCDEFGHIJ" * 200  # 2000 chars, well past one full rotor cycle
        m1 = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[("A", "Z"), ("B", "Y")],
        )
        ciphertext = m1.encrypt(plaintext)
        assert len(ciphertext) == 2000

        m2 = EnigmaMachine(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[("A", "Z"), ("B", "Y")],
        )
        assert m2.encrypt(ciphertext) == plaintext



# ============================================================================
# 2. PLAINTEXT GENERATOR
# ============================================================================

class TestGerman:

    @pytest.mark.parametrize("n,word", [
        (0, "NULL"), (1, "EINS"), (2, "ZWO"), (12, "ZWOELF"), (16, "SECHZEHN"), (21, "EINUNDZWANZIG"),
        (30, "DREISSIG"), (101, "EINHUNDERTEINS"), (1013, "EINTAUSENDDREIZEHN"),
        (9999, "NEUNTAUSENDNEUNHUNDERTNEUNUNDNEUNZIG"),
    ])
    def test_number(self, n, word):
        assert german.number(n) == word

    def test_normalise(self):
        assert german.normalise("Nicht schießen, Bärenführer.") == "NIQTSQIESSENZZBAERENFUEHRERX"

    @pytest.mark.parametrize("lo,hi", [(80, 120), (100, 150), (200, 300), (300, 400)])
    def test_message_length_and_alphabet(self, lo, hi):
        rng = random.Random(lo)
        for _ in range(100):
            m = german.message(rng, lo, hi)
            assert lo <= len(m) <= hi
            assert set(m) <= set(ALPHABET)

    def test_no_salutes(self):
        text = tasks.sample_text() + "".join(tasks.build_task(l, s)["plaintext"] for l in tasks.LEVELS for s in range(50))
        assert "HEIL" not in text and "HITLER" not in text


# ============================================================================
# 3. TASKS
# ============================================================================

# Changing the generator or the levels changes every task; update these hashes
# only together with a new task namespace.
PINNED = {
    (1, 0): "a3d29707bbd22942", (2, 5): "0aa04622868d27da", (3, 17): "7c59b52f36f86762",
    (4, 123): "5e4f61f5d8ce2b59", (5, 1003): "7b75106bcf2466d3",
}


def _task_hash(task):
    payload = json.dumps({k: task[k] for k in ("plaintext", "ciphertext", "key", "cribs")}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _loops_by_dfs(pairs):
    adj = collections.defaultdict(set)
    for p, c in pairs:
        adj[p].add(c)
        adj[c].add(p)
    seen, comps = set(), 0
    for v in adj:
        if v in seen:
            continue
        comps += 1
        stack = [v]
        while stack:
            u = stack.pop()
            if u not in seen:
                seen.add(u)
                stack.extend(adj[u] - seen)
    return len(pairs) - len(adj) + comps


class TestTasks:

    def test_pinned_hashes(self):
        for (level, seed), h in PINNED.items():
            assert _task_hash(tasks.build_task(level, seed)) == h, (level, seed)

    def test_deterministic_across_processes(self):
        code = "import tasks, json; t = tasks.build_task(4, 77); print(json.dumps([t['plaintext'], t['key']]))"
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                             cwd=os.path.dirname(os.path.abspath(__file__))).stdout
        t = tasks.build_task(4, 77)
        assert json.loads(out) == [t["plaintext"], t["key"]]

    @pytest.mark.parametrize("level", sorted(tasks.LEVELS))
    def test_task_consistency(self, level):
        cfg = tasks.LEVELS[level]
        for seed in range(40):
            t = tasks.build_task(level, seed)
            assert cfg["length"][0] <= len(t["plaintext"]) <= cfg["length"][1]
            assert tasks.machine(t["key"]).encrypt(t["plaintext"]) == t["ciphertext"]
            assert cfg["plugs"][0] <= len(t["key"]["plugboard"]) <= cfg["plugs"][1]
            assert t["key"]["reflector"] == "UKW-B"
            assert not tasks.overlaps_sample(t["plaintext"])
            assert ("rotor_order" in t["known"]) == cfg["known_order"]
            trace = tasks.rotor_trace(t["key"], len(t["plaintext"]))
            if cfg["attack"] != "crib":
                assert t["cribs"] == []
                assert len({w[0] for w in trace}) == 1
                continue
            assert len(t["cribs"]) == cfg["n_cribs"]
            pairs = []
            for c in t["cribs"]:
                assert t["plaintext"][c["position"]:c["position"] + len(c["text"])] == c["text"]
                assert cfg["crib_len"][0] <= len(c["text"]) <= cfg["crib_len"][1]
                pairs += [(t["plaintext"][i], t["ciphertext"][i])
                          for i in range(c["position"], c["position"] + len(c["text"]))]
            assert _loops_by_dfs(pairs) >= cfg["min_loops"]
            if cfg["motion"] == "no_middle_step":
                for c in t["cribs"]:
                    span = range(c["position"], c["position"] + len(c["text"]))
                    assert len({trace[i][1] for i in span}) == 1
            else:
                first, last = t["cribs"][0], t["cribs"][-1]
                span = range(first["position"], last["position"] + len(last["text"]))
                assert len({trace[i][0] for i in span}) == 1

    def test_list_tasks(self):
        train = EnigmaDecrypt.list_tasks("train")
        assert EnigmaDecrypt.list_splits() == ["train"] and EnigmaDecrypt.list_tasks("test") == []
        assert len(train) == 5 * len(tasks.TRAIN_SEEDS)
        assert len({t["id"] for t in train}) == len(train)
        assert all(set(t) == {"id", "level", "seed"} for t in train)
        assert EnigmaDecrypt.list_tasks("train") == train


# ============================================================================
# 4. REFERENCE SIMULATOR IN THE KIT
# ============================================================================

class TestKitSimulator:

    def test_python_311_syntax(self):
        ast.parse(simulator_source(), feature_version=(3, 11))

    def test_matches_machine(self):
        ns = {"__name__": "kit"}
        exec(simulator_source(), ns)
        rng = random.Random(0)
        for _ in range(200):
            key = tasks.random_key(rng, rng.randint(0, 13))
            text = "".join(rng.choice(ALPHABET) for _ in range(60))
            kit = ns["EnigmaMachine"](key["rotor_order"], key["ring_settings"], key["initial_positions"],
                                      key["reflector"], [(p[0], p[1]) for p in key["plugboard"]])
            assert kit.encrypt(text) == tasks.machine(key).encrypt(text)

    def test_cli(self, tmp_path):
        path = tmp_path / "enigma_reference.py"
        path.write_text(simulator_source())
        out = subprocess.run([sys.executable, str(path), "--rotors", "I", "II", "III"], input="AAAAAAAAAA",
                             capture_output=True, text=True, check=True).stdout.strip()
        assert out == "BDZGOWCXLT"


# ============================================================================
# 5. KEY SCORING
# ============================================================================

def _params(key, **override):
    d = {"rotor_order": key["rotor_order"], "reflector": key["reflector"],
         "ring_settings": key["ring_settings"], "initial_positions": key["initial_positions"],
         "plugboard": key["plugboard"]}
    d.update(override)
    return SubmitKeyParams(**d)


class TestScoring:

    @pytest.mark.parametrize("level", sorted(tasks.LEVELS))
    def test_gold_key_scores_one(self, level):
        for seed in range(10):
            t = tasks.build_task(level, seed)
            assert score_key(t, t["key"])["reward"] == 1.0

    def test_equivalent_key_scores_one(self):
        t = tasks.build_task(2, 3)
        key = dict(t["key"])
        # Shifting the left rotor's ring and position together keeps its offset.
        key["ring_settings"] = [t["key"]["ring_settings"][0] % 26 + 1] + t["key"]["ring_settings"][1:]
        key["initial_positions"] = [t["key"]["initial_positions"][0] % 26 + 1] + t["key"]["initial_positions"][1:]
        assert score_key(t, key)["reward"] == 1.0

    @pytest.mark.parametrize("level", [1, 4, 5])
    def test_random_keys_score_zero(self, level):
        rng = random.Random(level)
        rewards = []
        for seed in range(20):
            t = tasks.build_task(level, seed)
            rewards += [score_key(t, tasks.random_key(rng, 10))["reward"] for _ in range(10)]
        assert sum(rewards) / len(rewards) < 0.01
        assert max(rewards) < 0.1

    def test_partial_plugboard_is_monotone(self):
        means = []
        for k in range(11):
            total = 0.0
            for seed in range(20):
                t = tasks.build_task(2, seed)
                key = dict(t["key"], plugboard=t["key"]["plugboard"][:k])
                total += score_key(t, key)["reward"]
            means.append(total / 20)
        assert means == sorted(means) and means[0] < 0.5 and means[-1] == 1.0

    def test_crib_positions_not_scored(self):
        t = tasks.build_task(1, 0)
        assert len(scored_positions(t)) == len(t["plaintext"]) - sum(len(c["text"]) for c in t["cribs"])

    @pytest.mark.parametrize("override,msg", [
        ({"rotor_order": ["I", "I", "II"]}, "rotor_order"),
        ({"rotor_order": ["I", "II", "VI"]}, "rotor_order"),
        ({"reflector": "UKW-D"}, "reflector"),
        ({"ring_settings": [0, 1, 1]}, "ring_settings"),
        ({"initial_positions": [1, 27, 1]}, "initial_positions"),
        ({"initial_positions": "AB"}, "initial_positions"),
        ({"plugboard": ["AB", "BC"]}, "more than one"),
        ({"plugboard": ["AA"]}, "two different"),
        ({"plugboard": ["A1"]}, "two different"),
        ({"plugboard": [a + b for a, b in zip(ALPHABET[:14], ALPHABET[12:])][:14]}, "13"),
    ])
    def test_invalid_keys(self, override, msg):
        t = tasks.build_task(1, 0)
        with pytest.raises(ValueError, match=msg):
            parse_key(_params(t["key"], **override))

    def test_letters_for_settings(self):
        t = tasks.build_task(1, 0)
        rings = "".join(ALPHABET[r - 1] for r in t["key"]["ring_settings"])
        pos = "".join(ALPHABET[p - 1].lower() for p in t["key"]["initial_positions"])
        key = parse_key(_params(t["key"], ring_settings=rings, initial_positions=pos,
                                plugboard=[p.lower() for p in t["key"]["plugboard"]]))
        assert score_key(t, key)["reward"] == 1.0

    @pytest.mark.parametrize("rings,pos,plugs,order", [
        ("{r}", "{p}", "{pb_space}", "{o_space}"),
        ('"{r}"', '"{p}"', "{pb_comma}", '{o_json}'),
        ("{rn_space}", "{pn_space}", "{pb_json}", "{o_space}"),
        ("{rn_comma}", "{pn_comma}", "{pb_space}", "{o_space}"),
        ("{rn_json}", "{pn_json}", "{pb_space}", "{o_space}"),
        ("{rn_json_str}", "{pn_json_str}", "{pb_pairs_json}", "{o_space}"),
        ("{rl_json}", "{pl_json}", "{pb_space}", "{o_space}"),
    ])
    def test_key_field_encodings(self, rings, pos, plugs, order):
        """Every reasonable way of writing the same key scores 1."""
        t = tasks.build_task(1, 0)
        k = t["key"]
        r, p = k["ring_settings"], k["initial_positions"]
        letters = lambda v: "".join(ALPHABET[x - 1] for x in v)
        f = {"r": letters(r), "p": letters(p).lower(),
             "rn_space": " ".join(map(str, r)), "pn_space": " ".join(map(str, p)),
             "rn_comma": ",".join(map(str, r)), "pn_comma": ", ".join(map(str, p)),
             "rn_json": json.dumps(r), "pn_json": json.dumps(p),
             "rn_json_str": json.dumps([str(x) for x in r]), "pn_json_str": json.dumps([str(x) for x in p]),
             "rl_json": json.dumps(list(letters(r))), "pl_json": json.dumps(list(letters(p))),
             "pb_space": " ".join(k["plugboard"]), "pb_comma": ", ".join(x.lower() for x in k["plugboard"]),
             "pb_json": json.dumps(k["plugboard"]), "pb_pairs_json": json.dumps([list(x) for x in k["plugboard"]]),
             "o_space": " ".join(k["rotor_order"]), "o_json": json.dumps(k["rotor_order"])}
        params = SubmitKeyParams(rotor_order=order.format(**f), reflector="UKW-B",
                                 ring_settings=rings.format(**f), initial_positions=pos.format(**f),
                                 plugboard=plugs.format(**f))
        assert score_key(t, parse_key(params))["reward"] == 1.0

    @pytest.mark.parametrize("order,reflector,rings", [
        ("{o_arabic}", "UKWB", "{rn_dash}"), ("{o_dash}", "B", "{rn_space}"), ("{o_space}", "ukw b", "{rn_space}"),
    ])
    def test_rotor_and_reflector_spellings(self, order, reflector, rings):
        t = tasks.build_task(1, 0)
        k = t["key"]
        f = {"o_arabic": " ".join(str(["I", "II", "III", "IV", "V"].index(r) + 1) for r in k["rotor_order"]),
             "o_dash": "-".join(k["rotor_order"]), "o_space": " ".join(k["rotor_order"]),
             "rn_dash": "-".join(map(str, k["ring_settings"])), "rn_space": " ".join(map(str, k["ring_settings"]))}
        key = parse_key(_params(k, rotor_order=order.format(**f), reflector=reflector, ring_settings=rings.format(**f)))
        assert score_key(t, key)["reward"] == 1.0

    def test_native_lists_accepted(self):
        t = tasks.build_task(1, 0)
        assert score_key(t, parse_key(_params(t["key"])))["reward"] == 1.0

    def test_empty_plugboard(self):
        t = tasks.build_task(1, 0)
        assert parse_key(_params(t["key"], plugboard=""))["plugboard"] == []

    def test_extra_field_rejected(self):
        t = tasks.build_task(1, 0)
        with pytest.raises(Exception):
            SubmitKeyParams(**_params(t["key"]).model_dump(), note="x")


# ============================================================================
# 6. ENVIRONMENT (fake sandbox)
# ============================================================================

@dataclass
class FakeSandbox:
    started: bool = False
    stopped: bool = False
    calls: list = field(default_factory=list)

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    async def run(self, cmd, **kwargs):
        self.calls.append(cmd)
        return "", 0


class _TestEnv(EnigmaDecrypt):
    def __init__(self, level, seed):
        from openreward.environments import Environment
        spec = {"id": tasks.task_id(level, seed), "level": level, "seed": seed}
        Environment.__init__(self, spec)
        self.task = tasks.build_task(level, seed)
        self.submitted = False
        self.sandbox = FakeSandbox()


def _non_crib_windows(task, n=12):
    scored = set(scored_positions(task))
    p = task["plaintext"]
    return [p[i:i + n] for i in range(len(p) - n + 1) if all(j in scored for j in range(i, i + n))]


@pytest.fixture
def uploads(monkeypatch):
    got = {}

    async def fake_upload(sandbox, path, content):
        got[path] = content

    monkeypatch.setattr(enigma_env, "upload_text", fake_upload)
    return got


class TestEnvironment:

    def test_requires_api_key(self):
        with pytest.raises(ValueError, match="api_key"):
            EnigmaDecrypt({"id": "L1-0", "level": 1, "seed": 0}, secrets={})

    def test_rejects_mismatched_id(self):
        with pytest.raises(ValueError, match="invalid task spec"):
            EnigmaDecrypt({"id": "L1-1", "level": 1, "seed": 0}, secrets={"api_key": "x"})

    @pytest.mark.parametrize("level", sorted(tasks.LEVELS))
    def test_setup_uploads_kit_by_level(self, level, uploads):
        env = _TestEnv(level, 4)
        asyncio.run(env.setup())
        expected = {"ciphertext.txt", "task.md"}
        if tasks.LEVELS[level]["kit"]:
            expected |= {"enigma_reference.py", "german_sample.txt"}
        assert set(uploads) == {f"{enigma_env.WORKSPACE}/{n}" for n in expected}
        assert env.sandbox.started
        for content in uploads.values():
            assert env.task["plaintext"] not in content
        assert all(env.task["plaintext"] not in c for c in env.sandbox.calls)
        task_md = uploads[f"{enigma_env.WORKSPACE}/task.md"]
        assert ("Machine specification" in task_md) != tasks.LEVELS[level]["kit"]
        asyncio.run(env.teardown())
        assert env.sandbox.stopped

    def test_setup_refuses_leaking_files(self, uploads, monkeypatch):
        env = _TestEnv(1, 0)
        monkeypatch.setattr(env, "workspace_files", lambda: {"task.md": "x" + env.task["plaintext"]})
        with pytest.raises(RuntimeError, match="plaintext present") as e:
            asyncio.run(env.setup())
        assert env.task["plaintext"] not in str(e.value)
        assert not uploads

    @pytest.mark.parametrize("level", sorted(tasks.LEVELS))
    def test_prompt_and_files_do_not_leak(self, level, uploads):
        env = _TestEnv(level, 9)
        prompt = asyncio.run(env.get_prompt())[0].text
        asyncio.run(env.setup())
        ws = enigma_env.WORKSPACE
        task_texts = [prompt, uploads[f"{ws}/task.md"], uploads[f"{ws}/ciphertext.txt"]]
        kit_texts = [c for path, c in uploads.items() if path.endswith((".py", "sample.txt"))]
        short, long = _non_crib_windows(env.task, 12), _non_crib_windows(env.task, tasks.SAMPLE_OVERLAP)
        for text in task_texts:
            assert not any(w in text for w in short)
        # The text sample shares phrases with real messages by design, but no long passage.
        for text in kit_texts:
            assert not any(w in text for w in long)
        for text in task_texts + kit_texts:
            assert json.dumps(env.task["key"]["plugboard"]) not in text

    def test_submit_gold_then_repeat(self):
        env = _TestEnv(3, 2)
        out = asyncio.run(env.submit_key(_params(env.task["key"])))
        assert out.reward == 1.0 and out.finished
        blob = out.blocks[0].text + json.dumps(out.metadata)
        assert not any(w in blob for w in _non_crib_windows(env.task))
        again = asyncio.run(env.submit_key(_params(env.task["key"])))
        assert again.reward == enigma_env.REPEAT_SUBMISSION_PENALTY and again.finished

    def test_invalid_submit_does_not_finish(self):
        env = _TestEnv(1, 0)
        out = asyncio.run(env.submit_key(_params(env.task["key"], rotor_order=["I", "I", "I"])))
        assert out.reward == 0.0 and not out.finished
        good = asyncio.run(env.submit_key(_params(env.task["key"])))
        assert good.reward == 1.0 and good.finished

    def test_wrong_key_scores_zero(self):
        env = _TestEnv(5, 1)
        key = tasks.random_key(random.Random(9), 10)
        out = asyncio.run(env.submit_key(_params(key)))
        assert out.finished and out.reward < 0.1

    def test_toolset_limits(self):
        assert EnigmaDecrypt.workspace_root == "/workspace"
        assert enigma_env.EnigmaCLI.max_bash_timeout == 900
        assert enigma_env.EnigmaCLI in EnigmaDecrypt.toolsets
