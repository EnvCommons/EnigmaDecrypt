"""
Comprehensive test suite for the Enigma Decrypt environment.

Tests cover:
1. Enigma machine correctness (historical test vectors, properties)
2. Task corpus integrity (round-trips, cribs, splits)
3. Environment tool validation (input validation, scoring)
4. End-to-end workflow
"""

import pytest
import asyncio
import itertools
import math
import random
from collections import Counter

from enigma_machine import EnigmaMachine, ROTORS, REFLECTORS, ALPHABET
from tasks import ALL_TASKS, ALL_SPLITS, get_task_counts
from openreward.environments import TextBlock
from enigma import EnigmaDecrypt, TryDecryptInput, SubmitInput, expected_best_random_accuracy


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
# 2. TASK CORPUS INTEGRITY TESTS
# ============================================================================

class TestTaskCorpus:

    def test_total_task_count(self):
        """Verify we have exactly 60 tasks."""
        assert len(ALL_TASKS) == 60

    def test_split_counts(self):
        """Verify train/test split sizes."""
        counts = get_task_counts()
        assert counts["train"]["easy"] == 15
        assert counts["train"]["medium"] == 15
        assert counts["train"]["hard"] == 10
        assert counts["test"]["easy"] == 5
        assert counts["test"]["medium"] == 10
        assert counts["test"]["hard"] == 5

    def test_unique_ids(self):
        """All task IDs are unique."""
        ids = list(ALL_TASKS.keys())
        assert len(ids) == len(set(ids))

    def test_all_splits_valid(self):
        """All tasks have valid split values."""
        for task in ALL_TASKS.values():
            assert task["split"] in ALL_SPLITS

    def test_all_difficulties_valid(self):
        """All tasks have valid difficulty values."""
        for task in ALL_TASKS.values():
            assert task["difficulty"] in ("easy", "medium", "hard")

    @pytest.mark.parametrize("task_id", list(ALL_TASKS.keys()))
    def test_task_roundtrip(self, task_id):
        """Every task's ciphertext decrypts to its plaintext with stored settings."""
        task = ALL_TASKS[task_id]
        machine = EnigmaMachine(
            rotor_order=task["rotor_order"],
            ring_settings=task["ring_settings"],
            initial_positions=task["initial_positions"],
            reflector=task["reflector"],
            plugboard=[tuple(p) for p in task["plugboard"]],
        )
        decrypted = machine.encrypt(task["ciphertext"])
        assert decrypted == task["plaintext"], (
            f"Task {task_id} roundtrip failed: "
            f"expected '{task['plaintext'][:40]}...', got '{decrypted[:40]}...'"
        )

    @pytest.mark.parametrize("task_id", list(ALL_TASKS.keys()))
    def test_crib_positions(self, task_id):
        """All cribs appear at their stated positions in the plaintext."""
        task = ALL_TASKS[task_id]
        for crib in task["cribs"]:
            text = crib["text"]
            pos = crib["position"]
            actual = task["plaintext"][pos:pos + len(text)]
            assert actual == text, (
                f"Crib mismatch in task {task_id}: "
                f"expected '{text}' at pos {pos}, found '{actual}'"
            )

    @pytest.mark.parametrize("task_id", list(ALL_TASKS.keys()))
    def test_ciphertext_grouped_matches(self, task_id):
        """Grouped ciphertext matches raw ciphertext when spaces removed."""
        task = ALL_TASKS[task_id]
        ungrouped = task["ciphertext_grouped"].replace(" ", "")
        assert ungrouped == task["ciphertext"]

    @pytest.mark.parametrize("task_id", list(ALL_TASKS.keys()))
    def test_plaintext_is_uppercase_az(self, task_id):
        """All plaintexts contain only uppercase A-Z."""
        task = ALL_TASKS[task_id]
        for c in task["plaintext"]:
            assert c in ALPHABET, f"Invalid char '{c}' in plaintext of {task_id}"

    @pytest.mark.parametrize("task_id", list(ALL_TASKS.keys()))
    def test_ciphertext_is_uppercase_az(self, task_id):
        """All ciphertexts contain only uppercase A-Z."""
        task = ALL_TASKS[task_id]
        for c in task["ciphertext"]:
            assert c in ALPHABET, f"Invalid char '{c}' in ciphertext of {task_id}"

    @pytest.mark.parametrize("task_id", list(ALL_TASKS.keys()))
    def test_no_self_encryption_in_tasks(self, task_id):
        """No character maps to itself in any task."""
        task = ALL_TASKS[task_id]
        for i, (p, c) in enumerate(zip(task["plaintext"], task["ciphertext"])):
            assert p != c, (
                f"Self-encryption in task {task_id} at pos {i}: {p} -> {c}"
            )

    def test_revealed_info_easy(self):
        """Easy tasks reveal rotor_order, ring_settings, reflector, plugboard."""
        for task in ALL_TASKS.values():
            if task["difficulty"] == "easy":
                revealed = task["revealed_info"]
                assert "rotor_order" in revealed
                assert "ring_settings" in revealed
                assert "reflector" in revealed
                assert "plugboard" in revealed
                assert "initial_positions" not in revealed

    def test_revealed_info_medium(self):
        """Medium tasks reveal rotor_order and reflector only."""
        for task in ALL_TASKS.values():
            if task["difficulty"] == "medium":
                revealed = task["revealed_info"]
                assert "rotor_order" in revealed
                assert "reflector" in revealed
                assert "ring_settings" not in revealed
                assert "plugboard" not in revealed

    def test_revealed_info_hard(self):
        """Hard tasks reveal only reflector."""
        for task in ALL_TASKS.values():
            if task["difficulty"] == "hard":
                revealed = task["revealed_info"]
                assert "reflector" in revealed
                assert "rotor_order" not in revealed
                assert "ring_settings" not in revealed
                assert "plugboard" not in revealed


# ============================================================================
# Scoring reference (independent of the environment's implementation)
# ============================================================================

def _scored_positions(task):
    cribbed = set()
    for crib in task["cribs"]:
        cribbed.update(range(crib["position"], crib["position"] + len(crib["text"])))
    return [i for i in range(len(task["plaintext"])) if i not in cribbed]


def _scored_accuracy(text, task):
    plaintext = task["plaintext"]
    positions = _scored_positions(task)
    correct = sum(1 for i in positions if i < len(text) and text[i] == plaintext[i])
    return correct / (len(positions) + max(0, len(text) - len(plaintext)))


def _chance_accuracy(task):
    positions = _scored_positions(task)
    commonest = Counter(task["plaintext"][i] for i in positions).most_common(1)[0][1] / len(positions)
    return max(commonest, expected_best_random_accuracy(len(positions), 100))


def _expected_reward(text, task):
    chance = _chance_accuracy(task)
    return max(0.0, (_scored_accuracy(text, task) - chance) / (1 - chance))


def _wrong_letters(text):
    """Each letter replaced by a different one, so no position matches."""
    return "".join(ALPHABET[(ALPHABET.index(c) + 1) % 26] for c in text)


def _random_settings(task, rng):
    """A uniformly random key consistent with what the prompt reveals."""
    revealed = task["revealed_info"]
    if "plugboard" in revealed:
        plugboard = revealed["plugboard"]
    else:
        letters = rng.sample(ALPHABET, 2 * revealed["num_plugboard_pairs"])
        plugboard = [[letters[2 * i], letters[2 * i + 1]] for i in range(revealed["num_plugboard_pairs"])]
    return TryDecryptInput(
        rotor_order=revealed.get("rotor_order") or rng.sample(["I", "II", "III", "IV", "V"], 3),
        ring_settings=revealed.get("ring_settings") or [rng.randint(1, 26) for _ in range(3)],
        initial_positions=[rng.randint(1, 26) for _ in range(3)],
        reflector=revealed["reflector"],
        plugboard=plugboard,
    )


# ============================================================================
# 3. ENVIRONMENT TOOL TESTS
# ============================================================================

class TestEnvironmentTools:

    @pytest.fixture
    def easy_task_id(self):
        """Return the ID of an easy task."""
        for task_id, task in ALL_TASKS.items():
            if task["difficulty"] == "easy":
                return task_id
        pytest.fail("No easy task found")

    @pytest.fixture
    def easy_task(self, easy_task_id):
        return ALL_TASKS[easy_task_id]

    @pytest.mark.asyncio
    async def test_correct_decryption(self, easy_task_id, easy_task):
        """try_decrypt with correct settings returns the plaintext."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        result = await env.try_decrypt(TryDecryptInput(
            rotor_order=easy_task["rotor_order"],
            ring_settings=easy_task["ring_settings"],
            initial_positions=easy_task["initial_positions"],
            reflector=easy_task["reflector"],
            plugboard=easy_task["plugboard"],
        ))
        assert result.metadata["decrypted_text"] == easy_task["plaintext"]
        assert result.reward == 0.0
        assert result.finished is False

    @pytest.mark.asyncio
    async def test_perfect_submission(self, easy_task_id, easy_task):
        """Submitting exact plaintext gives reward 1.0."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        result = await env.submit(SubmitInput(plaintext=easy_task["plaintext"]))
        assert result.reward == 1.0
        assert result.finished is True

    @pytest.mark.asyncio
    async def test_empty_submission(self, easy_task_id):
        """Submitting empty string gives reward 0.0."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        result = await env.submit(SubmitInput(plaintext=""))
        assert result.reward == 0.0
        assert result.finished is True

    @pytest.mark.asyncio
    async def test_completely_wrong_submission(self, easy_task_id, easy_task):
        """Submitting all wrong characters gives low reward."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        wrong = "X" * len(easy_task["plaintext"])
        result = await env.submit(SubmitInput(plaintext=wrong))
        # Might have some X's matching by coincidence, but reward should be low
        assert result.reward < 0.2
        assert result.finished is True

    @pytest.mark.asyncio
    async def test_partial_submission(self, easy_task_id, easy_task):
        """Half-correct submission gives approximately half reward."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        correct = easy_task["plaintext"]
        half_len = len(correct) // 2
        partial = correct[:half_len] + "X" * (len(correct) - half_len)
        result = await env.submit(SubmitInput(plaintext=partial))
        assert 0.3 < result.reward < 0.7
        assert result.finished is True

    @pytest.mark.asyncio
    async def test_submission_normalizes_case(self, easy_task_id, easy_task):
        """Lowercase input is normalized to uppercase."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        result = await env.submit(SubmitInput(plaintext=easy_task["plaintext"].lower()))
        assert result.reward == 1.0

    @pytest.mark.asyncio
    async def test_submission_strips_non_alpha(self, easy_task_id, easy_task):
        """Non-alpha characters are stripped from submission."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        spaced = " ".join(easy_task["plaintext"][i:i+5] for i in range(0, len(easy_task["plaintext"]), 5))
        result = await env.submit(SubmitInput(plaintext=spaced))
        assert result.reward == 1.0

    @pytest.mark.asyncio
    async def test_invalid_rotor_name(self, easy_task_id):
        """Invalid rotor name returns error."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        result = await env.try_decrypt(TryDecryptInput(
            rotor_order=["I", "II", "VI"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        ))
        assert "error" in result.metadata
        assert result.reward == 0.0
        assert result.finished is False

    @pytest.mark.asyncio
    async def test_duplicate_rotors(self, easy_task_id):
        """Duplicate rotors return error."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        result = await env.try_decrypt(TryDecryptInput(
            rotor_order=["I", "I", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        ))
        assert "error" in result.metadata

    @pytest.mark.asyncio
    async def test_ring_setting_out_of_range(self, easy_task_id):
        """Ring setting outside 1-26 returns error."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        result = await env.try_decrypt(TryDecryptInput(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 27],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        ))
        assert "error" in result.metadata

    @pytest.mark.asyncio
    async def test_position_out_of_range(self, easy_task_id):
        """Position outside 1-26 returns error."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        result = await env.try_decrypt(TryDecryptInput(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[0, 1, 1],
            reflector="UKW-B",
            plugboard=[],
        ))
        assert "error" in result.metadata

    @pytest.mark.asyncio
    async def test_invalid_reflector(self, easy_task_id):
        """Invalid reflector returns error."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        result = await env.try_decrypt(TryDecryptInput(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-D",
            plugboard=[],
        ))
        assert "error" in result.metadata

    @pytest.mark.asyncio
    async def test_duplicate_plugboard_letter(self, easy_task_id):
        """Duplicate letter across plugboard pairs returns error."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        result = await env.try_decrypt(TryDecryptInput(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[["A", "B"], ["A", "C"]],
        ))
        assert "error" in result.metadata

    @pytest.mark.asyncio
    async def test_self_plugboard_pair(self, easy_task_id):
        """A letter paired with itself returns error."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        result = await env.try_decrypt(TryDecryptInput(
            rotor_order=["I", "II", "III"],
            ring_settings=[1, 1, 1],
            initial_positions=[1, 1, 1],
            reflector="UKW-B",
            plugboard=[["A", "A"]],
        ))
        assert "error" in result.metadata

    @pytest.mark.asyncio
    async def test_attempt_counter(self, easy_task_id, easy_task):
        """Attempt counter increments correctly."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        for i in range(3):
            result = await env.try_decrypt(TryDecryptInput(
                rotor_order=easy_task["rotor_order"],
                ring_settings=easy_task["ring_settings"],
                initial_positions=easy_task["initial_positions"],
                reflector=easy_task["reflector"],
                plugboard=easy_task["plugboard"],
            ))
            assert result.metadata["attempt"] == i + 1

    @pytest.mark.asyncio
    async def test_attempt_limit(self, easy_task_id, easy_task):
        """Max attempts limit is enforced."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        env.attempts = env.max_attempts  # Set to max

        result = await env.try_decrypt(TryDecryptInput(
            rotor_order=easy_task["rotor_order"],
            ring_settings=easy_task["ring_settings"],
            initial_positions=easy_task["initial_positions"],
            reflector=easy_task["reflector"],
            plugboard=easy_task["plugboard"],
        ))
        assert "error" in result.metadata
        assert "Maximum" in result.blocks[0].text

    @staticmethod
    def _settings(task, **overrides):
        settings = dict(
            rotor_order=task["rotor_order"],
            ring_settings=task["ring_settings"],
            initial_positions=task["initial_positions"],
            reflector=task["reflector"],
            plugboard=task["plugboard"],
        )
        settings.update(overrides)
        return TryDecryptInput(**settings)

    @staticmethod
    def _accuracy(text, task):
        return _scored_accuracy(text, task)

    def _budget_inputs(self, task, n):
        """n attempt inputs: one partially correct decryption in the middle
        (correct settings minus one plugboard pair), all others wrong settings."""
        wrong_rotors = [r for r in ["I", "II", "III", "IV", "V"] if r not in task["rotor_order"]][:2]
        wrong_rotors.append(task["rotor_order"][0])
        inputs = []
        for i in range(n):
            if i == n // 2:
                inputs.append(self._settings(task, plugboard=task["plugboard"][1:]))
            else:
                pos = [(i % 26) + 1, ((i // 26) % 26) + 1, 1]
                inputs.append(self._settings(task, rotor_order=wrong_rotors, initial_positions=pos))
        return inputs

    def test_attempt_budget_is_100(self, easy_task_id):
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        assert env.max_attempts == 100

    @pytest.mark.asyncio
    async def test_attempt_budget_finishes_with_best_attempt_accuracy(self, easy_task_id, easy_task):
        """The call that uses the last attempt returns its decryption, finishes the
        episode, and is rewarded with the best attempt's accuracy as submit would score it."""
        assert len(easy_task["plugboard"]) >= 2
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        plaintext = easy_task["plaintext"]
        inputs = self._budget_inputs(easy_task, env.max_attempts)

        decryptions = []
        for i, inp in enumerate(inputs[:-1]):
            result = await env.try_decrypt(inp)
            assert result.finished is False
            assert result.reward == 0.0
            assert set(result.metadata) == {"attempt", "decrypted_text"}
            assert result.metadata["attempt"] == i + 1
            assert "%" not in result.blocks[0].text
            assert "correct" not in result.blocks[0].text.lower()
            assert "accuracy" not in result.blocks[0].text.lower()
            decryptions.append(result.metadata["decrypted_text"])

        last = await env.try_decrypt(inputs[-1])
        decryptions.append(last.metadata["decrypted_text"])
        assert last.finished is True
        assert last.metadata["attempt"] == env.max_attempts

        accuracies = [self._accuracy(d, easy_task) for d in decryptions]
        best = max(accuracies)
        best_text = decryptions[accuracies.index(best)]
        # The best attempt is neither perfect nor the last one, so the reward is
        # not trivially 1.0 or the final attempt's accuracy.
        assert 0.0 < best < 1.0
        assert accuracies[-1] < best

        fresh = EnigmaDecrypt(task_spec={"id": easy_task_id})
        as_submitted = await fresh.submit(SubmitInput(plaintext=best_text))
        assert best > _chance_accuracy(easy_task)
        assert last.reward == as_submitted.reward == _expected_reward(best_text, easy_task) > 0.0
        assert last.metadata["accuracy"] == as_submitted.metadata["accuracy"] == best
        assert last.metadata["correct_chars"] == as_submitted.metadata["correct_chars"]
        assert last.metadata["total_chars"] == as_submitted.metadata["total_chars"]
        assert "plaintext" not in last.metadata

        text = last.blocks[0].text
        grouped = " ".join(decryptions[-1][i:i + 5] for i in range(0, len(decryptions[-1]), 5))
        assert grouped in text
        assert "Attempt budget used up" in text
        assert f"{best:.2%}" in text
        assert f"({as_submitted.metadata['correct_chars']}/{as_submitted.metadata['total_chars']} non-crib characters correct)" in text
        assert f"reward {last.reward:.3f}" in text

    @pytest.mark.asyncio
    async def test_submit_before_budget_scores_submitted_text(self, easy_task_id, easy_task):
        """An explicit submit scores the submitted text, not the best attempt."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        for _ in range(3):
            result = await env.try_decrypt(self._settings(easy_task))
            assert result.finished is False
        plaintext = easy_task["plaintext"]
        half = plaintext[:len(plaintext) // 2] + _wrong_letters(plaintext[len(plaintext) // 2:])
        final = await env.submit(SubmitInput(plaintext=half))
        assert final.finished is True
        assert 0.0 < final.reward == _expected_reward(half, easy_task) < 1.0
        assert final.metadata["attempts_used"] == 3

    @pytest.mark.asyncio
    async def test_calls_after_budget_finish_are_refused(self, easy_task_id, easy_task):
        """Once the last attempt finishes the episode, further tool calls are not run."""
        env = EnigmaDecrypt(task_spec={"id": easy_task_id})
        for inp in self._budget_inputs(easy_task, env.max_attempts):
            res = await env._call_tool("try_decrypt", inp.model_dump())
            assert res.root.ok is True
        assert res.root.output.finished is True

        after_decrypt = await env._call_tool("try_decrypt", self._settings(easy_task).model_dump())
        after_submit = await env._call_tool("submit", {"plaintext": easy_task["plaintext"]})
        for res in (after_decrypt, after_submit):
            assert res.root.ok is False
            assert res.root.reason == "episode_finished"
        assert env.attempts == env.max_attempts


class TestChanceCorrectedReward:
    """Both terminal paths score chance-corrected accuracy over non-crib positions:
    no-skill play (random decryptions, letter-frequency filler, copying the cribs)
    scores 0, a perfect decryption scores 1, and real progress is rewarded."""

    @pytest.mark.parametrize("n,attempts,p", [(1, 1, 0.3), (3, 2, 0.3), (4, 3, 1 / 25), (5, 2, 0.5)])
    def test_expected_best_random_accuracy_matches_enumeration(self, n, attempts, p):
        pmf = [math.comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(n + 1)]
        expected_max = sum(
            math.prod(pmf[k] for k in ks) * max(ks)
            for ks in itertools.product(range(n + 1), repeat=attempts)
        )
        assert expected_best_random_accuracy(n, attempts, p) == pytest.approx(expected_max / n, abs=1e-12)

    def test_expected_best_random_accuracy_grows_with_attempts(self):
        values = [expected_best_random_accuracy(70, a) for a in (1, 10, 100)]
        assert values[0] == pytest.approx(1 / 25)
        assert values[0] < values[1] < values[2] < 0.2

    @pytest.mark.parametrize("task_id", list(ALL_TASKS.keys()))
    def test_chance_level_leaves_room_for_progress(self, task_id):
        env = EnigmaDecrypt(task_spec={"id": task_id})
        assert len(env.scored_positions) > 0
        assert env.chance_accuracy == pytest.approx(_chance_accuracy(ALL_TASKS[task_id]))
        assert 0.0 < env.chance_accuracy < 0.3

    @pytest.mark.asyncio
    async def test_random_decryption_budget_scores_about_zero(self):
        """Spending all 100 attempts on random keys earns ~0 on every task."""
        rng = random.Random(1234)
        rewards = []
        for task_id, task in ALL_TASKS.items():
            env = EnigmaDecrypt(task_spec={"id": task_id})
            for _ in range(env.max_attempts):
                result = await env.try_decrypt(_random_settings(task, rng))
            assert result.finished is True
            assert result.reward < 0.1
            rewards.append(result.reward)
        assert sum(rewards) / len(rewards) < 0.01

    @pytest.mark.asyncio
    @pytest.mark.parametrize("task_id", list(ALL_TASKS.keys()))
    async def test_submissions_without_decrypting_score_zero(self, task_id):
        task = ALL_TASKS[task_id]
        plaintext = task["plaintext"]
        rng = random.Random(task_id)
        cribs_only = list(_wrong_letters(plaintext))
        cribs_with_e = ["E"] * len(plaintext)
        for crib in task["cribs"]:
            for j, c in enumerate(crib["text"]):
                cribs_only[crib["position"] + j] = c
                cribs_with_e[crib["position"] + j] = c
        guesses = [
            "".join(rng.choice(ALPHABET) for _ in plaintext),
            "E" * len(plaintext),
            "X" * len(plaintext),
            "".join(cribs_only),
            "".join(cribs_with_e),
        ]
        for guess in guesses:
            env = EnigmaDecrypt(task_spec={"id": task_id})
            result = await env.submit(SubmitInput(plaintext=guess))
            assert result.finished is True
            assert result.reward == 0.0, guess

    @pytest.mark.asyncio
    async def test_perfect_decryption_scores_one_on_both_paths(self):
        rng = random.Random(7)
        for task_id, task in list(ALL_TASKS.items())[::10]:
            env = EnigmaDecrypt(task_spec={"id": task_id})
            assert (await env.submit(SubmitInput(plaintext=task["plaintext"]))).reward == 1.0

            correct = TryDecryptInput(
                rotor_order=task["rotor_order"],
                ring_settings=task["ring_settings"],
                initial_positions=task["initial_positions"],
                reflector=task["reflector"],
                plugboard=task["plugboard"],
            )
            env = EnigmaDecrypt(task_spec={"id": task_id})
            await env.try_decrypt(correct)
            for _ in range(env.max_attempts - 1):
                result = await env.try_decrypt(_random_settings(task, rng))
            assert result.finished is True
            assert result.reward == 1.0

    @pytest.mark.asyncio
    @pytest.mark.parametrize("task_id", [tid for tid in ALL_TASKS][::7])
    async def test_partial_progress_is_monotone(self, task_id):
        """Reward is 0 up to the chance level, then strictly increases with each
        additional correct non-crib character, reaching 1 when all are correct."""
        task = ALL_TASKS[task_id]
        plaintext = task["plaintext"]
        positions = _scored_positions(task)
        chance = _chance_accuracy(task)
        rewards = []
        for k in range(len(positions) + 1):
            text = list(_wrong_letters(plaintext))
            for i in positions[:k]:
                text[i] = plaintext[i]
            env = EnigmaDecrypt(task_spec={"id": task_id})
            result = await env.submit(SubmitInput(plaintext="".join(text)))
            assert result.metadata["correct_chars"] == k
            rewards.append(result.reward)
        for k, (prev, cur) in enumerate(zip(rewards, rewards[1:]), start=1):
            if k / len(positions) <= chance:
                assert cur == 0.0
            else:
                assert cur > prev
        assert rewards[-1] == 1.0


# ============================================================================
# 4. ENVIRONMENT CLASS TESTS
# ============================================================================

class TestEnvironmentClass:

    def test_list_splits(self):
        """list_splits returns train and test."""
        splits = EnigmaDecrypt.list_splits()
        assert "train" in splits
        assert "test" in splits

    def test_list_tasks_train(self):
        """list_tasks returns 40 train tasks."""
        tasks = EnigmaDecrypt.list_tasks("train")
        assert len(tasks) == 40

    def test_list_tasks_test(self):
        """list_tasks returns 20 test tasks."""
        tasks = EnigmaDecrypt.list_tasks("test")
        assert len(tasks) == 20

    def test_list_tasks_invalid_split(self):
        """list_tasks raises on invalid split."""
        with pytest.raises(ValueError):
            EnigmaDecrypt.list_tasks("invalid")

    def test_invalid_task_id(self):
        """Invalid task ID raises ValueError."""
        with pytest.raises(ValueError):
            EnigmaDecrypt(task_spec={"id": "nonexistent_task"})

    @pytest.mark.asyncio
    async def test_get_prompt_returns_textblock(self):
        """get_prompt returns a list of TextBlock."""
        task_id = list(ALL_TASKS.keys())[0]
        env = EnigmaDecrypt(task_spec={"id": task_id})
        prompt = await env.get_prompt()
        assert isinstance(prompt, list)
        assert len(prompt) == 1
        assert isinstance(prompt[0], TextBlock)
        assert len(prompt[0].text) > 100

    @pytest.mark.asyncio
    async def test_prompt_contains_ciphertext(self):
        """Prompt includes the ciphertext."""
        task_id = list(ALL_TASKS.keys())[0]
        task = ALL_TASKS[task_id]
        env = EnigmaDecrypt(task_spec={"id": task_id})
        prompt = await env.get_prompt()
        assert task["ciphertext_grouped"] in prompt[0].text

    @pytest.mark.asyncio
    async def test_prompt_does_not_contain_plaintext(self):
        """Prompt does NOT include the plaintext."""
        task_id = list(ALL_TASKS.keys())[0]
        task = ALL_TASKS[task_id]
        env = EnigmaDecrypt(task_spec={"id": task_id})
        prompt = await env.get_prompt()
        # The full plaintext should not appear in the prompt
        assert task["plaintext"] not in prompt[0].text

    @pytest.mark.asyncio
    async def test_prompt_states_attempt_budget_and_auto_finish(self):
        """Prompt states the 100-attempt budget and that exhausting it ends the episode."""
        env = EnigmaDecrypt(task_spec={"id": list(ALL_TASKS.keys())[0]})
        text = (await env.get_prompt())[0].text
        assert "(100 attempts max)" in text
        assert "If you use all 100 attempts without submitting, the episode ends" in text


# ============================================================================
# 5. END-TO-END TESTS
# ============================================================================

class TestEndToEnd:

    @pytest.mark.asyncio
    async def test_full_workflow_easy(self):
        """Full workflow: get prompt, try decrypt with correct settings, submit."""
        # Find an easy task
        task_id = None
        for tid, t in ALL_TASKS.items():
            if t["difficulty"] == "easy":
                task_id = tid
                break

        task = ALL_TASKS[task_id]
        env = EnigmaDecrypt(task_spec={"id": task_id})

        # Get prompt
        prompt = await env.get_prompt()
        assert len(prompt[0].text) > 0

        # Try decrypt with correct settings
        result = await env.try_decrypt(TryDecryptInput(
            rotor_order=task["rotor_order"],
            ring_settings=task["ring_settings"],
            initial_positions=task["initial_positions"],
            reflector=task["reflector"],
            plugboard=task["plugboard"],
        ))
        decrypted = result.metadata["decrypted_text"]
        assert decrypted == task["plaintext"]
        assert result.finished is False

        # Submit
        final = await env.submit(SubmitInput(plaintext=decrypted))
        assert final.reward == 1.0
        assert final.finished is True
        assert final.metadata["attempts_used"] == 1

    @pytest.mark.asyncio
    async def test_full_workflow_wrong_then_right(self):
        """Try wrong settings first, then correct settings, then submit."""
        task_id = None
        for tid, t in ALL_TASKS.items():
            if t["difficulty"] == "easy":
                task_id = tid
                break

        task = ALL_TASKS[task_id]
        env = EnigmaDecrypt(task_spec={"id": task_id})

        # Wrong attempt
        result1 = await env.try_decrypt(TryDecryptInput(
            rotor_order=task["rotor_order"],
            ring_settings=task["ring_settings"],
            initial_positions=[1, 1, 1],  # Wrong positions
            reflector=task["reflector"],
            plugboard=task["plugboard"],
        ))
        assert result1.finished is False
        assert result1.metadata["attempt"] == 1

        # Correct attempt
        result2 = await env.try_decrypt(TryDecryptInput(
            rotor_order=task["rotor_order"],
            ring_settings=task["ring_settings"],
            initial_positions=task["initial_positions"],
            reflector=task["reflector"],
            plugboard=task["plugboard"],
        ))
        decrypted = result2.metadata["decrypted_text"]
        assert decrypted == task["plaintext"]
        assert result2.metadata["attempt"] == 2

        # Submit
        final = await env.submit(SubmitInput(plaintext=decrypted))
        assert final.reward == 1.0
        assert final.metadata["attempts_used"] == 2
