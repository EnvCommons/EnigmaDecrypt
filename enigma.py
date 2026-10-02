"""
Enigma Decrypt — OpenReward Environment

An RL environment where agents decrypt WWII-era Enigma-encoded German military
messages. Agents use tools to test Enigma machine configurations and submit
decrypted plaintext for character-level accuracy scoring.
"""

import math
from collections import Counter
from typing import List

from pydantic import BaseModel

from openreward.environments import Environment, JSONObject, ToolOutput, tool, TextBlock
from enigma_machine import EnigmaMachine, ROTORS, REFLECTORS, ALPHABET
from tasks import ALL_TASKS, ALL_SPLITS


# Reward for a submission made after the task has already been graded. Negative
# so repeat submissions are actively discouraged, not merely left unscored.
REPEAT_SUBMISSION_PENALTY = -0.1

# Chance that a wrong-key decryption matches the plaintext at one position.
# Enigma never encrypts a letter to itself, so neither the plaintext letter nor
# a wrong-key output letter equals the ciphertext letter: 25 candidates remain.
RANDOM_MATCH_P = 1 / 25


def expected_best_random_accuracy(n: int, attempts: int, p: float = RANDOM_MATCH_P) -> float:
    """Expected accuracy of the best of `attempts` decryptions of `n` scored
    characters when each character matches independently with probability p:
    E[max of `attempts` iid Binomial(n, p)] / n, computed exactly as
    sum_k P(max > k) = sum_k (1 - F(k)^attempts) with F the Binomial CDF."""
    cdf, expected_max = 0.0, 0.0
    for k in range(n):
        cdf += math.comb(n, k) * p ** k * (1 - p) ** (n - k)
        expected_max += 1.0 - min(cdf, 1.0) ** attempts
    return expected_max / n


class TaskSpec(BaseModel):
    id: str


class TryDecryptInput(BaseModel, extra="forbid"):
    """Configure an Enigma machine and attempt to decrypt the intercepted ciphertext."""
    rotor_order: list[str]
    ring_settings: list[int]
    initial_positions: list[int]
    reflector: str
    plugboard: list[list[str]]


class SubmitInput(BaseModel, extra="forbid"):
    """Submit the final decrypted plaintext for scoring."""
    plaintext: str


class EnigmaDecrypt(Environment):
    """
    WWII Enigma decryption environment.

    The agent receives an intercepted ciphertext encrypted by a Wehrmacht Enigma I
    machine, along with partial information about the machine settings and known
    plaintext fragments (cribs). The agent must deduce the remaining settings and
    recover the original German military message.
    """

    def __init__(self, task_spec: JSONObject, secrets: dict[str, str] = {}) -> None:
        super().__init__(task_spec)
        self.validated = TaskSpec.model_validate(task_spec)

        if self.validated.id not in ALL_TASKS:
            raise ValueError(f"Unknown task ID: {self.validated.id}")

        self.task = ALL_TASKS[self.validated.id]
        self.attempts = 0
        self.max_attempts = 100

        # Scoring ignores the crib positions (their letters are given in the
        # prompt) and is chance-corrected: accuracy at or below what is reachable
        # without decrypting scores 0, a perfect decryption scores 1. That level
        # is the higher of (a) filling every position with the commonest
        # plaintext letter and (b) the expected best of a full budget of random
        # decryptions. Both terminal paths (submit and the budget auto-finish)
        # use the same scale, so neither offers a no-skill floor.
        plaintext = self.task["plaintext"]
        crib_positions = {
            crib["position"] + j for crib in self.task["cribs"] for j in range(len(crib["text"]))
        }
        self.scored_positions = [i for i in range(len(plaintext)) if i not in crib_positions]
        n_scored = len(self.scored_positions)
        commonest_letter_rate = max(Counter(plaintext[i] for i in self.scored_positions).values()) / n_scored
        self.chance_accuracy = max(
            commonest_letter_rate, expected_best_random_accuracy(n_scored, self.max_attempts)
        )

        # Most accurate try_decrypt output so far, as (accuracy, correct_chars,
        # total_chars). Kept server-side only: it becomes the reward when the
        # attempt budget runs out before a submit, and is never shown on a
        # non-terminal attempt (that would be an accuracy oracle).
        self.best_attempt = (0.0, 0, n_scored)

        # Scored submissions this session. submit() reports character-level
        # accuracy against the hidden plaintext ("35/81 characters correct"),
        # which is a per-character oracle: change one letter, resubmit, and the
        # count says whether that letter was right. Uncapped, the plaintext is
        # recoverable letter by letter without ever breaking the cipher. The
        # try_decrypt exploration tool never reports accuracy and keeps its own
        # attempt budget.
        self.submitted = 0

    async def get_prompt(self) -> List[TextBlock]:
        task = self.task
        revealed = task["revealed_info"]

        lines = []

        # The ciphertext
        lines.append("Decrypt this Enigma I ciphertext:")
        lines.append("")
        lines.append(task["ciphertext_grouped"])
        lines.append("")

        # Known settings
        lines.append("Known settings:")
        if "rotor_order" in revealed:
            lines.append(f"  Walzenlage (rotor order, left to right): {' '.join(revealed['rotor_order'])}")
        if "ring_settings" in revealed:
            ring_letters = [ALPHABET[r - 1] for r in revealed["ring_settings"]]
            lines.append(f"  Ringstellung (ring settings): {' '.join(ring_letters)} ({', '.join(str(r) for r in revealed['ring_settings'])})")
        if "reflector" in revealed:
            lines.append(f"  Umkehrwalze (reflector): {revealed['reflector']}")
        if "plugboard" in revealed:
            pairs = [f"{p[0]}/{p[1]}" for p in revealed["plugboard"]]
            lines.append(f"  Steckerverbindungen (plugboard): {' '.join(pairs)}")
        if "num_plugboard_pairs" in revealed:
            lines.append(f"  Number of Stecker pairs: {revealed['num_plugboard_pairs']}")
        lines.append(f"  Unknown: {', '.join(revealed['hidden'])}")
        lines.append("")

        # Cribs
        if task["cribs"]:
            lines.append("Cribs:")
            for i, crib in enumerate(task["cribs"], 1):
                lines.append(f"  {i}. \"{crib['text']}\" at position {crib['position']}")
            lines.append("")

        # Minimal reference
        lines.append("Enigma properties: reciprocal (decryption = encryption with same settings), no letter encrypts to itself. Rotors: I-V (pick 3, no duplicates). Reflectors: UKW-A, UKW-B, UKW-C. Settings are 1-indexed (1=A ... 26=Z).")
        lines.append("")
        lines.append(
            f"Use try_decrypt to test configurations ({self.max_attempts} attempts max). Use submit with the recovered plaintext. "
            f"If you use all {self.max_attempts} attempts without submitting, the episode ends and is scored on the most accurate decryption among your attempts."
        )
        lines.append(
            "Scoring: character accuracy over the positions not covered by cribs, chance-corrected. "
            "Accuracy no better than guessing without decrypting (the commonest letter everywhere, "
            f"or the best of {self.max_attempts} random decryptions) scores 0; a perfect decryption scores 1."
        )

        return [TextBlock(text="\n".join(lines))]

    @tool
    async def try_decrypt(self, params: TryDecryptInput) -> ToolOutput:
        """
        Configure an Enigma machine with the given settings and decrypt the intercepted ciphertext.
        Returns the decrypted text so you can check if it looks like valid German plaintext.
        Use the known cribs to verify if the output matches at expected positions.
        The budget is 100 attempts: the call that uses the last one ends the episode,
        scored on the most accurate decryption among all your attempts.
        """
        # Check attempt limit
        if self.attempts >= self.max_attempts:
            return ToolOutput(
                metadata={"error": "Maximum attempts exceeded"},
                blocks=[TextBlock(text=f"Error: Maximum number of decryption attempts ({self.max_attempts}) exceeded. Please submit your best answer using the submit tool.")],
                reward=0.0,
                finished=False,
            )

        # Validate rotor order
        if len(params.rotor_order) != 3:
            return ToolOutput(
                metadata={"error": "Exactly 3 rotors required"},
                blocks=[TextBlock(text="Error: Exactly 3 rotors required. Choose from: I, II, III, IV, V")],
                reward=0.0,
                finished=False,
            )
        for r in params.rotor_order:
            if r not in ROTORS:
                return ToolOutput(
                    metadata={"error": f"Unknown rotor: {r}"},
                    blocks=[TextBlock(text=f"Error: Unknown rotor '{r}'. Valid rotors: I, II, III, IV, V")],
                    reward=0.0,
                    finished=False,
                )
        if len(set(params.rotor_order)) != 3:
            return ToolOutput(
                metadata={"error": "Duplicate rotors not allowed"},
                blocks=[TextBlock(text="Error: Duplicate rotors not allowed. Each rotor can only be used once.")],
                reward=0.0,
                finished=False,
            )

        # Validate ring settings
        if len(params.ring_settings) != 3:
            return ToolOutput(
                metadata={"error": "Exactly 3 ring settings required"},
                blocks=[TextBlock(text="Error: Exactly 3 ring settings required (1-26 each).")],
                reward=0.0,
                finished=False,
            )
        for rs in params.ring_settings:
            if not (1 <= rs <= 26):
                return ToolOutput(
                    metadata={"error": f"Ring setting out of range: {rs}"},
                    blocks=[TextBlock(text=f"Error: Ring setting {rs} out of range. Must be 1-26 (1=A, 26=Z).")],
                    reward=0.0,
                    finished=False,
                )

        # Validate initial positions
        if len(params.initial_positions) != 3:
            return ToolOutput(
                metadata={"error": "Exactly 3 initial positions required"},
                blocks=[TextBlock(text="Error: Exactly 3 initial positions required (1-26 each).")],
                reward=0.0,
                finished=False,
            )
        for ip in params.initial_positions:
            if not (1 <= ip <= 26):
                return ToolOutput(
                    metadata={"error": f"Initial position out of range: {ip}"},
                    blocks=[TextBlock(text=f"Error: Initial position {ip} out of range. Must be 1-26 (1=A, 26=Z).")],
                    reward=0.0,
                    finished=False,
                )

        # Validate reflector
        if params.reflector not in REFLECTORS:
            return ToolOutput(
                metadata={"error": f"Unknown reflector: {params.reflector}"},
                blocks=[TextBlock(text=f"Error: Unknown reflector '{params.reflector}'. Valid: UKW-A, UKW-B, UKW-C")],
                reward=0.0,
                finished=False,
            )

        # Validate plugboard
        used_letters = set()
        plugboard_tuples = []
        for pair in params.plugboard:
            if len(pair) != 2:
                return ToolOutput(
                    metadata={"error": "Each plugboard entry must be a pair of 2 letters"},
                    blocks=[TextBlock(text="Error: Each plugboard entry must be exactly 2 letters, e.g. [\"A\", \"B\"].")],
                    reward=0.0,
                    finished=False,
                )
            a, b = pair[0].upper(), pair[1].upper()
            if a not in ALPHABET or b not in ALPHABET:
                return ToolOutput(
                    metadata={"error": f"Invalid plugboard letters: {a}, {b}"},
                    blocks=[TextBlock(text=f"Error: Plugboard letters must be A-Z. Got: {a}, {b}")],
                    reward=0.0,
                    finished=False,
                )
            if a == b:
                return ToolOutput(
                    metadata={"error": f"Plugboard pair cannot connect a letter to itself: {a}"},
                    blocks=[TextBlock(text=f"Error: Plugboard pair cannot connect a letter to itself: {a}")],
                    reward=0.0,
                    finished=False,
                )
            if a in used_letters or b in used_letters:
                return ToolOutput(
                    metadata={"error": f"Duplicate letter in plugboard: {a} or {b}"},
                    blocks=[TextBlock(text=f"Error: Letter already used in another plugboard pair: {a} or {b}")],
                    reward=0.0,
                    finished=False,
                )
            used_letters.add(a)
            used_letters.add(b)
            plugboard_tuples.append((a, b))

        # Attempt decryption
        try:
            machine = EnigmaMachine(
                rotor_order=params.rotor_order,
                ring_settings=params.ring_settings,
                initial_positions=params.initial_positions,
                reflector=params.reflector,
                plugboard=plugboard_tuples,
            )
            decrypted = machine.encrypt(self.task["ciphertext"])
        except Exception as e:
            return ToolOutput(
                metadata={"error": str(e)},
                blocks=[TextBlock(text=f"Error during decryption: {str(e)}")],
                reward=0.0,
                finished=False,
            )

        self.attempts += 1
        correct, total = self._char_accuracy(decrypted)
        accuracy = correct / total if total else 0.0
        if accuracy > self.best_attempt[0]:
            self.best_attempt = (accuracy, correct, total)

        # Format output
        decrypted_grouped = " ".join(
            decrypted[i:i + 5] for i in range(0, len(decrypted), 5)
        )
        text = f"Attempt {self.attempts}/{self.max_attempts}\n\nDecrypted text:\n{decrypted_grouped}"

        if self.attempts >= self.max_attempts:
            best_accuracy, best_correct, best_total = self.best_attempt
            reward = self._reward(best_accuracy)
            return ToolOutput(
                metadata={
                    "attempt": self.attempts,
                    "decrypted_text": decrypted,
                    "reward": reward,
                    "accuracy": best_accuracy,
                    "correct_chars": best_correct,
                    "total_chars": best_total,
                    "attempts_used": self.attempts,
                },
                blocks=[TextBlock(
                    text=f"{text}\n\nAttempt budget used up — episode finished; scored your best decryption attempt: "
                         f"accuracy {best_accuracy:.2%} ({best_correct}/{best_total} non-crib characters correct), "
                         f"chance-corrected reward {reward:.3f}."
                )],
                reward=reward,
                finished=True,
            )

        return ToolOutput(
            metadata={
                "attempt": self.attempts,
                "decrypted_text": decrypted,
            },
            blocks=[TextBlock(text=text)],
            reward=0.0,
            finished=False,
        )

    @tool
    async def submit(self, params: SubmitInput) -> ToolOutput:
        """
        Submit your final decrypted plaintext for scoring.
        The score is chance-corrected character accuracy against the true plaintext,
        over the positions not covered by cribs.
        """
        if self.submitted > 0:
            return ToolOutput(
                blocks=[TextBlock(text="A plaintext has already been submitted for this task. "
                                       "This episode is over: it is not re-scored, and repeat "
                                       "submissions are penalised (reward -0.1).")],
                metadata={"already_submitted": True, "submission_count": self.submitted},
                reward=REPEAT_SUBMISSION_PENALTY,
                finished=True,
            )

        # Normalize: uppercase, keep only A-Z
        submitted = "".join(c for c in params.plaintext.upper() if c in ALPHABET)
        ground_truth = self.task["plaintext"]

        # Calculate character-level accuracy
        correct_count, max_len = self._char_accuracy(submitted)
        accuracy = correct_count / max_len
        reward = self._reward(accuracy)

        self.submitted += 1

        return ToolOutput(
            metadata={
                "reward": reward,
                "accuracy": accuracy,
                "correct_chars": correct_count,
                "total_chars": max_len,
                "submitted_length": len(submitted),
                "expected_length": len(ground_truth),
                "attempts_used": self.attempts,
            },
            blocks=[TextBlock(
                text=f"Submitted. Accuracy: {accuracy:.2%} ({correct_count}/{max_len} non-crib characters correct). "
                     f"Chance-corrected reward: {reward:.3f}. Attempts used: {self.attempts}."
            )],
            reward=reward,
            finished=True,
        )

    def _char_accuracy(self, text: str) -> tuple[int, int]:
        """(correct, total) characters of normalised A-Z text against the hidden
        plaintext, position by position, over the non-crib positions; characters
        beyond the plaintext length count towards total as wrong."""
        ground_truth = self.task["plaintext"]
        correct_count = sum(1 for i in self.scored_positions if i < len(text) and text[i] == ground_truth[i])
        total = len(self.scored_positions) + max(0, len(text) - len(ground_truth))
        return correct_count, total

    def _reward(self, accuracy: float) -> float:
        """Chance-corrected accuracy: 0 at or below self.chance_accuracy, 1 when perfect."""
        return max(0.0, (accuracy - self.chance_accuracy) / (1.0 - self.chance_accuracy))

    @classmethod
    def list_tasks(cls, split: str) -> list[JSONObject]:
        if split not in ALL_SPLITS:
            raise ValueError(f"Unknown split: {split}. Available: {ALL_SPLITS}")
        return [{"id": task_id} for task_id, task in ALL_TASKS.items() if task["split"] == split]

    @classmethod
    def list_splits(cls) -> list[str]:
        return list(ALL_SPLITS)
