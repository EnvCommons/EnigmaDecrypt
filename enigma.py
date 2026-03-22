"""
Enigma Decrypt — OpenReward Environment

An RL environment where agents decrypt WWII-era Enigma-encoded German military
messages. Agents use tools to test Enigma machine configurations and submit
decrypted plaintext for character-level accuracy scoring.
"""

from typing import List

from pydantic import BaseModel

from openreward.environments import Environment, JSONObject, ToolOutput, tool, TextBlock
from enigma_machine import EnigmaMachine, ROTORS, REFLECTORS, ALPHABET
from tasks import ALL_TASKS, ALL_SPLITS


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
        self.max_attempts = 500

    async def get_prompt(self) -> List[TextBlock]:
        task = self.task
        revealed = task["revealed_info"]
        difficulty = task["difficulty"]

        lines = []
        lines.append("You are a WWII Bletchley Park codebreaker. Your mission is to decrypt an intercepted German military message that was encrypted using a Wehrmacht Enigma I machine.")
        lines.append("")
        lines.append(f"## Intercepted Message")
        lines.append(f"**Classification:** {task['category']} message")
        lines.append(f"**Intelligence context:** {task['context']}")
        lines.append(f"**Difficulty:** {difficulty.upper()}")
        lines.append(f"**Message length:** {len(task['plaintext'])} characters")
        lines.append("")
        lines.append(f"**Ciphertext:**")
        lines.append(f"```")
        lines.append(task["ciphertext_grouped"])
        lines.append(f"```")
        lines.append("")

        # Revealed machine settings
        lines.append("## Known Machine Settings")
        if "rotor_order" in revealed:
            lines.append(f"- **Rotor order (left to right):** {' '.join(revealed['rotor_order'])}")
        if "ring_settings" in revealed:
            ring_letters = [ALPHABET[r - 1] for r in revealed["ring_settings"]]
            lines.append(f"- **Ring settings:** {revealed['ring_settings']} ({' '.join(ring_letters)})")
        if "reflector" in revealed:
            lines.append(f"- **Reflector:** {revealed['reflector']}")
        if "plugboard" in revealed:
            pairs = [f"{p[0]}/{p[1]}" for p in revealed["plugboard"]]
            lines.append(f"- **Plugboard:** {', '.join(pairs)}")
        if "num_plugboard_pairs" in revealed:
            lines.append(f"- **Number of plugboard pairs:** {revealed['num_plugboard_pairs']}")

        lines.append(f"- **Unknown settings:** {', '.join(revealed['hidden'])}")
        lines.append("")

        # Cribs
        if task["cribs"]:
            lines.append("## Known Plaintext (Cribs)")
            lines.append("Intelligence has identified the following plaintext fragments at known positions:")
            for i, crib in enumerate(task["cribs"], 1):
                lines.append(f"  {i}. \"{crib['text']}\" at position {crib['position']}")
            lines.append("")

        # Enigma properties reference
        lines.append("## Enigma Machine Properties")
        lines.append("- The Enigma is reciprocal: encrypting ciphertext with the correct settings produces the plaintext.")
        lines.append("- **No self-encryption:** A letter never encrypts to itself. Use this to eliminate impossible configurations.")
        lines.append("- **Rotors available:** I, II, III, IV, V (select any 3, no duplicates)")
        lines.append("- **Reflectors available:** UKW-A, UKW-B, UKW-C")
        lines.append("- Ring settings and initial positions are 1-indexed (1=A, 2=B, ..., 26=Z)")
        lines.append("- Plugboard pairs swap two letters before and after rotor processing")
        lines.append("")

        # Instructions
        lines.append("## Instructions")
        lines.append("1. Use `try_decrypt` to test different machine configurations and observe the output.")
        lines.append("2. Look for German language patterns in the decrypted output to identify correct settings.")
        lines.append("3. Use the cribs to verify — if your decryption matches the known plaintext at the given positions, you likely have the right settings.")
        lines.append("4. Once you have the correct decryption, use `submit` to submit the plaintext.")
        lines.append(f"5. You have a maximum of {self.max_attempts} decryption attempts.")
        lines.append("")
        lines.append("**Scoring:** Character-level accuracy (matching characters / total characters). A perfect decryption scores 1.0.")

        return [TextBlock(text="\n".join(lines))]

    @tool
    async def try_decrypt(self, params: TryDecryptInput) -> ToolOutput:
        """
        Configure an Enigma machine with the given settings and decrypt the intercepted ciphertext.
        Returns the decrypted text so you can check if it looks like valid German plaintext.
        Use the known cribs to verify if the output matches at expected positions.
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
        self.attempts += 1
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

        # Format output
        decrypted_grouped = " ".join(
            decrypted[i:i + 5] for i in range(0, len(decrypted), 5)
        )

        return ToolOutput(
            metadata={
                "attempt": self.attempts,
                "decrypted_text": decrypted,
            },
            blocks=[TextBlock(text=f"Attempt {self.attempts}/{self.max_attempts}\n\nDecrypted text:\n{decrypted_grouped}")],
            reward=0.0,
            finished=False,
        )

    @tool
    async def submit(self, params: SubmitInput) -> ToolOutput:
        """
        Submit your final decrypted plaintext for scoring.
        The score is based on character-level accuracy compared to the true plaintext.
        """
        # Normalize: uppercase, keep only A-Z
        submitted = "".join(c for c in params.plaintext.upper() if c in ALPHABET)
        ground_truth = self.task["plaintext"]

        # Calculate character-level accuracy
        max_len = max(len(ground_truth), len(submitted))
        if max_len == 0:
            reward = 0.0
            correct_count = 0
        else:
            correct_count = sum(
                1 for a, b in zip(submitted, ground_truth) if a == b
            )
            reward = correct_count / max_len

        return ToolOutput(
            metadata={
                "reward": reward,
                "correct_chars": correct_count,
                "total_chars": max_len,
                "submitted_length": len(submitted),
                "expected_length": len(ground_truth),
                "attempts_used": self.attempts,
            },
            blocks=[TextBlock(
                text=f"Submitted. Accuracy: {reward:.2%} ({correct_count}/{max_len} characters correct). "
                     f"Attempts used: {self.attempts}."
            )],
            reward=reward,
            finished=True,
        )

    @classmethod
    def list_tasks(cls, split: str) -> list[JSONObject]:
        if split not in ALL_SPLITS:
            raise ValueError(f"Unknown split: {split}. Available: {ALL_SPLITS}")
        return [{"id": task_id} for task_id, task in ALL_TASKS.items() if task["split"] == split]

    @classmethod
    def list_splits(cls) -> list[str]:
        return list(ALL_SPLITS)
