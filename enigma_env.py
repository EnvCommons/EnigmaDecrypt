"""
Enigma Decrypt — OpenReward Environment

The agent gets an Enigma I ciphertext of a German military message in a Python
sandbox and must recover the full key with its own code: known-plaintext (crib)
attacks at the lower levels, ciphertext-only statistical attacks at the upper
ones. It submits the key; the server decrypts the ciphertext with it and scores
the letter accuracy against the hidden plaintext.

The plaintext and key exist only on this server. The sandbox holds the
ciphertext, the task description and, at levels with a kit, a reference
simulator and a sample of German text from other messages.
"""

import json
import math
import re
from pathlib import Path
from typing import List

from pydantic import BaseModel, Field, field_validator

from openreward import AsyncOpenReward, SandboxSettings
from openreward.environments import Environment, JSONObject, TextBlock, ToolOutput, tool
from openreward.toolsets import CLIToolset

import enigma_machine
import tasks
from enigma_machine import ALPHABET, REFLECTORS, ROTORS, EnigmaMachine
from sandbox_io import upload_text

WORKSPACE = "/workspace"
SANDBOX_IMAGE = "generalreasoning/python-ds:3.12-tools"
SANDBOX_MACHINE_SIZE = "2:4"

# Reward for a submission made after the episode has already ended.
REPEAT_SUBMISSION_PENALTY = -0.1

# A wrong key's output letter is never the ciphertext letter (Enigma has no
# fixed points) and is otherwise uniform, as is the plaintext letter, so the two
# match with probability 1/25.
RANDOM_MATCH_P = 1 / 25

SIMULATOR_CLI = '''

if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Encrypt or decrypt stdin with an Enigma I key.")
    ap.add_argument("--rotors", nargs=3, required=True, help="left to right, e.g. II IV V")
    ap.add_argument("--reflector", default="UKW-B")
    ap.add_argument("--rings", nargs=3, type=int, default=[1, 1, 1], help="1-26 each")
    ap.add_argument("--positions", nargs=3, type=int, default=[1, 1, 1], help="1-26 each")
    ap.add_argument("--plugs", nargs="*", default=[], help="pairs, e.g. AB CD")
    a = ap.parse_args()
    m = EnigmaMachine(a.rotors, a.rings, a.positions, a.reflector, [(p[0], p[1]) for p in a.plugs])
    print(m.encrypt(sys.stdin.read()))
'''


def simulator_source() -> str:
    return Path(enigma_machine.__file__).read_text() + SIMULATOR_CLI


def _test_vectors() -> str:
    cases = [
        (["I", "II", "III"], [1, 1, 1], [1, 1, 1], [], "AAAAAAAAAA"),
        (["II", "IV", "V"], [2, 21, 12], [1, 5, 22], ["AV", "BS", "CG", "DL", "FU"], "QWERTZUIOPASDFGHJKLYXCVBNM"),
        (["V", "I", "III"], [7, 3, 25], [17, 4, 21], ["EQ", "IZ", "KX", "MO", "NR", "PT"], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ]
    lines = []
    for order, rings, pos, plugs, text in cases:
        out = EnigmaMachine(order, rings, pos, "UKW-B", [(p[0], p[1]) for p in plugs]).encrypt(text)
        lines.append(f"- rotors {' '.join(order)}, UKW-B, rings {rings}, positions {pos}, "
                     f"plugs {' '.join(plugs) or '(none)'}: {text} ({len(text)} letters) -> {out}")
    return "\n".join(lines)


def machine_spec() -> str:
    rotors = "\n".join(f"- {n}: {r['wiring']} (turnover when the window shows {r['turnover']})"
                       for n, r in ROTORS.items())
    reflectors = "\n".join(f"- {n}: {w}" for n, w in REFLECTORS.items())
    return f"""## Machine specification (Enigma I)

Rotor wirings (entry contact A..Z maps to the letter shown):
{rotors}

Reflectors:
{reflectors}

Stepping, before each letter is enciphered: if the middle rotor's window shows its
turnover letter, the middle and left rotors both step (double step); else if the
right rotor's window shows its turnover letter, the middle rotor steps. The right
rotor always steps. Turnover depends on the window letter, not the ring setting.

A rotor at window position p (0-25, A=0) with ring setting r (0-25, A=0) has
offset o = p - r: a signal entering at contact x leaves at wiring[(x + o) % 26] - o.
The signal path is plugboard, right, middle, left rotor, reflector, back through
left, middle, right (inverse wirings), plugboard.

Test vectors (rings and positions numbered 1-26 here, A=1, as in submit_key):
{_test_vectors()}
"""


def _group(text: str) -> str:
    return " ".join(text[i:i + 5] for i in range(0, len(text), 5))


class TaskSpec(BaseModel, extra="forbid"):
    id: str
    level: int
    seed: int


class SubmitKeyParams(BaseModel, extra="forbid"):
    """The full Enigma key. Every field is a short string."""
    rotor_order: str = Field(description='Three rotors, left to right, e.g. "II IV V"')
    reflector: str = Field(description='The reflector, e.g. "UKW-B"')
    ring_settings: str = Field(description='Three ring settings, left to right: numbers 1-26 or letters, '
                                           'e.g. "6 9 1" or "FIA"')
    initial_positions: str = Field(description='Three start positions (window letters), left to right: '
                                               'numbers 1-26 or letters, e.g. "1 5 18" or "AER"')
    plugboard: str = Field(description='The plugboard pairs separated by spaces, e.g. "AV BS CG"; '
                                       'an empty string for no pairs')

    @field_validator("*", mode="before")
    @classmethod
    def _lists_as_text(cls, v):
        return json.dumps(v) if isinstance(v, (list, tuple)) else v


class EnigmaCLI(CLIToolset):
    bash_timeout = 600
    max_bash_timeout = 900
    bash_max_bytes = 30_000


def _items(value: str) -> list:
    """Split a key field into items. Accepts plain text ("6 9 1", "6,9,1") as well
    as JSON lists and quoted strings ("[6, 9, 1]", '"FIA"')."""
    v = value.strip()
    for _ in range(3):
        try:
            parsed = json.loads(v)
        except ValueError:
            break
        if isinstance(parsed, list):
            return [json.dumps(x) if isinstance(x, list) else str(x).strip() for x in parsed]
        v = str(parsed).strip()
    return [t for t in re.split(r"[\s,;]+", v.strip("[]()'\"")) if t]


def _settings(value: str, name: str) -> list:
    example = 'e.g. "6 9 1" or "FIA"'
    items = [t.strip("'\"").upper() for t in _items(value.replace("-", " "))]
    if len(items) == 1 and len(items[0]) == 3 and items[0].isalpha():
        items = list(items[0])
    out = []
    for item in items:
        if item.isdigit() and 1 <= int(item) <= 26:
            out.append(int(item))
        elif len(item) == 1 and item in ALPHABET:
            out.append(ALPHABET.index(item) + 1)
        else:
            raise ValueError(f"{name}: {item!r} is not a number 1-26 or a letter A-Z ({example})")
    if len(out) != 3:
        raise ValueError(f"{name} must have exactly 3 values, left to right ({example})")
    return out


def parse_key(p: SubmitKeyParams) -> dict:
    """Validated key dict, or ValueError with a message for the agent."""
    roman = {str(i): r for i, r in enumerate(["I", "II", "III", "IV", "V"], start=1)}
    order = [r.strip("'\"").upper() for r in _items(p.rotor_order.replace("-", " "))]
    order = [roman.get(r, r) for r in order]
    if len(order) != 3 or len(set(order)) != 3 or any(r not in ROTORS for r in order):
        raise ValueError('rotor_order must be 3 distinct rotors from I, II, III, IV, V, left to right '
                         '(e.g. "II IV V")')
    letter = re.sub(r"[^A-Z]", "", p.reflector.upper()).removeprefix("UKW")
    reflector = f"UKW-{letter}"
    if reflector not in REFLECTORS:
        raise ValueError(f"reflector must be one of {', '.join(REFLECTORS)}")
    plugs = [re.sub(r"[^A-Za-z0-9]", "", s).upper() for s in _items(p.plugboard)]
    if len(plugs) > 13:
        raise ValueError("at most 13 plugboard pairs")
    seen = set()
    for pair in plugs:
        if len(pair) != 2 or any(c not in ALPHABET for c in pair) or pair[0] == pair[1]:
            raise ValueError(f'plugboard pair {pair!r} must be two different letters A-Z '
                             f'(pairs separated by spaces, e.g. "AV BS CG")')
        if seen & set(pair):
            raise ValueError(f"letter of {pair!r} is used in more than one plugboard pair")
        seen |= set(pair)
    return {
        "rotor_order": order,
        "reflector": reflector,
        "ring_settings": _settings(p.ring_settings, "ring_settings"),
        "initial_positions": _settings(p.initial_positions, "initial_positions"),
        "plugboard": plugs,
    }


def scored_positions(task: dict) -> list:
    crib = {c["position"] + i for c in task["cribs"] for i in range(len(c["text"]))}
    return [i for i in range(len(task["plaintext"])) if i not in crib]


def chance_level(n: int) -> float:
    """Random-key accuracy plus two standard deviations at n scored letters."""
    p = RANDOM_MATCH_P
    return p + 2 * math.sqrt(p * (1 - p) / n)


def score_key(task: dict, key: dict) -> dict:
    decrypted = tasks.machine(key).encrypt(task["ciphertext"])
    positions = scored_positions(task)
    correct = sum(decrypted[i] == task["plaintext"][i] for i in positions)
    accuracy = correct / len(positions)
    c = chance_level(len(positions))
    reward = min(1.0, max(0.0, (accuracy - c) / (1 - c)))
    return {"accuracy": accuracy, "reward": reward, "correct": correct, "n_scored": len(positions)}


class EnigmaDecrypt(Environment):
    """Break one Enigma I message in a Python sandbox and submit the key."""

    toolsets = [EnigmaCLI]
    workspace_root = WORKSPACE

    def __init__(self, task_spec: JSONObject, secrets: dict[str, str] = {}) -> None:
        super().__init__(task_spec)
        spec = TaskSpec.model_validate(task_spec)
        if spec.level not in tasks.LEVELS or spec.id != tasks.task_id(spec.level, spec.seed):
            raise ValueError(f"invalid task spec {spec.id!r}")
        if not secrets.get("api_key"):
            raise ValueError("OpenReward API key is required (secrets['api_key'])")
        self.task = tasks.build_task(spec.level, spec.seed)
        self.submitted = False
        self.sandbox_settings = SandboxSettings(
            environment="GeneralReasoning/EnigmaDecrypt",
            image=SANDBOX_IMAGE,
            machine_size=SANDBOX_MACHINE_SIZE,
            block_network=True,
        )
        self.sandbox = AsyncOpenReward(api_key=secrets["api_key"]).sandbox(self.sandbox_settings)

    def workspace_files(self) -> dict:
        files = {
            "ciphertext.txt": _group(self.task["ciphertext"]),
            "task.md": self.task_text(),
        }
        if self.task["kit"]:
            files["enigma_reference.py"] = simulator_source()
            files["german_sample.txt"] = tasks.sample_text()
        return files

    async def setup(self) -> None:
        # The workspace holds only what is uploaded here, so checking the files
        # before upload keeps the plaintext out of the sandbox entirely.
        files = self.workspace_files()
        if any(self.task["plaintext"] in content for content in files.values()):
            raise RuntimeError(f"task {self.task['id']}: plaintext present in the workspace files")
        await self.sandbox.start()
        await self.sandbox.run(f"mkdir -p {WORKSPACE}", timeout=60)
        for name, content in files.items():
            await upload_text(self.sandbox, f"{WORKSPACE}/{name}", content)

    async def teardown(self) -> None:
        await self.sandbox.stop()

    def task_text(self) -> str:
        t, known = self.task, self.task["known"]
        lines = [f"# Enigma task {t['id']}", "",
                 f"Ciphertext: {len(t['ciphertext'])} letters, also in `ciphertext.txt` (groups of five):", "",
                 _group(t["ciphertext"]), "",
                 "Known:",
                 f"- Machine: Enigma I, three rotors chosen from I-V, reflector {known['reflector']}.",
                 f"- Plugboard: exactly {known['plugboard_pairs']} pairs."]
        if "rotor_order" in known:
            lines.append(f"- Rotor order (left to right): {' '.join(known['rotor_order'])}.")
        else:
            lines.append("- Rotor order: unknown (any 3 distinct rotors of I-V, in any order).")
        lines.append("- Ring settings and start positions: unknown.")
        if t["cribs"]:
            lines += ["", "Cribs (known plaintext; positions are 0-indexed letter offsets into the ciphertext):"]
            lines += [f"- {c['text']} at position {c['position']}" for c in t["cribs"]]
            if tasks.LEVELS[t["level"]]["motion"] == "no_middle_step":
                lines.append("- The middle rotor does not step within the crib.")
            else:
                lines.append("- The left rotor does not move between the first and last crib.")
        else:
            lines += ["", "No cribs: this is a ciphertext-only task.",
                      "- The left rotor does not move during this message."]
        lines += ["",
                  "Plaintext conventions: German military text, A-Z only. X marks a full stop, ZZ a comma,",
                  "Q stands for CH, umlauts are written AE/OE/UE, and numbers are spelled out (ZWO for 2).", ""]
        if t["kit"]:
            lines += ["Also in this directory:",
                      "- `enigma_reference.py`: a correct but slow reference simulator (importable, or run",
                      "  `python enigma_reference.py --help`). Use it to check any faster implementation.",
                      "- `german_sample.txt`: German military messages of the same style (not this message),",
                      "  for letter and n-gram statistics.", ""]
        else:
            lines += [machine_spec()]
        return "\n".join(lines)

    async def get_prompt(self) -> List[TextBlock]:
        level = tasks.LEVELS[self.task["level"]]
        attack = ("You have known plaintext (cribs) to work from." if level["attack"] == "crib"
                  else "There is no known plaintext: you will need a statistical attack.")
        text = f"""Recover the Enigma key for an intercepted German military message.

You have a Linux sandbox with Python 3 (numpy and scipy installed) and no network.
Everything you are given is in {WORKSPACE}: start with `{WORKSPACE}/task.md`.
{attack}

{self.task_text()}
When you have the key, call `submit_key` once with:
- rotor_order: three rotors, left to right, e.g. "II IV V"
- reflector: e.g. "UKW-B"
- ring_settings: three values left to right, numbers 1-26 or letters, e.g. "6 9 1" or "FIA"
- initial_positions: the three start positions (window letters), e.g. "1 5 18" or "AER"
- plugboard: the pairs separated by spaces, e.g. "AV BS CG"

The server decrypts the ciphertext with your key and scores the letter accuracy
against the true plaintext (crib positions excluded), corrected for chance: a
random key scores 0 and a key that decrypts the whole message correctly scores 1.
Partly right keys get partial credit. Only the first valid submission counts and
it ends the task. A malformed key is rejected without ending the task.

Commands time out after {EnigmaCLI.bash_timeout:g} seconds by default (at most {EnigmaCLI.max_bash_timeout:g}).
For longer searches, start the job fully detached and check its log in later calls:
    setsid -f python search.py > search.log 2>&1 < /dev/null
The redirects must be on the outer command: `setsid -f bash -c 'cmd > log'` still
waits, because setsid's own output goes back to the call. A plain `command &` (even
with nohup) keeps the call waiting until the time limit, and the job is killed with
it. Use `python -u` (or flush output) so logs fill as the job runs. `ps` is not
installed: follow jobs through their logs (or /proc). A command that itself exits
with code 124 (e.g. your own `timeout`) is also reported as hitting the time limit.
"""
        return [TextBlock(text=text)]

    @tool
    async def submit_key(self, params: SubmitKeyParams) -> ToolOutput:
        """Submit the recovered Enigma key. The first valid key is scored and ends the task."""
        if self.submitted:
            return ToolOutput(
                blocks=[TextBlock(text="A key was already submitted; the task is over.")],
                metadata={"repeat_submission": True},
                reward=REPEAT_SUBMISSION_PENALTY,
                finished=True,
            )
        try:
            key = parse_key(params)
        except ValueError as e:
            return ToolOutput(blocks=[TextBlock(text=f"Invalid key: {e}. Nothing was scored.")],
                              metadata={"error": str(e)}, reward=0.0, finished=False)
        self.submitted = True
        s = score_key(self.task, key)
        return ToolOutput(
            blocks=[TextBlock(text=f"Key scored: {s['correct']}/{s['n_scored']} letters correct "
                                   f"({s['accuracy']:.1%}); reward {s['reward']:.3f}.")],
            metadata={"level": self.task["level"], "seed": self.task["seed"], **s,
                      "rotor_order_correct": key["rotor_order"] == self.task["key"]["rotor_order"]},
            reward=s["reward"],
            finished=True,
        )

    @classmethod
    def list_splits(cls) -> list[str]:
        return ["train", "test"]

    @classmethod
    def list_tasks(cls, split: str) -> list[JSONObject]:
        return tasks.list_specs(split)
