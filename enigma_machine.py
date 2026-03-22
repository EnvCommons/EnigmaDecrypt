"""
Wehrmacht Enigma I Machine Simulator

Implements a historically accurate 3-rotor Enigma I machine with:
- Rotors I-V with correct wirings and turnover notches
- Reflectors UKW-A, UKW-B, UKW-C
- Plugboard (Steckerbrett)
- Double-stepping anomaly

All rotor wirings sourced from historical specifications.
Ring settings and positions use 1-indexed values (1=A ... 26=Z).
"""

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Historical rotor wirings: maps input position -> output letter
# Turnover: the letter visible in the window when the notch engages the next rotor
ROTORS = {
    "I":   {"wiring": "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "turnover": "Q"},
    "II":  {"wiring": "AJDKSIRUXBLHWTMCQGZNPYFVOE", "turnover": "E"},
    "III": {"wiring": "BDFHJLCPRTXVZNYEIWGAKMUSQO", "turnover": "V"},
    "IV":  {"wiring": "ESOVPZJAYQUIRHXLNFTGKDCMWB", "turnover": "J"},
    "V":   {"wiring": "VZBRGITYUPSDNHLXAWMJQOFECK", "turnover": "Z"},
}

REFLECTORS = {
    "UKW-A": "EJMZALYXVBWFCRQUONTSPIKHGD",
    "UKW-B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "UKW-C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
}


class Rotor:
    """A single Enigma rotor with wiring, ring setting, and position."""

    def __init__(self, name: str, ring_setting: int, position: int):
        """
        Args:
            name: Rotor name (I, II, III, IV, V)
            ring_setting: 1-indexed ring setting (1=A ... 26=Z)
            position: 1-indexed initial position (1=A ... 26=Z)
        """
        if name not in ROTORS:
            raise ValueError(f"Unknown rotor: {name}")
        spec = ROTORS[name]
        self.name = name
        self.wiring = spec["wiring"]
        self.turnover = ALPHABET.index(spec["turnover"])
        # Convert to 0-indexed internally
        self.ring = ring_setting - 1
        self.position = position - 1

    def is_at_turnover(self) -> bool:
        """Check if rotor is at its turnover position."""
        return self.position == self.turnover

    def step(self):
        """Advance rotor by one position."""
        self.position = (self.position + 1) % 26

    def forward(self, char_index: int) -> int:
        """Pass signal through rotor in forward direction (right to left)."""
        offset = (self.position - self.ring) % 26
        input_idx = (char_index + offset) % 26
        output_char = self.wiring[input_idx]
        output_idx = (ALPHABET.index(output_char) - offset) % 26
        return output_idx

    def backward(self, char_index: int) -> int:
        """Pass signal through rotor in backward direction (left to right)."""
        offset = (self.position - self.ring) % 26
        input_idx = (char_index + offset) % 26
        output_idx = (self.wiring.index(ALPHABET[input_idx]) - offset) % 26
        return output_idx


class EnigmaMachine:
    """Wehrmacht Enigma I machine simulator."""

    def __init__(
        self,
        rotor_order: list[str],
        ring_settings: list[int],
        initial_positions: list[int],
        reflector: str,
        plugboard: list[tuple[str, str]] | None = None,
    ):
        """
        Args:
            rotor_order: List of 3 rotor names, left to right (e.g., ["II", "I", "III"])
            ring_settings: List of 3 ring settings, 1-indexed (e.g., [24, 13, 22])
            initial_positions: List of 3 initial positions, 1-indexed (e.g., [6, 15, 12])
            reflector: Reflector name (UKW-A, UKW-B, UKW-C)
            plugboard: List of letter pairs (e.g., [("A","M"), ("F","I")])
        """
        if len(rotor_order) != 3:
            raise ValueError("Exactly 3 rotors required")
        if len(ring_settings) != 3:
            raise ValueError("Exactly 3 ring settings required")
        if len(initial_positions) != 3:
            raise ValueError("Exactly 3 initial positions required")
        if reflector not in REFLECTORS:
            raise ValueError(f"Unknown reflector: {reflector}")

        # Create rotors: index 0 = left, 1 = middle, 2 = right
        self.rotors = [
            Rotor(rotor_order[i], ring_settings[i], initial_positions[i])
            for i in range(3)
        ]
        self.reflector_wiring = REFLECTORS[reflector]

        # Build plugboard mapping
        self.plugboard_map = {}
        if plugboard:
            for a, b in plugboard:
                a, b = a.upper(), b.upper()
                if a in self.plugboard_map or b in self.plugboard_map:
                    raise ValueError(f"Duplicate plugboard letter: {a} or {b}")
                self.plugboard_map[a] = b
                self.plugboard_map[b] = a

        # Store initial config for reset
        self._initial_positions = list(initial_positions)

    def reset(self, positions: list[int] | None = None):
        """Reset rotor positions. If positions is None, reset to initial positions."""
        pos = positions if positions is not None else self._initial_positions
        for i, p in enumerate(pos):
            self.rotors[i].position = p - 1

    def _plugboard(self, c: str) -> str:
        """Apply plugboard substitution."""
        return self.plugboard_map.get(c, c)

    def _reflect(self, char_index: int) -> int:
        """Pass through reflector."""
        return ALPHABET.index(self.reflector_wiring[char_index])

    def _step_rotors(self):
        """
        Advance rotors with double-stepping anomaly.

        Stepping happens BEFORE encryption of each character:
        1. If middle rotor is at turnover, middle AND left step (double-stepping).
        2. If right rotor is at turnover, middle steps.
        3. Right rotor always steps.
        """
        # Check turnover conditions BEFORE stepping
        middle_at_turnover = self.rotors[1].is_at_turnover()
        right_at_turnover = self.rotors[2].is_at_turnover()

        # Left rotor steps if middle is at turnover
        if middle_at_turnover:
            self.rotors[0].step()

        # Middle rotor steps if right is at turnover OR middle itself is at turnover (double-step)
        if middle_at_turnover or right_at_turnover:
            self.rotors[1].step()

        # Right rotor always steps
        self.rotors[2].step()

    def encrypt_char(self, c: str) -> str:
        """Encrypt a single character through the full Enigma circuit."""
        if c not in ALPHABET:
            return c

        # Step rotors before encryption
        self._step_rotors()

        # Plugboard in
        c = self._plugboard(c)

        # Convert to index
        idx = ALPHABET.index(c)

        # Forward through rotors: right -> middle -> left
        idx = self.rotors[2].forward(idx)
        idx = self.rotors[1].forward(idx)
        idx = self.rotors[0].forward(idx)

        # Reflector
        idx = self._reflect(idx)

        # Backward through rotors: left -> middle -> right
        idx = self.rotors[0].backward(idx)
        idx = self.rotors[1].backward(idx)
        idx = self.rotors[2].backward(idx)

        # Plugboard out
        result = ALPHABET[idx]
        result = self._plugboard(result)

        return result

    def encrypt(self, text: str) -> str:
        """Encrypt (or decrypt) a message. Only processes A-Z characters."""
        result = []
        for c in text.upper():
            if c in ALPHABET:
                result.append(self.encrypt_char(c))
        return "".join(result)

    @property
    def positions(self) -> list[int]:
        """Current rotor positions (1-indexed)."""
        return [r.position + 1 for r in self.rotors]
