# Enigma Decrypt

[![OpenReward Environment](https://img.shields.io/badge/%E2%AD%90%20OpenReward-Environment-f7e6cc)](https://openreward.ai/GeneralReasoning/enigma-decrypt)

## Description

Enigma Decrypt is an environment where agents decrypt WWII-era Enigma-encoded German military messages. Each task presents an intercepted ciphertext encrypted with a historically accurate Wehrmacht Enigma I machine (3-rotor, plugboard configuration). The agent is given partial information about the machine settings and known plaintext fragments (cribs), and must deduce the remaining settings to recover the original German military message.

The Enigma machine simulator is verified against the 1930 German military instruction manual test vector and validated for all fundamental Enigma properties: reciprocity, no self-encryption, and the double-stepping anomaly.

## Capabilities

- Cryptanalysis and systematic search over configuration spaces
- Exploiting mathematical properties of the Enigma cipher (no self-encryption, reciprocity)
- Known-plaintext attacks using cribs
- Strategic hypothesis testing and elimination
- Understanding of rotor machines and substitution ciphers

## Compute Requirements

Enigma Decrypt does not require a sandbox. The environment runs a pure-Python Enigma machine simulator with minimal compute requirements.

## License

MIT

## Tasks

There are 60 tasks across 2 splits and 3 difficulty tiers:

| Split | Easy | Medium | Hard | Total |
|-------|------|--------|------|-------|
| train | 15   | 15     | 10   | 40    |
| test  | 5    | 10     | 5    | 20    |

Messages span 5 categories of realistic WWII German military communications: weather reports (WETTER), U-boat reports (UBOOT), operational orders (BEFEHL), status reports (LAGEBERICHT), and miscellaneous intelligence/logistics. Messages follow authentic conventions: uppercase A-Z only, X for periods, ZZ for commas, Q replacing CH, and numbers spelled out in German.

### Difficulty Tiers

- **Easy:** Agent knows rotor order, ring settings, reflector, and plugboard. Must find the 3 initial rotor positions (17,576 possibilities). 1-2 cribs provided.
- **Medium:** Agent knows rotor order and reflector. Must find ring settings, initial positions, and plugboard (3-5 pairs). 2-3 cribs provided.
- **Hard:** Agent knows only the reflector. Must deduce rotor order (60 permutations), ring settings, initial positions, and plugboard (2-3 pairs). 3-4 cribs provided.

## Reward Structure

This is a verifiable reward environment. No LLM grader is used. The reward is deterministic character-level accuracy:

$$\text{reward} = \frac{\text{matching characters}}{\max(\text{length of ground truth}, \text{length of submission})}$$

A perfect decryption scores 1.0. Partial credit is awarded for partially correct submissions. The reward is computed once when the agent calls `submit`.

## Data

Tasks are generated from a corpus of 60 realistic WWII-style German military messages, each encrypted with randomly assigned Enigma machine settings. Every task is verified to round-trip correctly (decrypting the ciphertext with the stored settings recovers the plaintext exactly). All cribs are verified to appear at their stated positions.

## Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `try_decrypt` | `rotor_order`, `ring_settings`, `initial_positions`, `reflector`, `plugboard` | Configure an Enigma machine and decrypt the ciphertext. Returns the decrypted text for inspection. Does not score or finish the task. |
| `submit` | `plaintext` | Submit the final decrypted plaintext for scoring. Finishes the task and returns the accuracy reward. |

The agent has a maximum of 500 `try_decrypt` attempts per task.

## Time Horizon

Enigma Decrypt is a multi-turn environment. Easy tasks can be solved in a handful of tool calls with systematic position search. Medium and hard tasks require more strategic reasoning about Enigma properties and effective use of cribs.

## Environment Difficulty

Easy tasks are tractable with systematic search guided by cribs. Medium tasks require understanding of Enigma mechanics to narrow the search space. Hard tasks demand genuine cryptanalytic reasoning — exploiting no-self-encryption, crib dragging, and rotor identification techniques.

## Other Environment Requirements

There are no further environment requirements; Enigma Decrypt works out of the box with the OpenReward endpoint without any secrets.

## Safety

Agents in Enigma Decrypt interact only with a simulated historical cipher machine. The environment does not present safety risks — all data is synthetic (though historically informed), and the cryptographic techniques involved are of purely historical interest with no modern security implications.

## Citations

```bibtex
@dataset{GREnigmaDecrypt,
  author    = {General Reasoning Inc. Team},
  title     = {Enigma Decrypt},
  year      = {2026},
  publisher = {OpenReward},
  url       = {https://openreward.ai/GeneralReasoning/enigma-decrypt}
}
```
