# AutoCrypt: Automated cryptanalysis of lightweight block ciphers

> **Requirement:** the attack modules rely on the Gurobi optimizer and therefore need a Gurobi licence key. Gurobi provides free academic licences for students on its website (https://www.gurobi.com). See [Requirements](#requirements) for details.

AutoCrypt is a Python toolbox that implements several block ciphers **from scratch** (on bit arrays, for readability rather than speed) and uses **MILP solvers** to automate the search for linear and differential distinguishers, then uses them to attack reduced-round versions of the ciphers.

Everything is driven from a single interactive entry point, `launcher.py`.

> **Educational / research code.** The ciphers are written to be studied and attacked, not to be used. Do not use them to protect real data.

---

## Contents

- [Project status](#project-status)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Code overview](#code-overview)
- [Tests](#tests)
- [Limitations](#limitations)
- [References](#references)

---

## Project status

| Component | Status |
|---|---|
| Ciphers: GIFT-64, PRESENT-80, AES-128, Alzette, SPECK | Implemented (encryption + decryption, any number of rounds) |
| Linear attack, last-round key recovery (GIFT-64, PRESENT-80) | Fully implemented |
| Recursive linear attack (iterative key recovery + brute-force of the remaining bits) | Fully implemented |
| Differential trail search and distinguisher search (GIFT-64, PRESENT-80) | Implemented |
| Differential recursive attack / key recovery | Not implemented yet |
| Attacks on AES, Alzette, SPECK | Out of scope for now (cipher implementations only) |

---

## Features

### Ciphers

| Cipher | Block | Key | Rounds | Notes |
|---|---|---|---|---|
| GIFT-64 | 64 bits | 128 bits | 28 | Full key schedule and inverse key schedule |
| PRESENT | 64 bits | 80 bits | 31 | Full key schedule |
| AES-128 | 128 bits | 128 bits | 10 | Bit-level S-box computed in GF(2^8) |
| Alzette (ARX box) | 64 bits | - | n | Keyless 64-bit ARX permutation, behaves as a large S-box |
| SPECK | - | - | - | Available from the launcher |

Each cipher comes with a small text-file front-end: choose a file, an output name and (when relevant) a key and a number of rounds, and the program encrypts or decrypts it block by block.

### Linear cryptanalysis

- Linear Approximation Table (LAT) computation and display of the best approximations of an S-box.
- **MILP trail search (Gurobi):** finds a multi-round linear trail that minimises the number of active S-boxes, using the exact S-box transitions allowed by the LAT.
- **Last-round attack** (Matsui's Algorithm 2 style): generates known plaintext/ciphertext pairs, automatically determines which last-round-key bits influence the trail's output mask, guesses them and ranks the candidates by their bias |T0 - T1|.
- **Recursive attack:** repeatedly asks the MILP solver for a *new* trail (previous output masks are excluded), runs the last-round attack with it and accumulates recovered key bits until a chosen target is reached. The remaining unknown bits can then be brute-forced and the inverse key schedule applied to recover the **master key**.
- Reference implementations of Matsui's Algorithm 1 and 2 (`matsui1`, `matsui2`) that work with any cipher exposing a partial-decryption function.

### Differential cryptanalysis

- Difference Distribution Table (DDT) computation.
- Automatic modelling of S-box differential transitions as linear inequalities: convex hull of the possible transitions (computed with SageMath), followed by a greedy selection of a small set of inequalities that excludes every impossible transition.
- **MILP model (Gurobi)** that minimises the number of active S-boxes over n rounds, optionally with a fixed input and/or output difference, and collects a **pool of solutions**.
- Trail probability from the DDT, and differential probability obtained by summing over the trails found.
- **Automatic distinguisher search**, in two flavours:
  - *non-optimised*: random (input difference, output difference) pairs;
  - *optimised*: input differences enumerated by Hamming weight, with the best output differences found by the solver (parameters K1 and K2 control the size of the solution pools).
- Results are written to a text file, with a pass/fail flag against a probability threshold of 2^-t.

---

## Requirements

- **Python 3.9+**
- **NumPy**
- **Gurobi** and its Python package `gurobipy`, with a valid licence. The size-limited licence that ships with `pip install gurobipy` is not enough for models with many rounds. Students and academics can obtain a free academic licence from the Gurobi website.
- **SageMath**, *for differential cryptanalysis only* (used to compute the convex hull of the S-box transitions). The launcher runs this module with `sage -python`, so `numpy` and `gurobipy` must also be installed in Sage's Python environment.

The linear attacks and all ciphers run in a plain Python environment, without Sage.

---

## Installation

```bash
git clone <repository-url>
cd <repository>

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install numpy gurobipy
```

The launcher tries to activate a virtual environment automatically. The expected location is set by `VENV_PATH` at the top of `launcher.py`; if your environment lives elsewhere, edit that line (a warning is printed if it cannot be found, and the program then simply uses your current interpreter).

For the differential module, install the dependencies inside Sage as well:

```bash
sage -pip install numpy gurobipy
```

---

## Usage

Start the launcher from the source directory:

```bash
python launcher.py
```

It displays a menu and runs the chosen module in the same terminal:

```
[ 1] GIFT Cipher
[ 2] PRESENT Cipher
[ 3] AES Cipher
[ 4] ALZETTE (ARX) Cipher
[ 5] SPECK Cipher
[ 6] Linear Attack
[ 7] Differential Attack
[ 8] Tools
[ 0] Quit
```

(Entries marked `[NOT FOR DEMO]` are development tests.) Press `Ctrl+C` to go back or quit.

### Ciphers

Each cipher application offers *Encrypt*, *Decrypt*, and *Encrypt/Decrypt N rounds*. Input files are read from the `testfiles/` directory, the output is written there too, and the result is printed on screen. The text is converted to bits and zero-padded to the block size; blocks are processed independently (ECB-like).

### Linear attack (menu 6)

| Option | Action |
|---|---|
| 1 | Linear attack on GIFT-64 (single trail, last-round key recovery) |
| 2 | Linear attack on PRESENT |
| 3 | Recursive attack on GIFT-64 (iterative key recovery) |
| 4 | Recursive attack on PRESENT (iterative key recovery) |

You are asked for:

1. the **number of plaintext/ciphertext pairs** (Python expressions such as `2**20` are accepted);
2. the **number of rounds** covered by the linear trail;
3. a **key**, which the program uses to generate the data and to score the result (this is a demonstration tool: it reports at which rank the true key bits were found);
4. for the recursive attacks, the **number of unknown key bits you accept to leave** (e.g. 40, which is brute-forceable).

Example of the progress report during a recursive attack (unknown bits shown as `?`):

```
======================= GLOBAL RECOVERY REPORT =======================
Step 3 - Known bits of K_last : 48/128

?10?1?0??1...
======================================================================
```

When the target is reached, the program can brute-force the missing bits, undo the key schedule and print `Original Master Key` / `Recovered Master Key` / `Match`.

### Differential attack (menu 7)

Choose GIFT-64 or PRESENT, then one of:

1. **Minimum number of active S-boxes** over *n* rounds (MILP), with a text visualisation of the active S-boxes per round;
2. **Automatic distinguisher search, non-optimised** (random differences);
3. **Automatic distinguisher search, optimised** (differences enumerated by Hamming weight, K1/K2 parameters).

Options 2 and 3 write a report file (default `automated_diff_results.txt`). Sample output for 2 rounds of GIFT-64:

```
Differential Attack on GIFT-64 : number of round user = 2 , number of path = 100 , threshold = 64
Try : 1 | Input : 0000000000000003 -> Output : 0100000000000200 | Probability = 0.15625 | Passed the threshold : True | Exec time = 0.40s
Try : 31 | Input : 0000000000000018 -> Output : 0000800840000002 | Probability = 0.00244140625 | Passed the threshold : True | Exec time = 0.40s
```

---

## How it works

**Linear attack.** For a 4-bit S-box, the LAT gives the bias of every (input mask, output mask) pair. A MILP model with one binary variable per mask bit, per S-box activity and per allowed S-box transition propagates a mask through `n` rounds of S-boxes and bit permutation, and minimises the number of active S-boxes. The trail's total bias is estimated with the piling-up lemma. The attack then peels off the last round: it determines which key bits affect the output mask, tries every value of these bits, partially decrypts every ciphertext, and keeps the guess for which the approximation holds with the largest deviation from 1/2. In the recursive version each iteration adds a trail that ends on a different output mask, so a different set of key bits is revealed each time.

**Differential attack.** The DDT tells which (Din, Dout) S-box transitions are possible. The set of possible transitions is turned into a system of linear inequalities (convex hull, then a greedy selection to keep the model small), which lets the MILP solver search for the differential trails with the fewest active S-boxes. Trail probabilities are the products of `DDT[Din][Dout] / 16` over the active S-boxes; the differential probability sums the trails found for a given (Din, Dout).

---

## Code overview

| File | Role |
|---|---|
| `launcher.py` | Main entry point. Starts every other program as a module, handles the virtual environment and OS differences. |
| `gift_cipher.py` | GIFT-64: S-box, bit permutation, key schedule (and inverse), encryption/decryption. |
| `present_cipher_64_bit.py` | PRESENT-80. |
| `aes.py` | AES-128 on bit arrays (key expansion, SubBytes, ShiftRows, MixColumns and inverses, GF(2^8) arithmetic). |
| `alzette_cipher.py` | Alzette ARX box (encryption/decryption of a 64-bit block, one or several rounds). |
| `speck_cipher.py` | SPECK. |
| `linear_cryptanalysis.py` | LAT, MILP trail search, last-round and recursive attacks, Matsui 1 / 2. |
| `differential_cryptanalysis.py` | DDT, convex hull inequalities, MILP trail search, distinguisher search. Requires SageMath. |
| `tools.py` | Shared helpers: bit-array conversions, XOR, key input, brute-force of remaining key bits, menus, etc. |
| `tests/` | Unit tests and test vectors for ciphers, tools and attacks. |

---

## Tests

Test programs live in `tests/` (AES, GIFT, PRESENT, tools, linear, differential and MILP tests). They can be run from the launcher's development menu, or by passing a menu number to the launcher on the command line (this is what continuous integration does; the process exit code is the number of failed checks). The CI is split into implementation tests, linear-attack tests and the longer differential-attack tests.

---

## Limitations

- **Performance:** ciphers operate on Python lists of bits, which is clear but slow. Linear key recovery enumerates 2^k candidates, where k is the number of last-round key bits the trail depends on, so it is only practical for small k.
- **Bias estimate:** the bias of a MILP trail is estimated assuming each active S-box has the best bias (2^-1), so it is an optimistic figure for the actual approximation.
- **Differential module:** produces trails, probabilities and distinguishers, but there is no recursive attack and no key recovery yet.
- **Solver dependencies:** MILP models grow quickly with the number of rounds; a full Gurobi licence is needed for anything beyond small instances.
- **Cipher front-ends:** no mode of operation or secure padding (zero padding, ECB-like); demonstration only.
- **Alzette** uses a single fixed round constant (`0xb7e15162`) for all steps.
- The launcher does not stop worker threads cleanly: if a program uses threads, press `Ctrl+C` repeatedly.

---

## References

- A. Bogdanov et al., *PRESENT: An Ultra-Lightweight Block Cipher*, CHES 2007.
- S. Banik et al., *GIFT: A Small Present*, CHES 2017.
- NIST, *FIPS 197: Advanced Encryption Standard (AES)*, 2001.
- C. Beierle et al., *Alzette: A 64-Bit ARX-box*, CRYPTO 2020.
- M. Matsui, *Linear Cryptanalysis Method for DES Cipher*, EUROCRYPT 1993.
- E. Biham, A. Shamir, *Differential Cryptanalysis of DES-like Cryptosystems*, CRYPTO 1990.
- N. Mouha et al., *Differential and Linear Cryptanalysis Using Mixed-Integer Linear Programming*, Inscrypt 2011.
- S. Sun et al., *Towards Finding the Best Characteristic of Some Bit-oriented Block Ciphers and Automatic Enumeration of (Related-key) Differential and Linear Characteristics with Predefined Properties*, 2014 (convex hull modelling of S-boxes).

---

## Authors

Antonio Matta, Maria Mikael, Sacha Carlier, Arthur Schifano.
