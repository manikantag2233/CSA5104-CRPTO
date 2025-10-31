#!/usr/bin/env python3
"""
Automatic monoalphabetic substitution solver (hill-climb + frequency heuristics).

Usage:
  - Run: python3 monoattack.py
  - Paste ciphertext at the prompt (or give a filename when asked).
  - Choose how many top candidates to show and how many random restarts.

Notes:
  - Works best on reasonably long ciphertexts (hundreds of letters).
  - If you'd like better accuracy, I can add quadgram scoring (needs a data file
    or embedded table) or simulated annealing.
"""

import sys
import math
import random
import re
from collections import Counter

# ---- Configuration / heuristics ----
ENGLISH_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
COMMON_WORDS = [
    " the ", " and ", " that ", " have ", " for ", " not ", " with ", "you ",
    " this ", " but ", " are ", " from ", " was ", " they ", " his ", " her ",
    " there ", " their ", " will ", " would ", " what ", " which ", " when ",
    " where ", " your ", " all ", " can ", "said ", " say ", "like "
]
COMMON_DIGRAPHS = ["TH","HE","IN","ER","AN","RE","ON","AT","EN","ND","TI","ES","OR","TE","OF","ED","IS","IT","AL","AR","ST","TO"]

# weights (tune these if you wish)
WEIGHT_WORD = 10.0
WEIGHT_DIGRAPH = 1.0
WEIGHT_CHI = 0.5    # chi-square is *penalized* (lower chi is better)

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# ---- Utility functions ----

def clean_text(s):
    """Return only letters in uppercase, keep original for reinsertion if needed."""
    return "".join(ch for ch in s.upper() if ch.isalpha())

def letter_freq_counts(text):
    """Return counts for A-Z in text (letters only)."""
    text = clean_text(text)
    return Counter(text)

def build_initial_key_from_freq(ciphertext):
    """
    Build an initial substitution key by mapping most frequent cipher letters
    to most frequent English letters (ETAOIN...).
    Key representation: a string of 26 uppercase letters where index 0 = mapping for 'A' (cipher letter)
    i.e. plaintext_letter = key[ord(cipher_letter)-65]
    """
    freq = letter_freq_counts(ciphertext)
    # sort cipher letters by descending frequency
    letters_sorted = sorted(ALPHABET, key=lambda c: (-freq.get(c,0), c))
    # map them to ENGLISH_ORDER
    mapping = {}
    used = set()
    key_list = ['?'] * 26
    for i, c in enumerate(letters_sorted):
        if i < len(ENGLISH_ORDER):
            key_list[ord(c)-65] = ENGLISH_ORDER[i]
            used.add(ENGLISH_ORDER[i])
    # fill any remaining (in case of ties) with unused letters
    unused = [ch for ch in ALPHABET if ch not in used]
    ui = 0
    for i in range(26):
        if key_list[i] == '?':
            key_list[i] = unused[ui]
            ui += 1
    return "".join(key_list)

def apply_key(ciphertext, key):
    """Apply key mapping to ciphertext and return plaintext guess.
       key: string of length 26 giving plaintext letter for cipher A..Z.
       preserves non-letters unchanged and original case for letters.
    """
    out_chars = []
    for ch in ciphertext:
        if ch.isalpha():
            is_upper = ch.isupper()
            mapped = key[ord(ch.upper()) - 65]
            out_chars.append(mapped if is_upper else mapped.lower())
        else:
            out_chars.append(ch)
    return "".join(out_chars)

# ---- Scoring function ----
def score_plaintext(plaintext):
    """
    Score plaintext: higher is better.
    Combines:
     - occurrences of common words (weighted heavily)
     - counts of common digraphs
     - negative chi-square of letter freq vs English (penalize large deviations)
    """
    # lowercase copy for word searches
    text_low = plaintext.lower()
    score = 0.0

    # common words (with spaces) - count occurrences
    for w in COMMON_WORDS:
        start = 0
        w_low = w.strip()
        # search with word boundaries where possible (we use a simple contains)
        count = text_low.count(w_low)
        if count:
            score += WEIGHT_WORD * count

    # digraphs: check uppercase letters only (fast)
    up = clean_text(plaintext)
    for dg in COMMON_DIGRAPHS:
        score += WEIGHT_DIGRAPH * up.count(dg)

    # letter frequency chi-square: lower is better so subtract weighted inverse
    # compute observed % frequencies
    observed = Counter(up)
    n = len(up) if len(up) > 0 else 1
    # expected percentages for English (approx)
    english_freq = {
        'A':8.167,'B':1.492,'C':2.782,'D':4.253,'E':12.702,'F':2.228,'G':2.015,'H':6.094,
        'I':6.966,'J':0.153,'K':0.772,'L':4.025,'M':2.406,'N':6.749,'O':7.507,'P':1.929,
        'Q':0.095,'R':5.987,'S':6.327,'T':9.056,'U':2.758,'V':0.978,'W':2.360,'X':0.150,
        'Y':1.974,'Z':0.074
    }
    chi = 0.0
    for letter in ALPHABET:
        obs = (observed.get(letter,0) * 100.0) / n
        exp = english_freq[letter]
        chi += ((obs - exp) ** 2) / (exp if exp > 0 else 1.0)
    # smaller chi -> better: subtract weighted chi
    score -= WEIGHT_CHI * chi
    return score

# ---- Key operations ----
def swap_key(key, i, j):
    k = list(key)
    k[i], k[j] = k[j], k[i]
    return "".join(k)

def randomize_key(key, swaps=10):
    k = list(key)
    for _ in range(swaps):
        i = random.randrange(26)
        j = random.randrange(26)
        k[i], k[j] = k[j], k[i]
    return "".join(k)

# ---- Hill-climbing optimizer ----
def hill_climb(ciphertext, start_key, max_no_improve=1000):
    """
    Greedy hill-climb by trying all pairwise swaps and keeping improving swaps.
    Returns (best_key, best_score).
    """
    best_key = start_key
    best_plain = apply_key(ciphertext, best_key)
    best_score = score_plaintext(best_plain)

    no_improve = 0
    iteration = 0
    # try repeated sweeps of all pairs until no improvement for a while
    while no_improve < max_no_improve:
        improved = False
        iteration += 1
        # try all unordered pairs (i<j)
        for i in range(26):
            for j in range(i+1, 26):
                cand_key = swap_key(best_key, i, j)
                cand_plain = apply_key(ciphertext, cand_key)
                cand_score = score_plaintext(cand_plain)
                if cand_score > best_score + 1e-9:
                    best_key = cand_key
                    best_score = cand_score
                    best_plain = cand_plain
                    improved = True
                    # Apply immediate switch and continue searching from new key
        if not improved:
            no_improve += 1
        else:
            no_improve = 0
    return best_key, best_score, best_plain

# ---- Main attack routine ----
def attack(ciphertext, top_n=10, restarts=200, random_seed=None):
    if random_seed is not None:
        random.seed(random_seed)
    else:
        random.seed()

    ciphertext_clean = ciphertext  # we apply key preserving non-letters
    initial_key = build_initial_key_from_freq(ciphertext)
    candidates = []  # list of dicts {score,key,plain}

    # first run deterministic start
    k, s, p = hill_climb(ciphertext_clean, initial_key, max_no_improve=200)
    candidates.append({'score': s, 'key': k, 'plain': p})

    # random restarts
    for attempt in range(max(1,restarts)):
        if attempt % 5 == 0:
            # sometimes try fully random key
            letters = list(ALPHABET)
            random.shuffle(letters)
            start = "".join(letters)
        else:
            # randomize initial key by a few swaps
            start = randomize_key(initial_key, swaps=1 + random.randrange(12))

        k, s, p = hill_climb(ciphertext_clean, start, max_no_improve=150)
        # add if plaintext unique
        if not any(c['plain'] == p for c in candidates):
            candidates.append({'score': s, 'key': k, 'plain': p})

        # small local perturbations from this best
        for extra in range(2):
            start2 = randomize_key(k, swaps=1 + random.randrange(6))
            k2, s2, p2 = hill_climb(ciphertext_clean, start2, max_no_improve=100)
            if not any(c['plain'] == p2 for c in candidates):
                candidates.append({'score': s2, 'key': k2, 'plain': p2})

    # sort candidates descending by score
    candidates.sort(key=lambda x: -x['score'])
    return candidates[:top_n]

# ---- CLI / Interaction ----
def main():
    print("\nMonoalphabetic substitution solver (automatic)\n")
    # read ciphertext: either from file or paste
    choice = input("Enter path to file with ciphertext, or press Enter to paste ciphertext: ").strip()
    if choice:
        try:
            with open(choice, 'r', encoding='utf-8') as f:
                ciphertext = f.read()
        except Exception as e:
            print("Error reading file:", e)
            return
    else:
        print("Paste ciphertext (end input with a blank line):")
        lines = []
        while True:
            try:
                line = input().rstrip("\n")
            except EOFError:
                break
            if line == "":
                break
            lines.append(line)
        ciphertext = "\n".join(lines)
        if not ciphertext:
            print("No ciphertext provided. Exiting.")
            return

    top_n_raw = input("How many top candidates to show? (default 10) : ").strip() or "10"
    restarts_raw = input("How many random restarts? (default 200) : ").strip() or "200"
    try:
        top_n = int(top_n_raw)
        restarts = int(restarts_raw)
    except:
        print("Invalid numeric input; using defaults (10,200).")
        top_n = 10
        restarts = 200

    print("\nRunning attack... (this may take a little while depending on restarts and ciphertext length)\n")
    candidates = attack(ciphertext, top_n=top_n, restarts=restarts)

    print(f"\nTop {len(candidates)} candidates (ranked):\n")
    for i, cand in enumerate(candidates, start=1):
        print(f"----- Candidate #{i} (score = {cand['score']:.3f}) -----")
        print("Key mapping (cipher->plain) for A..Z:")
        print("".join(cand['key']))
        print("\nPlaintext (first 1000 chars shown):")
        # show plaintext with newlines preserved, but trimmed
        out = cand['plain']
        if len(out) > 1000:
            out = out[:1000] + " ... (truncated)"
        print(out)
        print("\n")

if __name__ == "__main__":
    main()
