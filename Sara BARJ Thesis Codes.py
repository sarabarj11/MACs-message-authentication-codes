#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implémentation des algorithmes du chapitre 5 de la thèse :
  "Blockchain & DLT Resilience: Analysis and Enhancing Based on a Layered Perspective"
  Auteur : Sara BARJ, INPT – Rabat, 2025

Contient :
  - Validation des paramètres (m, q)
  - Matrices symétriques (symboliques et numériques)
  - Protocole d'échange de clés (NG‑KEP) version 2 (n=72)
  - Générateurs de MAC (NG‑MACv1 et NG‑MACv2)
  - Démonstration complète

Respecte les spécifications :  - m ∈ [2, 21]
  - q premier ∈ [m², m³]
  - n = 72 pour v2
  - SHA3‑224 / SHA3‑512
  - Erreurs gaussiennes arrondies avec sigma = alpha / √(2π)
"""

import sympy as sp
import numpy as np
import hashlib
import json

# =========================================
# PART 1 — VALIDATION (m, q) avec SymPy
# =========================================

def valid_m_q_pairs():
    """Retourne un dictionnaire {m: [liste des premiers dans [m², m³]]}"""
    pairs = {}
    for m in range(2, 22):
        primes = list(sp.primerange(m**2, m**3 + 1))
        pairs[m] = primes
    return pairs

def is_valid_q(m, q):
    return (m**2 <= q <= m**3) and sp.isprime(q)

# =========================================
# PART 2 — MATRICES SYMÉTRIQUES (SymPy)
# =========================================

def symmetric_matrix_symbolic(m):
    """Matrice symétrique symbolique pour vérification algébrique"""
    M = sp.Matrix(m, m, lambda i, j: sp.symbols(f"a{i}{j}") if i <= j else 0)
    for i in range(m):
        for j in range(i+1, m):
            M[j, i] = M[i, j]
    return M

def verify_symmetric_property(m=3):
    """Vérifie (A·B)^T = B·A pour deux matrices symétriques A et B"""
    A = symmetric_matrix_symbolic(m)
    B = symmetric_matrix_symbolic(m)
    lhs = (A * B).T
    rhs = B * A
    return sp.simplify(lhs - rhs) == sp.zeros(m)

# =========================================
# PART 3 — NUMPY UTILS
# =========================================

def mod_q(x, q):
    return np.mod(x, q)

def random_matrix(low, high, shape):
    return np.random.randint(low, high, size=shape)

def symmetric_matrix_numeric(q, m):
    """Matrice symétrique d'entiers dans [0, q-1]"""
    M = np.zeros((m, m), dtype=int)
    for i in range(m):
        for j in range(i, m):
            val = np.random.randint(0, q)
            M[i][j] = val
            M[j][i] = val
    return M

def gaussian_matrix(m, alpha):
    """Matrice (m,m) d'erreurs : round(N(0, sigma)) avec sigma = alpha/√(2π)"""
    sigma = alpha / np.sqrt(2 * np.pi)
    return np.round(np.random.normal(0, sigma, (m, m))).astype(int)

# =========================================
# PART 4 — KEP
# =========================================

def public_params_v2(m, q):
    """
    Algorithm 5 du document : paramètres publics pour NG‑MACv2 (n=72)
    """
    if not is_valid_q(m, q):
        raise ValueError(f"m={m}, q={q} invalide")

    alpha = np.sqrt((m**3) * np.pi / (2**19))
    a = random_matrix(-2, 3, (m, 1))          # éléments dans [-2,2]
    M = symmetric_matrix_numeric(q, m)        # matrice symétrique publique
    A = random_matrix(0, q, (m, 72))          # n = 72
    return m, q, alpha, a, M, A

def generate_key_pair(m, q, alpha, M):
    """
    Algorithm 6 : génère (b_secret, pb_public1)
    b_secret = (b_secret1, Eb_secret1)
    pb_public1 = b_secret1·M + Eb_secret1 (mod q)
    """
    b_secret1 = symmetric_matrix_numeric(q, m)
    Eb_secret1 = gaussian_matrix(m, alpha)    # déjà de taille (m,m)
    pb_public1 = mod_q(b_secret1 @ M + Eb_secret1, q)
    return (b_secret1, Eb_secret1), pb_public1

def generate_sigma():
    """Algorithm 7 : sigma1 + sigma2 = 1"""
    sigma1 = np.random.randint(0, 2)
    sigma2 = 1 - sigma1
    return sigma1, sigma2

def compute_shared_secret(b_secret, pb_other, sigma, q, a, A):
    """
    Algorithm 8 : calcule [shared_0, shared_1]
    shared_0 : (n, m) avec n = A.shape[1] (72)
    shared_1 : (m, 1)
    """
    b, E = b_secret
    # inner = pb_other·b + E   (mod q)
    inner = mod_q(pb_other @ b + E, q)

    if sigma == 0:
        shared_0 = mod_q((inner @ A).T, q)    # (n, m)
        shared_1 = mod_q(inner @ a, q)        # (m, 1)
    else:
        # sigma == 1 : utiliser la transposée de inner
        shared_0 = mod_q((inner.T @ A).T, q)  # (n, m)
        shared_1 = mod_q(inner.T @ a, q)      # (m, 1)

    return (shared_0, shared_1)

# =========================================
# PART 5 — MAC KEY
# =========================================

def mac_keygen(shared_key, q, alpha, A):
    """
    Algorithm 9 : génère la clé de session (S, s, P, q)
    shared_key = (S, s) avec S (n, m) et s (m, 1)
    """
    S, s = shared_key
    m = S.shape[1]                # m est la deuxième dimension de S
    E = gaussian_matrix(m, alpha).T
    P = mod_q(A @ S + E, q)       # A (m,n), S (n,m) → (m,m)
    return (S, s, P, q)

# =========================================
# PART 6 — MAC v1 (SHA3-512)
# =========================================

def generate_mac_v1(key, message):
    """Algorithm 10 : MAC avec SHA3-512 et chiffrement LWE"""
    S, s, P, q = key
    n, m = S.shape

    # hash du message en SHA3-512
    h = hashlib.sha3_512(message.encode()).hexdigest()

    u = mod_q(S @ s, q)          # (n,1)
    c1 = mod_q(P @ s, q)         # (m,1)

    delta = []
    for c in h:
        val = int(c, 16)
        temp = int(round(q * val + c1[0, 0])) % q
        delta.append(temp)

    ct = {"result": [delta, u.flatten().tolist()]}
    ct_bytes = json.dumps(ct).encode()
    return hashlib.sha3_512(ct_bytes).hexdigest()

def verify_mac_v1(key, message, mac):
    return generate_mac_v1(key, message) == mac

# =========================================
# PART 7 — MAC v2 (SHA3-224, sortie réduite modulo 16)
# =========================================

def generate_mac_v2(key, message):
    """Algorithm 12 : MAC avec SHA3-224 et sortie compressée à 512 bits"""
    S, s, P, q = key
    n, m = S.shape

    h = hashlib.sha3_224(message.encode()).hexdigest()   # 56 caractères hex

    u = (mod_q(S @ s, q)) % 16          # (n,1) réduit modulo 16
    c1 = mod_q(P @ s, q)                # (m,1)

    hex_delta = ""
    for c in h:
        val = int(c, 16)
        temp = int(round(q * val + c1[0, 0])) % q
        temp = temp % 16
        hex_delta += format(temp, 'x')

    hex_u = ""
    for i in range(n):
        hex_u += format(int(u[i, 0]), 'x')

    return hex_delta + hex_u            # 56 + 72 = 128 caractères hex (512 bits)

def verify_mac_v2(key, message, mac):
    return generate_mac_v2(key, message) == mac

# =========================================
# PART 8 — DEMO COMPLETE
# =========================================

def demo():
    print("=== Vérification SymPy ===")
    print("Propriété matrices symétriques :", verify_symmetric_property())

    print("\n=== Génération (m,q) ===")
    pairs = valid_m_q_pairs()
    m = 10
    q = pairs[m][0]                 # premier nombre premier dans [m², m³]
    print(f"m={m}, q={q}, prime={sp.isprime(q)}")

    print("\n=== KEP + MAC ===")

    # 1. Paramètres publics
    m, q, alpha, a, M, A = public_params_v2(m, q)

    # 2. Génération des paires de clés pour Alice et Bob
    b_alice, pb_alice = generate_key_pair(m, q, alpha, M)
    b_bob,   pb_bob   = generate_key_pair(m, q, alpha, M)

    # 3. Sigmas
    sigma_alice, sigma_bob = generate_sigma()  # sigma_alice + sigma_bob = 1

    # 4. Secrets partagés
    shared_alice = compute_shared_secret(b_alice, pb_bob, sigma_alice, q, a, A)
    shared_bob   = compute_shared_secret(b_bob,   pb_alice, sigma_bob,   q, a, A)
    
    # 5. Clés de session
    key_alice = mac_keygen(shared_alice, q, alpha, A)
    key_bob   = mac_keygen(shared_bob,   q, alpha, A)
    
    if (key_alice[0] == key_bob[0]).all() and (key_alice[1] == key_bob[1]).all():
        print("Same shared keys:", True)
    else:
        print("Same shared keys:", False)
    
     
    msg = "HELLO"

    mac1 = generate_mac_v1(key_alice, msg)
    mac2 = generate_mac_v2(key_alice, msg)

    print("MACv1 (512 bits) :", len(mac1)*4)
    print("MACv2 (512 bits) :", len(mac2)*4)
    print("Longueur MACv2 :", len(mac2), "caractères hex")

    print("Vérification v1 :", verify_mac_v1(key_bob, msg, mac1))
    print("Vérification v2 :", verify_mac_v2(key_bob, msg, mac2))

    # Test avec un message falsifié
    fake_msg = "FAKE"
    print("Vérification v2 (message falsifié) :",
          not verify_mac_v2(key_bob, fake_msg, mac2))


if __name__ == "__main__":
    demo()
