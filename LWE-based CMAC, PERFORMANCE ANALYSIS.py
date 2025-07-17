import json
import numpy as np
from random import randint
from numpy.random import normal
import math
from math import log
import sympy
from sympy import *
import time
import datetime
from datetime import datetime
import hashlib
import hmac
import os
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

##############################################################################################################
#KEY EXCHAGE PROTOCOL inspired by DING
##############################################################################################################
#public parameters generation
def public_params_for_mac_v1(m,q):
    alpha = math.sqrt((m**3)*math.pi/(2**19)) 
    a = np.random.randint(-2,2,size=(m,1))
    M = np.zeros((m, m))
    for i in range(m):
        for j in range(i, m):
            # Fill the matrix with some values (you can replace this with your own logic)
            M[i][j] = M[j][i] = np.random.randint(0,q-1)
    n = round(1.1*m*math.log(q)/math.log(16))
    A = np.random.randint(q, size=(m, n)) 
    return m,q,alpha,a,M,A
    
def public_params_for_mac_v2(m,q):
    alpha = math.sqrt((m**3)*math.pi/(2**19)) 
    a = np.random.randint(-2,2,size=(m,1))
    M = np.zeros((m, m))
    for i in range(m):
        for j in range(i, m):
            # Fill the matrix with some values (you can replace this with your own logic)
            M[i][j] = M[j][i] = np.random.randint(0,q-1)
    n = 72
    A = np.random.randint(q, size=(m, n)) 
    return m,q,alpha,a,M,A


#key pair generation
def generate_key_pair(m,q,alpha,a,M):
    b_secret1 = np.zeros((m, m))
    for i in range(m):
        for j in range(i, m):
            # Fill the matrix with some values (you can replace this with your own logic)
            b_secret1[i][j] = b_secret1[j][i] = np.random.randint(0,q-1)
    Eb_secret1 = np.transpose(np.around([[np.random.normal(0,alpha / math.sqrt(2 * math.pi)) for i in range(m)] for j in range(m) ]))    
    pb_public1 = np.mod(np.matmul(b_secret1,M) + Eb_secret1,q) 
    b_secret = b_secret1, Eb_secret1
    return b_secret,pb_public1

#sigma generation
def generate_sigma():
    sigma1 = np.random.randint(0,1)
    sigma2 = 1 - sigma1
    return sigma1, sigma2

#shared secret keys computing
def compute_shared_secret(b_secret2,pb_public1,sigma2,m,q,alpha,a,M,A):
    
    shared_secret = {}
    if sigma2 == 0:
        shared_secret[0] = np.transpose(np.mod(np.matmul(np.matmul(np.matrix(pb_public1),b_secret2[0]) + b_secret2[1],A),q))
        shared_secret[1] = np.mod(np.matmul(np.matmul(np.matrix(pb_public1),b_secret2[0]) + b_secret2[1],a),q)
    else:
        shared_secret[0] = np.transpose(np.mod(np.matmul(np.transpose(np.matmul(np.matrix(pb_public1),b_secret2[0]) + b_secret2[1]),A),q))
        shared_secret[1] = np.mod(np.matmul(np.transpose(np.matmul(np.matrix(pb_public1),b_secret2[0]) + b_secret2[1]),a),q)
    return shared_secret

##############################################################################################################
#My MACs
##############################################################################################################
#secret key generation
def KeysGen(Shared_key,m,q,alpha,A) :
    S = Shared_key[0]
    s = Shared_key[1]
    E = np.transpose(np.around([[np.random.normal(0,alpha / math.sqrt(2 * math.pi)) for i in range(m)] for j in range(m) ]))    
    P = np.mod(np.matmul(A,S) + E, q)
    key = S,s,P,q
    return key
         
        
# Encryption function based on LWE and Hash function SHA-3_512
def generate_mac_v1(key, message):
    # Convert the ASCII message to bytes
    #message_bytes = message.encode('utf-8')
    #print(math.ceil(math.log2((len(message)*8)/1024)))
    # Create a SHA-3 hash object with a specified hash length (e.g., 512 bits)
    sha3_hash = hashlib.sha3_512()
    # Update the hash object with the ciphertext bytes
    sha3_hash.update(message)
    # Get the hexadecimal representation of the hash
    hash_hex_message = sha3_hash.hexdigest()
    S,s,P,q = key
    ciphertext = {}
    delta = []    
    l = S.shape[0]
    m = S.shape[1]
    u = np.matmul(S, s)
    c1 = np.matmul(P, s)   
    for i in hash_hex_message:
        temp = int(np.mod(np.around(q*int(i,16)/16) + c1[0][0], q)[0,0])
        delta.append(temp)
    ciphertext = json.dumps({'result':[delta,u.tolist()]})  
    # Convert the ASCII message to bytes
    ciphertext_bytes = ciphertext.encode('utf-8')
    # Create a SHA-3 hash object with a specified hash length (e.g., 512 bits)
    sha3_hash = hashlib.sha3_512()

    # Update the hash object with the ciphertext bytes
    sha3_hash.update(ciphertext_bytes)

    # Get the hexadecimal representation of the hash
    hash_hex = sha3_hash.hexdigest()
    
    return hex(int(hash_hex,16))[2:], S.shape, s.shape, S.shape, s.shape

# Verification Function
def verify_mac_v1(key, message, mac_to_verify):
    """
    Verify the integrity of the message using the provided key and MAC.
    """
    generated_mac = generate_mac_v1(key, message)
    return generated_mac == mac_to_verify


# Encryption function based on LWE and Hash function SHA-3_224
def generate_mac_v2(key, message):
    # Create a SHA-3 hash object with a specified hash length (e.g., 224 bits)
    sha3_hash = hashlib.sha3_224()
    # Update the hash object with the ciphertext bytes
    sha3_hash.update(message)
    # Get the hexadecimal representation of the hash
    hash_hex_message = sha3_hash.hexdigest()
    
    S,s,P,q = key
    delta = []    
    l = S.shape[0]
    m = S.shape[1]
    u = np.mod(np.mod(np.matmul(S, s),q),16)
    c1 = np.matmul(P, s)
    u_bytes = []
    u_base64 = []
    u_hex = []
    le = 0
    u_j = 0
    le1 = 0
    for i in hash_hex_message:
        temp = int(int(np.mod(np.mod(np.around(q*int(i,16)/16) + c1[0][0], q)[0,0],16)))
        temp_hex = hex(temp)[2:]
        delta.append(temp_hex)
        if le < len(str(temp_hex)):        
            le = len(str(temp_hex))
    for j in range(0,l):
        u_j = int(np.mod(int(round(u[j, 0])),16))
        u_hex_temp = hex(u_j)[2:]
        u_hex.append(u_hex_temp)
        
        if le1 < len(str(u_hex_temp)):        
            le1 = len(str(u_hex_temp))
    ciphertext = [delta,u_hex]
    ciphertext_string_part1 = ''.join(map(str, ciphertext[0]))
    ciphertext_string_part2 = ''.join(map(str,ciphertext[1]))
    ciphertext_hex = ciphertext_string_part1+ciphertext_string_part2
    
    return hex(int(ciphertext_hex,16))[2:], S.shape, s.shape, S.shape, s.shape
    
    
    
    
# Verification Function
def verify_mac_v2(key, message, mac_to_verify):
    """
    Verify the integrity of the message using the provided key and MAC.
    """
    generated_mac = generate_mac_v2(key, message)
    return generated_mac == mac_to_verify

##############################################################################################################
#HMAC with SHA-2_512 and KMAC with SHA-3_512
##############################################################################################################


def generate_random_key(key_length):
    # Generate a random key of the specified length
    return os.urandom(key_length)

def hmac_sha512(key, message):
    # Create an HMAC object using SHA-512 and the provided key
    h = hmac.new(key, message, hashlib.sha512)
    
    # Get the hexadecimal digest (resulting HMAC value)
    hmac_result = h.hexdigest()
    
    return hmac_result

# Verification Function
def verify_hmac(key, message, mac_to_verify):
    """
    Verify the integrity of the message using the provided key and MAC.
    """
    generated_mac = hmac_sha512(key, message)
    return generated_mac == mac_to_verify

def kmac_sha3_512(key, message):
    # Create a KMAC object using SHA3-512 and the provided key
    kmac_result = hmac.new(
        key,
        message,
        hashlib.sha3_512
    ).digest()

    return kmac_result.hex()

# Verification Function
def verify_kmac(key, message, mac_to_verify):
    """
    Verify the integrity of the message using the provided key and MAC.
    """
    generated_mac = kmac_sha3_512(key, message)
    return generated_mac == mac_to_verify

##############################################################################################################
#CMAC with AES_256 and SHA-3_512
##############################################################################################################


def generate_key(password, salt, iterations=100000):
    # Derive a key using PBKDF2
    key = PBKDF2(password, salt, dkLen=32, count=iterations, prf=None)
    return key
    
def cmac_aes256_sha512(key, data):
    # Create an AES-256 CMAC object
    cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)

    # Encrypt the data with AES-256
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    # Compute the SHA-512 hash of the ciphertext as the CMAC tag
    cmac_tag = hmac.new(key, ciphertext, hashlib.sha512).digest()

    return cmac_tag.hex()    
# Verification Function
def verify_cmac(key, message, mac_to_verify):
    """
    Verify the integrity of the message using the provided key and MAC.
    """
    generated_mac = cmac_aes256_sha512(key, message)
    return generated_mac == mac_to_verify

##############################################################################################################
#Generate random message from a length in bytes
##############################################################################################################

def generate_random_bytes_message(length_in_bytes):
    # Generate a random string of the required length
    random_bytes = secrets.token_bytes(length_in_bytes)
    
    return random_bytes

##############################################################################################################
#Tests
##############################################################################################################

messages_to_authenticate = [generate_random_bytes_message(1), generate_random_bytes_message(10000), generate_random_bytes_message(20000)]
for message_to_authenticate in messages_to_authenticate:    
    
    print("##############################################################################################################")
    print("Message length in bytes:", len(message_to_authenticate), "bytes.")
    print("##############################################################################################################")
    key_length = 64  # 64 bytes for a 512-bit key
    m,q = 8,113 # for a key length greater than 512-bit
    #m,q = 4, 47
    # Generate a random key
    secret_key = generate_random_key(key_length)
    # Generate the keys for mac_v1
    m,q,alpha,a,M,A = public_params_for_mac_v1(8,113)
    alice_private_key_v1, alice_public_key_v1 = generate_key_pair(m,q,alpha,a,M)
    bob_private_key_v1, bob_public_key_v1 = generate_key_pair(m,q,alpha,a,M)
    sigma_alice, sigma_bob = generate_sigma()
    alice_shared_secret_v1 = compute_shared_secret(alice_private_key_v1, bob_public_key_v1,sigma_alice, m,q,alpha,a,M,A)
    bob_shared_secret_v1 = compute_shared_secret(bob_private_key_v1, alice_public_key_v1,sigma_bob, m,q,alpha,a,M,A)
    print("Proof of correctness of the key exchange protocol:",alice_shared_secret_v1[0].all() == bob_shared_secret_v1[0].all() and  alice_shared_secret_v1[1].all() == bob_shared_secret_v1[1].all())
    S1,s1 = bob_shared_secret_v1[0],bob_shared_secret_v1[1]
    print("The shared secret key length for my MACv1 is:", len(''.join(format(ord(char), '08b') for char in json.dumps([S1.tolist(),s1.tolist()]))))
    bob_secret_key_v1 = KeysGen(bob_shared_secret_v1,m,q,alpha,A)
    alice_secret_key_v1 = KeysGen(alice_shared_secret_v1,m,q,alpha,A)
    # Generate the keys for mac_v2
    m,q,alpha,a,M,A = public_params_for_mac_v2(8,113)
    alice_private_key_v2, alice_public_key_v2 = generate_key_pair(m,q,alpha,a,M)
    bob_private_key_v2, bob_public_key_v2 = generate_key_pair(m,q,alpha,a,M)
    #sigma_alice, sigma_bob = generate_sigma()
    alice_shared_secret_v2 = compute_shared_secret(alice_private_key_v2, bob_public_key_v2,sigma_alice, m,q,alpha,a,M,A)
    bob_shared_secret_v2 = compute_shared_secret(bob_private_key_v2, alice_public_key_v2,sigma_bob, m,q,alpha,a,M,A)
    print("Proof of correctness of the key exchange protocol for MACv2:",alice_shared_secret_v2[0].all() == bob_shared_secret_v2[0].all() and  alice_shared_secret_v2[1].all() == bob_shared_secret_v2[1].all())
    S2,s2 = bob_shared_secret_v2[0],bob_shared_secret_v2[1]
    print("The shared secret key length for my MACv2 is:", len(''.join(format(ord(char), '08b') for char in json.dumps([S2.tolist(),s2.tolist()]))))
    bob_secret_key_v2 = KeysGen(bob_shared_secret_v2,m,q,alpha,A)
    alice_secret_key_v2 = KeysGen(alice_shared_secret_v2,m,q,alpha,A)
    # Calculate HMAC, KMAC, and my MACs
    start_time = datetime.now()
    result_hmac = hmac_sha512(secret_key, message_to_authenticate)
    end_time = datetime.now()
    duration = end_time - start_time
    print("Generate HMAC in milliseconds:", duration.total_seconds() * (10**3))
    print("HMAC correctness proof:", verify_hmac(secret_key, message_to_authenticate, result_hmac))
    start_time = datetime.now()
    result_kmac = kmac_sha3_512(secret_key, message_to_authenticate)
    end_time = datetime.now()
    duration = end_time - start_time
    print("Generate KMAC in milliseconds:", duration.total_seconds() * (10**3))
    
    # Generate a random key
    password = "your_password&"  # Use a strong passphrase
    salt = get_random_bytes(16)

    secret_key_for_cmac = generate_key(password.encode('utf-8'), salt)
    
    start_time = datetime.now()
    result_cmac = cmac_aes256_sha512(secret_key_for_cmac, message_to_authenticate)
    end_time = datetime.now()
    duration = end_time - start_time
    print("Generate CMAC in milliseconds:", duration.total_seconds() * (10**3))
    print("CMAC correctness proof:", verify_cmac(secret_key_for_cmac, message_to_authenticate, result_cmac))
    start_time = datetime.now()
    alice_mac_v1 = generate_mac_v1(alice_secret_key_v1, message_to_authenticate)
    end_time = datetime.now()
    duration = end_time - start_time
    print("My MACv1 generation by Alice in milliseconds:", duration.total_seconds() * (10**3))
    print("My MACv1 correctness proof:", verify_mac_v1(bob_secret_key_v1, message_to_authenticate, alice_mac_v1))
    start_time = datetime.now()
    alice_mac_v2 = generate_mac_v2(alice_secret_key_v2, message_to_authenticate)
    end_time = datetime.now()
    duration = end_time - start_time
    print("My MACv2 generation by Alice in milliseconds:", duration.total_seconds() * (10**3))
    print("My MACv2 correctness proof:", verify_mac_v2(bob_secret_key_v2, message_to_authenticate, alice_mac_v2))
    # Print the result
    print("Message length in bytes:", len(message_to_authenticate))
    print(f"Secret Key for HMAC-SHA2-512 and KMAC-SHA3-512: {secret_key.hex()}. Its length is: {8*len(bytes.fromhex(secret_key.hex()))}")
    print(f"Secret Key for CMAC that uses AES256 and SHA2-512: {secret_key_for_cmac.hex()}. Its length is: {8*len(bytes.fromhex(secret_key_for_cmac.hex()))}")
    print(f"HMAC-SHA2-512: {result_hmac}, its length is: {4*len(result_hmac)}")
    print(f"KMAC-SHA3-512: {result_kmac}, its length is: {4*len(result_kmac)}")
    print(f"CMAC-AES256-SHA2-512: {result_cmac}, its length is: {4*len(result_cmac)}")
    print(f"My MACv1: {alice_mac_v1}, its length is: {4*len(alice_mac_v1[0])}")
    print(f"My MACv2: {alice_mac_v2}, its length is: {4*len(alice_mac_v2[0])}")
