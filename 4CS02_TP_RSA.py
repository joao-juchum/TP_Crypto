#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Nov  3 16:29:08 2024

@author: sebastiencanard
"""

import random
import hashlib
import os
from sympy import isprime

"""
Génération des nombres premiers et des clés RSA
"""

def generate_prime(bits):
    """Génère un nombre premier de taille spécifiée en bits."""
    while True:
        num = random.getrandbits(bits)
        if isprime(num):
            return num

def generate_keys(bits=512):
    """Génère des clés RSA (public et privé) de taille spécifiée en bits."""
    # A implémenter     
    

"""
Question 4.1 - Chiffrement et déchiffrement RSA de base
"""

def encrypt_rsa(message, public_key):
    """Chiffre un message avec RSA et la clé publique (n, e)."""
    # A implémenter    

def decrypt_rsa(cipher_int, private_key):
    """Déchiffre un message chiffré avec RSA et la clé privée (n, d)."""
    # A implémenter     

"""
Question 4.2 - Implémentation de RSA-OAEP
"""

def mgf1(seed, mask_len, hash_func=hashlib.sha256):
    """Implémentation de MGF1 avec une fonction de hachage spécifiée (par défaut SHA-256)."""
    hash_len = hash_func().digest_size
    mask = b''
    for i in range((mask_len + hash_len - 1) // hash_len):
        C = i.to_bytes(4, 'big')  # compteur de 4 octets
        mask += hash_func(seed + C).digest()
    return mask[:mask_len]

def oaep_pad(message_bytes, label=b'', hash_func=hashlib.sha256):
    """Applique le padding OAEP à un message en utilisant un seed aléatoire et MGF1."""
    hash_len = hash_func().digest_size
    message_len = len(message_bytes)
    max_message_len = 128 - 2 * hash_len - 2  # Supposons un bloc de 128 octets
    
    if message_len > max_message_len:
        raise ValueError("Le message est trop long pour OAEP avec la taille de bloc spécifiée.")
    
    # Encodage du label avec le hachage
    l_hash = hash_func(label).digest()
    
    # Compléter le message pour la taille requise
    padding = b'\x00' * (max_message_len - message_len)
    data_block = l_hash + padding + b'\x01' + message_bytes
    
    # Génération d'un seed aléatoire
    seed = os.urandom(hash_len)
    
    # Masquage
    data_block_mask = mgf1(seed, len(data_block), hash_func)
    masked_data_block = bytes(x ^ y for x, y in zip(data_block, data_block_mask))
    
    seed_mask = mgf1(masked_data_block, hash_len, hash_func)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))
    
    # Concaténation pour obtenir le message paddé final
    return masked_seed + masked_data_block


def oaep_unpad(padded_message, label='', rounds=2):
    """Inverse du padding OAEP avec schéma de Feistel pour récupérer le message original."""
    # A implémenter    

def encrypt_rsa_oaep(message, public_key, label=''):
    """Chiffre un message avec RSA et OAEP."""
    # A implémenter    

def decrypt_rsa_oaep(cipher_int, private_key, label=''):
    """Déchiffre un message chiffré avec RSA et OAEP."""
    # A implémenter    


