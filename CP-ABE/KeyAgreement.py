from Cryptodome.Hash import SHAKE256
from Cryptodome.Protocol.DH import key_agreement
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pickle
import re

# This KDF has been agreed in advance
def kdf(x):
        return SHAKE256.new(x).read(32)

def sessionKeyGen(U_static, V_static):
    session_key = key_agreement(static_priv=U_static,
                                static_pub=V_static,
                                kdf=kdf)
    return session_key

def preprocess_data(group, key):
    new_key = {}
    for field in key:
        if type(key[field]) == list:
            new_key[field] = pickle.dumps(key[field])
        elif type(key[field]) == dict:
            temp = {}
            for N_field in key[field]:
                temp[N_field] = group.serialize(key[field][N_field])
            new_key[field] = temp
        else:
            new_key[field] = group.serialize(key[field])
    return new_key

def recover_data(group, key):
    new_key = {}
    pattern = re.compile(rb'^[0-9]:')
    for field in key:
        if type(key[field]) == dict:
            temp = {}
            for N_field in key[field]:
                temp[N_field] = group.deserialize(key[field][N_field])
            new_key[field] = temp
        elif bool(pattern.match(key[field])) == True:
            new_key[field] = group.deserialize(key[field])
        else:
            new_key[field] = pickle.loads((key[field]))
            
    return new_key

def key_agreement_encrypt(group, secret, nonce, server_prikey, client_pubkey):
    session_key = sessionKeyGen(server_prikey, client_pubkey)
    # Encrypt secret with session key (using AES-GCM)
    aesgcm = AESGCM(session_key)
    secret = preprocess_data(group, secret)
    encrypted_secret = {}
    for field in secret:
        if type(secret[field]) == dict:
            temp = {}
            for N_field in secret[field]:
                temp[N_field] = aesgcm.encrypt(nonce, secret[field][N_field], None)
            encrypted_secret[field] = temp
        else:
            encrypted_secret[field] = aesgcm.encrypt(nonce, secret[field], None)
    
    return encrypted_secret

def key_agreement_decrypt(group, encrypted_secret, nonce, client_prikey, server_pubkey):
    session_key = sessionKeyGen(client_prikey, server_pubkey)
    # Decrypt encrypted secret with session key (using AES-GCM)
    aesgcm = AESGCM(session_key)
    decrypted_secret = {}
    for field in encrypted_secret:
        if type(encrypted_secret[field]) == dict:
            temp = {}
            for N_field in encrypted_secret[field]:
                temp[N_field] = aesgcm.decrypt(nonce, encrypted_secret[field][N_field], None)
            decrypted_secret[field] = temp
        else:
            decrypted_secret[field] = aesgcm.decrypt(nonce, encrypted_secret[field], None)

    decrypted_secret = recover_data(group, decrypted_secret)
    return decrypted_secret


def policy_encrypt(secret, nonce, prikey, pubkey):
    session_key = sessionKeyGen(prikey, pubkey)
    aesgcm = AESGCM(session_key)
    encoded = aesgcm.encrypt(nonce, secret, None)
    return encoded


def policy_decrypt(secret, nonce, prikey, pubkey):
    session_key = sessionKeyGen(prikey, pubkey)
    aesgcm = AESGCM(session_key)
    decoded = aesgcm.decrypt(nonce, secret, None)
    return decoded