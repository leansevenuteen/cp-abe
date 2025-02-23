from charm.toolbox.pairinggroup import ZR,G1,G2,GT,pair,hashPair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from Cryptodome.PublicKey import ECC
from KeyAgreement import policy_encrypt, policy_decrypt
from Cryptodome.Math._IntegerGMP import IntegerGMP
import os

# type annotations
pk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
mk_t = {'beta':ZR, 'g2_alpha':G2 }
sk_t = { 'D':G2, 'Dj':G2, 'Djp':G1, 'S':str }
ct_t = { 'C_tilde':GT, 'C':G1, 'Cy':G1, 'Cyp':G2 }
prikey = { 'curve': str, 'point_x': str, 'point_y': str, 'd': str}
pubkey = { 'curve': str, 'point_x': str, 'point_y': str }

debug = False

class CPabe_BSW07(ABEnc):         
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

    @Output(pk_t, mk_t)    
    def setup(self):
        g, gp = group.random(G1), group.random(G2)
        alpha, beta = group.random(ZR), group.random(ZR)
        # initialize pre-processing for generators
        g.initPP(); gp.initPP()
        
        h = g ** beta; f = g ** ~beta
        e_gg_alpha = pair(g, gp ** alpha)
        
        pk = { 'g':g, 'g2':gp, 'h':h, 'f':f, 'e_gg_alpha':e_gg_alpha }
        mk = {'beta':beta, 'g2_alpha':gp ** alpha }
        return (pk, mk)
    
    @Input(pk_t, mk_t, [str])
    @Output(sk_t)
    def keygen(self, pk, mk, S):
        r = group.random() 
        g_r = (pk['g2'] ** r)    
        D = (mk['g2_alpha'] * g_r) ** (1 / mk['beta'])        
        D_j, D_j_pr = {}, {}
        for j in S:
            r_j = group.random()
            D_j[j] = g_r * (group.hash(j, G2) ** r_j)
            D_j_pr[j] = pk['g'] ** r_j
        return { 'D':D, 'Dj':D_j, 'Djp':D_j_pr, 'S':S }
    
    @Input(pk_t, bytes, str, prikey, pubkey)
    @Output(dict)
    def encrypt(self, pk, M, policy_str, private, public):
        M_GT = group.random(GT)
        # Symmetric encryption of the message
        sym_key = hashPair(M_GT)
        sym_crypto = SymmetricCryptoAbstraction(sym_key)
        ct_sym = sym_crypto.encrypt(M)
        
        server_pri = ECC.construct(
            curve=private['curve'],
            point_x=IntegerGMP(int(private['point_x'])),
            point_y=IntegerGMP(int(private['point_y'])),
            d=IntegerGMP(int(private['d']))
        )
        
        server_pub = ECC.construct(
            curve=public['curve'],
            point_x=IntegerGMP(int(public['point_x'])),
            point_y=IntegerGMP(int(public['point_y']))
        )
        
        nonce = os.urandom(64)
        encoded_policy = policy_str.encode('utf-8')
        encrypted_policy = policy_encrypt(encoded_policy, nonce, server_pri, server_pub)
        # ABE encryption of the symmetric key
        policy = util.createPolicy(policy_str)
        s = group.random(ZR)
        shares = util.calculateSharesDict(s, policy)      
        
        C = pk['h'] ** s
        C_y, C_y_pr = {}, {}
        for i in shares.keys():
            j = util.strip_index(i)
            C_y[i] = pk['g'] ** shares[i]
            C_y_pr[i] = group.hash(j, G2) ** shares[i]
        
        ct_abe = { 'C_tilde':(pk['e_gg_alpha'] ** s) * M_GT,
                 'C':C, 'Cy':C_y, 'Cyp':C_y_pr, 'policy':encrypted_policy }
        
        return {'ct_sym': ct_sym, 'ct_abe': ct_abe, 'ct_nonce': nonce}
    
    @Input(sk_t, dict, prikey, pubkey)
    @Output(bytes)
    def decrypt(self, sk, ct, private, public):
        ct_sym = ct['ct_sym']
        ct_abe = ct['ct_abe']
        nonce = ct['ct_nonce']

        server_pri = ECC.construct(
            curve=private['curve'],
            point_x=IntegerGMP(int(private['point_x'])),
            point_y=IntegerGMP(int(private['point_y'])),
            d=IntegerGMP(int(private['d']))
        )
        server_pub = ECC.construct(
            curve=public['curve'],
            point_x=IntegerGMP(int(public['point_x'])),
            point_y=IntegerGMP(int(public['point_y']))
        )
        
        decrypted_policy = policy_decrypt(ct_abe['policy'], nonce, server_pri, server_pub).decode('utf-8')
        # ABE decryption to get the symmetric key
        policy = util.createPolicy(decrypted_policy)
        pruned_list = util.prune(policy, sk['S'])
        if pruned_list == False:
            return b'False'
        z = util.getCoefficients(policy)
        A = 1 
        for i in pruned_list:
            j = i.getAttributeAndIndex(); k = i.getAttribute()
            A *= ( pair(ct_abe['Cy'][j], sk['Dj'][k]) / pair(sk['Djp'][k], ct_abe['Cyp'][j]) ) ** z[j]
        
        M_GT = ct_abe['C_tilde'] / (pair(ct_abe['C'], sk['D']) / A)

        sym_key = hashPair(M_GT)
        # Symmetric decryption of the message
        sym_crypto = SymmetricCryptoAbstraction(sym_key)
        M = sym_crypto.decrypt(ct_sym)
        return M