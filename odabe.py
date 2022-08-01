#! /usr/bin/python3
'''
| Type:     Single node Lightweight DABE 
| Notes:
| setting:  Pairing
| Date:     8/05/2022
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
import time
from datetime import timedelta
import sys 




class dabe(ABEncMultiAuth):
         
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)	
        group = groupObj				

    def setup(self):
        g = group.random(G1)
        H = lambda x: group.hash(x, G1)
        GP = {'g':g, 'H': H}
        return GP

    def authsetup(self, GP, attributes):
        SK = {} #dictionary of {attribute i: {alpha_i, beta_i}} 
        PK = {} #dictionary of {attribute i: {e(g,g)^alpha_i, g^beta_i}}
        for i in attributes: # This is done for each attribue that this AA handles
            alpha_i, beta_i = group.random(), group.random()   	# two random group elements
            e_gg_alpha_i = pair(GP['g'],GP['g']) ** alpha_i 	# first part of the PK
            g_beta_i = GP['g'] ** beta_i                          	# second part of the PK
            SK[i.upper()] = {'alpha_i': alpha_i, 'beta_i': beta_i} 	# The random group elements are the SK
            PK[i.upper()] = {'e(gg)^alpha_i': e_gg_alpha_i, 'g^beta_i': g_beta_i}

        if(debug):
            print("Authority Setup for %s" % attributes)
            print("SK = {alpha_i, beta_i}")
            print(SK)
            print("PK = {e(g,g) ^ alpha_i, g ^ beta_i}")
            print(PK)
        return (SK, PK)
    

    def keygen(self, GP, SK, i, gid, pkey):
        #Create a key for GID on attribute i belonging to an authority
        #SK is the private key for the releveant authority
        #gid it the GID of the client
        #i is the attribute i of the client
        #pkey is client's private key dictionary, to which the appropriate private key is added
        
        h = GP['H'](gid) 
        # hash of the gid.. Later this ensures that no two clients can share their keys for collisions.
	
        g = GP['g']
        k = (g ** SK[i.upper()]['alpha_i']) * (h ** SK[i.upper()]['beta_i'])
        

        pkey[i.upper()] = {'k': k}
        pkey['gid'] = gid


        if(debug):
            print("Key gen for %s on %s" % (gid, i))
            print("H(GID): '%s'" % h)
            print("K = g^alpha_i * H(GID) ^ beta_i: %s" % k)
        return None 

    def original_encrypt(self, GP, pk, M, policy_str):
        '''
        The origianl DABE encrypt algorithm. 
        But can be used instead of (prepare_encrypt_parameters) --> (pre_encrypt) --> (encrypt) procedures as the original version for testing'''
        # M is a group element (will be used later as the key for symmetric encryption)
        # pk is a dictionary with all the attributes of all authorities put together.
        
        s = group.random()      # choose a random secret s
        w = group.init(ZR, 0)   # set w to 0
        egg_s = pair(GP['g'], GP['g']) ** s
        C0 = M * egg_s
        C1, C2, C3 = {}, {}, {}



        policy = util.createPolicy(policy_str)
        s_shares = util.calculateSharesList(s, policy) # create a vector of the secret shares of the value s (note that s_0 = s)
        w_shares = util.calculateSharesList(w, policy) # create a vector of the secret shares of the value w (note that w_0 = 0)
	
        s_shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in s_shares])
        w_shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in w_shares])
        r = {}
        for attr, s_share in s_shares.items(): r[attr] = group.random()


        for attr, s_share in s_shares.items():
            k_attr = util.strip_index(attr)
            w_share = w_shares[attr]
            C1[attr] = (pair(GP['g'],GP['g']) ** s_share) * (pk[k_attr]['e(gg)^alpha_i'] ** r[attr]) 
            C2[attr] = GP['g'] ** r[attr] 
            C3[attr] = (pk[k_attr]['g^beta_i'] ** r[attr]) * (GP['g'] ** w_share) 
        return {'C0':C0, 'C1':C1, 'C2':C2, 'C3':C3, 'policy':policy_str}

    def original_decrypt(self, GP, sk, ct):
        '''
        Get the Global parameter (GP), the secret keys of the decryptor (sk), and the ciphertext (ct)
        Returns the plaintext (i.e. a group element M)
        '''
        usr_attribs = list(sk.keys())
        usr_attribs.remove('gid')
        policy = util.createPolicy(ct['policy'])
        pruned = util.prune(policy, usr_attribs)       # return either 1) a subset of attributes to satisfy the access structure or 2) false.
        if pruned == False:
            if verbose: print("Don't have the required attributes for decryption!")
            return None

        coff = util.getCoefficients(policy)
        h_gid = GP['H'](sk['gid'])
        egg_s = 1
	
        for pr in pruned:
            x = pr.getAttributeAndIndex()
            y = pr.getAttribute()
            num = ct['C1'][x] * pair(h_gid, ct['C3'][x])
            dem = pair(sk[y]['k'], ct['C2'][x])
            egg_s *= ( (num / dem) ** coff[x] )

        return ct['C0'] / egg_s

class singlenodev1():

    def publickeygen(self, GP, i, pk, private_xyz):
        ''' 
        This procedure is related to the single node encryption model.
        Each attribute authority gets a random number x (in private_xyz[i.upper()]['x']) and computes three values.
        These three values later are used to blind the calculations in the computational node.
        '''
        g = GP['g']
        x = private_xyz[i.upper()]['x']
        y = private_xyz[i.upper()]['y']
        z = private_xyz[i.upper()]['z']

        private_xyz[i.upper()]['g^y'] = (g ** y)
        private_xyz[i.upper()]['g^z'] = (g ** z)
        private_xyz[i.upper()]['g^beta_i*z'] = pk[i.upper()]['g^beta_i'] ** z
        private_xyz[i.upper()]['e(gg)^x'] = pair(g, g) ** x
        private_xyz[i.upper()]['e(gg)^alpha_i*z'] = pk[i.upper()]['e(gg)^alpha_i'] ** z
        

        return None 


    def prepare_encrypt_parameters(self, GP, policy_str, private_xyz):
        '''Prepare the required parameters for the encryption ... Done by the encryptor node'''
        
        s = group.random()      # choose a random secret s
        w = group.init(ZR, 0)   # set w to 0



        policy = util.createPolicy(policy_str)
        s_shares = util.calculateSharesList(s, policy) # create a vector of the secret shares of the value s (note that s_0 = s)
        w_shares = util.calculateSharesList(w, policy) # create a vector of the secret shares of the value w (note that w_0 = 0)
	
        s_shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in s_shares])
        w_shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in w_shares])
        r = {}
        for attr, _ in s_shares.items(): r[attr] = group.random() # for each attribute in the access structure create a random value r

        for attr, _ in s_shares.items():         # Blind the values by adding the random number d to them.
            s_shares[attr] += (-private_xyz[attr]['x'])
            w_shares[attr] += (-private_xyz[attr]['y'])
            r[attr] += (-private_xyz[attr]['z'])

        return {'s':s, 'w':w}, {'s_shares_':s_shares, 'w_shares_':w_shares, 'r_':r}


    def pre_encrypt(self, GP, pk, public_parameters):
        '''
        Pre Encrypt ... Done by the computational node
        The computational node does a pre encrypt with similar calculations to the normal encryption, but with received blinded values
        '''
        # pk is a dictionary with all the attributes of all authorities put together.
        
        E1_, E2_, E3_ = {}, {}, {}

        s_shares_ = public_parameters['s_shares_']
        w_shares_ = public_parameters['w_shares_']
        r_ = public_parameters['r_']

        for attr, s_share in s_shares_.items():
            k_attr = util.strip_index(attr)
            w_share = w_shares_[attr]
            E1_[attr] = (pair(GP['g'],GP['g']) ** s_share) * (pk[k_attr]['e(gg)^alpha_i'] ** r_[attr]) 
            E2_[attr] = GP['g'] ** r_[attr] 
            E3_[attr] = (pk[k_attr]['g^beta_i'] ** r_[attr]) * (GP['g'] ** w_share) 
        return {'E1_':E1_, 'E2_':E2_, 'E3_':E3_} 

    def encrypt(self, GP, E, M, policy_str,  private_parameters, private_xyz):
        '''
        Encrypt ... Done by the encryptor node
        The final step of encryption. Prior to this algorithm, the (prepare_encrypt_parameters) and (pre_encrypt) shdould be already done
        '''
        # M is a group element (will be used later as the key for symmetric encryption)        
        s = private_parameters['s']         # retrieve the value s. It has been already generated in (prepare_encrypt_parameters) step
        egg_s = pair(GP['g'], GP['g']) ** s
        C0 = M * egg_s
        C1, C2, C3 = {}, {}, {}


        for attr in E['E1_']:
            C1[attr] = E['E1_'][attr] * private_xyz[attr]['e(gg)^x'] * private_xyz[attr]['e(gg)^alpha_i*z']
            C2[attr] = E['E2_'][attr] * private_xyz[attr]['g^z']
            C3[attr] = E['E3_'][attr] * private_xyz[attr]['g^y'] * private_xyz[attr]['g^beta_i*z']
        return {'C0':C0, 'C1':C1, 'C2':C2, 'C3':C3, 'policy':policy_str}

    def encrypt_all_in_one(self, GP, pk, M, policy_str, private_xyz):
        '''
        This procedure will NOT called in this model. 
        But can be used instead of (prepare_encrypt_parameters) --> (pre_encrypt) --> (encrypt) procedures as a compact version for testing'''
        # M is a group element (will be used later as the key for symmetric encryption)
        # pk is a dictionary with all the attributes of all authorities put together.
        
        s = group.random()      # choose a random secret s
        w = group.init(ZR, 0)   # set w to 0
        egg_s = pair(GP['g'], GP['g']) ** s
        C0 = M * egg_s
        C1, C2, C3 = {}, {}, {}


        policy = util.createPolicy(policy_str)
        s_shares = util.calculateSharesList(s, policy) # create a vector of the secret shares of the value s (note that s_0 = s)
        w_shares = util.calculateSharesList(w, policy) # create a vector of the secret shares of the value w (note that w_0 = 0)
        if debug: print(s_shares)
	
        s_shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in s_shares])
        w_shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in w_shares])
        r = {}
        for attr, s_share in s_shares.items(): r[attr] = group.random()

        for attr, _ in s_shares.items():
            s_shares[attr] += (-private_xyz[attr]['x'])
            w_shares[attr] += (-private_xyz[attr]['y'])
            r[attr] += (-private_xyz[attr]['z'])
        if debug: print(s_shares)

        for attr, s_share in s_shares.items():
            k_attr = util.strip_index(attr)
            w_share = w_shares[attr]
            C1[attr] = (pair(GP['g'],GP['g']) ** s_share) * (pk[k_attr]['e(gg)^alpha_i'] ** r[attr]) * private_xyz[attr]['e(gg)^x'] * private_xyz[attr]['e(gg)^alpha_i*z']
            C2[attr] = GP['g'] ** r[attr] * private_xyz[attr]['g^z']
            C3[attr] = (pk[k_attr]['g^beta_i'] ** r[attr]) * (GP['g'] ** w_share) * private_xyz[attr]['g^y'] * private_xyz[attr]['g^beta_i*z']
        return {'C0':C0, 'C1':C1, 'C2':C2, 'C3':C3, 'policy':policy_str} 
        
def getattributelist(access_structure):
        '''
        Gets the access structure (as Boolean formula) 
        Returns a list with the used attributes in the access structure as the members of the list 
        '''
        access_structure = str(util.createPolicy(access_structure))
        access_structure = access_structure.replace('or', '')
        access_structure = access_structure.replace('and', '')
        access_structure = access_structure.replace('(', '')
        access_structure = access_structure.replace(')', '')
        access_structure = access_structure.replace('  ', ' ')
        access_structure = access_structure.replace('   ', ' ')
        result = access_structure.upper().split(' ')
        return result

def main():   
    groupObj = PairingGroup('SS512')
    decentralizedabe = dabe(groupObj)
    singlenode = singlenodev1()
    GP = decentralizedabe.setup()
    
    auth1_attrs = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'FIVE_0', 'FIVE_1']   # five_0 and five_1 in case the attribute five used twice in the access structure
    (SK_auth1, PK_auth1) = decentralizedabe.authsetup(GP, auth1_attrs)
    if debug: print("Authority 1 SK")
    if debug: print(SK_auth1)


    # Create two users with following attributes:
    # Alice credentials
    alice_gid, alice_sk = "alice", {}
    alice_attrs = ['ONE', 'TWO', 'THREE', 'FIVE']
    for i in alice_attrs: decentralizedabe.keygen(GP, SK_auth1, i, alice_gid, alice_sk)
    # Bob credentials
    bob_gid, bob_sk = "bob", {}
    bob_attrs = ['TWO', 'FOUR']
    for i in bob_attrs: decentralizedabe.keygen(GP, SK_auth1, i, bob_gid, bob_sk)    

    
    
    # This section is done by encryptor node 
    if(len(sys.argv) > 1):
        access_structure = sys.argv[1]
        if verbose: print('[x] acccess structure has been set to ', access_structure)
    else:
        access_structure = '(one OR five)' # access policy to the plaintext (i.e. an encrypted group member)
        if verbose: print('[x] no acccess structure has been provided. default is ', access_structure)
    rand_key = groupObj.random(GT)      # a random group member. This value will be encrypted using DABE 
    private_xyz =  {}     # This dictionary will be used by the encryptor to later does the lightweight DABE encryption
    senc = SymmetricCryptoAbstraction(extractor(rand_key))
    symmetric_ciphertext = senc.encrypt(b"our secret plaintext")  # symmetric AES encryption of the actual plaintext

    attrs = getattributelist(access_structure)
    if verbose: print('[x] access structure has {} attributes'.format(len(attrs)))#, attrs))
    for i in range(len(attrs)):
        private_xyz[attrs[i]] = {}
        private_xyz[attrs[i]]['x'] = group.random()  
        private_xyz[attrs[i]]['y'] = group.random()  
        private_xyz[attrs[i]]['z'] = group.random()  
    for i in attrs: singlenode.publickeygen(GP, i, PK_auth1, private_xyz)

    # ------------------------------------------------------  original encryption
    if dabe_execution:
        original_encrypt_start_time = time.monotonic()
        CT = decentralizedabe.original_encrypt(GP, PK_auth1, rand_key, access_structure)
        #CT = singlenode.encrypt_all_in_one(GP, PK_auth1, rand_key, access_structure, private_xyz)
        original_encrypt_end_time = time.monotonic()
    # ------------------------------------------------------  lightweight encryption
    if light_execution:
        preparation_start_time = time.monotonic()
        private_parameters, public_parameters = singlenode.prepare_encrypt_parameters(GP, access_structure, private_xyz) 
        preparation_end_time = time.monotonic()
        preencrypt_start_time = time.monotonic()
        E = singlenode.pre_encrypt(GP, PK_auth1, public_parameters) 
        preencrypt_end_time = time.monotonic()
        encrypt_start_time = time.monotonic()
        CT = singlenode.encrypt(GP, E, rand_key, access_structure, private_parameters, private_xyz) 
        encrypt_end_time = time.monotonic()
    # ------------------------------------------------------
    


    # Alice tries to decrypt the ciphertext
    if verbose: print("\n\n[x] Decrypt the random key by Alice...")
    alice_rec_key = decentralizedabe.original_decrypt(GP, alice_sk, CT)

    
    if (rand_key != alice_rec_key): 
        if verbose: print("[x] Failed Decryption of ciphertext by Alice.. No required attributes")
    else:
        sdec = SymmetricCryptoAbstraction(extractor(alice_rec_key))  
        pltext = sdec.decrypt(symmetric_ciphertext)
        if verbose: print("[x] Decrypted plaintext =>", pltext)
    # ------------------------------------------------------

    



    # Bob tries to decrypt the ciphertext
    if verbose: print("\n\n[x] Decrypt the random key by Bob...")
    bob_rec_key = decentralizedabe.original_decrypt(GP, bob_sk, CT)
 
    
    if (rand_key != bob_rec_key): 
        if verbose: print("[x] Failed Decryption of ciphertext by Bob.. No required attributes")
    else:
        sdec = SymmetricCryptoAbstraction(extractor(bob_rec_key))
        pltext = sdec.decrypt(symmetric_ciphertext)
        if verbose: print("[x] Decrypted plaintext =>", pltext)
    # ----------------------------------------------------
    
    if dabe_execution: 
        time_dabe_file = open('dabe_time.txt', 'a')
        time_dabe = timedelta(seconds=(original_encrypt_end_time - original_encrypt_start_time))
        if verbose: print("[x] Execution Time (original DABE) \t: ", time_dabe)
        time_dabe_file.write(str(time_dabe).split(":")[-1]+"\n")
        time_dabe_file.close()
    if light_execution:
        time_odabe_enc_file = open('odabe_encryptor_time.txt', 'a')

        time_odabe_enc = timedelta(seconds= (preparation_end_time - preparation_start_time) + (encrypt_end_time - encrypt_start_time))
        if verbose: print("[x] Execution Time (ODABE - encryptor) \t: ", time_odabe_enc)
        time_odabe_enc_file.write(str(time_odabe_enc).split(":")[-1]+"\n")
        time_odabe_enc_file.close()
        if verbose: print("[x] Execution Time (ODABE - computational node) : ", timedelta(seconds= (preencrypt_end_time - preencrypt_start_time)))
    if verbose: print("-----------------------------------")

if __name__ == "__main__":
    debug = False
    dabe_execution = True  # Set to (True) if original dabe is required to be executed
    light_execution = True  # Set to (True) if lightweight dabe is required to be executed
    verbose = False
    main()
   

