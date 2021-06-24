#!/usr/bin/env python
# coding: utf-8

# In[276]:


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend 
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigdecode_der, sigencode_der
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import utils


# In[277]:


class user:
    balance = 0
    def __init__(self,name):
        self.private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.name = name
        
    def pubkey_PEM(self):
        pem = self.public_key.public_bytes(encoding = serialization.Encoding.PEM,
                                           format = serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem.decode()


# In[333]:


#Define sender 
#establish sender_private_key
sender_private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())

sender_public_key = sender_private_key.public_key()
    
#DER encoded public key
sender_public_key_der = sender_public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)


#create hash of sender public key (sender_hash)
digest_sha1_s = hashes.Hash(hashes.SHA1(), default_backend())
sender_public_key_b = sender_public_key_der
digest_sha1_s.update(sender_public_key_b)
sender_hash = digest_sha1_s.finalize()

#deserialize the sender public key
deserialized_sender_pubkey = load_der_public_key(sender_public_key_der)



#Define Recipient
recipient_private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
recipient_public_key = recipient_private_key.public_key()
    
#DER encoded public key
recipient_public_key_der = recipient_public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    

#create hash of recipient public key (recipient_hash)
digest_sha1_r = hashes.Hash(hashes.SHA1(), default_backend())
recipient_public_key_b = recipient_public_key_der
digest_sha1_r.update(recipient_public_key_b)
recipient_hash = digest_sha1_r.finalize()

#deserialize the recipient public key
deserialized_recipient_pubkey = load_der_public_key(recipient_public_key_der)


# In[344]:


class Transaction:
    def __init__(self,sender_hash, recipient_hash, sender_public_key, amount,fee, nonce, signature, txid):
        self.sender_hash = sender_hash
        self.recipient_hash = recipient_hash
        self.sender_public_key = sender_public_key
        self.amount = amount
        self.fee = fee
        self.nonce = nonce
        self.signature = signature
        self.txid = txid
                

    def verify(self,sender_private_key, sender_balance,sender_previous_nonce):
        assert len(self.sender_hash)== 20 and len(self.recipient_hash)==20, f"sender_hash ({self.sender_hash}) or recipient_hash({self.recipient_hash}) length not equal to 20"
        
        digest_sha1_s = hashes.Hash(hashes.SHA1(), default_backend())
        sender_public_key_b = sender_public_key_der
        digest_sha1_s.update(sender_public_key_b)
        sender_hash = digest_sha1_s.finalize()
        
        assert self.sender_hash == sender_hash, f"sender_hash ({self.sender_hash}) not equal to SHA1 hash of sender_public_key"
        
        assert self.amount > 0 and self.amount <= sender_balance, f"Amount ({self.amount}) not between 1 and sender_balance"
        assert self.fee >= 0 and self.fee <= self.amount, f"Fee ({self.fee}) not between 0 and amount"
        assert self.nonce == sender_previous_nonce+1, f"Nonce ({self.nonce}) not equal to sender_previous_nonce + 1"
        
        amount_b = (self.amount).to_bytes(8, byteorder = 'little', signed=False)
        fee_b = (self.fee).to_bytes(8, byteorder = 'little', signed=False)
        nonce_b = (self.nonce).to_bytes(8, byteorder = 'little', signed=False)
        digest = hashes.Hash(hashes.SHA256(), default_backend())
        
        txid_b = self.sender_hash+self.recipient_hash+sender_public_key_b+amount_b+fee_b+nonce_b+self.signature
        digest.update(txid_b)
        
        txid_d = digest.finalize()
        
        assert self.txid == txid_d, f"txid ({self.txid}) not equal to hash of other fields in the transaction"        

    
        #receiving error for verification of signature below, unable to resolve
        
        #signature_d = self.recipient_hash+amount_b+fee_b+nonce_b
        #signature = sender_private_key.sign(signature_d, ec.ECDSA(hashes.SHA256()))

        #assert self.sender_public_key.verify(signature, self.recipient_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256()))), f"signature ({self.signature}) not a valid signature"

        
    


# In[345]:



def create_signed_transaction(sender_private_key,recipient_hash,amount,fee,nonce):


    #create signature
    amount_b = (amount).to_bytes(8, byteorder = 'little', signed=False)
    fee_b = (fee).to_bytes(8, byteorder = 'little', signed=False)
    nonce_b = (nonce).to_bytes(8, byteorder = 'little', signed=False)
    signature_d = recipient_hash+amount_b+fee_b+nonce_b
    signature = sender_private_key.sign(signature_d, ec.ECDSA(hashes.SHA256()))
    
    #create txid
    digest_txid = hashes.Hash(hashes.SHA256(), default_backend())
    txid_b = sender_hash+recipient_hash+sender_public_key_der+amount_b+fee_b+nonce_b+signature
    digest_txid.update(txid_b)
    txid = digest_txid.finalize()

    t = Transaction(sender_hash = sender_hash,
                        recipient_hash = recipient_hash,
                        sender_public_key = sender_public_key,
                        amount = amount,
                        fee = fee,
                        nonce = nonce,
                        signature = signature,
                        txid = txid)
    return (t, txid, signature)
    
    
    

    


# In[374]:


#TEST CASE 1
test_privatekey = ec.generate_private_key(ec.SECP256K1)
create_signed_transaction(sender_private_key,recipient_hash,amount,fee,nonce)

sender_balance = 1000
sender_previous_nonce = nonce - 1

try:
    t.verify(sender_balance = sender_balance, sender_private_key= sender_private_key, sender_previous_nonce = sender_previous_nonce)
except AssertionError as exc:
    print("Verification failed with assertion error: ",exc)


# In[397]:


#TEST CASE 2
amount = 100
fee = 55
nonce = 10
sender_balance = 1000
sender_previous_nonce = nonce - 1


try:
    t.verify(sender_balance = sender_balance, sender_private_key= sender_private_key, sender_previous_nonce = sender_previous_nonce)
except AssertionError as exc:
    print("Verification failed with assertion error: ",exc)
    
    
t,txid,signature = create_signed_transaction(sender_private_key = test_privatekey,
                                                recipient_hash = recipient_hash,
                                                amount = amount,
                                                fee = fee,
                                                nonce = nonce)

print(t,txid,signature)


# In[398]:


#TEST CASE 3
amount = 900 
fee = 55
nonce = 10
sender_balance = 10000
sender_previous_nonce = nonce - 1




try:
    t.verify(sender_balance = sender_balance, sender_private_key= sender_private_key, sender_previous_nonce = sender_previous_nonce)
except AssertionError as exc:
    print("Verification failed with assertion error: ",exc)
    
    
    
    
t,txid,signature = create_signed_transaction(sender_private_key = test_privatekey,
                                                recipient_hash = recipient_hash,
                                                amount = amount,
                                                fee = fee,
                                                nonce = nonce)

print(t,txid,signature)


# In[399]:


#TEST CASE 4.1
amount = 900 
fee = 55
nonce = 10
sender_balance = 100
sender_previous_nonce = nonce - 1




try:
    t.verify(sender_balance = sender_balance, sender_private_key= sender_private_key, sender_previous_nonce = sender_previous_nonce)
except AssertionError as exc:
    print("Verification failed with assertion error: ",exc)
    
    
    
    
t,txid,signature = create_signed_transaction(sender_private_key = test_privatekey,
                                                recipient_hash = recipient_hash,
                                                amount = amount,
                                                fee = fee,
                                                nonce = nonce)

print(t,txid,signature)


# In[400]:


#TEST CASE 4.2
amount = 900 
fee = 55
nonce = 10
sender_balance = 1000
sender_previous_nonce = nonce + 1




try:
    t.verify(sender_balance = sender_balance, sender_private_key= sender_private_key, sender_previous_nonce = sender_previous_nonce)
except AssertionError as exc:
    print("Verification failed with assertion error: ",exc)
    
    
    
    
t,txid,signature = create_signed_transaction(sender_private_key = test_privatekey,
                                                recipient_hash = recipient_hash,
                                                amount = amount,
                                                fee = fee,
                                                nonce = nonce)

print(t,txid,signature)


# In[407]:


#TEST CASE 5
amount = 900 
fee = 55
nonce = 10
sender_balance = 1000
sender_previous_nonce = nonce -1

privatekey_A = ec.generate_private_key(ec.SECP256K1)
privatekey_B = ec.generate_private_key(ec.SECP256K1)


t,txid,signature = create_signed_transaction(sender_private_key = privatekey_A,
                                                recipient_hash = recipient_hash,
                                                amount = amount,
                                                fee = fee,
                                                nonce = nonce)

try:
    t.verify(sender_balance = sender_balance, sender_private_key= sender_private_key, sender_previous_nonce = sender_previous_nonce)
except AssertionError as exc:
    print("Verification failed with assertion error: ",exc)
    

print(t,txid,signature)


# In[412]:


#TEST CASE 6

amount = 900 
fee = 55
nonce = 10
sender_balance = 10000
sender_previous_nonce = nonce - 1

t = Transaction(
bytes.fromhex("3df8f04b3c159fdc6631c4b8b0874940344d173d"),
bytes.fromhex("5c1499a0484ace2f731b0afb83241e15f0e168ca"),
bytes.fromhex("3056301006072a8648ce3d020106052b8104000a03420004886ed03cb7ffd4cbd95579ea2e202f1db29afc3bf5d7c2c34a34701bbb0685a7b535f1e631373afe8d1c860a9ac47d8e2659b74d437435b05f2c55bf3f033ac1"),
10,
2,
5,
bytes.fromhex("3046022100f9c076a72a2341a1b8cb68520713e12f173378cf78cf79c7978a2337fbad141d022100ec27704d4d604f839f99e62c02e65bf60cc93ae1735c1ccf29fd31bd3c5a40ed"),
bytes.fromhex("ca388e0890b71bd1775460d478f26af3776c9b4f6c2b936e1e788c5c87657bc3"))


try:
    t.verify(sender_balance, sender_private_key, sender_previous_nonce)
except AssertionError as exc:
    print("Verification failed with assertion error: ",exc)
    
    
    
    
t,txid,signature = create_signed_transaction(sender_private_key = test_privatekey,
                                                recipient_hash = recipient_hash,
                                                amount = amount,
                                                fee = fee,
                                                nonce = nonce)

print(t,txid,signature)


# In[ ]:




