from Crypto.Util.number import getPrime
import hashlib

def gen_rsa_keypair(bits):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = getPrime(20)
    assert(phi_n % e != 0)
    d = pow(e, -1, phi_n)
    return ((e, n), (d, n))

Ap, As = gen_rsa_keypair(512)
print(Ap, "\n")
print(As, "\n")

def rsa(message, clef):
    e, n = clef
    return pow(message, e, n)

def rsa_enc(message, clef):
    msg = int.from_bytes(message.encode('utf-8'), 'big')
    return rsa(msg, clef)

def rsa_dec(message_crypter, clef):
    msg = rsa(message_crypter, clef)
    return msg.to_bytes((msg.bit_length() + 7) // 8, 'big').decode('utf-8')

message = "Bonjour tu va bien ?"
print(message, "\n")
crypter = rsa_enc(message, Ap)
print(crypter, "\n")
print(rsa_dec(crypter, As), "\n")

def h(n):
    sha256 = hashlib.sha256(n.encode('utf-8')).hexdigest()
    return sha256
    
def rsa_sign(rsa_msg, clef):
    msg_hash = h(rsa_msg)
    return (rsa_msg, rsa_enc(msg_hash, clef))

def rsa_verify(sign_hash, message, clef):
    msg_clear = rsa_dec(sign_hash[1], clef)
    msg = h(message)
    if msg == msg_clear:
        return True
    return False

message2 = "Fake"

signed_message = rsa_sign(message, As)
print(signed_message, "\n")
print(rsa_verify(signed_message, message, Ap), "\n")