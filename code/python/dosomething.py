from Crypto.Ciphers import AES

def bad2(): #semgrep supressed
    # nosemgrep
    cipher = AES.new("", AES.MODE_CFB, iv)
    msg = iv + cipher.encrypt(b'Attack at dawn')

def bad3(): #semgrep supressed
    # nosemgrep: empty-aes-key
    cipher = AES.new("", AES.MODE_CFB, iv)
    msg = iv + cipher.encrypt(b'Attack at dawn')

def bad4(): #semgrep supressed
    cipher = AES.new("", AES.MODE_CFB, iv) # nosemgrep
    msg = iv + cipher.encrypt(b'Attack at dawn')

def bad5(): #semgrep supressed
    cipher = AES.new("", AES.MODE_CFB, iv) # nosemgrep: empty-aes-key
    msg = iv + cipher.encrypt(b'Attack at dawn')

def ok1(key):
    # ok: empty-aes-key
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
