import random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def dhke(alpha, q):
    x = random.randint(1, q)
    y = pow(alpha, x, q)
    return x, y

def sha_hash(user_text, digest_size):
    '''
    Write a program that uses SHA256 to hash arbitrary inputs and print
    the resulting digests to the screen in hexadecimal format. 
    '''
    temp = SHA256.new()
    temp.update(bytes(user_text, 'utf-8'))

    full_digest = temp.hexdigest()

    # Convert the hexadecimal digest to binary
    binary_digest = bin(int(full_digest, 16))[2:]

    # Truncate the binary digest to the specified number of bits
    truncated_digest = binary_digest[-digest_size:].zfill(digest_size)

    return truncated_digest

if __name__ == "__main__":
    alpha = "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 855E6EEB 22B3B2E5"
    q = "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371"
    
    # run diffie hellman
    xA, yA = dhke(int(alpha.replace(" ", ""), 16), int(q.replace(" ", ""), 16))
    xB, yB = dhke(int(alpha.replace(" ", ""), 16), int(q.replace(" ", ""), 16))

    sA = pow(yB, xA, int(q.replace(" ", ""), 16))
    sB = pow(yA, xB, int(q.replace(" ", ""), 16))

    # hash the mod values
    keyA = sha_hash(str(sA), 16)
    keyB = sha_hash(str(sB), 16)
                
    # write message
    mA = "This is a secret."
    mB = "I'm trying to deliver a message."

    iv = get_random_bytes(16)

    # generate cipher, pad text, and encrypt
    cA = AES.new(keyA.encode('utf-8'), AES.MODE_CBC, iv)
    pA = pad(mA.encode('utf-8'), AES.block_size, style='pkcs7')
    eA = cA.encrypt(pA)
    
    # generate cipher, pad text, and encrypt
    cB = AES.new(keyB.encode('utf-8'), AES.MODE_CBC, iv)
    pB = pad(mB.encode('utf-8'), AES.block_size, style='pkcs7')
    eB = cB.encrypt(pB)
        
    # Decrypt eA
    cA_decrypt = AES.new(keyA.encode('utf-8'), AES.MODE_CBC, iv)
    dA = cA_decrypt.decrypt(eA)
    uA = unpad(dA, AES.block_size, style='pkcs7').decode('utf-8')
    print("Decrypted message from A:", uA)
    
    # Decrypt eB
    cB_decrypt = AES.new(keyB.encode('utf-8'), AES.MODE_CBC, iv)
    dB = cB_decrypt.decrypt(eB)
    uB = unpad(dB, AES.block_size, style='pkcs7').decode('utf-8')
    print("Decrypted message from B:", uB)
