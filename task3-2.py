from Crypto.Util.number import getPrime
import binascii, random
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

def extendedGCD(a, b):
    '''
    Extended Euclidean Algorithm to find 
    the greatest common divisor (g) of a 
    and b, along with coefficients x and 
    y such that ax+by=g
    '''
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extendedGCD(b % a, a)
        return g, y - (b // a) * x, x

def inverse(e, eulerTotient):
    '''
    Checks if the GCD is really 1
    '''
    g, x, y = extendedGCD(e, eulerTotient)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % eulerTotient

def rsaKeyGen(lenPrime):
    # Generate a 2048-bit prime number
    p = getPrime(lenPrime)
    q = getPrime(lenPrime)
    n = p*q
    eulerTotient = (p-1)*(q-1)
    e = 65537
    d = inverse(e, eulerTotient)
    return e, n, d, n

def strToHexToInt(s, n):
    intVal = int(''.join(hex(ord(char))[2:] for char in s), 16)
    if intVal >= n:
        raise ValueError("Message is not less that n")
    return intVal

def intToHexToChar(s):
    hex_string = hex(s)[2:]
    return binascii.unhexlify(hex_string).decode('utf-8')

if  __name__ == "__main__":
    lenPrime = 2048
    e, n, d, n = rsaKeyGen(lenPrime)
    
    messages = ['Serendipity', 'Mellifluous', 'Quixotic', 'Luminous', 'Ebullient', 'Effervescent', 'Mellifluous', 'Nebulous', 'Resplendent', 'Ephemeral']
    for m in messages:
        # turn message to int
        sB = strToHexToInt(m, n)
    
        # original c essentially trashed
        c = pow(sB, e, n)
        c = 0
        
        # generate sA based on known c
        sA = pow(c, d, n)
        keyA = sha_hash(str(sA), 16)
        
        # generate cipherText
        cipherText = pow(sA, e, n)
        
        # generate cipher, pad text, and encrypt
        iv = get_random_bytes(16)
        cA = AES.new(keyA.encode('utf-8'), AES.MODE_CBC, iv)
        pA = pad(m.encode('utf-8'), AES.block_size, style='pkcs7')
        eA = cA.encrypt(pA)
        
        # Decrypt eA using s = 0 so don't need d bc c changed to 0
        s = 0
        keyA = sha_hash(str(s), 16)
        cA_decrypt = AES.new(keyA.encode('utf-8'), AES.MODE_CBC, iv)
        dA = cA_decrypt.decrypt(eA)
        uA = unpad(dA, AES.block_size, style='pkcs7').decode('utf-8')
        print("Decrypted message from B:", uA)
    