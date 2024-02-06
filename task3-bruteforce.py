from Crypto.Util.number import getPrime
import binascii
from Crypto.Hash import SHA256


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
    return (e, n), (d, n)

def strToHexToInt(s, n):
    intVal = int(''.join(hex(ord(char))[2:] for char in s), 16)
    if intVal >= n:
        raise ValueError("Message is not less that n")
    return intVal

def intToHexToChar(s):
    hex_string = hex(s)[2:]
    return binascii.unhexlify(hex_string).decode('utf-8')

def findPrimeFactors(product):
    ''' returns two prime factors of n'''
    product = int(product)
    if product % 2 == 0:
        return 2, product / 2
    for i in range(3, product // 2, 2):
        if product % i == 0:
            return i, product // i

def evilFunction(publicKey, eulerTotient):
    d = inverse(publicKey[0],  eulerTotient)
    return (d, int(publicKey[1]))

if  __name__ == "__main__":
    lenPrime = 8
    publicKey, privateKey = rsaKeyGen(lenPrime)
    messages = ['hi', 'go', 'ct', 'do', 're', 'fn', 'sn', 'at', 'on', 'up']
    for m in messages:
        intVal = strToHexToInt(m, publicKey[1])
        cipherText = pow(intVal, publicKey[0], publicKey[1])
        try:
            prime1, prime2 = findPrimeFactors(publicKey[1])
            eveKey = evilFunction(publicKey, (prime1-1)*(prime2-1))
            decrypted = pow(cipherText,  int(eveKey[0]), eveKey[1])
            print("Cipher Text : ", cipherText, 
                "\nDecryption   : ", intToHexToChar(decrypted), "\n")
        except:
            print("The message is too long to be encrypted\n")