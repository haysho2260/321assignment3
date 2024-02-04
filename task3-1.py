from Crypto.Util.number import getPrime
import binascii

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

if  __name__ == "__main__":
    lenPrime = 2048
    publicKey, privateKey = rsaKeyGen(lenPrime)
    messages = ['Serendipity', 'Mellifluous', 'Quixotic', 'Luminous', 'Ebullient', 'Effervescent', 'Mellifluous', 'Nebulous', 'Resplendent', 'Ephemeral']
    for m in messages:
        intVal = strToHexToInt(m, publicKey[1])
        try:
            cipherText = pow(intVal, publicKey[0], publicKey[1])
            decrypted = pow(cipherText,  privateKey[0], privateKey[1])
            print("Cipher Text : ", cipherText, 
                "\nDecryption   : ", intToHexToChar(decrypted), "\n")
        except:
            print("The message is too long to be encrypted\n")