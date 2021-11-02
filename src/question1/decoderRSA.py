#https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e
#https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/

def modInverse(a, m):
    for x in range(1, m):
        if (((a%m) * (x%m)) % m == 1):
            return x
    return -1


p = 7963
q = 16033
e = 7
ct = 122880244
ct2= 27613890


n = p * q

phi = (p-1) * (q-1)
d = modInverse(e,phi)


# Decrypt ciphertext
pt = pow(ct, d, n) 
print( "encrypted: " + str(ct) + ", decrypted: " + str(pt) )
pt = pow(ct2, d, n)
print( "encrypted: " + str(ct2) + ", decrypted: " + str(pt) )
