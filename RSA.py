import random
import sys
import getopt
import pickle
import hashlib
def bit_mask(size):
    mask = 0
    for _ in range(size):
        mask = (mask << 1) + 1
    return mask
###产生大素数函数
def rabin_miller(num):
    s = num - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1
    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True

def is_prime(num):
    # 排除0,1和负数
    if num < 2:
        return False
    # 创建小素数的列表,可以大幅加快速度
    # 如果是小素数,那么直接返回true
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
    if num in small_primes:
        return True
    # 如果大数是这些小素数的倍数,那么就是合数,返回false
    for prime in small_primes:
        if num % prime == 0:
            return False
    # 如果这样没有分辨出来,就一定是大整数,那么就调用rabin算法
    return rabin_miller(num)

def getd(e,pha_n):
    a = 1
    b = 0
    c = 0
    d = 1
    m = e
    n = pha_n
    while (m!=1 and n!=1):
        if m>n:
            k = m // n
            m = m - k*n
            a = a - k*c
            b = b - k*d
        else:
            k = n // m
            n = n - k*m
            c = c - k*a
            d = d - k*b
    if m == 1:
        return (c-(n-1)*a,d-(n-1)*b)
    else:
        return (a-(m-1)*c,b-(m-1)*d)

# 得到大整数,默认位数为1024
def get_prime(key_size=1024):
    while True:
        num = random.randrange(2**(key_size-1), 2**key_size)
        if is_prime(num):
            return num

class RSA():
    def __init__(self,bit_length=256):
        self.public_key = None
        self.private_key = None
        self.bit_length = bit_length
    def GenerateKey(self):
        #RSA 加密算法
        #任意选取两个不同的大素数p和q计算乘积
        p = get_prime(self.bit_length)
        q = get_prime(self.bit_length)
        n = p * q
        pha_n = (p-1) * (q-1)
        #任意选取一个大整数e，满足 ，整数e用做加密钥
        normal_prime = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]
        select_prime = []
        for i in normal_prime:
            if pha_n % i != 0:
                select_prime.append(i)
        select = random.randint(0,len(select_prime)-1)
        if pha_n % 65537 != 0:
            e = 65537 if 65537 < pha_n else select_prime[select]
        else:
            e = select_prime[select]
        #确定的解密钥d ed%pha_n = 1
        d,_ = getd(e,pha_n)
        if d < 0:
            d += abs(d//n)*n
        #确定公私钥对
        self.public_key  = (n,e)
        self.private_key = (n,d)
        with open("Key.txt","w") as f:
            f.write("Public Key:{}\n".format(self.public_key))
            f.write("Private Key:{}".format(self.private_key))
oaep_k0 = 128 # bit
oaep_k1 = 120 # bit
def hashFunction(x):
    h = hashlib.md5()
    x = x.to_bytes(128, 'big')
    h.update(x)
    return int.from_bytes(h.digest(), 'big')
def oaep_encode(plain_text):
    oaep_msg = []
    for num in plain_text:
        m = num << oaep_k1
        r = get_prime(oaep_k1)

        X = m ^ hashFunction(r)
        Y = r ^ hashFunction(X)

        oaep_msg.append((X << oaep_k0) | Y)
    return oaep_msg
def oaep_decode(cipher_text):
    oaep_msg = []
    for num in cipher_text:
        Y = num & bit_mask(oaep_k0)
        X = num >> oaep_k0
        r = Y ^ hashFunction(X)
        m = (X ^ hashFunction(r)) >> oaep_k1
        oaep_msg.append(m)
    return oaep_msg

bit_length = 256
file_name  = "plain_text.txt"
mode = 0 # 0 Encrypt 1 Decrypt
rsa_file = "rsa.pkl"
oaep_flag = 0
if len(sys.argv) != 1:
    opts,args = getopt.getopt(sys.argv[1:],"b:f:m:r:o:",["bit_length=file=mode=rsa=oaep="])
    for opt,msg in opts:
        if opt in ("-b","--bit_length"):
            bit_length = int(msg)
        if opt in ("-f","--file"):
            file_name = str(msg)
        if opt in ("-m","--mode"):
            mode = int(msg)
        if opt in ("-r","--rsa"):
            rsa_file = str(msg)
        if opt in ("-o","--oaep"):
            oaep_flag = 1
rsa = RSA(bit_length)
##加密
if mode == 0:
    rsa.GenerateKey()
    with open("rsa.pkl","wb") as f:
        f.write(pickle.dumps(rsa))
    ciphertext = []
    with open(file_name) as f:
        msg = f.read()
        ##编码
        enc = [int(b) for b in str.encode(msg)]
        if oaep_flag == 1:
            enc = oaep_encode(enc)
        ##加密
        n,e = rsa.public_key 
        for bit in enc:
            ciphertext.append(pow(bit, e, n))
    with open("ciphertext.txt","w") as f:
        for i in range(len(ciphertext)):
            f.write("{}\n".format(str(ciphertext[i])))
##解密
elif mode == 1:
    with open(rsa_file,'rb') as f:
        rsa  = pickle.loads(f.read())
    ciphertext = []
    with open(file_name) as f:
        for cipher in f:
            ciphertext.append(int(cipher))
    plain_text = ""
    enc = []
    n,d = rsa.private_key
    for cipher in ciphertext:
        enc.append(pow(cipher,d,n))
    if oaep_flag == 1:
        enc = oaep_decode(enc)
    plain_text = bytearray(enc).decode()
    with open("plaintext.txt","w") as f:
        f.write(plain_text)





    





