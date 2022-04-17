from Crypto.Cipher import AES
from RSA import RSA
import random
from Crypto.Hash import SHA256
import random
import sys
import getopt
import pickle
from RSA import get_prime
import hashlib
def bit_mask(size):
    mask = 0
    for _ in range(size):
        mask = (mask << 1) + 1
    return mask
def WUP(content, mac, ID):
    res = []
    for i in range(0, len(content), 1024):
        sub_content = content[i: min(len(content), i + 1024)]
        if len(sub_content) < 1024:
            sub_content += " " * (1024 - len(sub_content))
        text = "\t".join([sub_content, mac, ID]).encode('utf-8')
        if len(text)%16 != 0:
            text += b'\t'*(16-len(text)%16)
        sha = SHA256.new()
        sha.update(text)
        checksum = sha.hexdigest().encode('utf-8')
        res.append(text + checksum)
    return res
oaep_k0 = 12 # bit
oaep_k1 = 10 # bit
def hashFunction(x):
    h = hashlib.md5()
    x = x.to_bytes(600, 'big')
    h.update(x)
    return int.from_bytes(h.digest(), 'big')
def oaep_encode(plain_text):
    m = plain_text << oaep_k1
    r = get_prime(oaep_k1)
    X = m ^ hashFunction(r)
    Y = r ^ hashFunction(X)
    return (X << oaep_k0)|Y
def oaep_decode(cipher_text):
    Y = cipher_text & bit_mask(oaep_k0)
    X = cipher_text >> oaep_k0
    r = Y ^ hashFunction(X)
    m = (X ^ hashFunction(r)) >> oaep_k1
    return m
class Client():
    def __init__(self):
        self.oaep_flag = 0
        randomMac = [0x52,0x54,0x00,random.randint(0x00,0x7f),random.randint(0x00,0xff),random.randint(0x00,0xff)]
        self.mac = ':'.join(map(lambda x:"%02x" % x, randomMac))
        randID = [random.randint(100000, 999999),random.randint(10, 99),random.randint(100000, 999999),random.randint(0, 9)]
        self.ID =  '-'.join(map(lambda x:str(x),randID))
    def make_wup(self,content,AESKey,aes):
        wupMessage = WUP(content,self.mac,self.ID)
        Encrypt_wup = [aes.encrypt(msg) for msg in wupMessage]
        return [(AESKey,wup) for wup in Encrypt_wup]
    def send_wup(self,content,public_key):
        AESKey = random.getrandbits(128)
        aes = AES.new(AESKey.to_bytes(16, 'big'),AES.MODE_ECB)
        msgs = self.make_wup(content,AESKey,aes)
        n,e = public_key
        send_msg = []
        cipher = pow(AESKey, e, n)
        if self.oaep_flag == 1:
            cipher = oaep_encode(cipher)
        for data in msgs:
            key,wup = data
            send_msg.append((cipher,wup))
        return send_msg
    def receive_msg(self,msgs):
        content = ""
        Mac = 0
        ID = 0
        for msg in msgs:
            AESKey,wup = msg
            aes = AES.new(AESKey,AES.MODE_ECB)
            decrypt_wup = aes.decrypt(wup)
            wup_msg = []
            for data in decrypt_wup.split(b'\t'):
                if data != b'':
                    wup_msg.append(data)
            #wup_msg 为 content,mac,ID,checksum
            #首先验证
            text = wup_msg[0]+b'\t'+wup_msg[1]+b'\t'+wup_msg[2]
            if len(text)%16 != 0:
                text += b'\t'*(16-len(text)%16)
            sha = SHA256.new()
            sha.update(text)
            checksum = sha.hexdigest().encode('utf-8')
            if checksum == wup_msg[-1]:
                content += str(wup_msg[0],encoding = "utf-8") 
                Mac = str(wup_msg[1],encoding = "utf-8") 
                ID = str(wup_msg[2],encoding = "utf-8") 
            else:
                #接收错误信息
                print("Client:wrong content!")
                return None
        print("Client receive:"+content)
        return (content,Mac,ID)
class Server():
    def __init__(self,bit_length=256):
        #RSA
        self.oaep_flag = 0
        self.RSA = RSA(bit_length)
        self.RSA.GenerateKey()
        self.public_key = self.RSA.public_key
        self.private_key = self.RSA.private_key
        randomMac = [0x52,0x54,0x00,random.randint(0x00,0x7f),random.randint(0x00,0xff),random.randint(0x00,0xff)]
        self.mac = ':'.join(map(lambda x:"%02x" % x, randomMac))
        randID = [random.randint(100000, 999999),random.randint(10, 99),random.randint(100000, 999999),random.randint(0, 9)]
        self.ID =  '-'.join(map(lambda x:str(x),randID))
    def make_wup(self,content,AESKey,aes):
        wupMessage = WUP(content,self.mac,self.ID)
        Encrypt_wup = [aes.encrypt(msg) for msg in wupMessage]
        return [(AESKey,wup) for wup in Encrypt_wup]
    def send_msg(self,content,targetMac,targetID):
        AESKey = random.getrandbits(128).to_bytes(16, 'big')
        aes = AES.new(AESKey,AES.MODE_ECB)
        content = "Responce:"+content+"To:"+targetMac+"and"+targetID
        msgs = self.make_wup(content,AESKey,aes)
        return msgs
    def receive_wup(self,msgs):
        content = ""
        targetMac = 0
        targetID = 0
        try:
            for msg in msgs:
                cipherKey,wup = msg
                #首先私钥解密
                n,d = self.private_key
                plainKey = pow(cipherKey,d,n)
                if self.oaep_flag == 1:
                    plainKey = oaep_decode(plainKey)
                plainKey = bit_mask(128) & plainKey
                #这里得到了AESKey
                aes = AES.new(plainKey.to_bytes(16, 'big'),AES.MODE_ECB)
                decrypt_wup = aes.decrypt(wup)
                #接下来
                wup_msg = []
                for data in decrypt_wup.split(b'\t'):
                    if data != b'':
                        wup_msg.append(data)
                #wup_msg 为 content,mac,ID,checksum
                #首先验证
                text = wup_msg[0]+b'\t'+wup_msg[1]+b'\t'+wup_msg[2]
                if len(text)%16 != 0:
                    text += b'\t'*(16-len(text)%16)
                sha = SHA256.new()
                sha.update(text)
                checksum = sha.hexdigest().encode('utf-8')
                if checksum == wup_msg[-1]:
                    content += str(wup_msg[0],encoding = "utf-8") 
                    targetMac = str(wup_msg[1],encoding = "utf-8") 
                    targetID = str(wup_msg[2],encoding = "utf-8") 
                else:
                    #接收错误信息
                    print("Server:wrong content!")
                    return None
        except:
            print("Server:error message!")
            return None
        print("Sever receive message:"+content)
        #针对请求发送响应
        return self.send_msg(content,targetMac,targetID)


class attacker(Client):
    def __init__(self):
        super(attacker, self).__init__()
    def attack(self,public_key,msgs,server):
        cipherKey,wup = msgs[0]
        k_b = 0
        n,e = public_key
        for b in range(127,-1,-1):
            C_b = cipherKey * ((1 << b*e) % n) % n 
            aesKey = bit_mask(128) & (k_b << b)
            aesKey = aesKey.to_bytes(16, 'big')
            aes = AES.new(aesKey,AES.MODE_ECB)
            messages = self.make_wup("attacking test",aesKey,aes)
            send_msg = []
            for msg in messages:
                key,wup = msg
                send_msg.append((C_b,wup))
            if  server.receive_wup(send_msg) == None:
                k_b = k_b | (1<<(127-b))
        resKey = k_b.to_bytes(16, 'big')
        aes = AES.new(resKey,AES.MODE_ECB)
        content = ""
        for data in msgs:
            _,msg = data
            decrypt_wup = aes.decrypt(msg)
            wup_msg = []
            for data in decrypt_wup.split(b'\t'):
                if data != b'':
                    wup_msg.append(data)
            text = wup_msg[0]+b'\t'+wup_msg[1]+b'\t'+wup_msg[2]
            if len(text)%16 != 0:
                text += b'\t'*(16-len(text)%16)
            sha = SHA256.new()
            sha.update(text)
            checksum = sha.hexdigest().encode('utf-8')
            if checksum == wup_msg[-1]:
                content += str(wup_msg[0],encoding = "utf-8") 
                targetMac = str(wup_msg[1],encoding = "utf-8") 
                targetID = str(wup_msg[2],encoding = "utf-8") 
            else: 
                print("The messages have error!")
        print("The wup content:",content)
        return k_b

#test:
def test():
    client = Client()
    server = Server(1024)
    # c向s发送wup
    msg = client.send_wup("Hello world!",server.public_key)
    #s接收
    rec_msg = server.receive_wup(msg)
    #c接收
    fianl_msg = client.receive_msg(rec_msg)
    #print(fianl_msg[0])
def attack():
    client = Client()
    hack = attacker()
    server = Server(1024)
    msg = client.send_wup("Hello world!",server.public_key)
    hack.attack(server.public_key,msg,server)
def oaep_attack():
    client = Client()
    hack = attacker()
    server = Server(1024)
    client.oaep_flag = 1
    server.oaep_flag = 1
    hack.oaep_flag = 1
    msg = client.send_wup("Hello world!",server.public_key)
    hack.attack(server.public_key,msg,server)
if __name__ == "__main__":
    select = input()
    print(select)
    if select == 'test':
        test()
    elif select == 'attack':
        attack()
    elif select == 'oaep':
        oaep_attack()

