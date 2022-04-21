# Network_Security_Project

## Part 1

**Goal**: Implement the textbook RSA algorithm (without any padding)

The code for this part is mainly in [rsa.py](https://github.com/Huanghongru/Network-security-course-project/blob/master/rsa.py) and it is able to:

* **Generate** a random RSA key pair with a given key size (e.g., 1024bit) :white_check_mark:
* **Encrypt** a plaintext with the public key :white_check_mark:
* **Decrypt** a ciphertext with the private key :white_check_mark:

## Part 2

**Goal**: Perform a CCA2 attack on textbook RSA. The attak is **to gradually reveal** information about an encrypted message, or about the decryption key iteself.

In this attack, the server knows **RSA key pair** and **AES key**. The adversary knows **RSA public key**, **RSA-encrypted AES key** and **an AES-encrypted WUP request**. More detail can be found on this [paper](https://arxiv.org/pdf/1802.03367.pdf).

The code for this part is mainly in [client\_server.py](https://github.com/Huanghongru/Network-security-course-project/blob/master/client_server.py) and [attacker.py](https://github.com/Huanghongru/Network-security-course-project/blob/master/attacker.py). They are able to:

* Simulate the server-client communication. :white_check_mark:
* Generate history message and they are guaranteed to include RSA-encrypted AES key and an AES-encrypted request. :white_check_mark:
* Present the attack process to obtain the AES key and further decrypt the encrypted request. :white_check_mark:

## Part 3

**Goal**: defend the attack by implementing a RSA-OAEP algorithm. 

The code for this part is mainly in [utils.py](https://github.com/Huanghongru/Network-security-course-project/blob/master/utils.py#L119). It is able to add the OAEP padding module to the textbook RSA implementation.

* add the OAEP padding module to the textbook RSA implementation :white_check_mark:
* give a discussion on the advantages of RSA-OAEP compared to the textbook RSA :white_check_mark:
* As a bonus, you can futher try to present CCA2 attack to RSA-OAEP to see whether it can thwart the CCA2 attack you have implemented in part 2 :white_check_mark:

Feel free to run:

```Bash
python main.py
```

to see all of the required results.


## For more details please read my pdf

![1](https://user-images.githubusercontent.com/61941806/163713708-bb868e07-9897-413c-b023-c6cbf7f0c29a.png)
![2](https://user-images.githubusercontent.com/61941806/163713709-dcd361c3-f3db-4008-894d-3750a2ea58d6.png)
![3](https://user-images.githubusercontent.com/61941806/163713710-867d2b2a-e4c7-4957-a1a0-2d4832c868ed.png)
![4](https://user-images.githubusercontent.com/61941806/163713711-23d60f9f-e9e7-44fe-94cf-6f604105fa0a.png)
![5](https://user-images.githubusercontent.com/61941806/163713712-a60ba3e4-2692-487c-841c-aca3bdb15e33.png)
![6](https://user-images.githubusercontent.com/61941806/163713713-88e46a4a-ab18-4bac-8b9b-0ffd7054e7b2.png)
![7](https://user-images.githubusercontent.com/61941806/163713714-d893287b-12bf-4d2c-9dc0-c6bc02f4bc01.png)
![8](https://user-images.githubusercontent.com/61941806/163713707-d100f2ce-bcb9-4530-be57-fed26e228c22.png)
