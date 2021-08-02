In this task, I am to design and (partially) implement a secure communication system between two parties.

# Requirements:

The requirements of the system include:

1.) The two parties have each other’s RSA public key. Each of them holds his/her own RSA private key.

2.) Each party’s message (from a .txt file) is encrypted using AES before sending it to another party.

3.) The AES key used in 2) is encrypted using the receiver’s RSA public key. The encrypted AES key is sent together with the encrypted message obtained from 2).

4.) Message authentication code should be appended to data transmitted. You are free to choose the specific protocol of MAC.

5.) The receiver should be able to successfully authenticate, decrypt the message, and read the original message.

 

You need to implement a program for each role (i.e., sender and receiver). You don’t need to include actual socket programming in your code. You can just use local files to simulate the communication in the network. For example, to implement requirement 1 above, we let each party locally generate a key pair and save each key in a corresponding file. The other party will be able to know the public key by accessing the file. You can create a file called “Transmitted_Data”, which can include all data transmitted between sender and receiver, i.e., encrypted message, encrypted AES key, and the MAC. This file is written by the sender and read by the receiver.

Programming language and library

You can choose either OpenSSL Crypto Library or you can use Java Cryptography Architecture for your project. 

# Deliverables

A report which includes following components.

Explanations of your system design, particular algorithms used, key lengths used, etc, and a brief explanation on how to use your programs. All the requirements above should be met.

Security analysis of your system, i.e., general security level, vulnerabilities and possible attacks.

Discussions of possible countermeasures to the attack analyzed in b.

Well-commented source codes.

# Copyright 2021 Rene B. Dena

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
