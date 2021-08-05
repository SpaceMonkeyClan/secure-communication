 /**
 * CS4600 - Secure Communication - HW#3
 * Author: Rene. B Dena
 * Last Modified: 8/5/21
 * File Name: Main.java
 */

 // ____________________Requirements_______________________________________

 /**
 * The requirements of the system include:
 *
 * 1.) The two parties have each other’s RSA public key. Each of them holds his/her own RSA private key.
 *
 * 2.) Each party’s message (from a .txt file) is encrypted using AES before sending it to another party.
 *
 * 3.) The AES key used in 2) is encrypted using the receiver’s RSA public key. The encrypted AES key is sent together
 *      with the encrypted message obtained from 2).
 *
 * 4.) Message authentication code should be appended to data transmitted. You are free to choose the specific protocol
 *      of MAC.
 *
 * 5.) The receiver should be able to successfully authenticate, decrypt the message, and read the original message.
 *
 * You need to implement a program for each role (i.e., sender and receiver). You don’t need to include actual socket
 * programming in your code. You can just use local files to simulate the communication in the network. For example,
 * to implement requirement 1 above, we let each party locally generate a key pair and save each key in a corresponding
 * file. The other party will be able to know the public key by accessing the file. You can create a file called
 * “Transmitted_Data”, which can include all data transmitted between sender and receiver, i.e., encrypted message,
 * encrypted AES key, and the MAC. This file is written by the sender and read by the receiver.
 */

// _______________________Start Script________________________________________

public class Main
{
    public static void main(String[] args) throws Exception
    {
        // Initiates the message to send
        String senderMessage = "Hello, this message is to be encrypted then decrypted!";
        String receiverMessage = null;

        // Creating the sender and receiver objects
        Sender sender = new Sender();
        Receiver receiver = new Receiver();

        // Generating key pairs for both sender and receiver
        sender.generateKeyPair();
        receiver.generateKeyPair();

        // Sets, encrypts, and sends the message
        sender.setMessage(senderMessage);
        sender.encryptMessage();
        sender.sendMessage();

        // Receives, decrypts, and sets received message to variable
        receiver.receiveMessage();
        receiver.decryptMessage();
        receiverMessage = receiver.getMessage();

        // Printing of the sent and received messages
        System.out.println("Message sent: " + senderMessage);
        System.out.println("Message Received: " + receiverMessage);
    }
}

// _______________________End Script________________________________________