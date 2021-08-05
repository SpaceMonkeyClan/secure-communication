/**
 * CS4600 - Secure Communication - HW#3
 * Author: Rene. B Dena
 * Last Modified: 8/5/21
 * File Name: Demo.java
*/

// _______________________Start Script________________________________________

public class Demo
{
    public static void main(String[] args) throws Exception
    {
        // Initiates the message to send
        String senderMessage = "Hello, world!";
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
        System.out.println("Sent message: " + senderMessage);
        System.out.println("Received message: " + receiverMessage);
    }
}

// _______________________End Script________________________________________