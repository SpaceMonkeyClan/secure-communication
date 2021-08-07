 /**
 * CS4600 - Secure Communication - HW#3
 * Author: Rene. B Dena
 * Last Modified: 8/5/21
 * File Name: Sender.java
 */

 // _______________________Task to complete_________________________________

 /**
  * 1.) The two parties have each other’s RSA public key. Each of them holds his/her own RSA private key.
  * 2.) Each party’s message (from a .txt file) is encrypted using AES before sending it to another party.
  * 3.) The AES key used in 2) is encrypted using the receiver’s RSA public key. The encrypted AES key is sent together
  *     with the encrypted message obtained from 2).
  * 4.) Message authentication code should be appended to data transmitted. You are free to choose the specific protocol
  *     of MAC.
  */

// _______________________Modules___________________________________________

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;

// _______________________Start Class________________________________________

public class Sender
{
    // Task 1 - Create RSA public key and RSA private key
    // Generates RSA key pair and writes the private key to `sender.private.key` and public key to `sender.public.key`
    public void generateKeyPair() throws Exception
    {
        // Generates key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048, secureRandom);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey senderPrivateKey = keyPair.getPrivate();
        PublicKey senderPublicKey = keyPair.getPublic();

        // Writes private key of sender
        FileOutputStream senderPrivateKeyFile = new FileOutputStream("sender.private.key");
        senderPrivateKeyFile.write(Base64.getEncoder().encodeToString(senderPrivateKey.getEncoded()).getBytes());
        senderPrivateKeyFile.close();

        // Writes public key of sender
        FileOutputStream senderPublicKeyFile = new FileOutputStream("sender.public.key");
        senderPublicKeyFile.write(Base64.getEncoder().encodeToString(senderPublicKey.getEncoded()).getBytes());
        senderPublicKeyFile.close();
    }

    // Grabs the message to send.
    public void setMessage(String message)
    {
        this.message = message;
    }

    // Task 2 - Encrypt using AES
    // Encrypts the message to send.
    public void encryptMessage() throws Exception
    {
        // Reads `receiverPublicKey`
        FileInputStream receiverPublicKeyFile = new FileInputStream("receiver.public.key");
        byte[] receiverPublicKeyBytes = new byte[receiverPublicKeyFile.available()];
        receiverPublicKeyFile.read(receiverPublicKeyBytes);
        receiverPublicKeyFile.close();
        byte[] decodedReceiverPublicKey = Base64.getDecoder().decode(receiverPublicKeyBytes);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decodedReceiverPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
        receiverPublicKey = keyFactory.generatePublic(pubKeySpec);

        // Generates AES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(secureRandom);
        SecretKey aesKey = keyGenerator.generateKey();

        // Encrypts the message
        Cipher aesCipher = Cipher.getInstance(AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        encryptedMessage = aesCipher.doFinal(message.getBytes());

        // Task 3 - AES key encrypted using the `receiverPublicKey` The encrypted AES key is sent together with the encrypted message obtained from 2).
        // Encrypts the key
        Cipher rsaCipher = Cipher.getInstance(RSA);
        rsaCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Generating of MAC
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(aesKey);
        macBytes = mac.doFinal(message.getBytes());
    }

    // Task 3 - Encrypted AES key is sent with the encrypted message
    // Task 4 - Message authentication appended to Transmitted_Data
    // Writes the message to `Transmitted_Data`.
    public void sendMessage() throws Exception
    {
        FileOutputStream transmittedDataFile = new FileOutputStream("Transmitted_Data");

        // Message
        transmittedDataFile.write(Base64.getEncoder().encodeToString(encryptedMessage).getBytes());
        transmittedDataFile.write('\n');

        // Key
        transmittedDataFile.write(Base64.getEncoder().encodeToString(encryptedKey).getBytes());
        transmittedDataFile.write('\n');

        // Mac
        transmittedDataFile.write(Base64.getEncoder().encodeToString(macBytes).getBytes());
        transmittedDataFile.write('\n');

        transmittedDataFile.close();
    }

    private PrivateKey senderPrivateKey;
    private PublicKey senderPublicKey;
    private PublicKey receiverPublicKey;
    private String message;
    private byte[] encryptedKey;
    private byte[] encryptedMessage;
    private byte[] macBytes;

    private static SecureRandom secureRandom = new SecureRandom();

    private static final String RSA = "RSA";
    private static final String AES = "AES";
}

// _______________________End Class________________________________________