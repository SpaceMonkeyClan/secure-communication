 /**
 * CS4600 - Secure Communication - HW#3
 * Author: Rene. B Dena
 * Last Modified: 8/5/21
 * File Name: Receiver.java
 */

 // _______________________Task to complete_________________________________

 /**
  * 1.) The two parties have each other’s RSA public key. Each of them holds his/her own RSA private key.
  * 5.) The receiver should be able to successfully authenticate, decrypt the message, and read the original message.
  */

// _______________________Modules___________________________________________

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.util.*;

// _______________________Start Class________________________________________

public class Receiver
{
    // Task 1 - Create RSA public key and RSA private key
    // Generates RSA key pair and writes the private key to `receiver.private.key` and public key to `receiver.public.key`
    public void generateKeyPair() throws Exception
    {
        // Generates key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048, secureRandom);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        receiverPrivateKey = keyPair.getPrivate();
        receiverPublicKey = keyPair.getPublic();

        // Writes private key of receiver
        FileOutputStream receiverPrivateKeyFile = new FileOutputStream("receiver.private.key");
        receiverPrivateKeyFile.write(Base64.getEncoder().encodeToString(receiverPrivateKey.getEncoded()).getBytes());
        receiverPrivateKeyFile.close();

        // Writes public key of receiver
        FileOutputStream receiverPublicKeyFile = new FileOutputStream("receiver.public.key");
        receiverPublicKeyFile.write(Base64.getEncoder().encodeToString(receiverPublicKey.getEncoded()).getBytes());
        receiverPublicKeyFile.close();
    }

    // Reads the message from `Transmitted_Data`
    public void receiveMessage() throws Exception
    {
        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream("Transmitted_Data")));

        encryptedMessage = br.readLine().getBytes();
        encryptedKey = br.readLine().getBytes();
        macBytes = br.readLine().getBytes();

        br.close();
    }

    // Task 5 - Authenticate, decrypt the message, and read the original message.
    // Decrypts the message to read.
    public void decryptMessage() throws Exception
    {
        // Reads senderPublicKey
        FileInputStream senderPublicKeyFile = new FileInputStream("sender.public.key");
        byte[] senderPublicKeyBytes = new byte[senderPublicKeyFile.available()];
        senderPublicKeyFile.read(senderPublicKeyBytes);
        senderPublicKeyFile.close();
        byte[] decodedSenderPublicKey = Base64.getDecoder().decode(senderPublicKeyBytes);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decodedSenderPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA, "SunRsaSign");
        senderPublicKey = keyFactory.generatePublic(pubKeySpec);

        // Decrypts AES key
        byte[] decodedKey = Base64.getDecoder().decode(encryptedKey);
        Cipher rsaCipher = Cipher.getInstance(RSA);
        rsaCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
        decodedKey = rsaCipher.doFinal(decodedKey);
        SecretKey aesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        // Decrypts the message
        byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);
        Cipher aesCipher = Cipher.getInstance(AES);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        decodedMessage = aesCipher.doFinal(decodedMessage);
        message = new String(decodedMessage);

        // Decrypts MAC
        byte[] decryptedMacBytes = Base64.getDecoder().decode(macBytes);

        // Generating of MAC
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(aesKey);
        macBytes = mac.doFinal(message.getBytes());

        System.out.println("Mac Authentication: " +
                (Arrays.equals(macBytes, decryptedMacBytes) ? "Successful" : "Failed"));
    }

    // Gets the message.
    public String getMessage()
    {
        return message;
    }

    private PrivateKey receiverPrivateKey;
    private PublicKey receiverPublicKey;
    private PublicKey senderPublicKey;
    private String message;
    private byte[] encryptedKey;
    private byte[] encryptedMessage;
    private byte[] macBytes;

    private static SecureRandom secureRandom = new SecureRandom();

    private static final String RSA = "RSA";
    private static final String AES = "AES";
}


// _______________________End Class________________________________________