import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;

public class Sender
{
    /**
     * Generates RSA key pair and writes
     * the private key to sender.private.key
     * and public key to sender.public.key.
     */
    public void generateKeyPair() throws Exception
    {
        // generating key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048, secureRandom);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey senderPrivateKey = keyPair.getPrivate();
        PublicKey senderPublicKey = keyPair.getPublic();

        // writing private key of sender
        FileOutputStream senderPrivateKeyFile = new FileOutputStream("sender.private.key");
        senderPrivateKeyFile.write(Base64.getEncoder().encodeToString(senderPrivateKey.getEncoded()).getBytes());
        senderPrivateKeyFile.close();

        // writing public key of sender
        FileOutputStream senderPublicKeyFile = new FileOutputStream("sender.public.key");
        senderPublicKeyFile.write(Base64.getEncoder().encodeToString(senderPublicKey.getEncoded()).getBytes());
        senderPublicKeyFile.close();
    }

    /**
     * Sets the message to send.
     * @param   message     The message to send.
     */
    public void setMessage(String message)
    {
        this.message = message;
    }

    /**
     * Encrypts the message to send.
     */
    public void encryptMessage() throws Exception
    {
        // reading receiverPublicKey
        FileInputStream receiverPublicKeyFile = new FileInputStream("receiver.public.key");
        byte[] receiverPublicKeyBytes = new byte[receiverPublicKeyFile.available()];
        receiverPublicKeyFile.read(receiverPublicKeyBytes);
        receiverPublicKeyFile.close();
        byte[] decodedReceiverPublicKey = Base64.getDecoder().decode(receiverPublicKeyBytes);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decodedReceiverPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
        receiverPublicKey = keyFactory.generatePublic(pubKeySpec);

        // generating AES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(secureRandom);
        SecretKey aesKey = keyGenerator.generateKey();

        // encrypting the message
        Cipher aesCipher = Cipher.getInstance(AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        encryptedMessage = aesCipher.doFinal(message.getBytes());

        // encrypting the key
        Cipher rsaCipher = Cipher.getInstance(RSA);
        rsaCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Mac
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(aesKey);
        macBytes = mac.doFinal(message.getBytes());
    }

    /**
     * Writes the message to Transmitted_Data.
     */
    public void sendMessage() throws Exception
    {
        FileOutputStream transmittedDataFile = new FileOutputStream("Transmitted_Data");

        // message
        transmittedDataFile.write(Base64.getEncoder().encodeToString(encryptedMessage).getBytes());
        transmittedDataFile.write('\n');

        // key
        transmittedDataFile.write(Base64.getEncoder().encodeToString(encryptedKey).getBytes());
        transmittedDataFile.write('\n');

        // mac
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