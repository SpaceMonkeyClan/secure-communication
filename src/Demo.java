public class Demo
{
    public static void main(String[] args) throws Exception
    {
        // messages
        String senderMessage = "Hello, world!";
        String receiverMessage = null;

        // creating the sender and
        // receiver objects
        Sender sender = new Sender();
        Receiver receiver = new Receiver();

        // generating keypairs
        // for both sender and
        // receiver
        sender.generateKeyPair();
        receiver.generateKeyPair();

        // sending the message
        sender.setMessage(senderMessage);
        sender.encryptMessage();
        sender.sendMessage();

        // receiving the message
        receiver.receiveMessage();
        receiver.decryptMessage();
        receiverMessage = receiver.getMessage();

        // printing the messages
        System.out.println("Sent message: " + senderMessage);
        System.out.println("Received message: " + receiverMessage);
    }
}
