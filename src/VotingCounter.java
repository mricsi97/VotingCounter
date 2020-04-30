import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class VotingCounter {

    private static int saltLength = 20;

    private static RSAPublicKey authorityPublicBlindingKey;
    private static final String authorityPublicBlindingKeyString =
            "-----BEGIN PUBLIC KEY-----\n" +
                    "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgF8hrv+1z1yMJA6UFZ5J/uFQ+Xp9\n" +
                    "hq/iT4ibZz2a7JpZf7VO3jJaQsiMowubOvpm70rmBUTPZdP9U7uHaRXPcL++oNIX\n" +
                    "pG/5Nfv1sUSIA97pfAJiUjqSVNX/VVud4wxs+F6Rn1a6QEf3NukDF8Yc9BPRJF5o\n" +
                    "Nmf8GXzGZp1AgGgdAgMBAAE=\n" +
                    "-----END PUBLIC KEY-----";

    private static HashMap<Integer, String> votes = new HashMap<Integer, String>();
    private static Integer idCounter = 0;

    public void start(){
        createKeyObjectsFromStrings();

        try (ServerSocket serverSocket = new ServerSocket(6869)){
            while(true){
                System.out.println("Waiting for client to connect...");
                Socket client = serverSocket.accept();
                System.out.println("Client connected");
                ClientHandler clientHandler = new ClientHandler(client);
                new Thread(clientHandler).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void createKeyObjectsFromStrings() {
        // Authority public key
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader reader = new BufferedReader(new StringReader(authorityPublicBlindingKeyString));
        String line;
        while (true){
            try {
                if ((line = reader.readLine()) == null) break;
                pkcs8Lines.append(line);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PUBLIC KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PUBLIC KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");

        byte[] authorityLongTermPublicKeyBytes = Base64.getDecoder().decode(pkcs8Pem);
        KeySpec keySpec = new X509EncodedKeySpec(authorityLongTermPublicKeyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            authorityPublicBlindingKey = (RSAPublicKey) kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private static class ClientHandler implements Runnable {
        private final Socket clientSocket;

        public ClientHandler(Socket socket) {this.clientSocket = socket;}

        @Override
        public void run() {
            String line = null;
            InputStreamReader isr = null;
            BufferedReader in = null;
            try {
                isr = new InputStreamReader(clientSocket.getInputStream());
                in = new BufferedReader(isr);
                System.out.println("Waiting for data...");
                line = in.readLine();
                System.out.println("Received data");
            } catch (IOException e) {
                System.err.println("Failed receiving data from client.");
                e.printStackTrace();
            } finally {
                try {
                    clientSocket.shutdownInput();
                } catch (IOException e) {
                    System.err.println("Problem while shutting down input stream.");
                    e.printStackTrace();
                }
            }

            if(line == null){
                System.out.println("Invalid data received");
                return;
            }

            String commitmentString = line.substring(0, 44);
            String signatureString = line.substring(44);
            System.out.println("Commitment: " + commitmentString);
            System.out.println("Signature: " + signatureString);

            byte[] commitment = Base64.getDecoder().decode(commitmentString);
            byte[] signature = Base64.getDecoder().decode(signatureString);

            if(!verifySHA256withRSAandPSS(authorityPublicBlindingKey, commitment, signature)) {
                System.out.println("Authority's signature on commitment NOT valid.");
                return;
            }
            System.out.println("Authority's signature on commitment valid.");

            votes.put(idCounter, commitmentString + signatureString);


            try ( OutputStreamWriter osw = new OutputStreamWriter(clientSocket.getOutputStream());
                  PrintWriter out = new PrintWriter(osw) ) {
                System.out.println("Sending identifier to client...");
                out.println(idCounter.toString());
                System.out.println("Identifier sent");
                idCounter++;
            } catch (IOException e) {
                votes.remove(idCounter);
                System.err.println("Failed sending data to client.");
                e.printStackTrace();
            }
        }
    }

    private static Boolean verifySHA256withRSAandPSS(RSAPublicKey verificationKey, byte[] message, byte[] signature){
        RSAKeyParameters keyParameters = new RSAKeyParameters(false, verificationKey.getModulus(), verificationKey.getPublicExponent());

        PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), saltLength);
        signer.init(false, keyParameters);
        signer.update(message, 0, message.length);

        return signer.verifySignature(signature);
    }
}
