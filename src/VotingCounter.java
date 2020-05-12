import helper.CryptoUtils;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;

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
        authorityPublicBlindingKey = (RSAPublicKey) CryptoUtils.createRSAKeyFromString(authorityPublicBlindingKeyString);
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

            Integer pollId = Integer.parseInt(line.substring(0, 7));
            String commitmentString = line.substring(7, 51);
            String signatureString = line.substring(51);
            System.out.println("Commitment: " + commitmentString);
            System.out.println("Signature: " + signatureString);

            byte[] commitment = Base64.getDecoder().decode(commitmentString);
            byte[] signature = Base64.getDecoder().decode(signatureString);

            if(!CryptoUtils.verifySHA256withRSAandPSS(authorityPublicBlindingKey, commitment, signature, saltLength)) {
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
}
