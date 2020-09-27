import data.Ballot;
import helper.CryptoUtils;
import org.bouncycastle.crypto.Commitment;
import org.bouncycastle.crypto.Committer;
import org.bouncycastle.crypto.commitments.GeneralHashCommitter;
import org.bouncycastle.crypto.digests.SHA256Digest;

import javax.json.*;
import javax.json.stream.JsonGenerator;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class VotingCounter {

    private static final String COUNTER_RESULT_POLL_NOT_FOUND = "COUNTER_RESULT_INVALID_POLL_ID";
    private static final String COUNTER_RESULT_POLL_EXPIRED = "COUNTER_RESULT_POLL_EXPIRED";
    private static final String COUNTER_RESULT_VOTE_NOT_VALID = "COUNTER_RESULT_VOTE_NOT_VALID";
    private static final String COUNTER_RESULT_VOTE_VALID = "COUNTER_RESULT_VOTE_VALID";
    private static final String COUNTER_RESULT_ALREADY_OPEN = "COUNTER_RESULT_ALREADY_OPEN";
    private static final String COUNTER_RESULT_WRONG_BALLOT_ID = "COUNTER_RESULT_WRONG_BALLOT_ID";
    private static final String COUNTER_RESULT_INVALID_SIGNATURE = "COUNTER_RESULT_INVALID_SIGNATURE";

    static final String serverIp = "192.168.0.153";
    static final int authorityPort = 6868;
    private static int saltLength = 32;

    private static RSAPublicKey authorityVerificationKey;

    // <pollId, <ballotId, Ballot>>
    private static HashMap<Integer, HashMap<Integer, Ballot>> bulletinBoard = new HashMap<>();
    // <pollId, <candidate, voteCount>>
    private static HashMap<Integer, HashMap<String, Integer>> validVoteLists = new HashMap<>();
    private static HashMap<Integer, HashMap<String, Integer>> tally = new HashMap<>();
    // <pollId, <ballotId>>
    private static HashMap<Integer, HashSet<Integer>> alreadyOpenedLists;
    // <pollId, expireTime>
    private static HashMap<Integer, Long> pollExpirations = new HashMap<>();
    private static HashSet<Integer> ballotIds;

    private static final SecureRandom random = new SecureRandom();

    public void start() {
        loadVerificationKey();
        readBallotsFile();
        readValidVotesFile();
        readAlreadyOpenedFile();

        long lastTime = Calendar.getInstance().getTimeInMillis();

        try (ServerSocket serverSocket = new ServerSocket(6869)) {
            serverSocket.setSoTimeout(60 * 1000);

            while (true) {
                // Tally polls every 55 seconds
                long currentTime = Calendar.getInstance().getTimeInMillis();
                if ((currentTime - lastTime) / 1000L > 55L) {
                    fetchPollsFromAuthority();
                    tallyPolls();
                    lastTime = currentTime;
                }

                System.out.println("Waiting for client to connect...");
                Socket client = null;
                try {
                    client = serverSocket.accept();
                } catch (SocketTimeoutException e) {
                    System.out.println("Socket accept timed out after 1 minute.");
                    continue;
                }
                System.out.println("Client connected");

                ClientHandler clientHandler = new ClientHandler(client);
                new Thread(clientHandler).start();
            }
        } catch (IOException e) {
            System.err.println("Failed opening socket.");
            e.printStackTrace();
        }
    }

    private void loadVerificationKey() {
        final File keyFile = new File(System.getProperty("user.dir") + "/authority_public.pem");

        StringBuilder pemBuilder = new StringBuilder();
        try (FileReader fr = new FileReader(keyFile);
             BufferedReader br = new BufferedReader(fr)) {
            String line;
            while((line = br.readLine()) != null) {
                pemBuilder.append(line);
            }
        } catch (IOException e) {
            System.err.println("Failed reading verification key file.");
            e.printStackTrace();
        }

        String pem = pemBuilder.toString();
        authorityVerificationKey = (RSAPublicKey) CryptoUtils.createRSAKeyFromString(pem);
    }

    private class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private String resultForClient;

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        @Override
        public void run() {
            InputStreamReader isr;
            BufferedReader in;
            try {
                isr = new InputStreamReader(clientSocket.getInputStream());
                in = new BufferedReader(isr);
                System.out.println("Waiting for data...");

                String command = in.readLine();
                if (command.equals("open ballot")) {
                    String pollIdString = in.readLine();
                    String ballotIdString = in.readLine();
                    String vote = in.readLine();
                    String commitmentSecretString = in.readLine();

                    System.out.println("Poll ID: " + pollIdString);
                    System.out.println("Ballot ID: " + ballotIdString);
                    System.out.println("Vote: " + vote);
                    System.out.println("Commitment secret: " + commitmentSecretString);

                    Integer pollId = Integer.parseInt(pollIdString);
                    Integer ballotId = Integer.parseInt(ballotIdString);
                    byte[] commitmentSecret = Base64.getDecoder().decode(commitmentSecretString);

                    openBallot(pollId, ballotId, vote, commitmentSecret);
                    sendResultToClient();
                } else if (command.equals("cast vote")) {
                    String pollIdString = in.readLine();
                    String commitmentString = in.readLine();
                    String signatureString = in.readLine();

                    System.out.println("Poll ID: " + pollIdString);
                    System.out.println("Commitment: " + commitmentString);
                    System.out.println("Signature: " + signatureString);

                    Integer pollId = Integer.parseInt(pollIdString);
                    byte[] commitment = Base64.getDecoder().decode(commitmentString);
                    byte[] signature = Base64.getDecoder().decode(signatureString);

                    castVote(pollId, commitment, signature);
                    writeBallotsFile();
                }
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
        }

        private void castVote(Integer pollId, byte[] commitment, byte[] signature) {
            // Check if poll has a record
            long currentTime = Calendar.getInstance().getTimeInMillis();
            if (!pollExpirations.containsKey(pollId)) {
                // Try to fetch polls for 30 seconds
                long startTime = currentTime;
                while (!fetchPollsFromAuthority() && (currentTime - startTime) / 1000L < 30L) {
                    currentTime = Calendar.getInstance().getTimeInMillis();
                }

                if (!pollExpirations.containsKey(pollId)) {
                    System.out.println("No poll found with the given poll ID.");
                    resultForClient = COUNTER_RESULT_POLL_NOT_FOUND;
                    sendResultToClient();
                    return;
                }
            }

            // Check if poll is expired
            long expirationTime = pollExpirations.get(pollId);
            if (expirationTime < currentTime) {
                System.out.println("Poll is expired.");
                resultForClient = COUNTER_RESULT_POLL_EXPIRED;
                sendResultToClient();
                return;
            }

            // Verify authority's signature
            if (!CryptoUtils.verifySHA256withRSAandPSS(authorityVerificationKey, commitment, signature, saltLength)) {
                System.out.println("Authority's signature on commitment NOT valid.");
                resultForClient = COUNTER_RESULT_INVALID_SIGNATURE;
                sendResultToClient();
                return;
            }
            System.out.println("Authority's signature on commitment valid.");

            // Generate new ballotId
            Integer ballotId = random.nextInt(Integer.MAX_VALUE);
            while (ballotIds.contains(ballotId)) {
                ballotId = random.nextInt(Integer.MAX_VALUE);
            }

            // Put ballot on the bulletin board of the poll
            HashMap<Integer, Ballot> ballots;
            if (bulletinBoard.containsKey(pollId)) {
                ballots = bulletinBoard.get(pollId);
            } else {
                ballots = new HashMap<>();
                bulletinBoard.put(pollId, ballots);
            }
            Ballot ballot = new Ballot(ballotId, commitment, signature);
            ballots.put(ballotId, ballot);
            System.out.println("Ballot saved with ID: " + ballotId);

            PrintWriter out;
            try {
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                System.out.println("Sending identifier to client...");
                out.println(ballotId.toString());
                System.out.println("Identifier sent");
            } catch (IOException e) {
                ballots.remove(ballotId);
                System.err.println("Failed sending data to client.");
                e.printStackTrace();
            } finally {
                try {
                    clientSocket.shutdownOutput();
                } catch (IOException e) {
                    System.err.println("Problem while shutting down output stream.");
                    e.printStackTrace();
                }
            }
        }

        private void openBallot(Integer pollId, Integer ballotId, String vote, byte[] commitmentSecret) {
            // Check if poll exists
            if (!bulletinBoard.containsKey(pollId)) {
                System.out.println("Given poll doesn't exist.");
                return;
            }

            // Check if ballot exists
            if (!bulletinBoard.get(pollId).containsKey(ballotId)) {
                resultForClient = COUNTER_RESULT_WRONG_BALLOT_ID;
                System.out.println("Ballot to open doesn't exist.");
                return;
            }

            Ballot ballot = bulletinBoard.get(pollId).get(ballotId);

            // Check if ballot has already been opened
            if (alreadyOpenedLists.containsKey(pollId)) {
                HashSet<Integer> alreadyOpenedList = alreadyOpenedLists.get(pollId);
                if (alreadyOpenedList.contains(ballotId)) {
                    resultForClient = COUNTER_RESULT_ALREADY_OPEN;
                    System.out.println("Ballot has already been opened.");
                    return;
                }
            }

            // Open commitment and check if valid
            Committer committer = new GeneralHashCommitter(new SHA256Digest(), new SecureRandom());
            byte[] voteBytes = vote.getBytes(StandardCharsets.UTF_8);
            Commitment commitment = new Commitment(commitmentSecret, ballot.getCommitment());

            boolean isValid;
            try {
                isValid = committer.isRevealed(commitment, voteBytes);
            } catch (Exception e) {
                resultForClient = COUNTER_RESULT_VOTE_NOT_VALID;
                System.out.println("Failed checking validity with the given inputs.");
                return;
            }

            if (isValid) {
                HashMap<String, Integer> validVoteList;
                HashSet<Integer> alreadyOpenedList;
                Integer voteCount = 0;
                if (validVoteLists.containsKey(pollId)) {
                    validVoteList = validVoteLists.get(pollId);
                    alreadyOpenedList = alreadyOpenedLists.get(pollId);
                    if (validVoteList.containsKey(vote)) {
                        voteCount = validVoteList.get(vote);
                    }
                } else {
                    validVoteList = new HashMap<>();
                    validVoteLists.put(pollId, validVoteList);
                    alreadyOpenedList = new HashSet<>();
                    alreadyOpenedLists.put(pollId, alreadyOpenedList);
                }

                voteCount++;
                validVoteList.put(vote, voteCount);
                alreadyOpenedList.add(ballotId);

                writeValidVotesFile();
                writeAlreadyOpenedFile();
                resultForClient = COUNTER_RESULT_VOTE_VALID;
                System.out.println("Vote was valid.");
                return;
            }
            resultForClient = COUNTER_RESULT_VOTE_NOT_VALID;
            System.out.println("Vote was NOT invalid.");
        }

        private void sendResultToClient() {
            PrintWriter out;
            try {
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                System.out.println("Sending to client...");
                out.println(resultForClient);
                System.out.println("Data sent");
            } catch (IOException e) {
                System.err.println("Failed sending data to client.");
                e.printStackTrace();
            } finally {
                try {
                    clientSocket.shutdownOutput();
                } catch (IOException e) {
                    System.err.println("Problem while shutting down output stream.");
                    e.printStackTrace();
                }
            }
        }
    }

    private Boolean fetchPollsFromAuthority() {
        // while(!isCancelled())
        System.out.println("Connecting to authority...");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(serverIp, authorityPort), 10 * 1000);
            System.out.println("Connected successfully");

            PrintWriter out;
            try {
                out = new PrintWriter(socket.getOutputStream(), true);
                System.out.println("Fetching polls...");
                out.println("fetch polls");
                System.out.println("Request sent");
            } catch (IOException e) {
                System.err.println("Failed sending fetch request to authority.");
                e.printStackTrace();
            } finally {
                socket.shutdownOutput();
            }

            try (InputStreamReader isr = new InputStreamReader(socket.getInputStream());
                 BufferedReader in = new BufferedReader(isr)) {
                System.out.println("Waiting for polls...");
                String answer = in.readLine();
                if (answer.equals("no polls")) {
                    System.out.println("No polls received.");
                    return false;
                }
                if (answer.equals("sending polls")) {
                    pollExpirations = new HashMap<>();
                    String pollId;
                    while ((pollId = in.readLine()) != null) {
                        in.readLine();
                        Long expireTime = Long.parseLong(in.readLine());
                        in.readLine();

                        pollExpirations.put(Integer.parseInt(pollId), expireTime);
                    }
                    System.out.println("Received polls");
                }
            } catch (IOException e) {
                System.err.println("Failed receiving polls from authority.");
                e.printStackTrace();
            }
        } catch (IOException e) {
            System.err.println("Failed connecting to the authority with the given IP address and port.");
        }
        return true;
    }

    // Reads 'ballots' file, then builds 'ballotIds' and 'bulletinBoard'
    private void readBallotsFile() {
        ballotIds = new HashSet<>();
        bulletinBoard = new HashMap<Integer, HashMap<Integer, Ballot>>();

        File ballotsFile = new File(System.getProperty("user.dir") + "/ballots.json");
        if (!ballotsFile.exists()) {
            System.out.println("Ballots file doesn't exist.");
            return;
        }

        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonReaderFactory jrf = Json.createReaderFactory(properties);

        JsonArray pollArray = null;
        try (FileInputStream fis = new FileInputStream(ballotsFile);
             InputStreamReader isr = new InputStreamReader(fis);
             JsonReader jsonReader = jrf.createReader(isr)) {

            pollArray = jsonReader.readArray();

        } catch (FileNotFoundException e) {
            System.err.println("Couldn't find file: " + ballotsFile.getPath());
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't read ballots file.");
            e.printStackTrace();
        }

        if (pollArray == null) {
            System.out.println("Ballots file was empty.");
            return;
        }

        for (JsonValue pollValue : pollArray) {
            JsonObject pollObject = pollValue.asJsonObject();

            Integer pollId = pollObject.getInt("poll id");
            JsonArray ballotArray = pollObject.getJsonArray("ballots");

            HashMap<Integer, Ballot> ballots = new HashMap<>();
            for (JsonValue ballotValue : ballotArray) {
                JsonObject ballotObject = ballotValue.asJsonObject();

                Integer ballotId = ballotObject.getInt("ballot id");
                String commitmentString = ballotObject.getString("commitment");
                String signatureString = ballotObject.getString("signature");

                byte[] commitment = Base64.getDecoder().decode(commitmentString);
                byte[] signature = Base64.getDecoder().decode(signatureString);

                Ballot ballot = new Ballot(ballotId, commitment, signature);
                ballots.put(ballotId, ballot);
                ballotIds.add(ballotId);
            }
            bulletinBoard.put(pollId, ballots);
        }
        System.out.println("Reading ballots file completed successfully.");
    }

    // Reads 'valid_votes' file, then builds 'validVoteLists'
    private void readValidVotesFile() {
        validVoteLists = new HashMap<Integer, HashMap<String, Integer>>();

        File validVotesFile = new File(System.getProperty("user.dir") + "/valid_votes.json");
        if (!validVotesFile.exists()) {
            System.out.println("Valid votes file doesn't exist.");
            return;
        }

        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonReaderFactory jrf = Json.createReaderFactory(properties);

        JsonArray pollArray = null;
        try (FileInputStream fis = new FileInputStream(validVotesFile);
             InputStreamReader isr = new InputStreamReader(fis);
             JsonReader jsonReader = jrf.createReader(isr)) {

            pollArray = jsonReader.readArray();

        } catch (FileNotFoundException e) {
            System.err.println("Couldn't find file: " + validVotesFile.getPath());
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't read valid votes file.");
            e.printStackTrace();
        }

        if (pollArray == null) {
            System.out.println("Valid votes file was empty.");
            return;
        }

        for (JsonValue pollValue : pollArray) {
            JsonObject pollObject = pollValue.asJsonObject();

            Integer pollId = pollObject.getInt("poll id");
            JsonArray votesArray = pollObject.getJsonArray("votes");

            HashMap<String, Integer> votes = new HashMap<>();
            for (JsonValue voteValue : votesArray) {
                JsonObject voteObject = voteValue.asJsonObject();

                String vote = voteObject.getString("vote");
                Integer voteCount = voteObject.getInt("count");

                votes.put(vote, voteCount);
            }
            validVoteLists.put(pollId, votes);
        }
        System.out.println("Reading valid votes file completed successfully.");
    }

    // Reads 'already_opened' file, then build 'alreadyOpenedLists'
    private void readAlreadyOpenedFile() {
        alreadyOpenedLists = new HashMap<Integer, HashSet<Integer>>();

        File alreadyOpenedFile = new File(System.getProperty("user.dir") + "/already_opened.json");
        if (!alreadyOpenedFile.exists()) {
            System.out.println("'Already opened' file doesn't exist.");
            return;
        }

        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonReaderFactory jrf = Json.createReaderFactory(properties);

        JsonArray pollArray = null;
        try (FileInputStream fis = new FileInputStream(alreadyOpenedFile);
             InputStreamReader isr = new InputStreamReader(fis);
             JsonReader jsonReader = jrf.createReader(isr)) {

            pollArray = jsonReader.readArray();

        } catch (FileNotFoundException e) {
            System.err.println("Couldn't find file: " + alreadyOpenedFile.getPath());
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't read 'already opened' file.");
            e.printStackTrace();
        }

        if (pollArray == null) {
            System.out.println("'Already opened' file was empty.");
            return;
        }

        for (JsonValue pollValue : pollArray) {
            JsonObject pollObject = pollValue.asJsonObject();

            Integer pollId = pollObject.getInt("poll id");

            JsonArray ballotArray = pollObject.getJsonArray("ballots");
            HashSet<Integer> ballots = new HashSet<>();
            for (JsonValue ballotValue : ballotArray) {
                JsonObject ballotObject = ballotValue.asJsonObject();
                Integer ballotId = ballotObject.getInt("ballot id");
                ballots.add(ballotId);
            }
            alreadyOpenedLists.put(pollId, ballots);
        }
        System.out.println("Reading 'already opened' file completed successfully.");
    }

    private void writeBallotsFile() {
        JsonArrayBuilder pollArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder pollBuilder = Json.createObjectBuilder();
        JsonArrayBuilder ballotArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder ballotBuilder = Json.createObjectBuilder();

        for (Map.Entry<Integer, HashMap<Integer, Ballot>> pollEntry : bulletinBoard.entrySet()) {
            pollBuilder.add("poll id", pollEntry.getKey());
            for (Map.Entry<Integer, Ballot> ballotEntry : pollEntry.getValue().entrySet()) {
                ballotBuilder.add("ballot id", ballotEntry.getKey());

                Ballot ballot = ballotEntry.getValue();
                String commitmentString = Base64.getEncoder().encodeToString(ballot.getCommitment());
                String signatureString = Base64.getEncoder().encodeToString(ballot.getSignature());

                ballotBuilder.add("commitment", commitmentString);
                ballotBuilder.add("signature", signatureString);
                ballotArrayBuilder.add(ballotBuilder);

            }
            pollBuilder.add("ballots", ballotArrayBuilder);
            pollArrayBuilder.add(pollBuilder);
        }

        JsonArray pollArray = pollArrayBuilder.build();

        File ballotsFile = new File(System.getProperty("user.dir") + "/ballots.json");

        // Format JSON to readable form instead of one line
        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonWriterFactory jwf = Json.createWriterFactory(properties);

        try (FileOutputStream fos = new FileOutputStream(ballotsFile);
             OutputStreamWriter osw = new OutputStreamWriter(fos);
             JsonWriter jsonWriter = jwf.createWriter(osw)) {

            jsonWriter.writeArray(pollArray);

        } catch (FileNotFoundException e) {
            System.err.println("Ballots file not found.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't write ballots file.");
            e.printStackTrace();
        }
        System.out.println("Writing ballots file completed successfully.");
    }

    private void writeValidVotesFile() {
        JsonArrayBuilder pollArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder pollBuilder = Json.createObjectBuilder();
        JsonArrayBuilder voteArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder voteBuilder = Json.createObjectBuilder();

        for (Map.Entry<Integer, HashMap<String, Integer>> pollEntry : validVoteLists.entrySet()) {
            pollBuilder.add("poll id", pollEntry.getKey());
            for (Map.Entry<String, Integer> voteEntry : pollEntry.getValue().entrySet()) {
                voteBuilder.add("vote", voteEntry.getKey());
                voteBuilder.add("count", voteEntry.getValue());
                voteArrayBuilder.add(voteBuilder);
            }
            pollBuilder.add("votes", voteArrayBuilder);
            pollArrayBuilder.add(pollBuilder);
        }

        JsonArray pollArray = pollArrayBuilder.build();

        File validVotesFile = new File(System.getProperty("user.dir") + "/valid_votes.json");

        // Format JSON to readable form instead of one line
        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonWriterFactory jwf = Json.createWriterFactory(properties);

        try (FileOutputStream fos = new FileOutputStream(validVotesFile);
             OutputStreamWriter osw = new OutputStreamWriter(fos);
             JsonWriter jsonWriter = jwf.createWriter(osw)) {

            jsonWriter.writeArray(pollArray);

        } catch (FileNotFoundException e) {
            System.err.println("Valid votes file not found.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't write valid votes file.");
            e.printStackTrace();
        }
        System.out.println("Writing valid votes file completed successfully.");
    }

    private void writeAlreadyOpenedFile() {
        JsonArrayBuilder pollArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder pollBuilder = Json.createObjectBuilder();
        JsonArrayBuilder ballotArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder ballotBuilder = Json.createObjectBuilder();

        for (Map.Entry<Integer, HashSet<Integer>> pollEntry : alreadyOpenedLists.entrySet()) {
            pollBuilder.add("poll id", pollEntry.getKey());
            for (Integer ballotId : pollEntry.getValue()) {
                ballotBuilder.add("ballot id", ballotId);
                ballotArrayBuilder.add(ballotBuilder);
            }
            pollBuilder.add("ballots", ballotArrayBuilder);
            pollArrayBuilder.add(pollBuilder);
        }

        JsonArray pollArray = pollArrayBuilder.build();

        File alreadyOpenedFile = new File(System.getProperty("user.dir") + "/already_opened.json");

        // Format JSON to readable form instead of one line
        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonWriterFactory jwf = Json.createWriterFactory(properties);

        try (FileOutputStream fos = new FileOutputStream(alreadyOpenedFile);
             OutputStreamWriter osw = new OutputStreamWriter(fos);
             JsonWriter jsonWriter = jwf.createWriter(osw)) {

            jsonWriter.writeArray(pollArray);

        } catch (FileNotFoundException e) {
            System.err.println("'Already opened' file not found.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't write 'already opened' file.");
            e.printStackTrace();
        }
        System.out.println("Writing 'already opened' file completed successfully.");
    }

    private void writeTallyFile() {
        JsonArrayBuilder pollArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder pollBuilder = Json.createObjectBuilder();
        JsonArrayBuilder voteArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder voteBuilder = Json.createObjectBuilder();

        for (Map.Entry<Integer, HashMap<String, Integer>> pollEntry : tally.entrySet()) {
            pollBuilder.add("poll id", pollEntry.getKey());
            for (Map.Entry<String, Integer> voteEntry : pollEntry.getValue().entrySet()) {
                voteBuilder.add("vote", voteEntry.getKey());
                voteBuilder.add("count", voteEntry.getValue());
                voteArrayBuilder.add(voteBuilder);

            }
            pollBuilder.add("votes", voteArrayBuilder);
            pollArrayBuilder.add(pollBuilder);
        }

        JsonArray pollArray = pollArrayBuilder.build();

        File tallyFile = new File(System.getProperty("user.dir") + "/tally.json");

        // Format JSON to readable form instead of one line
        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonWriterFactory jwf = Json.createWriterFactory(properties);

        try (FileOutputStream fos = new FileOutputStream(tallyFile);
             OutputStreamWriter osw = new OutputStreamWriter(fos);
             JsonWriter jsonWriter = jwf.createWriter(osw)) {

            jsonWriter.writeArray(pollArray);

        } catch (FileNotFoundException e) {
            System.err.println("Tally file not found.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't write tally file.");
            e.printStackTrace();
        }
        System.out.println("Writing tally file completed successfully.");
    }

    // Writes results of polls that have been expired for 2 minutes to a file
    private void tallyPolls() {
        tally = new HashMap<Integer, HashMap<String, Integer>>();

        if(pollExpirations.isEmpty()){
            System.out.println("No expiration record found.");
            return;
        }

        long currentTime = Calendar.getInstance().getTimeInMillis();
        for (Map.Entry<Integer, Long> expiration : pollExpirations.entrySet()) {
            if (expiration.getValue() + 120L * 1000L < currentTime) {
                Integer pollId = expiration.getKey();
                if (validVoteLists.containsKey(pollId)) {
                    tally.put(pollId, validVoteLists.get(pollId));
                }
            }
        }

        writeTallyFile();
    }
}
