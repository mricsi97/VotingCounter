import data.Ballot;
import helper.CryptoUtils;

import javax.json.*;
import javax.json.stream.JsonGenerator;
import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class VotingCounter {

    private static final String COUNTER_RESULT_POLL_NOT_FOUND = "COUNTER_RESULT_INVALID_POLL_ID";
    private static final String COUNTER_RESULT_POLL_EXPIRED = "COUNTER_RESULT_POLL_EXPIRED";
    private static final String COUNTER_RESULT_VOTE_NOT_VALID = "COUNTER_RESULT_VOTE_NOT_VALID";
    private static final String COUNTER_RESULT_VOTE_VALID = "COUNTER_RESULT_VOTE_VALID";
    private static final String COUNTER_RESULT_ALREADY_OPEN = "COUNTER_RESULT_ALREADY_OPEN";
    private static final String COUNTER_RESULT_WRONG_BALLOT_ID = "COUNTER_RESULT_WRONG_BALLOT_ID";
    private static final String COUNTER_RESULT_INVALID_SIGNATURE = "COUNTER_RESULT_INVALID_SIGNATURE";

    static final String serverIp = "192.168.0.101";
    static final int authorityPort = 6868;

    private static RSAPublicKey authorityVerificationKey;

    // <pollId, <ballotId, Ballot>>
    private static final ConcurrentHashMap<Integer, ConcurrentHashMap<Integer, Ballot>> bulletinBoard = new ConcurrentHashMap<>();
    // <pollId, <candidate, voteCount>>
    private static final ConcurrentHashMap<Integer, ConcurrentHashMap<String, Integer>> validVoteLists = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Integer, ConcurrentHashMap<String, Integer>> tally = new ConcurrentHashMap<>();
    // <pollId, <ballotId>>
    private static final ConcurrentHashMap<Integer, Set<Integer>> alreadyOpenedLists = new ConcurrentHashMap<>();
    // <pollId, expireTime>
    private static final ConcurrentHashMap<Integer, Long> pollExpirations = new ConcurrentHashMap<>();
    private static final Set<Integer> ballotIds = Collections.synchronizedSet(new HashSet<>());

    private static final SecureRandom random = new SecureRandom();

    public void start() {
        loadVerificationKey();
        readBallotsFile();
        readValidVotesFile();
        readAlreadyOpenedFile();

        long lastTime = System.currentTimeMillis();

        try (ServerSocket serverSocket = new ServerSocket(6869)) {
            serverSocket.setSoTimeout(60 * 1000);

            while (true) {
                // Every 5 minutes save data to disk
                long currentTime = System.currentTimeMillis();
                long deltaTime = (currentTime - lastTime) / 1000L;
                if (deltaTime > 60L * 5) {
                    fetchPollsFromAuthority();
                    tallyPolls();
                    writeTallyFile();
                    writeBallotsFile();
                    writeValidVotesFile();
                    writeAlreadyOpenedFile();
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
            long currentTime = System.currentTimeMillis();
            if (!pollExpirations.containsKey(pollId)) {
                // Try to fetch polls for 30 seconds
                long startTime = currentTime;
                while (!fetchPollsFromAuthority() && (currentTime - startTime) / 1000L < 30L) {
                    try {
                        Thread.sleep(1000L);
                    } catch (InterruptedException e) {
                        System.err.println("Thread has been interrupted.");
                        e.printStackTrace();
                    }
                    currentTime = System.currentTimeMillis();
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
            if (!CryptoUtils.verifySHA256withRSAandPSS(authorityVerificationKey, commitment, signature)) {
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
            ballotIds.add(ballotId);

            // Put ballot on the bulletin board of the poll
            ConcurrentHashMap<Integer, Ballot> ballots;
            if (bulletinBoard.containsKey(pollId)) {
                ballots = bulletinBoard.get(pollId);
            } else {
                ballots = new ConcurrentHashMap<>();
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
                Set<Integer> alreadyOpenedList = alreadyOpenedLists.get(pollId);
                if (alreadyOpenedList.contains(ballotId)) {
                    resultForClient = COUNTER_RESULT_ALREADY_OPEN;
                    System.out.println("Ballot has already been opened.");
                    return;
                }
            }

            // Open commitment and check if valid
            Boolean commitmentIsValid = CryptoUtils.verifyCommitment(ballot.getCommitment(), vote, commitmentSecret);
            if(!commitmentIsValid) {
                resultForClient = COUNTER_RESULT_VOTE_NOT_VALID;
                System.out.println("Failed checking validity with the given inputs.");
            }
            else {
                ConcurrentHashMap<String, Integer> validVoteList;
                Set<Integer> alreadyOpenedList;
                Integer voteCount = 0;
                if (validVoteLists.containsKey(pollId)) {
                    validVoteList = validVoteLists.get(pollId);
                    alreadyOpenedList = alreadyOpenedLists.get(pollId);
                    if (validVoteList.containsKey(vote)) {
                        voteCount = validVoteList.get(vote);
                    }
                } else {
                    validVoteList = new ConcurrentHashMap<>();
                    validVoteLists.put(pollId, validVoteList);
                    alreadyOpenedList = new HashSet<>();
                    alreadyOpenedLists.put(pollId, alreadyOpenedList);
                }

                voteCount++;
                validVoteList.put(vote, voteCount);
                alreadyOpenedList.add(ballotId);

                resultForClient = COUNTER_RESULT_VOTE_VALID;
                System.out.println("Vote was valid.");
            }
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

            ConcurrentHashMap<Integer, Ballot> ballots = new ConcurrentHashMap<>();
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

            ConcurrentHashMap<String, Integer> votes = new ConcurrentHashMap<>();
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

        for (Map.Entry<Integer, ConcurrentHashMap<Integer, Ballot>> pollEntry : bulletinBoard.entrySet()) {
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

        for (Map.Entry<Integer, ConcurrentHashMap<String, Integer>> pollEntry : validVoteLists.entrySet()) {
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

        for (Map.Entry<Integer, Set<Integer>> pollEntry : alreadyOpenedLists.entrySet()) {
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

        for (Map.Entry<Integer, ConcurrentHashMap<String, Integer>> pollEntry : tally.entrySet()) {
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
        if(pollExpirations.isEmpty()){
            System.out.println("No expiration record found.");
            return;
        }

        long currentTime = System.currentTimeMillis();
        for (Map.Entry<Integer, Long> expiration : pollExpirations.entrySet()) {
            if (expiration.getValue() + 120L * 1000L < currentTime) {
                Integer pollId = expiration.getKey();
                if (validVoteLists.containsKey(pollId)) {
                    tally.put(pollId, validVoteLists.get(pollId));
                }
            }
        }
    }
}
