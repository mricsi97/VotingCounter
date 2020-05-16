package data;

public class Ballot {

    private Integer id;
    private byte[] commitment;
    private byte[] signature;

    public Ballot(Integer id, byte[] commitment, byte[] signature){
        this.id = id;
        this.commitment = commitment;
        this.signature = signature;
    }

    public byte[] getCommitment() {
        return this.commitment;
    }

    public byte[] getSignature() {
        return this.signature;
    }
}
