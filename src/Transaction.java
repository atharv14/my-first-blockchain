import java.security.*;
import java.util.ArrayList;

public class Transaction {

    public String transactionID;
    public PublicKey sender;
    public PublicKey recipient;
    public  float value;
    public byte[] signature;

    public ArrayList<TransactionInput> inputs;
    public ArrayList<TransactionOutput> outputs = new ArrayList<>();

    private static int sequence = 0;

    // Constructor
    public Transaction(PublicKey from, PublicKey to, float value, ArrayList<TransactionInput> inputs) {
        this.sender = from;
        this.recipient = to;
        this.value = value;
        this.inputs = inputs;
    }

    // This Calculates the transaction hash (which will be used as its ID)
    private String calculateHash() {
        sequence++;
        return StringUtil.applySHA256(
                StringUtil.getStringFromKey(sender) +
                      StringUtil.getStringFromKey(recipient) +
                      Float.toString(value) +
                      sequence
        );
    }

    // Signs all the data we don't wish to be tampered with
    public void generateSignature(PrivateKey privateKey) {
        String data = StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(recipient) + Float.toString(value);
        signature = StringUtil.applyECDSASig(privateKey, data);
    }

    // Verifies the data we signed hasn't been tampered with
    public boolean verifySignature() {
        String data = StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(recipient) + Float.toString(value);
        return StringUtil.verifyECDSASig(sender, data, signature);
    }

    // Returns true if new transaction could be created
    public boolean processTransaction() {

        if (!verifySignature()) {
            System.out.println("#Transaction Signature Error: Failed to verify signature");
            return false;
        }

        // gather transaction input (Make sure they are unspent):
        for (TransactionInput input : inputs) {
            input.UTXO = Main.UTXOs.get(input.transactionOutputId);
        }

        // Check if transaction is valid:
        if (getInputsValue() < Main.minimumTransaction) {
            System.out.println("#Transaction Inputs to small: " + getInputsValue());
            return false;
        }

        // Generate transaction outputs:
        float leftOver = getInputsValue() - value;  // get value of inputs
        transactionID = calculateHash();
        outputs.add(new TransactionOutput(this.recipient, value, transactionID));   // send value to recipient
        outputs.add(new TransactionOutput(this.sender, leftOver, transactionID));   // send the left over 'change' back to sender

        // add outputs to unspent list
        for (TransactionOutput output : outputs) {
            Main.UTXOs.put(output.id, output);
        }

        // remove transaction inputs from UTXO lists as spent:
        for (TransactionInput input : inputs) {
            if (input.UTXO == null) continue;
            Main.UTXOs.remove(input.UTXO.id);
        }

        return true;
    }

    // Returns sum of inputs(UTXOs) value
    public float getInputsValue() {
        float total = 0;
        for (TransactionInput input : inputs) {
            if (input.UTXO == null) continue;
            total += input.UTXO.value;
        }
        return total;
    }

    // Returns sum of outputs:
    public float getOutputsValue() {
        float total = 0;
        for (TransactionOutput output : outputs) {
            total += output.value;
        }
        return total;
    }
}
