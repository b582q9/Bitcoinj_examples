import com.google.common.collect.ImmutableList;
import org.bitcoinj.base.*;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.*;
import org.bitcoinj.core.Transaction.SigHash;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.net.discovery.PeerDiscoveryException;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptPattern;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;

/**
 * @author
 * created: 05.10.2023-13:12
 * @version 0.1
 */
public class MultisigBitcoinjExample {
    //private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();
    private int n = 2, m = 3;

    public MultisigBitcoinjExample() {
        testMultiSigTx();
    }

    public static void main(String... args) {
        new MultisigBitcoinjExample();
    }


    @Test
    public void testMultiSigTx() {

        List<ECKey> privKeys = ImmutableList.of(ECKey.fromPrivate(Hex.decode("secret_key_1")),
                ECKey.fromPrivate(Hex.decode("secret_key_1")),
                ECKey.fromPrivate(Hex.decode("secret_key_1")));


        List<ECKey> pubKeys = Arrays.asList(ECKey.fromPublicOnly(Hex.decode("03f8233393cb1b583facab1d8c321f7360d8c26694e29afa88d90b100fd6d45576")),
                ECKey.fromPublicOnly(Hex.decode("02e6a9a41dae0587a5d8653575a56720a578b3ee80269b5bf4359f30ac20276ef8")),
                ECKey.fromPublicOnly(Hex.decode("03132bef2f48237928df567645a570dba1deb4503015e8a82eef09486e017b596c")));

        pubKeys.sort(ECKey.PUBKEY_COMPARATOR);

        Script redeemScript = ScriptBuilder.createRedeemScript(n, pubKeys);
        Script scriptPubKey = ScriptBuilder.createP2SHOutputScript(redeemScript);
        String multiSigAddress = LegacyAddress.fromScriptHash(BitcoinNetwork.MAINNET, ScriptPattern.extractHashFromP2SH(scriptPubKey)).toString();
        System.out.println("multiSigAddress = " + multiSigAddress);
        assertEquals("3Qz5HbXih96iShgS3fjW6npjge5561yD74", multiSigAddress);

        //https://blockchain.info/rawaddr/multiSigAddress //Get last tx hash by address
        //https://blockchain.info/rawtx/ee63c442ec5f45e874c75b83140d52ee455ef186cd7c5ed28ad5140a5d0aa90b?format=hex //Get tx in hex
        byte[] bytes = ByteUtils.parseHex("0100000001e58c9d0ceee925e744ef750020b4ce0d9df93d08688a1aef58aeecd9658a8dd217000000fc00473044022015bd9e4867cec57aa8f9eeac28e68e12d0c4259e8f9a2c23e55be0428f06ec3d02204e63857b9c6bfb525c486dd7a494226306efc8e71b54c5439348e89f9bcb131f0147304402202c09b2f94187fb941c5e7b8643821f0709eb59155255b0a7dee7cf35e0b9e2fb02207095487d398b3c0808c4c66536aba8a130827da18e07a0ea6074ac303b6db847014c695221020623c0414d3b4105e152c474e707f5f2c26705dad9158989bb87dccae431ae6d21027f6c8fa644731637c9234b45a2d9b3f1d486f19314dbcb6afcb12f275bd0bab22103e4d502ce626103898eb89bcb86b85a2e1c63b7f561e0360ead1914b6a598cd1053aeffffffff012c4c00000000000017a914ff84c58a8c39b641e15f66d62c5ac4b281c9e93b8700000000");
        Transaction transaction = MAINNET.getDefaultSerializer().makeTransaction(ByteBuffer.wrap(bytes));
        TransactionOutput previousTxOutput = transaction.getOutput(0); //Get index from tx info: https://blockchain.info/rawtx/ee63c442ec5f45e874c75b83140d52ee455ef186cd7c5ed28ad5140a5d0aa90b

        //Set tx fee
        //Coin txFee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(10); //10000
        Coin txFee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE; //1000
        if (txFee.value <= 1000)
            Logger.getGlobal().log(Level.WARNING, "Transaction fee = " + txFee.value + ", fee is too low!");
        System.out.println(previousTxOutput.getValue() + " - " + txFee + " = " + previousTxOutput.getValue().subtract(txFee));


        Coin sendValue = previousTxOutput.getValue().subtract(txFee);
        Address address = LegacyAddress.fromBase58("31ho5FMuiRUUZmmtM1ttd4fxRhxC8KRik5", BitcoinNetwork.MAINNET);
        Script outputScript = ScriptBuilder.createOutputScript(address);

        //Build spend tx
        Transaction spendTx = new Transaction();
        spendTx.addOutput(sendValue, outputScript);
        TransactionInput spendTxInput = spendTx.addInput(previousTxOutput);

        //Sign tx, will fall if no private keys specified
        List<TransactionInput> spendTxInputs = spendTx.getInputs();
        ArrayList<TransactionSignature> txSigs = new ArrayList<>();
        spendTxInputs.iterator().forEachRemaining(input -> {
            Sha256Hash sighash = spendTx.hashForSignature(input.getIndex(), redeemScript, SigHash.ALL, false);
            IntStream.range(0, n).forEach(i -> txSigs.add(new TransactionSignature(privKeys.get(i).sign(sighash), SigHash.ALL, false)));
        });

        //Build tx input script
        Script inputScript = ScriptBuilder.createP2SHMultiSigInputScript(txSigs, redeemScript);
        spendTxInput.setScriptSig(inputScript);
        try {
            //Verify tx, if no exceptions - broadcast
            spendTxInput.verify(previousTxOutput);

            // Broadcast tx
            PeerGroup pGroup = new PeerGroup(MAINNET);
            int minConnections = 10;
            pGroup.startAsync();

            var Peers = new DnsDiscovery.DnsSeedDiscovery(MAINNET, "seed.bitcoin.sipa.be").getPeers(Services.NODE_NETWORK, Duration.ofSeconds(1));
            System.out.println("Peers = " + Peers);
            Peers.stream().forEach(p -> System.out.println(p.getAddress().getHostAddress()));
            Peers.stream().forEach(p -> {
                try {
                    pGroup.addAddress(InetAddress.getByName(p.getAddress().getHostAddress()));
                } catch (UnknownHostException e) {
                    throw new RuntimeException(e);
                }
            });
            //pGroup.broadcastTransaction(spendTx, minConnections, true).broadcastOnly().get();
            var tx = pGroup.broadcastTransaction(spendTx, minConnections, true).broadcastOnly().get();
            System.out.println(tx.awaitSent().isDone() + "|" + tx.awaitRelayed().isDone());

        } catch (ScriptException ex) {
            throw new RuntimeException(ex);
        } catch (VerificationException ex) {
            throw new RuntimeException(ex);
        } catch (PeerDiscoveryException | InterruptedException | ExecutionException ex) {
            throw new RuntimeException(ex);
        }
        System.out.println("spendTx: " + spendTx);
        System.out.println("Tx hex: " + ByteUtils.formatHex(spendTx.serialize()));
    }
}