package terminal;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECTestHost {
    private static byte[] SELECT = { (byte) 0x00, (byte) 0xA4, (byte) 0x04,
	    (byte) 0x00, (byte) 0x06, (byte) 0x35, (byte) 0x01, (byte) 0x02,
	    (byte) 0x03, (byte) 0x04, (byte) 0x05 };

    static final BigInteger
    _0 = BigInteger.valueOf(0L),
    _1 = BigInteger.valueOf(1L),
    _2 = BigInteger.valueOf(2L),
    _3 = BigInteger.valueOf(3L),
    _4 = BigInteger.valueOf(4L),
    _5 = BigInteger.valueOf(5L),
    _6 = BigInteger.valueOf(6L),
    _7 = BigInteger.valueOf(7L),
    _9 = BigInteger.valueOf(9L),
    _24 = BigInteger.valueOf(24L);

    /**
     * @param args
     *            the command line arguments
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
//	for (Enumeration e = ECNamedCurveTable.getNames(); e.hasMoreElements();) { System.out.println(e.nextElement()); }

	// Setup the EC stuff
	Security.addProvider(new BouncyCastleProvider());
	KeyPairGenerator genKey = KeyPairGenerator.getInstance("ECDSA", "BC");
	genKey.initialize(new ECGenParameterSpec("secp192r1"));
	KeyPair keyPair = genKey.generateKeyPair();

	// The private key: a BigInteger
	ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
	byte[] privKeyData = privKey.getS().toByteArray();
	if (privKeyData[0] == 0 && privKeyData.length > 1) {
	    System.err.println("Applying BigInteger.toByteArray() fix...");
	    privKeyData = Arrays.copyOfRange(privKeyData, 1, privKeyData.length);
	}
	System.out.println("privKeyData.length = " + privKeyData.length);
	
	// The public key: an ECPoint
	ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
	byte[] pubKeyData = pubKey.getQ().getEncoded();
	System.out.println("pubKeyData.length = " + pubKeyData.length);
	
	// Host signature:
	Signature signer = Signature.getInstance("SHA1WITHECDSA", "BC");
	signer.initSign(privKey);
	signer.update(privKeyData);
	byte[] hostSign = signer.sign();
	byte[] hostLen = {(byte) (hostSign.length >> 8), (byte) hostSign.length};
	System.out.println("hostSign.length = " + hostSign.length);
	printArray(hostSign);
	
	// Card signature:
	TerminalFactory factory = TerminalFactory.getDefault();
	CardTerminal terminal = factory.terminals().list().get(1);
	Card card = terminal.connect("*");
	CardChannel channel = card.getBasicChannel();

	if (!check9000(channel.transmit(new CommandAPDU(SELECT)))) System.out.println("SELECT failed");

	byte[] keyData = Arrays.copyOf(privKeyData, 24 + 49 + 2 + hostSign.length);
	System.arraycopy(pubKeyData, 0, keyData, 24, pubKeyData.length);
	System.arraycopy(hostLen, 0, keyData, 24 + 49, hostLen.length);
	System.arraycopy(hostSign, 0, keyData, 24 + 49 + 2, hostSign.length);
	
	ResponseAPDU response = channel.transmit(new CommandAPDU(0, 2, 0, 0,
		keyData, 50));
	if (!check9000(response)) System.out.println("REQUEST failed: " + response);

	byte[] data = response.getData();
	byte[] cardSign = Arrays.copyOf(data, data.length - 1);

	System.out.println("cardSign.length = " + cardSign.length);
	printArray(cardSign);
	
	// Verify signatures
	signer.initVerify(keyPair.getPublic());
	System.out.println("Host verification:");
	signer.update(privKeyData);
	System.out.println(" Host signature OK? " + signer.verify(hostSign));
	signer.update(privKeyData);
	System.out.println(" Card signature OK? " + signer.verify(cardSign));
	
	System.out.println("Card verification:"); 
	System.out.println(" Host signature OK? " + ((data[data.length - 1] & 0x02) == 2));
	System.out.println(" Card signature OK? " + ((data[data.length - 1] & 0x01) == 1));
	
	card.disconnect(false);
    }

    public static boolean check9000(ResponseAPDU ra) {
	byte[] response = ra.getBytes();
	return (response[response.length - 2] == (byte) 0x90 && response[response.length - 1] == (byte) 0x00);
    }
    
    public static void printArray(byte[] array) {
	for (int i = 0; i < array.length; i++) {
	    String s = Integer.toHexString(array[i] & 0xff).toString();
	    if (s.length() == 1) {
		System.out.print("(byte) 0x0" + s + ", ");
	    } else {
		System.out.print("(byte) 0x" + s + ", ");
	    }
	}
	System.out.println();
    }
}
