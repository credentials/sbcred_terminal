/**
 * GateClient.java
 *
 * Terminal application performing gate operations on a CardClient
 * 
 * Copyright (C) TNO ICT Daniel Boonstra, December 2009. Based on work by Pim Vullers and Wojciech Mostowski.
 * Copyright (C) Pim Vullers, October 2009. Based on work by Wojciech Mostowski.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package terminal;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.InteractiveConsoleCardService;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElementFp12;
import org.bouncycastle.math.ec.ECFieldElementFp2;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPointFp2;
import org.bouncycastle.math.ec.pairing.ECCurveWithPairing;

import proxy.CardProxy;
import service.ACService;
import card.CardInterface;

public class GateClient implements GateLogger {

    // Whether to use randomised keys or not
    static final boolean RANDOMISE = false;

    // The amount of attributes to be generated for the randomised setup
    static final int ATTRIBUTE_COUNT = 4;

    // The length of the keys which is used
    public static final int KEY_LENGTH = 128;

    // Whether to use simulation or not
    static final boolean SIMULATE = false;

    class Attribute {
	byte id;
	BigInteger value;
    }

    ECCurveWithPairing c;
    ECParameterSpec c_params;
    ECPoint Q;
    Attribute[] a;
    BigInteger[] sa;
    ECPoint[] saQ;    
    ECPoint Pc;

    static SecureRandom random = new SecureRandom();
    CardProxy card;
    static ECFieldElement ONE;
    static Signature signer;

    GateLogger log = this;

    public GateClient() {
	// Register BouncyCastle as a SecurityProvider
	Security.addProvider(new BouncyCastleProvider());

	// Initialise the signer
	try {
	    signer = Signature.getInstance("SHA1WITHECDSA", "BC");
	} catch (NoSuchAlgorithmException e) {
	    e.printStackTrace();
	} catch (NoSuchProviderException e) {
	    e.printStackTrace();
	}

	// Select the CardInterface to use
	//if (SIMULATE) {
	//card = new CardClient();
	card = new CardProxy();
	//} else {
	//card = new CardProxy();
	//}

	// Construct an Elliptic Curve based on the KEY_LENGTH used by the card 
	c = constructCurve(KEY_LENGTH);
	c_params = new ECParameterSpec(c, c.getG(), c.getR());

	// Construct the fixed point on the curve
	Q = constructFixedPoint(c);

	// Construct a number of attributes
	a = constructAttributes();

	// Construct the private keys for the attributes
	sa = constructPrivateAttributeKeys(c);

	// Construct the public keys for the attributes from sa and Q
	saQ = constructPublicAttributeKeys(sa, Q);
    }

    /**
     * Construct an elliptic curve for the given length (in bits)
     */
    static private ECCurveWithPairing constructCurve(int length) {
	BigInteger u;

	switch (length) {
	    case 128:
		u = new BigInteger("1678770247");
		break;
	    case 160:
		u = new BigInteger("448873116367");
		break;
	    case 192:
		u = new BigInteger("105553250485267");
		break;
	    case 224:
		u = new BigInteger("29417389579040251");
		break;
	    default:
		u = null;
		break;
	}

	return new ECCurveWithPairing(u);
    }

    /**
     * Construct a fixed point on the given curve 
     */
    static private ECPointFp2 constructFixedPoint(ECCurveWithPairing curve) {
	ECPointFp2 fixed_point;

	if (RANDOMISE) {
	    fixed_point = (ECPointFp2) ECCurveWithPairing.FindNewPoint(curve.getTwistedCurve());
	} else {
	    ECFieldElement Qx1, Qx2, Qy1, Qy2;

	    switch (curve.getFieldSize()) {
		case 128:
		    Qx1 = curve.fromBigInteger(new BigInteger("6608942705488818925026082852251483154"));
		    Qx2 = curve.fromBigInteger(new BigInteger("110386064370833072982563086539924190163"));
		    Qy1 = curve.fromBigInteger(new BigInteger("233835185036331024500142662901760278727"));
		    Qy2 = curve.fromBigInteger(new BigInteger("269217395288346913820929092968881851980"));
		    break;
		case 160:		    
		    Qx1 = curve.fromBigInteger(new BigInteger("1368080763551537842864000867494632960265168873699"));
		    Qx2 = curve.fromBigInteger(new BigInteger("643284081012003100145372605441605069929358220305"));
		    Qy1 = curve.fromBigInteger(new BigInteger("1429829949789822849115078061391392735933877185539"));
		    Qy2 = curve.fromBigInteger(new BigInteger("320378783996916664601716070577207726212948757265"));
		    break;
		case 192:
		    Qx1 = curve.fromBigInteger(new BigInteger("1034344551609471602370610719988082697293410563719698469006"));
		    Qx2 = curve.fromBigInteger(new BigInteger("2903704171802298378325242062709100903880592437723006672773"));
		    Qy1 = curve.fromBigInteger(new BigInteger("1613585477473619097296000057982415887715414154353961900643"));
		    Qy2 = curve.fromBigInteger(new BigInteger("3154781622325109970942793240041155216575064371213525353572"));
		    break;
		default:
		    Qx1 = null;
		    Qx2 = null; 
		    Qy1 = null; 
		    Qy2 = null;
		    break;
	    }

	    ECFieldElementFp2 Qx = new ECFieldElementFp2(Qx1, Qx2, true);
	    ECFieldElementFp2 Qy = new ECFieldElementFp2(Qy1, Qy2, true);

	    fixed_point = new ECPointFp2(curve.getTwistedCurve(), Qx, Qy);
	}

	return fixed_point;
    }

    /**
     * Construct a number of attributes
     */
    private Attribute[] constructAttributes() {
	Attribute[] attribute;

	if (RANDOMISE) {
	    attribute = new Attribute[ATTRIBUTE_COUNT];
	    for (int i = 0; i < ATTRIBUTE_COUNT; i++) {
		attribute[i] = new Attribute();
		attribute[i].id = (byte)(i + 1);
		attribute[i].value = new BigInteger(random.generateSeed(16));
	    }
	} else {
	    attribute = new Attribute[4];
	    for (int i = 0; i < 4; i++) {
		attribute[i] = new Attribute();
	    }
	    attribute[0].id = 1;
	    attribute[0].value = new BigInteger("100001");
	    attribute[1].id = 2;
	    attribute[1].value = new BigInteger("200002");
	    attribute[2].id = 3;
	    attribute[2].value = new BigInteger("300003");
	    attribute[3].id = 4;
	    attribute[3].value = new BigInteger("400004");
	}

	return attribute;
    }

    /**
     * Construct a number of private attribute keys for the given curve 
     */
    static private BigInteger[] constructPrivateAttributeKeys(ECCurve.Fp curve) {
	BigInteger[] private_key;

	if (RANDOMISE) {
	    private_key = new BigInteger[ATTRIBUTE_COUNT];
	    for (int i = 0; i < ATTRIBUTE_COUNT; i++) {
		byte[] seed = random.generateSeed(curve.getFieldSize());
		private_key[i] = new BigInteger(seed).mod(curve.getQ());
	    }
	} else {
	    private_key = new BigInteger[4];
	    switch (curve.getFieldSize()) {
		case 128:
		    private_key[0] = new BigInteger("225372274231985790200027551690655815158");
		    private_key[1] = new BigInteger("245101174517207170638066748358856317475");
		    private_key[2] = new BigInteger("151090931996779535702545347407601272920");
		    private_key[3] = new BigInteger("136791876731881043202558472946915414935");
		    break;
		case 160:
		    private_key[0] = new BigInteger("330901983855736385735122296827923334307263610761");
		    private_key[1] = new BigInteger("186811774159849458934010617336619260142261775654");
		    private_key[2] = new BigInteger("200301894953491984814918734560179597654129668224");
		    private_key[3] = new BigInteger("750491186790593356184026972752047947855576453650");
		    break;
		case 192:
		    private_key[0] = new BigInteger("3593628016221464844523691788059997682516891660955827077913");
		    private_key[1] = new BigInteger("4464361787165100929465907257058278398048745164767155554885");
		    private_key[2] = new BigInteger("2968611473043184454125366431770946774998904765828172704480");
		    private_key[3] = new BigInteger("2662731123551621877786553098979283273055334939330269203348");
		    break;
		default:
		    break;
	    }
	}

	return private_key;
    }

    /**
     * Construct the corresponding public keys using the fixed point
     */
    static private ECPoint[] constructPublicAttributeKeys(BigInteger[] private_key, ECPoint fixed_point) {
	ECPoint[] public_key = new ECPoint[private_key.length];

	for (int i = 0; i < private_key.length; i++) {
	    public_key[i] = fixed_point.multiply(private_key[i]);
	}

	return public_key;
    }

    static private ECPoint[] constructCertificates(BigInteger[] private_key, ECPoint public_key) {
	ECPoint[] certificate = new ECPoint[private_key.length];

	for (int i = 0; i < private_key.length; i++) {
	    certificate[i] = public_key.multiply(private_key[i]);
	}

	return certificate;
    }

    public void personalise(byte[] attribute_id) {
	log.append("---> Personalising card with parameters:");
	log.append("  key_length = " + KEY_LENGTH);
	log.append("");

	// Initialise the card by storing the ECC parameters
	ECPoint card_key = card.initialise(c.getP(), c.getR(), 
		c.getA().toBigInteger(), c.getB().toBigInteger(), c.getG());

	// Construct certificates based on the card's key
	ECPoint[] cert = constructCertificates(sa, card_key);

	// Select the requested attributes and certificates for personalisation
	BigInteger[] attribute = new BigInteger[attribute_id.length];
	ECPoint[] certificate = new ECPoint[attribute_id.length];

	for (int i = 0; i < attribute_id.length; i++) {

	    int j = 0; 
	    while (j < a.length && attribute_id[i] != a[j].id) j++;

	    if (attribute_id[i] != a[j].id) {
		log.append("!!! Unknown attribute ID: " + attribute_id[i]);
		return;
	    } else {
		attribute[i] = a[j].value;
		certificate[i] = cert[j];
	    }	    
	}

	card.personalise(attribute_id, attribute, certificate);
    }

    public BigInteger[] proveAttribute(int attrIndex) {
	log.append("---> Get Attributes");
	BigInteger N = BigInteger.probablePrime(127, random);		
	ECPoint nonce = c.getG().multiply(N);
	BigInteger[] attr = card.getAttribute(a[attrIndex].id, nonce);
	if (attr == null) {
	    return null;
	}
	for(BigInteger ti : attr) {
	    System.out.println("attr: "+ti);
	}

	// *** NONCE SIGNATURE VERIFICATION ***
	long start = System.nanoTime();
	ECPoint sn = reconstructPoint(c, attr[CardInterface.SIGNED_NONCE], false);
	ECPoint bk = reconstructPoint(c, attr[CardInterface.BLINDED_KEY], false);

	ECPoint bkn = bk.multiply(N); 
	if (!bkn.equals(sn)) {
	    log.append("Nonce signature verification failed (n.bk != sn)");
	    if (!bkn.negate().equals(sn)) {
		log.append("Nonce signature verification failed (-n.bk != sn)");
		return null;
	    } else {
		log.append("Nonce signature verification succeeded (-n.bk == sn)");
	    }
	} else {
	    log.append("Nonce signature verification succeeded (n.bk == sn)");
	}
	
	// *** PAIRING SIGNATURE VERIFICATION ***
	ECFieldElement e1 = c.R_atePairing(bk, saQ[attrIndex]);

	ECPoint bs = reconstructPoint(c, attr[CardInterface.BLINDED_SIGNATURE], false);
	ECFieldElement e2 = c.R_atePairing(bs, Q);

	ONE = new ECFieldElementFp12(new ECFieldElement.Fp(c.getQ(), BigInteger.valueOf(1)));

	if (!e1.equals(e2)) {
	    log.append("Pairing signature verification failed (e1 != e2)");
	    if(!ONE.equals(e1.multiply(e2))) {
		log.append("Pairing signature verification failed (!equals ONE)");
		return null;
	    }
	    else {
		log.append("Pairing signature verification succeeded (equals ONE)");
	    }
	} else {
	    log.append("Pairing signature verification succeeded (e1 == e2)");
	}

	long end = System.nanoTime();
	log.append("*** VERIFICATION ***");
	System.out.format(" d = %.2f ms\n", (end - start) / 1000000.0);
	return attr;
    }

  /*  public static void main(String[] args) {
	Security.addProvider(new BouncyCastleProvider());
	BigInteger u = new BigInteger("1678770247");// 128 bits
	//BigInteger u = new BigInteger("448873116367");// 160 bits	
	//BigInteger u = new BigInteger("105553250485267");// 192 bits
	//BigInteger u = new BigInteger("29417389579040251");// 224 bits
	ECCurveWithPairing c = new ECCurveWithPairing(u);
	System.out.println("Key length = " + c.getFieldSize());
	System.out.println("Blinder length = " + c.getFieldSize()/4);

	for (int j = 0; j < 10; j++) {
	    System.out.println();
	    System.out.println("=== Run " + j + " ===");
	    System.out.println();

	    CardInterface cc = new CardProxy();
	    //CardInterface card = new CardClient();
	    ECPoint cardPubKey = cc.initialise(c.getP(), c.getR(), 
		    c.getA().toBigInteger(), c.getB().toBigInteger(), c.getG());

	    BigInteger[] a = new BigInteger[4];
	    a[0] = BigInteger.ONE;
	    a[1] = BigInteger.TEN;
	    a[2] = BigInteger.ZERO;
	    a[3] = BigInteger.probablePrime(16, random);

	    BigInteger[] sa = new BigInteger[4];
	    sa[0] = BigInteger.probablePrime(192, random).mod(c.getR());
	    sa[1] = BigInteger.probablePrime(192, random).mod(c.getR());
	    sa[2] = BigInteger.probablePrime(192, random).mod(c.getR());
	    sa[3] = BigInteger.probablePrime(192, random).mod(c.getR());

	    //ECPoint Qt = ECCurveWithPairing.FindNewPoint(c.getTwistedCurve());
	    //ECFieldElement zero_p = new ECFieldElement.Fp(c.getP(), BigInteger.ZERO);	
	    //	    ECPoint Q = ECCurveWithPairing.FindNewPoint(c.getTwistedCurve());
	    ECFieldElement Qx1 = null, Qx2 = null, Qy1 = null, Qy2 = null;
	    switch (c.getFieldSize()) {
		case 128:
		    Qx1 = c.fromBigInteger(new BigInteger("6608942705488818925026082852251483154"));
		    Qx2 = c.fromBigInteger(new BigInteger("110386064370833072982563086539924190163"));
		    Qy1 = c.fromBigInteger(new BigInteger("233835185036331024500142662901760278727"));
		    Qy2 = c.fromBigInteger(new BigInteger("269217395288346913820929092968881851980"));
		    break;
		case 160:		    
		    Qx1 = c.fromBigInteger(new BigInteger("1368080763551537842864000867494632960265168873699"));
		    Qx2 = c.fromBigInteger(new BigInteger("643284081012003100145372605441605069929358220305"));
		    Qy1 = c.fromBigInteger(new BigInteger("1429829949789822849115078061391392735933877185539"));
		    Qy2 = c.fromBigInteger(new BigInteger("320378783996916664601716070577207726212948757265"));
		    break;
		case 192:
		    Qx1 = c.fromBigInteger(new BigInteger("1034344551609471602370610719988082697293410563719698469006"));
		    Qx2 = c.fromBigInteger(new BigInteger("2903704171802298378325242062709100903880592437723006672773"));
		    Qy1 = c.fromBigInteger(new BigInteger("1613585477473619097296000057982415887715414154353961900643"));
		    Qy2 = c.fromBigInteger(new BigInteger("3154781622325109970942793240041155216575064371213525353572"));
		    break;
		default:
		    break;
	    }

	    ECFieldElementFp2 Qx = new ECFieldElementFp2(Qx1, Qx2, true);
	    ECFieldElementFp2 Qy = new ECFieldElementFp2(Qy1, Qy2, true);
	    ECPoint Q = new ECPointFp2(c.getTwistedCurve(), Qx, Qy);

	    ECPoint[] saQ = new ECPoint[4];
	    saQ[0] = Q.multiply(sa[0]);
	    saQ[1] = Q.multiply(sa[1]);
	    saQ[2] = Q.multiply(sa[2]);
	    saQ[3] = Q.multiply(sa[3]);

	    ECPoint[] saPc = new ECPoint[4];
	    saPc[0] = cardPubKey.multiply(sa[0]);
	    saPc[1] = cardPubKey.multiply(sa[1]);
	    saPc[2] = cardPubKey.multiply(sa[2]);
	    saPc[3] = cardPubKey.multiply(sa[3]);

	    //cc.personalise(a, saPc);

	    byte attrIndex = 0;
	    ECPoint nonce = null;
	    BigInteger[] attr = cc.getAttribute(attrIndex, nonce);
	    System.out.println("Received attribute: " + attr[CardInterface.ATTRIBUTE]);

	    ECPoint bk = null, bs = null;
	    //System.out.println("*** VERIFY ***");
	    long start = System.nanoTime();

	    // Check signature via pairing
	    //	    ECFieldElement e1 = c.TatePairing(bk, saQ[attrIndex]);
	    //	    ECFieldElement e1_ate = c.atePairing(Pc, saQ[attrIndex]);
	    ECFieldElement e1 = c.R_atePairing(bk, saQ[attrIndex]);

	    bs = reconstructPoint(c, attr[CardInterface.BLINDED_SIGNATURE], false);
	    //	    ECFieldElement e2 = c.TatePairing(bs, Q);
	    //	    ECFieldElement e2_ate = c.atePairing(saPc[attrIndex], Q);
	    ECFieldElement e2 = c.R_atePairing(bs, Q);
	    //	    System.out.println("atePairing check: " + e1_ate.equals(e2_ate));
	    //	    System.out.println("R-atePairing check: " + e1_R_ate.equals(e2_R_ate));
	    if (!e1.equals(e2)) {
		System.out.println("Pairing signature verification failed");
		ECFieldElement ONE = new ECFieldElementFp12(new ECFieldElement.Fp(c.getQ(), BigInteger.valueOf(1)));
		//		System.out.println("atePairing check2: " + ONE.equals(e1_ate.multiply(e2_ate)));
		//		System.out.println("R-atePairing check2: " + ONE.equals(e1_R_ate.multiply(e2_R_ate)));
		if(!ONE.equals(e1.multiply(e2))) {
		    System.out.println("Pairing signature verification failed");
		    return;
		}
	    }
	    System.out.println("Pairing signature verification succeeded");

	    long end = System.nanoTime();
	    System.out.println("*** VERIFY ***");
	    System.out.format(" d = %.2f ms\n", (end - start) / 1000000.0);
	}
    }*/

    private static ECPoint reconstructPoint(ECCurve c, BigInteger i, boolean negate) {	
	ECFieldElement x = c.fromBigInteger(i);
	ECFieldElement y = x.multiply(x).multiply(x).add(
		c.getA().multiply(x)).add(c.getB()).sqrt();
	if (negate) {
	    return c.createPoint(x.toBigInteger(), y.toBigInteger().negate(), false);
	} else {
	    return c.createPoint(x.toBigInteger(), y.toBigInteger(), false);
	}
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

    public void setLogger(GateLogger logger) {
	log = logger;
    }
/*
    public static void main(String[] args) {
	GateClient client = new GateClient();
	for (int i = 0; i < 10; i++) {
	    byte[] id = {(byte)0x01};
	    client.personalise(id);
	    client.proveAttribute(0);
	}
    }
*/

    
    // GateLogger functionality
    public void append(String message) {
	System.out.println(message);
    }

    public void clear() {
	// Cannot clear System.out
    }
}
