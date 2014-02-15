/**
 * CardClient.java
 *
 * Simulate JavaCard operations
 * 
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

package card;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * JavaCard simulation class 
 */
public class CardClient implements CardInterface {
    static {
	Security.addProvider(
		new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * Fields representing the objects on the card
     */
    private ECCurve curve;
    private ECParameterSpec ecParams;
    private ECDomainParameters ecDom; 
    private KeyPairGenerator keyGen;
    private KeyPair keys;
    private ECPrivateKey blinder;
    private byte[] attribute_id;
    private BigInteger[] attribute;
    private ECPoint[] signature;

    // The card stores:
    // crypto parameters (embedded in the key object?)
    // private key (generated each time?, only private, kc part?) kc, P
    // common private coordinate, s
    //   
    // Using key agreement
    public CardClient() {}

    /**
     * Initialise the cryptographic parameters on the card
     *  
     * @param p Prime number for the finite field F_P
     * @param a A parameter defining the curve: y^2 = x^3 + Ax + B (mod P)
     * @param b B parameter defining the curve: y^2 = x^3 + Ax + B (mod P)
     * @param g Generator point on the curve
     * @param r Order of the generator
     * @return 
     */
    public ECPoint initialise(BigInteger p, BigInteger r, BigInteger a, BigInteger b, ECPoint g) {
	try {
	    curve = new ECCurve.Fp(p, a, b);
	    ecParams = new ECParameterSpec(curve, g, r);
	    ecDom = new ECDomainParameters(curve, g, r);
	    keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
	    keyGen.initialize(ecParams);
	    keys = keyGen.generateKeyPair();
	} catch (Exception e) {
	    e.printStackTrace();
	}
	
	return ((ECPublicKey) keys.getPublic()).getQ();
    }

    /**
     * Store a number of attributes (with corresponding signatures) on the card
     * 
     * @param attribute List of attributes
     * @param signature List of signatures over the attributes
     */
    public void personalise(byte[] attribute_id, BigInteger[] attribute, ECPoint[] signature) {
	this.attribute_id = attribute_id;
	this.attribute = attribute;
	this.signature = signature;
    }
    
    /**
     * Get an attribute from the card
     * 
     * @param i Index of the attribute.
     * @return Blinded public key, blinded attribute signature and the attribute
     */
    public BigInteger[] getAttribute(byte id, ECPoint nonce) {
	BigInteger[] result = new BigInteger[3];
	
	int i = 0;
	while (i < attribute.length && attribute_id[i] != id) i++;
	
	if (i >= attribute.length || attribute_id[i] != id) { 
	    return null;
	}
	result[ATTRIBUTE] = attribute[i];
	
	// generate a blinding factor b
	blinder = (ECPrivateKey) keyGen.generateKeyPair().getPrivate();
	
	// blind public key, attribute signature and signed nonce
	try {
	    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
	    agreement.init(new ECPrivateKeyParameters(blinder.getD(), ecDom));
	    
	    result[BLINDED_KEY] = agreement.calculateAgreement(new ECPublicKeyParameters(((ECPublicKey) keys.getPublic()).getQ(), ecDom));
	    result[BLINDED_SIGNATURE] = agreement.calculateAgreement(new ECPublicKeyParameters(signature[i], ecDom));
	    result[SIGNED_NONCE] = agreement.calculateAgreement(new ECPublicKeyParameters(nonce.multiply(((ECPrivateKey)keys.getPrivate()).getD()), ecDom));	    
	} catch (Exception e) {
	    e.printStackTrace();
	}
		
	// return blinded public key, blinded attribute signature, blinded signed nonce, attribute
	return result;
    }
}
