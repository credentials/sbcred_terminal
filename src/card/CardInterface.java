/**
 * CardInterface.java
 *
 * Common interface for card implementations
 * 
 * Copyright (C) Pim Vullers, October 2009.
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

import org.bouncycastle.math.ec.ECPoint;

public interface CardInterface {
    
    /**
     * Indices for the result of the getAttribute method 
     */
    static final public int BLINDED_KEY = 0;
    static final public int SIGNED_NONCE = 1;
    static final public int BLINDED_SIGNATURE = 2;
    static final public int ATTRIBUTE = 3;
    
    /**
     * Initialise the cryptographic parameters on the card
     *  
     * @param p Prime number for the finite field F_P
     * @param a A parameter defining the curve: y^2 = x^3 + Ax + B (mod P)
     * @param b B parameter defining the curve: y^2 = x^3 + Ax + B (mod P)
     * @param g Generator point on the curve
     * @param r Order of the elliptic curve
     * @return 
     */
    public abstract ECPoint initialise(BigInteger p, BigInteger r,
	    BigInteger a, BigInteger b, ECPoint g);

    /**
     * Store a number of attributes (with corresponding signatures) on the card
     * 
     * @param attribute List of attributes
     * @param signature List of signatures over the attributes
     */
    public abstract void personalise(byte[] attribute_id, BigInteger[] attribute, ECPoint[] signature);

    /**
     * Get an attribute from the card
     * 
     * @param i Index of the attribute.
     * @return Blinded public key, blinded attribute signature and the attribute
     */
    public abstract BigInteger[] getAttribute(byte id, ECPoint nonce);
}