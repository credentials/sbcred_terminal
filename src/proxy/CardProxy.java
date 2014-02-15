/**
 * CardProxy.java
 *
 * Relay and translate JavaCard operations
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

package proxy;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.swing.JOptionPane;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import card.CardInterface;

/**
 * JavaCard proxy class  
 */
public class CardProxy implements CardInterface {

    private static boolean TIMING = true;
    private static boolean VERBOSE = true;

    private static final int[] SELECT        = { 0x00, 0xA4, 0x04, 0x00 };
    private static final int[] INITIALISE    = { 0x00, 0x01, 0x00, 0x00 };
    private static final int[] PERSONALISE   = { 0x00, 0x02, 0x00, 0x00 };
    private static final int[] GET_ATTRIBUTE = { 0x00, 0x03, 0x00, 0x00 };
    private static final int[] GET_KEY       = { 0x00, 0x04, 0x00, 0x00 };

    private static final byte[] AID = { 0x35, 0x01, 0x02, 0x03, 0x04, 0x07 };

    private CardChannel channel = null;
    public static CardTerminal defaultTerminal = null;
    
    static {
        if(CardProxyConfiguration.GUI_CHOOSE) {
            try{
              List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
              if(terminals.size() == 0) {
                  JOptionPane.showMessageDialog(null, "No readers found!", "Error", JOptionPane.ERROR_MESSAGE);
                  System.exit(1);
              }
              Object choice = JOptionPane.showInputDialog(null, "Choose reader", "Reader", JOptionPane.QUESTION_MESSAGE, null, terminals.toArray(), terminals.toArray()[0]);
              defaultTerminal = (CardTerminal)choice;
              if(defaultTerminal == null) {
                  System.exit(0);                  
              }
            }catch(CardException ce) {
                JOptionPane.showMessageDialog(null, "No readers found!", "Error", JOptionPane.ERROR_MESSAGE);
                System.exit(1);
            }
         }
    }
    
    /**
     * Setup a connection with the smart card 
     */
    private void connect() {
	while (channel == null) {
	    try {
		TerminalFactory factory = TerminalFactory.getDefault();
		CardTerminal terminal = null;
		if(defaultTerminal != null) {
		    terminal = defaultTerminal;
		}else{
		   terminal = factory.terminals().list().get(CardProxyConfiguration.TERMINAL_ID);
		}
		terminal.waitForCardPresent(100);
		if (!terminal.isCardPresent()) continue;
		Card card = terminal.connect("*");
		channel = card.getBasicChannel();

		byte[][] data = {AID};
		CommandAPDU cmd = APDUprepare(SELECT, data, 0);
		if (channel.transmit(cmd).getSW() != 0x9000) {
		    throw new CardException("SELECT Failed");
		}
	    } catch (CardException e) {
		System.err.println(e.getMessage());
		channel = null;
		continue;
	    }
	}
    }

    /**
     * Connect to the card and transmit the command
     * 
     * @param cmd Command to be transmitted to the card
     * @return Response received from the card
     * @throws CardException
     */
    private ResponseAPDU transmit(CommandAPDU cmd) {
	connect();

	long start = System.nanoTime();
	if (VERBOSE) {
		System.out.println("Sending @" + start + ": " + cmd);
		byte[] buf = cmd.getBytes() ;
		System.out.print(" - command bytes: ") ;
		for (int i = 0 ; i < buf.length ; i++ )
			System.out.format("%02x", buf[i]) ;
		System.out.println("\n") ;
	}

	ResponseAPDU resp = null;
	try {
	    resp = channel.transmit(cmd);
	} catch (CardException e) {
	    channel = null;
	    System.err.println("transmit failed: ");
	    e.printStackTrace();
	}
	long end = System.nanoTime();
	if (VERBOSE) {
		System.out.println("Received @" + end + ": " + resp);
		byte[] buf = resp.getBytes() ;
		System.out.print(" - command bytes: ") ;
		for (int i = 0 ; i < buf.length ; i++ )
			System.out.format("%02x", buf[i]) ;
		System.out.println("\n") ;
	}
	if (VERBOSE || TIMING) 
		System.out.format(" d = %.2f ms\n", (end - start) / 1000000.0);

	return resp;
    }


    /**
     * Initialise the cryptographic parameters on the card
     *  
     * @param p Prime number for the finite field F_P
     * @param a A parameter defining the curve: y^2 = x^3 + Ax + B (mod P)
     * @param b B parameter defining the curve: y^2 = x^3 + Ax + B (mod P)
     * @param g Generator point on the curve
     * @param r Order of the elliptic curve
     */
    public ECPoint initialise(BigInteger p, BigInteger r, BigInteger a, BigInteger b, ECPoint g) {
	if (VERBOSE || TIMING) System.out.println("*** INITIALISE ***");

	ECPoint key = null;

	byte[][] data = { toAPDU(p), toAPDU(r), toAPDU(a), toAPDU(b),
		toAPDU(g)};
	CommandAPDU cmd = APDUprepare(INITIALISE, data, g.getEncoded().length);

	try {
	    ResponseAPDU response = transmit(cmd);
	    if (response.getSW() != 0x9000) {
		System.err.println("Received SW: " + response.getSW());
	    } else {
		byte[] resp = response.getData();
		ECCurve curve = new ECCurve.Fp(p, a, b);
		int length = ((resp[0] << 8) | (resp[1] & 0xff));
		byte[] pt = new byte[length];
		System.arraycopy(resp, 2, pt, 0, length);
		key = curve.decodePoint(pt);
	    }
	} catch (Exception e) {
	    e.printStackTrace();
	}

	return key;
    }

    public ECPoint getCardKey(BigInteger p, BigInteger a, BigInteger b, ECPoint g) {
        if (VERBOSE || TIMING) System.out.println("*** GET CARD PUBLIC KEY ***");

        ECPoint key = null;

        CommandAPDU cmd = APDUprepare(GET_KEY, new byte[][]{}, g.getEncoded().length);

        try {
            ResponseAPDU response = transmit(cmd);
            if (response.getSW() != 0x9000) {
                System.err.println("Received SW: " + response.getSW());
            } else {
                byte[] resp = response.getData();
                ECCurve curve = new ECCurve.Fp(p, a, b);
                int length = ((resp[0] << 8) | (resp[1] & 0xff));
                byte[] pt = new byte[length];
                System.arraycopy(resp, 2, pt, 0, length);
                key = curve.decodePoint(pt);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return key;
    }

    /**
     * Store a number of attributes (with corresponding signatures) on the card
     * 
     * @param attribute List of attributes
     * @param signature List of signatures over the attributes
     */
    public void personalise(byte[] attribute_id, BigInteger[] attribute, ECPoint[] signature) {
	if (VERBOSE || TIMING) System.out.println("*** PERSONALISE ***");

	int length = attribute.length;
	byte[][] data = new byte[length * 3 + 1][];
	data[0] = new byte[2];	
	data[0][0] = (byte)((length & 0xFF00) >> 8);
	data[0][1] = (byte)(length & 0xFF);
	
	for (int i = 0; i < length; i++) {
	    data[3*i + 1] = new byte[1];
	    data[3*i + 1][0] = attribute_id[i];
	    data[3*i + 2] = signature[i].getEncoded();
	    data[3*i + 3] = toAPDU(attribute[i]);
	}

	CommandAPDU cmd = APDUprepare(PERSONALISE, data, 0);

	transmit(cmd);
    }

    /**
     * Get an attribute from the card
     * 
     * @param a Index of the attribute.
     * @return Blinded public key, blinded attribute signature and the attribute
     */
    public BigInteger[] getAttribute(byte a, ECPoint N) {
	if (VERBOSE || TIMING) System.out.println("*** GET_ATTRIBUTE ***");

	channel = null;
	
	byte[][] data = new byte[2][];
	data[0] = new byte[1];
	data[0][0] = a;
	data[1] = toAPDU(N);
	CommandAPDU cmd = APDUprepare(GET_ATTRIBUTE, data, 9);

	BigInteger[] result = new BigInteger[4];
	ResponseAPDU response = transmit(cmd);
	if (response.getSW() != 0x9000) {
	    System.err.println("Request failed: " + response.getSW());
	    result = null;
	    channel = null;
	} else {
	    byte[] resp = response.getData();	
	    int offset = 0;
	    result[SIGNED_NONCE] = fromAPDU(resp, offset);
	    offset += (result[SIGNED_NONCE].bitLength() + 7) / 8 + 2;
	    result[BLINDED_KEY] = fromAPDU(resp, offset);
	    offset += (result[BLINDED_KEY].bitLength() + 7) / 8 + 2;
	    result[BLINDED_SIGNATURE] = fromAPDU(resp, offset);
	    offset += (result[BLINDED_SIGNATURE].bitLength() + 7) / 8 + 2;
	    result[ATTRIBUTE] = fromAPDU(resp, offset);
	}

	return result;
    }

    private byte[] toAPDU(BigInteger i) {
	byte[] array = i.toByteArray();

	int length = (i.bitLength() + 7) / 8;
	if (length == 0) length++;
	int offset = array.length - length;

	byte[] result = new byte[length +2];
	result[0] = (byte)((length & 0xff00) >> 8);
	result[1] = (byte)(length & 0xff);	
	System.arraycopy(array, offset, result, 2, length);	

	return result;
    }

    @SuppressWarnings("unused")
    private byte[] toAPDU(byte[] a) {
	byte[] result = new byte[a.length + 2];
	result[0] = (byte)((a.length & 0xFF00) >> 8);
	result[1] = (byte)(a.length & 0xFF);	
	System.arraycopy(a, 0, result, 2, a.length);
	return result;
    }

    private BigInteger fromAPDU(byte[] array, int offset) {
	int length = ((array[offset] << 8) | (array[offset + 1] & 0xff));
	array[offset + 1] = 0x00;
	return new BigInteger(Arrays.copyOfRange(array, offset + 1, offset + 2 + length));
    }

    private byte[] toAPDU(ECPoint p) {
	byte[] array = p.getEncoded();

	byte[] result = new byte[2 + array.length];
	result[0] = (byte)(array.length >> 8);
	result[1] = (byte)array.length ;	
	System.arraycopy(array, 0, result, 2, array.length);	

	return result;
    }

    private CommandAPDU APDUprepare(int[] c, byte[][] d, int e) {
	int length = 0;
	for (int i = 0; i < d.length; i++) {
	    length += d[i].length;
	}

	byte[] data = new byte[length];
	int offset = 0;
	if (VERBOSE) System.out.print("data = { ");
	for (int i = 0; i < d.length; i++) {
	    if (VERBOSE) System.out.print(d[i].length + "@" + Integer.toHexString(offset & 0xff) + "; ");
	    System.arraycopy(d[i], 0, data, offset, d[i].length);
	    offset += d[i].length;
	}
	if (VERBOSE) System.out.println("}");

	return new CommandAPDU(c[0], c[1], c[2], c[3], data, e);
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
