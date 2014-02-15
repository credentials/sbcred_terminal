package service;

import java.math.BigInteger;
import java.security.SecureRandom;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import net.sourceforge.scuba.smartcards.APDUEvent;
import net.sourceforge.scuba.smartcards.APDUListener;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.InteractiveConsoleCardService;
import net.sourceforge.scuba.smartcards.TerminalCardService;
import net.sourceforge.scuba.util.Hex;

public class ServiceTest implements APDUListener {

    static SecureRandom random = new SecureRandom();

    public static void main(String[] args) throws CardServiceException, CardException {
	    new ServiceTest().run();
    }
    
    public void run() throws CardException, CardServiceException {
    	byte[][] a = new byte[4][];
	    a[0] = BigInteger.ONE.toByteArray();
	    a[1] = BigInteger.TEN.toByteArray();
	    a[2] = BigInteger.ZERO.toByteArray();
	    a[3] = BigInteger.probablePrime(16, random).toByteArray();

	    CardTerminal term = TerminalFactory.getDefault().terminals().list().get(1);
	    TerminalCardService terms = new TerminalCardService(term);
	    ACService cc = new ACService(terms, a);
	    //ACService cc = new ACService(new InteractiveConsoleCardService(), a);
	    cc.open();
	    cc.initialiseCard();
	    cc.testDH();
	    //cc.personalise(new byte[]{1,2,3,4});
	    //cc.proveAttribute(1);//*/
    }

	@Override
	public void exchangedAPDU(APDUEvent e) {
		System.out.println("C: " + Hex.toHexString(e.getCommandAPDU().getBytes()));
		System.out.println("R: " + Hex.toHexString(e.getResponseAPDU().getBytes()));
	}
}
