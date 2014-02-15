/**
 * GateClientGUI.java
 *
 * Graphical User Interface (GUI) for the GateClient
 * 
 * Copyright (C) TNO ICT Daniel Boonstra, December 2009. Based on work by Pim Vullers and Wojciech Mostowski.
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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.border.Border;

import net.sourceforge.gpj.cardservices.AID;
import net.sourceforge.gpj.cardservices.APDUListener;
import net.sourceforge.gpj.cardservices.GPUtil;
import net.sourceforge.gpj.cardservices.GlobalPlatformService;

import proxy.CardProxy;
import proxy.CardProxyConfiguration;

public class GateClientGUI extends JPanel implements GateLogger {

    private static final long serialVersionUID = -6092833890061111562L;

    // constants declaration
    // static final long serialVersionUID = 0;
    static final String TITLE = "OV-chip 2.0 DEMO";

    // variables declarations
    int attrIndex = 0;

    // GUI variables declaration
    JFrame windowPersonalise, windowGetAttributes, windowUpload;
    JButton uploadAppletButton, personaliseCardButton, verifyCardButton,
            personaliseButton, provingAttributesButton, backButton;
    JTextArea statusTextArea;
    JCheckBox[] attributeBoxes = new JCheckBox[5];
    String[] attributeNames = new String[] { "Train ticket", "Metro ticket",
            "Tram ticket", "Bus ticket", "All tickets" };
    JLabel[] labels = new JLabel[4];
    JTextField[] fields = new JTextField[4];
    JButton[] buttons = new JButton[4];

    static JOptionPane personalise;

    GateClient protocol = new GateClient();
    GateLogger log = this;

    public GateClientGUI(JFrame parent) {
        protocol.setLogger(log);
        buildGUI(parent);
    }

    void buildGUI(JFrame parent) {
        setLayout(new BorderLayout());

        JPanel uploadPanel = new JPanel();
        uploadAppletButton = new JButton("Upload OV-chip applet");
        uploadAppletButton.setPreferredSize(new Dimension(250, 100));
        UploadEventListener uploadEventListener = new UploadEventListener();
        uploadAppletButton.addActionListener(uploadEventListener);
        uploadPanel.add(uploadAppletButton);

        JPanel personaliseCardPanel = new JPanel();
        personaliseCardButton = new JButton("Personalise OV-chip");
        personaliseCardButton.setPreferredSize(new Dimension(250, 100));
        PersonaliseCardEventListener personaliseCardEventListener = new PersonaliseCardEventListener();
        personaliseCardButton.addActionListener(personaliseCardEventListener);
        personaliseCardPanel.add(personaliseCardButton);

        JPanel verifyCardPanel = new JPanel();
        verifyCardButton = new JButton("Check OV-chip");
        verifyCardButton.setPreferredSize(new Dimension(250, 100));
        VerifyCardEventListener verifyCardEventListener = new VerifyCardEventListener();
        verifyCardButton.addActionListener(verifyCardEventListener);
        verifyCardPanel.add(verifyCardButton);

        JPanel controlsPanel = new JPanel(new GridLayout(3, 1));
        controlsPanel.add(uploadPanel);
        controlsPanel.add(personaliseCardPanel);
        controlsPanel.add(verifyCardPanel);

        add(controlsPanel, BorderLayout.CENTER);

        parent.addWindowListener(new CloseEventListener());
    }

    void buildWindowPersonalise() {
        windowPersonalise = new JFrame("Personalise OV-chip");
        Dimension d = new Dimension(420,600);
        windowPersonalise.setSize(d);
        windowPersonalise.setMinimumSize(d);
        windowPersonalise.setPreferredSize(d);
        windowPersonalise.pack();
        windowPersonalise.setVisible(true);
        windowPersonalise.setLayout(new BorderLayout());

        JPanel[] attributePanels = new JPanel[attributeBoxes.length];

        for (int i = 0; i < attributeBoxes.length; i++) {
            JPanel p = new JPanel();
            p.setPreferredSize(new Dimension(40, 40));
            p.setLayout(new BorderLayout());
            JCheckBox b = new JCheckBox(attributeNames[i], false);
            p.add(b, BorderLayout.WEST);
            attributeBoxes[i] = b;
            attributePanels[i] = p;
        }

        JPanel personalisePanel = new JPanel();
        personalisePanel.setLayout(new BorderLayout());
        backButton = new JButton("Back");
        BackOneEventListener backOneEventListener = new BackOneEventListener();
        backButton.addActionListener(backOneEventListener);
        personaliseButton = new JButton("Personalise");
        PersonaliseEventListener personaliseEventListener = new PersonaliseEventListener();
        personaliseButton.addActionListener(personaliseEventListener);
        personalisePanel.add(backButton, BorderLayout.WEST);
        personalisePanel.add(personaliseButton, BorderLayout.EAST);

        JPanel controlsPanel = new JPanel(new GridLayout(6, 1));
        for (JPanel p : attributePanels) {
            controlsPanel.add(p);
        }
        controlsPanel.add(personalisePanel);

        windowPersonalise.add(controlsPanel, BorderLayout.NORTH);

        statusTextArea = new JTextArea(5, 35);
        windowPersonalise.add(new JScrollPane(statusTextArea),
                BorderLayout.CENTER);

        windowPersonalise.addWindowListener(new WPCloseEventListener());
    }

    void buildWindowUpload() {
        windowUpload = new JFrame("Upload OV-chip applet");
        Dimension d = new Dimension(420,600);
        windowUpload.setSize(d);
        windowUpload.setMinimumSize(d);
        windowUpload.setPreferredSize(d);
        windowUpload.pack();
        windowUpload.setVisible(true);
        windowUpload.setLayout(new BorderLayout());

        JPanel buttonsPanel = new JPanel();
        GridLayout l = new GridLayout(1, 3);
        l.setHgap(10);
        l.setVgap(10);
        buttonsPanel.setLayout(l);
        JButton b = new JButton("Upload");
        b.setEnabled(true);
        b.addActionListener(new UploadAppletEventListener());
        buttonsPanel.add(b);
        b = new JButton("Delete");
        b.setEnabled(true);
        b.addActionListener(new DeleteAppletEventListener());
        buttonsPanel.add(b);
        b = new JButton("Back");
        b.setEnabled(true);
        b.addActionListener(new BackThreeEventListener());
        buttonsPanel.add(b);

        JPanel controlsPanel = new JPanel(new GridLayout(2, 1));
        controlsPanel.add(buttonsPanel);

        windowUpload.add(controlsPanel, BorderLayout.NORTH);

        statusTextArea = new JTextArea(5, 35);
        windowUpload.add(new JScrollPane(statusTextArea), BorderLayout.CENTER);

        windowUpload.addWindowListener(new WPCloseEventListener());
    }

    void buildWindowGetAttributes() {
        windowGetAttributes = new JFrame("Check OV-chip");
        Dimension d = new Dimension(420,700);
        windowGetAttributes.setSize(d);
        windowGetAttributes.setMinimumSize(d);
        windowGetAttributes.setPreferredSize(d);
        windowGetAttributes.pack();
        windowGetAttributes.setVisible(true);
        windowGetAttributes.setLayout(new BorderLayout());

        windowGetAttributes.add(new JScrollPane(statusTextArea),
                BorderLayout.CENTER);

        ProvingAttributesEventListener provingAttributesEventListener = new ProvingAttributesEventListener();

        JPanel[] idPanels = new JPanel[labels.length];
        String[] labelNames = { "train", "metro", "tram", "bus" };

        for (int i = 0; i < labels.length; i++) {
            idPanels[i] = new JPanel();
            fields[i] = new JTextField(15);
            buttons[i] = new JButton("Activate");
            buttons[i].setActionCommand("" + i);
            buttons[i].addActionListener(provingAttributesEventListener);
            idPanels[i].add(buttons[i]);
            idPanels[i].add(new JLabel("BLINDED SIGNATURE:"));
            idPanels[i].add(fields[i]);
            labels[i] = new JLabel("Entry to " + labelNames[i],
                    SwingConstants.CENTER);
            Border b1 = BorderFactory.createEtchedBorder();
            Border b2 = BorderFactory.createMatteBorder(4, 4, 4, 4, Color.gray);
            labels[i].setBorder(BorderFactory.createCompoundBorder(b1, b2));
        }

        JPanel provingAttributesPanel = new JPanel();
        backButton = new JButton("Back");
        BackTwoEventListener backTwoEventListener = new BackTwoEventListener();
        backButton.addActionListener(backTwoEventListener);
        provingAttributesPanel.add(backButton);

        JPanel controlsPanel = new JPanel(new GridLayout(9, 1));
        for (int i = 0; i < labels.length; i++) {
            controlsPanel.add(labels[i]);
            controlsPanel.add(idPanels[i]);
        }
        controlsPanel.add(provingAttributesPanel);

        windowGetAttributes.add(controlsPanel, BorderLayout.NORTH);

        statusTextArea = new JTextArea(5, 35);
        windowGetAttributes.add(new JScrollPane(statusTextArea),
                BorderLayout.CENTER);

        windowGetAttributes.addWindowListener(new WGACloseEventListener());
    }

    class PersonaliseCardEventListener implements ActionListener {
        public void actionPerformed(ActionEvent ae) {
            try {
                enableMainButtons(false);
                buildWindowPersonalise();
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
    }

    class BackOneEventListener implements ActionListener {
        public void actionPerformed(ActionEvent ae) {
            try {
                windowPersonalise.setVisible(false);
                enableMainButtons(true);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
    }

    class VerifyCardEventListener implements ActionListener {
        public void actionPerformed(ActionEvent ae) {
            try {
                enableMainButtons(false);
                buildWindowGetAttributes();
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
    }

    class UploadEventListener implements ActionListener {
        public void actionPerformed(ActionEvent ae) {
            try {
                enableMainButtons(false);
                buildWindowUpload();
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
    }

    private CardChannel getCardChannel() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            CardTerminal terminal = null;
            if (CardProxy.defaultTerminal != null) {
                terminal = CardProxy.defaultTerminal;
            } else {
                terminal = factory.terminals().list().get(
                        CardProxyConfiguration.TERMINAL_ID);
            }
            terminal.waitForCardPresent(100);
            if (!terminal.isCardPresent()) {
                statusTextArea.append("\nNo card on/in the reader!");
                return null;
            }
            Card card = terminal.connect("*");
            return card.getBasicChannel();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }

    }

    private URL getCapFileURL() {
        URL url = getClass().getResource("GateClientGUI.class");
        String path = url.toString();
        int i = path.indexOf("terminal/GateClientGUI.class");
        path = path.substring(0,i)+"javacard/applet.cap";
        try {
            url = new URL(path);
        } catch (MalformedURLException e) {
        }
        return url;
    }
    
    static byte[] packageAID = { 0x35, 0x01, 0x02, 0x03, 0x04 };
    static byte[] appletAID = { 0x35, 0x01, 0x02, 0x03, 0x04, 0x07 };
    static byte[] sdAID = { (byte) 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00 };

    class UploadAppletEventListener implements ActionListener {
        public void actionPerformed(ActionEvent ae) {
            try {
                CardChannel channel = getCardChannel();
                if (channel == null)
                    return;
                statusTextArea.setText("");
                GlobalPlatformService s = new GlobalPlatformService(new AID(
                        sdAID), channel);
                s.addAPDUListener(new APDUListener() {
                    public void exchangedAPDU(CommandAPDU c, ResponseAPDU r) {
                        statusTextArea
                                .append("C: "
                                        + GPUtil
                                                .byteArrayToString(c.getBytes())
                                        + "\n");
                        statusTextArea
                                .append("R: "
                                        + GPUtil
                                                .byteArrayToString(r.getBytes())
                                        + "\n");
                    }
                });
                s.openWithDefaultKeys();
                statusTextArea.append("\nDeleting previous instance.\n");
                try {
                    s.deleteAID(new AID(packageAID), true);
                } catch (CardException ce) {
                    statusTextArea.append("\nPrevious instance not found.\n");
                }
                URL url = getCapFileURL();
                s.loadCapFile(url, false, false, 247, false, false);
                s.installAndMakeSelecatable(new AID(packageAID), new AID(
                        appletAID), null, (byte) 0, null, null);
                statusTextArea.append("\nUpload successful.\n");
                channel.getCard().disconnect(false);

            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }

    }

    class DeleteAppletEventListener implements ActionListener {
        public void actionPerformed(ActionEvent ae) {
            try {
                CardChannel channel = getCardChannel();
                if (channel == null)
                    return;
                statusTextArea.setText("");
                GlobalPlatformService s = new GlobalPlatformService(new AID(
                        sdAID), channel);
                s.addAPDUListener(new APDUListener() {
                    public void exchangedAPDU(CommandAPDU c, ResponseAPDU r) {
                        statusTextArea
                                .append("C: "
                                        + GPUtil
                                                .byteArrayToString(c.getBytes())
                                        + "\n");
                        statusTextArea
                                .append("R: "
                                        + GPUtil
                                                .byteArrayToString(r.getBytes())
                                        + "\n");
                    }
                });
                s.openWithDefaultKeys();
                try {
                    s.deleteAID(new AID(packageAID), true);
                    statusTextArea.append("\nDeletion successful.\n");
                } catch (CardException ce) {
                    statusTextArea.append("\nApplet instance not found.\n");
                }
                channel.getCard().disconnect(false);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }

    }

    private void enableMainButtons(boolean state) {
        personaliseCardButton.setEnabled(state);
        verifyCardButton.setEnabled(state);
        uploadAppletButton.setEnabled(state);
    }

    class BackTwoEventListener implements ActionListener {
        public void actionPerformed(ActionEvent ae) {
            try {
                windowGetAttributes.setVisible(false);
                enableMainButtons(true);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
    }

    class BackThreeEventListener implements ActionListener {
        public void actionPerformed(ActionEvent ae) {
            try {
                windowUpload.setVisible(false);
                enableMainButtons(true);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
    }

    class PersonaliseEventListener implements ActionListener {
        public void actionPerformed(ActionEvent ae) {
            try {
                List<Byte> a = new ArrayList<Byte>();
                for (int i = 0; i < attributeBoxes.length; i++) {
                    if (attributeBoxes[i].isSelected()) {
                        Byte num = new Byte((byte) (i + 1));
                        if (num.byteValue() == (byte) 5) {
                            a.clear();
                            a.add(new Byte((byte) 1));
                            a.add(new Byte((byte) 2));
                            a.add(new Byte((byte) 3));
                            a.add(new Byte((byte) 4));
                        } else {
                            a.add(num);
                        }
                    }
                }

                byte[] attribute = new byte[a.size()];
                for (int i = 0; i < a.size(); i++) {
                    attribute[i] = a.get(i);
                }
                protocol.personalise(attribute);
                personaliseButton.setEnabled(false);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println(e.getMessage());
            }
        }
    }

    class ProvingAttributesEventListener implements ActionListener {
        public void actionPerformed(ActionEvent ae) {

            // reset GUI parameters
            Border xx = BorderFactory.createEtchedBorder();
            Border yy = BorderFactory.createMatteBorder(4, 4, 4, 4, Color.gray);
            log.clear();

            for (int i = 0; i < labels.length; i++) {
                labels[i].setBorder(BorderFactory.createCompoundBorder(xx, yy));
                fields[i].setText("");
                buttons[i].setEnabled(false);
            }

            try {
                BigInteger[] attr = null;
                try {
                    attrIndex = Integer.parseInt(ae.getActionCommand());
                } catch (NumberFormatException nfe) {
                    attrIndex = 0;
                }

                Border ba = BorderFactory.createEtchedBorder();
                Border bb = BorderFactory.createMatteBorder(4, 4, 4, 4,
                        Color.lightGray);
                labels[attrIndex].setBorder(BorderFactory.createCompoundBorder(
                        ba, bb));
                fields[attrIndex].setText("Waiting for card...");

                windowGetAttributes.update(windowGetAttributes.getGraphics());

                attr = protocol.proveAttribute((byte) attrIndex);
                if (attr != null) {
                    Border aa = BorderFactory.createEtchedBorder();
                    Border ab = BorderFactory.createMatteBorder(4, 4, 4, 4,
                            Color.green);
                    labels[attrIndex].setBorder(BorderFactory
                            .createCompoundBorder(aa, ab));
                    fields[attrIndex].setText(attr[0].toString(16) + " - "
                            + attr[1].toString(16) + " - "
                            + attr[1].toString(16));
                } else {
                    Border aa = BorderFactory.createEtchedBorder();
                    Border ab = BorderFactory.createMatteBorder(4, 4, 4, 4,
                            Color.red);
                    labels[attrIndex].setBorder(BorderFactory
                            .createCompoundBorder(aa, ab));
                    fields[attrIndex].setText("Entry denied");
                }

                for (int i = 0; i < buttons.length; i++) {
                    buttons[i].setEnabled(true);
                }

                windowGetAttributes.update(windowGetAttributes.getGraphics());

            } catch (Exception e) {
                log.append("Total verification failed:\n");
                log.append(e.getMessage());
                e.printStackTrace();
                for (int i = 0; i < buttons.length; i++) {
                    buttons[i].setEnabled(true);
                }
            }
        }
    }

    class CloseEventListener extends WindowAdapter {
        public void windowClosing(WindowEvent we) {
            try {

            } catch (Exception e) {
                System.out.println(e.getMessage());
            } finally {
                System.exit(0);
            }
        }
    }

    class WPCloseEventListener extends WindowAdapter {
        public void windowClosing(WindowEvent we) {
            try {
                windowPersonalise.setVisible(false);
                personaliseCardButton.setEnabled(true);
                verifyCardButton.setEnabled(true);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            } finally {
                // System.exit(0);
            }
        }
    }

    class WGACloseEventListener extends WindowAdapter {
        public void windowClosing(WindowEvent we) {
            try {
                windowGetAttributes.setVisible(false);
                personaliseCardButton.setEnabled(true);
                verifyCardButton.setEnabled(true);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            } finally {
                // System.exit(0);
            }
        }
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame(TITLE);
        Container ct = frame.getContentPane();
        GateClientGUI panel = new GateClientGUI(frame);
        ct.add(panel);
        frame.pack();
        frame.setVisible(true);
    }

    // GateLogger functionality
    public void append(String txt) {
        statusTextArea.append(txt + "\n");
        statusTextArea.update(statusTextArea.getGraphics());
    }

    public void clear() {
        statusTextArea.setText("");
        statusTextArea.update(statusTextArea.getGraphics());
    }

}
