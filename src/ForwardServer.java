/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server
 * and adapted for IK2206.
 * <p>
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.security.cert.CertificateException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

public class ForwardServer {
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "127.0.0.1";
    public static final String PROGRAMNAME = "ForwardServer";
    private static final boolean ENABLE_LOGGING = true;
    private static Arguments arguments;


    private ServerSocket handshakeSocket;

    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;
    private SessionKey key;
    private IvParameterSpec iv;

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--serverhost=<hostname>");
        System.err.println(indent + "--serverport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
            throws Exception {
        arguments = new Arguments();
//        String path = "C:\\Users\\Achil\\OneDrive\\master\\Internet Security and Privacy\\ex\\VPN\\code\\";
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
//        arguments.setDefault("usercert", path+"server.pem");
//        arguments.setDefault("cacert", path+"ca.pem");
//        arguments.setDefault("key", path+"server-private.der");

        arguments.loadArguments(args);

        ForwardServer srv = new ForwardServer();
        try {
            srv.startForwardServer();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Do handshake negotiation with client to authenticate, learn
     * target host/port, etc.
     */
    private void doHandshake() throws Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        X509Certificate caCertificate = null;
        X509Certificate serverCertificate = null;
        try (InputStream inStream = new FileInputStream(arguments.get("cacert"));
             InputStream inStream2 = new FileInputStream(arguments.get("usercert"))) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            caCertificate = (X509Certificate) cf.generateCertificate(inStream);
            serverCertificate = (X509Certificate) cf.generateCertificate(inStream2);
        } catch (Exception e) {
            System.out.println(e);
        }

        checkCertificateCN(caCertificate, "ca-pf.ik2206.kth.se");
        checkCertificateCN(serverCertificate, "server-pf.ik2206.kth.se");

        PublicKey caPubKey = caCertificate.getPublicKey();
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.recv(clientSocket);

        if (!clientHello.getParameter("MessageType").equals("ClientHello")) {
            throw new Exception("Message-Type was not Client-Hello");
        }
        String ucEncoded = clientHello.getParameter("Certificate");
        byte[] ucBin = Base64.getDecoder().decode(ucEncoded);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate userCertificate =
                (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(ucBin));
        checkCertificateCN(userCertificate, "client-pf.ik2206.kth.se");
        userCertificate.checkValidity();
        userCertificate.verify(caPubKey);
        PublicKey userPubKey = userCertificate.getPublicKey();

        String scStr = Base64.getEncoder().encodeToString(serverCertificate.getEncoded());

        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.putParameter("MessageType", "ServerHello");
        serverHello.putParameter("Certificate", scStr);
        serverHello.send(clientSocket);

        HandshakeMessage forward = new HandshakeMessage();
        forward.recv(clientSocket);
        if (!forward.getParameter("MessageType").equals("Forward")) {
            throw new Exception("Message-Type was not Forward");
        }
        this.targetHost = forward.getParameter("TargetHost");
        this.targetPort = Integer.valueOf(forward.getParameter("TargetPort"));
        System.out.println("requested target " + targetHost + " " + targetPort);
        this.listenSocket = new ServerSocket(0);
        System.out.println("waiting client at " + listenSocket.getLocalPort());
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, userPubKey);
        this.key = new SessionKey(256);
        String sessionKeyEnc = Base64.getEncoder().encodeToString(cipher.doFinal(this.key.getSecretKey().getEncoded()));
        final byte[] array = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(array);
        this.iv = new IvParameterSpec(array);
        String ivEnc = Base64.getEncoder().encodeToString(cipher.doFinal(iv.getIV()));


        HandshakeMessage sessionMessage = new HandshakeMessage();
        sessionMessage.putParameter("MessageType", "Session");
        sessionMessage.putParameter("SessionKey", sessionKeyEnc);
        sessionMessage.putParameter("SessionIV", ivEnc);
        sessionMessage.putParameter("ServerHost", "localhost");
        sessionMessage.putParameter("ServerPort", String.valueOf(this.listenSocket.getLocalPort()));
        sessionMessage.send(clientSocket);
        System.out.println("handshake completed");
        System.out.println("session key " + this.key.encodeKey());
        System.out.print("iv ");
        for (byte b : iv.getIV()) {
            System.out.print(b);
        }
        System.out.println();

        clientSocket.close();

        /* listenSocket is a new socket where the ForwardServer waits for the
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort).
         * (This may give "Address already in use" errors, but that's OK for now.)
         */
    }

    private static void checkCertificateCN(X509Certificate cert, String cn) throws CertificateException {
        String[] fields = cert.getSubjectX500Principal().getName().split(",");
        String cnField = Arrays.stream(fields).filter(field -> field.startsWith("CN")).findFirst().get();
        String cnValue = cnField.split("=")[1];
        if(!cn.equals(cnValue)){
            throw new CertificateException("Expected CN:"+ cn + ", but given CN: "+ cnField);
        }
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
            throws Exception {

        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port);
        }

        log("Nakov Forward Server started on TCP port " + port);

        // Accept client connections and process them until stopped
        while (true) {

            try {
                ForwardServerClientThread forwardThread;
                doHandshake();
                forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort);
                forwardThread.setKey(this.key, this.iv);
                forwardThread.start();
            } catch (IOException e) {
                throw e;
            }
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage) {
        if (ENABLE_LOGGING)
            System.out.println(aMessage);
    }

}
