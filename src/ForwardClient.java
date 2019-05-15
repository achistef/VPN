/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server
 * and adapted for IK2206.
 * <p>
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
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
import javax.crypto.spec.IvParameterSpec;
import javax.security.cert.CertificateException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.stream.Stream;

public class ForwardClient {
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "127.0.0.1";
    public static final String PROGRAMNAME = "ForwardClient";
    private static final boolean ENABLE_LOGGING = true;
    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;
    private static SessionKey key;
    private static IvParameterSpec iv;

    private static void doHandshake() throws Exception {

        /* Connect to forward server server */
        System.out.println("Connect to " + arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        X509Certificate userCertificate = null;
        X509Certificate caCertificate = null;
        try (InputStream inStream = new FileInputStream(arguments.get("usercert"));
             InputStream inStream2 = new FileInputStream(arguments.get("cacert"))) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            userCertificate = (X509Certificate) cf.generateCertificate(inStream);
            caCertificate = (X509Certificate) cf.generateCertificate(inStream2);
        } catch (Exception e) {
            System.out.println(e);
        }

        checkCertificateCN(userCertificate, "client-pf.ik2206.kth.se");
        checkCertificateCN(caCertificate, "ca-pf.ik2206.kth.se");

        PublicKey caPubKey = caCertificate.getPublicKey();
        String ucStr = Base64.getEncoder().encodeToString(userCertificate.getEncoded());
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.putParameter("MessageType", "ClientHello");
        clientHello.putParameter("Certificate", ucStr);
        clientHello.send(socket);

        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(socket);

        if (!serverHello.getParameter("MessageType").equals("ServerHello")) {
            throw new Exception("Message-Type was not Server-Hello");
        }
        String scEncoded = serverHello.getParameter("Certificate");
        byte[] scBin = Base64.getDecoder().decode(scEncoded);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate serverCertificate =
                (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(scBin));
        checkCertificateCN(serverCertificate, "server-pf.ik2206.kth.se");
        serverCertificate.checkValidity();
        serverCertificate.verify(caPubKey);

        HandshakeMessage forward = new HandshakeMessage();
        forward.putParameter("MessageType", "Forward");
        forward.putParameter("TargetHost", arguments.get("targethost"));
        forward.putParameter("TargetPort", arguments.get("targetport"));
        forward.send(socket);

        HandshakeMessage session = new HandshakeMessage();
        session.recv(socket);
        if (!session.getParameter("MessageType").equals("Session")) {
            throw new Exception("Message-Type was not Session");
        }
        serverHost = session.getParameter("ServerHost");
        serverPort = Integer.parseInt(session.getParameter("ServerPort"));
        System.out.println("next endpoint " + serverHost + " " + serverPort);
        byte[] bytes = Files.readAllBytes(Paths.get(arguments.get("key")));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey userPrivateKey = keyFactory.generatePrivate(keySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, userPrivateKey);
        String keyStr = session.getParameter("SessionKey");
        byte[] keyBytes = cipher.doFinal(Base64.getDecoder().decode(keyStr.getBytes()));
        key = new SessionKey(keyBytes);
        String ivStr = session.getParameter("SessionIV");
        byte[] ivBytes = cipher.doFinal(Base64.getDecoder().decode(ivStr.getBytes()));
        iv = new IvParameterSpec(ivBytes);
        System.out.println("handshake completed");
        System.out.println("session key " + key.encodeKey());
        System.out.print("iv ");
        for (byte b : iv.getIV()) {
            System.out.print(b);
        }
        System.out.println();

        socket.close();
    }

    private static void checkCertificateCN(X509Certificate cert, String cn) throws CertificateException {
        String[] fields = cert.getSubjectX500Principal().getName().split(",");
        String cnField = Arrays.stream(fields).filter(field -> field.startsWith("CN")).findFirst().get();
        String cnValue = cnField.split("=")[1];
        if(!cn.equals(cnValue)){
            throw new CertificateException("Expected CN:"+ cn + ", but given CN: "+ cnField);
        }
    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }

    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws Exception {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;

        try {
            /* Create a new socket. This is to where the user should connect.
             * ForwardClient sets up port forwarding between this socket
             * and the ServerHost/ServerPort learned from the handshake */
            listensocket = new ServerSocket(0);
            /* Let the system pick a port number */
            /* Tell the user, so the user knows where to connect */
            tellUser(listensocket);
            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            log("Accepted client from " + clientHostPort + " to " + clientSocket.getLocalPort());

            forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort);
            forwardThread.setKey(key, iv);
            forwardThread.start();

        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage) {
        if (ENABLE_LOGGING)
            System.out.println(aMessage);
    }

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) {
        try {
            arguments = new Arguments();
//            String path = "C:\\Users\\Achil\\OneDrive\\master\\Internet Security and Privacy\\ex\\VPN\\code\\";
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
//            arguments.setDefault("targethost", "127.0.0.1");
//            arguments.setDefault("targetport", "55555");
//            arguments.setDefault("usercert", path+"client.pem");
//            arguments.setDefault("cacert", path+"ca.pem");
//            arguments.setDefault("key", path+"client-private.der");
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch (IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        try {
            startForwardClient();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
