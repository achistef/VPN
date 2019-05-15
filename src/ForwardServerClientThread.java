/**
 * ForwardServerClientThread handles the clients of Nakov Forward Server. It
 * connects two sockets and starts the TCP forwarding between given client
 * and its assigned server. After the forwarding is failed and the two threads
 * are stopped, closes the sockets.
 * <p>
 * <p>
 * Modifications for IK2206:
 * - Server pool removed
 * - Two variants - client connects to listening socket or client is already connected
 * <p>
 * Peter Sjodin, KTH
 * <p>
 * Modifications for IK2206:
 * - Server pool removed
 * - Two variants - client connects to listening socket or client is already connected
 * <p>
 * Peter Sjodin, KTH
 * <p>
 * Modifications for IK2206:
 * - Server pool removed
 * - Two variants - client connects to listening socket or client is already connected
 * <p>
 * Peter Sjodin, KTH
 * <p>
 * Modifications for IK2206:
 * - Server pool removed
 * - Two variants - client connects to listening socket or client is already connected
 * <p>
 * Peter Sjodin, KTH
 */

/**
 * Modifications for IK2206:
 * - Server pool removed
 * - Two variants - client connects to listening socket or client is already connected
 *
 * Peter Sjodin, KTH
 */

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class ForwardServerClientThread extends Thread {
    private Socket mClientSocket = null;
    private Socket mServerSocket = null;
    private ServerSocket mListenSocket = null;
    private boolean mBothConnectionsAreAlive = false;
    private String mClientHostPort;
    private String mServerHostPort;
    private int mServerPort;
    private String mServerHost;
    private SessionKey key;
    private IvParameterSpec iv;

    /**
     * Creates a client thread for handling clients of NakovForwardServer.
     * A client socket should be connected and passed to this constructor.
     * A server socket is created later by run() method.
     */
    public ForwardServerClientThread(Socket aClientSocket, String serverhost, int serverport) {
        mClientSocket = aClientSocket;
        mServerPort = serverport;
        mServerHost = serverhost;
    }


    /**
     * Creates a client thread for handling clients of NakovForwardServer.
     * Wait for client to connect on client listening socket.
     * A server socket is created later by run() method.
     */
    public ForwardServerClientThread(ServerSocket listensocket, String serverhost, int serverport) throws IOException {
        mListenSocket = listensocket;
        //mServerHost =  listensocket.getInetAddress().getHostAddress();
        mServerPort = serverport;
        mServerHost = serverhost;
    }

    public ServerSocket getListenSocket() {
        return mListenSocket;
    }

    public void setKey(SessionKey key, IvParameterSpec iv) {
        this.key = key;
        this.iv = iv;
    }

    /**
     * Obtains a destination server socket to some of the servers in the list.
     * Starts two threads for forwarding : "client in <--> dest server out" and
     * "dest server in <--> client out", waits until one of these threads stop
     * due to read/write failure or connection closure. Closes opened connections.
     *
     * If there is a listen socket, first wait for incoming connection
     * on the listen socket.
     */
    public void run() {
        try {

            // Wait for incoming connection on listen socket, if there is one 
            if (mListenSocket != null) {
                mClientSocket = mListenSocket.accept();
                mClientHostPort = mClientSocket.getInetAddress().getHostAddress() + ":" + mClientSocket.getPort();
                Logger.log("Accepted from  " + mServerPort + " <--> " + mClientHostPort + "  started.");

            } else {
                mClientHostPort = mClientSocket.getInetAddress().getHostAddress() + ":" + mClientSocket.getPort();
            }

            try {
                mServerSocket = new Socket(mServerHost, mServerPort);
            } catch (Exception e) {
                System.out.println("Connection failed to " + mServerHost + ":" + mServerPort);
                e.printStackTrace();
                // Prints what exception has been thrown
                System.out.println(e);
            }


            Cipher encrypter = null;
            Cipher decrypter = null;
            try {
                encrypter = Cipher.getInstance("AES/CTR/NoPadding");
                encrypter.init(Cipher.ENCRYPT_MODE, this.key.getSecretKey(), this.iv);
                decrypter = Cipher.getInstance("AES/CTR/NoPadding");
                decrypter.init(Cipher.DECRYPT_MODE, this.key.getSecretKey(), this.iv);
            } catch (Exception e) {
                System.out.println(e);
            }

            InputStream clientIn = null;
            OutputStream clientOut = null;
            InputStream serverIn = null;
            OutputStream serverOut = null;
            //clientIn = mClientSocket.getInputStream();
            //clientOut = mClientSocket.getOutputStream();
            // clientIn = new CipherInputStream(mClientSocket.getInputStream(), decrypter);
            // clientOut = new CipherOutputStream(mClientSocket.getOutputStream(), encrypter);
            //serverIn = mServerSocket.getInputStream();
            // serverIn = new CipherInputStream(mServerSocket.getInputStream(), decrypter);
            //serverOut = mServerSocket.getOutputStream();
            // serverOut = new CipherOutputStream(mServerSocket.getOutputStream(), encrypter);
            // Obtain input and output streams of server and client
            if (mListenSocket != null) {
                System.out.println("server");
                clientIn = new CipherInputStream(mClientSocket.getInputStream(), decrypter);
                clientOut = new CipherOutputStream(mClientSocket.getOutputStream(), encrypter);
                serverIn = mServerSocket.getInputStream();
                serverOut = mServerSocket.getOutputStream();
            } else {
                System.out.println("client");
                clientIn = mClientSocket.getInputStream();
                clientOut = mClientSocket.getOutputStream();
                serverIn = new CipherInputStream(mServerSocket.getInputStream(), decrypter);
                serverOut = new CipherOutputStream(mServerSocket.getOutputStream(), encrypter);
            }

            mServerHostPort = mServerHost + ":" + mServerPort;
            Logger.log("TCP Forwarding  " + mClientHostPort + " <--> " + mServerHostPort + "  started.");
            // Start forwarding of socket data between server and client
            ForwardThread clientForward = new ForwardThread(this, clientIn, serverOut);
            ForwardThread serverForward = new ForwardThread(this, serverIn, clientOut);
            mBothConnectionsAreAlive = true;
            clientForward.start();
            serverForward.start();
            System.out.println("clientSocket local to out : " + mClientSocket.getLocalPort() + " " + mClientSocket.getPort());
            System.out.println("serverSocket local to out : " + mServerSocket.getLocalPort() + " " + mServerSocket.getPort());

        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    /**
     * connectionBroken() method is called by forwarding child threads to notify
     * this thread (their parent thread) that one of the connections (server or client)
     * is broken (a read/write failure occured). This method disconnects both server
     * and client sockets causing both threads to stop forwarding.
     */
    public synchronized void connectionBroken() {
        if (mBothConnectionsAreAlive) {
            // One of the connections is broken. Close the other connection and stop forwarding
            // Closing these socket connections will close their input/output streams
            // and that way will stop the threads that read from these streams
            try {
                mServerSocket.close();
            } catch (IOException e) {
            }
            try {
                mClientSocket.close();
            } catch (IOException e) {
            }

            mBothConnectionsAreAlive = false;

            Logger.log("TCP Forwarding  " + mClientHostPort + " <--> " + mServerHostPort + "  stopped.");
        }
    }

}
