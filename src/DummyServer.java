import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class DummyServer {

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(55555);
        System.out.println("Listening to " + serverSocket.getInetAddress().getHostAddress() + ":" + serverSocket.getLocalPort());
        Socket socket = serverSocket.accept();
        System.out.println("Connection accepted from " + socket.getLocalPort() + " to " + socket.getPort());

        PrintWriter pr = new PrintWriter(socket.getOutputStream());
        pr.write("Time flies like an arrow. Fruit flies like a banana.");
        pr.flush();

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
        while (true) {
            int bytesRead = in.read();
            System.out.format("%c", bytesRead);
            if (bytesRead == -1) {
                break; // End of stream is reached --> exit the thread
            }
        }

    }
}
