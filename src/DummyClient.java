import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class DummyClient {
    public static void main(String[] args) throws Exception {
        int port = Integer.valueOf(args[0]);
        Socket socket = new Socket("localhost", port);
        System.out.println("from: " + socket.getLocalPort());
        PrintWriter pr = new PrintWriter(socket.getOutputStream());
        pr.write("Time flies like an arrow. Fruit flies like a banana.");
        pr.flush();
        //pr.close();
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
        Thread.sleep(1000);
        while (true) {
            int bytesRead = in.read();
            System.out.format("%c", bytesRead);
            if (bytesRead == -1) {
                break; // End of stream is reached --> exit the thread
            }
        }
        socket.close();
    }
}
