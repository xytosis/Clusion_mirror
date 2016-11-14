package org.crypto.remote;

import org.crypto.sse.MMGlobal;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;

/**
 * This class should be run on a remote server, the client should stream images to it
 */
public class ImageServer {

    private int port;
    private ServerSocket serverSock;
    private MMGlobal twolev;
    private Socket sock;
    private ObjectInputStream in;
    private ObjectOutputStream out;

    public ImageServer(int port) {
        this.port = port;
        try {
            this.serverSock = new ServerSocket(port);
        } catch (IOException e) {
            System.out.println("Could not build socket");
        }
    }

    /**
     * Gets the index
     */
    public void runSetup() {
        // we do the initial "handshake", where we send over the serialized data structure
        try {
            this.sock = serverSock.accept();
            try {
                InputStream input  = sock.getInputStream();
                this.in = new ObjectInputStream(input);
                OutputStream output = sock.getOutputStream();
                this.out = new ObjectOutputStream(output);
                this.twolev = (MMGlobal) in.readObject();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                System.out.println("class not found");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Runs the query phase
     */
    public void runQuery() {
        try {
            while (true) {
                byte[][] token = (byte[][]) in.readObject();
                List<String> files = twolev.testSI(token, twolev.getDictionary(), twolev.getArray());
                out.writeObject(files);
                out.flush();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Runs the server
     */
    public void run() {
        runSetup();
        runQuery();
    }

    public static void main(String[] args) {
        new ImageServer(8080).run();
    }

}
