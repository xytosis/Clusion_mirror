package org.crypto.remote;

import org.crypto.sse.MMGlobal;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * This class should be run on a remote server, the client should stream images to it
 */
public class ImageServer {

    private int port;
    private ServerSocket serverSock;
    private MMGlobal twolev;

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
            Socket sock = serverSock.accept();
            try {
                InputStream input  = sock.getInputStream();
                OutputStream output = sock.getOutputStream();
                ObjectInputStream in = new ObjectInputStream(input);
                this.twolev = (MMGlobal) in.readObject();
                sock.close();
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
                Socket sock = serverSock.accept();
                InputStream input = sock.getInputStream();
                ObjectInputStream in = new ObjectInputStream(input);
                byte[][] token = (byte[][]) in.readObject();
                System.out.println(twolev.testSI(token, twolev.getDictionary(), twolev.getArray()));
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
