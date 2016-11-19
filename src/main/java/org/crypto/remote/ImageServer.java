package org.crypto.remote;

import org.crypto.sse.MMGlobal;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
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
        // we do the initial "handshake", where we send over the encrypted files and serialized data structure
        try {
            this.sock = serverSock.accept();
            try {
                InputStream input  = sock.getInputStream();
                this.in = new ObjectInputStream(input);
                OutputStream output = sock.getOutputStream();
                this.out = new ObjectOutputStream(output);
                getFiles();
                this.twolev = (MMGlobal) in.readObject();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                System.out.println("class not found");
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void getFiles() throws Exception {
        // make our directory to store the encrypted files
        File dir = new File("encrypted");
        if (Files.notExists(dir.toPath())) {
            dir.mkdir();
        }
        // get the number of files to read
        Integer numFiles = (Integer) this.in.readObject();
        for (int i = 0; i < numFiles; i++) {
            EncFile f = (EncFile) this.in.readObject();
            f.save("encrypted");
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
                /*out.writeObject(files);
                out.flush();*/
                // write the number of files we're sending over
                out.writeObject(new Integer(files.size()));
                out.flush();
                // send over the files
                for (String filename : files) {
                    File file = new File("encrypted/" + filename);
                    out.writeObject(new EncFile(file.getName(), Files.readAllBytes(file.toPath())));
                    out.flush();
                }
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
