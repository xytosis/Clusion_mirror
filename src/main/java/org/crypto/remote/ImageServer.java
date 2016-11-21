package org.crypto.remote;

import org.crypto.sse.MMGlobal;
import org.crypto.sse.RH2Lev;

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
    private RH2Lev rh2Lev;

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
    public void run2levSetup() {
        // we do the initial "handshake", where we send over the encrypted files and serialized data structure
        try {
            getFiles();
            this.twolev = (MMGlobal) in.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            System.out.println("class not found");
        } catch (Exception e) {
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
    public void run2levQuery() {
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

    public void runrh2levSetup() {
        try {
            getFiles();
            this.rh2Lev = (RH2Lev) in.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void runrh2levQuery() {
        try {
            while (true) {
                byte[] token1 = (byte[]) in.readObject();
                byte[][] token2 = (byte[][]) in.readObject();
                List<String> files = rh2Lev.resolve(token1,
                        rh2Lev.testSI(token2, rh2Lev.getDictionary(), rh2Lev.getArray()));
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

    public String doHandShake() throws IOException, ClassNotFoundException {
        this.sock = serverSock.accept();
        InputStream input  = sock.getInputStream();
        this.in = new ObjectInputStream(input);
        OutputStream output = sock.getOutputStream();
        this.out = new ObjectOutputStream(output);
        return (String) in.readObject();
    }

    /**
     * Runs the server
     */
    public void run() {
        try {
            String scheme = doHandShake();
            if (scheme.equals("2lev")) {
                run2levSetup();
                run2levQuery();
            } else if (scheme.equals("rh2lev")) {
                runrh2levSetup();
                runrh2levQuery();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new ImageServer(8080).run();
    }

}
