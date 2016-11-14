package org.crypto.remote;

import org.crypto.sse.IEX2Lev;
import org.crypto.sse.MMGlobal;
import org.crypto.sse.TextExtractPar;
import org.crypto.sse.TextProc;

import java.io.*;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class ImageClient {

    private String host;
    private int port;
    private List<byte[]> listSK;
    private Socket sock;
    private ObjectInputStream in;
    private ObjectOutputStream out;

    public ImageClient(String host, int port) {
        this.port = port;
        this.host = host;
    }

    public void runSetup() {
        try {
            this.sock = new Socket(host, port);
            // construct a twolev
            MMGlobal twolev = setupTwoLev();
            // send this over the network
            this.out = new ObjectOutputStream(sock.getOutputStream());
            this.in = new ObjectInputStream(sock.getInputStream());
            out.writeObject(twolev);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void runQuery() throws Exception {
        while (true) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Enter your query :");
            String query = reader.readLine();
            byte[][] token = MMGlobal.genToken(listSK.get(0), query);
            Socket sock = new Socket(host, port);
            out.writeObject(token);
            out.flush();
            System.out.println((List<String>) in.readObject());
        }
    }

    public void run() {
        try {
            runSetup();
            runQuery();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public MMGlobal setupTwoLev() throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Enter your password :");

        String pass = keyRead.readLine();

        this.listSK = IEX2Lev.keyGen(256, pass, "salt/salt", 100);

        System.out.println("Enter the relative path name of the folder that contains the files to make searchable");

        String pathName = keyRead.readLine();

        ArrayList<File> listOfFile = new ArrayList<File>();
        TextProc.listf(pathName, listOfFile);

        TextProc.TextProc(false, pathName);

        // The two parameters depend on the size of the dataset. Change
        // accordingly to have better search performance
        int bigBlock = 1000;
        int smallBlock = 100;
        int dataSize = 10000;

        // Construction of the global multi-map
        System.out.println("\nBeginning of Global MM creation \n");
        return MMGlobal.constructEMMParGMM(listSK.get(0), TextExtractPar.lp1, bigBlock, smallBlock,
                dataSize);
    }

    public static void main(String[] args) {
        new ImageClient("localhost", 8080).run();
    }

}
