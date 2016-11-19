package org.crypto.remote;

import org.crypto.sse.*;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class ImageClient {

    private String host;
    private int port;
    private List<byte[]> listSK;
    private Socket sock;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private String pathName;
    private byte[] encKey;

    public ImageClient(String host, int port) {
        this.port = port;
        this.host = host;
    }

    public void runSetup() {
        try {
            // construct a twolev
            MMGlobal twolev = setupTwoLev();
            // send this over the network
            this.sock = new Socket(host, port);
            this.out = new ObjectOutputStream(sock.getOutputStream());
            this.in = new ObjectInputStream(sock.getInputStream());
            encryptFiles(pathName);
            sendFiles("temp");
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
            out.writeObject(token);
            out.flush();
            Integer numFiles = (Integer) in.readObject();
            for (int i = 0; i < numFiles; i++) {
                EncFile f = (EncFile) in.readObject();
                CryptoPrimitives.decryptAES_CTR("query_output", f.contents, encKey);
            }
        }
    }

    public void encryptFiles(String directory) {
        File folder = new File(directory);
        File[] files = folder.listFiles();

        try {
            for (File f: files) {
                CryptoPrimitives.encryptAES_CTR("temp", f.getName(), f.getParent(),
                        f.getName(), encKey, CryptoPrimitives.randomBytes(16));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Sends over the encrypted files in a directory
     */
    public void sendFiles(String directory) {
        File folder = new File(directory);
        File[] files = folder.listFiles();
        try {
            // write how many files we are to expect
            out.writeObject(new Integer(files.length));
            out.flush();
            // now we write each file
            for (File file : files) {
                byte[] contents = Files.readAllBytes(file.toPath());
                String name = file.getName();
                out.writeObject(new EncFile(name, contents));
                out.flush();
            }
        } catch (Exception e) {
            e.printStackTrace();
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

        // set up the key we use to encrypt the files
        this.encKey = new byte[16];
        byte[] temp = this.listSK.get(1);
        for (int i = 0; i < 16; i++) {
            encKey[i] = temp[i];
        }

        System.out.println("Enter the relative path name of the folder that contains the files to make searchable");

        this.pathName = keyRead.readLine();

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

    public void setupRHTwoLev() throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Enter your password :");

        String pass	=	keyRead.readLine();

        byte[] sk	=	MMGlobal.keyGenSI(256, pass, "salt/salt", 100);


        System.out.println("Enter the relative path name of the folder that contains the files to make searchable");

        String pathName	=	keyRead.readLine();

        ArrayList<File> listOfFile=new ArrayList<File>();
        TextProc.listf(pathName, listOfFile);

        TextProc.TextProc(false, pathName);

        //The two parameters depend on the size of the dataset. Change accordingly to have better search performance
        int bigBlock	=	1000;
        int smallBlock	=	100;
        int dataSize	=	10000;

        //Construction of the global multi-map
        System.out.println("\nBeginning of Global MM creation \n");

        RH2Lev.master = sk;

        RH2Lev twolev	=	RH2Lev.constructEMMParGMM(sk, TextExtractPar.lp1, bigBlock, smallBlock, dataSize);
    }

    public static void main(String[] args) {
        new ImageClient("localhost", 8080).run();
    }

}
