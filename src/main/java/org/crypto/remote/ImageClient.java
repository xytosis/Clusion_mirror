package org.crypto.remote;

import com.google.common.collect.Multimap;
import org.crypto.sse.*;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.util.*;

import static org.crypto.sse.TextExtractPar.lp1;

public class ImageClient {

    private String host;
    private int port;
    private List<byte[]> listSK;
    private Socket sock;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private String pathName;
    private byte[] encKey;
    private Map<String, String> randomToName;
    private Map<String, String> nameToRandom;
    private byte[] rh2levsk;

    public ImageClient(String host, int port) {
        this.port = port;
        this.host = host;
    }

    public void setup2Lev() {
        try {
            // construct a twolev
            MMGlobal twolev = constructTwoLev();
            // send this over the network
            connectToServer();
            // tell the server we're going to be using 2lev
            out.writeObject("2lev");
            out.flush();
            encryptFiles(pathName);
            sendFiles("temp");
            out.writeObject(twolev);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void setupRH2Lev() {
        try {
            // construct a 2lev rh
            RH2Lev rh2Lev = constructRHTwoLev();
            // send this over the network
            connectToServer();
            out.writeObject("rh2lev");
            out.flush();
            encryptFiles(pathName);
            sendFiles("temp");
            out.writeObject(rh2Lev);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void run2levQuery() throws Exception {
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

    public void runrh2levQuery() throws Exception {
        while (true) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Enter your query :");
            String query = reader.readLine();
            byte[] token1 = CryptoPrimitives.generateCmac(this.rh2levsk, 3+new String());
            byte[][] token2 = MMGlobal.genToken(this.rh2levsk, query);
            out.writeObject(token1);
            out.flush();
            out.writeObject(token2);
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
                out.writeObject(new EncFile(nameToRandom.get(name), contents));
                out.flush();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void run2lev() {
        try {
            setup2Lev();
            run2levQuery();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void runrh2lev() {
        try {
            setupRH2Lev();
            runrh2levQuery();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void connectToServer() throws IOException {
        this.sock = new Socket(host, port);
        this.out = new ObjectOutputStream(sock.getOutputStream());
        this.in = new ObjectInputStream(sock.getInputStream());
    }

    /**
     * We generate random names to files, and then change all the file names
     * in the multimap to hide the response
     * @param lp1
     * @return
     */
    public void hideFileNames(List<String> filenames, Multimap<String, String> lp1) {
        this.nameToRandom = new HashMap<>();
        this.randomToName = new HashMap<>();
        for (String name: filenames) {
            String randName = randomString();
            nameToRandom.put(name, randName);
            randomToName.put(randName, name);
        }
        for (String key : lp1.keySet()) {
            Collection<String> hiding = new ArrayList<>();
            for (String s : lp1.get(key)) {
                hiding.add(nameToRandom.get(s));
            }
            lp1.replaceValues(key, hiding);
        }
    }

    /**
     * Generate a 10 character alphanumeric string
     * @return
     */
    private String randomString() {
        String chars = "abcdefghijklmnopqrstuvwxyz1234567890";
        StringBuilder stringBuilder = new StringBuilder();
        Random rnd = new Random();
        while (stringBuilder.length() < 10) {
            int index = rnd.nextInt(chars.length());
            stringBuilder.append(chars.charAt(index));
        }
        return stringBuilder.toString();
    }

    public MMGlobal constructTwoLev() throws Exception {
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

        // obfuscate file names in multimap
        List<String> fileNames = new ArrayList<>();
        listOfFile.forEach(f -> fileNames.add(f.getName()));
        hideFileNames(fileNames, lp1);

        // Construction of the global multi-map
        System.out.println("\nBeginning of Global MM creation \n");
        return MMGlobal.constructEMMParGMM(listSK.get(0), lp1, bigBlock, smallBlock,
                dataSize);
    }

    public RH2Lev constructRHTwoLev() throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Enter your password :");

        String pass	=	keyRead.readLine();

        this.rh2levsk = MMGlobal.keyGenSI(256, pass, "salt/salt", 100);
        this.listSK = IEX2Lev.keyGen(256, pass, "salt/salt", 100);

        // set up the key we use to encrypt the files
        this.encKey = new byte[16];
        byte[] temp = this.listSK.get(1);
        for (int i = 0; i < 16; i++) {
            encKey[i] = temp[i];
        }

        System.out.println("Enter the relative path name of the folder that contains the files to make searchable");

        this.pathName = keyRead.readLine();

        ArrayList<File> listOfFile=new ArrayList<File>();
        TextProc.listf(pathName, listOfFile);

        TextProc.TextProc(false, pathName);

        //The two parameters depend on the size of the dataset. Change accordingly to have better search performance
        int bigBlock	=	1000;
        int smallBlock	=	100;
        int dataSize	=	10000;

        // obfuscate file names in multimap
        List<String> fileNames = new ArrayList<>();
        listOfFile.forEach(f -> fileNames.add(f.getName()));
        hideFileNames(fileNames, lp1);

        //Construction of the global multi-map
        System.out.println("\nBeginning of Global MM creation \n");

        RH2Lev.master = this.rh2levsk;
        RH2Lev rh2Lev = RH2Lev.constructEMMParGMM(this.rh2levsk, lp1, bigBlock, smallBlock, dataSize);
        RH2Lev.master = null; // erase sk
        return rh2Lev;
    }

    public static void main(String[] args) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Select the encryption scheme - (1) 2lev (2) rh2lev: ");
            String response = reader.readLine();
            if (response.equals("1")) {
                new ImageClient("localhost", 8080).run2lev();
            } else if (response.equals("2")) {
                new ImageClient("localhost", 8080).runrh2lev();
            } else {
                System.out.println("Incorrect response");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
