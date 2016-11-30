package org.crypto.remote;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import org.crypto.sse.*;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.SecureRandom;
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
    private IEX2Lev iex2Lev;
    private IEXRH2Lev iexrh2Lev;

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

    public void setupIEX2Lev() {
        try {
            // build a iex2lev
            this.iex2Lev = constructIEX2Lev();
            // send this over the network
            connectToServer();
            out.writeObject("iex2lev");
            out.flush();
            encryptFiles(pathName);
            sendFiles("temp");
            out.writeObject(iex2Lev);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void setupIEXRH2Lev() {
        try {
            this.iexrh2Lev = constructIEXRH2Lev();
            connectToServer();
            out.writeObject("iexrh2lev");
            out.flush();
            encryptFiles(pathName);
            sendFiles("temp");
            out.writeObject(iexrh2Lev);
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

    public void runIEX2LevQuery() throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            // we first ask for the user input
            System.out.println("How many disjunctions? ");
            int numDisjunctions = Integer.parseInt(keyRead.readLine());

            // Storing the CNF form
            String[][] bool = new String[numDisjunctions][];
            for (int i = 0; i < numDisjunctions; i++) {
                System.out.println("Enter the keywords of the disjunctions ");
                bool[i] = keyRead.readLine().split(" ");
            }

            // Generate the IEX token
            List<String> searchBol = new ArrayList<String>();
            for (int i = 0; i < bool[0].length; i++) {
                searchBol.add(bool[0][i]);
            }

            Set<String> tmpBol = IEX2Lev.testDIS(IEX2Lev.genToken(listSK, searchBol), this.iex2Lev);
            List<List<TokenDIS>> allTokenTMP = new ArrayList<>();
            for (int i = 1; i < bool.length; i++) {
                for (int k = 0; k < bool[0].length; k++) {
                    List<String> searchTMP = new ArrayList<String>();
                    searchTMP.add(bool[0][k]);
                    for (int r = 0; r < bool[i].length; r++) {
                        searchTMP.add(bool[i][r]);
                    }
                    allTokenTMP.add(IEX2Lev.genToken(listSK, searchTMP));
                }
            }
            // now we send these two things over to the server
            out.writeObject(tmpBol);
            out.flush();
            out.writeObject(allTokenTMP);
            out.flush();
            out.writeObject(new Integer(bool.length));
            out.flush();
            out.writeObject(new Integer(bool[0].length));
            out.flush();

            // now we read in the files we have queried
            Integer numFiles = (Integer) in.readObject();
            for (int i = 0; i < numFiles; i++) {
                EncFile f = (EncFile) in.readObject();
                CryptoPrimitives.decryptAES_CTR("query_output", f.contents, encKey);
            }
        }
    }

    public void runIEXRH2LevQuery() throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            System.out.println("How many disjunctions? ");
            int numDisjunctions = Integer.parseInt(keyRead.readLine());

            // Storing the CNF form
            String[][] bool = new String[numDisjunctions][];
            for (int i = 0; i < numDisjunctions; i++) {
                System.out.println("Enter the keywords of the disjunctions ");
                bool[i] = keyRead.readLine().split(" ");
            }

            // Generate the IEX token
            List<String> searchBol = new ArrayList<String>();
            for (int i = 0; i < bool[0].length; i++) {
                searchBol.add(bool[0][i]);
            }

            Set<String> tmpBol = IEXRH2Lev.testDIS(IEXRH2Lev.genToken(listSK, searchBol), this.iexrh2Lev);
            List<List<TokenDIS>> allTokenTMP = new ArrayList<>();
            for (int i = 1; i < bool.length; i++) {
                for (int k = 0; k < bool[0].length; k++) {
                    List<String> searchTMP = new ArrayList<String>();
                    searchTMP.add(bool[0][k]);
                    for (int r = 0; r < bool[i].length; r++) {
                        searchTMP.add(bool[i][r]);
                    }
                    allTokenTMP.add(IEXRH2Lev.genToken(listSK, searchTMP));
                }
            }
            // now we send these two things over to the server
            out.writeObject(tmpBol);
            out.flush();
            out.writeObject(allTokenTMP);
            out.flush();
            out.writeObject(CryptoPrimitives.generateCmac(listSK.get(0), 3 + new String()));
            out.flush();
            out.writeObject(new Integer(bool.length));
            out.flush();
            out.writeObject(new Integer(bool[0].length));
            out.flush();

            // now we read in the files we have queried
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

    /**
     * The server is running a pre-existing two lev
     */
    public void login2lev() throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Enter your password :");

        String pass = keyRead.readLine();

        this.listSK = IEX2Lev.keyGen(256, pass, "salt/saltInvIX", 100);

        // set up the key we use to encrypt the files
        this.encKey = new byte[16];
        byte[] temp = this.listSK.get(1);
        for (int i = 0; i < 16; i++) {
            encKey[i] = temp[i];
        }

        connectToServer();
        run2levQuery();
    }

    public void runrh2lev() {
        try {
            setupRH2Lev();
            runrh2levQuery();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void loginrh2lev() throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Enter your password :");

        String pass	=	keyRead.readLine();

        this.rh2levsk = MMGlobal.keyGenSI(256, pass, "salt/saltInvIX", 100);
        this.listSK = IEX2Lev.keyGen(256, pass, "salt/saltInvIX", 100);

        // set up the key we use to encrypt the files
        this.encKey = new byte[16];
        byte[] temp = this.listSK.get(1);
        for (int i = 0; i < 16; i++) {
            encKey[i] = temp[i];
        }
        connectToServer();
        runrh2levQuery();
    }

    public void runiex2lev() {
        try {
            setupIEX2Lev();
            runIEX2LevQuery();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void loginiex2lev(String filepath) throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Enter your password :");

        String pass = keyRead.readLine();

        this.listSK = IEX2Lev.keyGen(256, pass, "salt/saltInvIX", 100);

        this.encKey = new byte[16];
        byte[] temp = this.listSK.get(1);
        for (int i = 0; i < 16; i++) {
            encKey[i] = temp[i];
        }

        // load in the client side iex2lev
        ObjectInputStream input = new ObjectInputStream(new FileInputStream(filepath));
        this.iex2Lev = (IEX2Lev) input.readObject();
        input.close();

        connectToServer();
        runIEX2LevQuery();
    }

    public void runiexrh2lev() {
        try {
            setupIEXRH2Lev();
            runIEXRH2LevQuery();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void loginiexrh2lev(String filepath) throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Enter your password :");

        String pass = keyRead.readLine();

        this.listSK = IEX2Lev.keyGen(256, pass, "salt/saltInvIX", 100);
        this.encKey = new byte[16];
        byte[] temp = this.listSK.get(1);
        for (int i = 0; i < 16; i++) {
            encKey[i] = temp[i];
        }

        // load in the client side iexrh2lev
        ObjectInputStream input = new ObjectInputStream(new FileInputStream(filepath));
        this.iexrh2Lev = (IEXRH2Lev) input.readObject();
        input.close();

        connectToServer();
        runIEXRH2LevQuery();
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
    public void hideFileNames(List<String> filenames, Multimap<String, String> lp1,
                              Multimap<String, String> lp2) {
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
        Multimap<String, String> templp2 = ArrayListMultimap.create();
        for (String key : lp2.keySet()) {
            Collection<String> keywords = lp2.get(key);
            templp2.putAll(nameToRandom.get(key), keywords);
        }
        TextExtractPar.lp2 = templp2;
    }

    /**
     * Generate a 10 character alphanumeric string
     * TODO: just generate a random number and transform it to a string
     * @return
     */
    private String randomString() {
        String chars = "abcdefghijklmnopqrstuvwxyz1234567890";
        StringBuilder stringBuilder = new StringBuilder();
        SecureRandom rnd = new SecureRandom();
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

        this.listSK = IEX2Lev.keyGen(256, pass, "salt/saltInvIX", 100);

        // set up the key we use to encrypt the files
        this.encKey = new byte[16];
        byte[] temp = this.listSK.get(1);
        for (int i = 0; i < 16; i++) {
            encKey[i] = temp[i];
        }

        System.out.println("Enter the relative path name of the folder that contains the files to make searchable");

        this.pathName = keyRead.readLine();

        ArrayList<File> listOfFile = new ArrayList<>();
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
        hideFileNames(fileNames, lp1, TextExtractPar.lp2);
        System.out.println(lp1);

        // Construction of the global multi-map
        System.out.println("\nBeginning of Global MM creation \n");
        return MMGlobal.constructEMMParGMM(listSK.get(0), lp1, bigBlock, smallBlock,
                dataSize);
    }

    public RH2Lev constructRHTwoLev() throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Enter your password :");

        String pass	=	keyRead.readLine();

        this.rh2levsk = MMGlobal.keyGenSI(256, pass, "salt/saltInvIX", 100);
        this.listSK = IEX2Lev.keyGen(256, pass, "salt/saltInvIX", 100);

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
        hideFileNames(fileNames, TextExtractPar.lp1, TextExtractPar.lp2);

        //Construction of the global multi-map
        System.out.println("\nBeginning of Global MM creation \n");

        RH2Lev.master = this.rh2levsk;
        RH2Lev rh2Lev = RH2Lev.constructEMMParGMM(this.rh2levsk, TextExtractPar.lp1, bigBlock, smallBlock, dataSize);
        RH2Lev.master = null; // erase sk
        return rh2Lev;
    }

    public IEX2Lev constructIEX2Lev() throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Enter your password :");

        String pass = keyRead.readLine();

        this.listSK = IEX2Lev.keyGen(256, pass, "salt/saltInvIX", 100);

        System.out.println("Enter the relative path name of the folder that contains the files to make searchable: ");

        this.pathName = keyRead.readLine();
        this.encKey = new byte[16];
        byte[] temp = this.listSK.get(1);
        for (int i = 0; i < 16; i++) {
            encKey[i] = temp[i];
        }

        // Creation of different files based on selectivity
        // Selectivity was computed in an inclusive way. All files that include
        // x(i+1) include necessarily xi
        // This is used for benchmarking and can be taken out of the code

        ArrayList<File> listOfFile = new ArrayList<File>();
        TextProc.listf(pathName, listOfFile);
        TextProc.TextProc(false, pathName);


        List<String> fileNames = new ArrayList<>();
        listOfFile.forEach(f -> fileNames.add(f.getName()));
        hideFileNames(fileNames, TextExtractPar.lp1, TextExtractPar.lp2);

        int bigBlock = 1000;
        int smallBlock = 100;

        IEX2Lev iex =  IEX2Lev.setupDISJ(listSK, TextExtractPar.lp1, TextExtractPar.lp2, bigBlock, smallBlock, 0);

        // save the iex2lev construction to the client for future loading
        ObjectOutputStream fout = new ObjectOutputStream(new FileOutputStream("iex2lev_client"));
        fout.writeObject(iex);
        fout.close();
        return iex;
    }

    public IEXRH2Lev constructIEXRH2Lev() throws Exception {
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Enter your password :");

        String pass = keyRead.readLine();

        this.listSK = IEX2Lev.keyGen(256, pass, "salt/saltInvIX", 100);
        this.encKey = new byte[16];
        byte[] temp = this.listSK.get(1);
        for (int i = 0; i < 16; i++) {
            encKey[i] = temp[i];
        }

        System.out.println("Enter the relative path name of the folder that contains the files to make searchable");

        this.pathName = keyRead.readLine();

        // Creation of different files based on selectivity
        // Selectivity was computed in an inclusive way. All files that include
        // x(i+1) include necessarily xi
        // This is used for benchmarking and can be taken out of the code

        ArrayList<File> listOfFile = new ArrayList<File>();
        TextProc.listf(pathName, listOfFile);

        TextProc.TextProc(false, pathName);

        int bigBlock = 1000;
        int smallBlock = 100;


        RH2Lev.master = listSK.get(0);
        List<String> fileNames = new ArrayList<>();
        listOfFile.forEach(f -> fileNames.add(f.getName()));
        hideFileNames(fileNames, TextExtractPar.lp1, TextExtractPar.lp2);
        System.out.println(TextExtractPar.lp1);
        System.out.println(TextExtractPar.lp2);

        IEXRH2Lev iexrh = IEXRH2Lev.setupDISJ(listSK, TextExtractPar.lp1, TextExtractPar.lp2, bigBlock, smallBlock, 0);

        // save the iex2lev construction to the client for future loading
        ObjectOutputStream fout = new ObjectOutputStream(new FileOutputStream("iexrh2lev_client"));
        fout.writeObject(iexrh);
        fout.close();

        return iexrh;
    }

    public static void main(String[] args) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Select the encryption scheme - (1) 2lev (2) rh2lev (3) iex2lev (4) iexrh2lev: ");
            String response = reader.readLine();
            ImageClient cli = new ImageClient("localhost", 8080);
            System.out.println("Is the server running existing EDS - (1) no (2) yes");
            String mode = reader.readLine();
            if (mode.equals("1")) {
                if (response.equals("1")) {
                    cli.run2lev();
                } else if (response.equals("2")) {
                    cli.runrh2lev();
                } else if (response.equals("3")) {
                    cli.runiex2lev();
                } else if (response.equals("4")) {
                    cli.runiexrh2lev();
                } else {
                    System.out.println("Incorrect response");
                }
            } else if (mode.equals("2")) {
                if (response.equals("1")) {
                    cli.login2lev();
                } else if (response.equals("2")) {
                    cli.loginrh2lev();
                } else if (response.equals("3")) {
                    System.out.println("Enter the path to the clientside iex2lev");
                    cli.loginiex2lev(reader.readLine());
                } else if (response.equals("4")) {
                    System.out.println("Enter the path to the clientside iexrh2lev");
                    cli.loginiexrh2lev(reader.readLine());
                } else {
                    System.out.println("Incorrect response");
                }
            } else {
                System.out.println("Please choose (1) or (2)");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
