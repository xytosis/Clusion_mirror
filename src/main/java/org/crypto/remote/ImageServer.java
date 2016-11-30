package org.crypto.remote;

import org.crypto.sse.*;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
    private IEX2Lev disj;
    private IEXRH2Lev disjrh;
    private String scheme;

    public ImageServer(int port) {
        this.port = port;
        try {
            this.serverSock = new ServerSocket(port);
        } catch (IOException e) {
            System.out.println("Could not build socket");
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

    public void runrh2levSetup() {
        try {
            getFiles();
            this.rh2Lev = (RH2Lev) in.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void runIEX2LevSetup() {
        try {
            getFiles();
            this.disj = (IEX2Lev) in.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void runIEXRH2LevSetup() {
        try {
            getFiles();
            this.disjrh = (IEXRH2Lev) in.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

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

    public void runIEX2LevQuery() {
        try {
            while (true) {
                Set<String> tmpBol = (Set<String>) in.readObject();
                List<List<TokenDIS>> allTokenTMP = (List<List<TokenDIS>>) in.readObject();
                Integer boolLength = (Integer) in.readObject();
                Integer bool0Length = (Integer) in.readObject();
                int tok = 0;
                for (int i = 1; i < boolLength; i++) {
                    Set<String> finalResult = new HashSet<>();
                    for (int k = 0; k < bool0Length; k++) {
                        List<TokenDIS> tokenTMP = allTokenTMP.get(tok);

                        Set<String> result = new HashSet<String>(MMGlobal.testSI(tokenTMP.get(0).getTokenMMGlobal(),
                                disj.getGlobalMM().getDictionary(), disj.getGlobalMM().getArray()));
                        if (!(tmpBol.size() == 0)) {
                            List<Integer> temp = new ArrayList<Integer>(
                                    disj.getDictionaryForMM().get(new String(tokenTMP.get(0).getTokenDIC())));

                            if (!(temp.size() == 0)) {
                                int pos = temp.get(0);

                                for (int j = 0; j < tokenTMP.get(0).getTokenMMLocal().size(); j++) {

                                    Set<String> temporary = new HashSet<String>();
                                    List<String> tempoList = MMGlobal.testSI(tokenTMP.get(0).getTokenMMLocal().get(j),
                                            disj.getLocalMultiMap()[pos].getDictionary(),
                                            disj.getLocalMultiMap()[pos].getArray());

                                    if (!(tempoList == null)) {
                                        temporary = new HashSet<String>(
                                                MMGlobal.testSI(tokenTMP.get(0).getTokenMMLocal().get(j),
                                                        disj.getLocalMultiMap()[pos].getDictionary(),
                                                        disj.getLocalMultiMap()[pos].getArray()));
                                    }

                                    finalResult.addAll(temporary);

                                    if (tmpBol.isEmpty()) {
                                        break;
                                    }

                                }
                            }

                        }
                        tok++;
                    }
                    tmpBol.retainAll(finalResult);
                }
                // send over the files
                out.writeObject(new Integer(tmpBol.size()));
                out.flush();
                for (String filename : tmpBol) {
                    File file = new File("encrypted/" + filename);
                    out.writeObject(new EncFile(file.getName(), Files.readAllBytes(file.toPath())));
                    out.flush();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void runIEXRH2LevQuery() {
        try {
            while (true) {
                Set<String> tmpBol = (Set<String>) in.readObject();
                List<List<TokenDIS>> allTokenTMP = (List<List<TokenDIS>>) in.readObject();
                byte[] cmac = (byte[]) in.readObject();
                Integer boolLength = (Integer) in.readObject();
                Integer bool0Length = (Integer) in.readObject();
                int tok = 0;
                for (int i = 1; i < boolLength; i++) {
                    Set<String> finalResult = new HashSet<String>();
                    for (int k = 0; k < bool0Length; k++) {
                        List<TokenDIS> tokenTMP = allTokenTMP.get(tok);
                        Set<String> result = new HashSet<String>(RH2Lev.testSI(tokenTMP.get(0).getTokenMMGlobal(),
                                disjrh.getGlobalMM().getDictionary(), disjrh.getGlobalMM().getArray()));

                        if (!(tmpBol.size() == 0)) {
                            List<Integer> temp = new ArrayList<Integer>(
                                    disjrh.getDictionaryForMM().get(new String(tokenTMP.get(0).getTokenDIC())));
                            if (!(temp.size() == 0)) {
                                int pos = temp.get(0);

                                for (int j = 0; j < tokenTMP.get(0).getTokenMMLocal().size(); j++) {

                                    Set<String> temporary = new HashSet<String>();
                                    List<String> tempoList = RH2Lev.testSI(tokenTMP.get(0).getTokenMMLocal().get(j),
                                            disjrh.getLocalMultiMap()[pos].getDictionary(),
                                            disjrh.getLocalMultiMap()[pos].getArray());

                                    if (!(tempoList == null)) {
                                        temporary = new HashSet<String>(
                                                RH2Lev.testSI(tokenTMP.get(0).getTokenMMLocal().get(j),
                                                        disjrh.getLocalMultiMap()[pos].getDictionary(),
                                                        disjrh.getLocalMultiMap()[pos].getArray()));
                                    }

                                    finalResult.addAll(temporary);

                                    if (tmpBol.isEmpty()) {
                                        break;
                                    }

                                }
                            }

                        }
                    }
                    tmpBol.retainAll(finalResult);
                    tok++;
                }
                // send over the files
                List<String> files = RH2Lev.resolve(cmac, new ArrayList<>(tmpBol));
                out.writeObject(new Integer(files.size()));
                out.flush();
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
        acceptConnection();
        return (String) in.readObject();
    }

    public void acceptConnection() throws IOException {
        this.sock = serverSock.accept();
        InputStream input  = sock.getInputStream();
        this.in = new ObjectInputStream(input);
        OutputStream output = sock.getOutputStream();
        this.out = new ObjectOutputStream(output);
    }

    /**
     * Runs the server
     */
    public void run() {
        try {
            this.scheme = doHandShake();
            switch (scheme) {
                case "2lev":
                    run2levSetup();
                    persist();
                    run2levQuery();
                    break;
                case "rh2lev":
                    runrh2levSetup();
                    persist();
                    runrh2levQuery();
                    break;
                case "iex2lev":
                    runIEX2LevSetup();
                    persist();
                    runIEX2LevQuery();
                    break;
                case "iexrh2lev":
                    runIEXRH2LevSetup();
                    persist();
                    runIEXRH2LevQuery();
                    break;
                default:
                    System.out.println("could not find valid scheme");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void runFromFile(String scheme, String filepath) throws IOException, ClassNotFoundException {
        ObjectInputStream input = new ObjectInputStream(new FileInputStream(filepath));
        switch (scheme) {
            case "1":
                this.twolev = (MMGlobal) input.readObject();
                acceptConnection();
                run2levQuery();
                break;
            case "2":
                this.rh2Lev = (RH2Lev) input.readObject();
                acceptConnection();
                runrh2levQuery();
                break;
            case "3":
                this.disj = (IEX2Lev) input.readObject();
                acceptConnection();
                runIEX2LevQuery();
                break;
            case "4":
                this.disjrh = (IEXRH2Lev) input.readObject();
                acceptConnection();
                runIEXRH2LevQuery();
                break;
            default:
                System.out.println("could not find valid scheme");
        }
        input.close();
    }

    /**
     * Persists the EDS into memory
     */
    public void persist() throws IOException {
        ObjectOutputStream fout = new ObjectOutputStream(new FileOutputStream(scheme));
        switch (scheme) {
            case "2lev":
                fout.writeObject(this.twolev);
                break;
            case "rh2lev":
                fout.writeObject(this.rh2Lev);
                break;
            case "iex2lev":
                fout.writeObject(this.disj);
                break;
            case "iexrh2lev":
                fout.writeObject(this.disjrh);
                break;
            default:
                System.out.println("could not find valid scheme");
        }
        fout.close();
    }

    public static void main(String[] args) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Enter directory of preloaded EDS or press enter to skip: ");
            String resp = reader.readLine();
            if (resp.isEmpty()) {
                // run from scratch
                new ImageServer(8080).run();
            } else {
                // load in a file and listen for queries
                System.out.println("Select the encryption scheme - (1) 2lev (2) rh2lev (3) iex2lev (4) iexrh2lev: ");
                new ImageServer(8080).runFromFile(reader.readLine(), resp);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
