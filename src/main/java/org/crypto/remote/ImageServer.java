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
            } else if (scheme.equals("iex2lev")) {
                runIEX2LevSetup();
                runIEX2LevQuery();
            } else if (scheme.equals("iexrh2lev")) {
                runIEXRH2LevSetup();
                runIEXRH2LevQuery();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new ImageServer(8080).run();
    }

}
