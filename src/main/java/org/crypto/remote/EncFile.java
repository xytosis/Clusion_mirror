package org.crypto.remote;

import java.io.FileOutputStream;
import java.io.Serializable;

/**
 * A wrapper for an encrypted file that includes its filename and contents
 */
public class EncFile implements Serializable {

    String filename;
    byte[] contents;

    public EncFile(String filename, byte[] contents) {
        this.filename = filename;
        this.contents = contents;
    }

    /**
     * Writes this file out to the directory
     * @param directory the directory to write the file to
     */
    public void save(String directory) {
        try {
            FileOutputStream fos = new FileOutputStream(directory + "/" + filename);
            fos.write(contents);
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
