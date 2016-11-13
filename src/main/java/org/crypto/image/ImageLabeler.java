package org.crypto.image;

import com.ibm.watson.developer_cloud.alchemy.v1.AlchemyVision;
import com.ibm.watson.developer_cloud.alchemy.v1.model.ImageKeywords;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class uses AlchemyVision to get keywords from images
 */
public class ImageLabeler {

    private static AlchemyVision service = new AlchemyVision();

    public ImageLabeler(String apiKey) {
        service.setApiKey(apiKey);
    }

    /**
     * Takes a directory name and maps the file names to the list of keywords
     * @param directory the directory of images
     * @return multimap of filenames to labels
     */
    public Map<String, List<String>> labelImages(String directory) {
        File imageFolder = new File(directory);
        File[] imageList = imageFolder.listFiles();
        Map<String, List<String>> labels = new HashMap<>();
        for (File image: imageList) {
            List<String> keywords = getKeywords(image);
            String filename = image.getName();
            System.out.println(filename + " " + keywords);
            labels.put(filename, keywords);
        }
        return labels;
    }

    /**
     * Takes in a single image and returns the labels associated with that image
     * @param image the image
     * @return labels of a single image
     * @throws NumberFormatException
     */
    public List<String> getKeywords(File image) {
        try {
            ImageKeywords keywords = service.getImageKeywords(image, false, false).execute();
            List<String> keywordTexts = new ArrayList<>();
            keywords.getImageKeywords().forEach(i -> keywordTexts.add(i.getText()));
            return keywordTexts;
        } catch (NumberFormatException e) {
            System.out.println("Image has no labels");
            return new ArrayList<>();
        }
    }

}