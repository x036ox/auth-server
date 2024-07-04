package com.artur.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.FileSystemUtils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@Service
public class FileSystemObjectStorageService implements ObjectStorageService{
    private static final Logger logger = LoggerFactory.getLogger(FileSystemObjectStorageService.class);

    @Value("${path.data:data/}")
    private String DATA_PATH;

    @Override
    public void removeFolder(String prefix) throws IOException {
        FileSystemUtils.deleteRecursively(Path.of(prefix));
    }

    @Override
    public void putObject(InputStream inputStream, String objectName) throws IOException {
        Assert.notNull(inputStream, "Input stream can not be null");
        Assert.notNull(objectName, "Name can not be null");
        Assert.isTrue(objectName.contains("."), "Name should be with extension");

        if(objectName.contains("/")){
            putFolder(objectName.substring(0, objectName.lastIndexOf("/")));
        }
        File file = new File(DATA_PATH + objectName);
        try (inputStream; FileOutputStream fileOutputStream = new FileOutputStream(file)) {
            inputStream.transferTo(fileOutputStream);
        }
    }

    @Override
    public void uploadObject(File object, String pathname) throws Exception {
        putObject(new FileInputStream(object), pathname);
    }

    @Override
    public void putFolder(String prefix) {
        Path path = Path.of(DATA_PATH + prefix);
        if(Files.notExists(path)){
            try {
                Files.createDirectories(path);
            } catch (IOException e) {
                logger.error("Could not create directory [ " + path + " ]", e);
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public List<?> listFiles(String prefix) throws Exception {
        File directory = new File(prefix);
        if(!directory.isDirectory()){
            throw new IllegalArgumentException("Could not get list of file because [ " + prefix + " ] is not a directory");
        }
        return Arrays.asList(Objects.requireNonNull(directory.listFiles()));
    }

    @Override
    public InputStream getObject(String objectName) throws Exception {
        return new FileInputStream(DATA_PATH + objectName);
    }

    @Override
    public void removeObject(String objectName) throws Exception {
        Files.deleteIfExists(Path.of(DATA_PATH + objectName));
    }
}
