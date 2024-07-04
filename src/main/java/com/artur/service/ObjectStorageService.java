package com.artur.service;

import com.artur.exception.NotFoundException;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public interface ObjectStorageService {

    void putObject(InputStream objectInputStream, String objectName) throws Exception;

    void uploadObject(File object, String pathname) throws Exception;

    void putFolder(String folderName) throws Exception;

    List<?> listFiles(String prefix) throws Exception;

    InputStream getObject(String objectName) throws Exception;

    void removeObject(String objectName) throws Exception;

    void removeFolder(String prefix) throws Exception;
}
