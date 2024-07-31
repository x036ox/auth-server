package com.artur.config;

import com.artur.objectstorage.service.FileSystemObjectStorageService;
import com.artur.objectstorage.service.ObjectStorageService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ObjectStorageConfig {

    @Value("${path.data:data/}")
    String dataPath;

    @Bean
    public ObjectStorageService objectStorageService(){
        return new FileSystemObjectStorageService(dataPath);
    }
}
