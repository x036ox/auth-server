package com.artur.service;

import com.artur.MainTest;
import com.artur.entity.UserEntity;
import com.artur.request.model.UserCreateRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockMultipartFile;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

class UserServiceTest extends MainTest {

    @Autowired
    UserService userService;
    @Value("${path.user-picture}")
    String userPicturePath;
    @Value("${path.data:data/}")
    String dataPath;

    @Test
    void registerUser() throws Exception {
        Path picturePath = null;
        try {
            UserCreateRequest userCreateRequest = new UserCreateRequest(
                    "email@gmail.com",
                    "username",
                    "password",
                    new MockMultipartFile("picture",
                            "default-user.png",
                            "image/png",
                            new ClassPathResource("static/default-user.png").getInputStream())
            );
            UserEntity userEntity = userService.registerUser(userCreateRequest);
            picturePath = Path.of(dataPath + userPicturePath + userEntity.getId() + ".png");
            assertTrue(Files.exists(picturePath));
            assertTrue(Objects.nonNull(userEntity.getId()) && !userEntity.getId().isEmpty());
            assertEquals(userEntity.getEmail(), "email@gmail.com");
            assertNotEquals(userEntity.getPassword(), "password");
        } finally {
            if(Objects.nonNull(picturePath)){
                Files.deleteIfExists(picturePath);
            }
        }
    }
}