package com.artur.service;

import com.artur.entity.UserEntity;
import com.artur.exception.AlreadyExistsException;
import com.artur.repository.UserRepository;
import com.artur.request.model.UserCreateRequest;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.Objects;

@Service
public class UserService implements UserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    ObjectStorageService objectStorageService;
    @Value("${path.user-picture}")
    String userPicturePath;
    @Value("${path.default-user-picture}")
    String defaultUserPicturePath;

    @Transactional(rollbackOn = Throwable.class)
    public UserEntity registerUser(UserCreateRequest userCreateRequest) throws Exception {
        if(userRepository.existsByEmail(userCreateRequest.getEmail())){
           throw new AlreadyExistsException("User with this email already exists");
        }

        UserEntity userEntity = userRepository.save(UserEntity.builder()
                .email(userCreateRequest.getEmail())
                .password(passwordEncoder.encode(userCreateRequest.getPassword()))
                .nickname(userCreateRequest.getUsername())
                .authorities("ROLE_USER")
                .dateCreated(Instant.now())
                .build());
        if(Objects.nonNull(userCreateRequest.getPicture())){
            MultipartFile picture = userCreateRequest.getPicture();
            try (InputStream inputStream = picture.getInputStream()){
                String filename = userEntity.getId() + '.' + StringUtils.getFilenameExtension(picture.getOriginalFilename());
                userEntity.setPicture(savePicture(inputStream, filename));
            }
        } else {
            try (InputStream inputStream = new ClassPathResource(defaultUserPicturePath).getInputStream()){
                String filename = userEntity.getId() + '.' + StringUtils.getFilenameExtension(defaultUserPicturePath);
                userEntity.setPicture(savePicture(inputStream, filename));
            }
        }
        return userEntity;
    }

    public InputStream getPicture(String name) throws Exception {
        return objectStorageService.getObject(userPicturePath + name);
    }

    /**Process and save picture. Input stream will not be closed
     * @param inputStream input stream of the picture
     * @param filename name of the picture
     * @return path along which picture should be received
     * @throws Exception - if something went wrong
     */
    private String savePicture(InputStream inputStream, String filename) throws Exception {
        objectStorageService.putObject(inputStream, userPicturePath + filename);
        return "/picture/" + filename;
    }

    public void createAdmin(){
        try {
            UserEntity userEntity = registerUser(new UserCreateRequest(
                    "admin@gmail.com",
                    "admin",
                    "11",
                    null
            ));
            userEntity.setAuthorities("ROLE_ADMIN");
            userRepository.save(userEntity);
        } catch (Exception e) {
            logger.warn("Unable to create admin user", e);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findById(username).orElseGet(() -> userRepository.findByEmail(username));
    }
}
