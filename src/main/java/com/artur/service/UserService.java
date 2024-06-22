package com.artur.service;

import com.artur.entity.UserEntity;
import com.artur.exception.AlreadyExistsException;
import com.artur.repository.UserRepository;
import com.artur.request.model.UserCreateRequest;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class UserService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;

    @Transactional(rollbackOn = Exception.class)
    public UserEntity registerUser(UserCreateRequest userCreateRequest) throws Exception {
        if(userRepository.existsByEmail(userCreateRequest.getEmail())){
           throw new AlreadyExistsException("User with this email already exists");
        }
        UserEntity userEntity = userRepository.save(UserEntity.builder()
                .email(userCreateRequest.getEmail())
                .password(passwordEncoder.encode(userCreateRequest.getPassword()))
                .username(userCreateRequest.getUsername())
                .authority("ROLE_USER")
                .dateCreated(Instant.now())
                .build());
        return userEntity;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username);
    }
}
