package com.artur;

import com.artur.repository.UserRepository;
import com.artur.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Objects;
import java.util.UUID;

@SpringBootApplication
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(UserRepository userRepository, UserService userService,  PasswordEncoder passwordEncoder, RegisteredClientRepository clientRepository){
        return args ->{
            if(!userRepository.existsByEmail("admin@gmail.com")) {
                userService.createAdmin();
            }
            if(Objects.isNull(clientRepository.findByClientId("registrar-client"))){
                RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("registrar-client")
                        .clientSecret(passwordEncoder.encode("admin"))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .scope("client.read")
                        .scope("client.create")
                        .build();
                clientRepository.save(client);
            }
        };
    }
}