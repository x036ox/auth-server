package com.artur;

import com.artur.entity.UserEntity;
import com.artur.repository.ClientRepository;
import com.artur.repository.JpaRegisteredClientRepository;
import com.artur.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

@SpringBootApplication
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(UserRepository userRepository, PasswordEncoder passwordEncoder, RegisteredClientRepository clientRepository){
        return args ->{
            if(!userRepository.existsByEmail("admin")) {
                userRepository.save(new UserEntity(null, "admin", passwordEncoder.encode("11"), "ROLE_ADMIN","admin",  Instant.now()));
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