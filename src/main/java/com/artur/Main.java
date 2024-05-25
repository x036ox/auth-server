package com.artur;

import com.artur.entity.UserEntity;
import com.artur.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Date;

@SpringBootApplication
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(UserRepository userRepository, PasswordEncoder passwordEncoder){
        return args ->{
            if(!userRepository.existsById(8L)){
                userRepository.save(new UserEntity(null, "admin", passwordEncoder.encode("11"),"ROLE_ADMIN", Date.from(Instant.now())));
            }
            System.out.println(userRepository.findByUsername("admin"));
        };
    }
}