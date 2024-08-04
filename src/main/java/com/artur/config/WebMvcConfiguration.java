package com.artur.config;

import com.artur.repository.ClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;

import java.net.URI;
import java.util.Arrays;

@EnableWebMvc
@Configuration
public class WebMvcConfiguration implements WebMvcConfigurer {

    @Autowired
    ClientRepository clientRepository;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(obtainOrigins());
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/login").setViewName("index");
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**").addResourceLocations("classpath:/static/");
    }

    private String[] obtainOrigins(){
        return clientRepository.findAll().stream()
                .flatMap(client -> Arrays.stream(client.getRedirectUris().split(",")))
                .filter(redirectUris -> !redirectUris.isEmpty())
                .map(redirectUri -> URI.create(redirectUri).resolve("/").toString())
                .toArray(String[]::new);
    }
}
