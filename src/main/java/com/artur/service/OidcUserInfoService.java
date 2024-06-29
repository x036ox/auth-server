package com.artur.service;


import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

public interface OidcUserInfoService {
    OidcUserInfo loadByUsername(String username);
}
