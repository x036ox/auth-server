package com.artur.request.model;


import jakarta.annotation.Nullable;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class UserCreateRequest{
    @NotEmpty @Email String email;
    @NotEmpty String username;
    @NotEmpty String password;
    @Nullable MultipartFile picture;
}

