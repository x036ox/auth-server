package com.artur.request.model;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
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
    @NotNull MultipartFile picture;
}

