package com.artur.controller;

import com.artur.exception.AlreadyExistsException;
import com.artur.request.model.UserCreateRequest;
import com.artur.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.net.URI;
import java.util.Objects;

@Controller
@RequestMapping("")
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService userService;

    @GetMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/registration")
    public String showRegistrationForm(){
        return "index";
    }

    @PostMapping("/registration")
    public ResponseEntity<?> postUser(@ModelAttribute UserCreateRequest user,
                                      HttpServletRequest request,
                                      HttpSession session
    ){
        UserDetails userDetails;
        try {
            userDetails = userService.registerUser(user);
        }catch (AlreadyExistsException e){
            logger.warn("User with this email already exists", e);
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).build();
        }
        catch (Exception e) {
            logger.error("Could not register user", e);
            return ResponseEntity.internalServerError().build();
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                userDetails.getPassword(),
                userDetails.getAuthorities());
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

        HttpHeaders headers = new HttpHeaders();
        Object attribute = session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        if(Objects.nonNull(attribute) && attribute.getClass().isAssignableFrom(DefaultSavedRequest.class)){
            DefaultSavedRequest savedRequest = (DefaultSavedRequest) attribute;
            headers.setLocation(URI.create(savedRequest.getRedirectUrl()));
        } else{
            headers.setLocation(URI.create("/login"));
        }
        return ResponseEntity.status(HttpStatus.FOUND).headers(headers).build();
    }
}
