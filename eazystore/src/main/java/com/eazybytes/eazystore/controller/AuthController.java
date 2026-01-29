package com.eazybytes.eazystore.controller;

import com.eazybytes.eazystore.dto.LoginRequestDto;
import com.eazybytes.eazystore.dto.LoginResponseDto;
import com.eazybytes.eazystore.dto.RegisterRequestDto;
import com.eazybytes.eazystore.dto.UserDto;
import com.eazybytes.eazystore.util.JwtUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("api/v1/auth")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final InMemoryUserDetailsManager inMemoryUserDetailsManager;
    private final PasswordEncoder passwordEncoder;
    private  final JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> apilogin(@RequestBody LoginRequestDto loginRequestDto) {
        try
        {
            log.debug("Login attempt for username: {}", loginRequestDto.username());
            Authentication authentication= authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequestDto.username(),loginRequestDto.password()));
           String jwtToken= jwtUtil.generateJwtToken(authentication);
           var userDto= new UserDto();
           var loggedInUser=(User) authentication.getPrincipal();
           userDto.setName(loggedInUser.getUsername());
           log.info("Login successful for user: {}", loginRequestDto.username());
            return ResponseEntity.status(HttpStatus.OK).body(new LoginResponseDto(HttpStatus.OK.getReasonPhrase(),userDto,jwtToken));
        }
        catch (BadCredentialsException e){
            log.warn("Bad credentials for user: {}", loginRequestDto.username());
            return buildErrorResponse(HttpStatus.UNAUTHORIZED,"Invalid username or password");

        }
        catch(AuthenticationException e)
        {
            log.warn("Authentication failed for user: {}", loginRequestDto.username(), e);
            return buildErrorResponse(HttpStatus.UNAUTHORIZED,"Authentication Failed");
        }
        catch (Exception e){
            log.error("Unexpected error during login for user: {}", loginRequestDto.username(), e);
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR,"Internal Server Error");
        }


    }
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegisterRequestDto registerRequestDto ) {
        inMemoryUserDetailsManager.createUser(new User (registerRequestDto.getEmail(),passwordEncoder.encode(registerRequestDto.getPassword()),
                List.of(new SimpleGrantedAuthority("USER"))));
        return ResponseEntity.status(HttpStatus.CREATED).body("Register Successfully");
    }

    private  ResponseEntity<LoginResponseDto>buildErrorResponse(HttpStatus status, String message){
        return ResponseEntity
                .status(status)
                .body(new LoginResponseDto(message,null,null));
    }
}
