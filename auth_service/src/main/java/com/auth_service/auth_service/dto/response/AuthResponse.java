package com.auth_service.auth_service.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Builder;
import lombok.Data;
 
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {
 
    private String accessToken;
    private String refreshToken;
 
    @Builder.Default
    private String tokenType = "Bearer";
 
    private long accessTokenExpiresIn;   // milliseconds
    private UserResponse user;
}