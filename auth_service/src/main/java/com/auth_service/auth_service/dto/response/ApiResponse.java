package com.auth_service.auth_service.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;
 
import java.time.Instant;
 
/**
 * Standard API response envelope.
 * Every endpoint returns this — success or error.
 * Consumers can always expect the same shape.
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {
 
    private boolean success;
    private String message;
    private T data;
    private String errorCode;
 
    @Builder.Default
    private Instant timestamp = Instant.now();
 
    public static <T> ApiResponse<T> success(String message, T data) {
        return ApiResponse.<T>builder()
                .success(true)
                .message(message)
                .data(data)
                .build();
    }
 
    public static <T> ApiResponse<T> success(T data) {
        return success("Success", data);
    }
 
    public static <T> ApiResponse<T> error(String message, String errorCode) {
        return ApiResponse.<T>builder()
                .success(false)
                .message(message)
                .errorCode(errorCode)
                .build();
    }
}
 