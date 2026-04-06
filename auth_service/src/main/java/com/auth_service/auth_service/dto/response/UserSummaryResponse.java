package com.auth_service.auth_service.dto.response;


import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Builder;
import lombok.Data;

/**
 * Lightweight user object returned in paginated lists.
 * Full UserResponse is used for single-user detail endpoints.
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserSummaryResponse {

    private UUID id;
    private String firstName;
    private String lastName;
    private String email;
    private Set<String> roles;
    private boolean enabled;
    private boolean accountLocked;
    private Instant createdAt;
    private Instant lastLoginAt;
}