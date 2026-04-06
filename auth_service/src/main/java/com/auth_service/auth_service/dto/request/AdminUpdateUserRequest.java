package com.auth_service.auth_service.dto.request;


import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.Set;

/**
 * Used by ADMIN only — can change roles, lock/unlock, enable/disable.
 * Regular users cannot access any endpoint that accepts this DTO.
 */
@Data
public class AdminUpdateUserRequest {

    // null means "don't change this field"
    private Set<String> roles;       // e.g. ["ROLE_USER", "ROLE_ADMIN"]
    private Boolean accountLocked;
    private Boolean enabled;
}