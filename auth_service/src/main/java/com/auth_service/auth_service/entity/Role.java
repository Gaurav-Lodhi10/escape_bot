package com.auth_service.auth_service.entity;


import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
 
@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role {
 
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
 
    @Column(nullable = false, unique = true, length = 50)
    @Enumerated(EnumType.STRING)
    private RoleName name;
 
    public enum RoleName {
        ROLE_USER,
        ROLE_ADMIN,
        ROLE_SERVICE    // for service-to-service calls
    }
}
 