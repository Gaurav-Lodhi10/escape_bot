package com.auth_service.auth_service.entity;

import java.security.Timestamp;

import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

enum Role{
    ADMINSTRATIVE,
    ADMIN,
    OPERATOR,
    RESPONDER

}



@Entity
@Table(name = "users")
@Data


public class User {

    private static final String NAME_MANDATORY = "Username is mandatory";
    private static final String PASSWORD_REQUIRED= "Password is mandatory";
    private static final String PASSWORD_SHOULD_HAVE_ATLEAST_6_CHARACTER= "Password atleast 6 Character long";


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "userID")
    private Long userId;

    @Column(unique = true, nullable = false)
    @NotBlank(message = NAME_MANDATORY)
    @Pattern(regexp = "^[a-zA-Z0-9_]+$")
    private String username;

    @Column(nullable = false)
    @NotBlank(message = NAME_MANDATORY)
    private String name;

    @Column
    private String portfolio; //optional

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @jakarta.validation.constraints.NotNull(message = "Role is Required")
    private Role role;

    @Column(name="created_at",updatable = false)
    @CreationTimestamp
    private Timestamp createdAt;


    @Column(nullable = false)
    @NotBlank(message = PASSWORD_REQUIRED)
    @Size(min = 6,message = PASSWORD_SHOULD_HAVE_ATLEAST_6_CHARACTER)
    private String password;



}
