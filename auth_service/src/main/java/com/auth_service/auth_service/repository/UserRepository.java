package com.auth_service.auth_service.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.auth_service.auth_service.entity.User;

@Repository

public interface UserRepository extends JpaRepository<User,Long> {
    Optional<User>findByusername(String username);

    boolean existsByusername(String username);
    
} 