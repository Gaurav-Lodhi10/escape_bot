package com.auth_service.auth_service.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth_service.auth_service.entity.User;
import com.auth_service.auth_service.service.UserService;

import lombok.RequiredArgsConstructor;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;




@RestController
@RequiredArgsConstructor
@RequestMapping("/users")


public class UserController {

    private final UserService userService;

    @PostMapping
    public ResponseEntity<User>createUser(@RequestBody User user){
        User createdUser=userService.createUser(user);
        return ResponseEntity.ok(createdUser);
    }

    @GetMapping("/{id}")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }
    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/username/{username}")
    public ResponseEntity<User> getUserByusername(@PathVariable String username) {
        return ResponseEntity.ok(userService.getUserbyusername(username));
        
    }
    
    
    
    
    
}
