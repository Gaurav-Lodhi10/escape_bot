package com.auth_service.auth_service.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.auth_service.auth_service.entity.User;
import com.auth_service.auth_service.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor

public class UserService {
    
    private final UserRepository userRepository;

    public User createUser(User user){
        if(userRepository.existsByusername(user.getUsername())){
            throw new RuntimeException("username Already exists ");
        }
        return userRepository.save(user);
    }
    public List<User>getAllUsers(){
        return userRepository.findAll();
    }

    public User getUserById(Long id){
        return userRepository.findById(id).orElseThrow(()-> new RuntimeException("User not found"));
    }

    public User getUserbyusername(String username){
        return userRepository.findByusername(username).orElseThrow(()-> new RuntimeException("User not found"));
    }
}
