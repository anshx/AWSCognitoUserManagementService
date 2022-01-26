package com.example.sharebackend.controller;

import com.amazonaws.services.cognitoidp.model.ConfirmSignUpResult;
import com.amazonaws.services.cognitoidp.model.SignUpResult;
import com.example.sharebackend.model.Role;
import com.example.sharebackend.model.User;
import com.example.sharebackend.service.CognitoService;
import com.example.sharebackend.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private CognitoService cognitoService;

    @GetMapping("/user")
    public ResponseEntity<User> getUser(@RequestParam(name = "username") String userName) {
        return ResponseEntity.ok().body(userService.getUser(userName));
    }

    @GetMapping("/user/all")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<List<User>> getUsers() {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/user")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        return ResponseEntity.ok().body(userService.saveUser(user));
    }

    @PostMapping("/role")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        return ResponseEntity.ok().body(userService.saveRole(role));
    }

    @PostMapping("/user/{user}/role/{role}")
    public ResponseEntity<?> addRoleToUser(@PathVariable String user, @PathVariable String role) {
        userService.addRoleToUser(user, role);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/user/signup")
    public SignUpResult signUp(@RequestParam(name = "username") String username, @RequestParam(name = "password") String password) {
        return cognitoService.signUp(username, password);
    }

    @GetMapping("/user/confirmsignup")
    public ConfirmSignUpResult confirmSignUp(@RequestParam(name = "username") String username, @RequestParam(name = "confirmationCode") String confirmationCode) {
        return cognitoService.confirmSignUp(username, confirmationCode);
    }

    @GetMapping("/user/login")
    public Map<String, String> login(@RequestParam(name = "username") String username, @RequestParam(name = "password") String password) {
        return cognitoService.login(username, password);
    }



}
