package com.example.sharebackend.service;

import com.example.sharebackend.model.Role;
import com.example.sharebackend.model.User;

import java.util.List;

public interface UserService {
    public User saveUser(User user);
    public Role saveRole(Role role);
    public void addRoleToUser(String userName, String roleName);
    public User getUser(String userName);
    public List<User> getUsers();
}
