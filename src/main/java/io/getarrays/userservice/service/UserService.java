package io.getarrays.userservice.service;

import io.getarrays.userservice.domain.Role;
import io.getarrays.userservice.domain.User;

import java.util.List;

import org.springframework.web.multipart.MultipartFile;

/**
 * @author Get Arrays (https://www.getarrays.io/)
 * @version 1.0
 * @since 7/10/2021
 */
public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    User getUserById(Long id);
    List<User>getUsers();
    
	void UpdateUser(Long id, User NewUserInfo);
	void RemoveUser(Long id);
	void updateuserb(Long id, User NewUserInfo);

    
}
