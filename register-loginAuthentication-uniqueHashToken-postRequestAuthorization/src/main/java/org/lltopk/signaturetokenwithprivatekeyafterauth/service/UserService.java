package org.lltopk.signaturetokenwithprivatekeyafterauth.service;

import org.lltopk.httpsecuritycommon.po.UserPo;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.LoginRequest;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.LoginResponse;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.RegisterRequest;

public interface UserService {
    
    /**
     * Register a new user with generated key pair
     * @param request registration request
     * @return registered user
     */
    UserPo register(RegisterRequest request);
    
    /**
     * Login with public key encryption and signature verification
     * @param request login request with encrypted data and signature
     * @return login response with token
     */
    LoginResponse login(LoginRequest request);
    
    /**
     * Get user by username
     * @param username username
     * @return user or null
     */
    UserPo findByUsername(String username);
    
    /**
     * Get user by id
     * @param id user id
     * @return user
     */
    UserPo findById(Long id);
}
