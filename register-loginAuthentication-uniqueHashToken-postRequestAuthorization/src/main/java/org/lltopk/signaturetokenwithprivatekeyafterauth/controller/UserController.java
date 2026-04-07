package org.lltopk.signaturetokenwithprivatekeyafterauth.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.lltopk.httpsecuritycommon.po.UserPo;
import org.lltopk.signaturetokenwithprivatekeyafterauth.config.ServerKeyConfig;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.ApiResponse;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.LoginRequest;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.LoginResponse;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.RegisterRequest;
import org.lltopk.signaturetokenwithprivatekeyafterauth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * User controller for registration, login, and profile management.
 * 
 * Security Model:
 * - Server generates and manages a single RSA key pair
 * - Client encrypts sensitive data with server's public key
 * - No client-side key generation required
 * - JWT token used for authentication after login
 */
@RestController
@RequestMapping("/api/auth")
@Slf4j
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private ServerKeyConfig serverKeyConfig;

    /**
     * Register a new user
     * POST /api/auth/register
     * 
     * Note: Server's public key should be obtained separately via GET /api/auth/server-public-key
     */
    @PostMapping("/register")
    public ApiResponse<Map<String, Object>> register(@Valid @RequestBody RegisterRequest request) {
        try {
            log.info("Registration request for username: {}", request.getUsername());

            UserPo user = userService.register(request);

            Map<String, Object> data = new HashMap<>();
            data.put("userId", user.getId());
            data.put("username", user.getUsername());
            data.put("email", user.getEmail());
            data.put("createTime", user.getCreateTime());
            data.put("publicSecretKey", serverKeyConfig.getServerPublicKeyBase64());

            return ApiResponse.success("Registration successful", data);
        } catch (RuntimeException e) {
            log.error("Registration failed: {}", e.getMessage());
            return ApiResponse.error(400, e.getMessage());
        } catch (Exception e) {
            log.error("Registration failed with unexpected error", e);
            return ApiResponse.error("Registration failed: " + e.getMessage());
        }
    }

    /**
     * Login with server public key encryption
     * POST /api/auth/login
     * 
     * Authentication Flow:
     * 1. Client obtains server's public key via GET /api/auth/server-public-key
     * 2. Client creates data: timestamp:nonce:password
     * 3. Client encrypts data with server's public key
     * 4. Server decrypts with its private key and validates
     * 5. Server returns JWT token and server's public key
     */
    @PostMapping("/login")
    public ApiResponse<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        try {
            log.info("Login request for username: {}", request.getUsername());

            LoginResponse response = userService.login(request);

            return ApiResponse.success("Login successful", response);
        } catch (RuntimeException e) {
            log.error("Login failed: {}", e.getMessage());
            return ApiResponse.error(401, e.getMessage());
        } catch (Exception e) {
            log.error("Login failed with unexpected error", e);
            return ApiResponse.error("Login failed: " + e.getMessage());
        }
    }

    /**
     * Get server's public key for client encryption
     * GET /api/auth/server-public-key
     * 
     * Clients should call this endpoint before login to get the server's public key
     * for encrypting their credentials.
     */
    @GetMapping("/server-public-key")
    public ApiResponse<Map<String, String>> getServerPublicKey() {
        try {
            Map<String, String> data = new HashMap<>();
            data.put("serverPublicKey", serverKeyConfig.getServerPublicKeyBase64());
            return ApiResponse.success(data);
        } catch (Exception e) {
            log.error("Failed to get server public key", e);
            return ApiResponse.error("Failed to get server public key: " + e.getMessage());
        }
    }

    /**
     * Get current user profile (requires token)
     * GET /api/auth/profile
     */
    @GetMapping("/profile")
    public ApiResponse<Map<String, Object>> getProfile(
            @RequestAttribute("userId") Long userId,
            @RequestAttribute("username") String username) {
        try {
            log.info("Profile request for user: {}", username);

            UserPo user = userService.findById(userId);
            if (user == null) {
                return ApiResponse.error(404, "User not found");
            }

            Map<String, Object> data = new HashMap<>();
            data.put("userId", user.getId());
            data.put("username", user.getUsername());
            data.put("email", user.getEmail());
            data.put("createTime", user.getCreateTime());

            return ApiResponse.success(data);
        } catch (Exception e) {
            log.error("Get profile failed", e);
            return ApiResponse.error("Failed to get profile: " + e.getMessage());
        }
    }

    /**
     * Get user by ID (requires token)
     * GET /api/auth/users/{id}
     */
    @GetMapping("/users/{id}")
    public ApiResponse<Map<String, Object>> getUserById(@PathVariable("id") Long id) {
        try {
            log.info("Get user by id: {}", id);

            UserPo user = userService.findById(id);
            if (user == null) {
                return ApiResponse.error(404, "User not found");
            }

            Map<String, Object> data = new HashMap<>();
            data.put("userId", user.getId());
            data.put("username", user.getUsername());
            data.put("email", user.getEmail());
            data.put("createTime", user.getCreateTime());

            return ApiResponse.success(data);
        } catch (Exception e) {
            log.error("Get user by id failed", e);
            return ApiResponse.error("Failed to get user: " + e.getMessage());
        }
    }
}
