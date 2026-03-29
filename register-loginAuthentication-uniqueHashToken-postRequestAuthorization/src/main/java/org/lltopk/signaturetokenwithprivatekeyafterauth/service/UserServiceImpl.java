package org.lltopk.signaturetokenwithprivatekeyafterauth.service;

import lombok.extern.slf4j.Slf4j;
import org.lltopk.httpsecuritycommon.po.UserPo;
import org.lltopk.signaturetokenwithprivatekeyafterauth.config.ServerKeyConfig;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dao.UserMapper;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.LoginRequest;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.LoginResponse;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.RegisterRequest;
import org.lltopk.signaturetokenwithprivatekeyafterauth.token.TokenUtil;
import org.lltopk.signaturetokenwithprivatekeyafterauth.util.CryptoUtil;
import org.lltopk.signaturetokenwithprivatekeyafterauth.util.PasswordUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.Base64;

@Slf4j
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private ServerKeyConfig serverKeyConfig;

    @Autowired
    private RedisNonceService redisNonceService;

    private static final long TOKEN_EXPIRE_MS = 7200 * 1000; // 2 hours

    @Override
    @Transactional(rollbackFor = Exception.class)
    public UserPo register(RegisterRequest request) {
        log.info("Registering user: {}", request.getUsername());

        // Check if username already exists
        UserPo existingUser = userMapper.findByUsername(request.getUsername());
        if (existingUser != null) {
            throw new org.lltopk.signaturetokenwithprivatekeyafterauth.exception.AuthenticationException(
                "Username already exists: " + request.getUsername());
        }

        // Check if email already exists
        UserPo existingEmail = userMapper.findByEmail(request.getEmail());
        if (existingEmail != null) {
            throw new org.lltopk.signaturetokenwithprivatekeyafterauth.exception.AuthenticationException(
                "Email already registered: " + request.getEmail());
        }

        // Generate salt and hash password
        String salt = PasswordUtil.generateSalt();
        String hashedPassword = PasswordUtil.hashPassword(request.getPassword(), salt);

        // Create user (no per-user key pair, server uses single key pair)
        UserPo user = UserPo.builder()
                .id(null)
                .username(request.getUsername())
                .password(hashedPassword)
                .email(request.getEmail())
                .salt(salt)
                .createTime(LocalDateTime.now())
                .updateTime(LocalDateTime.now())
                .build();

        userMapper.save(user);
        log.info("User registered successfully: {}", request.getUsername());

        return user;
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public LoginResponse login(LoginRequest request) {
        log.info("Login attempt for user: {}", request.getUsername());

        // Find user by username
        UserPo user = userMapper.findByUsername(request.getUsername());
        if (user == null) {
            throw new org.lltopk.signaturetokenwithprivatekeyafterauth.exception.AuthenticationException(
                "User not found: " + request.getUsername());
        }

        // Get server's key pair
        KeyPair serverKeyPair = serverKeyConfig.serverKeyPair();

        // Decrypt the encrypted data using server's private key
        String decryptedData = CryptoUtil.decryptByPrivateKey(
                serverKeyPair.getPrivate(),
                request.getEncryptedData()
        );

        // Parse decrypted data (format: timestamp:nonce:password)
        String[] parts = decryptedData.split(":");
        if (parts.length != 3) {
            throw new org.lltopk.signaturetokenwithprivatekeyafterauth.exception.AuthenticationException(
                "Invalid encrypted data format");
        }

        String timestamp = parts[0];
        String nonce = parts[1];
        String password = parts[2];

        // Verify timestamp (prevent replay attack within 5 minutes)
        long currentTime = System.currentTimeMillis();
        long requestTime = Long.parseLong(timestamp);
        if (Math.abs(currentTime - requestTime) > 5 * 60 * 1000) {
            throw new org.lltopk.signaturetokenwithprivatekeyafterauth.exception.AuthenticationException(
                "Request timestamp expired");
        }

        // Check nonce for replay attack prevention (using Redis)
        if (redisNonceService.isNonceExists(nonce)) {
            throw new org.lltopk.signaturetokenwithprivatekeyafterauth.exception.AuthenticationException(
                "Nonce already used, possible replay attack");
        }

        // Verify password
        String hashedPassword = PasswordUtil.hashPassword(password, user.getSalt());
        if (!hashedPassword.equals(user.getPassword())) {
            throw new org.lltopk.signaturetokenwithprivatekeyafterauth.exception.AuthenticationException(
                "Invalid password");
        }

        // Save nonce to Redis to prevent replay
        redisNonceService.saveNonce(nonce, requestTime);

        // Generate digest of user info for token
        String digest = generateUserDigest(user);

        // Generate token with HMAC256 signature
        String token = TokenUtil.getToken(user, digest);

        log.info("User logged in successfully: {}", request.getUsername());

        return LoginResponse.builder()
                .token(token)
                .userId(String.valueOf(user.getId()))
                .username(user.getUsername())
                .expiresIn(TOKEN_EXPIRE_MS / 1000)
                .serverPublicKey(serverKeyConfig.getServerPublicKeyBase64())
                .build();
    }

    @Override
    public UserPo findByUsername(String username) {
        return userMapper.findByUsername(username);
    }

    @Override
    public UserPo findById(Long id) {
        return userMapper.findById(id);
    }

    /**
     * Generate digest of user information
     */
    private String generateUserDigest(UserPo user) {
        String data = user.getId() + ":" + user.getUsername() + ":" + user.getEmail();
        return CryptoUtil.sha256Digest(data);
    }
}
