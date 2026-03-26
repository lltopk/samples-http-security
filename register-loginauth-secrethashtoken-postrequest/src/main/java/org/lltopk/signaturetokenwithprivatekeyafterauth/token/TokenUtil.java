package org.lltopk.signaturetokenwithprivatekeyafterauth.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.lltopk.httpsecuritycommon.po.UserPo;

import java.util.Date;
import java.util.Optional;

@Slf4j
public class TokenUtil {

    private static final String ISSUER = "http-security-auth";
    private static final String AUDIENCE = "http-security-client";
    private static final String SECRET_KEY = System.getenv("JWT_SECRET_KEY") != null 
            ? System.getenv("JWT_SECRET_KEY") 
            : "your-secure-secret-key-change-in-production-2024";
    private static final long TOKEN_EXPIRE_MS = 7200 * 1000; // 2 hours

    /**
     * Generate JWT token with HMAC256 signature
     * @param user user information
     * @param digest user digest for additional verification
     * @return JWT token string
     */
    public static String getToken(UserPo user, String digest) {
        Date now = new Date();
        Date expiresAt = new Date(System.currentTimeMillis() + TOKEN_EXPIRE_MS);
        
        return JWT.create()
                .withIssuer(ISSUER)
                .withAudience(AUDIENCE)
                .withSubject(String.valueOf(user.getId()))
                .withExpiresAt(expiresAt)
                .withNotBefore(now)
                .withIssuedAt(now)
                .withJWTId(generateJWTId(user.getId()))
                .withClaim("username", user.getUsername())
                .withClaim("email", user.getEmail())
                .withClaim("digest", digest)
                .withClaim("iat_ts", now.getTime())
                .withClaim("exp_ts", expiresAt.getTime())
                .sign(Algorithm.HMAC256(SECRET_KEY));
    }

    /**
     * Verify JWT token
     * @param token JWT token string
     * @return DecodedJWT if valid, null otherwise
     */
    public static DecodedJWT verifyToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(ISSUER)
                    .withAudience(AUDIENCE)
                    .build();
            return verifier.verify(token);
        } catch (Exception e) {
            log.error("Token verification failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extract user id from token
     * @param token JWT token string
     * @return user id or null
     */
    public static Long getUserIdFromToken(String token) {
        DecodedJWT jwt = verifyToken(token);
        if (jwt == null) {
            return null;
        }
        try {
            return Long.parseLong(jwt.getSubject());
        } catch (NumberFormatException e) {
            log.error("Failed to parse user id from token");
            return null;
        }
    }

    /**
     * Extract username from token
     * @param token JWT token string
     * @return username or null
     */
    public static String getUsernameFromToken(String token) {
        DecodedJWT jwt = verifyToken(token);
        if (jwt == null) {
            return null;
        }
        return jwt.getClaim("username").asString();
    }

    /**
     * Extract digest from token
     * @param token JWT token string
     * @return digest or null
     */
    public static String getDigestFromToken(String token) {
        DecodedJWT jwt = verifyToken(token);
        if (jwt == null) {
            return null;
        }
        return jwt.getClaim("digest").asString();
    }

    /**
     * Check if token is expired
     * @param token JWT token string
     * @return true if expired
     */
    public static boolean isTokenExpired(String token) {
        DecodedJWT jwt = verifyToken(token);
        if (jwt == null) {
            return true;
        }
        Date expiresAt = jwt.getExpiresAt();
        return expiresAt != null && expiresAt.before(new Date());
    }

    /**
     * Get expiration time from token
     * @param token JWT token string
     * @return expiration timestamp or null
     */
    public static Long getExpirationTime(String token) {
        DecodedJWT jwt = verifyToken(token);
        if (jwt == null) {
            return null;
        }
        return jwt.getClaim("exp_ts").asLong();
    }

    /**
     * Generate unique JWT ID
     * @param userId user id
     * @return unique JWT ID
     */
    private static String generateJWTId(Long userId) {
        return userId + "-" + System.currentTimeMillis() + "-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * Get token expiration time in milliseconds
     * @return expiration time in ms
     */
    public static long getTokenExpireMs() {
        return TOKEN_EXPIRE_MS;
    }
}
