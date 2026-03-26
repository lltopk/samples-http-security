package org.lltopk.signaturetokenwithprivatekeyafterauth.interceptor;

import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.lltopk.signaturetokenwithprivatekeyafterauth.service.RedisNonceService;
import org.lltopk.signaturetokenwithprivatekeyafterauth.token.TokenUtil;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Token interceptor for validating JWT tokens in requests
 * Supports nonce validation for replay attack prevention
 */
@Slf4j
@Component
public class TokenInterceptor implements HandlerInterceptor {

    private static final String TOKEN_HEADER = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String NONCE_HEADER = "X-Request-Nonce";
    private static final String TIME_STAMP = "X-Request-TIMESTAMP";

    private final RedisNonceService redisNonceService;

    public TokenInterceptor(RedisNonceService redisNonceService) {
        this.redisNonceService = redisNonceService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // Skip OPTIONS requests (CORS preflight)
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        String token = extractToken(request);

        if (token == null || token.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":401,\"message\":\"Token is required\"}");
            return false;
        }

        // Verify token
        DecodedJWT jwt = TokenUtil.verifyToken(token);
        if (jwt == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":401,\"message\":\"Invalid or expired token\"}");
            return false;
        }

        // Check if token is expired
        if (TokenUtil.isTokenExpired(token)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":401,\"message\":\"Token has expired\"}");
            return false;
        }

        // Verify timestamp (prevent replay attack within 5 minutes)
        String timestamp = request.getHeader(TIME_STAMP);
        long currentTime = System.currentTimeMillis();
        long requestTime = Long.parseLong(timestamp);
        if (Math.abs(currentTime - requestTime) > 5 * 60 * 1000) {
            throw new org.lltopk.signaturetokenwithprivatekeyafterauth.exception.AuthenticationException(
                    "Request timestamp expired");
        }
        // Validate nonce if present in header
        String nonce = request.getHeader(NONCE_HEADER);
        if (nonce != null && !nonce.isEmpty()) {
            if (redisNonceService.isNonceExists(nonce)) {
                log.warn("Duplicate nonce detected: {}, possible replay attack", nonce);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().write("{\"code\":401,\"message\":\"Duplicate nonce, possible replay attack\"}");
                return false;
            }
            // Save nonce for future validation
            redisNonceService.saveNonce(nonce, System.currentTimeMillis());
            log.debug("Nonce validated and saved: {}", nonce);
        }

        // Store user info in request attributes for downstream use
        request.setAttribute("userId", TokenUtil.getUserIdFromToken(token));
        request.setAttribute("username", TokenUtil.getUsernameFromToken(token));
        request.setAttribute("digest", TokenUtil.getDigestFromToken(token));
        request.setAttribute("jti", jwt.getId());

        log.debug("Token validated for user: {}", request.getAttribute("username"));
        return true;
    }

    /**
     * Extract token from Authorization header
     */
    private String extractToken(HttpServletRequest request) {
        String authHeader = request.getHeader(TOKEN_HEADER);
        if (authHeader != null && authHeader.startsWith(TOKEN_PREFIX)) {
            return authHeader.substring(TOKEN_PREFIX.length());
        }
        
        // Also support token in query parameter (for WebSocket or special cases)
        String tokenParam = request.getParameter("token");
        if (tokenParam != null && !tokenParam.isEmpty()) {
            return tokenParam;
        }
        
        return null;
    }
}
