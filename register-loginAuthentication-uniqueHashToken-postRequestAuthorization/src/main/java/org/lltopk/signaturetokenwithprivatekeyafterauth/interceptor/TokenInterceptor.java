package org.lltopk.signaturetokenwithprivatekeyafterauth.interceptor;

import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.lltopk.signaturetokenwithprivatekeyafterauth.service.PermissionService;
import org.lltopk.signaturetokenwithprivatekeyafterauth.service.RedisNonceService;
import org.lltopk.signaturetokenwithprivatekeyafterauth.token.TokenUtil;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Set;

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
    private final PermissionService permissionService;

    // 路径匹配器，用于支持 Ant 风格的路径匹配 (如 /api/admin/**)
    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    /**
     * Spring4.3开始推荐构造注入, 并且当只有一个构造函数的时候, 可以省略@Autowired注解
     * @param redisNonceService
     * @param permissionService
     */
    public TokenInterceptor(RedisNonceService redisNonceService, PermissionService permissionService) {
        this.redisNonceService = redisNonceService;
        this.permissionService = permissionService;
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

        //鉴权Authorization
        if (!hasAuthorizationAccess(token, request.getRequestURI(), request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":403,\"message\":\"Access Denied: Insufficient Permissions\"}");
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

    /**
     * hasAccess方法里拿token, 提取出用户索引找到权限列表(缓存配置)，用Ant风格的路径匹配判断当前URL是否在权限范围内。
     * @param token
     * @param uri
     * @param method
     * @return
     */
    private boolean hasAuthorizationAccess(String token, String uri, String method){
        //1. 提取用户索引
        String userId = String.valueOf(TokenUtil.getUserIdFromToken(token));
        Set<String> userPermissions = permissionService.getUserPermissions(userId);

        // 策略：权限Value存储格式为 "METHOD:PATH" (例如 "GET:/api/data", "POST:/api/data")
        // 或者简单的路径匹配，如果需要忽略方法，只匹配路径即可
        for (String permission : userPermissions) {
            // 情况 A: 如果权限配置包含方法前缀 (例如 "GET:/api/**")
            if (permission.contains(":")) {
                String[] parts = permission.split(":");
                String allowedMethod = parts[0];
                String allowedPath = parts[1];

                if (allowedMethod.equals(method) && antPathMatcher.match(allowedPath, uri)) {
                    return true;
                }
            }
            // 情况 B: 如果权限配置只是路径 (例如 "/api/public/**")，则忽略方法
            else {
                if (antPathMatcher.match(permission, uri)) {
                    return true;
                }
            }
        }
        return false;
    }

}
