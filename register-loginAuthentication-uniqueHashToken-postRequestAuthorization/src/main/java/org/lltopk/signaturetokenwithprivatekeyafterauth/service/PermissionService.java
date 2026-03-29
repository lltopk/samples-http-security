package org.lltopk.signaturetokenwithprivatekeyafterauth.service;

import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class PermissionService {

    // 模拟从 Redis 获取用户的权限路径列表
    // Key 可能是 "user:permissions:1001"
    // Value 可能是 ["/api/user/info", "/api/public/**", "/api/order/*"]
    public Set<String> getUserPermissions(String userId) {
        // TODO: 实际实现应该调用 redisTemplate.opsForSet().members(...)

        // 模拟数据：假设用户 1001 是普通用户
        if ("1001".equals(userId)) {
            return Set.of("/api/user/info", "/api/public/**");
        }

        // 模拟数据：假设用户 1002 是管理员
        if ("1002".equals(userId)) {
            return Set.of("/api/**"); // 管理员拥有所有权限
        }

        return Set.of();
    }
}
