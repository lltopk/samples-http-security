package org.lltopk.openapibasedmessageauthenticationcode.openapp;

import org.lltopk.openapibasedmessageauthenticationcode.mapper.OpenAppMapper;
import org.lltopk.openapibasedmessageauthenticationcode.model.OpenAppPo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.UUID;
/**
 * 凭证管理涉及的就是生成、存储、查询。
 *
 * AppKey用ak_前缀加16位随机字符串，方便在日志里一眼区分。
 *
 * AppSecret用48位随机字符串，长度够用，SecureRandom生成，密码学安全。
 */
@Component
public class OpenAppGenerator {
    // SecureRandom保证密码学安全，不要用Math.random()
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Autowired
    OpenAppMapper openAppMapper;

    public OpenAppPo generate(String appName) {
        OpenAppPo app = new OpenAppPo();
        app.setAppKey("ak_" + UUID.randomUUID().toString()
                .replace("-", "").substring(0, 16));
        app.setAppSecret(generateSecret(48));
        app.setAppName(appName);
        app.setStatus(1);
        openAppMapper.insert(app);
        return app;
    }

    private String generateSecret(int i) {
        return null;
    }
}
