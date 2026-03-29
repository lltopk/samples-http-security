package org.lltopk.openapibasedmessageauthenticationcode.model;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@TableName("http_security_mac_open_app")
public class OpenAppPo {
    private Long id;

    private String appKey;

    private String appSecret;

    private String appName;

    private Integer status;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
}
