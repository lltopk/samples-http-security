package org.lltopk.httpsecuritycommon.po;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@TableName("user_http_security")
public class UserPo {
    private Long id;
    private String username;
    private String password;
    private String email;
    private String salt;
    private LocalDateTime createTime;
    private LocalDateTime updateTime;
}
