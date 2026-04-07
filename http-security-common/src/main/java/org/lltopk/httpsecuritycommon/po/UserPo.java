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
    /**
     * 非对称公钥加密后的密码, 服务器会先私钥解密取出rawPassword之后做认证
     */
    private String password;
    private String email;
    /**
     * 一般来说,
     * 注册阶段, 服务器用私钥解密, 获得rawPassword, 然后encode(salt + rawPassword)一起存储,
     * 登录阶段, 服务器用私钥解密, 获得rawPassword, 从数据库根据用户名查询user获得encodePassword和salt, 然后对登录密码再次encode(salt + rawPassword), 对比数据库的encodePassword看是否一致
     *
     * 方便期间我们的salt单独存储, 其实在安全框架或者组件当中, salt往往会混合在encodePassword中一起存储
     * 比如spring security BCrypt, 为并约定salt在encodePassword中的偏移量x以及长度y, 其中salt也是每个用户独立的
     * 这样在登录match的时候, 根据encodePassword就能解析出salt, 然后对登录密码再次encode(salt + rawPassword)
     * 好处是不用单独存储salt
     */
    private String salt;
    private LocalDateTime createTime;
    private LocalDateTime updateTime;
}
