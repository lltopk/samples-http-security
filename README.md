
## 一. 共享密钥消息认证码MAC
正常来说求哈希不需要密钥, 如MD5、SHA-1等，仅依赖于输入数据本身，而不需要任何额外的密钥信息。这类函数广泛应用于数据完整性校验和数字签名中。

如果求哈希带密钥, 就转换为了共享密钥消息认证码MAC,  如基于哈希的消息认证码HMAC, 是一种结合了哈希函数和共享密钥的技术，用于消息认证性。

工作原理：通信双方（例如Alice和Bob）预先共享一个秘密密钥AppSecret。客户端（Alice）对关键信息(拼接请求方法+路径+参数+请求体)使用该密钥进行复杂哈希运算生成认证码（即MAC值），并将关键信息和认证码一起附在请求头中发送服务器.

服务器（Bob）收到MAC后，用同样的哈希算法再次对关键信息哈希, 然后用同样的密钥进行复杂哈希计算出新的MAC值。二者对比如果一致，说明客户端就是用共享密钥发送的请求, 则通过认证

由于共享密钥消息认证码同时使用了哈希和密钥, 因此也叫做签名, 只不过和服务器用非对称私钥签名的区别是:
1.	共享密钥消息认证码MAC是共享同一个密钥, 而服务器非对称私钥签名用的是密钥对中的私钥
2.	共享密钥消息认证码MAC是先对内容用密钥拼接, 然后对整体哈希(比如以HMAC它的核心思想是将密钥以特定的方式，在哈希计算过程中使用两次，形成一个“内层”和“外层”的双层结构). 而服务器非对称私钥签名是先对内容哈希, 然后对哈希后的结果进行私钥签名

因此 MAC在认证的同时, 由于签名属性, 也具有防篡改的功能, 毕竟除了CS双方, 其他人没有密钥, 黑客只能去修改关键信息(请求方法+路径+参数+请求体), 但只要一个参数被改动，服务器算出来的签名都会和客户端的签名不一样。



## 二. 用户注册 登录认证 Token检查 用户索引 后续鉴权
本系统实现了一个安全的认证和鉴权流程，分为用户注册登录, 以及登录认证之后的流程

### 用户注册 登录认证
初始的这两个阶段要需要 **服务器端管理的 RSA 非对称密钥对**：

- 服务器密钥管理：服务器生成并管理非对称 RSA 密钥对
- 无需客户端生成密钥：客户端不生成任何密钥
- 用户注册: 保存用户名username, 盐值slat, 密码password混合盐值slat进行哈希MD5之后最终password到数据库. 注册成功并返回服务器公钥给客户端
- 用户登录: 客户端用公钥对明文密码加密然后调用登录接口, 传输给后端, 服务端私钥解析密码, 并用相同的哈希算法再次计算哈希, 与数据库密码对比, 一致则通过认证

### Token检查 用户索引 后续鉴权

用户登录成功之后, 服务器要生成JWT令牌即Token给客户端, 以后每次请求都需携带Token证明身份
- JWT令牌：登录认证成功后服务器用哈希算法HMAC256, 用JWT专属的密钥进行复杂哈希运算制作令牌(由于同时使用哈希和密钥因此也叫签名sign)返回给客户端
- 检查令牌：后续所有用户请求都需要有效的 JWT 令牌, 验证原理是也用相同的哈希算法HMAC256和相同的JWT专属密钥, 对用户名等负载再次生成签名sign, 验证与用户传输token中的sign是否相等
- 请求鉴权: 你能干什么。系统根据token找到这个用户的权限列表(可配置)，判断当前请求的资源（通常就是URL + HTTP方法）是否在权限范围内。

我之前就写过一个认证+鉴权方式如下库，核心就是一个泛型接口：
```java
public interface Authenticator<P, C, T> {
    // 用户首次登录验证密码(凭据), 认证成功返回token和权限列表
    AuthResult<T> authenticate(P principal, C credentials);
    
    // 后续请求携带Token, 服务器根据token获取当前用户的权限集合
    Set<String> getAuthorities(T token);
    
    // 判断当前请求是否有权限访问
    boolean hasAccess(T token, String uri, String method);
}
```
实现这个接口的时候，authenticate方法里查数据库验证用户名密码，验证通过就生成一个token，同时把用户的权限列表缓存起来。

hasAccess方法里拿token找到权限列表，用Ant风格的路径匹配判断当前URL是否在权限范围内。

配合一个Servlet Filter或者Spring的HandlerInterceptor，在请求进入业务逻辑之前做一次拦截，整个鉴权流程就跑通了。

这个思路我用了很多年，换过不同的项目和团队，从来没遇到过它解决不了的场景。


_Token本质上也是共享密钥消息认证码MAC, 只不过Token不用客户端做哈希和签名sign, 偷懒让用户原封不动携带Token(sign), 也不用把共享密钥发给客户端._

一个完整的jwt实际上就是一个字符串，它由三部分组成:
- 头部head、
- 载荷Payload、
- 签名signature

这三个部分都是json格式

头部head用于描述关于该JWT的最基本的信息，例如下面说明了这是一个JWT，并且我们所用的签名算法是HS256算法。
```
{
"typ": "JWT",
"alg": "HS256"
}
```

载荷Payload可以用来放一些不敏感的信息。
```

"iss": "John Wu JWT",
"iat": 1441593502,
"exp": 1441594722,
"aud": "www.example.com",
"sub": "jrocket@example.com",
"from_user": "B",
"target_user": "A"
}
```

这里面的前五个字段都是由JWT的标准所定义的。

- `iss`: 该JWT的签发者
- `sub`: 该JWT所面向的用户
- `aud`: 接收该JWT的一方
- `exp`(expires): 什么时候过期，这里是一个Unix时间戳
- `iat`(issued at): 在什么时候签发的

把头部和载荷分别进行Base64编码之后得到两个字符串，然后再将这两个编码后的字符串用英文句号 `.`连接在一起（头部在前），形成新的字符串：
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
.eyJmcm9tX3VzZXIiOiJCIiwidGFyZ2V0X3VzZXIiOiJBIn0
```

服务器使用私钥secret将上面拼接完的字符串用HS256算法进行加密，得到签名, 把这个签名拼接在刚才的字符串后面就能得到完整的jwt，返回给客户端。
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
.eyJmcm9tX3VzZXIiOiJCIiwidGFyZ2V0X3VzZXIiOiJBIn0
.rSWamyAYwuHCo7IFAgd1oRpSP7nzL7BF5t7ItqpKViM
```
由于jwt的头部和载荷都是使用base64编码的，并没有加密，是透明的，因此jwt中不能直接存储username或者password等敏感数据，

上述服务器利用密钥进行复杂哈希运算, 然后用密钥签名生成Token之后发送给客户端

此后客户端每次请求是原封不动的携带Token(这就相当于是客户端用同样的密钥进行哈希计算了).  然后服务端接收到Token之后用同样的密钥进行复杂哈希计算得到新的签名,
服务端将结果与用户携带的Token对比, 一致则通过. 并且Token还实现了过期时间机制

要说弊端, 就是token经过编码后特别长, 相比传统的sessionId开销要大


### API 端点测试用例

#### 1. 获取服务器公钥
**端点：** `GET /api/auth/server-public-key`

客户端必须在登录前调用此端点以获取服务器的公钥用于加密。

**响应：**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "serverPublicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE..."
  }
}
```

**注意：** 保存此公钥用于加密登录凭据。

---

#### 2. 用户注册
**端点：** `POST /api/auth/register`

**请求体：**
```json
{
  "username": "testuser",
  "password": "securePassword123",
  "email": "test@example.com"
}
```

**响应：**
```json
{
  "code": 200,
  "message": "Registration successful",
  "data": {
    "userId": 1,
    "username": "testuser",
    "email": "test@example.com",
    "createTime": "2024-01-01 12:00:00"
  }
}
```

**注意：** 不返回公钥。请使用 `GET /api/auth/server-public-key` 获取服务器公钥。

---

#### 3. 用户登录
**端点：** `POST /api/auth/login`

**认证流程：**
1. 客户端通过 `GET /api/auth/server-public-key` 获取服务器公钥
2. 客户端创建数据字符串：`timestamp:nonce:password`
3. 客户端使用服务器公钥加密数据(加密密码)
4. 客户端发送登录请求，包含加密数据
5. 服务器使用私钥解密并通过再次哈希的方式验证密码是否和数据库里面的md5相等
6. 服务器返回 JWT 令牌

**请求体：**
```json
{
  "username": "testuser",
  "password": "securePassword123",
  "encryptedData": "Base64EncodedEncryptedData..."
}
```

**响应：**
```json
{
  "code": 200,
  "message": "Login successful",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "userId": "1",
    "username": "testuser",
    "expiresIn": 7200,
  }
}
```

**注意：** 保存响应中的 `serverPublicKey` 用于后续登录。

---

#### 4. 获取用户信息（受保护）
**端点：** `GET /api/auth/profile`

**请求头：**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**响应：**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "userId": 1,
    "username": "testuser",
    "email": "test@example.com",
    "createTime": "2024-01-01 12:00:00"
  }
}
```

---

#### 5. 根据 ID 获取用户（受保护）
**端点：** `GET /api/auth/users/{id}`

**请求头：**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 客户端实现指南

#### 步骤 1：获取服务器公钥
```java
// 调用 GET /api/auth/server-public-key
HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
Map<String, Object> responseBody = objectMapper.readValue(response.body(), Map.class);
String serverPublicKey = (String) ((Map) responseBody.get("data")).get("serverPublicKey");

// 保存此公钥
saveServerPublicKey(serverPublicKey);
```

#### 步骤 2：注册
```java
RegisterRequest request = new RegisterRequest("testuser", "password123", "test@example.com");
ApiResponse<Map> response = httpClient.post("/api/auth/register", request);
```

#### 步骤 3：登录
```java
// 准备登录数据
long timestamp = System.currentTimeMillis();
String nonce = UUID.randomUUID().toString();
String data = timestamp + ":" + nonce + ":" + password;

// 使用服务器公钥加密密码
String encryptedData = CryptoUtil.encryptByPublicKey(
    Base64.getDecoder().decode(serverPublicKey),
    data.getBytes()
);

// 登录请求（不需要 clientPublicKey 和 signature）
LoginRequest loginRequest = new LoginRequest(
    "testuser",
    password,
    encryptedData
);

ApiResponse<LoginResponse> loginResponse = httpClient.post("/api/auth/login", loginRequest);

// 客户端保存令牌和服务器公钥
String token = loginResponse.getData().getToken();
```

#### 步骤 4：访问受保护的端点
```java
// 将令牌添加到请求头
httpClient.setHeader("Authorization", "Bearer " + token);

// 访问受保护的端点
ApiResponse<Map> profile = httpClient.get("/api/auth/profile");
```

---

### 错误响应

#### 401 未授权
```json
{
  "code": 401,
  "message": "Invalid password"
}
```

#### 400 错误请求
```json
{
  "code": 400,
  "message": "Username already exists"
}
```

#### 500 服务器内部错误
```json
{
  "code": 500,
  "message": "Registration failed: Database error"
}
```

---

### 可配置
- 整个应用使用单个 RSA-2048 密钥对
- 密钥可在 `application.yaml` 中配置，或在启动时生成
- 私钥在服务器上安全保存（生产环境请使用 HSM/KMS）

#### 环境变量
- `JWT_SECRET_KEY`：JWT 签名密钥（生产环境请更改！）
- `DATABASE_URL`：MySQL 连接 URL
- `DATABASE_USERNAME`：数据库用户名
- `DATABASE_PASSWORD`：数据库密码

#### application.yaml
```yaml
server:
  rsa:
    # 可选：预配置的 RSA 密钥对（Base64 编码）
    # 如果未设置，将在启动时生成密钥
    private-key: "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
    public-key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE..."

jwt:
  secret-key: "your-secure-secret-key-change-in-production-2024"
  expiration-ms: 7200000  # 2 小时

security:
  replay-prevention:
    nonce-expire-minutes: 5
    timestamp-tolerance-minutes: 5
```

## 三. 重放攻击防护NONCE
请求头中携带Timestamp和随机串Nonce, 和基于密钥对Timestamp和Nonce计算的摘要结果sign
- Timestamp时间戳验证（5 分钟窗口）
- Nonce随机串 跟踪（每个 nonce 只能使用一次）
- sign

服务器提取Timestamp和随机串Nonce, 验证流程如下
- 如果时间窗口curTime - Timestamp大于设定值窗口, 直接丢弃请求
- 如果时间窗口curTime - Timestamp小于设定值窗口, 则用nonce判断是否出现过, 未出现过则在服务缓存中加入nonce, 出现过则直接丢弃

以上保证了防重放攻击.

通过重放攻击之后, 服务器按照正常的MAC消息认证码的认证流程, 用同样的哈希算法和密钥再次对关键信息(请求体请求方法请求参数等)计算sign, 对比二者sign是否相等, 相等则认证通过


