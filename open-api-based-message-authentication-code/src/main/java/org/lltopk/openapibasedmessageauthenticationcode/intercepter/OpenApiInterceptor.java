package org.lltopk.openapibasedmessageauthenticationcode.intercepter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.lltopk.openapibasedmessageauthenticationcode.model.OpenAppPo;
import org.lltopk.openapibasedmessageauthenticationcode.service.INonceService;
import org.lltopk.openapibasedmessageauthenticationcode.service.IOpenAppService;
import org.lltopk.openapibasedmessageauthenticationcode.service.ISignatureService;
import org.lltopk.openapibasedmessageauthenticationcode.utils.SpringUtil;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

@Slf4j
public class OpenApiInterceptor implements HandlerInterceptor {
    private IOpenAppService openAppService;
    private INonceService nonceService;
    private ISignatureService signatureService;

    private IOpenAppService getOpenAppService() {
        if (Objects.nonNull(openAppService)) {
            return openAppService;
        }
        openAppService = SpringUtil.getBeanByApplicationContextAware(IOpenAppService.class);
        return openAppService;
    }

    private INonceService getNonceService() {
        if (Objects.nonNull(nonceService)) {
            return nonceService;
        }
        nonceService = SpringUtil.getBeanByApplicationContextAware(INonceService.class);
        return nonceService;
    }

    private ISignatureService getSignatureService() {
        if (Objects.nonNull(signatureService)) {
            return signatureService;
        }
        signatureService = SpringUtil.getBeanByApplicationContextAware(ISignatureService.class);
        return signatureService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {

        log.info("第一次读取HttpServletRequest {}", readRequest(request));
        // 只拦截Controller方法
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }
        // 检查@RequireSignature注解，没有就放行
        // ...

        // 提取4个签名Header
        String appKey = request.getHeader("X-App-Key");
        String timestamp = request.getHeader("X-Timestamp");
        String nonce = request.getHeader("X-Nonce");
        //客户端根据请求体
        String signature = request.getHeader("X-Signature");

        // 时间戳校验：与服务器时间差超过5分钟就拒绝
        //时间戳有效期不要设太短。客户端和服务端的时钟不一定完全同步，网络传输也有延迟。5分钟是一个比较安全的阈值。设成30秒或1分钟的话，时钟偏差稍大就会误拒正常请求。
        long diff = Math.abs(System.currentTimeMillis() - Long.valueOf(timestamp));
        if (diff > 5 * 60 * 1000L) {
//            writeError(response, ResultCode.TIMESTAMP_EXPIRED);
            return false;
        }
        // Nonce去重
        if (!getNonceService().checkAndSave(appKey, nonce)) {
//            writeError(response, ResultCode.NONCE_DUPLICATE);
            return false;
        }
        // 查AppSecret，走本地缓存
        OpenAppPo app = getOpenAppService().getByAppKey(appKey);
        String requestParams = buildSortedQuery(request.getParameterMap());
        String method = request.getMethod();
        String body = new String(readRequest(request));

        // 读Body、拼签名串、算签名、比对
        String expectedSign = signatureService.sign(requestParams,method,body,
                app.getAppSecret());

        // 常量时间比对, 为什么不能用String.equals
        // 这里有一个安全细节：签名比对不能用String.equals()，要用MessageDigest.isEqual()。
        // 原因是String.equals()在发现第一个不匹配的字符时就返回false，攻击者可以通过测量响应时间来逐位猜测正确的签名值，这叫时序攻击。
        // MessageDigest.isEqual()会比较完所有字节再返回结果，无论是否匹配，耗时都一样。
        if (!signatureService.verifySignature(expectedSign, signature)) {
//            writeError(response, ResultCode.SIGNATURE_MISMATCH);
            return false;
        }

        return true; // 允许请求继续
    }



    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           ModelAndView modelAndView) throws Exception {
        log.info("第二次读取HttpServletRequest {}", readRequest(request));
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
                                Exception ex) throws Exception {
        log.info("第三次读取HttpServletRequest {}", readRequest(request));
    }

    /**
     * 当请求的URL中包含同名参数时，服务器端如何解析这些参数取决于服务器和客户端的处理方式
     * 1. 将重复参数视为一个列表
     * 2. 覆盖之前的值
     *
     * 但无论是哪种方式, 客户端都有可能这样干, 所以我们做MAC认证要兼容这种场景, 规定参数值默认升序处理
     * @param parameterMap
     * @return
     */
    private String buildSortedQuery(Map<String, String[]> parameterMap) {
        if (parameterMap == null || parameterMap.isEmpty()) {
            return "";
        }
        // 按参数名排序
        TreeMap<String, String[]> sorted = new TreeMap<>(parameterMap);
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String[]> entry : sorted.entrySet()) {
            String key = entry.getKey();
            String[] values = entry.getValue();
            // 同名参数的值也排序
            Arrays.sort(values);
            for (String value : values) {
                if (sb.length() > 0) {
                    sb.append("&");
                }
                sb.append(key).append("=").append(value);
            }
        }
        return sb.toString();
    }
    /**
     * 读取请求体, 注意请求体编码问题 ,从InputStream读取Body时，编码要用请求头中Content-Type指定的charset。
     *
     * 如果用默认UTF-8, 如果客户端和服务端编码不一致，同样的JSON字符串算出来的签名就不一样。
     * @param request
     * @return
     * @throws IOException
     */
    private byte[] readRequest(HttpServletRequest request) throws IOException {
        //TODO Content-Type
        try (InputStream is = request.getInputStream()) {
            return is.readAllBytes();
        }
    }
}