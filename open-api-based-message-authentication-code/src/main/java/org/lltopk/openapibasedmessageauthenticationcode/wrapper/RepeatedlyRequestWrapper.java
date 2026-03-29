package org.lltopk.openapibasedmessageauthenticationcode.wrapper;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * Spring自带一个ContentCachingRequestWrapper，看名字好像能用，实际上不行。
 *
 * 它是惰性缓存：只有请求体被消费过之后才有缓存内容。在拦截器的preHandle阶段，Body还没被任何人读过，调getContentAsByteArray()拿到的是空数组。
 *
 * 因此我们自定义HttpServletRequestWrapper
 */
public class RepeatedlyRequestWrapper extends HttpServletRequestWrapper {

    /**
     * 缓存请求体字节数据
     */
    private final byte[] body;

    public RepeatedlyRequestWrapper(HttpServletRequest request, ServletResponse response) throws IOException {
        super(request);
        request.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        this.body = readBody(request);
    }

    private byte[] readBody(HttpServletRequest request) throws IOException {
        try (InputStream is = request.getInputStream()) {
            return is.readAllBytes();
        }
    }

    /**
     * getReader方法同样也是用户的读取API, 我们也要重写
     * @return
     */
    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }

    /**
     * getInputStream方法是用户的读取API, 我们重写这个方法每次从成员变量private final byte[] body中生成新的流供用户读取
     * @return
     */
    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(body);
        return new ServletInputStream() {

            @Override
            public int read() {
                return inputStream.read();
            }

            @Override
            public boolean isFinished() {
                return inputStream.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // no-op
            }
        };
    }
}
