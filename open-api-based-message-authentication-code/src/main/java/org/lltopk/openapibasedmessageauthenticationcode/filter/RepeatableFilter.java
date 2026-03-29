package org.lltopk.openapibasedmessageauthenticationcode.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.lltopk.openapibasedmessageauthenticationcode.wrapper.RepeatedlyRequestWrapper;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * 在过滤器的时候放入我们的RepeatedlyRequestWrapper到请求链中
 *
 * 支持 RequestBody 重复读取的过滤器
 */
public class RepeatableFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        ServletRequest wrappedRequest = delegatedRequest(request, response);

        chain.doFilter(wrappedRequest, response);
    }

    private ServletRequest delegatedRequest(ServletRequest request, ServletResponse response) throws IOException {

        if (request instanceof HttpServletRequest httpRequest
                && StringUtils.hasText(httpRequest.getContentType())
                && httpRequest.getContentType().startsWith(MediaType.APPLICATION_JSON_VALUE)) {

            return new RepeatedlyRequestWrapper(httpRequest, response);
        }

        return request;
    }
}