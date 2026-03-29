package org.lltopk.openapibasedmessageauthenticationcode.config;

import org.lltopk.openapibasedmessageauthenticationcode.intercepter.OpenApiInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebMvc
public class InterceptorConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new OpenApiInterceptor())
                .addPathPatterns("/**") // 指定拦截所有请求
                .excludePathPatterns("/excludePath"); // 排除某些路径不进行拦截
    }
}