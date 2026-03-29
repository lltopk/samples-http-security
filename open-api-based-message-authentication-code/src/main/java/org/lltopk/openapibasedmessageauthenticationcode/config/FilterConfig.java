package org.lltopk.openapibasedmessageauthenticationcode.config;

import org.lltopk.openapibasedmessageauthenticationcode.filter.RepeatableFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Filter 注册配置
 */
@Configuration
public class FilterConfig {

    /**
     * 注册一个最高优先级的FilterRegistrationBean
     *
     * Filter和Interceptor的执行顺序: 默认先Filter后Interceptor
     *
     * RepeatableReadFilter必须在DispatcherServlet之前执行，最好设置order为最高优先级。
     * 如果Filter没有包装Request就进了Interceptor，Interceptor读完Body后Controller拿到的就是空的。
     * @return
     */
    @Bean
    public FilterRegistrationBean<RepeatableFilter> repeatableFilterRegistration() {
        FilterRegistrationBean<RepeatableFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new RepeatableFilter());
        registration.addUrlPatterns("/*");
        registration.setName("repeatableFilter");
        registration.setOrder(1); // 优先级必须足够高
        return registration;
    }
}
