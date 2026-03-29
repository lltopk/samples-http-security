package org.lltopk.openapibasedmessageauthenticationcode;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("org.lltopk.openapibasedmessageauthenticationcode.mapper")
public class OpenApiBasedMessageAuthenticationCodeApplication {

    public static void main(String[] args) {
        SpringApplication.run(OpenApiBasedMessageAuthenticationCodeApplication.class, args);
    }

}
