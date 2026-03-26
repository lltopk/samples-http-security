package org.lltopk.signaturetokenwithprivatekeyafterauth;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("org.lltopk.signaturetokenwithprivatekeyafterauth.dao")
public class MainSpringBootApplication {

    public static void main(String[] args) {
        SpringApplication.run(MainSpringBootApplication.class, args);
    }

}
