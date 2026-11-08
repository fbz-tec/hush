package com.fbztec.hush;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class HushApplication {

    static void main(String[] args) {
        SpringApplication.run(HushApplication.class, args);
    }

}
