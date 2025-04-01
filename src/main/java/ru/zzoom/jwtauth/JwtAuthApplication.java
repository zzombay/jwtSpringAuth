package ru.zzoom.jwtauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtAuthApplication {
    private JwtCore jwtCore;

    public void JwtCore(JwtCore jwtCore) {
        this.jwtCore = jwtCore;
    }

    public static void main(String[] args) {
        SpringApplication.run(JwtAuthApplication.class, args);
    }

}
