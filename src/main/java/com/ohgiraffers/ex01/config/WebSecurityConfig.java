package com.ohgiraffers.ex01.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    @Value("${jwt.secretKey}") private String secretKey;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filter(HttpSecurity http ) throws Exception{
        http
                .csrf( csrf -> csrf.disable() )

                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOriginPatterns(List.of("*")); //모든 ip 허용.허용할 FrontEnd ip설정
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE")); // 허용할 HTTP 메서드
                    config.setAllowedHeaders(List.of("*")); // 모든 헤더 허용
                    config.setAllowCredentials(true); // 쿠키 및 인증 정보 허용
                    return config;
                }))

                .authorizeHttpRequests( auth -> auth
                        .requestMatchers("/cicd").permitAll()
                        .requestMatchers("/mem/login").permitAll()
                        .requestMatchers(HttpMethod.GET, "/mem").permitAll()
                        .requestMatchers(HttpMethod.GET, "/mem/{fileName}/image").permitAll()
                        .requestMatchers(HttpMethod.POST, "/mem").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .addFilterBefore( new JwtFilter( secretKey )
                        , UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
