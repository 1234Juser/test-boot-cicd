package com.ohgiraffers.ex01.config;

import com.ohgiraffers.ex01.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;


@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    private final String secretKey;
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException{

        final  String auth = request.getHeader(HttpHeaders.AUTHORIZATION);
        log.info("auth : {}", auth);

        if( auth == null ){
            filterChain.doFilter(request, response);
            return;
        }

        String token = auth.split(" ")[1];
        if( JwtUtil.isExpired( token, secretKey ) ){
            filterChain.doFilter(request, response);
            return ;
        }

        String username = JwtUtil.getUsername(token, secretKey);
        String role = JwtUtil.getRole( token, secretKey );

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken( username, null,
                        List.of(new SimpleGrantedAuthority("ROLE_"+role)) );

        SecurityContextHolder.getContext().setAuthentication( authenticationToken );


        filterChain.doFilter(request, response);
    }
}

