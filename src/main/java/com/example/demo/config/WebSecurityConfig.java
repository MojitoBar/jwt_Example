package com.example.demo.config;

import com.example.demo.core.security.Role;
import com.example.demo.exception.JwtAccessDeniedHandler;
import com.example.demo.exception.JwtAuthenticationEntryPoint;
import com.example.demo.provider.security.JwtAuthTokenProvider;
import com.example.demo.security.JWTConfigurer;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtAuthTokenProvider jwtAuthTokenProvider;
    private final JwtAuthenticationEntryPoint authenticationErrorHandler;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf().disable()

                .exceptionHandling()
                .authenticationEntryPoint(authenticationErrorHandler)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // /api/v1/login으로 시작하는 요청은 인증 성공 여부와 상관없이 모두 접근 가능
                .and()
                .authorizeRequests()
                .antMatchers("/api/v1/login/**").permitAll()

                // /api/v1/coffees으로 시작하는 요청은 인증을 반드시 통과해야 하며, 인가(USER 권한)이 있는 사용자만 접근 가능
                .antMatchers("/api/v1/coffees/**").hasAnyAuthority(Role.USER.getCode())
                .anyRequest().authenticated()

                .and()
                .apply(securityConfigurerAdapter());
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .antMatchers(HttpMethod.OPTIONS, "/**")

                // allow anonymous resource requests
                .antMatchers(
                        "/",
                        "/h2-console/**"
                );
    }

    private JWTConfigurer securityConfigurerAdapter() {
        return new JWTConfigurer(jwtAuthTokenProvider);
    }
}
