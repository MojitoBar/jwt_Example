package com.example.demo.config;

import com.example.demo.provider.security.AuthInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {

    private final AuthInterceptor authInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 인터셉터
        // 컨트롤러에 들어온 요청과 응답을 가로채는 기능
        // 로그인 체크 유무 혹은 권한 체크에 주로 사용
        // .addPathPatterns -> 추가할 URL
        // .excludePathPatterns -> 제외할 URL
        registry.addInterceptor(authInterceptor)
                .addPathPatterns("/api/v1/coffees/**")
                .excludePathPatterns("/api/v1/login/**");
    }

}
