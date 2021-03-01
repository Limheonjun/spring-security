package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*인가 정책*/
        http                                    // http프로토콜 통신 방식에 작동
                .authorizeRequests()            // 요청에 권한을 부여
                .anyRequest().authenticated();  // 모든 요청에 인증 필요
        /*인증 정책*/
        http
                .formLogin();                   //form로그인으로 인증할 수 있도록 설정
    }
}
