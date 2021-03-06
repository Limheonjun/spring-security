package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * 인가 관련 설정(역할-ROLL)
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig2 extends WebSecurityConfigurerAdapter {

    // 사용자 생성 및 권한 설정 메소드
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()   //메모리 방식으로 사용자 생성
                .withUser("user")
                .password("{noop}1111")     //비밀번호 앞 프리픽스를 붙여 어떤 유형의 알고리즘을 사용하는지 설정
                .roles("USER");
        auth
                .inMemoryAuthentication()
                .withUser("sys")
                .password("{noop}1111")
                .roles("SYS", "USER");
        auth
                .inMemoryAuthentication()   //메모리 방식으로 사용자 생성
                .withUser("admin")
                .password("{noop}1111")     //비밀번호 앞 프리픽스를 붙여 어떤 유형의 알고리즘을 사용하는지 설정
                .roles("ADMIN", "SYS", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN") //구체적인 경로가 모든경로(**)설정보다 위에 와야함
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();
        http
                .formLogin();
    }
}
