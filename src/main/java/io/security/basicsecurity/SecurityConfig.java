package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*인가 정책*/
        http                                            // http프로토콜 통신 방식에 작동
                .authorizeRequests()                    // 요청에 권한을 부여
                .anyRequest().authenticated();          // 모든 요청에 인증 필요
        /*인증 정책*/
        http
                .formLogin()                            // form로그인으로 인증할 수 있도록 설정
//                .loginPage("/loginPage")                // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")                 // 인증 성공 시 기본 이동 url
                .failureUrl("/login")                   // 인증 실패 시 기본 이동 url
                .usernameParameter("userId")            // 아이디 파라미터 설정
                .passwordParameter("passwd")            // 비밀번호 파라미터 설정
                .loginProcessingUrl("/login_proc")      // form의 action 속성에 할당될 url
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override                                                                                     /* 인증 성공 시 인증결과를 담은 객체 */
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override                                                                                     /* 인증 실패 시 예외를 담은 객체 */
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll();                           // loginPage로의 접근을 모두 허용

        /* 로그아웃 처리 */
        http
                .logout()
                .logoutUrl("/logout")                   //logout url
                .logoutSuccessUrl("/login")             //logout 성공시 이동 url
                // 로그아웃 핸들러는 기본적으로 4가지를 제공(쿠키클리어, csrf, SecurityContext, LogoutSuccess이벤트)
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                // 위에 추가한 핸들러가 모두 성공적으로 종료 된 뒤 실행되는 핸들러
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                // 쿠키삭제
                .deleteCookies("remember-me");
    }
}
