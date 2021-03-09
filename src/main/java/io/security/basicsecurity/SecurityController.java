package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(HttpSession httpSession) {

        //1. 인증객체 바로 꺼내오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        //2. 세션에서 인증객체 꺼내오기
        // 세션에서도 아래와 같이 SecurityContext를 꺼내올 수 있음
       SecurityContext context = (SecurityContext) httpSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
       Authentication authentication1 = context.getAuthentication();

        return "home";
    }

    @GetMapping("/thread")
    public String thread() {

        //인증 당시에 인증객체를 메인쓰레드로컬에 담았지
        // 아래 new Thread로 생성한 자식쓰레드로컬에 담지 않았기 때문에
        // 인증객체는 null이 나옴
        // 자식쓰레드로컬에서도 인증객체를 공유하려면
        // SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL)로 변경해야함
       new Thread(() -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        }).start();

        return "thread";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin() {
        return "admin";
    }

    @GetMapping("/denied")
    public String denied() {
        return "Access is denied";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
