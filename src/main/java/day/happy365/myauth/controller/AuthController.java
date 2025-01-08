package day.happy365.myauth.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/auth")
@Slf4j
public class AuthController {
    @PostMapping("/do-login")
    public String performLogin(HttpServletRequest request) {
        String username = request.getParameter("username");
        log.info("username: {}", username);
        return "homepage";
    }

    @RequestMapping("/hello")
    @ResponseBody
    public String hello() {
        return "hello!";
    }
}
