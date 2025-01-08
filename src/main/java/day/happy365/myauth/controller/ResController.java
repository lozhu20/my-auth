package day.happy365.myauth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/res")
@RestController
public class ResController {
    /**
     * 所有角色都能访问
     */
    @GetMapping("/hello")
    public String hello() {
        return "hello!";
    }

    /**
     * admin 角色的人访问
     */
    @GetMapping("/admin/hello")
    public String admin() {
        return "admin hello!";
    }

    /**
     * user 角色的人访问
     */
    @GetMapping("/user/hello")
    public String user() {
        return "user hello!";
    }
}
