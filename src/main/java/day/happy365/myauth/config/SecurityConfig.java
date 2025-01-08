package day.happy365.myauth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import day.happy365.myauth.constant.RoleEnum;
import day.happy365.myauth.service.UserService;
import jakarta.servlet.ServletOutputStream;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private DataSource dataSource;
    @Autowired
    private UserService userService;

//    @Bean
//    public InMemoryUserDetailsManager userDetailsManager() {
//        UserDetails user1 = User.withUsername("u1")
//                .password(passwordEncoder().encode("p1"))
//                .roles(RoleEnum.ADMIN.name())
//                .accountExpired(false)
//                .credentialsExpired(false)
//                .disabled(false)
//                .accountLocked(false)
//                .build();
//        UserDetails user2 = User.withUsername("u2")
//                .password(passwordEncoder().encode("p2"))
//                .roles(RoleEnum.USER.name())
//                .build();
//        return new InMemoryUserDetailsManager(user1, user2);
//    }
//
//    @Bean
//    public UserDetailsService userDetailsService() {
//        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
//        if (!jdbcUserDetailsManager.userExists("u1")) {
//            jdbcUserDetailsManager.createUser(
//                    User.withUsername("u1")
//                            .password(passwordEncoder().encode("u1"))
//                            .roles(RoleEnum.ADMIN.name())
//                            .build()
//            );
//        }
//        if (!jdbcUserDetailsManager.userExists("u2")) {
//            jdbcUserDetailsManager.createUser(
//                    User.withUsername("u2")
//                            .password(passwordEncoder().encode("u2"))
//                            .roles(RoleEnum.USER.name())
//                            .build()
//            );
//        }
//        return jdbcUserDetailsManager;
//    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setUserDetailsService(userService);
        return new ProviderManager(authenticationProvider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        // 角色继承需要手动添加 "ROLE_" 前缀
        roleHierarchy.setHierarchy("ROLE_" + RoleEnum.ADMIN.name() + " > " + "ROLE_" + RoleEnum.USER.name());
        return roleHierarchy;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("/res/admin/**").hasRole(RoleEnum.ADMIN.name())
                                .requestMatchers("/res/user/**").hasRole(RoleEnum.USER.name())
                                .anyRequest().authenticated()
                )
                .formLogin(form -> form.defaultSuccessUrl("/homepage")
                        .successHandler((request, response, authentication) -> {
                            Object principal = authentication.getPrincipal();
                            response.setContentType("application/json;charset=utf-8");
                            ServletOutputStream outputStream = response.getOutputStream();
                            outputStream.write(new ObjectMapper().writeValueAsString(principal).getBytes());
                            outputStream.flush();
                            outputStream.close();
                        }).failureHandler((request, response, exception) -> {
                            response.setContentType("application/json;charset=utf-8");
                            PrintWriter out = response.getWriter();
                            Map<String, String> res = new HashMap<>();
                            res.put("message", exception.getMessage());
                            if (exception instanceof LockedException) {
                                res.put("message", "账户被锁定，请联系管理员");
                            } else if (exception instanceof CredentialsExpiredException) {
                                res.put("message", "密码过期，请联系管理员");
                            } else if (exception instanceof AccountExpiredException) {
                                res.put("message", "账户过期，请联系管理员");
                            } else if (exception instanceof DisabledException) {
                                res.put("message", "账户被禁用，请联系管理员");
                            } else if (exception instanceof BadCredentialsException) {
                                res.put("message", "用户名或者密码输入错误，请重新输入");
                            }
                            out.write(new ObjectMapper().writeValueAsString(res));
                            out.flush();
                            out.close();
                        })
                )
                .rememberMe(httpSecurityRememberMeConfigurer -> {
                    httpSecurityRememberMeConfigurer.alwaysRemember(true);
                    httpSecurityRememberMeConfigurer.key("my_auth");
                })
                .build();
    }
}
