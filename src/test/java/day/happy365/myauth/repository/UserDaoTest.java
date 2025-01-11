package day.happy365.myauth.repository;

import day.happy365.myauth.entity.Role;
import day.happy365.myauth.entity.User;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.ArrayList;
import java.util.List;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest
public class UserDaoTest {
    @Autowired
    private UserDao userDao;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void saveUser() {
        User user1 = User.builder()
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .enabled(true)
                .username("u1")
                .password(passwordEncoder.encode("p1"))
                .build();
        Role role1 = Role.builder()
                .description("管理员")
                .role("ROLE_ADMIN")
                .build();
        List<Role> roleList1 = List.of(role1);
        user1.setRoles(roleList1);

        User user2 = User.builder()
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .enabled(true)
                .username("u2")
                .password(passwordEncoder.encode("p2"))
                .build();
        Role role2 = Role.builder()
                .description("普通用户")
                .role("ROLE_USER")
                .build();
        List<Role> roleList2 = List.of(role2);
        user2.setRoles(roleList2);

        userDao.save(user1);
        userDao.save(user2);
    }
}