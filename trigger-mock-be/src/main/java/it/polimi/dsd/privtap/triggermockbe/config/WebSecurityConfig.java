package it.polimi.dsd.privtap.triggermockbe.config;

import it.polimi.dsd.privtap.triggermockbe.UserEntity;
import it.polimi.dsd.privtap.triggermockbe.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class WebSecurityConfig {

    @Autowired
    private UserRepository repo;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.formLogin()
                .and()
                .authorizeHttpRequests()
                .anyRequest()
                .authenticated()
                .and().build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        List<UserDetails> users=new ArrayList<>();
        UserDetailsManager udsManager = new InMemoryUserDetailsManager();
        for(UserEntity u: repo.findAll()){
            users.add(User.withUsername(u.getUsername())
                .password(u.getPassword())
                .roles("USER")
                .build());
        }
        users.forEach(userDetails -> udsManager.createUser(userDetails));
        return udsManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
