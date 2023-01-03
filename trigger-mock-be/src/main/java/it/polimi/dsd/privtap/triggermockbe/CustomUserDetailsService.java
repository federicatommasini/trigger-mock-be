package it.polimi.dsd.privtap.triggermockbe;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {


    private final UserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    @Bean
    public PasswordEncoder passwordEncoder(){
        passwordEncoder=new BCryptPasswordEncoder();
        return passwordEncoder;
    }



    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserEntity> user = userRepository.findByUsername(username);
        if (user.isEmpty()) {
            throw new UsernameNotFoundException(username);
        }
        return new UserPrincipal(user.get().getId(),
                user.get().getUsername(),
                user.get().getPassword(),
                user.get().getAuthorities());
    }

    public UserEntity createUser(UserEntity usr){
        UserEntity user= new UserEntity();
        user.setUsername(usr.getUsername());
        user.setPassword(passwordEncoder.encode(usr.getPassword()));
        return userRepository.save(user);
    }

}
