package it.polimi.dsd.privtap.triggermockbe;

import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@AllArgsConstructor
@RestController
@RequestMapping("/")
public class UserController {
   /* @Autowired
    private UserRepository repo;

    @Autowired
    private PasswordEncoder passwordEncoder;*/

    private CustomUserDetailsService userService;

    @GetMapping("/")
    public String home() {
        return "Home page!";
    }

    @GetMapping("/login")
    public String login(){
        return "logged in!!";
    }

   /* @GetMapping("/registration/{username}/{pw}")
    public String registration(@PathVariable String username, @PathVariable String pw){
        UserEntity user= new UserEntity();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(pw));
        repo.save(user);
        return "user saved";
    }*/

    @PostMapping("/register")
    public void register(@RequestBody UserEntity usr) {
        userService.createUser(usr);
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/current-user")
    public UserPrincipal getCurrentUser(@AuthenticationPrincipal UserPrincipal user) {
        return user;
    }

}

