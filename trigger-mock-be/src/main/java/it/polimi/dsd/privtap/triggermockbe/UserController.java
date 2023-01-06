package it.polimi.dsd.privtap.triggermockbe;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserRepository repo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping
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
    }


    @PostMapping("/registration")
    public void register(@RequestBody UserEntity usr) {
        UserEntity user= new UserEntity();
        user.setUsername(usr.getUsername());
        user.setPassword(passwordEncoder.encode(usr.getPassword()));
        repo.save(user);
    }

    @PostMapping("/authenticate")
    public String authenticate(@RequestBody UserEntity usr) {
        UserEntity user= new UserEntity();
        user.setUsername(usr.getUsername());
        user.setPassword(passwordEncoder.encode(usr.getPassword()));
        repo.save(user);
    }*/

}

