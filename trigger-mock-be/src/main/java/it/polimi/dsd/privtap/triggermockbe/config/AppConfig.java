package it.polimi.dsd.privtap.triggermockbe.config;

import lombok.Data;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

import java.util.List;

@Data
@EnableAsync
@Configuration
public class AppConfig {
    private List<String> authorizedRedirectUris = List.of("http://localhost:9000/login");//localhost:3000/oauth2/redirect

    private String tokenSecret = "08473246f3a16ecb7b0e8de2e8631516";

    private long tokenExpirationMsec = 864000000;
}
