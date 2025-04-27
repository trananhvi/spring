package com.vitran.login;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SamlLoginHandlerController {

    private static final Logger log = LoggerFactory.getLogger(SamlLoginHandlerController.class);

    @PostMapping("/saml_login_handler")
    public String handleSamlLogin(
            @RequestParam("username") String username,
            @RequestParam("password") String password) {

        // print to console
        System.out.println("Received SAML login:");
        System.out.println("  username = " + username);
        System.out.println("  password = " + password);

        // print via logger
        log.info("SAML login attempt: username='{}', password='{}'", username, password);

        // you can now authenticate against your SAML provider…
        // for now, just return a simple message
        return "Login received for user: " + username;
    }
}