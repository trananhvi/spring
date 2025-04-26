package com.vitran.login;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SamlLoginController {

    @GetMapping("/saml_login")
    public String saml_login() {
        return "saml_login"; // Return the name of the login template
    }
    @GetMapping("/home")
    public String home() {
        return "home";
    }
}

