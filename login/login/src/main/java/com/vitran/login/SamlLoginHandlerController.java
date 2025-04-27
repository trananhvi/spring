package com.vitran.login;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.util.UriUtils;
import java.util.Iterator;

import java.nio.charset.StandardCharsets;

@RestController
public class SamlLoginHandlerController {

    private static final Logger log = LoggerFactory.getLogger(SamlLoginHandlerController.class);

    private final RelyingPartyRegistrationRepository registrations;

    @Autowired
    public SamlLoginHandlerController(RelyingPartyRegistrationRepository registrations) {
        this.registrations = registrations;
    }

    @PostMapping("/saml_login_handler")
    public String handleSamlLogin(@RequestParam("username") String username) {
        if (!username.contains("@")) {
            return "redirect:/saml_login?error";
        }

        // grab the first (or only) registration dynamically
        Iterator<RelyingPartyRegistration> it =
                ((Iterable<RelyingPartyRegistration>) registrations).iterator();

        if (!it.hasNext()) {
            throw new IllegalStateException("No SAML registrations configured");
        }

        String registrationId = it.next().getRegistrationId();

        // build the redirect URL
        String hint = UriUtils.encode(username, StandardCharsets.UTF_8);
        return "redirect:/saml2/authenticate/"
                + registrationId
                + "?login_hint="
                + hint;
    }
}
