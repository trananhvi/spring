package com.vitran.login;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.*;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.w3c.dom.Element;


import org.opensaml.core.xml.util.XMLObjectSupport;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Configuration
public class SecurityConfiguration {

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/saml_login",
                                "/saml_login_handler",
                                "/saml2/authenticate/*"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .saml2Login(login -> login
                        .loginPage("/saml_login")
                        .authenticationRequestResolver(authenticationRequestResolver(relyingPartyRegistrationRepository))
                        .defaultSuccessUrl("/home", true)
                )
                .csrf().disable(); // For simplicity during testing

        ;
        return http.build();

    }
/*
    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
                .fromMetadataLocation("https://dev-82990638.okta.com/app/exkobvb50io3pyNd05d7/sso/saml/metadata")
                .registrationId("okta")
                .decryptionX509Credentials(
                        (c) -> c.add(Saml2X509Credential.decryption(this.privateKey, relyingPartyCertificate())))
                .signingX509Credentials(
                        (c) -> c.add(Saml2X509Credential.signing(this.privateKey, relyingPartyCertificate())))
                .singleLogoutServiceLocation(
                        "https://dev-05937739.okta.com/app/dev-05937739_springgsecuritysaml2idp_1/exk46xofd8NZvFCpS5d7/slo/saml")
                .singleLogoutServiceResponseLocation("http://localhost:8080/logout/saml2/slo")
                .singleLogoutServiceBinding(Saml2MessageBinding.POST)
                .build();

        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
    }

*/

    /*
    @Bean
    public Saml2AuthenticationRequestResolver authenticationRequestResolver(RelyingPartyRegistrationRepository registrations) {
        RelyingPartyRegistrationResolver registrationResolver = new DefaultRelyingPartyRegistrationResolver(registrations);
        OpenSaml4AuthenticationRequestResolver delegate = new OpenSaml4AuthenticationRequestResolver(registrationResolver);

        // Step 1: Customize the AuthnRequest (inject Subject/NameID)
        delegate.setAuthnRequestCustomizer(context -> {
            AuthnRequest authnRequest = context.getAuthnRequest();

            NameID nameId = new NameIDBuilder().buildObject();
            nameId.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
            nameId.setValue(getLoginHintEmail()); // dynamic email

            Subject subject = new SubjectBuilder().buildObject();
            subject.setNameID(nameId);

            authnRequest.setSubject(subject);
        });

        // Step 2: Wrap the resolver to append login_hint to the final URL
        return (request) -> {
            Saml2RedirectAuthenticationRequest authenticationRequest = delegate.resolve(request);
            if (authenticationRequest == null) {
                return null;
            }

            String originalUri = authenticationRequest.getAuthenticationRequestUri();
            String loginHint = request.getParameter("email");
            if (loginHint == null || loginHint.isEmpty()) {
                loginHint = "defaultuser@example.com"; // fallback
            }

            String separator = originalUri.contains("?") ? "&" : "?";
            String modifiedUri = originalUri + separator + "login_hint=" + URLEncoder.encode(loginHint, StandardCharsets.UTF_8);

            String registrationId = authenticationRequest.getRelyingPartyRegistrationId();
            RelyingPartyRegistration relyingPartyRegistration = registrations.findByRegistrationId(registrationId);
            if (relyingPartyRegistration == null) {
                throw new IllegalStateException("RelyingPartyRegistration not found");
            }

            return Saml2RedirectAuthenticationRequest
                    .withRelyingPartyRegistration(relyingPartyRegistration)
                    .samlRequest(authenticationRequest.getSamlRequest())
                    .relayState(authenticationRequest.getRelayState())
                    .sigAlg(authenticationRequest.getSigAlg())
                    .signature(authenticationRequest.getSignature())
                    .authenticationRequestUri(modifiedUri)
                    .build();
        };
    }

*/
    @Bean
    Saml2AuthenticationRequestResolver authenticationRequestResolver(RelyingPartyRegistrationRepository registrations) {
        RelyingPartyRegistrationResolver registrationResolver = new DefaultRelyingPartyRegistrationResolver(registrations);
        OpenSaml4AuthenticationRequestResolver authenticationRequestResolver =
                new OpenSaml4AuthenticationRequestResolver(registrationResolver);

        authenticationRequestResolver.setAuthnRequestCustomizer(context -> {
            System.out.println("Biding" + context.getRelyingPartyRegistration().getRegistrationId() + "_" + context.getAuthnRequest().getProtocolBinding());

            AuthnRequest authnRequest = context.getAuthnRequest();

            // Create NameID
            NameID nameId = new NameIDBuilder().buildObject();
            nameId.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
            nameId.setValue(getLoginHintEmail()); // dynamic email

            // Create Subject
            Subject subject = new SubjectBuilder().buildObject();
            subject.setNameID(nameId);

            // Inject Subject into the AuthnRequest
            authnRequest.setSubject(subject);
            debugPrintAuthnRequests(authnRequest);
        });


        return authenticationRequestResolver;
    }


    public void debugPrintAuthnRequests(AuthnRequest authnRequest) {
        try {
            Element element = XMLObjectSupport.marshall(authnRequest);
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");

            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(element), new StreamResult(writer));
            String xml = writer.toString();
            System.out.println("AuthnRequest: " + xml);

        } catch (Exception e) {

        }

    }

    //just a mock
    private String getLoginHintEmail() {
        return "vitran@example.com";
    }

}
