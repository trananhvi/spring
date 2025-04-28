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
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
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
                //remove the formLogin, which asks Spring to form the login form
                /*.formLogin(form -> form
                        .loginPage("/saml_login") // Use a different URL for login page
                        .loginProcessingUrl("/saml_login_handler") // URL to submit the login form
                        .permitAll()
                        .defaultSuccessUrl("/home", true)
                )*/
                .csrf().disable(); // For simplicity during testing

        ;
        return http.build();

    }

    @Bean
    Saml2AuthenticationRequestResolver authenticationRequestResolver(RelyingPartyRegistrationRepository registrations) {
        RelyingPartyRegistrationResolver registrationResolver = new DefaultRelyingPartyRegistrationResolver(registrations);
        OpenSaml4AuthenticationRequestResolver authenticationRequestResolver =
                new OpenSaml4AuthenticationRequestResolver(registrationResolver);

        authenticationRequestResolver.setAuthnRequestCustomizer(context -> {
            System.out.println("Biding" + context.getRelyingPartyRegistration().getRegistrationId() + "_" + context.getAuthnRequest().getProtocolBinding());

            var authnRequest = context.getAuthnRequest();

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
        try{
            Element element = XMLObjectSupport.marshall(authnRequest);
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");

            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(element), new StreamResult(writer));
            String xml = writer.toString();
            System.out.println("AuthnRequest: " + xml);

        }catch (Exception e) {

        }

    }
    //just a mock
    private String getLoginHintEmail() {
        return "vitran@example.com";
    }

}
