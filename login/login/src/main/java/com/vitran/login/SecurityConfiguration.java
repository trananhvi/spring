package com.vitran.login;

import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationRequestFilter;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorize -> authorize
                        .antMatchers("/saml_login",
                                "/saml_login_handler",
                                "/saml2/authenticate/*"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .saml2Login(login -> login
                        .loginPage("/saml_login")
                        .defaultSuccessUrl("/home", true)
                )
                .csrf().disable(); // For simplicity during testing

        // Configure custom SAML authentication request filter
        configureCustomSamlRequestFilter(http);
    }

    private void configureCustomSamlRequestFilter(HttpSecurity http) throws Exception {
        DefaultRelyingPartyRegistrationResolver registrationResolver =
                new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);

        Saml2WebSsoAuthenticationRequestFilter filter =
                new Saml2WebSsoAuthenticationRequestFilter(registrationResolver);

        filter.setAuthenticationRequestFactory(context -> {
            System.out.println("Binding: " + context.getRelyingPartyRegistration().getRegistrationId() +
                    "_" + context.getRelyingPartyRegistration().getAssertionConsumerServiceLocation());

            AuthnRequest authnRequest = createDefaultAuthnRequest(context);

            // Create NameID
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            NameID nameId = (NameID) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME)
                    .buildObject(NameID.DEFAULT_ELEMENT_NAME);
            nameId.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
            nameId.setValue(getLoginHintEmail()); // dynamic email

            // Create Subject
            Subject subject = (Subject) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME)
                    .buildObject(Subject.DEFAULT_ELEMENT_NAME);
            subject.setNameID(nameId);

            // Inject Subject into the AuthnRequest
            authnRequest.setSubject(subject);
            debugPrintAuthnRequests(authnRequest);

            // Convert the OpenSAML AuthnRequest to the expected format for Spring Security 5.7.x
            try {
                // Marshal the AuthnRequest to XML
                Element element = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                        .getMarshaller(authnRequest).marshall(authnRequest);

                // Convert to a byte array for Spring Security
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                Transformer transformer = transformerFactory.newTransformer();
                transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

                StringWriter stringWriter = new StringWriter();
                transformer.transform(new DOMSource(element), new StreamResult(stringWriter));
                String xmlString = stringWriter.toString();

                // Return the XML as a byte array (what Spring Security 5.7.x expects)
                return xmlString.getBytes("UTF-8");
            } catch (Exception e) {
                throw new RuntimeException("Error marshalling SAML AuthnRequest", e);
            }
        });

        http.addFilterBefore(filter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
    }

    // Helper method to create a basic AuthnRequest - you'll need to implement this
    private AuthnRequest createDefaultAuthnRequest(org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext context) {
        // Create a basic AuthnRequest object using OpenSAML 3
        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            AuthnRequest authnRequest = (AuthnRequest) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME)
                    .buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);

            // Set required attributes
            authnRequest.setID("_" + java.util.UUID.randomUUID().toString());
            authnRequest.setIssueInstant(new org.joda.time.DateTime());
            authnRequest.setDestination(context.getRelyingPartyRegistration().getAssertionConsumerServiceLocation());
            authnRequest.setAssertionConsumerServiceURL(context.getRelyingPartyRegistration()
                    .getAssertionConsumerServiceLocation());

            // In Spring Security 5.7.x, use the binding format constant
            String protocolBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"; // Default to POST binding
            // You can also check what binding is configured and set accordingly

            authnRequest.setProtocolBinding(protocolBinding);

            // Set issuer
            org.opensaml.saml.saml2.core.Issuer issuer =
                    (org.opensaml.saml.saml2.core.Issuer) builderFactory
                            .getBuilder(org.opensaml.saml.saml2.core.Issuer.DEFAULT_ELEMENT_NAME)
                            .buildObject(org.opensaml.saml.saml2.core.Issuer.DEFAULT_ELEMENT_NAME);
            issuer.setValue(context.getRelyingPartyRegistration().getEntityId());
            authnRequest.setIssuer(issuer);

            // Set ForceAuthn if needed
            // authnRequest.setForceAuthn(false);

            // Set IsPassive if needed
            // authnRequest.setIsPassive(false);

            return authnRequest;
        }
        catch (Exception e) {
            throw new RuntimeException("Error creating SAML AuthnRequest", e);
        }
    }

    public void debugPrintAuthnRequests(AuthnRequest authnRequest) {
        try {
            Element element = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest).marshall(authnRequest);
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");

            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(element), new StreamResult(writer));
            String xml = writer.toString();
            System.out.println("AuthnRequest: " + xml);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Just a mock
    private String getLoginHintEmail() {
        return "vitran@example.com";
    }
}