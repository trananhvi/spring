package com.vitran.login;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/saml_login", "/saml_login_handler").permitAll()
                        .anyRequest().authenticated()
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
}
