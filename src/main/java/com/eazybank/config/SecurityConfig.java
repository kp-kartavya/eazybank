package com.eazybank.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
//		.requiresChannel(rcc -> rcc.anyRequest().requiresSecure()) // ONLY FOR HTTPS REQUEST ENABLE
				.authorizeHttpRequests(
						(requests) -> requests.requestMatchers("/myAccounts", "/myLoans", "/myCards", "/myBalances")
								.authenticated().requestMatchers("/myNotices", "/myContacts", "/error", "/register")
								.permitAll());

		http.headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));
		http.csrf(csrf -> csrf.disable());

		http.formLogin(Customizer.withDefaults());
		http.httpBasic(hbc -> hbc.authenticationEntryPoint(new EazyBankAuthenticationEntryPoint())); // Only during httpBasic flow that is during login
//		http.exceptionHandling(ehc -> ehc.authenticationEntryPoint(new EazyBankAuthenticationEntryPoint())); // This is global configuration
		return http.build();
	}

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
