package com.eazybank.config;

import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import com.eazybank.exception.EazyBankAccessDeniedHandler;
import com.eazybank.filter.AuthoritiesLoggingAtFilter;
import com.eazybank.filter.AuthoritiesLoggingFilterAfter;
import com.eazybank.filter.CsrfCookieFilter;
import com.eazybank.filter.RequestValidationBeforeFilter;
import com.eazybank.filter.jwt.JwtTokenGeneratorFilter;
import com.eazybank.filter.jwt.JwtTokenValidationFilter;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();

		http.cors(cors -> cors.configurationSource(new CorsConfigurationSource() {
			@Override
			public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
				CorsConfiguration config = new CorsConfiguration();
				config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
				config.setAllowedMethods(Collections.singletonList("*"));
				config.setAllowCredentials(true);
				config.setAllowedHeaders(Collections.singletonList("*"));
				config.setExposedHeaders(Collections.singletonList("Authorization"));
				config.setMaxAge(3600L);
				return config;
			}
		})).sessionManagement(smc -> smc.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//				.sessionFixation(sfc -> sfc.none()).invalidSessionUrl("/invalidSession")
//				.maximumSessions(1).maxSessionsPreventsLogin(true))
				.csrf(csrf -> csrf.csrfTokenRequestHandler(csrfHandler)
						.ignoringRequestMatchers("/contact", "/register", "/notices", "/apiLogin")
						.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
				.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
				.addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
				.addFilterAfter(new AuthoritiesLoggingFilterAfter(), BasicAuthenticationFilter.class)
				.addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class)

				.addFilterAfter(new JwtTokenGeneratorFilter(), BasicAuthenticationFilter.class)
				.addFilterBefore(new JwtTokenValidationFilter(), BasicAuthenticationFilter.class)

				.requiresChannel(rcc -> rcc.anyRequest().requiresInsecure()) // ONLY FOR HTTPS REQUEST ENABLE
				.authorizeHttpRequests((requests) -> requests
//						.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
//						.requestMatchers("/myBalance").hasAnyAuthority("VIEWBALANCE", "VIEWACCOUNT")
//						.requestMatchers("/myLoans").hasAuthority("VIEWLOANS").requestMatchers("/myCards")
//						.hasAuthority("VIEWCARDS")
						.requestMatchers("/myAccount").hasRole("USER").requestMatchers("/myBalance")
						.hasAnyRole("USER", "ADMIN").requestMatchers("/myLoans").hasRole("USER")
						.requestMatchers("/myCards").hasRole("USER").requestMatchers("/user").authenticated()
//						.requestMatchers("/myAccount", "/myLoans", "/myCards", "/myBalance", "/user").authenticated()
						.requestMatchers("/contact", "/error", "/register", "/invalidSession", "/notices", "/apiLogin")
						.permitAll().requestMatchers("/h2/**").permitAll());

		http.headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));

		http.formLogin(Customizer.withDefaults());
		// Only httpBasic flow that is during login
		http.httpBasic(hbc -> hbc.authenticationEntryPoint(new EazyBankAuthenticationEntryPoint()));
		// This is global configuration
		http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new EazyBankAccessDeniedHandler()));
		return http.build();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
			PasswordEncoder passwordEncoder) {
		EazyBankAuthenticationProvder authProvider = new EazyBankAuthenticationProvder(userDetailsService,
				passwordEncoder);
		ProviderManager providerManager = new ProviderManager(authProvider);
		providerManager.setEraseCredentialsAfterAuthentication(false);
		return providerManager;
	}
}
