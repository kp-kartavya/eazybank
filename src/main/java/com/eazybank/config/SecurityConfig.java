package com.eazybank.config;

import com.eazybank.exception.EazyBankAccessDeniedHandler;
import com.eazybank.filter.CsrfCookieFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
public class SecurityConfig {
  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();

    http.securityContext(sc -> sc.requireExplicitSave(false))
        .cors(cors -> cors.configurationSource(new CorsConfigurationSource() {
          @Override
          public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
            config.setAllowedMethods(Collections.singletonList("*"));
            config.setAllowCredentials(true);
            config.setAllowedHeaders(Collections.singletonList("*"));
            config.setMaxAge(3600L);
            return config;
          }
        })).sessionManagement(smc -> smc.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
//				.sessionFixation(sfc -> sfc.none()).invalidSessionUrl("/invalidSession")
//				.maximumSessions(1).maxSessionsPreventsLogin(true))
        .csrf(csrf -> csrf.csrfTokenRequestHandler(csrfHandler)
            .ignoringRequestMatchers("/contact", "/register", "/notices")
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
        .requiresChannel(rcc -> rcc.anyRequest().requiresInsecure()) // ONLY FOR HTTPS REQUEST ENABLE
        .authorizeHttpRequests((requests) -> requests
            .requestMatchers("/myAccount", "/myLoans", "/myCards", "/myBalance", "/user").authenticated()
            .requestMatchers("/contact", "/error", "/register", "/invalidSession", "/notices").permitAll()
            .requestMatchers("/h2/**").permitAll());

    http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

    http.formLogin(Customizer.withDefaults());
    // Only httpBasic flow that is during login
    http.httpBasic(hbc -> hbc.authenticationEntryPoint(new EazyBankAuthenticationEntryPoint()));
    // This is global configuration
    http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new EazyBankAccessDeniedHandler()));
    return http.build();
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
