package com.eazybank.filter.jwt;

import com.eazybank.utils.ApplicationConstants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtTokenGeneratorFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (null != auth) {
      Environment env = getEnvironment();
      if (null != env) {
        String secret = env.getProperty(ApplicationConstants.JWT_SECRET_KEY,
          ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        String jwt = Jwts.builder().issuer("Eazy Bank").subject("Jwt Token").claim("username", auth.getName())
          .claim("authorities",
            auth.getAuthorities().stream().map(GrantedAuthority::getAuthority)
              .collect(Collectors.joining(",")))
          .issuedAt(new Date()).expiration(new Date(new Date().getTime() + 30000000)).signWith(key)
          .compact();
        response.setHeader(ApplicationConstants.JWT_HEADER, jwt);
      }
    }
    filterChain.doFilter(request, response);
  }

  protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    return !request.getServletPath().equals("/user");
  }
}
