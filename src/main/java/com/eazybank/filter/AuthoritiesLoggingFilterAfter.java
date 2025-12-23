package com.eazybank.filter;

import jakarta.servlet.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;

@Slf4j
public class AuthoritiesLoggingFilterAfter implements Filter {

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
    throws IOException, ServletException {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (null != auth) {
      log.info("User " + auth.getName() + " is successfully authenticated and has authorities "
        + auth.getAuthorities().toString());
    }
    chain.doFilter(request, response);
  }

}
