package com.eazybytes.springsecurity.filter;

import jakarta.servlet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class AuthoritiesLoggingBeforeFilter implements Filter {

    private Logger logger = LoggerFactory.getLogger(AuthoritiesLoggingBeforeFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        logger.info("Authentication Validation started");
        chain.doFilter(request, response);
    }
}
