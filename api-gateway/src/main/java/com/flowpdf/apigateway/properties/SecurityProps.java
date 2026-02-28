package com.flowpdf.apigateway.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.security")
public record SecurityProps(
        String userLoginHeader,
        String userLoginClaim
) {}