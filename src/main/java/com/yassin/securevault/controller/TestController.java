package com.yassin.securevault.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
public class TestController {

    @GetMapping("/api/hello")
    public String hello(Authentication auth) {
        return "Hello " + (auth != null ? auth.getName() : "anonymous");
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/api/admin")
    public String admin(Authentication auth) {
        return "Admin area for " + auth.getName();
    }
}
