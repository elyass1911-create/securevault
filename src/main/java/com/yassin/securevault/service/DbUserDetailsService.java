package com.yassin.securevault.service;

import com.yassin.securevault.entity.User;
import com.yassin.securevault.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DbUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public DbUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User u = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        // Spring Security expects roles as authorities; you already use ROLE_ in JWT
        var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + u.getRole().name()));

        return org.springframework.security.core.userdetails.User
                .withUsername(u.getEmail())
                .password(u.getPasswordHash())
                .authorities(authorities)
                .build();
    }
}
