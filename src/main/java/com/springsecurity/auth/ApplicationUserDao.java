package com.springsecurity.auth;

import org.springframework.context.annotation.Bean;

import java.util.Optional;

public interface ApplicationUserDao {


    Optional<ApplicationUser> selectApplicationByUsername(String username);
}
