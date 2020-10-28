package com.springsecurity;

import com.springsecurity.auth.ApplicationUserDao;
import com.springsecurity.auth.FakeApplicationUserDaoService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringSecurityWithAmigoscodeApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityWithAmigoscodeApplication.class, args);
	}

}
