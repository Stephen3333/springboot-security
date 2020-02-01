package com.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
      /*  http.csrf().disable().authorizeRequests()
               //.antMatchers("/").permitAll()
                .antMatchers("/users").hasRole("ADMIN")
                .antMatchers("/").hasAnyRole("USER","ADMIN")
                //.antMatchers("/").hasRole("USER")
               // .antMatchers(HttpMethod.POST, "/login").permitAll().anyRequest().authenticated().and().formLogin();

                .antMatchers( "/login").permitAll().anyRequest().authenticated().and().formLogin();
               //.anyRequest().authenticated()
              */ 
              /*  .and()
                // We filter the api/login requests
                .addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                // And filter other requests to check the presence of JWT in header
                .addFilterBefore(new JWTAuthenticationFilter(),
                        UsernamePasswordAuthenticationFilter.class);
      */
    	
    	 http.csrf().disable().authorizeRequests()
         .antMatchers("/").permitAll()
         .antMatchers(HttpMethod.POST, "/login").permitAll()
         .anyRequest().authenticated()
         .and()
         // We filter the api/login requests
         .addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
                 UsernamePasswordAuthenticationFilter.class)
         // And filter other requests to check the presence of JWT in header
         .addFilterBefore(new JWTAuthenticationFilter(),
                 UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Create a default account
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("password")
                //.roles("ADMIN", "USER")
                .roles("ADMIN");
//                .and().withUser("user")
//                .password("user")
//                .roles("USER");
    }
    @Bean
    public PasswordEncoder getPasswordEncoder(){
    	return NoOpPasswordEncoder.getInstance();
    }
    }
