package com.dskim.security1.config;
//google login 후처리 필요 1. 코드받기(인증된 사용) 2. 엑세스토큰(사용자 정보 접근 권한 획득) 3. 사용자프로필 가져오기 

//4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
//4-2. 추가 정보가 필요할 경우 추가 정보 요
//Tip. 코드X, (엑세스토큰 + 사용자프로필 정보O)를 한번에 받음 

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.dskim.security1.config.oauth.PrincipalOauth2UserService;

@Configuration
@EnableWebSecurity // spring security filter가 spring filter chain에 등록
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured annotation 활성화, preAuthorize,
																			// postAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;

	// Bean annotation > 해당 메서드의 리턴되는 오브젝트를 IoC로 등록
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests().antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소
				.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
				.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')").anyRequest().permitAll().and().formLogin()
				.loginPage("/loginForm").loginProcessingUrl("/login") // /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인 진행
				.defaultSuccessUrl("/").and().oauth2Login().loginPage("/loginForm").userInfoEndpoint()
				.userService(principalOauth2UserService);
	}

}
