package com.dskim.security1.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.dskim.security1.model.User;

import lombok.Data;

// security가 /login address request가 오면 낚아채서 로그인 진행시킴
// 로그인을 진행이 완료가 되면 시큐리티 session을 만들어 줌. (Security ContextHolder)
// 오브젝트 타입 => Authentication 타입 객체만 들어 갈 수 있음
// Authentication 안에 User 정보가 있어야 됨.
// User 오브젝트 타입 => UserDetails 타입 객체

// Security Session => Authentication 객체만 출입 가능 => UserDetails(PrincipalDetails) 타입만 Authentication 객체 안에 저장 가능 

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

	private User user; // composition
	private Map<String, Object> attributes;

	// 일반 로그인 시 사
	public PrincipalDetails(User user) {
		this.user = user;
	}

	// OAuth 로그인
	public PrincipalDetails(User user, Map<String, Object> attributes) {
		this.user = user;
		this.attributes = attributes;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	@Override
	public String getName() {
		return null;
	}

	// 해당 유저의 권한 리턴하는 곳!!
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collect = new ArrayList<GrantedAuthority>();
		collect.add(new GrantedAuthority() {

			@Override
			public String getAuthority() {
				return user.getRole();
			}
		});
		return collect;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		// 우리 사이트에서 1년동안 회원이 로그인을 안하면 휴면 계정으로 하기로 할경우
		// User 모델에 lastLoginDate 같은 걸 작성해서 계산 후 true or false 리
		return true;
	}
}
