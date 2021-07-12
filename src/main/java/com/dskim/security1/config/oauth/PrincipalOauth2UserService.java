package com.dskim.security1.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.dskim.security1.config.auth.PrincipalDetails;
import com.dskim.security1.model.User;
import com.dskim.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@Autowired
	private UserRepository userRepository;

	// google로부터 받은 userRequest 데이터에 대한 후처리 되는 함수
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		// userRequest.getClientRegistration() > registrationId로 어떤 OAuth로 로그인 했는 지 확인
		// 가능.

		OAuth2User oauth2User = super.loadUser(userRequest);
		System.out.println("getAttributes: " + oauth2User.getAttributes());

		// 회원가입을 강제로 진행해볼 예정
		String provider = userRequest.getClientRegistration().getClientId(); // google
		String providerId = oauth2User.getAttribute("sub");
		String username = provider + "_" + providerId; // google_101046933161514265813
		String password = bCryptPasswordEncoder.encode(username);
		String email = oauth2User.getAttribute("email");
		String role = "ROLE_USER";

		User userEntity = userRepository.findByUsername(username);
		if (userEntity == null) {
			System.out.println("구글 로그인이 최초입니다.");
			userEntity = User.builder().username(username).password(password).email(email).role(role).provider(provider)
					.providerId(providerId).build();
			userRepository.save(userEntity);
		} else {
			System.out.println("구글 로그인을 이미 한적이 있습니다. 당신은 자동회원가입이 되어 있습니다.");
		}

		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}
}
