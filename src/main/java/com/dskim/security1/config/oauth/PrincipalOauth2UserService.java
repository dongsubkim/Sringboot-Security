package com.dskim.security1.config.oauth;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.dskim.security1.config.auth.PrincipalDetails;
import com.dskim.security1.config.oauth.provider.FacebookUserInfo;
import com.dskim.security1.config.oauth.provider.GoogleUserInfo;
import com.dskim.security1.config.oauth.provider.NaverUserInfo;
import com.dskim.security1.config.oauth.provider.OAuth2UserInfo;
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
		System.out.println("getClientRegistration: " + userRequest.getClientRegistration());
		System.out.println("getAccessToken: " + userRequest.getAccessToken());
		// userRequest.getClientRegistration() > registrationId로 어떤 OAuth로 로그인 했는 지 확인
		// 가능.

		OAuth2User oauth2User = super.loadUser(userRequest);
		System.out.println("getAttributes: " + oauth2User.getAttributes());

		// 회원가입을 강제로 진행해볼 예정
		OAuth2UserInfo oAuth2UserInfo = null;
		if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
			System.out.println("Google login request");
			oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
		} else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
			System.out.println("Facebook login request");
			oAuth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
		} else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
			System.out.println("Naver login request");
			oAuth2UserInfo = new NaverUserInfo((Map) oauth2User.getAttributes().get("response"));
		} else {
			System.out.println("우리는 구글과 페이스북, 네이버 만 지원해요.");
		}
		String provider = oAuth2UserInfo.getProvider();
		String providerId = oAuth2UserInfo.getProviderId();
		String username = provider + "_" + providerId;
		String password = bCryptPasswordEncoder.encode(username);
		String email = oAuth2UserInfo.getEmail();
		String role = "ROLE_USER";

		User userEntity = userRepository.findByUsername(username);
		if (userEntity == null) {
			System.out.println("최초 로그인 요청입니다. ");
			userEntity = User.builder().username(username).password(password).email(email).role(role).provider(provider)
					.providerId(providerId).build();
			userRepository.save(userEntity);
		} else {
			System.out.println("이미 한적이 있습니다. 당신은 자동회원가입이 되어 있습니다.");
		}

		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}
}
