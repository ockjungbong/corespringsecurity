package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response,
			final AuthenticationException exception) throws IOException, ServletException {

		// 디폴트 에러 메세지
		String errorMessage = "Invalid Username or Password";

		// 인증 예외에 따라서 다른 에러 메세지를 출력
		if (exception instanceof BadCredentialsException) {
			errorMessage = "Invalid Username or Password";

		} else if (exception instanceof InsufficientAuthenticationException) {
			errorMessage = "Invalid Secret";
		}

		setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);

		// 최종적으로 클라이언트에게 응답을 보내기 위해 부모 클래스에 위임
		super.onAuthenticationFailure(request, response, exception);

	}

}
