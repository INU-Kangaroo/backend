package com.kangaroo.sparring.global.security.oauth2.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kangaroo.sparring.domain.user.dto.AuthResponse;
import com.kangaroo.sparring.global.security.jwt.JwtUtil;
import com.kangaroo.sparring.global.security.oauth2.user.CustomOAuth2User;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

        Long userId = oAuth2User.getUserId();
        String email = oAuth2User.getEmail();
        String username = oAuth2User.getUsername();

        log.info("OAuth2 Login Success - UserId: {}, Email: {}, Username: {}", userId, email, username);

        String accessToken = jwtUtil.generateAccessToken(userId, email);

        AuthResponse authResponse = AuthResponse.builder()
                .accessToken(accessToken)
                .userId(userId)
                .email(email)
                .username(username)
                .tokenType("Bearer")
                .build();

        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write(objectMapper.writeValueAsString(authResponse));

        log.info("JWT Token issued for user: {}", email);
    }
}
