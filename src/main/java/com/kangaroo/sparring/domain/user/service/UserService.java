package com.kangaroo.sparring.domain.user.service;

import com.kangaroo.sparring.domain.user.dto.AuthResponse;
import com.kangaroo.sparring.domain.user.dto.LoginRequest;
import com.kangaroo.sparring.domain.user.dto.SignupRequest;
import com.kangaroo.sparring.domain.user.entity.SocialProvider;
import com.kangaroo.sparring.domain.user.entity.User;
import com.kangaroo.sparring.domain.user.repository.UserRepository;
import com.kangaroo.sparring.global.exception.CustomException;
import com.kangaroo.sparring.global.exception.ErrorCode;
import com.kangaroo.sparring.global.security.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @Transactional
    public AuthResponse signup(SignupRequest request) {
        log.info("회원가입 시도: {}", request.getEmail());

        validateDuplicateEmail(request.getEmail());
        User user = userRepository.save(createUser(request));

        log.info("회원가입 성공: userId={}, email={}", user.getId(), user.getEmail());

        return generateAuthResponse(user);
    }

    // 이메일 중복 체크
    private void validateDuplicateEmail(String email) {
        if (userRepository.existsByEmail(email)) {
            throw new CustomException(ErrorCode.DUPLICATE_EMAIL);
        }
    }

    // 사용자 생성
    private User createUser(SignupRequest request) {
        return User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .username(request.getUsername())
                .build();
    }

    private AuthResponse generateAuthResponse(User user) {
        String accessToken = jwtUtil.generateAccessToken(user.getId(), user.getEmail());
        return AuthResponse.of(user.getId(), user.getEmail(), user.getUsername(), accessToken);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        log.info("로그인 시도: {}", request.getEmail());

        // 사용자 조회
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        // 비밀번호 검증
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new CustomException(ErrorCode.INVALID_PASSWORD);
        }

        // 탈퇴/비활성 사용자 체크
        if (!user.getIsActive() || user.isDeleted()) {
            throw new CustomException(ErrorCode.INACTIVE_USER);
        }

        // 마지막 로그인 시간 업데이트
        user.updateLastLogin();

        // JWT 토큰 생성
        String accessToken = jwtUtil.generateAccessToken(user.getId(), user.getEmail());

        log.info("로그인 성공: userId={}", user.getId());
        return AuthResponse.of(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                accessToken
        );
    }
}
