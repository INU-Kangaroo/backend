package com.kangaroo.sparring.domain.user.service;

import com.kangaroo.sparring.domain.user.dto.AuthResponse;
import com.kangaroo.sparring.domain.user.dto.LoginRequest;
import com.kangaroo.sparring.domain.user.dto.SignupRequest;
import com.kangaroo.sparring.domain.user.entity.User;
import com.kangaroo.sparring.domain.user.repository.UserRepository;
import com.kangaroo.sparring.global.exception.CustomException;
import com.kangaroo.sparring.global.exception.ErrorCode;
import com.kangaroo.sparring.global.security.jwt.JwtUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private UserService userService;

    @Test
    @DisplayName("회원가입 성공 시 사용자 저장은 한 번만 발생하고 토큰을 반환한다")
    void signup_success() {
        SignupRequest request = new SignupRequest("test@example.com", "password123!", "테스터");

        when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(request.getPassword())).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User param = invocation.getArgument(0);
            return User.builder()
                    .id(1L)
                    .email(param.getEmail())
                    .password(param.getPassword())
                    .username(param.getUsername())
                    .build();
        });
        when(jwtUtil.generateAccessToken(1L, request.getEmail())).thenReturn("jwt-token");

        AuthResponse response = userService.signup(request);

        assertThat(response.getUserId()).isEqualTo(1L);
        assertThat(response.getEmail()).isEqualTo(request.getEmail());
        assertThat(response.getAccessToken()).isEqualTo("jwt-token");
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("이메일 중복 시 CustomException(DUPLICATE_EMAIL)을 던진다")
    void signup_duplicateEmail() {
        SignupRequest request = new SignupRequest("dupe@example.com", "password123!", "중복");

        when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);

        assertThatThrownBy(() -> userService.signup(request))
                .isInstanceOf(CustomException.class)
                .satisfies(ex -> assertThat(((CustomException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.DUPLICATE_EMAIL));

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("로그인 성공 시 JWT 토큰을 포함한 응답을 반환한다")
    void login_success() {
        LoginRequest request = new LoginRequest("login@example.com", "password123!");
        User storedUser = User.builder()
                .id(5L)
                .email(request.getEmail())
                .password("encoded-password")
                .username("로그인유저")
                .build();

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(storedUser));
        when(passwordEncoder.matches(request.getPassword(), storedUser.getPassword())).thenReturn(true);
        when(jwtUtil.generateAccessToken(storedUser.getId(), storedUser.getEmail())).thenReturn("jwt-token");

        AuthResponse response = userService.login(request);

        assertThat(response.getUserId()).isEqualTo(5L);
        assertThat(response.getAccessToken()).isEqualTo("jwt-token");
        verify(userRepository).findByEmail(request.getEmail());
        verify(passwordEncoder).matches(request.getPassword(), storedUser.getPassword());
    }

    @Test
    @DisplayName("로그인 시 비밀번호가 일치하지 않으면 CustomException(INVALID_PASSWORD)을 던진다")
    void login_invalidPassword() {
        LoginRequest request = new LoginRequest("login@example.com", "wrong-pass");
        User storedUser = User.builder()
                .id(5L)
                .email(request.getEmail())
                .password("encoded-password")
                .username("로그인유저")
                .build();

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(storedUser));
        when(passwordEncoder.matches(request.getPassword(), storedUser.getPassword())).thenReturn(false);

        assertThatThrownBy(() -> userService.login(request))
                .isInstanceOf(CustomException.class)
                .satisfies(ex -> assertThat(((CustomException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_PASSWORD));

        verify(jwtUtil, never()).generateAccessToken(anyLong(), anyString());
    }
}
