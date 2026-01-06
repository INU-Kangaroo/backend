package com.kangaroo.sparring.domain.user.dto.res;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
@Schema(description = "메시지 응답")
public class MessageResponse {

    @Schema(description = "이메일")
    private String email;

    @Schema(description = "응답 메시지")
    private String message;

    public static MessageResponse of(String email, String message) {
        return new MessageResponse(email, message);
    }
}