package study.security.sessionmanagement.core.controller;

import lombok.*;

import java.time.LocalDateTime;
import java.util.Date;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class SessionInfo {

    private String sessionId;
    private Date time;
}
