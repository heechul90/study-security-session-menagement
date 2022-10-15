package study.security.sessionmanagement.core.controller;

import lombok.*;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
public class UserSession {

    private String username;
    private List<SessionInfo> sessions;

    public int getCount() {
        return sessions.size();
    }
}
