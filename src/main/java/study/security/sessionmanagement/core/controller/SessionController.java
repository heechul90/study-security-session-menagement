package study.security.sessionmanagement.core.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import study.security.sessionmanagement.core.domain.User;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Controller
@RequiredArgsConstructor
public class SessionController {

    private final SessionRegistry sessionRegistry;

    @GetMapping("/sessions")
    public String sessions(Model model) {
        List<UserSession> sessionList = sessionRegistry.getAllPrincipals().stream()
                .map(principal -> UserSession.builder()
                        .username(((User) principal).getUsername())
                        .sessions(
                                sessionRegistry.getAllSessions(principal, false).stream()
                                        .map(session -> SessionInfo.builder()
                                                .sessionId(session.getSessionId())
                                                .time(session.getLastRequest())
                                                .build()
                                        )
                                        .collect(Collectors.toList())
                        )
                        .build()
                )
                .collect(Collectors.toList());
        model.addAttribute("sessionList", sessionList);
        return "/sessionList";
    }

    @PostMapping("/session/expire")
    public String expireSession(@RequestParam String sessionId) {
        SessionInformation sessionInformation = sessionRegistry.getSessionInformation(sessionId);
        if (!sessionInformation.isExpired()) {
            sessionInformation.expireNow();
        }
        return "redirect:/sessions";
    }

    @GetMapping("/session-expired")
    public String sessionexpired() {
        return "/sessionExpired";
    }
}
