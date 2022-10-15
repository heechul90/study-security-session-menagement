package study.security.sessionmanagement.core.controller;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class YouCannotAccessUserPage extends AccessDeniedException {

    public YouCannotAccessUserPage() {
        super("유저페이지 접근 거부");
    }
}
