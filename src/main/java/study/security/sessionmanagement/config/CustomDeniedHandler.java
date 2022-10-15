package study.security.sessionmanagement.config;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import study.security.sessionmanagement.core.controller.YouCannotAccessUserPage;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        if (accessDeniedException instanceof YouCannotAccessUserPage) {
            request.getRequestDispatcher("/access-denied").forward(request, response);
        } else {
            request.getRequestDispatcher("/access-denied").forward(request, response);
        }
    }
}
