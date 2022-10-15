package study.security.sessionmanagement.core.repositoy;

import org.springframework.data.jpa.repository.JpaRepository;
import study.security.sessionmanagement.core.domain.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findMemberByEmail(String email);

}
