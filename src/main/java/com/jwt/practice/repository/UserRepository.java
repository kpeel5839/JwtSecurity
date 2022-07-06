package com.jwt.practice.repository;

import com.jwt.practice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUserEmail(String userEmail); // findByUserEmail 을 만들어서, AuthenticationProvider -> CustomUserDetailService 에서 요청을 보내게 되면 User 를 반환한다.
}
