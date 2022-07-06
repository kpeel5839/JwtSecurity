package com.jwt.practice.service;

import com.jwt.practice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor // UserRepository Bean 주입
@Service
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { // UserNameNotFouncException 을 던짐 못 찾으면
        return userRepository.findByUserEmail(username) // 근데 여기서 UserDetails 를 반환할 수 있는 이유는 UserDetails 를 상속받았어서?
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
    }
}