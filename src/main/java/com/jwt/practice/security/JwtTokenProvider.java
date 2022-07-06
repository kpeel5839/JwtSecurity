package com.jwt.practice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.List;

// 토큰을 생성하고 검증하는 클래스입니다.
// 해당 컴포넌트는 필터클래스에서 사전 검증을 거칩니다.
@RequiredArgsConstructor
@Component
public class JwtTokenProvider {
    private String secretKey = "myprojectsecret"; // secretKey 사실 이건 뭐든 중요하지 않다, 중요한 것은 해당 secretKey 를 가지고 base64 로 인코딩하고 디코딩한다는 거?

    // 토큰 유효시간 30분
    private long tokenValidTime = 30 * 60 * 1000L; // 유효시간 조정

    private final UserDetailsService userDetailsService; // userDetailService (기존에 있는 Service class 이다)

    // 객체 초기화, secretKey를 Base64로 인코딩한다.
    @PostConstruct
    protected void init() { // 당연히 객체 초기화에는 secretKey 를 인코딩 해야 한다 인코딩 안하면 JWT 하는 이유가 없음
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // JWT 토큰 생성
    public String createToken(String userPk, List<String> roles) { // Token 을 생성해주는 메소드 (Controller 에서, Token 발급시 사용한다.)
        Claims claims = Jwts.claims().setSubject(userPk); // JWT payload 에 저장되는 정보단위, 보통 여기서 user를 식별하는 값을 넣는다. (payload 에다가 userPk를 넣는다.)
        claims.put("roles", roles); // 정보는 key / value 쌍으로 저장된다.
        Date now = new Date(); // 유효 시간을 설정하기 위해서 현재 시간 + tokenValidTime 즉 유효시간을 더해준다.
        return Jwts.builder() // 그냥 JWT 만드는 과정
                .setClaims(claims) // 정보 저장
                .setIssuedAt(now) // 토큰 발행 시간 정보
                .setExpiration(new Date(now.getTime() + tokenValidTime)) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, secretKey)  // 사용할 암호화 알고리즘과
                // signature 에 들어갈 secret값 세팅
                .compact();
    }

    // JWT 토큰에서 인증 정보 조회
    public Authentication getAuthentication(String token) { // 실제로 JWT TOKEN 에서, userPk 를 뽑아내서 DB 에서 확인한다. 그리고 UsernamePassword... -> Authentication 으로 감싸서 내보냄
        UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserPk(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    // 토큰에서 회원 정보 추출
    public String getUserPk(String token) {
        // Jwt parser 를 이용해서 서명을 등록하고 (secretKey, 이것을 통해서 인증을 해야지 token 의 user 정보를 얻을 수 있다 (인증 과정)) token 내의 userPk 를 꺼냄
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    // Request의 Header에서 token 값을 가져옵니다. "Authorization" : "TOKEN값'
    public String resolveToken(HttpServletRequest request) { // header 도 map 형식인가보다, getHeader method 를 통해서 Token 값을 얻어낸다 (<key, value>)
        return request.getHeader("Authorization");
    }

    // 토큰의 유효성 + 만료일자 확인
    public boolean validateToken(String jwtToken) { // 유효시간 확인
        try {
            // 항상 인증을 하기 위해서는 signingKey 를 등록하고 parseClaimJws 를 통해서 jwtToken 내에 Jws 을 얻어내야 함
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
            return !claims.getBody().getExpiration().before(new Date()); // 지났으면 false
        } catch (Exception e) { // exception 이 발생하면, 인증 안된 거 아닐까
            return false;
        }
    }
}