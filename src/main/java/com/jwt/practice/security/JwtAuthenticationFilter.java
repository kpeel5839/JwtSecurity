package com.jwt.practice.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean { // GenericFilterBean 을 상속받으면서, Filter 를 Overriding 하여 CustomFilter 를 적용

    private final JwtTokenProvider jwtTokenProvider; // Custom JwtTokenProvider 임

    /**
     * Security 방법은 크게 두 가지가 있는데 하나는 이렇게 Filter 에서 거르는 과정, 그리고 또 하나는 Interceptor 방법이 있다.
     * 둘의 차이점은, Filter 는 Dispatcher Servlet 에 도달하기 이전에 요청을 낚아채 인증을 진행, Interceptor 은 Controller 로 가기 이전에, 낚아 채는 것이다.
     * 그래서 둘의 가장 큰 차이는 Dispatcher Servlet 의 차이이다.
     *
     * Dispatcher Servlet 은 프론트 컨트롤러이다.
     * 옛날에는 요청이 들어오게 되면, 각각의 Controller 가 들어올 수 있게 xml 로 url 을 다 관리했다고 한다.
     * 하지만 지금은 그렇게 안하고 annotation 으로 다 해결할 수 있다, 그게 가능했던 이유는 Dispatcher Servlet 과 같은 프론트 컨트롤러 때문에 가능한 것이다.
     *
     * 그냥 간단히 말하면 Dispatcher Servlet 은 이전에는 Controller 각각이 받았던 요청을 모두 본인이 받아 올바른 Controller 에게 Mapping 해주는 역할을 한다.
     * 그래서 Map 을 사용하여서 <key, value> 형태로 관리하게 된다.
     *
     * 그래서 뭐 요청의 형태들을 가지고 url 과 get, post, put, delete 이냐 이러한 정보를 가지고 올바른 Controller 를 찾는 역할을 한다.
     *
     * 쨌든 Dispatcher Servlet 을 간략하게 설명한 이유는 내가 나중에 까먹을까봐 적어봤다.
     * Dispatcher Servlet 에 대해서 너무 잘 설명한 블로그이니, 나중에 혹시 까먹게 되면 이 링크로 들어가서 다시 보자. https://mangkyu.tistory.com/18
     *
     * 쨋든 Filter 에서 거르게 되면 Readme File 에 있는 사진처럼 로직이 처리되게 된다.
     * 그러면 Filter 에서 해주어야 하는 점은 일단 Header 에서 Token 을 빼내고 (jwtTokenProvider.resolveToken() 에서 request.get("Authorization") 을 통해서 Token 값을 얻어낼 수 있다.)
     *
     * 그리고 해당 Token 이 없으면 token != null 에서 걸리고, 있다라면 validateToken 을 수행하여, 유효기간이 남아있나 확인한다 (JwtToken 의 유효기간은 짧기 때문에, 여기서 계속 새로운 Token 을 발급해 갱신하는 방법도 충분히 가능할 듯)
     * 만일 이것도 통과했다면
     *
     * jwtTokenProvider 의 getAuthentication(token) 을 이용하여, UsernamePasswordAuthenticationToken 을 얻어온다.
     * 위의 메소드에서 유저의 email 을 확인하여 DB 에 등록되어 있는 User 이면 UserDetails 로 감싸고 또 UsernamePasswordAuthenticationToken 로 감싸고 또 최종적으로 Authentication 으로 감싸는 것이다.
     *
     * 그래서 SecurityContextHolder 안에 있는 SecurityContext 에다가 인증 정보를 저장하고
     * request, response 를 다시 등록하고 (잠깐 낚아 챘기 때문에 처리하고 다시 등록) 끝낸다.
     */

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException { // doFilter Overriding
        // 헤더에서 JWT 를 받아옵니다.
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) request);
        // 유효한 토큰인지 확인합니다.
        if (token != null && jwtTokenProvider.validateToken(token)) {
            // 토큰이 유효하면 토큰으로부터 유저 정보를 받아옵니다.
            Authentication authentication = jwtTokenProvider.getAuthentication(token);
            // SecurityContext 에 Authentication 객체를 저장합니다.
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }
}
