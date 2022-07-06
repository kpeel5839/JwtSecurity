package com.jwt.practice.config;

import com.jwt.practice.security.JwtAuthenticationFilter;
import com.jwt.practice.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtTokenProvider jwtTokenProvider;

    // authenticationManager를 Bean 등록합니다.
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception { // Bean 으로 등록함으로서 AuthenticationManager 를 사용 가능케한다.
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(WebSecurity web) throws Exception { // h2 database 가 접속이 안되서 해당 configure 를 추가했음
        web.ignoring().antMatchers("/h2-console/**"); // 여기서, 그냥 ignoring 해주어야함, http 에서 거르면 통과를 못하네..
        // 일단 여기서 먼저 통과시켜야지 할 수 있는 듯
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();
        //http.httpBasic().disable(); // 일반적인 루트가 아닌 다른 방식으로 요청시 거절, header에 id, pw가 아닌 token(jwt)을 달고 간다. 그래서 basic이 아닌 bearer를 사용한다.
        http.httpBasic().disable()
                .authorizeRequests()
                // 요청에 대한 사용권한 체크, 여기서 해당 url 을 authenticated 한다고 해서, 다른 url 들이 filter 를 안거치는게 아님, 모든 요청은 filter 를 거침, 하지만, 다른 url 들은 authenticated 를 통해 SecurityContext 내에 있는 Authentication 을 확인안 할 뿐임
                .antMatchers("/test").authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasRole("USER") // ROLE 에다가 ROLE_ADMIN or ROLE_USER 를 입력하면, 접근 권한 설정 가능함
                .antMatchers("/**").permitAll()
                .and()
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), // Filter 를 등록
                        UsernamePasswordAuthenticationFilter.class); // JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 전에 넣는다
        // + 토큰에 저장된 유저정보를 활용하여야 하기 때문에 CustomUserDetailService 클래스를 생성합니다.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 세션 사용안한다고 명시


    }
}
