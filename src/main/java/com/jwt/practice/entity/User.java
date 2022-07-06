package com.jwt.practice.entity;

import com.jwt.practice.enumtype.Admin;
import com.jwt.practice.enumtype.Gender;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Builder
@Data
@Entity
@Table(name = "T_USER")
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails { // UserDetails는 시큐리티가 관리하는 객체이다 (그래서 UserDetails 를 상속 받음)

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "USER_SEQUENCE_ID")
    private Long userSequenceId;

    @Column(name = "USER_EMAIL", nullable = false, length = 100, unique = true)
    private String userEmail;

    @Column(name = "USER_BIRTH", length = 6)
    private String userBirth;

    @Column(name = "USER_NICKNAME", length = 15)
    private String userNickname;

    @Column(name = "GENDER", length = 1)
    @Enumerated(EnumType.STRING)
    private Gender gender;

    @Column(name = "ADMIN", length = 4)
    @Enumerated(EnumType.STRING) // 열거형으로 관리되는 컬럼
    private Admin admin;

    // 해당 컬럼이 컬렉션이라는 것을 알려주고, 그냥 @OneToMany 로 관리된다고 생각하면 됨, 하지만 roles 가 따로 독립적일 수는 없음, 그게 OneToMany 와 차이점
    @ElementCollection(fetch = FetchType.EAGER)
    @Builder.Default
    private List<String> roles = new ArrayList<>();


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { // UserDetails 의 메소드를 오버라이딩 한 것임
        return this.roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList()); // 유저의 roles 를 stream 을 통해서 SimpleGrantedAuthority 로 다 감싸고, List 로써 다시 반환한다. (처리한 결과를)
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return userEmail;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}