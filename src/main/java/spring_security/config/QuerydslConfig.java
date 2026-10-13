package spring_security.config;

import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class QuerydslConfig {

    @PersistenceContext
    private EntityManager entityManager;

    /** 주소록·사용자 Querydsl 조회용 팩토리. */
    @Bean
    public JPAQueryFactory jpaQueryFactory() {
        // ContactQueryRepository / SysUserQueryRepository가 이 팩토리로 조회.
        return new JPAQueryFactory(entityManager);
    }
}
