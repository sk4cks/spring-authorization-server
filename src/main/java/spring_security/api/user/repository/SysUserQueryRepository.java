package spring_security.api.user.repository;

import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import spring_security.api.user.domain.AuthProvider;
import spring_security.api.user.domain.SysUser;
import spring_security.api.user.domain.UserStatus;

import java.util.Optional;

import static spring_security.api.user.domain.QSysUser.sysUser;

@Repository
@RequiredArgsConstructor
public class SysUserQueryRepository {

    private final JPAQueryFactory queryFactory;

    public Optional<SysUser> findByUserIdAndAuthProviderAndStatus(
            String userId, AuthProvider authProvider, UserStatus status) {
        SysUser result = queryFactory
                .selectFrom(sysUser)
                .where(
                        sysUser.userId.eq(userId),
                        sysUser.authProvider.eq(authProvider),
                        sysUser.status.eq(status))
                .fetchOne();
        return Optional.ofNullable(result);
    }

    public Optional<SysUser> findByUserId(String userId) {
        SysUser result = queryFactory
                .selectFrom(sysUser)
                .where(sysUser.userId.eq(userId))
                .fetchOne();
        return Optional.ofNullable(result);
    }

    public boolean existsByUserId(String userId) {
        Integer found = queryFactory
                .selectOne()
                .from(sysUser)
                .where(sysUser.userId.eq(userId))
                .fetchFirst();
        return found != null;
    }

    public boolean existsByMailAddress(String mailAddress) {
        Integer found = queryFactory
                .selectOne()
                .from(sysUser)
                .where(sysUser.mailAddress.eq(mailAddress))
                .fetchFirst();
        return found != null;
    }
}
