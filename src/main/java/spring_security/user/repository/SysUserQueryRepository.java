package spring_security.user.repository;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;
import spring_security.user.domain.AuthProvider;
import spring_security.common.constants.DelYn;
import spring_security.user.domain.SysUser;
import spring_security.user.domain.UserStatus;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static spring_security.user.domain.QSysUser.sysUser;

/**
 * SYS_USER 조회 (Querydsl). 탈퇴({@code DEL_YN=Y})는 기본으로 제외.
 * 쓰기는 {@link SysUserRepository}.
 */
@Repository
@RequiredArgsConstructor
public class SysUserQueryRepository {

    private final JPAQueryFactory queryFactory;

    /** 탈퇴하지 않은 SYS_USER. */
    private static BooleanExpression notDeleted() {
        return sysUser.delYn.eq(DelYn.N);
    }

    /** 로컬 로그인. LOCAL + ACTIVE + 미삭제만. */
    public Optional<SysUser> findByUserIdAndAuthProviderAndStatus(
            String userId, AuthProvider authProvider, UserStatus status) {
        SysUser result = queryFactory
                .selectFrom(sysUser)
                .where(
                        sysUser.userId.eq(userId),
                        sysUser.authProvider.eq(authProvider),
                        sysUser.status.eq(status),
                        notDeleted())
                .fetchOne();

        return Optional.ofNullable(result);
    }

    /** userId 정확 일치. 로그인·탈퇴·메일함. */
    public Optional<SysUser> findByUserId(String userId) {
        SysUser result = queryFactory
                .selectFrom(sysUser)
                .where(sysUser.userId.eq(userId), notDeleted())
                .fetchOne();

        return Optional.ofNullable(result);
    }

    /** PK로 한 건. 그룹 소유자 id를 붙일 때. */
    public Optional<SysUser> findByUserSeq(Long userSeq) {
        SysUser result = queryFactory
                .selectFrom(sysUser)
                .where(sysUser.userSeq.eq(userSeq), notDeleted())
                .fetchOne();

        return Optional.ofNullable(result);
    }

    /** 주소록 디렉터리. 탈퇴하지 않은 전체. */
    public List<SysUser> findAllActive() {
        return queryFactory
                .selectFrom(sysUser)
                .where(notDeleted())
                .orderBy(sysUser.userId.asc())
                .fetch();
    }

    /** 그룹 계정 멤버 펼치기. */
    public List<SysUser> findActiveByUserSeqs(Collection<Long> userSeqs) {
        // Hibernate in () 빈 리스트 방지.
        if (userSeqs == null || userSeqs.isEmpty()) {
            return List.of();
        }

        return queryFactory
                .selectFrom(sysUser)
                .where(sysUser.userSeq.in(userSeqs), notDeleted())
                .orderBy(sysUser.userId.asc())
                .fetch();
    }

    /** 가입 계정 메일과 개인 연락처가 겹치는지. 대소문자 무시. */
    public boolean existsActiveMailIgnoreCase(String mailAddress) {
        if (!StringUtils.hasText(mailAddress)) {
            return false;
        }

        Integer found = queryFactory
                .selectOne()
                .from(sysUser)
                .where(
                        notDeleted(),
                        sysUser.mailAddress.lower().eq(mailAddress.trim().toLowerCase(Locale.ROOT)))
                .fetchFirst();

        return found != null;
    }

    /** 그 메일의 가입 계정. 그룹 멤버를 계정 seq로 바꿀 때. */
    public Optional<SysUser> findActiveByMailIgnoreCase(String mailAddress) {
        if (!StringUtils.hasText(mailAddress)) {
            return Optional.empty();
        }

        SysUser result = queryFactory
                .selectFrom(sysUser)
                .where(
                        notDeleted(),
                        sysUser.mailAddress.lower().eq(mailAddress.trim().toLowerCase(Locale.ROOT)))
                .fetchOne();

        return Optional.ofNullable(result);
    }

    /** userId 중복. 가입 전 체크. */
    public boolean existsByUserId(String userId) {
        Integer found = queryFactory
                .selectOne()
                .from(sysUser)
                .where(sysUser.userId.eq(userId), notDeleted())
                .fetchFirst();

        return found != null;
    }

    /** 메일 주소 정확 일치 중복. */
    public boolean existsByMailAddress(String mailAddress) {
        Integer found = queryFactory
                .selectOne()
                .from(sysUser)
                .where(sysUser.mailAddress.eq(mailAddress), notDeleted())
                .fetchFirst();

        return found != null;
    }

    /** SNS provider + 외부 id로 온보딩된 계정. */
    public Optional<SysUser> findByAuthProviderAndExternalId(AuthProvider authProvider, String externalId) {
        SysUser result = queryFactory
                .selectFrom(sysUser)
                .where(
                        sysUser.authProvider.eq(authProvider),
                        sysUser.externalId.eq(externalId),
                        notDeleted())
                .fetchOne();

        return Optional.ofNullable(result);
    }

    /** 같은 SNS 계정이 이미 SYS_USER에 있는지. */
    public boolean existsByAuthProviderAndExternalId(AuthProvider authProvider, String externalId) {
        Integer found = queryFactory
                .selectOne()
                .from(sysUser)
                .where(
                        sysUser.authProvider.eq(authProvider),
                        sysUser.externalId.eq(externalId),
                        notDeleted())
                .fetchFirst();

        return found != null;
    }
}
