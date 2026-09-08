package spring_security.contact.repository;

import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import static spring_security.contact.domain.QMailContactGroupMember.mailContactGroupMember;

/**
 * 주소록 쓰기.
 * 엔티티가 MailContact / Group / Member / Share 네 종류라 {@code JpaRepository<한타입>} 대신
 * {@link EntityManager#persist}로 INSERT한다. 조회는 {@link ContactQueryRepository}.
 */
@Repository
@RequiredArgsConstructor
public class ContactRepository {

    private final EntityManager entityManager;
    private final JPAQueryFactory queryFactory;

    /** 새 엔티티 INSERT. PK는 DB 시퀀스가 persist 시점에 채워진다. */
    public <T> T save(T entity) {
        // merge가 아니라 persist. 호출부는 항상 새 엔티티다.
        entityManager.persist(entity);

        return entity;
    }

    /**
     * 그 그룹의 MAIL_CONTACT_GROUP_MEMBER를 전부 DELETE.
     * bulk라 영속성 컨텍스트와 어긋날 수 있어 flush 후 clear한다. 멤버 전체 교체 전에 호출한다.
     */
    public void deleteByGroupSeq(Long groupSeq) {
        // 앞에서 persist한 소유자 연락처 복사가 DB에 반영되게 먼저 flush.
        entityManager.flush();

        queryFactory
                .delete(mailContactGroupMember)
                .where(mailContactGroupMember.groupSeq.eq(groupSeq))
                .execute();

        // bulk delete 뒤 캐시된 멤버 엔티티가 남지 않게 비운다.
        entityManager.clear();
    }
}
