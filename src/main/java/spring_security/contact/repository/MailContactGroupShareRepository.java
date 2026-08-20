package spring_security.contact.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import spring_security.contact.domain.MailContactGroupShare;

import java.util.List;
import java.util.Optional;

public interface MailContactGroupShareRepository extends JpaRepository<MailContactGroupShare, Long> {

    @Query("""
            select s from MailContactGroupShare s
            where s.groupSeq = :groupSeq and s.delYn = 'N'
            order by s.shareSeq
            """)
    List<MailContactGroupShare> findActiveByGroupSeq(@Param("groupSeq") Long groupSeq);

    @Query("""
            select s from MailContactGroupShare s
            where s.groupSeq = :groupSeq and s.sharedWithUserSeq = :userSeq and s.delYn = 'N'
            """)
    Optional<MailContactGroupShare> findActive(
            @Param("groupSeq") Long groupSeq, @Param("userSeq") Long userSeq);

    @Query("""
            select s from MailContactGroupShare s
            where s.shareSeq = :shareSeq and s.groupSeq = :groupSeq and s.delYn = 'N'
            """)
    Optional<MailContactGroupShare> findActiveBySeqAndGroup(
            @Param("shareSeq") Long shareSeq, @Param("groupSeq") Long groupSeq);
}
