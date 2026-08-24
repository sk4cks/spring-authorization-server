package spring_security.contact.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import spring_security.contact.domain.MailContact;

import java.util.List;
import java.util.Optional;

public interface MailContactRepository extends JpaRepository<MailContact, Long> {

    @Query("""
            select c from MailContact c
            where c.userSeq = :userSeq and c.delYn = 'N'
            order by lower(coalesce(c.displayName, c.email))
            """)
    List<MailContact> findActiveByUserSeq(@Param("userSeq") Long userSeq);

    @Query("""
            select c from MailContact c
            where c.contactSeq = :contactSeq and c.userSeq = :userSeq and c.delYn = 'N'
            """)
    Optional<MailContact> findActiveBySeqAndUser(
            @Param("contactSeq") Long contactSeq, @Param("userSeq") Long userSeq);

    @Query("""
            select case when count(c) > 0 then true else false end from MailContact c
            where c.userSeq = :userSeq and c.delYn = 'N' and lower(c.email) = lower(:email)
            """)
    boolean existsActiveEmail(@Param("userSeq") Long userSeq, @Param("email") String email);

    @Query("""
            select c from MailContact c
            where c.userSeq = :userSeq and c.delYn = 'N' and lower(c.email) = lower(:email)
            """)
    Optional<MailContact> findActiveByUserAndEmail(
            @Param("userSeq") Long userSeq, @Param("email") String email);

    @Query("""
            select c from MailContact c
            where c.contactSeq in :ids and c.delYn = 'N'
            """)
    List<MailContact> findActiveBySeqs(@Param("ids") List<Long> ids);
}
