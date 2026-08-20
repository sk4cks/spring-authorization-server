package spring_security.contact.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import spring_security.contact.domain.MailContactGroup;

import java.util.List;
import java.util.Optional;

public interface MailContactGroupRepository extends JpaRepository<MailContactGroup, Long> {

    @Query("""
            select g from MailContactGroup g
            where g.ownerUserSeq = :ownerUserSeq and g.delYn = 'N'
            order by lower(g.name)
            """)
    List<MailContactGroup> findActiveByOwner(@Param("ownerUserSeq") Long ownerUserSeq);

    @Query("""
            select g from MailContactGroup g
            where g.groupSeq = :groupSeq and g.delYn = 'N'
            """)
    Optional<MailContactGroup> findActiveBySeq(@Param("groupSeq") Long groupSeq);

    @Query("""
            select g from MailContactGroup g
            where g.delYn = 'N'
              and (g.ownerUserSeq = :userSeq
                   or g.groupSeq in (
                        select s.groupSeq from MailContactGroupShare s
                        where s.sharedWithUserSeq = :userSeq and s.delYn = 'N'))
            order by lower(g.name)
            """)
    List<MailContactGroup> findAccessibleByUser(@Param("userSeq") Long userSeq);

    @Query("""
            select g from MailContactGroup g
            where g.delYn = 'N'
              and lower(g.name) like lower(concat('%', :q, '%'))
              and (g.ownerUserSeq = :userSeq
                   or g.groupSeq in (
                        select s.groupSeq from MailContactGroupShare s
                        where s.sharedWithUserSeq = :userSeq and s.delYn = 'N'))
            order by lower(g.name)
            """)
    List<MailContactGroup> searchAccessibleByUser(@Param("userSeq") Long userSeq, @Param("q") String q);
}
