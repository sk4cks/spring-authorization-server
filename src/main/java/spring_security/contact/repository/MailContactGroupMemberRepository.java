package spring_security.contact.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import spring_security.contact.domain.MailContactGroupMember;

import java.util.List;

public interface MailContactGroupMemberRepository extends JpaRepository<MailContactGroupMember, Long> {

    @Query("""
            select m.contactSeq from MailContactGroupMember m
            where m.groupSeq = :groupSeq and m.contactSeq is not null
            """)
    List<Long> findContactSeqsByGroupSeq(@Param("groupSeq") Long groupSeq);

    @Query("""
            select m.contactSeq from MailContactGroupMember m
            where m.groupSeq in :groupSeqs and m.contactSeq is not null
            """)
    List<Long> findContactSeqsByGroupSeqs(@Param("groupSeqs") List<Long> groupSeqs);

    @Query("""
            select m.memberUserSeq from MailContactGroupMember m
            where m.groupSeq = :groupSeq and m.memberUserSeq is not null
            """)
    List<Long> findUserSeqsByGroupSeq(@Param("groupSeq") Long groupSeq);

    @Modifying(clearAutomatically = true)
    @Query("delete from MailContactGroupMember m where m.groupSeq = :groupSeq")
    void deleteByGroupSeq(@Param("groupSeq") Long groupSeq);
}
