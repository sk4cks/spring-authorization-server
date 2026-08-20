package spring_security.contact.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import spring_security.contact.domain.MailContactGroupMember;

import java.util.List;

public interface MailContactGroupMemberRepository
        extends JpaRepository<MailContactGroupMember, MailContactGroupMember.Pk> {

    List<MailContactGroupMember> findByGroupSeq(Long groupSeq);

    @Query("select m.contactSeq from MailContactGroupMember m where m.groupSeq = :groupSeq")
    List<Long> findContactSeqsByGroupSeq(@Param("groupSeq") Long groupSeq);

    @Modifying(clearAutomatically = true)
    @Query("delete from MailContactGroupMember m where m.groupSeq = :groupSeq")
    void deleteByGroupSeq(@Param("groupSeq") Long groupSeq);

    @Query("""
            select m.contactSeq from MailContactGroupMember m
            where m.groupSeq in :groupSeqs
            """)
    List<Long> findContactSeqsByGroupSeqs(@Param("groupSeqs") List<Long> groupSeqs);
}
