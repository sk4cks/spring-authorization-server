package spring_security.contact.dto;

import jakarta.validation.constraints.NotBlank;
import spring_security.contact.domain.ContactSharePermission;
import spring_security.contact.domain.MailContactGroup;

import java.util.List;

/**
 * 연락처 그룹 API 입출력.
 * 멤버는 가입 계정과 소유자 MAIL_CONTACT가 한 리스트에 섞인다.
 */
public final class ContactGroupDto {

    private ContactGroupDto() {}


    /**
     * 그룹 생성·이름 변경 body.
     *
     * @param name 그룹 이름
     */
    public record Request(@NotBlank String name) {}

    /**
     * 멤버 전체 교체 body. 둘 다 비어 있으면 멤버 없는 그룹이 된다.
     *
     * @param contactIds MAIL_CONTACT PK. 소유자 또는 WRITE 공유자 본인 주소록이어야 함
     * @param accountUserSeqs 가입 계정 USER_SEQ
     */
    public record MembersRequest(List<Long> contactIds, List<Long> accountUserSeqs) {}

    /**
     * 그룹 한 건 + 멤버.
     *
     * @param id GROUP_SEQ
     * @param name 그룹 이름
     * @param owned 지금 보는 사람이 소유자인지
     * @param permission 소유자면 항상 WRITE, 아니면 공유 권한
     * @param ownerUserId 소유자 로그인 id
     * @param sharedByUserId 공유해 준 사람. 내 그룹이면 null
     * @param members 계정 멤버 + 주소록 멤버
     */
    public record Response(
            Long id,
            String name,
            boolean owned,
            ContactSharePermission permission,
            String ownerUserId,
            String sharedByUserId,
            List<ContactDto.Response> members) {

        public static Response of(
                MailContactGroup group,
                boolean owned,
                ContactSharePermission permission,
                String ownerUserId,
                String sharedByUserId,
                List<ContactDto.Response> members) {
            return new Response(
                    group.getGroupSeq(),
                    group.getName(),
                    owned,
                    permission,
                    ownerUserId,
                    sharedByUserId,
                    members);
        }
    }
}
