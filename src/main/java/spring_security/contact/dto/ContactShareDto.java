package spring_security.contact.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import spring_security.contact.domain.ContactSharePermission;
import spring_security.contact.domain.MailContactGroupShare;

/**
 * 그룹 공유 API 입출력.
 * 한 그룹을 다른 SYS_USER에게 READ 또는 WRITE로 열어 준다.
 */
public final class ContactShareDto {

    private ContactShareDto() {}


    /**
     * 공유 생성/권한 변경 body.
     *
     * @param sharedWithUserId 공유받을 사람 로그인 id
     * @param permission READ(보기만) 또는 WRITE(멤버·공유 수정)
     */
    public record Request(
            @NotBlank String sharedWithUserId, @NotNull ContactSharePermission permission) {}

    /**
     * 공유 한 줄.
     *
     * @param id SHARE_SEQ
     * @param groupId GROUP_SEQ
     * @param sharedWithUserId 공유받은 사람 로그인 id
     * @param permission 그 사람의 권한
     */
    public record Response(
            Long id, Long groupId, String sharedWithUserId, ContactSharePermission permission) {

        public static Response of(MailContactGroupShare share, String sharedWithUserId) {
            return new Response(
                    share.getShareSeq(), share.getGroupSeq(), sharedWithUserId, share.getPermission());
        }
    }
}
