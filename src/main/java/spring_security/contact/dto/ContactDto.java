package spring_security.contact.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import spring_security.contact.domain.MailContact;
import spring_security.user.domain.SysUser;

/**
 * 연락처 API 입출력.
 * 같은 JSON으로 가입 계정({@code fromAccount=true})과 수동 주소록 행 응답.
 */
public final class ContactDto {

    /** 정적 팩토리만 쓰는 DTO. */
    private ContactDto() {}


    /**
     * 개인 연락처 추가 body.
     *
     * @param displayName 표시 이름. 비면 null로 저장
     * @param email 필수. SYS_USER·내 주소록과 중복이면 생성 실패
     */
    public record Request(
            String displayName,
            @NotBlank @Email String email) {}

    /**
     * 목록/그룹 멤버에 쓰는 연락처 한 줄.
     *
     * @param id MAIL_CONTACT PK. 계정이면 null
     * @param accountUserSeq SYS_USER PK. 개인 연락처면 null
     * @param displayName 계정이면 userId, 아니면 주소록 표시명
     * @param email 메일 주소
     * @param fromAccount true면 가입 계정 디렉터리, false면 MAIL_CONTACT
     */
    public record Response(
            Long id, Long accountUserSeq, String displayName, String email, boolean fromAccount) {

        /** 수동 주소록 행 → 응답. */
        /** 수동 주소록 행 → 응답. */
        public static Response from(MailContact contact) {
            // fromAccount=false, accountUserSeq는 빈 값.
            return new Response(
                    contact.getContactSeq(), null, contact.getDisplayName(), contact.getEmail(), false);
        }

        /** 가입 계정 → 응답. id 대신 accountUserSeq 설정. */
        public static Response fromAccount(SysUser user) {
            // 표시명은 로그인 id. 메일함 주소가 email.
            return new Response(null, user.getUserSeq(), user.getUserId(), user.getMailAddress(), true);
        }
    }
}
