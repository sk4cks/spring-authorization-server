package spring_security.contact.dto;

import java.util.List;

/**
 * 수신자 자동완성 한 줄.
 *
 * @param type {@code contact} 또는 {@code group} (BFF가 히스토리를 붙일 때는 {@code history})
 * @param id 연락처면 accountUserSeq 또는 contactSeq, 그룹이면 groupSeq
 * @param displayName 표시 이름(그룹이면 그룹명)
 * @param email 연락처 한 명일 때. 그룹이면 null
 * @param emails 그룹 멤버 메일들. 연락처면 빈 리스트
 */
public record RecipientSuggestItem(
        String type, Long id, String displayName, String email, List<String> emails) {

    /** 사람 한 명 후보. */
    public static RecipientSuggestItem contact(Long id, String displayName, String email) {
        return new RecipientSuggestItem("contact", id, displayName, email, List.of());
    }

    /** 그룹 후보. 칩에 펼칠 메일 목록을 같이 준다. */
    public static RecipientSuggestItem group(Long id, String name, List<String> emails) {
        return new RecipientSuggestItem("group", id, name, null, emails);
    }
}
