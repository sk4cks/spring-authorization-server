package spring_security.contact.dto;

import java.util.List;

/** 자동완성 후보. type=contact|group */
public record RecipientSuggestItem(
        String type, Long id, String displayName, String email, List<String> emails) {

    public static RecipientSuggestItem contact(Long id, String displayName, String email) {
        return new RecipientSuggestItem("contact", id, displayName, email, List.of());
    }

    public static RecipientSuggestItem group(Long id, String name, List<String> emails) {
        return new RecipientSuggestItem("group", id, name, null, emails);
    }
}
