package spring_security.common.util;

import org.springframework.util.StringUtils;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 한글 부분 입력·초성 검색. ㄱ / 기 / 김 / ㄱㅊㅅ 모두 김철수를 찾는다.
 */
public final class KoreanTextMatcher {

    /** 가. 한글 음절 유니코드 시작. */
    private static final int SYLLABLE_BASE = 0xAC00;
    /** 힣. 한글 음절 유니코드 끝. */
    private static final int SYLLABLE_LAST = 0xD7A3;
    private static final int CHO_JAMO = 0x1100;
    private static final int JUNG_JAMO = 0x1161;
    private static final int JONG_JAMO = 0x11A8;
    private static final String CHO = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ";
    private static final String[] JUNG_EXPAND = {
        "ㅏ", "ㅐ", "ㅑ", "ㅒ", "ㅓ", "ㅔ", "ㅕ", "ㅖ",
        "ㅗ", "ㅗㅏ", "ㅗㅐ", "ㅗㅣ", "ㅛ",
        "ㅜ", "ㅜㅓ", "ㅜㅔ", "ㅜㅣ", "ㅠ",
        "ㅡ", "ㅡㅣ", "ㅣ"
    };
    private static final String[] JONG_EXPAND = {
        "",
        "ㄱ", "ㄲ", "ㄱㅅ", "ㄴ", "ㄴㅈ", "ㄴㅎ", "ㄷ",
        "ㄹ", "ㄹㄱ", "ㄹㅁ", "ㄹㅂ", "ㄹㅅ", "ㄹㅌ", "ㄹㅍ", "ㄹㅎ",
        "ㅁ", "ㅂ", "ㅂㅅ", "ㅅ", "ㅆ", "ㅇ", "ㅈ", "ㅊ", "ㅋ", "ㅌ", "ㅍ", "ㅎ"
    };
    private static final String[] COMPAT_CONSONANT = {
        "ㄱ", "ㄲ", "ㄱㅅ", "ㄴ", "ㄴㅈ", "ㄴㅎ", "ㄷ", "ㄸ", "ㄹ",
        "ㄹㄱ", "ㄹㅁ", "ㄹㅂ", "ㄹㅅ", "ㄹㅌ", "ㄹㅍ", "ㄹㅎ",
        "ㅁ", "ㅂ", "ㅃ", "ㅂㅅ", "ㅅ", "ㅆ", "ㅇ", "ㅈ", "ㅉ", "ㅊ", "ㅋ", "ㅌ", "ㅍ", "ㅎ"
    };

    private KoreanTextMatcher() {}

    public static boolean matches(String query, String... fields) {
        String needle = normalize(query);

        // 검색어가 없으면 필터를 걸지 않는다. 주소록 전체 목록이 이 경로다.
        if (needle.isEmpty()) {
            return true;
        }

        for (String field : fields) {
            // 이름 또는 이메일 중 하나라도 맞으면 통과.
            if (field != null && contains(needle, normalize(field))) {
                return true;
            }
        }

        return false;
    }

    private static String normalize(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }

        // NFC로 맞추고, 대소문자·공백은 비교에서 뺀다.
        return Normalizer.normalize(value, Normalizer.Form.NFC)
                .toLowerCase(Locale.ROOT)
                .replaceAll("\\s+", "");
    }

    private static boolean contains(String query, String hay) {
        // 영문·숫자·완성 한글은 그냥 substring.
        if (hay.contains(query)) {
            return true;
        }

        // 초성 검색은 자모 리스트에서 query가 hay의 부분열인지 본다.
        List<String> hayJamo = jamoChars(hay);
        List<String> queryJamo = jamoChars(query);
        for (int start = 0; start < hayJamo.size(); start++) {
            if (matchFrom(queryJamo, hayJamo, start)) {
                return true;
            }
        }

        return false;
    }

    private static boolean matchFrom(List<String> query, List<String> hay, int start) {
        int qi = 0;
        int hi = start;
        while (qi < query.size()) {
            // hay 자모가 query 자모로 시작하면 맞다. ㄱ은 김(ㄱㅣㅁ)의 prefix.
            if (hi >= hay.size() || !hay.get(hi).startsWith(query.get(qi))) {
                return false;
            }

            qi += 1;
            hi += 1;
        }

        return true;
    }

    private static List<String> jamoChars(String text) {
        List<String> chars = new ArrayList<>();
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            chars.add(toJamo(cp));
            i += Character.charCount(cp);
        }

        return chars;
    }

    private static String toJamo(int cp) {
        // 가~힣을 초성+중성+종성 문자열로 푼다. 김 → ㄱㅣㅁ.
        if (cp >= SYLLABLE_BASE && cp <= SYLLABLE_LAST) {
            int s = cp - SYLLABLE_BASE;
            int cho = s / 588;
            int jung = (s % 588) / 28;
            int jong = s % 28;

            return CHO.charAt(cho) + JUNG_EXPAND[jung] + JONG_EXPAND[jong];
        }

        // ㄱ~ㅎ 호환 자모.
        if (cp >= 0x3131 && cp <= 0x314E) {
            return COMPAT_CONSONANT[cp - 0x3131];
        }

        // ㅏ~ㅣ 호환 모음.
        if (cp >= 0x314F && cp <= 0x3163) {
            return JUNG_EXPAND[cp - 0x314F];
        }

        if (cp >= CHO_JAMO && cp <= CHO_JAMO + 18) {
            return String.valueOf(CHO.charAt(cp - CHO_JAMO));
        }

        if (cp >= JUNG_JAMO && cp <= JUNG_JAMO + 20) {
            return JUNG_EXPAND[cp - JUNG_JAMO];
        }

        if (cp >= JONG_JAMO && cp <= JONG_JAMO + 26) {
            return JONG_EXPAND[cp - JONG_JAMO + 1];
        }

        // 영문·숫자는 그대로. 주소록 이메일 검색에 쓴다.
        return Character.toString(cp);
    }
}
