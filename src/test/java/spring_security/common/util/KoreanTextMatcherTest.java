package spring_security.common.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class KoreanTextMatcherTest {

    @Test
    void matchesIncompleteSyllableAndChosung() {
        assertThat(KoreanTextMatcher.matches("ㄱ", "김철수")).isTrue();
        assertThat(KoreanTextMatcher.matches("기", "김철수")).isTrue();
        assertThat(KoreanTextMatcher.matches("김", "김철수")).isTrue();
        assertThat(KoreanTextMatcher.matches("ㄱㅊㅅ", "김철수")).isTrue();
        assertThat(KoreanTextMatcher.matches("김ㅊ", "김철수")).isTrue();
        assertThat(KoreanTextMatcher.matches("ㄱㅅ", "김철수")).isFalse();
        assertThat(KoreanTextMatcher.matches("박", "김철수")).isFalse();
    }

    @Test
    void matchesAsciiAndEmail() {
        assertThat(KoreanTextMatcher.matches("sk", "sk5cks", "a@b.com")).isTrue();
        assertThat(KoreanTextMatcher.matches("b.com", "sk5cks", "a@b.com")).isTrue();
        assertThat(KoreanTextMatcher.matches("", "아무나")).isTrue();
    }
}
