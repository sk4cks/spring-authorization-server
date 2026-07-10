package spring_security.user.domain;

import org.junit.jupiter.api.Test;
import spring_security.common.constants.DelYn;

import static org.assertj.core.api.Assertions.assertThat;

class SysUserTest {

    @Test
    void softDelete_marksDeletedAndInactive() {
        SysUser user = SysUser.createLocal("sk4cks", "sk4cks@note.local", "{noop}1234");

        user.softDelete(1L);

        assertThat(user.getDelYn()).isEqualTo(DelYn.Y);
        assertThat(user.getDeletedAt()).isNotNull();
        assertThat(user.getStatus()).isEqualTo(UserStatus.INACTIVE);
        assertThat(user.getUpdatedBy()).isEqualTo(1L);
        assertThat(user.isActive()).isFalse();
    }

    @Test
    void softDelete_isIdempotent() {
        SysUser user = SysUser.createLocal("sk4cks", "sk4cks@note.local", "{noop}1234");
        user.softDelete(1L);
        var deletedAt = user.getDeletedAt();

        user.softDelete(99L);

        assertThat(user.getDeletedAt()).isEqualTo(deletedAt);
        assertThat(user.getUpdatedBy()).isEqualTo(1L);
    }
}
