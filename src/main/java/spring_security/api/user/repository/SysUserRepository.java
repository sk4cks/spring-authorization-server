package spring_security.api.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring_security.api.user.domain.SysUser;

public interface SysUserRepository extends JpaRepository<SysUser, Long> {
}
