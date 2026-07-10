package spring_security.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring_security.user.domain.SysUser;

public interface SysUserRepository extends JpaRepository<SysUser, Long> {
}
