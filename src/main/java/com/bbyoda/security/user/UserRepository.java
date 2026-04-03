package com.bbyoda.security.user;

import com.bbyoda.security.authorization.rbac.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    List<Role> findAllByRole(String email);

    @Modifying
    @Query("UPDATE User u SET u.accountNonLocked = :locked WHERE u.id = :id")
    void updateAccountLockStatus(@Param("id") String id, @Param("locked") boolean locked);

    @Modifying
    @Query("UPDATE User u SET u.enabled = :enabled WHERE u.id = :id")
    void updateEnabledStatus(@Param("id") String id, @Param("enabled") boolean enabled);
}
