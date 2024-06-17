package com.artur.repository;

import com.artur.entity.UserEntity;
import org.springframework.data.repository.ListCrudRepository;

public interface UserRepository extends ListCrudRepository<UserEntity, Long> {

    boolean existsByUsername(String username);
    UserEntity findByUsername(String username);
    UserEntity findByEmail(String email);
}
