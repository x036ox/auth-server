package com.artur.repository;

import com.artur.entity.UserEntity;
import org.springframework.data.repository.ListCrudRepository;

public interface UserRepository extends ListCrudRepository<UserEntity, Long> {

    UserEntity findByUsername(String username);
}
