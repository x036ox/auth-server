package com.artur;

import jakarta.transaction.Transactional;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ActiveProfiles;

@Transactional
@Rollback
@SpringBootTest
@ActiveProfiles("dev")
public class MainTest {

}