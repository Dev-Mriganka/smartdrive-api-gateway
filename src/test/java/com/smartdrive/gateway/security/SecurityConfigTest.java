package com.smartdrive.gateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

@WebFluxTest
@Import(SecurityConfig.class)
@ActiveProfiles("test")
class SecurityConfigTest {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    void publicEndpoints_ShouldBeAccessible() {
        webTestClient.get()
            .uri("/actuator/health")
            .exchange()
            .expectStatus().isOk();

        webTestClient.get()
            .uri("/auth/oauth2/authorize")
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    void protectedEndpoints_WithoutAuth_ShouldReturnUnauthorized() {
        webTestClient.get()
            .uri("/api/v1/users/profile")
            .exchange()
            .expectStatus().isUnauthorized();

        webTestClient.get()
            .uri("/api/v1/files/list")
            .exchange()
            .expectStatus().isUnauthorized();
    }

    @Test
    @WithMockUser(roles = "SMARTDRIVE_USER")
    void userEndpoints_WithUserRole_ShouldBeAccessible() {
        webTestClient.get()
            .uri("/api/v1/users/profile")
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    @WithMockUser(roles = "SMARTDRIVE_ADMIN")
    void adminEndpoints_WithAdminRole_ShouldBeAccessible() {
        webTestClient.get()
            .uri("/auth/api/v1/admin/users")
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    @WithMockUser(roles = "SMARTDRIVE_USER")
    void adminEndpoints_WithUserRole_ShouldReturnForbidden() {
        webTestClient.get()
            .uri("/auth/api/v1/admin/users")
            .exchange()
            .expectStatus().isForbidden();
    }
}