package br.dev.saed.boilerplatespringsecuritykotlin.controllers

import br.dev.saed.boilerplatespringsecuritykotlin.dtos.UserDTO
import br.dev.saed.boilerplatespringsecuritykotlin.services.UserService
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(value = ["/users"])
class UserController(
    private val service: UserService
) {

    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_CLIENT')")
    @GetMapping(value = ["/me"])
    fun getMe() : ResponseEntity<UserDTO> {
        return ResponseEntity.ok(service.getMe())
    }

}