package br.dev.saed.boilerplatespringsecuritykotlin.services

import br.dev.saed.boilerplatespringsecuritykotlin.dtos.UserDTO
import br.dev.saed.boilerplatespringsecuritykotlin.entities.Role
import br.dev.saed.boilerplatespringsecuritykotlin.entities.User
import br.dev.saed.boilerplatespringsecuritykotlin.repositories.UserRepository
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class UserService(
    private val repository: UserRepository
) : UserDetailsService {

    override fun loadUserByUsername(username: String?): UserDetails {
        if (username == null) {
            throw UsernameNotFoundException("User not found")
        }
        val usersDetailsProjections = repository.searchUserAndRolesByEmail(username)
        if (usersDetailsProjections.isEmpty()) {
            throw UsernameNotFoundException("User not found")
        }

        val user = User(
            email = usersDetailsProjections.first().username,
            userPassword = usersDetailsProjections.first().password
        )

        usersDetailsProjections.forEach { user.addRole(Role(it.roleId, it.authority)) }

        return user
    }

    protected fun authenticated() : User {
        try {
            val authentication = SecurityContextHolder.getContext().authentication
            val jwt = authentication.principal as Jwt
            val username = jwt.getClaim<String>("username")
            val user = repository.findByEmail(username) ?: throw UsernameNotFoundException("User not found")
            return user
        } catch (e: Exception) {
            throw UsernameNotFoundException("User not found")
        }
    }

    @Transactional(readOnly = true)
    fun getMe(): UserDTO {
        return UserDTO.fromEntity(authenticated())
    }
}