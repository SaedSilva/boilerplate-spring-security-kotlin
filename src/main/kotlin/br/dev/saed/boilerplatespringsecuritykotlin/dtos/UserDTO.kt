package br.dev.saed.boilerplatespringsecuritykotlin.dtos

import br.dev.saed.boilerplatespringsecuritykotlin.entities.User

class UserDTO(
    val id: Long?,
    val email: String,
    val roles: List<String> = emptyList()
) {
    companion object {
        fun fromEntity(entity: User): UserDTO {
            return UserDTO(
                id = entity.id,
                email = entity.email,
                roles = entity.roles.map { it.roleAuthority }
            )
        }
    }
}