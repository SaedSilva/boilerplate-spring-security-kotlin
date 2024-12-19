package br.dev.saed.boilerplatespringsecuritykotlin.repositories

import br.dev.saed.boilerplatespringsecuritykotlin.entities.User
import br.dev.saed.boilerplatespringsecuritykotlin.projections.UserDetailsProjection
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query

interface UserRepository: JpaRepository<User, Long> {
    @Query(nativeQuery = true, value =
    "SELECT tb_user.email AS username, tb_user.password, tb_role.id AS roleId, tb_role.authority " +
            "FROM tb_user " +
            "INNER JOIN tb_user_role ON tb_user.id = tb_user_role.user_id " +
            "INNER JOIN tb_role ON tb_role.id = tb_user_role.role_id " +
            "WHERE tb_user.email = :email")
    fun searchUserAndRolesByEmail(email: String) : List<UserDetailsProjection>

    fun findByEmail(email: String) : User?
}