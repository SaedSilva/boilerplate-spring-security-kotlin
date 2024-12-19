package br.dev.saed.boilerplatespringsecuritykotlin.entities

import jakarta.persistence.*
import org.springframework.security.core.GrantedAuthority

@Entity
@Table(name = "tb_role")
class Role(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long,
    @Column(name = "authority")
    val roleAuthority: String
) : GrantedAuthority {
    override fun getAuthority(): String {
        return roleAuthority
    }
}