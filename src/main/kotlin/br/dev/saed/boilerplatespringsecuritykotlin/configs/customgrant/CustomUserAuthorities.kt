package br.dev.saed.boilerplatespringsecuritykotlin.configs.customgrant

import org.springframework.security.core.GrantedAuthority

class CustomUserAuthorities(
    val username: String,
    val authorities: Collection<GrantedAuthority>
) {

}
