package br.dev.saed.boilerplatespringsecuritykotlin.configs.customgrant

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken

class CustomPasswordAuthenticationToken(
    clientPrincipal: Authentication?,
    scopes: MutableSet<String>?,
    additionalParameters: MutableMap<String, Any>
) :
    OAuth2AuthorizationGrantAuthenticationToken(
        AuthorizationGrantType("password"),
        clientPrincipal,
        additionalParameters
    ) {
    val username: String = additionalParameters["username"] as String
    val password: String = additionalParameters["password"] as String
    val scopes: Set<String> = if (scopes == null) setOf() else HashSet(scopes)
}
