package br.dev.saed.boilerplatespringsecuritykotlin.configs.customgrant

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import java.security.Principal

class CustomPasswordAuthenticationProvider(
    private val authorizationService: OAuth2AuthorizationService,
    private val tokenGenerator: OAuth2TokenGenerator<out OAuth2Token?>,
    private val userDetailsService: UserDetailsService,
    private val passwordEncoder: PasswordEncoder
) : AuthenticationProvider {

    lateinit var username: String
    lateinit var password: String
    lateinit var authorizedScopes: Set<String>

    override fun authenticate(authentication: Authentication): Authentication {
        val customPasswordAuthenticationToken = authentication as CustomPasswordAuthenticationToken
        val clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(authentication)
        val registeredClient = clientPrincipal.registeredClient
        println(registeredClient?.scopes)
        username = customPasswordAuthenticationToken.username
        password = customPasswordAuthenticationToken.password

        val user = try {
            userDetailsService.loadUserByUsername(username)
        } catch (e: Exception) {
            throw OAuth2AuthenticationException("Invalid credentials")
        }

        if (!passwordEncoder.matches(password, user.password) || !user.username.equals(username)) {
            throw OAuth2AuthenticationException("Invalid credentials")
        }

        authorizedScopes =
            user.authorities.map { it.authority }.filter {
                registeredClient?.scopes?.contains(it) ?: false
            }.toSet()

        //-----------Create a new Security Context Holder Context----------
        val oAuth2ClientAuthenticationToken =
            SecurityContextHolder.getContext().authentication as OAuth2ClientAuthenticationToken
        val customPasswordUser = CustomUserAuthorities(username, user.authorities)
        oAuth2ClientAuthenticationToken.details = customPasswordUser

        val newContext = SecurityContextHolder.createEmptyContext()
        newContext.authentication = oAuth2ClientAuthenticationToken
        SecurityContextHolder.setContext(newContext)

        //-----------TOKEN BUILDERS----------
        val tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(clientPrincipal)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(authorizedScopes)
            .authorizationGrantType(AuthorizationGrantType("password"))
            .authorizationGrant(customPasswordAuthenticationToken)

        val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .attribute(Principal::class.java.name, clientPrincipal)
            .principalName(clientPrincipal.name)
            .authorizationGrantType(AuthorizationGrantType("password"))
            .authorizedScopes(authorizedScopes)

        //-----------ACCESS TOKEN----------
        val tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build()
        val generatedAccessToken = tokenGenerator.generate(tokenContext)
        if (generatedAccessToken == null) {
            val error = OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR,
                "The token generator failed to generate the access token.",
                ERROR_URI
            )
            throw OAuth2AuthenticationException(error)
        }

        val accessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.tokenValue,
            generatedAccessToken.issuedAt,
            generatedAccessToken.expiresAt,
            tokenContext.authorizedScopes
        )
        if (generatedAccessToken is ClaimAccessor) {
            authorizationBuilder.token(accessToken) { metadata ->
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = (generatedAccessToken as ClaimAccessor).claims
            }
        } else {
            authorizationBuilder.accessToken(accessToken)
        }

        val authorization = authorizationBuilder.build()
        authorizationService.save(authorization)

        return OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken)
    }

    private fun getAuthenticatedClientElseThrowInvalidClient(authentication: CustomPasswordAuthenticationToken): OAuth2ClientAuthenticationToken {
        val assignableFrom =
            OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(authentication.principal.javaClass)
        val clientPrincipal = if (assignableFrom) {
            authentication.principal as OAuth2ClientAuthenticationToken
        } else {
            null
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated) {
            return clientPrincipal
        }

        throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)
    }

    override fun supports(authentication: Class<*>): Boolean {
        return CustomPasswordAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    companion object {
        const val ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2"
    }
}
