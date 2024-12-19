package br.dev.saed.boilerplatespringsecuritykotlin.configs

import br.dev.saed.boilerplatespringsecuritykotlin.configs.customgrant.CustomPasswordAuthenticationConverter
import br.dev.saed.boilerplatespringsecuritykotlin.configs.customgrant.CustomPasswordAuthenticationProvider
import br.dev.saed.boilerplatespringsecuritykotlin.configs.customgrant.CustomUserAuthorities
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.*
import org.springframework.security.web.SecurityFilterChain
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.*

@Configuration
class AuthorizationServerConfig(
    private val userDetailsService: UserDetailsService
) {
    @Value("\${security.client-id}")
    private lateinit var clientId: String

    @Value("\${security.client-secret}")
    private lateinit var clientSecret: String

    @Value("\${security.jwt.duration}")
    private lateinit var jwtDurationSeconds: String

    @Bean
    @Order(2)
    fun asSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer()
        http.securityMatcher(authorizationServerConfigurer.endpointsMatcher)
            .with(authorizationServerConfigurer, Customizer.withDefaults()).authorizeHttpRequests {
                it.anyRequest().authenticated()
            }

        http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
            .tokenEndpoint {
                it.accessTokenRequestConverter(CustomPasswordAuthenticationConverter())
                it.authenticationProvider(
                    CustomPasswordAuthenticationProvider(
                        authorizationService(),
                        tokenGenerator(),
                        userDetailsService,
                        passwordEncoder()
                    )
                )
            }

        http.oauth2ResourceServer {
            it.jwt(Customizer.withDefaults())
        }

        return http.build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }

    @Bean
    fun tokenGenerator(): OAuth2TokenGenerator<out OAuth2Token?> {
        val jwtEncoder = NimbusJwtEncoder(jwkSource())
        val jwtGenerator = JwtGenerator(jwtEncoder)
        jwtGenerator.setJwtCustomizer(tokenCustomizer())
        val accessTokenGenerator = OAuth2AccessTokenGenerator()
        return DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator)
    }

    @Bean
    fun tokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer { context ->
            val principal = context.getPrincipal<OAuth2ClientAuthenticationToken>()
            val user = principal.details as CustomUserAuthorities
            val authorities = user.authorities.map { it.authority }
            if (context.tokenType.value.equals("access_token")) {
                context.claims
                    .claim("authorities", authorities)
                    .claim("username", user.username)
            }
        }
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val rsaKey: RSAKey = generateRsa()
        val jwkSet = JWKSet(rsaKey)
        return JWKSource { jwkSelector, _ ->
            jwkSelector.select(jwkSet)
        }
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }


    @Bean
    fun authorizationService(): OAuth2AuthorizationService {
        return InMemoryOAuth2AuthorizationService()
    }

    @Bean
    fun oAuth2AuthorizationConsentService(): OAuth2AuthorizationConsentService {
        return InMemoryOAuth2AuthorizationConsentService()
    }

    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val registeredClient = RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientSecret(passwordEncoder().encode(clientSecret))
            .scope("read")
            .scope("write")
            .authorizationGrantType(AuthorizationGrantType("password"))
            .tokenSettings(tokenSettings())
            .clientSettings(clientSettings())
            .build()

        return InMemoryRegisteredClientRepository(registeredClient)
    }

    @Bean
    fun clientSettings(): ClientSettings {
        return ClientSettings.builder().build()
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder()
            .tokenEndpoint("/login")
            .build()
    }

    @Bean
    fun tokenSettings(): TokenSettings {
        return TokenSettings.builder()
            .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
            .accessTokenTimeToLive(Duration.ofSeconds(jwtDurationSeconds.toLong()))
            .build()
    }

    private fun generateRsa(): RSAKey {
        val keyPair = generateRsaKey()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        return RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build()
    }

    private fun generateRsaKey(): KeyPair {
        val keyPair: KeyPair
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPair = keyPairGenerator.generateKeyPair()
        } catch (ex: Exception) {
            throw IllegalStateException(ex)
        }
        return keyPair
    }
}