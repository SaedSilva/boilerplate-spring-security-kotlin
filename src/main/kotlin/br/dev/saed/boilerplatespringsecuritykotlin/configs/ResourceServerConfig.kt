package br.dev.saed.boilerplatespringsecuritykotlin.configs

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.security.servlet.PathRequest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.filter.CorsFilter

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class ResourceServerConfig {
    @Value("\${cors.origins}")
    private lateinit var corsOrigins: String

    @Bean
    @Profile("test")
    @Order(1)
    fun h2SecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.securityMatcher(PathRequest.toH2Console()).csrf { csrf ->
            csrf.disable()
        }.headers { headers ->
            headers.frameOptions { frameOptionsConfig ->
                frameOptionsConfig.disable()
            }
        }
        return http.build()
    }

    @Bean
    @Order(3)
    fun rsSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.csrf { it.disable() }
        http.authorizeHttpRequests { it.anyRequest().permitAll() }
        http.oauth2ResourceServer { it.jwt(Customizer.withDefaults()) }
        http.cors { it.configurationSource(corsConfigurationSource()) }
        return http.build()
    }

    @Bean
    fun jwtAuthenticationConverter(): JwtAuthenticationConverter {
        val grantedAuthoritiesConverter = JwtGrantedAuthoritiesConverter()
        grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities")
        grantedAuthoritiesConverter.setAuthorityPrefix("")

        val jwtAuthenticationConverter = JwtAuthenticationConverter()
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter)
        return jwtAuthenticationConverter
    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val origins = corsOrigins.split(",")

        val corsConfig = CorsConfiguration()
        corsConfig.setAllowedOriginPatterns(origins)
        corsConfig.allowedMethods = listOf("POST", "GET", "PUT", "DELETE", "PATCH")
        corsConfig.allowCredentials = true
        corsConfig.allowedHeaders = listOf("Authorization", "Content-Type")

        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", corsConfig)
        return source
    }

    @Bean
    fun corsFilter(): CorsFilter {
        val corsFilter = CorsFilter(corsConfigurationSource())
        return corsFilter
    }
}