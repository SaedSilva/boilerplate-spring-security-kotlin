package br.dev.saed.boilerplatespringsecuritykotlin.configs.customgrant

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap

class CustomPasswordAuthenticationConverter : AuthenticationConverter {
    override fun convert(request: HttpServletRequest): Authentication? {
        val grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE)

        if (!grantType.equals("password")) {
            return null
        }

        val parameters = getParameters(request)

        val scope = parameters.getFirst(OAuth2ParameterNames.SCOPE)
        if (!scope.isNullOrEmpty() && parameters[OAuth2ParameterNames.SCOPE]?.size != 1) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        val username = parameters.getFirst(OAuth2ParameterNames.USERNAME)
        if (username.isNullOrEmpty() || parameters[OAuth2ParameterNames.USERNAME]?.size != 1) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        val password = parameters.getFirst(OAuth2ParameterNames.PASSWORD)
        if (password.isNullOrEmpty() || parameters[OAuth2ParameterNames.PASSWORD]?.size != 1) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        var requestedScopes: MutableSet<String>? = null
        if (scope != null) {
            if (scope.isNotEmpty()) {
                requestedScopes = mutableSetOf()
                scope.split(" ").forEach {
                    requestedScopes.add(it)
                }
            }
        }

        val additionalParameters = mutableMapOf<String, Any>()
        parameters.forEach { (key, values) ->
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) && !key.equals(OAuth2ParameterNames.SCOPE)) {
                additionalParameters[key] = values.first()
            }
        }

        val clientPrincipal = SecurityContextHolder.getContext().authentication
        return CustomPasswordAuthenticationToken(clientPrincipal, requestedScopes, additionalParameters)
    }

    private fun getParameters(request: HttpServletRequest): MultiValueMap<String, String> {
        val parameterMap = request.parameterMap
        val parameters = LinkedMultiValueMap<String, String>(parameterMap.size)
        parameterMap.forEach { (key, values) ->
            values.forEach { value ->
                parameters.add(key, value)
            }
        }
        return parameters
    }
}
