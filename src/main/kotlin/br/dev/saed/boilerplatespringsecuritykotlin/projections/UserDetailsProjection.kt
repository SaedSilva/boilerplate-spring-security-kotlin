package br.dev.saed.boilerplatespringsecuritykotlin.projections

interface UserDetailsProjection {
    val username: String
    val password: String
    val roleId: Long
    val authority: String
}