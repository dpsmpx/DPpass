package com.dpsmpx.dppass.app

internal interface RootDpiRuntime {
    suspend fun start(): Result<Unit>
    suspend fun stop(): Result<Unit>
    suspend fun alive(): Boolean
}
