package com.dpsmpx.dppass.app

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Retained process host for the future Android Service. The public status
 * contains no secrets. No receiver, activity or boot hook starts it.
 * Actual runtime factories must be internal and independently validated.
 */
internal object RootHotspotProcessHost {
    private val state = MutableStateFlow(processRootHotspotServiceOwner.snapshot())
    val status: StateFlow<RootHotspotServiceOwner.Snapshot> = state.asStateFlow()
    val coordinator by lazy {
        RootHotspotServiceCoordinator(processRootHotspotServiceOwner,
            RootHotspotServiceCoordinator.processWorker(), { state.value = it })
    }
}
