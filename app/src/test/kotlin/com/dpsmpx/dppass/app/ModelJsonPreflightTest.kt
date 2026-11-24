package com.dpsmpx.dppass.app

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ModelJsonPreflightTest {
    private fun accepts(value: String) = ModelJsonPreflight.accepts(value.encodeToByteArray(), 4096)

    @Test
    fun acceptsGeneratedModelShapesAndLegacyOptionalNull() {
        for (json in listOf(
            """{"format":"dppass-zapret2-mlp-v3","parameters":100000,"hidden":[[0.125,-1e-4]],"sparse":{"0":0.2},"observations":0}""",
            """{"format":"dppass-server-mlp-v2","context_observations":[1,2],"deep_hidden":[],"deep_bias":[]}""",
            """{"format":"dppass-zapret2-mlp-v2","sparse":null}""",
            """{"\u0066ormat":"test","bias":[0.0,1E+2]}""",
            " \n{}\t",
        )) assertTrue(accepts(json), json)
    }

    @Test
    fun rejectsAmbiguousMalformedOrExcessivelyNestedDocuments() {
        for (json in listOf(
            """{"format":"first","format":"second"}""",
            """{"format":"first","\u0066ormat":"second"}""",
            """{"Format":"test"}""",
            """{"unknown":0}""",
            """{"sparse":{"0":1,"0":2}}""",
            """{"sparse":{"0":null}}""",
            """{"hidden":[[null]]}""",
            """{"hidden":[[[[[0]]]]]}""",
            """{"bias":[01]}""",
            """{"bias":[1.]}""",
            """{"bias":[1e+]}""",
            """{"bias":[+1]}""",
            """{"bias":[0,]}""",
            """{"format":"\x00"}""",
            """{"format":"test",}""",
            """{'format':'test'}""",
            """{"format":"test"}{}""",
            """{"format":/*comment*/"test"}""",
            "[]",
            "{\"format\":\"a\nb\"}",
        )) assertFalse(accepts(json), json)
        assertFalse(ModelJsonPreflight.accepts(byteArrayOf(0xff.toByte()), 4096))
        assertFalse(ModelJsonPreflight.accepts("{}".encodeToByteArray(), 1))
    }
}
