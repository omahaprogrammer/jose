/*
 * Copyright 2016 Jonathan Paz <jonathan@pazdev.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.pazdev.jose;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
public class JWETest {
    
    public JWETest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    @Test
    public void testExampleA1() {
        String cleartext = "The true sign of intelligence is not knowledge but imagination.";
        JWE.Builder builder = JWE.builder();
        builder.withPayload(cleartext);
        builder.withProtectedHeader(
                Header.builder()
                        .withAlgorithm(Algorithm.RSA_OAEP)
                        .withEncryptionAlgorithm(Algorithm.A128GCM).build());
        JWK key = JWK.parse("{\"kty\":\"RSA\",\n" +
            "\"n\":\"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW" +
                    "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S" +
                    "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a" +
                    "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS" +
                    "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj" +
                    "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw\",\n" +
            "\"e\":\"AQAB\",\n" +
            "\"d\":\"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N" +
                    "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9" +
                    "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk" +
                    "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl" +
                    "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd" +
                    "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ\",\n" +
            "\"p\":\"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-" +
                    "SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf" +
                    "fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0\",\n" +
            "\"q\":\"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm" +
                    "UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX" +
                    "IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc\",\n" +
            "\"dp\":\"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL" +
                     "hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827" +
                     "rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE\"," +
            "\"dq\":\"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj" +
                     "ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB" +
                     "UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis\",\n" +
            "\"qi\":\"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7" +
                     "AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3" +
                     "eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY\"\n" +
            "}");
        builder.withKey(key.getKeys().get("public"));
        JWE jwe = builder.build();
        System.out.println(jwe.toCompact());
        assertEquals(cleartext, jwe.decryptString(key.getKeys().get("private"), StandardCharsets.UTF_8));
    }

    @Test
    public void testExampleA2() {
        String cleartext = "Live long and prosper.";
        Header protectedHeader = Header.builder()
                .withAlgorithm(Algorithm.RSA1_5)
                .withEncryptionAlgorithm(Algorithm.A128CBC_HS256)
                .build();
        JWK key = JWK.parse("{\"kty\":\"RSA\"," +
                "\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
                "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
                "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_" +
                "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI" +
                "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU" +
                "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\"," +
                "\"e\":\"AQAB\"," +
                "\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq" +
                "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry" +
                "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_" +
                "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj" +
                "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj" +
                "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\"," +
                "\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68" +
                "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP" +
                "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\"," +
                "\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y" +
                "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN" +
                "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\"," +
                "\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv" +
                "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra" +
                "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\"," +
                "\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff" +
                "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_" +
                "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\"," +
                "\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC" +
                "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ" +
                "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\"" +
                "}");
        JWE jwe = JWE.builder()
                .withKey(key.getKeys().get("public"))
                .withProtectedHeader(protectedHeader)
                .withPayload(cleartext)
                .build();
        System.out.println(jwe.toCompact());
        assertEquals(cleartext, jwe.decryptString(key.getKeys().get("private"), StandardCharsets.UTF_8));
    }

    @Test
    public void testExampleA3() {
        String cleartext = "Live long and prosper.";
        Header protectedHeader = Header.builder()
                .withAlgorithm(Algorithm.A128KW)
                .withEncryptionAlgorithm(Algorithm.A128CBC_HS256)
                .build();
        JWK key = JWK.parse("{\"kty\":\"oct\",\n" +
                "\"k\":\"GawgguFyGrWKav7AX4VKUg\"\n" +
                "}");
        JWE jwe = JWE.builder()
                .withKey(key.getKeys().get("secret"))
                .withProtectedHeader(protectedHeader)
                .withPayload(cleartext)
                .build();
        System.out.println(jwe.toCompact());
        assertEquals(cleartext, jwe.decryptString(key.getKeys().get("secret"), StandardCharsets.UTF_8));
    }

    @Test
    public void testExampleA5() {
        String cleartext = "Live long and prosper.";
        Header protectedHeader = Header.builder()
                .withEncryptionAlgorithm(Algorithm.A128CBC_HS256)
                .build();
        Header recipient1 = Header.builder()
                .withAlgorithm(Algorithm.RSA1_5)
                .withKeyId("2011-04-29")
                .build();
        Header recipient2 = Header.builder()
                .withAlgorithm(Algorithm.A128KW)
                .withKeyId("7")
                .build();
        Header shared = Header.builder()
                .withJwkSetUrl(URI.create("https://server.example.com/keys.jwks"))
                .build();
        JWK key1 = JWK.parse("{\"kty\":\"RSA\"," +
                "\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
                "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
                "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_" +
                "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI" +
                "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU" +
                "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\"," +
                "\"e\":\"AQAB\"," +
                "\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq" +
                "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry" +
                "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_" +
                "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj" +
                "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj" +
                "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\"," +
                "\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68" +
                "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP" +
                "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\"," +
                "\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y" +
                "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN" +
                "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\"," +
                "\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv" +
                "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra" +
                "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\"," +
                "\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff" +
                "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_" +
                "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\"," +
                "\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC" +
                "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ" +
                "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\"" +
                "}");
        JWK key2 = JWK.parse("{\"kty\":\"oct\",\n" +
                "\"k\":\"GawgguFyGrWKav7AX4VKUg\"\n" +
                "}");
        JWE jwe = JWE.builder()
                .withProtectedHeader(protectedHeader)
                .withSharedHeader(shared)
                .withRecipient(recipient1, key1.getKeys().get("public"))
                .withRecipient(recipient2, key2.getKeys().get("secret"))
                .withPayload(cleartext)
                .build();
        System.out.println(jwe.toJson());
        assertEquals(cleartext, jwe.decrypt(0, key1.getKeys().get("private"), StandardCharsets.UTF_8));
        assertEquals(cleartext, jwe.decrypt(1, key2.getKeys().get("secret"), StandardCharsets.UTF_8));
    }

    @Test
    public void testExampleA6() {
        String cleartext = "Live long and prosper.";
        Header protectedHeader = Header.builder()
                .withEncryptionAlgorithm(Algorithm.A128CBC_HS256)
                .build();
        Header recipient2 = Header.builder()
                .withAlgorithm(Algorithm.A128KW)
                .withKeyId("7")
                .build();
        Header shared = Header.builder()
                .withJwkSetUrl(URI.create("https://server.example.com/keys.jwks"))
                .build();
        JWK key2 = JWK.parse("{\"kty\":\"oct\",\n" +
                "\"k\":\"GawgguFyGrWKav7AX4VKUg\"\n" +
                "}");
        JWE jwe = JWE.builder()
                .withProtectedHeader(protectedHeader)
                .withSharedHeader(shared)
                .withRecipient(recipient2, key2.getKeys().get("secret"))
                .withPayload(cleartext)
                .build();
        System.out.println(jwe.toJson());
        assertEquals(cleartext, jwe.decrypt(0, key2.getKeys().get("secret"), StandardCharsets.UTF_8));
        assertEquals(cleartext, jwe.decryptString(key2.getKeys().get("secret"), StandardCharsets.UTF_8));
    }

    @Test
    public void testECDH() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("P-521"));
        KeyPair pair = gen.generateKeyPair();
        String cleartext = "For unto us a child is born, unto us a son is given!";
        Header header = Header.builder().withAlgorithm(Algorithm.ECDH_ES).withEncryptionAlgorithm(Algorithm.A256GCM).build();
        JWE jwe = JWE.builder().withPayload(cleartext).withKey(pair.getPublic()).withProtectedHeader(header).build();
        System.out.println(jwe.toCompact());
        System.out.println(jwe.toJson());
        assertEquals(cleartext, jwe.decryptString(pair.getPrivate()));
    }

    @Test
    public void testECDHKW() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("P-521"));
        KeyPair pair = gen.generateKeyPair();
        String cleartext = "For unto us a child is born, unto us a son is given!";
        Header header = Header.builder().withAlgorithm(Algorithm.ECDH_ES_A256KW).withEncryptionAlgorithm(Algorithm.A256GCM).build();
        JWE jwe = JWE.builder().withPayload(cleartext).withKey(pair.getPublic()).withProtectedHeader(header).build();
        System.out.println(jwe.toCompact());
        System.out.println(jwe.toJson());
        assertEquals(cleartext, jwe.decryptString(pair.getPrivate()));
    }
}
