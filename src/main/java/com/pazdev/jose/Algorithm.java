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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
public class Algorithm {
    static enum Type {HMAC, DS, NONE, KE, KW, DIRECT, KA_DIRECT, KA_KW, PWD_KW, CE, ZIP};

    private static final Map<String, Algorithm> REGISTER = new ConcurrentHashMap<>();

    public static final Algorithm HS256 = Algorithm.getAlgorithm("HS256", Type.HMAC, true, 256, 32);
    public static final Algorithm HS384 = Algorithm.getAlgorithm("HS384", Type.HMAC, true, 384, 48);
    public static final Algorithm HS512 = Algorithm.getAlgorithm("HS512", Type.HMAC, true, 512, 64);
    public static final Algorithm RS256 = Algorithm.getAlgorithm("RS256", Type.DS, true, 0, 0);
    public static final Algorithm RS384 = Algorithm.getAlgorithm("RS384", Type.DS, true, 0, 0);
    public static final Algorithm RS512 = Algorithm.getAlgorithm("RS512", Type.DS, true, 0, 0);
    public static final Algorithm ES256 = Algorithm.getAlgorithm("ES256", Type.DS, true, 512, 64);
    public static final Algorithm ES384 = Algorithm.getAlgorithm("ES384", Type.DS, true, 512, 64);
    public static final Algorithm ES512 = Algorithm.getAlgorithm("ES512", Type.DS, true, 512, 64);
    public static final Algorithm PS256 = Algorithm.getAlgorithm("PS256", Type.DS, true, 0, 0);
    public static final Algorithm PS384 = Algorithm.getAlgorithm("PS384", Type.DS, true, 0, 0);
    public static final Algorithm PS512 = Algorithm.getAlgorithm("PS512", Type.DS, true, 0, 0);
    public static final Algorithm NONE = Algorithm.getAlgorithm("none", Type.NONE, true, 0, 0);
    public static final Algorithm RSA1_5 = Algorithm.getAlgorithm("RSA1_5", Type.KE, true, 0, 0);
    public static final Algorithm RSA_OAEP = Algorithm.getAlgorithm("RSA-OAEP", Type.KE, true, 0, 0);
    public static final Algorithm RSA_OAEP_256 = Algorithm.getAlgorithm("RSA-OAEP-256", Type.KE, true, 0, 0);
    public static final Algorithm A128KW = Algorithm.getAlgorithm("A128KW", Type.KW, true, 128, 16);
    public static final Algorithm A192KW = Algorithm.getAlgorithm("A192KW", Type.KW, true, 192, 24);
    public static final Algorithm A256KW = Algorithm.getAlgorithm("A256KW", Type.KW, true, 256, 32);
    public static final Algorithm DIR = Algorithm.getAlgorithm("dir", Type.DIRECT, true, 0, 0);
    public static final Algorithm ECDH_ES = Algorithm.getAlgorithm("ECDH-ES", Type.KA_DIRECT, true, 0, 0);
    public static final Algorithm ECDH_ES_A128KW = Algorithm.getAlgorithm("ECDH-ES+A128KW", Type.KA_KW, true, 128, 16);
    public static final Algorithm ECDH_ES_A192KW = Algorithm.getAlgorithm("ECDH-ES+A192KW", Type.KA_KW, true, 192, 24);
    public static final Algorithm ECDH_ES_A256KW = Algorithm.getAlgorithm("ECDH-ES+A256KW", Type.KA_KW, true, 256, 32);
    public static final Algorithm A128GCMKW = Algorithm.getAlgorithm("A128GCMKW", Type.KW, true, 128, 16);
    public static final Algorithm A192GCMKW = Algorithm.getAlgorithm("A192GCMKW", Type.KW, true, 192, 24);
    public static final Algorithm A256GCMKW = Algorithm.getAlgorithm("A256GCMKW", Type.KW, true, 256, 32);
    public static final Algorithm PBES2_HS256_A128KW = Algorithm.getAlgorithm("PBES2-HS256+A128KW", Type.PWD_KW, true, 128, 16);
    public static final Algorithm PBES2_HS384_A192KW = Algorithm.getAlgorithm("PBES2-HS384+A192KW", Type.PWD_KW, true, 192, 24);
    public static final Algorithm PBES2_HS512_A256KW = Algorithm.getAlgorithm("PBES2-HS512+A256KW", Type.PWD_KW, true, 256, 32);
    public static final Algorithm A128CBC_HS256 = Algorithm.getAlgorithm("A128CBC-HS256", Type.CE, true, 128, 16);
    public static final Algorithm A192CBC_HS384 = Algorithm.getAlgorithm("A192CBC-HS384", Type.CE, true, 192, 24);
    public static final Algorithm A256CBC_HS512 = Algorithm.getAlgorithm("A256CBC-HS512", Type.CE, true, 256, 32);
    public static final Algorithm A128GCM = Algorithm.getAlgorithm("A128GCM", Type.CE, true, 128, 16);
    public static final Algorithm A192GCM = Algorithm.getAlgorithm("A192GCM", Type.CE, true, 192, 24);
    public static final Algorithm A256GCM = Algorithm.getAlgorithm("A256GCM", Type.CE, true, 256, 32);
    public static final Algorithm DEFLATE = Algorithm.getAlgorithm("DEF", Type.ZIP, true, 0, 0);

    private final String name;
    private final Type type;
    private final boolean supported;
    private final int bitSize;
    private final int byteSize;

    private Algorithm(String name, Type type, boolean supported, int bitSize, int byteSize) {
        this.name = name;
        this.type = type;
        this.supported = supported;
        this.bitSize = bitSize;
        this.byteSize = byteSize;
    }

    @JsonValue
    public String getName() {
        return name;
    }

    Type getType() {
        return type;
    }

    boolean isSupported() {
        return supported;
    }

    public int getBitSize() {
        return bitSize;
    }

    public int getByteSize() {
        return byteSize;
    }

    @JsonCreator
    public static Algorithm getAlgorithm(String name) {
        return getAlgorithm(name, null, false, 0, 0);
    }

    private static Algorithm getAlgorithm(String name, Type type, boolean supported, int bitSize, int byteSize) {
        Algorithm retval = REGISTER.get(name);
        if (retval == null) {
            retval = new Algorithm(name, type, supported, bitSize, byteSize);
            REGISTER.put(name, retval);
        }
        return retval;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 53 * hash + Objects.hashCode(this.name);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Algorithm other = (Algorithm) obj;
        return Objects.equals(this.name, other.name);
    }

    @Override
    public String toString() {
        return getName();
    }

}
