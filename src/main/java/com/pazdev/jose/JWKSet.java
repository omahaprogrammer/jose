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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.google.common.collect.ImmutableList;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
@JsonDeserialize(builder = JWKSet.Builder.class)
public class JWKSet {
    @JsonPOJOBuilder
    public static final class Builder {
        LinkedList<JWK> jwks = new LinkedList<>();

        public Builder withKeys(List<JWK> jwks) {
            jwks.addAll(jwks);
            return this;
        }

        @JsonIgnore
        public Builder withKey(JWK key) {
            jwks.add(key);
            return this;
        }

        public JWKSet build() {
            return new JWKSet(ImmutableList.copyOf(jwks));
        }
    }
    
    private final List<JWK> keys;

    private JWKSet(List<JWK> keys) {
        this.keys = keys;
    }

    public JWKSet(JWKSet other) {
        this(other.keys);
    }

    public List<JWK> getKeys() {
        return keys;
    }

}
