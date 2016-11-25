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

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.pazdev.jose.json.CertDeserializer;
import com.pazdev.jose.json.CertSerializer;
import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * This class is a representation of a JOSE header as described in 
 * <a href="https://tools.ietf.org/html/rfc7515">RFC 7515</a>, 
 * <a href="https://tools.ietf.org/html/rfc7516">RFC 7516</a>, 
 * <a href="https://tools.ietf.org/html/rfc7518">RFC 7518</a>, and
 * <a href="https://tools.ietf.org/html/rfc7519">RFC 7519</a>. This class is
 * annotated to support serialization to JSON via Jackson. Instances of this class
 * are immutable; a builder is available to create new instances.
 * 
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
@JsonDeserialize(builder = Header.Builder.class)
public class Header implements Serializable {

    /**
     * This class provides a mechanism to create new {@link Header} instances.
     * Instances of this class are not thread-safe.
     * 
     * @author Jonathan Paz <jonathan@pazdev.com
     */
    @JsonPOJOBuilder
    public static final class Builder {
        private Algorithm algorithm;
        private URI jwkSetUrl;
        private JWK jsonWebKey;
        private String keyId;
        private URI x509Url;
        private List<byte[]> x509CertificateChain;
        private byte[] x509CertificateSHA1Thumbprint;
        private byte[] x509CertificateSHA256Thumbprint;
        private String type;
        private String contentType;
        private List<String> critical;
        private Algorithm encryptionAlgorithm;
        private Algorithm compressionAlgorithm;
        private JWK ephemeralPublicKey;
        private byte[] agreementPartyUInfo;
        private byte[] agreementPartyVInfo;
        private byte[] initializationVector;
        private byte[] authenticationTag;
        private byte[] pbe2SaltInput;
        private Integer pbes2Count;
        private String b64EncodedPayload;
        @JsonProperty("iss")
        private String issuer;
        @JsonProperty("sub")
        private String subject;
        @JsonProperty("aud")
        private String audience;
        private final HashMap<String,Object> claims = new HashMap<>();

        public Builder withHeader(Header h) {
            algorithm = h.algorithm;
            jwkSetUrl = h.jwkSetUrl;
            jsonWebKey = h.jsonWebKey;
            keyId = h.keyId;
            x509Url = h.x509Url;
            x509CertificateChain = ImmutableList.copyOf(h.x509CertificateChain.stream().map(byte[]::clone).collect(Collectors.toList()));
            x509CertificateSHA1Thumbprint = h.x509CertificateSHA1Thumbprint.clone();
            x509CertificateSHA256Thumbprint = h.x509CertificateSHA256Thumbprint.clone();
            type = h.type;
            contentType = h.contentType;
            critical = ImmutableList.copyOf(h.critical);
            encryptionAlgorithm = h.encryptionAlgorithm;
            compressionAlgorithm = h.compressionAlgorithm;
            ephemeralPublicKey = h.ephemeralPublicKey;
            agreementPartyUInfo = h.agreementPartyUInfo;
            agreementPartyVInfo = h.agreementPartyVInfo;
            initializationVector = h.initializationVector.clone();
            authenticationTag = h.authenticationTag.clone();
            pbe2SaltInput = h.pbe2SaltInput.clone();
            pbes2Count = h.pbes2Count;
            b64EncodedPayload = h.b64EncodedPayload;
            claims.putAll(h.claims);
            return this;
        }
        /**
         * Sets the given algorithm to the builder, q.v.
         * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1">RFC 7515, Section 4.1.1</a>
         * and
         * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1">RFC 7516, Section 4.1.1</a>.
         * 
         * @param alg the algorithm for the header
         * @return this object
         */
        @JsonProperty("alg")
        public Builder withAlgorithm(Algorithm alg) {
            this.algorithm = alg;
            return this;
        }

        /**
         * Sets the URI that refers to a resource for a set of JSON-encoded public
         * keys, q.v. 
         * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.2">RFC 7515, Section 4.1.2</a>
         * and
         * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.4">RFC 7516, Section 4.1.4</a>.
         * 
         * @param jku a URI that refers to a resource for a set of JSON-encoded
         * public keys.
         * @return this object
         */
        @JsonProperty("jku")
        public Builder withJwkSetUrl(URI jku) {
            this.jwkSetUrl = jku;
            return this;
        }

        @JsonProperty("jwk")
        public Builder withJsonWebKey(JWK jwk) {
            this.jsonWebKey = jwk;
            return this;
        }

        @JsonProperty("kid")
        public Builder withKeyId(String kid) {
            this.keyId = kid;
            return this;
        }

        @JsonProperty("x5u")
        public Builder withX509Url(URI x5u) {
            this.x509Url = x5u;
            return this;
        }

        @JsonProperty("x5c")
        @JsonDeserialize(contentAs = CertDeserializer.class)
        public Builder withX509CertificateChain(List<byte[]> chain) {
            if (chain == null || chain.isEmpty()) {
                this.x509CertificateChain = null;
            } else {
                this.x509CertificateChain = ImmutableList.copyOf(
                        chain.stream()
                                .filter(e -> e != null && e.length > 0)
                                .map((e) -> e.clone())
                                .collect(Collectors.toList()));
            }
            return this;
        }

        @JsonProperty("x5t")
        public Builder withX509CertificateSHA1Thumbprint(byte[] sha1) {
            if (sha1 == null || sha1.length == 0) {
                sha1 = null;
            } else {
                sha1 = sha1.clone();
            }
            this.x509CertificateSHA1Thumbprint = sha1;
            return this;
        }

        @JsonProperty("x5t#S256")
        public Builder withX509CertificateSHA256Thumbprint(byte[] sha256) {
            if (sha256 == null || sha256.length == 0) {
                sha256 = null;
            } else {
                sha256 = sha256.clone();
            }
            this.x509CertificateSHA256Thumbprint = sha256;
            return this;
        }
        @JsonProperty("typ")
        public Builder withType(String typ) {
            this.type = typ;
            return this;
        }

        @JsonProperty("cty")
        public Builder withContentType(String cty) {
            this.contentType = cty;
            return this;
        }

        @JsonProperty("crit")
        public Builder withCritical(List<String> crit) {
            this.critical = ImmutableList.copyOf(crit.stream().filter(e -> e != null).collect(Collectors.toList()));
            return this;
        }

        @JsonProperty(value = "enc")
        public Builder withEncryptionAlgorithm(Algorithm enc) {
            this.encryptionAlgorithm = enc;
            return this;
        }

        @JsonProperty(value = "zip")
        public Builder withCompressionAlgorithm(Algorithm zip) {
            this.compressionAlgorithm = zip;
            return this;
        }

        @JsonProperty(value = "epk")
        public Builder withEphemeralPublicKey(JWK epk) {
            this.ephemeralPublicKey = epk;
            return this;
        }

        @JsonProperty(value = "apu")
        public Builder withAgreementPartyUInfo(byte[] apu) {
            this.agreementPartyUInfo = apu.clone();
            return this;
        }

        @JsonProperty(value = "apv")
        public Builder withAgreementPartyVInfo(byte[] apv) {
            this.agreementPartyVInfo = apv.clone();
            return this;
        }

        @JsonProperty(value = "iv")
        public Builder withInitializationVector(byte[] iv) {
            if (iv == null || iv.length == 0) {
                iv = null;
            } else {
                iv = iv.clone();
            }
            this.initializationVector = iv;
            return this;
        }

        @JsonProperty(value = "tag")
        public Builder withAuthenticationTag(byte[] tag) {
            if (tag == null || tag.length == 0) {
                tag = null;
            } else {
                tag = tag.clone();
            }
            this.authenticationTag = tag;
            return this;
        }

        @JsonProperty(value = "p2s")
        public Builder withPbe2SaltInput(byte[] p2s) {
            if (p2s == null || p2s.length == 0) {
                p2s = null;
            } else {
                p2s = p2s.clone();
            }
            this.pbe2SaltInput = p2s;
            return this;
        }

        @JsonProperty(value = "p2c")
        public Builder withPbes2Count(Integer p2c) {
            this.pbes2Count = p2c;
            return this;
        }

        @JsonProperty("b64")
        public Builder withB64EncodedPayload(String b64) {
            this.b64EncodedPayload = b64;
            return this;
        }

        @JsonProperty("iss")
        public Builder withIssuer(String iss) {
            this.issuer = iss;
            return this;
        }

        @JsonProperty("sub")
        public Builder withSubject(String sub) {
            this.subject = sub;
            return this;
        }

        @JsonProperty("aud")
        public Builder withAudience(String aud) {
            this.audience = aud;
            return this;
        }

        @JsonAnySetter
        public Builder withClaim(String name, Object o) {
            if (name != null && o != null) {
                this.claims.put(name, o);
            }
            return this;
        }

        public Builder withClaims(Map<String, Object> claims) {
            if (claims != null) {
                claims.entrySet().stream()
                        .filter(e -> e.getKey() != null && e.getValue() != null)
                        .forEach(e -> this.claims.put(e.getKey(), e.getValue()));
            }
            return this;
        }

        public Header build() {
            return new Header(algorithm,
                    jwkSetUrl,
                    jsonWebKey,
                    keyId,
                    x509Url,
                    x509CertificateChain,
                    x509CertificateSHA1Thumbprint,
                    x509CertificateSHA256Thumbprint,
                    type,
                    contentType,
                    critical,
                    encryptionAlgorithm,
                    compressionAlgorithm,
                    ephemeralPublicKey,
                    agreementPartyUInfo,
                    agreementPartyVInfo,
                    initializationVector,
                    authenticationTag,
                    pbe2SaltInput,
                    pbes2Count,
                    b64EncodedPayload,
                    issuer,
                    subject,
                    audience,
                    (claims.isEmpty()) ? null : claims);
        }
    }

    @JsonProperty("alg")
    private final Algorithm algorithm;
    @JsonProperty("jku")
    private final URI jwkSetUrl;
    @JsonProperty("jwk")
    private final JWK jsonWebKey;
    @JsonProperty("kid")
    private final String keyId;
    @JsonProperty("x5u")
    private final URI x509Url;
    @JsonProperty("x5c")
    @JsonSerialize(contentAs = CertSerializer.class)
    private final List<byte[]> x509CertificateChain;
    @JsonProperty("x5t")
    private final byte[] x509CertificateSHA1Thumbprint;
    @JsonProperty("x5t#S256")
    private final byte[] x509CertificateSHA256Thumbprint;
    @JsonProperty("typ")
    private final String type;
    @JsonProperty("cty")
    private final String contentType;
    @JsonProperty("crit")
    private final List<String> critical;
    @JsonProperty(value = "enc")
    private final Algorithm encryptionAlgorithm;
    @JsonProperty(value = "zip")
    private final Algorithm compressionAlgorithm;
    @JsonProperty(value = "epk")
    private final JWK ephemeralPublicKey;
    @JsonProperty(value = "apu")
    private final byte[] agreementPartyUInfo;
    @JsonProperty(value = "apv")
    private final byte[] agreementPartyVInfo;
    @JsonProperty(value = "iv")
    private final byte[] initializationVector;
    @JsonProperty(value = "tag")
    private final byte[] authenticationTag;
    @JsonProperty(value = "p2s")
    private final byte[] pbe2SaltInput;
    @JsonProperty(value = "p2c")
    private final Integer pbes2Count;
    @JsonProperty("b64")
    private final String b64EncodedPayload;
    @JsonProperty("iss")
    private final String issuer;
    @JsonProperty("sub")
    private final String subject;
    @JsonProperty("aud")
    private final String audience;
    private final Map<String,Object> claims;

    public Header(Algorithm algorithm, URI jwkSetUrl, JWK jsonWebKey, String keyId, URI x509Url, List<byte[]> x509CertificateChain, byte[] x509CertificateSHA1Thumbprint, byte[] x509CertificateSHA256Thumbprint, String type, String contentType, List<String> critical, Algorithm encryptionAlgorithm, Algorithm compressionAlgorithm, JWK ephemeralPublicKey, byte[] agreementPartyUInfo, byte[] agreementPartyVInfo, byte[] initializationVector, byte[] authenticationTag, byte[] pbe2SaltInput, Integer pbes2Count, String b64EncodedPayload, String issuer, String subject, String audience, Map<String, Object> claims) {
        this.algorithm = algorithm;
        this.jwkSetUrl = jwkSetUrl;
        this.jsonWebKey = jsonWebKey;
        this.keyId = keyId;
        this.x509Url = x509Url;
        this.x509CertificateChain = x509CertificateChain;
        this.x509CertificateSHA1Thumbprint = x509CertificateSHA1Thumbprint;
        this.x509CertificateSHA256Thumbprint = x509CertificateSHA256Thumbprint;
        this.type = type;
        this.contentType = contentType;
        this.critical = critical;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.compressionAlgorithm = compressionAlgorithm;
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.agreementPartyUInfo = agreementPartyUInfo;
        this.agreementPartyVInfo = agreementPartyVInfo;
        this.initializationVector = initializationVector;
        this.authenticationTag = authenticationTag;
        this.pbe2SaltInput = pbe2SaltInput;
        this.pbes2Count = pbes2Count;
        this.b64EncodedPayload = b64EncodedPayload;
        this.issuer = issuer;
        this.subject = subject;
        this.audience = audience;
        this.claims = claims;
    }

    public Header(Header other) {
        this(other.algorithm,
                other.jwkSetUrl,
                other.jsonWebKey,
                other.keyId,
                other.x509Url,
                other.x509CertificateChain,
                other.x509CertificateSHA1Thumbprint,
                other.x509CertificateSHA256Thumbprint,
                other.type,
                other.contentType,
                other.critical,
                other.encryptionAlgorithm,
                other.compressionAlgorithm,
                other.ephemeralPublicKey,
                other.agreementPartyUInfo,
                other.agreementPartyVInfo,
                other.initializationVector,
                other.authenticationTag,
                other.pbe2SaltInput,
                other.pbes2Count,
                other.b64EncodedPayload,
                other.issuer,
                other.subject,
                other.audience,
                other.claims);
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public URI getJwkSetUrl() {
        return jwkSetUrl;
    }

    public JWK getJsonWebKey() {
        return jsonWebKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public URI getX509Url() {
        return x509Url;
    }

    public List<byte[]> getX509CertificateChain() {
        return Collections.unmodifiableList(x509CertificateChain.stream().map(byte[]::clone).collect(Collectors.toList()));
    }

    public byte[] getX509CertificateSHA1Thumbprint() {
        return JoseUtils.clone(x509CertificateSHA1Thumbprint);
    }

    public byte[] getX509CertificateSHA256Thumbprint() {
        return JoseUtils.clone(x509CertificateSHA256Thumbprint);
    }

    public String getType() {
        return type;
    }

    public String getContentType() {
        return contentType;
    }

    public List<String> getCritical() {
        return critical;
    }

    public Algorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public Algorithm getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    public JWK getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public byte[] getAgreementPartyUInfo() {
        return agreementPartyUInfo;
    }

    public byte[] getAgreementPartyVInfo() {
        return agreementPartyVInfo;
    }

    public byte[] getInitializationVector() {
        return JoseUtils.clone(initializationVector);
    }

    public byte[] getAuthenticationTag() {
        return JoseUtils.clone(authenticationTag);
    }

    public byte[] getPbe2SaltInput() {
        return JoseUtils.clone(pbe2SaltInput);
    }

    public Integer getPbes2Count() {
        return pbes2Count;
    }

    public String getB64EncodedPayload() {
        return b64EncodedPayload;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSubject() {
        return subject;
    }

    public String getAudience() {
        return audience;
    }

    public Object getClaim(String key) {
        return claims.get(key);
    }

    public <T> T getClaim(String key, Class<T> cls) {
        return cls.cast(getClaim(key));
    }

    @JsonAnyGetter
    public Map<String, Object> getClaims() {
        return claims;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Header merge(Header mainHeader, Header... headers) throws IllegalArgumentException {
        if (headers == null || headers.length == 0) {
            return mainHeader;
        }
        if (mainHeader == null) {
            return merge(headers[0], Arrays.copyOfRange(headers, 1, headers.length));
        }
        Base64.Encoder b64urlEncoder = Base64.getUrlEncoder().withoutPadding();
        Base64.Decoder b64urlDecoder = Base64.getUrlDecoder();
        Algorithm algorithm = mainHeader.algorithm;
        URI jwkSetUrl = mainHeader.jwkSetUrl;
        JWK jsonWebKey = mainHeader.jsonWebKey;
        String keyId = mainHeader.keyId;
        URI x509Url = mainHeader.x509Url;
        List<String> x509CertificateChain = ImmutableList.copyOf(
                mainHeader.x509CertificateChain.stream()
                        .map(e -> Base64.getEncoder().encodeToString(e))
                        .collect(Collectors.toList()));
        String x509CertificateSHA1Thumbprint = b64urlEncoder.encodeToString(mainHeader.x509CertificateSHA1Thumbprint);
        String x509CertificateSHA256Thumbprint = b64urlEncoder.encodeToString(mainHeader.x509CertificateSHA256Thumbprint);
        String type = mainHeader.type;
        String contentType = mainHeader.contentType;
        List<String> critical = mainHeader.critical;
        Algorithm encryptionAlgorithm = mainHeader.encryptionAlgorithm;
        Algorithm compressionAlgorithm = mainHeader.compressionAlgorithm;
        JWK ephemeralPublicKey = mainHeader.ephemeralPublicKey;
        String agreementPartyUInfo = b64urlEncoder.encodeToString(mainHeader.agreementPartyUInfo);
        String agreementPartyVInfo = b64urlEncoder.encodeToString(mainHeader.agreementPartyVInfo);
        String initializationVector = b64urlEncoder.encodeToString(mainHeader.initializationVector);
        String authenticationTag = b64urlEncoder.encodeToString(mainHeader.authenticationTag);
        String pbe2SaltInput = b64urlEncoder.encodeToString(mainHeader.pbe2SaltInput);
        Integer pbes2Count = mainHeader.pbes2Count;
        String b64EncodedPayload = mainHeader.b64EncodedPayload;
        String issuer = mainHeader.issuer;
        String subject = mainHeader.subject;
        String audience = mainHeader.audience;
        Map<String,Object> claims = new HashMap<>(mainHeader.claims);

        for (Header header : headers) {
            if (header == null) {
                continue;
            }
            if (header.algorithm != null) {
                if (algorithm == null || algorithm.equals(header.algorithm)) {
                    algorithm = header.algorithm;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.jwkSetUrl != null) {
                if (jwkSetUrl == null || jwkSetUrl.equals(header.jwkSetUrl)) {
                    jwkSetUrl = header.jwkSetUrl;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.jsonWebKey != null) {
                if (jsonWebKey == null || jsonWebKey.equals(header.jsonWebKey)) {
                    jsonWebKey = header.jsonWebKey;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.keyId != null) {
                if (keyId == null || keyId.equals(header.keyId)) {
                    keyId = header.keyId;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.x509Url != null) {
                if (x509Url == null || x509Url.equals(header.x509Url)) {
                    x509Url = header.x509Url;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.x509CertificateChain != null) {
                List<String> chain = ImmutableList.copyOf(
                        header.x509CertificateChain.stream()
                                .map(e -> Base64.getEncoder().encodeToString(e))
                                .collect(Collectors.toList()));
                if (x509CertificateChain == null || x509CertificateChain.equals(chain)) {
                    x509CertificateChain = chain;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.x509CertificateSHA1Thumbprint != null) {
                String thumbprint = b64urlEncoder.encodeToString(header.x509CertificateSHA1Thumbprint);
                if (x509CertificateSHA1Thumbprint == null || x509CertificateSHA1Thumbprint.equals(thumbprint)) {
                    x509CertificateSHA1Thumbprint = thumbprint;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.x509CertificateSHA256Thumbprint != null) {
                String thumbprint = b64urlEncoder.encodeToString(header.x509CertificateSHA256Thumbprint);
                if (x509CertificateSHA256Thumbprint == null || x509CertificateSHA256Thumbprint.equals(thumbprint)) {
                    x509CertificateSHA256Thumbprint = thumbprint;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.type != null) {
                if (type == null || type.equals(header.type)) {
                    type = header.type;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.contentType != null) {
                if (contentType == null || contentType.equals(header.contentType)) {
                    contentType = header.contentType;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.critical != null) {
                if (critical == null || critical.equals(header.critical)) {
                    critical = header.critical;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.encryptionAlgorithm != null) {
                if (encryptionAlgorithm == null || encryptionAlgorithm.equals(header.encryptionAlgorithm)) {
                    encryptionAlgorithm = header.encryptionAlgorithm;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.compressionAlgorithm != null) {
                if (compressionAlgorithm == null || compressionAlgorithm.equals(header.compressionAlgorithm)) {
                    compressionAlgorithm = header.compressionAlgorithm;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.ephemeralPublicKey != null) {
                if (ephemeralPublicKey == null || ephemeralPublicKey.equals(header.ephemeralPublicKey)) {
                    ephemeralPublicKey = header.ephemeralPublicKey;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.agreementPartyUInfo != null) {
                String apu = b64urlEncoder.encodeToString(header.agreementPartyUInfo);
                if (agreementPartyUInfo == null || agreementPartyUInfo.equals(apu)) {
                    agreementPartyUInfo = apu;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.agreementPartyVInfo != null) {
                String apv = b64urlEncoder.encodeToString(header.agreementPartyVInfo);
                if (agreementPartyVInfo == null || agreementPartyVInfo.equals(apv)) {
                    agreementPartyVInfo = apv;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.initializationVector != null) {
                String iv = b64urlEncoder.encodeToString(header.initializationVector);
                if (initializationVector == null || initializationVector.equals(iv)) {
                    initializationVector = iv;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.authenticationTag != null) {
                String tag = b64urlEncoder.encodeToString(header.authenticationTag);
                if (authenticationTag == null || authenticationTag.equals(tag)) {
                    authenticationTag = tag;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.pbe2SaltInput != null) {
                String salt = b64urlEncoder.encodeToString(header.pbe2SaltInput);
                if (pbe2SaltInput == null || pbe2SaltInput.equals(salt)) {
                    pbe2SaltInput = salt;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.pbes2Count != null) {
                if (pbes2Count == null || pbes2Count.equals(header.pbes2Count)) {
                    pbes2Count = header.pbes2Count;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.b64EncodedPayload != null) {
                if (b64EncodedPayload == null || b64EncodedPayload.equals(header.b64EncodedPayload)) {
                    b64EncodedPayload = header.b64EncodedPayload;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.issuer != null) {
                if (issuer == null || issuer.equals(header.issuer)) {
                    issuer = header.issuer;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.subject != null) {
                if (subject == null || subject.equals(header.subject)) {
                    subject = header.subject;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            if (header.audience != null) {
                if (audience == null || audience.equals(header.audience)) {
                    audience = header.audience;
                } else {
                    throw new IllegalArgumentException();
                }
            }
            header.claims.entrySet().forEach(e -> {
                String key = e.getKey();
                Object o = e.getValue();
                Object old = claims.put(key, o);
                if (old != null && !old.equals(o)) {
                    throw new IllegalArgumentException();
                }
            });
        }

        return new Header(algorithm,
                jwkSetUrl,
                jsonWebKey,
                keyId,
                x509Url,
                ImmutableList.copyOf(
                        x509CertificateChain.stream()
                                .map(e -> Base64.getMimeDecoder().decode(e))
                                .collect(Collectors.toList())),
                b64urlDecoder.decode(x509CertificateSHA1Thumbprint),
                b64urlDecoder.decode(x509CertificateSHA256Thumbprint),
                type,
                contentType,
                critical,
                encryptionAlgorithm,
                compressionAlgorithm,
                ephemeralPublicKey,
                b64urlDecoder.decode(agreementPartyUInfo),
                b64urlDecoder.decode(agreementPartyVInfo),
                b64urlDecoder.decode(initializationVector),
                b64urlDecoder.decode(authenticationTag),
                b64urlDecoder.decode(pbe2SaltInput),
                pbes2Count,
                b64EncodedPayload,
                issuer,
                subject,
                audience,
                ImmutableMap.copyOf(claims));
    }

    public String toJson() {
        ObjectMapper om = new ObjectMapper();
        om.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
        try {
            return om.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public static Header parse(String json) {
        ObjectMapper om = new ObjectMapper();
        om.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
        try {
            return om.readValue(json, Header.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
