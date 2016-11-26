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
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAMultiPrimePrivateCrtKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAMultiPrimePrivateCrtKeySpec;
import java.security.spec.RSAOtherPrimeInfo;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

/**
 *
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
@JsonDeserialize(builder = JWK.Builder.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class JWK implements Serializable {
    @JsonPOJOBuilder
    public static final class Builder {
        private String keyId = null;
        private String keyType = null;
        private String publicKeyUse = null;
        private List<String> keyOperations = null;
        private String algorithm = null;
        private URI x509Url = null;
        private List<String> x509CertificateChain = null;
        private byte[] x509CertificateSHA1Thumbprint = null;
        private byte[] x509CertificateSHA256Thumbprint = null;
        private String curve = null;
        private byte[] xCoordinate = null;
        private byte[] yCoordinate = null;
        private byte[] privateKey = null;
        private byte[] modulus = null;
        private byte[] exponent = null;
        private byte[] firstPrimeFactor = null;
        private byte[] secondPrimeFactor = null;
        private byte[] firstFactorCrtExponent = null;
        private byte[] secondFactorCrtExponent = null;
        private byte[] firstCrtCoefficient = null;
        private List<OtherPrimeInfo> otherPrimesInfo = null;
        private byte[] keyValue = null;
        private final Map<String, Object> claims = new HashMap<>();

        @JsonProperty("kid")
        public Builder withKeyId(String keyId) {
            if (keyId == null || keyId.isEmpty()) {
                keyId = null;
            }
            this.keyId = keyId;
            return this;
        }

        @JsonProperty("kty")
        public Builder withKeyType(String keyType) {
            if (keyType == null || keyType.isEmpty()) {
                keyType = null;
            }
            this.keyType = keyType;
            return this;
        }

        @JsonProperty("use")
        public Builder withPublicKeyUse(String publicKeyUse) {
            if (publicKeyUse == null || publicKeyUse.isEmpty()) {
                publicKeyUse = null;
            }
            this.publicKeyUse = publicKeyUse;
            return this;
        }

        /**
         * Add the given key operations to the builder. This method will save
         * an immutable copy of the given list in this builder.
         * @param keyOperations the key operations for the new JWK
         * @return this builder
         */
        @JsonProperty("key_ops")
        public Builder withKeyOperations(List<String> keyOperations) {
            if (keyOperations == null || keyOperations.isEmpty()) {
                keyOperations = null;
            } else {
                keyOperations = keyOperations.stream().filter(s -> s != null && !s.isEmpty()).collect(Collectors.toList());
            }
            this.keyOperations = ImmutableList.copyOf(keyOperations);
            return this;
        }

        @JsonProperty("alg")
        public Builder withAlgorithm(String algorithm) {
            if (algorithm == null || algorithm.isEmpty()) {
                algorithm = null;
            }
            this.algorithm = algorithm;
            return this;
        }

        @JsonProperty("x5u")
        public Builder withX509Url(URI x509Url) {
            this.x509Url = x509Url;
            return this;
        }

        /**
         * Adds the given X.509 certificate chain (in binary format) to the builder.
         * This method will save an immutable copy of the given list, containing a
         * copy of each array within it, in this builder.
         * @param chain the X.509 certificate chain, in binary format
         * @return this builder.
         */
        @JsonProperty("x5c")
        public Builder withX509CertificateChain(List<String> chain) {
            if (chain == null || chain.isEmpty()) {
                this.x509CertificateChain = null;
            } else {
                this.x509CertificateChain = ImmutableList.copyOf(chain);
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

        @JsonProperty("crv")
        public Builder withCurve(String curve) {
            this.curve = curve;
            return this;
        }

        @JsonProperty("x")
        public Builder withXCoordinate(byte[] x) {
            if (x == null || x.length == 0) {
                x = null;
            } else {
                x = x.clone();
            }
            this.xCoordinate = x;
            return this;
        }

        @JsonProperty("y")
        public Builder withYCoordinate(byte[] y) {
            if (y == null || y.length == 0) {
                y = null;
            } else {
                y = y.clone();
            }
            this.yCoordinate = y;
            return this;
        }

        @JsonProperty("d")
        public Builder withPrivateKey(byte[] key) {
            if (key == null || key.length == 0) {
                key = null;
            } else {
                key = key.clone();
            }
            this.privateKey = key;
            return this;
        }

        @JsonProperty("n")
        public Builder withModulus(byte[] n) {
            if (n == null || n.length == 0) {
                n = null;
            } else {
                n = n.clone();
            }
            this.modulus = n;
            return this;
        }

        @JsonProperty("e")
        public Builder withExponent(byte[] e) {
            if (e == null || e.length == 0) {
                e = null;
            } else {
                e = e.clone();
            }
            this.exponent = e;
            return this;
        }

        @JsonProperty("p")
        public Builder withFirstPrimeFactor(byte[] p) {
            if (p == null || p.length == 0) {
                p = null;
            } else {
                p = p.clone();
            }
            this.firstPrimeFactor = p;
            return this;
        }

        @JsonProperty("q")
        public Builder withSecondPrimeFactor(byte[] q) {
            if (q == null || q.length == 0) {
                q = null;
            } else {
                q = q.clone();
            }
            this.secondPrimeFactor = q;
            return this;
        }

        @JsonProperty("dp")
        public Builder withFirstFactorCrtExponent(byte[] dp) {
            if (dp == null || dp.length == 0) {
                dp = null;
            } else {
                dp = dp.clone();
            }
            this.firstFactorCrtExponent = dp;
            return this;
        }

        @JsonProperty("dq")
        public Builder withSecondFactorCrtExponent(byte[] dq) {
            if (dq == null || dq.length == 0) {
                dq = null;
            } else {
                dq = dq.clone();
            }
            this.secondFactorCrtExponent = dq;
            return this;
        }

        @JsonProperty("qi")
        public Builder withFirstCrtCoefficient(byte[] qi) {
            if (qi == null || qi.length == 0) {
                qi = null;
            } else {
                qi = qi.clone();
            }
            this.firstCrtCoefficient = qi;
            return this;
        }

        @JsonProperty("oth")
        public Builder withOtherPrimesInfo(List<OtherPrimeInfo> oth) {
            this.otherPrimesInfo = ImmutableList.copyOf(oth.stream().filter(e -> e != null).collect(Collectors.toList()));
            return this;
        }

        @JsonProperty("k")
        public Builder withKeyValue(byte[] k) {
            if (k == null || k.length == 0) {
                k = null;
            } else {
                k = k.clone();
            }
            this.keyValue = k;
            return this;
        }

        @JsonAnySetter
        public Builder withClaim(String name, Object o) {
            claims.put(name, o);
            return this;
        }

        @JsonIgnore
        public Builder withClaims(Map<String, Object> m) {
            if (m != null) {
                claims.putAll(m);
            }
            return this;
        }

        @JsonIgnore
        public Builder withPublicKey(ECPublicKey pub) {
            this.keyType = "EC";
            this.curve = CURVE_NAMES.get(new ECParameterSpecEqual(pub.getParams())).getName();
            this.xCoordinate = pub.getW().getAffineX().toByteArray();
            this.yCoordinate = pub.getW().getAffineY().toByteArray();
            return this;
        }

        @JsonIgnore
        public Builder withKeyPair(ECPublicKey pub, ECPrivateKey priv) {
            withPublicKey(pub);
            this.privateKey = priv.getS().toByteArray();
            return this;
        }

        @JsonIgnore
        public Builder withPublicKey(RSAPublicKey pub) {
            this.keyType = "RSA";
            this.modulus = pub.getModulus().toByteArray();
            this.exponent = pub.getPublicExponent().toByteArray();
            return this;
        }

        @JsonIgnore
        public Builder withKeyPair(RSAPublicKey pub, RSAPrivateKey priv) {
            withPublicKey(pub);
            this.privateKey = priv.getPrivateExponent().toByteArray();
            return this;
        }

        @JsonIgnore
        public Builder withKeyPair(RSAPublicKey pub, RSAPrivateCrtKey priv) {
            withPublicKey(pub);
            this.privateKey = priv.getPrivateExponent().toByteArray();
            this.firstPrimeFactor = priv.getPrimeP().toByteArray();
            this.secondPrimeFactor = priv.getPrimeQ().toByteArray();
            this.firstFactorCrtExponent = priv.getPrimeExponentP().toByteArray();
            this.secondFactorCrtExponent = priv.getPrimeExponentQ().toByteArray();
            this.firstCrtCoefficient = priv.getCrtCoefficient().toByteArray();
            return this;
        }

        @JsonIgnore
        public Builder withKeyPair(RSAPublicKey pub, RSAMultiPrimePrivateCrtKey priv) {
            withPublicKey(pub);
            this.privateKey = priv.getPrivateExponent().toByteArray();
            this.privateKey = priv.getPrivateExponent().toByteArray();
            this.firstPrimeFactor = priv.getPrimeP().toByteArray();
            this.secondPrimeFactor = priv.getPrimeQ().toByteArray();
            this.firstFactorCrtExponent = priv.getPrimeExponentP().toByteArray();
            this.secondFactorCrtExponent = priv.getPrimeExponentQ().toByteArray();
            this.firstCrtCoefficient = priv.getCrtCoefficient().toByteArray();
            RSAOtherPrimeInfo[] info = priv.getOtherPrimeInfo();
            if (info != null) {
                otherPrimesInfo = ImmutableList.copyOf(Arrays.asList(info).stream()
                        .map((i) -> new OtherPrimeInfo(
                                i.getPrime().toByteArray(),
                                i.getExponent().toByteArray(),
                                i.getCrtCoefficient().toByteArray()))
                        .collect(Collectors.toList()));
            }
            return this;
        }

        @JsonIgnore
        public Builder withSecretKey(SecretKey key) {
            this.keyType = "oct";
            byte[] encoded = key.getEncoded();
            this.keyValue = encoded.clone();
            return this;
        }

        @JsonIgnore
        public Builder withSecretKey(SecretKey key1, SecretKey key2) {
            this.keyType = "oct";
            byte[] encoded1 = key1.getEncoded();
            byte[] encoded2 = key2.getEncoded();
            byte[] value = new byte[encoded1.length + encoded2.length];
            System.arraycopy(encoded1, 0, value, 0, encoded1.length);
            System.arraycopy(encoded2, 0, value, encoded1.length, encoded2.length);
            this.keyValue = value;
            return this;
        }

        @JsonIgnore
        public Builder withSecretKey(SecretKey... keys) {
            List<byte[]> encodedKeys = Arrays.asList(keys).stream().map(SecretKey::getEncoded).collect(Collectors.toList());
            int total = encodedKeys.stream().collect(Collectors.summingInt((a) -> a.length));
            int i = 0;
            byte[] value = new byte[total];
            for (byte[] k : encodedKeys) {
                System.arraycopy(k, 0, value, i, k.length);
                i += k.length;
            }
            this.keyValue = value;
            return this;
        }

        @JsonIgnore
        public Builder withCertificate(X509Certificate cert) {
            PublicKey pub = cert.getPublicKey();
            if (pub instanceof ECPublicKey) {
                withPublicKey((ECPublicKey)pub);
            } else if (pub instanceof RSAPublicKey) {
                withPublicKey((RSAPublicKey)pub);
            } else {
                throw new IllegalArgumentException("This implementation does not support this type of certificate");
            }
            try {
                byte[] encoded = cert.getEncoded();
                this.x509CertificateChain = ImmutableList.of(Base64.getEncoder().encodeToString(encoded));
                MessageDigest sha1 = MessageDigest.getInstance("SHA-1", "BC");
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "BC");
                this.x509CertificateSHA1Thumbprint = sha1.digest(encoded);
                this.x509CertificateSHA256Thumbprint = sha256.digest(encoded);
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException("Malformed Certificate", e);
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new RuntimeException(e);
            }
            return this;
        }

        @JsonIgnore
        public Builder withCertificate(X509Certificate... certs) {
            X509Certificate last = null;
            try {
                ImmutableList.Builder<String> ders = ImmutableList.builder();
                for (X509Certificate cert : certs) {
                    last = cert;
                    ders.add(Base64.getEncoder().encodeToString(cert.getEncoded()));
                }
                if (last == null) {
                    throw new IllegalArgumentException("Empty list");
                }
                this.x509CertificateChain = ders.build();
                byte[] encoded = last.getEncoded();
                MessageDigest sha1 = MessageDigest.getInstance("SHA-1", "BC");
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "BC");
                this.x509CertificateSHA1Thumbprint = sha1.digest(encoded);
                this.x509CertificateSHA256Thumbprint = sha256.digest(encoded);
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException("Malformed certificate", e);
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new RuntimeException(e);
            }
            return this;
        }

        public JWK build() {
            return new JWK(keyId,
                    keyType,
                    publicKeyUse,
                    keyOperations,
                    algorithm,
                    x509Url,
                    x509CertificateChain,
                    x509CertificateSHA1Thumbprint,
                    x509CertificateSHA256Thumbprint,
                    curve,
                    xCoordinate,
                    yCoordinate,
                    privateKey,
                    modulus,
                    exponent,
                    firstPrimeFactor,
                    secondPrimeFactor,
                    firstFactorCrtExponent,
                    secondFactorCrtExponent,
                    firstCrtCoefficient,
                    otherPrimesInfo,
                    keyValue,
                    (claims.isEmpty()) ? null : ImmutableMap.copyOf(claims));
        }
    }
    /**
     * This class represents prime factors for RSA Chinese Remainder Theorem when
     * there are more than two prime factor sets described.
     * 
     * @author Jonathan Paz <jonathan@pazdev.com>
     */
    public static class OtherPrimeInfo {
        @JsonProperty(value = "r")
        private final byte[] primeFactor;
        @JsonProperty(value = "d")
        private final byte[] factorCrtExponent;
        @JsonProperty(value = "t")
        private final byte[] factorCrtCoefficient;

        public OtherPrimeInfo(byte[] primeFactor, byte[] factorCrtExponent, byte[] factorCrtCoefficient) {
            super();
            this.primeFactor = primeFactor;
            this.factorCrtExponent = factorCrtExponent;
            this.factorCrtCoefficient = factorCrtCoefficient;
        }

        public OtherPrimeInfo(OtherPrimeInfo other) {
            this(other.primeFactor, other.factorCrtExponent, other.factorCrtCoefficient);
        }

        public byte[] getPrimeFactor() {
            return primeFactor;
        }

        public byte[] getFactorCrtExponent() {
            return factorCrtExponent;
        }

        public byte[] getFactorCrtCoefficient() {
            return factorCrtCoefficient;
        }

    }
    
    /**
     * This class represents a name for an elliptic curve. This is designed to
     * describe multiple names for the same elliptic curve. This class is
     * necessary because an {@link ECParameterSpec} does not itself have the name
     * of the curve that it represents, so the name needs to be found.
     */
    private static final class ECNames {
        private String x962;
        private String sec;
        private String nist;
        private String teletrust;
        private String other;
        private static final Pattern X962_PATTERN = Pattern.compile("(?:prime\\d\\d\\dv\\d)|(?:c2\\wnb\\d\\d\\d\\w\\d)", 0);
        private static final Pattern SEC_PATTERN = Pattern.compile("sec\\w\\d\\d\\d\\w\\d", 0);
        private static final Pattern NIST_PATTERN = Pattern.compile("[PBK]-\\d\\d\\d");
        private static final Pattern TELETRUST_PATTERN = Pattern.compile("brainpool\\w\\d\\d\\d\\w\\d");

        private ECNames(String name) {
            super();
            this.addName(name);
        }

        private ECNames merge(ECNames other) {
            if (this.nist == null && other.nist != null) {
                this.nist = other.nist;
            }
            if (this.x962 == null && other.x962 != null) {
                this.x962 = other.x962;
            }
            if (this.sec == null && other.sec != null) {
                this.sec = other.sec;
            }
            if (this.teletrust == null && other.teletrust != null) {
                this.teletrust = other.teletrust;
            }
            if (this.other == null && other.other != null) {
                this.other = other.other;
            }
            return this;
        }

        private void addName(String name) {
            Matcher x962matcher = X962_PATTERN.matcher(name);
            Matcher secMatcher = SEC_PATTERN.matcher(name);
            Matcher nistMatcher = NIST_PATTERN.matcher(name);
            Matcher teletrustMatcher = TELETRUST_PATTERN.matcher(name);
            if (x962matcher.matches()) {
                x962 = name;
            } else if (secMatcher.matches()) {
                sec = name;
            } else if (nistMatcher.matches()) {
                nist = name;
            } else if (teletrustMatcher.matches()) {
                teletrust = name;
            } else {
                other = name;
            }
        }

        private String getName() {
            if (nist != null) {
                return nist;
            } else if (sec != null) {
                return sec;
            } else if (x962 != null) {
                return x962;
            } else if (teletrust != null) {
                return teletrust;
            } else {
                return other;
            }
        }
    }

    private static final Map<ECParameterSpecEqual, ECNames> CURVE_NAMES =
            Collections.list((Enumeration<String>)ECNamedCurveTable.getNames()).stream()
                    .map((name) -> ECNamedCurveTable.getParameterSpec(name))
                    .map((spec) -> new ECNamedCurveSpec(
                            spec.getName(),
                            spec.getCurve(),
                            spec.getG(),
                            spec.getN(),
                            spec.getH(),
                            spec.getSeed()))
                    .collect(Collectors.toMap(
                            (spec) -> new ECParameterSpecEqual(spec),
                            (spec) -> new ECNames(spec.getName()),
                            (name1, name2) -> name1.merge(name2)));

    @JsonProperty("kid")
    private final String keyId;
    @JsonProperty("kty")
    private final String keyType;
    @JsonProperty("use")
    private final String publicKeyUse;
    @JsonProperty("key_ops")
    private final List<String> keyOperations;
    @JsonProperty("alg")
    private final String algorithm;
    @JsonProperty("x5u")
    private final URI x509Url;
    @JsonProperty("x5c")
    private final List<String> x509CertificateChain;
    @JsonProperty("x5t")
    private final byte[] x509CertificateSHA1Thumbprint;
    @JsonProperty("x5t#S256")
    private final byte[] x509CertificateSHA256Thumbprint;
    @JsonProperty("crv")
    private final String curve;
    @JsonProperty("x")
    private final byte[] xCoordinate;
    @JsonProperty("y")
    private final byte[] yCoordinate;
    @JsonProperty("d")
    private final byte[] privateKey;
    @JsonProperty("n")
    private final byte[] modulus;
    @JsonProperty("e")
    private final byte[] exponent;
    @JsonProperty("p")
    private final byte[] firstPrimeFactor;
    @JsonProperty("q")
    private final byte[] secondPrimeFactor;
    @JsonProperty("dp")
    private final byte[] firstFactorCrtExponent;
    @JsonProperty("dq")
    private final byte[] secondFactorCrtExponent;
    @JsonProperty("qi")
    private final byte[] firstCrtCoefficient;
    @JsonProperty("oth")
    private final List<OtherPrimeInfo> otherPrimesInfo;
    @JsonProperty("k")
    private final byte[] keyValue;
    private final Map<String, Object> claims;

    private JWK(String keyId, String keyType, String publicKeyUse, List<String> keyOperations, String algorithm, URI x509Url, List<String> x509CertificateChain, byte[] x509CertificateSHA1Thumbprint, byte[] x509CertificateSHA256Thumbprint, String curve, byte[] xCoordinate, byte[] yCoordinate, byte[] privateKey, byte[] modulus, byte[] exponent, byte[] firstPrimeFactor, byte[] secondPrimeFactor, byte[] firstFactorCrtExponent, byte[] secondFactorCrtExponent, byte[] firstCrtCoefficient, List<OtherPrimeInfo> otherPrimesInfo, byte[] keyValue, Map<String, Object> claims) {
        this.keyId = keyId;
        this.keyType = keyType;
        this.publicKeyUse = publicKeyUse;
        this.keyOperations = keyOperations;
        this.algorithm = algorithm;
        this.x509Url = x509Url;
        this.x509CertificateChain = x509CertificateChain;
        this.x509CertificateSHA1Thumbprint = x509CertificateSHA1Thumbprint;
        this.x509CertificateSHA256Thumbprint = x509CertificateSHA256Thumbprint;
        this.curve = curve;
        this.xCoordinate = xCoordinate;
        this.yCoordinate = yCoordinate;
        this.privateKey = privateKey;
        this.modulus = modulus;
        this.exponent = exponent;
        this.firstPrimeFactor = firstPrimeFactor;
        this.secondPrimeFactor = secondPrimeFactor;
        this.firstFactorCrtExponent = firstFactorCrtExponent;
        this.secondFactorCrtExponent = secondFactorCrtExponent;
        this.firstCrtCoefficient = firstCrtCoefficient;
        this.otherPrimesInfo = otherPrimesInfo;
        this.keyValue = keyValue;
        this.claims = claims;
    }

    public JWK(JWK other) {
        this(other.keyId,
                other.keyType,
                other.publicKeyUse,
                other.keyOperations,
                other.algorithm,
                other.x509Url,
                other.x509CertificateChain,
                other.x509CertificateSHA1Thumbprint,
                other.x509CertificateSHA256Thumbprint,
                other.curve,
                other.xCoordinate,
                other.yCoordinate,
                other.privateKey,
                other.modulus,
                other.exponent,
                other.firstPrimeFactor,
                other.secondPrimeFactor,
                other.firstFactorCrtExponent,
                other.secondFactorCrtExponent,
                other.firstCrtCoefficient,
                other.otherPrimesInfo,
                other.keyValue,
                other.claims);
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getKeyId() {
        return keyId;
    }

    public String getKeyType() {
        return keyType;
    }

    public String getPublicKeyUse() {
        return publicKeyUse;
    }

    public List<String> getKeyOperations() {
        return keyOperations;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public URI getX509Url() {
        return x509Url;
    }

    public List<String> getX509CertificateChain() {
        return x509CertificateChain;
    }

    public byte[] getX509CertificateSHA1Thumbprint() {
        return JoseUtils.clone(x509CertificateSHA1Thumbprint);
    }

    public byte[] getX509CertificateSHA256Thumbprint() {
        return JoseUtils.clone(x509CertificateSHA256Thumbprint);
    }

    public String getCurve() {
        return curve;
    }

    public byte[] getxCoordinate() {
        return JoseUtils.clone(xCoordinate);
    }

    public byte[] getyCoordinate() {
        return JoseUtils.clone(yCoordinate);
    }

    public byte[] getPrivateKey() {
        return JoseUtils.clone(privateKey);
    }

    public byte[] getModulus() {
        return JoseUtils.clone(modulus);
    }

    public byte[] getExponent() {
        return JoseUtils.clone(exponent);
    }

    public byte[] getFirstPrimeFactor() {
        return JoseUtils.clone(firstPrimeFactor);
    }

    public byte[] getSecondPrimeFactor() {
        return JoseUtils.clone(secondPrimeFactor);
    }

    public byte[] getFirstFactorCrtExponent() {
        return JoseUtils.clone(firstFactorCrtExponent);
    }

    public byte[] getSecondFactorCrtExponent() {
        return JoseUtils.clone(secondFactorCrtExponent);
    }

    public byte[] getFirstCrtCoefficient() {
        return JoseUtils.clone(firstCrtCoefficient);
    }

    public List<OtherPrimeInfo> getOtherPrimesInfo() {
        return otherPrimesInfo;
    }

    public byte[] getKeyValue() {
        return JoseUtils.clone(keyValue);
    }

    @JsonAnyGetter
    public Map<String, Object> getClaims() {
        return claims;
    }

    @JsonIgnore
    public Object getClaim(String name) {
        return claims.get(name);
    }

    @JsonIgnore
    public <T> T getClaim(String name, Class<T> cls) {
        return cls.cast(getClaim(name));
    }

    /**
     * <p>
     * Converts the keys described in this JWK to JCE {@link Key} objects. The map
     * returned will either be empty, signifying that no keys could be obtained
     * based on the given information, or one of the following keys:
     * </p>
     * <ul>
     * <li>public</li>
     * <li>private</li>
     * <li>secret</li>
     * </ul>
     * @return a map containing all the obtainable keys.
     */
    @JsonIgnore
    public Map<String, Key> getKeys() {
        HashMap<String, Key> retval = new HashMap<>();
        try {
            if (null != keyType) switch (keyType) {
                case "EC":{
                    KeyFactory fac = KeyFactory.getInstance("EC", "BC");
                    ECNamedCurveParameterSpec ecParamSpecBC = ECNamedCurveTable.getParameterSpec(curve);
                    ECNamedCurveSpec ecParamSpec = new ECNamedCurveSpec(
                            ecParamSpecBC.getName(),
                            ecParamSpecBC.getCurve(),
                            ecParamSpecBC.getG(),
                            ecParamSpecBC.getN(),
                            ecParamSpecBC.getH(),
                            ecParamSpecBC.getSeed());
                    if (privateKey != null && privateKey.length > 0) {
                        ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(new BigInteger(1, privateKey), ecParamSpec);
                        retval.put("private", fac.generatePrivate(privateSpec));
                    }       if (xCoordinate != null && xCoordinate.length > 0) {
                        ECPublicKeySpec publicSpec = new ECPublicKeySpec(
                                new ECPoint(new BigInteger(1, xCoordinate), new BigInteger(1, yCoordinate)),
                                ecParamSpec);
                        retval.put("public", fac.generatePublic(publicSpec));
                    }
                    break;
                }
                case "RSA":{
                    KeyFactory fac = KeyFactory.getInstance("RSA", "BC");
                    BigInteger m = new BigInteger(1, modulus);
                    BigInteger e = new BigInteger(1, exponent);
                    retval.put("public", fac.generatePublic(new RSAPublicKeySpec(m, e)));
                    if (privateKey != null && privateKey.length > 0) {
                        BigInteger d = new BigInteger(1, privateKey);
                        BigInteger p,q,dp,dq,qi;
                        RSAOtherPrimeInfo[] otherPrimes = null;
                        if (firstPrimeFactor != null && firstPrimeFactor.length > 0) {
                            p = new BigInteger(1, firstPrimeFactor);
                        } else {
                            p = null;
                        }
                        if (secondPrimeFactor != null && secondPrimeFactor.length > 0) {
                            q = new BigInteger(1, secondPrimeFactor);
                        } else {
                            q = null;
                        }
                        if (firstFactorCrtExponent != null && firstFactorCrtExponent.length > 0) {
                            dp = new BigInteger(1, firstFactorCrtExponent);
                        } else {
                            dp = null;
                        }
                        if (secondFactorCrtExponent != null && secondFactorCrtExponent.length > 0) {
                            dq = new BigInteger(1, secondFactorCrtExponent);
                        } else {
                            dq = null;
                        }
                        if (firstCrtCoefficient != null && firstCrtCoefficient.length > 0) {
                            qi = new BigInteger(1, firstCrtCoefficient);
                        } else {
                            qi = null;
                        }
                        if (otherPrimesInfo != null && otherPrimesInfo.size() > 0) {
                            otherPrimes = new RSAOtherPrimeInfo[otherPrimesInfo.size()];
                            for (int i = otherPrimes.length - 1; i >= 0; --i) {
                                BigInteger or,od,ot;
                                OtherPrimeInfo other = otherPrimesInfo.get(i);
                                if (other.primeFactor != null && other.primeFactor.length > 0) {
                                    or = new BigInteger(1, other.primeFactor);
                                } else {
                                    or = null;
                                }
                                if (other.factorCrtExponent != null && other.factorCrtExponent.length > 0) {
                                    od = new BigInteger(1, other.factorCrtExponent);
                                } else {
                                    od = null;
                                }
                                if (other.factorCrtCoefficient != null && other.factorCrtCoefficient.length > 0) {
                                    ot = new BigInteger(1, other.factorCrtCoefficient);
                                } else {
                                    ot = null;
                                }
                                otherPrimes[i] = new RSAOtherPrimeInfo(or, od, ot);
                            }
                        }
                        if (p != null || q != null || dp != null || dq != null) {
                            if (otherPrimes != null) {
                                RSAMultiPrimePrivateCrtKeySpec spec = new RSAMultiPrimePrivateCrtKeySpec(m, e, d, p, q, dp, dq, qi, otherPrimes);
                                retval.put("private", fac.generatePrivate(spec));
                            } else {
                                RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(m, e, d, p, q, dp, dq, qi);
                                retval.put("private", fac.generatePrivate(spec));
                            }
                        } else {
                            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(m, d);
                            retval.put("private", fac.generatePrivate(spec));
                        }
                    }
                    break;
                }
                case "oct":
                    retval.put("secret", new SecretKeySpec(keyValue, algorithm != null ? algorithm : "AES"));
                    break;
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return retval;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 23 * hash + Objects.hashCode(this.keyId);
        hash = 23 * hash + Objects.hashCode(this.keyType);
        hash = 23 * hash + Objects.hashCode(this.publicKeyUse);
        hash = 23 * hash + Objects.hashCode(this.keyOperations);
        hash = 23 * hash + Objects.hashCode(this.algorithm);
        hash = 23 * hash + Objects.hashCode(this.x509Url);
        hash = 23 * hash + Objects.hashCode(this.x509CertificateChain);
        hash = 23 * hash + Arrays.hashCode(this.x509CertificateSHA1Thumbprint);
        hash = 23 * hash + Arrays.hashCode(this.x509CertificateSHA256Thumbprint);
        hash = 23 * hash + Objects.hashCode(this.curve);
        hash = 23 * hash + Arrays.hashCode(this.xCoordinate);
        hash = 23 * hash + Arrays.hashCode(this.yCoordinate);
        hash = 23 * hash + Arrays.hashCode(this.privateKey);
        hash = 23 * hash + Arrays.hashCode(this.modulus);
        hash = 23 * hash + Arrays.hashCode(this.exponent);
        hash = 23 * hash + Arrays.hashCode(this.firstPrimeFactor);
        hash = 23 * hash + Arrays.hashCode(this.secondPrimeFactor);
        hash = 23 * hash + Arrays.hashCode(this.firstFactorCrtExponent);
        hash = 23 * hash + Arrays.hashCode(this.secondFactorCrtExponent);
        hash = 23 * hash + Arrays.hashCode(this.firstCrtCoefficient);
        hash = 23 * hash + Objects.hashCode(this.otherPrimesInfo);
        hash = 23 * hash + Arrays.hashCode(this.keyValue);
        hash = 23 * hash + Objects.hashCode(this.claims);
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
        final JWK other = (JWK) obj;
        if (!Objects.equals(this.keyId, other.keyId)) {
            return false;
        }
        if (!Objects.equals(this.keyType, other.keyType)) {
            return false;
        }
        if (!Objects.equals(this.publicKeyUse, other.publicKeyUse)) {
            return false;
        }
        if (!Objects.equals(this.algorithm, other.algorithm)) {
            return false;
        }
        if (!Objects.equals(this.curve, other.curve)) {
            return false;
        }
        if (!Objects.equals(this.keyOperations, other.keyOperations)) {
            return false;
        }
        if (!Objects.equals(this.x509Url, other.x509Url)) {
            return false;
        }
        if (!Objects.equals(this.x509CertificateChain, other.x509CertificateChain)) {
            return false;
        }
        if (!Arrays.equals(this.x509CertificateSHA1Thumbprint, other.x509CertificateSHA1Thumbprint)) {
            return false;
        }
        if (!Arrays.equals(this.x509CertificateSHA256Thumbprint, other.x509CertificateSHA256Thumbprint)) {
            return false;
        }
        if (!Arrays.equals(this.xCoordinate, other.xCoordinate)) {
            return false;
        }
        if (!Arrays.equals(this.yCoordinate, other.yCoordinate)) {
            return false;
        }
        if (!Arrays.equals(this.privateKey, other.privateKey)) {
            return false;
        }
        if (!Arrays.equals(this.modulus, other.modulus)) {
            return false;
        }
        if (!Arrays.equals(this.exponent, other.exponent)) {
            return false;
        }
        if (!Arrays.equals(this.firstPrimeFactor, other.firstPrimeFactor)) {
            return false;
        }
        if (!Arrays.equals(this.secondPrimeFactor, other.secondPrimeFactor)) {
            return false;
        }
        if (!Arrays.equals(this.firstFactorCrtExponent, other.firstFactorCrtExponent)) {
            return false;
        }
        if (!Arrays.equals(this.secondFactorCrtExponent, other.secondFactorCrtExponent)) {
            return false;
        }
        if (!Arrays.equals(this.firstCrtCoefficient, other.firstCrtCoefficient)) {
            return false;
        }
        if (!Objects.equals(this.otherPrimesInfo, other.otherPrimesInfo)) {
            return false;
        }
        if (!Arrays.equals(this.keyValue, other.keyValue)) {
            return false;
        }
        return Objects.equals(this.claims, other.claims);
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

    public static JWK parse(String json) {
        ObjectMapper om = new ObjectMapper();
        om.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
        try {
            return om.readValue(json, JWK.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    
}

class ECParameterSpecEqual extends ECParameterSpec {

    public ECParameterSpecEqual(EllipticCurve curve, ECPoint g, BigInteger n, int h) {
        super(curve, g, n, h);
    }
    
    public ECParameterSpecEqual(ECParameterSpec spec) {
        this(spec.getCurve(), spec.getGenerator(), spec.getOrder(), spec.getCofactor());
    }

    @Override
    public boolean equals(Object obj) {
        if (this.getClass().equals(obj.getClass())) {
            ECParameterSpecEqual other = (ECParameterSpecEqual) obj;
            return this.getCurve().equals(other.getCurve())
                    && this.getGenerator().equals(other.getGenerator())
                    && this.getOrder().equals(other.getOrder())
                    && this.getCofactor() == other.getCofactor();
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(getCurve(), getGenerator(), getOrder(), getCofactor());
    }
}