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
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.google.common.collect.ImmutableList;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
@JsonDeserialize(builder = JWS.JsonBuilder.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class JWS {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    @JsonProperty
    private final byte[] payload;
    @JsonProperty
    private final List<Signature> signatures;
    @JsonProperty("protected")
    private final byte[] protectedHeader;
    @JsonProperty
    private final Header header;
    @JsonProperty
    private final byte[] signature;

    public static final class Signature {
        @JsonProperty("protected")
        private final byte[] protectedHeader;
        @JsonProperty
        private final Header header;
        @JsonProperty
        private final byte[] signature;

        @JsonCreator
        public Signature(byte[] protectedHeader, Header header, byte[] signature) {
            this.protectedHeader = protectedHeader;
            this.header = header;
            this.signature = signature;
        }

        public byte[] getProtectedHeader() {
            return JoseUtils.clone(protectedHeader);
        }

        @JsonIgnore
        public Header getProtectedHeaderAsObject() {
            byte[] raw = Base64.getUrlDecoder().decode(protectedHeader);
            String h= new String(raw, StandardCharsets.UTF_8);
            ObjectMapper mapper = new ObjectMapper();
            mapper.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
            try {
                return mapper.readValue(h, Header.class);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public Header getHeader() {
            return header;
        }

        public byte[] getSignature() {
            return JoseUtils.clone(signature);
        }

    }

    public static final class Builder {
        private byte[] payload;
        private final ArrayList<Header> protectedHeaders = new ArrayList<>();
        private final ArrayList<Header> unprotectedHeaders = new ArrayList<>();
        private final ArrayList<Key> keys = new ArrayList<>();

        public Builder withPayload(Object payload) {
            ObjectMapper mapper = new ObjectMapper();
            mapper.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
            try {
                return withPayload(mapper.writeValueAsBytes(payload));
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }

        public Builder withPayload(String payload) {
            return withPayload(payload, StandardCharsets.UTF_8);
        }

        public Builder withPayload(String payload, Charset charset) {
            this.payload = payload.getBytes(charset);
            return this;
        }

        public Builder withPayload(byte[] payload) {
            this.payload = payload.clone();
            return this;
        }

        public Builder withSignature(Header protectedHeader, Header unprotected, Key key) {
            Objects.requireNonNull(key);
            if (protectedHeader == null && unprotected == null) {
                throw new NullPointerException("A header is required");
            }
            Header joseHeader = Header.merge(protectedHeader, unprotected);
            if (joseHeader.getCritical() != null && !joseHeader.getCritical().isEmpty()) {
                throw new IllegalArgumentException("This implementation does not support critical elements");
            }
            Algorithm alg = joseHeader.getAlgorithm();
            if (!alg.isSupported()) {
                throw new IllegalArgumentException(alg.getName() + " is not supported");
            }
            protectedHeaders.add(protectedHeader);
            unprotectedHeaders.add(unprotected);
            keys.add(key);
            return this;
        }

        public JWS build() {
            LinkedList<Signature> sigs = null;
            byte[] protectedHeader = null;
            Header unprotectedHeader = null;
            byte[] signature = null;
            int ct = keys.size();

            // Step 1 was done before we got here
            
            // Step 2
            String payloadStr = Base64.getUrlEncoder().withoutPadding().encodeToString(payload);

            for (int i = 0; i < ct; i++) {
                // step 3
                Header ph = protectedHeaders.get(i);
                Header uh = unprotectedHeaders.get(i);
                Header joseHeader = Header.merge(ph, uh);
                Algorithm alg = joseHeader.getAlgorithm();
                Key key = keys.get(i);

                // step 4
                byte[] phArray;
                String phBase64;
                if (ph != null) {
                    try {
                        ObjectMapper om = new ObjectMapper();
                        om.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
                        String hdrstr = om.writeValueAsString(ph);
                        phArray = hdrstr.getBytes(StandardCharsets.UTF_8);
                        phBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(phArray);
                    } catch (JsonProcessingException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    phArray = null;
                    phBase64 = "";
                }

                // step 5
                byte[] message = String.format("%s.%s",
                                phBase64,
                                Base64.getUrlEncoder().withoutPadding().encodeToString(payload))
                        .getBytes(StandardCharsets.US_ASCII);
                byte[] siggy;
                try {
                    if (Algorithm.ES256.equals(alg)) {
                        java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA", "BC");
                        sig.initSign((ECPrivateKey)key);
                        sig.update(message);
                        siggy = sig.sign();
                    } else if (Algorithm.ES384.equals(alg)) {
                        java.security.Signature sig = java.security.Signature.getInstance("SHA384withECDSA", "BC");
                        sig.initSign((ECPrivateKey)key);
                        sig.update(message);
                        siggy = sig.sign();
                    } else if (Algorithm.ES512.equals(alg)) {
                        java.security.Signature sig = java.security.Signature.getInstance("SHA512withECDSA", "BC");
                        sig.initSign((ECPrivateKey)key);
                        sig.update(message);
                        siggy = sig.sign();
                    } else if (Algorithm.HS256.equals(alg)) {
                        Mac mac = Mac.getInstance("HmacSHA256", "BC");
                        mac.init(key);
                        siggy = mac.doFinal(message);
                    } else if (Algorithm.HS384.equals(alg)) {
                        Mac mac = Mac.getInstance("HmacSHA384", "BC");
                        mac.init(key);
                        siggy = mac.doFinal(message);
                    } else if (Algorithm.HS512.equals(alg)) {
                        Mac mac = Mac.getInstance("HmacSHA512", "BC");
                        mac.init(key);
                        siggy = mac.doFinal(message);
                    } else if (Algorithm.RS256.equals(alg)) {
                        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA", "BC");
                        sig.initSign((RSAPrivateKey)key);
                        sig.update(message);
                        siggy = sig.sign();
                    } else if (Algorithm.RS384.equals(alg)) {
                        java.security.Signature sig = java.security.Signature.getInstance("SHA384withRSA", "BC");
                        sig.initSign((RSAPrivateKey)key);
                        sig.update(message);
                        siggy = sig.sign();
                    } else if (Algorithm.RS512.equals(alg)) {
                        java.security.Signature sig = java.security.Signature.getInstance("SHA512withRSA", "BC");
                        sig.initSign((RSAPrivateKey)key);
                        sig.update(message);
                        siggy = sig.sign();
                    } else {
                        throw new UnsupportedOperationException("Unsupported algorithm");
                    }
                } catch (NoSuchAlgorithmException
                        | NoSuchProviderException
                        | InvalidKeyException
                        | SignatureException e) {
                    throw new RuntimeException(e);
                }
                if (ct == 1) {
                    protectedHeader = phArray;
                    unprotectedHeader = uh;
                    signature = siggy;
                } else {
                    if (sigs == null) {
                        sigs = new LinkedList<>();
                    }
                    sigs.add(new Signature(phArray, uh, siggy));
                }
            }

            return new JWS(payload, sigs, protectedHeader, unprotectedHeader, signature);
        }
    }

    @JsonPOJOBuilder
    public static final class JsonBuilder {
        private byte[] payload;
        private List<Signature> signatures;
        private byte[] protectedHeader;
        private Header header;
        private byte[] signature;

        @JsonProperty
        public JsonBuilder withPayload(byte[] payload) {
            this.payload = payload.clone();
            return this;
        }
        @JsonProperty
        public JsonBuilder withSignatures(List<Signature> sig) {
            if (this.protectedHeader != null || this.header != null || this.signature != null) {
                throw new IllegalStateException("Cannot mix message types");
            }
            this.signatures = ImmutableList.copyOf(sig);
            return this;
        }
        @JsonProperty("protected")
        public JsonBuilder withProtectedHeader(byte[] payload) {
            if (this.signatures != null) {
                throw new IllegalStateException("Cannot mix message types");
            }
            this.protectedHeader = payload.clone();
            return this;
        }
        @JsonProperty
        public JsonBuilder withHeader(Header header) {
            if (this.signatures != null) {
                throw new IllegalStateException("Cannot mix message types");
            }
            this.header = header;
            return this;
        }
        @JsonProperty
        public JsonBuilder withSignature(byte[] sig) {
            if (this.signatures != null) {
                throw new IllegalStateException("Cannot mix message types");
            }
            this.signature = sig.clone();
            return this;
        }
        public JWS build() {
            return new JWS(payload, signatures, protectedHeader, header, signature);
        }
    }

    private JWS(byte[] payload, List<Signature> signatures, byte[] protectedHeader, Header header, byte[] signature) {
        this.payload = payload;
        this.signatures = signatures;
        this.protectedHeader = protectedHeader;
        this.header = header;
        this.signature = signature;
    }

    public JWS(JWS other) {
        this(other.payload, other.signatures, other.protectedHeader, other.header, other.signature);
    }

    public byte[] getPayload() {
        return JoseUtils.clone(payload);
    }

    public String getPayload(Charset charset) {
        return new String(payload, charset);
    }

    public <T> T getJsonPayload(Class<T> objType) {
        ObjectMapper om = new ObjectMapper();
        om.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
        try {
            return om.readValue(payload, objType);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public List<Signature> getSignatures() {
        return signatures;
    }

    public byte[] getProtectedHeader() {
        return JoseUtils.clone(protectedHeader);
    }

    public Header getProtectedHeaderAsObject() {
        byte[] raw = Base64.getUrlDecoder().decode(protectedHeader);
        String h= new String(raw, StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper();
        mapper.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
        try {
            return mapper.readValue(h, Header.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Header getHeader() {
        return header;
    }

    public byte[] getSignature() {
        return JoseUtils.clone(signature);
    }

    public boolean verify(Key key) {
        if (signatures != null && signatures.size() > 1) {
            throw new UnsupportedOperationException("Unspecified signature");
        }
        return verify(0, key);
    }

    public boolean verify(int sigidx, Key key) {
        boolean retval = false;

        // step 1 - 3
        byte[] phbytes;
        Header ph;
        Header uh;
        byte[] siggy;
        if (sigidx == 0 && signatures == null) {
            siggy = signature;
            phbytes = protectedHeader;
            ph = getProtectedHeaderAsObject();
            uh = header;
        } else {
            Signature sigobj = signatures.get(sigidx);
            siggy = sigobj.signature;
            phbytes = sigobj.protectedHeader;
            ph = sigobj.getProtectedHeaderAsObject();
            uh = sigobj.header;
        }

        // step 4
        Header joseHeader = Header.merge(ph,uh);

        // step 5
        if (joseHeader.getCritical() != null) {
            throw new UnsupportedOperationException("Critical parameters not supported");
        }

        // step 6 & 7 is done naturally

        // step 8
        Algorithm alg = joseHeader.getAlgorithm();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        byte[] message = String.format("%s.%s", encoder.encodeToString(phbytes), encoder.encodeToString(payload))
                .getBytes(StandardCharsets.US_ASCII);
        try {
            if (Algorithm.ES256.equals(alg)) {
                java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA", "BC");
                sig.initVerify((ECPublicKey)key);
                sig.update(message);
                retval = sig.verify(siggy);
            } else if (Algorithm.ES384.equals(alg)) {
                java.security.Signature sig = java.security.Signature.getInstance("SHA384withECDSA", "BC");
                sig.initVerify((ECPublicKey)key);
                sig.update(message);
                retval = sig.verify(siggy);
            } else if (Algorithm.ES512.equals(alg)) {
                java.security.Signature sig = java.security.Signature.getInstance("SHA512withECDSA", "BC");
                sig.initVerify((ECPublicKey)key);
                sig.update(message);
                retval = sig.verify(siggy);
            } else if (Algorithm.HS256.equals(alg)) {
                Mac mac = Mac.getInstance("HmacSHA256", "BC");
                mac.init(key);
                retval = verify(siggy, mac.doFinal(message));
            } else if (Algorithm.HS384.equals(alg)) {
                Mac mac = Mac.getInstance("HmacSHA384", "BC");
                mac.init(key);
                retval = verify(siggy, mac.doFinal(message));
            } else if (Algorithm.HS512.equals(alg)) {
                Mac mac = Mac.getInstance("HmacSHA512", "BC");
                mac.init(key);
                retval = verify(siggy, mac.doFinal(message));
            } else if (Algorithm.RS256.equals(alg)) {
                java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA", "BC");
                sig.initVerify((RSAPublicKey)key);
                sig.update(message);
                retval = sig.verify(siggy);
            } else if (Algorithm.RS384.equals(alg)) {
                java.security.Signature sig = java.security.Signature.getInstance("SHA384withRSA", "BC");
                sig.initVerify((RSAPublicKey)key);
                sig.update(message);
                retval = sig.verify(siggy);
            } else if (Algorithm.RS512.equals(alg)) {
                java.security.Signature sig = java.security.Signature.getInstance("SHA512withRSA", "BC");
                sig.initVerify((RSAPublicKey)key);
                sig.update(message);
                retval = sig.verify(siggy);
            } else {
                throw new UnsupportedOperationException("Unsupported algorithm");
            }
        } catch (NoSuchAlgorithmException
                | NoSuchProviderException
                | InvalidKeyException
                | SignatureException e) {
            throw new RuntimeException(e);
        }
        return retval;
    }

    private static boolean verify(byte[] a, byte[] b) {
        int ct = Math.min(a.length, b.length);
        boolean retval = a.length == b.length;
        for (int i = 0; i < ct; i++) {
            if (a[i] != b[i]) {
                retval = false;
            }
        }
        return retval;
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

    public String toCompact() {
        if (signatures != null) {
            throw new UnsupportedOperationException("Cannot support multiple recipients");
        }
        if (header != null) {
            throw new UnsupportedOperationException("Unprotected header not supported");
        }
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return String.format("%s.%s.%s",
                encoder.encodeToString(protectedHeader),
                encoder.encodeToString(payload),
                encoder.encodeToString(signature)
        );
    }

    private static final Pattern COMPACT = Pattern.compile("[a-zA-Z0-9\\-_=]*\\.[a-zA-Z0-9\\-_=]*\\.[a-zA-Z0-9\\-_=]*");
    public static JWS parse(String ser) {
        if (COMPACT.matcher(ser).matches()) {
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String[] parts = ser.split("\\.");
            return new JsonBuilder()
                    .withProtectedHeader(decoder.decode(parts[0]))
                    .withPayload(decoder.decode(parts[1]))
                    .withSignature(decoder.decode(parts[2]))
                    .build();
        } else {
            ObjectMapper om = new ObjectMapper();
            om.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
            try {
                return om.readValue(ser, JWS.class);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
    
    public static Builder builder() {
        return new Builder();
    }

    public static JsonBuilder jsonBuilder() {
        return new JsonBuilder();
    }
}
