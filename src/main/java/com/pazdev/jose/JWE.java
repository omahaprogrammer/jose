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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.google.common.collect.ImmutableList;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.DeflaterInputStream;
import java.util.zip.InflaterInputStream;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

/**
 *
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
@JsonDeserialize(builder = JWE.JsonBuilder.class)
public final class JWE {
    @JsonProperty("protected")
    private final byte[] protectedHeader;
    @JsonProperty("unprotected")
    private final Header unprotectedHeader;
    @JsonProperty
    private final byte[] iv;
    @JsonProperty
    private final byte[] aad;
    @JsonProperty
    private final byte[] ciphertext;
    @JsonProperty
    private final byte[] tag;
    @JsonProperty
    private final List<RecipientHeader> recipients;
    @JsonProperty
    private final Header header;
    @JsonProperty("encrypted_key")
    private final byte[] encryptedKey;

    private JWE(byte[] protectedHeader, Header unprotectedHeader, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag, List<RecipientHeader> recipients, Header header, byte[] encryptedKey) {
        this.protectedHeader = protectedHeader;
        this.unprotectedHeader = unprotectedHeader;
        this.iv = iv;
        this.aad = aad;
        this.ciphertext = ciphertext;
        this.tag = tag;
        this.recipients = recipients;
        this.header = header;
        this.encryptedKey = encryptedKey;
    }

    public JWE(JWE other) {
        this(other.protectedHeader,
                other.unprotectedHeader,
                other.iv,
                other.aad,
                other.ciphertext,
                other.tag,
                other.recipients,
                other.header,
                other.encryptedKey);
    }
    public static final class RecipientHeader {
        @JsonProperty
        private final Header header;
        @JsonProperty("encrypted_key")
        private final byte[] encryptedKey;

        @JsonCreator
        public RecipientHeader(Header header, byte[] encryptedKey) {
            this.header = header;
            this.encryptedKey = encryptedKey;
        }

        public Header getHeader() {
            return header;
        }

        public byte[] getEncryptedKey() {
            return encryptedKey;
        }

    }

    public static final class Builder {
        private Header protectedHeader;
        private Header sharedHeader;
        private byte[] cleartext;
        private byte[] aad = null;
        private final ArrayList<Header> recipients = new ArrayList<>();
        private final ArrayList<char[]> passwords = new ArrayList<>();
        private final ArrayList<Key> keys = new ArrayList<>();

        public Builder withProtectedHeader(Header header) {
            this.protectedHeader = header;
            return this;
        }

        public Builder withSharedHeader(Header header) {
            this.sharedHeader = header;
            return this;
        }

        public Builder withAAD(byte[] aad) {
            this.aad = aad.clone();
            return this;
        }

        public Builder withPayload(Object payload) {
            ObjectMapper mapper = new ObjectMapper();
            mapper.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
            try {
                return withPayload(mapper.writeValueAsBytes(payload));
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }

        public Builder withPayload(String cleartext) {
            this.cleartext = cleartext.getBytes(StandardCharsets.UTF_8);
            return this;
        }

        public Builder withPayload(byte[] cleartext) {
            this.cleartext = cleartext.clone();
            return this;
        }

        public Builder withKey(Key key) {
            recipients.clear();
            keys.clear();
            passwords.clear();
            recipients.add(null);
            keys.add(key);
            passwords.add(null);
            return this;
        }

        public Builder withPassword(char[] password) {
            recipients.clear();
            keys.clear();
            passwords.clear();
            recipients.add(null);
            keys.add(null);
            passwords.add(password.clone());
            return this;
        }

        public Builder withRecipient(Header header, char[] password) {
            withRecipient(header);
            keys.add(null);
            passwords.add(password.clone());
            return this;
        }

        public Builder withRecipient(Header header, Key key) {
            withRecipient(header);
            keys.add(key);
            passwords.add(null);
            return this;
        }

        private Builder withRecipient(Header header) {
            Objects.requireNonNull(header);
            if (header.getCritical() != null && !header.getCritical().isEmpty()) {
                throw new IllegalArgumentException("This implementation does not support critical elements");
            }
            Algorithm alg = header.getAlgorithm();
            if (!alg.isSupported()) {
                throw new IllegalArgumentException(alg.getName() + " is not supported");
            }
            if (recipients.size() == 1 && recipients.get(0) == null) {
                keys.clear();
                passwords.clear();
                recipients.clear();
            }
            recipients.add(header);

            return this;
        }

        private static final EnumSet<Algorithm.Type> STEP_2 = EnumSet.of(Algorithm.Type.KW, Algorithm.Type.KE, Algorithm.Type.KA_KW);
        private static final EnumSet<Algorithm.Type> STEP_3A = EnumSet.of(Algorithm.Type.KA_DIRECT, Algorithm.Type.KA_KW);
        public JWE build() {
            SecureRandom rand = new SecureRandom();
            ArrayList<byte[]> encryptedCEKs = new ArrayList<>(recipients.size());
            Algorithm enc = null;
            Key cek = null;
            byte[] iv;
            
            Algorithm penc = protectedHeader != null ? protectedHeader.getEncryptionAlgorithm() : null;
            Algorithm senc = sharedHeader != null ? sharedHeader.getEncryptionAlgorithm() : null;

            Algorithm palg = null;
            Algorithm salg = null;

            for (int i = 0, ct = recipients.size(); i < ct; i++) {
                Key kek = null;
                Header recipient = recipients.get(i);
                Key key = keys.get(i);
                byte[] encryptedCEK;
                char[] password = passwords.get(i);
                Algorithm renc = recipient != null ? recipient.getEncryptionAlgorithm() : null;
                Algorithm ralg = recipient != null ? recipient.getAlgorithm() : null;
                Algorithm thisenc = determineAlgorithm(penc, senc, renc);
                if (thisenc != null) {
                    if (enc != null && !enc.equals(thisenc)) {
                        throw new IllegalStateException("Conflicting encryption algorithms");
                    } else {
                        enc = thisenc;
                    }
                }

                // step 1
                Algorithm alg = determineAlgorithm(palg, salg, ralg);

                // step 2
                if (STEP_2.contains(alg.getType())) {
                    if (cek == null) {
                        cek = generateKey(enc, rand);
                    }
                }
                
                // step 3
                try {
                    if (STEP_3A.contains(alg.getType())) {
                        String algorithmID;
                        int bits, bytes;
                        if (Algorithm.ECDH_ES.equals(alg)) {
                            if (enc == null) {
                                throw new IllegalStateException("Missing encryption");
                            }
                            algorithmID = enc.getName();
                            bits = enc.getBitSize();
                            bytes = enc.getByteSize();
                        } else {
                            algorithmID = alg.getName();
                            bits = alg.getBitSize();
                            bytes = alg.getByteSize();
                        }
                        if (key == null) {
                            throw new IllegalStateException("This recipient does not have a key");
                        }
                        ECPublicKey pub = (ECPublicKey) key;
                        EllipticCurve curve = pub.getParams().getCurve();
                        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
                        gen.initialize(pub.getParams(), rand);
                        KeyPair pair = gen.generateKeyPair();
                        ECPrivateKey priv = (ECPrivateKey) pair.getPrivate();
                        KeyAgreement agr = KeyAgreement.getInstance("ECDHwithSHA256CKDF", "BC");
                        byte[] apu;
                        byte[] apv;
                        if (recipient != null) {
                            apu = recipient.getAgreementPartyUInfo();
                            apv = recipient.getAgreementPartyVInfo();
                        } else {
                            byte[] papu = protectedHeader != null ? protectedHeader.getAgreementPartyUInfo() : null;
                            byte[] papv = protectedHeader != null ? protectedHeader.getAgreementPartyVInfo() : null;
                            byte[] sapu = sharedHeader != null ? sharedHeader.getAgreementPartyUInfo() : null;
                            byte[] sapv = sharedHeader != null ? sharedHeader.getAgreementPartyVInfo() : null;
                            if (papu != null || papv != null) {
                                apu = papu;
                                apv = papv;
                            } else {
                                apu = sapu;
                                apv = sapv;
                            }
                        }
                        if (apu == null) {
                            apu = new byte[0];
                        }
                        if (apv == null) {
                            apv = new byte[0];
                        }
                        int otherInfoSize = 0;
                        otherInfoSize += 4 + alg.getName().length();
                        otherInfoSize += 4 + apu.length;
                        otherInfoSize += 4 + apv.length;
                        otherInfoSize += 4; // SuppPubInfo
                        byte[] otherInfo = new byte[otherInfoSize];
                        ByteBuffer buf = ByteBuffer.wrap(otherInfo);
                        buf.putInt(alg.getName().length());
                        buf.put(alg.getName().getBytes(StandardCharsets.US_ASCII));
                        buf.putInt(apu.length);
                        buf.put(apu);
                        buf.putInt(apv.length);
                        buf.put(apv);
                        buf.putInt(alg.getByteSize());
                        UserKeyingMaterialSpec spec = new UserKeyingMaterialSpec(otherInfo);
                        agr.init(pair.getPrivate(), spec, rand);
                        agr.doPhase(pub, true);
                        SecretKey sharedKey = agr.generateSecret(String.format("AES[%d]", alg.getBitSize()));
                        if (Algorithm.ECDH_ES.equals(alg)) {
                            if (cek != null && !cek.equals(sharedKey)) {
                                throw new IllegalStateException("More than one recipient specifies direct encryption");
                            }
                            cek = sharedKey;
                        } else {
                            kek = sharedKey;
                        }
                        JWK epk = JWK.builder().withPublicKey((ECPublicKey)pair.getPublic()).build();
                        if (recipient != null) {
                            recipient = Header.builder()
                                    .withHeader(recipient)
                                    .withEphemeralPublicKey(epk)
                                    .build();
                            recipients.set(i, recipient);
                        } else {
                            Header.Builder builder = Header.builder();
                            if (protectedHeader != null) {
                                builder.withHeader(protectedHeader);
                            }
                            builder.withEphemeralPublicKey(epk);
                            protectedHeader = builder.build();
                        }
                    }
                } catch (NoSuchAlgorithmException
                        | NoSuchProviderException
                        | InvalidAlgorithmParameterException
                        | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }

                // step 4
                if (Algorithm.PBES2_HS256_A128KW.equals(alg)
                        || Algorithm.PBES2_HS384_A192KW.equals(alg)
                        || Algorithm.PBES2_HS512_A256KW.equals(alg)) {
                    byte[] algnamebytes = alg.getName().getBytes(StandardCharsets.UTF_8);
                    byte[] salt = new byte[alg.getByteSize()];
                    rand.nextBytes(salt);
                    ByteBuffer buf = ByteBuffer.wrap(salt);
                    buf.put(algnamebytes);
                    buf.put((byte) 0x00);
                    Integer pbesct;
                    Integer prnds = protectedHeader != null ? protectedHeader.getPbes2Count() : null;
                    Integer srnds = sharedHeader != null ? sharedHeader.getPbes2Count() : null;
                    Integer rrnds = recipient != null ? recipient.getPbes2Count() : null;
                    if (rrnds != null) {
                        pbesct = rrnds;
                    } else if (srnds != null) {
                        pbesct = srnds;
                    } else {
                        pbesct = prnds;
                    }
                    if (pbesct == null || pbesct < 1000) {
                        pbesct = 65536;
                    }
                    try {
                        SecretKeyFactory fac;
                        PBEKeySpec spec;
                        if (Algorithm.PBES2_HS256_A128KW.equals(alg)) {
                            fac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");
                            spec = new PBEKeySpec(password, salt, pbesct, 128);
                        } else if (Algorithm.PBES2_HS384_A192KW.equals(alg)) {
                            fac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA384", "BC");
                            spec = new PBEKeySpec(password, salt, pbesct, 192);
                        } else if (Algorithm.PBES2_HS512_A256KW.equals(alg)) {
                            fac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BC");
                            spec = new PBEKeySpec(password, salt, pbesct, 256);
                        } else {
                            throw new IllegalStateException("Unknown algorithm: " + alg.getName());
                        }
                        kek = fac.generateSecret(spec);
                        spec.clearPassword();
                    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
                        throw new RuntimeException(e);
                    }
                }
                try {
                    if (Algorithm.RSA1_5.equals(alg)) {
                        Cipher c = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");
                        c.init(Cipher.WRAP_MODE, kek, rand);
                        encryptedCEK = c.wrap(cek);
                    } else if (Algorithm.RSA_OAEP.equals(alg)) {
                        Cipher c = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
                        c.init(Cipher.WRAP_MODE, kek, rand);
                        encryptedCEK = c.wrap(cek);
                    } else if (Algorithm.RSA_OAEP_256.equals(alg)) {
                        Cipher c = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
                        c.init(Cipher.WRAP_MODE, kek, rand);
                        encryptedCEK = c.wrap(cek);
                    } else if (Algorithm.A128KW.equals(alg)
                            || Algorithm.A128KW.equals(alg)
                            || Algorithm.A256KW.equals(alg)
                            || Algorithm.ECDH_ES_A128KW.equals(alg)
                            || Algorithm.ECDH_ES_A192KW.equals(alg)
                            || Algorithm.ECDH_ES_A256KW.equals(alg)
                            || Algorithm.PBES2_HS256_A128KW.equals(alg)
                            || Algorithm.PBES2_HS384_A192KW.equals(alg)
                            || Algorithm.PBES2_HS512_A256KW.equals(alg)) {
                        Cipher c = Cipher.getInstance("AESWrap", "BC");
                        c.init(Cipher.WRAP_MODE, kek, rand);
                        encryptedCEK = c.wrap(cek);
                    } else if (Algorithm.A128GCMKW.equals(alg)
                            || Algorithm.A192GCMKW.equals(alg)
                            || Algorithm.A256GCMKW.equals(alg)) {
                        Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "BC");
                        byte[] keyIV = new byte[12];
                        c.init(Cipher.WRAP_MODE, kek, new GCMParameterSpec(128, keyIV), rand);
                        byte[] wrappedKey = c.wrap(cek);
                        encryptedCEK = Arrays.copyOf(wrappedKey, wrappedKey.length - 16);
                        if (recipient != null) {
                            recipient = Header.builder()
                                    .withHeader(recipient)
                                    .withInitializationVector(keyIV)
                                    .withAuthenticationTag(
                                            Arrays.copyOfRange(
                                                    wrappedKey,
                                                    wrappedKey.length - 16,
                                                    wrappedKey.length))
                                    .build();
                            recipients.set(i, recipient);
                        } else {
                            Header.Builder builder = Header.builder();
                            if (protectedHeader != null) {
                                builder.withHeader(protectedHeader);
                            }
                            builder.withInitializationVector(keyIV);
                            builder.withAuthenticationTag(Arrays.copyOfRange(wrappedKey, wrappedKey.length - 16, wrappedKey.length));
                            protectedHeader = builder.build();
                        }
                    // step 5
                    } else if (Algorithm.DIR.equals(alg)
                            || Algorithm.ECDH_ES.equals(alg)) {
                        encryptedCEK = new byte[0];
                    } else {
                        throw new IllegalStateException("Unknown algorithm");
                    }
                } catch (NoSuchAlgorithmException
                        | NoSuchPaddingException
                        | NoSuchProviderException
                        | InvalidKeyException 
                        | IllegalBlockSizeException
                        | InvalidAlgorithmParameterException e) {
                    throw new RuntimeException(e);
                }

                // step 6
                if (Algorithm.DIR.equals(alg)) {
                    if (cek != null) {
                        throw new IllegalStateException("Content encryption key already set");
                    }
                    cek = key;
                }

                // step 7 (encoding is done later, but here is where we collect them)
                encryptedCEKs.add(encryptedCEK);

                // step 8 end loop
            }

            if (cek == null) {
                throw new IllegalStateException("Missing content encryption key");
            }
            if (enc == null) {
                throw new IllegalStateException("Missing encryption algorithm");
            }

            passwords.forEach((e) -> {
                if (e != null) {
                    Arrays.fill(e, '\0');
                }
            });
            
            // step 9
            if (Algorithm.A128GCM.equals(enc)
                    || Algorithm.A192GCM.equals(enc)
                    || Algorithm.A256GCM.equals(enc)) {
                iv = new byte[12];
                rand.nextBytes(iv);
            } else {
                iv = new byte[16];
                rand.nextBytes(iv);
            }

            // step 10 is done naturally

            // step 11
            Algorithm zip = protectedHeader != null ? protectedHeader.getCompressionAlgorithm() : null;
            if (zip != null) {
                try {
                    if (Algorithm.DEFLATE.equals(zip)) {
                        DeflaterInputStream in = new DeflaterInputStream(new ByteArrayInputStream(cleartext));
                        ByteArrayOutputStream out = new ByteArrayOutputStream(cleartext.length);
                        int b;
                        while ((b = in.read()) != -1) {
                            out.write(b);
                        }
                        out.flush();
                        Arrays.fill(cleartext, (byte) 0);
                        cleartext = out.toByteArray();
                    } else {
                        throw new UnsupportedOperationException("Unsupported zip algorithm: " + zip.getName());
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            // step 12
            ArrayList<RecipientHeader> newRecipients = null;
            Header newHeader = null;
            byte[] newEncryptedKey = null;
            int ct = recipients.size();
            if (ct == 1) {
                newHeader = recipients.get(0);
                newEncryptedKey = encryptedCEKs.get(0);
                if (newEncryptedKey.length == 0) {
                    newEncryptedKey = null;
                }
            } else if (ct > 1) {
                newRecipients = new ArrayList<>(ct);
                for (int i = 0; i < ct; i++) {
                    Header h = recipients.get(i);
                    byte[] k = encryptedCEKs.get(i);
                    if (k.length == 0) {
                        k = null;
                    }
                    newRecipients.add(new RecipientHeader(h, k));
                }
            }
            
            // step 13
            byte[] protectedHeaderArray;
            String protectedHeaderBase64;
            if (protectedHeader != null) {
                protectedHeaderArray = protectedHeader.toJson().getBytes(StandardCharsets.UTF_8);
                protectedHeaderBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(protectedHeaderArray);
            } else {
                protectedHeaderArray = new byte[0];
                protectedHeaderBase64 = "";
            }

            // step 14
            byte[] jweAAD;
            if (aad != null || aad.length > 0) {
                jweAAD = String.format("%s.%s",
                            protectedHeaderBase64,
                            Base64.getUrlEncoder().withoutPadding().encodeToString(aad))
                        .getBytes(StandardCharsets.US_ASCII);
            } else {
                jweAAD = protectedHeaderBase64.getBytes(StandardCharsets.US_ASCII);
            }

            // step 15
            byte[] ciphertext;
            byte[] tag;
            try {
                if (Algorithm.A128CBC_HS256.equals(enc)
                        || Algorithm.A192CBC_HS384.equals(enc)
                        || Algorithm.A256CBC_HS512.equals(enc)) {
                    byte[] key = cek.getEncoded();
                    byte[] macKey = Arrays.copyOfRange(key, 0, enc.getByteSize());
                    byte[] encKey = Arrays.copyOfRange(key, enc.getByteSize(), key.length);
                    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
                    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv), rand);
                    ciphertext = c.doFinal(cleartext);
                    Arrays.fill(cleartext, (byte)0);

                    byte[] al = new byte[Long.BYTES];
                    ByteBuffer buf = ByteBuffer.wrap(al);
                    buf.putLong((long) jweAAD.length);
                    
                    Mac mac;
                    int tLen;
                    if (Algorithm.A128CBC_HS256.equals(enc)) {
                        mac = Mac.getInstance("HmacSHA256", "BC");
                        mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
                        tLen = 16;
                    } else if (Algorithm.A192CBC_HS384.equals(enc)) {
                        mac = Mac.getInstance("HmacSHA384", "BC");
                        mac.init(new SecretKeySpec(macKey, "HmacSHA384"));
                        tLen = 24;
                    } else if (Algorithm.A256CBC_HS512.equals(enc)) {
                        mac = Mac.getInstance("HmacSHA512", "BC");
                        mac.init(new SecretKeySpec(macKey, "HmacSHA512"));
                        tLen = 32;
                    } else {
                        throw new IllegalStateException("Unsupported HMAC");
                    }
                    mac.update(jweAAD);
                    mac.update(iv);
                    mac.update(ciphertext);
                    mac.update(al);
                    tag = Arrays.copyOf(mac.doFinal(), tLen);
                } else if (Algorithm.A128GCM.equals(enc)
                        || Algorithm.A192GCM.equals(enc)
                        || Algorithm.A256GCM.equals(enc)) {
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "BC");
                    c.init(Cipher.ENCRYPT_MODE, cek, new GCMParameterSpec(128, iv), rand);
                    c.updateAAD(jweAAD);
                    byte[] output = c.doFinal(cleartext);
                    Arrays.fill(cleartext, (byte)0);
                    ciphertext = Arrays.copyOf(output, output.length - 128);
                    tag = Arrays.copyOfRange(output, output.length - 128, output.length);
                } else {
                    throw new IllegalStateException("Unsupported encryption algorithm");
                }
            } catch (NoSuchAlgorithmException
                    | NoSuchPaddingException
                    | NoSuchProviderException
                    | InvalidAlgorithmParameterException
                    | InvalidKeyException
                    | BadPaddingException
                    | IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            }

            // steps 16-18 are performed naturally

            return new JWE(protectedHeaderArray, sharedHeader, iv, aad, ciphertext, tag, newRecipients, newHeader, newEncryptedKey);
        }

        private static Algorithm determineAlgorithm(Algorithm palg, Algorithm salg, Algorithm ralg) throws UnsupportedOperationException {
            Algorithm alg;
            if (palg == null) {
                if (salg == null) {
                    if (ralg == null) {
                        throw new UnsupportedOperationException("Unspecified key management algorithm");
                    } else {
                        alg = ralg;
                    }
                } else {
                    if (ralg == null || salg.equals(ralg)) {
                        alg = salg;
                    } else {
                        throw new UnsupportedOperationException("Conflicting key management algorithms");
                    }
                }
            } else {
                if (salg == null || palg.equals(salg)) {
                    if (ralg == null || palg.equals(salg)) {
                        alg = palg;
                    } else {
                        throw new UnsupportedOperationException("Conflicting key management algorithms");
                    }
                } else {
                    throw new UnsupportedOperationException("Conflicting key management algorithms");
                }
            }
            return alg;
        }

        private SecretKey generateKey(Algorithm enc, SecureRandom rand) {
            if (enc == null) {
                throw new UnsupportedOperationException("Unknown encryption");
            }
            SecretKey key;
            try {
                switch (enc.getName()) {
                    case "A128CBC-HS256": {
                        KeyGenerator gen1 = KeyGenerator.getInstance("HmacSHA256");
                        gen1.init(128, rand);
                        KeyGenerator gen2 = KeyGenerator.getInstance("AES");
                        gen2.init(128, rand);
                        SecretKey hmac = gen1.generateKey();
                        SecretKey secret = gen2.generateKey();
                        byte[] combined = new byte[256];
                        ByteBuffer buf = ByteBuffer.wrap(combined);
                        buf.put(hmac.getEncoded());
                        buf.put(secret.getEncoded());
                        key = new SecretKeySpec(combined, "HMAC-AES");
                        break;
                    }
                    case "A192CBC-HS384": {
                        KeyGenerator gen1 = KeyGenerator.getInstance("HmacSHA384");
                        gen1.init(192, rand);
                        KeyGenerator gen2 = KeyGenerator.getInstance("AES");
                        gen2.init(192, rand);
                        SecretKey hmac = gen1.generateKey();
                        SecretKey secret = gen2.generateKey();
                        byte[] combined = new byte[384];
                        ByteBuffer buf = ByteBuffer.wrap(combined);
                        buf.put(hmac.getEncoded());
                        buf.put(secret.getEncoded());
                        key = new SecretKeySpec(combined, "HMAC-AES");
                        break;
                    }
                    case "A256CBC-HS512": {
                        KeyGenerator gen1 = KeyGenerator.getInstance("HmacSHA512");
                        gen1.init(256, rand);
                        KeyGenerator gen2 = KeyGenerator.getInstance("AES");
                        gen2.init(256, rand);
                        SecretKey hmac = gen1.generateKey();
                        SecretKey secret = gen2.generateKey();
                        byte[] combined = new byte[512];
                        ByteBuffer buf = ByteBuffer.wrap(combined);
                        buf.put(hmac.getEncoded());
                        buf.put(secret.getEncoded());
                        key = new SecretKeySpec(combined, "HMAC-AES");
                        break;
                    }
                    case "A128GCM":
                    case "A192GCM":
                    case "A256GCM": {
                        KeyGenerator gen = KeyGenerator.getInstance("AES");
                        gen.init(enc.getBitSize(), rand);
                        key = gen.generateKey();
                        break;
                    }
                    default:
                        throw new IllegalArgumentException("Unsupported encryption algorithm");
                }
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            return key;
        }
    }

    @JsonPOJOBuilder
    public static final class JsonBuilder {
        private byte[] protectedHeader;
        private Header unprotectedHeader;
        private byte[] iv;
        private byte[] aad;
        private byte[] ciphertext;
        private byte[] tag;
        private List<RecipientHeader> recipients;
        private Header header;
        private byte[] encryptedKey;

        @JsonProperty("protected")
        public JsonBuilder withProtectedHeader(byte[] protectedHeader) {
            if (protectedHeader == null || protectedHeader.length == 0) {
                protectedHeader = null;
            } else {
                protectedHeader = protectedHeader.clone();
            }
            this.protectedHeader = protectedHeader;
            return this;
        }
        @JsonProperty("unprotected")
        public JsonBuilder withUnprotectedHeader(Header unprotectedHeader) {
            this.unprotectedHeader = unprotectedHeader;
            return this;
        }
        @JsonProperty("iv")
        public JsonBuilder withIv(byte[] iv) {
            if (iv == null || iv.length == 0) {
                iv = null;
            } else {
                iv = iv.clone();
            }
            this.iv = iv;
            return this;
        }
        @JsonProperty
        public JsonBuilder withAad(byte[] aad) {
            if (aad == null || aad.length == 0) {
                aad = null;
            } else {
                aad = aad.clone();
            }
            this.aad = aad;
            return this;
        }
        @JsonProperty
        public JsonBuilder withCiphertext(byte[] ciphertext) {
            if (ciphertext == null || ciphertext.length == 0) {
                ciphertext = null;
            } else {
                ciphertext = ciphertext.clone();
            }
            this.ciphertext = ciphertext;
            return this;
        }
        @JsonProperty
        public JsonBuilder withTag(byte[] tag) {
            if (tag == null || tag.length == 0) {
                tag = null;
            } else {
                tag = tag.clone();
            }
            this.tag = tag;
            return this;
        }
        @JsonProperty
        public JsonBuilder withRecipients(List<RecipientHeader> recipients) {
            this.recipients = ImmutableList.copyOf(recipients.stream().filter(e -> e != null).collect(Collectors.toList()));
            return this;
        }
        @JsonProperty
        public JsonBuilder withHeader(Header header) {
            this.header = header;
            return this;
        }
        @JsonProperty("encrypted_key")
        public JsonBuilder withEncryptedKey(byte[] encryptedKey) {
            if (encryptedKey == null || encryptedKey.length == 0) {
                encryptedKey = null;
            } else {
                encryptedKey = encryptedKey.clone();
            }
            this.encryptedKey = encryptedKey;
            return this;
        }

        public JWE build() {
            return new JWE(protectedHeader,
                    unprotectedHeader,
                    iv,
                    aad,
                    ciphertext,
                    tag,
                    recipients,
                    header,
                    encryptedKey);
        }
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

    public Header getUnprotectedHeader() {
        return unprotectedHeader;
    }

    public byte[] getIv() {
        return JoseUtils.clone(iv);
    }

    public byte[] getAad() {
        return JoseUtils.clone(aad);
    }

    public byte[] getCiphertext() {
        return JoseUtils.clone(ciphertext);
    }

    public byte[] getTag() {
        return JoseUtils.clone(tag);
    }

    public List<RecipientHeader> getRecipients() {
        return recipients;
    }

    public Header getHeader() {
        return header;
    }

    public byte[] getEncryptedKey() {
        return JoseUtils.clone(encryptedKey);
    }

    public String getCompactSerialization() {
        if (recipients.size() > 1) {
            throw new IllegalStateException("This object has multiple recipients");
        } else if (aad != null) {
            throw new IllegalStateException("AAD is not supported for compact serialization");
        }
        return String.format("%s.%s.%s.%s.%s",
                Base64.getUrlEncoder().withoutPadding().encodeToString(protectedHeader),
                (encryptedKey != null) ? Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedKey) : "",
                Base64.getUrlEncoder().withoutPadding().encodeToString(iv),
                Base64.getUrlEncoder().withoutPadding().encodeToString(ciphertext),
                Base64.getUrlEncoder().withoutPadding().encodeToString(tag));
    }

    public <T> T decryptJson(Key decryptKey, Class<T> objType) {
        byte[] clear = decrypt(decryptKey);
        ObjectMapper om = new ObjectMapper();
        om.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
        try {
            return om.readValue(clear, objType);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public <T> T decryptJson(int recipient, Key decryptKey, Class<T> objType) {
        byte[] clear = decrypt(recipient, decryptKey);
        ObjectMapper om = new ObjectMapper();
        om.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
        try {
            return om.readValue(clear, objType);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String decrypt(Key decryptKey, Charset charset) {
        return new String(decrypt(decryptKey), charset);
    }

    public String decrypt(int recipient, Key decryptKey, Charset charset) {
        return new String(decrypt(recipient, decryptKey), charset);
    }

    public byte[] decrypt(Key decryptKey) {
        if (recipients != null && recipients.size() > 1) {
            throw new UnsupportedOperationException("Unspecified recipient");
        }
        return decrypt(0, decryptKey);
    }

    public byte[] decrypt(int recipientIndex, Key decryptKey) {
        // steps 1 - 3 occur naturally

        // step 4
        Header ph, sh, rh;
        if (recipients != null && !recipients.isEmpty()) {
            rh = recipients.get(recipientIndex).header;
        } else {
            rh = header;
        }
        ph = getProtectedHeaderAsObject();
        sh = getUnprotectedHeader();
        Header joseHeader = Header.merge(ph, sh, rh);
        if (joseHeader.getCritical() != null && !joseHeader.getCritical().isEmpty()) {
            throw new UnsupportedOperationException("Cannot process critical elements");
        }

        // step 6
        Algorithm alg = joseHeader.getAlgorithm();
        Algorithm enc = joseHeader.getEncryptionAlgorithm();
        Algorithm zip = joseHeader.getCompressionAlgorithm();

        Key kek, cek;

        // step 7... how did we get this far without a key?

        if (Algorithm.ECDH_ES.equals(alg)
                || Algorithm.ECDH_ES_A128KW.equals(alg)
                || Algorithm.ECDH_ES_A192KW.equals(alg)
                || Algorithm.ECDH_ES_A256KW.equals(alg)) {
        // step 8
            JWK eph = joseHeader.getEphemeralPublicKey();
            Key publicKey = eph.getKeys().get("public");
            try {
                KeyAgreement ka = KeyAgreement.getInstance("ECDHwithSHA256CKDF", "BC");
                byte[] apu = joseHeader.getAgreementPartyUInfo();
                byte[] apv = joseHeader.getAgreementPartyVInfo();
                if (apu == null) {
                    apu = new byte[0];
                }
                if (apv == null) {
                    apv = new byte[0];
                }
                Algorithm keyalg = alg;
                if (alg == Algorithm.ECDH_ES) {
                    keyalg = enc;
                }
                int otherInfoSize = 0;
                otherInfoSize += 4 + keyalg.getName().length();
                otherInfoSize += 4 + apu.length;
                otherInfoSize += 4 + apv.length;
                otherInfoSize += 4; // SuppPubInfo
                byte[] otherInfo = new byte[otherInfoSize];
                ByteBuffer buf = ByteBuffer.wrap(otherInfo);
                buf.putInt(keyalg.getName().length());
                buf.put(keyalg.getName().getBytes(StandardCharsets.US_ASCII));
                buf.putInt(apu.length);
                buf.put(apu);
                buf.putInt(apv.length);
                buf.put(apv);
                buf.putInt(keyalg.getByteSize());
                UserKeyingMaterialSpec spec = new UserKeyingMaterialSpec(otherInfo);
                ka.init(decryptKey, spec);
                ka.doPhase(publicKey, true);
                SecretKey sharedKey = ka.generateSecret(String.format("AES[%d]", keyalg.getBitSize()));
                if (Algorithm.ECDH_ES.equals(alg)) {
                    kek = null;
                    cek = sharedKey;
                } else {
                    kek = sharedKey;
                    cek = null;
                }
            } catch (InvalidAlgorithmParameterException
                    | NoSuchAlgorithmException
                    | NoSuchProviderException
                    | InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        } else if (Algorithm.RSA1_5.equals(alg)
                || Algorithm.RSA_OAEP.equals(alg)
                || Algorithm.RSA_OAEP_256.equals(alg)
                || Algorithm.A128KW.equals(alg)
                || Algorithm.A192KW.equals(alg)
                || Algorithm.A256KW.equals(alg)
                || Algorithm.A128GCMKW.equals(alg)
                || Algorithm.A192GCMKW.equals(alg)
                || Algorithm.A256GCMKW.equals(alg)
                || Algorithm.PBES2_HS256_A128KW.equals(alg)
                || Algorithm.PBES2_HS384_A192KW.equals(alg)
                || Algorithm.PBES2_HS512_A256KW.equals(alg)) {
            kek = decryptKey;
            cek = null;
        } else if (Algorithm.DIR.equals(alg)) {
            // step 11
            kek = null;
            cek = decryptKey;
        } else {
            throw new UnsupportedOperationException();
        }

        // step 9
        try {
            if (Algorithm.RSA1_5.equals(alg)) {
                Cipher c = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");
                c.init(Cipher.UNWRAP_MODE, kek);
                cek = c.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);
            } else if (Algorithm.RSA_OAEP.equals(alg)) {
                Cipher c = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
                c.init(Cipher.UNWRAP_MODE, kek);
                cek = c.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);
            } else if (Algorithm.RSA_OAEP_256.equals(alg)) {
                Cipher c = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
                c.init(Cipher.UNWRAP_MODE, kek);
                cek = c.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);
            } else if (Algorithm.A128KW.equals(alg)
                    || Algorithm.A128KW.equals(alg)
                    || Algorithm.A256KW.equals(alg)
                    || Algorithm.ECDH_ES_A128KW.equals(alg)
                    || Algorithm.ECDH_ES_A192KW.equals(alg)
                    || Algorithm.ECDH_ES_A256KW.equals(alg)
                    || Algorithm.PBES2_HS256_A128KW.equals(alg)
                    || Algorithm.PBES2_HS384_A192KW.equals(alg)
                    || Algorithm.PBES2_HS512_A256KW.equals(alg)) {
                Cipher c = Cipher.getInstance("AESWrap", "BC");
                c.init(Cipher.UNWRAP_MODE, kek);
                cek = c.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);
            } else if (Algorithm.A128GCMKW.equals(alg)
                    || Algorithm.A192GCMKW.equals(alg)
                    || Algorithm.A256GCMKW.equals(alg)) {
                byte[] cipheredKey = new byte[encryptedKey.length + 16];
                ByteBuffer buf = ByteBuffer.wrap(cipheredKey);
                buf.put(encryptedKey);
                buf.put(joseHeader.getAuthenticationTag());
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "BC");
                byte[] keyIV = joseHeader.getInitializationVector();
                c.init(Cipher.UNWRAP_MODE, kek, new GCMParameterSpec(128, keyIV));
                cek = c.unwrap(cipheredKey, "AES", Cipher.SECRET_KEY);
            }
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | NoSuchProviderException
                | InvalidKeyException 
                | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        
        // step 10
        if (Algorithm.DIR.equals(alg) || Algorithm.ECDH_ES.equals(alg)
                && encryptedKey != null && encryptedKey.length > 0) {
            throw new IllegalArgumentException("An encrypted key exists when direct algorithms are used");
        }

        // step 12
        if (cek == null) {
            throw new IllegalArgumentException("The content key cannot be found");
        }
        
        // step 13 is implemented by this method being called per recipient

        // step 14
        String protectedString = Base64.getUrlEncoder().withoutPadding().encodeToString(protectedHeader);

        // step 15
        byte[] jweAAD;
        if (aad != null && aad.length > 0) {
            String aadString = Base64.getUrlEncoder().withoutPadding().encodeToString(aad);
            jweAAD = String.format("%s.%s", protectedString, aadString).getBytes(StandardCharsets.US_ASCII);
        } else {
            jweAAD = protectedString.getBytes(StandardCharsets.US_ASCII);
        }

        byte[] output;
        // step 16
        try {
            if (Algorithm.A128CBC_HS256.equals(alg)
                    || Algorithm.A192CBC_HS384.equals(alg)
                    || Algorithm.A256CBC_HS512.equals(alg)) {
                byte[] k = cek.getEncoded();
                byte[] macKey = Arrays.copyOf(k, alg.getByteSize());
                byte[] encKey = Arrays.copyOfRange(k, alg.getByteSize(), k.length);

                byte[] al = new byte[Long.BYTES];
                ByteBuffer buf = ByteBuffer.wrap(al);
                buf.putLong((long) aad.length);
                
                Mac mac;
                int tLen;
                if (Algorithm.A128CBC_HS256.equals(enc)) {
                    mac = Mac.getInstance("HmacSHA256", "BC");
                    mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
                    tLen = 16;
                } else if (Algorithm.A192CBC_HS384.equals(enc)) {
                    mac = Mac.getInstance("HmacSHA384", "BC");
                    mac.init(new SecretKeySpec(macKey, "HmacSHA384"));
                    tLen = 24;
                } else if (Algorithm.A256CBC_HS512.equals(enc)) {
                    mac = Mac.getInstance("HmacSHA512", "BC");
                    mac.init(new SecretKeySpec(macKey, "HmacSHA512"));
                    tLen = 32;
                } else {
                    throw new IllegalStateException("Unsupported HMAC");
                }
                mac.update(aad);
                mac.update(iv);
                mac.update(ciphertext);
                mac.update(al);
                byte[] thistag = mac.doFinal();
                boolean match = true;
                for (int i = tLen - 1; i >= 0; --i) {
                    if (tag[i] != thistag[i]) {
                        match = false;
                    }
                }
                if (!match) {
                    throw new IllegalArgumentException("The message is invalid");
                }
                Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
                c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv));
                output = c.doFinal(ciphertext);
            } else if (Algorithm.A128GCM.equals(enc)
                    || Algorithm.A192GCM.equals(enc)
                    || Algorithm.A256GCM.equals(enc)) {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "BC");
                c.init(Cipher.DECRYPT_MODE, cek, new GCMParameterSpec(128, iv));
                c.updateAAD(jweAAD);
                byte[] block = new byte[ciphertext.length + 128];
                ByteBuffer buf = ByteBuffer.wrap(block);
                buf.put(ciphertext);
                buf.put(aad);
                try {
                    output = c.doFinal(block);
                } catch (AEADBadTagException e) {
                    throw new IllegalArgumentException("The message is invalid", e);
                }
            } else {
                throw new IllegalArgumentException("Unknown algorithm");
            }
        } catch (InvalidKeyException
                | NoSuchAlgorithmException
                | NoSuchProviderException
                | BadPaddingException
                | IllegalBlockSizeException
                | InvalidAlgorithmParameterException
                | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }

        // step 17
        if (zip != null) {
            if (Algorithm.DEFLATE.equals(zip)) {
                try {
                    InflaterInputStream in = new InflaterInputStream(new ByteArrayInputStream(output));
                    ByteArrayOutputStream out = new ByteArrayOutputStream(output.length * 2);
                    int b;
                    while ((b = in.read()) != -1) {
                        out.write(b);
                    }
                    out.flush();
                    output = out.toByteArray();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            } else {
                throw new IllegalArgumentException("Unknown compression");
            }
        }
        return output;
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
        if (recipients != null) {
            throw new UnsupportedOperationException("Cannot support multiple recipients");
        }
        if (unprotectedHeader != null) {
            throw new UnsupportedOperationException("Shared header not supported");
        }
        if (aad != null) {
            throw new UnsupportedOperationException("Additional authentication data not supported");
        }
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return String.format("%s.%s.%s.%s.%s",
                encoder.encodeToString(protectedHeader),
                encryptedKey != null ? encoder.encodeToString(encryptedKey) : "",
                encoder.encodeToString(iv),
                encoder.encodeToString(ciphertext),
                encoder.encodeToString(tag)
        );
    }

    private static final Pattern COMPACT = Pattern.compile("[a-zA-Z0-9\\-_=]*\\.[a-zA-Z0-9\\-_=]*\\.[a-zA-Z0-9\\-_=]*\\.[a-zA-Z0-9\\-_=]*\\.[a-zA-Z0-9\\-_=]*");
    public static JWE parse(String ser) {
        if (COMPACT.matcher(ser).matches()) {
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String[] parts = ser.split("\\.");
            return new JsonBuilder()
                    .withProtectedHeader(decoder.decode(parts[0]))
                    .withEncryptedKey(decoder.decode(parts[1]))
                    .withIv(decoder.decode(parts[2]))
                    .withCiphertext(decoder.decode(parts[3]))
                    .withTag(decoder.decode(parts[4]))
                    .build();
        } else {
            ObjectMapper om = new ObjectMapper();
            om.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
            try {
                return om.readValue(ser, JWE.class);
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
