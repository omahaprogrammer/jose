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
package com.pazdev.jose.json;

import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.deser.std.PrimitiveArrayDeserializers;
import com.fasterxml.jackson.databind.util.ArrayBuilders;
import java.io.IOException;

/**
 *
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
public class CertDeserializer extends PrimitiveArrayDeserializers<byte[]>{

    public CertDeserializer() {
        super(byte[].class);
    }

    public CertDeserializer(PrimitiveArrayDeserializers<?> base, Boolean unwrapSingle) {
        super(base, unwrapSingle);
    }
    
    @Override
    protected PrimitiveArrayDeserializers<?> withResolved(Boolean unwrapSingle) {
        return new CertDeserializer(this, unwrapSingle);
    }

    @Override
    protected byte[] handleSingleElementUnwrapped(JsonParser p, DeserializationContext ctxt) throws IOException {
            byte value;
            JsonToken t = p.getCurrentToken();
            if (t == JsonToken.VALUE_NUMBER_INT || t == JsonToken.VALUE_NUMBER_FLOAT) {
                value = p.getByteValue();
            } else {
                if (t == JsonToken.VALUE_NULL) {
                    return null;
                }
                Number n = (Number) ctxt.handleUnexpectedToken(_valueClass.getComponentType(), p);
                value = n.byteValue();
            }
            return new byte[] { value };
    }

    @Override
    public byte[] deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
            JsonToken t = p.getCurrentToken();
            
            if (t == JsonToken.VALUE_STRING) {
                return p.getBinaryValue(Base64Variants.MIME_NO_LINEFEEDS);
            }

            if (t == JsonToken.VALUE_EMBEDDED_OBJECT) {
                Object ob = p.getEmbeddedObject();
                if (ob == null) return null;
                if (ob instanceof byte[]) {
                    return (byte[]) ob;
                }
            }
            if (!p.isExpectedStartArrayToken()) {
                return handleNonArray(p, ctxt);
            }
            ArrayBuilders.ByteBuilder builder = ctxt.getArrayBuilders().getByteBuilder();
            byte[] chunk = builder.resetAndStart();
            int ix = 0;

            try {
                while ((t = p.nextToken()) != JsonToken.END_ARRAY) {
                    byte value;
                    if (t == JsonToken.VALUE_NUMBER_INT || t == JsonToken.VALUE_NUMBER_FLOAT) {
                        value = p.getByteValue();
                    } else {
                        if (t == JsonToken.VALUE_NULL) {
                            value = (byte) 0;
                        } else {
                            Number n = (Number) ctxt.handleUnexpectedToken(_valueClass.getComponentType(), p);
                            value = n.byteValue();
                        }
                    }
                    if (ix >= chunk.length) {
                        chunk = builder.appendCompletedChunk(chunk, ix);
                        ix = 0;
                    }
                    chunk[ix++] = value;
                }
            } catch (IOException | RuntimeException e) {
                throw JsonMappingException.wrapWithPath(e, chunk, builder.bufferedSize() + ix);
            }
            return builder.completeAndClearBuffer(chunk, ix);
    }
    
}
