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
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.fasterxml.jackson.databind.ser.std.ByteArraySerializer;
import java.io.IOException;

/**
 *
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
public class CertSerializer extends ByteArraySerializer {

    @Override
    public void serialize(byte[] value, JsonGenerator g, SerializerProvider provider) throws IOException {
        g.writeBinary(Base64Variants.MIME_NO_LINEFEEDS, value, 0, value.length);
    }

    @Override
    public void serializeWithType(byte[] value, JsonGenerator g, SerializerProvider provider, TypeSerializer typeSer) throws IOException
    {
        typeSer.writeTypePrefixForScalar(value, g);
        g.writeBinary(Base64Variants.MIME_NO_LINEFEEDS, value, 0, value.length);
        typeSer.writeTypeSuffixForScalar(value, g);
    }
    
}
