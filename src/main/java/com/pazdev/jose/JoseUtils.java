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

/**
 *
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
final class JoseUtils {
    static boolean[] clone(boolean[] target) {
        if (target == null) {
            return null;
        }
        return target.clone();
    }
    static byte[] clone(byte[] target) {
        if (target == null) {
            return null;
        }
        return target.clone();
    }
    static short[] clone(short[] target) {
        if (target == null) {
            return null;
        }
        return target.clone();
    }
    static int[] clone(int[] target) {
        if (target == null) {
            return null;
        }
        return target.clone();
    }
    static long[] clone(long[] target) {
        if (target == null) {
            return null;
        }
        return target.clone();
    }
    static float[] clone(float[] target) {
        if (target == null) {
            return null;
        }
        return target.clone();
    }
    static double[] clone(double[] target) {
        if (target == null) {
            return null;
        }
        return target.clone();
    }
    static <T> T[] clone(T[] target) {
        if (target == null) {
            return null;
        }
        return target.clone();
    }
    private JoseUtils(){};
}
