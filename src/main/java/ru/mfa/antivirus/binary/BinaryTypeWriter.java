package ru.mfa.antivirus.binary;

import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Component
public class BinaryTypeWriter {

    // Записывает uint8 в BigEndian.
    public void writeUInt8(ByteArrayOutputStream out, int value) {
        ensureRange(value, 0, 0xFF, "uint8");
        out.write(value & 0xFF);
    }

    // Записывает uint16 в BigEndian.
    public void writeUInt16(ByteArrayOutputStream out, int value) {
        ensureRange(value, 0, 0xFFFF, "uint16");
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    // Записывает uint32 в BigEndian.
    public void writeUInt32(ByteArrayOutputStream out, long value) {
        ensureRange(value, 0L, 0xFFFF_FFFFL, "uint32");
        out.write((int) ((value >>> 24) & 0xFF));
        out.write((int) ((value >>> 16) & 0xFF));
        out.write((int) ((value >>> 8) & 0xFF));
        out.write((int) (value & 0xFF));
    }

    // Записывает int64 в BigEndian.
    public void writeInt64(ByteArrayOutputStream out, long value) {
        out.write((int) ((value >>> 56) & 0xFF));
        out.write((int) ((value >>> 48) & 0xFF));
        out.write((int) ((value >>> 40) & 0xFF));
        out.write((int) ((value >>> 32) & 0xFF));
        out.write((int) ((value >>> 24) & 0xFF));
        out.write((int) ((value >>> 16) & 0xFF));
        out.write((int) ((value >>> 8) & 0xFF));
        out.write((int) (value & 0xFF));
    }

    // Записывает UUID как 16 байт (MSB + LSB).
    public void writeUuid(ByteArrayOutputStream out, UUID value) {
        writeInt64(out, value.getMostSignificantBits());
        writeInt64(out, value.getLeastSignificantBits());
    }

    // Записывает UTF-8 строку как uint16 length + bytes.
    public void writeStringUtf8(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeUInt16(out, bytes.length);
        out.writeBytes(bytes);
    }

    // Записывает byte[] как uint32 length + bytes.
    public void writeByteArray(ByteArrayOutputStream out, byte[] value) {
        writeUInt32(out, value.length);
        out.writeBytes(value);
    }

    // Записывает ASCII magic без префикса длины.
    public void writeMagic(ByteArrayOutputStream out, String value) {
        out.writeBytes(value.getBytes(StandardCharsets.US_ASCII));
    }

    private void ensureRange(long value, long min, long max, String type) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(type + " out of range: " + value);
        }
    }
}
