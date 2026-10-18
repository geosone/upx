/* i286-win16.ne.c -- extraction stub for packed Windows 16-bit NE programs

   This file is part of the UPX executable compressor.

   Copyright (C) The UPX Team. All Rights Reserved.
   UPX and this stub are distributed under the terms of the GNU General
   Public License; see COPYING.
 */

#include <windows.h>

#define TRAILER_SIZE 32
#define INPUT_SIZE 1024
#define OUTPUT_SIZE 2048
#define WINDOW_SIZE 32768U

static unsigned char input_buffer[INPUT_SIZE];
static unsigned char output_buffer[OUTPUT_SIZE];
static unsigned char window_buffer[WINDOW_SIZE];

typedef struct {
    HFILE file;
    unsigned pos;
    unsigned end;
    unsigned long remaining;
} Input;

typedef struct {
    HFILE file;
    unsigned pos;
    unsigned window_pos;
    unsigned long produced;
    unsigned long adler_s1;
    unsigned long adler_s2;
} Output;

static unsigned get_u16(const unsigned char *p) { return p[0] | ((unsigned)p[1] << 8); }

static unsigned long get_u32(const unsigned char *p) {
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) |
           ((unsigned long)p[3] << 24);
}

static void delete_file(const char *name) {
    OFSTRUCT info;
    OpenFile(name, &info, OF_DELETE);
}

static int input_byte(Input *in, unsigned *value) {
    unsigned count;
    if (in->remaining == 0)
        return 0;
    if (in->pos == in->end) {
        count = in->remaining > INPUT_SIZE ? INPUT_SIZE : (unsigned)in->remaining;
        if (_lread(in->file, input_buffer, count) != count)
            return 0;
        in->pos = 0;
        in->end = count;
    }
    *value = input_buffer[in->pos++];
    --in->remaining;
    return 1;
}

static int input_bit(Input *in, unsigned long *bit_buffer, unsigned *value) {
    unsigned next;
    if ((*bit_buffer & 0x7fUL) != 0)
        *bit_buffer *= 2;
    else {
        if (!input_byte(in, &next))
            return 0;
        *bit_buffer = (unsigned long)next * 2 + 1;
    }
    *value = (unsigned)((*bit_buffer >> 8) & 1);
    return 1;
}

static int flush_output(Output *out) {
    if (out->pos != 0 && _lwrite(out->file, output_buffer, out->pos) != out->pos)
        return 0;
    out->pos = 0;
    return 1;
}

static int copy_dos_prefix(HFILE source, HFILE output, unsigned prefix_size) {
    unsigned copied = 0;
    unsigned count;
    unsigned i;
    if (_llseek(source, 0, 0) < 0)
        return 0;
    while (copied < prefix_size) {
        count = prefix_size - copied > OUTPUT_SIZE ? OUTPUT_SIZE : prefix_size - copied;
        if (_lread(source, output_buffer, count) != count)
            return 0;
        for (i = 0; i < 4; ++i)
            if (copied <= 0x3c + i && 0x3c + i < copied + count)
                output_buffer[0x3c + i - copied] =
                    (unsigned char)((unsigned long)prefix_size >> (8 * i));
        if (_lwrite(output, output_buffer, count) != count)
            return 0;
        copied += count;
    }
    return 1;
}

static int output_byte(Output *out, unsigned value) {
    window_buffer[out->window_pos] = (unsigned char)value;
    out->window_pos = (out->window_pos + 1) & (WINDOW_SIZE - 1);
    output_buffer[out->pos++] = (unsigned char)value;
    if (out->pos == OUTPUT_SIZE && !flush_output(out))
        return 0;
    out->adler_s1 += value;
    if (out->adler_s1 >= 65521UL)
        out->adler_s1 -= 65521UL;
    out->adler_s2 += out->adler_s1;
    if (out->adler_s2 >= 65521UL)
        out->adler_s2 -= 65521UL;
    ++out->produced;
    return 1;
}

static int decompress_nrv2b(Input *in, Output *out, unsigned long expected_size) {
    unsigned bit;
    unsigned value;
    unsigned long bit_buffer = 0;
    unsigned long last_offset = 1;
    unsigned long offset;
    unsigned long length;

    for (;;) {
        if (!input_bit(in, &bit_buffer, &bit))
            return 0;
        while (bit != 0) {
            if (!input_byte(in, &value) || out->produced >= expected_size ||
                !output_byte(out, value) || !input_bit(in, &bit_buffer, &bit))
                return 0;
        }

        offset = 1;
        do {
            if (!input_bit(in, &bit_buffer, &bit))
                return 0;
            offset = offset * 2 + bit;
            if (!input_bit(in, &bit_buffer, &bit))
                return 0;
        } while (bit == 0);

        if (offset == 2)
            offset = last_offset;
        else {
            if (!input_byte(in, &value))
                return 0;
            offset = (offset - 3) * 256UL + value;
            if (offset == 0xffffffffUL)
                break;
            last_offset = ++offset;
        }
        if (offset == 0 || offset > WINDOW_SIZE || offset > out->produced)
            return 0;

        if (!input_bit(in, &bit_buffer, &bit))
            return 0;
        length = bit;
        if (!input_bit(in, &bit_buffer, &bit))
            return 0;
        length = length * 2 + bit;
        if (length == 0) {
            ++length;
            do {
                if (!input_bit(in, &bit_buffer, &bit))
                    return 0;
                length = length * 2 + bit;
                if (length >= expected_size)
                    return 0;
                if (!input_bit(in, &bit_buffer, &bit))
                    return 0;
            } while (bit == 0);
            length += 2;
        }
        if (offset > 0xd00)
            ++length;
        ++length;

        while (length-- != 0) {
            value = window_buffer[(out->window_pos - (unsigned)offset) & (WINDOW_SIZE - 1)];
            if (out->produced >= expected_size || !output_byte(out, value))
                return 0;
        }
    }
    return in->remaining == 0 && out->produced == expected_size && flush_output(out);
}

static int unpack_self(HINSTANCE instance, char *target) {
    unsigned char trailer[TRAILER_SIZE];
    char self_name[260];
    HFILE source = HFILE_ERROR;
    HFILE output = HFILE_ERROR;
    long file_size;
    unsigned long compressed_size;
    unsigned long original_ne_size;
    unsigned long original_adler;
    unsigned long stub_size;
    unsigned prefix_size;
    unsigned target_length;
    Input in;
    Output out;
    int ok = 0;

    if (!GetModuleFileName(instance, self_name, sizeof(self_name)))
        goto done;
    source = _lopen(self_name, OF_READ | OF_SHARE_DENY_WRITE);
    if (source == HFILE_ERROR)
        goto done;
    file_size = _llseek(source, 0, 2);
    if (file_size < TRAILER_SIZE || _llseek(source, file_size - TRAILER_SIZE, 0) < 0 ||
        _lread(source, trailer, sizeof(trailer)) != sizeof(trailer))
        goto done;
    if (trailer[0] != 'U' || trailer[1] != 'P' || trailer[2] != 'X' || trailer[3] != '1' ||
        trailer[4] != '6' || trailer[5] != 'N' || trailer[6] != 'E' || trailer[7] != 0 ||
        trailer[8] != 1 || trailer[9] != 1)
        goto done;

    prefix_size = get_u16(trailer + 10);
    compressed_size = get_u32(trailer + 12);
    original_ne_size = get_u32(trailer + 16);
    original_adler = get_u32(trailer + 20);
    stub_size = get_u32(trailer + 28);
    if (prefix_size < 64 || prefix_size > stub_size ||
        stub_size + compressed_size + TRAILER_SIZE != (unsigned long)file_size)
        goto done;
    if (!GetTempFileName(0, "UPX", 0, target))
        goto done;
    for (target_length = 0; target[target_length] != 0; ++target_length)
        ;
    if (target_length < 3)
        goto done;
    delete_file(target);
    target[target_length - 3] = 'E';
    target[target_length - 2] = 'X';
    target[target_length - 1] = 'E';
    output = _lcreat(target, 0);
    if (output == HFILE_ERROR || !copy_dos_prefix(source, output, prefix_size) ||
        _llseek(source, stub_size, 0) < 0)
        goto done;

    in.file = source;
    in.pos = in.end = 0;
    in.remaining = compressed_size;
    out.file = output;
    out.pos = out.window_pos = 0;
    out.produced = 0;
    out.adler_s1 = 1;
    out.adler_s2 = 0;
    if (!decompress_nrv2b(&in, &out, original_ne_size))
        goto done;
    if (((out.adler_s2 << 16) | out.adler_s1) != original_adler)
        goto done;
    ok = 1;

done:
    if (output != HFILE_ERROR)
        _lclose(output);
    if (source != HFILE_ERROR)
        _lclose(source);
    if (!ok && target[0] != 0)
        delete_file(target);
    return ok;
}

static int write_source_path(HINSTANCE instance, const char *target, char *source_path) {
    char self_name[260];
    HFILE file;
    unsigned i;

    for (i = 0; target[i] != 0 && i + 1 < 260; ++i)
        source_path[i] = target[i];
    source_path[i] = 0;
    if (i < 3 || !GetModuleFileName(instance, self_name, sizeof(self_name)))
        return 0;
    source_path[i - 3] = 'S';
    source_path[i - 2] = 'R';
    source_path[i - 1] = 'C';
    file = _lcreat(source_path, 0);
    if (file == HFILE_ERROR)
        return 0;
    for (i = 0; self_name[i] != 0; ++i)
        ;
    if (_lwrite(file, self_name, i) != i) {
        _lclose(file);
        delete_file(source_path);
        source_path[0] = 0;
        return 0;
    }
    _lclose(file);
    return 1;
}

int PASCAL WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command_line, int show) {
    char target[260];
    char source_path[260];
    char launch[390];
    HINSTANCE child;
    UINT child_result;
    unsigned i;
    unsigned j;

    (void)previous;
    target[0] = 0;
    if (!unpack_self(instance, target)) {
        MessageBox(0, "The packed program is damaged or incomplete.", "UPX", MB_OK | MB_ICONSTOP);
        return 1;
    }

    source_path[0] = 0;
    write_source_path(instance, target, source_path);
    for (i = 0, j = 0; target[i] != 0 && j + 2 < sizeof(launch); ++i)
        launch[j++] = target[i];
    if (command_line[0] != 0) {
        launch[j++] = ' ';
        for (i = 0; command_line[i] != 0 && j + 1 < sizeof(launch); ++i)
            launch[j++] = command_line[i];
    }
    launch[j] = 0;

    child_result = WinExec(launch, show);
    if (child_result < 32) {
        delete_file(target);
        if (source_path[0] != 0)
            delete_file(source_path);
        MessageBox(0, "Cannot start the unpacked program.", "UPX", MB_OK | MB_ICONSTOP);
        return 1;
    }
    child = (HINSTANCE)child_result;
    while (GetModuleUsage(child) != 0)
        Yield();
    delete_file(target);
    if (source_path[0] != 0)
        delete_file(source_path);
    return 0;
}
