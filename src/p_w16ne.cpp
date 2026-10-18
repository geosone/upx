/* p_w16ne.cpp -- Windows 16-bit NE executable format

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   Copyright (C) Laszlo Molnar
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 */

#include "conf.h"
#include "file.h"
#include "filter.h"
#include "packer.h"
#include "p_w16ne.h"
#define WANT_EHDR_ENUM 1
#include "p_elf_enum.h"
#include "linker.h"

static const CLANG_FORMAT_DUMMY_STATEMENT
#include "stub/i286-win16.ne.h"

namespace {

enum {
    NE_HEADER_BYTES = 64,
    NE_ENTRY_TABLE_OFFSET = 0x04,
    NE_ENTRY_TABLE_LENGTH = 0x06,
    NE_SEGMENT_COUNT = 0x1c,
    NE_MODULE_COUNT = 0x1e,
    NE_NONRESIDENT_SIZE = 0x20,
    NE_SEGMENT_TABLE_OFFSET = 0x22,
    NE_RESOURCE_TABLE_OFFSET = 0x24,
    NE_RESIDENT_TABLE_OFFSET = 0x26,
    NE_MODULE_TABLE_OFFSET = 0x28,
    NE_IMPORT_TABLE_OFFSET = 0x2a,
    NE_NONRESIDENT_OFFSET = 0x2c,
    NE_ALIGNMENT_SHIFT = 0x32,
    NE_TARGET_OS = 0x36,
    NE_FLAGS = 0x0c,
    NE_FLAG_LIBRARY = 0x8000,
    PACK_TRAILER_SIZE = 32,
    PACK_TRAILER_VERSION = 1,
    PACK_METHOD_NRV2B8 = 1,
    PACK_WINDOW_SIZE = 32768,
};

static const byte pack_magic[8] = {'U', 'P', 'X', '1', '6', 'N', 'E', 0};

static bool rangeFits(upx_uint64_t offset, upx_uint64_t length, upx_uint64_t size) noexcept {
    return offset <= size && length <= size - offset;
}

static bool relativeRangeFits(const byte *header, unsigned field, unsigned length,
                              unsigned ne_offset, upx_uint64_t file_size) noexcept {
    const unsigned offset = get_le16(header + field);
    return offset >= NE_HEADER_BYTES &&
           rangeFits((upx_uint64_t) ne_offset + offset, length, file_size);
}

static bool validWindowsNeHeader(const byte *header, unsigned ne_offset,
                                 upx_uint64_t file_size) noexcept {
    if (get_le16(header) != ('N' + 'E' * 256) || header[NE_TARGET_OS] != 2)
        return false;

    const unsigned segment_count = get_le16(header + NE_SEGMENT_COUNT);
    const unsigned module_count = get_le16(header + NE_MODULE_COUNT);
    const unsigned entry_length = get_le16(header + NE_ENTRY_TABLE_LENGTH);
    const unsigned nonresident_size = get_le16(header + NE_NONRESIDENT_SIZE);
    const unsigned alignment_shift = get_le16(header + NE_ALIGNMENT_SHIFT);
    if (segment_count == 0 || alignment_shift > 15)
        return false;

    if (!relativeRangeFits(header, NE_ENTRY_TABLE_OFFSET, entry_length, ne_offset, file_size) ||
        !relativeRangeFits(header, NE_SEGMENT_TABLE_OFFSET, segment_count * 8u, ne_offset,
                           file_size) ||
        !relativeRangeFits(header, NE_RESOURCE_TABLE_OFFSET, 2, ne_offset, file_size) ||
        !relativeRangeFits(header, NE_RESIDENT_TABLE_OFFSET, 1, ne_offset, file_size) ||
        !relativeRangeFits(header, NE_IMPORT_TABLE_OFFSET, 1, ne_offset, file_size))
        return false;
    if (module_count != 0 &&
        !relativeRangeFits(header, NE_MODULE_TABLE_OFFSET, module_count * 2u, ne_offset, file_size))
        return false;

    const unsigned nonresident_offset = get_le32(header + NE_NONRESIDENT_OFFSET);
    if (nonresident_size != 0 && !rangeFits(nonresident_offset, nonresident_size, file_size))
        return false;
    return true;
}

} // namespace

/*************************************************************************
//
**************************************************************************/

PackW16Ne::PackW16Ne(InputFile *f) : super(f) { bele = &N_BELE_RTP::le_policy; }

Linker *PackW16Ne::newLinker() const { return new ElfLinkerX86(); }

const int *PackW16Ne::getCompressionMethods(int method, int level) const {
    static const int m_nrv2b[] = {M_NRV2B_8, M_END};
    UNUSED(method);
    UNUSED(level);
    return m_nrv2b;
}

const int *PackW16Ne::getFilters() const { return nullptr; }

void PackW16Ne::buildLoader(const Filter *) { throwCantPack("win16/ne loader is not implemented"); }

/*************************************************************************
// header parsing
**************************************************************************/

int PackW16Ne::readFileHeader() {
    ne_offset = 0;
    original_prefix_size = 0;
    memset(ne_header, 0, sizeof(ne_header));
    if (file_size_u < DOS_HEADER_SIZE + NE_HEADER_SIZE)
        return 0;

    byte dos_header[DOS_HEADER_SIZE];
    fi->seek(0, SEEK_SET);
    fi->readx(dos_header, sizeof(dos_header));
    if (get_le16(dos_header) != ('M' + 'Z' * 256))
        return 0;

    ne_offset = get_le32(dos_header + 0x3c);
    if (!rangeFits(ne_offset, NE_HEADER_SIZE, file_size_u))
        return 0;
    fi->seek(ne_offset, SEEK_SET);
    fi->readx(ne_header, sizeof(ne_header));
    if (!validWindowsNeHeader(ne_header, ne_offset, file_size_u))
        return 0;
    original_prefix_size = ne_offset;
    return UPX_F_WIN16_NE;
}

bool PackW16Ne::readPackTrailer(bool strict) {
    packed_stub_size = 0;
    if (file_size_u < sizeof(stub_i286_win16_ne) + PACK_TRAILER_SIZE)
        return false;

    byte trailer[PACK_TRAILER_SIZE];
    fi->seek(file_size - PACK_TRAILER_SIZE, SEEK_SET);
    fi->readx(trailer, sizeof(trailer));
    if (memcmp(trailer, pack_magic, sizeof(pack_magic)) != 0)
        return false;
    if (trailer[8] != PACK_TRAILER_VERSION || trailer[9] != PACK_METHOD_NRV2B8) {
        if (strict)
            throwCantUnpack("win16/ne: unsupported pack trailer");
        return false;
    }

    original_prefix_size = get_le16(trailer + 10);
    ph.c_len = get_le32(trailer + 12);
    ph.u_len = get_le32(trailer + 16);
    ph.u_adler = get_le32(trailer + 20);
    ph.c_adler = get_le32(trailer + 24);
    packed_stub_size = get_le32(trailer + 28);
    if (original_prefix_size < DOS_HEADER_SIZE || packed_stub_size < original_prefix_size ||
        ph.c_len == 0 || ph.u_len == 0 ||
        (upx_uint64_t) packed_stub_size + ph.c_len + PACK_TRAILER_SIZE != file_size_u) {
        if (strict)
            throwCantUnpack("win16/ne: damaged pack trailer");
        return false;
    }
    ph.method = M_NRV2B_8;
    ph.level = 8;
    ph.u_file_size = original_prefix_size + ph.u_len;
    return true;
}

tribool PackW16Ne::canPack() {
    if (!readFileHeader())
        return false;
    if (readPackTrailer(false))
        throwAlreadyPackedByUPX();
    if (original_prefix_size > 0xffff)
        throwCantPack("win16/ne: DOS stub is too large");
    if ((get_le16(ne_header + NE_FLAGS) & NE_FLAG_LIBRARY) != 0)
        throwCantPack("win16/ne: DLL packing is not implemented");
    return true;
}

tribool PackW16Ne::canUnpack() {
    if (!readFileHeader())
        return false;
    return readPackTrailer(true);
}

void PackW16Ne::pack(OutputFile *fo) {
    ibuf.alloc(file_size);
    obuf.allocForCompression(file_size);
    fi->seek(0, SEEK_SET);
    fi->readx(ibuf, file_size);

    upx_compress_config_t cconf;
    cconf.reset();
    cconf.conf_ucl.max_offset = PACK_WINDOW_SIZE;
    const unsigned ne_size = file_size - original_prefix_size;
    if (!compress(ibuf + original_prefix_size, ne_size, obuf, &cconf))
        throwNotCompressible();
    if (ph.method != M_NRV2B_8 || ph.max_offset_found > PACK_WINDOW_SIZE)
        throwInternalError("win16/ne: invalid compression result");

    const unsigned template_ne_offset = get_le32(stub_i286_win16_ne + 0x3c);
    const byte *template_ne = stub_i286_win16_ne + template_ne_offset;
    const unsigned alignment_shift = get_le16(template_ne + NE_ALIGNMENT_SHIFT);
    const unsigned alignment = 1u << alignment_shift;
    const unsigned wrapper_ne_offset = ALIGN_UP(original_prefix_size, alignment);
    const int offset_delta = (int) wrapper_ne_offset - (int) template_ne_offset;
    if ((offset_delta & (alignment - 1)) != 0)
        throwInternalError("win16/ne: stub alignment error");

    packed_stub_size = wrapper_ne_offset + sizeof(stub_i286_win16_ne) - template_ne_offset;
    MemBuffer packed_stub(packed_stub_size);
    memcpy(packed_stub, ibuf, original_prefix_size);
    memset(packed_stub + original_prefix_size, 0, wrapper_ne_offset - original_prefix_size);
    memcpy(packed_stub + wrapper_ne_offset, template_ne,
           sizeof(stub_i286_win16_ne) - template_ne_offset);
    set_le32(packed_stub + 0x3c, wrapper_ne_offset);

    byte *wrapper_ne = packed_stub + wrapper_ne_offset;
    const unsigned segment_count = get_le16(wrapper_ne + NE_SEGMENT_COUNT);
    byte *segment_table = wrapper_ne + get_le16(wrapper_ne + NE_SEGMENT_TABLE_OFFSET);
    for (unsigned i = 0; i < segment_count; ++i) {
        unsigned sector = get_le16(segment_table + i * 8);
        if (sector != 0)
            set_le16(segment_table + i * 8, sector + offset_delta / (int) alignment);
    }
    unsigned nonresident_offset = get_le32(wrapper_ne + NE_NONRESIDENT_OFFSET);
    if (nonresident_offset != 0)
        set_le32(wrapper_ne + NE_NONRESIDENT_OFFSET, nonresident_offset + offset_delta);

    byte trailer[PACK_TRAILER_SIZE] = {};
    memcpy(trailer, pack_magic, sizeof(pack_magic));
    trailer[8] = PACK_TRAILER_VERSION;
    trailer[9] = PACK_METHOD_NRV2B8;
    set_le16(trailer + 10, original_prefix_size);
    set_le32(trailer + 12, ph.c_len);
    set_le32(trailer + 16, ph.u_len);
    set_le32(trailer + 20, ph.u_adler);
    set_le32(trailer + 24, ph.c_adler);
    set_le32(trailer + 28, packed_stub_size);

    fo->write(packed_stub, packed_stub_size);
    fo->write(obuf, ph.c_len);
    fo->write(trailer, sizeof(trailer));
    // A preserved DOS program can dominate a dual-mode executable. Accept any
    // real size reduction after accounting for the Win16 extraction stub.
    if ((upx_uint64_t)fo->getBytesWritten() >= file_size_u)
        throwNotCompressible();
}

void PackW16Ne::unpack(OutputFile *fo) {
    ibuf.alloc(ph.c_len);
    obuf.allocForDecompression(ph.u_len);
    fi->seek(packed_stub_size, SEEK_SET);
    fi->readx(ibuf, ph.c_len);
    decompress(ibuf, obuf);
    if (fo != nullptr) {
        MemBuffer prefix(original_prefix_size);
        fi->seek(0, SEEK_SET);
        fi->readx(prefix, original_prefix_size);
        set_le32(prefix + 0x3c, original_prefix_size);
        fo->write(prefix, original_prefix_size);
        fo->write(obuf, ph.u_len);
    }
}

/*************************************************************************
// doctest checks
**************************************************************************/

TEST_CASE("win16/ne header validation") {
    byte header[NE_HEADER_BYTES] = {};
    set_le16(header, 'N' + 'E' * 256);
    header[NE_TARGET_OS] = 2;
    set_le16(header + NE_ENTRY_TABLE_OFFSET, 0x40);
    set_le16(header + NE_ENTRY_TABLE_LENGTH, 1);
    set_le16(header + NE_SEGMENT_COUNT, 1);
    set_le16(header + NE_SEGMENT_TABLE_OFFSET, 0x41);
    set_le16(header + NE_RESOURCE_TABLE_OFFSET, 0x49);
    set_le16(header + NE_RESIDENT_TABLE_OFFSET, 0x4b);
    set_le16(header + NE_MODULE_TABLE_OFFSET, 0x4c);
    set_le16(header + NE_IMPORT_TABLE_OFFSET, 0x4c);
    set_le16(header + NE_ALIGNMENT_SHIFT, 9);
    CHECK(validWindowsNeHeader(header, 0x40, 0x100));

    header[NE_TARGET_OS] = 1;
    CHECK_FALSE(validWindowsNeHeader(header, 0x40, 0x100));
    header[NE_TARGET_OS] = 2;
    set_le16(header + NE_SEGMENT_TABLE_OFFSET, 0xfff0);
    CHECK_FALSE(validWindowsNeHeader(header, 0x40, 0x100));
}

/* vim:set ts=4 sw=4 et: */
