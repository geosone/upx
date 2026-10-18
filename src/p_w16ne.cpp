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
};

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
    return Packer::getDefaultCompressionMethods_8(method, level, true);
}

const int *PackW16Ne::getFilters() const { return nullptr; }

void PackW16Ne::buildLoader(const Filter *) { throwCantPack("win16/ne loader is not implemented"); }

/*************************************************************************
// header parsing
**************************************************************************/

int PackW16Ne::readFileHeader() {
    ne_offset = 0;
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
    return UPX_F_WIN16_NE;
}

tribool PackW16Ne::canPack() {
    if (!readFileHeader())
        return false;
    throwCantPack("win16/ne: packing is not implemented yet");
}

tribool PackW16Ne::canUnpack() {
    if (!readFileHeader())
        return false;
    return false;
}

void PackW16Ne::pack(OutputFile *) { throwCantPack("win16/ne: packing is not implemented yet"); }

void PackW16Ne::unpack(OutputFile *) { throwCantUnpack("win16/ne: unpacking is not implemented"); }

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
