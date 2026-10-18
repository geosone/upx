/* p_w16ne.h -- Windows 16-bit NE executable format

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

#pragma once

/*************************************************************************
// win16/ne
**************************************************************************/

class PackW16Ne final : public Packer {
    typedef Packer super;

public:
    explicit PackW16Ne(InputFile *f);
    virtual int getVersion() const override { return 13; }
    virtual int getFormat() const override { return UPX_F_WIN16_NE; }
    virtual const char *getName() const override { return "win16/ne"; }
    virtual const char *getFullName(const Options *) const override { return "i286-win16.ne"; }
    virtual const int *getCompressionMethods(int method, int level) const override;
    virtual const int *getFilters() const override;

    virtual void pack(OutputFile *fo) override;
    virtual void unpack(OutputFile *fo) override;

    virtual tribool canPack() override;
    virtual tribool canUnpack() override;

protected:
    virtual void buildLoader(const Filter *ft) override;
    virtual Linker *newLinker() const override;

    int readFileHeader();

    static constexpr unsigned DOS_HEADER_SIZE = 64;
    static constexpr unsigned NE_HEADER_SIZE = 64;

    byte ne_header[NE_HEADER_SIZE] = {};
    unsigned ne_offset = 0;
};

/* vim:set ts=4 sw=4 et: */
