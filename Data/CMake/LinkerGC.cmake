# SPDX-License-Identifier: MIT

# This applies some common linker options that reduce code size and linking time in Release mode. Namely:
# --gc-sections: Linktime garbage collection, discards unused sections from the final output
# --strip-all  : Similar to running `strip`, discards the symbol table from the final output
# --as-needed  : Only includes libraries that are actually needed in the final output.

macro(LinkerGC target)
  if (CMAKE_BUILD_TYPE MATCHES "RELEASE")
    if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
      # Apple's ld64 doesn't understand the GNU ld/lld flags above. -dead_strip is its
      # section-gc equivalent; there's no ld64 flag matching --strip-all/--as-needed as cleanly,
      # so those are left to a separate strip step (sogen already does this via
      # sogen_strip_target() for its own targets) rather than guessing at a rough substitute.
      target_link_options(${target} PRIVATE "LINKER:-dead_strip")
    else()
      target_link_options(${target} PRIVATE
        "LINKER:--gc-sections"
        "LINKER:--strip-all"
        "LINKER:--as-needed")
    endif()
  endif()
endmacro()
