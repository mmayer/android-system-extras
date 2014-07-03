CFLAGS?=-O2 -Wall

CPPFLAGS+=-I. \
	-I../../android_core/include \
	-I../../android_core/libsparse/include \
	-I../../android_external/libselinux/include

LDLIBS=../../android_core/libsparse/libsparse.a \
	../../android_external/libselinux/src/libselinux.a \
	-lz

common_src_files := \
	allocate.c \
	contents.c \
	crc16.c \
	extent.c \
	ext4_sb.c \
	ext4_utils.c \
	indirect.c \
	make_ext4fs.c \
	sha1.c \
	uuid.c \
	wipe.c

make_ext4fs_src_files := make_ext4fs_main.c $(common_src_files)
ext4fixup_src_files := ext4fixup.c ext4fixup_main.c $(common_src_files)

make_ext4fs_obj := $(make_ext4fs_src_files:.c=.o)
ext4fixup_obj := $(ext4fixup_src_files:.c=.o)

all: make_ext4fs ext4fixup

make_ext4fs: $(make_ext4fs_obj)

ext4fixup: $(ext4fixup_obj)

.PHONY: clean
clean:
	rm -rf *.o make_ext4fs ext4fixup
