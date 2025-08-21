BUILD_ROOT = $(shell pwd)

BUILD_DIR = $(BUILD_ROOT)/zlib/ \
			$(BUILD_ROOT)/libelf-0.193/   \
			$(BUILD_ROOT)/libbpf-1.1.0/src

compile:
	@for dir in $(BUILD_DIR); \
	do \
		make -C $$dir install; \
	done


clean:
	@for dir in $(BUILD_DIR); \
	do \
		make -C $$dir clean; \
	done
