make clean
cd arch/
rm -rf csky     ia64     loongarch  microblaze  nios2     parisc   riscv  sh     um   xtensa
rm -rf arm64  hexagon  Kconfig  m68k  mips  openrisc  powerpc  s390  sparc  x86
rm -rf alpha/ arc/
cd ..          
rm -rf arch/arm/boot/zImage 
rm -rf arch/arm/boot/Image 
rm -rf samples/
rm -rf rust/
rm -rf Documentation/
rm -rf drivers/
rm -rf lib
rm -rf tools
