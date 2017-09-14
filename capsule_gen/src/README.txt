NOTE: This script uses libtomcrypt. Getting libtomcrypt from apt-get won't work!
libtomcrypt needs to be compiled while specifying tomsfastmath as an extra
library.
--------------------------------------------------------------------------------
1) Clone tomsfastmath from source

git clone https://github.com/libtom/tomsfastmath.git
--------------------------------------------------------------------------------
2) Build and install the library
   - The makefile defines GROUP=wheel (I think this is for BSD) and will cause
	   an error on linux. Just change 'wheel' to 'root'.

sudo make install
--------------------------------------------------------------------------------
3) Clone libtomcrypt from source

git clone https://github.com/libtom/libtomcrypt.git
--------------------------------------------------------------------------------
4) Build, install, run tests for library.
   - Turn off latex compiling, either by defining NODOCS when running make, or:
	   - in makefile:260, comment out "docs"
		 - in makefile:270, comment out the whole line
   - In makefile.include:106, change the GROUP=wheel to GROUP=root

sudo CFLAGS="-DTFM_DESC -DUSE_TFM" EXTRALIBS=-ltfm make install \
	test timing
--------------------------------------------------------------------------------
5) Now the script should properly build.

make
make run
--------------------------------------------------------------------------------

