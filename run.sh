echo '$0 = ' $0
echo '$1 = ' $1
echo '$2 = ' $2

# $1 compiles the optee_app
# $2 runs qemu with the compiled optee_app

if [ "$1" = "1" ]; then
	rm logfile
	make clean >> logfile
	make >> logfile
fi

if [ "$2" = "1" ]; then
	cd ../network-scripts/
	sudo sh qemu-ifup.sh eth0 >> logfile
	cd ../build
	make all run
	#quit
	cd ../network-scripts/
	sudo sh qemu-ifdown.sh eth0 >> logfile
fi


