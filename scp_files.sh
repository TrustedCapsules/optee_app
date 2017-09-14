#!/bin/bash

USERNAME="acarb95"
ADDRESS="198.162.52.26"
TC_PATH="~/trustedcapsules/hikey"

if [ "$1" = 'apps' ]
 then
	scp $USERNAME@$ADDRESS:$TC_PATH/optee_app/ta/ffa39702-9ce0-47e0-a1cb4048cfdb847d.ta /lib/optee_armtz/
	scp $USERNAME@$ADDRESS:$TC_PATH/optee_app/host/capsule_test /usr/bin/
	scp $USERNAME@$ADDRESS:$TC_PATH/optee_app/host/capsule_test_policy /usr/bin/
	scp $USERNAME@$ADDRESS:$TC_PATH/optee_app/test_app/test_app /usr/bin/
elif [ "$1" = 'capsules' ]
 then
	scp $USERNAME@$ADDRESS:$TC_PATH/optee_app/capsule_gen/capsules/test_capsules/* /etc/test_capsules
	scp $USERNAME@$ADDRESS:$TC_PATH/optee_app/capsule_gen/capsules/use_case_capsules/* /etc/use_case_capsules
	scp $USERNAME@$ADDRESS:$TC_PATH/optee_app/capsule_gen/capsules/* /etc/other_capsules
elif [ "$1" = 'drivers' ]
 then
	scp $USERNAME@$ADDRESS:$TC_PATH/optee_linuxdriver/armtz/optee_armtz.ko /lib/modules/3.18.0-linaro-hikey/extra/armtz/
	scp $USERNAME@$ADDRESS:$TC_PATH/optee_linuxdriver/core/optee.ko /lib/modules/3.18.0-linaro-hikey/extra/core/
	scp $USERNAME@$ADDRESS:$TC_PATH/optee_linuxdriver/interceptor/interceptor.ko /lib/modules/3.18.0-linaro-hikey/extra/interceptor/
else
	echo "USAGE: ./scp_files.sh [apps|capsules|drivers]"
fi
