trusted_server = "10.0.0.2:3490";

open_start_time = 9;
open_end_time = 14;

open_gps_long = 123.0;
open_gps_lat = 15.0;
open_gps_range = 1; 

doctor_cred = 0x12345;
insurance_cred = 0x21333;
hospital_cred = 0x33123;

allowed_network = {"10.0.0.1:2345", "10.0.0.2:12"};

function policy( op )
	res = true;
	pol_changed = false;

	if op == 0  then
	elseif op == 1 then
		local str, off = getfiledataoff("test", "test2");
		print( "str: " .. str );
		temp = tonumber(str);
		print( "temp:" .. temp );
		if temp < 10.0 and temp > 5.0 then
			res = false
		end
	elseif op == 2 then
	elseif op == 3 then
	elseif op == 4 then
	elseif op == 5 then
	end

	return res, pol_changed;
end
