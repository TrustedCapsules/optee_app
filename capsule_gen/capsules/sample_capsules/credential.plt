trusted_server = "198.162.52.244"
port = 3490
replace_char = "#"

function policy( op )
	res = true;
	pol_changed = false;

	if getlocalstate( "cred" ) ~= "doct" then
		res = false;
	end
	
	-- OPEN
	if op == 0 then
	-- READ
	elseif op == 1 then 
	-- WRITE
	elseif op == 2 then
	-- DECLASSIFY
	elseif op == 3 then
	-- CLOSE
	elseif op == 4 then
		res = true;
	end 

	return res, pol_changed;
end

----
location: Vancouver, BC
----
Mon May 28 16:34:34 2018 - CREATED credential [ location: Vancouver, BC ]
----
This test performs by checking the credential of the device in the TrustZone to allow 
open/read/write/declassify operations. 
