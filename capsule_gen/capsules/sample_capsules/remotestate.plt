trusted_server = "198.162.52.26"
--trusted_server = "10.0.0.1"
port = 3490
replace_char = "#"

function policy( op )
	res = true;	
	pol_changed = false;
	
	-- OPEN
	if op == 0 then
		local x = getserverstate( "still_employed" );
		if x ~= "true" then
			res = false;
		end		
	-- READ
	elseif op == 1 then 
	-- WRITE
	elseif op == 2 then
	-- DECLASSIFY
	elseif op == 3 then
	end 

	return res, pol_changed;
end

----
location: Vancouver, BC
----
Mon May 28 16:34:34 2018 - CREATED remotestate [ location: Vancouver, BC ]
----
ask if an this device belongs to someone who is still employed or not on open.
