trusted_server = "198.162.52.26"
--trusted_server = "10.0.0.1"
port = 3490
replace_char = "#"

function policy( op )
	res = true;	
	pol_changed = false;	


	-- OPEN
	if op == 0 then
		reportlocid( 0 );
	-- READ
	elseif op == 1 then 
		reportlocid( 1 );
	-- WRITE
	elseif op == 2 then
		reportlocid( 2 );
	-- DECLASSIFY
	elseif op == 3 then
	end 

	return res, pol_changed;
end

----
location: Vancouver, BC
----
Mon May 28 16:34:34 2018 - CREATED reportlocid [ location: Vancouver, BC ]
----
simply reports to the server the location, id and time of the operation and the operation
