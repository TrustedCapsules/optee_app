trusted_server = "198.162.52.26"
--trusted_server = "10.0.0.1"
port = 3490
replace_char = "#"
version = 1

function policy( op )
	res = false;	
	pol_changed = false;	

	pol_changed = checkpolicychange( version );

	-- OPEN
	if op == 0 then
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
Mon May 28 16:34:34 2018 - CREATED policychange [ location: Vancouver, BC ]
----
the data will have its policy changed on open and on subsequent read, the policy would be already updated so it won't change. 
