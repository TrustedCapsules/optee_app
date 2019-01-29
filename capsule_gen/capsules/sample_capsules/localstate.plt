trusted_server = "198.162.52.244"
port = 3490
replace_char = "#"

function policy( op )
	res = true;	
	pol_changed = false;
	
	-- OPEN
	if op == 0 then
		x = getlocalstate( "num_access" );
		if x == "none" then
			setstate( "num_access", 1 );		
		else
 			if tonumber(x) + 1 > 2 then
				res = false
			else
				setstate( "num_access", tostring( tonumber(x)+1 ) );
			end
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
Mon May 28 16:34:34 2018 - CREATED localstate [ location: Vancouver, BC ]
----
local state works by a policy that allows a file to only be opened 2 times. This has no
policy on read/write
