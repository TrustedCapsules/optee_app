trusted_server = "198.162.52.244"
port = 3490
replace_char = "#"

function policy( op )
	res = true;
	pol_changed = false;

	local long, lat = getgps();
	if  ((long - 10330) >= 10 or (10330-long) >= 10) or 
		((lat - 2136 >= 10) or (2136-lat >= 10)) then
		res = false;
	end
	
	-- OPEN
	if op == 0 then
	-- READ
	elseif op == 1 then 
	-- WRITE
	elseif op == 2 then
		if((lat - 2130 >= 10) or (2130 - lat >= 10)) or ((lat - 22223 >= 10) or (22223-lat >= 10 )) then
			res = false;
		end
	-- DECLASSIFY
	elseif op == 3 then
	end 

	return res, pol_changed;
end

----
location: Vancouver, BC
----
Mon May 28 16:34:34 2018 - CREATED gps [ location: Vancouver, BC ]
----
This fake tests the gps policy. For any operation it must be within 10 units of our fake coordinate system. However, to write, it must be somewhere else. As this could not possibly satisfy both conditions, every thing but write can work, but write cannot.
