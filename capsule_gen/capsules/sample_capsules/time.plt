trusted_server = "198.162.52.244"
port = 3490
replace_char = "#"

function policy( op )
	res = true;	
	pol_changed = false;	

	-- 09/29/2016 22:05:26
	if gettime() < 1475211926 then
		res = true;
	end

	-- OPEN
	if op == 0 then
	-- READ
	elseif op == 1 then 
	-- WRITE
	elseif op == 2 then
		if gettime() > 0 then
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
Mon May 28 16:34:34 2018 - CREATED time [ location: Vancouver, BC ]
----
this checks the time before allowing a file to be opened, in this policy, we check that a certain
date has passed. 
