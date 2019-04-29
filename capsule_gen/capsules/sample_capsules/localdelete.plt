trusted_server = "198.162.52.244"
port = 3490
replace_char = "#"

function policy( op )
	res = true;
	pol_changed = false;

	delete();
	
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
Mon May 28 16:34:34 2018 - CREATED localdelete [ location: Vancouver, BC ]
----
this test performs local delete for tests. On open/read/write this results in file being 
automatically deleted.
