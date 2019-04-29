trusted_server = "198.162.52.244"
port = 3490
replace_char = "#"

function policy( op )
	res = true;
	pol_changed = false;

	-- OPEN
	if op == 0 then
	-- READ
	elseif op == 1 then 
	elseif op == 2 then
	elseif op == 3 then
	end 

	return res, pol_changed;
end

----
location: Vancouver, BC
----
Mon May 28 16:34:34 2018 - CREATED bio_copy [ location: Vancouver, BC ]
----
Name: Peter Chen
Age: 25
Gender: Male
Address: 1234 High Park Avenue, Baltimore, MD
Occupation: Student
Blood Type: A+
Illness: none
