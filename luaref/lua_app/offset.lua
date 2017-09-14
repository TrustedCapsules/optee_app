-- format {start1, end1, start2, end2...}
-- these are just test cases
redact = {1, 4, 9, 9, 81, 88};

--output
unredacted = {};

--input
start_off = 0;
len = 44;

unredacted[1] = start_off;
unredacted[2] = start_off + len;

-- when putting in policy, remove the prints
function policy()
	
	print( "before size = " .. #unredacted);
	for i=1,#unredacted do
		print(unredacted[i]);
	end

	for i=1,#redact,2 do
		print( "i: " .. i );
		for j=1,#unredacted,2 do
			-- redact entirely cover unredacted
			if redact[i] <= unredacted[j] and redact[i+1] >= unredacted[j+1] then 
				table.remove( unredacted, j );
				table.remove( unredacted, j );
				print( "redact entirely cover unredacted for set " .. i .. "," .. j );
			-- partial cover, overlap start
			elseif redact[i] <= unredacted[j] and redact[i+1] < unredacted[j+1] 
				   and redact[i+1] >= unredacted[j] then
				unredacted[j] = redact[i+1]+1;
				print( "front overlap for set " .. i .. "," .. j );
			-- partial cover, overlap end
			elseif redact[i] > unredacted[j] and redact[i+1] >= unredacted[j+1] 
				   and redact[i] <= unredacted[j+1] then 
				unredacted[j+1] = redact[i]-1;	
				print( "end overlap for set " .. i .. "," .. j );
			-- unredacted entirely cover redacted
			elseif redact[i] > unredacted[j] and redact[i+1] < unredacted[j+1] then
				table.insert( unredacted, j+1, redact[i+1]+1 );
				table.insert( unredacted, j+1, redact[i]-1 );
				print( "unredacted entirely cover redact for set " .. i .. "," .. j );
			end
		end
	end

	print( "after size = " .. #unredacted);
	for i=1,#unredacted do
		print(unredacted[i]);
	end

end

function policy2()
	
	print( "before size = " .. #unredacted);
	for i=1,#unredacted do
		print(unredacted[i]);
	end
	
	redact_offset( "redact" );

	print( "after size = " .. #unredacted);
	for i=1,#unredacted do
		print(unredacted[i]);
	end
end
