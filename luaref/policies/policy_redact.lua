-- API keywords
policy_version = 0 
remote_server = "10.0.0.2:3490"

-- log
log_open = true
log_close = true

-- return keywords
policy_result = POLICY_ALLOW
comment = ""

-- policy-specific keywords
replace_var1 = "THIS IS A SECRET"
replace_var2 = "<secret></secret>"

function evaluate_policy( op )

	err = redact( 0, 10, "" )	
	if err ~= POLICY_NIL then
		policy_result = err
		return
	end
	
	err = redact( 12, 20, "replace_var1" )	
	if err ~= POLICY_NIL then
		policy_result = err
		return
	end

	err = redact( 25, 30, "replace_var2" )	
	if err ~= POLICY_NIL then
		policy_result = err
		return
	end	

	if op == POLICY_OP_OPEN  then
	elseif op == POLICY_OP_CLOSE then
	else 
		policy_result = POLICY_ERROR_UNKNOWN_OP
		comment = "Unknown Operation" 
	end
end
