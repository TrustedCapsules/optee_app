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
credential = "Dr. James Allison"

function evaluate_policy( op )
		
	err = setState( "credential", credential, POLICY_CAPSULE_META )
	if err ~= POLICY_NIL then
		policy_result = err
		return
	end

	if op == POLICY_OP_OPEN then
	elseif op == POLICY_OP_CLOSE then
	else 
		policy_result = POLICY_ERROR_UNKNOWN_OP
		comment = "Unknown Operation" 
	end
		
end
