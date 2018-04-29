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
function evaluate_policy( op )

	len = newCapsuleLength()
	if len == -1 then
		policy_result = POLICY_NOT_ALLOW
	end

	if op == POLICY_OP_OPEN  then
	elseif op == POLICY_OP_CLOSE then
	else 
		policy_result = POLICY_ERROR_UNKNOWN_OP
		comment = "Unknown Operation" 
	end
end
