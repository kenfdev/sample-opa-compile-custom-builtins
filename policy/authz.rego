package authz

import data.policies

default allow = false

allow = r {
    policy := policies[input.user]
    policy.effect == "allow"
    r := hello(input.user)
}
